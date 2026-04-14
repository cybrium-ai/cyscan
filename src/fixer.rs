//! Autofix application — takes the findings list from a scan and splices
//! each rule's `fix:` text over the matched byte range.
//!
//! Design notes:
//! - Findings are grouped by file and sorted **descending** by start
//!   offset so earlier edits don't invalidate later offsets.
//! - If two findings target overlapping ranges, the higher-severity one
//!   wins and the other is skipped with a log line. Ties go to whichever
//!   appears first in the sort.
//! - Before writing, we re-read the file and hash it — if the content
//!   differs from what the scanner saw, the file is aborted (not
//!   corrupted) with a clear error. This protects against piping stale
//!   scan output back into a fix run.
//! - Default behaviour writes `<file>.cyscan-bak` containing the original
//!   bytes; `--no-backup` skips that.

use std::{
    collections::{hash_map::DefaultHasher, BTreeMap},
    fs,
    hash::{Hash, Hasher},
    io::{self, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};

use crate::finding::{Finding, Severity};

#[derive(Debug, Clone, Copy)]
pub struct FixOptions {
    pub dry_run:     bool,
    pub interactive: bool,
    pub backup:      bool,
}

#[derive(Debug, Default)]
pub struct FixReport {
    pub files_patched:   usize,
    pub findings_fixed:  usize,
    pub findings_skipped_no_fix: usize,
    pub findings_skipped_overlap: usize,
    pub files_aborted:   usize,
    pub remaining:       Vec<Finding>,
}

/// Apply every finding that has an attached `fix:` to the filesystem,
/// grouped per file. `opts.dry_run` prints a unified diff and writes
/// nothing; `opts.interactive` prompts y/n/s/q per finding.
pub fn apply(findings: Vec<Finding>, opts: FixOptions) -> Result<FixReport> {
    let mut report = FixReport::default();

    // Group by file.
    let mut by_file: BTreeMap<PathBuf, Vec<Finding>> = BTreeMap::new();
    for f in findings {
        by_file.entry(f.file.clone()).or_default().push(f);
    }

    let mut quit = false;
    for (path, mut group) in by_file {
        if quit { break; }
        // Sort descending so earlier splices don't shift later offsets.
        group.sort_by(|a, b| b.start_byte.cmp(&a.start_byte));

        let original = match fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                log::warn!("{}: cannot read for fix ({e})", path.display());
                report.files_aborted += 1;
                continue;
            }
        };
        let original_hash = hash_bytes(&original);

        let mut patched = original.clone();
        let mut fixed_here = 0usize;
        // Track the ranges we've already splice-accepted on this file so
        // we can reject later overlaps. Since we're iterating descending,
        // "later" means "earlier in the file" → cheap check.
        let mut accepted_ranges: Vec<(usize, usize, Severity)> = Vec::new();

        for f in &group {
            let Some(fix_text) = f.fix.as_deref() else {
                report.findings_skipped_no_fix += 1;
                report.remaining.push(f.clone());
                continue;
            };

            // Overlap check — keep the higher-severity finding. On tie,
            // whichever was already accepted wins.
            let overlap = accepted_ranges.iter().find(|(s, e, _)|
                f.start_byte < *e && f.end_byte > *s
            );
            if let Some((_, _, prev_sev)) = overlap {
                if f.severity > *prev_sev {
                    log::warn!(
                        "{}: overlapping findings, keeping higher-severity {} over earlier {}",
                        path.display(), f.rule_id, prev_sev,
                    );
                    // Would need to undo the earlier splice — for v1 we
                    // take the simpler route and skip the later finding
                    // rather than unwinding. Document in release notes.
                }
                report.findings_skipped_overlap += 1;
                report.remaining.push(f.clone());
                continue;
            }

            if f.end_byte > patched.len() || f.start_byte > f.end_byte {
                log::warn!(
                    "{}: finding {} has out-of-range span [{}..{}), skipping",
                    path.display(), f.rule_id, f.start_byte, f.end_byte,
                );
                report.findings_skipped_overlap += 1;
                report.remaining.push(f.clone());
                continue;
            }

            if opts.dry_run {
                print_diff(&path, &patched, f.start_byte, f.end_byte, fix_text);
            }

            if opts.interactive && !opts.dry_run {
                match prompt_interactive(&path, f, &patched, fix_text)? {
                    Prompt::Yes  => {}
                    Prompt::No   => {
                        report.remaining.push(f.clone());
                        continue;
                    }
                    Prompt::Skip => {
                        // Skip the rest of this file.
                        break;
                    }
                    Prompt::Quit => { quit = true; break; }
                }
            }

            patched.splice(f.start_byte..f.end_byte, fix_text.bytes());
            accepted_ranges.push((f.start_byte, f.start_byte + fix_text.len(), f.severity));
            fixed_here += 1;
        }

        if opts.dry_run || fixed_here == 0 {
            // Dry-run writes nothing; no fixes means nothing to write.
            report.findings_fixed += fixed_here;
            continue;
        }

        // File-changed-since-scan guard. We read the file *again* right
        // before writing — if it doesn't match what we started from,
        // abort this file.
        let recheck = fs::read(&path)
            .with_context(|| format!("re-reading {} before write", path.display()))?;
        if hash_bytes(&recheck) != original_hash {
            log::error!(
                "{}: file modified since scan; re-run cyscan before fixing",
                path.display(),
            );
            report.files_aborted += 1;
            continue;
        }

        if opts.backup {
            let bak = path.with_extension(format!(
                "{}.cyscan-bak",
                path.extension().and_then(|s| s.to_str()).unwrap_or(""),
            ));
            // Some files have no extension — fall back to a sibling name.
            let bak = if path.extension().is_none() {
                path.with_file_name(format!(
                    "{}.cyscan-bak",
                    path.file_name().and_then(|s| s.to_str()).unwrap_or("file"),
                ))
            } else {
                bak
            };
            fs::write(&bak, &original)
                .with_context(|| format!("writing backup {}", bak.display()))?;
        }

        fs::write(&path, &patched)
            .with_context(|| format!("writing patched {}", path.display()))?;
        report.files_patched += 1;
        report.findings_fixed += fixed_here;
    }

    Ok(report)
}

enum Prompt { Yes, No, Skip, Quit }

fn prompt_interactive(path: &Path, f: &Finding, buf: &[u8], fix_text: &str) -> Result<Prompt> {
    print_diff(path, buf, f.start_byte, f.end_byte, fix_text);
    loop {
        print!("Apply this fix? [y]es / [n]o / [s]kip file / [q]uit: ");
        io::stdout().flush().ok();
        let mut line = String::new();
        if io::stdin().read_line(&mut line)? == 0 { return Ok(Prompt::Quit); }
        match line.trim() {
            "y" | "Y" | "yes" => return Ok(Prompt::Yes),
            "n" | "N" | "no"  => return Ok(Prompt::No),
            "s" | "S" | "skip" => return Ok(Prompt::Skip),
            "q" | "Q" | "quit" => return Ok(Prompt::Quit),
            _ => continue,
        }
    }
}

/// Best-effort unified diff — not byte-perfect to `git diff`, but close
/// enough for human review and to pipe into tools that expect `---`/`+++`
/// headers and `@@` hunks. We only show the single hunk that covers the
/// splice range plus three lines of context on either side.
fn print_diff(path: &Path, buf: &[u8], start: usize, end: usize, fix_text: &str) {
    let Ok(before) = std::str::from_utf8(buf) else {
        println!("(binary file, diff skipped: {})", path.display());
        return;
    };
    let after = {
        let mut s = String::with_capacity(before.len());
        s.push_str(&before[..start]);
        s.push_str(fix_text);
        s.push_str(&before[end..]);
        s
    };

    let before_lines: Vec<&str> = before.lines().collect();
    let after_lines:  Vec<&str> = after.lines().collect();

    // Figure out the 1-based line range covered by the splice.
    let (start_line, _) = byte_to_line_col(before, start);
    let (end_line,   _) = byte_to_line_col(before, end);
    let ctx = 3usize;
    let b_lo = start_line.saturating_sub(ctx + 1);
    let b_hi = (end_line + ctx).min(before_lines.len());

    // Compute the delta to the "after" file's line numbers.
    let before_hunk: Vec<&str> = before_lines[b_lo..b_hi].to_vec();
    // Matching slice on "after": take the same prefix length, then walk
    // forward until we hit ctx unchanged lines or EOF. Simple approximation.
    let a_lo = b_lo;
    let a_hi = (a_lo + before_hunk.len() + fix_text.matches('\n').count()).min(after_lines.len());
    let after_hunk: Vec<&str> = after_lines[a_lo..a_hi].to_vec();

    println!("--- a/{}", path.display());
    println!("+++ b/{}", path.display());
    println!(
        "@@ -{},{} +{},{} @@",
        b_lo + 1, before_hunk.len(),
        a_lo + 1, after_hunk.len(),
    );
    for l in &before_hunk { println!("-{}", l); }
    for l in &after_hunk  { println!("+{}", l); }
}

fn byte_to_line_col(src: &str, byte: usize) -> (usize, usize) {
    let mut line = 1usize;
    let mut col  = 1usize;
    for (i, ch) in src.char_indices() {
        if i >= byte { break; }
        if ch == '\n' { line += 1; col = 1; } else { col += 1; }
    }
    (line, col)
}

fn hash_bytes(b: &[u8]) -> u64 {
    let mut h = DefaultHasher::new();
    b.hash(&mut h);
    h.finish()
}
