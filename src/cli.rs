//! CLI command tree.

use std::{path::PathBuf, process::ExitCode};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use crate::{finding::Severity, fixer, output, rule::RulePack, scanner, self_update, supply};

#[derive(Debug, Parser)]
#[command(
    name    = "cyscan",
    about   = "Cybrium Scan — fast multi-language SAST engine",
    version,
    bin_name = "cyscan",
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Scan a directory or file against a rule pack.
    Scan {
        /// Target path (file or directory). Respects .gitignore when a dir.
        #[arg(default_value = ".")]
        target: PathBuf,

        /// Rule pack directory. Recursively loads every .yml/.yaml.
        /// Falls back to the bundled rules/ if omitted.
        #[arg(long, short = 'r')]
        rules: Option<PathBuf>,

        /// Output format.
        #[arg(long, short = 'f', value_enum, default_value_t = Format::Text)]
        format: Format,

        /// Exit with non-zero status if any finding is at or above this
        /// severity. Disabled when unset.
        #[arg(long)]
        fail_on: Option<Severity>,

        /// Parallelism override. Default = rayon's detected CPU count.
        #[arg(long)]
        jobs: Option<usize>,
    },

    /// Scan dependency lockfiles against advisories + typosquat + policy.
    Supply {
        #[arg(default_value = ".")]
        target: PathBuf,

        /// Rule pack directory (for `dependency:` policy rules).
        #[arg(long, short = 'r')]
        rules: Option<PathBuf>,

        /// Advisory snapshot dir (defaults to bundled rules/advisories).
        #[arg(long)]
        advisories: Option<PathBuf>,

        /// Skip the OSV advisory match — useful for policy-only scans.
        #[arg(long)]
        no_advisories: bool,

        /// Suppress snapshot-freshness warnings (for air-gapped runs).
        #[arg(long)]
        offline: bool,

        #[arg(long, short = 'f', value_enum, default_value_t = Format::Text)]
        format: Format,

        #[arg(long)]
        fail_on: Option<Severity>,
    },

    /// Apply autofixes for every finding whose rule has a `fix:` block.
    Fix {
        /// Target path (file or directory).
        #[arg(default_value = ".")]
        target: PathBuf,

        /// Rule pack directory. Same resolution as `scan`.
        #[arg(long, short = 'r')]
        rules: Option<PathBuf>,

        /// Print a unified diff per finding — write nothing.
        #[arg(long)]
        dry_run: bool,

        /// Prompt y/n/s/q per finding.
        #[arg(long)]
        interactive: bool,

        /// Skip writing `<file>.cyscan-bak` before rewriting.
        #[arg(long)]
        no_backup: bool,

        /// Exit with non-zero status if any finding at or above this
        /// severity was left unfixed (no `fix:` block, skipped overlap,
        /// declined in interactive mode).
        #[arg(long)]
        fail_on: Option<Severity>,
    },

    /// Inspect the configured rule pack.
    Rules {
        #[command(subcommand)]
        cmd: RulesCmd,
    },

    /// Check repository security health (governance, secrets, supply chain).
    Health {
        /// Target directory to analyze.
        #[arg(default_value = ".")]
        target: PathBuf,

        /// Output format.
        #[arg(long, short = 'f', value_enum, default_value_t = Format::Text)]
        format: Format,
    },

    /// Detect frameworks used in the codebase.
    Frameworks {
        /// Target directory to analyze.
        #[arg(default_value = ".")]
        target: PathBuf,

        /// Output format.
        #[arg(long, short = 'f', value_enum, default_value_t = Format::Text)]
        format: Format,
    },

    /// Check for updates and self-update the binary.
    Update,

    /// Show version and check for updates.
    Version,
}

#[derive(Debug, Subcommand)]
enum RulesCmd {
    /// List every rule in the pack with severity + language.
    List {
        #[arg(long, short = 'r')]
        rules: Option<PathBuf>,
    },
    /// Validate the pack — parse each file, report errors.
    Validate {
        #[arg(long, short = 'r')]
        rules: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum Format {
    #[default]
    Text,
    Json,
    Sarif,
}

fn print_banner() {
    eprintln!("\x1b[35m");
    eprintln!(r#"   ___  _   _  ___   ___    _    _  _ "#);
    eprintln!(r#"  / __|| | | |/ __| / __|  /_\  | \| |"#);
    eprintln!(r#" | (__ | |_| |\__ \| (__  / _ \ | .` |"#);
    eprintln!(r#"  \___| \__, ||___/ \___|/_/ \_\|_|\_|"#);
    eprintln!(r#"        |___/                         "#);
    eprintln!("\x1b[0m");
    eprintln!(
        "  \x1b[35m\x1b[1mcyscan\x1b[0m v{} — \x1b[2mCybrium AI SAST Engine\x1b[0m",
        env!("CARGO_PKG_VERSION")
    );
    eprintln!();
}

pub fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    match &cli.cmd {
        Cmd::Scan { .. } | Cmd::Supply { .. } | Cmd::Fix { .. } => print_banner(),
        _ => {}
    }
    match cli.cmd {
        Cmd::Scan { target, rules, format, fail_on, jobs } => {
            if let Some(n) = jobs {
                rayon::ThreadPoolBuilder::new()
                    .num_threads(n)
                    .build_global()
                    .ok();
            }
            let pack = load_pack(rules.as_deref())?;
            let findings = scanner::run(&target, &pack)?;

            match format {
                Format::Text  => output::text::emit(&findings)?,
                Format::Json  => output::json::emit(&findings)?,
                Format::Sarif => output::sarif::emit(&findings)?,
            }

            let fail_hit = match fail_on {
                Some(min) => findings.iter().any(|f| f.severity >= min),
                None      => false,
            };
            Ok(ExitCode::from(if fail_hit { 1 } else { 0 }))
        }

        Cmd::Supply { target, rules, advisories, no_advisories, offline: _, format, fail_on } => {
            let pack = load_pack(rules.as_deref())?;
            let snapshot = if no_advisories {
                supply::advisory::Snapshot::default()
            } else {
                let dir = advisories.unwrap_or_else(bundled_advisories_path);
                supply::advisory::Snapshot::load_dir(&dir)?
            };
            let findings = supply::run(&target, &pack, &snapshot)?;
            match format {
                Format::Text  => output::text::emit(&findings)?,
                Format::Json  => output::json::emit(&findings)?,
                Format::Sarif => output::sarif::emit(&findings)?,
            }
            let fail_hit = match fail_on {
                Some(min) => findings.iter().any(|f| f.severity >= min),
                None      => false,
            };
            Ok(ExitCode::from(if fail_hit { 1 } else { 0 }))
        }

        Cmd::Fix { target, rules, dry_run, interactive, no_backup, fail_on } => {
            let pack = load_pack(rules.as_deref())?;
            let findings = scanner::run(&target, &pack)?;
            let total = findings.len();

            let report = fixer::apply(findings, fixer::FixOptions {
                dry_run,
                interactive,
                backup: !no_backup,
            })?;

            eprintln!(
                "fix: {} patched, {} fixed, {} skipped (no fix), {} skipped (overlap), {} aborted; {} findings remain",
                report.files_patched,
                report.findings_fixed,
                report.findings_skipped_no_fix,
                report.findings_skipped_overlap,
                report.files_aborted,
                total - report.findings_fixed,
            );

            let fail_hit = match fail_on {
                Some(min) => report.remaining.iter().any(|f| f.severity >= min),
                None      => false,
            };
            Ok(ExitCode::from(if fail_hit { 1 } else { 0 }))
        }

        Cmd::Rules { cmd: RulesCmd::List { rules } } => {
            let pack = load_pack(rules.as_deref())?;
            for rule in pack.rules() {
                println!("{:<40} {:<8} {}", rule.id, rule.severity, rule.title);
            }
            println!("\n{} rule(s) loaded", pack.rules().len());
            Ok(ExitCode::from(0))
        }

        Cmd::Rules { cmd: RulesCmd::Validate { rules } } => {
            let pack = load_pack(rules.as_deref())?;
            println!("✓ {} rule(s) parsed cleanly", pack.rules().len());
            Ok(ExitCode::from(0))
        }

        Cmd::Health { target, format } => {
            let health = crate::framework::check_repo_health(&target);
            match format {
                Format::Json => {
                    println!("{}", serde_json::to_string_pretty(&health).unwrap_or_default());
                }
                _ => {
                    let icon = if health.score >= 80 { "PASS" } else if health.score >= 50 { "WARN" } else { "FAIL" };
                    println!("\nRepository Health Score: {}/100 [{}]\n", health.score, icon);
                    for check in &health.checks {
                        let status = if check.passed { " PASS " } else { " FAIL " };
                        let sev = match check.severity {
                            "critical" => "CRIT",
                            "high" => "HIGH",
                            "medium" => "MED ",
                            "low" => "LOW ",
                            _ => "INFO",
                        };
                        println!("  [{}] [{}] {}", status, sev, check.name);
                        if !check.passed {
                            println!("         → {}", check.detail);
                        }
                    }
                    println!();
                }
            }
            Ok(ExitCode::from(if health.score >= 50 { 0 } else { 1 }))
        }

        Cmd::Frameworks { target, format } => {
            let detected = crate::framework::detect(&target);
            if detected.is_empty() {
                println!("No frameworks detected.");
            } else {
                match format {
                    Format::Json => {
                        println!("{}", serde_json::to_string_pretty(&detected).unwrap_or_default());
                    }
                    _ => {
                        println!("{} framework(s) detected:\n", detected.len());
                        for fw in &detected {
                            let ver = fw.version.as_deref().map(|v| format!(" v{v}")).unwrap_or_default();
                            println!("  {:<20} {:<12} {:<8} confidence {:.0}%{}",
                                fw.name, fw.language, fw.category, fw.confidence * 100.0, ver);
                            for loc in &fw.detected_in {
                                println!("    found in: {loc}");
                            }
                        }
                    }
                }
            }
            Ok(ExitCode::from(0))
        }

        Cmd::Update => {
            self_update::update("cybrium-ai/cyscan", "cyscan")?;
            Ok(ExitCode::from(0))
        }

        Cmd::Version => {
            self_update::version("cybrium-ai/cyscan");
            Ok(ExitCode::from(0))
        }
    }
}

fn load_pack(path: Option<&std::path::Path>) -> Result<RulePack> {
    let path = path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| bundled_rules_path());
    RulePack::load_dir(&path).with_context(|| format!("loading rules from {}", path.display()))
}

/// Best-effort resolution of the bundled rules directory.
///
/// Search order (first hit wins):
///   1. `$CYSCAN_RULES` env var (explicit override)
///   2. `<exe_dir>/rules`             — tarball layout (bin + rules side-by-side)
///   3. `<exe_dir>/../rules`          — Homebrew layout (bin/ + rules/ under prefix)
///   4. `<exe_dir>/../share/cyscan/rules` — FHS-friendly Linux package layout
///   5. `<CARGO_MANIFEST_DIR>/rules`  — cargo run / dev mode
fn bundled_rules_path() -> PathBuf {
    if let Ok(p) = std::env::var("CYSCAN_RULES") {
        return PathBuf::from(p);
    }

    // Try exe-relative paths (works for tarball + Homebrew layouts)
    if let Ok(exe) = std::env::current_exe() {
        // Resolve symlinks first (macOS Homebrew uses symlinks)
        let real_exe = std::fs::canonicalize(&exe).unwrap_or(exe);
        if let Some(dir) = real_exe.parent() {
            for rel in ["rules", "../rules", "../share/cyscan/rules"] {
                let candidate = dir.join(rel);
                if candidate.exists() {
                    return candidate.canonicalize().unwrap_or(candidate);
                }
            }
        }
    }

    // Homebrew-specific fallback (macOS)
    for prefix in ["/opt/homebrew/opt/cyscan", "/usr/local/opt/cyscan"] {
        let candidate = PathBuf::from(prefix).join("rules");
        if candidate.exists() {
            return candidate;
        }
    }

    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rules")
}

fn bundled_advisories_path() -> PathBuf {
    if let Ok(p) = std::env::var("CYSCAN_ADVISORIES") {
        return PathBuf::from(p);
    }
    if let Ok(exe) = std::env::current_exe() {
        let real_exe = std::fs::canonicalize(&exe).unwrap_or(exe);
        if let Some(dir) = real_exe.parent() {
            for rel in ["rules/advisories", "../rules/advisories", "../share/cyscan/rules/advisories"] {
                let c = dir.join(rel);
                if c.exists() { return c.canonicalize().unwrap_or(c); }
            }
        }
    }
    for prefix in ["/opt/homebrew/opt/cyscan", "/usr/local/opt/cyscan"] {
        let c = PathBuf::from(prefix).join("rules/advisories");
        if c.exists() { return c; }
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rules/advisories")
}
