//! CLI command tree.

use std::{path::PathBuf, process::ExitCode};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use crate::{finding::Severity, fixer, k8s, output, rule::RulePack, scanner, self_update, supply};

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

        /// Path to a baseline file. Findings in this file will be suppressed.
        #[arg(long, short = 'b')]
        baseline: Option<PathBuf>,

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

        /// Verify detected secrets are live by making safe, read-only API calls.
        #[arg(long, default_value_t = false)]
        verify: bool,

        /// Show CIA triad posture summary (Confidentiality, Integrity, Availability scores).
        #[arg(long, default_value_t = false)]
        cia: bool,
    },

    /// Scan dependency lockfiles against advisories + typosquat + policy.
    Supply {
        /// Target path (file or directory).
        #[arg(default_value = ".")]
        target: PathBuf,

        /// Rule pack directory.
        #[arg(long, short = 'r')]
        rules: Option<PathBuf>,

        /// Advisory snapshot directory.
        #[arg(long)]
        advisories: Option<PathBuf>,

        /// Skip bundled/local advisories and only run typosquat + policy checks.
        #[arg(long, default_value_t = false)]
        no_advisories: bool,

        /// Reserved compatibility flag for disconnected environments.
        #[arg(long, default_value_t = false)]
        offline: bool,

        /// Output format.
        #[arg(long, short = 'f', value_enum, default_value_t = Format::Text)]
        format: Format,

        #[arg(long)]
        fail_on: Option<Severity>,
    },

    /// Create a baseline of current findings to ignore them in future scans.
    Baseline {
        /// Target path to scan for the baseline.
        #[arg(default_value = ".")]
        target: PathBuf,

        /// Rule pack directory.
        #[arg(long, short = 'r')]
        rules: Option<PathBuf>,

        /// Path to save the baseline file.
        #[arg(long, short = 'o', default_value = ".cyscan-baseline.json")]
        output: PathBuf,
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

    /// Scan a live Kubernetes cluster for vulnerabilities, misconfigs, and secrets.
    K8s {
        /// Kubeconfig file path (uses default if omitted).
        #[arg(long)]
        kubeconfig: Option<PathBuf>,

        /// Scan a specific namespace only (default: all namespaces).
        #[arg(long, short = 'n')]
        namespace: Option<String>,

        /// Report format: summary (table) or full (detailed findings).
        #[arg(long, default_value = "summary")]
        report: K8sReportMode,

        /// Output format (applies to full report mode).
        #[arg(long, short = 'f', value_enum, default_value_t = Format::Text)]
        format: Format,

        /// Also scan container images for CVEs (requires grype or trivy).
        #[arg(long, default_value_t = false)]
        scan_images: bool,

        /// Rule pack directory.
        #[arg(long, short = 'r')]
        rules: Option<PathBuf>,

        /// Exit with non-zero if any finding at or above this severity.
        #[arg(long)]
        fail_on: Option<Severity>,
    },

    /// Scan an application package (.app, .ipa, .pkg, .apk, .exe, .msi, .deb, .rpm).
    App {
        /// Path to the application package.
        target: PathBuf,

        /// Output format.
        #[arg(long, short = 'f', value_enum, default_value_t = Format::Text)]
        format: Format,

        /// Exit with non-zero if score is below this threshold (0-100).
        #[arg(long)]
        fail_below: Option<u32>,
    },

    /// Scan this endpoint for security posture (encryption, firewall, updates, etc.).
    Endpoint {
        /// Output format.
        #[arg(long, short = 'f', value_enum, default_value_t = Format::Text)]
        format: Format,

        /// Exit with non-zero if score is below this threshold (0-100).
        #[arg(long)]
        fail_below: Option<u32>,
    },

    /// Check for updates and self-update the binary.
    Update,

    /// Show version and check for updates.
    Version,
}

#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum K8sReportMode {
    #[default]
    Summary,
    Full,
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
        Cmd::Scan { target, rules, baseline, format, fail_on, jobs, verify, cia: show_cia } => {
            if let Some(n) = jobs {
                rayon::ThreadPoolBuilder::new()
                    .num_threads(n)
                    .build_global()
                    .ok();
            }
            let pack = load_pack(rules.as_deref())?;
            
            // --- Code to Cloud Synergy: Automatic Manifest Context ---
            let cloud_ctx = if target.is_dir() {
                Some(collect_cloud_context(&target))
            } else {
                None
            };

            let mut findings = scanner::run_with_context(&target, &pack, cloud_ctx)?;

            if let Some(baseline_path) = baseline {
                let baseline_content = std::fs::read_to_string(&baseline_path)
                    .with_context(|| format!("reading baseline file {}", baseline_path.display()))?;
                let baseline_fingerprints: std::collections::HashSet<String> = serde_json::from_str(&baseline_content)
                    .with_context(|| "parsing baseline JSON (expected an array of fingerprint strings)")?;
                
                let original_count = findings.len();
                findings.retain(|f| !baseline_fingerprints.contains(&f.fingerprint));
                let suppressed = original_count - findings.len();
                if suppressed > 0 {
                    eprintln!("  Suppressed {} finding(s) present in baseline", suppressed);
                }
            }

            if verify {
                eprintln!("Verifying detected secrets...");
                crate::matcher::verify::enrich_findings(&mut findings);
                let live_count = findings.iter()
                    .filter(|f| f.evidence.get("verified").and_then(|v| v.as_bool()) == Some(true))
                    .count();
                eprintln!("  {} live secrets confirmed", live_count);
            }

            match format {
                Format::Text  => output::text::emit(&findings)?,
                Format::Json  => output::json::emit(&findings)?,
                Format::Sarif => output::sarif::emit(&findings)?,
            }

            if show_cia {
                let cia_scores = crate::cia::score(&findings, &pack);
                match format {
                    Format::Json => {
                        println!("{}", serde_json::to_string_pretty(&cia_scores).unwrap_or_default());
                    }
                    _ => {
                        crate::cia::print_summary(&cia_scores, &findings, &pack);
                    }
                    Format::Sarif => {}
                }
            }

            let fail_hit = match fail_on {
                Some(min) => findings.iter().any(|f| f.severity >= min),
                None      => false,
            };
            Ok(ExitCode::from(if fail_hit { 1 } else { 0 }))
        }

        Cmd::Baseline { target, rules, output } => {
            let pack = load_pack(rules.as_deref())?;
            let findings = scanner::run(&target, &pack)?;
            let fingerprints: std::collections::BTreeSet<String> = findings.into_iter()
                .map(|f| f.fingerprint)
                .collect();
            
            let json = serde_json::to_string_pretty(&fingerprints)?;
            std::fs::write(&output, json)
                .with_context(|| format!("writing baseline to {}", output.display()))?;
            
            eprintln!("✓ Baseline created with {} unique finding(s) in {}", fingerprints.len(), output.display());
            Ok(ExitCode::from(0))
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

        Cmd::K8s { kubeconfig, namespace, report, format, scan_images, rules, fail_on } => {
            print_banner();
            let pack = load_pack(rules.as_deref())?;
            let opts = k8s::K8sOptions {
                kubeconfig,
                namespace,
                scan_images,
            };
            let k8s_report = k8s::run(&pack, &opts)?;

            match report {
                K8sReportMode::Summary => k8s::summary::print_summary(&k8s_report),
                K8sReportMode::Full => match format {
                    Format::Text  => k8s::summary::print_full(&k8s_report),
                    Format::Json  => output::json::emit(&k8s_report.all_findings)?,
                    Format::Sarif => output::sarif::emit(&k8s_report.all_findings)?,
                },
            }

            let fail_hit = match fail_on {
                Some(min) => k8s_report.all_findings.iter().any(|f| f.severity >= min),
                None      => false,
            };
            Ok(ExitCode::from(if fail_hit { 1 } else { 0 }))
        }

        Cmd::App { target, format, fail_below } => {
            print_banner();
            let report = crate::appscan::scan(&target)?;

            match format {
                Format::Json => {
                    println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
                }
                _ => {
                    let icon = if report.score >= 80 { "\x1b[32mGOOD\x1b[0m" }
                        else if report.score >= 50 { "\x1b[33mFAIR\x1b[0m" }
                        else { "\x1b[31mPOOR\x1b[0m" };

                    println!();
                    println!("  App: {} ({})", report.app_name, report.app_type);
                    println!("  Bundle ID: {}", report.bundle_id);
                    println!("  Version: {}", report.version);
                    if !report.frameworks.is_empty() {
                        println!("  Frameworks: {}", report.frameworks.len());
                    }
                    println!();
                    println!("  Security Score: {}/100 [{}]", report.score, icon);
                    println!("  Passed: {}  Failed: {}  Total: {}", report.passed, report.failed, report.passed + report.failed);
                    println!();

                    for f in &report.findings {
                        let status = if f.passed {
                            "\x1b[32m PASS \x1b[0m"
                        } else {
                            match f.severity.as_str() {
                                "critical" => "\x1b[31m FAIL \x1b[0m",
                                "high"     => "\x1b[33m FAIL \x1b[0m",
                                _          => "\x1b[36m FAIL \x1b[0m",
                            }
                        };
                        let sev = match f.severity.as_str() {
                            "critical" => "CRIT", "high" => "HIGH", "medium" => "MED ", "low" => "LOW ", _ => "INFO",
                        };
                        println!("  [{}] [{}] {}", status, sev, f.check);
                        if !f.passed {
                            println!("           {}", f.detail);
                            if !f.remediation.is_empty() {
                                println!("           \x1b[2m{}\x1b[0m", f.remediation);
                            }
                        }
                    }

                    if !report.entitlements.is_empty() {
                        println!();
                        println!("  Entitlements ({}):", report.entitlements.len());
                        for ent in &report.entitlements {
                            println!("    {}", ent);
                        }
                    }

                    if !report.frameworks.is_empty() {
                        println!();
                        println!("  Embedded Frameworks ({}):", report.frameworks.len());
                        for fw in &report.frameworks {
                            println!("    {}", fw);
                        }
                    }
                    println!();
                }
                Format::Sarif => {
                    println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
                }
            }

            let fail_hit = match fail_below {
                Some(threshold) => report.score < threshold,
                None => false,
            };
            Ok(ExitCode::from(if fail_hit { 1 } else { 0 }))
        }

        Cmd::Endpoint { format, fail_below } => {
            print_banner();
            let report = crate::endpoint::scan();

            match format {
                Format::Json => {
                    println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
                }
                _ => {
                    let icon = if report.score >= 80 { "\x1b[32mGOOD\x1b[0m" }
                        else if report.score >= 50 { "\x1b[33mFAIR\x1b[0m" }
                        else { "\x1b[31mPOOR\x1b[0m" };

                    println!();
                    println!("  Endpoint: {} ({})", report.hostname, report.os);
                    println!("  OS Version: {}", report.os_version);
                    println!();
                    println!("  Security Score: {}/100 [{}]", report.score, icon);
                    println!("  Passed: {}  Failed: {}  Total: {}", report.passed, report.failed, report.total);
                    println!();

                    for check in &report.checks {
                        let status = if check.passed {
                            "\x1b[32m PASS \x1b[0m"
                        } else {
                            match check.severity.as_str() {
                                "critical" => "\x1b[31m FAIL \x1b[0m",
                                "high"     => "\x1b[33m FAIL \x1b[0m",
                                _          => "\x1b[36m FAIL \x1b[0m",
                            }
                        };
                        let sev = match check.severity.as_str() {
                            "critical" => "CRIT",
                            "high" => "HIGH",
                            "medium" => "MED ",
                            "low" => "LOW ",
                            _ => "INFO",
                        };
                        println!("  [{}] [{}] {}", status, sev, check.name);
                        if !check.passed {
                            println!("           {}", check.detail);
                            println!("           \x1b[2m{}\x1b[0m", check.remediation);
                        }
                    }
                    println!();
                }
                Format::Sarif => {
                    // Convert to findings for SARIF output
                    println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
                }
            }

            let fail_hit = match fail_below {
                Some(threshold) => report.score < threshold,
                None => false,
            };
            Ok(ExitCode::from(if fail_hit { 1 } else { 0 }))
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

fn collect_cloud_context(target: &std::path::Path) -> scanner::CloudContext {
    let mut ctx = scanner::CloudContext::default();
    
    // Quick heuristic scan of manifests in the same repo
    let walker = ignore::WalkBuilder::new(target)
        .standard_filters(true)
        .build();

    for entry in walker.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() {
            let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
            if ext == "yaml" || ext == "yml" || ext == "json" {
                if let Ok(content) = std::fs::read_to_string(path) {
                    if content.contains("privileged: true") {
                        ctx.privileged_pods.insert(path.to_string_lossy().into());
                    }
                    if content.contains("hostNetwork: true") {
                        ctx.host_networks.insert(path.to_string_lossy().into());
                    }
                    
                    // Resource Extraction (Heuristic for S3/Storage)
                    // Matches strings like bucket: "my-data" or name: "my-bucket" in public contexts
                    if content.contains("public") || content.contains("allUsers") || content.contains("0.0.0.0") {
                        for line in content.lines() {
                            if line.contains("bucket") || line.contains("name") {
                                if let Some(name) = line.split(':').nth(1) {
                                    let clean_name = name.trim().trim_matches('"').trim_matches('\'').to_string();
                                    if clean_name.len() > 3 {
                                        ctx.public_resources.insert(clean_name, path.to_string_lossy().into());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    ctx
}
