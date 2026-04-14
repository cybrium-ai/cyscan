//! CLI command tree.

use std::{path::PathBuf, process::ExitCode};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use crate::{finding::Severity, output, rule::RulePack, scanner};

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

    /// Inspect the configured rule pack.
    Rules {
        #[command(subcommand)]
        cmd: RulesCmd,
    },
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

pub fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
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
    }
}

fn load_pack(path: Option<&std::path::Path>) -> Result<RulePack> {
    let path = path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| bundled_rules_path());
    RulePack::load_dir(&path).with_context(|| format!("loading rules from {}", path.display()))
}

/// Best-effort resolution of the bundled rules directory. Looks at:
///   1. `$CYSCAN_RULES` env var
///   2. `rules/` next to the binary (expected in CI-built archives)
///   3. `rules/` next to Cargo.toml (dev mode)
fn bundled_rules_path() -> PathBuf {
    if let Ok(p) = std::env::var("CYSCAN_RULES") {
        return PathBuf::from(p);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("rules");
            if candidate.exists() {
                return candidate;
            }
        }
    }
    // dev mode — workspace-relative
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rules")
}
