//! Human-readable CLI output. Honours NO_COLOR via the `colored` crate.

use std::io::{self, Write};

use colored::Colorize;

use crate::finding::{Finding, Severity};

pub fn emit(findings: &[Finding]) -> io::Result<()> {
    let mut out = io::stdout().lock();

    if findings.is_empty() {
        writeln!(out, "{}", "No findings.".green())?;
        return Ok(());
    }

    for f in findings {
        let sev = colored_sev(f.severity);
        writeln!(
            out,
            "{sev}  {id}  {file}:{line}:{col}",
            id = f.rule_id.bold(),
            file = f.file.display(),
            line = f.line,
            col = f.column,
        )?;
        writeln!(out, "        {}", f.title)?;
        if let Some(status) = f.evidence.get("triage_status").and_then(|v| v.as_str()) {
            writeln!(out, "        triage: {}", status)?;
        }
        if !f.snippet.is_empty() {
            writeln!(out, "        {} {}", "│".dimmed(), f.snippet.dimmed())?;
        }
        if let Some(fix) = &f.fix_recipe {
            writeln!(out, "        {} {}", "→ fix:".cyan(), fix)?;
        }
        writeln!(out)?;
    }

    writeln!(out, "{} finding(s)", findings.len())?;
    Ok(())
}

fn colored_sev(s: Severity) -> colored::ColoredString {
    match s {
        Severity::Critical => "[crit]".red().bold(),
        Severity::High => "[high]".red(),
        Severity::Medium => "[med ]".yellow(),
        Severity::Low => "[low ]".blue(),
        Severity::Info => "[info]".normal(),
    }
}
