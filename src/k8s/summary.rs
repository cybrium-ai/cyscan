//! Summary table formatter — replicates the `trivy k8s --report summary` output.

use super::{K8sReport, ResourceReport, SeverityCounts};

/// Print the summary report (Trivy-style table).
pub fn print_summary(report: &K8sReport) {
    println!();
    println!("\x1b[1;4mSummary Report for {}\x1b[0m", report.cluster_name);
    println!();

    if !report.workloads.is_empty() {
        println!("\x1b[1mWorkload Assessment\x1b[0m");
        println!();
        print_table(&report.workloads);
        println!();
    }

    if !report.infra.is_empty() {
        println!("\x1b[1mInfra Assessment\x1b[0m");
        println!();
        print_table(&report.infra);
        println!();
    }

    if report.workloads.is_empty() && report.infra.is_empty() {
        println!("  No issues found.");
        println!();
    }

    // Stats line
    let total_vulns: usize = report.workloads.iter().chain(report.infra.iter())
        .map(|r| r.vulns.total()).sum();
    let total_misconfigs: usize = report.workloads.iter().chain(report.infra.iter())
        .map(|r| r.misconfigs.total()).sum();
    let total_secrets: usize = report.workloads.iter().chain(report.infra.iter())
        .map(|r| r.secrets.total()).sum();

    println!("Totals: {} vulnerabilities, {} misconfigurations, {} secrets",
        total_vulns, total_misconfigs, total_secrets);

    if report.images_scanned > 0 {
        println!("Images scanned: {}, image vulnerabilities: {}",
            report.images_scanned, report.image_vulns);
    }

    println!();
    println!("Severities: \x1b[31mC\x1b[0m=CRITICAL \x1b[33mH\x1b[0m=HIGH \x1b[36mM\x1b[0m=MEDIUM \x1b[34mL\x1b[0m=LOW \x1b[37mU\x1b[0m=UNKNOWN");
    println!();
}

fn print_table(resources: &[ResourceReport]) {
    // Column widths
    let ns_w = resources.iter().map(|r| r.namespace.len()).max().unwrap_or(9).max(9);
    let res_w = resources.iter()
        .map(|r| format!("{}/{}", r.kind, r.name).len())
        .max().unwrap_or(8).max(8);

    // Header
    let sep_ns = "─".repeat(ns_w + 2);
    let sep_res = "─".repeat(res_w + 2);
    let sep_5 = "─────";
    println!("┌{}┬{}┬─────────────────────────────┬─────────────────────────────┬─────────────────────────────┐",
        sep_ns, sep_res);
    println!("│ {:<ns_w$} │ {:<res_w$} │      Vulnerabilities        │     Misconfigurations       │          Secrets            │",
        "Namespace", "Resource", ns_w = ns_w, res_w = res_w);
    println!("│ {:<ns_w$} │ {:<res_w$} │─────┬─────┬─────┬─────┬─────│─────┬─────┬─────┬─────┬─────│─────┬─────┬─────┬─────┬─────│",
        "", "", ns_w = ns_w, res_w = res_w);
    println!("│ {:<ns_w$} │ {:<res_w$} │  C  │  H  │  M  │  L  │  U  │  C  │  H  │  M  │  L  │  U  │  C  │  H  │  M  │  L  │  U  │",
        "", "", ns_w = ns_w, res_w = res_w);
    println!("├{}┼{}┼─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┤",
        sep_ns, sep_res);

    for res in resources {
        let resource_str = format!("{}/{}", res.kind, res.name);
        println!(
            "│ {:<ns_w$} │ {:<res_w$} │{}│{}│{}│{}│{}│{}│{}│{}│{}│{}│{}│{}│{}│{}│{}│",
            res.namespace,
            resource_str,
            fmt_cell(res.vulns.critical, "31"),
            fmt_cell(res.vulns.high, "33"),
            fmt_cell(res.vulns.medium, "36"),
            fmt_cell(res.vulns.low, "34"),
            fmt_cell(res.vulns.unknown, "37"),
            fmt_cell(res.misconfigs.critical, "31"),
            fmt_cell(res.misconfigs.high, "33"),
            fmt_cell(res.misconfigs.medium, "36"),
            fmt_cell(res.misconfigs.low, "34"),
            fmt_cell(res.misconfigs.unknown, "37"),
            fmt_cell(res.secrets.critical, "31"),
            fmt_cell(res.secrets.high, "33"),
            fmt_cell(res.secrets.medium, "36"),
            fmt_cell(res.secrets.low, "34"),
            fmt_cell(res.secrets.unknown, "37"),
            ns_w = ns_w,
            res_w = res_w,
        );
    }

    println!("└{}┴{}┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┘",
        sep_ns, sep_res);
}

/// Format a count cell with color. Zero = empty.
fn fmt_cell(count: usize, color: &str) -> String {
    if count == 0 {
        "     ".to_string()
    } else {
        format!("\x1b[{}m{:>4}\x1b[0m ", color, count)
    }
}

/// Print full findings list (non-summary mode).
pub fn print_full(report: &K8sReport) {
    println!();
    println!("\x1b[1;4mCluster Scan Report for {}\x1b[0m", report.cluster_name);
    println!();

    if report.all_findings.is_empty() {
        println!("  No issues found.");
        return;
    }

    for finding in &report.all_findings {
        let sev = match finding.severity {
            crate::finding::Severity::Critical => "\x1b[31mcrit\x1b[0m",
            crate::finding::Severity::High     => "\x1b[33mhigh\x1b[0m",
            crate::finding::Severity::Medium   => "\x1b[36mmed \x1b[0m",
            crate::finding::Severity::Low      => "\x1b[34mlow \x1b[0m",
            crate::finding::Severity::Info     => "\x1b[37minfo\x1b[0m",
        };
        println!("[{}]  {}  {}", sev, finding.rule_id, finding.file.display());
        println!("        {}", finding.title);
        if !finding.snippet.is_empty() {
            println!("        │ {}", finding.snippet);
        }
        println!();
    }

    println!("{} finding(s)", report.all_findings.len());
}
