//! Endpoint security posture scanner — checks the local machine for
//! security configuration issues (encryption, firewall, updates, etc.).
//!
//! Usage:
//!   cyscan endpoint                    # scan this machine
//!   cyscan endpoint --format json      # JSON output
//!   cyscan endpoint --fail-on high     # CI gate

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod linux;

pub mod score;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct EndpointCheck {
    pub name:     String,
    pub category: String,
    pub passed:   bool,
    pub severity: String,   // critical, high, medium, low
    pub detail:   String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EndpointReport {
    pub hostname:  String,
    pub os:        String,
    pub os_version: String,
    pub score:     u32,
    pub checks:    Vec<EndpointCheck>,
    pub passed:    usize,
    pub failed:    usize,
    pub total:     usize,
}

/// Run all endpoint checks for the current platform.
pub fn scan() -> EndpointReport {
    let mut checks = Vec::new();

    #[cfg(target_os = "macos")]
    {
        checks = macos::run_checks();
    }

    #[cfg(target_os = "linux")]
    {
        checks = linux::run_checks();
    }

    let passed = checks.iter().filter(|c| c.passed).count();
    let failed = checks.iter().filter(|c| !c.passed).count();
    let total = checks.len();
    let score_val = score::compute(&checks);

    let hostname = hostname();
    let (os_name, os_ver) = os_info();

    EndpointReport {
        hostname,
        os: os_name,
        os_version: os_ver,
        score: score_val,
        checks,
        passed,
        failed,
        total,
    }
}

fn hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
}

fn os_info() -> (String, String) {
    #[cfg(target_os = "macos")]
    {
        let ver = cmd_output("sw_vers", &["-productVersion"]);
        ("macOS".into(), ver)
    }
    #[cfg(target_os = "linux")]
    {
        let ver = std::fs::read_to_string("/etc/os-release")
            .unwrap_or_default()
            .lines()
            .find(|l| l.starts_with("PRETTY_NAME="))
            .map(|l| l.trim_start_matches("PRETTY_NAME=").trim_matches('"').to_string())
            .unwrap_or_else(|| "Linux".into());
        ("Linux".into(), ver)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        ("Unknown".into(), "Unknown".into())
    }
}

/// Run a command and return trimmed stdout.
pub fn cmd_output(cmd: &str, args: &[&str]) -> String {
    std::process::Command::new(cmd)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

/// Check if a command's stdout contains a substring.
pub fn cmd_contains(cmd: &str, args: &[&str], needle: &str) -> bool {
    cmd_output(cmd, args).contains(needle)
}
