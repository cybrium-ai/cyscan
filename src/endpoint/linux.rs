//! Linux-specific endpoint security checks.

use super::{EndpointCheck, cmd_output, cmd_contains};

pub fn run_checks() -> Vec<EndpointCheck> {
    vec![
        check_disk_encryption(),
        check_firewall(),
        check_selinux(),
        check_unattended_upgrades(),
        check_ssh_root_login(),
        check_ssh_password_auth(),
        check_ssh_port(),
        check_suid_binaries(),
        check_failed_logins(),
        check_kernel_hardening(),
        check_core_dumps(),
        check_auditd(),
    ]
}

fn check_disk_encryption() -> EndpointCheck {
    let output = cmd_output("lsblk", &["-o", "NAME,TYPE,MOUNTPOINT,FSTYPE"]);
    let has_luks = output.contains("crypto_LUKS") || output.contains("crypt");
    EndpointCheck {
        name: "Disk Encryption (LUKS)".into(),
        category: "encryption".into(),
        passed: has_luks,
        severity: "critical".into(),
        detail: if has_luks {
            "LUKS disk encryption detected".into()
        } else {
            "No disk encryption detected".into()
        },
        remediation: "Encrypt the disk during OS installation or use cryptsetup".into(),
    }
}

fn check_firewall() -> EndpointCheck {
    // Check ufw first, then iptables
    let ufw = cmd_output("ufw", &["status"]);
    if ufw.contains("active") {
        return EndpointCheck {
            name: "Firewall (UFW)".into(),
            category: "network".into(),
            passed: true,
            severity: "high".into(),
            detail: "UFW firewall is active".into(),
            remediation: "".into(),
        };
    }

    let iptables = cmd_output("iptables", &["-L", "-n"]);
    let has_rules = iptables.lines().count() > 8; // more than default empty chains
    EndpointCheck {
        name: "Firewall (iptables/nftables)".into(),
        category: "network".into(),
        passed: has_rules,
        severity: "high".into(),
        detail: if has_rules {
            "iptables has active rules".into()
        } else {
            "No firewall rules configured".into()
        },
        remediation: "Enable UFW: sudo ufw enable".into(),
    }
}

fn check_selinux() -> EndpointCheck {
    let getenforce = cmd_output("getenforce", &[]);
    if !getenforce.is_empty() {
        let enforcing = getenforce.contains("Enforcing");
        return EndpointCheck {
            name: "SELinux".into(),
            category: "system".into(),
            passed: enforcing,
            severity: "high".into(),
            detail: format!("SELinux status: {}", getenforce),
            remediation: "Enable: sudo setenforce 1 and set SELINUX=enforcing in /etc/selinux/config".into(),
        };
    }

    // Check AppArmor
    let aa_status = cmd_output("aa-status", &[]);
    let active = aa_status.contains("profiles are loaded");
    EndpointCheck {
        name: "AppArmor".into(),
        category: "system".into(),
        passed: active,
        severity: "high".into(),
        detail: if active {
            "AppArmor is active".into()
        } else {
            "Neither SELinux nor AppArmor is active".into()
        },
        remediation: "Install and enable AppArmor or SELinux".into(),
    }
}

fn check_unattended_upgrades() -> EndpointCheck {
    let exists = std::path::Path::new("/etc/apt/apt.conf.d/20auto-upgrades").exists()
        || std::path::Path::new("/etc/dnf/automatic.conf").exists();
    EndpointCheck {
        name: "Automatic Security Updates".into(),
        category: "updates".into(),
        passed: exists,
        severity: "high".into(),
        detail: if exists {
            "Unattended upgrades are configured".into()
        } else {
            "Automatic security updates are NOT configured".into()
        },
        remediation: "Install: sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades".into(),
    }
}

fn check_ssh_root_login() -> EndpointCheck {
    let sshd_config = std::fs::read_to_string("/etc/ssh/sshd_config").unwrap_or_default();
    let permits_root = sshd_config.lines()
        .filter(|l| !l.trim().starts_with('#'))
        .any(|l| l.contains("PermitRootLogin") && (l.contains("yes") || l.contains("without-password")));
    EndpointCheck {
        name: "SSH Root Login".into(),
        category: "access".into(),
        passed: !permits_root,
        severity: "critical".into(),
        detail: if permits_root {
            "SSH root login is PERMITTED".into()
        } else {
            "SSH root login is disabled".into()
        },
        remediation: "Set PermitRootLogin no in /etc/ssh/sshd_config".into(),
    }
}

fn check_ssh_password_auth() -> EndpointCheck {
    let sshd_config = std::fs::read_to_string("/etc/ssh/sshd_config").unwrap_or_default();
    let allows_password = sshd_config.lines()
        .filter(|l| !l.trim().starts_with('#'))
        .any(|l| l.contains("PasswordAuthentication") && l.contains("yes"));
    EndpointCheck {
        name: "SSH Password Authentication".into(),
        category: "access".into(),
        passed: !allows_password,
        severity: "high".into(),
        detail: if allows_password {
            "SSH password authentication is ENABLED — use key-based auth".into()
        } else {
            "SSH password authentication is disabled (key-based only)".into()
        },
        remediation: "Set PasswordAuthentication no in /etc/ssh/sshd_config".into(),
    }
}

fn check_ssh_port() -> EndpointCheck {
    let sshd_config = std::fs::read_to_string("/etc/ssh/sshd_config").unwrap_or_default();
    let uses_default = !sshd_config.lines()
        .filter(|l| !l.trim().starts_with('#'))
        .any(|l| l.starts_with("Port") && !l.contains("22"));
    EndpointCheck {
        name: "SSH Port".into(),
        category: "network".into(),
        passed: !uses_default,
        severity: "low".into(),
        detail: if uses_default {
            "SSH runs on default port 22".into()
        } else {
            "SSH runs on a non-default port".into()
        },
        remediation: "Consider changing SSH port in /etc/ssh/sshd_config (security through obscurity, low value)".into(),
    }
}

fn check_suid_binaries() -> EndpointCheck {
    let output = cmd_output("find", &["/usr", "/bin", "/sbin", "-perm", "-4000", "-type", "f"]);
    let count = output.lines().filter(|l| !l.is_empty()).count();
    let passed = count < 30; // typical systems have 15-25 SUID binaries
    EndpointCheck {
        name: "SUID Binaries".into(),
        category: "system".into(),
        passed,
        severity: "medium".into(),
        detail: format!("{} SUID binaries found (typical: 15-25)", count),
        remediation: "Audit SUID binaries: find / -perm -4000 -type f 2>/dev/null and remove unnecessary ones".into(),
    }
}

fn check_failed_logins() -> EndpointCheck {
    let output = cmd_output("lastb", &["-n", "100"]);
    let count = output.lines().filter(|l| !l.trim().is_empty() && !l.contains("btmp")).count();
    let passed = count < 50;
    EndpointCheck {
        name: "Failed Login Attempts".into(),
        category: "access".into(),
        passed,
        severity: if count > 100 { "high" } else { "medium" }.into(),
        detail: format!("{} failed login attempts in recent history", count),
        remediation: "Install fail2ban: sudo apt install fail2ban".into(),
    }
}

fn check_kernel_hardening() -> EndpointCheck {
    let aslr = std::fs::read_to_string("/proc/sys/kernel/randomize_va_space")
        .unwrap_or_default().trim().to_string();
    let passed = aslr == "2"; // full ASLR
    EndpointCheck {
        name: "Kernel ASLR".into(),
        category: "system".into(),
        passed,
        severity: "high".into(),
        detail: if passed {
            "Full ASLR enabled (randomize_va_space = 2)".into()
        } else {
            format!("ASLR is not fully enabled (randomize_va_space = {})", aslr)
        },
        remediation: "Enable: echo 2 | sudo tee /proc/sys/kernel/randomize_va_space".into(),
    }
}

fn check_core_dumps() -> EndpointCheck {
    let output = cmd_output("ulimit", &["-c"]);
    let disabled = output.trim() == "0";
    EndpointCheck {
        name: "Core Dumps".into(),
        category: "system".into(),
        passed: disabled,
        severity: "medium".into(),
        detail: if disabled {
            "Core dumps are disabled".into()
        } else {
            "Core dumps are ENABLED — may leak sensitive memory contents".into()
        },
        remediation: "Disable: add '* hard core 0' to /etc/security/limits.conf".into(),
    }
}

fn check_auditd() -> EndpointCheck {
    let output = cmd_output("systemctl", &["is-active", "auditd"]);
    let active = output.trim() == "active";
    EndpointCheck {
        name: "Audit Daemon (auditd)".into(),
        category: "logging".into(),
        passed: active,
        severity: "high".into(),
        detail: if active {
            "auditd is running".into()
        } else {
            "auditd is NOT running — system calls are not being audited".into()
        },
        remediation: "Enable: sudo systemctl enable --now auditd".into(),
    }
}
