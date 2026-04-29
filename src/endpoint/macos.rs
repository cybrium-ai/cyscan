//! macOS-specific endpoint security checks.
//!
//! All checks use native macOS commands — no MDM required.
//! Runs as the current user; some checks may need sudo for full results.

use super::{EndpointCheck, cmd_output, cmd_contains};

pub fn run_checks() -> Vec<EndpointCheck> {
    vec![
        check_filevault(),
        check_gatekeeper(),
        check_sip(),
        check_firewall(),
        check_auto_update(),
        check_auto_download(),
        check_screen_lock(),
        check_screen_lock_delay(),
        check_remote_login(),
        check_remote_management(),
        check_file_sharing(),
        check_screen_sharing(),
        check_airdrop(),
        check_os_currency(),
        check_xprotect(),
        check_find_my_mac(),
        check_guest_account(),
        check_password_hints(),
        check_safari_autofill(),
        check_bluetooth_sharing(),
        check_internet_sharing(),
        check_content_caching(),
        check_unsigned_kexts(),
    ]
}

fn check_filevault() -> EndpointCheck {
    let output = cmd_output("fdesetup", &["status"]);
    let enabled = output.contains("On");
    EndpointCheck {
        name: "FileVault Disk Encryption".into(),
        category: "encryption".into(),
        passed: enabled,
        severity: "critical".into(),
        detail: if enabled {
            "FileVault is enabled — disk is encrypted at rest".into()
        } else {
            "FileVault is NOT enabled — disk is unencrypted".into()
        },
        remediation: "Enable FileVault: System Settings > Privacy & Security > FileVault > Turn On".into(),
    }
}

fn check_gatekeeper() -> EndpointCheck {
    let output = cmd_output("spctl", &["--status"]);
    let enabled = output.contains("enabled") || output.contains("assessments enabled");
    EndpointCheck {
        name: "Gatekeeper".into(),
        category: "malware".into(),
        passed: enabled,
        severity: "critical".into(),
        detail: if enabled {
            "Gatekeeper is enabled — only signed apps can run".into()
        } else {
            "Gatekeeper is DISABLED — unsigned apps can run".into()
        },
        remediation: "Enable Gatekeeper: sudo spctl --master-enable".into(),
    }
}

fn check_sip() -> EndpointCheck {
    let output = cmd_output("csrutil", &["status"]);
    let enabled = output.contains("enabled");
    EndpointCheck {
        name: "System Integrity Protection (SIP)".into(),
        category: "system".into(),
        passed: enabled,
        severity: "critical".into(),
        detail: if enabled {
            "SIP is enabled — system files are protected".into()
        } else {
            "SIP is DISABLED — system files can be modified".into()
        },
        remediation: "Enable SIP: boot into Recovery Mode (Cmd+R), open Terminal, run: csrutil enable".into(),
    }
}

fn check_firewall() -> EndpointCheck {
    let output = cmd_output(
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        &["--getglobalstate"],
    );
    let enabled = output.contains("enabled") || output.contains("1");
    EndpointCheck {
        name: "macOS Firewall".into(),
        category: "network".into(),
        passed: enabled,
        severity: "high".into(),
        detail: if enabled {
            "Firewall is enabled".into()
        } else {
            "Firewall is DISABLED — all inbound connections are allowed".into()
        },
        remediation: "Enable Firewall: System Settings > Network > Firewall > Turn On".into(),
    }
}

fn check_auto_update() -> EndpointCheck {
    let output = cmd_output(
        "defaults",
        &["read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"],
    );
    let enabled = output.trim() == "1";
    EndpointCheck {
        name: "Automatic Update Check".into(),
        category: "updates".into(),
        passed: enabled,
        severity: "high".into(),
        detail: if enabled {
            "Automatic update checking is enabled".into()
        } else {
            "Automatic update checking is DISABLED".into()
        },
        remediation: "Enable: System Settings > General > Software Update > Automatic Updates".into(),
    }
}

fn check_auto_download() -> EndpointCheck {
    let output = cmd_output(
        "defaults",
        &["read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticDownload"],
    );
    let enabled = output.trim() == "1";
    EndpointCheck {
        name: "Automatic Update Download".into(),
        category: "updates".into(),
        passed: enabled,
        severity: "medium".into(),
        detail: if enabled {
            "Updates are downloaded automatically".into()
        } else {
            "Updates are NOT downloaded automatically".into()
        },
        remediation: "Enable: System Settings > General > Software Update > Download new updates when available".into(),
    }
}

fn check_screen_lock() -> EndpointCheck {
    let output = cmd_output(
        "defaults",
        &["read", "com.apple.screensaver", "askForPassword"],
    );
    let enabled = output.trim() == "1";
    EndpointCheck {
        name: "Screen Lock Password".into(),
        category: "access".into(),
        passed: enabled,
        severity: "high".into(),
        detail: if enabled {
            "Password is required after screen lock".into()
        } else {
            "NO password required after screen lock".into()
        },
        remediation: "Enable: System Settings > Lock Screen > Require password after screen saver begins".into(),
    }
}

fn check_screen_lock_delay() -> EndpointCheck {
    let output = cmd_output(
        "defaults",
        &["read", "com.apple.screensaver", "askForPasswordDelay"],
    );
    let delay: u64 = output.trim().parse().unwrap_or(999);
    let passed = delay <= 5; // 5 seconds or less
    EndpointCheck {
        name: "Screen Lock Delay".into(),
        category: "access".into(),
        passed,
        severity: "medium".into(),
        detail: if passed {
            format!("Screen lock password delay: {} seconds", delay)
        } else {
            format!("Screen lock password delay is {} seconds — should be 5 or less", delay)
        },
        remediation: "Set to Immediately: System Settings > Lock Screen > Require password immediately".into(),
    }
}

fn check_remote_login() -> EndpointCheck {
    let output = cmd_output("systemsetup", &["-getremotelogin"]);
    let disabled = output.contains("Off") || output.contains("off");
    EndpointCheck {
        name: "Remote Login (SSH)".into(),
        category: "network".into(),
        passed: disabled,
        severity: "high".into(),
        detail: if disabled {
            "Remote Login (SSH) is disabled".into()
        } else {
            "Remote Login (SSH) is ENABLED — remote access is possible".into()
        },
        remediation: "Disable: System Settings > General > Sharing > Remote Login > Off".into(),
    }
}

fn check_remote_management() -> EndpointCheck {
    // Check if ARD agent is running
    let output = cmd_output("ps", &["aux"]);
    let running = output.contains("ARDAgent");
    EndpointCheck {
        name: "Remote Management (ARD)".into(),
        category: "network".into(),
        passed: !running,
        severity: "medium".into(),
        detail: if running {
            "Remote Management (ARD) is RUNNING".into()
        } else {
            "Remote Management is not running".into()
        },
        remediation: "Disable: System Settings > General > Sharing > Remote Management > Off".into(),
    }
}

fn check_file_sharing() -> EndpointCheck {
    let output = cmd_output("launchctl", &["list"]);
    let running = output.contains("com.apple.smbd");
    EndpointCheck {
        name: "File Sharing (SMB)".into(),
        category: "network".into(),
        passed: !running,
        severity: "medium".into(),
        detail: if running {
            "File Sharing (SMB) is ENABLED".into()
        } else {
            "File Sharing is disabled".into()
        },
        remediation: "Disable: System Settings > General > Sharing > File Sharing > Off".into(),
    }
}

fn check_screen_sharing() -> EndpointCheck {
    let output = cmd_output("launchctl", &["list"]);
    let running = output.contains("com.apple.screensharing");
    EndpointCheck {
        name: "Screen Sharing".into(),
        category: "network".into(),
        passed: !running,
        severity: "medium".into(),
        detail: if running {
            "Screen Sharing is ENABLED".into()
        } else {
            "Screen Sharing is disabled".into()
        },
        remediation: "Disable: System Settings > General > Sharing > Screen Sharing > Off".into(),
    }
}

fn check_airdrop() -> EndpointCheck {
    let output = cmd_output(
        "defaults",
        &["read", "com.apple.NetworkBrowser", "DisableAirDrop"],
    );
    let disabled = output.trim() == "1";
    // AirDrop being enabled is low severity — convenient feature
    EndpointCheck {
        name: "AirDrop".into(),
        category: "network".into(),
        passed: disabled,
        severity: "low".into(),
        detail: if disabled {
            "AirDrop is disabled".into()
        } else {
            "AirDrop is enabled (can receive files from nearby devices)".into()
        },
        remediation: "Disable via: defaults write com.apple.NetworkBrowser DisableAirDrop -bool true".into(),
    }
}

fn check_os_currency() -> EndpointCheck {
    let current = cmd_output("sw_vers", &["-productVersion"]);
    // Check available updates
    let updates = cmd_output("softwareupdate", &["-l", "--no-scan"]);
    let has_updates = updates.contains("Software Update found") || updates.contains("Label:");
    EndpointCheck {
        name: "OS Version Currency".into(),
        category: "updates".into(),
        passed: !has_updates,
        severity: "high".into(),
        detail: if has_updates {
            format!("macOS {} — updates available", current)
        } else {
            format!("macOS {} — up to date", current)
        },
        remediation: "Update: System Settings > General > Software Update".into(),
    }
}

fn check_xprotect() -> EndpointCheck {
    // Check XProtect is active
    let output = cmd_output("system_profiler", &["SPInstallHistoryDataType"]);
    let has_xprotect = output.contains("XProtect");
    EndpointCheck {
        name: "XProtect (Malware Definitions)".into(),
        category: "malware".into(),
        passed: has_xprotect,
        severity: "high".into(),
        detail: if has_xprotect {
            "XProtect malware definitions are installed".into()
        } else {
            "XProtect status could not be verified".into()
        },
        remediation: "XProtect updates automatically — ensure automatic updates are enabled".into(),
    }
}

fn check_find_my_mac() -> EndpointCheck {
    let output = cmd_output(
        "defaults",
        &["read", "com.apple.FindMyMac", "FMMEnabled"],
    );
    let enabled = output.trim() == "1";
    EndpointCheck {
        name: "Find My Mac".into(),
        category: "theft".into(),
        passed: enabled,
        severity: "medium".into(),
        detail: if enabled {
            "Find My Mac is enabled".into()
        } else {
            "Find My Mac is DISABLED — cannot locate or wipe if stolen".into()
        },
        remediation: "Enable: System Settings > Apple ID > iCloud > Find My Mac".into(),
    }
}

fn check_guest_account() -> EndpointCheck {
    let output = cmd_output(
        "defaults",
        &["read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"],
    );
    let disabled = output.trim() == "0" || output.contains("does not exist");
    EndpointCheck {
        name: "Guest Account".into(),
        category: "access".into(),
        passed: disabled,
        severity: "medium".into(),
        detail: if disabled {
            "Guest account is disabled".into()
        } else {
            "Guest account is ENABLED — anyone can use this Mac".into()
        },
        remediation: "Disable: System Settings > Users & Groups > Guest User > Off".into(),
    }
}

fn check_password_hints() -> EndpointCheck {
    let output = cmd_output(
        "defaults",
        &["read", "/Library/Preferences/com.apple.loginwindow", "RetriesUntilHint"],
    );
    let disabled = output.trim() == "0" || output.contains("does not exist");
    EndpointCheck {
        name: "Login Password Hints".into(),
        category: "access".into(),
        passed: disabled,
        severity: "low".into(),
        detail: if disabled {
            "Password hints are disabled at login".into()
        } else {
            "Password hints are shown at login — could aid attackers".into()
        },
        remediation: "Disable: sudo defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0".into(),
    }
}

fn check_safari_autofill() -> EndpointCheck {
    let output = cmd_output(
        "defaults",
        &["read", "com.apple.Safari", "AutoFillPasswords"],
    );
    let disabled = output.trim() == "0";
    EndpointCheck {
        name: "Safari Password AutoFill".into(),
        category: "browser".into(),
        passed: disabled,
        severity: "low".into(),
        detail: if disabled {
            "Safari password autofill is disabled".into()
        } else {
            "Safari password autofill is enabled — use a password manager instead".into()
        },
        remediation: "Disable: Safari > Settings > AutoFill > User names and passwords".into(),
    }
}

fn check_bluetooth_sharing() -> EndpointCheck {
    let output = cmd_output("defaults", &["-currentHost", "read", "com.apple.Bluetooth", "PrefKeyServicesEnabled"]);
    let disabled = output.trim() == "0" || output.contains("does not exist");
    EndpointCheck {
        name: "Bluetooth Sharing".into(),
        category: "network".into(),
        passed: disabled,
        severity: "medium".into(),
        detail: if disabled {
            "Bluetooth sharing is disabled".into()
        } else {
            "Bluetooth sharing is ENABLED — files can be received via Bluetooth".into()
        },
        remediation: "Disable: System Settings > General > Sharing > Bluetooth Sharing > Off".into(),
    }
}

fn check_internet_sharing() -> EndpointCheck {
    let output = cmd_output(
        "defaults",
        &["read", "/Library/Preferences/SystemConfiguration/com.apple.nat", "NAT"],
    );
    let disabled = !output.contains("Enabled = 1");
    EndpointCheck {
        name: "Internet Sharing".into(),
        category: "network".into(),
        passed: disabled,
        severity: "high".into(),
        detail: if disabled {
            "Internet sharing is disabled".into()
        } else {
            "Internet sharing is ENABLED — this Mac is acting as a router".into()
        },
        remediation: "Disable: System Settings > General > Sharing > Internet Sharing > Off".into(),
    }
}

fn check_content_caching() -> EndpointCheck {
    let output = cmd_output("AssetCacheLocatorUtil", &[]);
    let active = output.contains("guid");
    EndpointCheck {
        name: "Content Caching".into(),
        category: "network".into(),
        passed: !active,
        severity: "low".into(),
        detail: if active {
            "Content caching is active — this Mac caches Apple content for the network".into()
        } else {
            "Content caching is not active".into()
        },
        remediation: "Disable: System Settings > General > Sharing > Content Caching > Off".into(),
    }
}

fn check_unsigned_kexts() -> EndpointCheck {
    let output = cmd_output("kextstat", &[]);
    let unsigned: Vec<&str> = output.lines()
        .filter(|l| !l.contains("com.apple.") && !l.contains("Index"))
        .collect();
    let passed = unsigned.is_empty();
    EndpointCheck {
        name: "Unsigned Kernel Extensions".into(),
        category: "system".into(),
        passed,
        severity: "high".into(),
        detail: if passed {
            "No unsigned kernel extensions loaded".into()
        } else {
            format!("{} non-Apple kernel extension(s) loaded: {}",
                unsigned.len(),
                unsigned.iter().take(3).map(|l| l.trim()).collect::<Vec<_>>().join(", "))
        },
        remediation: "Review loaded kexts with: kextstat | grep -v com.apple".into(),
    }
}
