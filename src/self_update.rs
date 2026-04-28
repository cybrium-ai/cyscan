//! Self-update — download latest release from GitHub (sync version).

use anyhow::{bail, Result};

pub fn version(repo: &str) {
    let current = env!("CARGO_PKG_VERSION");
    println!("{} {} — Cybrium AI", env!("CARGO_PKG_NAME"), current);
    println!("https://github.com/{repo}");

    // Quick update check (blocking, 3s timeout)
    let client = reqwest::blocking::Client::builder()
        .user_agent(format!("{}/{current}", env!("CARGO_PKG_NAME")))
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .unwrap();

    if let Ok(resp) = client
        .get(format!("https://api.github.com/repos/{repo}/releases/latest"))
        .header("Accept", "application/vnd.github+json")
        .send()
    {
        if let Ok(data) = resp.json::<serde_json::Value>() {
            let latest = data["tag_name"].as_str().unwrap_or("").trim_start_matches('v');
            if !latest.is_empty() && latest != current {
                println!("\nUpdate available: v{latest} (run: {} update)", env!("CARGO_PKG_NAME"));
            }
        }
    }
}

pub fn update(repo: &str, binary_name: &str) -> Result<()> {
    let current = env!("CARGO_PKG_VERSION");
    eprintln!("Current version: {current}");
    eprintln!("Checking for updates...");

    let client = reqwest::blocking::Client::builder()
        .user_agent(format!("{binary_name}/{current}"))
        .build()?;

    let resp = client
        .get(format!("https://api.github.com/repos/{repo}/releases/latest"))
        .header("Accept", "application/vnd.github+json")
        .send()?;

    if !resp.status().is_success() {
        bail!("Cannot reach GitHub API");
    }

    let data: serde_json::Value = resp.json()?;
    let latest = data["tag_name"].as_str().unwrap_or("unknown").trim_start_matches('v');

    if latest == current {
        eprintln!("Already up to date!");
        return Ok(());
    }

    eprintln!("New version: {current} -> {latest}");

    let asset_name = if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        format!("{binary_name}-darwin-arm64")
    } else if cfg!(target_os = "macos") && cfg!(target_arch = "x86_64") {
        format!("{binary_name}-darwin-amd64")
    } else if cfg!(target_os = "linux") && cfg!(target_arch = "aarch64") {
        format!("{binary_name}-linux-arm64")
    } else {
        format!("{binary_name}-linux-amd64")
    };

    // Also check for tar.gz variants (cyscan releases as .tar.gz)
    let download_url = data["assets"]
        .as_array()
        .and_then(|a| {
            // Try exact name first, then tar.gz
            a.iter()
                .find(|asset| asset["name"].as_str().map_or(false, |n| n == asset_name))
                .or_else(|| a.iter().find(|asset| {
                    asset["name"].as_str().map_or(false, |n| n.contains(&asset_name) || n.contains(binary_name))
                }))
                .and_then(|asset| asset["browser_download_url"].as_str())
        });

    let url = match download_url {
        Some(u) => u,
        None => bail!("No binary found for platform: {asset_name}"),
    };

    eprintln!("Downloading...");
    let resp = client.get(url).send()?;
    let bytes = resp.bytes()?;

    if bytes.is_empty() {
        bail!("Download returned empty");
    }

    let exe_path = std::env::current_exe()?;
    let real_exe = std::fs::canonicalize(&exe_path).unwrap_or(exe_path.clone());
    let backup = real_exe.with_extension("old");

    // Extract binary from tarball if it's a .tar.gz
    let binary_bytes = if &bytes[..2] == b"\x1f\x8b" {
        // gzip compressed — extract the binary from tar.gz
        eprintln!("Extracting from archive...");
        use std::io::Read;
        let decoder = flate2::read::GzDecoder::new(&bytes[..]);
        let mut archive = tar::Archive::new(decoder);
        let mut found = Vec::new();
        for entry in archive.entries()? {
            let mut entry = entry?;
            let path = entry.path()?.to_path_buf();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == binary_name {
                entry.read_to_end(&mut found)?;
                break;
            }
        }
        if found.is_empty() {
            bail!("Binary '{binary_name}' not found in archive");
        }
        found
    } else {
        // Raw binary (no archive wrapper)
        bytes.to_vec()
    };

    std::fs::rename(&real_exe, &backup)?;

    if let Err(e) = std::fs::write(&real_exe, &binary_bytes) {
        std::fs::rename(&backup, &real_exe).ok();
        bail!("Cannot write new binary: {e}");
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&real_exe, std::fs::Permissions::from_mode(0o755)).ok();
    }

    std::fs::remove_file(&backup).ok();
    eprintln!("Updated to v{latest}!");
    Ok(())
}
