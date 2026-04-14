//! Compact JSON output — one top-level array of findings, each record
//! already matching the Finding shape declared in `crate::finding`.

use std::io;

use crate::finding::Finding;

pub fn emit(findings: &[Finding]) -> io::Result<()> {
    let out = io::stdout();
    serde_json::to_writer_pretty(out.lock(), findings)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    println!();
    Ok(())
}
