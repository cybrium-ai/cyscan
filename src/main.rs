//! `cyscan` — Cybrium Scan engine entry point.
//!
//! Thin binary wrapper. All real work is in the `cyscan` library modules.

use std::process::ExitCode;

fn main() -> ExitCode {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("cyscan=info,warn"),
    )
    .format_timestamp(None)
    .init();

    match cyscan::cli::run() {
        Ok(exit) => exit,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(2)
        }
    }
}
