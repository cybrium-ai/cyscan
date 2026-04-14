//! Cybrium Scan library crate.
//!
//! Structured so both the `cyscan` binary and future library consumers
//! (tests, a platform sidecar wrapping this in a service) import the
//! same modules. The binary at `src/main.rs` is a ~10-line wrapper.

pub mod cli;
pub mod finding;
pub mod lang;
pub mod matcher;
pub mod output;
pub mod rule;
pub mod scanner;
