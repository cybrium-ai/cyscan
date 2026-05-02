//! Cybrium Scan library crate.
//!
//! Structured so both the `cyscan` binary and future library consumers
//! (tests, a platform sidecar wrapping this in a service) import the
//! same modules. The binary at `src/main.rs` is a ~10-line wrapper.

pub mod appscan;
pub mod cia;
pub mod cli;
pub mod endpoint;
pub mod finding;
pub mod fixer;
pub mod framework;
pub mod k8s;
pub mod lang;
pub mod matcher;
pub mod output;
pub mod reachability;
pub mod rule;
pub mod scanner;
pub mod self_update;
pub mod supply;
pub mod triage;
