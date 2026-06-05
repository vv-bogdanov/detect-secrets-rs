//! Native Rust API for `detect-secrets-rs`.
//!
//! The current crate is a performance POC. It exposes the same scan pipeline
//! used by the `detect-secrets-rs` binary so compatibility harnesses and tests
//! can run without spawning a process.

mod app;
mod baseline;
mod cli;
mod detectors;
mod files;
mod scan;

pub use app::{ScanOutcome, run_cli_args, run_current_process};
pub use baseline::{Baseline, Finding};
pub use cli::{Cli, Command, ScanArgs, ScanOptions};
pub use detectors::PLUGIN_NAMES;
pub use files::SourceFile;
pub use scan::{ScanResult, scan};
