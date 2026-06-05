use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Top-level command-line parser.
#[derive(Debug, Parser)]
#[command(name = "detect-secrets-rs", version, about = "fast detect-secrets POC")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Supported top-level commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scan files and write a deterministic baseline-like JSON document.
    Scan(ScanArgs),
}

/// Raw `scan` command arguments.
#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Paths to scan. Defaults to the current directory.
    #[arg(value_name = "path")]
    pub paths: Vec<PathBuf>,

    /// Scan all files recursively instead of preferring git-tracked files.
    #[arg(long = "all-files")]
    pub all_files: bool,

    /// Exclude files whose path matches this regex. Can be repeated or comma-separated.
    #[arg(long = "exclude-files", value_name = "regex")]
    pub exclude_files: Vec<String>,

    /// Exclude lines whose text matches this regex. Can be repeated or comma-separated.
    #[arg(long = "exclude-lines", value_name = "regex")]
    pub exclude_lines: Vec<String>,

    /// Exclude matched secrets whose raw value matches this regex. Can be repeated or comma-separated.
    #[arg(long = "exclude-secrets", value_name = "regex")]
    pub exclude_secrets: Vec<String>,

    /// Disable a detector by upstream-style plugin name. Can be repeated or comma-separated.
    #[arg(long = "disable-plugin", value_name = "name")]
    pub disable_plugin: Vec<String>,

    /// Accepted for upstream CLI compatibility. The POC does not perform online verification.
    #[arg(short = 'n', long = "no-verify")]
    pub no_verify: bool,

    /// Print all built-in detector names and exit.
    #[arg(long = "list-all-plugins")]
    pub list_all_plugins: bool,
}

/// Normalized scan options used by the library pipeline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanOptions {
    pub paths: Vec<PathBuf>,
    pub all_files: bool,
    pub exclude_files: Vec<String>,
    pub exclude_lines: Vec<String>,
    pub exclude_secrets: Vec<String>,
    pub disabled_plugins: Vec<String>,
    pub no_verify: bool,
}

impl ScanOptions {
    pub fn from_args(args: ScanArgs) -> Self {
        Self {
            paths: default_paths(args.paths),
            all_files: args.all_files,
            exclude_files: split_values(args.exclude_files),
            exclude_lines: split_values(args.exclude_lines),
            exclude_secrets: split_values(args.exclude_secrets),
            disabled_plugins: split_values(args.disable_plugin),
            no_verify: args.no_verify,
        }
    }
}

fn default_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    if paths.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        paths
    }
}

fn split_values(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .flat_map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_path_to_current_directory() {
        let options = ScanOptions::from_args(ScanArgs {
            paths: Vec::new(),
            all_files: false,
            exclude_files: Vec::new(),
            exclude_lines: Vec::new(),
            exclude_secrets: Vec::new(),
            disable_plugin: Vec::new(),
            no_verify: false,
            list_all_plugins: false,
        });

        assert_eq!(options.paths, vec![PathBuf::from(".")]);
    }

    #[test]
    fn splits_repeated_and_comma_values() {
        assert_eq!(
            split_values(vec!["A,B".to_string(), " C ".to_string()]),
            vec!["A", "B", "C"]
        );
    }
}
