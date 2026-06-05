use std::ffi::OsString;
use std::io::{self, BufWriter, Write};

use anyhow::Result;
use clap::Parser;

use crate::baseline::Baseline;
use crate::cli::{Cli, Command, ScanOptions};

/// Result of running the native CLI pipeline.
#[derive(Clone, Debug)]
pub struct ScanOutcome {
    /// Baseline-like scan output, if the command produced one.
    pub baseline: Option<Baseline>,
}

/// Run the CLI pipeline from the current process arguments.
pub fn run_current_process() -> Result<ScanOutcome> {
    run_cli(Cli::parse())
}

/// Run the CLI pipeline from upstream-style argv.
///
/// The first argument should be the binary name, matching `std::env::args`.
pub fn run_cli_args<I, T>(args: I) -> Result<ScanOutcome>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    run_cli(Cli::try_parse_from(args)?)
}

fn run_cli(cli: Cli) -> Result<ScanOutcome> {
    match cli.command {
        Command::Scan(args) => {
            if args.list_all_plugins {
                for plugin in crate::detectors::PLUGIN_NAMES {
                    println!("{plugin}");
                }
                return Ok(ScanOutcome { baseline: None });
            }

            let options = ScanOptions::from_args(args);
            let result = crate::scan(&options)?;
            let baseline = Baseline::from_scan_result(result);
            let stdout = io::stdout();
            let mut writer = BufWriter::new(stdout.lock());
            serde_json::to_writer_pretty(&mut writer, &baseline)?;
            writeln!(writer)?;
            Ok(ScanOutcome {
                baseline: Some(baseline),
            })
        }
    }
}
