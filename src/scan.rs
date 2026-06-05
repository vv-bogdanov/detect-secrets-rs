use std::sync::Arc;

use anyhow::{Context, Result};
use rayon::prelude::*;
use regex::Regex;
use sha1::{Digest, Sha1};

use crate::baseline::Finding;
use crate::cli::ScanOptions;
use crate::detectors::DetectorSet;
use crate::files::SourceFile;

/// Complete scan result before baseline grouping.
#[derive(Clone, Debug)]
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub plugins_used: Vec<String>,
    pub filters_used: Vec<String>,
}

/// Run file discovery, filters, detectors, and deterministic result sorting.
pub fn scan(options: &ScanOptions) -> Result<ScanResult> {
    let filters = CompiledFilters::new(options)?;
    let detectors = DetectorSet::new(&options.disabled_plugins)?;
    let files = crate::files::discover(options, &filters)?;

    let mut findings = files
        .par_iter()
        .flat_map(|file| scan_file(file, &detectors, &filters))
        .collect::<Vec<_>>();

    findings.sort();
    findings.dedup();

    Ok(ScanResult {
        findings,
        plugins_used: detectors.plugin_names(),
        filters_used: filters.names(),
    })
}

/// Compiled regex filters shared by discovery and scanning.
#[derive(Clone, Debug)]
pub struct CompiledFilters {
    exclude_files: Vec<Regex>,
    exclude_lines: Vec<Regex>,
    exclude_secrets: Vec<Regex>,
}

impl CompiledFilters {
    pub fn new(options: &ScanOptions) -> Result<Self> {
        Ok(Self {
            exclude_files: compile_regexes("--exclude-files", &options.exclude_files)?,
            exclude_lines: compile_regexes("--exclude-lines", &options.exclude_lines)?,
            exclude_secrets: compile_regexes("--exclude-secrets", &options.exclude_secrets)?,
        })
    }

    pub fn is_file_excluded(&self, filename: &str) -> bool {
        self.exclude_files
            .iter()
            .any(|regex| regex.is_match(filename))
    }

    pub fn has_file_exclusions(&self) -> bool {
        !self.exclude_files.is_empty()
    }

    fn is_line_excluded(&self, line: &str) -> bool {
        self.exclude_lines.iter().any(|regex| regex.is_match(line))
    }

    fn is_secret_excluded(&self, secret: &str) -> bool {
        self.exclude_secrets
            .iter()
            .any(|regex| regex.is_match(secret))
    }

    fn names(&self) -> Vec<String> {
        let mut names = Vec::new();
        if !self.exclude_files.is_empty() {
            names.push("detect_secrets.filters.regex.should_exclude_file".to_string());
        }
        if !self.exclude_lines.is_empty() {
            names.push("detect_secrets.filters.regex.should_exclude_line".to_string());
        }
        if !self.exclude_secrets.is_empty() {
            names.push("detect_secrets.filters.regex.should_exclude_secret".to_string());
        }
        names.push("detect_secrets.filters.allowlist.is_line_allowlisted".to_string());
        names
    }
}

fn compile_regexes(flag: &str, patterns: &[String]) -> Result<Vec<Regex>> {
    patterns
        .iter()
        .map(|pattern| Regex::new(pattern).with_context(|| format!("invalid {flag} `{pattern}`")))
        .collect()
}

fn scan_file(
    file: &SourceFile,
    detectors: &DetectorSet,
    filters: &CompiledFilters,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut filename = None::<Arc<str>>;
    let mut previous_allowlisted_nextline = false;

    for (line_idx, line) in file.content.lines().enumerate() {
        let has_pragma = line.contains("pragma");
        let allowlisted = previous_allowlisted_nextline
            || (has_pragma && line.contains("pragma: allowlist secret"));
        previous_allowlisted_nextline =
            has_pragma && line.contains("pragma: allowlist nextline secret");

        if allowlisted || filters.is_line_excluded(line) {
            continue;
        }

        detectors.visit_line(&file.filename, line, |_, secret_type, secret| {
            if !filters.is_secret_excluded(secret) {
                let filename = filename
                    .get_or_insert_with(|| Arc::<str>::from(file.filename.as_str()))
                    .clone();
                findings.push(to_finding(filename, line_idx + 1, secret_type, secret));
            }
        });
    }

    findings
}

fn to_finding(filename: Arc<str>, line_number: usize, secret_type: &str, secret: &str) -> Finding {
    Finding {
        secret_type: secret_type.to_string(),
        filename,
        hashed_secret: hash_secret(secret),
        is_verified: false,
        line_number,
    }
}

fn hash_secret(secret: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let digest = Sha1::digest(secret.as_bytes());
    let mut output = Vec::with_capacity(40);
    for byte in digest {
        output.push(HEX[(byte >> 4) as usize]);
        output.push(HEX[(byte & 0x0f) as usize]);
    }

    // Hex table output is always valid ASCII.
    unsafe { String::from_utf8_unchecked(output) }
}

#[cfg(test)]
mod tests {
    use crate::cli::ScanOptions;

    use super::*;

    #[test]
    fn allowlist_nextline_skips_finding() {
        let detectors = DetectorSet::new(&[]).unwrap();
        let filters = CompiledFilters::new(&ScanOptions {
            paths: vec![".".into()],
            all_files: true,
            exclude_files: Vec::new(),
            exclude_lines: Vec::new(),
            exclude_secrets: Vec::new(),
            disabled_plugins: Vec::new(),
            no_verify: false,
        })
        .unwrap();
        let file = SourceFile {
            filename: "demo.py".to_string(),
            content: "# pragma: allowlist nextline secret\nkey = 'AKIA1234567890ABCDEF'\n"
                .to_string(),
        };

        assert!(scan_file(&file, &detectors, &filters).is_empty());
    }

    #[test]
    fn hashes_do_not_equal_raw_secret() {
        let hash = hash_secret("AKIA1234567890ABCDEF");

        assert_ne!(hash, "AKIA1234567890ABCDEF");
        assert_eq!(hash.len(), 40);
    }
}
