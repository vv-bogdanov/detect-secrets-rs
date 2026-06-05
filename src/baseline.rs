use std::collections::BTreeMap;
use std::sync::Arc;

use serde::Serialize;

use crate::scan::ScanResult;

/// Deterministic baseline-like scan output.
#[derive(Clone, Debug, Serialize)]
pub struct Baseline {
    pub version: String,
    pub plugins_used: Vec<PluginUsed>,
    pub filters_used: Vec<FilterUsed>,
    pub results: BTreeMap<String, Vec<Finding>>,
}

/// Detector metadata included in the baseline-like output.
#[derive(Clone, Debug, Serialize)]
pub struct PluginUsed {
    pub name: String,
}

/// Filter metadata included in the baseline-like output.
#[derive(Clone, Debug, Serialize)]
pub struct FilterUsed {
    pub path: String,
}

/// One detected secret without the raw secret value.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Finding {
    #[serde(rename = "type")]
    pub secret_type: String,
    #[serde(skip_serializing)]
    pub filename: Arc<str>,
    pub hashed_secret: String,
    pub is_verified: bool,
    pub line_number: usize,
}

impl Baseline {
    pub fn from_scan_result(result: ScanResult) -> Self {
        let mut grouped = BTreeMap::<String, Vec<Finding>>::new();
        for finding in result.findings {
            grouped
                .entry(finding.filename.to_string())
                .or_default()
                .push(finding);
        }
        for findings in grouped.values_mut() {
            findings.sort();
        }

        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            plugins_used: result
                .plugins_used
                .into_iter()
                .map(|name| PluginUsed { name })
                .collect(),
            filters_used: result
                .filters_used
                .into_iter()
                .map(|path| FilterUsed { path })
                .collect(),
            results: grouped,
        }
    }
}
