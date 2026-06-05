use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use ignore::{DirEntry, WalkBuilder};
use rayon::prelude::*;

use crate::cli::ScanOptions;
use crate::scan::CompiledFilters;

/// Text source prepared for scanning.
#[derive(Clone, Debug)]
pub struct SourceFile {
    pub filename: String,
    pub content: String,
}

pub fn discover(options: &ScanOptions, filters: &CompiledFilters) -> Result<Vec<SourceFile>> {
    let candidates = if options.all_files {
        recursive_candidates(&options.paths, false)?
    } else {
        git_tracked_candidates(&options.paths)?
            .unwrap_or(recursive_candidates(&options.paths, true)?)
    };

    let mut files = read_candidates(candidates, filters)?;

    files.sort_by(|left, right| left.filename.cmp(&right.filename));
    Ok(files)
}

fn read_candidates(candidates: Vec<PathBuf>, filters: &CompiledFilters) -> Result<Vec<SourceFile>> {
    if candidates.len() >= 512 {
        return candidates
            .into_par_iter()
            .filter(|path| !is_excluded_path(path, filters))
            .filter_map(|path| read_source(&path).transpose())
            .collect::<Vec<_>>()
            .into_iter()
            .collect::<Result<Vec<_>>>();
    }

    candidates
        .into_iter()
        .filter(|path| !is_excluded_path(path, filters))
        .filter_map(|path| read_source(&path).transpose())
        .collect()
}

fn is_excluded_path(path: &Path, filters: &CompiledFilters) -> bool {
    filters.has_file_exclusions() && filters.is_file_excluded(&display_path(path))
}

fn git_tracked_candidates(paths: &[PathBuf]) -> Result<Option<Vec<PathBuf>>> {
    let mut command = Command::new("git");
    command.args(["ls-files", "-z", "--"]);
    command.args(paths);

    let output = match command.output() {
        Ok(output) if output.status.success() && !output.stdout.is_empty() => output,
        _ => return Ok(None),
    };

    let mut candidates = output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| PathBuf::from(String::from_utf8_lossy(entry).into_owned()))
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.dedup();

    if candidates.is_empty() {
        Ok(None)
    } else {
        Ok(Some(candidates))
    }
}

fn recursive_candidates(paths: &[PathBuf], respect_ignore: bool) -> Result<Vec<PathBuf>> {
    let mut candidates = Vec::new();
    for path in paths {
        if path.is_file() {
            candidates.push(path.clone());
            continue;
        }

        let mut builder = WalkBuilder::new(path);
        builder
            .hidden(false)
            .ignore(respect_ignore)
            .git_ignore(respect_ignore)
            .git_exclude(respect_ignore)
            .git_global(respect_ignore)
            .filter_entry(|entry| !is_git_dir(entry));

        for entry in builder.build() {
            let entry = entry.with_context(|| format!("failed to walk `{}`", path.display()))?;
            if entry
                .file_type()
                .is_some_and(|file_type| file_type.is_file())
            {
                candidates.push(entry.into_path());
            }
        }
    }

    candidates.sort();
    candidates.dedup();
    Ok(candidates)
}

fn is_git_dir(entry: &DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .is_some_and(|name| name == ".git")
}

fn read_source(path: &Path) -> Result<Option<SourceFile>> {
    let bytes = fs::read(path).with_context(|| format!("failed to read `{}`", path.display()))?;
    if bytes.contains(&0) {
        return Ok(None);
    }
    let content = match String::from_utf8(bytes) {
        Ok(content) => content,
        Err(_) => return Ok(None),
    };

    Ok(Some(SourceFile {
        filename: display_path(path),
        content,
    }))
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_binary_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bin.dat");
        fs::write(&path, b"a\0b").unwrap();

        assert!(read_source(&path).unwrap().is_none());
    }
}
