use assert_cmd::Command;
use serde_json::Value;

#[test]
fn list_all_plugins_prints_builtin_detectors() {
    let mut command = Command::cargo_bin("detect-secrets-rs").unwrap();

    let output = command
        .args(["scan", "--list-all-plugins"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(output).unwrap();

    assert!(stdout.contains("AWSKeyDetector"));
    assert!(stdout.contains("KeywordDetector"));
}

#[test]
fn scan_outputs_hashed_findings_without_raw_secret() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("config.js");
    std::fs::write(&source, "const aws = 'AKIA1234567890ABCDEF';\n").unwrap();

    let mut command = Command::cargo_bin("detect-secrets-rs").unwrap();
    let output = command
        .arg("scan")
        .arg("--all-files")
        .arg(dir.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(output).unwrap();

    assert!(!stdout.contains("AKIA1234567890ABCDEF"));
    assert!(stdout.contains("AWS Access Key"));
    assert!(stdout.contains("hashed_secret"));
}

#[test]
fn scan_respects_exclude_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("config.js");
    std::fs::write(&source, "const aws = 'AKIA1234567890ABCDEF';\n").unwrap();

    let mut command = Command::cargo_bin("detect-secrets-rs").unwrap();
    let output = command
        .arg("scan")
        .arg("--all-files")
        .arg("--exclude-secrets")
        .arg("AKIA")
        .arg(dir.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(output).unwrap();

    assert!(!stdout.contains("AWS Access Key"));
}

#[test]
fn scan_string_prints_verdicts_without_raw_secret() {
    let mut command = Command::cargo_bin("detect-secrets-rs").unwrap();
    let output = command
        .args(["scan", "--string", "const aws = 'AKIA1234567890ABCDEF';"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(output).unwrap();

    assert!(stdout.contains("AWSKeyDetector"));
    assert!(stdout.contains("True"));
    assert!(!stdout.contains("AKIA1234567890ABCDEF"));
}

#[test]
fn scan_only_allowlisted_scans_only_allowlisted_lines() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("config.js");
    std::fs::write(
        &source,
        "const plain = 'AKIA1234567890ABCDEF';\n\
         // pragma: allowlist nextline secret\n\
         const marked = 'AKIA1234567890ABCDEG';\n",
    )
    .unwrap();

    let mut command = Command::cargo_bin("detect-secrets-rs").unwrap();
    let output = command
        .arg("scan")
        .arg("--all-files")
        .arg("--only-allowlisted")
        .arg(dir.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).unwrap();
    let findings = report["results"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .as_array()
        .unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["line_number"], 3);
    assert!(
        !String::from_utf8(output)
            .unwrap()
            .contains("AKIA1234567890ABCDEG")
    );
}

#[test]
fn scan_slim_omits_line_numbers() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("config.js");
    std::fs::write(&source, "const aws = 'AKIA1234567890ABCDEF';\n").unwrap();

    let mut command = Command::cargo_bin("detect-secrets-rs").unwrap();
    let output = command
        .arg("scan")
        .arg("--all-files")
        .arg("--slim")
        .arg(dir.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(output).unwrap();

    assert!(stdout.contains("AWS Access Key"));
    assert!(!stdout.contains("line_number"));
}

#[test]
fn scan_base64_limit_overrides_default_entropy_threshold() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("config.js");
    std::fs::write(
        &source,
        "const value = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/';\n",
    )
    .unwrap();

    let mut default_command = Command::cargo_bin("detect-secrets-rs").unwrap();
    let default_output = default_command
        .arg("scan")
        .arg("--all-files")
        .arg(dir.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert!(
        String::from_utf8(default_output)
            .unwrap()
            .contains("Base64 High Entropy String")
    );

    let mut high_limit_command = Command::cargo_bin("detect-secrets-rs").unwrap();
    let high_limit_output = high_limit_command
        .arg("scan")
        .arg("--all-files")
        .arg("--base64-limit")
        .arg("8")
        .arg(dir.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert!(
        !String::from_utf8(high_limit_output)
            .unwrap()
            .contains("Base64 High Entropy String")
    );
}
