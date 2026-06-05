use assert_cmd::Command;

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
