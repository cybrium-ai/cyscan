//! End-to-end test: run the built cyscan binary against the fixture
//! directory and assert we see the expected rule IDs.

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn fixture_scan_reports_expected_rule_ids() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let fixtures = format!("{manifest}/tests/fixtures");
    let rules    = format!("{manifest}/rules");

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", &fixtures, "--rules", &rules, "--format", "text"])
        .assert()
        .stdout(predicate::str::contains("CBR-PY-SQLI-STRING-CONCAT"))
        .stdout(predicate::str::contains("CBR-SECRETS-AWS-KEY"))
        .stdout(predicate::str::contains("CBR-JS-XSS-INNER-HTML"));
}

#[test]
fn fix_dry_run_writes_nothing() {
    use std::fs;
    let manifest = env!("CARGO_MANIFEST_DIR");
    let src = format!("{manifest}/tests/fixtures");
    let tmp = tempfile::tempdir().unwrap();
    copy_tree(std::path::Path::new(&src), tmp.path());
    let before = fs::read(tmp.path().join("bad.py")).unwrap();
    let rules  = format!("{manifest}/rules");

    Command::cargo_bin("cyscan").unwrap()
        .args(["fix", tmp.path().to_str().unwrap(), "--rules", &rules, "--dry-run"])
        .assert()
        .stdout(predicate::str::contains("+++").and(predicate::str::contains("---")));

    let after = fs::read(tmp.path().join("bad.py")).unwrap();
    assert_eq!(before, after, "dry-run must not modify source files");
}

#[test]
fn fix_patches_files_and_writes_backups() {
    use std::fs;
    let manifest = env!("CARGO_MANIFEST_DIR");
    let src = format!("{manifest}/tests/fixtures");
    let tmp = tempfile::tempdir().unwrap();
    copy_tree(std::path::Path::new(&src), tmp.path());
    let rules  = format!("{manifest}/rules");

    Command::cargo_bin("cyscan").unwrap()
        .args(["fix", tmp.path().to_str().unwrap(), "--rules", &rules])
        .assert()
        .success();

    assert!(tmp.path().join("bad.py.cyscan-bak").exists(), "python backup missing");
    assert!(tmp.path().join("bad.go.cyscan-bak").exists(), "go backup missing");

    let py = fs::read_to_string(tmp.path().join("bad.py")).unwrap();
    assert!(!py.contains("AKIA1234567890ABCDEF"), "AWS key not spliced out: {py}");
    let go = fs::read_to_string(tmp.path().join("bad.go")).unwrap();
    assert!(go.contains("InsecureSkipVerify: false"), "TLS fix not applied: {go}");
    assert!(go.contains(r#""crypto/sha256""#), "weak-hash fix not applied: {go}");

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", &rules, "--format", "text"])
        .assert()
        .stdout(predicate::str::contains("CBR-GO-TLS-INSECURE-SKIP-VERIFY").not())
        .stdout(predicate::str::contains("CBR-GO-WEAK-HASH").not())
        .stdout(predicate::str::contains("CBR-SECRETS-AWS-KEY").not());
}

fn copy_tree(src: &std::path::Path, dst: &std::path::Path) {
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let ft = entry.file_type().unwrap();
        let to = dst.join(entry.file_name());
        if ft.is_dir() {
            std::fs::create_dir_all(&to).unwrap();
            copy_tree(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).unwrap();
        }
    }
}
