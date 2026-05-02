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

    // After fixing, re-scan and verify the FIXED rules are gone.
    // Use regex to match rule IDs at finding-header position (not in snippets).
    let rescan = Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", &rules, "--format", "text"])
        .output().unwrap();
    let stdout = String::from_utf8_lossy(&rescan.stdout);
    // Check that fixed rules don't appear as finding headers (] RULE_ID path)
    for fixed_rule in &["CBR-GO-TLS-INSECURE-SKIP-VERIFY", "CBR-GO-WEAK-HASH", "CBR-SECRETS-AWS-KEY"] {
        let header_pattern = format!("]  {fixed_rule}  ");
        assert!(!stdout.contains(&header_pattern),
            "Rule {fixed_rule} should not appear as a finding after fix.\nOutput: {stdout}");
    }
}

#[test]
fn supply_detects_advisories_typosquat_and_policy() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let target = format!("{manifest}/tests/fixtures/lockfiles");
    let rules  = format!("{manifest}/rules");

    Command::cargo_bin("cyscan").unwrap()
        .args(["supply", &target, "--rules", &rules, "--format", "text"])
        .assert()
        // npm advisory (event-stream)
        .stdout(predicate::str::contains("GHSA-mh6f-8j2x-4483"))
        // pypi advisory (urllib3)
        .stdout(predicate::str::contains("GHSA-vqm2-6jp7-jqvx"))
        // crates advisory (tokio 1.7.3)
        .stdout(predicate::str::contains("GHSA-w36q-p22w-6q94"))
        // typosquat: `reakt` vs `react`
        .stdout(predicate::str::contains("CBR-SUPPLY-TYPOSQUAT"))
        // user policy rule from rules/supply/
        .stdout(predicate::str::contains("CBR-DEP-EVENT-STREAM-MALWARE"));
}

#[test]
fn supply_no_advisories_flag_skips_osv() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let target = format!("{manifest}/tests/fixtures/lockfiles");
    let rules  = format!("{manifest}/rules");

    Command::cargo_bin("cyscan").unwrap()
        .args(["supply", &target, "--rules", &rules, "--no-advisories", "--format", "text"])
        .assert()
        // Policy + typosquat still fire.
        .stdout(predicate::str::contains("CBR-DEP-EVENT-STREAM-MALWARE"))
        // But no GHSA-prefixed advisory findings.
        .stdout(predicate::str::contains("GHSA-").not());
}

// ─── Reachability evidence tests (Gap 4 / C3) ───────────────────────────────

#[test]
fn supply_reachability_emits_dependency_path_and_callsite_evidence() {
    // Run `cyscan supply` against the fixture lockfiles tree and verify
    // every advisory finding carries the new C3 evidence shape:
    //   - package
    //   - reachable_dependency_path (Vec<String>, falls back to [package])
    //   - reachable_dependency_path_string
    //   - reachable_callsite_count
    //   - reachability verdict on the finding itself
    let manifest = env!("CARGO_MANIFEST_DIR");
    let fixtures = format!("{manifest}/tests/fixtures/lockfiles");
    let rules    = format!("{manifest}/rules");

    let out = Command::cargo_bin("cyscan").unwrap()
        .args(["supply", &fixtures, "--rules", &rules, "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    // Pure advisory findings have rule_id `CBR-SUPPLY-GHSA-…` or
    // `CBR-SUPPLY-CVE-…` — typosquat (`CBR-SUPPLY-TYPOSQUAT`) and policy
    // (`CBR-DEP-…`) findings don't carry the dep-path evidence shape so
    // we filter them out.
    let advisories: Vec<&serde_json::Value> = json
        .as_array().unwrap().iter()
        .filter(|f| {
            let id = f["rule_id"].as_str().unwrap_or("");
            id.starts_with("CBR-SUPPLY-GHSA") || id.starts_with("CBR-SUPPLY-CVE")
        })
        .collect();
    assert!(!advisories.is_empty(), "fixture should produce at least one advisory finding");

    for f in &advisories {
        let ev = &f["evidence"];
        assert!(
            ev["package"].is_string(),
            "advisory finding must carry package evidence; got rule={} evidence={:?}",
            f["rule_id"], ev,
        );
        assert!(
            ev["reachable_dependency_path"].is_array(),
            "advisory finding must carry reachable_dependency_path",
        );
        assert!(
            ev["reachable_dependency_path_string"].is_string(),
            "advisory finding must carry reachable_dependency_path_string",
        );
        assert!(
            ev["reachable_callsite_count"].is_number(),
            "advisory finding must carry reachable_callsite_count",
        );
        // reachability verdict on the finding itself
        let verdict = f["reachability"].as_str().unwrap_or("");
        assert!(
            ["reachable", "unreachable", "unknown"].contains(&verdict),
            "reachability must be one of the three verdicts, got '{verdict}'",
        );
    }
}

// ─── DSL semantics tests (Gap 3 / B1) ───────────────────────────────────────

#[test]
fn dsl_pattern_either_groups_match_complete_branch() {
    // pattern_either_groups requires that at least one group fully matches
    // (every entry in the group satisfied somewhere in the source).
    use std::fs;
    let tmp = tempfile::tempdir().unwrap();
    let rules = tmp.path().join("rules");
    fs::create_dir(&rules).unwrap();
    fs::write(rules.join("either_groups.yml"), r#"
id: TEST-DSL-EITHER-GROUPS
title: "Either groups"
severity: high
languages: [python]
regex: "TARGET"
pattern_either_groups:
  - ["AAA", "BBB"]
  - ["XXX", "YYY"]
message: "matched"
"#).unwrap();

    // Source where only group 1 fully matches
    let src = tmp.path().join("a.py");
    fs::write(&src, "TARGET\nAAA\nBBB\n").unwrap();
    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", rules.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("TEST-DSL-EITHER-GROUPS"));

    // Source with neither group fully present — only AAA + XXX → no match
    fs::write(&src, "TARGET\nAAA\nXXX\n").unwrap();
    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", rules.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("TEST-DSL-EITHER-GROUPS").not());
}

#[test]
fn dsl_pattern_not_inside_excludes_enclosing_context() {
    use std::fs;
    let tmp = tempfile::tempdir().unwrap();
    let rules = tmp.path().join("rules");
    fs::create_dir(&rules).unwrap();
    fs::write(rules.join("not_inside.yml"), r#"
id: TEST-DSL-NOT-INSIDE
title: "Not inside"
severity: medium
languages: [python]
regex: "FORBIDDEN"
pattern_not_inside:
  - "def safe_zone"
message: "matched"
"#).unwrap();

    // FORBIDDEN appears outside any safe_zone → should fire
    let src = tmp.path().join("a.py");
    fs::write(&src, "x = FORBIDDEN\n").unwrap();
    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", rules.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("TEST-DSL-NOT-INSIDE"));

    // FORBIDDEN inside def safe_zone(): block → suppressed
    fs::write(&src, "def safe_zone():\n    x = FORBIDDEN\n").unwrap();
    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", rules.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("TEST-DSL-NOT-INSIDE").not());
}

#[test]
fn dsl_metavariable_comparisons_filter_capture() {
    // Sanity: regex matcher invokes metavariable_comparisons. With a
    // length comparison on the synthetic `match` capture we filter
    // matches that don't satisfy `len > N`.
    use std::fs;
    let tmp = tempfile::tempdir().unwrap();
    let rules = tmp.path().join("rules");
    fs::create_dir(&rules).unwrap();
    fs::write(rules.join("metavar.yml"), r#"
id: TEST-DSL-METAVAR
title: "Long-token only"
severity: low
languages: [python]
regex: "TOKEN_[A-Z0-9]+"
metavariable_comparisons:
  - "len($match) > 10"
message: "matched"
"#).unwrap();

    let src = tmp.path().join("a.py");
    // TOKEN_ABCDEFGHIJ is 16 chars (matches), TOKEN_X is 7 (filtered out)
    fs::write(&src, "x = TOKEN_X\ny = TOKEN_ABCDEFGHIJ\n").unwrap();
    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", rules.to_str().unwrap(), "-f", "json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("TOKEN_ABCDEFGHIJ"))
        .stdout(predicate::str::contains("TOKEN_X").not());
}

// ─── Triage workflow tests (Gap 1) ──────────────────────────────────────────

#[test]
fn triage_init_set_list_and_history_work() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let tmp = tempfile::tempdir().unwrap();
    let triage_path = tmp.path().join("triage.json");

    // init
    Command::cargo_bin("cyscan").unwrap()
        .args(["triage", "init", "--path", triage_path.to_str().unwrap()])
        .assert()
        .success();
    assert!(triage_path.exists(), "triage file should be created");

    // set
    let fp = "deadbeefcafef00d";
    Command::cargo_bin("cyscan").unwrap()
        .args([
            "triage", "set", fp, "false_positive",
            "--path", triage_path.to_str().unwrap(),
            "--note", "test note",
            "--author", "anand",
        ])
        .assert()
        .success();

    // list — should contain the fingerprint and status
    Command::cargo_bin("cyscan").unwrap()
        .args(["triage", "list", "--path", triage_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains(fp))
        .stdout(predicate::str::contains("false_positive"));

    // history — should show one event
    Command::cargo_bin("cyscan").unwrap()
        .args(["triage", "history", fp, "--path", triage_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("anand"))
        .stdout(predicate::str::contains("test note"));

    let _ = manifest; // suppress unused warning when only used for cwd anchor elsewhere
}

#[test]
fn scan_applies_triage_status_and_hide_triaged() {
    use std::fs;
    let manifest = env!("CARGO_MANIFEST_DIR");
    let rules = format!("{manifest}/rules");
    let tmp = tempfile::tempdir().unwrap();

    // fixture: one Python file with eval()
    let src = tmp.path().join("vuln.py");
    fs::write(&src, "eval(user_input)\n").unwrap();
    let triage_path = tmp.path().join("triage.json");

    // initial scan to grab the fingerprint
    let out = Command::cargo_bin("cyscan").unwrap()
        .args([
            "scan", tmp.path().to_str().unwrap(),
            "--rules", &rules,
            "--format", "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let fp = json[0]["fingerprint"].as_str().unwrap().to_string();
    assert!(!fp.is_empty(), "scanner must populate finding.fingerprint");

    // mark as false_positive
    Command::cargo_bin("cyscan").unwrap()
        .args([
            "triage", "init", "--path", triage_path.to_str().unwrap(),
        ]).assert().success();
    Command::cargo_bin("cyscan").unwrap()
        .args([
            "triage", "set", &fp, "false_positive",
            "--path", triage_path.to_str().unwrap(),
        ]).assert().success();

    // re-scan with --hide-triaged: that finding should be gone
    let out2 = Command::cargo_bin("cyscan").unwrap()
        .args([
            "scan", tmp.path().to_str().unwrap(),
            "--rules", &rules,
            "--format", "json",
            "--triage", triage_path.to_str().unwrap(),
            "--hide-triaged",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json2: serde_json::Value = serde_json::from_slice(&out2).unwrap();
    let arr = json2.as_array().unwrap();
    assert!(
        arr.iter().all(|f| f["fingerprint"].as_str() != Some(&fp)),
        "triaged finding should be hidden",
    );
}

#[test]
fn triaged_findings_do_not_trigger_fail_on() {
    use std::fs;
    let manifest = env!("CARGO_MANIFEST_DIR");
    let rules = format!("{manifest}/rules");
    let tmp = tempfile::tempdir().unwrap();

    let src = tmp.path().join("vuln.py");
    fs::write(&src, "eval(user_input)\n").unwrap();
    let triage_path = tmp.path().join("triage.json");

    // Without triage → fail-on=high should exit non-zero (eval is high+)
    Command::cargo_bin("cyscan").unwrap()
        .args([
            "scan", tmp.path().to_str().unwrap(),
            "--rules", &rules,
            "--fail-on", "low",
        ])
        .assert()
        .code(1);

    // Capture fingerprint, then mark every finding as accepted_risk
    let out = Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", &rules, "--format", "json"])
        .assert()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    Command::cargo_bin("cyscan").unwrap()
        .args(["triage", "init", "--path", triage_path.to_str().unwrap()]).assert().success();
    for f in json.as_array().unwrap() {
        let fp = f["fingerprint"].as_str().unwrap();
        Command::cargo_bin("cyscan").unwrap()
            .args(["triage", "set", fp, "accepted_risk", "--path", triage_path.to_str().unwrap()])
            .assert().success();
    }

    // Now the same scan with --triage should exit 0 — all findings excluded
    Command::cargo_bin("cyscan").unwrap()
        .args([
            "scan", tmp.path().to_str().unwrap(),
            "--rules", &rules,
            "--fail-on", "low",
            "--triage", triage_path.to_str().unwrap(),
        ])
        .assert()
        .code(0);
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
