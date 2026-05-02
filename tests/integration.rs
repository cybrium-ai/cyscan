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

// ─── Semgrep-max DSL parity (Phase B) ───────────────────────────────────────

#[test]
fn dsl_metavariable_regex_filters_capture() {
    use std::fs;
    let tmp = tempfile::tempdir().unwrap();
    let rules = tmp.path().join("rules");
    fs::create_dir(&rules).unwrap();
    fs::write(rules.join("metavar_re.yml"), r#"
id: TEST-MR
title: "URL token"
severity: low
languages: [python]
regex: "TOKEN_[A-Za-z0-9_]+"
metavariable_regex:
  match: "^TOKEN_[A-Z]{6,}$"
message: "matched"
"#).unwrap();
    fs::write(tmp.path().join("a.py"), "x = TOKEN_short\ny = TOKEN_LONGENOUGH\n").unwrap();
    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", rules.to_str().unwrap(), "-f", "json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("TOKEN_LONGENOUGH"))
        .stdout(predicate::str::contains("TOKEN_short").not());
}

#[test]
fn dsl_pattern_not_regex_suppresses_matched_span() {
    use std::fs;
    let tmp = tempfile::tempdir().unwrap();
    let rules = tmp.path().join("rules");
    fs::create_dir(&rules).unwrap();
    fs::write(rules.join("not_re.yml"), r#"
id: TEST-PNR
title: "Naked SELECT"
severity: medium
languages: [python]
regex: "SELECT \\* FROM"
pattern_not_regex:
  - "WHERE id ="
message: "matched"
"#).unwrap();
    let src = tmp.path().join("a.py");
    fs::write(&src, "x = \"SELECT * FROM users\"\n").unwrap();
    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", rules.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("TEST-PNR"));

    fs::write(&src, "x = \"SELECT * FROM users WHERE id = 1\"\n").unwrap();
    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", rules.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("TEST-PNR").not());
}

// ─── Cross-service evidence + aggregation + path prefix (v0.17.0) ──────────

#[test]
fn xservice_path_prefix_composes_for_spring_class_level_mapping() {
    // Spring lets @RequestMapping("/api") at class level compose with
    // @PostMapping("/users") at method level → "/api/users". This must
    // match a C# client calling "/api/users".
    use std::fs;
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("Auth.cs"), r#"
public class Auth {
    public async Task Run() {
        await httpClient.PostAsync("/api/users", body);
    }
}
"#).unwrap();
    fs::write(tmp.path().join("UserService.java"), r#"
@RequestMapping("/api")
public class UserService {
    @PostMapping("/users")
    public Response create(@RequestBody Body b) { return null; }
}
"#).unwrap();
    let out = Command::cargo_bin("cyscan").unwrap()
        .args(["xservice", tmp.path().to_str().unwrap(), "-f", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let map: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let links = map["links"].as_array().unwrap();
    let cs_to_java = links.iter().find(|l| {
        l["client"]["language"].as_str() == Some("csharp")
            && l["handler"].is_object()
            && l["handler"]["language"].as_str() == Some("java")
    });
    assert!(
        cs_to_java.is_some(),
        "C# /api/users should match Java @RequestMapping(/api) + @PostMapping(/users); got {:#?}",
        links,
    );
}

#[test]
fn scan_findings_in_handler_carry_cross_service_callers_evidence() {
    use std::fs;
    let tmp   = tempfile::tempdir().unwrap();
    let cs    = tmp.path().join("auth");
    let py    = tmp.path().join("svc");
    let rules = tmp.path().join("rules");
    fs::create_dir(&cs).unwrap();
    fs::create_dir(&py).unwrap();
    fs::create_dir(&rules).unwrap();

    fs::write(cs.join("Auth.cs"), r#"
public class Auth {
    public async Task Run() {
        await httpClient.PostAsync("/svc/danger", body);
    }
}
"#).unwrap();
    fs::write(py.join("svc.py"), r#"
@app.route("/svc/danger", methods=["POST"])
def handler():
    DANGER_TOKEN
"#).unwrap();
    fs::write(rules.join("danger.yml"), r#"
id: TEST-XSVC-CALLERS
title: "danger"
severity: high
languages: [python]
regex: "DANGER_TOKEN"
message: "matched"
"#).unwrap();

    let out = Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", rules.to_str().unwrap(), "-f", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let hit = json.as_array().unwrap().iter()
        .find(|f| f["rule_id"].as_str() == Some("TEST-XSVC-CALLERS"))
        .expect("rule should fire on the handler");
    let callers = hit["evidence"]["cross_service_callers"].as_array()
        .expect("cross_service_callers evidence should be present");
    assert!(
        !callers.is_empty(),
        "callers list should include the C# upstream caller, got {:?}", callers,
    );
    assert_eq!(callers[0]["language"].as_str(), Some("csharp"));
    assert_eq!(callers[0]["method"].as_str(),   Some("POST"));
    assert_eq!(callers[0]["path"].as_str(),     Some("/svc/danger"));
}

#[test]
fn xservice_dot_and_mermaid_render_for_polyglot_graph() {
    use std::fs;
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("Auth.cs"), r#"
public class Auth { public async Task R() { await httpClient.PostAsync("/x", b); } }
"#).unwrap();
    fs::write(tmp.path().join("svc.py"), r#"
@app.route("/x", methods=["POST"])
def h(): pass
"#).unwrap();
    let dot = Command::cargo_bin("cyscan").unwrap()
        .args(["xservice", tmp.path().to_str().unwrap(), "-f", "dot"])
        .assert().success().get_output().stdout.clone();
    let dot = String::from_utf8(dot).unwrap();
    assert!(dot.starts_with("digraph cyscan_xservice"), "DOT preamble missing: {dot}");
    assert!(dot.contains("POST /x"), "DOT should label edge with method+path");

    let mer = Command::cargo_bin("cyscan").unwrap()
        .args(["xservice", tmp.path().to_str().unwrap(), "-f", "mermaid"])
        .assert().success().get_output().stdout.clone();
    let mer = String::from_utf8(mer).unwrap();
    assert!(mer.starts_with("graph LR"), "Mermaid preamble missing: {mer}");
    assert!(mer.contains("|POST /x|"), "Mermaid edge missing label");
}

// ─── Cross-service API contract (Option 1 / v0.16.0) ───────────────────────

#[test]
fn xservice_pairs_csharp_client_to_java_to_python() {
    use std::fs;
    let tmp = tempfile::tempdir().unwrap();
    let cs   = tmp.path().join("auth");
    let java = tmp.path().join("user-svc");
    let py   = tmp.path().join("db");
    fs::create_dir(&cs).unwrap();
    fs::create_dir(&java).unwrap();
    fs::create_dir(&py).unwrap();

    fs::write(cs.join("AuthController.cs"), r#"
public class AuthController {
    public async Task<Response> Login(LoginRequest body) {
        return await httpClient.PostAsync("/api/users/{id}/login", body);
    }
}
"#).unwrap();
    fs::write(java.join("UserService.java"), r#"
@RestController
public class UserService {
    @PostMapping("/api/users/{id}/login")
    public Response login(@PathVariable String id, @RequestBody LoginRequest body) {
        return restTemplate.getForObject("/db/lookup/{id}", Response.class);
    }
}
"#).unwrap();
    fs::write(py.join("db.py"), r#"
@app.route("/db/lookup/<id>", methods=["GET"])
def lookup(id):
    return {"user": id}
"#).unwrap();

    let out = Command::cargo_bin("cyscan").unwrap()
        .args(["xservice", tmp.path().to_str().unwrap(), "-f", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let map: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let links = map["links"].as_array().unwrap();
    assert!(links.len() >= 2, "expected >= 2 links, got {}", links.len());

    // Find the C# → Java link
    let cs_to_java = links.iter().find(|l| {
        l["client"]["language"].as_str() == Some("csharp")
            && l["handler"].is_object()
            && l["handler"]["language"].as_str() == Some("java")
    });
    assert!(cs_to_java.is_some(), "C# → Java link should exist; got {:#?}", links);

    // Find the Java → Python link
    let java_to_py = links.iter().find(|l| {
        l["client"]["language"].as_str() == Some("java")
            && l["handler"].is_object()
            && l["handler"]["language"].as_str() == Some("python")
    });
    assert!(java_to_py.is_some(), "Java → Python link should exist; got {:#?}", links);
}

#[test]
fn xservice_normalises_path_param_styles() {
    use std::fs;
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("client.py"), r#"
requests.get("/users/123")
"#).unwrap();
    fs::write(tmp.path().join("server.py"), r#"
@app.route("/users/<id>", methods=["GET"])
def view(id): pass
"#).unwrap();
    // Different param styles in client vs server — must still match.
    fs::write(tmp.path().join("openapi.yaml"), r#"
openapi: 3.0.0
info: { title: t, version: 1 }
paths:
  /users/{id}:
    get:
      operationId: getUser
"#).unwrap();
    let out = Command::cargo_bin("cyscan").unwrap()
        .args(["xservice", tmp.path().to_str().unwrap(), "-f", "json"])
        .assert()
        .success()
        .get_output()
        .stdout.clone();
    let map: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let specs = map["specs"].as_array().unwrap();
    assert!(!specs.is_empty(), "openapi.yaml should be discovered");
    let ops = specs[0]["operations"].as_array().unwrap();
    assert!(
        ops.iter().any(|op| op["normalised_path"].as_str() == Some("/users/{}")),
        "openapi op should normalise to /users/{{}}, got {:?}", ops,
    );
}

// ─── Engine depth: dynamic dispatch / decorators / metaprogramming ────────

#[test]
fn callable_alias_extracted_for_eval() {
    // Phase A — `f = eval` should populate callable_aliases.
    let src = "f = eval\n";
    let s = cyscan::matcher::semantics::extract(cyscan::lang::Lang::Python, src);
    assert_eq!(
        s.callable_aliases.get("f").map(|s| s.as_str()),
        Some("eval"),
        "callable_aliases should map `f -> eval`, got {:?}",
        s.callable_aliases,
    );
}

#[test]
fn decorator_implies_framework_for_handler() {
    // Phase C — a function decorated `@app.route` makes a `frameworks: [flask]`
    // rule fire even when the file's import doesn't pull from flask directly.
    use std::fs;
    let tmp = tempfile::tempdir().unwrap();
    let rules = tmp.path().join("rules");
    let src   = tmp.path().join("src");
    fs::create_dir(&rules).unwrap();
    fs::create_dir(&src).unwrap();

    fs::write(rules.join("flask_only.yml"), r#"
id: TEST-DECO-FW
title: "Flask handler bug"
severity: high
languages: [python]
frameworks: [flask]
regex: "DANGER"
message: "matched"
"#).unwrap();
    fs::write(src.join("handler.py"), r#"
from app import app

@app.route("/x", methods=["POST"])
def view():
    DANGER
"#).unwrap();

    let out = Command::cargo_bin("cyscan").unwrap()
        .args(["scan", src.to_str().unwrap(), "--rules", rules.to_str().unwrap(), "-f", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let hits: Vec<&serde_json::Value> = json.as_array().unwrap().iter()
        .filter(|f| f["rule_id"].as_str() == Some("TEST-DECO-FW"))
        .collect();
    assert_eq!(hits.len(), 1, "decorator-implied framework should fire the rule");
    let fw = &hits[0]["evidence"]["framework"];
    assert!(fw.is_array(), "framework evidence should be array, got {:?}", fw);
    let fws: Vec<&str> = fw.as_array().unwrap().iter().filter_map(|v| v.as_str()).collect();
    assert!(fws.contains(&"flask"), "should report flask via decorator, got {:?}", fws);
}

#[test]
fn metaprogrammed_class_surfaces_in_evidence() {
    // Phase D — class with `metaclass=` should be flagged on every
    // finding inside its body so reviewers know to double-check.
    use std::fs;
    let tmp = tempfile::tempdir().unwrap();
    let rules = tmp.path().join("rules");
    let src   = tmp.path().join("src");
    fs::create_dir(&rules).unwrap();
    fs::create_dir(&src).unwrap();
    fs::write(rules.join("meta.yml"), r#"
id: TEST-META
title: "danger in class"
severity: low
languages: [python]
regex: "DANGER"
message: "matched"
"#).unwrap();
    fs::write(src.join("plugin.py"), r#"
class Plugin(metaclass=Registry):
    DANGER
"#).unwrap();
    let out = Command::cargo_bin("cyscan").unwrap()
        .args(["scan", src.to_str().unwrap(), "--rules", rules.to_str().unwrap(), "-f", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let hit = json.as_array().unwrap().iter()
        .find(|f| f["rule_id"].as_str() == Some("TEST-META"))
        .expect("rule should fire");
    let mp = &hit["evidence"]["metaprogrammed_class"];
    assert!(mp.is_object(), "metaprogrammed_class evidence should be present");
    assert_eq!(mp["class"].as_str(), Some("Plugin"));
    let reasons: Vec<&str> = mp["reasons"].as_array().unwrap().iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        reasons.iter().any(|r| r.contains("metaclass=")),
        "reasons should mention metaclass, got {:?}", reasons,
    );
}

// ─── Inter-procedural dataflow tests (Gap A4) ───────────────────────────────

#[test]
fn dataflow_require_reachable_suppresses_when_no_source_reaches_sink() {
    use std::fs;
    let tmp = tempfile::tempdir().unwrap();
    let rules = tmp.path().join("rules");
    let src   = tmp.path().join("src");
    fs::create_dir(&rules).unwrap();
    fs::create_dir(&src).unwrap();

    fs::write(rules.join("sqli.yml"), r#"
id: TEST-DF-SQLI
title: "SQL string-format"
severity: high
languages: [python]
regex: "SELECT \\* FROM users WHERE"
dataflow:
  require_reachable: true
message: "matched"
"#).unwrap();

    // Variant A — tainted source (request.GET) reaches format_query → fire
    fs::write(src.join("util.py"), r#"
def format_query(name):
    return f"SELECT * FROM users WHERE name = '{name}'"
"#).unwrap();
    fs::write(src.join("handler.py"), r#"
from util import format_query

def handle_request(request):
    user = request.GET.get("name")
    return format_query(user)
"#).unwrap();

    let out = Command::cargo_bin("cyscan").unwrap()
        .args(["scan", src.to_str().unwrap(), "--rules", rules.to_str().unwrap(), "-f", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let arr  = json.as_array().unwrap();
    let hits: Vec<&serde_json::Value> = arr.iter()
        .filter(|f| f["rule_id"].as_str() == Some("TEST-DF-SQLI"))
        .collect();
    assert_eq!(hits.len(), 1, "tainted source should make the rule fire, got {} hits", hits.len());
    let ev = &hits[0]["evidence"];
    assert_eq!(
        ev["dataflow_reachable"].as_bool(),
        Some(true),
        "evidence.dataflow_reachable should be true",
    );
    assert!(
        ev["dataflow_path"].is_array(),
        "evidence.dataflow_path should be a list, got {:?}",
        ev["dataflow_path"],
    );

    // Variant B — replace handler with a hardcoded call (no source) →
    // the same rule should NOT fire because require_reachable: true.
    fs::write(src.join("handler.py"), r#"
from util import format_query

def boot():
    return format_query("admin")
"#).unwrap();

    let out = Command::cargo_bin("cyscan").unwrap()
        .args(["scan", src.to_str().unwrap(), "--rules", rules.to_str().unwrap(), "-f", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let hits: Vec<&serde_json::Value> = json.as_array().unwrap().iter()
        .filter(|f| f["rule_id"].as_str() == Some("TEST-DF-SQLI"))
        .collect();
    assert_eq!(
        hits.len(),
        0,
        "require_reachable: true should suppress findings when no source reaches the sink",
    );
}

#[test]
fn dataflow_path_carries_source_kind_when_caller_chain_unavailable() {
    // Variant where the source is a built-in (request.GET.get) — the
    // caller chain ends at the source's host function, not at another
    // user-defined function. dataflow_path should still surface the
    // source kind so reviewers see WHERE the taint comes from.
    use std::fs;
    let tmp = tempfile::tempdir().unwrap();
    let rules = tmp.path().join("rules");
    let src   = tmp.path().join("src");
    fs::create_dir(&rules).unwrap();
    fs::create_dir(&src).unwrap();

    fs::write(rules.join("sqli.yml"), r#"
id: TEST-DF-PATH
title: "df-path"
severity: medium
languages: [python]
regex: "SELECT \\*"
dataflow: { require_reachable: true }
message: "matched"
"#).unwrap();
    fs::write(src.join("util.py"), r#"
def format_query(name):
    return f"SELECT * FROM users WHERE name = '{name}'"
"#).unwrap();
    fs::write(src.join("h.py"), r#"
from util import format_query
def handle(request):
    return format_query(request.GET.get("name"))
"#).unwrap();

    let out = Command::cargo_bin("cyscan").unwrap()
        .args(["scan", src.to_str().unwrap(), "--rules", rules.to_str().unwrap(), "-f", "json"])
        .assert()
        .success()
        .get_output()
        .stdout.clone();
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let h = json.as_array().unwrap().iter()
        .find(|f| f["rule_id"].as_str() == Some("TEST-DF-PATH"))
        .expect("rule should fire");
    let path = h["evidence"]["dataflow_path"].as_array().expect("dataflow_path array");
    let path_strs: Vec<&str> = path.iter().filter_map(|v| v.as_str()).collect();
    assert!(
        path_strs.iter().any(|p| p.starts_with("source:")),
        "dataflow_path should contain a source: entry, got {:?}",
        path_strs,
    );
}

// ─── Type-resolution + framework-propagation tests (Gap 2 + 5 / A5 + B2) ──

#[test]
fn semantics_framework_filter_only_fires_in_matching_files() {
    use std::fs;
    let tmp = tempfile::tempdir().unwrap();
    let rules = tmp.path().join("rules");
    fs::create_dir(&rules).unwrap();
    fs::write(rules.join("framework_only.yml"), r#"
id: TEST-FW-DJANGO-ONLY
title: "Django-only rule"
severity: medium
languages: [python]
frameworks: [django]
regex: "FORBIDDEN"
message: "matched"
"#).unwrap();

    let django_file = tmp.path().join("with_django.py");
    fs::write(&django_file, "from django.shortcuts import redirect\nFORBIDDEN\n").unwrap();
    let plain_file = tmp.path().join("plain.py");
    fs::write(&plain_file, "FORBIDDEN\n").unwrap();

    let out = Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", rules.to_str().unwrap(), "-f", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let arr = json.as_array().unwrap();
    let hits: Vec<&serde_json::Value> = arr.iter()
        .filter(|f| f["rule_id"].as_str() == Some("TEST-FW-DJANGO-ONLY"))
        .collect();

    // Must fire exactly once — on the django file only.
    assert_eq!(hits.len(), 1, "framework filter should fire only in django file, got {} hits", hits.len());
    let hit = hits[0];
    assert!(
        hit["file"].as_str().unwrap_or("").contains("with_django.py"),
        "django hit should be on with_django.py",
    );
    let fw = &hit["evidence"]["framework"];
    assert!(fw.is_array(), "evidence.framework should be array, got {:?}", fw);
    assert_eq!(fw[0].as_str(), Some("django"));
}

#[test]
fn semantics_extracts_imports_for_python() {
    // Direct unit test through the public API. Confirms FileSemantics
    // populates imported_modules + frameworks when it sees real Python.
    let src = r#"
from django.urls import path
from django.shortcuts import redirect
import yaml
import requests

def view(req):
    target = req.GET.get("next")
    return redirect(target)
"#;
    let s = cyscan::matcher::semantics::extract(cyscan::lang::Lang::Python, src);
    assert!(s.imported_modules.contains("django.urls") || s.imported_modules.contains("django"),
        "expected django imports, got {:?}", s.imported_modules);
    assert!(s.imported_modules.contains("yaml"));
    assert!(s.imported_modules.contains("requests"));
    assert!(
        s.frameworks.contains("django"),
        "django framework should be detected from `from django.X import` lines, got {:?}", s.frameworks,
    );
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
