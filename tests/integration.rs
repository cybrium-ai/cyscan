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

#[test]
fn python_pickle_alias_is_detected() {
    use std::fs;
    let manifest = env!("CARGO_MANIFEST_DIR");
    let rules  = format!("{manifest}/rules");
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("alias_pickle.py");
    fs::write(&src, "import pickle as p\npayload = b'data'\np.loads(payload)\n").unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", &rules, "--format", "text"])
        .assert()
        .stdout(predicate::str::contains("CBR-PY-PICKLE-LOADS"));
}

#[test]
fn js_settimeout_callback_is_not_flagged_as_eval() {
    use std::fs;
    let manifest = env!("CARGO_MANIFEST_DIR");
    let rules  = format!("{manifest}/rules");
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("timer.js");
    fs::write(&src, "setTimeout(handler, 1000);\n").unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", &rules, "--format", "text"])
        .assert()
        .stdout(predicate::str::contains("CBR-JS-CODE-EVAL").not());
}

#[test]
fn python_sqlalchemy_execute_symbol_is_not_misclassified_as_cursor_execute() {
    use std::fs;
    let manifest = env!("CARGO_MANIFEST_DIR");
    let rules  = format!("{manifest}/rules");
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("sqlalchemy_style.py");
    fs::write(&src, "from sqlalchemy import text\nquery = 'select * from users where id=' + user_id\ntext.execute(query)\n").unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", &rules, "--format", "text"])
        .assert()
        .stdout(predicate::str::contains("CBR-PY-SQLI-STRING-CONCAT").not());
}

#[test]
fn python_eval_inside_if_false_is_marked_unreachable() {
    use std::fs;
    let manifest = env!("CARGO_MANIFEST_DIR");
    let rules  = format!("{manifest}/rules");
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("dead_eval.py");
    fs::write(&src, "if False:\n    eval(user_input)\n").unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", &rules, "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-PY-CODE-EVAL\""))
        .stdout(predicate::str::contains("\"reachability\": \"unreachable\""))
        .stdout(predicate::str::contains("\"path_sensitivity_reason\": \"dead_branch_false_condition\""));
}

#[test]
fn js_innerhtml_with_dompurify_is_marked_guarded() {
    use std::fs;
    let manifest = env!("CARGO_MANIFEST_DIR");
    let rules  = format!("{manifest}/rules");
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("safe_innerhtml.js");
    fs::write(&src, "el.innerHTML = DOMPurify.sanitize(userBio);\n").unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", &rules, "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-JS-XSS-INNER-HTML\""))
        .stdout(predicate::str::contains("\"reachability\": \"unknown\""))
        .stdout(predicate::str::contains("\"path_sensitivity_reason\": \"dompurify_sanitized\""))
        .stdout(predicate::str::contains("\"confidence\": \"low\""));
}

#[test]
fn python_flask_eval_request_arg_is_marked_tainted_reachable() {
    use std::fs;
    let manifest = env!("CARGO_MANIFEST_DIR");
    let rules  = format!("{manifest}/rules");
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("flask_eval.py");
    fs::write(
        &src,
        "from flask import request\nuser_code = request.args.get('code')\neval(user_code)\n",
    ).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", &rules, "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-PY-CODE-EVAL\""))
        .stdout(predicate::str::contains("\"reachability\": \"reachable\""))
        .stdout(predicate::str::contains("\"path_sensitivity\": \"tainted\""))
        .stdout(predicate::str::contains("\"source_kind\": \"flask.request.args\""))
        .stdout(predicate::str::contains("\"framework\": \"flask\""))
        .stdout(predicate::str::contains("\"confidence\": \"high\""));
}

#[test]
fn python_django_eval_request_get_is_marked_tainted_reachable() {
    use std::fs;
    let manifest = env!("CARGO_MANIFEST_DIR");
    let rules  = format!("{manifest}/rules");
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("django_eval.py");
    fs::write(
        &src,
        "from django.http import HttpRequest\nvalue = request.GET.get('code')\neval(value)\n",
    ).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", &rules, "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-PY-CODE-EVAL\""))
        .stdout(predicate::str::contains("\"reachability\": \"reachable\""))
        .stdout(predicate::str::contains("\"path_sensitivity\": \"tainted\""))
        .stdout(predicate::str::contains("\"source_kind\": \"django.request.GET\""))
        .stdout(predicate::str::contains("\"framework\": \"django\""));
}

#[test]
fn python_eval_later_assignment_does_not_backpropagate_taint() {
    use std::fs;
    let manifest = env!("CARGO_MANIFEST_DIR");
    let rules  = format!("{manifest}/rules");
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("ordered_eval.py");
    fs::write(
        &src,
        "from flask import request\n\ndef run():\n    code = 'safe'\n    eval(code)\n    code = request.args.get('code')\n",
    ).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", &rules, "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-PY-CODE-EVAL\""))
        .stdout(predicate::str::contains("\"reachability\": \"unknown\""))
        .stdout(predicate::str::contains("\"path_sensitivity_reason\": \"python_intra_function_no_source\""))
        .stdout(predicate::str::contains("\"confidence\": \"medium\""));
}

#[test]
fn python_eval_sanitized_assignment_is_marked_guarded() {
    use std::fs;
    let manifest = env!("CARGO_MANIFEST_DIR");
    let rules  = format!("{manifest}/rules");
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("sanitized_eval.py");
    fs::write(
        &src,
        "from flask import request\nimport html\n\ndef run():\n    code = request.args.get('code')\n    safe_code = html.escape(code)\n    eval(safe_code)\n",
    ).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", &rules, "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-PY-CODE-EVAL\""))
        .stdout(predicate::str::contains("\"reachability\": \"unknown\""))
        .stdout(predicate::str::contains("\"path_sensitivity\": \"guarded\""))
        .stdout(predicate::str::contains("\"path_sensitivity_reason\": \"escaped_input\""))
        .stdout(predicate::str::contains("\"confidence\": \"low\""));
}

#[test]
fn js_express_query_innerhtml_is_marked_tainted_reachable() {
    use std::fs;
    let manifest = env!("CARGO_MANIFEST_DIR");
    let rules  = format!("{manifest}/rules");
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("express_innerhtml.js");
    fs::write(
        &src,
        "const express = require('express');\nconst body = req.query.html;\nel.innerHTML = body;\n",
    ).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", &rules, "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-JS-XSS-INNER-HTML\""))
        .stdout(predicate::str::contains("\"reachability\": \"reachable\""))
        .stdout(predicate::str::contains("\"path_sensitivity\": \"tainted\""))
        .stdout(predicate::str::contains("\"source_kind\": \"express.req.query\""))
        .stdout(predicate::str::contains("\"framework\": \"express\""));
}

#[test]
fn js_eval_later_assignment_does_not_backpropagate_taint() {
    use std::fs;
    let tmp = tempfile::tempdir().unwrap();
    let rules_dir = tmp.path().join("rules");
    fs::create_dir_all(&rules_dir).unwrap();
    fs::write(
        rules_dir.join("js-eval.yml"),
        r#"
id:         CBR-JS-CODE-EVAL
title:      "eval() usage"
severity:   critical
languages:  [javascript]
message: |
  Passing dynamic input to eval is unsafe.
query: |
  (call_expression
    function: (identifier) @fn
    (#eq? @fn "eval")) @call
"#,
    ).unwrap();
    let src = tmp.path().join("ordered_eval.js");
    fs::write(
        &src,
        "const express = require('express');\nfunction run() {\n  let code = 'safe';\n  eval(code);\n  code = req.query.code;\n}\n",
    ).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", rules_dir.to_str().unwrap(), "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-JS-CODE-EVAL\""))
        .stdout(predicate::str::contains("\"reachability\": \"unknown\""))
        .stdout(predicate::str::contains("\"path_sensitivity_reason\": \"javascript_intra_function_no_source\""));
}

#[test]
fn js_sanitized_assignment_is_marked_guarded() {
    use std::fs;
    let manifest = env!("CARGO_MANIFEST_DIR");
    let rules  = format!("{manifest}/rules");
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("sanitized_innerhtml.js");
    fs::write(
        &src,
        "const express = require('express');\nfunction render() {\n  const html = req.query.html;\n  const safeHtml = DOMPurify.sanitize(html);\n  el.innerHTML = safeHtml;\n}\n",
    ).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", &rules, "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-JS-XSS-INNER-HTML\""))
        .stdout(predicate::str::contains("\"reachability\": \"unknown\""))
        .stdout(predicate::str::contains("\"path_sensitivity\": \"guarded\""))
        .stdout(predicate::str::contains("\"sanitizer_kind\": \"dompurify_sanitized\""));
}

#[test]
fn js_react_dangerous_html_is_framework_labeled() {
    use std::fs;
    let manifest = env!("CARGO_MANIFEST_DIR");
    let rules  = format!("{manifest}/rules");
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("component.jsx");
    fs::write(
        &src,
        "import React from 'react';\nexport function Card(props) { return <div dangerouslySetInnerHTML={{ __html: props.html }} />; }\n",
    ).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", &rules, "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-JS-REACT-DANGEROUS-HTML\""))
        .stdout(predicate::str::contains("\"framework\": \"react\""))
        .stdout(predicate::str::contains("\"sink_kind\": \"react.dangerously_set_inner_html\""))
        .stdout(predicate::str::contains("\"reachability\": \"unknown\""));
}

#[test]
fn ruby_rails_raw_params_is_marked_tainted_reachable() {
    use std::fs;
    let manifest = env!("CARGO_MANIFEST_DIR");
    let rules  = format!("{manifest}/rules");
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("view.rb");
    fs::write(
        &src,
        "name = params[:name]\nraw(name)\n",
    ).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", &rules, "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-RUBY-AVOID_RAW\""))
        .stdout(predicate::str::contains("\"framework\": \"rails\""))
        .stdout(predicate::str::contains("\"sink_kind\": \"rails.raw\""))
        .stdout(predicate::str::contains("\"source_kind\": \"rails.params\""))
        .stdout(predicate::str::contains("\"reachability\": \"reachable\""));
}

#[test]
fn python_flask_make_response_is_framework_labeled() {
    use std::fs;
    let manifest = env!("CARGO_MANIFEST_DIR");
    let rules  = format!("{manifest}/rules");
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("response.py");
    fs::write(
        &src,
        "import flask\nvalue = flask.request.args.get('name')\nflask.make_response(value)\n",
    ).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", &rules, "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-PYTH-MAKE_RESPONSE_WITH_UNKNOWN_CON\""))
        .stdout(predicate::str::contains("\"framework\": \"flask\""))
        .stdout(predicate::str::contains("\"sink_kind\": \"flask.make_response\""))
        .stdout(predicate::str::contains("\"source_kind\": \"flask.request.args\""))
        .stdout(predicate::str::contains("\"reachability\": \"reachable\""));
}

#[test]
fn python_flask_render_template_string_is_framework_labeled() {
    use std::fs;
    let manifest = env!("CARGO_MANIFEST_DIR");
    let rules  = format!("{manifest}/rules");
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("template.py");
    fs::write(
        &src,
        "import flask\npayload = flask.request.args.get('tpl')\nflask.render_template_string(payload)\n",
    ).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", &rules, "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-PYTH-RENDER_TEMPLATE_STRING\""))
        .stdout(predicate::str::contains("\"framework\": \"flask\""))
        .stdout(predicate::str::contains("\"sink_kind\": \"flask.render_template_string\""))
        .stdout(predicate::str::contains("\"source_kind\": \"flask.request.args\""))
        .stdout(predicate::str::contains("\"reachability\": \"reachable\""));
}

#[test]
fn python_flask_sqli_concat_is_sink_labeled() {
    use std::fs;
    let manifest = env!("CARGO_MANIFEST_DIR");
    let rules  = format!("{manifest}/rules");
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("flask_sqli.py");
    fs::write(
        &src,
        "from flask import request\nuser_id = request.args.get('id')\ncursor.execute(\"select * from users where id = \" + user_id)\n",
    ).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", &rules, "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-PY-SQLI-STRING-CONCAT\""))
        .stdout(predicate::str::contains("\"framework\": \"flask\""))
        .stdout(predicate::str::contains("\"sink_kind\": \"python.db.execute\""))
        .stdout(predicate::str::contains("\"source_kind\": \"flask.request.args\""))
        .stdout(predicate::str::contains("\"reachability\": \"reachable\""));
}

#[test]
fn js_express_document_write_is_sink_labeled() {
    use std::fs;
    let manifest = env!("CARGO_MANIFEST_DIR");
    let rules  = format!("{manifest}/rules");
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("express_write.js");
    fs::write(
        &src,
        "const express = require('express');\nconst html = req.query.html;\ndocument.write(html);\n",
    ).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", &rules, "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-JS-DOCUMENT-WRITE\""))
        .stdout(predicate::str::contains("\"framework\": \"express\""))
        .stdout(predicate::str::contains("\"sink_kind\": \"dom.document_write\""))
        .stdout(predicate::str::contains("\"source_kind\": \"express.req.query\""))
        .stdout(predicate::str::contains("\"reachability\": \"reachable\""));
}

#[test]
fn java_spring_redirect_param_is_sink_labeled() {
    use std::fs;
    let manifest = env!("CARGO_MANIFEST_DIR");
    let rules  = format!("{manifest}/rules");
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("Controller.java");
    fs::write(
        &src,
        "import org.springframework.web.bind.annotation.RequestParam;\nclass Controller {\n  String go(@RequestParam String next) {\n    return \"redirect:\" + next;\n  }\n}\n",
    ).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", &rules, "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-JAVA-SPRING_UNVALIDATED_REDIRECT\""))
        .stdout(predicate::str::contains("\"framework\": \"spring\""))
        .stdout(predicate::str::contains("\"sink_kind\": \"spring.redirect\""))
        .stdout(predicate::str::contains("\"source_kind\": \"spring.request_param\""))
        .stdout(predicate::str::contains("\"reachability\": \"reachable\""));
}

#[test]
fn ruby_render_text_params_is_sink_labeled() {
    use std::fs;
    let manifest = env!("CARGO_MANIFEST_DIR");
    let rules  = format!("{manifest}/rules");
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("view.rb");
    fs::write(
        &src,
        "body = params[:body]\nrender text: body\n",
    ).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", &rules, "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-RUBY-AVOID_RENDER_TEXT\""))
        .stdout(predicate::str::contains("\"framework\": \"rails\""))
        .stdout(predicate::str::contains("\"sink_kind\": \"rails.render_text\""))
        .stdout(predicate::str::contains("\"source_kind\": \"rails.params\""))
        .stdout(predicate::str::contains("\"reachability\": \"reachable\""));
}

#[test]
fn java_spring_script_engine_param_is_sink_labeled() {
    use std::fs;
    let manifest = env!("CARGO_MANIFEST_DIR");
    let rules  = format!("{manifest}/rules");
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("Controller.java");
    fs::write(
        &src,
        "import org.springframework.web.bind.annotation.RequestParam;\nclass Controller {\n  String go(@RequestParam String expr, javax.script.ScriptEngine engine) throws Exception {\n    engine.eval(expr);\n    return expr;\n  }\n}\n",
    ).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", &rules, "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-JAVA-SCRIPT_ENGINE_INJECTION\""))
        .stdout(predicate::str::contains("\"framework\": \"spring\""))
        .stdout(predicate::str::contains("\"sink_kind\": \"java.script_engine.eval\""))
        .stdout(predicate::str::contains("\"source_kind\": \"spring.request_param\""))
        .stdout(predicate::str::contains("\"reachability\": \"reachable\""));
}

#[test]
fn java_spring_prepare_statement_query_is_sink_labeled() {
    use std::fs;
    let manifest = env!("CARGO_MANIFEST_DIR");
    let rules  = format!("{manifest}/rules");
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("Controller.java");
    fs::write(
        &src,
        "import java.sql.Connection;\nimport java.sql.PreparedStatement;\nimport org.springframework.web.bind.annotation.RequestParam;\nclass Controller {\n  void run(@RequestParam String user, Connection conn) throws Exception {\n    String query = \"select * from users where name='\" + user + \"'\";\n    PreparedStatement ps = conn.prepareStatement(query);\n  }\n}\n",
    ).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", &rules, "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-JAVA-FIND_SQL_STRING_CONCATENATION\""))
        .stdout(predicate::str::contains("\"framework\": \"spring\""))
        .stdout(predicate::str::contains("\"sink_kind\": \"java.sql.prepare_statement\""))
        .stdout(predicate::str::contains("\"source_kind\": \"spring.request_param\""))
        .stdout(predicate::str::contains("\"reachability\": \"reachable\""));
}

#[test]
fn java_redirect_later_assignment_does_not_backpropagate_taint() {
    use std::fs;
    let tmp = tempfile::tempdir().unwrap();
    let rules_dir = tmp.path().join("rules");
    fs::create_dir_all(&rules_dir).unwrap();
    fs::write(
        rules_dir.join("java-redirect.yml"),
        r#"
id:        CBR-JAVA-SPRING_UNVALIDATED_REDIRECT
title:     "Spring redirect"
severity:  high
languages: ['java']
message: |
  redirect with user input
regex: 'return\s+"redirect:"\s*\+\s*[A-Za-z_][A-Za-z0-9_]*'
"#,
    ).unwrap();
    let src = tmp.path().join("Controller.java");
    fs::write(
        &src,
        "class Controller {\n  String go(javax.servlet.http.HttpServletRequest request) {\n    String next = \"home\";\n    return \"redirect:\" + next;\n    next = request.getParameter(\"next\");\n  }\n}\n",
    ).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", rules_dir.to_str().unwrap(), "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-JAVA-SPRING_UNVALIDATED_REDIRECT\""))
        .stdout(predicate::str::contains("\"reachability\": \"unknown\""))
        .stdout(predicate::str::contains("\"path_sensitivity\": \"no_source_detected\""));
}

#[test]
fn java_redirect_sanitized_assignment_is_marked_guarded() {
    use std::fs;
    let tmp = tempfile::tempdir().unwrap();
    let rules_dir = tmp.path().join("rules");
    fs::create_dir_all(&rules_dir).unwrap();
    fs::write(
        rules_dir.join("java-redirect.yml"),
        r#"
id:        CBR-JAVA-SPRING_UNVALIDATED_REDIRECT
title:     "Spring redirect"
severity:  high
languages: ['java']
message: |
  redirect with user input
regex: 'return\s+"redirect:"\s*\+\s*[A-Za-z_][A-Za-z0-9_]*'
"#,
    ).unwrap();
    let src = tmp.path().join("Controller.java");
    fs::write(
        &src,
        "import java.net.URLEncoder;\nclass Controller {\n  String go(javax.servlet.http.HttpServletRequest request) throws Exception {\n    String next = request.getParameter(\"next\");\n    String safe = URLEncoder.encode(next, \"UTF-8\");\n    return \"redirect:\" + safe;\n  }\n}\n",
    ).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", rules_dir.to_str().unwrap(), "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-JAVA-SPRING_UNVALIDATED_REDIRECT\""))
        .stdout(predicate::str::contains("\"reachability\": \"unknown\""))
        .stdout(predicate::str::contains("\"path_sensitivity\": \"guarded\""))
        .stdout(predicate::str::contains("\"sanitizer_kind\": \"spring.url_encode\""));
}

#[test]
fn ruby_render_inline_params_is_sink_labeled() {
    use std::fs;
    let manifest = env!("CARGO_MANIFEST_DIR");
    let rules  = format!("{manifest}/rules");
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("view.rb");
    fs::write(
        &src,
        "template = params[:template]\nrender inline: template\n",
    ).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", &rules, "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-RUBY-AVOID_RENDER_INLINE\""))
        .stdout(predicate::str::contains("\"framework\": \"rails\""))
        .stdout(predicate::str::contains("\"sink_kind\": \"rails.render_inline\""))
        .stdout(predicate::str::contains("\"source_kind\": \"rails.params\""))
        .stdout(predicate::str::contains("\"reachability\": \"reachable\""));
}

#[test]
fn ruby_content_tag_params_is_sink_labeled() {
    use std::fs;
    let manifest = env!("CARGO_MANIFEST_DIR");
    let rules  = format!("{manifest}/rules");
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("view.rb");
    fs::write(
        &src,
        "title = params[:title]\ncontent_tag(:div, title)\n",
    ).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", &rules, "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-RUBY-AVOID_CONTENT_TAG\""))
        .stdout(predicate::str::contains("\"framework\": \"rails\""))
        .stdout(predicate::str::contains("\"sink_kind\": \"rails.content_tag\""))
        .stdout(predicate::str::contains("\"source_kind\": \"rails.params\""))
        .stdout(predicate::str::contains("\"reachability\": \"reachable\""));
}

#[test]
fn ruby_raw_later_assignment_does_not_backpropagate_taint() {
    use std::fs;
    let tmp = tempfile::tempdir().unwrap();
    let rules_dir = tmp.path().join("rules");
    fs::create_dir_all(&rules_dir).unwrap();
    fs::write(
        rules_dir.join("ruby-raw.yml"),
        r#"
id:        CBR-RUBY-AVOID_RAW
title:     "Avoid Raw"
severity:  high
languages: ['ruby']
message: |
  raw on user input is unsafe
regex: 'raw\(.+\)'
"#,
    ).unwrap();
    let src = tmp.path().join("view.rb");
    fs::write(
        &src,
        "html = '<b>safe</b>'\nraw(html)\nhtml = params[:html]\n",
    ).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", rules_dir.to_str().unwrap(), "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-RUBY-AVOID_RAW\""))
        .stdout(predicate::str::contains("\"reachability\": \"unknown\""))
        .stdout(predicate::str::contains("\"path_sensitivity\": \"no_source_detected\""));
}

#[test]
fn ruby_raw_sanitized_assignment_is_marked_guarded() {
    use std::fs;
    let tmp = tempfile::tempdir().unwrap();
    let rules_dir = tmp.path().join("rules");
    fs::create_dir_all(&rules_dir).unwrap();
    fs::write(
        rules_dir.join("ruby-raw.yml"),
        r#"
id:        CBR-RUBY-AVOID_RAW
title:     "Avoid Raw"
severity:  high
languages: ['ruby']
message: |
  raw on user input is unsafe
regex: 'raw\(.+\)'
"#,
    ).unwrap();
    let src = tmp.path().join("view.rb");
    fs::write(
        &src,
        "html = params[:html]\nsafe = sanitize(html)\nraw(safe)\n",
    ).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", rules_dir.to_str().unwrap(), "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-RUBY-AVOID_RAW\""))
        .stdout(predicate::str::contains("\"reachability\": \"unknown\""))
        .stdout(predicate::str::contains("\"path_sensitivity\": \"guarded\""))
        .stdout(predicate::str::contains("\"sanitizer_kind\": \"rails.sanitize\""));
}

#[test]
fn ruby_raw_with_sanitize_is_marked_guarded() {
    use std::fs;
    let manifest = env!("CARGO_MANIFEST_DIR");
    let rules  = format!("{manifest}/rules");
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("view.rb");
    fs::write(
        &src,
        "raw(sanitize(params[:html]))\n",
    ).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", &rules, "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-RUBY-AVOID_RAW\""))
        .stdout(predicate::str::contains("\"sanitizer_kind\": \"rails.sanitize\""))
        .stdout(predicate::str::contains("\"reachability\": \"unknown\""))
        .stdout(predicate::str::contains("\"confidence\": \"low\""));
}

#[test]
fn python_make_response_with_escape_is_marked_guarded() {
    use std::fs;
    let manifest = env!("CARGO_MANIFEST_DIR");
    let rules  = format!("{manifest}/rules");
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("response.py");
    fs::write(
        &src,
        "import flask\nvalue = flask.request.args.get('name')\nflask.make_response(flask.escape(value))\n",
    ).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", &rules, "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-PYTH-MAKE_RESPONSE_WITH_UNKNOWN_CON\""))
        .stdout(predicate::str::contains("\"sanitizer_kind\": \"flask.escape\""))
        .stdout(predicate::str::contains("\"reachability\": \"unknown\""))
        .stdout(predicate::str::contains("\"confidence\": \"low\""));
}

#[test]
fn ruby_content_tag_with_strip_tags_is_marked_guarded() {
    use std::fs;
    let manifest = env!("CARGO_MANIFEST_DIR");
    let rules  = format!("{manifest}/rules");
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("view.rb");
    fs::write(
        &src,
        "title = params[:title]\ncontent_tag(:div, strip_tags(title))\n",
    ).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", &rules, "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-RUBY-AVOID_CONTENT_TAG\""))
        .stdout(predicate::str::contains("\"sanitizer_kind\": \"rails.strip_tags\""))
        .stdout(predicate::str::contains("\"reachability\": \"unknown\""))
        .stdout(predicate::str::contains("\"confidence\": \"low\""));
}

#[test]
fn go_command_later_assignment_does_not_backpropagate_taint() {
    use std::fs;
    let tmp = tempfile::tempdir().unwrap();
    let rules_dir = tmp.path().join("rules");
    fs::create_dir_all(&rules_dir).unwrap();
    fs::write(
        rules_dir.join("go-command.yml"),
        r#"
id:        CBR-GO-COMMAND_INJECTION
title:     "Go command injection"
severity:  critical
languages: ['go']
message: |
  exec.Command on user input is unsafe
query: |
  (call_expression
    function: (selector_expression
      (_) @pkg
      (field_identifier) @method (#match? @method "^Command(Context)?$"))
    arguments: (argument_list
      (_) @arg))
"#,
    ).unwrap();
    let src = tmp.path().join("handler.go");
    fs::write(
        &src,
        "package main\n\nimport (\n  \"os/exec\"\n)\n\nfunc run(c Context) {\n  cmd := \"date\"\n  exec.Command(cmd)\n  cmd = c.Query(\"cmd\")\n}\n",
    ).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", rules_dir.to_str().unwrap(), "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-GO-COMMAND_INJECTION\""))
        .stdout(predicate::str::contains("\"reachability\": \"unknown\""))
        .stdout(predicate::str::contains("\"path_sensitivity_reason\": \"go_intra_function_no_source\""));
}

#[test]
fn go_command_sanitized_assignment_is_marked_guarded() {
    use std::fs;
    let tmp = tempfile::tempdir().unwrap();
    let rules_dir = tmp.path().join("rules");
    fs::create_dir_all(&rules_dir).unwrap();
    fs::write(
        rules_dir.join("go-command.yml"),
        r#"
id:        CBR-GO-COMMAND_INJECTION
title:     "Go command injection"
severity:  critical
languages: ['go']
message: |
  exec.Command on user input is unsafe
query: |
  (call_expression
    function: (selector_expression
      (_) @pkg
      (field_identifier) @method (#match? @method "^Command(Context)?$"))
    arguments: (argument_list
      (_) @arg))
"#,
    ).unwrap();
    let src = tmp.path().join("handler.go");
    fs::write(
        &src,
        "package main\n\nimport (\n  \"net/url\"\n  \"os/exec\"\n)\n\nfunc run(c Context) {\n  cmd := c.Query(\"cmd\")\n  safe := url.QueryEscape(cmd)\n  exec.Command(safe)\n}\n",
    ).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", rules_dir.to_str().unwrap(), "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-GO-COMMAND_INJECTION\""))
        .stdout(predicate::str::contains("\"reachability\": \"unknown\""))
        .stdout(predicate::str::contains("\"path_sensitivity\": \"guarded\""))
        .stdout(predicate::str::contains("\"sanitizer_kind\": \"go.url_escape\""));
}

#[test]
fn duplicate_rules_collapse_to_one_finding() {
    use std::fs;
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("target");
    let rules_dir = tmp.path().join("rules");
    fs::create_dir_all(&target).unwrap();
    fs::create_dir_all(&rules_dir).unwrap();
    fs::write(target.join("app.py"), "eval(input())\n").unwrap();

    let rule = r#"id: CBR-TEST-DUP
title: Duplicate test
severity: high
languages: [python]
regex: 'eval\('
message: test
"#;
    fs::write(rules_dir.join("a.yml"), rule).unwrap();
    fs::write(rules_dir.join("b.yml"), rule).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", target.to_str().unwrap(), "--rules", rules_dir.to_str().unwrap(), "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-TEST-DUP\"").count(1));
}

#[test]
fn fixture_path_is_context_suppressed_and_fingerprinted() {
    use std::fs;
    let manifest = env!("CARGO_MANIFEST_DIR");
    let rules  = format!("{manifest}/rules");
    let tmp = tempfile::tempdir().unwrap();
    let fixtures_dir = tmp.path().join("tests").join("fixtures");
    fs::create_dir_all(&fixtures_dir).unwrap();
    let src = fixtures_dir.join("app.py");
    fs::write(&src, "from flask import request\nuser_code = request.args.get('code')\neval(user_code)\n").unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", &rules, "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"context_suppression\": \"test_fixture_path\""))
        .stdout(predicate::str::contains("\"finding_fingerprint\":"))
        .stdout(predicate::str::contains("\"confidence\": \"low\""));
}

#[test]
fn csharp_safe_wrapper_is_marked_low_confidence() {
    use std::fs;
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("target");
    let rules_dir = tmp.path().join("rules");
    fs::create_dir_all(&target).unwrap();
    fs::create_dir_all(&rules_dir).unwrap();
    fs::write(
        target.join("Controller.cs"),
        "using System.Web;\nclass C { string Go(string userInput) { return HttpUtility.HtmlEncode(userInput); } }\n",
    ).unwrap();

    let rule = r#"id: CBR-CSHARP-TEST
title: Csharp wrapper test
severity: medium
languages: [csharp]
regex: 'HtmlEncode'
message: test
"#;
    fs::write(rules_dir.join("a.yml"), rule).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", target.to_str().unwrap(), "--rules", rules_dir.to_str().unwrap(), "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-CSHARP-TEST\""))
        .stdout(predicate::str::contains("\"safe_wrapper_kind\": \"aspnet.html_encode\""))
        .stdout(predicate::str::contains("\"confidence\": \"low\""));
}

#[test]
fn generated_csharp_path_is_context_suppressed() {
    use std::fs;
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("Views");
    let rules_dir = tmp.path().join("rules");
    fs::create_dir_all(&target).unwrap();
    fs::create_dir_all(&rules_dir).unwrap();
    fs::write(
        target.join("Generated.g.cs"),
        "using System.Web;\nclass C { string Go(string userInput) { return Html.Encode(userInput); } }\n",
    ).unwrap();

    let rule = r#"id: CBR-CSHARP-GEN
title: Generated csharp test
severity: medium
languages: [csharp]
regex: 'Encode'
message: test
"#;
    fs::write(rules_dir.join("a.yml"), rule).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", rules_dir.to_str().unwrap(), "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"context_suppression\": \"generated_path\""))
        .stdout(predicate::str::contains("\"context_suppression_reason\": \"generated_dotnet_source\""))
        .stdout(predicate::str::contains("\"confidence\": \"low\""));
}

#[test]
fn csharp_sql_command_is_detected_but_local_execute_reader_collision_is_not() {
    use std::fs;
    let tmp = tempfile::tempdir().unwrap();
    let rules_dir = tmp.path().join("rules");
    fs::create_dir_all(&rules_dir).unwrap();
    fs::write(
        rules_dir.join("csharp-sql.yml"),
        r#"
id:        CBR-CSHA-SQL_INJECTION
title:     "SQL Injection via String Concatenation"
severity:  critical
languages: ['csharp']
cwe:       ['CWE-89']
message: |
  Detected raw SQL execution with string concatenation.
query: |
  (invocation_expression
    function: (member_access_expression
      expression: (_) @obj
      name: (identifier) @m (#match? @m "^Execute(Reader|Scalar|NonQuery|XmlReader|Sql)?$"))
    arguments: (argument_list
      (argument
        (binary_expression
          left: (_)
          operator: "+"
          right: (_))) @concat))
"#,
    ).unwrap();

    let vulnerable = tmp.path().join("RealController.cs");
    fs::write(
        &vulnerable,
        r#"
using Microsoft.Data.SqlClient;
class RealController {
    void Run(SqlConnection connection) {
        SqlCommand cmd = new SqlCommand();
        cmd.ExecuteReader("select * from users where id = " + Request.Query["id"]);
    }
}
"#,
    ).unwrap();

    let safe_collision = tmp.path().join("FakeController.cs");
    fs::write(
        &safe_collision,
        r#"
class FakeExecutor {
    public void ExecuteReader(string query) {}
}
class FakeController {
    void Run() {
        FakeExecutor exec = new FakeExecutor();
        exec.ExecuteReader("select * from users where id = " + Request.Query["id"]);
    }
}
"#,
    ).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", rules_dir.to_str().unwrap(), "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-CSHA-SQL_INJECTION\""))
        .stdout(predicate::str::contains("\"source_kind\": \"aspnet.request_query\""))
        .stdout(predicate::str::contains("\"sink_kind\": \"dotnet.sql.execute\""))
        .stdout(predicate::str::contains("FakeController.cs").not());
}

#[test]
fn csharp_html_raw_later_assignment_does_not_backpropagate_taint() {
    use std::fs;
    let tmp = tempfile::tempdir().unwrap();
    let rules_dir = tmp.path().join("rules");
    fs::create_dir_all(&rules_dir).unwrap();
    fs::write(
        rules_dir.join("csharp-raw.yml"),
        r#"
id:        CBR-CSHA-XSS_HTML_RAW
title:     "Cross-Site Scripting (XSS) via Html.Raw"
severity:  high
languages: ['csharp']
message: |
  Html.Raw on user input is unsafe.
query: |
  (invocation_expression
    function: (member_access_expression
      expression: (identifier) @obj (#eq? @obj "Html")
      name: (identifier) @method (#eq? @method "Raw"))
    arguments: (argument_list
      (argument) @arg))
"#,
    ).unwrap();
    let src = tmp.path().join("ordered_raw.cs");
    fs::write(
        &src,
        r#"
class Demo {
    void Run() {
        var html = "<b>safe</b>";
        Html.Raw(html);
        html = Request.Query["html"];
    }
}
"#,
    ).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", rules_dir.to_str().unwrap(), "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-CSHA-XSS_HTML_RAW\""))
        .stdout(predicate::str::contains("\"reachability\": \"unknown\""))
        .stdout(predicate::str::contains("\"path_sensitivity_reason\": \"csharp_intra_function_no_source\""));
}

#[test]
fn csharp_html_raw_sanitized_assignment_is_marked_guarded() {
    use std::fs;
    let tmp = tempfile::tempdir().unwrap();
    let rules_dir = tmp.path().join("rules");
    fs::create_dir_all(&rules_dir).unwrap();
    fs::write(
        rules_dir.join("csharp-raw.yml"),
        r#"
id:        CBR-CSHA-XSS_HTML_RAW
title:     "Cross-Site Scripting (XSS) via Html.Raw"
severity:  high
languages: ['csharp']
message: |
  Html.Raw on user input is unsafe.
query: |
  (invocation_expression
    function: (member_access_expression
      expression: (identifier) @obj (#eq? @obj "Html")
      name: (identifier) @method (#eq? @method "Raw"))
    arguments: (argument_list
      (argument) @arg))
"#,
    ).unwrap();
    let src = tmp.path().join("sanitized_raw.cs");
    fs::write(
        &src,
        r#"
using System.Web;
class Demo {
    void Run() {
        var html = Request.Query["html"];
        var safe = HttpUtility.HtmlEncode(html);
        Html.Raw(safe);
    }
}
"#,
    ).unwrap();

    Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", rules_dir.to_str().unwrap(), "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"rule_id\": \"CBR-CSHA-XSS_HTML_RAW\""))
        .stdout(predicate::str::contains("\"reachability\": \"unknown\""))
        .stdout(predicate::str::contains("\"path_sensitivity\": \"guarded\""))
        .stdout(predicate::str::contains("\"sanitizer_kind\": \"aspnet.html_encoded\""));
}

#[test]
fn python_interprocedural_taint_uses_resolved_import_targets() {
    use std::fs;
    use serde_json::Value;
    let tmp = tempfile::tempdir().unwrap();
    let rules_dir = tmp.path().join("rules");
    fs::create_dir_all(&rules_dir).unwrap();
    fs::write(
        rules_dir.join("python-eval.yml"),
        r#"
id:        CBR-PY-CODE-EVAL
title:     "Unsafe eval() usage"
severity:  critical
languages: ['python']
cwe:       ['CWE-94']
message: |
  Detected eval() on dynamic input.
query: |
  (call
    function: (identifier) @fn (#eq? @fn "eval")
    arguments: (argument_list (_) @arg))
"#,
    ).unwrap();

    fs::write(
        tmp.path().join("entry.py"),
        r#"
from flask import request
from helper import run

def handle():
    user = request.args.get("cmd")
    run(user)
"#,
    ).unwrap();

    fs::write(
        tmp.path().join("helper.py"),
        r#"
def run(data):
    eval(data)
"#,
    ).unwrap();

    fs::write(
        tmp.path().join("other.py"),
        r#"
def run(data):
    eval(data)
"#,
    ).unwrap();

    let output = Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", rules_dir.to_str().unwrap(), "--format", "json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "scan failed: {}", String::from_utf8_lossy(&output.stderr));

    let findings: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    let helper = findings.iter().find(|f| f["file"].as_str().is_some_and(|s| s.ends_with("helper.py"))).unwrap();
    assert_eq!(helper["evidence"]["source_kind"], "flask.request.args");
    assert_eq!(helper["evidence"]["path_sensitivity"], "tainted");
    assert_eq!(helper["reachability"], "reachable");

    let other = findings.iter().find(|f| f["file"].as_str().is_some_and(|s| s.ends_with("other.py"))).unwrap();
    assert!(other["evidence"].get("source_kind").is_none());
    assert_eq!(other["reachability"], "unknown");
}

#[test]
fn javascript_interprocedural_taint_uses_resolved_import_targets() {
    use std::fs;
    use serde_json::Value;
    let tmp = tempfile::tempdir().unwrap();
    let rules_dir = tmp.path().join("rules");
    fs::create_dir_all(&rules_dir).unwrap();
    fs::write(
        rules_dir.join("js-eval.yml"),
        r#"
id:         CBR-JS-CODE-EVAL
title:      "eval() usage"
severity:   critical
languages:  [javascript]
message: |
  Passing dynamic input to eval is unsafe.
query: |
  (call_expression
    function: (identifier) @fn
    (#eq? @fn "eval")) @call
"#,
    ).unwrap();

    fs::write(
        tmp.path().join("entry.js"),
        r#"
import { run } from './helper'
const user = req.query.cmd;
run(user);
"#,
    ).unwrap();

    fs::write(
        tmp.path().join("helper.js"),
        r#"
export function run(data) {
  eval(data);
}
"#,
    ).unwrap();

    fs::write(
        tmp.path().join("other.js"),
        r#"
export function run(data) {
  eval(data);
}
"#,
    ).unwrap();

    let output = Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", rules_dir.to_str().unwrap(), "--format", "json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "scan failed: {}", String::from_utf8_lossy(&output.stderr));

    let findings: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    let helper = findings.iter().find(|f| f["file"].as_str().is_some_and(|s| s.ends_with("helper.js"))).unwrap();
    assert_eq!(helper["evidence"]["source_kind"], "express.req.query");
    assert_eq!(helper["evidence"]["path_sensitivity"], "tainted");
    assert_eq!(helper["reachability"], "reachable");

    let other = findings.iter().find(|f| f["file"].as_str().is_some_and(|s| s.ends_with("other.js"))).unwrap();
    assert!(other["evidence"].get("source_kind").is_none());
    assert_eq!(other["reachability"], "unknown");
}

#[test]
fn java_interprocedural_taint_uses_resolved_import_targets() {
    use std::fs;
    use serde_json::Value;
    let tmp = tempfile::tempdir().unwrap();
    let rules_dir = tmp.path().join("rules");
    fs::create_dir_all(&rules_dir).unwrap();
    fs::create_dir_all(tmp.path().join("app/helper")).unwrap();
    fs::create_dir_all(tmp.path().join("app/other")).unwrap();
    fs::write(
        rules_dir.join("java-danger.yml"),
        r#"
id:         CBR-JAVA-SCRIPT_ENGINE_INJECTION
title:      "danger() usage"
severity:   critical
languages:  [java]
message: |
  Passing dynamic input to danger is unsafe.
query: |
  (method_invocation
    name: (identifier) @fn
    arguments: (argument_list (_) @arg)
    (#eq? @fn "danger")) @call
"#,
    ).unwrap();

    fs::write(
        tmp.path().join("app/Entry.java"),
        r#"
package app;
import app.helper.Runner;
class Entry {
    void handle(HttpServletRequest request) {
        String user = request.getParameter("cmd");
        Runner.run(user);
    }
}
"#,
    ).unwrap();

    fs::write(
        tmp.path().join("app/helper/Runner.java"),
        r#"
package app.helper;
class Runner {
    static void run(String data) {
        danger(data);
    }
    static void danger(String data) {
    }
}
"#,
    ).unwrap();

    fs::write(
        tmp.path().join("app/other/Runner.java"),
        r#"
package app.other;
class Runner {
    static void run(String data) {
        danger(data);
    }
    static void danger(String data) {
    }
}
"#,
    ).unwrap();

    let output = Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", rules_dir.to_str().unwrap(), "--format", "json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "scan failed: {}", String::from_utf8_lossy(&output.stderr));

    let findings: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    let helper = findings.iter().find(|f| f["file"].as_str().is_some_and(|s| s.ends_with("app/helper/Runner.java"))).unwrap();
    assert_eq!(helper["evidence"]["source_kind"], "spring.http_request_parameter");
    assert_eq!(helper["evidence"]["path_sensitivity"], "tainted");
    assert_eq!(helper["reachability"], "reachable");

    let other = findings.iter().find(|f| f["file"].as_str().is_some_and(|s| s.ends_with("app/other/Runner.java"))).unwrap();
    assert!(other["evidence"].get("source_kind").is_none());
    assert_eq!(other["reachability"], "unknown");
}

#[test]
fn go_interprocedural_taint_uses_resolved_import_targets() {
    use std::fs;
    use serde_json::Value;
    let tmp = tempfile::tempdir().unwrap();
    let rules_dir = tmp.path().join("rules");
    fs::create_dir_all(&rules_dir).unwrap();
    fs::create_dir_all(tmp.path().join("helper")).unwrap();
    fs::create_dir_all(tmp.path().join("other")).unwrap();
    fs::write(
        rules_dir.join("go-danger.yml"),
        r#"
id:         CBR-GO-COMMAND_INJECTION
title:      "danger() usage"
severity:   critical
languages:  [go]
message: |
  Passing dynamic input to danger is unsafe.
query: |
  (call_expression
    function: (identifier) @fn
    arguments: (argument_list (_) @arg)
    (#eq? @fn "danger")) @call
"#,
    ).unwrap();

    fs::write(
        tmp.path().join("entry.go"),
        r#"
package main
import helper "helper"
func handle(c *Context) {
    user := c.Query("cmd")
    helper.Run(user)
}
"#,
    ).unwrap();

    fs::write(
        tmp.path().join("helper/helper.go"),
        r#"
package helper
func Run(data string) {
    danger(data)
}
func danger(data string) {
}
"#,
    ).unwrap();

    fs::write(
        tmp.path().join("other/other.go"),
        r#"
package other
func Run(data string) {
    danger(data)
}
func danger(data string) {
}
"#,
    ).unwrap();

    let output = Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", rules_dir.to_str().unwrap(), "--format", "json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "scan failed: {}", String::from_utf8_lossy(&output.stderr));

    let findings: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    let helper = findings.iter().find(|f| f["file"].as_str().is_some_and(|s| s.ends_with("helper/helper.go"))).unwrap();
    assert_eq!(helper["evidence"]["source_kind"], "go.http.query");
    assert_eq!(helper["evidence"]["path_sensitivity"], "tainted");
    assert_eq!(helper["reachability"], "reachable");

    let other = findings.iter().find(|f| f["file"].as_str().is_some_and(|s| s.ends_with("other/other.go"))).unwrap();
    assert!(other["evidence"].get("source_kind").is_none());
    assert_eq!(other["reachability"], "unknown");
}

#[test]
fn ruby_interprocedural_taint_uses_resolved_import_targets() {
    use std::fs;
    use serde_json::Value;
    let tmp = tempfile::tempdir().unwrap();
    let rules_dir = tmp.path().join("rules");
    fs::create_dir_all(&rules_dir).unwrap();
    fs::write(
        rules_dir.join("ruby-raw.yml"),
        r#"
id:         CBR-RUBY-AVOID_RAW
title:      "raw() usage"
severity:   high
languages:  [ruby]
message: |
  Passing dynamic input to raw is unsafe.
regex:      '\braw\s*\([^)]+\)'
"#,
    ).unwrap();

    fs::write(
        tmp.path().join("entry.rb"),
        r#"
require_relative './helper'
value = params[:name]
Helper.run(value)
"#,
    ).unwrap();

    fs::write(
        tmp.path().join("helper.rb"),
        r#"
module Helper
  def self.run(data)
    raw(data)
  end
end
"#,
    ).unwrap();

    fs::write(
        tmp.path().join("other.rb"),
        r#"
module Other
  def self.run(data)
    raw(data)
  end
end
"#,
    ).unwrap();

    let output = Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", rules_dir.to_str().unwrap(), "--format", "json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "scan failed: {}", String::from_utf8_lossy(&output.stderr));

    let findings: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    let helper = findings.iter().find(|f| f["file"].as_str().is_some_and(|s| s.ends_with("helper.rb"))).unwrap();
    assert_eq!(helper["evidence"]["source_kind"], "rails.params");
    assert_eq!(helper["evidence"]["path_sensitivity"], "tainted");
    assert_eq!(helper["reachability"], "reachable");

    let other = findings.iter().find(|f| f["file"].as_str().is_some_and(|s| s.ends_with("other.rb"))).unwrap();
    assert!(other["evidence"].get("source_kind").is_none());
    assert_eq!(other["reachability"], "unknown");
}

#[test]
fn csharp_interprocedural_taint_uses_resolved_import_targets() {
    use std::fs;
    use serde_json::Value;
    let tmp = tempfile::tempdir().unwrap();
    let rules_dir = tmp.path().join("rules");
    fs::create_dir_all(&rules_dir).unwrap();
    fs::create_dir_all(tmp.path().join("Demo/Web")).unwrap();
    fs::create_dir_all(tmp.path().join("Demo/Other")).unwrap();
    fs::write(
        rules_dir.join("csharp-raw.yml"),
        r#"
id:        CBR-CSHA-XSS_HTML_RAW
title:     "Cross-Site Scripting (XSS) via Html.Raw"
severity:  high
languages: ['csharp']
message: |
  Html.Raw on user input is unsafe.
query: |
  (invocation_expression
    function: (member_access_expression
      expression: (identifier) @obj (#eq? @obj "Html")
      name: (identifier) @method (#eq? @method "Raw"))
    arguments: (argument_list
      (argument) @arg))
"#,
    ).unwrap();

    fs::write(
        tmp.path().join("Demo/Entry.cs"),
        r#"
using Helper = Demo.Web.Helper;
class Entry {
    void Handle() {
        var value = Request.Query["id"];
        Helper.Run(value);
    }
}
"#,
    ).unwrap();

    fs::write(
        tmp.path().join("Demo/Web/Helper.cs"),
        r#"
namespace Demo.Web;
class Helper {
    public static void Run(string data) {
        Html.Raw(data);
    }
}
"#,
    ).unwrap();

    fs::write(
        tmp.path().join("Demo/Other/Helper.cs"),
        r#"
namespace Demo.Other;
class Helper {
    public static void Run(string data) {
        Html.Raw(data);
    }
}
"#,
    ).unwrap();

    let output = Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", rules_dir.to_str().unwrap(), "--format", "json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "scan failed: {}", String::from_utf8_lossy(&output.stderr));

    let findings: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    let helper = findings.iter().find(|f| f["file"].as_str().is_some_and(|s| s.ends_with("Demo/Web/Helper.cs"))).unwrap();
    assert_eq!(helper["evidence"]["source_kind"], "aspnet.request_query");
    assert_eq!(helper["evidence"]["path_sensitivity"], "tainted");
    assert_eq!(helper["reachability"], "reachable");

    let other = findings.iter().find(|f| f["file"].as_str().is_some_and(|s| s.ends_with("Demo/Other/Helper.cs"))).unwrap();
    assert!(other["evidence"].get("source_kind").is_none());
    assert_eq!(other["reachability"], "unknown");
}

#[test]
fn treesitter_pattern_inside_limits_matches_to_enclosing_context() {
    use std::fs;
    use serde_json::Value;
    let tmp = tempfile::tempdir().unwrap();
    let rules_dir = tmp.path().join("rules");
    fs::create_dir_all(&rules_dir).unwrap();
    fs::write(
        rules_dir.join("python-eval-inside.yml"),
        r#"
id:        CBR-PY-CODE-EVAL
title:     "Unsafe eval() usage"
severity:  critical
languages: ['python']
cwe:       ['CWE-94']
message: |
  Detected eval() on dynamic input.
pattern_inside: "def dangerous"
query: |
  (call
    function: (identifier) @fn (#eq? @fn "eval")
    arguments: (argument_list (_) @arg))
"#,
    ).unwrap();

    fs::write(
        tmp.path().join("inside.py"),
        r#"
def dangerous():
    eval(user)

def safe():
    eval(user)
"#,
    ).unwrap();

    let output = Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", rules_dir.to_str().unwrap(), "--format", "json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "scan failed: {}", String::from_utf8_lossy(&output.stderr));
    let findings: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["line"], 3);
}

#[test]
fn treesitter_patterns_all_of_limit_query_matches() {
    use std::fs;
    use serde_json::Value;
    let tmp = tempfile::tempdir().unwrap();
    let rules_dir = tmp.path().join("rules");
    fs::create_dir_all(&rules_dir).unwrap();
    fs::write(
        rules_dir.join("python-eval-patterns.yml"),
        r#"
id:        CBR-PY-CODE-EVAL
title:     "Unsafe eval() usage"
severity:  critical
languages: ['python']
message: |
  Detected eval() on dynamic input.
patterns:
  - "eval("
  - "user"
query: |
  (call
    function: (identifier) @fn (#eq? @fn "eval")
    arguments: (argument_list (_) @arg))
"#,
    ).unwrap();

    fs::write(
        tmp.path().join("patterns.py"),
        r#"
eval(user)
eval(other)
"#,
    ).unwrap();

    let output = Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", rules_dir.to_str().unwrap(), "--format", "json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "scan failed: {}", String::from_utf8_lossy(&output.stderr));
    let findings: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["line"], 2);
}

#[test]
fn treesitter_pattern_not_excludes_query_match() {
    use std::fs;
    use serde_json::Value;
    let tmp = tempfile::tempdir().unwrap();
    let rules_dir = tmp.path().join("rules");
    fs::create_dir_all(&rules_dir).unwrap();
    fs::write(
        rules_dir.join("js-call-pattern-not.yml"),
        r#"
id:        CBR-JS-CALL-FILTER
title:     "Filtered JavaScript call"
severity:  medium
languages: ['javascript']
message: |
  Filtered JavaScript call.
pattern: "eval"
pattern_not: "safeEval"
query: |
  (call_expression
    function: (identifier) @fn
    arguments: (arguments (_) @arg)) @call
"#,
    ).unwrap();

    fs::write(
        tmp.path().join("pattern_not.js"),
        r#"
eval(user)
safeEval(user)
"#,
    ).unwrap();

    let output = Command::cargo_bin("cyscan").unwrap()
        .args(["scan", tmp.path().to_str().unwrap(), "--rules", rules_dir.to_str().unwrap(), "--format", "json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "scan failed: {}", String::from_utf8_lossy(&output.stderr));
    let findings: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["line"], 2);
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
