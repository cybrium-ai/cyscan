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
