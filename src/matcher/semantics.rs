use std::collections::{HashMap, HashSet};
use std::path::Path;

use regex::Regex;

use crate::lang::Lang;

#[derive(Debug, Clone)]
pub struct CallAssignment {
    pub ident: String,
    pub target: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ParamCallEdge {
    pub caller: String,
    pub callee: String,
    pub callee_arg_idx: usize,
    pub caller_param_idx: usize,
}

#[derive(Debug, Default, Clone)]
pub struct FileSemantics {
    pub module_identity: Option<String>,
    pub imported_modules: HashSet<String>,
    pub alias_to_module: HashMap<String, String>,
    pub imported_symbols: HashMap<String, String>,
    pub python_from_import_modules: HashMap<String, String>,
    pub js_namespace_imports: HashMap<String, String>,
    pub js_named_imports: HashMap<String, String>,
    pub frameworks: HashSet<String>,
    pub tainted_identifiers: HashMap<String, String>,
    pub sanitized_identifiers: HashMap<String, String>,
    /// Maps function names to the list of their parameter names.
    pub function_definitions: HashMap<String, Vec<String>>,
    /// List of (function_name, argument_index, source_kind) for calls in this file.
    pub tainted_calls: Vec<(String, usize, String)>,
    /// Call edges that propagate a caller parameter into a callee argument.
    pub param_call_edges: Vec<ParamCallEdge>,
    /// Functions that return one or more of their parameters by index.
    pub return_param_indices: HashMap<String, Vec<usize>>,
    /// Functions that directly return a source kind without caller-controlled params.
    pub direct_return_sources: HashMap<String, Vec<String>>,
    /// Functions that return sanitized versions of specific parameters.
    pub return_param_sanitizers: HashMap<String, Vec<(usize, String)>>,
    /// Functions that directly return sanitized source-derived values.
    pub direct_sanitized_returns: HashMap<String, Vec<String>>,
    /// Local variables assigned from resolved function calls.
    pub call_assignments: Vec<CallAssignment>,
    /// Maps identifiers (e.g. "db") to their inferred type/module (e.g. "sqlite3").
    pub variable_types: HashMap<String, String>,
}

pub fn extract(lang: Lang, source: &str) -> FileSemantics {
    extract_with_context(lang, source, None, None)
}

pub fn extract_with_context(
    lang: Lang,
    source: &str,
    path: Option<&Path>,
    base_path: Option<&Path>,
) -> FileSemantics {
    match lang {
        Lang::Python => extract_python(source, path, base_path),
        Lang::Javascript | Lang::Typescript => extract_javascript(source, path, base_path),
        Lang::Ruby => extract_ruby(source, path, base_path),
        Lang::Java => extract_java(source, path, base_path),
        Lang::Csharp => extract_csharp(source, path, base_path),
        Lang::Go => extract_go(source, path, base_path),
        Lang::Rust => extract_rust(source, path, base_path),
        Lang::Php => extract_php(source, path, base_path),
        Lang::Swift => extract_swift(source, path, base_path),
        Lang::Scala => extract_scala(source, path, base_path),
        Lang::C => extract_c(source, path, base_path),
        Lang::Bash => extract_bash(source, path, base_path),
        _ => FileSemantics::default(),
    }
}

fn extract_python(source: &str, path: Option<&Path>, base_path: Option<&Path>) -> FileSemantics {
    let mut semantics = FileSemantics::default();
    semantics.module_identity = python_module_identity(path, base_path);
    let module_identity = semantics.module_identity
        .clone()
        .unwrap_or_else(|| "local".to_string());

    let import_re = Regex::new(
        r"^\s*import\s+([A-Za-z_][A-Za-z0-9_\.]*)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?\s*$"
    ).unwrap();
    let from_re = Regex::new(
        r"^\s*from\s+([A-Za-z_][A-Za-z0-9_\.]*)\s+import\s+(.+?)\s*$"
    ).unwrap();
    let assign_re = Regex::new(
        r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$"
    ).unwrap();
    let def_re = Regex::new(r#"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\):"#).unwrap();
    let return_re = Regex::new(r#"^\s*return\s+(.+?)\s*$"#).unwrap();
    let direct_call_re = Regex::new(r#"([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)"#).unwrap();
    let member_call_re = Regex::new(r#"([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)"#).unwrap();
    let lines: Vec<&str> = source.lines().collect();
    let mut current_fn: Option<(String, usize, Vec<String>, HashMap<String, Result<usize, String>>)> = None;

    for raw_line in &lines {
        let indent = raw_line.chars().take_while(|c| c.is_whitespace()).count();
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if let Some((func_identity, fn_indent, params, local_taint)) = current_fn.as_mut() {
            if !line.is_empty() && indent > *fn_indent {
                if let Some(caps) = assign_re.captures(line) {
                    let ident = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
                    let rhs = caps.get(2).map(|m| m.as_str()).unwrap_or("").trim();
                    if !ident.is_empty() && !rhs.is_empty() {
                        if let Some(source_kind) = python_source_kind(rhs) {
                            semantics.tainted_identifiers.insert(ident.clone(), source_kind.to_string());
                            local_taint.insert(ident, Err(source_kind.to_string()));
                        } else if let Some(idx) = params.iter().position(|param| param == rhs) {
                            local_taint.insert(ident, Ok(idx));
                        } else if let Some(kind) = local_taint.get(rhs).cloned() {
                            if let Err(source_kind) = &kind {
                                semantics.tainted_identifiers.insert(ident.clone(), source_kind.clone());
                            }
                            local_taint.insert(ident, kind);
                        }
                    }
                }
                for caps in member_call_re.captures_iter(line) {
                    let object = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                    let method = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                    let args_raw = caps.get(3).map(|m| m.as_str()).unwrap_or("");
                    let Some(target) = resolve_python_call_target(&semantics, &module_identity, object, Some(method)) else {
                        continue;
                    };
                    record_param_call_edges(&mut semantics, func_identity, &target, args_raw, params, local_taint);
                    record_python_tainted_call(&mut semantics, &target, args_raw);
                }
                for caps in direct_call_re.captures_iter(line) {
                    let func_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                    let args_raw = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                    let Some(target) = resolve_python_call_target(&semantics, &module_identity, func_name, None) else {
                        continue;
                    };
                    record_param_call_edges(&mut semantics, func_identity, &target, args_raw, params, local_taint);
                    record_python_tainted_call(&mut semantics, &target, args_raw);
                }
                if let Some(caps) = return_re.captures(line) {
                    let expr = caps.get(1).map(|m| m.as_str()).unwrap_or("").trim();
                    record_return_semantics(&mut semantics, func_identity, expr, params, local_taint, Lang::Python, python_source_kind);
                }
                continue;
            }
            current_fn = None;
        }

        if line.is_empty() {
            continue;
        }

        if let Some(caps) = def_re.captures(line) {
            let func_name = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let params_raw = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let params: Vec<String> = params_raw.split(',')
                .map(|s| s.trim().split('=').next().unwrap_or("").trim().to_string())
                .filter(|s| !s.is_empty() && s != "self" && s != "cls")
                .collect();
            semantics.function_definitions.insert(
                format!("{module_identity}::{func_name}"),
                params,
            );
            current_fn = Some((
                format!("{module_identity}::{func_name}"),
                indent,
                semantics.function_definitions.get(&format!("{module_identity}::{func_name}")).cloned().unwrap_or_default(),
                HashMap::new(),
            ));
        }

        if let Some(caps) = import_re.captures(line) {
            let module = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            if module.is_empty() {
                continue;
            }
            semantics.imported_modules.insert(module.clone());
            let alias = caps.get(2)
                .map(|m| m.as_str().to_string())
                .unwrap_or_else(|| module.rsplit('.').next().unwrap_or(&module).to_string());
            semantics.alias_to_module.insert(alias, module);
            tag_python_frameworks(&mut semantics);
            continue;
        }

        if let Some(caps) = from_re.captures(line) {
            let module = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let imported = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            if module.is_empty() {
                continue;
            }
            semantics.imported_modules.insert(module.clone());

            for item in imported.split(',') {
                let item = item.trim().trim_matches(|c| c == '(' || c == ')');
                if item.is_empty() || item == "*" {
                    continue;
                }
                let mut parts = item.split_whitespace();
                let symbol = parts.next().unwrap_or("");
                if symbol.is_empty() {
                    continue;
                }
                let alias = match (parts.next(), parts.next()) {
                    (Some("as"), Some(alias)) => alias.to_string(),
                    _ => symbol.to_string(),
                };
                semantics.imported_symbols.insert(alias, format!("{module}.{symbol}"));
                semantics.python_from_import_modules.insert(symbol.to_string(), module.clone());
            }
            tag_python_frameworks(&mut semantics);
            continue;
        }

        if let Some(caps) = assign_re.captures(line) {
            let ident = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let rhs = caps.get(2).map(|m| m.as_str()).unwrap_or("").trim();
            if ident.is_empty() || rhs.is_empty() {
                continue;
            }

            if let Some(call_caps) = member_call_re.captures(rhs) {
                let object = call_caps.get(1).map(|m| m.as_str()).unwrap_or("");
                let method = call_caps.get(2).map(|m| m.as_str()).unwrap_or("");
                let args_raw = call_caps.get(3).map(|m| m.as_str()).unwrap_or("");
                if let Some(target) = resolve_python_call_target(&semantics, &module_identity, object, Some(method)) {
                    semantics.call_assignments.push(CallAssignment {
                        ident: ident.clone(),
                        target,
                        args: args_raw.split(',').map(|arg| arg.trim().to_string()).collect(),
                    });
                }
            } else if let Some(call_caps) = direct_call_re.captures(rhs) {
                let func_name = call_caps.get(1).map(|m| m.as_str()).unwrap_or("");
                let args_raw = call_caps.get(2).map(|m| m.as_str()).unwrap_or("");
                if let Some(target) = resolve_python_call_target(&semantics, &module_identity, func_name, None) {
                    semantics.call_assignments.push(CallAssignment {
                        ident: ident.clone(),
                        target,
                        args: args_raw.split(',').map(|arg| arg.trim().to_string()).collect(),
                    });
                }
            }

            // Type Inference: Look for common factory patterns
            if rhs.contains(".connect(") || rhs.contains(".Client(") || rhs.contains(".Session(") || rhs.contains(".create_engine(") {
                let parts: Vec<&str> = rhs.split('.').collect();
                if parts.len() > 1 {
                    let module = parts[0];
                    // If it's a known module or an alias
                    let resolved = semantics.alias_to_module.get(module).cloned().unwrap_or_else(|| module.to_string());
                    semantics.variable_types.insert(ident.clone(), resolved);
                }
            }

            if let Some(source_kind) = python_source_kind(rhs) {
                semantics.tainted_identifiers.insert(ident, source_kind.to_string());
            } else {
                for token in rhs.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.')) {
                    if let Some(source_kind) = semantics.tainted_identifiers.get(token) {
                        semantics.tainted_identifiers.insert(ident.clone(), source_kind.clone());
                        break;
                    }
                }
            }
        }
    }

    for raw_line in &lines {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        for caps in member_call_re.captures_iter(line) {
            let object = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let method = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let args_raw = caps.get(3).map(|m| m.as_str()).unwrap_or("");
            let Some(target) = resolve_python_call_target(&semantics, &module_identity, object, Some(method)) else {
                continue;
            };
            record_python_tainted_call(&mut semantics, &target, args_raw);
        }

        for caps in direct_call_re.captures_iter(line) {
            let func_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let args_raw = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let Some(target) = resolve_python_call_target(&semantics, &module_identity, func_name, None) else {
                continue;
            };
            record_python_tainted_call(&mut semantics, &target, args_raw);
        }
    }

    semantics
}

fn python_module_identity(path: Option<&Path>, base_path: Option<&Path>) -> Option<String> {
    let path = path?;
    let relative = base_path
        .and_then(|base| path.strip_prefix(base).ok())
        .unwrap_or(path);
    let mut parts: Vec<String> = relative
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();
    let last = parts.last_mut()?;
    if let Some(stripped) = last.strip_suffix(".py") {
        *last = stripped.to_string();
    }
    if parts.last().map(String::as_str) == Some("__init__") {
        parts.pop();
    }
    if parts.is_empty() {
        return None;
    }
    Some(parts.join("."))
}

fn resolve_python_call_target(
    semantics: &FileSemantics,
    module_identity: &str,
    head: &str,
    member: Option<&str>,
) -> Option<String> {
    match member {
        Some(method) => {
            let module = semantics.alias_to_module.get(head)?;
            Some(format!("{module}::{method}"))
        }
        None => {
            if let Some(imported) = semantics.imported_symbols.get(head) {
                return Some(qualified_symbol_identity(imported));
            }
            let local_target = format!("{module_identity}::{head}");
            if semantics.function_definitions.contains_key(&local_target) {
                return Some(local_target);
            }
            None
        }
    }
}

fn record_python_tainted_call(
    semantics: &mut FileSemantics,
    target: &str,
    args_raw: &str,
) {
    for (idx, arg) in args_raw.split(',').enumerate() {
        let arg = arg.trim();
        if let Some(source_kind) = semantics.tainted_identifiers.get(arg) {
            semantics.tainted_calls.push((target.to_string(), idx, source_kind.clone()));
        }
    }
}

fn qualified_symbol_identity(symbol: &str) -> String {
    if let Some((module, function)) = symbol.rsplit_once('.') {
        return format!("{module}::{function}");
    }
    symbol.to_string()
}

fn push_unique_usize(map: &mut HashMap<String, Vec<usize>>, key: &str, value: usize) {
    let values = map.entry(key.to_string()).or_default();
    if !values.contains(&value) {
        values.push(value);
    }
}

fn push_unique_string(map: &mut HashMap<String, Vec<String>>, key: &str, value: &str) {
    let values = map.entry(key.to_string()).or_default();
    if !values.iter().any(|v| v == value) {
        values.push(value.to_string());
    }
}

fn push_unique_param_sanitizer(
    map: &mut HashMap<String, Vec<(usize, String)>>,
    key: &str,
    idx: usize,
    sanitizer: &str,
) {
    let values = map.entry(key.to_string()).or_default();
    if !values.iter().any(|(existing_idx, existing_sanitizer)| *existing_idx == idx && existing_sanitizer == sanitizer) {
        values.push((idx, sanitizer.to_string()));
    }
}

fn record_return_semantics(
    semantics: &mut FileSemantics,
    func_identity: &str,
    expr: &str,
    params: &[String],
    local_taint: &HashMap<String, Result<usize, String>>,
    lang: Lang,
    source_kind: fn(&str) -> Option<&'static str>,
) {
    let expr = expr.trim();
    if expr.is_empty() {
        return;
    }
    if let Some(kind) = source_kind(expr) {
        push_unique_string(&mut semantics.direct_return_sources, func_identity, kind);
        return;
    }
    if let Some((idx, sanitizer)) = return_param_sanitizer(lang, expr, params, local_taint) {
        push_unique_param_sanitizer(&mut semantics.return_param_sanitizers, func_identity, idx, &sanitizer);
        return;
    }
    if let Some(sanitizer) = direct_return_sanitizer(lang, expr, local_taint) {
        push_unique_string(&mut semantics.direct_sanitized_returns, func_identity, &sanitizer);
        return;
    }
    if let Some(idx) = params.iter().position(|param| param == expr) {
        push_unique_usize(&mut semantics.return_param_indices, func_identity, idx);
        return;
    }
    if let Some(kind) = local_taint.get(expr) {
        match kind {
            Ok(idx) => push_unique_usize(&mut semantics.return_param_indices, func_identity, *idx),
            Err(source_kind) => push_unique_string(&mut semantics.direct_return_sources, func_identity, source_kind),
        }
    }
}

fn return_param_sanitizer(
    lang: Lang,
    expr: &str,
    params: &[String],
    local_taint: &HashMap<String, Result<usize, String>>,
) -> Option<(usize, String)> {
    let mut tainted = HashMap::<String, String>::new();
    let mut param_by_ident = HashMap::<String, usize>::new();
    for (idx, param) in params.iter().enumerate() {
        tainted.insert(param.clone(), "param".into());
        param_by_ident.insert(param.clone(), idx);
    }
    for (ident, kind) in local_taint {
        if let Ok(idx) = kind {
            tainted.insert(ident.clone(), "param".into());
            param_by_ident.insert(ident.clone(), *idx);
        }
    }
    let Some(sanitizer) = semantic_sanitizer_kind(lang, expr, &tainted) else {
        return None;
    };
    for token in semantic_tokens(expr) {
        if let Some(idx) = param_by_ident.get(token) {
            return Some((*idx, sanitizer));
        }
    }
    None
}

fn direct_return_sanitizer(
    lang: Lang,
    expr: &str,
    local_taint: &HashMap<String, Result<usize, String>>,
) -> Option<String> {
    let mut tainted = HashMap::<String, String>::new();
    for (ident, kind) in local_taint {
        if let Err(source_kind) = kind {
            tainted.insert(ident.clone(), source_kind.clone());
        }
    }
    semantic_sanitizer_kind(lang, expr, &tainted)
}

fn semantic_sanitizer_kind(
    lang: Lang,
    text: &str,
    tainted: &HashMap<String, String>,
) -> Option<String> {
    if !semantic_tokens(text).any(|token| tainted.contains_key(token)) {
        return None;
    }
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    match lang {
        Lang::Python => {
            if compact.contains("html.escape(") || compact.contains("django.utils.html.escape(") {
                return Some("escaped_input".into());
            }
            if compact.contains("markupsafe.escape(") || compact.contains("flask.escape(") {
                return Some("html_escaped".into());
            }
            if compact.contains("ast.literal_eval(") {
                return Some("literal_eval_guard".into());
            }
        }
        Lang::Javascript | Lang::Typescript => {
            if compact.contains("DOMPurify.sanitize(") {
                return Some("dompurify_sanitized".into());
            }
            if compact.contains("escapeHtml(") || compact.contains("he.encode(") {
                return Some("html_escaped".into());
            }
        }
        Lang::Csharp => {
            if compact.contains("HttpUtility.HtmlEncode(")
                || compact.contains("WebUtility.HtmlEncode(")
                || compact.contains("HtmlEncoder.Default.Encode(")
                || compact.contains("AntiXssEncoder.HtmlEncode(")
            {
                return Some("aspnet.html_encoded".into());
            }
            if compact.contains("Uri.EscapeDataString(")
                || compact.contains("HttpUtility.UrlEncode(")
                || compact.contains("WebUtility.UrlEncode(")
            {
                return Some("aspnet.url_encoded".into());
            }
        }
        Lang::Java => {
            if compact.contains("HtmlUtils.htmlEscape(") || compact.contains("ESAPI.encoder().encodeForHTML(") {
                return Some("java_html_encoded".into());
            }
            if compact.contains("UriUtils.encode(") || compact.contains("URLEncoder.encode(") {
                return Some("java_url_encoded".into());
            }
        }
        Lang::Ruby => {
            if compact.contains("sanitize(") {
                return Some("rails.sanitize".into());
            }
            if compact.contains("strip_tags(") {
                return Some("rails.strip_tags".into());
            }
            if compact.contains("ERB::Util.html_escape(") || compact.contains("html_escape(") {
                return Some("rails.html_escape".into());
            }
        }
        Lang::Go => {
            if compact.contains("template.HTMLEscapeString(") {
                return Some("go.html_escape".into());
            }
            if compact.contains("url.QueryEscape(") || compact.contains("template.URLQueryEscaper(") {
                return Some("go.url_escape".into());
            }
        }
        _ => {}
    }
    None
}

fn semantic_tokens(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
        .filter(|token| !token.is_empty())
}

fn record_param_call_edges(
    semantics: &mut FileSemantics,
    caller: &str,
    callee: &str,
    args_raw: &str,
    params: &[String],
    local_taint: &HashMap<String, Result<usize, String>>,
) {
    for (callee_arg_idx, arg) in args_raw.split(',').enumerate() {
        let arg = arg.trim();
        let caller_param_idx = if let Some(idx) = params.iter().position(|param| param == arg) {
            Some(idx)
        } else {
            match local_taint.get(arg) {
                Some(Ok(idx)) => Some(*idx),
                _ => None,
            }
        };
        let Some(caller_param_idx) = caller_param_idx else { continue };
        if !semantics.param_call_edges.iter().any(|edge|
            edge.caller == caller
                && edge.callee == callee
                && edge.callee_arg_idx == callee_arg_idx
                && edge.caller_param_idx == caller_param_idx
        ) {
            semantics.param_call_edges.push(ParamCallEdge {
                caller: caller.to_string(),
                callee: callee.to_string(),
                callee_arg_idx,
                caller_param_idx,
            });
        }
    }
}

fn path_module_identity(
    path: Option<&Path>,
    base_path: Option<&Path>,
    exts: &[&str],
) -> Option<String> {
    let path = path?;
    let relative = base_path
        .and_then(|base| path.strip_prefix(base).ok())
        .unwrap_or(path);
    let mut parts: Vec<String> = relative
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();
    let last = parts.last_mut()?;
    for ext in exts {
        if let Some(stripped) = last.strip_suffix(ext) {
            *last = stripped.to_string();
            break;
        }
    }
    if parts.last().map(String::as_str) == Some("index") {
        parts.pop();
    }
    if parts.is_empty() {
        return None;
    }
    Some(parts.join("."))
}

fn extract_javascript(source: &str, path: Option<&Path>, base_path: Option<&Path>) -> FileSemantics {
    let mut semantics = FileSemantics::default();
    semantics.module_identity = js_module_identity(path, base_path);
    let module_identity = semantics.module_identity
        .clone()
        .unwrap_or_else(|| "local".to_string());

    let import_ns_re = Regex::new(
        r#"^\s*import\s+\*\s+as\s+([A-Za-z_$][A-Za-z0-9_$]*)\s+from\s+['"]([^'"]+)['"]"#
    ).unwrap();
    let import_default_re = Regex::new(
        r#"^\s*import\s+([A-Za-z_$][A-Za-z0-9_$]*)\s+from\s+['"]([^'"]+)['"]"#
    ).unwrap();
    let import_named_re = Regex::new(
        r#"^\s*import\s+\{([^}]+)\}\s+from\s+['"]([^'"]+)['"]"#
    ).unwrap();
    let require_named_re = Regex::new(
        r#"^\s*(?:const|let|var)\s+\{([^}]+)\}\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)"#
    ).unwrap();
    let require_re = Regex::new(
        r#"^\s*(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)"#
    ).unwrap();
    let assign_re = Regex::new(
        r#"^\s*(?:const|let|var)?\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(.+?)\s*;?\s*$"#
    ).unwrap();
    let fn_re = Regex::new(
        r#"^\s*(?:export\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\((.*?)\)"#
    ).unwrap();
    let arrow_re = Regex::new(
        r#"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*\((.*?)\)\s*=>"# 
    ).unwrap();
    let function_expr_re = Regex::new(
        r#"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*function\s*\((.*?)\)"#
    ).unwrap();
    let return_re = Regex::new(r#"^\s*return\s+(.+?)\s*;?\s*$"#).unwrap();
    let direct_call_re = Regex::new(r#"([A-Za-z_$][A-Za-z0-9_$]*)\s*\((.*?)\)"#).unwrap();
    let member_call_re = Regex::new(r#"([A-Za-z_$][A-Za-z0-9_$]*)\.([A-Za-z_$][A-Za-z0-9_$]*)\s*\((.*?)\)"#).unwrap();
    let lines: Vec<&str> = source.lines().collect();
    let mut current_fn: Option<(String, Vec<String>, i32, HashMap<String, Result<usize, String>>)> = None;

    for raw_line in &lines {
        let line = raw_line.split("//").next().unwrap_or("").trim();
        if let Some((func_identity, params, brace_depth, local_taint)) = current_fn.as_mut() {
            if !line.is_empty() {
                if let Some(caps) = assign_re.captures(line) {
                    let ident = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
                    let rhs = caps.get(2).map(|m| m.as_str()).unwrap_or("").trim().trim_end_matches(';');
                    if !ident.is_empty() && !rhs.is_empty() {
                        if let Some(source_kind) = js_source_kind(rhs) {
                            semantics.tainted_identifiers.insert(ident.clone(), source_kind.to_string());
                            local_taint.insert(ident, Err(source_kind.to_string()));
                        } else if let Some(idx) = params.iter().position(|param| param == rhs) {
                            local_taint.insert(ident, Ok(idx));
                        } else if let Some(kind) = local_taint.get(rhs).cloned() {
                            if let Err(source_kind) = &kind {
                                semantics.tainted_identifiers.insert(ident.clone(), source_kind.clone());
                            }
                            local_taint.insert(ident, kind);
                        }
                    }
                }
                for caps in member_call_re.captures_iter(line) {
                    let object = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                    let method = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                    let args_raw = caps.get(3).map(|m| m.as_str()).unwrap_or("");
                    let Some(target) = resolve_js_call_target(&semantics, &module_identity, object, Some(method)) else {
                        continue;
                    };
                    record_param_call_edges(&mut semantics, func_identity, &target, args_raw, params, local_taint);
                    record_js_tainted_call(&mut semantics, &target, args_raw);
                }
                for caps in direct_call_re.captures_iter(line) {
                    let func_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                    let args_raw = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                    let Some(target) = resolve_js_call_target(&semantics, &module_identity, func_name, None) else {
                        continue;
                    };
                    record_param_call_edges(&mut semantics, func_identity, &target, args_raw, params, local_taint);
                    record_js_tainted_call(&mut semantics, &target, args_raw);
                }
                if let Some(caps) = return_re.captures(line) {
                    let expr = caps.get(1).map(|m| m.as_str()).unwrap_or("").trim().trim_end_matches(';');
                    record_return_semantics(&mut semantics, func_identity, expr, params, local_taint, Lang::Javascript, js_source_kind);
                }
            }
            *brace_depth += line.matches('{').count() as i32;
            *brace_depth -= line.matches('}').count() as i32;
            if *brace_depth <= 0 {
                current_fn = None;
            }
        }

        if line.is_empty() {
            continue;
        }

        if let Some(caps) = fn_re.captures(line)
            .or_else(|| arrow_re.captures(line))
            .or_else(|| function_expr_re.captures(line))
        {
            let func_name = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let params_raw = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let params: Vec<String> = params_raw.split(',')
                .map(|s| s.trim().split('=').next().unwrap_or("").trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !func_name.is_empty() {
                let func_identity = format!("{module_identity}::{func_name}");
                semantics.function_definitions.insert(func_identity.clone(), params.clone());
                if line.contains('{') {
                    current_fn = Some((
                        func_identity,
                        params,
                        line.matches('{').count() as i32 - line.matches('}').count() as i32,
                        HashMap::new(),
                    ));
                } else if let Some(arrow_pos) = line.find("=>") {
                    let expr = line[arrow_pos + 2..].trim().trim_end_matches(';');
                    let params = semantics.function_definitions
                        .get(&func_identity)
                        .cloned()
                        .unwrap_or_default();
                    let empty_local_taint = HashMap::new();
                    record_return_semantics(
                        &mut semantics,
                        &func_identity,
                        expr,
                        &params,
                        &empty_local_taint,
                        Lang::Javascript,
                        js_source_kind,
                    );
                }
            }
        }

        if let Some(caps) = import_ns_re.captures(line) {
            let alias = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let raw_module = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let module = resolve_js_import_target(raw_module, &module_identity);
            if !alias.is_empty() && !module.is_empty() {
                semantics.js_namespace_imports.insert(alias, module.clone());
                semantics.imported_modules.insert(module);
                tag_js_frameworks(&mut semantics);
            }
            continue;
        }

        if let Some(caps) = import_named_re.captures(line) {
            let names = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let raw_module = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let module = resolve_js_import_target(raw_module, &module_identity);
            if module.is_empty() {
                continue;
            }
            semantics.imported_modules.insert(module.clone());
            for item in names.split(',') {
                let item = item.trim();
                if item.is_empty() {
                    continue;
                }
                let mut parts = item.split_whitespace();
                let symbol = parts.next().unwrap_or("");
                let alias = match (parts.next(), parts.next()) {
                    (Some("as"), Some(alias)) => alias,
                    _ => symbol,
                };
                if !alias.is_empty() {
                    semantics.js_named_imports.insert(alias.to_string(), format!("{module}.{symbol}"));
                    semantics.imported_symbols.insert(alias.to_string(), format!("{module}.{symbol}"));
                }
            }
            tag_js_frameworks(&mut semantics);
            continue;
        }

        if let Some(caps) = import_default_re.captures(line) {
            let alias = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let raw_module = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let module = resolve_js_import_target(raw_module, &module_identity);
            if !alias.is_empty() && !module.is_empty() {
                semantics.js_namespace_imports.insert(alias.clone(), module.clone());
                semantics.alias_to_module.insert(alias, module.clone());
                semantics.imported_modules.insert(module);
                tag_js_frameworks(&mut semantics);
            }
            continue;
        }

        if let Some(caps) = require_named_re.captures(line) {
            let names = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let raw_module = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let module = resolve_js_import_target(raw_module, &module_identity);
            if module.is_empty() {
                continue;
            }
            semantics.imported_modules.insert(module.clone());
            for item in names.split(',') {
                let item = item.trim();
                if item.is_empty() {
                    continue;
                }
                let mut parts = item.split(':');
                let symbol = parts.next().unwrap_or("").trim();
                let alias = parts.next().unwrap_or(symbol).trim();
                if !alias.is_empty() && !symbol.is_empty() {
                    semantics.js_named_imports.insert(alias.to_string(), format!("{module}.{symbol}"));
                    semantics.imported_symbols.insert(alias.to_string(), format!("{module}.{symbol}"));
                }
            }
            tag_js_frameworks(&mut semantics);
            continue;
        }

        if let Some(caps) = require_re.captures(line) {
            let alias = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let raw_module = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let module = resolve_js_import_target(raw_module, &module_identity);
            if !alias.is_empty() && !module.is_empty() {
                semantics.js_namespace_imports.insert(alias.clone(), module.clone());
                semantics.alias_to_module.insert(alias, module.clone());
                semantics.imported_modules.insert(module);
                tag_js_frameworks(&mut semantics);
            }
            continue;
        }

        if let Some(caps) = assign_re.captures(line) {
            let ident = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let rhs = caps.get(2).map(|m| m.as_str()).unwrap_or("").trim();
            if ident.is_empty() || rhs.is_empty() {
                continue;
            }
            if let Some(call_caps) = member_call_re.captures(rhs) {
                let object = call_caps.get(1).map(|m| m.as_str()).unwrap_or("");
                let method = call_caps.get(2).map(|m| m.as_str()).unwrap_or("");
                let args_raw = call_caps.get(3).map(|m| m.as_str()).unwrap_or("");
                if let Some(target) = resolve_js_call_target(&semantics, &module_identity, object, Some(method)) {
                    semantics.call_assignments.push(CallAssignment {
                        ident: ident.clone(),
                        target,
                        args: args_raw.split(',').map(|arg| arg.trim().to_string()).collect(),
                    });
                }
            } else if let Some(call_caps) = direct_call_re.captures(rhs) {
                let func_name = call_caps.get(1).map(|m| m.as_str()).unwrap_or("");
                let args_raw = call_caps.get(2).map(|m| m.as_str()).unwrap_or("");
                if let Some(target) = resolve_js_call_target(&semantics, &module_identity, func_name, None) {
                    semantics.call_assignments.push(CallAssignment {
                        ident: ident.clone(),
                        target,
                        args: args_raw.split(',').map(|arg| arg.trim().to_string()).collect(),
                    });
                }
            }
            if let Some(source_kind) = js_source_kind(rhs) {
                semantics.tainted_identifiers.insert(ident, source_kind.to_string());
            } else {
                for token in rhs.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '$')) {
                    if let Some(source_kind) = semantics.tainted_identifiers.get(token) {
                        semantics.tainted_identifiers.insert(ident.clone(), source_kind.clone());
                        break;
                    }
                }
            }
        }
    }

    for raw_line in &lines {
        let line = raw_line.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        for caps in member_call_re.captures_iter(line) {
            let object = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let method = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let args_raw = caps.get(3).map(|m| m.as_str()).unwrap_or("");
            let Some(target) = resolve_js_call_target(&semantics, &module_identity, object, Some(method)) else {
                continue;
            };
            record_js_tainted_call(&mut semantics, &target, args_raw);
        }

        for caps in direct_call_re.captures_iter(line) {
            let func_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let args_raw = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let Some(target) = resolve_js_call_target(&semantics, &module_identity, func_name, None) else {
                continue;
            };
            record_js_tainted_call(&mut semantics, &target, args_raw);
        }
    }

    semantics
}

fn js_module_identity(path: Option<&Path>, base_path: Option<&Path>) -> Option<String> {
    let path = path?;
    let relative = base_path
        .and_then(|base| path.strip_prefix(base).ok())
        .unwrap_or(path);
    let mut parts: Vec<String> = relative
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();
    let last = parts.last_mut()?;
    for ext in [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"] {
        if let Some(stripped) = last.strip_suffix(ext) {
            *last = stripped.to_string();
            break;
        }
    }
    if parts.last().map(String::as_str) == Some("index") {
        parts.pop();
    }
    if parts.is_empty() {
        return None;
    }
    Some(parts.join("."))
}

fn resolve_js_import_target(raw_module: &str, module_identity: &str) -> String {
    if raw_module.starts_with("./") || raw_module.starts_with("../") {
        let mut base_parts: Vec<&str> = module_identity.split('.').collect();
        base_parts.pop();
        let mut rel = raw_module;
        while let Some(rest) = rel.strip_prefix("../") {
            rel = rest;
            if !base_parts.is_empty() {
                base_parts.pop();
            }
        }
        if let Some(rest) = rel.strip_prefix("./") {
            rel = rest;
        }
        let rel = rel.trim_end_matches(".js")
            .trim_end_matches(".jsx")
            .trim_end_matches(".ts")
            .trim_end_matches(".tsx");
        let rel_parts = rel.split('/').filter(|s| !s.is_empty() && *s != ".").collect::<Vec<_>>();
        let mut parts = base_parts.into_iter().map(str::to_string).collect::<Vec<_>>();
        parts.extend(rel_parts.into_iter().map(str::to_string));
        return parts.join(".");
    }
    raw_module.to_string()
}

fn resolve_js_call_target(
    semantics: &FileSemantics,
    module_identity: &str,
    head: &str,
    member: Option<&str>,
) -> Option<String> {
    match member {
        Some(method) => {
            let module = semantics.js_namespace_imports.get(head)
                .or_else(|| semantics.alias_to_module.get(head))?;
            Some(format!("{module}::{method}"))
        }
        None => {
            if let Some(imported) = semantics.imported_symbols.get(head) {
                return Some(qualified_symbol_identity(imported));
            }
            if let Some(imported) = semantics.js_named_imports.get(head) {
                return Some(qualified_symbol_identity(imported));
            }
            let local_target = format!("{module_identity}::{head}");
            if semantics.function_definitions.contains_key(&local_target) {
                return Some(local_target);
            }
            None
        }
    }
}

fn record_js_tainted_call(
    semantics: &mut FileSemantics,
    target: &str,
    args_raw: &str,
) {
    for (idx, arg) in args_raw.split(',').enumerate() {
        let arg = arg.trim();
        if let Some(source_kind) = semantics.tainted_identifiers.get(arg) {
            semantics.tainted_calls.push((target.to_string(), idx, source_kind.clone()));
        }
    }
}

fn extract_ruby(source: &str, path: Option<&Path>, base_path: Option<&Path>) -> FileSemantics {
    let mut semantics = FileSemantics::default();
    semantics.module_identity = path_module_identity(path, base_path, &[".rb"]);
    let module_identity = semantics.module_identity
        .clone()
        .unwrap_or_else(|| "local".to_string());
    let require_re = Regex::new(r#"^\s*require(?:_relative)?\s+['"]([^'"]+)['"]"#).unwrap();
    let require_relative_re = Regex::new(r#"^\s*require_relative\s+['"]([^'"]+)['"]"#).unwrap();
    let assign_re = Regex::new(
        r#"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$"#
    ).unwrap();
    let def_re = Regex::new(
        r#"^\s*def\s+(?:self\.)?([A-Za-z_][A-Za-z0-9_!?=]*)\s*(?:\((.*?)\))?"#
    ).unwrap();
    let return_re = Regex::new(r#"^\s*return\s+(.+?)\s*$"#).unwrap();
    let direct_call_re = Regex::new(r#"([A-Za-z_][A-Za-z0-9_!?=]*)\s*\((.*?)\)"#).unwrap();
    let member_call_re = Regex::new(r#"([A-Z][A-Za-z0-9_:]*)\s*[\.:]{1,2}\s*([A-Za-z_][A-Za-z0-9_!?=]*)\s*\((.*?)\)"#).unwrap();
    let lines: Vec<&str> = source.lines().collect();
    let mut current_fn: Option<(String, Vec<String>, i32, HashMap<String, Result<usize, String>>)> = None;

    if source.contains("params[")
        || source.contains("params.")
        || source.contains("ActionController")
        || source.contains("html_safe")
        || source.contains("render text:")
        || source.contains("raw(")
    {
        semantics.frameworks.insert("rails".into());
    }

    for raw_line in &lines {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if let Some((func_identity, params, depth, local_taint)) = current_fn.as_mut() {
            if !line.is_empty() {
                if let Some(caps) = assign_re.captures(line) {
                    let ident = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
                    let rhs = caps.get(2).map(|m| m.as_str()).unwrap_or("").trim();
                    if !ident.is_empty() && !rhs.is_empty() {
                        if let Some(source_kind) = ruby_source_kind(rhs) {
                            semantics.tainted_identifiers.insert(ident.clone(), source_kind.to_string());
                            local_taint.insert(ident, Err(source_kind.to_string()));
                        } else if let Some(idx) = params.iter().position(|param| param == rhs) {
                            local_taint.insert(ident, Ok(idx));
                        } else if let Some(kind) = local_taint.get(rhs).cloned() {
                            if let Err(source_kind) = &kind {
                                semantics.tainted_identifiers.insert(ident.clone(), source_kind.clone());
                            }
                            local_taint.insert(ident, kind);
                        } else {
                            for token in rhs.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':' )) {
                                if let Some(kind) = local_taint.get(token).cloned() {
                                    if let Err(source_kind) = &kind {
                                        semantics.tainted_identifiers.insert(ident.clone(), source_kind.clone());
                                    }
                                    local_taint.insert(ident.clone(), kind);
                                    break;
                                }
                            }
                        }
                    }
                }

                for caps in member_call_re.captures_iter(line) {
                    let object = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                    let method = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                    let args_raw = caps.get(3).map(|m| m.as_str()).unwrap_or("");
                    let Some(target) = resolve_ruby_call_target(&semantics, &module_identity, object, Some(method)) else {
                        continue;
                    };
                    record_param_call_edges(&mut semantics, func_identity, &target, args_raw, params, local_taint);
                    record_tainted_call(&mut semantics, &target, args_raw);
                }

                for caps in direct_call_re.captures_iter(line) {
                    let func_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                    let args_raw = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                    let Some(target) = resolve_ruby_call_target(&semantics, &module_identity, func_name, None) else {
                        continue;
                    };
                    record_param_call_edges(&mut semantics, func_identity, &target, args_raw, params, local_taint);
                    record_tainted_call(&mut semantics, &target, args_raw);
                }

                if let Some(caps) = return_re.captures(line) {
                    let expr = caps.get(1).map(|m| m.as_str()).unwrap_or("").trim();
                    record_return_semantics(&mut semantics, func_identity, expr, params, local_taint, Lang::Ruby, ruby_source_kind);
                }
            }

            if line.starts_with("def ") {
                *depth += 1;
            }
            if line == "end" {
                *depth -= 1;
                if *depth <= 0 {
                    current_fn = None;
                }
            }
            continue;
        }

        if line.is_empty() {
            continue;
        }

        if let Some(caps) = def_re.captures(line) {
            let func_name = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let params_raw = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let params: Vec<String> = params_raw.split(',')
                .map(|s| s.trim().split('=').next().unwrap_or("").trim().trim_start_matches('*').to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !func_name.is_empty() {
                let func_identity = format!("{module_identity}::{func_name}");
                semantics.function_definitions.insert(
                    func_identity.clone(),
                    params.clone(),
                );
                current_fn = Some((func_identity, params, 1, HashMap::new()));
            }
        }

        if let Some(caps) = require_re.captures(line) {
            let module = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            if !module.is_empty() {
                semantics.imported_modules.insert(module);
            }
        }

        if let Some(caps) = require_relative_re.captures(line) {
            let raw_module = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let module = resolve_ruby_import_target(raw_module, &module_identity);
            if !module.is_empty() {
                let constant = ruby_constant_for_module(&module);
                semantics.imported_modules.insert(module.clone());
                semantics.alias_to_module.insert(constant, module);
            }
        }

        if let Some(caps) = assign_re.captures(line) {
            let ident = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let rhs = caps.get(2).map(|m| m.as_str()).unwrap_or("").trim();
            if ident.is_empty() || rhs.is_empty() {
                continue;
            }
            if let Some(source_kind) = ruby_source_kind(rhs) {
                semantics.tainted_identifiers.insert(ident, source_kind.to_string());
            } else {
                for token in rhs.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':' )) {
                    if let Some(source_kind) = semantics.tainted_identifiers.get(token) {
                        semantics.tainted_identifiers.insert(ident.clone(), source_kind.clone());
                        break;
                    }
                }
            }
        }
    }

    for raw_line in &lines {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        for caps in member_call_re.captures_iter(line) {
            let object = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let method = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let args_raw = caps.get(3).map(|m| m.as_str()).unwrap_or("");
            let Some(target) = resolve_ruby_call_target(&semantics, &module_identity, object, Some(method)) else {
                continue;
            };
            record_tainted_call(&mut semantics, &target, args_raw);
        }

        for caps in direct_call_re.captures_iter(line) {
            let func_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let args_raw = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let Some(target) = resolve_ruby_call_target(&semantics, &module_identity, func_name, None) else {
                continue;
            };
            record_tainted_call(&mut semantics, &target, args_raw);
        }
    }

    semantics
}

fn resolve_ruby_import_target(raw_module: &str, module_identity: &str) -> String {
    resolve_relative_module_target(raw_module, module_identity, &[".rb"])
}

fn ruby_constant_for_module(module: &str) -> String {
    module.rsplit('.').next()
        .unwrap_or(module)
        .split('_')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<String>()
}

fn resolve_ruby_call_target(
    semantics: &FileSemantics,
    module_identity: &str,
    head: &str,
    member: Option<&str>,
) -> Option<String> {
    match member {
        Some(method) => {
            let module = semantics.alias_to_module.get(head)?;
            Some(format!("{module}::{method}"))
        }
        None => {
            let local_target = format!("{module_identity}::{head}");
            if semantics.function_definitions.contains_key(&local_target) {
                return Some(local_target);
            }
            None
        }
    }
}

fn extract_java(source: &str, path: Option<&Path>, base_path: Option<&Path>) -> FileSemantics {
    let mut semantics = FileSemantics::default();
    semantics.module_identity = java_module_identity(source, path, base_path);
    let module_identity = semantics.module_identity
        .clone()
        .unwrap_or_else(|| "local".to_string());
    let import_re = Regex::new(r#"^\s*import\s+([\w\.]+);"#).unwrap();
    let static_import_re = Regex::new(r#"^\s*import\s+static\s+([\w\.]+)\.([A-Za-z_][A-Za-z0-9_]*)\s*;"#).unwrap();
    let assign_re = Regex::new(
        r#"^\s*(?:[A-Za-z_][A-Za-z0-9_<>\[\]]*\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*;?\s*$"#
    ).unwrap();
    let method_re = Regex::new(
        r#"^\s*(?:public|private|protected)?\s*(?:static\s+)?(?:final\s+)?[A-Za-z_][A-Za-z0-9_<>\[\]]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)\s*\{"#
    ).unwrap();
    let return_re = Regex::new(r#"^\s*return\s+(.+?)\s*;?\s*$"#).unwrap();
    let direct_call_re = Regex::new(r#"([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)"#).unwrap();
    let member_call_re = Regex::new(r#"([A-Za-z_][A-Za-z0-9_\.]*)\.([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)"#).unwrap();
    let request_param_re = Regex::new(
        r#"@RequestParam(?:\([^)]*\))?\s+(?:final\s+)?(?:[A-Za-z_][A-Za-z0-9_<>\[\]]*\s+)+([A-Za-z_][A-Za-z0-9_]*)"#
    ).unwrap();
    let path_variable_re = Regex::new(
        r#"@PathVariable(?:\([^)]*\))?\s+(?:final\s+)?(?:[A-Za-z_][A-Za-z0-9_<>\[\]]*\s+)+([A-Za-z_][A-Za-z0-9_]*)"#
    ).unwrap();

    if source.contains("org.springframework")
        || source.contains("@RequestParam")
        || source.contains("@PathVariable")
        || source.contains("@RestController")
        || source.contains("@Controller")
        || source.contains("SpringApplication")
    {
        semantics.frameworks.insert("spring".into());
    }

    for caps in request_param_re.captures_iter(source) {
        if let Some(ident) = caps.get(1).map(|m| m.as_str()) {
            semantics.tainted_identifiers.insert(ident.to_string(), "spring.request_param".into());
        }
    }
    for caps in path_variable_re.captures_iter(source) {
        if let Some(ident) = caps.get(1).map(|m| m.as_str()) {
            semantics.tainted_identifiers.insert(ident.to_string(), "spring.path_variable".into());
        }
    }

    let lines: Vec<&str> = source.lines().collect();
    let mut current_fn: Option<(String, Vec<String>, i32, HashMap<String, Result<usize, String>>)> = None;

    for raw_line in &lines {
        let line = raw_line.split("//").next().unwrap_or("").trim();
        if let Some((func_identity, params, brace_depth, local_taint)) = current_fn.as_mut() {
            if !line.is_empty() {
                if let Some(caps) = assign_re.captures(line) {
                    let ident = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
                    let rhs = caps.get(2).map(|m| m.as_str()).unwrap_or("").trim().trim_end_matches(';');
                    if !ident.is_empty() && !rhs.is_empty() {
                        if let Some(source_kind) = java_source_kind(rhs) {
                            semantics.tainted_identifiers.insert(ident.clone(), source_kind.to_string());
                            local_taint.insert(ident, Err(source_kind.to_string()));
                        } else if let Some(idx) = params.iter().position(|param| param == rhs) {
                            local_taint.insert(ident, Ok(idx));
                        } else if let Some(kind) = local_taint.get(rhs).cloned() {
                            if let Err(source_kind) = &kind {
                                semantics.tainted_identifiers.insert(ident.clone(), source_kind.clone());
                            }
                            local_taint.insert(ident, kind);
                        } else {
                            for token in rhs.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.')) {
                                if let Some(kind) = local_taint.get(token).cloned() {
                                    if let Err(source_kind) = &kind {
                                        semantics.tainted_identifiers.insert(ident.clone(), source_kind.clone());
                                    }
                                    local_taint.insert(ident.clone(), kind);
                                    break;
                                }
                            }
                        }
                    }
                }

                for caps in member_call_re.captures_iter(line) {
                    let object = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                    let method = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                    let args_raw = caps.get(3).map(|m| m.as_str()).unwrap_or("");
                    let Some(target) = resolve_java_call_target(&semantics, &module_identity, object, Some(method)) else {
                        continue;
                    };
                    record_param_call_edges(&mut semantics, func_identity, &target, args_raw, params, local_taint);
                    record_tainted_call(&mut semantics, &target, args_raw);
                }

                for caps in direct_call_re.captures_iter(line) {
                    let func_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                    let args_raw = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                    let Some(target) = resolve_java_call_target(&semantics, &module_identity, func_name, None) else {
                        continue;
                    };
                    record_param_call_edges(&mut semantics, func_identity, &target, args_raw, params, local_taint);
                    record_tainted_call(&mut semantics, &target, args_raw);
                }

                if let Some(caps) = return_re.captures(line) {
                    let expr = caps.get(1).map(|m| m.as_str()).unwrap_or("").trim().trim_end_matches(';');
                    record_return_semantics(&mut semantics, func_identity, expr, params, local_taint, Lang::Java, java_source_kind);
                }
            }
            *brace_depth += line.matches('{').count() as i32;
            *brace_depth -= line.matches('}').count() as i32;
            if *brace_depth <= 0 {
                current_fn = None;
            }
        }

        if line.is_empty() {
            continue;
        }

        if let Some(caps) = method_re.captures(line) {
            let func_name = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let params_raw = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let params: Vec<String> = params_raw.split(',')
                .map(|param| param.trim())
                .filter(|param| !param.is_empty())
                .filter_map(java_param_name)
                .collect();
            if !func_name.is_empty() {
                let func_identity = format!("{module_identity}::{func_name}");
                semantics.function_definitions.insert(func_identity.clone(), params.clone());
                current_fn = Some((
                    func_identity,
                    params,
                    line.matches('{').count() as i32 - line.matches('}').count() as i32,
                    HashMap::new(),
                ));
            }
        }

        if let Some(caps) = static_import_re.captures(line) {
            let class_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let symbol = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            if !class_name.is_empty() && !symbol.is_empty() {
                semantics.imported_modules.insert(class_name.to_string());
                semantics.imported_symbols.insert(symbol.to_string(), format!("{class_name}.{symbol}"));
            }
            continue;
        }

        if let Some(caps) = import_re.captures(line) {
            let module = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            if !module.is_empty() {
                semantics.imported_modules.insert(module.clone());
                if let Some(symbol) = module.rsplit('.').next() {
                    semantics.imported_symbols.insert(symbol.to_string(), module);
                }
            }
        }

        if let Some(caps) = assign_re.captures(line) {
            let ident = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let rhs = caps.get(2).map(|m| m.as_str()).unwrap_or("").trim();
            if ident.is_empty() || rhs.is_empty() {
                continue;
            }
            if let Some(source_kind) = java_source_kind(rhs) {
                semantics.tainted_identifiers.insert(ident, source_kind.to_string());
            } else {
                for token in rhs.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.')) {
                    if let Some(source_kind) = semantics.tainted_identifiers.get(token) {
                        semantics.tainted_identifiers.insert(ident.clone(), source_kind.clone());
                        break;
                    }
                }
            }
        }
    }

    for raw_line in &lines {
        let line = raw_line.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        for caps in member_call_re.captures_iter(line) {
            let object = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let method = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let args_raw = caps.get(3).map(|m| m.as_str()).unwrap_or("");
            let Some(target) = resolve_java_call_target(&semantics, &module_identity, object, Some(method)) else {
                continue;
            };
            record_tainted_call(&mut semantics, &target, args_raw);
        }

        for caps in direct_call_re.captures_iter(line) {
            let func_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let args_raw = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let Some(target) = resolve_java_call_target(&semantics, &module_identity, func_name, None) else {
                continue;
            };
            record_tainted_call(&mut semantics, &target, args_raw);
        }
    }

    semantics
}

fn java_module_identity(source: &str, path: Option<&Path>, base_path: Option<&Path>) -> Option<String> {
    let fallback = path_module_identity(path, base_path, &[".java"]);
    let package_re = Regex::new(r#"^\s*package\s+([\w\.]+);"#).unwrap();
    let package = package_re.captures(source)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()));
    match (package, path.and_then(|p| p.file_stem()).map(|s| s.to_string_lossy().to_string())) {
        (Some(package), Some(stem)) if !stem.is_empty() => Some(format!("{package}.{stem}")),
        _ => fallback,
    }
}

fn java_param_name(param: &str) -> Option<String> {
    let cleaned = param.split('=').next()?.trim();
    let tokens: Vec<&str> = cleaned.split_whitespace().collect();
    tokens.last()
        .map(|name| name.trim_matches(|c| c == ',' || c == ')').to_string())
        .filter(|name| !name.is_empty() && *name != "final")
}

fn resolve_java_call_target(
    semantics: &FileSemantics,
    module_identity: &str,
    head: &str,
    member: Option<&str>,
) -> Option<String> {
    match member {
        Some(method) => {
            if let Some(imported) = semantics.imported_symbols.get(head) {
                return Some(format!("{imported}::{method}"));
            }
            if semantics.imported_modules.contains(head) {
                return Some(format!("{head}::{method}"));
            }
            None
        }
        None => {
            if let Some(imported) = semantics.imported_symbols.get(head) {
                return Some(qualified_symbol_identity(imported));
            }
            let local_target = format!("{module_identity}::{head}");
            if semantics.function_definitions.contains_key(&local_target) {
                return Some(local_target);
            }
            None
        }
    }
}

fn tag_python_frameworks(semantics: &mut FileSemantics) {
    if semantics.imported_modules.iter().any(|m| m.starts_with("django")) {
        semantics.frameworks.insert("django".into());
    }
    if semantics.imported_modules.iter().any(|m| m.starts_with("flask")) {
        semantics.frameworks.insert("flask".into());
    }
}

fn tag_js_frameworks(semantics: &mut FileSemantics) {
    if semantics.imported_modules.iter().any(|m| m == "express") {
        semantics.frameworks.insert("express".into());
    }
    if semantics.imported_modules.iter().any(|m| m == "react") {
        semantics.frameworks.insert("react".into());
    }
}

fn python_source_kind(rhs: &str) -> Option<&'static str> {
    let compact: String = rhs.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.contains("request.args.get(") || compact.contains("flask.request.args.get(") {
        return Some("flask.request.args");
    }
    if compact.contains("request.form.get(") || compact.contains("flask.request.form.get(") {
        return Some("flask.request.form");
    }
    if compact.contains("request.GET.get(") || compact.contains("request.GET[") {
        return Some("django.request.GET");
    }
    if compact.contains("request.POST.get(") || compact.contains("request.POST[") {
        return Some("django.request.POST");
    }
    if compact.contains("input(") {
        return Some("python.input");
    }
    None
}

fn js_source_kind(rhs: &str) -> Option<&'static str> {
    let compact: String = rhs.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.contains("req.query.") || compact.contains("request.query.") {
        return Some("express.req.query");
    }
    if compact.contains("req.params.") || compact.contains("request.params.") {
        return Some("express.req.params");
    }
    if compact.contains("req.body.") || compact.contains("request.body.") {
        return Some("express.req.body");
    }
    None
}

fn ruby_source_kind(rhs: &str) -> Option<&'static str> {
    let compact: String = rhs.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.contains("params[") || compact.contains("params.") {
        return Some("rails.params");
    }
    None
}

fn java_source_kind(rhs: &str) -> Option<&'static str> {
    let compact: String = rhs.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.contains("request.getParameter(") {
        return Some("spring.http_request_parameter");
    }
    None
}

fn extract_csharp(source: &str, path: Option<&Path>, base_path: Option<&Path>) -> FileSemantics {
    let mut semantics = FileSemantics::default();
    semantics.module_identity = csharp_module_identity(source, path, base_path);
    let module_identity = semantics.module_identity
        .clone()
        .unwrap_or_else(|| "local".to_string());

    let using_re = Regex::new(r"^\s*using\s+([A-Za-z_][A-Za-z0-9_\.]*)\s*;").unwrap();
    let using_static_re = Regex::new(r#"^\s*using\s+static\s+([A-Za-z_][A-Za-z0-9_\.]*)\s*;"#).unwrap();
    let using_alias_re = Regex::new(r#"^\s*using\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_\.]*)\s*;"#).unwrap();
    let assign_re = Regex::new(r#"^\s*(?:[A-Za-z_][A-Za-z0-9_<>\[\]]*\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*;?\s*$"#).unwrap();
    let explicit_decl_re = Regex::new(
        r#"^\s*([A-Za-z_][A-Za-z0-9_<>\.\[\]]*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*;?\s*$"#
    ).unwrap();
    let new_type_re = Regex::new(r#"new\s+([A-Za-z_][A-Za-z0-9_<>\.]*)\s*\("#).unwrap();
    let method_re = Regex::new(
        r#"^\s*(?:public|private|protected|internal)?\s*(?:static\s+)?(?:async\s+)?(?:sealed\s+)?(?:override\s+)?[A-Za-z_][A-Za-z0-9_<>\.\[\]]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)\s*\{"#
    ).unwrap();
    let return_re = Regex::new(r#"^\s*return\s+(.+?)\s*;?\s*$"#).unwrap();
    let direct_call_re = Regex::new(r#"([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)"#).unwrap();
    let member_call_re = Regex::new(r#"([A-Za-z_][A-Za-z0-9_\.]*)\.([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)"#).unwrap();
    let lines: Vec<&str> = source.lines().collect();
    let mut current_fn: Option<(String, Vec<String>, i32, HashMap<String, Result<usize, String>>)> = None;

    for raw_line in &lines {
        let line = raw_line.split("//").next().unwrap_or("").trim();
        if let Some((func_identity, params, brace_depth, local_taint)) = current_fn.as_mut() {
            if !line.is_empty() {
                if let Some(caps) = assign_re.captures(line) {
                    let ident = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
                    let rhs = caps.get(2).map(|m| m.as_str()).unwrap_or("").trim().trim_end_matches(';');
                    if !ident.is_empty() && !rhs.is_empty() {
                        if let Some(source_kind) = csharp_source_kind(rhs) {
                            semantics.tainted_identifiers.insert(ident.clone(), source_kind.to_string());
                            local_taint.insert(ident, Err(source_kind.to_string()));
                        } else if let Some(idx) = params.iter().position(|param| param == rhs) {
                            local_taint.insert(ident, Ok(idx));
                        } else if let Some(kind) = local_taint.get(rhs).cloned() {
                            if let Err(source_kind) = &kind {
                                semantics.tainted_identifiers.insert(ident.clone(), source_kind.clone());
                            }
                            local_taint.insert(ident, kind);
                        } else {
                            for token in rhs.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.')) {
                                if let Some(kind) = local_taint.get(token).cloned() {
                                    if let Err(source_kind) = &kind {
                                        semantics.tainted_identifiers.insert(ident.clone(), source_kind.clone());
                                    }
                                    local_taint.insert(ident.clone(), kind);
                                    break;
                                }
                            }
                        }
                    }
                }

                for caps in member_call_re.captures_iter(line) {
                    let object = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                    let method = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                    let args_raw = caps.get(3).map(|m| m.as_str()).unwrap_or("");
                    let Some(target) = resolve_csharp_call_target(&semantics, &module_identity, object, Some(method)) else {
                        continue;
                    };
                    record_param_call_edges(&mut semantics, func_identity, &target, args_raw, params, local_taint);
                    record_tainted_call(&mut semantics, &target, args_raw);
                }

                for caps in direct_call_re.captures_iter(line) {
                    let func_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                    let args_raw = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                    let Some(target) = resolve_csharp_call_target(&semantics, &module_identity, func_name, None) else {
                        continue;
                    };
                    record_param_call_edges(&mut semantics, func_identity, &target, args_raw, params, local_taint);
                    record_tainted_call(&mut semantics, &target, args_raw);
                }

                if let Some(caps) = return_re.captures(line) {
                    let expr = caps.get(1).map(|m| m.as_str()).unwrap_or("").trim().trim_end_matches(';');
                    record_return_semantics(&mut semantics, func_identity, expr, params, local_taint, Lang::Csharp, csharp_source_kind);
                }
            }
            *brace_depth += line.matches('{').count() as i32;
            *brace_depth -= line.matches('}').count() as i32;
            if *brace_depth <= 0 {
                current_fn = None;
            }
        }

        if line.is_empty() {
            continue;
        }

        if let Some(caps) = method_re.captures(line) {
            let func_name = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let params_raw = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let params: Vec<String> = params_raw.split(',')
                .map(|param| param.trim())
                .filter(|param| !param.is_empty())
                .filter_map(csharp_param_name)
                .collect();
            if !func_name.is_empty() {
                let func_identity = format!("{module_identity}::{func_name}");
                semantics.function_definitions.insert(func_identity.clone(), params.clone());
                current_fn = Some((
                    func_identity,
                    params,
                    line.matches('{').count() as i32 - line.matches('}').count() as i32,
                    HashMap::new(),
                ));
            }
        }

        if let Some(caps) = using_static_re.captures(line) {
            let target = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            if !target.is_empty() {
                semantics.imported_modules.insert(target);
            }
            continue;
        }

        if let Some(caps) = using_alias_re.captures(line) {
            let alias = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let target = caps.get(2).map(|m| m.as_str()).unwrap_or("").to_string();
            if !alias.is_empty() && !target.is_empty() {
                semantics.alias_to_module.insert(alias.clone(), target.clone());
                semantics.imported_symbols.insert(alias, target);
            }
            continue;
        }

        if let Some(caps) = using_re.captures(line) {
            let namespace = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            semantics.imported_modules.insert(namespace.clone());
            if namespace.starts_with("Microsoft.AspNetCore") {
                semantics.frameworks.insert("aspnet".into());
            }
            continue;
        }

        if let Some(caps) = explicit_decl_re.captures(line) {
            let declared_type = caps.get(1).map(|m| m.as_str()).unwrap_or("").trim();
            let ident = caps.get(2).map(|m| m.as_str()).unwrap_or("").to_string();
            let rhs = caps.get(3).map(|m| m.as_str()).unwrap_or("").trim();
            if !ident.is_empty() {
                if let Some(command_type) = csharp_db_command_type_from_decl(declared_type, rhs) {
                    semantics.variable_types.insert(ident.clone(), command_type);
                } else if let Some(command_type) = csharp_db_command_type_from_rhs(rhs) {
                    semantics.variable_types.insert(ident.clone(), command_type);
                }
            }
        } else if let Some(caps) = assign_re.captures(line) {
            let ident = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let rhs = caps.get(2).map(|m| m.as_str()).unwrap_or("").trim();
            if !ident.is_empty() {
                if let Some(command_type) = csharp_db_command_type_from_rhs(rhs) {
                    semantics.variable_types.insert(ident.clone(), command_type);
                } else if let Some(new_type) = new_type_re.captures(rhs)
                    .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()))
                {
                    if csharp_is_db_command_type(&new_type) {
                        semantics.variable_types.insert(ident.clone(), new_type);
                    }
                }
            }
        }

        if let Some(caps) = assign_re.captures(line) {
            let ident = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let rhs = caps.get(2).map(|m| m.as_str()).unwrap_or("").trim();
            if ident.is_empty() || rhs.is_empty() {
                continue;
            }
            if let Some(source_kind) = csharp_source_kind(rhs) {
                semantics.tainted_identifiers.insert(ident, source_kind.to_string());
            } else {
                for token in rhs.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.')) {
                    if let Some(source_kind) = semantics.tainted_identifiers.get(token) {
                        semantics.tainted_identifiers.insert(ident.clone(), source_kind.clone());
                        break;
                    }
                }
            }
        }
    }

    if source.contains("Microsoft.AspNetCore") || source.contains("IActionResult") || source.contains("ApiController") {
        semantics.frameworks.insert("aspnet".into());
    }

    for raw_line in &lines {
        let line = raw_line.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        for caps in member_call_re.captures_iter(line) {
            let object = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let method = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let args_raw = caps.get(3).map(|m| m.as_str()).unwrap_or("");
            let Some(target) = resolve_csharp_call_target(&semantics, &module_identity, object, Some(method)) else {
                continue;
            };
            record_tainted_call(&mut semantics, &target, args_raw);
        }

        for caps in direct_call_re.captures_iter(line) {
            let func_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let args_raw = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let Some(target) = resolve_csharp_call_target(&semantics, &module_identity, func_name, None) else {
                continue;
            };
            record_tainted_call(&mut semantics, &target, args_raw);
        }
    }

    semantics
}

fn csharp_module_identity(source: &str, path: Option<&Path>, base_path: Option<&Path>) -> Option<String> {
    let fallback = path_module_identity(path, base_path, &[".cs"]);
    let namespace_re = Regex::new(r#"^\s*namespace\s+([A-Za-z_][A-Za-z0-9_\.]*)"#).unwrap();
    let namespace = namespace_re.captures(source)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()));
    match (namespace, path.and_then(|p| p.file_stem()).map(|s| s.to_string_lossy().to_string())) {
        (Some(namespace), Some(stem)) if !stem.is_empty() => Some(format!("{namespace}.{stem}")),
        _ => fallback,
    }
}

fn csharp_param_name(param: &str) -> Option<String> {
    let cleaned = param.split('=').next()?.trim();
    let tokens: Vec<&str> = cleaned.split_whitespace().collect();
    tokens.last()
        .map(|name| name.trim_start_matches('@').to_string())
        .filter(|name| !name.is_empty())
}

fn resolve_csharp_call_target(
    semantics: &FileSemantics,
    module_identity: &str,
    head: &str,
    member: Option<&str>,
) -> Option<String> {
    match member {
        Some(method) => {
            if let Some(module) = semantics.alias_to_module.get(head) {
                return Some(format!("{module}::{method}"));
            }
            None
        }
        None => {
            if let Some(imported) = semantics.imported_symbols.get(head) {
                return Some(qualified_symbol_identity(imported));
            }
            let local_target = format!("{module_identity}::{head}");
            if semantics.function_definitions.contains_key(&local_target) {
                return Some(local_target);
            }
            None
        }
    }
}

fn extract_go(source: &str, path: Option<&Path>, base_path: Option<&Path>) -> FileSemantics {
    let mut semantics = FileSemantics::default();
    semantics.module_identity = go_module_identity(path, base_path);
    let module_identity = semantics.module_identity
        .clone()
        .unwrap_or_else(|| "local".to_string());
    let single_import_re = Regex::new(r#"^\s*import\s+(?:(\w+)\s+)?"([^"]+)""#).unwrap();
    let block_import_re = Regex::new(r#"^\s*(?:(\w+)\s+)?"([^"]+)""#).unwrap();
    let assign_re = Regex::new(
        r#"^\s*(?:var\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?::=|=)\s*(.+?)\s*$"#
    ).unwrap();
    let func_re = Regex::new(r#"^\s*func\s+(?:\([^)]+\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)"#).unwrap();
    let return_re = Regex::new(r#"^\s*return\s+(.+?)\s*$"#).unwrap();
    let direct_call_re = Regex::new(r#"([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)"#).unwrap();
    let member_call_re = Regex::new(r#"([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)"#).unwrap();
    let mut in_import_block = false;
    let lines: Vec<&str> = source.lines().collect();
    let mut current_fn: Option<(String, Vec<String>, i32, HashMap<String, Result<usize, String>>)> = None;

    for raw_line in &lines {
        let line = raw_line.split("//").next().unwrap_or("").trim();
        if let Some((func_identity, params, brace_depth, local_taint)) = current_fn.as_mut() {
            if !line.is_empty() {
                if let Some(caps) = assign_re.captures(line) {
                    let ident = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
                    let rhs = caps.get(2).map(|m| m.as_str()).unwrap_or("").trim();
                    if !ident.is_empty() && !rhs.is_empty() {
                        if let Some(source_kind) = go_source_kind(rhs) {
                            semantics.tainted_identifiers.insert(ident.clone(), source_kind.to_string());
                            local_taint.insert(ident, Err(source_kind.to_string()));
                        } else if let Some(idx) = params.iter().position(|param| param == rhs) {
                            local_taint.insert(ident, Ok(idx));
                        } else if let Some(kind) = local_taint.get(rhs).cloned() {
                            if let Err(source_kind) = &kind {
                                semantics.tainted_identifiers.insert(ident.clone(), source_kind.clone());
                            }
                            local_taint.insert(ident, kind);
                        } else {
                            for token in rhs.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.')) {
                                if let Some(kind) = local_taint.get(token).cloned() {
                                    if let Err(source_kind) = &kind {
                                        semantics.tainted_identifiers.insert(ident.clone(), source_kind.clone());
                                    }
                                    local_taint.insert(ident.clone(), kind);
                                    break;
                                }
                            }
                        }
                    }
                }

                for caps in member_call_re.captures_iter(line) {
                    let object = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                    let method = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                    let args_raw = caps.get(3).map(|m| m.as_str()).unwrap_or("");
                    let Some(target) = resolve_go_call_target(&semantics, &module_identity, object, Some(method)) else {
                        continue;
                    };
                    record_param_call_edges(&mut semantics, func_identity, &target, args_raw, params, local_taint);
                    record_tainted_call(&mut semantics, &target, args_raw);
                }

                for caps in direct_call_re.captures_iter(line) {
                    let func_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                    let args_raw = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                    let Some(target) = resolve_go_call_target(&semantics, &module_identity, func_name, None) else {
                        continue;
                    };
                    record_param_call_edges(&mut semantics, func_identity, &target, args_raw, params, local_taint);
                    record_tainted_call(&mut semantics, &target, args_raw);
                }

                if let Some(caps) = return_re.captures(line) {
                    let expr = caps.get(1).map(|m| m.as_str()).unwrap_or("").trim();
                    record_return_semantics(&mut semantics, func_identity, expr, params, local_taint, Lang::Go, go_source_kind);
                }
            }
            *brace_depth += line.matches('{').count() as i32;
            *brace_depth -= line.matches('}').count() as i32;
            if *brace_depth <= 0 {
                current_fn = None;
            }
        }

        if line.is_empty() {
            continue;
        }

        if let Some(caps) = func_re.captures(line) {
            let func_name = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let params_raw = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let params: Vec<String> = params_raw.split(',')
                .map(|param| param.trim())
                .filter(|param| !param.is_empty())
                .filter_map(go_param_name)
                .collect();
            if !func_name.is_empty() {
                let func_identity = format!("{module_identity}::{func_name}");
                semantics.function_definitions.insert(func_identity.clone(), params.clone());
                current_fn = Some((
                    func_identity,
                    params,
                    line.matches('{').count() as i32 - line.matches('}').count() as i32,
                    HashMap::new(),
                ));
            }
        }

        if line == "import (" {
            in_import_block = true;
            continue;
        }
        if in_import_block && line == ")" {
            in_import_block = false;
            continue;
        }

        let import_caps = if in_import_block {
            block_import_re.captures(line)
        } else {
            single_import_re.captures(line)
        };
        if let Some(caps) = import_caps {
            let alias = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let module = caps.get(2).map(|m| m.as_str()).unwrap_or("").to_string();
            if !module.is_empty() {
                let default_alias = module.rsplit('/').next().unwrap_or(&module).to_string();
                semantics.imported_modules.insert(module.clone());
                semantics.alias_to_module.insert(
                    if alias.is_empty() { default_alias } else { alias },
                    module.clone(),
                );
                if module.contains("gin-gonic/gin") {
                    semantics.frameworks.insert("gin".into());
                }
                if module.contains("labstack/echo") {
                    semantics.frameworks.insert("echo".into());
                }
                if module.contains("gofiber/fiber") {
                    semantics.frameworks.insert("fiber".into());
                }
                if module.contains("gorm.io/gorm") {
                    semantics.frameworks.insert("gorm".into());
                }
            }
            continue;
        }

        if let Some(caps) = assign_re.captures(line) {
            let ident = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let rhs = caps.get(2).map(|m| m.as_str()).unwrap_or("").trim();
            if ident.is_empty() || rhs.is_empty() {
                continue;
            }
            if let Some(source_kind) = go_source_kind(rhs) {
                semantics.tainted_identifiers.insert(ident, source_kind.to_string());
            } else {
                for token in rhs.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.')) {
                    if let Some(source_kind) = semantics.tainted_identifiers.get(token) {
                        semantics.tainted_identifiers.insert(ident.clone(), source_kind.clone());
                        break;
                    }
                }
            }
        }
    }

    for raw_line in &lines {
        let line = raw_line.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        for caps in member_call_re.captures_iter(line) {
            let object = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let method = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let args_raw = caps.get(3).map(|m| m.as_str()).unwrap_or("");
            let Some(target) = resolve_go_call_target(&semantics, &module_identity, object, Some(method)) else {
                continue;
            };
            record_tainted_call(&mut semantics, &target, args_raw);
        }

        for caps in direct_call_re.captures_iter(line) {
            let func_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let args_raw = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let Some(target) = resolve_go_call_target(&semantics, &module_identity, func_name, None) else {
                continue;
            };
            record_tainted_call(&mut semantics, &target, args_raw);
        }
    }

    semantics
}

fn extract_rust(source: &str, path: Option<&Path>, base_path: Option<&Path>) -> FileSemantics {
    let mut semantics = FileSemantics::default();
    semantics.module_identity = rust_module_identity(path, base_path);
    let module_identity = semantics.module_identity
        .clone()
        .unwrap_or_else(|| "local".to_string());
    let use_re = Regex::new(r#"^\s*use\s+([^;]+);"#).unwrap();
    let assign_re = Regex::new(
        r#"^\s*let\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=]+)?=\s*(.+?)\s*;?\s*$"#
    ).unwrap();
    let fn_re = Regex::new(r#"^\s*fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)"#).unwrap();
    let return_re = Regex::new(r#"^\s*return\s+(.+?)\s*;?\s*$"#).unwrap();
    let direct_call_re = Regex::new(r#"([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)"#).unwrap();
    let path_call_re = Regex::new(r#"([A-Za-z_][A-Za-z0-9_:]*)::([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)"#).unwrap();
    let method_call_re = Regex::new(r#"([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)"#).unwrap();
    let lines: Vec<&str> = source.lines().collect();
    let mut current_fn: Option<(String, Vec<String>, i32, HashMap<String, Result<usize, String>>)> = None;

    for raw_line in &lines {
        let line = raw_line.split("//").next().unwrap_or("").trim();
        if let Some((func_identity, params, brace_depth, local_taint)) = current_fn.as_mut() {
            if !line.is_empty() {
                if let Some(caps) = assign_re.captures(line) {
                    let ident = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
                    let rhs = caps.get(2).map(|m| m.as_str()).unwrap_or("").trim().trim_end_matches(';');
                    if !ident.is_empty() && !rhs.is_empty() {
                        if let Some(source_kind) = rust_source_kind(rhs) {
                            semantics.tainted_identifiers.insert(ident.clone(), source_kind.to_string());
                            local_taint.insert(ident, Err(source_kind.to_string()));
                        } else if let Some(idx) = params.iter().position(|param| param == rhs) {
                            local_taint.insert(ident, Ok(idx));
                        } else if let Some(kind) = local_taint.get(rhs).cloned() {
                            if let Err(source_kind) = &kind {
                                semantics.tainted_identifiers.insert(ident.clone(), source_kind.clone());
                            }
                            local_taint.insert(ident, kind);
                        } else {
                            for token in rhs.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':' || c == '.')) {
                                if let Some(kind) = local_taint.get(token).cloned() {
                                    if let Err(source_kind) = &kind {
                                        semantics.tainted_identifiers.insert(ident.clone(), source_kind.clone());
                                    }
                                    local_taint.insert(ident.clone(), kind);
                                    break;
                                }
                            }
                        }
                    }
                }

                for caps in path_call_re.captures_iter(line) {
                    let head = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                    let method = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                    let args_raw = caps.get(3).map(|m| m.as_str()).unwrap_or("");
                    let Some(target) = resolve_rust_call_target(&semantics, &module_identity, head, Some(method)) else {
                        continue;
                    };
                    record_param_call_edges(&mut semantics, func_identity, &target, args_raw, params, local_taint);
                    record_tainted_call(&mut semantics, &target, args_raw);
                }

                for caps in method_call_re.captures_iter(line) {
                    let object = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                    let method = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                    let args_raw = caps.get(3).map(|m| m.as_str()).unwrap_or("");
                    let Some(target) = resolve_rust_call_target(&semantics, &module_identity, object, Some(method)) else {
                        continue;
                    };
                    record_param_call_edges(&mut semantics, func_identity, &target, args_raw, params, local_taint);
                    record_tainted_call(&mut semantics, &target, args_raw);
                }

                for caps in direct_call_re.captures_iter(line) {
                    let func_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                    let args_raw = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                    let Some(target) = resolve_rust_call_target(&semantics, &module_identity, func_name, None) else {
                        continue;
                    };
                    record_param_call_edges(&mut semantics, func_identity, &target, args_raw, params, local_taint);
                    record_tainted_call(&mut semantics, &target, args_raw);
                }

                if let Some(caps) = return_re.captures(line) {
                    let expr = caps.get(1).map(|m| m.as_str()).unwrap_or("").trim().trim_end_matches(';');
                    record_return_semantics(&mut semantics, func_identity, expr, params, local_taint, Lang::Rust, rust_source_kind);
                }
            }
            *brace_depth += line.matches('{').count() as i32;
            *brace_depth -= line.matches('}').count() as i32;
            if *brace_depth <= 0 {
                current_fn = None;
            }
        }

        if line.is_empty() {
            continue;
        }

        if let Some(caps) = fn_re.captures(line) {
            let func_name = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let params_raw = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let params: Vec<String> = params_raw.split(',')
                .map(|param| param.trim())
                .filter(|param| !param.is_empty())
                .filter_map(rust_param_name)
                .collect();
            if !func_name.is_empty() {
                let func_identity = format!("{module_identity}::{func_name}");
                semantics.function_definitions.insert(func_identity.clone(), params.clone());
                current_fn = Some((
                    func_identity,
                    params,
                    line.matches('{').count() as i32 - line.matches('}').count() as i32,
                    HashMap::new(),
                ));
            }
        }

        if let Some(caps) = use_re.captures(line) {
            let raw_import = caps.get(1).map(|m| m.as_str()).unwrap_or("").trim();
            record_rust_imports(&mut semantics, raw_import, &module_identity);
            continue;
        }

        if let Some(caps) = assign_re.captures(line) {
            let ident = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let rhs = caps.get(2).map(|m| m.as_str()).unwrap_or("").trim();
            if ident.is_empty() || rhs.is_empty() {
                continue;
            }
            if let Some(source_kind) = rust_source_kind(rhs) {
                semantics.tainted_identifiers.insert(ident, source_kind.to_string());
            } else {
                for token in rhs.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':' || c == '.')) {
                    if let Some(source_kind) = semantics.tainted_identifiers.get(token) {
                        semantics.tainted_identifiers.insert(ident.clone(), source_kind.clone());
                        break;
                    }
                }
            }
        }
    }

    for raw_line in &lines {
        let line = raw_line.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        for caps in path_call_re.captures_iter(line) {
            let head = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let method = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let args_raw = caps.get(3).map(|m| m.as_str()).unwrap_or("");
            let Some(target) = resolve_rust_call_target(&semantics, &module_identity, head, Some(method)) else {
                continue;
            };
            record_tainted_call(&mut semantics, &target, args_raw);
        }

        for caps in method_call_re.captures_iter(line) {
            let object = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let method = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let args_raw = caps.get(3).map(|m| m.as_str()).unwrap_or("");
            let Some(target) = resolve_rust_call_target(&semantics, &module_identity, object, Some(method)) else {
                continue;
            };
            record_tainted_call(&mut semantics, &target, args_raw);
        }

        for caps in direct_call_re.captures_iter(line) {
            let func_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let args_raw = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let Some(target) = resolve_rust_call_target(&semantics, &module_identity, func_name, None) else {
                continue;
            };
            record_tainted_call(&mut semantics, &target, args_raw);
        }
    }

    semantics
}

fn extract_php(source: &str, path: Option<&Path>, base_path: Option<&Path>) -> FileSemantics {
    let mut semantics = FileSemantics::default();
    semantics.module_identity = path_module_identity(path, base_path, &[".php", ".phtml"]);
    if source.contains("Illuminate\\") || source.contains("Laravel") || source.contains("->redirect(") {
        semantics.frameworks.insert("laravel".into());
    }
    if source.contains("Symfony\\") || source.contains("$this->redirect(") {
        semantics.frameworks.insert("symfony".into());
    }
    if source.contains("add_action(") || source.contains("wp_redirect(") || source.contains("check_ajax_referer(") {
        semantics.frameworks.insert("wordpress".into());
    }
    let use_re = Regex::new(r#"^\s*use\s+([A-Za-z_\\][A-Za-z0-9_\\]*)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?\s*;"#).unwrap();
    let assign_re = Regex::new(r#"^\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*;?\s*$"#).unwrap();
    let function_re = Regex::new(r#"^\s*function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)"#).unwrap();
    let lines: Vec<&str> = source.lines().collect();

    for raw_line in &lines {
        let line = raw_line.split("//").next().unwrap_or("").split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(caps) = function_re.captures(line) {
            let func_name = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let params_raw = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let params: Vec<String> = params_raw.split(',')
                .map(|p| p.trim().trim_start_matches('$').split('=').next().unwrap_or("").trim().to_string())
                .filter(|p| !p.is_empty())
                .collect();
            if let Some(module_identity) = semantics.module_identity.as_deref() {
                semantics.function_definitions.insert(format!("{module_identity}::{func_name}"), params);
            }
        }
        if let Some(caps) = use_re.captures(line) {
            let module = caps.get(1).map(|m| m.as_str()).unwrap_or("").replace('\\', ".");
            let alias = caps.get(2).map(|m| m.as_str().to_string())
                .unwrap_or_else(|| module.rsplit('.').next().unwrap_or(&module).to_string());
            if !module.is_empty() {
                semantics.imported_modules.insert(module.clone());
                semantics.alias_to_module.insert(alias, module);
            }
        }
        if let Some(caps) = assign_re.captures(line) {
            let ident = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let rhs = caps.get(2).map(|m| m.as_str()).unwrap_or("").trim();
            if let Some(source_kind) = php_source_kind(rhs) {
                semantics.tainted_identifiers.insert(format!("${ident}"), source_kind.to_string());
                semantics.tainted_identifiers.insert(ident, source_kind.to_string());
            } else {
                for token in rhs.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '$' || c == '>' || c == '[' || c == ']')) {
                    if let Some(source_kind) = semantics.tainted_identifiers.get(token).cloned() {
                        semantics.tainted_identifiers.insert(format!("${ident}"), source_kind.clone());
                        semantics.tainted_identifiers.insert(ident.clone(), source_kind);
                        break;
                    }
                }
            }
        }
    }
    semantics
}

fn extract_swift(source: &str, path: Option<&Path>, base_path: Option<&Path>) -> FileSemantics {
    let mut semantics = FileSemantics::default();
    semantics.module_identity = path_module_identity(path, base_path, &[".swift"]);
    let import_re = Regex::new(r#"^\s*import\s+([A-Za-z_][A-Za-z0-9_]*)"#).unwrap();
    for raw_line in source.lines() {
        let line = raw_line.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(caps) = import_re.captures(line) {
            let module = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            if !module.is_empty() {
                semantics.imported_modules.insert(module.clone());
                semantics.alias_to_module.insert(module.clone(), module.clone());
                if module == "GoogleGenerativeAI" {
                    semantics.frameworks.insert("gemini".into());
                }
                if module == "Vision" || module == "CoreML" {
                    semantics.frameworks.insert("apple_coreml".into());
                }
                if module == "WebKit" {
                    semantics.frameworks.insert("webkit".into());
                }
            }
        }
    }
    semantics
}

fn extract_scala(source: &str, path: Option<&Path>, base_path: Option<&Path>) -> FileSemantics {
    let mut semantics = FileSemantics::default();
    semantics.module_identity = path_module_identity(path, base_path, &[".scala"]);
    let import_re = Regex::new(r#"^\s*import\s+([A-Za-z_][A-Za-z0-9_\.{}]+)"#).unwrap();
    let assign_re = Regex::new(r#"^\s*(?:val|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$"#).unwrap();
    for raw_line in source.lines() {
        let line = raw_line.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(caps) = import_re.captures(line) {
            let module = caps.get(1).map(|m| m.as_str()).unwrap_or("").trim_end_matches("._").to_string();
            if !module.is_empty() {
                semantics.imported_modules.insert(module.clone());
                if module.contains("play.api") {
                    semantics.frameworks.insert("play".into());
                }
                if module.contains("scalaj.http") {
                    semantics.frameworks.insert("scalaj".into());
                }
                if module.contains("dispatch") {
                    semantics.frameworks.insert("dispatch".into());
                }
            }
        }
        if let Some(caps) = assign_re.captures(line) {
            let ident = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let rhs = caps.get(2).map(|m| m.as_str()).unwrap_or("").trim();
            if let Some(source_kind) = scala_source_kind(rhs) {
                semantics.tainted_identifiers.insert(ident, source_kind.to_string());
            }
        }
    }
    semantics
}

fn extract_c(source: &str, path: Option<&Path>, base_path: Option<&Path>) -> FileSemantics {
    let mut semantics = FileSemantics::default();
    semantics.module_identity = path_module_identity(path, base_path, &[".c", ".h"]);
    let include_re = Regex::new(r#"^\s*#include\s+[<"]([^>"]+)[>"]"#).unwrap();
    let assign_re = Regex::new(r#"^\s*(?:char\s*\*|const\s+char\s*\*|int\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*;?\s*$"#).unwrap();
    for raw_line in source.lines() {
        let line = raw_line.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(caps) = include_re.captures(line) {
            let module = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            if !module.is_empty() {
                semantics.imported_modules.insert(module);
            }
        }
        if let Some(caps) = assign_re.captures(line) {
            let ident = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let rhs = caps.get(2).map(|m| m.as_str()).unwrap_or("").trim();
            if let Some(source_kind) = c_source_kind(rhs) {
                semantics.tainted_identifiers.insert(ident, source_kind.to_string());
            }
        }
    }
    semantics
}

fn extract_bash(source: &str, path: Option<&Path>, base_path: Option<&Path>) -> FileSemantics {
    let mut semantics = FileSemantics::default();
    semantics.module_identity = path_module_identity(path, base_path, &[".sh", ".bash"]);
    let assign_re = Regex::new(r#"^\s*([A-Za-z_][A-Za-z0-9_]*)=(.+?)\s*$"#).unwrap();
    for raw_line in source.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(caps) = assign_re.captures(line) {
            let ident = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let rhs = caps.get(2).map(|m| m.as_str()).unwrap_or("").trim();
            if let Some(source_kind) = bash_source_kind(rhs) {
                semantics.tainted_identifiers.insert(format!("${ident}"), source_kind.to_string());
                semantics.tainted_identifiers.insert(ident, source_kind.to_string());
            } else {
                for token in rhs.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '$')) {
                    if let Some(source_kind) = semantics.tainted_identifiers.get(token).cloned() {
                        semantics.tainted_identifiers.insert(format!("${ident}"), source_kind.clone());
                        semantics.tainted_identifiers.insert(ident.clone(), source_kind);
                        break;
                    }
                }
            }
        }
    }
    semantics
}

fn go_module_identity(path: Option<&Path>, base_path: Option<&Path>) -> Option<String> {
    path_module_identity(path, base_path, &[".go"]).map(|identity| {
        identity.rsplit_once('.')
            .map(|(module, _)| module.to_string())
            .unwrap_or(identity)
    })
}

fn rust_module_identity(path: Option<&Path>, base_path: Option<&Path>) -> Option<String> {
    path_module_identity(path, base_path, &[".rs"]).map(|identity| {
        if identity.ends_with(".mod") {
            identity.trim_end_matches(".mod").to_string()
        } else {
            identity
        }
    })
}

fn go_param_name(param: &str) -> Option<String> {
    let cleaned = param.split('=').next()?.trim();
    let tokens: Vec<&str> = cleaned.split_whitespace().collect();
    tokens.first()
        .map(|name| name.trim_start_matches("...").to_string())
        .filter(|name| !name.is_empty())
}

fn rust_param_name(param: &str) -> Option<String> {
    let cleaned = param.split('=').next()?.trim();
    let name = cleaned.split(':').next()?.trim();
    let name = name
        .trim_start_matches("mut ")
        .trim_start_matches('&')
        .trim_start_matches("mut ")
        .trim();
    if name == "self" || name == "&self" || name == "&mut self" {
        return None;
    }
    if name.is_empty() {
        return None;
    }
    Some(name.to_string())
}

fn resolve_go_call_target(
    semantics: &FileSemantics,
    module_identity: &str,
    head: &str,
    member: Option<&str>,
) -> Option<String> {
    match member {
        Some(method) => {
            let module = semantics.alias_to_module.get(head)?;
            Some(format!("{module}::{method}"))
        }
        None => {
            let local_target = format!("{module_identity}::{head}");
            if semantics.function_definitions.contains_key(&local_target) {
                return Some(local_target);
            }
            None
        }
    }
}

fn record_rust_imports(
    semantics: &mut FileSemantics,
    raw_import: &str,
    module_identity: &str,
) {
    if let Some(prefix) = raw_import.strip_suffix("::*") {
        let module = resolve_rust_import_target(prefix.trim(), module_identity);
        if !module.is_empty() {
            semantics.imported_modules.insert(module.clone());
            if let Some(alias) = module.rsplit('.').next() {
                semantics.alias_to_module.insert(alias.to_string(), module.clone());
            }
            tag_rust_frameworks(semantics, &module);
        }
        return;
    }

    if let Some((prefix, suffix)) = raw_import.rsplit_once("::{") {
        let base = resolve_rust_import_target(prefix.trim(), module_identity);
        let suffix = suffix.trim_end_matches('}');
        for item in suffix.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let (symbol, alias) = match item.split_once(" as ") {
                Some((symbol, alias)) => (symbol.trim(), alias.trim()),
                None => (item, item.rsplit("::").next().unwrap_or(item)),
            };
            let qualified = format!("{base}.{}", symbol.replace("::", "."));
            semantics.imported_symbols.insert(alias.to_string(), qualified.clone());
            semantics.alias_to_module.insert(alias.to_string(), qualified);
        }
        semantics.imported_modules.insert(base.clone());
        tag_rust_frameworks(semantics, &base);
        return;
    }

    let (target, alias) = match raw_import.rsplit_once(" as ") {
        Some((target, alias)) => (target.trim(), Some(alias.trim())),
        None => (raw_import.trim(), None),
    };
    let qualified = resolve_rust_import_target(target, module_identity);
    if qualified.is_empty() {
        return;
    }
    semantics.imported_modules.insert(qualified.clone());
    let tail = target.rsplit("::").next().unwrap_or(target);
    let alias = alias.unwrap_or(tail);
    if target.contains("::") && tail.chars().next().is_some_and(|c| c.is_ascii_lowercase()) {
        semantics.imported_symbols.insert(alias.to_string(), qualified.clone());
    }
    semantics.alias_to_module.insert(alias.to_string(), qualified.clone());
    tag_rust_frameworks(semantics, &qualified);
}

fn resolve_rust_import_target(raw_import: &str, module_identity: &str) -> String {
    let raw_import = raw_import.trim();
    if let Some(rest) = raw_import.strip_prefix("crate::") {
        let crate_root = module_identity.split('.').next().unwrap_or(module_identity);
        return if rest.is_empty() {
            crate_root.to_string()
        } else {
            format!("{crate_root}.{}", rest.replace("::", "."))
        };
    }
    if raw_import == "self" {
        return module_identity.to_string();
    }
    if let Some(rest) = raw_import.strip_prefix("self::") {
        let mut parts: Vec<&str> = module_identity.split('.').collect();
        parts.pop();
        let mut base = parts.join(".");
        if !base.is_empty() && !rest.is_empty() {
            base.push('.');
        }
        return format!("{base}{}", rest.replace("::", "."));
    }
    if let Some(rest) = raw_import.strip_prefix("super::") {
        let mut parts: Vec<&str> = module_identity.split('.').collect();
        parts.pop();
        if !parts.is_empty() {
            parts.pop();
        }
        let mut base = parts.join(".");
        if !base.is_empty() && !rest.is_empty() {
            base.push('.');
        }
        return format!("{base}{}", rest.replace("::", "."));
    }
    raw_import.replace("::", ".")
}

fn tag_rust_frameworks(semantics: &mut FileSemantics, import: &str) {
    if import.contains("actix_web") {
        semantics.frameworks.insert("actix".into());
    }
    if import.contains("axum") {
        semantics.frameworks.insert("axum".into());
    }
    if import.contains("rocket") {
        semantics.frameworks.insert("rocket".into());
    }
    if import.contains("reqwest") {
        semantics.frameworks.insert("reqwest".into());
    }
}

fn resolve_rust_call_target(
    semantics: &FileSemantics,
    module_identity: &str,
    head: &str,
    member: Option<&str>,
) -> Option<String> {
    match member {
        Some(method) => {
            if let Some(imported) = semantics.imported_symbols.get(head) {
                return Some(format!("{}::{method}", imported.replace('.', "::")));
            }
            let module = semantics.alias_to_module.get(head)?;
            Some(format!("{}::{method}", module.replace('.', "::")))
        }
        None => {
            if let Some(imported) = semantics.imported_symbols.get(head) {
                return Some(qualified_symbol_identity(imported));
            }
            let local_target = format!("{module_identity}::{head}");
            if semantics.function_definitions.contains_key(&local_target) {
                return Some(local_target);
            }
            None
        }
    }
}

fn resolve_relative_module_target(raw_module: &str, module_identity: &str, exts: &[&str]) -> String {
    if raw_module.starts_with("./") || raw_module.starts_with("../") {
        let mut base_parts: Vec<&str> = module_identity.split('.').collect();
        base_parts.pop();
        let mut rel = raw_module;
        while let Some(rest) = rel.strip_prefix("../") {
            rel = rest;
            if !base_parts.is_empty() {
                base_parts.pop();
            }
        }
        if let Some(rest) = rel.strip_prefix("./") {
            rel = rest;
        }
        let mut rel = rel.to_string();
        for ext in exts {
            rel = rel.trim_end_matches(ext).to_string();
        }
        let rel_parts = rel.split('/')
            .filter(|s| !s.is_empty() && *s != ".")
            .collect::<Vec<_>>();
        let mut parts = base_parts.into_iter().map(str::to_string).collect::<Vec<_>>();
        parts.extend(rel_parts.into_iter().map(str::to_string));
        return parts.join(".");
    }
    raw_module.to_string()
}

fn record_tainted_call(
    semantics: &mut FileSemantics,
    target: &str,
    args_raw: &str,
) {
    for (idx, arg) in args_raw.split(',').enumerate() {
        let arg = arg.trim();
        if let Some(source_kind) = semantics.tainted_identifiers.get(arg) {
            semantics.tainted_calls.push((target.to_string(), idx, source_kind.clone()));
        }
    }
}

fn csharp_db_command_type_from_decl(declared_type: &str, rhs: &str) -> Option<String> {
    if csharp_is_db_command_type(declared_type) {
        return Some(declared_type.to_string());
    }
    csharp_db_command_type_from_rhs(rhs)
}

fn csharp_db_command_type_from_rhs(rhs: &str) -> Option<String> {
    let compact: String = rhs.chars().filter(|c| !c.is_whitespace()).collect();
    for marker in [
        "newSqlCommand(",
        "newMicrosoft.Data.SqlClient.SqlCommand(",
        "newSystem.Data.SqlClient.SqlCommand(",
        "newNpgsqlCommand(",
        "newMySqlCommand(",
        "newOracleCommand(",
        "newSQLiteCommand(",
        "newSqliteCommand(",
    ] {
        if compact.contains(marker) {
            return Some(marker.trim_start_matches("new").trim_end_matches('(').to_string());
        }
    }
    if compact.contains(".CreateCommand(") {
        return Some("DbCommand".into());
    }
    None
}

fn csharp_is_db_command_type(ty: &str) -> bool {
    let normalized = ty.rsplit('.').next().unwrap_or(ty).trim();
    matches!(
        normalized,
        "SqlCommand"
            | "DbCommand"
            | "SqliteCommand"
            | "SQLiteCommand"
            | "NpgsqlCommand"
            | "MySqlCommand"
            | "OracleCommand"
    )
}

fn csharp_source_kind(rhs: &str) -> Option<&'static str> {
    let compact: String = rhs.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.contains("Request.Query[") || compact.contains("Request.Query.Get(") {
        return Some("aspnet.request_query");
    }
    if compact.contains("Request.Form[") || compact.contains("Request.Form.Get(") {
        return Some("aspnet.request_form");
    }
    if compact.contains("Request.Headers[") {
        return Some("aspnet.request_headers");
    }
    if compact.contains("Request.Cookies[") {
        return Some("aspnet.request_cookies");
    }
    None
}

fn go_source_kind(rhs: &str) -> Option<&'static str> {
    let compact: String = rhs.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.contains("c.Query(") || compact.contains("ctx.Query(") {
        return Some("go.http.query");
    }
    if compact.contains("c.Param(") || compact.contains("ctx.Param(") {
        return Some("go.http.param");
    }
    if compact.contains("c.FormValue(") || compact.contains("ctx.FormValue(") || compact.contains("r.FormValue(") {
        return Some("go.http.form");
    }
    if compact.contains("r.URL.Query().Get(") {
        return Some("go.http.query");
    }
    None
}

fn rust_source_kind(rhs: &str) -> Option<&'static str> {
    let compact: String = rhs.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.contains("std::env::args()")
        || compact.contains("std::env::args().nth(")
        || compact.contains("std::env::args().next(")
    {
        return Some("rust.env.args");
    }
    if compact.contains("std::env::args_os()")
        || compact.contains("std::env::args_os().nth(")
        || compact.contains("std::env::args_os().next(")
    {
        return Some("rust.env.args_os");
    }
    if compact.contains("std::env::var(") || compact.contains("std::env::var_os(") {
        return Some("rust.env.var");
    }
    None
}

fn php_source_kind(rhs: &str) -> Option<&'static str> {
    let compact: String = rhs.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.contains("$_GET[") || compact.contains("$_GET") {
        return Some("php.request.get");
    }
    if compact.contains("$_POST[") || compact.contains("$_POST") {
        return Some("php.request.post");
    }
    if compact.contains("$_REQUEST[") || compact.contains("$_REQUEST") {
        return Some("php.request.request");
    }
    if compact.contains("$_COOKIE[") || compact.contains("$_COOKIE") {
        return Some("php.request.cookie");
    }
    None
}

fn scala_source_kind(rhs: &str) -> Option<&'static str> {
    let compact: String = rhs.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.contains("request.getParameter(") || compact.contains("request.getQueryString(") {
        return Some("scala.http.request_parameter");
    }
    if compact.contains("request.queryString") {
        return Some("scala.http.query_string");
    }
    None
}

fn c_source_kind(rhs: &str) -> Option<&'static str> {
    let compact: String = rhs.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.contains("argv[") {
        return Some("c.argv");
    }
    if compact.contains("getenv(") {
        return Some("c.getenv");
    }
    None
}

fn bash_source_kind(rhs: &str) -> Option<&'static str> {
    let compact: String = rhs.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.contains("$1") || compact.contains("${1}") {
        return Some("bash.positional_arg");
    }
    if compact.contains("$@") || compact.contains("$*") {
        return Some("bash.positional_args");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_import_aliases_are_extracted() {
        let source = "import pickle as p\nfrom pickle import loads as pl\n";
        let semantics = extract(Lang::Python, source);
        assert_eq!(semantics.alias_to_module.get("p").map(String::as_str), Some("pickle"));
        assert_eq!(semantics.imported_symbols.get("pl").map(String::as_str), Some("pickle.loads"));
    }

    #[test]
    fn js_import_aliases_are_extracted() {
        let source = "import * as React from 'react'\nconst DOMPurify = require('dompurify')\n";
        let semantics = extract(Lang::Javascript, source);
        assert_eq!(semantics.js_namespace_imports.get("React").map(String::as_str), Some("react"));
        assert_eq!(semantics.js_namespace_imports.get("DOMPurify").map(String::as_str), Some("dompurify"));
    }

    #[test]
    fn js_module_function_identities_and_tainted_calls_are_resolved() {
        use std::path::Path;
        let source = "import { run } from './helper'\nconst user = req.query.cmd;\nrun(user)\n";
        let semantics = extract_with_context(
            Lang::Javascript,
            source,
            Some(Path::new("/repo/src/entry.js")),
            Some(Path::new("/repo")),
        );
        assert_eq!(semantics.module_identity.as_deref(), Some("src.entry"));
        assert_eq!(semantics.imported_symbols.get("run").map(String::as_str), Some("src.helper.run"));
        assert!(semantics.tainted_calls.iter().any(|(target, idx, kind)|
            target == "src.helper::run" && *idx == 0 && kind == "express.req.query"
        ));
    }

    #[test]
    fn java_module_function_identities_and_tainted_calls_are_resolved() {
        use std::path::Path;
        let source = r#"
            package app;
            import static app.helper.Runner.run;
            class Entry {
                void handle(HttpServletRequest request) {
                    String user = request.getParameter("user");
                    run(user);
                }
            }
        "#;
        let semantics = extract_with_context(
            Lang::Java,
            source,
            Some(Path::new("/repo/src/app/Entry.java")),
            Some(Path::new("/repo/src")),
        );
        assert_eq!(semantics.module_identity.as_deref(), Some("app.Entry"));
        assert_eq!(semantics.imported_symbols.get("run").map(String::as_str), Some("app.helper.Runner.run"));
        assert!(semantics.tainted_calls.iter().any(|(target, idx, kind)|
            target == "app.helper.Runner::run" && *idx == 0 && kind == "spring.http_request_parameter"
        ));
    }

    #[test]
    fn ruby_module_function_identities_and_tainted_calls_are_resolved() {
        use std::path::Path;
        let source = "require_relative './helper'\nvalue = params[:name]\nHelper.run(value)\n";
        let semantics = extract_with_context(
            Lang::Ruby,
            source,
            Some(Path::new("/repo/app/controllers/entry.rb")),
            Some(Path::new("/repo")),
        );
        assert_eq!(semantics.module_identity.as_deref(), Some("app.controllers.entry"));
        assert_eq!(semantics.alias_to_module.get("Helper").map(String::as_str), Some("app.controllers.helper"));
        assert!(semantics.tainted_calls.iter().any(|(target, idx, kind)|
            target == "app.controllers.helper::run" && *idx == 0 && kind == "rails.params"
        ));
    }

    #[test]
    fn csharp_module_function_identities_and_tainted_calls_are_resolved() {
        use std::path::Path;
        let source = r#"
            namespace Demo.Web;
            class Entry {
                void Handle() {
                    var value = Request.Query["id"];
                    Run(value);
                }

                void Run(string data) {
                }
            }
        "#;
        let semantics = extract_with_context(
            Lang::Csharp,
            source,
            Some(Path::new("/repo/src/Entry.cs")),
            Some(Path::new("/repo")),
        );
        assert_eq!(semantics.module_identity.as_deref(), Some("Demo.Web.Entry"));
        assert!(semantics.function_definitions.contains_key("Demo.Web.Entry::Run"));
        assert!(semantics.tainted_calls.iter().any(|(target, idx, kind)|
            target == "Demo.Web.Entry::Run" && *idx == 0 && kind == "aspnet.request_query"
        ));
    }

    #[test]
    fn go_module_function_identities_and_tainted_calls_are_resolved() {
        use std::path::Path;
        let source = r#"
            import helper "app/helper"
            func handler(c *Context) {
                user := c.Query("user")
                helper.Run(user)
            }
        "#;
        let semantics = extract_with_context(
            Lang::Go,
            source,
            Some(Path::new("/repo/cmd/server/main.go")),
            Some(Path::new("/repo")),
        );
        assert_eq!(semantics.module_identity.as_deref(), Some("cmd.server"));
        assert_eq!(semantics.alias_to_module.get("helper").map(String::as_str), Some("app/helper"));
        assert!(semantics.tainted_calls.iter().any(|(target, idx, kind)|
            target == "app/helper::Run" && *idx == 0 && kind == "go.http.query"
        ));
    }

    #[test]
    fn rust_module_function_identities_and_tainted_calls_are_resolved() {
        use std::path::Path;
        let source = r#"
            use crate::helper::run;
            fn entry() {
                let user = std::env::args().nth(1);
                run(user);
            }
        "#;
        let semantics = extract_with_context(
            Lang::Rust,
            source,
            Some(Path::new("/repo/src/main.rs")),
            Some(Path::new("/repo")),
        );
        assert_eq!(semantics.module_identity.as_deref(), Some("src.main"));
        assert_eq!(semantics.imported_symbols.get("run").map(String::as_str), Some("src.helper.run"));
        assert_eq!(semantics.tainted_identifiers.get("user").map(String::as_str), Some("rust.env.args"));
        assert!(semantics.tainted_calls.iter().any(|(target, idx, kind)|
            target == "src.helper::run" && *idx == 0 && kind == "rust.env.args"
        ));
    }

    #[test]
    fn rust_use_groups_and_frameworks_are_extracted() {
        let source = r#"
            use reqwest::{Client, header::HeaderMap};
            use axum as web;
        "#;
        let semantics = extract(Lang::Rust, source);
        assert_eq!(semantics.imported_symbols.get("Client").map(String::as_str), Some("reqwest.Client"));
        assert_eq!(semantics.imported_symbols.get("HeaderMap").map(String::as_str), Some("reqwest.header.HeaderMap"));
        assert!(semantics.frameworks.contains("reqwest"));
        assert!(semantics.frameworks.contains("axum"));
        assert_eq!(semantics.alias_to_module.get("web").map(String::as_str), Some("axum"));
    }

    #[test]
    fn php_request_sources_are_extracted() {
        let source = "$name = $_GET['name'];\n";
        let semantics = extract(Lang::Php, source);
        assert_eq!(semantics.tainted_identifiers.get("name").map(String::as_str), Some("php.request.get"));
        assert_eq!(semantics.tainted_identifiers.get("$name").map(String::as_str), Some("php.request.get"));
    }

    #[test]
    fn swift_imports_are_extracted() {
        let source = "import GoogleGenerativeAI\nimport Vision\n";
        let semantics = extract(Lang::Swift, source);
        assert!(semantics.frameworks.contains("gemini"));
        assert!(semantics.frameworks.contains("apple_coreml"));
    }

    #[test]
    fn scala_request_sources_are_extracted() {
        let source = "val url = request.getParameter(\"url\")\n";
        let semantics = extract(Lang::Scala, source);
        assert_eq!(semantics.tainted_identifiers.get("url").map(String::as_str), Some("scala.http.request_parameter"));
    }

    #[test]
    fn c_argv_sources_are_extracted() {
        let source = "char *value = argv[1];\n";
        let semantics = extract(Lang::C, source);
        assert_eq!(semantics.tainted_identifiers.get("value").map(String::as_str), Some("c.argv"));
    }

    #[test]
    fn bash_positional_sources_are_extracted() {
        let source = "cmd=$1\n";
        let semantics = extract(Lang::Bash, source);
        assert_eq!(semantics.tainted_identifiers.get("cmd").map(String::as_str), Some("bash.positional_arg"));
    }

    #[test]
    fn python_taint_is_propagated() {
        let source = "from flask import request\nuser = request.args.get('u')\nname = user\n";
        let semantics = extract(Lang::Python, source);
        assert_eq!(semantics.tainted_identifiers.get("user").map(String::as_str), Some("flask.request.args"));
        assert_eq!(semantics.tainted_identifiers.get("name").map(String::as_str), Some("flask.request.args"));
        assert!(semantics.frameworks.contains("flask"));
    }

    #[test]
    fn js_taint_is_propagated() {
        let source = "const express = require('express');\nconst q = req.query.id;\nconst value = q;\n";
        let semantics = extract(Lang::Javascript, source);
        assert_eq!(semantics.tainted_identifiers.get("q").map(String::as_str), Some("express.req.query"));
        assert_eq!(semantics.tainted_identifiers.get("value").map(String::as_str), Some("express.req.query"));
        assert!(semantics.frameworks.contains("express"));
    }

    #[test]
    fn ruby_taint_is_propagated() {
        let source = "name = params[:name]\nhtml = name\nraw(html)\n";
        let semantics = extract(Lang::Ruby, source);
        assert_eq!(semantics.tainted_identifiers.get("name").map(String::as_str), Some("rails.params"));
        assert_eq!(semantics.tainted_identifiers.get("html").map(String::as_str), Some("rails.params"));
        assert!(semantics.frameworks.contains("rails"));
    }

    #[test]
    fn csharp_db_command_types_are_extracted() {
        let source = r#"
            using Microsoft.AspNetCore.Mvc;
            using Microsoft.Data.SqlClient;
            class C {
                void Run() {
                    SqlCommand cmd = new SqlCommand();
                    var cmd2 = new SqlCommand();
                    var cmd3 = connection.CreateCommand();
                }
            }
        "#;
        let semantics = extract(Lang::Csharp, source);
        assert_eq!(semantics.variable_types.get("cmd").map(String::as_str), Some("SqlCommand"));
        assert_eq!(semantics.variable_types.get("cmd2").map(String::as_str), Some("SqlCommand"));
        assert_eq!(semantics.variable_types.get("cmd3").map(String::as_str), Some("DbCommand"));
    }

    #[test]
    fn java_imports_are_extracted() {
        let source = "import org.springframework.web.bind.annotation.RequestParam;\nimport java.sql.PreparedStatement;\n";
        let semantics = extract(Lang::Java, source);
        assert!(semantics.imported_modules.contains("org.springframework.web.bind.annotation.RequestParam"));
        assert_eq!(
            semantics.imported_symbols.get("PreparedStatement").map(String::as_str),
            Some("java.sql.PreparedStatement")
        );
    }

    #[test]
    fn ruby_requires_are_extracted() {
        let source = "require 'rails'\nname = params[:name]\n";
        let semantics = extract(Lang::Ruby, source);
        assert!(semantics.imported_modules.contains("rails"));
        assert!(semantics.frameworks.contains("rails"));
    }

    #[test]
    fn csharp_using_aliases_are_extracted() {
        let source = "using Sql = Microsoft.Data.SqlClient.SqlCommand;\n";
        let semantics = extract(Lang::Csharp, source);
        assert_eq!(
            semantics.alias_to_module.get("Sql").map(String::as_str),
            Some("Microsoft.Data.SqlClient.SqlCommand")
        );
        assert_eq!(
            semantics.imported_symbols.get("Sql").map(String::as_str),
            Some("Microsoft.Data.SqlClient.SqlCommand")
        );
    }

    #[test]
    fn go_imports_frameworks_and_sources_are_extracted() {
        let source = r#"
            import (
                "github.com/gin-gonic/gin"
                db "gorm.io/gorm"
            )
            func handler(c *gin.Context) {
                user := c.Query("user")
                _ = user
                _ = db
            }
        "#;
        let semantics = extract(Lang::Go, source);
        assert!(semantics.imported_modules.contains("github.com/gin-gonic/gin"));
        assert_eq!(
            semantics.alias_to_module.get("db").map(String::as_str),
            Some("gorm.io/gorm")
        );
        assert!(semantics.frameworks.contains("gin"));
        assert!(semantics.frameworks.contains("gorm"));
        assert_eq!(
            semantics.tainted_identifiers.get("user").map(String::as_str),
            Some("go.http.query")
        );
    }

}
