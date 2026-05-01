use std::collections::{HashMap, HashSet};
use std::path::Path;

use regex::Regex;

use crate::lang::Lang;

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
    /// Maps function names to the list of their parameter names.
    pub function_definitions: HashMap<String, Vec<String>>,
    /// List of (function_name, argument_index, source_kind) for calls in this file.
    pub tainted_calls: Vec<(String, usize, String)>,
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
        Lang::Javascript | Lang::Typescript => extract_javascript(source),
        Lang::Ruby => extract_ruby(source),
        Lang::Java => extract_java(source),
        Lang::Csharp => extract_csharp(source),
        Lang::Go => extract_go(source),
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
    let direct_call_re = Regex::new(r#"([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)"#).unwrap();
    let member_call_re = Regex::new(r#"([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)"#).unwrap();
    let lines: Vec<&str> = source.lines().collect();

    for raw_line in &lines {
        let line = raw_line.split('#').next().unwrap_or("").trim();
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

fn extract_javascript(source: &str) -> FileSemantics {
    let mut semantics = FileSemantics::default();

    let import_ns_re = Regex::new(
        r#"^\s*import\s+\*\s+as\s+([A-Za-z_$][A-Za-z0-9_$]*)\s+from\s+['"]([^'"]+)['"]"#
    ).unwrap();
    let import_default_re = Regex::new(
        r#"^\s*import\s+([A-Za-z_$][A-Za-z0-9_$]*)\s+from\s+['"]([^'"]+)['"]"#
    ).unwrap();
    let import_named_re = Regex::new(
        r#"^\s*import\s+\{([^}]+)\}\s+from\s+['"]([^'"]+)['"]"#
    ).unwrap();
    let require_re = Regex::new(
        r#"^\s*(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)"#
    ).unwrap();
    let assign_re = Regex::new(
        r#"^\s*(?:const|let|var)?\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(.+?)\s*;?\s*$"#
    ).unwrap();

    for raw_line in source.lines() {
        let line = raw_line.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        if let Some(caps) = import_ns_re.captures(line) {
            let alias = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let module = caps.get(2).map(|m| m.as_str()).unwrap_or("").to_string();
            if !alias.is_empty() && !module.is_empty() {
                semantics.js_namespace_imports.insert(alias, module.clone());
                semantics.imported_modules.insert(module);
                tag_js_frameworks(&mut semantics);
            }
            continue;
        }

        if let Some(caps) = import_named_re.captures(line) {
            let names = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let module = caps.get(2).map(|m| m.as_str()).unwrap_or("").to_string();
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
                }
            }
            tag_js_frameworks(&mut semantics);
            continue;
        }

        if let Some(caps) = import_default_re.captures(line) {
            let alias = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let module = caps.get(2).map(|m| m.as_str()).unwrap_or("").to_string();
            if !alias.is_empty() && !module.is_empty() {
                semantics.js_namespace_imports.insert(alias, module.clone());
                semantics.imported_modules.insert(module);
                tag_js_frameworks(&mut semantics);
            }
            continue;
        }

        if let Some(caps) = require_re.captures(line) {
            let alias = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let module = caps.get(2).map(|m| m.as_str()).unwrap_or("").to_string();
            if !alias.is_empty() && !module.is_empty() {
                semantics.js_namespace_imports.insert(alias, module.clone());
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

    semantics
}

fn extract_ruby(source: &str) -> FileSemantics {
    let mut semantics = FileSemantics::default();
    let require_re = Regex::new(r#"^\s*require(?:_relative)?\s+['"]([^'"]+)['"]"#).unwrap();
    let assign_re = Regex::new(
        r#"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$"#
    ).unwrap();

    if source.contains("params[")
        || source.contains("params.")
        || source.contains("ActionController")
        || source.contains("html_safe")
        || source.contains("render text:")
        || source.contains("raw(")
    {
        semantics.frameworks.insert("rails".into());
    }

    for raw_line in source.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        if let Some(caps) = require_re.captures(line) {
            let module = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            if !module.is_empty() {
                semantics.imported_modules.insert(module);
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

    semantics
}

fn extract_java(source: &str) -> FileSemantics {
    let mut semantics = FileSemantics::default();
    let import_re = Regex::new(r#"^\s*import\s+([\w\.]+);"#).unwrap();
    let assign_re = Regex::new(
        r#"^\s*(?:[A-Za-z_][A-Za-z0-9_<>\[\]]*\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*;?\s*$"#
    ).unwrap();
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

    for raw_line in source.lines() {
        let line = raw_line.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
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

    semantics
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

fn extract_csharp(source: &str) -> FileSemantics {
    let mut semantics = FileSemantics::default();

    let using_re = Regex::new(r"^\s*using\s+([A-Za-z_][A-Za-z0-9_\.]*)\s*;").unwrap();
    let using_alias_re = Regex::new(r#"^\s*using\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_\.]*)\s*;"#).unwrap();
    let assign_re = Regex::new(r#"^\s*(?:[A-Za-z_][A-Za-z0-9_<>\[\]]*\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*;?\s*$"#).unwrap();
    let explicit_decl_re = Regex::new(
        r#"^\s*([A-Za-z_][A-Za-z0-9_<>\.\[\]]*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*;?\s*$"#
    ).unwrap();
    let new_type_re = Regex::new(r#"new\s+([A-Za-z_][A-Za-z0-9_<>\.]*)\s*\("#).unwrap();

    for raw_line in source.lines() {
        let line = raw_line.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
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

    semantics
}

fn extract_go(source: &str) -> FileSemantics {
    let mut semantics = FileSemantics::default();
    let single_import_re = Regex::new(r#"^\s*import\s+(?:(\w+)\s+)?"([^"]+)""#).unwrap();
    let block_import_re = Regex::new(r#"^\s*(?:(\w+)\s+)?"([^"]+)""#).unwrap();
    let assign_re = Regex::new(
        r#"^\s*(?:var\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?::=|=)\s*(.+?)\s*$"#
    ).unwrap();
    let mut in_import_block = false;

    for raw_line in source.lines() {
        let line = raw_line.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
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

    semantics
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
