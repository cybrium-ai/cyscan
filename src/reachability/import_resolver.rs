use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};

use regex::Regex;

#[derive(Debug)]
pub struct ImportIndex {
    imports: HashMap<String, HashSet<PathBuf>>,
    call_sites: HashMap<String, Vec<(String, String)>>,
    file_count: usize,
    total_imports: usize,
}

impl ImportIndex {
    pub fn total_imports(&self) -> usize { self.total_imports }
    pub fn file_count(&self) -> usize { self.file_count }

    pub fn is_package_imported(&self, package: &str) -> bool {
        package_variants(package)
            .iter()
            .any(|candidate| self.imports.contains_key(candidate))
    }

    pub fn is_any_package_imported(&self, packages: &[String]) -> bool {
        packages.iter().any(|package| self.is_package_imported(package))
    }

    pub fn get_import_sites(&self, package: &str) -> Vec<(String, String)> {
        for candidate in package_variants(package) {
            if let Some(sites) = self.imports.get(&candidate) {
                return sites
                    .iter()
                    .map(|file| (file.display().to_string(), format!("import {candidate}")))
                    .collect();
            }
        }
        Vec::new()
    }

    pub fn get_import_sites_any(&self, packages: &[String]) -> Vec<(String, String)> {
        for package in packages {
            let sites = self.get_import_sites(package);
            if !sites.is_empty() {
                return sites;
            }
        }
        Vec::new()
    }

    pub fn find_call_chain(&self, package: &str, symbol: &str) -> Option<Vec<(String, String)>> {
        let symbol_variants = symbol_variants(symbol);
        for package_variant in package_variants(package) {
            for symbol_variant in &symbol_variants {
                let key = callsite_key(&package_variant, symbol_variant);
                if let Some(sites) = self.call_sites.get(&key) {
                    if !sites.is_empty() {
                        return Some(sites.clone());
                    }
                }
            }
        }
        None
    }
}

pub fn build_import_index(target: &Path) -> ImportIndex {
    let mut imports: HashMap<String, HashSet<PathBuf>> = HashMap::new();
    let mut call_sites: HashMap<String, Vec<(String, String)>> = HashMap::new();
    let (mut file_count, mut total_imports) = (0usize, 0usize);
    let walker = walkdir::WalkDir::new(target).into_iter().filter_entry(|e| {
        if e.depth() == 0 {
            return true;
        }
        let n = e.file_name().to_str().unwrap_or("");
        !n.starts_with('.')
            && n != "node_modules"
            && n != "target"
            && n != "__pycache__"
            && n != "vendor"
            && n != "venv"
    });

    for entry in walker.filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let src = match fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let (file_imports, file_calls) = match ext {
            "py" => py(&src, path),
            "js" | "mjs" | "cjs" | "jsx" | "ts" | "tsx" => js(&src, path),
            "go" => go(&src, path),
            "java" | "kt" => java(&src, path),
            _ => continue,
        };
        if !file_imports.is_empty() {
            file_count += 1;
        }
        for import_name in file_imports {
            total_imports += 1;
            add_import(&mut imports, &import_name, path);
        }
        for (package, symbol, loc, snippet) in file_calls {
            add_call(&mut call_sites, &package, &symbol, loc, snippet);
        }
    }

    ImportIndex { imports, call_sites, file_count, total_imports }
}

type CallSite = (String, String, String, String);

fn add_import(imports: &mut HashMap<String, HashSet<PathBuf>>, import_name: &str, path: &Path) {
    for candidate in package_variants(import_name) {
        imports.entry(candidate).or_default().insert(path.to_path_buf());
    }
}

fn add_call(
    call_sites: &mut HashMap<String, Vec<(String, String)>>,
    package: &str,
    symbol: &str,
    loc: String,
    snippet: String,
) {
    for package_variant in package_variants(package) {
        for symbol_variant in symbol_variants(symbol) {
            call_sites
                .entry(callsite_key(&package_variant, &symbol_variant))
                .or_default()
                .push((loc.clone(), snippet.clone()));
        }
    }
}

fn callsite_key(package: &str, symbol: &str) -> String {
    format!("{}::{}", normalize_package(package), normalize_symbol(symbol))
}

fn package_variants(package: &str) -> Vec<String> {
    let normalized = normalize_package(package);
    let slash = normalized.replace('-', "/");
    let underscore = normalized.replace('-', "_");
    let tail = normalized.rsplit('/').next().unwrap_or(&normalized).to_string();
    let mut out = vec![package.to_string(), normalized, slash, underscore, tail];
    out.sort();
    out.dedup();
    out
}

fn normalize_package(package: &str) -> String {
    package.to_ascii_lowercase().replace('_', "-")
}

fn symbol_variants(symbol: &str) -> Vec<String> {
    let normalized = normalize_symbol(symbol);
    let tail = normalized.rsplit('.').next().unwrap_or(&normalized).to_string();
    let mut out = vec![symbol.to_string(), normalized, tail];
    out.sort();
    out.dedup();
    out
}

fn normalize_symbol(symbol: &str) -> String {
    symbol.replace("::", ".").replace('/', ".")
}

fn py(src: &str, path: &Path) -> (Vec<String>, Vec<CallSite>) {
    let (mut imports, mut calls) = (Vec::new(), Vec::new());
    let mut names: HashMap<String, String> = HashMap::new();
    let mut imported_symbols: HashMap<String, (String, String)> = HashMap::new();
    let import_re = Regex::new(r"^\s*import\s+([A-Za-z_][\w.]*)").unwrap();
    let from_re = Regex::new(r"^\s*from\s+([A-Za-z_][\w.]*)\s+import\s+(.+)").unwrap();
    let member_call_re = Regex::new(r"([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)\s*\(").unwrap();
    let direct_call_re = Regex::new(r"(?m)(?:^|[^.\w])([A-Za-z_][A-Za-z0-9_]*)\s*\(").unwrap();

    for line in src.lines() {
        if let Some(caps) = import_re.captures(line) {
            let package = caps[1].to_string();
            let alias = package.split('.').next().unwrap_or(&package).to_string();
            names.insert(alias, package.clone());
            imports.push(package);
        }
        if let Some(caps) = from_re.captures(line) {
            let package = caps[1].to_string();
            imports.push(package.clone());
            for item in caps[2].split(',') {
                let item = item.trim();
                let alias = item.split(" as ").nth(1).unwrap_or(item).trim();
                let symbol = item.split(" as ").next().unwrap_or("").trim();
                if !alias.is_empty() && alias != "*" && !symbol.is_empty() {
                    imported_symbols.insert(alias.to_string(), (package.clone(), symbol.to_string()));
                }
            }
        }
    }

    for (line_no, line) in src.lines().enumerate() {
        for caps in member_call_re.captures_iter(line) {
            if let Some(package) = names.get(&caps[1]) {
                calls.push((
                    package.clone(),
                    caps[2].to_string(),
                    format!("{}:{}", path.display(), line_no + 1),
                    line.trim().to_string(),
                ));
            }
        }
        for caps in direct_call_re.captures_iter(line) {
            let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            if let Some((package, symbol)) = imported_symbols.get(name) {
                calls.push((
                    package.clone(),
                    symbol.clone(),
                    format!("{}:{}", path.display(), line_no + 1),
                    line.trim().to_string(),
                ));
            }
        }
    }

    (imports, calls)
}

fn js(src: &str, path: &Path) -> (Vec<String>, Vec<CallSite>) {
    let (mut imports, mut calls) = (Vec::new(), Vec::new());
    let mut namespace_names: HashMap<String, String> = HashMap::new();
    let mut imported_symbols: HashMap<String, (String, String)> = HashMap::new();
    let require_re = Regex::new(
        r#"(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]"#
    ).unwrap();
    let import_default_re = Regex::new(
        r#"import\s+([A-Za-z_$][A-Za-z0-9_$]*)\s+from\s+['"]([^'"]+)['"]"#
    ).unwrap();
    let import_named_re = Regex::new(r#"import\s+\{([^}]+)\}\s+from\s+['"]([^'"]+)['"]"#).unwrap();
    let require_named_re = Regex::new(
        r#"(?:const|let|var)\s+\{([^}]+)\}\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)"#
    ).unwrap();
    let member_call_re = Regex::new(r"([A-Za-z_$][A-Za-z0-9_$]*)\.([A-Za-z_$][A-Za-z0-9_$]*)\s*\(").unwrap();
    let direct_call_re = Regex::new(r"(?m)(?:^|[^.\w])([A-Za-z_$][A-Za-z0-9_$]*)\s*\(").unwrap();

    for line in src.lines() {
        if let Some(caps) = require_re.captures(line) {
            namespace_names.insert(caps[1].to_string(), caps[2].to_string());
            imports.push(caps[2].to_string());
        }
        if let Some(caps) = import_default_re.captures(line) {
            namespace_names.insert(caps[1].to_string(), caps[2].to_string());
            imports.push(caps[2].to_string());
        }
        if let Some(caps) = import_named_re.captures(line) {
            let package = caps[2].to_string();
            imports.push(package.clone());
            for item in caps[1].split(',') {
                let item = item.trim();
                let alias = item.split(" as ").nth(1).unwrap_or(item).trim();
                let symbol = item.split(" as ").next().unwrap_or("").trim();
                if !alias.is_empty() && !symbol.is_empty() {
                    imported_symbols.insert(alias.to_string(), (package.clone(), symbol.to_string()));
                }
            }
        }
        if let Some(caps) = require_named_re.captures(line) {
            let package = caps[2].to_string();
            imports.push(package.clone());
            for item in caps[1].split(',') {
                let item = item.trim();
                let mut parts = item.split(':');
                let symbol = parts.next().unwrap_or("").trim();
                let alias = parts.next().unwrap_or(symbol).trim();
                if !alias.is_empty() && !symbol.is_empty() {
                    imported_symbols.insert(alias.to_string(), (package.clone(), symbol.to_string()));
                }
            }
        }
    }

    for (line_no, line) in src.lines().enumerate() {
        for caps in member_call_re.captures_iter(line) {
            if let Some(package) = namespace_names.get(&caps[1]) {
                calls.push((
                    package.clone(),
                    caps[2].to_string(),
                    format!("{}:{}", path.display(), line_no + 1),
                    line.trim().to_string(),
                ));
            }
        }
        for caps in direct_call_re.captures_iter(line) {
            let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            if let Some((package, symbol)) = imported_symbols.get(name) {
                calls.push((
                    package.clone(),
                    symbol.clone(),
                    format!("{}:{}", path.display(), line_no + 1),
                    line.trim().to_string(),
                ));
            }
        }
    }

    (imports, calls)
}

fn go(src: &str, path: &Path) -> (Vec<String>, Vec<CallSite>) {
    let (mut imports, mut calls) = (Vec::new(), Vec::new());
    let mut names: HashMap<String, String> = HashMap::new();
    let single_import_re = Regex::new(r#"^\s*import\s+(?:(\w+)\s+)?"([^"]+)""#).unwrap();
    let block_import_re = Regex::new(r#"^\s*(?:(\w+)\s+)?"([^"]+)""#).unwrap();
    let member_call_re = Regex::new(r"([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)\s*\(").unwrap();
    let mut in_import_block = false;

    for line in src.lines() {
        let trimmed = line.trim();
        if trimmed == "import (" {
            in_import_block = true;
            continue;
        }
        if in_import_block && trimmed == ")" {
            in_import_block = false;
            continue;
        }
        let import_caps = if in_import_block {
            block_import_re.captures(trimmed)
        } else {
            single_import_re.captures(trimmed)
        };
        if let Some(caps) = import_caps {
            let alias = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let package = caps.get(2).map(|m| m.as_str()).unwrap_or("").to_string();
            if !package.is_empty() {
                let default_alias = package.rsplit('/').next().unwrap_or(&package).to_string();
                names.insert(if alias.is_empty() { default_alias } else { alias.to_string() }, package.clone());
                imports.push(package);
            }
        }
    }

    for (line_no, line) in src.lines().enumerate() {
        for caps in member_call_re.captures_iter(line) {
            if let Some(package) = names.get(&caps[1]) {
                calls.push((
                    package.clone(),
                    caps[2].to_string(),
                    format!("{}:{}", path.display(), line_no + 1),
                    line.trim().to_string(),
                ));
            }
        }
    }

    (imports, calls)
}

fn java(src: &str, path: &Path) -> (Vec<String>, Vec<CallSite>) {
    let (mut imports, mut calls) = (Vec::new(), Vec::new());
    let mut class_names: HashMap<String, String> = HashMap::new();
    let mut imported_symbols: HashMap<String, (String, String)> = HashMap::new();
    let import_re = Regex::new(r#"^\s*import\s+([\w.]+);"#).unwrap();
    let static_import_re = Regex::new(r#"^\s*import\s+static\s+([\w.]+)\.([A-Za-z_][A-Za-z0-9_]*)\s*;"#).unwrap();
    let member_call_re = Regex::new(r"([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)\s*\(").unwrap();
    let direct_call_re = Regex::new(r"(?m)(?:^|[^.\w])([A-Za-z_][A-Za-z0-9_]*)\s*\(").unwrap();

    for line in src.lines() {
        if let Some(caps) = static_import_re.captures(line) {
            let package = caps[1].to_string();
            let symbol = caps[2].to_string();
            imports.push(package.clone());
            imported_symbols.insert(symbol.clone(), (package, symbol));
            continue;
        }
        if let Some(caps) = import_re.captures(line) {
            let package = caps[1].to_string();
            if let Some(alias) = package.rsplit('.').next() {
                class_names.insert(alias.to_string(), package.clone());
            }
            imports.push(package);
        }
    }

    for (line_no, line) in src.lines().enumerate() {
        for caps in member_call_re.captures_iter(line) {
            if let Some(package) = class_names.get(&caps[1]) {
                calls.push((
                    package.clone(),
                    caps[2].to_string(),
                    format!("{}:{}", path.display(), line_no + 1),
                    line.trim().to_string(),
                ));
            }
        }
        for caps in direct_call_re.captures_iter(line) {
            let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            if let Some((package, symbol)) = imported_symbols.get(name) {
                calls.push((
                    package.clone(),
                    symbol.clone(),
                    format!("{}:{}", path.display(), line_no + 1),
                    line.trim().to_string(),
                ));
            }
        }
    }

    (imports, calls)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_from_import_direct_call_is_recorded() {
        let (_, calls) = py("from yaml import load\nload(data)\n", Path::new("app.py"));
        assert!(calls.iter().any(|(pkg, sym, _, _)| pkg == "yaml" && sym == "load"));
    }

    #[test]
    fn javascript_named_import_direct_call_is_recorded() {
        let (_, calls) = js("import { template } from 'lodash'\ntemplate(input)\n", Path::new("app.js"));
        assert!(calls.iter().any(|(pkg, sym, _, _)| pkg == "lodash" && sym == "template"));
    }

    #[test]
    fn go_alias_call_is_recorded() {
        let (_, calls) = go("import helper \"github.com/acme/helper\"\nfunc run(){ helper.Run(x) }\n", Path::new("main.go"));
        assert!(calls.iter().any(|(pkg, sym, _, _)| pkg == "github.com/acme/helper" && sym == "Run"));
    }

    #[test]
    fn java_static_import_direct_call_is_recorded() {
        let (_, calls) = java("import static app.helper.Runner.run;\nclass X { void x(){ run(data); } }\n", Path::new("X.java"));
        assert!(calls.iter().any(|(pkg, sym, _, _)| pkg == "app.helper.Runner" && sym == "run"));
    }

    #[test]
    fn import_index_finds_python_direct_import_call_chain() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("app.py"), "from yaml import load\nload(data)\n").unwrap();
        let index = build_import_index(tmp.path());
        let chain = index.find_call_chain("yaml", "yaml.load");
        assert!(chain.is_some());
    }
}
