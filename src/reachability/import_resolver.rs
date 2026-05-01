use std::{collections::{HashMap, HashSet}, fs, path::{Path, PathBuf}};
use regex::Regex;

#[derive(Debug)]
pub struct ImportIndex {
    imports: HashMap<String, HashSet<PathBuf>>,
    call_sites: HashMap<(String, String), Vec<(String, String)>>,
    file_count: usize,
    total_imports: usize,
}

impl ImportIndex {
    pub fn total_imports(&self) -> usize { self.total_imports }
    pub fn file_count(&self) -> usize { self.file_count }
    pub fn is_package_imported(&self, package: &str) -> bool {
        let n = package.to_lowercase().replace('_', "-");
        self.imports.contains_key(package) || self.imports.contains_key(&n)
            || self.imports.keys().any(|k| k.contains(package))
    }
    pub fn get_import_sites(&self, package: &str) -> Vec<(String, String)> {
        let n = package.to_lowercase().replace('_', "-");
        self.imports.get(package).or_else(|| self.imports.get(&n))
            .map(|s| s.iter().map(|f| (f.display().to_string(), format!("import {package}"))).collect())
            .unwrap_or_default()
    }
    pub fn find_call_chain(&self, package: &str, symbol: &str) -> Option<Vec<(String, String)>> {
        let variants = symbol_variants(symbol);
        let package_variants = package_variants(package);
        for pkg in &package_variants {
            for sym in &variants {
                if let Some(s) = self.call_sites.get(&(pkg.clone(), sym.clone())) {
                    if !s.is_empty() {
                        return Some(s.clone());
                    }
                }
            }
        }
        for ((p, s), sites) in &self.call_sites {
            if package_variants.iter().any(|pkg| pkg == p)
                && variants.iter().any(|sym| s == sym || s.contains(sym))
                && !sites.is_empty()
            {
                return Some(sites.clone());
            }
        }
        None
    }
}

pub fn build_import_index(target: &Path) -> ImportIndex {
    let mut imports: HashMap<String, HashSet<PathBuf>> = HashMap::new();
    let mut call_sites: HashMap<(String, String), Vec<(String, String)>> = HashMap::new();
    let (mut fc, mut ti) = (0usize, 0usize);
    let walker = walkdir::WalkDir::new(target).into_iter().filter_entry(|e| {
        if e.depth() == 0 {
            return true;
        }
        let n = e.file_name().to_str().unwrap_or("");
        !n.starts_with('.') && n != "node_modules" && n != "target" && n != "__pycache__" && n != "vendor" && n != "venv"
    });
    for entry in walker.filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() { continue; }
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let src = match fs::read_to_string(path) { Ok(s) => s, Err(_) => continue };
        let (fi, fc2) = match ext {
            "py" => py(&src, path), "js"|"mjs"|"cjs"|"jsx"|"ts"|"tsx" => js(&src, path),
            "go" => go(&src, path), "java"|"kt" => java(&src, path), _ => continue,
        };
        if !fi.is_empty() { fc += 1; }
        for (pkg, _) in &fi { imports.entry(pkg.clone()).or_default().insert(path.to_path_buf()); ti += 1; }
        for (pkg, sym, loc, snip) in fc2 { call_sites.entry((pkg, sym)).or_default().push((loc, snip)); }
    }
    ImportIndex { imports, call_sites, file_count: fc, total_imports: ti }
}

type I = (String, String);
type C = (String, String, String, String);

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
    package.to_lowercase().replace('_', "-")
}

fn symbol_variants(symbol: &str) -> Vec<String> {
    let normalized = symbol.replace("::", ".").replace('/', ".");
    let tail = normalized.rsplit('.').next().unwrap_or(&normalized).to_string();
    let mut out = vec![symbol.to_string(), normalized, tail];
    out.sort();
    out.dedup();
    out
}

fn py(src: &str, p: &Path) -> (Vec<I>, Vec<C>) {
    let (mut im, mut ca) = (vec![], vec![]);
    let mut names: HashMap<String, String> = HashMap::new();
    let mut imported_symbols: HashMap<String, (String, String)> = HashMap::new();
    let ri = Regex::new(r"^\s*import\s+(\w[\w.]*)").unwrap();
    let rf = Regex::new(r"^\s*from\s+(\w[\w.]*)\s+import\s+(.+)").unwrap();
    let rc = Regex::new(r"(\w+)\.(\w+)\s*\(").unwrap();
    let rd = Regex::new(r"(?m)(?:^|[^.\w])([A-Za-z_][A-Za-z0-9_]*)\s*\(").unwrap();
    for (_, l) in src.lines().enumerate() {
        if let Some(c) = ri.captures(l) { let pk=c[1].to_string(); let t=pk.split('.').next().unwrap_or(&pk).to_string(); names.insert(t.clone(),pk.clone()); im.push((pk,t)); }
        if let Some(c) = rf.captures(l) {
            let pk=c[1].to_string();
            let t=pk.split('.').next().unwrap_or(&pk).to_string();
            im.push((pk.clone(),t.clone()));
            for s in c[2].split(',') {
                let item = s.trim();
                let alias = item.split(" as ").nth(1).unwrap_or(item).trim();
                let sym = item.split(" as ").next().unwrap_or("").trim();
                if !alias.is_empty() && alias != "*" && !sym.is_empty() {
                    names.insert(alias.to_string(),pk.clone());
                    imported_symbols.insert(alias.to_string(), (pk.clone(), sym.to_string()));
                }
            }
        }
    }
    for (ln, l) in src.lines().enumerate() { for c in rc.captures_iter(l) { if let Some(pk) = names.get(&c[1]) { ca.push((pk.clone(),c[2].to_string(),format!("{}:{}",p.display(),ln+1),l.trim().to_string())); } } }
    for (ln, l) in src.lines().enumerate() {
        for c in rd.captures_iter(l) {
            let name = c.get(1).map(|m| m.as_str()).unwrap_or("");
            if let Some((pk, sym)) = imported_symbols.get(name) {
                ca.push((pk.clone(), sym.clone(), format!("{}:{}", p.display(), ln + 1), l.trim().to_string()));
            }
        }
    }
    (im, ca)
}

fn js(src: &str, p: &Path) -> (Vec<I>, Vec<C>) {
    let (mut im, mut ca) = (vec![], vec![]);
    let mut names: HashMap<String, String> = HashMap::new();
    let mut imported_symbols: HashMap<String, (String, String)> = HashMap::new();
    let rr = Regex::new(r#"(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]"#).unwrap();
    let ri = Regex::new(r#"import\s+(\w+)\s+from\s+['"]([^'"]+)['"]"#).unwrap();
    let rn = Regex::new(r#"import\s+\{([^}]+)\}\s+from\s+['"]([^'"]+)['"]"#).unwrap();
    let rc = Regex::new(r"(\w+)\.(\w+)\s*\(").unwrap();
    let rd = Regex::new(r"(?m)(?:^|[^.\w])([A-Za-z_$][A-Za-z0-9_$]*)\s*\(").unwrap();
    for (_, l) in src.lines().enumerate() {
        if let Some(c) = rr.captures(l) { names.insert(c[1].to_string(),c[2].to_string()); im.push((c[2].to_string(),c[1].to_string())); }
        if let Some(c) = ri.captures(l) { names.insert(c[1].to_string(),c[2].to_string()); im.push((c[2].to_string(),c[1].to_string())); }
        if let Some(c) = rn.captures(l) {
            let module = c[2].to_string();
            im.push((module.clone(), module.rsplit('/').next().unwrap_or(&module).to_string()));
            for item in c[1].split(',') {
                let item = item.trim();
                let alias = item.split(" as ").nth(1).unwrap_or(item).trim();
                let sym = item.split(" as ").next().unwrap_or("").trim();
                if !alias.is_empty() && !sym.is_empty() {
                    imported_symbols.insert(alias.to_string(), (module.clone(), sym.to_string()));
                }
            }
        }
    }
    for (ln, l) in src.lines().enumerate() { for c in rc.captures_iter(l) { if let Some(pk) = names.get(&c[1]) { ca.push((pk.clone(),c[2].to_string(),format!("{}:{}",p.display(),ln+1),l.trim().to_string())); } } }
    for (ln, l) in src.lines().enumerate() {
        for c in rd.captures_iter(l) {
            let name = c.get(1).map(|m| m.as_str()).unwrap_or("");
            if let Some((pk, sym)) = imported_symbols.get(name) {
                ca.push((pk.clone(), sym.clone(), format!("{}:{}", p.display(), ln + 1), l.trim().to_string()));
            }
        }
    }
    (im, ca)
}

fn go(src: &str, p: &Path) -> (Vec<I>, Vec<C>) {
    let (mut im, mut ca) = (vec![], vec![]);
    let mut names: HashMap<String, String> = HashMap::new();
    let re = Regex::new(r#"^\s*"([^"]+)""#).unwrap();
    let rc = Regex::new(r"(\w+)\.(\w+)\s*\(").unwrap();
    let mut ib = false;
    for (_, l) in src.lines().enumerate() {
        if l.trim()=="import (" { ib=true; continue; } if ib && l.trim()==")" { ib=false; continue; }
        if ib || l.trim_start().starts_with("import \"") { if let Some(c)=re.captures(l) { let pk=c[1].to_string(); let s=pk.split('/').last().unwrap_or(&pk).to_string(); names.insert(s.clone(),pk.clone()); im.push((pk,s)); } }
    }
    for (ln, l) in src.lines().enumerate() { for c in rc.captures_iter(l) { if let Some(pk) = names.get(&c[1]) { ca.push((pk.clone(),c[2].to_string(),format!("{}:{}",p.display(),ln+1),l.trim().to_string())); } } }
    (im, ca)
}

fn java(src: &str, _p: &Path) -> (Vec<I>, Vec<C>) {
    let mut im = vec![];
    let re = Regex::new(r"^\s*import\s+([\w.]+);").unwrap();
    for (_, l) in src.lines().enumerate() { if let Some(c) = re.captures(l) { let f=c[1].to_string(); let s=f.split('.').last().unwrap_or(&f).to_string(); im.push((f,s)); } }
    (im, vec![])
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
    fn import_index_finds_python_direct_import_call_chain() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("app.py"), "from yaml import load\nload(data)\n").unwrap();
        let index = build_import_index(tmp.path());
        let chain = index.find_call_chain("yaml", "yaml.load");
        assert!(chain.is_some());
    }
}
