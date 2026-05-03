//! Symbol-table layer (Phase C — start of compiler-grade resolution).
//!
//! The semantic extractor in `matcher::semantics` is a flat regex pass
//! that records `variable_types: HashMap<String, String>`. That works
//! for the common case (`db = sqlite3.connect()` → `db: sqlite3`) but
//! collapses on shadowing, late binding, and dynamic dispatch.
//!
//! This module adds a real *scope-aware* symbol table: a stack of
//! lexical scopes, each carrying its own bindings, with lookup that
//! walks outward to the enclosing function / module / global. It's
//! still regex-driven at the parse layer (a real symbol-table pass
//! would consume tree-sitter trees), but the **resolution** is now
//! correct under shadowing — which was the headline limitation in the
//! parity audit.
//!
//! Currently covers Python only — the other languages will follow in
//! later releases. Consumers (rule guards, dataflow propagation) call
//! `resolve(file, line, name) -> Option<Symbol>` to get the binding
//! that's in scope at a given source position.

use std::collections::HashMap;

/// A single binding in a scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    pub name:    String,
    /// Declared type or originating module — best-effort. `None` means
    /// the resolver couldn't infer it (e.g. `x = compute()` where
    /// `compute` returns dynamically).
    pub kind:    Option<String>,
    /// Source line where the binding starts. 1-indexed.
    pub line:    usize,
    /// Source line where the enclosing scope ends — `usize::MAX` for
    /// module-level bindings.
    pub end_line: usize,
    pub scope_kind: ScopeKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeKind {
    Module,
    Function,
    Class,
}

/// File-level symbol table — multiple scopes ordered by start_line.
#[derive(Debug, Default, Clone)]
pub struct SymbolTable {
    pub scopes: Vec<Scope>,
}

#[derive(Debug, Clone)]
pub struct Scope {
    pub kind:       ScopeKind,
    pub start_line: usize,
    pub end_line:   usize,
    pub indent:     usize,
    pub bindings:   HashMap<String, Symbol>,
    pub parent_idx: Option<usize>,
}

impl SymbolTable {
    /// Resolve `name` in the scope active at `line`. Walks outward
    /// through enclosing scopes. Returns the *narrowest* binding that
    /// covers the line — i.e. shadowing wins.
    pub fn resolve(&self, line: usize, name: &str) -> Option<&Symbol> {
        // Find the smallest scope containing `line`.
        let mut best: Option<usize> = None;
        let mut best_size = usize::MAX;
        for (i, sc) in self.scopes.iter().enumerate() {
            if sc.start_line <= line && line <= sc.end_line {
                let size = sc.end_line.saturating_sub(sc.start_line);
                if size < best_size {
                    best = Some(i);
                    best_size = size;
                }
            }
        }
        let mut cur = best?;
        loop {
            if let Some(sym) = self.scopes[cur].bindings.get(name) {
                if sym.line <= line {
                    return Some(sym);
                }
            }
            cur = self.scopes[cur].parent_idx?;
        }
    }
}

/// Walk curly braces in a source file and produce a scope tree. Each
/// `{` opens a new scope, `}` closes the innermost one. Strings are
/// skipped via a cheap quote-aware tokenizer — good enough for the
/// statically-typed languages we care about (JS/TS, Java, C#, Go,
/// Rust). The `classify_header` closure is called with the prefix
/// before each `{` to decide the scope kind.
fn build_braced_scope_table<F>(source: &str, mut classify_header: F) -> SymbolTable
where
    F: FnMut(&str, &str) -> ScopeKind,
{
    let mut table = SymbolTable::default();
    let total_lines = source.lines().count().max(1);
    table.scopes.push(Scope {
        kind:       ScopeKind::Module,
        start_line: 1,
        end_line:   total_lines,
        indent:     0,
        bindings:   HashMap::new(),
        parent_idx: None,
    });

    struct Open { idx: usize, depth: usize }
    let mut stack: Vec<Open> = Vec::new();
    let mut depth = 0usize;

    for (line_idx, raw) in source.lines().enumerate() {
        let line_no = line_idx + 1;
        let bytes = raw.as_bytes();
        let mut in_str: Option<u8> = None;
        let mut i = 0usize;
        while i < bytes.len() {
            let c = bytes[i];
            if let Some(q) = in_str {
                if c == b'\\' { i = i.saturating_add(2); continue }
                if c == q { in_str = None; }
                i += 1; continue;
            }
            match c {
                b'"' | b'\'' | b'`' => { in_str = Some(c); }
                b'{' => {
                    depth += 1;
                    let prefix = if i == 0 { "" } else { &raw[..i] };
                    let through = &raw[..=i];
                    let kind = classify_header(prefix, through);
                    let parent_idx = stack.last().map(|o| o.idx).or(Some(0));
                    table.scopes.push(Scope {
                        kind,
                        start_line: line_no,
                        end_line:   total_lines,
                        indent:     0,
                        bindings:   HashMap::new(),
                        parent_idx,
                    });
                    let new_idx = table.scopes.len() - 1;
                    stack.push(Open { idx: new_idx, depth });
                }
                b'}' => {
                    if let Some(top) = stack.last() {
                        if top.depth == depth {
                            table.scopes[top.idx].end_line = line_no;
                            stack.pop();
                        }
                    }
                    depth = depth.saturating_sub(1);
                }
                _ => {}
            }
            i += 1;
        }
    }
    table
}

/// Build a scope-aware symbol table for a single JavaScript or
/// TypeScript source file. Curly-brace scope detection — every `{`
/// opens a new scope, `}` closes the innermost one. We tag the scope
/// kind based on the immediately-preceding header token (`function`,
/// `class`, `=>` for arrow fns, anything else = block scope).
pub fn build_javascript_symbol_table(source: &str) -> SymbolTable {
    use ::regex::Regex;
    let header_fn_re   = Regex::new(r"\bfunction\s+([A-Za-z_][A-Za-z_0-9]*)\s*\(").unwrap();
    let header_anon_re = Regex::new(r"\bfunction\s*\(").unwrap();
    let header_arrow_re = Regex::new(r"=>\s*\{").unwrap();
    let header_class_re = Regex::new(r"\bclass\s+([A-Za-z_][A-Za-z_0-9]*)").unwrap();
    let mut table = build_braced_scope_table(source, |prefix, through| {
        if header_fn_re.is_match(prefix)
            || header_anon_re.is_match(prefix)
            || header_arrow_re.is_match(through)
        {
            ScopeKind::Function
        } else if header_class_re.is_match(prefix) {
            ScopeKind::Class
        } else {
            // Block scope (if/for/while/{...}). Still pushed so
            // shadowing works — tagged as Function for resolution.
            ScopeKind::Function
        }
    });
    let lines: Vec<&str> = source.lines().collect();

    // Pass 2 — extract bindings:
    //   var/let/const NAME [= EXPR]
    //   function NAME(
    //   class NAME
    //   import NAME from 'mod'
    //   import { a, b as c } from 'mod'
    //   import * as NS from 'mod'
    //   const { a, b } = require('mod')
    let var_re      = Regex::new(r"\b(?:var|let|const)\s+([A-Za-z_$][A-Za-z_0-9$]*)\s*(?:=\s*([A-Za-z_$][A-Za-z_0-9$.]*))?").unwrap();
    let fn_decl_re  = Regex::new(r"\bfunction\s+([A-Za-z_$][A-Za-z_0-9$]*)").unwrap();
    let class_re    = Regex::new(r"\bclass\s+([A-Za-z_$][A-Za-z_0-9$]*)").unwrap();
    let import_default_re   = Regex::new(r#"\bimport\s+([A-Za-z_$][A-Za-z_0-9$]*)\s+from\s+['"]([^'"]+)['"]"#).unwrap();
    let import_named_re     = Regex::new(r#"\bimport\s+\{([^}]+)\}\s+from\s+['"]([^'"]+)['"]"#).unwrap();
    let import_ns_re        = Regex::new(r#"\bimport\s+\*\s+as\s+([A-Za-z_$][A-Za-z_0-9$]*)\s+from\s+['"]([^'"]+)['"]"#).unwrap();
    let require_re          = Regex::new(r#"\b(?:var|let|const)\s+([A-Za-z_$][A-Za-z_0-9$]*)\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)"#).unwrap();
    let require_destruc_re  = Regex::new(r#"\b(?:var|let|const)\s+\{([^}]+)\}\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)"#).unwrap();

    for (idx, raw) in lines.iter().enumerate() {
        let line_no = idx + 1;
        let scope_idx = scope_for_line(&table, line_no);
        let scope_end  = table.scopes[scope_idx].end_line;
        let scope_kind = table.scopes[scope_idx].kind;

        if let Some(c) = require_destruc_re.captures(raw) {
            let names = c.get(1).unwrap().as_str();
            let module = c.get(2).unwrap().as_str().to_string();
            for n in names.split(',') {
                let raw_n = n.trim();
                let alias = raw_n.split(':').last().unwrap_or(raw_n).trim();
                if alias.is_empty() { continue; }
                table.scopes[scope_idx].bindings.insert(alias.to_string(), Symbol {
                    name: alias.to_string(),
                    kind: Some(format!("{module}.{alias}")),
                    line: line_no,
                    end_line: scope_end,
                    scope_kind,
                });
            }
            continue;
        }

        if let Some(c) = require_re.captures(raw) {
            let name = c.get(1).unwrap().as_str().to_string();
            let module = c.get(2).unwrap().as_str().to_string();
            table.scopes[scope_idx].bindings.insert(name.clone(), Symbol {
                name, kind: Some(module), line: line_no, end_line: scope_end, scope_kind,
            });
            continue;
        }

        if let Some(c) = import_ns_re.captures(raw) {
            let alias = c.get(1).unwrap().as_str().to_string();
            let module = c.get(2).unwrap().as_str().to_string();
            table.scopes[scope_idx].bindings.insert(alias.clone(), Symbol {
                name: alias, kind: Some(module), line: line_no, end_line: scope_end, scope_kind,
            });
            continue;
        }

        if let Some(c) = import_named_re.captures(raw) {
            let names = c.get(1).unwrap().as_str();
            let module = c.get(2).unwrap().as_str().to_string();
            for n in names.split(',') {
                let raw_n = n.trim();
                let parts: Vec<&str> = raw_n.split(" as ").collect();
                let original = parts.first().copied().unwrap_or(raw_n).trim();
                let alias    = parts.get(1).copied().unwrap_or(original).trim();
                if alias.is_empty() { continue; }
                table.scopes[scope_idx].bindings.insert(alias.to_string(), Symbol {
                    name: alias.to_string(),
                    kind: Some(format!("{module}.{original}")),
                    line: line_no,
                    end_line: scope_end,
                    scope_kind,
                });
            }
            continue;
        }

        if let Some(c) = import_default_re.captures(raw) {
            let name = c.get(1).unwrap().as_str().to_string();
            let module = c.get(2).unwrap().as_str().to_string();
            table.scopes[scope_idx].bindings.insert(name.clone(), Symbol {
                name, kind: Some(module), line: line_no, end_line: scope_end, scope_kind,
            });
            continue;
        }

        if let Some(c) = var_re.captures(raw) {
            let name = c.get(1).unwrap().as_str().to_string();
            let kind = c.get(2).map(|m| m.as_str()).and_then(guess_kind_from_rhs);
            table.scopes[scope_idx].bindings.insert(name.clone(), Symbol {
                name, kind, line: line_no, end_line: scope_end, scope_kind,
            });
        }

        if let Some(c) = fn_decl_re.captures(raw) {
            let name = c.get(1).unwrap().as_str().to_string();
            table.scopes[scope_idx].bindings.insert(name.clone(), Symbol {
                name: name.clone(),
                kind: Some("function".to_string()),
                line: line_no,
                end_line: scope_end,
                scope_kind,
            });
        }

        if let Some(c) = class_re.captures(raw) {
            let name = c.get(1).unwrap().as_str().to_string();
            table.scopes[scope_idx].bindings.insert(name.clone(), Symbol {
                name: name.clone(),
                kind: Some(name),
                line: line_no,
                end_line: scope_end,
                scope_kind: ScopeKind::Class,
            });
        }
    }

    table
}

/// Build a scope-aware symbol table for a single Java source file.
/// Curly-brace scope detection. Tracks `import com.foo.Bar;` as a
/// module-level binding and `Bar x = new Bar()` as a typed local.
pub fn build_java_symbol_table(source: &str) -> SymbolTable {
    use ::regex::Regex;
    let header_method = Regex::new(
        r"\b(?:public|private|protected|static|final|abstract|synchronized|native|default|\s)+\s+[A-Za-z_<>\[\]\?,\s\.]+\s+([A-Za-z_][A-Za-z_0-9]*)\s*\([^)]*\)\s*(?:throws\s+[^{]+)?$",
    ).unwrap();
    let header_class = Regex::new(r"\b(?:class|interface|enum|record)\s+([A-Za-z_][A-Za-z_0-9]*)").unwrap();

    let mut table = build_braced_scope_table(source, |prefix, _through| {
        if header_class.is_match(prefix) {
            ScopeKind::Class
        } else if header_method.is_match(prefix.trim_end()) {
            ScopeKind::Function
        } else {
            ScopeKind::Function
        }
    });
    let module_end = table.scopes[0].end_line;

    let import_re   = Regex::new(r"^\s*import\s+(?:static\s+)?([A-Za-z_][A-Za-z_0-9.]*)\s*;").unwrap();
    let pkg_re      = Regex::new(r"^\s*package\s+([A-Za-z_][A-Za-z_0-9.]*)\s*;").unwrap();
    let local_decl  = Regex::new(
        r"^\s*(?:final\s+)?([A-Z][A-Za-z_0-9<>\[\]]*)\s+([A-Za-z_][A-Za-z_0-9]*)\s*(?:=|;|\)|,)",
    ).unwrap();
    let new_assign  = Regex::new(
        r"^\s*(?:final\s+)?(?:[A-Z][A-Za-z_0-9<>\[\]]*\s+)?([A-Za-z_][A-Za-z_0-9]*)\s*=\s*new\s+([A-Z][A-Za-z_0-9]*)",
    ).unwrap();
    let class_re    = Regex::new(r"\b(?:class|interface|enum|record)\s+([A-Za-z_][A-Za-z_0-9]*)").unwrap();

    let mut package: Option<String> = None;
    let lines: Vec<&str> = source.lines().collect();
    for (idx, raw) in lines.iter().enumerate() {
        let line_no = idx + 1;
        let scope_idx = scope_for_line(&table, line_no);
        let scope_end = table.scopes[scope_idx].end_line;
        let scope_kind = table.scopes[scope_idx].kind;

        if let Some(c) = pkg_re.captures(raw) {
            package = Some(c.get(1).unwrap().as_str().to_string());
            continue;
        }

        if let Some(c) = import_re.captures(raw) {
            let fqn = c.get(1).unwrap().as_str().to_string();
            let alias = fqn.rsplit('.').next().unwrap_or(&fqn).to_string();
            // Module-scope binding so it's visible everywhere.
            table.scopes[0].bindings.insert(alias.clone(), Symbol {
                name: alias, kind: Some(fqn), line: line_no,
                end_line: module_end,
                scope_kind: ScopeKind::Module,
            });
            continue;
        }

        if let Some(c) = new_assign.captures(raw) {
            let name = c.get(1).unwrap().as_str().to_string();
            let ty   = c.get(2).unwrap().as_str().to_string();
            let resolved = resolve_imported(&table, &ty).unwrap_or(ty);
            table.scopes[scope_idx].bindings.insert(name.clone(), Symbol {
                name, kind: Some(resolved), line: line_no, end_line: scope_end, scope_kind,
            });
            continue;
        }

        if let Some(c) = local_decl.captures(raw) {
            let ty   = c.get(1).unwrap().as_str().to_string();
            let name = c.get(2).unwrap().as_str().to_string();
            let resolved = resolve_imported(&table, &ty).unwrap_or(ty);
            table.scopes[scope_idx].bindings.insert(name.clone(), Symbol {
                name, kind: Some(resolved), line: line_no, end_line: scope_end, scope_kind,
            });
        }

        if let Some(c) = class_re.captures(raw) {
            let cls = c.get(1).unwrap().as_str().to_string();
            let fqn = match &package {
                Some(p) => format!("{p}.{cls}"),
                None    => cls.clone(),
            };
            table.scopes[scope_idx].bindings.insert(cls.clone(), Symbol {
                name: cls.clone(), kind: Some(fqn),
                line: line_no, end_line: scope_end,
                scope_kind: ScopeKind::Class,
            });
        }
    }

    table
}

/// Build a scope-aware symbol table for a single C# source file.
pub fn build_csharp_symbol_table(source: &str) -> SymbolTable {
    use ::regex::Regex;
    let header_class = Regex::new(r"\b(?:class|interface|struct|record|enum)\s+([A-Za-z_][A-Za-z_0-9]*)").unwrap();
    let header_method = Regex::new(
        r"\b(?:public|private|protected|internal|static|virtual|override|abstract|async|sealed|partial|\s)+\s+[A-Za-z_<>\[\]\?,\s\.]+\s+([A-Za-z_][A-Za-z_0-9]*)\s*\(",
    ).unwrap();

    let mut table = build_braced_scope_table(source, |prefix, _through| {
        if header_class.is_match(prefix) {
            ScopeKind::Class
        } else if header_method.is_match(prefix.trim_end()) {
            ScopeKind::Function
        } else {
            ScopeKind::Function
        }
    });
    let module_end = table.scopes[0].end_line;

    let using_re   = Regex::new(r"^\s*using\s+(?:static\s+)?(?:([A-Za-z_][A-Za-z_0-9]*)\s*=\s*)?([A-Za-z_][A-Za-z_0-9.]*)\s*;").unwrap();
    let local_decl = Regex::new(
        r"^\s*(?:var|[A-Z][A-Za-z_0-9<>\[\]]*)\s+([A-Za-z_][A-Za-z_0-9]*)\s*=\s*new\s+([A-Z][A-Za-z_0-9]*)",
    ).unwrap();
    let typed_decl = Regex::new(
        r"^\s*([A-Z][A-Za-z_0-9<>\[\]]*)\s+([A-Za-z_][A-Za-z_0-9]*)\s*(?:=|;|,)",
    ).unwrap();
    let class_re = Regex::new(r"\b(?:class|interface|struct|record|enum)\s+([A-Za-z_][A-Za-z_0-9]*)").unwrap();

    let lines: Vec<&str> = source.lines().collect();
    for (idx, raw) in lines.iter().enumerate() {
        let line_no = idx + 1;
        let scope_idx = scope_for_line(&table, line_no);
        let scope_end = table.scopes[scope_idx].end_line;
        let scope_kind = table.scopes[scope_idx].kind;

        if let Some(c) = using_re.captures(raw) {
            let alias = c.get(1).map(|m| m.as_str().to_string());
            let fqn   = c.get(2).unwrap().as_str().to_string();
            let key   = alias.clone().unwrap_or_else(|| {
                fqn.rsplit('.').next().unwrap_or(&fqn).to_string()
            });
            // For namespace `using` (no alias), bind every short
            // name in the namespace to the FQN — but we don't know
            // the names yet; record the namespace itself so
            // resolve_imported can prefix-match.
            table.scopes[0].bindings.insert(key, Symbol {
                name: alias.unwrap_or_default(), kind: Some(fqn),
                line: line_no, end_line: module_end,
                scope_kind: ScopeKind::Module,
            });
            continue;
        }

        if let Some(c) = local_decl.captures(raw) {
            let name = c.get(1).unwrap().as_str().to_string();
            let ty   = c.get(2).unwrap().as_str().to_string();
            let resolved = resolve_imported(&table, &ty).unwrap_or(ty);
            table.scopes[scope_idx].bindings.insert(name.clone(), Symbol {
                name, kind: Some(resolved), line: line_no, end_line: scope_end, scope_kind,
            });
            continue;
        }

        if let Some(c) = typed_decl.captures(raw) {
            let ty   = c.get(1).unwrap().as_str().to_string();
            let name = c.get(2).unwrap().as_str().to_string();
            // Skip language keywords mistaken for types.
            if matches!(ty.as_str(),
                "var" | "return" | "if" | "for" | "while" | "do" | "switch"
                | "using" | "namespace" | "public" | "private" | "protected"
                | "internal" | "static" | "void" | "int" | "string" | "bool"
            ) { continue; }
            let resolved = resolve_imported(&table, &ty).unwrap_or(ty);
            table.scopes[scope_idx].bindings.insert(name.clone(), Symbol {
                name, kind: Some(resolved), line: line_no, end_line: scope_end, scope_kind,
            });
        }

        if let Some(c) = class_re.captures(raw) {
            let cls = c.get(1).unwrap().as_str().to_string();
            table.scopes[scope_idx].bindings.insert(cls.clone(), Symbol {
                name: cls.clone(), kind: Some(cls),
                line: line_no, end_line: scope_end,
                scope_kind: ScopeKind::Class,
            });
        }
    }

    table
}

/// Build a scope-aware symbol table for a single Go source file.
/// Handles `var x T`, `x := expr`, and `import` blocks.
pub fn build_go_symbol_table(source: &str) -> SymbolTable {
    use ::regex::Regex;
    let header_func   = Regex::new(r"\bfunc\s+(?:\(\s*[A-Za-z_][A-Za-z_0-9]*\s+\*?[A-Za-z_][A-Za-z_0-9]*\s*\)\s+)?([A-Za-z_][A-Za-z_0-9]*)\s*\(").unwrap();
    let header_struct = Regex::new(r"\btype\s+([A-Za-z_][A-Za-z_0-9]*)\s+struct").unwrap();

    let mut table = build_braced_scope_table(source, |prefix, _through| {
        if header_func.is_match(prefix) {
            ScopeKind::Function
        } else if header_struct.is_match(prefix) {
            ScopeKind::Class
        } else {
            ScopeKind::Function
        }
    });
    let module_end = table.scopes[0].end_line;

    let single_import = Regex::new(r#"^\s*import\s+(?:([A-Za-z_][A-Za-z_0-9]*)\s+)?"([^"]+)""#).unwrap();
    let block_import_line = Regex::new(r#"^\s*(?:([A-Za-z_][A-Za-z_0-9]*)\s+)?"([^"]+)""#).unwrap();
    let var_decl    = Regex::new(r"^\s*var\s+([A-Za-z_][A-Za-z_0-9]*)\s+(?:\*|&)?([A-Za-z_][A-Za-z_0-9.]*)").unwrap();
    // Short decl: `db := ...` or `db, err := ...` (we bind the
    // first identifier; second-tuple elements are usually `_`/`err`).
    let short_decl  = Regex::new(r"^\s*([A-Za-z_][A-Za-z_0-9]*)\s*(?:,\s*[A-Za-z_][A-Za-z_0-9]*\s*)*:=\s*(?:&|\*)?([A-Za-z_][A-Za-z_0-9.]*)").unwrap();
    let type_decl   = Regex::new(r"^\s*type\s+([A-Za-z_][A-Za-z_0-9]*)\s+(?:struct|interface|[A-Za-z_])").unwrap();

    let lines: Vec<&str> = source.lines().collect();
    let mut in_import_block = false;
    for (idx, raw) in lines.iter().enumerate() {
        let line_no = idx + 1;
        let scope_idx = scope_for_line(&table, line_no);
        let scope_end = table.scopes[scope_idx].end_line;
        let scope_kind = table.scopes[scope_idx].kind;
        let trimmed = raw.trim();

        if trimmed.starts_with("import (") { in_import_block = true; continue; }
        if in_import_block && trimmed.starts_with(')') { in_import_block = false; continue; }

        if in_import_block {
            if let Some(c) = block_import_line.captures(raw) {
                let alias = c.get(1).map(|m| m.as_str().to_string());
                let path  = c.get(2).unwrap().as_str().to_string();
                let key = alias.clone().unwrap_or_else(|| {
                    path.rsplit('/').next().unwrap_or(&path).to_string()
                });
                table.scopes[0].bindings.insert(key, Symbol {
                    name: alias.unwrap_or_default(), kind: Some(path),
                    line: line_no, end_line: module_end,
                    scope_kind: ScopeKind::Module,
                });
            }
            continue;
        }

        if let Some(c) = single_import.captures(raw) {
            let alias = c.get(1).map(|m| m.as_str().to_string());
            let path  = c.get(2).unwrap().as_str().to_string();
            let key = alias.clone().unwrap_or_else(|| {
                path.rsplit('/').next().unwrap_or(&path).to_string()
            });
            table.scopes[0].bindings.insert(key, Symbol {
                name: alias.unwrap_or_default(), kind: Some(path),
                line: line_no, end_line: module_end,
                scope_kind: ScopeKind::Module,
            });
            continue;
        }

        if let Some(c) = var_decl.captures(raw) {
            let name = c.get(1).unwrap().as_str().to_string();
            let ty   = c.get(2).unwrap().as_str().to_string();
            let resolved = resolve_imported(&table, &ty).unwrap_or(ty);
            table.scopes[scope_idx].bindings.insert(name.clone(), Symbol {
                name, kind: Some(resolved), line: line_no, end_line: scope_end, scope_kind,
            });
            continue;
        }

        if let Some(c) = short_decl.captures(raw) {
            let name = c.get(1).unwrap().as_str().to_string();
            let ty   = c.get(2).unwrap().as_str().to_string();
            // For `db := sql.Open(...)` we want kind = "sql".
            let kind = ty.split('.').next().unwrap_or(&ty).to_string();
            let resolved = resolve_imported(&table, &kind).unwrap_or(kind);
            table.scopes[scope_idx].bindings.insert(name.clone(), Symbol {
                name, kind: Some(resolved), line: line_no, end_line: scope_end, scope_kind,
            });
            continue;
        }

        if let Some(c) = type_decl.captures(raw) {
            let cls = c.get(1).unwrap().as_str().to_string();
            table.scopes[scope_idx].bindings.insert(cls.clone(), Symbol {
                name: cls.clone(), kind: Some(cls),
                line: line_no, end_line: scope_end,
                scope_kind: ScopeKind::Class,
            });
        }
    }

    table
}

/// Build a scope-aware symbol table for a single Rust source file.
/// Handles `let`, `let mut`, `use`, `struct`, `impl`.
pub fn build_rust_symbol_table(source: &str) -> SymbolTable {
    use ::regex::Regex;
    let header_fn     = Regex::new(r"\bfn\s+([A-Za-z_][A-Za-z_0-9]*)\s*(?:<[^>]*>\s*)?\(").unwrap();
    let header_struct = Regex::new(r"\b(?:struct|enum|trait|impl)\s+([A-Za-z_][A-Za-z_0-9]*)").unwrap();

    let mut table = build_braced_scope_table(source, |prefix, _through| {
        if header_fn.is_match(prefix) {
            ScopeKind::Function
        } else if header_struct.is_match(prefix) {
            ScopeKind::Class
        } else {
            ScopeKind::Function
        }
    });
    let module_end = table.scopes[0].end_line;

    let use_re      = Regex::new(r"^\s*use\s+([A-Za-z_:][A-Za-z_0-9:]*?)(?:::\{([^}]+)\})?\s*(?:as\s+([A-Za-z_][A-Za-z_0-9]*))?\s*;").unwrap();
    let let_decl    = Regex::new(r"^\s*let\s+(?:mut\s+)?([A-Za-z_][A-Za-z_0-9]*)\s*(?::\s*(?:&\s*mut\s*)?(?:&\s*)?([A-Za-z_][A-Za-z_0-9:]*))?\s*=\s*([A-Za-z_][A-Za-z_0-9:]*)?").unwrap();
    let struct_re   = Regex::new(r"\b(?:struct|enum|trait)\s+([A-Za-z_][A-Za-z_0-9]*)").unwrap();

    let lines: Vec<&str> = source.lines().collect();
    for (idx, raw) in lines.iter().enumerate() {
        let line_no = idx + 1;
        let scope_idx = scope_for_line(&table, line_no);
        let scope_end = table.scopes[scope_idx].end_line;
        let scope_kind = table.scopes[scope_idx].kind;

        if let Some(c) = use_re.captures(raw) {
            let path = c.get(1).unwrap().as_str().to_string();
            let inner = c.get(2).map(|m| m.as_str().to_string());
            let alias = c.get(3).map(|m| m.as_str().to_string());
            if let Some(inner) = inner {
                for n in inner.split(',') {
                    let raw_n = n.trim();
                    let parts: Vec<&str> = raw_n.split(" as ").collect();
                    let original = parts.first().copied().unwrap_or(raw_n).trim().to_string();
                    let key = parts.get(1).copied().unwrap_or(&original).trim().to_string();
                    if key.is_empty() { continue; }
                    table.scopes[0].bindings.insert(key.clone(), Symbol {
                        name: key, kind: Some(format!("{path}::{original}")),
                        line: line_no, end_line: module_end,
                        scope_kind: ScopeKind::Module,
                    });
                }
            } else {
                let key = alias.clone().unwrap_or_else(|| {
                    path.rsplit("::").next().unwrap_or(&path).to_string()
                });
                table.scopes[0].bindings.insert(key.clone(), Symbol {
                    name: key, kind: Some(path),
                    line: line_no, end_line: module_end,
                    scope_kind: ScopeKind::Module,
                });
            }
            continue;
        }

        if let Some(c) = let_decl.captures(raw) {
            let name = c.get(1).unwrap().as_str().to_string();
            let typ  = c.get(2).map(|m| m.as_str().to_string());
            let rhs  = c.get(3).map(|m| m.as_str().to_string());
            let kind = typ.or(rhs).map(|t| {
                t.split("::").next().unwrap_or(&t).to_string()
            });
            let resolved = kind.as_ref().and_then(|k| resolve_imported(&table, k));
            table.scopes[scope_idx].bindings.insert(name.clone(), Symbol {
                name, kind: resolved.or(kind),
                line: line_no, end_line: scope_end, scope_kind,
            });
            continue;
        }

        if let Some(c) = struct_re.captures(raw) {
            let cls = c.get(1).unwrap().as_str().to_string();
            table.scopes[scope_idx].bindings.insert(cls.clone(), Symbol {
                name: cls.clone(), kind: Some(cls),
                line: line_no, end_line: scope_end,
                scope_kind: ScopeKind::Class,
            });
        }
    }

    table
}

/// Look up an unqualified short name (e.g. `SqlConnection`) in the
/// module-level imports of `table`. Returns the FQN that was bound
/// for that short name, if any.
fn resolve_imported(table: &SymbolTable, short: &str) -> Option<String> {
    table.scopes.first()
        .and_then(|s| s.bindings.get(short))
        .and_then(|sym| sym.kind.clone())
}

/// Build a scope-aware symbol table for a single Python source file.
/// Indentation-based scope detection — Python's whitespace structure
/// makes this tractable without a full AST.
pub fn build_python_symbol_table(source: &str) -> SymbolTable {
    let mut table = SymbolTable::default();

    // Module scope first.
    let total_lines = source.lines().count().max(1);
    table.scopes.push(Scope {
        kind:       ScopeKind::Module,
        start_line: 1,
        end_line:   total_lines,
        indent:     0,
        bindings:   HashMap::new(),
        parent_idx: None,
    });

    let lines: Vec<&str> = source.lines().collect();

    // Pass 1 — detect scope headers (def/class) and stash them with
    // their start line + header indent. End line is computed in pass 2
    // by walking until a sibling/outer-indented non-empty line shows up.
    let mut headers: Vec<(usize, ScopeKind, usize, String)> = Vec::new(); // (line_no, kind, indent, name)
    for (idx, raw) in lines.iter().enumerate() {
        let trimmed = raw.trim_start();
        let indent = raw.len() - trimmed.len();
        if let Some(rest) = trimmed.strip_prefix("def ") {
            if let Some(name) = rest.split(['(', ':']).next() {
                headers.push((idx + 1, ScopeKind::Function, indent, name.trim().to_string()));
            }
        } else if let Some(rest) = trimmed.strip_prefix("async def ") {
            if let Some(name) = rest.split(['(', ':']).next() {
                headers.push((idx + 1, ScopeKind::Function, indent, name.trim().to_string()));
            }
        } else if let Some(rest) = trimmed.strip_prefix("class ") {
            if let Some(name) = rest.split(['(', ':']).next() {
                headers.push((idx + 1, ScopeKind::Class, indent, name.trim().to_string()));
            }
        }
    }

    // Pass 2 — close each scope at the next line whose indent ≤ header
    // indent (or EOF).
    for (start_line, kind, header_indent, _name) in &headers {
        let mut end_line = lines.len();
        for (idx, raw) in lines.iter().enumerate().skip(*start_line) {
            let trimmed = raw.trim();
            if trimmed.is_empty() { continue; }
            let indent = raw.len() - raw.trim_start().len();
            if indent <= *header_indent {
                end_line = idx; // exclusive: line `idx + 1` is the sibling
                break;
            }
        }
        // Find parent scope: smallest scope whose range contains
        // start_line and is itself non-equal to ourselves.
        let parent_idx = table
            .scopes
            .iter()
            .enumerate()
            .filter(|(_, sc)| sc.start_line <= *start_line && sc.end_line >= end_line)
            .min_by_key(|(_, sc)| sc.end_line.saturating_sub(sc.start_line))
            .map(|(i, _)| i);
        table.scopes.push(Scope {
            kind:       *kind,
            start_line: *start_line,
            end_line,
            indent:     *header_indent,
            bindings:   HashMap::new(),
            parent_idx,
        });
    }

    // Pass 3 — extract bindings (`x = expr`, `x: T = expr`, `from m import a, b`,
    // `import m`). Assignments map to whichever scope they fall in.
    use ::regex::Regex;
    // Capture every `name [= rhs]` assignment, including string-literal
    // and call RHSes. Group 2 (rhs identifier prefix) is optional —
    // when absent, the kind is None.
    let assign_re  = Regex::new(r"^\s*([A-Za-z_][A-Za-z_0-9]*)\s*(?::[^=]+)?=\s*(?:([A-Za-z_][A-Za-z_0-9.]*))?").unwrap();
    let import_re  = Regex::new(r"^\s*import\s+([A-Za-z_][A-Za-z_0-9.]*)\s*(?:as\s+([A-Za-z_][A-Za-z_0-9]*))?").unwrap();
    let from_re    = Regex::new(r"^\s*from\s+([A-Za-z_][A-Za-z_0-9.]*)\s+import\s+(.+)").unwrap();

    for (idx, raw) in lines.iter().enumerate() {
        let line_no = idx + 1;
        let scope_idx = scope_for_line(&table, line_no);

        let scope_end  = table.scopes[scope_idx].end_line;
        let scope_kind = table.scopes[scope_idx].kind;

        if let Some(c) = assign_re.captures(raw) {
            let name = c.get(1).unwrap().as_str().to_string();
            let kind = c.get(2).map(|m| m.as_str()).and_then(guess_kind_from_rhs);
            table.scopes[scope_idx].bindings.insert(name.clone(), Symbol {
                name,
                kind,
                line: line_no,
                end_line: scope_end,
                scope_kind,
            });
            continue;
        }

        if let Some(c) = import_re.captures(raw) {
            let module = c.get(1).unwrap().as_str().to_string();
            let alias  = c.get(2).map(|m| m.as_str().to_string()).unwrap_or_else(|| {
                module.split('.').next().unwrap_or(&module).to_string()
            });
            table.scopes[scope_idx].bindings.insert(alias.clone(), Symbol {
                name:    alias,
                kind:    Some(module),
                line:    line_no,
                end_line: scope_end,
                scope_kind,
            });
            continue;
        }

        if let Some(c) = from_re.captures(raw) {
            let module = c.get(1).unwrap().as_str().to_string();
            let names  = c.get(2).unwrap().as_str();
            for n in names.split(',') {
                let raw_n  = n.trim();
                let parts: Vec<&str> = raw_n.split(" as ").collect();
                let original = parts.first().copied().unwrap_or(raw_n).trim();
                let alias    = parts.get(1).copied().unwrap_or(original).trim();
                if alias.is_empty() { continue; }
                table.scopes[scope_idx].bindings.insert(alias.to_string(), Symbol {
                    name:    alias.to_string(),
                    kind:    Some(format!("{module}.{original}")),
                    line:    line_no,
                    end_line: scope_end,
                    scope_kind,
                });
            }
        }
    }

    table
}

fn scope_for_line(table: &SymbolTable, line: usize) -> usize {
    table.scopes.iter()
        .enumerate()
        .filter(|(_, sc)| sc.start_line <= line && line <= sc.end_line)
        .min_by_key(|(_, sc)| sc.end_line.saturating_sub(sc.start_line))
        .map(|(i, _)| i)
        .unwrap_or(0)
}

fn guess_kind_from_rhs(rhs: &str) -> Option<String> {
    let r = rhs.trim();
    if r.is_empty() { return None }
    if let Some((before_dot, _)) = r.split_once('.') {
        return Some(before_dot.to_string());
    }
    if r.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) {
        return Some(r.split('(').next().unwrap_or(r).to_string());
    }
    None
}

// Adapter so `c.get(2).map(|m| m.as_str()).and_then(guess_kind_from_rhs)`
// type-checks (the `and_then` callable wants `&str -> Option<String>`,
// which `guess_kind_from_rhs(&str)` already is, but the regex `Match`
// borrows from the captures. The closure form above keeps it explicit.)
#[allow(dead_code)]
fn guess_kind_from_rhs_owned(rhs: String) -> Option<String> {
    guess_kind_from_rhs(&rhs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_module_level_binding() {
        let src = "import sqlite3\ndb = sqlite3.connect(':memory:')\n";
        let t = build_python_symbol_table(src);
        let s = t.resolve(2, "db").expect("db should be resolved");
        assert_eq!(s.kind.as_deref(), Some("sqlite3"));
    }

    #[test]
    fn function_scope_shadows_module_binding() {
        let src = "\
db = 'module-db'

def view():
    db = 'function-db'
    return db
";
        let t = build_python_symbol_table(src);
        let inside = t.resolve(4, "db").expect("function-scope binding");
        assert_eq!(inside.scope_kind, ScopeKind::Function);
        assert_eq!(inside.kind.as_deref(), None); // 'function-db' is a string literal, no module
        let outside = t.resolve(1, "db").expect("module-scope binding");
        assert_eq!(outside.scope_kind, ScopeKind::Module);
    }

    #[test]
    fn from_import_unpacks_names() {
        let src = "from os.path import join, exists as p_exists\n";
        let t = build_python_symbol_table(src);
        assert_eq!(t.resolve(1, "join").unwrap().kind.as_deref(), Some("os.path.join"));
        // `as`-aliased name uses the alias as the bound key
        assert!(t.resolve(1, "p_exists").is_some(), "alias from `import X as Y` should be bound");
    }

    // ── JavaScript / TypeScript ───────────────────────────────────

    #[test]
    fn js_resolves_import_default() {
        let src = "import express from 'express';\nconst app = express();\n";
        let t = build_javascript_symbol_table(src);
        let s = t.resolve(2, "express").expect("express should be bound");
        assert_eq!(s.kind.as_deref(), Some("express"));
    }

    #[test]
    fn js_named_import_with_alias() {
        let src = "import { readFile, writeFile as wf } from 'fs/promises';\n";
        let t = build_javascript_symbol_table(src);
        assert_eq!(
            t.resolve(1, "readFile").unwrap().kind.as_deref(),
            Some("fs/promises.readFile"),
        );
        assert!(t.resolve(1, "wf").is_some(), "alias `writeFile as wf` should bind to wf");
    }

    #[test]
    fn js_function_scope_shadows_module_const() {
        let src = "\
const db = 'module-db';

function view() {
  const db = 'function-db';
  return db;
}
";
        let t = build_javascript_symbol_table(src);
        let inside = t.resolve(4, "db").expect("function-scope binding");
        assert_eq!(inside.scope_kind, ScopeKind::Function);
        let outside = t.resolve(1, "db").expect("module-scope binding");
        assert_eq!(outside.scope_kind, ScopeKind::Module);
    }

    #[test]
    fn js_require_destructure() {
        let src = "const { readFile, writeFile } = require('fs');\n";
        let t = build_javascript_symbol_table(src);
        assert_eq!(
            t.resolve(1, "readFile").unwrap().kind.as_deref(),
            Some("fs.readFile"),
        );
    }

    // ── Java ──────────────────────────────────────────────────────

    #[test]
    fn java_resolves_imported_type_assignment() {
        let src = "\
package com.acme;
import java.sql.Connection;
class App {
    void run() {
        Connection conn = makeConn();
        conn.prepareStatement(\"SELECT 1\");
    }
}
";
        let t = build_java_symbol_table(src);
        let s = t.resolve(5, "conn").expect("conn binding");
        assert_eq!(s.kind.as_deref(), Some("java.sql.Connection"));
    }

    #[test]
    fn java_block_scope_shadows_method_local() {
        let src = "\
import java.sql.Connection;
class App {
    void run() {
        Connection conn = makeConn();
        if (true) {
            String conn = \"shadowed\";
            System.out.println(conn);
        }
    }
}
";
        let t = build_java_symbol_table(src);
        let inner = t.resolve(7, "conn").expect("inner shadow");
        assert_eq!(inner.kind.as_deref(), Some("String"));
        let outer = t.resolve(4, "conn").expect("outer binding");
        assert_eq!(outer.kind.as_deref(), Some("java.sql.Connection"));
    }

    // ── C# ────────────────────────────────────────────────────────

    #[test]
    fn csharp_resolves_using_namespace_then_typed_local() {
        let src = "\
using System.Data.SqlClient;
class App {
    void Run() {
        SqlConnection conn = new SqlConnection(\"...\");
        conn.Open();
    }
}
";
        let t = build_csharp_symbol_table(src);
        let s = t.resolve(4, "conn").expect("conn binding");
        // SqlConnection itself is the resolved type; the FQN is
        // recorded under the namespace import.
        assert!(
            s.kind.as_deref().map(|k| k.contains("SqlConnection")
                || k.contains("System.Data.SqlClient")).unwrap_or(false),
            "got kind={:?}", s.kind
        );
    }

    // ── Go ────────────────────────────────────────────────────────

    #[test]
    fn go_short_decl_resolves_import_alias() {
        let src = "\
package main
import (
    \"database/sql\"
)
func main() {
    db, _ := sql.Open(\"postgres\", \"...\")
    db.Query(\"SELECT 1\")
}
";
        let t = build_go_symbol_table(src);
        let s = t.resolve(6, "db").expect("db binding");
        // kind = "sql" → resolved to "database/sql"
        assert_eq!(s.kind.as_deref(), Some("database/sql"));
    }

    // ── Rust ──────────────────────────────────────────────────────

    #[test]
    fn rust_let_binding_resolves_use_alias() {
        let src = "\
use rusqlite::Connection;
fn main() {
    let conn = Connection::open(\":memory:\").unwrap();
    conn.execute(\"SELECT 1\", []).unwrap();
}
";
        let t = build_rust_symbol_table(src);
        let s = t.resolve(3, "conn").expect("conn binding");
        // kind = "Connection" → resolved to "rusqlite::Connection"
        assert!(
            s.kind.as_deref().map(|k| k.contains("Connection")).unwrap_or(false),
            "got kind={:?}", s.kind
        );
    }

    #[test]
    fn rust_block_scope_shadows_outer_let() {
        let src = "\
fn main() {
    let conn = 42;
    {
        let conn = \"inner\";
        println!(\"{}\", conn);
    }
}
";
        let t = build_rust_symbol_table(src);
        let inner = t.resolve(5, "conn").expect("inner shadow");
        assert_eq!(inner.scope_kind, ScopeKind::Function);
        let outer = t.resolve(2, "conn").expect("outer binding");
        assert_eq!(outer.line, 2);
    }
}
