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

/// Build a scope-aware symbol table for a single JavaScript or
/// TypeScript source file. Curly-brace scope detection — every `{`
/// opens a new scope, `}` closes the innermost one. We tag the scope
/// kind based on the immediately-preceding header token (`function`,
/// `class`, `=>` for arrow fns, anything else = block scope).
pub fn build_javascript_symbol_table(source: &str) -> SymbolTable {
    let mut table = SymbolTable::default();
    let total_lines = source.lines().count().max(1);

    // Module scope first.
    table.scopes.push(Scope {
        kind:       ScopeKind::Module,
        start_line: 1,
        end_line:   total_lines,
        indent:     0,
        bindings:   HashMap::new(),
        parent_idx: None,
    });

    let lines: Vec<&str> = source.lines().collect();

    // Pass 1 — walk braces line-by-line. Track a stack of open scopes
    // and close them when matching `}` is seen. The scope kind is set
    // from the header token on the line that opens the brace.
    use ::regex::Regex;
    let header_fn_re   = Regex::new(r"\bfunction\s+([A-Za-z_][A-Za-z_0-9]*)\s*\(").unwrap();
    let header_anon_re = Regex::new(r"\bfunction\s*\(").unwrap();
    let header_arrow_re = Regex::new(r"=>\s*\{").unwrap();
    let header_class_re = Regex::new(r"\bclass\s+([A-Za-z_][A-Za-z_0-9]*)").unwrap();

    struct Open { idx: usize, depth: usize }
    let mut stack: Vec<Open> = Vec::new();
    let mut depth = 0usize;

    for (line_idx, raw) in lines.iter().enumerate() {
        let line_no = line_idx + 1;
        // Tokenise the line into '{' and '}' positions, ignoring those
        // inside string literals — cheap heuristic, good enough for our
        // current needs.
        let bytes = raw.as_bytes();
        let mut in_str: Option<u8> = None;
        let mut prev_open_at: Option<usize> = None;
        let mut i = 0usize;
        while i < bytes.len() {
            let c = bytes[i];
            if let Some(q) = in_str {
                if c == b'\\' { i += 2; continue }
                if c == q { in_str = None; }
                i += 1; continue;
            }
            match c {
                b'"' | b'\'' | b'`' => { in_str = Some(c); }
                b'{' => {
                    depth += 1;
                    // Determine scope kind from the line up to this point.
                    let prefix = &raw[..i];
                    let kind = if header_fn_re.is_match(prefix)
                        || header_anon_re.is_match(prefix)
                        || header_arrow_re.is_match(&raw[..=i])
                    {
                        ScopeKind::Function
                    } else if header_class_re.is_match(prefix) {
                        ScopeKind::Class
                    } else {
                        // Block scope (if/for/while/{...}). We still push it so
                        // shadowing inside blocks works — but we tag it as
                        // Function for resolution purposes (closest enclosing).
                        ScopeKind::Function
                    };
                    let parent_idx = stack.last().map(|o| o.idx).or(Some(0));
                    table.scopes.push(Scope {
                        kind,
                        start_line: line_no,
                        end_line:   total_lines, // updated on close
                        indent:     0,
                        bindings:   HashMap::new(),
                        parent_idx,
                    });
                    let new_idx = table.scopes.len() - 1;
                    stack.push(Open { idx: new_idx, depth });
                    prev_open_at = Some(i);
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
        let _ = prev_open_at;
    }

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
}
