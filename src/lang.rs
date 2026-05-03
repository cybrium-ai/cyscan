//! Language registry — filename → tree-sitter grammar. New languages
//! slot in by adding a grammar dep + an extension match here.
//! Languages without tree-sitter grammars use regex-only matching.

use std::path::Path;

use serde::{Deserialize, Serialize};
use tree_sitter::Language;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    // Tier 1 — tree-sitter AST support
    Python, Javascript, Typescript, Go,
    // Tier 2 — regex-only, high usage
    Java, Ruby, Php, C, Csharp, Rust, Kotlin, Swift, Scala, Bash,
    // Tier 3 — regex-only, niche languages
    Perl, Lua, R, Dart, Elixir, Erlang, Haskell, Clojure, Groovy,
    ObjectiveC, Powershell, Vb, Fsharp, Julia, Zig, Nim, Crystal,
    Ocaml, Cobol, Fortran, Ada, Prolog, Lisp, Scheme, Tcl,
    Solidity, Vyper, Move, Cairo,  // blockchain
    Sql, Plsql, Tsql,             // database
    Xml, Toml, Ini, Properties, Csv, Markdown,  // config/data
    Makefile, Cmake, Gradle, Maven, Bazel,      // build systems
    Ansible, Puppet, Chef, Saltstack,           // IaC/config mgmt
    Nginx, Apache, Caddy,                       // server configs
    Systemd, Crontab,                           // system configs
    Protobuf, Thrift, Graphql, Avro,            // schemas
    Latex, Rst,                                 // docs
    // Generic / config
    Generic, Json, Yaml, Terraform, Docker,
    // Kubernetes — pseudo-language for YAML files that contain a
    // K8s manifest (have `apiVersion:` + `kind:` headers). Detected
    // via content sniff in `Lang::refine_with_content`. Lets K8s
    // rules opt in via `languages: ['kubernetes']` instead of
    // `['yaml']` (too broad — fires on GitHub Actions, Helm
    // values, kustomize, ansible playbooks, etc.).
    Kubernetes,
}

impl Lang {
    pub fn from_extension(ext: &str) -> Option<Self> {
        Some(match ext {
            // Tier 1 — tree-sitter
            "py"  => Self::Python,
            "js" | "mjs" | "cjs" | "jsx" => Self::Javascript,
            "ts" | "tsx" => Self::Typescript,
            "go" => Self::Go,
            // Tier 2 — regex-only, high usage
            "java" => Self::Java,
            "rb" | "erb" => Self::Ruby,
            "php" | "phtml" => Self::Php,
            "c" | "h" | "cpp" | "cc" | "cxx" | "hpp" | "hxx" => Self::C,
            "cs" => Self::Csharp,
            "rs" => Self::Rust,
            "kt" | "kts" => Self::Kotlin,
            "swift" => Self::Swift,
            "scala" | "sc" => Self::Scala,
            "sh" | "bash" | "zsh" => Self::Bash,
            // Tier 3 — niche languages
            "pl" | "pm" => Self::Perl,
            "lua" => Self::Lua,
            "r" | "R" => Self::R,
            "dart" => Self::Dart,
            "ex" | "exs" => Self::Elixir,
            "erl" | "hrl" => Self::Erlang,
            "hs" | "lhs" => Self::Haskell,
            "clj" | "cljs" | "cljc" | "edn" => Self::Clojure,
            "groovy" | "gvy" | "gy" => Self::Groovy,
            "m" | "mm" => Self::ObjectiveC,
            "ps1" | "psm1" | "psd1" => Self::Powershell,
            "vb" | "vbs" | "bas" => Self::Vb,
            "fs" | "fsi" | "fsx" => Self::Fsharp,
            "jl" => Self::Julia,
            "zig" => Self::Zig,
            "nim" | "nims" => Self::Nim,
            "cr" => Self::Crystal,
            "ml" | "mli" => Self::Ocaml,
            "cob" | "cbl" | "cpy" => Self::Cobol,
            "f90" | "f95" | "f03" | "f08" | "for" | "ftn" => Self::Fortran,
            "adb" | "ads" => Self::Ada,
            "pro" | "P" => Self::Prolog,
            "lisp" | "lsp" | "cl" => Self::Lisp,
            "scm" | "ss" => Self::Scheme,
            "tcl" => Self::Tcl,
            // Blockchain
            "sol" => Self::Solidity,
            "vy" => Self::Vyper,
            "move" => Self::Move,
            "cairo" => Self::Cairo,
            // Database
            "sql" => Self::Sql,
            "pls" | "pck" | "pkb" | "pks" => Self::Plsql,
            // Config / data
            "xml" | "xsl" | "xslt" | "xsd" | "svg" | "xhtml" => Self::Xml,
            "toml" => Self::Toml,
            "ini" | "cfg" => Self::Ini,
            "properties" => Self::Properties,
            "csv" | "tsv" => Self::Csv,
            "md" | "mdx" => Self::Markdown,
            // Build systems
            "cmake" => Self::Cmake,
            "gradle" => Self::Gradle,
            "bzl" => Self::Bazel,
            // Schemas
            "proto" => Self::Protobuf,
            "thrift" => Self::Thrift,
            "graphql" | "gql" => Self::Graphql,
            "avsc" | "avdl" => Self::Avro,
            // Docs
            "tex" | "sty" => Self::Latex,
            "rst" => Self::Rst,
            // Core config
            "json" => Self::Json,
            "yml" | "yaml" => Self::Yaml,
            "tf" | "hcl" => Self::Terraform,
            // Config / env files — scan as generic for secret detection.
            // Note: `cfg` is already routed to Ini higher up; we keep
            // the rest of the list (env/conf/config/secret*/credentials/
            // pem/key/crt/cert/keystore/jks/p12/pfx) as Generic so the
            // entropy-based secret detector still fires on them.
            "env" | "conf" | "config" | "secret" | "secrets"
                | "credentials" | "pem" | "key" | "crt" | "cert"
                | "keystore" | "jks" | "p12" | "pfx" => Self::Generic,
            _ => return None,
        })
    }

    /// Check if a file path matches this language, including special filenames.
    pub fn from_path(path: &Path) -> Option<Self> {
        // Check special filenames first
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            let lower = name.to_lowercase();
            match name {
                "Dockerfile" | "Containerfile" => return Some(Self::Docker),
                "Makefile" | "GNUmakefile" => return Some(Self::Makefile),
                "CMakeLists.txt" => return Some(Self::Cmake),
                "Gemfile" | "Rakefile" => return Some(Self::Ruby),
                "BUILD" | "BUILD.bazel" | "WORKSPACE" => return Some(Self::Bazel),
                // Config / secret files — scan as generic for entropy detection
                ".env" | ".env.local" | ".env.production" | ".env.staging"
                    | ".env.development" | ".env.test" | ".npmrc" | ".pypirc"
                    | ".netrc" | ".pgpass" | ".my.cnf" | ".git-credentials"
                    | "credentials" | "config" => return Some(Self::Generic),
                _ => {}
            }
            // Ansible playbooks / roles
            if lower.ends_with(".yml") || lower.ends_with(".yaml") {
                if lower.contains("playbook") || lower.contains("ansible") {
                    return Some(Self::Ansible);
                }
            }
            // Nginx / Apache / Caddy configs
            if lower.starts_with("nginx") || lower == "nginx.conf" {
                return Some(Self::Nginx);
            }
            if lower.starts_with("httpd") || lower == "apache2.conf" || lower == ".htaccess" {
                return Some(Self::Apache);
            }
            if lower == "caddyfile" {
                return Some(Self::Caddy);
            }
            // System configs
            if lower.ends_with(".service") || lower.ends_with(".timer") || lower.ends_with(".socket") {
                return Some(Self::Systemd);
            }
            if lower == "crontab" || lower.starts_with("cron") {
                return Some(Self::Crontab);
            }
            // Puppet
            if lower.ends_with(".pp") {
                return Some(Self::Puppet);
            }
            // Maven
            if lower == "pom.xml" {
                return Some(Self::Maven);
            }
            // Chef
            if lower == "metadata.rb" || lower == "berksfile" {
                return Some(Self::Chef);
            }
            // Salt
            if lower.ends_with(".sls") {
                return Some(Self::Saltstack);
            }
        }
        let ext = path.extension()?.to_str()?;
        Self::from_extension(ext)
    }

    /// Refine the language classification using a peek at the file
    /// content. Currently used for one purpose: a YAML file whose
    /// head contains both `apiVersion:` and `kind:` is reclassified
    /// as `Kubernetes`. Catches K8s manifests wherever they live —
    /// `helm template` outputs, GitOps app manifests, mixed-content
    /// directories — without forcing rule authors to enumerate
    /// every plausible path glob.
    ///
    /// Pass the first ~2 KB of the file (cheap to read up-front).
    /// Returns the refined language; falls back to the original if
    /// no refinement applies.
    pub fn refine_with_content(self, source_head: &str) -> Self {
        if matches!(self, Self::Yaml) && looks_like_k8s_manifest(source_head) {
            return Self::Kubernetes;
        }
        self
    }

    /// Returns the tree-sitter grammar if available. Languages without
    /// a grammar (Java, Ruby, etc.) return None and use regex-only matching.
    pub fn tree_sitter(self) -> Option<Language> {
        Some(match self {
            Self::Python => tree_sitter_python::language(),
            Self::Javascript | Self::Typescript => tree_sitter_javascript::language(),
            Self::Go => tree_sitter_go::language(),
            // Languages without tree-sitter grammars compiled in — regex-only
            _ => return None,
        })
    }

    /// Whether this language has full AST pattern matching (tree-sitter).
    /// Languages without it use regex-only matching.
    pub fn has_ast_support(self) -> bool {
        matches!(self, Self::Python | Self::Javascript | Self::Typescript | Self::Go)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            // Tier 1
            Self::Python     => "python",
            Self::Javascript => "javascript",
            Self::Typescript => "typescript",
            Self::Go         => "go",
            // Tier 2
            Self::Java       => "java",
            Self::Ruby       => "ruby",
            Self::Php        => "php",
            Self::C          => "c",
            Self::Csharp     => "csharp",
            Self::Rust       => "rust",
            Self::Kotlin     => "kotlin",
            Self::Swift      => "swift",
            Self::Scala      => "scala",
            Self::Bash       => "bash",
            // Tier 3
            Self::Perl       => "perl",
            Self::Lua        => "lua",
            Self::R          => "r",
            Self::Dart       => "dart",
            Self::Elixir     => "elixir",
            Self::Erlang     => "erlang",
            Self::Haskell    => "haskell",
            Self::Clojure    => "clojure",
            Self::Groovy     => "groovy",
            Self::ObjectiveC => "objective_c",
            Self::Powershell => "powershell",
            Self::Vb         => "vb",
            Self::Fsharp     => "fsharp",
            Self::Julia      => "julia",
            Self::Zig        => "zig",
            Self::Nim        => "nim",
            Self::Crystal    => "crystal",
            Self::Ocaml      => "ocaml",
            Self::Cobol      => "cobol",
            Self::Fortran    => "fortran",
            Self::Ada        => "ada",
            Self::Prolog     => "prolog",
            Self::Lisp       => "lisp",
            Self::Scheme     => "scheme",
            Self::Tcl        => "tcl",
            // Blockchain
            Self::Solidity   => "solidity",
            Self::Vyper      => "vyper",
            Self::Move       => "move",
            Self::Cairo      => "cairo",
            // Database
            Self::Sql        => "sql",
            Self::Plsql      => "plsql",
            Self::Tsql       => "tsql",
            // Config / data
            Self::Xml        => "xml",
            Self::Toml       => "toml",
            Self::Ini        => "ini",
            Self::Properties => "properties",
            Self::Csv        => "csv",
            Self::Markdown   => "markdown",
            // Build systems
            Self::Makefile   => "makefile",
            Self::Cmake      => "cmake",
            Self::Gradle     => "gradle",
            Self::Maven      => "maven",
            Self::Bazel      => "bazel",
            // IaC / config mgmt
            Self::Ansible    => "ansible",
            Self::Puppet     => "puppet",
            Self::Chef       => "chef",
            Self::Saltstack  => "saltstack",
            // Server configs
            Self::Nginx      => "nginx",
            Self::Apache     => "apache",
            Self::Caddy      => "caddy",
            // System configs
            Self::Systemd    => "systemd",
            Self::Crontab    => "crontab",
            // Schemas
            Self::Protobuf   => "protobuf",
            Self::Thrift     => "thrift",
            Self::Graphql    => "graphql",
            Self::Avro       => "avro",
            // Docs
            Self::Latex      => "latex",
            Self::Rst        => "rst",
            // Core config
            Self::Generic    => "generic",
            Self::Json       => "json",
            Self::Yaml       => "yaml",
            Self::Terraform  => "terraform",
            Self::Docker     => "docker",
            Self::Kubernetes => "kubernetes",
        }
    }
}

/// True when the leading bytes of a YAML file look like a Kubernetes
/// manifest. Heuristic: contains both `apiVersion:` and `kind:` in
/// the first ~2 KB. The two together are universal across every K8s
/// resource (Deployment, Service, ConfigMap, RBAC, CRDs, etc.) and
/// vanishingly unlikely to appear in non-K8s YAML by accident.
///
/// Multi-document YAML (`---` separators) only needs the first
/// document to look like a manifest — every doc that follows is
/// almost certainly also K8s.
fn looks_like_k8s_manifest(head: &str) -> bool {
    // Trim large heads — we only inspect the front of the file.
    let head = if head.len() > 4096 {
        &head[..4096]
    } else {
        head
    };

    let mut has_api_version = false;
    let mut has_kind = false;
    for raw in head.lines() {
        let line = raw.trim_start();
        // `apiVersion:` and `kind:` always appear at the document's
        // top level (zero indent in K8s) but Helm-template outputs
        // can have minor leading whitespace from comment blocks.
        if !has_api_version && line.starts_with("apiVersion:") {
            has_api_version = true;
        }
        if !has_kind && line.starts_with("kind:") {
            has_kind = true;
        }
        if has_api_version && has_kind {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn k8s_manifest_detected() {
        let src = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: app-config\n";
        assert_eq!(Lang::Yaml.refine_with_content(src), Lang::Kubernetes);
    }

    #[test]
    fn github_actions_workflow_stays_yaml() {
        let src = "name: CI\non:\n  push:\n    branches: [main]\njobs:\n  test:\n    runs-on: ubuntu-latest\n";
        assert_eq!(Lang::Yaml.refine_with_content(src), Lang::Yaml);
    }

    #[test]
    fn helm_chart_values_stays_yaml() {
        let src = "image:\n  repository: nginx\n  tag: latest\nreplicaCount: 1\n";
        assert_eq!(Lang::Yaml.refine_with_content(src), Lang::Yaml);
    }

    #[test]
    fn ansible_playbook_stays_yaml() {
        // Ansible has `- name:` and `tasks:` but no `apiVersion:`.
        let src = "- name: install nginx\n  hosts: web\n  tasks:\n    - apt:\n        name: nginx\n";
        assert_eq!(Lang::Yaml.refine_with_content(src), Lang::Yaml);
    }

    #[test]
    fn multi_doc_k8s_stream_detected_from_first_doc() {
        let src = "apiVersion: v1\nkind: Service\n---\napiVersion: apps/v1\nkind: Deployment\n";
        assert_eq!(Lang::Yaml.refine_with_content(src), Lang::Kubernetes);
    }

    #[test]
    fn non_yaml_lang_is_not_refined() {
        // Even if the source head looks K8s-shaped, a Python file
        // stays Python.
        let src = "apiVersion: v1\nkind: thing";
        assert_eq!(Lang::Python.refine_with_content(src), Lang::Python);
    }
}

impl std::fmt::Display for Lang {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
