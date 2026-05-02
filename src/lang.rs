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
    Python, Javascript, Typescript, Go, Csharp, Rust, Java, Ruby,
    // Tier 2 — regex-only, high usage
    Php, C, Kotlin, Swift, Scala, Bash,
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
    Generic, Json, Yaml, Kubernetes, Terraform, Docker,
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
            // Config / env files — scan as generic for secret detection
            "env" | "cfg" | "conf" | "config" | "secret" | "secrets"
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

    /// Returns the tree-sitter grammar if available. Languages without
    /// a grammar (Java, Ruby, etc.) return None and use regex-only matching.
    pub fn tree_sitter(self) -> Option<Language> {
        Some(match self {
            Self::Python => tree_sitter_python::language(),
            Self::Javascript | Self::Typescript => tree_sitter_javascript::language(),
            Self::Go => tree_sitter_go::language(),
            Self::Csharp => tree_sitter_c_sharp::language(),
            Self::Rust => tree_sitter_rust::language(),
            Self::Java => tree_sitter_java::language(),
            Self::Ruby => tree_sitter_ruby::language(),
            // Languages without tree-sitter grammars compiled in — regex-only
            _ => return None,
        })
    }

    /// Whether this language has full AST pattern matching (tree-sitter).
    /// Languages without it use regex-only matching.
    pub fn has_ast_support(self) -> bool {
        matches!(self, Self::Python | Self::Javascript | Self::Typescript | Self::Go | Self::Csharp | Self::Rust | Self::Java | Self::Ruby)
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
            Self::Kubernetes => "kubernetes",
            Self::Terraform  => "terraform",
            Self::Docker     => "docker",
        }
    }
}

impl std::fmt::Display for Lang {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
