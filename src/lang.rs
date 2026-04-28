//! Language registry — filename → tree-sitter grammar. New languages
//! slot in by adding a grammar dep + an extension match here.
//! Languages without tree-sitter grammars use regex-only matching.

use std::path::Path;

use serde::{Deserialize, Serialize};
use tree_sitter::Language;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    Python,
    Javascript,
    Typescript,
    Go,
    Java,
    Ruby,
    Php,
    C,
    Csharp,
    Rust,
    Kotlin,
    Swift,
    Scala,
    Bash,
    Generic,
    Json,
    Yaml,
    Terraform,
    Docker,
}

impl Lang {
    pub fn from_extension(ext: &str) -> Option<Self> {
        Some(match ext {
            "py"  => Self::Python,
            "js" | "mjs" | "cjs" | "jsx" => Self::Javascript,
            "ts" | "tsx" => Self::Typescript,
            "go" => Self::Go,
            "java" => Self::Java,
            "rb" | "erb" => Self::Ruby,
            "php" => Self::Php,
            "c" | "h" | "cpp" | "cc" | "cxx" | "hpp" => Self::C,
            "cs" => Self::Csharp,
            "rs" => Self::Rust,
            "kt" | "kts" => Self::Kotlin,
            "swift" => Self::Swift,
            "scala" | "sc" => Self::Scala,
            "sh" | "bash" | "zsh" => Self::Bash,
            "json" => Self::Json,
            "yml" | "yaml" => Self::Yaml,
            "tf" | "hcl" => Self::Terraform,
            _ => return None,
        })
    }

    /// Check if a file path matches this language, including special filenames.
    pub fn from_path(path: &Path) -> Option<Self> {
        // Check special filenames first
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            match name {
                "Dockerfile" | "Containerfile" => return Some(Self::Docker),
                "Makefile" | "GNUmakefile" => return Some(Self::Bash),
                _ => {}
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
            Self::Python     => "python",
            Self::Javascript => "javascript",
            Self::Typescript => "typescript",
            Self::Go         => "go",
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
            Self::Generic    => "generic",
            Self::Json       => "json",
            Self::Yaml       => "yaml",
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
