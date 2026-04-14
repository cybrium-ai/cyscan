//! Language registry — filename → tree-sitter grammar. New languages
//! slot in by adding a grammar dep + an extension match here.

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
}

impl Lang {
    pub fn from_extension(ext: &str) -> Option<Self> {
        Some(match ext {
            "py" => Self::Python,
            "js" | "mjs" | "cjs" => Self::Javascript,
            "ts" | "tsx" => Self::Typescript,
            "go" => Self::Go,
            _ => return None,
        })
    }

    pub fn from_path(path: &Path) -> Option<Self> {
        let ext = path.extension()?.to_str()?;
        Self::from_extension(ext)
    }

    pub fn tree_sitter(self) -> Language {
        match self {
            Self::Python     => tree_sitter_python::language(),
            // JavaScript grammar handles jsx too. For plain TypeScript
            // we currently alias to the JS grammar; v0.2 can swap in the
            // official tree-sitter-typescript grammar.
            Self::Javascript | Self::Typescript => tree_sitter_javascript::language(),
            Self::Go         => tree_sitter_go::language(),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Python     => "python",
            Self::Javascript => "javascript",
            Self::Typescript => "typescript",
            Self::Go         => "go",
        }
    }
}

impl std::fmt::Display for Lang {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
