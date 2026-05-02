//! Cross-service API contract scanning (Option 1 from v0.15.0 honest
//! assessment).
//!
//! Goal: when a customer's repo has a C# controller calling a Java
//! service that calls a Python DB helper, we can answer **which file
//! talks to which file**. We do NOT trace taint values across runtime
//! boundaries — neither Semgrep Pro nor Checkmarx One do that today.
//! What we DO is recognise the call surface and pair clients ↔ servers
//! ↔ specs by HTTP `(method, path)`.
//!
//! That alone is a real value proposition no other OSS scanner ships:
//!
//!   * `cyscan xservice` — print the discovered cross-service map.
//!   * Findings emitted inside an HTTP handler get
//!     `evidence.cross_service` tagged so reviewers see the calling
//!     controller surface without leaving the report.
//!   * OpenAPI / Protobuf specs in the repo are parsed and matched
//!     against the discovered handlers / clients.
//!
//! Path matching is normalised: `/users/{id}` ≡ `/users/:id` ≡
//! `/users/<int:id>` ≡ `/users/(?P<id>[^/]+)`. Parameter style varies
//! by framework; we collapse them all to `/users/{}`.

pub mod discovery;
pub mod spec;
pub mod match_engine;

use std::path::PathBuf;

/// HTTP method recognised by the discovery layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Method {
    Get, Post, Put, Patch, Delete, Head, Options, Any,
}

impl Method {
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.trim().to_uppercase().as_str() {
            "GET"     => Some(Self::Get),
            "POST"    => Some(Self::Post),
            "PUT"     => Some(Self::Put),
            "PATCH"   => Some(Self::Patch),
            "DELETE"  => Some(Self::Delete),
            "HEAD"    => Some(Self::Head),
            "OPTIONS" => Some(Self::Options),
            "ANY" | "ALL" | "*" => Some(Self::Any),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET", Self::Post => "POST", Self::Put => "PUT",
            Self::Patch => "PATCH", Self::Delete => "DELETE", Self::Head => "HEAD",
            Self::Options => "OPTIONS", Self::Any => "ANY",
        }
    }
}

/// One discovered HTTP client call. Caller-side surface.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ClientCall {
    pub file:     PathBuf,
    pub line:     usize,
    pub language: String,
    pub method:   Method,
    pub path:     String,
    /// Normalised path with `{}` placeholders so it matches against
    /// server handlers regardless of parameter syntax.
    pub normalised_path: String,
    /// Library / framework that produced the call (e.g. "requests",
    /// "axios", "HttpClient", "RestTemplate").
    pub via:      String,
}

/// One discovered HTTP server endpoint. Server-side surface.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ServerEndpoint {
    pub file:            PathBuf,
    pub line:            usize,
    pub language:        String,
    pub framework:       String,
    pub method:          Method,
    pub path:            String,
    pub normalised_path: String,
    pub handler_name:    Option<String>,
}

/// One pair: a client call matched to a handler. The `matched_via`
/// field carries either "direct" (path/method matched a server in the
/// same scan), "openapi:<spec>" (matched through an OpenAPI spec), or
/// "protobuf:<spec>" (matched through a Protobuf service definition).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ServiceLink {
    pub client:      ClientCall,
    pub handler:     Option<ServerEndpoint>,
    pub matched_via: String,
}

/// Aggregated cross-service map for the entire scan target.
#[derive(Debug, Default, serde::Serialize)]
pub struct CrossServiceMap {
    pub clients:  Vec<ClientCall>,
    pub handlers: Vec<ServerEndpoint>,
    pub links:    Vec<ServiceLink>,
    pub specs:    Vec<spec::DiscoveredSpec>,
}

/// Build the project-wide cross-service map by walking `target` once,
/// running the per-language discovery, parsing any OpenAPI/Protobuf
/// specs, and pairing clients to handlers/specs.
pub fn build<P: AsRef<std::path::Path>>(target: P) -> CrossServiceMap {
    let target = target.as_ref();
    let clients  = discovery::find_client_calls(target);
    let handlers = discovery::find_server_endpoints(target);
    let specs    = spec::find_specs(target);
    let links    = match_engine::pair_clients_to_handlers(&clients, &handlers, &specs);
    CrossServiceMap { clients, handlers, links, specs }
}

/// Normalise a path so framework-specific param styles all collapse to
/// `/users/{}`. Drops trailing slash, lowercases the static parts.
/// Used internally + by the matcher engine.
pub fn normalise_path(path: &str) -> String {
    use ::regex::Regex;
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(
        // Match every common parameter syntax:
        //   {id}           — Spring / FastAPI / OpenAPI
        //   :id            — Express / Rails
        //   <id>           — Flask / Django
        //   <int:id>       — Flask / Django converters
        //   (?P<id>...)    — Django regex
        //   (?<id>...)     — .NET / Java named groups
        r"\{[^}]+\}|:[A-Za-z_][A-Za-z_0-9]*|<[^>]+>|\(\?P?<[^>]+>[^)]*\)"
    ).unwrap());
    let collapsed = re.replace_all(path.trim(), "{}").to_string();
    let trimmed = collapsed.trim_end_matches('/').to_string();
    if trimmed.is_empty() { "/".into() } else { trimmed }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalise_collapses_param_styles() {
        assert_eq!(normalise_path("/users/{id}"),     "/users/{}");
        assert_eq!(normalise_path("/users/:id"),      "/users/{}");
        assert_eq!(normalise_path("/users/<id>"),     "/users/{}");
        assert_eq!(normalise_path("/users/<int:id>"), "/users/{}");
        assert_eq!(normalise_path("/users/(?P<id>[^/]+)"), "/users/{}");
        assert_eq!(normalise_path("/users/{id}/posts/{post_id}/"), "/users/{}/posts/{}");
    }
}
