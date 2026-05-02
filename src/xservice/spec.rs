//! OpenAPI + Protobuf spec discovery.
//!
//! When the repo has these files committed, we parse them and use the
//! result as a third match source: client → handler can pair via
//! `(method, path)` directly, but it can also pair via "both ends
//! reference the same OpenAPI operation".

use std::path::{Path, PathBuf};

use ignore::WalkBuilder;

use super::{normalise_path, Method};

#[derive(Debug, Clone, serde::Serialize)]
pub struct DiscoveredSpec {
    pub file:       PathBuf,
    pub kind:       SpecKind,
    pub operations: Vec<SpecOperation>,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SpecKind {
    OpenApi,
    Protobuf,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SpecOperation {
    pub method:          Method,
    pub path:            String,
    pub normalised_path: String,
    /// OpenAPI operationId or Protobuf method name.
    pub operation_id:    Option<String>,
}

/// Walk the target and return every recognisable spec file with its
/// extracted operations.
pub fn find_specs(target: &Path) -> Vec<DiscoveredSpec> {
    let mut out = Vec::new();
    for entry in WalkBuilder::new(target).standard_filters(true).hidden(false).build()
        .filter_map(|r| r.ok())
        .filter(|e| e.file_type().map_or(false, |ft| ft.is_file()))
    {
        let path = entry.path();
        let Some(ext) = path.extension().and_then(|e| e.to_str()) else { continue };
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
        let lower = name.to_lowercase();

        if lower == "openapi.yaml" || lower == "openapi.yml" || lower == "openapi.json"
            || lower == "swagger.yaml" || lower == "swagger.yml" || lower == "swagger.json"
        {
            if let Some(spec) = parse_openapi(path) { out.push(spec); }
            continue;
        }
        if ext == "proto" {
            if let Some(spec) = parse_protobuf(path) { out.push(spec); }
            continue;
        }
        // Files named *.openapi.yaml / *.swagger.json also count.
        if lower.contains("openapi") && (ext == "yaml" || ext == "yml" || ext == "json") {
            if let Some(spec) = parse_openapi(path) { out.push(spec); }
        }
    }
    out
}

fn parse_openapi(path: &Path) -> Option<DiscoveredSpec> {
    let body = std::fs::read_to_string(path).ok()?;
    let value: serde_json::Value = if path.extension().and_then(|e| e.to_str()) == Some("json") {
        serde_json::from_str(&body).ok()?
    } else {
        // serde_yaml -> serde_json::Value via a quick round-trip
        let y: serde_yaml::Value = serde_yaml::from_str(&body).ok()?;
        serde_json::to_value(y).ok()?
    };
    let paths = value.get("paths")?.as_object()?;
    let mut operations = Vec::new();
    for (raw_path, methods) in paths {
        let Some(methods_obj) = methods.as_object() else { continue };
        for (verb, op) in methods_obj {
            let Some(method) = Method::from_str_loose(verb) else { continue };
            let operation_id = op.get("operationId").and_then(|v| v.as_str()).map(String::from);
            operations.push(SpecOperation {
                method,
                path:            raw_path.clone(),
                normalised_path: normalise_path(raw_path),
                operation_id,
            });
        }
    }
    Some(DiscoveredSpec { file: path.to_path_buf(), kind: SpecKind::OpenApi, operations })
}

fn parse_protobuf(path: &Path) -> Option<DiscoveredSpec> {
    use ::regex::Regex;
    use std::sync::OnceLock;
    let body = std::fs::read_to_string(path).ok()?;

    static SVC: OnceLock<Regex> = OnceLock::new();
    let svc_re = SVC.get_or_init(|| Regex::new(
        r"(?ms)service\s+([A-Za-z_][A-Za-z_0-9]*)\s*\{(?P<body>[^}]*)\}"
    ).unwrap());
    static RPC: OnceLock<Regex> = OnceLock::new();
    let rpc_re = RPC.get_or_init(|| Regex::new(
        r"rpc\s+([A-Za-z_][A-Za-z_0-9]*)\s*\("
    ).unwrap());

    let mut operations = Vec::new();
    for caps in svc_re.captures_iter(&body) {
        let svc_name = caps.get(1)?.as_str();
        let body = caps.name("body")?.as_str();
        for rpc in rpc_re.captures_iter(body) {
            let method_name = rpc.get(1)?.as_str();
            let path = format!("/{}/{}", svc_name, method_name);
            operations.push(SpecOperation {
                method:          Method::Post, // gRPC over HTTP/2 = POST by convention
                path:            path.clone(),
                normalised_path: path,
                operation_id:    Some(format!("{svc_name}.{method_name}")),
            });
        }
    }
    if operations.is_empty() { return None }
    Some(DiscoveredSpec { file: path.to_path_buf(), kind: SpecKind::Protobuf, operations })
}
