//! Kubernetes / Helm topology awareness for cross-service URL resolution.
//!
//! When a C# client calls `https://user-svc/api/users`, the path side
//! matches a Java handler at `/api/users` — but the discovery only
//! knew the path. With this module, we also know that `user-svc`
//! resolves to a k8s `Service` whose selector matches a `Deployment`
//! in this repo, so we can confirm the call is intra-cluster and tag
//! the link with the deployment / pod context.
//!
//! Out of scope (deliberately):
//!   * Live cluster lookups (the scanner is offline / hermetic)
//!   * Helm template rendering (we read raw YAML — `{{ .Values.xxx }}`
//!     is left intact and matched as a literal)
//!   * Service-mesh sidecar resolution (Istio VirtualService / Envoy
//!     can be added later if customers ask)

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use ignore::WalkBuilder;
use serde::Deserialize;

#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct K8sTopology {
    /// Service name → metadata. Multiple files may declare the same
    /// service name in different envs; we keep the first one we see.
    pub services: HashMap<String, ServiceInfo>,
    /// Deployment label-selector key → list of deployment names that
    /// match it. Lets us answer "which deployment runs `user-svc`?"
    pub deployments_by_label: HashMap<String, Vec<String>>,
    /// Helm chart roots discovered (paths to dirs containing
    /// `Chart.yaml`). Their templates are parsed alongside plain
    /// manifests.
    pub helm_charts: Vec<PathBuf>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ServiceInfo {
    pub name:      String,
    pub namespace: Option<String>,
    pub ports:     Vec<u16>,
    pub selector:  HashMap<String, String>,
    pub source:    PathBuf,
}

/// Walk `target`, parse every k8s manifest + Helm template, and
/// build the topology view. Files that don't parse as YAML — or that
/// parse but don't carry `kind: Service` / `kind: Deployment` — are
/// silently ignored.
pub fn discover_topology(target: &Path) -> K8sTopology {
    let mut topology = K8sTopology::default();
    for entry in WalkBuilder::new(target).standard_filters(true).hidden(false).build()
        .filter_map(|r| r.ok())
        .filter(|e| e.file_type().map_or(false, |ft| ft.is_file()))
    {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name == "Chart.yaml" {
            if let Some(parent) = path.parent() {
                topology.helm_charts.push(parent.to_path_buf());
            }
            continue;
        }
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "yaml" && ext != "yml" { continue; }
        let Ok(body) = std::fs::read_to_string(path) else { continue };

        // YAML files can contain multiple `---`-separated documents.
        for doc in body.split("\n---") {
            // Strip the optional leading `---` from the first doc.
            let doc = doc.trim_start_matches("---").trim_start();
            if doc.is_empty() { continue; }
            ingest_yaml_doc(doc, path, &mut topology);
        }
    }
    topology
}

#[derive(Debug, Deserialize)]
struct K8sObject {
    #[serde(rename = "kind")]
    kind: Option<String>,
    metadata: Option<K8sMeta>,
    spec: Option<K8sSpec>,
}

#[derive(Debug, Deserialize)]
struct K8sMeta {
    name: Option<String>,
    namespace: Option<String>,
    labels: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct K8sSpec {
    ports:    Option<Vec<K8sPort>>,
    selector: Option<serde_yaml::Value>,
    template: Option<K8sTemplate>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // target_port read via deserialiser only
struct K8sPort {
    port:        Option<u16>,
    target_port: Option<serde_yaml::Value>,
}

#[derive(Debug, Deserialize)]
struct K8sTemplate {
    metadata: Option<K8sMeta>,
}

fn ingest_yaml_doc(doc: &str, source: &Path, topology: &mut K8sTopology) {
    let Ok(obj) = serde_yaml::from_str::<K8sObject>(doc) else { return };
    let kind = obj.kind.as_deref().unwrap_or("");
    match kind {
        "Service" => {
            let Some(meta) = obj.metadata.as_ref() else { return };
            let Some(name) = meta.name.as_deref() else { return };
            let ports: Vec<u16> = obj.spec.as_ref()
                .and_then(|s| s.ports.as_ref())
                .map(|ps| ps.iter().filter_map(|p| p.port).collect())
                .unwrap_or_default();
            let selector: HashMap<String, String> = obj.spec.as_ref()
                .and_then(|s| s.selector.as_ref())
                .and_then(|v| serde_yaml::from_value::<HashMap<String, String>>(v.clone()).ok())
                .unwrap_or_default();
            topology.services.entry(name.to_string()).or_insert(ServiceInfo {
                name:      name.to_string(),
                namespace: meta.namespace.clone(),
                ports,
                selector,
                source:    source.to_path_buf(),
            });
        }
        "Deployment" | "StatefulSet" | "DaemonSet" => {
            let Some(meta) = obj.metadata.as_ref() else { return };
            let Some(name) = meta.name.as_deref() else { return };
            // Combine top-level labels and pod-template labels.
            let mut labels: HashMap<String, String> = meta.labels.clone().unwrap_or_default();
            if let Some(template_meta) = obj.spec.as_ref()
                .and_then(|s| s.template.as_ref())
                .and_then(|t| t.metadata.as_ref())
            {
                if let Some(template_labels) = &template_meta.labels {
                    labels.extend(template_labels.clone());
                }
            }
            for (k, v) in &labels {
                let key = format!("{k}={v}");
                topology.deployments_by_label.entry(key).or_default().push(name.to_string());
            }
        }
        _ => {}
    }
}

/// Resolve a client URL to a k8s `Service` if the host part matches
/// one. Returns the resolved service info plus the deployment name(s)
/// that satisfy the service's selector. None means the host doesn't
/// resolve to anything we know about.
pub fn resolve_url<'a>(
    raw_url: &str,
    topology: &'a K8sTopology,
) -> Option<ResolvedUrl<'a>> {
    // Pull the host out of `http://user-svc/path`, `https://user-svc:8080/...`,
    // or just `user-svc/path` (relative). FQDN like
    // `user-svc.default.svc.cluster.local` resolves on the leftmost
    // segment.
    let (host, _) = extract_host(raw_url)?;
    let host = host.split('.').next().unwrap_or(host);
    let svc = topology.services.get(host)?;
    let selector_key = svc.selector.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>();
    let deployments: Vec<String> = selector_key.iter()
        .flat_map(|k| topology.deployments_by_label.get(k).cloned().unwrap_or_default())
        .collect();
    Some(ResolvedUrl { service: svc, deployments })
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ResolvedUrl<'a> {
    pub service:     &'a ServiceInfo,
    pub deployments: Vec<String>,
}

fn extract_host(raw: &str) -> Option<(&str, Option<u16>)> {
    let stripped = raw.trim_start_matches("https://").trim_start_matches("http://");
    let (host_port, _) = stripped.split_once('/').unwrap_or((stripped, ""));
    if host_port.is_empty() { return None }
    if let Some((host, port)) = host_port.rsplit_once(':') {
        let port: Option<u16> = port.parse().ok();
        Some((host, port))
    } else {
        Some((host_port, None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_host_handles_protocol_and_port() {
        assert_eq!(extract_host("http://user-svc/path"),       Some(("user-svc", None)));
        assert_eq!(extract_host("https://user-svc:8080/path"), Some(("user-svc", Some(8080))));
        assert_eq!(extract_host("user-svc/path"),              Some(("user-svc", None)));
    }
}
