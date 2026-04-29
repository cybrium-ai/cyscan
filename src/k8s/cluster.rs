//! Cluster interaction via kubectl — extract manifests, images, context info.

use std::collections::HashSet;
use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};

/// A discovered Kubernetes resource.
#[derive(Debug, Clone)]
pub struct K8sResource {
    pub namespace: String,
    pub kind:      String,
    pub name:      String,
    pub images:    Vec<String>,
    pub manifest:  String,
}

/// Get the current kubectl context name.
pub fn current_context(kubeconfig: Option<&Path>) -> Result<String> {
    let mut cmd = Command::new("kubectl");
    cmd.args(["config", "current-context"]);
    if let Some(kc) = kubeconfig {
        cmd.env("KUBECONFIG", kc);
    }
    let out = cmd.output().context("failed to run kubectl — is it installed?")?;
    if !out.status.success() {
        bail!("kubectl config current-context failed: {}",
            String::from_utf8_lossy(&out.stderr));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Resource types to scan.
const RESOURCE_TYPES: &[&str] = &[
    "pods", "deployments", "daemonsets", "statefulsets", "replicasets",
    "jobs", "cronjobs", "services", "configmaps", "secrets",
    "ingresses", "networkpolicies", "roles", "rolebindings",
    "clusterroles", "clusterrolebindings", "serviceaccounts",
    "persistentvolumeclaims", "nodes",
];

/// Extract all manifests from the cluster and write them to `output_dir`.
/// Returns a list of discovered resources.
pub fn extract_manifests(
    kubeconfig: Option<&Path>,
    namespace: Option<&str>,
    output_dir: &Path,
) -> Result<Vec<K8sResource>> {
    let mut resources = Vec::new();

    for resource_type in RESOURCE_TYPES {
        let mut cmd = Command::new("kubectl");
        cmd.arg("get").arg(resource_type);

        if let Some(ns) = namespace {
            cmd.args(["-n", ns]);
        } else {
            cmd.arg("-A");
        }

        cmd.args(["-o", "json"]);

        if let Some(kc) = kubeconfig {
            cmd.env("KUBECONFIG", kc);
        }

        let out = match cmd.output() {
            Ok(o) => o,
            Err(_) => continue,
        };

        if !out.status.success() {
            // Some resource types might not exist in the cluster — skip silently
            continue;
        }

        let json: serde_json::Value = match serde_json::from_slice(&out.stdout) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let items = match json.get("items").and_then(|i| i.as_array()) {
            Some(items) => items,
            None => continue,
        };

        for item in items {
            let kind = item.get("kind")
                .and_then(|k| k.as_str())
                .unwrap_or(resource_type)
                .to_string();

            let metadata = item.get("metadata");
            let name = metadata
                .and_then(|m| m.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("unknown")
                .to_string();

            let ns = metadata
                .and_then(|m| m.get("namespace"))
                .and_then(|n| n.as_str())
                .unwrap_or("cluster-scope")
                .to_string();

            // Extract container images from pod specs
            let images = extract_images_from_spec(item);

            // Write manifest to a file for scanning
            let safe_name = name.replace('/', "_").replace('\\', "_");
            let safe_kind = kind.to_lowercase();

            // Create namespace subdirectory
            let ns_dir = output_dir.join(&ns);
            std::fs::create_dir_all(&ns_dir).ok();

            let filename = format!("{}_{}.yaml", safe_kind, safe_name);
            let filepath = ns_dir.join(&filename);

            // Convert to YAML for scanning
            if let Ok(yaml) = serde_yaml::to_string(item) {
                std::fs::write(&filepath, &yaml).ok();
                resources.push(K8sResource {
                    namespace: ns,
                    kind,
                    name,
                    images,
                    manifest: yaml,
                });
            }
        }
    }

    Ok(resources)
}

/// Extract container image references from a K8s resource spec.
fn extract_images_from_spec(item: &serde_json::Value) -> Vec<String> {
    let mut images = Vec::new();

    // Try pod spec directly (for Pod resources)
    if let Some(containers) = item.pointer("/spec/containers") {
        collect_images(containers, &mut images);
    }
    if let Some(init) = item.pointer("/spec/initContainers") {
        collect_images(init, &mut images);
    }

    // Try nested pod template (for Deployment, DaemonSet, StatefulSet, Job, etc.)
    if let Some(containers) = item.pointer("/spec/template/spec/containers") {
        collect_images(containers, &mut images);
    }
    if let Some(init) = item.pointer("/spec/template/spec/initContainers") {
        collect_images(init, &mut images);
    }

    // CronJob has an extra nesting level
    if let Some(containers) = item.pointer("/spec/jobTemplate/spec/template/spec/containers") {
        collect_images(containers, &mut images);
    }

    images
}

fn collect_images(containers: &serde_json::Value, out: &mut Vec<String>) {
    if let Some(arr) = containers.as_array() {
        for c in arr {
            if let Some(img) = c.get("image").and_then(|i| i.as_str()) {
                out.push(img.to_string());
            }
        }
    }
}

/// Collect all unique container images across resources.
pub fn extract_images(resources: &[K8sResource]) -> HashSet<String> {
    let mut images = HashSet::new();
    for res in resources {
        for img in &res.images {
            images.insert(img.clone());
        }
    }
    images
}
