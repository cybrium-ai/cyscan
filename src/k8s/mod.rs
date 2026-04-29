//! Kubernetes cluster scanner — connects to a live cluster via kubectl,
//! extracts manifests + running images, scans for misconfigurations,
//! secrets, and container image CVEs.
//!
//! Usage:
//!   cyscan k8s                              # scan current context, all namespaces
//!   cyscan k8s --namespace kube-system      # single namespace
//!   cyscan k8s --report summary             # summary table (like trivy k8s)
//!   cyscan k8s --report full                # full findings list
//!   cyscan k8s --kubeconfig ~/.kube/config   # explicit kubeconfig

pub mod cluster;
pub mod image_scan;
pub mod summary;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::finding::{Finding, Severity};
use crate::rule::RulePack;
use crate::scanner;

/// A K8s resource with its findings grouped.
#[derive(Debug, Clone)]
pub struct ResourceReport {
    pub namespace:    String,
    pub kind:         String,
    pub name:         String,
    pub vulns:        SeverityCounts,
    pub misconfigs:   SeverityCounts,
    pub secrets:      SeverityCounts,
}

#[derive(Debug, Clone, Default)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high:     usize,
    pub medium:   usize,
    pub low:      usize,
    pub unknown:  usize,
}

impl SeverityCounts {
    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.unknown
    }

    fn inc(&mut self, sev: Severity) {
        match sev {
            Severity::Critical => self.critical += 1,
            Severity::High     => self.high += 1,
            Severity::Medium   => self.medium += 1,
            Severity::Low      => self.low += 1,
            Severity::Info     => self.unknown += 1,
        }
    }
}

#[derive(Debug, Clone)]
pub struct K8sReport {
    pub cluster_name:  String,
    pub workloads:     Vec<ResourceReport>,
    pub infra:         Vec<ResourceReport>,
    pub all_findings:  Vec<Finding>,
    pub images_scanned: usize,
    pub image_vulns:   usize,
}

pub struct K8sOptions {
    pub kubeconfig: Option<PathBuf>,
    pub namespace:  Option<String>,
    pub scan_images: bool,
}

/// Run a full Kubernetes cluster scan.
pub fn run(pack: &RulePack, opts: &K8sOptions) -> Result<K8sReport> {
    let cluster_name = cluster::current_context(opts.kubeconfig.as_deref())?;
    eprintln!("Scanning cluster: {}", cluster_name);

    // Step 1: Extract all manifests from cluster
    eprintln!("  Extracting manifests...");
    let temp_dir = tempfile::tempdir().context("creating temp dir")?;
    let resources = cluster::extract_manifests(
        opts.kubeconfig.as_deref(),
        opts.namespace.as_deref(),
        temp_dir.path(),
    )?;
    eprintln!("  Extracted {} resources", resources.len());

    // Step 2: Scan manifests with cyscan rules (misconfigs + secrets)
    // Filter pack to only K8s-relevant rules (yaml, docker, terraform, generic, json)
    let k8s_pack = pack.filter_languages(&[
        "yaml", "docker", "terraform", "generic", "json",
        "kubernetes", "bash", "ini", "toml", "xml",
    ]);
    eprintln!("  Scanning for misconfigurations and secrets ({} rules)...", k8s_pack.rules().len());
    let manifest_findings = scanner::run(temp_dir.path(), &k8s_pack)?;
    eprintln!("  Found {} issues", manifest_findings.len());

    // Step 3: Extract container images and scan for CVEs
    let mut image_findings = Vec::new();
    let mut images_scanned = 0;
    if opts.scan_images {
        let images = cluster::extract_images(&resources);
        let unique_images: Vec<_> = images.into_iter().collect();
        eprintln!("  Scanning {} unique container images for CVEs...", unique_images.len());
        for img in &unique_images {
            eprintln!("    Scanning {}...", img);
            match image_scan::scan_image(img) {
                Ok(findings) => {
                    image_findings.extend(findings);
                    images_scanned += 1;
                }
                Err(e) => {
                    eprintln!("    Warning: failed to scan {}: {}", img, e);
                }
            }
        }
    }

    let image_vulns = image_findings.len();

    // Step 4: Group findings by resource
    let mut all_findings = Vec::new();
    all_findings.extend(manifest_findings);
    all_findings.extend(image_findings);

    let (workloads, infra) = group_findings(&all_findings, &resources);

    Ok(K8sReport {
        cluster_name,
        workloads,
        infra,
        all_findings,
        images_scanned,
        image_vulns,
    })
}

/// Group findings into workload vs infrastructure resources.
fn group_findings(
    findings: &[Finding],
    resources: &[cluster::K8sResource],
) -> (Vec<ResourceReport>, Vec<ResourceReport>) {
    let mut reports: HashMap<String, ResourceReport> = HashMap::new();

    // Initialize from extracted resources
    for res in resources {
        let key = format!("{}/{}/{}", res.namespace, res.kind, res.name);
        reports.entry(key).or_insert_with(|| ResourceReport {
            namespace:  res.namespace.clone(),
            kind:       res.kind.clone(),
            name:       res.name.clone(),
            vulns:      SeverityCounts::default(),
            misconfigs: SeverityCounts::default(),
            secrets:    SeverityCounts::default(),
        });
    }

    // Classify and count findings
    for finding in findings {
        // Try to match finding to a resource via filename
        let fname = finding.file.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("");

        // Find the best matching resource
        let key = reports.keys()
            .find(|k| {
                let parts: Vec<&str> = k.split('/').collect();
                if parts.len() >= 3 {
                    let res_name = parts[2];
                    let res_kind = parts[1].to_lowercase();
                    fname.contains(res_name) || fname.contains(&res_kind)
                } else {
                    false
                }
            })
            .cloned()
            .unwrap_or_else(|| {
                // Fallback: create a generic resource
                let ns = finding.file.parent()
                    .and_then(|p| p.file_name())
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
                    .to_string();
                format!("{}/Unknown/{}", ns, fname)
            });

        let report = reports.entry(key.clone()).or_insert_with(|| {
            let parts: Vec<&str> = key.split('/').collect();
            ResourceReport {
                namespace:  parts.first().unwrap_or(&"unknown").to_string(),
                kind:       parts.get(1).unwrap_or(&"Unknown").to_string(),
                name:       parts.get(2).unwrap_or(&"unknown").to_string(),
                vulns:      SeverityCounts::default(),
                misconfigs: SeverityCounts::default(),
                secrets:    SeverityCounts::default(),
            }
        });

        // Classify finding type
        if finding.rule_id.contains("LIC-") || finding.rule_id.contains("DEP-")
            || finding.rule_id.contains("CVE-") || finding.rule_id.contains("GHSA-")
            || finding.rule_id.starts_with("CBR-IMG-")
        {
            report.vulns.inc(finding.severity);
        } else if finding.rule_id.contains("SECRET") || finding.rule_id.contains("CREDENTIAL")
            || finding.rule_id.contains("PASSWORD") || finding.rule_id.contains("TOKEN")
            || finding.rule_id.contains("API-KEY") || finding.rule_id.contains("PRIVATE-KEY")
            || finding.rule_id.contains("LEAK")
        {
            report.secrets.inc(finding.severity);
        } else {
            report.misconfigs.inc(finding.severity);
        }
    }

    // Split into workload vs infra namespaces
    let infra_namespaces = ["kube-system", "kube-public", "kube-node-lease",
        "cert-manager", "ingress-nginx", "keda", "monitoring", "istio-system"];

    let mut workloads = Vec::new();
    let mut infra = Vec::new();

    for (_, report) in reports {
        // Skip resources with zero findings
        if report.vulns.total() + report.misconfigs.total() + report.secrets.total() == 0 {
            continue;
        }

        if infra_namespaces.contains(&report.namespace.as_str()) {
            infra.push(report);
        } else {
            workloads.push(report);
        }
    }

    // Sort by namespace, then kind, then name
    let sorter = |a: &ResourceReport, b: &ResourceReport| {
        a.namespace.cmp(&b.namespace)
            .then_with(|| a.kind.cmp(&b.kind))
            .then_with(|| a.name.cmp(&b.name))
    };
    workloads.sort_by(sorter);
    infra.sort_by(sorter);

    (workloads, infra)
}
