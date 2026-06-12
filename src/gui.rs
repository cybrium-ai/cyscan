//! `cyscan gui` — local findings dashboard (Cybrium UI Kit).
//!
//! Loopback-only HTTP server. The browser POSTs a target path to
//! `/api/scan`; the response is the same finding shape as `cyscan scan`
//! (+ optional `cyscan supply`) so the UI renders the platform's data
//! verbatim. No auth, no TLS — bound to 127.0.0.1 only.
//!
//! The HTML shell (theme, header, palette tokens, word-filter) mirrors
//! the rest of the cy* fleet (cy-tls / cyproxy). To change the look,
//! update sentinel-ai docs/design/cybrium-ui-kit.md and propagate.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};

use crate::finding::Finding;

#[derive(Clone)]
struct AppState {
    /// Newest-last log of every scan run this session.
    history: Arc<tokio::sync::RwLock<Vec<ScanRun>>>,
}

#[derive(Clone, Serialize)]
struct ScanRun {
    target:   String,
    findings: Vec<Finding>,
    counts:   Counts,
}

#[derive(Clone, Default, Serialize)]
struct Counts {
    critical: usize,
    high:     usize,
    medium:   usize,
    low:      usize,
    info:     usize,
    total:    usize,
}

fn count(findings: &[Finding]) -> Counts {
    let mut c = Counts::default();
    for f in findings {
        match f.severity.as_str() {
            "critical" => c.critical += 1,
            "high"     => c.high += 1,
            "medium"   => c.medium += 1,
            "low"      => c.low += 1,
            _          => c.info += 1,
        }
        c.total += 1;
    }
    c
}

pub fn run(port: u16, no_open: bool) -> Result<()> {
    // cyscan is otherwise sync; spin a small multi-thread runtime just
    // for the GUI server rather than making the whole binary async.
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(serve(port, no_open))
}

async fn serve(port: u16, no_open: bool) -> Result<()> {
    let state = AppState {
        history: Arc::new(tokio::sync::RwLock::new(Vec::new())),
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/api/scan", post(api_scan))
        .route("/api/tpm", get(api_tpm))
        .route("/api/history", get(api_history))
        .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any))
        .with_state(state);

    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    eprintln!("cyscan GUI on http://{addr}");
    if !no_open {
        let _ = open_browser(&format!("http://{addr}"));
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn index() -> Html<String> {
    Html(INDEX_HTML.replace("{{VERSION}}", env!("CARGO_PKG_VERSION")))
}

#[derive(Debug, Deserialize)]
struct ScanRequest {
    target: String,
    /// Also run dependency / supply-chain analysis (OSV + typosquat +
    /// tampering + malicious-package detection) over discovered lockfiles.
    #[serde(default)]
    supply: bool,
}

async fn api_scan(
    State(state): State<AppState>,
    Json(req): Json<ScanRequest>,
) -> impl IntoResponse {
    let target = req.target.trim().to_string();
    if target.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "no target path provided" })),
        )
            .into_response();
    }
    let path = PathBuf::from(&target);
    if !path.exists() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("path does not exist: {target}") })),
        )
            .into_response();
    }

    // scanner::run / supply::run are synchronous + CPU-bound — keep them
    // off the reactor.
    let supply = req.supply;
    let result = tokio::task::spawn_blocking(move || run_scan(&path, supply)).await;

    match result {
        Ok(Ok(findings)) => {
            let counts = count(&findings);
            let run = ScanRun { target: target.clone(), findings, counts: counts.clone() };
            state.history.write().await.push(run.clone());
            Json(serde_json::json!({
                "target":   run.target,
                "findings": run.findings,
                "counts":   counts,
            }))
            .into_response()
        }
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("scan task failed: {e}") })),
        )
            .into_response(),
    }
}

fn run_scan(target: &std::path::Path, supply: bool) -> Result<Vec<Finding>> {
    let pack = crate::cli::load_pack(None)?;
    let mut findings = crate::scanner::run(target, &pack)?;
    for f in findings.iter_mut() {
        f.fingerprint = f.compute_fingerprint();
    }
    if supply {
        let snapshot = crate::supply::advisory::Snapshot::default();
        if let Ok(mut sca) = crate::supply::run(target, &pack, &snapshot) {
            for f in sca.iter_mut() {
                f.fingerprint = f.compute_fingerprint();
            }
            findings.extend(sca);
        }
    }
    Ok(findings)
}

async fn api_tpm() -> impl IntoResponse {
    Json(crate::hardware_rot::detect())
}

async fn api_history(State(state): State<AppState>) -> impl IntoResponse {
    let hist = state.history.read().await;
    Json(serde_json::json!({ "runs": *hist }))
}

fn open_browser(url: &str) -> Result<()> {
    let cmd = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(target_os = "windows") {
        "cmd"
    } else {
        "xdg-open"
    };
    let args: Vec<&str> = if cfg!(target_os = "windows") {
        vec!["/C", "start", url]
    } else {
        vec![url]
    };
    std::process::Command::new(cmd).args(args).spawn()?;
    Ok(())
}

const INDEX_HTML: &str = include_str!("../assets/index.html");
