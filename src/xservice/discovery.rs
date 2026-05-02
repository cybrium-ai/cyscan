//! HTTP client + server endpoint discovery across languages.
//!
//! Per-language regex patterns find call sites and handler decls. We
//! prefer false positives over false negatives — a call that *looks*
//! like a `requests.post("/url")` will be reported even if it's
//! technically wrapped in a function the engine can't fully resolve.
//! The match engine downstream filters out spurious pairs.

use std::path::Path;
use std::sync::OnceLock;

use ignore::WalkBuilder;
use regex::Regex;

use super::{normalise_path, ClientCall, Method, ServerEndpoint};
use crate::lang::Lang;

/// Walk `target` and collect every HTTP client call we recognise.
pub fn find_client_calls(target: &Path) -> Vec<ClientCall> {
    let mut out = Vec::new();
    for entry in WalkBuilder::new(target).standard_filters(true).hidden(false).build()
        .filter_map(|r| r.ok())
        .filter(|e| e.file_type().map_or(false, |ft| ft.is_file()))
    {
        let path = entry.path();
        let Some(lang) = Lang::from_path(path) else { continue };
        let Ok(source) = std::fs::read_to_string(path) else { continue };
        match lang {
            Lang::Python                                  => python_clients(path, &source, &mut out),
            Lang::Javascript | Lang::Typescript          => js_clients(path, &source, &mut out),
            Lang::Csharp                                  => csharp_clients(path, &source, &mut out),
            Lang::Java                                    => java_clients(path, &source, &mut out),
            Lang::Go                                      => go_clients(path, &source, &mut out),
            Lang::Ruby                                    => ruby_clients(path, &source, &mut out),
            _ => {}
        }
    }
    out
}

/// Walk `target` and collect every HTTP server handler we recognise.
pub fn find_server_endpoints(target: &Path) -> Vec<ServerEndpoint> {
    let mut out = Vec::new();
    for entry in WalkBuilder::new(target).standard_filters(true).hidden(false).build()
        .filter_map(|r| r.ok())
        .filter(|e| e.file_type().map_or(false, |ft| ft.is_file()))
    {
        let path = entry.path();
        let Some(lang) = Lang::from_path(path) else { continue };
        let Ok(source) = std::fs::read_to_string(path) else { continue };
        match lang {
            Lang::Python                                  => python_handlers(path, &source, &mut out),
            Lang::Javascript | Lang::Typescript          => js_handlers(path, &source, &mut out),
            Lang::Csharp                                  => csharp_handlers(path, &source, &mut out),
            Lang::Java                                    => java_handlers(path, &source, &mut out),
            Lang::Go                                      => go_handlers(path, &source, &mut out),
            Lang::Ruby                                    => ruby_handlers(path, &source, &mut out),
            _ => {}
        }
    }
    out
}

// ────────────────────────────────────────────────────────────────────
// Python — clients
// ────────────────────────────────────────────────────────────────────
fn python_clients(path: &Path, source: &str, out: &mut Vec<ClientCall>) {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(
        // requests.get("..."), requests.post(...), httpx.post(...),
        // aiohttp.ClientSession.post("..."), session.get("...")
        r#"(?P<lib>requests|httpx|aiohttp|session|client)\.(?P<m>get|post|put|patch|delete|head|options)\s*\(\s*['"](?P<url>[^'"]+)['"]"#
    ).unwrap());
    for (i, line) in source.lines().enumerate() {
        for c in re.captures_iter(line) {
            push_client(out, path, i+1, "python", &c["lib"], &c["m"], &c["url"]);
        }
    }
}

// Python — handlers (Flask + FastAPI + Django)
fn python_handlers(path: &Path, source: &str, out: &mut Vec<ServerEndpoint>) {
    static FLASK: OnceLock<Regex> = OnceLock::new();
    static FASTAPI: OnceLock<Regex> = OnceLock::new();
    static FASTAPI_VERB: OnceLock<Regex> = OnceLock::new();
    static DJANGO: OnceLock<Regex> = OnceLock::new();

    let flask = FLASK.get_or_init(|| Regex::new(
        r#"@(?:app|blueprint|bp)\.route\s*\(\s*['"](?P<url>[^'"]+)['"](?:[^)]*methods\s*=\s*\[\s*['"](?P<m>[A-Z]+)['"])?"#
    ).unwrap());
    let fastapi = FASTAPI.get_or_init(|| Regex::new(
        r#"@(?:app|router)\.api_route\s*\(\s*['"](?P<url>[^'"]+)['"](?:[^)]*methods\s*=\s*\[\s*['"](?P<m>[A-Z]+)['"])?"#
    ).unwrap());
    let fastapi_verb = FASTAPI_VERB.get_or_init(|| Regex::new(
        r#"@(?:app|router)\.(?P<m>get|post|put|patch|delete|head|options)\s*\(\s*['"](?P<url>[^'"]+)['"]"#
    ).unwrap());
    let django = DJANGO.get_or_init(|| Regex::new(
        r#"\b(?:path|re_path)\s*\(\s*r?['"](?P<url>[^'"]+)['"]"#
    ).unwrap());

    for (i, line) in source.lines().enumerate() {
        for c in flask.captures_iter(line) {
            let m = c.name("m").map(|x| x.as_str()).unwrap_or("GET");
            push_handler(out, path, i+1, "python", "flask", m, &c["url"]);
        }
        for c in fastapi.captures_iter(line) {
            let m = c.name("m").map(|x| x.as_str()).unwrap_or("GET");
            push_handler(out, path, i+1, "python", "fastapi", m, &c["url"]);
        }
        for c in fastapi_verb.captures_iter(line) {
            push_handler(out, path, i+1, "python", "fastapi", &c["m"], &c["url"]);
        }
        for c in django.captures_iter(line) {
            // Django's path is verb-agnostic; record as ANY.
            push_handler(out, path, i+1, "python", "django", "ANY", &c["url"]);
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// JS / TS — clients (fetch, axios, http.request)
// ────────────────────────────────────────────────────────────────────
fn js_clients(path: &Path, source: &str, out: &mut Vec<ClientCall>) {
    static FETCH: OnceLock<Regex> = OnceLock::new();
    static AXIOS: OnceLock<Regex> = OnceLock::new();

    let fetch = FETCH.get_or_init(|| Regex::new(
        r#"(?:fetch|axios|http\.request|got|node-fetch)\s*\(\s*['"`](?P<url>[^'"`]+)['"`](?:[^)]*method\s*:\s*['"`](?P<m>[A-Z]+)['"`])?"#
    ).unwrap());
    let axios = AXIOS.get_or_init(|| Regex::new(
        r#"(?:axios|got|http)\.(?P<m>get|post|put|patch|delete|head|options)\s*\(\s*['"`](?P<url>[^'"`]+)['"`]"#
    ).unwrap());
    for (i, line) in source.lines().enumerate() {
        for c in fetch.captures_iter(line) {
            let m = c.name("m").map(|x| x.as_str()).unwrap_or("GET");
            push_client(out, path, i+1, "javascript", "fetch", m, &c["url"]);
        }
        for c in axios.captures_iter(line) {
            push_client(out, path, i+1, "javascript", "axios", &c["m"], &c["url"]);
        }
    }
}

// JS / TS — handlers (Express, NestJS, Hono, Fastify)
fn js_handlers(path: &Path, source: &str, out: &mut Vec<ServerEndpoint>) {
    static EXPRESS: OnceLock<Regex> = OnceLock::new();
    static NEST_DECORATOR: OnceLock<Regex> = OnceLock::new();
    static NEST_PATH: OnceLock<Regex> = OnceLock::new();

    let express = EXPRESS.get_or_init(|| Regex::new(
        r#"(?:app|router|server)\.(?P<m>get|post|put|patch|delete|head|options|all)\s*\(\s*['"`](?P<url>[^'"`]+)['"`]"#
    ).unwrap());
    let nest_decorator = NEST_DECORATOR.get_or_init(|| Regex::new(
        r#"@(?P<m>Get|Post|Put|Patch|Delete|Head|Options)\s*\(\s*(?:['"`](?P<url>[^'"`]+)['"`])?\s*\)"#
    ).unwrap());
    let nest_path = NEST_PATH.get_or_init(|| Regex::new(
        r#"@Controller\s*\(\s*['"`](?P<url>[^'"`]+)['"`]"#
    ).unwrap());

    for (i, line) in source.lines().enumerate() {
        for c in express.captures_iter(line) {
            push_handler(out, path, i+1, "javascript", "express", &c["m"], &c["url"]);
        }
        for c in nest_decorator.captures_iter(line) {
            let url = c.name("url").map(|x| x.as_str()).unwrap_or("/");
            push_handler(out, path, i+1, "javascript", "nestjs", &c["m"], url);
        }
        for c in nest_path.captures_iter(line) {
            // @Controller declares a base path — record as ANY/<path>.
            push_handler(out, path, i+1, "javascript", "nestjs", "ANY", &c["url"]);
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// C# — clients (HttpClient.PostAsync, etc.)
// ────────────────────────────────────────────────────────────────────
fn csharp_clients(path: &Path, source: &str, out: &mut Vec<ClientCall>) {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(
        r#"\.(?P<m>GetAsync|PostAsync|PutAsync|PatchAsync|DeleteAsync|SendAsync)\s*\(\s*"(?P<url>[^"]+)""#
    ).unwrap());
    for (i, line) in source.lines().enumerate() {
        for c in re.captures_iter(line) {
            let method = match &c["m"] {
                "GetAsync"   => "GET",
                "PostAsync"  => "POST",
                "PutAsync"   => "PUT",
                "PatchAsync" => "PATCH",
                "DeleteAsync"=> "DELETE",
                _            => "GET",
            };
            push_client(out, path, i+1, "csharp", "HttpClient", method, &c["url"]);
        }
    }
}

// C# — handlers (ASP.NET Core attributes + minimal API)
fn csharp_handlers(path: &Path, source: &str, out: &mut Vec<ServerEndpoint>) {
    static ATTR: OnceLock<Regex> = OnceLock::new();
    static MINIMAL: OnceLock<Regex> = OnceLock::new();

    let attr = ATTR.get_or_init(|| Regex::new(
        r#"\[Http(?P<m>Get|Post|Put|Patch|Delete|Head|Options)\s*(?:\(\s*"(?P<url>[^"]+)"\s*\))?\]"#
    ).unwrap());
    let minimal = MINIMAL.get_or_init(|| Regex::new(
        r#"app\.Map(?P<m>Get|Post|Put|Patch|Delete)\s*\(\s*"(?P<url>[^"]+)""#
    ).unwrap());

    for (i, line) in source.lines().enumerate() {
        for c in attr.captures_iter(line) {
            let url = c.name("url").map(|x| x.as_str()).unwrap_or("/");
            push_handler(out, path, i+1, "csharp", "aspnet", &c["m"], url);
        }
        for c in minimal.captures_iter(line) {
            push_handler(out, path, i+1, "csharp", "aspnet-minimal", &c["m"], &c["url"]);
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// Java — clients (RestTemplate / WebClient)
// ────────────────────────────────────────────────────────────────────
fn java_clients(path: &Path, source: &str, out: &mut Vec<ClientCall>) {
    static REST_TEMPLATE: OnceLock<Regex> = OnceLock::new();
    static WEB_CLIENT: OnceLock<Regex> = OnceLock::new();

    let rt = REST_TEMPLATE.get_or_init(|| Regex::new(
        r#"\.(?P<m>getForObject|postForObject|put|patchForObject|delete|exchange)\s*\(\s*"(?P<url>[^"]+)""#
    ).unwrap());
    let wc = WEB_CLIENT.get_or_init(|| Regex::new(
        r#"\.(?P<m>get|post|put|patch|delete)\s*\(\s*\)\s*\.uri\s*\(\s*"(?P<url>[^"]+)""#
    ).unwrap());

    for (i, line) in source.lines().enumerate() {
        for c in rt.captures_iter(line) {
            let m = match &c["m"] {
                "getForObject"     => "GET",
                "postForObject"    => "POST",
                "put"              => "PUT",
                "patchForObject"   => "PATCH",
                "delete"           => "DELETE",
                "exchange"         => "ANY",
                _                  => "GET",
            };
            push_client(out, path, i+1, "java", "RestTemplate", m, &c["url"]);
        }
        for c in wc.captures_iter(line) {
            push_client(out, path, i+1, "java", "WebClient", &c["m"], &c["url"]);
        }
    }
}

// Java — handlers (Spring MVC)
fn java_handlers(path: &Path, source: &str, out: &mut Vec<ServerEndpoint>) {
    static MAPPING: OnceLock<Regex> = OnceLock::new();
    static REQUEST_MAPPING: OnceLock<Regex> = OnceLock::new();

    let mapping = MAPPING.get_or_init(|| Regex::new(
        r#"@(?P<m>Get|Post|Put|Patch|Delete|Head|Options)Mapping\s*(?:\(\s*(?:value\s*=\s*)?"(?P<url>[^"]+)")?"#
    ).unwrap());
    let request_mapping = REQUEST_MAPPING.get_or_init(|| Regex::new(
        r#"@RequestMapping\s*\(\s*(?:value\s*=\s*)?"(?P<url>[^"]+)"(?:[^)]*method\s*=\s*RequestMethod\.(?P<m>[A-Z]+))?"#
    ).unwrap());

    for (i, line) in source.lines().enumerate() {
        for c in mapping.captures_iter(line) {
            let url = c.name("url").map(|x| x.as_str()).unwrap_or("/");
            push_handler(out, path, i+1, "java", "spring", &c["m"], url);
        }
        for c in request_mapping.captures_iter(line) {
            let m = c.name("m").map(|x| x.as_str()).unwrap_or("ANY");
            push_handler(out, path, i+1, "java", "spring", m, &c["url"]);
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// Go — clients + handlers
// ────────────────────────────────────────────────────────────────────
fn go_clients(path: &Path, source: &str, out: &mut Vec<ClientCall>) {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(
        r#"http\.(?P<m>Get|Post|Put|Patch|Delete|Head)\s*\(\s*"(?P<url>[^"]+)""#
    ).unwrap());
    for (i, line) in source.lines().enumerate() {
        for c in re.captures_iter(line) {
            push_client(out, path, i+1, "go", "net/http", &c["m"], &c["url"]);
        }
    }
}

fn go_handlers(path: &Path, source: &str, out: &mut Vec<ServerEndpoint>) {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(
        r#"(?:http\.HandleFunc|router\.HandleFunc|mux\.HandleFunc|r\.HandleFunc)\s*\(\s*"(?P<url>[^"]+)""#
    ).unwrap());
    for (i, line) in source.lines().enumerate() {
        for c in re.captures_iter(line) {
            push_handler(out, path, i+1, "go", "net/http", "ANY", &c["url"]);
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// Ruby — clients (Net::HTTP, HTTParty) + handlers (Rails routes)
// ────────────────────────────────────────────────────────────────────
fn ruby_clients(path: &Path, source: &str, out: &mut Vec<ClientCall>) {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(
        r#"(?:Net::HTTP|HTTParty|RestClient|Faraday)\.(?P<m>get|post|put|patch|delete|head)\s*\(\s*['"](?P<url>[^'"]+)['"]"#
    ).unwrap());
    for (i, line) in source.lines().enumerate() {
        for c in re.captures_iter(line) {
            push_client(out, path, i+1, "ruby", "Net::HTTP", &c["m"], &c["url"]);
        }
    }
}

fn ruby_handlers(path: &Path, source: &str, out: &mut Vec<ServerEndpoint>) {
    static ROUTES: OnceLock<Regex> = OnceLock::new();
    let re = ROUTES.get_or_init(|| Regex::new(
        r#"^\s*(?P<m>get|post|put|patch|delete|head|options|match)\s+['"](?P<url>[^'"]+)['"]"#
    ).unwrap());
    for (i, line) in source.lines().enumerate() {
        for c in re.captures_iter(line) {
            push_handler(out, path, i+1, "ruby", "rails", &c["m"], &c["url"]);
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// helpers
// ────────────────────────────────────────────────────────────────────
fn push_client(
    out: &mut Vec<ClientCall>,
    path: &Path, line: usize, language: &str, via: &str, method: &str, url: &str,
) {
    let Some(m) = Method::from_str_loose(method) else { return };
    out.push(ClientCall {
        file:            path.to_path_buf(),
        line,
        language:        language.into(),
        method:          m,
        path:            url.into(),
        normalised_path: normalise_path(url),
        via:             via.into(),
    });
}

fn push_handler(
    out: &mut Vec<ServerEndpoint>,
    path: &Path, line: usize, language: &str, framework: &str, method: &str, url: &str,
) {
    let Some(m) = Method::from_str_loose(method) else { return };
    out.push(ServerEndpoint {
        file:            path.to_path_buf(),
        line,
        language:        language.into(),
        framework:       framework.into(),
        method:          m,
        path:            url.into(),
        normalised_path: normalise_path(url),
        handler_name:    None,
    });
}
