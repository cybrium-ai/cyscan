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
            Lang::Rust                                    => rust_clients(path, &source, &mut out),
            Lang::Swift                                   => swift_clients(path, &source, &mut out),
            Lang::Elixir                                  => elixir_clients(path, &source, &mut out),
            _ => {}
        }
        // GraphQL clients are language-agnostic patterns embedded in
        // any tier-1 source file. Run regardless of the per-language
        // discovery above.
        if matches!(lang, Lang::Python | Lang::Javascript | Lang::Typescript
                        | Lang::Csharp | Lang::Java | Lang::Go | Lang::Ruby
                        | Lang::Rust | Lang::Swift | Lang::Elixir) {
            graphql_clients(path, &source, lang, &mut out);
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
            Lang::Python                                  => {
                python_handlers(path, &source, &mut out);
                python_extra_handlers(path, &source, &mut out);
            }
            Lang::Javascript | Lang::Typescript          => js_handlers(path, &source, &mut out),
            Lang::Csharp                                  => csharp_handlers(path, &source, &mut out),
            Lang::Java                                    => java_handlers(path, &source, &mut out),
            Lang::Go                                      => {
                go_handlers(path, &source, &mut out);
                go_extra_handlers(path, &source, &mut out);
            }
            Lang::Ruby                                    => ruby_handlers(path, &source, &mut out),
            Lang::Rust                                    => rust_handlers(path, &source, &mut out),
            Lang::Swift                                   => swift_handlers(path, &source, &mut out),
            Lang::Elixir                                  => elixir_handlers(path, &source, &mut out),
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

// JS / TS — handlers (Express, NestJS, Hono, Fastify) with class-level
// path-prefix composition for NestJS @Controller("/users") + @Get(":id").
fn js_handlers(path: &Path, source: &str, out: &mut Vec<ServerEndpoint>) {
    static EXPRESS: OnceLock<Regex> = OnceLock::new();
    static NEST_DECORATOR: OnceLock<Regex> = OnceLock::new();
    static NEST_CONTROLLER: OnceLock<Regex> = OnceLock::new();
    static FASTIFY: OnceLock<Regex> = OnceLock::new();
    static HONO: OnceLock<Regex> = OnceLock::new();
    static CLASS_HEAD: OnceLock<Regex> = OnceLock::new();

    let express = EXPRESS.get_or_init(|| Regex::new(
        r#"(?:app|router|server|fastify|hono)\.(?P<m>get|post|put|patch|delete|head|options|all)\s*\(\s*['"`](?P<url>[^'"`]+)['"`]"#
    ).unwrap());
    let nest_decorator = NEST_DECORATOR.get_or_init(|| Regex::new(
        r#"@(?P<m>Get|Post|Put|Patch|Delete|Head|Options)\s*\(\s*(?:['"`](?P<url>[^'"`]+)['"`])?\s*\)"#
    ).unwrap());
    let nest_controller = NEST_CONTROLLER.get_or_init(|| Regex::new(
        r#"@Controller\s*\(\s*['"`](?P<url>[^'"`]+)['"`]"#
    ).unwrap());
    let _ = FASTIFY.get_or_init(|| Regex::new("").unwrap());
    let _ = HONO.get_or_init(|| Regex::new("").unwrap());
    let class_head = CLASS_HEAD.get_or_init(|| Regex::new(
        r#"\bclass\s+[A-Za-z_$][A-Za-z_0-9$]*"#
    ).unwrap());

    let mut current_prefix = String::new();
    let mut pending_prefix: Option<String> = None;

    for (i, line) in source.lines().enumerate() {
        if let Some(c) = nest_controller.captures(line) {
            pending_prefix = Some(c["url"].to_string());
        }
        if class_head.is_match(line) {
            current_prefix = pending_prefix.take().unwrap_or_default();
        }

        for c in express.captures_iter(line) {
            push_handler(out, path, i+1, "javascript", "express", &c["m"], &c["url"]);
        }
        for c in nest_decorator.captures_iter(line) {
            let url = c.name("url").map(|x| x.as_str()).unwrap_or("/");
            let composed = compose_path(&current_prefix, url);
            push_handler(out, path, i+1, "javascript", "nestjs", &c["m"], &composed);
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

// C# — handlers (ASP.NET Core attributes + minimal API) with class-level
// [Route("/api/users")] composition.
fn csharp_handlers(path: &Path, source: &str, out: &mut Vec<ServerEndpoint>) {
    static ATTR: OnceLock<Regex> = OnceLock::new();
    static MINIMAL: OnceLock<Regex> = OnceLock::new();
    static CLASS_ROUTE: OnceLock<Regex> = OnceLock::new();
    static CLASS_HEAD: OnceLock<Regex> = OnceLock::new();

    let attr = ATTR.get_or_init(|| Regex::new(
        r#"\[Http(?P<m>Get|Post|Put|Patch|Delete|Head|Options)\s*(?:\(\s*"(?P<url>[^"]+)"\s*\))?\]"#
    ).unwrap());
    let minimal = MINIMAL.get_or_init(|| Regex::new(
        r#"app\.Map(?P<m>Get|Post|Put|Patch|Delete)\s*\(\s*"(?P<url>[^"]+)""#
    ).unwrap());
    let class_route = CLASS_ROUTE.get_or_init(|| Regex::new(
        r#"\[Route\s*\(\s*"(?P<url>[^"]+)"\s*\)\]"#
    ).unwrap());
    let class_head = CLASS_HEAD.get_or_init(|| Regex::new(
        r#"\bclass\s+[A-Za-z_][A-Za-z_0-9]*"#
    ).unwrap());

    let mut current_prefix = String::new();
    let mut pending_prefix: Option<String> = None;

    for (i, line) in source.lines().enumerate() {
        if let Some(c) = class_route.captures(line) {
            pending_prefix = Some(c["url"].to_string());
        }
        if class_head.is_match(line) {
            current_prefix = pending_prefix.take().unwrap_or_default();
        }

        for c in attr.captures_iter(line) {
            let url = c.name("url").map(|x| x.as_str()).unwrap_or("/");
            let composed = compose_path(&current_prefix, url);
            push_handler(out, path, i+1, "csharp", "aspnet", &c["m"], &composed);
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

// Java — handlers (Spring MVC, path-prefix-aware)
//
// Spring lets you put a class-level @RequestMapping("/api") that
// composes with method-level @PostMapping("/users") to produce
// "/api/users". We track the class-level prefix as we walk the file.
fn java_handlers(path: &Path, source: &str, out: &mut Vec<ServerEndpoint>) {
    static MAPPING: OnceLock<Regex> = OnceLock::new();
    static REQUEST_MAPPING: OnceLock<Regex> = OnceLock::new();
    static CLASS_HEAD: OnceLock<Regex> = OnceLock::new();
    static CLASS_LEVEL_MAPPING: OnceLock<Regex> = OnceLock::new();

    let mapping = MAPPING.get_or_init(|| Regex::new(
        r#"@(?P<m>Get|Post|Put|Patch|Delete|Head|Options)Mapping\s*(?:\(\s*(?:value\s*=\s*)?"(?P<url>[^"]+)")?"#
    ).unwrap());
    let request_mapping = REQUEST_MAPPING.get_or_init(|| Regex::new(
        r#"@RequestMapping\s*\(\s*(?:value\s*=\s*)?"(?P<url>[^"]+)"(?:[^)]*method\s*=\s*RequestMethod\.(?P<m>[A-Z]+))?"#
    ).unwrap());
    let class_head = CLASS_HEAD.get_or_init(|| Regex::new(
        r#"\bclass\s+[A-Za-z_][A-Za-z_0-9]*"#
    ).unwrap());
    let class_level_mapping = CLASS_LEVEL_MAPPING.get_or_init(|| Regex::new(
        r#"@RequestMapping\s*\(\s*(?:value\s*=\s*)?"(?P<url>[^"]+)""#
    ).unwrap());

    let mut current_prefix = String::new();
    let mut pending_class_prefix: Option<String> = None;

    for (i, line) in source.lines().enumerate() {
        // Stash a class-level @RequestMapping so the next `class` line
        // adopts it as its prefix. Skip when the line also contains a
        // method= clause — that's a method-level mapping, not class.
        if !line.contains("method") && !line.contains("Mapping(method") {
            if let Some(c) = class_level_mapping.captures(line) {
                pending_class_prefix = Some(c["url"].to_string());
            }
        }
        // When we see a class header, lock in the prefix.
        if class_head.is_match(line) {
            current_prefix = pending_class_prefix.take().unwrap_or_default();
        }

        for c in mapping.captures_iter(line) {
            let url = c.name("url").map(|x| x.as_str()).unwrap_or("/");
            let composed = compose_path(&current_prefix, url);
            push_handler(out, path, i+1, "java", "spring", &c["m"], &composed);
        }
        for c in request_mapping.captures_iter(line) {
            let m = c.name("m").map(|x| x.as_str()).unwrap_or("ANY");
            let composed = compose_path(&current_prefix, &c["url"]);
            push_handler(out, path, i+1, "java", "spring", m, &composed);
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

// ────────────────────────────────────────────────────────────────────
// Sanic / Tornado — extra Python frameworks
// ────────────────────────────────────────────────────────────────────
fn python_extra_handlers(path: &Path, source: &str, out: &mut Vec<ServerEndpoint>) {
    static SANIC: OnceLock<Regex> = OnceLock::new();
    static TORNADO: OnceLock<Regex> = OnceLock::new();
    let sanic = SANIC.get_or_init(|| Regex::new(
        r#"@(?:app|bp)\.(?P<m>get|post|put|patch|delete|head|options)\s*\(\s*['"](?P<url>[^'"]+)['"]"#
    ).unwrap());
    let tornado = TORNADO.get_or_init(|| Regex::new(
        r#"\(\s*r?['"](?P<url>[^'"]+)['"](?:\s*,\s*[A-Za-z_][A-Za-z_0-9]*Handler)?\s*\)"#
    ).unwrap());
    for (i, line) in source.lines().enumerate() {
        for c in sanic.captures_iter(line) {
            push_handler(out, path, i+1, "python", "sanic", &c["m"], &c["url"]);
        }
        if line.contains("URLSpec") || line.contains("(r\"") || line.contains("Application([") {
            for c in tornado.captures_iter(line) {
                push_handler(out, path, i+1, "python", "tornado", "ANY", &c["url"]);
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// Echo / Gin — Go frameworks beyond net/http
// ────────────────────────────────────────────────────────────────────
fn go_extra_handlers(path: &Path, source: &str, out: &mut Vec<ServerEndpoint>) {
    static ECHO_GIN: OnceLock<Regex> = OnceLock::new();
    let re = ECHO_GIN.get_or_init(|| Regex::new(
        // Echo:  e.GET("/path", handler), Gin: r.GET("/path", handler),
        // also chi: r.Get("/path", handler) (capitalised)
        r#"\b(?:e|r|router|app|engine|group)\.(?P<m>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|Get|Post|Put|Patch|Delete|Head|Options)\s*\(\s*"(?P<url>[^"]+)""#
    ).unwrap());
    for (i, line) in source.lines().enumerate() {
        for c in re.captures_iter(line) {
            let framework = if line.contains("gin.") || line.contains("Gin(") {
                "gin"
            } else if line.contains("echo.") || line.contains("Echo()") {
                "echo"
            } else { "go-router" };
            push_handler(out, path, i+1, "go", framework, &c["m"], &c["url"]);
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// Rust — Actix-web, Axum, Rocket
// ────────────────────────────────────────────────────────────────────
fn rust_clients(path: &Path, source: &str, out: &mut Vec<ClientCall>) {
    static REQWEST: OnceLock<Regex> = OnceLock::new();
    static REQWEST_BUILDER: OnceLock<Regex> = OnceLock::new();
    let direct = REQWEST.get_or_init(|| Regex::new(
        r#"reqwest::(?P<m>get|post|put|patch|delete|head)\s*\(\s*"(?P<url>[^"]+)""#
    ).unwrap());
    let builder = REQWEST_BUILDER.get_or_init(|| Regex::new(
        r#"\.(?P<m>get|post|put|patch|delete|head)\s*\(\s*"(?P<url>[^"]+)""#
    ).unwrap());
    for (i, line) in source.lines().enumerate() {
        for c in direct.captures_iter(line) {
            push_client(out, path, i+1, "rust", "reqwest", &c["m"], &c["url"]);
        }
        // The builder pattern (`client.get("/url")`) is broader so we
        // gate on the line mentioning a known crate name to keep noise
        // low.
        if line.contains("Client::") || line.contains("reqwest::Client")
            || line.contains("ClientBuilder") || line.contains(".send(")
        {
            for c in builder.captures_iter(line) {
                if c.get(2).map(|m| m.as_str().starts_with("http")).unwrap_or(false) {
                    push_client(out, path, i+1, "rust", "reqwest-builder", &c["m"], &c["url"]);
                }
            }
        }
    }
}

fn rust_handlers(path: &Path, source: &str, out: &mut Vec<ServerEndpoint>) {
    static ACTIX: OnceLock<Regex> = OnceLock::new();
    static ROCKET: OnceLock<Regex> = OnceLock::new();
    static AXUM: OnceLock<Regex> = OnceLock::new();
    let actix = ACTIX.get_or_init(|| Regex::new(
        // #[get("/path")], #[post(...)], etc.
        r##"#\[\s*(?P<m>get|post|put|patch|delete|head|options)\s*\(\s*"(?P<url>[^"]+)"\s*\)"##
    ).unwrap());
    let rocket = ROCKET.get_or_init(|| Regex::new(
        // #[get("/path")], #[post("/path", data = "<x>")] — same shape
        // as Actix; we report Rocket separately based on the file
        // mentioning rocket::.
        r##"#\[\s*(?P<m>get|post|put|patch|delete)\s*\(\s*"(?P<url>[^"]+)""##
    ).unwrap());
    let axum = AXUM.get_or_init(|| Regex::new(
        // .route("/path", get(handler).post(handler2))
        r#"\.route\s*\(\s*"(?P<url>[^"]+)"\s*,\s*(?P<m>get|post|put|patch|delete|head|options|any)\s*\("#
    ).unwrap());
    for (i, line) in source.lines().enumerate() {
        for c in actix.captures_iter(line) {
            // Disambiguate Actix vs Rocket by source markers.
            let framework = if source.contains("rocket::") || source.contains("[macro_use] extern crate rocket") {
                "rocket"
            } else if source.contains("actix_web") {
                "actix-web"
            } else { "rust-attribute" };
            push_handler(out, path, i+1, "rust", framework, &c["m"], &c["url"]);
        }
        for c in axum.captures_iter(line) {
            push_handler(out, path, i+1, "rust", "axum", &c["m"], &c["url"]);
        }
        let _ = rocket; // covered by ACTIX regex; framework label disambiguated above
    }
}

// ────────────────────────────────────────────────────────────────────
// Swift — Vapor
// ────────────────────────────────────────────────────────────────────
fn swift_clients(path: &Path, source: &str, out: &mut Vec<ClientCall>) {
    static URL_SESSION: OnceLock<Regex> = OnceLock::new();
    let re = URL_SESSION.get_or_init(|| Regex::new(
        r#"URLSession\.shared\.(?:dataTask|data)\s*\(\s*with:\s*URL\(string:\s*"(?P<url>[^"]+)""#
    ).unwrap());
    for (i, line) in source.lines().enumerate() {
        for c in re.captures_iter(line) {
            push_client(out, path, i+1, "swift", "URLSession", "GET", &c["url"]);
        }
    }
}

fn swift_handlers(path: &Path, source: &str, out: &mut Vec<ServerEndpoint>) {
    static VAPOR: OnceLock<Regex> = OnceLock::new();
    let re = VAPOR.get_or_init(|| Regex::new(
        // app.get("/path") { ... }, app.post("users", "create") { ... }
        r#"(?:app|router|routes)\.(?P<m>get|post|put|patch|delete|head)\s*\(\s*"(?P<url>[^"]+)""#
    ).unwrap());
    for (i, line) in source.lines().enumerate() {
        for c in re.captures_iter(line) {
            push_handler(out, path, i+1, "swift", "vapor", &c["m"], &c["url"]);
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// Elixir — Phoenix
// ────────────────────────────────────────────────────────────────────
fn elixir_clients(path: &Path, source: &str, out: &mut Vec<ClientCall>) {
    static HTTPOISON: OnceLock<Regex> = OnceLock::new();
    let re = HTTPOISON.get_or_init(|| Regex::new(
        r#"HTTPoison\.(?P<m>get|post|put|patch|delete|head|request)\s*\(\s*"(?P<url>[^"]+)""#
    ).unwrap());
    for (i, line) in source.lines().enumerate() {
        for c in re.captures_iter(line) {
            push_client(out, path, i+1, "elixir", "HTTPoison", &c["m"], &c["url"]);
        }
    }
}

fn elixir_handlers(path: &Path, source: &str, out: &mut Vec<ServerEndpoint>) {
    static PHOENIX: OnceLock<Regex> = OnceLock::new();
    let re = PHOENIX.get_or_init(|| Regex::new(
        // Phoenix router.ex: get "/users", UserController, :index
        r#"^\s*(?P<m>get|post|put|patch|delete|head|options|forward)\s+"(?P<url>[^"]+)""#
    ).unwrap());
    for (i, line) in source.lines().enumerate() {
        for c in re.captures_iter(line) {
            push_handler(out, path, i+1, "elixir", "phoenix", &c["m"], &c["url"]);
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// GraphQL — language-agnostic embedded queries / mutations
// ────────────────────────────────────────────────────────────────────
fn graphql_clients(path: &Path, source: &str, lang: Lang, out: &mut Vec<ClientCall>) {
    static QUERY_LIT: OnceLock<Regex> = OnceLock::new();
    // Captures `query Foo { ... }` and `mutation Bar { ... }` blocks.
    // Also captures the FIRST root field accessed (we use it as the
    // synthesised path for matching against the spec).
    let re = QUERY_LIT.get_or_init(|| Regex::new(
        r"(?ms)(?P<kind>query|mutation|subscription)\s+(?P<name>[A-Za-z_][A-Za-z_0-9]*)?\s*[^{]*\{\s*(?P<root>[A-Za-z_][A-Za-z_0-9]*)"
    ).unwrap());
    let language = match lang {
        Lang::Python                       => "python",
        Lang::Javascript | Lang::Typescript => "javascript",
        Lang::Csharp                       => "csharp",
        Lang::Java                         => "java",
        Lang::Go                           => "go",
        Lang::Ruby                         => "ruby",
        Lang::Rust                         => "rust",
        Lang::Swift                        => "swift",
        Lang::Elixir                       => "elixir",
        _                                  => "unknown",
    };
    for c in re.captures_iter(source) {
        let kind = match c.name("kind").map(|m| m.as_str()) {
            Some("query")        => "Query",
            Some("mutation")     => "Mutation",
            Some("subscription") => "Subscription",
            _                    => continue,
        };
        let root_field = c.name("root").map(|m| m.as_str()).unwrap_or("?");
        let path_str = format!("/graphql#{kind}.{root_field}");
        // Locate the line number — find the start byte of `kind` in
        // source and count newlines.
        let start = c.get(0).map(|m| m.start()).unwrap_or(0);
        let line_no = source[..start].matches('\n').count() + 1;
        out.push(ClientCall {
            file:            path.to_path_buf(),
            line:            line_no,
            language:        language.into(),
            method:          Method::Post,
            path:            path_str.clone(),
            normalised_path: path_str,
            via:             "graphql".into(),
        });
    }
}

/// Compose a class-level path prefix with a method-level relative
/// path. Empty prefix returns the relative path as-is. Otherwise
/// trims '/' boundaries so we never emit `/api//users`.
pub(super) fn compose_path(prefix: &str, relative: &str) -> String {
    let p = prefix.trim_end_matches('/').trim();
    let r = relative.trim_start_matches('/').trim();
    if p.is_empty() {
        if relative.starts_with('/') { relative.into() } else { format!("/{r}") }
    } else if r.is_empty() {
        p.into()
    } else {
        format!("{p}/{r}")
    }
}
