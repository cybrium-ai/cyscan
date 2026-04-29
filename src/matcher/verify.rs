//! Secret liveness verification — tests if detected credentials are
//! actually valid by making safe, read-only API calls.
//!
//! Only runs when `--verify` flag is passed. Never modifies, writes,
//! or creates anything — strictly read-only identity checks.
//!
//! Verification results are added to the finding's evidence map:
//!   evidence.verified = true|false
//!   evidence.verified_as = "user@example.com" (identity if available)

use std::collections::HashMap;
use std::time::Duration;

use anyhow::Result;

/// Verification result.
#[derive(Debug)]
pub struct VerifyResult {
    pub is_live:  bool,
    pub identity: Option<String>,  // who the credential belongs to
    pub detail:   String,
}

/// Attempt to verify a secret's liveness based on its rule ID and value.
/// Returns None if verification is not supported for this secret type.
pub fn verify_secret(rule_id: &str, secret_value: &str) -> Option<VerifyResult> {
    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(false)
        .build()
    {
        Ok(c) => c,
        Err(_) => return None,
    };

    match rule_id {
        "CBR-SEC-AWS-ACCESS-KEY-ID" | "CBR-SECRETS-AWS-KEY" => {
            // AWS keys need both access key + secret key — can't verify standalone
            Some(VerifyResult {
                is_live: false,
                identity: None,
                detail: "AWS keys require both access key ID and secret — verify manually with: aws sts get-caller-identity".into(),
            })
        }

        "CBR-SEC-GITHUB-PAT" | "CBR-SEC-GITHUB-FINE-PAT" | "CBR-SEC-GITHUB-OAUTH" => {
            verify_github(&client, secret_value)
        }

        "CBR-SEC-GITLAB-PAT" => {
            verify_gitlab(&client, secret_value)
        }

        "CBR-SEC-SLACK-BOT-TOKEN" | "CBR-SEC-SLACK-USER-TOKEN" => {
            verify_slack(&client, secret_value)
        }

        "CBR-SEC-STRIPE-SECRET" | "CBR-SEC-STRIPE-RESTRICTED" => {
            verify_stripe(&client, secret_value)
        }

        "CBR-SEC-SENDGRID-API-KEY" => {
            verify_sendgrid(&client, secret_value)
        }

        "CBR-SEC-TWILIO-API-KEY" | "CBR-SEC-TWILIO-AUTH-TOKEN" => {
            // Twilio needs account SID + auth token pair
            Some(VerifyResult {
                is_live: false,
                identity: None,
                detail: "Twilio requires Account SID + Auth Token pair — verify manually".into(),
            })
        }

        "CBR-SEC-OPENAI-API-KEY" | "CBR-SEC-OPENAI-PROJECT-KEY" => {
            verify_openai(&client, secret_value)
        }

        "CBR-SEC-ANTHROPIC-API-KEY" => {
            verify_anthropic(&client, secret_value)
        }

        "CBR-SEC-HUGGINGFACE-TOKEN" => {
            verify_huggingface(&client, secret_value)
        }

        "CBR-SEC-DATADOG-API-KEY" => {
            verify_datadog(&client, secret_value)
        }

        "CBR-SEC-NPM-TOKEN" | "CBR-SEC-NPMRC-AUTH" => {
            verify_npm(&client, secret_value)
        }

        "CBR-SEC-PYPI-TOKEN" => {
            verify_pypi(&client, secret_value)
        }

        "CBR-SEC-DOCKER-HUB-PAT" => {
            verify_dockerhub(&client, secret_value)
        }

        "CBR-SEC-HEROKU-API-KEY" => {
            verify_heroku(&client, secret_value)
        }

        "CBR-SEC-DIGITALOCEAN-TOKEN" | "CBR-SEC-DIGITALOCEAN-OAUTH" => {
            verify_digitalocean(&client, secret_value)
        }

        "CBR-SEC-CLOUDFLARE-API-TOKEN" => {
            verify_cloudflare(&client, secret_value)
        }

        "CBR-SEC-HASHICORP-VAULT-TOKEN" => {
            // Vault needs the server URL — can't verify standalone
            Some(VerifyResult {
                is_live: false,
                identity: None,
                detail: "Vault token requires VAULT_ADDR — verify with: vault token lookup".into(),
            })
        }

        "CBR-SEC-GCP-API-KEY" => {
            verify_gcp_api_key(&client, secret_value)
        }

        "CBR-SEC-NEWRELIC-KEY" => {
            verify_newrelic(&client, secret_value)
        }

        "CBR-SEC-SHOPIFY-ACCESS-TOKEN" => {
            // Shopify needs the store domain
            Some(VerifyResult {
                is_live: false,
                identity: None,
                detail: "Shopify token requires store domain — verify manually".into(),
            })
        }

        "CBR-SEC-LINEAR-API-KEY" => {
            verify_linear(&client, secret_value)
        }

        "CBR-SEC-SENTRY-DSN" => {
            // DSN format includes the project — just check if it's reachable
            verify_sentry(&client, secret_value)
        }

        _ => None,  // Verification not supported for this secret type
    }
}

// ── Provider-specific verifiers ─────────────────────────────────────────

fn verify_github(client: &reqwest::blocking::Client, token: &str) -> Option<VerifyResult> {
    let resp = client
        .get("https://api.github.com/user")
        .header("Authorization", format!("Bearer {}", token))
        .header("User-Agent", "cyscan-verify/1.0")
        .send()
        .ok()?;

    if resp.status().is_success() {
        let body: serde_json::Value = resp.json().ok()?;
        let login = body["login"].as_str().unwrap_or("unknown");
        Some(VerifyResult {
            is_live: true,
            identity: Some(format!("github.com/{}", login)),
            detail: format!("LIVE — authenticated as {}", login),
        })
    } else {
        Some(VerifyResult {
            is_live: false,
            identity: None,
            detail: format!("Invalid or expired (HTTP {})", resp.status()),
        })
    }
}

fn verify_gitlab(client: &reqwest::blocking::Client, token: &str) -> Option<VerifyResult> {
    let resp = client
        .get("https://gitlab.com/api/v4/user")
        .header("PRIVATE-TOKEN", token)
        .send()
        .ok()?;

    if resp.status().is_success() {
        let body: serde_json::Value = resp.json().ok()?;
        let username = body["username"].as_str().unwrap_or("unknown");
        Some(VerifyResult {
            is_live: true,
            identity: Some(format!("gitlab.com/{}", username)),
            detail: format!("LIVE — authenticated as {}", username),
        })
    } else {
        Some(VerifyResult { is_live: false, identity: None, detail: "Invalid or expired".into() })
    }
}

fn verify_slack(client: &reqwest::blocking::Client, token: &str) -> Option<VerifyResult> {
    let resp = client
        .get("https://slack.com/api/auth.test")
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .ok()?;

    let body: serde_json::Value = resp.json().ok()?;
    if body["ok"].as_bool() == Some(true) {
        let team = body["team"].as_str().unwrap_or("unknown");
        let user = body["user"].as_str().unwrap_or("unknown");
        Some(VerifyResult {
            is_live: true,
            identity: Some(format!("{}/{}", team, user)),
            detail: format!("LIVE — workspace: {}, user: {}", team, user),
        })
    } else {
        Some(VerifyResult { is_live: false, identity: None, detail: "Invalid token".into() })
    }
}

fn verify_stripe(client: &reqwest::blocking::Client, key: &str) -> Option<VerifyResult> {
    let resp = client
        .get("https://api.stripe.com/v1/charges?limit=1")
        .basic_auth(key, None::<&str>)
        .send()
        .ok()?;

    if resp.status().is_success() {
        Some(VerifyResult {
            is_live: true,
            identity: Some("stripe-account".into()),
            detail: "LIVE — Stripe key is valid and has API access".into(),
        })
    } else if resp.status().as_u16() == 401 {
        Some(VerifyResult { is_live: false, identity: None, detail: "Invalid key".into() })
    } else {
        Some(VerifyResult {
            is_live: true,
            identity: None,
            detail: format!("Possibly live (HTTP {})", resp.status()),
        })
    }
}

fn verify_sendgrid(client: &reqwest::blocking::Client, key: &str) -> Option<VerifyResult> {
    let resp = client
        .get("https://api.sendgrid.com/v3/user/profile")
        .header("Authorization", format!("Bearer {}", key))
        .send()
        .ok()?;

    if resp.status().is_success() {
        let body: serde_json::Value = resp.json().ok()?;
        let email = body["email"].as_str().unwrap_or("unknown");
        Some(VerifyResult {
            is_live: true,
            identity: Some(email.to_string()),
            detail: format!("LIVE — SendGrid account: {}", email),
        })
    } else {
        Some(VerifyResult { is_live: false, identity: None, detail: "Invalid key".into() })
    }
}

fn verify_openai(client: &reqwest::blocking::Client, key: &str) -> Option<VerifyResult> {
    let resp = client
        .get("https://api.openai.com/v1/models")
        .header("Authorization", format!("Bearer {}", key))
        .send()
        .ok()?;

    if resp.status().is_success() {
        Some(VerifyResult {
            is_live: true,
            identity: Some("openai-account".into()),
            detail: "LIVE — OpenAI key has API access".into(),
        })
    } else {
        Some(VerifyResult { is_live: false, identity: None, detail: "Invalid or expired".into() })
    }
}

fn verify_anthropic(client: &reqwest::blocking::Client, key: &str) -> Option<VerifyResult> {
    let resp = client
        .get("https://api.anthropic.com/v1/models")
        .header("x-api-key", key)
        .header("anthropic-version", "2023-06-01")
        .send()
        .ok()?;

    if resp.status().is_success() {
        Some(VerifyResult {
            is_live: true,
            identity: Some("anthropic-account".into()),
            detail: "LIVE — Anthropic key has API access".into(),
        })
    } else {
        Some(VerifyResult { is_live: false, identity: None, detail: "Invalid or expired".into() })
    }
}

fn verify_huggingface(client: &reqwest::blocking::Client, token: &str) -> Option<VerifyResult> {
    let resp = client
        .get("https://huggingface.co/api/whoami-v2")
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .ok()?;

    if resp.status().is_success() {
        let body: serde_json::Value = resp.json().ok()?;
        let name = body["name"].as_str().unwrap_or("unknown");
        Some(VerifyResult {
            is_live: true,
            identity: Some(name.to_string()),
            detail: format!("LIVE — HuggingFace user: {}", name),
        })
    } else {
        Some(VerifyResult { is_live: false, identity: None, detail: "Invalid token".into() })
    }
}

fn verify_datadog(client: &reqwest::blocking::Client, key: &str) -> Option<VerifyResult> {
    let resp = client
        .get("https://api.datadoghq.com/api/v1/validate")
        .header("DD-API-KEY", key)
        .send()
        .ok()?;

    if resp.status().is_success() {
        Some(VerifyResult {
            is_live: true,
            identity: None,
            detail: "LIVE — Datadog API key is valid".into(),
        })
    } else {
        Some(VerifyResult { is_live: false, identity: None, detail: "Invalid key".into() })
    }
}

fn verify_npm(client: &reqwest::blocking::Client, token: &str) -> Option<VerifyResult> {
    let resp = client
        .get("https://registry.npmjs.org/-/whoami")
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .ok()?;

    if resp.status().is_success() {
        let body: serde_json::Value = resp.json().ok()?;
        let username = body["username"].as_str().unwrap_or("unknown");
        Some(VerifyResult {
            is_live: true,
            identity: Some(format!("npm/{}", username)),
            detail: format!("LIVE — npm user: {}", username),
        })
    } else {
        Some(VerifyResult { is_live: false, identity: None, detail: "Invalid token".into() })
    }
}

fn verify_pypi(client: &reqwest::blocking::Client, token: &str) -> Option<VerifyResult> {
    let resp = client
        .get("https://upload.pypi.org/legacy/")
        .basic_auth("__token__", Some(token))
        .send()
        .ok()?;

    // PyPI returns 405 for GET but authenticates — 401 = bad token
    if resp.status().as_u16() != 401 && resp.status().as_u16() != 403 {
        Some(VerifyResult {
            is_live: true,
            identity: None,
            detail: "LIVE — PyPI token accepted".into(),
        })
    } else {
        Some(VerifyResult { is_live: false, identity: None, detail: "Invalid token".into() })
    }
}

fn verify_dockerhub(client: &reqwest::blocking::Client, token: &str) -> Option<VerifyResult> {
    let resp = client
        .get("https://hub.docker.com/v2/user")
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .ok()?;

    if resp.status().is_success() {
        let body: serde_json::Value = resp.json().ok()?;
        let username = body["username"].as_str().unwrap_or("unknown");
        Some(VerifyResult {
            is_live: true,
            identity: Some(format!("docker.io/{}", username)),
            detail: format!("LIVE — Docker Hub user: {}", username),
        })
    } else {
        Some(VerifyResult { is_live: false, identity: None, detail: "Invalid token".into() })
    }
}

fn verify_heroku(client: &reqwest::blocking::Client, key: &str) -> Option<VerifyResult> {
    let resp = client
        .get("https://api.heroku.com/account")
        .header("Authorization", format!("Bearer {}", key))
        .header("Accept", "application/vnd.heroku+json; version=3")
        .send()
        .ok()?;

    if resp.status().is_success() {
        let body: serde_json::Value = resp.json().ok()?;
        let email = body["email"].as_str().unwrap_or("unknown");
        Some(VerifyResult {
            is_live: true,
            identity: Some(email.to_string()),
            detail: format!("LIVE — Heroku account: {}", email),
        })
    } else {
        Some(VerifyResult { is_live: false, identity: None, detail: "Invalid key".into() })
    }
}

fn verify_digitalocean(client: &reqwest::blocking::Client, token: &str) -> Option<VerifyResult> {
    let resp = client
        .get("https://api.digitalocean.com/v2/account")
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .ok()?;

    if resp.status().is_success() {
        let body: serde_json::Value = resp.json().ok()?;
        let email = body["account"]["email"].as_str().unwrap_or("unknown");
        Some(VerifyResult {
            is_live: true,
            identity: Some(email.to_string()),
            detail: format!("LIVE — DigitalOcean account: {}", email),
        })
    } else {
        Some(VerifyResult { is_live: false, identity: None, detail: "Invalid token".into() })
    }
}

fn verify_cloudflare(client: &reqwest::blocking::Client, token: &str) -> Option<VerifyResult> {
    let resp = client
        .get("https://api.cloudflare.com/client/v4/user/tokens/verify")
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .ok()?;

    if resp.status().is_success() {
        Some(VerifyResult {
            is_live: true,
            identity: None,
            detail: "LIVE — Cloudflare API token is valid".into(),
        })
    } else {
        Some(VerifyResult { is_live: false, identity: None, detail: "Invalid token".into() })
    }
}

fn verify_gcp_api_key(client: &reqwest::blocking::Client, key: &str) -> Option<VerifyResult> {
    // Use the Generative Language API as a lightweight check
    let resp = client
        .get(format!("https://generativelanguage.googleapis.com/v1/models?key={}", key))
        .send()
        .ok()?;

    if resp.status().is_success() {
        Some(VerifyResult {
            is_live: true,
            identity: None,
            detail: "LIVE — GCP API key has access".into(),
        })
    } else if resp.status().as_u16() == 403 {
        Some(VerifyResult {
            is_live: true,
            identity: None,
            detail: "LIVE — GCP API key valid but restricted scope".into(),
        })
    } else {
        Some(VerifyResult { is_live: false, identity: None, detail: "Invalid key".into() })
    }
}

fn verify_newrelic(client: &reqwest::blocking::Client, key: &str) -> Option<VerifyResult> {
    let resp = client
        .get("https://api.newrelic.com/v2/users.json")
        .header("Api-Key", key)
        .send()
        .ok()?;

    if resp.status().is_success() {
        Some(VerifyResult {
            is_live: true,
            identity: None,
            detail: "LIVE — New Relic API key is valid".into(),
        })
    } else {
        Some(VerifyResult { is_live: false, identity: None, detail: "Invalid key".into() })
    }
}

fn verify_linear(client: &reqwest::blocking::Client, key: &str) -> Option<VerifyResult> {
    let resp = client
        .post("https://api.linear.app/graphql")
        .header("Authorization", key)
        .json(&serde_json::json!({"query": "{ viewer { id name } }"}))
        .send()
        .ok()?;

    if resp.status().is_success() {
        let body: serde_json::Value = resp.json().ok()?;
        let name = body["data"]["viewer"]["name"].as_str().unwrap_or("unknown");
        Some(VerifyResult {
            is_live: true,
            identity: Some(name.to_string()),
            detail: format!("LIVE — Linear user: {}", name),
        })
    } else {
        Some(VerifyResult { is_live: false, identity: None, detail: "Invalid key".into() })
    }
}

fn verify_sentry(client: &reqwest::blocking::Client, dsn: &str) -> Option<VerifyResult> {
    // Just check if the Sentry ingest endpoint is reachable
    let resp = client.get(dsn).send().ok()?;
    if resp.status().as_u16() != 404 {
        Some(VerifyResult {
            is_live: true,
            identity: None,
            detail: "LIVE — Sentry DSN endpoint is reachable".into(),
        })
    } else {
        Some(VerifyResult { is_live: false, identity: None, detail: "DSN not found".into() })
    }
}

/// Enrich findings with verification results.
pub fn enrich_findings(findings: &mut [crate::finding::Finding]) {
    for finding in findings.iter_mut() {
        // Only verify secret-type findings
        if !finding.rule_id.starts_with("CBR-SEC-") && !finding.rule_id.starts_with("CBR-SECRETS-") {
            continue;
        }

        // Extract the secret value from the snippet
        let secret = extract_secret_from_snippet(&finding.snippet);
        if secret.is_empty() {
            continue;
        }

        if let Some(result) = verify_secret(&finding.rule_id, &secret) {
            finding.evidence.insert(
                "verified".into(),
                serde_json::Value::Bool(result.is_live),
            );
            finding.evidence.insert(
                "verification_detail".into(),
                serde_json::Value::String(result.detail.clone()),
            );
            if let Some(identity) = &result.identity {
                finding.evidence.insert(
                    "verified_as".into(),
                    serde_json::Value::String(identity.clone()),
                );
            }

            // Escalate severity if the secret is verified live
            if result.is_live {
                finding.severity = crate::finding::Severity::Critical;
                finding.message = format!(
                    "VERIFIED LIVE SECRET — {}\n\n{}",
                    result.detail, finding.message
                );
            }
        }
    }
}

/// Extract the probable secret value from a finding snippet.
fn extract_secret_from_snippet(snippet: &str) -> String {
    // Try to extract quoted value
    if let Some(start) = snippet.find('"') {
        if let Some(end) = snippet[start + 1..].find('"') {
            return snippet[start + 1..start + 1 + end].to_string();
        }
    }
    if let Some(start) = snippet.find('\'') {
        if let Some(end) = snippet[start + 1..].find('\'') {
            return snippet[start + 1..start + 1 + end].to_string();
        }
    }
    // Try value after = sign
    if let Some(eq) = snippet.find('=') {
        return snippet[eq + 1..].trim().trim_matches('"').trim_matches('\'').to_string();
    }
    // Return the whole snippet as fallback
    snippet.trim().to_string()
}
