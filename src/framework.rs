//! Framework detection — identify which frameworks/libraries are used
//! in the scanned codebase by analyzing imports, config files, and lockfiles.
//!
//! Outputs a list of detected frameworks with confidence scores.
//! Used to: tag findings, filter rules, and show in dashboard.

use std::{
    collections::HashMap,
    fs,
    path::Path,
};

use regex::Regex;

/// A detected framework with metadata.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DetectedFramework {
    pub name: String,
    pub language: String,
    pub category: &'static str,
    pub version: Option<String>,
    pub confidence: f64,
    pub detected_in: Vec<String>,
}

/// Framework definition for detection.
struct FrameworkDef {
    name: &'static str,
    language: &'static str,
    category: &'static str,
    /// Import patterns to search for in source files
    import_patterns: &'static [&'static str],
    /// Lockfile/config file indicators
    config_indicators: &'static [(&'static str, &'static str)], // (filename_pattern, content_pattern)
}

const FRAMEWORKS: &[FrameworkDef] = &[
    // ── Python ──────────────────────────────────────────────────────
    FrameworkDef { name: "Django", language: "python", category: "web",
        import_patterns: &["from django", "import django", "django.conf", "django.urls"],
        config_indicators: &[("requirements*.txt", "django"), ("Pipfile", "django"), ("pyproject.toml", "django"), ("settings.py", "INSTALLED_APPS")]
    },
    FrameworkDef { name: "Flask", language: "python", category: "web",
        import_patterns: &["from flask", "import flask", "Flask(__name__)"],
        config_indicators: &[("requirements*.txt", "flask"), ("Pipfile", "flask")]
    },
    FrameworkDef { name: "FastAPI", language: "python", category: "web",
        import_patterns: &["from fastapi", "import fastapi", "FastAPI()"],
        config_indicators: &[("requirements*.txt", "fastapi"), ("pyproject.toml", "fastapi")]
    },
    FrameworkDef { name: "SQLAlchemy", language: "python", category: "orm",
        import_patterns: &["from sqlalchemy", "import sqlalchemy"],
        config_indicators: &[("requirements*.txt", "sqlalchemy")]
    },
    FrameworkDef { name: "Celery", language: "python", category: "task-queue",
        import_patterns: &["from celery", "import celery", "Celery("],
        config_indicators: &[("requirements*.txt", "celery")]
    },
    FrameworkDef { name: "Pandas", language: "python", category: "data",
        import_patterns: &["import pandas", "from pandas"],
        config_indicators: &[("requirements*.txt", "pandas")]
    },
    FrameworkDef { name: "PyTorch", language: "python", category: "ml",
        import_patterns: &["import torch", "from torch"],
        config_indicators: &[("requirements*.txt", "torch")]
    },
    FrameworkDef { name: "TensorFlow", language: "python", category: "ml",
        import_patterns: &["import tensorflow", "from tensorflow"],
        config_indicators: &[("requirements*.txt", "tensorflow")]
    },
    // ── JavaScript / TypeScript ─────────────────────────────────────
    FrameworkDef { name: "React", language: "javascript", category: "web",
        import_patterns: &["from 'react'", "from \"react\"", "require('react')"],
        config_indicators: &[("package.json", "\"react\"")]
    },
    FrameworkDef { name: "Next.js", language: "javascript", category: "web",
        import_patterns: &["from 'next", "next/router", "next/image"],
        config_indicators: &[("package.json", "\"next\""), ("next.config", "")]
    },
    FrameworkDef { name: "Express", language: "javascript", category: "web",
        import_patterns: &["require('express')", "from 'express'", "express()"],
        config_indicators: &[("package.json", "\"express\"")]
    },
    FrameworkDef { name: "Vue", language: "javascript", category: "web",
        import_patterns: &["from 'vue'", "require('vue')", "createApp"],
        config_indicators: &[("package.json", "\"vue\"")]
    },
    FrameworkDef { name: "Angular", language: "javascript", category: "web",
        import_patterns: &["@angular/core", "@angular/common"],
        config_indicators: &[("package.json", "\"@angular/core\""), ("angular.json", "")]
    },
    FrameworkDef { name: "Svelte", language: "javascript", category: "web",
        import_patterns: &["from 'svelte'", "svelte/store"],
        config_indicators: &[("package.json", "\"svelte\"")]
    },
    FrameworkDef { name: "NestJS", language: "typescript", category: "web",
        import_patterns: &["@nestjs/common", "@nestjs/core"],
        config_indicators: &[("package.json", "\"@nestjs/core\"")]
    },
    FrameworkDef { name: "Prisma", language: "typescript", category: "orm",
        import_patterns: &["@prisma/client", "PrismaClient"],
        config_indicators: &[("package.json", "\"prisma\""), ("schema.prisma", "")]
    },
    FrameworkDef { name: "Sequelize", language: "javascript", category: "orm",
        import_patterns: &["require('sequelize')", "from 'sequelize'"],
        config_indicators: &[("package.json", "\"sequelize\"")]
    },
    // ── Java ────────────────────────────────────────────────────────
    FrameworkDef { name: "Spring Boot", language: "java", category: "web",
        import_patterns: &["org.springframework.boot", "@SpringBootApplication", "@RestController"],
        config_indicators: &[("pom.xml", "spring-boot"), ("build.gradle", "spring-boot")]
    },
    FrameworkDef { name: "Spring", language: "java", category: "web",
        import_patterns: &["org.springframework", "@Autowired", "@Component"],
        config_indicators: &[("pom.xml", "spring-context"), ("build.gradle", "spring-context")]
    },
    FrameworkDef { name: "Hibernate", language: "java", category: "orm",
        import_patterns: &["org.hibernate", "@Entity", "@Table"],
        config_indicators: &[("pom.xml", "hibernate"), ("build.gradle", "hibernate")]
    },
    FrameworkDef { name: "Struts", language: "java", category: "web",
        import_patterns: &["org.apache.struts"],
        config_indicators: &[("pom.xml", "struts")]
    },
    // ── Go ──────────────────────────────────────────────────────────
    FrameworkDef { name: "Gin", language: "go", category: "web",
        import_patterns: &["github.com/gin-gonic/gin"],
        config_indicators: &[("go.mod", "gin-gonic/gin")]
    },
    FrameworkDef { name: "Echo", language: "go", category: "web",
        import_patterns: &["github.com/labstack/echo"],
        config_indicators: &[("go.mod", "labstack/echo")]
    },
    FrameworkDef { name: "Fiber", language: "go", category: "web",
        import_patterns: &["github.com/gofiber/fiber"],
        config_indicators: &[("go.mod", "gofiber/fiber")]
    },
    FrameworkDef { name: "GORM", language: "go", category: "orm",
        import_patterns: &["gorm.io/gorm"],
        config_indicators: &[("go.mod", "gorm.io/gorm")]
    },
    // ── Ruby ────────────────────────────────────────────────────────
    FrameworkDef { name: "Rails", language: "ruby", category: "web",
        import_patterns: &["Rails.application", "ActionController", "ActiveRecord"],
        config_indicators: &[("Gemfile", "rails"), ("config/routes.rb", "")]
    },
    FrameworkDef { name: "Sinatra", language: "ruby", category: "web",
        import_patterns: &["require 'sinatra'", "Sinatra::Base"],
        config_indicators: &[("Gemfile", "sinatra")]
    },
    // ── PHP ─────────────────────────────────────────────────────────
    FrameworkDef { name: "Laravel", language: "php", category: "web",
        import_patterns: &["Illuminate\\", "use App\\"],
        config_indicators: &[("composer.json", "laravel/framework"), ("artisan", "")]
    },
    FrameworkDef { name: "Symfony", language: "php", category: "web",
        import_patterns: &["Symfony\\Component", "Symfony\\Bundle"],
        config_indicators: &[("composer.json", "symfony/")]
    },
    FrameworkDef { name: "WordPress", language: "php", category: "cms",
        import_patterns: &["wp_", "add_action", "add_filter", "WP_Query"],
        config_indicators: &[("wp-config.php", ""), ("wp-content/", "")]
    },
    // ── Rust ────────────────────────────────────────────────────────
    FrameworkDef { name: "Actix Web", language: "rust", category: "web",
        import_patterns: &["actix_web", "use actix_web"],
        config_indicators: &[("Cargo.toml", "actix-web")]
    },
    FrameworkDef { name: "Axum", language: "rust", category: "web",
        import_patterns: &["use axum"],
        config_indicators: &[("Cargo.toml", "axum")]
    },
    FrameworkDef { name: "Tokio", language: "rust", category: "runtime",
        import_patterns: &["use tokio", "#[tokio::main]"],
        config_indicators: &[("Cargo.toml", "tokio")]
    },
    // ── Terraform / IaC ────────────────────────────────────────────
    FrameworkDef { name: "Terraform AWS", language: "terraform", category: "cloud",
        import_patterns: &["provider \"aws\"", "aws_"],
        config_indicators: &[("*.tf", "provider \"aws\"")]
    },
    FrameworkDef { name: "Terraform Azure", language: "terraform", category: "cloud",
        import_patterns: &["provider \"azurerm\"", "azurerm_"],
        config_indicators: &[("*.tf", "provider \"azurerm\"")]
    },
    FrameworkDef { name: "Terraform GCP", language: "terraform", category: "cloud",
        import_patterns: &["provider \"google\"", "google_"],
        config_indicators: &[("*.tf", "provider \"google\"")]
    },
];

/// Detect frameworks used in the target directory.
pub fn detect(target: &Path) -> Vec<DetectedFramework> {
    let mut results: HashMap<&str, DetectedFramework> = HashMap::new();

    let walker = walkdir::WalkDir::new(target)
        .max_depth(5)
        .into_iter()
        .filter_entry(|e| {
            let n = e.file_name().to_str().unwrap_or("");
            !n.starts_with('.') && n != "node_modules" && n != "target"
                && n != "__pycache__" && n != "vendor" && n != "venv"
        });

    for entry in walker.filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() { continue; }
        let path = entry.path();
        let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let source = match fs::read_to_string(path) { Ok(s) => s, Err(_) => continue };

        for fw in FRAMEWORKS {
            // Check import patterns in source files
            for pattern in fw.import_patterns {
                if source.contains(pattern) {
                    let entry = results.entry(fw.name).or_insert_with(|| DetectedFramework {
                        name: fw.name.to_string(),
                        language: fw.language.to_string(),
                        category: fw.category,
                        version: None,
                        confidence: 0.0,
                        detected_in: Vec::new(),
                    });
                    entry.confidence = (entry.confidence + 0.3).min(1.0);
                    let loc = path.display().to_string();
                    if !entry.detected_in.contains(&loc) && entry.detected_in.len() < 5 {
                        entry.detected_in.push(loc);
                    }
                    break;
                }
            }

            // Check config files
            for (config_pattern, content_pattern) in fw.config_indicators {
                let matches_name = if config_pattern.contains('*') {
                    let prefix = config_pattern.split('*').next().unwrap_or("");
                    fname.starts_with(prefix)
                } else {
                    fname == *config_pattern
                };

                if matches_name {
                    let content_matches = content_pattern.is_empty() || source.contains(content_pattern);
                    if content_matches {
                        let entry = results.entry(fw.name).or_insert_with(|| DetectedFramework {
                            name: fw.name.to_string(),
                            language: fw.language.to_string(),
                            category: fw.category,
                            version: None,
                            confidence: 0.0,
                            detected_in: Vec::new(),
                        });
                        entry.confidence = (entry.confidence + 0.5).min(1.0);

                        // Try to extract version from lockfile/config
                        if entry.version.is_none() && !content_pattern.is_empty() {
                            entry.version = extract_version(&source, content_pattern);
                        }

                        let loc = path.display().to_string();
                        if !entry.detected_in.contains(&loc) && entry.detected_in.len() < 3 {
                            entry.detected_in.push(loc);
                        }
                    }
                }
            }
        }
    }

    let mut detected: Vec<DetectedFramework> = results.into_values()
        .filter(|f| f.confidence >= 0.3)
        .collect();
    detected.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));

    log::info!("framework: detected {} frameworks", detected.len());
    for fw in &detected {
        log::info!("  {} ({}) — confidence {:.0}%{}", fw.name, fw.language, fw.confidence * 100.0,
            fw.version.as_deref().map(|v| format!(" v{v}")).unwrap_or_default());
    }

    detected
}

/// Try to extract a version string near a package name in a config file.
fn extract_version(content: &str, package: &str) -> Option<String> {
    let re = Regex::new(&format!(
        r#"(?i){}\S*[\s=:~^"']*(\d+\.\d+[\.\d]*)"#,
        regex::escape(package)
    )).ok()?;
    re.captures(content)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

// ── Repository Health Check ──────────────────────────────────────────────────

/// Repository health metrics — checks for security hygiene.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RepoHealth {
    pub score: u8, // 0-100
    pub checks: Vec<HealthCheck>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthCheck {
    pub name: &'static str,
    pub category: &'static str,
    pub passed: bool,
    pub detail: String,
    pub severity: &'static str,
}

/// Evaluate repository health — security hygiene, dependency age, CI config, etc.
pub fn check_repo_health(target: &Path) -> RepoHealth {
    let mut checks = Vec::new();

    // 1. License file exists
    checks.push(check_file_exists(target, &["LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE"], "License file", "governance", "low"));

    // 2. README exists
    checks.push(check_file_exists(target, &["README.md", "README.rst", "README.txt", "README"], "README file", "documentation", "info"));

    // 3. SECURITY.md (vulnerability disclosure policy)
    checks.push(check_file_exists(target, &["SECURITY.md", ".github/SECURITY.md"], "Security policy (SECURITY.md)", "governance", "medium"));

    // 4. .gitignore exists
    checks.push(check_file_exists(target, &[".gitignore"], ".gitignore file", "hygiene", "low"));

    // 5. CI/CD configuration
    let ci_files = [
        ".github/workflows", ".gitlab-ci.yml", "Jenkinsfile",
        ".circleci/config.yml", "azure-pipelines.yml", ".travis.yml",
    ];
    checks.push(check_file_exists(target, &ci_files, "CI/CD pipeline configuration", "automation", "medium"));

    // 6. Lockfile exists (dependencies pinned)
    let lockfiles = [
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        "Pipfile.lock", "poetry.lock", "Cargo.lock",
        "go.sum", "Gemfile.lock", "composer.lock",
    ];
    checks.push(check_file_exists(target, &lockfiles, "Dependency lockfile (pinned versions)", "supply-chain", "high"));

    // 7. No .env file committed
    let env_exists = target.join(".env").exists();
    checks.push(HealthCheck {
        name: "No .env file in repository",
        category: "secrets",
        passed: !env_exists,
        detail: if env_exists { ".env file found — may contain secrets".into() } else { "No .env file committed".into() },
        severity: "critical",
    });

    // 8. No hardcoded secrets in common config files
    let secret_patterns = ["password", "secret_key", "api_key", "access_key", "private_key"];
    let config_files = ["docker-compose.yml", "docker-compose.yaml", "app.yaml", "config.yaml"];
    let mut secrets_found = Vec::new();
    for cf in &config_files {
        let p = target.join(cf);
        if let Ok(content) = fs::read_to_string(&p) {
            let lower = content.to_lowercase();
            for sp in &secret_patterns {
                if lower.contains(sp) && (lower.contains("=") || lower.contains(":")) {
                    // Check it's not a reference to env var
                    if !lower.contains(&format!("${{{}}}", sp)) && !lower.contains("${") {
                        secrets_found.push(format!("{cf}: may contain {sp}"));
                    }
                }
            }
        }
    }
    checks.push(HealthCheck {
        name: "No hardcoded secrets in config files",
        category: "secrets",
        passed: secrets_found.is_empty(),
        detail: if secrets_found.is_empty() { "Config files clean".into() } else { secrets_found.join(", ") },
        severity: "critical",
    });

    // 9. CODEOWNERS file
    checks.push(check_file_exists(target, &["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"], "CODEOWNERS file", "governance", "low"));

    // 10. Dependabot or Renovate configured
    let depbot_files = [
        ".github/dependabot.yml", ".github/dependabot.yaml",
        "renovate.json", ".renovaterc", ".renovaterc.json",
    ];
    checks.push(check_file_exists(target, &depbot_files, "Automated dependency updates (Dependabot/Renovate)", "supply-chain", "medium"));

    // 11. Branch protection (check for .github/settings.yml or CONTRIBUTING.md)
    checks.push(check_file_exists(target, &["CONTRIBUTING.md", ".github/CONTRIBUTING.md"], "Contributing guidelines", "governance", "low"));

    // 12. Dockerfile uses non-root user
    let dockerfile = target.join("Dockerfile");
    if dockerfile.exists() {
        if let Ok(content) = fs::read_to_string(&dockerfile) {
            let has_user = content.lines().any(|l| l.trim_start().starts_with("USER ") && !l.contains("root"));
            checks.push(HealthCheck {
                name: "Dockerfile runs as non-root user",
                category: "container",
                passed: has_user,
                detail: if has_user { "Non-root USER directive found".into() } else { "No USER directive — container runs as root".into() },
                severity: "high",
            });
        }
    }

    // 13. No TODO/FIXME/HACK with security implications
    let mut security_todos = 0;
    let security_keywords = ["TODO.*security", "FIXME.*auth", "HACK.*password", "TODO.*encrypt", "FIXME.*ssl", "TODO.*sanitiz"];
    let re_patterns: Vec<regex::Regex> = security_keywords.iter()
        .filter_map(|p| regex::Regex::new(&format!("(?i){p}")).ok())
        .collect();

    for entry in walkdir::WalkDir::new(target).max_depth(4).into_iter()
        .filter_entry(|e| {
            let n = e.file_name().to_str().unwrap_or("");
            !n.starts_with('.') && n != "node_modules" && n != "target" && n != "vendor"
        })
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() { continue; }
        if let Ok(content) = fs::read_to_string(entry.path()) {
            for re in &re_patterns {
                security_todos += re.find_iter(&content).count();
            }
        }
        if security_todos > 0 { break; } // found at least one
    }
    checks.push(HealthCheck {
        name: "No security-related TODOs/FIXMEs",
        category: "hygiene",
        passed: security_todos == 0,
        detail: if security_todos == 0 { "No security TODOs found".into() } else { format!("{security_todos} security-related TODO/FIXME comments found") },
        severity: "medium",
    });

    // 14. Package.json has no wildcard versions
    let pkg_json = target.join("package.json");
    if pkg_json.exists() {
        if let Ok(content) = fs::read_to_string(&pkg_json) {
            let has_wildcard = content.contains("\"*\"") || content.contains("\"latest\"");
            checks.push(HealthCheck {
                name: "No wildcard dependency versions",
                category: "supply-chain",
                passed: !has_wildcard,
                detail: if has_wildcard { "Found '*' or 'latest' in dependencies".into() } else { "All dependencies have pinned versions".into() },
                severity: "high",
            });
        }
    }

    // Calculate score
    let total = checks.len() as f64;
    let passed = checks.iter().filter(|c| c.passed).count() as f64;
    let score = ((passed / total) * 100.0).round() as u8;

    log::info!("repo-health: score {}/100 — {}/{} checks passed", score, passed as u8, total as u8);

    RepoHealth { score, checks }
}

fn check_file_exists(target: &Path, candidates: &[&str], name: &'static str, category: &'static str, severity: &'static str) -> HealthCheck {
    let found = candidates.iter().any(|f| target.join(f).exists());
    HealthCheck {
        name,
        category,
        passed: found,
        detail: if found { "Found".into() } else { "Not found".into() },
        severity,
    }
}
