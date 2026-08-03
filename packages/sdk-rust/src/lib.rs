//! Defenso — fail-open WAF for Rust web services (axum, actix, warp, hyper).
//!
//! Design (mirrors the Node / PHP / Python / Go / Ruby / .NET SDKs):
//! - **Fails open.** If Defenso is unreachable or slow, the request is allowed.
//! - **Policy is cached.** Rules are pulled on a background thread and evaluated
//!   locally; the request path never blocks on a network call.
//! - **Logs are fire-and-forget.**
//!
//! This crate exposes a framework-agnostic [`Guard`]: build it once, then call
//! [`Guard::inspect`] per request. Framework adapters (axum layer, actix
//! middleware) wrap this core.

use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use regex::Regex;
use serde::Deserialize;

#[derive(Clone)]
pub struct Config {
    pub token: String,
    pub api_url: String,
    pub policy_refresh: Duration,
    pub timeout: Duration,
}

impl Config {
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
            api_url: "https://app.defen.so/api".to_string(),
            policy_refresh: Duration::from_secs(300),
            timeout: Duration::from_secs(1),
        }
    }
}

struct CompiledRule {
    id: String,
    action: String,
    target: String,
    category: String,
    re: Regex,
}

#[derive(Deserialize)]
struct RuleDto {
    id: String,
    pattern: String,
    #[serde(default)]
    flags: String,
    #[serde(default)]
    target: String,
    #[serde(default)]
    action: String,
    #[serde(default)]
    category: String,
}

#[derive(Deserialize)]
struct PolicyDto {
    #[serde(default)]
    rules: Vec<RuleDto>,
}

/// A blocked verdict. `None` from [`Guard::inspect`] means "allow".
pub struct Verdict {
    pub rule_id: String,
    pub category: String,
}

pub struct Guard {
    cfg: Config,
    rules: Arc<RwLock<Vec<CompiledRule>>>,
    queue: Arc<Mutex<Vec<serde_json::Value>>>,
}

impl Guard {
    /// Build a guard and start the background policy refresh. Never blocks.
    pub fn new(cfg: Config) -> Arc<Self> {
        let guard = Arc::new(Self {
            cfg,
            rules: Arc::new(RwLock::new(Vec::new())),
            queue: Arc::new(Mutex::new(Vec::new())),
        });
        if !guard.cfg.token.is_empty() {
            let g = guard.clone();
            std::thread::spawn(move || loop {
                g.refresh_once();
                std::thread::sleep(g.cfg.policy_refresh);
            });
        }
        guard
    }

    fn refresh_once(&self) {
        // Fail open on any error — keep last-known-good rules.
        let url = format!("{}/policy", self.cfg.api_url.trim_end_matches('/'));
        let resp = match ureq::get(&url)
            .set("Authorization", &format!("Bearer {}", self.cfg.token))
            .set("Accept", "application/json")
            .timeout(self.cfg.timeout)
            .call()
        {
            Ok(r) => r,
            Err(_) => return,
        };
        let dto: PolicyDto = match resp.into_json() {
            Ok(d) => d,
            Err(_) => return,
        };
        let compiled: Vec<CompiledRule> = dto
            .rules
            .into_iter()
            .filter_map(|r| {
                let pat = if r.flags.contains('i') {
                    format!("(?i){}", r.pattern)
                } else {
                    r.pattern
                };
                Regex::new(&pat).ok().map(|re| CompiledRule {
                    id: r.id,
                    action: if r.action.is_empty() { "block".into() } else { r.action },
                    target: if r.target.is_empty() { "query".into() } else { r.target },
                    category: r.category,
                    re,
                })
            })
            .collect();
        if let Ok(mut w) = self.rules.write() {
            *w = compiled;
        }
    }

    /// Inspect a request. Returns `Some(Verdict)` when it must be blocked.
    /// Pass the request path, raw query string, and a flattened header string.
    pub fn inspect(&self, path: &str, query: &str, headers: &str) -> Option<Verdict> {
        let rules = self.rules.read().ok()?;
        for rule in rules.iter() {
            let hay = match rule.target.as_str() {
                "url" => path,
                "headers" => headers,
                "query" | "" => query,
                // Body inspection is not done in-process; skip rather than
                // mis-match a body-target rule against the query string.
                _ => continue,
            };
            if !hay.is_empty() && rule.re.is_match(hay) && rule.action == "block" {
                self.queue_log(&rule.id, &rule.category, path, query);
                return Some(Verdict {
                    rule_id: rule.id.clone(),
                    category: rule.category.clone(),
                });
            }
        }
        None
    }

    fn queue_log(&self, rule_id: &str, category: &str, path: &str, query: &str) {
        let entry = serde_json::json!({
            "at": now_unix(),
            "verdict": { "action": "block", "rule": { "id": rule_id }, "reason": category },
            "request": { "method": "", "url": format!("{}?{}", path, query), "ip": "" },
        });
        let mut batch: Option<Vec<serde_json::Value>> = None;
        if let Ok(mut q) = self.queue.lock() {
            q.push(entry);
            if q.len() >= 25 {
                batch = Some(std::mem::take(&mut *q));
            }
        }
        if let Some(b) = batch {
            let url = format!("{}/attacks/ingest", self.cfg.api_url.trim_end_matches('/'));
            let token = self.cfg.token.clone();
            let timeout = self.cfg.timeout;
            std::thread::spawn(move || {
                let _ = ureq::post(&url)
                    .set("Authorization", &format!("Bearer {}", token))
                    .set("Content-Type", "application/json")
                    .timeout(timeout)
                    .send_json(serde_json::json!({ "logs": b }));
            });
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
