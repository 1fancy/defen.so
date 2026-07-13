//! Defenso — fail-open security Tower layer for axum, warp, actix.
//!
//! Alpha scaffold. Full impl: policy fetch + local eval + background attack ingest.

pub struct DefensoLayer {
    token: String,
}

impl DefensoLayer {
    pub fn new(token: impl Into<String>) -> Self {
        Self { token: token.into() }
    }

    pub fn token(&self) -> &str {
        &self.token
    }
}
