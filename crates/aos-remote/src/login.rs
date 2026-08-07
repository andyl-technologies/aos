//! The hub login exchange: a provisioning secret for a short-lived access JWT.
//!
//! Unlike the rest of [`crate::hub`], which speaks ConnectRPC, the registry
//! hub's login is a plain REST endpoint — `POST /oauth2/token` with the
//! provisioning secret as a `Bearer` credential, returning a JSON grant:
//!
//! ```text
//! POST /oauth2/token
//! Authorization: Bearer <provisioning-secret>
//! Content-Type: application/x-www-form-urlencoded
//!
//! grant_type=urn:aos:params:oauth:grant-type:provisioning-token
//!
//! 200 OK
//! { "access_token": "<jwt>", "token_type": "Bearer", "expires_in": 900 }
//! ```
//!
//! [`exchange_token`] performs that exchange so the `aos hub login` command can
//! turn a provisioning secret (minted by `apr`/the hub) into the access JWT the
//! token-gated `aos hub …` read commands take via `--token`.

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::client::validate_base_url;

/// Per-request timeout for the login exchange.
const LOGIN_TIMEOUT_SECS: u64 = 30;

/// A short-lived hub access grant returned by `POST /oauth2/token`.
///
/// The fields mirror the hub's `TokenResponse` JSON exactly.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenGrant {
    /// The minted HS256 access JWT to send as `Authorization: Bearer …`.
    pub access_token: String,
    /// The credential type; always `Bearer` for this endpoint.
    pub token_type: String,
    /// The grant's lifetime in seconds from issuance.
    pub expires_in: i64,
}

/// Exchanges a provisioning secret for a hub access JWT at `POST /oauth2/token`.
///
/// `base_url` is the hub root (`http(s)://…`); `provisioning_secret` is the
/// `aos_`-prefixed provisioning secret minted by the hub.
/// The secret is sent as a `Bearer` credential and never logged.
///
/// # Errors
///
/// Returns an error if `base_url` is not a valid `http(s)://` URL, the hub is
/// unreachable, the exchange is rejected (`401` invalid/missing secret, `429`
/// rate limited), or the response is not the expected JSON grant.
pub async fn exchange_token(base_url: &str, provisioning_secret: &str) -> Result<TokenGrant> {
    // Reuse the shared base-URL validation (http(s) scheme, parseable) so a
    // typo fails fast with the same message as the ConnectRPC clients.
    let base = validate_base_url(base_url)?;
    let url = format!("{}oauth2/token", ensure_trailing_slash(&base.to_string()));

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(LOGIN_TIMEOUT_SECS))
        .build()
        .context("building the login HTTP client")?;

    let response = client
        .post(&url)
        .bearer_auth(provisioning_secret)
        .form(&[(
            "grant_type",
            "urn:aos:params:oauth:grant-type:provisioning-token",
        )])
        .send()
        .await
        .with_context(|| format!("contacting the hub at {url}"))?;

    let status = response.status();
    if !status.is_success() {
        // The hub returns a short plain-text reason on failure; surface it
        // (the body never echoes the secret).
        let detail = response.text().await.unwrap_or_default();
        let detail = detail.trim();
        anyhow::bail!(
            "token exchange rejected ({status}){}",
            if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            }
        );
    }

    response
        .json::<TokenGrant>()
        .await
        .context("parsing the hub's token grant")
}

/// Returns `s` with a single trailing slash so `format!("{base}oauth2/token")`
/// joins cleanly whether or not the caller's URL already ended in `/`.
fn ensure_trailing_slash(s: &str) -> String {
    if s.ends_with('/') {
        s.to_string()
    } else {
        format!("{s}/")
    }
}
