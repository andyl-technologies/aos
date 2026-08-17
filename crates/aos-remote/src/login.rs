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
    /// Rotating opaque refresh credential, present for interactive login.
    pub refresh_token: Option<String>,
    /// Refresh credential's remaining idle lifetime in seconds.
    pub refresh_token_expires_in: Option<i64>,
}

/// Device-authorization details displayed while the user approves a CLI.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceAuthorization {
    /// Opaque secret the CLI polls with.
    pub device_code: String,
    /// Short code the user confirms in the browser.
    pub user_code: String,
    /// Browser URL for entering the user code.
    pub verification_uri: String,
    /// Browser URL with the user code already populated.
    pub verification_uri_complete: String,
    /// Remaining authorization-window lifetime in seconds.
    pub expires_in: i64,
    /// Minimum polling interval in seconds.
    pub interval: i64,
}

/// Non-terminal result of polling an RFC 8628 device grant.
#[derive(Debug, Clone)]
pub enum DeviceTokenPoll {
    /// The user has not completed approval yet.
    Pending,
    /// The server requires the client to increase its polling interval.
    SlowDown,
    /// The user approved and the server issued access and refresh credentials.
    Granted(TokenGrant),
}

#[derive(Debug, Deserialize)]
struct OAuthError {
    error: String,
    error_description: Option<String>,
}

const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const PROVISIONING_GRANT: &str = "urn:aos:params:oauth:grant-type:provisioning-token";

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
        .form(&[("grant_type", PROVISIONING_GRANT)])
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

/// Starts an interactive device authorization for the AOS CLI.
///
/// # Errors
///
/// Returns an error for an invalid Hub URL, transport failure, rejected scope
/// or permission set, or malformed authorization response.
pub async fn start_device_authorization(
    base_url: &str,
    scope: Option<&str>,
    permissions: &[&str],
) -> Result<DeviceAuthorization> {
    let base = validate_base_url(base_url)?;
    let url = format!(
        "{}oauth2/device_authorization",
        ensure_trailing_slash(&base.to_string())
    );
    let client = oauth_client()?;
    let permission = permissions.join(" ");
    let mut form = vec![("client_id", "aos-cli"), ("permission", &permission)];
    if let Some(scope) = scope {
        form.push(("scope", scope));
    }
    let response = client
        .post(&url)
        .form(&form)
        .send()
        .await
        .with_context(|| format!("contacting the hub at {url}"))?;
    require_success(response, "device authorization")
        .await?
        .json::<DeviceAuthorization>()
        .await
        .context("parsing the hub's device authorization")
}

/// Polls one device code at the server-provided cadence.
///
/// # Errors
///
/// Returns an error for an invalid Hub URL, transport failure, denied or
/// expired grant, unsupported response, or malformed token response.
pub async fn poll_device_token(base_url: &str, device_code: &str) -> Result<DeviceTokenPoll> {
    let base = validate_base_url(base_url)?;
    let url = format!("{}oauth2/token", ensure_trailing_slash(&base.to_string()));
    let response = oauth_client()?
        .post(&url)
        .form(&[
            ("grant_type", DEVICE_GRANT),
            ("client_id", "aos-cli"),
            ("device_code", device_code),
        ])
        .send()
        .await
        .with_context(|| format!("polling the hub at {url}"))?;
    if response.status().is_success() {
        return response
            .json::<TokenGrant>()
            .await
            .map(DeviceTokenPoll::Granted)
            .context("parsing the hub's device token grant");
    }
    let status = response.status();
    let error = response
        .json::<OAuthError>()
        .await
        .context("parsing the hub's device-token error")?;
    match error.error.as_str() {
        "authorization_pending" => Ok(DeviceTokenPoll::Pending),
        "slow_down" => Ok(DeviceTokenPoll::SlowDown),
        "access_denied" => anyhow::bail!("device authorization was denied"),
        "expired_token" => anyhow::bail!("device authorization expired"),
        _ => anyhow::bail!(
            "device token exchange rejected ({status}): {}{}",
            error.error,
            error
                .error_description
                .as_deref()
                .map(|description| format!(": {description}"))
                .unwrap_or_default()
        ),
    }
}

/// Rotates a refresh credential and returns the next credential pair.
///
/// # Errors
///
/// Returns an error for an invalid Hub URL, transport failure, invalid or
/// replayed refresh credential, or malformed token response.
pub async fn refresh_token(base_url: &str, refresh_token: &str) -> Result<TokenGrant> {
    let base = validate_base_url(base_url)?;
    let url = format!("{}oauth2/token", ensure_trailing_slash(&base.to_string()));
    let response = oauth_client()?
        .post(&url)
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", "aos-cli"),
            ("refresh_token", refresh_token),
        ])
        .send()
        .await
        .with_context(|| format!("refreshing credentials at {url}"))?;
    require_success(response, "token refresh")
        .await?
        .json::<TokenGrant>()
        .await
        .context("parsing the hub's refreshed token grant")
}

/// Revokes the refresh-token family containing `refresh_token`.
///
/// # Errors
///
/// Returns an error for an invalid Hub URL, transport failure, or a rejected
/// revocation request.
pub async fn revoke_refresh_token(base_url: &str, refresh_token: &str) -> Result<()> {
    let base = validate_base_url(base_url)?;
    let url = format!("{}oauth2/revoke", ensure_trailing_slash(&base.to_string()));
    let response = oauth_client()?
        .post(&url)
        .form(&[
            ("client_id", "aos-cli"),
            ("token_type_hint", "refresh_token"),
            ("token", refresh_token),
        ])
        .send()
        .await
        .with_context(|| format!("revoking credentials at {url}"))?;
    require_success(response, "token revocation").await?;
    Ok(())
}

fn oauth_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(LOGIN_TIMEOUT_SECS))
        .build()
        .context("building the login HTTP client")
}

async fn require_success(
    response: reqwest::Response,
    operation: &str,
) -> Result<reqwest::Response> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let detail = response.text().await.unwrap_or_default();
    let detail = detail.trim();
    anyhow::bail!(
        "{operation} rejected ({status}){}",
        if detail.is_empty() {
            String::new()
        } else {
            format!(": {detail}")
        }
    )
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
