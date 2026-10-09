//! Portable authentication grants and identity-provider configuration.

/// An org's OIDC identity-provider configuration (system-of-record row).
///
/// Mirrors the `org_idp_configs` row one-to-one. The client secret is held
/// **sealed** in [`IdpConfigRecord::client_secret_enc`]; unseal it through a
/// [`crate::auth::seal::SecretSealer`] only at the moment of the token
/// exchange, never store or log the plaintext.
#[derive(Debug, Clone)]
pub struct IdpConfigRecord {
    /// Owning org id (the table's primary key — one IdP per org).
    pub org_id: i64,
    /// The IdP's issuer identifier; the `iss` claim every id_token must carry.
    pub issuer: String,
    /// The OAuth2 authorization endpoint the browser is redirected to.
    pub authorization_endpoint: String,
    /// The OAuth2 token endpoint the authorization code is exchanged at.
    pub token_endpoint: String,
    /// The JWKS endpoint whose keys verify the id_token signature.
    pub jwks_uri: String,
    /// The client id registered with the IdP for this hub.
    pub client_id: String,
    /// The sealed client secret, or `None` for a public client.
    ///
    /// Sealed by a [`crate::auth::seal::SecretSealer`]; never the plaintext.
    pub client_secret_enc: Option<String>,
    /// The space-separated scope string requested at authorization.
    pub scopes: String,
    /// The id_token claim carrying the user's groups, or `None` to skip
    /// group→role mapping.
    pub groups_claim: Option<String>,
    /// The `group -> role` mapping as a JSON object string, applied on every
    /// SSO login.
    pub role_map_json: String,
    /// Whether an unknown `(iss, sub)` may be just-in-time provisioned.
    pub allow_jit: bool,
    /// Whether members of the org are forced through SSO (email-first login
    /// on a captured domain redirects to the IdP rather than offering magic
    /// links).
    pub enforce_sso: bool,
    /// The role a JIT-provisioned user receives at the org scope when no
    /// group mapping applies.
    pub default_role: String,
    /// Optimistic-concurrency version for retained-control mutations.
    pub resource_version: i64,
    /// Immutable incarnation that changes when a deleted resource is recreated.
    pub incarnation_id: Option<String>,
    /// Reviewed plan that produced the current state, when any.
    pub mutation_plan_id: Option<String>,
}

/// A validated provisioning token: who owns it and what it may do.
///
/// Produced by [`Database::validate_token`] after a secret checks out
/// (hash matches, not expired, not hard-revoked, and — if rotated — still
/// inside the rotation grace window). The `scope`/`permissions` here are
/// the token's *own* grants. The RPC plane additionally intersects them
/// with the owner's current memberships at decision time
/// (the database grant resolver); the machine plane authorizes from
/// these grants alone, bounded by the JWT TTL (see `auth::extract`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TokenAuth {
    /// The token's id (UUID); the JWT `sub` and the revoke/rotate key.
    pub token_id: String,
    /// The principal that owns the token.
    pub owner: crate::domain::Principal,
    /// The immutable authorization scope the token is bound to.
    pub scope: crate::domain::Scope,
    /// The permission verbs the token grants.
    pub permissions: Vec<crate::domain::Permission>,
}

use crate::domain::Role;
use anyhow::{Context as _, Result};
use std::collections::BTreeMap;

const MAX_URL_BYTES: usize = 2048;
const MAX_CLIENT_ID_BYTES: usize = 255;
const MAX_SCOPES_BYTES: usize = 1024;
const MAX_SCOPE_COUNT: usize = 32;
const MAX_CLAIM_NAME_BYTES: usize = 128;
const MAX_ROLE_MAP_BYTES: usize = 16 * 1024;
const MAX_ROLE_MAP_ENTRIES: usize = 64;
const MAX_GROUP_BYTES: usize = 256;

/// Validates the complete persisted OIDC configuration contract.
///
/// This is the shared admission boundary used by the reviewed service mutation
/// and by test-fixture seeding, so native and Worker runtimes enforce the same
/// persisted contract.
///
/// # Errors
///
/// Returns an error for unsafe/non-canonical URLs, oversized or malformed
/// fields, missing `openid`, unknown roles, or an invalid role-map shape.
pub fn validate_idp_config_record(record: &IdpConfigRecord) -> Result<()> {
    for (label, raw) in [
        ("issuer", record.issuer.as_str()),
        (
            "authorization endpoint",
            record.authorization_endpoint.as_str(),
        ),
        ("token endpoint", record.token_endpoint.as_str()),
        ("JWKS URI", record.jwks_uri.as_str()),
    ] {
        anyhow::ensure!(
            !raw.is_empty() && raw.len() <= MAX_URL_BYTES,
            "{label} length is invalid"
        );
        let url = url::Url::parse(raw).with_context(|| format!("{label} is not a valid URL"))?;
        let debug_loopback_http = cfg!(debug_assertions)
            && url.scheme() == "http"
            && matches!(
                std::env::var("AOS_HUB_ALLOW_LOCAL_REMOTES").as_deref(),
                Ok("1" | "true" | "yes")
            )
            && url
                .host_str()
                .is_some_and(|host| matches!(host, "127.0.0.1" | "::1" | "localhost"));
        anyhow::ensure!(
            url.scheme() == "https" || debug_loopback_http,
            "{label} must use https"
        );
        anyhow::ensure!(
            url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none()
                && url.query().is_none(),
            "{label} cannot contain credentials, query, or fragment"
        );
        anyhow::ensure!(url.host_str().is_some(), "{label} must have a host");
        crate::url_guard::is_safe_remote_url(raw).with_context(|| format!("unsafe {label}"))?;
    }
    anyhow::ensure!(
        !record.client_id.is_empty() && record.client_id.len() <= MAX_CLIENT_ID_BYTES,
        "OIDC client id length is invalid"
    );
    anyhow::ensure!(
        !record.client_id.chars().any(char::is_control),
        "OIDC client id contains a control character"
    );
    anyhow::ensure!(
        record.scopes.len() <= MAX_SCOPES_BYTES,
        "OIDC scopes are too long"
    );
    let scopes = record.scopes.split_ascii_whitespace().collect::<Vec<_>>();
    anyhow::ensure!(
        !scopes.is_empty()
            && scopes.len() <= MAX_SCOPE_COUNT
            && scopes
                .iter()
                .all(|scope| !scope.is_empty() && scope.len() <= 64)
            && scopes.iter().filter(|scope| **scope == "openid").count() == 1,
        "OIDC scopes must contain one openid scope and at most {MAX_SCOPE_COUNT} bounded tokens"
    );
    if let Some(name) = record.groups_claim.as_deref() {
        anyhow::ensure!(
            !name.is_empty()
                && name.len() <= MAX_CLAIM_NAME_BYTES
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')),
            "OIDC groups claim name is invalid"
        );
    }
    anyhow::ensure!(
        record.role_map_json.len() <= MAX_ROLE_MAP_BYTES,
        "OIDC role map is too large"
    );
    let role_map: BTreeMap<String, String> =
        serde_json::from_str(&record.role_map_json).context("OIDC role map must be an object")?;
    anyhow::ensure!(
        role_map.len() <= MAX_ROLE_MAP_ENTRIES,
        "OIDC role map has too many entries"
    );
    for (group, role) in &role_map {
        anyhow::ensure!(
            !group.is_empty()
                && group.len() <= MAX_GROUP_BYTES
                && !group.chars().any(char::is_control),
            "OIDC role-map group is invalid"
        );
        anyhow::ensure!(
            Role::parse(role).is_some(),
            "OIDC role map contains an unknown role"
        );
    }
    anyhow::ensure!(
        Role::parse(&record.default_role).is_some(),
        "OIDC default role is invalid"
    );
    if let Some(sealed) = record.client_secret_enc.as_deref() {
        anyhow::ensure!(
            !sealed.is_empty() && sealed.len() <= 32 * 1024,
            "sealed OIDC client secret length is invalid"
        );
    }
    Ok(())
}
