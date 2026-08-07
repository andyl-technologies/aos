//! Per-org OIDC single sign-on: the authorization-code + PKCE flow.
//!
//! This module implements RFC-0004's "Per-org OIDC SSO": each org may
//! configure one OpenID Connect identity provider; an email-first login on a
//! captured domain routes to that IdP, and a successful round-trip provisions
//! or links a hub user keyed on `(issuer, subject)` — never bare email.
//!
//! # Runtime-neutral by construction (RFC-0004 Phase 5, console-dedup stage F)
//!
//! The flow makes only two network calls — the token exchange and the JWKS
//! fetch — and it makes both through the
//! [`HttpClient`](crate::web::console::ports::HttpClient) port rather than a
//! concrete client, so it is transport- and runtime-neutral: the native hub
//! satisfies the port with its hardened [`reqwest`] client (SSRF resolver,
//! request timeout, body cap), and the Cloudflare Worker satisfies it through
//! the fixed authenticated egress gateway. The port already performs the
//! error-for-status check and the response body cap, so this module never sees
//! a streaming response.
//!
//! Crypto is dependency-light and **fully pure-Rust**: [`sha2`] for the PKCE
//! S256 challenge, [`rand`] for the high-entropy `state`/`nonce`/`code_verifier`,
//! [`base64`] for base64url, and `jwt-rustcrypto` for RS256 id_token
//! verification. `jwt-rustcrypto` builds the RSA verifying key straight from a
//! JWK's `(n, e)` components (`VerifyingKey::from_rsa_components`) and validates
//! the token, all over the RustCrypto `rsa` crate — the same `rsa` this crate
//! already uses for WebAuthn, with no `ring` and no C. Only RS256 is supported,
//! which covers the overwhelming majority of IdPs (Okta, Entra, Auth0, Keycloak,
//! Google, Dex). Being pure-Rust, the verifier compiles to
//! `wasm32-unknown-unknown` with no C toolchain, so it is the identical code path
//! on the native hub and the Cloudflare Worker.
//!
//! # The flow
//!
//! ```text
//! begin_login(org).await                         complete_login(code, state).await
//! ─────────────────                        ───────────────────────────
//! 1. load org IdP config                   1. take_oidc_flow(state).await  ← single-use
//! 2. verifier = random 43..128 chars          (validates + consumes; expiry)
//!    challenge = b64url(sha256(verifier))   2. POST token_endpoint:
//!    state, nonce = random                       grant_type=authorization_code
//! 3. create_oidc_flow(state, nonce,             code, redirect_uri, client_id,
//!                     verifier).await                  client_secret (unsealed),
//! 4. redirect to authorization_endpoint?         code_verifier   ← PKCE proof
//!      response_type=code                    3. fetch JWKS, find kid
//!      client_id, redirect_uri, scope        4. verify id_token (RS256):
//!      state, nonce                              iss == config.issuer
//!      code_challenge=b64url(sha256(v))          aud == client_id, exp
//!      code_challenge_method=S256                nonce == flow.nonce
//!                                            5. extract sub, email[_verified],
//!         user───approves at IdP───►            groups
//!         IdP redirects to                   6. link_or_create_identity(iss,sub).await
//!         /auth/oidc/callback?code=&state=   7. map groups → roles, grant
//! ```
//!
//! # Configuration
//!
//! An [`IdpConfig`] mirrors the `org_idp_configs` row (see [`crate::db`]). The
//! client secret is held **sealed**; it is unsealed through a [`SecretSealer`]
//! only at the token exchange. Production seals with
//! [`AesGcmSealer`](crate::auth::seal::AesGcmSealer) (AES-256-GCM, keyed by the
//! persisted instance key); [`XorSealer`] is a deliberately **placeholder**
//! sealer (see its docs) used only under `--dev` and in tests.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use rand::Rng;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::auth::seal::SecretSealer;
use crate::db::{Database, IdpConfigRecord};
use crate::domain::{Principal, Role, Scope};
use crate::web::console::ports::HttpClient;

/// Lifetime of an in-flight OIDC authorization-code request (10 minutes).
///
/// A callback whose `state` flow is older than this is rejected, bounding the
/// window in which a leaked authorization URL can be replayed.
pub const FLOW_TTL_SECS: i64 = 10 * 60;

/// Maximum number of keys accepted from a JWKS document.
///
/// A legitimate JWKS holds a handful of signing keys (typically one or two,
/// plus a rotated predecessor). A document advertising thousands of keys — or
/// keys with absurd RSA moduli — is a verification-DoS vector, so the key set
/// is rejected past this bound before any RSA verifying key is built.
const MAX_JWKS_KEYS: usize = 32;
const MAX_URL_BYTES: usize = 2048;
const MAX_CLIENT_ID_BYTES: usize = 255;
const MAX_SCOPES_BYTES: usize = 1024;
const MAX_SCOPE_COUNT: usize = 32;
const MAX_CLAIM_NAME_BYTES: usize = 128;
const MAX_ROLE_MAP_BYTES: usize = 16 * 1024;
const MAX_ROLE_MAP_ENTRIES: usize = 64;
const MAX_GROUP_BYTES: usize = 256;
const MAX_CALLBACK_CODE_BYTES: usize = 8 * 1024;
const MAX_ID_TOKEN_BYTES: usize = 96 * 1024;
const MAX_JWT_HEADER_BYTES: usize = 8 * 1024;
const MAX_JWT_PAYLOAD_BYTES: usize = 64 * 1024;
const MAX_JWT_SIGNATURE_BYTES: usize = 2 * 1024;
const MAX_JWKS_BYTES: usize = 1024 * 1024;
const MIN_RSA_MODULUS_BYTES: usize = 256;
const MAX_RSA_MODULUS_BYTES: usize = 1024;

/// An org's OIDC identity-provider configuration, with the client secret in
/// whatever (possibly sealed) form the caller holds.
///
/// This mirrors [`IdpConfigRecord`] but is the *typed* form the flow operates
/// on: `role_map` is parsed from the row's JSON, and `client_secret_enc`
/// carries the **sealed** secret (unsealed only at the token exchange).
#[derive(Debug, Clone)]
pub struct IdpConfig {
    /// Owning org id.
    pub org_id: i64,
    /// The IdP issuer; the `iss` every id_token must carry.
    pub issuer: String,
    /// The authorization endpoint the browser is redirected to.
    pub authorization_endpoint: String,
    /// The token endpoint the authorization code is exchanged at.
    pub token_endpoint: String,
    /// The JWKS endpoint whose keys verify the id_token.
    pub jwks_uri: String,
    /// The client id registered with the IdP.
    pub client_id: String,
    /// The **sealed** client secret, or `None` for a public client.
    pub client_secret_enc: Option<String>,
    /// The space-separated scope string requested at authorization.
    pub scopes: String,
    /// The id_token claim carrying the user's groups, or `None`.
    pub groups_claim: Option<String>,
    /// The parsed `group -> role` mapping applied on every login.
    pub role_map: BTreeMap<String, Role>,
    /// Whether an unknown `(iss, sub)` may be JIT-provisioned.
    pub allow_jit: bool,
    /// Whether the org forces members through SSO.
    pub enforce_sso: bool,
    /// The role a JIT user receives at the org scope when no group maps.
    pub default_role: Role,
}

impl IdpConfig {
    /// Builds the typed config from a stored row.
    ///
    /// Parses `role_map_json` (a `{"group":"role"}` object) and `default_role`
    /// into domain [`Role`]s; an unknown role name in either is skipped (the
    /// mapping) or falls back to [`Role::Viewer`] (the default).
    #[must_use]
    pub fn from_record(record: IdpConfigRecord) -> IdpConfig {
        let role_map = parse_role_map(&record.role_map_json);
        let default_role = Role::parse(&record.default_role).unwrap_or(Role::Viewer);
        IdpConfig {
            org_id: record.org_id,
            issuer: record.issuer,
            authorization_endpoint: record.authorization_endpoint,
            token_endpoint: record.token_endpoint,
            jwks_uri: record.jwks_uri,
            client_id: record.client_id,
            client_secret_enc: record.client_secret_enc,
            scopes: record.scopes,
            groups_claim: record.groups_claim,
            role_map,
            allow_jit: record.allow_jit,
            enforce_sso: record.enforce_sso,
            default_role,
        }
    }
}

/// Validates the complete persisted OIDC configuration contract.
///
/// This is the single admission boundary used by API, CLI, Web, native, and
/// Worker paths because every writer reaches [`Database::upsert_idp_config`].
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

/// Parse a `{"group": "role"}` JSON object into a role map, skipping unknown
/// roles.
fn parse_role_map(json: &str) -> BTreeMap<String, Role> {
    let raw: BTreeMap<String, String> = serde_json::from_str(json).unwrap_or_default();
    raw.into_iter()
        .filter_map(|(group, role)| Role::parse(&role).map(|r| (group, r)))
        .collect()
}

/// A redirect to the IdP's authorization endpoint.
#[derive(Debug, Clone)]
pub struct AuthRedirect {
    /// The fully-formed authorization URL to redirect the browser to.
    pub url: String,
}

/// The result of a completed login: the resolved hub user and email.
#[derive(Debug, Clone)]
pub struct OidcLogin {
    /// The resolved (linked or provisioned) hub user id.
    pub user_id: i64,
    /// The user's email as asserted by the IdP, if any.
    pub email: Option<String>,
    /// Whether a brand-new user was provisioned (vs. linked/existing).
    pub provisioned: bool,
    /// Where to redirect the browser after the session is set, from the
    /// staged flow (`None` for the instance home).
    pub redirect_after: Option<String>,
}

/// Generates a PKCE code verifier: 43 high-entropy base64url characters.
///
/// RFC 7636 permits 43–128 characters from the unreserved set; 32 random bytes
/// base64url-encoded yields 43, comfortably inside the range.
#[must_use]
pub fn new_code_verifier() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Computes the PKCE S256 code challenge for a verifier.
///
/// `base64url(sha256(verifier))`, per RFC 7636. This is the value sent as
/// `code_challenge` with `code_challenge_method=S256`.
#[must_use]
pub fn code_challenge_s256(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// Generates a fresh opaque token (256 bits, base64url) for `state`/`nonce`.
#[must_use]
fn new_opaque() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The redirect URI the IdP returns to, derived from the hub's external URL.
#[must_use]
pub fn redirect_uri(external_url: &str) -> String {
    format!("{}/auth/oidc/callback", external_url.trim_end_matches('/'))
}

/// Begin an OIDC login: stage the flow and build the authorization redirect.
///
/// Loads the org's IdP config, generates the PKCE verifier/challenge and the
/// `state`/`nonce`, records the flow via
/// [`Database::create_oidc_flow`], and returns the authorization-endpoint URL
/// to redirect the browser to. `redirect_after` is where the browser lands
/// after a successful callback (defaulting to the instance home).
///
/// # Errors
///
/// Returns an error when the org has no IdP configured, when persisting the
/// flow fails, or on database failure.
pub async fn begin_login(
    db: &Database,
    external_url: &str,
    org_id: i64,
    redirect_after: Option<&str>,
) -> Result<AuthRedirect> {
    let record = db
        .idp_config(org_id)
        .await?
        .with_context(|| format!("org {org_id} has no OIDC identity provider configured"))?;
    validate_idp_config_record(&record)?;
    let config = IdpConfig::from_record(record);

    let verifier = new_code_verifier();
    let challenge = code_challenge_s256(&verifier);
    let state = new_opaque();
    let nonce = new_opaque();

    db.create_oidc_flow(
        &state,
        org_id,
        &nonce,
        &verifier,
        redirect_after,
        FLOW_TTL_SECS,
    )
    .await?;

    let mut url = url::Url::parse(&config.authorization_endpoint)
        .context("IdP authorization_endpoint is not a valid URL")?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &config.client_id)
        .append_pair("redirect_uri", &redirect_uri(external_url))
        .append_pair("scope", &config.scopes)
        .append_pair("state", &state)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");

    Ok(AuthRedirect {
        url: url.to_string(),
    })
}

/// The callback parameters the IdP returns.
#[derive(Debug, Clone, Deserialize)]
pub struct CallbackParams {
    /// The authorization code to exchange at the token endpoint.
    pub code: String,
    /// The opaque CSRF `state` echoed back; identifies the staged flow.
    pub state: String,
}

fn validate_callback_params(params: &CallbackParams) -> Result<()> {
    anyhow::ensure!(
        !params.code.is_empty()
            && params.code.len() <= MAX_CALLBACK_CODE_BYTES
            && !params.code.chars().any(char::is_control),
        "OIDC authorization code is empty, oversized, or contains controls"
    );
    let state = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&params.state)
        .context("OIDC state is not canonical base64url")?;
    anyhow::ensure!(
        state.len() == 32
            && base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&state) == params.state,
        "OIDC state is not a canonical 256-bit value"
    );
    Ok(())
}

/// The token-endpoint response (only the id_token is required).
#[derive(Debug, Deserialize)]
struct TokenResponse {
    id_token: String,
    #[serde(default)]
    #[allow(dead_code)]
    access_token: Option<String>,
}

/// One JWK from the IdP's JWKS document (RSA keys only).
#[derive(Debug, Deserialize)]
struct Jwk {
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    kty: String,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

/// The IdP's JWKS document.
#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

/// The id_token claims the hub reads.
#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    sub: String,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<bool>,
    /// Captured so an arbitrary `groups_claim` name can be resolved.
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}

/// Complete an OIDC login: consume the flow, exchange the code, verify the
/// id_token, and link/provision the user.
///
/// Steps, fail-closed at every network and parse boundary:
///
/// 1. [`Database::take_oidc_flow`] consumes the `state` (single-use; expiry
///    enforced) — a forged or replayed `state` is rejected here.
/// 2. POST the token endpoint with the code, PKCE `code_verifier`, and the
///    **unsealed** client secret; read the `id_token`. The HTTP call goes
///    through the [`HttpClient`] port, which applies the deployment's body cap
///    and error-for-status check.
/// 3. Fetch the JWKS, find the signing key by `kid`, and verify the id_token
///    with RS256, checking `iss == config.issuer`, `aud == client_id`, and
///    `exp`.
/// 4. Check `nonce == flow.nonce` (replay defense).
/// 5. Extract `sub`, `email`/`email_verified`, and the configured groups
///    claim; reconcile the user via [`Database::link_or_create_identity`]
///    (keyed on `(iss, sub)`), then map groups → roles and grant the
///    memberships at the org scope.
///
/// # Errors
///
/// Returns an error when the flow is unknown/expired, the token exchange or
/// JWKS fetch fails, the id_token fails verification (signature, `iss`, `aud`,
/// `exp`, or `nonce`), or — when `allow_jit` is false and the `(iss, sub)`
/// identity is unknown — the login is not permitted.
pub async fn complete_login(
    db: &Database,
    sealer: &dyn SecretSealer,
    http: &dyn HttpClient,
    external_url: &str,
    params: &CallbackParams,
) -> Result<OidcLogin> {
    validate_callback_params(params)?;
    // 1. Consume the flow (single-use, expiry-checked).
    let flow = db
        .take_oidc_flow(&params.state)
        .await?
        .ok_or_else(|| anyhow!("unknown, expired, or replayed login state"))?;

    let record = db
        .idp_config(flow.org_id)
        .await?
        .with_context(|| format!("org {} has no OIDC identity provider", flow.org_id))?;
    validate_idp_config_record(&record)?;
    let config = IdpConfig::from_record(record);

    // 2. Exchange the authorization code (with PKCE proof) for tokens. The
    // `HttpClient` port already enforces the body cap and the error-for-status
    // check, so we only build the form and decode the returned bytes.
    let mut form = vec![
        ("grant_type".to_string(), "authorization_code".to_string()),
        ("code".to_string(), params.code.clone()),
        ("redirect_uri".to_string(), redirect_uri(external_url)),
        ("client_id".to_string(), config.client_id.clone()),
        ("code_verifier".to_string(), flow.code_verifier.clone()),
    ];
    if let Some(sealed) = &config.client_secret_enc {
        let secret = sealer
            .unseal(sealed)
            .context("unsealing OIDC client secret")?;
        anyhow::ensure!(secret.len() <= 16 * 1024, "OIDC client secret is too large");
        form.push(("client_secret".to_string(), secret));
    }
    let form_bytes = form
        .iter()
        .try_fold(0usize, |total, (key, value)| {
            total
                .checked_add(key.len())
                .and_then(|total| total.checked_add(value.len()))
        })
        .context("OIDC token form length overflow")?;
    anyhow::ensure!(
        form.len() <= 8 && form_bytes <= 64 * 1024,
        "OIDC token form is too large"
    );
    let token_bytes = http
        .post_form(&config.token_endpoint, &form)
        .await
        .context("OIDC token request failed")?;
    anyhow::ensure!(
        token_bytes.len() <= MAX_ID_TOKEN_BYTES + 16 * 1024,
        "OIDC token response is too large"
    );
    let token: TokenResponse =
        serde_json::from_slice(&token_bytes).context("decoding OIDC token response")?;
    anyhow::ensure!(
        !token.id_token.is_empty() && token.id_token.len() <= MAX_ID_TOKEN_BYTES,
        "OIDC id_token length is invalid"
    );
    let _ = &token.access_token; // reserved for at_hash / userinfo later

    // 3/4. Verify the id_token against the JWKS and the flow's nonce.
    let claims = verify_id_token(http, &config, &token.id_token, &flow.nonce).await?;

    // 5. Reconcile the user, keyed on (iss, sub).
    let email = claims.email.clone();
    let email_verified = claims.email_verified.unwrap_or(false);
    let link = db
        .link_or_create_identity(
            &config.issuer,
            &claims.sub,
            email.as_deref(),
            email_verified,
            config.org_id,
            config.allow_jit,
        )
        .await?
        .ok_or_else(|| {
            anyhow!("just-in-time provisioning is disabled and this identity is unknown")
        })?;
    let user_id = link.user_id();

    // Map groups → roles and grant memberships at the org scope. Re-evaluated
    // on every login; full deprovisioning/sync (revoking SSO-granted roles no
    // longer mapped) is a later phase — here we ensure the mapped roles are
    // granted, plus the default role so a JIT user is never left with nothing.
    grant_mapped_roles(db, &config, &claims).await?;

    Ok(OidcLogin {
        user_id,
        email,
        provisioned: matches!(link, crate::db::IdentityLink::Created(_)),
        redirect_after: flow.redirect_after.clone(),
    })
}

/// Verify an id_token: RS256 signature via JWKS, plus iss/aud/exp/nonce.
///
/// Fetches the JWKS (through the [`HttpClient`] port), selects the RSA key by
/// `kid` (or the sole RSA key when the header carries no `kid`), builds a
/// `jwt_rustcrypto::VerifyingKey` from the JWK's `(n, e)`, and decodes with the
/// accepted-algorithm set pinned to `RS256` (rejecting `alg` confusion),
/// validating `aud` and `exp`. `iss` is checked against `config.issuer`, and
/// `nonce` against the flow's nonce.
///
/// # Errors
///
/// Returns an error on JWKS fetch failure, a missing/non-RSA key, signature or
/// claim validation failure, an `iss` mismatch, or a `nonce` mismatch.
async fn verify_id_token(
    http: &dyn HttpClient,
    config: &IdpConfig,
    id_token: &str,
    expected_nonce: &str,
) -> Result<IdTokenClaims> {
    use jwt_rustcrypto::{decode, decode_only, Algorithm, ValidationOptions, VerifyingKey};

    validate_jwt_components(id_token)?;

    // Parse the header (unverified) to select the signing key by `kid`.
    let header = decode_only(id_token)
        .map_err(|err| anyhow!("id_token header is malformed: {err}"))?
        .header;
    if let Some(kid) = header.kid.as_deref() {
        anyhow::ensure!(
            !kid.is_empty() && kid.len() <= 256 && !kid.chars().any(char::is_control),
            "id_token kid is invalid"
        );
    }

    // The `HttpClient` port already enforces the body cap and the
    // error-for-status check, so we only decode the returned bytes.
    let jwks_bytes = http
        .get(&config.jwks_uri)
        .await
        .context("JWKS request failed")?;
    anyhow::ensure!(
        jwks_bytes.len() <= MAX_JWKS_BYTES,
        "JWKS document is too large"
    );
    let jwks: Jwks = serde_json::from_slice(&jwks_bytes).context("decoding JWKS document")?;

    // Reject an absurdly large key set before building any decoding key: a JWKS
    // with thousands of keys (or keys with oversized RSA moduli) is an
    // RSA-verify DoS vector.
    if jwks.keys.len() > MAX_JWKS_KEYS {
        bail!(
            "JWKS document advertises {} keys, exceeding the {MAX_JWKS_KEYS}-key limit",
            jwks.keys.len()
        );
    }
    for key in &jwks.keys {
        anyhow::ensure!(key.kty.len() <= 16, "JWK key type is too long");
        if let Some(kid) = key.kid.as_deref() {
            anyhow::ensure!(
                !kid.is_empty() && kid.len() <= 256 && !kid.chars().any(char::is_control),
                "JWK kid is invalid"
            );
        }
        anyhow::ensure!(
            key.n.as_ref().map_or(true, |value| value.len() <= 1400),
            "JWK modulus is too large"
        );
        anyhow::ensure!(
            key.e.as_ref().map_or(true, |value| value.len() <= 16),
            "JWK exponent is too large"
        );
    }

    // Select the RSA key: by kid when the header names one, else the lone RSA
    // key (a single-key JWKS is the common case).
    let rsa_keys: Vec<&Jwk> = jwks.keys.iter().filter(|k| k.kty == "RSA").collect();
    let jwk = match &header.kid {
        Some(kid) => rsa_keys
            .iter()
            .copied()
            .find(|k| k.kid.as_deref() == Some(kid))
            .ok_or_else(|| anyhow!("JWKS has no RSA key for kid {kid}"))?,
        None => {
            if rsa_keys.len() == 1 {
                rsa_keys[0]
            } else {
                bail!("id_token has no kid and the JWKS does not have exactly one RSA key");
            }
        }
    };
    let (n, e) = match (&jwk.n, &jwk.e) {
        (Some(n), Some(e)) => (n, e),
        _ => bail!("RSA JWK is missing the n/e components"),
    };
    anyhow::ensure!(
        n.len() <= 1400 && e.len() <= 16,
        "RSA JWK components exceed encoded size limits"
    );
    // The JWK carries the modulus/exponent as base64url; jwt-rustcrypto's
    // `from_rsa_components` takes the raw big-endian bytes and builds the key via
    // the pure-Rust `rsa` crate (no C, so it compiles to wasm32).
    let n_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(n)
        .context("decoding JWK modulus (n)")?;
    let e_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(e)
        .context("decoding JWK exponent (e)")?;
    anyhow::ensure!(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&n_bytes) == *n
            && base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&e_bytes) == *e,
        "RSA JWK components are not canonical base64url"
    );
    anyhow::ensure!(
        n_bytes.first().is_some_and(|byte| *byte != 0)
            && e_bytes.first().is_some_and(|byte| *byte != 0),
        "RSA JWK components contain a redundant leading zero"
    );
    anyhow::ensure!(
        (MIN_RSA_MODULUS_BYTES..=MAX_RSA_MODULUS_BYTES).contains(&n_bytes.len()),
        "RSA JWK modulus must be between 2048 and 8192 bits"
    );
    let modulus_bits = n_bytes.len() * 8 - n_bytes[0].leading_zeros() as usize;
    anyhow::ensure!(
        (2048..=8192).contains(&modulus_bits),
        "RSA JWK modulus must be between 2048 and 8192 significant bits"
    );
    anyhow::ensure!(
        (1..=8).contains(&e_bytes.len()),
        "RSA JWK exponent length is invalid"
    );
    let exponent = e_bytes
        .iter()
        .try_fold(0_u64, |value, byte| {
            value.checked_mul(256)?.checked_add(u64::from(*byte))
        })
        .context("RSA JWK exponent overflow")?;
    anyhow::ensure!(
        exponent >= 3 && exponent % 2 == 1,
        "RSA JWK exponent is invalid"
    );
    let key = VerifyingKey::from_rsa_components(&n_bytes, &e_bytes)
        .map_err(|err| anyhow!("building RSA verifying key from JWK components: {err}"))?;

    // RS256 only — `ValidationOptions::new` pins the accepted algorithm set to
    // {RS256}, so an id_token claiming `alg: none`/`HS256` is rejected before the
    // signature is checked (alg-confusion defense). Audience and issuer are
    // exact-matched, and `exp` is required and checked with a 60-second leeway
    // (matching the hub's prior jsonwebtoken default).
    let validation = ValidationOptions::new(Algorithm::RS256)
        .with_audience(&config.client_id)
        .with_issuer(&config.issuer)
        .with_leeway(60)
        .with_required_claim("exp")
        .with_required_claim("iss")
        .with_required_claim("aud");

    let decoded = decode(id_token, &key, &validation)
        .map_err(|err| anyhow!("id_token signature or claim validation failed: {err}"))?;
    let claims: IdTokenClaims =
        serde_json::from_value(decoded.payload).context("decoding id_token claims")?;
    anyhow::ensure!(
        !claims.sub.is_empty() && claims.sub.len() <= 512,
        "id_token subject length is invalid"
    );
    if let Some(email) = claims.email.as_deref() {
        anyhow::ensure!(
            email.len() <= 320 && !email.chars().any(char::is_control),
            "id_token email is invalid"
        );
    }

    // Nonce binds the id_token to *this* login attempt (replay defense).
    match &claims.nonce {
        Some(nonce) if nonce == expected_nonce => {}
        _ => bail!("id_token nonce does not match the login flow"),
    }

    Ok(claims)
}

fn validate_jwt_components(token: &str) -> Result<()> {
    anyhow::ensure!(token.len() <= MAX_ID_TOKEN_BYTES, "id_token is too large");
    let components = token.split('.').collect::<Vec<_>>();
    anyhow::ensure!(components.len() == 3, "id_token must have three components");
    for (index, (component, decoded_limit)) in components
        .iter()
        .zip([
            MAX_JWT_HEADER_BYTES,
            MAX_JWT_PAYLOAD_BYTES,
            MAX_JWT_SIGNATURE_BYTES,
        ])
        .enumerate()
    {
        anyhow::ensure!(!component.is_empty(), "id_token component {index} is empty");
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(component)
            .with_context(|| format!("id_token component {index} is not base64url"))?;
        anyhow::ensure!(
            decoded.len() <= decoded_limit,
            "id_token component {index} is too large"
        );
        anyhow::ensure!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(&decoded)
                .as_str()
                == *component,
            "id_token component {index} is not canonically encoded"
        );
    }
    Ok(())
}

/// Map the id_token's groups claim to roles and grant them at the org scope.
///
/// Reads the configured `groups_claim` (a JSON array or single string) from the
/// id_token, looks each group up in `config.role_map`, and grants every mapped
/// role at the org scope. When no group maps (or no groups claim is
/// configured), the org's `default_role` is granted so a JIT user is never left
/// without read access.
///
/// # Errors
///
/// Returns an error on database failure while granting memberships.
async fn grant_mapped_roles(
    db: &Database,
    config: &IdpConfig,
    claims: &IdTokenClaims,
) -> Result<()> {
    let org = db
        .org_by_id(config.org_id)
        .await?
        .with_context(|| format!("org {} vanished mid-login", config.org_id))?;
    let scope = Scope::parse(&org.stable_id);
    let user_id = db
        .identity_user(&config.issuer, &claims.sub)
        .await?
        .with_context(|| "identity vanished mid-login")?;
    let principal = Principal::user(user_id);

    let groups = config
        .groups_claim
        .as_deref()
        .map(|name| extract_groups(claims, name))
        .transpose()?
        .unwrap_or_default();

    let mut mapped: Vec<Role> = groups
        .iter()
        .filter_map(|g| config.role_map.get(g).copied())
        .collect();
    if mapped.is_empty() {
        mapped.push(config.default_role);
    }
    mapped.sort_by_key(|r| std::cmp::Reverse(r.rank()));
    mapped.dedup();

    for role in mapped {
        db.grant_membership(
            principal.kind.as_str(),
            principal.id,
            scope.as_str(),
            role.as_str(),
        )
        .await?;
    }
    Ok(())
}

/// Extract group names from the id_token's `groups_claim`.
///
/// The claim may be a JSON array of strings or a single string; anything else
/// yields no groups.
fn extract_groups(claims: &IdTokenClaims, name: &str) -> Result<Vec<String>> {
    let groups = match claims.extra.get(name) {
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_string)
                    .context("id_token groups array contains a non-string value")
            })
            .collect::<Result<Vec<_>>>()?,
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    };
    anyhow::ensure!(
        groups.len() <= 256,
        "id_token groups claim has too many entries"
    );
    anyhow::ensure!(
        groups.iter().all(|group| !group.is_empty()
            && group.len() <= MAX_GROUP_BYTES
            && !group.chars().any(char::is_control)),
        "id_token groups claim contains an invalid entry"
    );
    Ok(groups)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_is_s256_of_verifier() {
        // RFC 7636 Appendix B vector.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = code_challenge_s256(verifier);
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn verifier_is_in_range_and_unique() {
        let a = new_code_verifier();
        assert!(a.len() >= 43 && a.len() <= 128, "len {}", a.len());
        assert!(a
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        assert_ne!(a, new_code_verifier());
    }

    #[test]
    fn redirect_uri_is_callback() {
        assert_eq!(
            redirect_uri("https://hub.example.com/"),
            "https://hub.example.com/auth/oidc/callback"
        );
        assert_eq!(
            redirect_uri("http://127.0.0.1:8420"),
            "http://127.0.0.1:8420/auth/oidc/callback"
        );
    }

    #[test]
    fn role_map_parses_known_roles_only() {
        let map =
            parse_role_map(r#"{"acme-admins":"admin","ghosts":"nonsense","devs":"developer"}"#);
        assert_eq!(map.get("acme-admins"), Some(&Role::Admin));
        assert_eq!(map.get("devs"), Some(&Role::Developer));
        assert!(!map.contains_key("ghosts"));
    }

    fn config_record() -> IdpConfigRecord {
        IdpConfigRecord {
            org_id: 1,
            issuer: "https://idp.example/tenant".into(),
            authorization_endpoint: "https://idp.example/authorize".into(),
            token_endpoint: "https://idp.example/token".into(),
            jwks_uri: "https://idp.example/jwks".into(),
            client_id: "hub-client".into(),
            client_secret_enc: None,
            scopes: "openid email profile".into(),
            groups_claim: Some("groups".into()),
            role_map_json: r#"{"admins":"admin"}"#.into(),
            allow_jit: true,
            enforce_sso: false,
            default_role: "viewer".into(),
            resource_version: 1,
            mutation_plan_id: None,
        }
    }

    #[test]
    fn idp_configuration_is_strict_and_centralized() {
        let valid = config_record();
        assert!(validate_idp_config_record(&valid).is_ok());
        let mut invalid = valid.clone();
        invalid.token_endpoint = "http://169.254.169.254/token".into();
        assert!(validate_idp_config_record(&invalid).is_err());
        let mut invalid = valid.clone();
        invalid.jwks_uri = "https://idp.example/jwks?tenant=other".into();
        assert!(validate_idp_config_record(&invalid).is_err());
        let mut invalid = valid.clone();
        invalid.scopes = "email profile".into();
        assert!(validate_idp_config_record(&invalid).is_err());
        let mut invalid = valid;
        invalid.role_map_json = format!("{{\"{}\":\"admin\"}}", "g".repeat(MAX_GROUP_BYTES + 1));
        assert!(validate_idp_config_record(&invalid).is_err());
    }

    #[test]
    fn callback_and_jwt_components_are_bounded_and_canonical() {
        let params = CallbackParams {
            code: "code".into(),
            state: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([5_u8; 32]),
        };
        assert!(validate_callback_params(&params).is_ok());
        let mut oversized = params.clone();
        oversized.code = "x".repeat(MAX_CALLBACK_CODE_BYTES + 1);
        assert!(validate_callback_params(&oversized).is_err());
        assert!(validate_jwt_components(&dummy_rs256_token()).is_ok());
        let oversized_header =
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(vec![b'x'; MAX_JWT_HEADER_BYTES + 1]);
        assert!(validate_jwt_components(&format!("{oversized_header}.e30.c2ln")).is_err());
    }

    /// Minimal `header.payload.sig` JWT shell with a valid RS256 header so
    /// `decode_only` succeeds and verification proceeds to the JWKS fetch.
    /// The signature is irrelevant here: the key-count guard rejects the JWKS
    /// before any signature is checked.
    fn dummy_rs256_token() -> String {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"sub":"x"}"#);
        format!("{header}.{payload}.sig")
    }

    fn test_idp_config(base: &str) -> IdpConfig {
        IdpConfig {
            org_id: 1,
            issuer: base.to_string(),
            authorization_endpoint: format!("{base}/authorize"),
            token_endpoint: format!("{base}/token"),
            jwks_uri: format!("{base}/jwks"),
            client_id: "hub-client".into(),
            client_secret_enc: None,
            scopes: "openid".into(),
            groups_claim: None,
            role_map: BTreeMap::new(),
            allow_jit: true,
            enforce_sso: false,
            default_role: Role::Viewer,
        }
    }

    /// A canned [`HttpClient`] that returns fixed bytes for `get` (the JWKS)
    /// and `post_form` (the token response), with no network at all.
    ///
    /// This keeps the verification tests transport-free: the same bytes a real
    /// IdP would return are served straight from memory, exercising
    /// [`verify_id_token`]'s parse-and-guard path without standing up a server.
    struct CannedHttpClient {
        jwks: Vec<u8>,
    }

    #[async_trait::async_trait]
    impl HttpClient for CannedHttpClient {
        async fn post_form(&self, _url: &str, _form: &[(String, String)]) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }

        async fn get(&self, _url: &str) -> Result<Vec<u8>> {
            Ok(self.jwks.clone())
        }
    }

    /// A JWKS advertising more keys than [`MAX_JWKS_KEYS`] is rejected before
    /// any decoding key is built — the RSA-verify DoS guard.
    #[tokio::test]
    async fn verify_id_token_rejects_oversized_jwks_key_set() {
        let keys: Vec<serde_json::Value> = (0..MAX_JWKS_KEYS + 1)
            .map(|i| {
                serde_json::json!({
                    "kty": "RSA",
                    "kid": format!("k{i}"),
                    "n": "abc",
                    "e": "AQAB",
                })
            })
            .collect();
        let jwks = serde_json::to_vec(&serde_json::json!({ "keys": keys }))
            .expect("serializing the oversized JWKS");
        let http = CannedHttpClient { jwks };
        let config = test_idp_config("https://idp.example");
        let err = verify_id_token(&http, &config, &dummy_rs256_token(), "nonce")
            .await
            .expect_err("an oversized JWKS must be rejected");
        assert!(
            err.to_string().contains("key limit"),
            "expected a key-limit error, got: {err:#}"
        );
    }
}
