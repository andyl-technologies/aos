//! Per-org OIDC single sign-on: the authorization-code + PKCE flow.
//!
//! This module implements RFC-0004's "Per-org OIDC SSO": each org may
//! configure one OpenID Connect identity provider; an email-first login on a
//! captured domain routes to that IdP, and a successful round-trip provisions
//! or links a hub user keyed on `(issuer, subject)` — never bare email.
//!
//! # Why a direct implementation, not the `openidconnect` crate
//!
//! RFC-0004 flags the `openidconnect` crate as needing a *WASM* spike (it must
//! also run on Cloudflare Workers). That concern does **not** apply to this
//! native axum binary: here a direct, dependency-light implementation over
//! crates already in the workspace is the leaner choice. The flow uses
//! [`reqwest`] for the token/JWKS HTTP, [`sha2`] for the PKCE S256 challenge,
//! [`rand`] for the high-entropy `state`/`nonce`/`code_verifier`, [`base64`]
//! for base64url, and — crucially — the workspace's existing [`jsonwebtoken`]
//! dependency for RS256 id_token verification: `jsonwebtoken` builds an RSA
//! `DecodingKey` straight from a JWK's `(n, e)` components
//! (`DecodingKey::from_rsa_components`), so no new signature-verification crate
//! is needed. Only RS256 is supported, which covers the overwhelming majority
//! of IdPs (Okta, Entra, Auth0, Keycloak, Google, Dex).
//!
//! # The flow
//!
//! ```text
//! begin_login(org)                         complete_login(code, state)
//! ─────────────────                        ───────────────────────────
//! 1. load org IdP config                   1. take_oidc_flow(state)  ← single-use
//! 2. verifier = random 43..128 chars          (validates + consumes; expiry)
//!    challenge = b64url(sha256(verifier))   2. POST token_endpoint:
//!    state, nonce = random                       grant_type=authorization_code
//! 3. create_oidc_flow(state, nonce,             code, redirect_uri, client_id,
//!                     verifier)                  client_secret (unsealed),
//! 4. redirect to authorization_endpoint?         code_verifier   ← PKCE proof
//!      response_type=code                    3. fetch JWKS, find kid
//!      client_id, redirect_uri, scope        4. verify id_token (RS256):
//!      state, nonce                              iss == config.issuer
//!      code_challenge=b64url(sha256(v))          aud == client_id, exp
//!      code_challenge_method=S256                nonce == flow.nonce
//!                                            5. extract sub, email[_verified],
//!         user───approves at IdP───►            groups
//!         IdP redirects to                   6. link_or_create_identity(iss,sub)
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

use crate::db::{Database, IdpConfigRecord};
use crate::domain::{Principal, Role, Scope};

/// Lifetime of an in-flight OIDC authorization-code request (10 minutes).
///
/// A callback whose `state` flow is older than this is rejected, bounding the
/// window in which a leaked authorization URL can be replayed.
pub const FLOW_TTL_SECS: i64 = 10 * 60;

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

/// Parse a `{"group": "role"}` JSON object into a role map, skipping unknown
/// roles.
fn parse_role_map(json: &str) -> BTreeMap<String, Role> {
    let raw: BTreeMap<String, String> = serde_json::from_str(json).unwrap_or_default();
    raw.into_iter()
        .filter_map(|(group, role)| Role::parse(&role).map(|r| (group, r)))
        .collect()
}

/// Seals and unseals client secrets at rest.
///
/// The hub stores OIDC client secrets *sealed* and unseals them only at the
/// instant of the token exchange. Production uses
/// [`AesGcmSealer`](crate::auth::seal::AesGcmSealer); the placeholder
/// [`XorSealer`] is reachable only under `--dev` and in tests.
pub trait SecretSealer: Send + Sync {
    /// Seals a plaintext secret into the at-rest form stored in
    /// `org_idp_configs.client_secret_enc`.
    ///
    /// # Errors
    ///
    /// Returns an error if sealing fails (never, for [`XorSealer`]).
    fn seal(&self, plaintext: &str) -> Result<String>;

    /// Unseals an at-rest secret back to plaintext.
    ///
    /// # Errors
    ///
    /// Returns an error if the sealed value is malformed or cannot be
    /// unsealed.
    fn unseal(&self, sealed: &str) -> Result<String>;
}

/// A **placeholder** [`SecretSealer`]: XOR with an instance key, base64url.
///
/// # ⚠️ Not real encryption
///
/// This is **not** confidentiality-grade. XOR with a repeating key is trivially
/// reversible by anyone who can read both the database and the instance key,
/// and offers no integrity. It exists only so phase 3d can store client
/// secrets in a *non-plaintext* form behind the [`SecretSealer`] seam. It is
/// now **test/dev-only**: production `serve` uses
/// [`AesGcmSealer`](crate::auth::seal::AesGcmSealer) instead, and `XorSealer`
/// is reachable only under `--dev` (where reproducibility, not confidentiality,
/// is the goal) and in tests via [`dev_sealer`].
#[derive(Debug, Clone)]
pub struct XorSealer {
    key: Vec<u8>,
}

impl XorSealer {
    /// Builds a placeholder sealer from an instance key.
    ///
    /// The key should be high-entropy and at least a few bytes; an empty key
    /// is rejected so a misconfiguration cannot produce a no-op "seal".
    ///
    /// # Errors
    ///
    /// Returns an error when `key` is empty.
    pub fn new(key: &[u8]) -> Result<XorSealer> {
        if key.is_empty() {
            bail!("XorSealer instance key must not be empty");
        }
        Ok(XorSealer { key: key.to_vec() })
    }

    fn xor(&self, bytes: &[u8]) -> Vec<u8> {
        bytes
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ self.key[i % self.key.len()])
            .collect()
    }
}

impl SecretSealer for XorSealer {
    fn seal(&self, plaintext: &str) -> Result<String> {
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.xor(plaintext.as_bytes())))
    }

    fn unseal(&self, sealed: &str) -> Result<String> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(sealed)
            .context("decoding sealed client secret")?;
        String::from_utf8(self.xor(&bytes)).context("unsealed client secret is not valid UTF-8")
    }
}

/// The fixed instance key the dev/test placeholder sealer uses.
const DEV_SEALER_KEY: &[u8] = b"aos-hub-dev-instance-key";

/// Builds the placeholder [`XorSealer`] used in dev mode and tests.
///
/// Uses a fixed non-empty instance key, so construction is infallible and no
/// panic path is introduced. **Never** use this in production — see
/// [`XorSealer`] for the (large) caveat.
#[must_use]
pub fn dev_sealer() -> std::sync::Arc<dyn SecretSealer> {
    std::sync::Arc::new(XorSealer {
        key: DEV_SEALER_KEY.to_vec(),
    })
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
pub fn begin_login(
    db: &Database,
    external_url: &str,
    org_id: i64,
    redirect_after: Option<&str>,
) -> Result<AuthRedirect> {
    let config = db
        .idp_config(org_id)?
        .map(IdpConfig::from_record)
        .with_context(|| format!("org {org_id} has no OIDC identity provider configured"))?;

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
    )?;

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
///    **unsealed** client secret; read the `id_token`.
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
    http: &reqwest::Client,
    external_url: &str,
    params: &CallbackParams,
) -> Result<OidcLogin> {
    // 1. Consume the flow (single-use, expiry-checked).
    let flow = db
        .take_oidc_flow(&params.state)?
        .ok_or_else(|| anyhow!("unknown, expired, or replayed login state"))?;

    let config = db
        .idp_config(flow.org_id)?
        .map(IdpConfig::from_record)
        .with_context(|| format!("org {} has no OIDC identity provider", flow.org_id))?;

    // 2. Exchange the authorization code (with PKCE proof) for tokens.
    let mut form = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", params.code.clone()),
        ("redirect_uri", redirect_uri(external_url)),
        ("client_id", config.client_id.clone()),
        ("code_verifier", flow.code_verifier.clone()),
    ];
    if let Some(sealed) = &config.client_secret_enc {
        let secret = sealer
            .unseal(sealed)
            .context("unsealing OIDC client secret")?;
        form.push(("client_secret", secret));
    }
    let token: TokenResponse = http
        .post(&config.token_endpoint)
        .form(&form)
        .send()
        .await
        .context("OIDC token request failed")?
        .error_for_status()
        .context("OIDC token endpoint returned an error status")?
        .json()
        .await
        .context("decoding OIDC token response")?;
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
        )?
        .ok_or_else(|| {
            anyhow!("just-in-time provisioning is disabled and this identity is unknown")
        })?;
    let user_id = link.user_id();

    // Map groups → roles and grant memberships at the org scope. Re-evaluated
    // on every login; full deprovisioning/sync (revoking SSO-granted roles no
    // longer mapped) is a later phase — here we ensure the mapped roles are
    // granted, plus the default role so a JIT user is never left with nothing.
    grant_mapped_roles(db, &config, &claims)?;

    Ok(OidcLogin {
        user_id,
        email,
        provisioned: matches!(link, crate::db::IdentityLink::Created(_)),
        redirect_after: flow.redirect_after.clone(),
    })
}

/// Verify an id_token: RS256 signature via JWKS, plus iss/aud/exp/nonce.
///
/// Fetches the JWKS, selects the RSA key by `kid` (or the sole RSA key when the
/// header carries no `kid`), builds a [`jsonwebtoken::DecodingKey`] from the
/// JWK's `(n, e)`, and decodes with `Algorithm::RS256` validating `aud` and
/// `exp`. `iss` is checked explicitly against `config.issuer`, and `nonce`
/// against the flow's nonce.
///
/// # Errors
///
/// Returns an error on JWKS fetch failure, a missing/non-RSA key, signature or
/// claim validation failure, an `iss` mismatch, or a `nonce` mismatch.
async fn verify_id_token(
    http: &reqwest::Client,
    config: &IdpConfig,
    id_token: &str,
    expected_nonce: &str,
) -> Result<IdTokenClaims> {
    use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};

    let header = decode_header(id_token).context("id_token header is malformed")?;

    let jwks: Jwks = http
        .get(&config.jwks_uri)
        .send()
        .await
        .context("JWKS request failed")?
        .error_for_status()
        .context("JWKS endpoint returned an error status")?
        .json()
        .await
        .context("decoding JWKS document")?;

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
    let key = DecodingKey::from_rsa_components(n, e)
        .context("building RSA decoding key from JWK components")?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[&config.client_id]);
    validation.set_issuer(&[&config.issuer]);
    // `exp` is validated by default; require it explicitly.
    validation.validate_exp = true;
    validation.required_spec_claims = ["exp", "iss", "aud"]
        .iter()
        .map(|s| s.to_string())
        .collect();

    let data = decode::<IdTokenClaims>(id_token, &key, &validation)
        .context("id_token signature or claim validation failed")?;
    let claims = data.claims;

    // Nonce binds the id_token to *this* login attempt (replay defense).
    match &claims.nonce {
        Some(nonce) if nonce == expected_nonce => {}
        _ => bail!("id_token nonce does not match the login flow"),
    }

    Ok(claims)
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
fn grant_mapped_roles(db: &Database, config: &IdpConfig, claims: &IdTokenClaims) -> Result<()> {
    let org = db
        .org_by_id(config.org_id)?
        .with_context(|| format!("org {} vanished mid-login", config.org_id))?;
    let scope = Scope::parse(&org.slug);
    let user_id = db
        .identity_user(&config.issuer, &claims.sub)?
        .with_context(|| "identity vanished mid-login")?;
    let principal = Principal::user(user_id);

    let groups = config
        .groups_claim
        .as_deref()
        .map(|name| extract_groups(claims, name))
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
        )?;
    }
    Ok(())
}

/// Extract group names from the id_token's `groups_claim`.
///
/// The claim may be a JSON array of strings or a single string; anything else
/// yields no groups.
fn extract_groups(claims: &IdTokenClaims, name: &str) -> Vec<String> {
    match claims.extra.get(name) {
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
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
    fn xor_sealer_roundtrips() {
        let sealer = XorSealer::new(b"instance-key-0123456789").unwrap();
        let sealed = sealer.seal("super-secret-client-secret").unwrap();
        assert_ne!(sealed, "super-secret-client-secret");
        assert_eq!(
            sealer.unseal(&sealed).unwrap(),
            "super-secret-client-secret"
        );
    }

    #[test]
    fn xor_sealer_rejects_empty_key() {
        assert!(XorSealer::new(b"").is_err());
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
}
