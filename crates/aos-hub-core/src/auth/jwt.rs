//! Short-lived HS256 JWTs minted from a validated provisioning token.
//!
//! A client exchanges its long-lived provisioning secret at
//! `POST /oauth2/token` for one of these access tokens; the JWT then rides
//! every machine-path request in `Authorization: Bearer`. The token is
//! self-describing — it carries the owner, the stable scope key, the explicit
//! permission verbs — so the gate can decide without a database round-trip on
//! the hot path.
//!
//! The HS256 signing and verification are implemented directly over `hmac` +
//! `sha2` (no `jsonwebtoken`/`ring`), so this compiles to
//! `wasm32-unknown-unknown` for the Cloudflare Worker (RFC-0004 Phase 5). These
//! access tokens are short-lived and never persisted, so the only contract is
//! mint↔verify self-consistency.
//!
//! # Claim shape
//!
//! The HS256-signed payload ([`Claims`]) is:
//!
//! ```text
//! {
//!   "sub":        "1f0c…",                 token id (UUID) it was minted from
//!   "owner_kind": "user",                  "user" | "service_account"
//!   "owner_id":   42,                      owning principal's row id
//!   "scope":      "project:0123…",         stable scope the token is bound to
//!   "perms":      ["read","publish"],      permission verbs (snake-case)
//!   "authz_version": "stable-scope-1",     authorization-model epoch
//!   "iat":        1718200000,              issued-at, Unix seconds
//!   "exp":        1718200900               expiry, Unix seconds
//! }
//! ```
//!
//! The token wire form is the standard compact JWT
//! `base64url(header).base64url(claims).base64url(HMAC-SHA256(header.claims))`,
//! with a fixed `{"alg":"HS256","typ":"JWT"}` header.
//!
//! The secret is an HS256 symmetric key ([`JwtKeys`]); supply a stable key
//! in production so tokens survive a restart, or let [`JwtKeys::random`]
//! generate an ephemeral 32-byte key for tests and dev mode.

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::db::TokenAuth;
use aos_oci_types::RepositoryName;

/// HMAC-SHA256 keyed by the JWT signing secret.
type HmacSha256 = Hmac<Sha256>;

/// base64url, no padding — the JWT segment encoding (RFC 7515).
const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// The fixed compact-JWS header for an HS256 token.
const HEADER_JSON: &[u8] = br#"{"alg":"HS256","typ":"JWT"}"#;

/// Domain-separated compact-JWS header for OCI repository tokens.
const OCI_HEADER_JSON: &[u8] = br#"{"alg":"HS256","typ":"application/vnd.aos.oci-token+jwt"}"#;

/// Authorization-model epoch embedded in every newly minted access token.
///
/// Verification rejects any other value, including tokens minted before the
/// stable-scope cutover. Increment this whenever claim interpretation or the
/// authorization graph changes incompatibly.
pub const AUTHORIZATION_CLAIMS_VERSION: &str = "stable-scope-1";

/// Authorization-model epoch for repository-scoped Distribution tokens.
pub const OCI_AUTHORIZATION_CLAIMS_VERSION: &str = "aos-oci-pull-1";

/// The HS256-signed claims carried by a hub access token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Token id (UUID) of the provisioning token this JWT was minted from.
    pub sub: String,
    /// Owning principal kind: `"user"` or `"service_account"`.
    pub owner_kind: String,
    /// Owning principal's row id.
    pub owner_id: i64,
    /// The immutable authorization scope key the token is bound to.
    pub scope: String,
    /// Permission verbs the token grants, as snake-case wire names.
    pub perms: Vec<String>,
    /// Authorization-model epoch used to invalidate pre-cutover tokens.
    pub authz_version: String,
    /// Issued-at timestamp (Unix seconds).
    pub iat: i64,
    /// Expiry timestamp (Unix seconds).
    pub exp: i64,
}

/// Inputs bound into one repository-scoped OCI token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciTokenGrant {
    /// Stable principal or anonymous-session subject.
    pub subject: String,
    /// Exact canonical Distribution service authority.
    pub authority: String,
    /// Stable id of the owning AOS registry incarnation.
    pub registry_stable_id: String,
    /// Exact repository local to that registry.
    pub repository: RepositoryName,
    /// Sorted exact Distribution actions, currently only `pull`.
    pub actions: Vec<String>,
}

/// Claims carried only by a repository-scoped OCI Distribution token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciClaims {
    /// Token-contract epoch.
    pub oci_version: String,
    /// Stable authenticated principal.
    pub sub: String,
    /// Exact canonical Distribution service authority.
    pub aud: String,
    /// Stable owning-registry incarnation.
    pub registry: String,
    /// Exact registry-local repository.
    pub repository: RepositoryName,
    /// Sorted exact Distribution actions.
    pub actions: Vec<String>,
    /// Issued-at timestamp in Unix seconds.
    pub iat: i64,
    /// Expiry timestamp in Unix seconds.
    pub exp: i64,
}

/// An HS256 signing key for minting and verifying access tokens.
///
/// Clone-cheap: it holds the raw HS256 secret bytes. Construct from a
/// configured secret with [`JwtKeys::from_secret`] or generate an ephemeral
/// one with [`JwtKeys::random`].
#[derive(Clone)]
pub struct JwtKeys {
    secret: Vec<u8>,
}

impl JwtKeys {
    /// Builds a key set from raw HS256 secret bytes.
    #[must_use]
    pub fn from_secret(secret: &[u8]) -> JwtKeys {
        JwtKeys {
            secret: secret.to_vec(),
        }
    }

    /// Generates an ephemeral key set from 32 random bytes.
    ///
    /// Use this for tests and dev mode where access tokens need not survive
    /// a process restart; production should pass a stable configured
    /// secret to [`JwtKeys::from_secret`].
    #[must_use]
    pub fn random() -> JwtKeys {
        let bytes: [u8; 32] = rand::rng().random();
        JwtKeys::from_secret(&bytes)
    }

    /// HMAC-SHA256 of `msg` under the secret. Infallible (HMAC accepts any key
    /// length).
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.secret)
            .unwrap_or_else(|_| unreachable!("HMAC-SHA256 accepts any key length"));
        mac.update(msg);
        mac.finalize().into_bytes().to_vec()
    }

    /// Mints a signed access token for a validated provisioning token.
    ///
    /// The claims copy the owner, scope, and permission verbs from `auth`;
    /// the token is issued now and expires `ttl_secs` later.
    ///
    /// # Errors
    ///
    /// Returns an error if the system clock is before the Unix epoch or
    /// claim serialization fails.
    pub fn mint(&self, auth: &TokenAuth, ttl_secs: i64) -> Result<String> {
        let now = unix_now()?;
        let claims = Claims {
            sub: auth.token_id.clone(),
            owner_kind: auth.owner.kind.as_str().to_string(),
            owner_id: auth.owner.id,
            scope: auth.scope.as_str().to_string(),
            perms: auth
                .permissions
                .iter()
                .map(|p| p.as_str().to_string())
                .collect(),
            authz_version: AUTHORIZATION_CLAIMS_VERSION.to_string(),
            iat: now,
            exp: now + ttl_secs,
        };
        let claims_json = serde_json::to_vec(&claims).context("serializing JWT claims")?;
        let signing_input = format!("{}.{}", B64.encode(HEADER_JSON), B64.encode(claims_json));
        let signature = self.sign(signing_input.as_bytes());
        Ok(format!("{signing_input}.{}", B64.encode(signature)))
    }

    /// Verifies a JWT and returns its claims.
    ///
    /// The signature is checked with HS256 (constant-time) and the `exp` claim
    /// is enforced strictly — no clock-skew leeway, so a token whose expiry has
    /// passed is rejected the instant it lapses.
    ///
    /// # Errors
    ///
    /// Returns an error if the token is malformed, the signature is invalid,
    /// the token is expired, its authorization epoch is obsolete, or the
    /// claims cannot be deserialized.
    pub fn verify(&self, token: &str) -> Result<Claims> {
        let claims_bytes = self.verify_compact(token, HEADER_JSON)?;
        let claims: Claims = serde_json::from_slice(&claims_bytes).context("invalid JWT claims")?;
        if claims.authz_version != AUTHORIZATION_CLAIMS_VERSION {
            bail!("JWT was minted for an incompatible authorization model");
        }
        let now = unix_now()?;
        if claims.exp <= now {
            bail!("JWT has expired");
        }
        Ok(claims)
    }

    /// Mints a short-lived token bound to one OCI service and repository.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed grant identity, unsupported actions,
    /// invalid lifetime, clock failure, or claim serialization failure.
    pub fn mint_oci(&self, grant: &OciTokenGrant, ttl_secs: i64) -> Result<String> {
        validate_oci_grant(grant)?;
        if !(1..=900).contains(&ttl_secs) {
            bail!("OCI token lifetime must be between 1 and 900 seconds");
        }
        let now = unix_now()?;
        let claims = OciClaims {
            oci_version: OCI_AUTHORIZATION_CLAIMS_VERSION.to_string(),
            sub: grant.subject.clone(),
            aud: grant.authority.clone(),
            registry: grant.registry_stable_id.clone(),
            repository: grant.repository.clone(),
            actions: grant.actions.clone(),
            iat: now,
            exp: now + ttl_secs,
        };
        self.mint_compact(OCI_HEADER_JSON, &claims, "OCI token claims")
    }

    /// Verifies an OCI token against the exact request authority and repository.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed or expired token, the ordinary Hub JWT
    /// header, an incompatible token epoch, or any authority, registry,
    /// repository, or action mismatch.
    pub fn verify_oci(
        &self,
        token: &str,
        authority: &str,
        registry_stable_id: &str,
        repository: &RepositoryName,
        required_action: &str,
    ) -> Result<OciClaims> {
        let claims = self.verify_oci_claims(token)?;
        if claims.aud != authority
            || claims.registry != registry_stable_id
            || &claims.repository != repository
            || !claims
                .actions
                .iter()
                .any(|action| action == required_action)
        {
            bail!("OCI token is not authorized for this repository request");
        }
        Ok(claims)
    }

    /// Verifies the signature, token type, epoch, lifetime, and grant shape of
    /// an OCI token without applying a request-specific authorization check.
    ///
    /// This split lets the Distribution handler distinguish an invalid
    /// credential (`UNAUTHORIZED`) from a valid token presented for the wrong
    /// authority, registry, repository, or action (`DENIED`).
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed signature or claims body, an ordinary
    /// Hub JWT, an incompatible epoch, an invalid lifetime, or a malformed
    /// repository grant.
    pub fn verify_oci_claims(&self, token: &str) -> Result<OciClaims> {
        let claims_bytes = self.verify_compact(token, OCI_HEADER_JSON)?;
        let claims: OciClaims =
            serde_json::from_slice(&claims_bytes).context("invalid OCI token claims")?;
        if claims.oci_version != OCI_AUTHORIZATION_CLAIMS_VERSION {
            bail!("OCI token was minted for an incompatible authorization model");
        }
        let now = unix_now()?;
        if claims.exp <= now || claims.iat > now || claims.exp - claims.iat > 900 {
            bail!("OCI token lifetime is invalid or expired");
        }
        let grant = OciTokenGrant {
            subject: claims.sub.clone(),
            authority: claims.aud.clone(),
            registry_stable_id: claims.registry.clone(),
            repository: claims.repository.clone(),
            actions: claims.actions.clone(),
        };
        validate_oci_grant(&grant)?;
        Ok(claims)
    }

    fn mint_compact<T: Serialize>(
        &self,
        header: &[u8],
        claims: &T,
        context: &'static str,
    ) -> Result<String> {
        let claims_json =
            serde_json::to_vec(claims).with_context(|| format!("serializing {context}"))?;
        let signing_input = format!("{}.{}", B64.encode(header), B64.encode(claims_json));
        let signature = self.sign(signing_input.as_bytes());
        Ok(format!("{signing_input}.{}", B64.encode(signature)))
    }

    fn verify_compact(&self, token: &str, expected_header: &[u8]) -> Result<Vec<u8>> {
        let mut parts = token.split('.');
        let (Some(header_b64), Some(claims_b64), Some(sig_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            bail!("invalid JWT: expected three dot-separated segments");
        };
        let header = B64
            .decode(header_b64)
            .context("invalid JWT header base64")?;
        if header != expected_header {
            bail!("invalid JWT: unexpected token type or algorithm");
        }
        let signing_input = format!("{header_b64}.{claims_b64}");
        let signature = B64
            .decode(sig_b64)
            .context("invalid JWT signature base64")?;
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.secret)
            .unwrap_or_else(|_| unreachable!("HMAC-SHA256 accepts any key length"));
        mac.update(signing_input.as_bytes());
        mac.verify_slice(&signature)
            .map_err(|_| anyhow::anyhow!("invalid JWT signature"))?;
        B64.decode(claims_b64).context("invalid JWT claims base64")
    }
}

fn validate_oci_grant(grant: &OciTokenGrant) -> Result<()> {
    for (value, field, maximum) in [
        (grant.subject.as_str(), "OCI token subject", 128_usize),
        (grant.authority.as_str(), "OCI token authority", 255_usize),
        (
            grant.registry_stable_id.as_str(),
            "OCI token registry identity",
            128_usize,
        ),
    ] {
        if value.is_empty()
            || value.len() > maximum
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
        {
            bail!("{field} is malformed");
        }
    }
    if grant.authority != grant.authority.to_ascii_lowercase()
        || grant
            .authority
            .bytes()
            .any(|byte| matches!(byte, b'/' | b'@' | b'?' | b'#'))
    {
        bail!("OCI token authority is not canonical");
    }
    if grant.registry_stable_id.len() != "registry:".len() + 32
        || !grant
            .registry_stable_id
            .strip_prefix("registry:")
            .is_some_and(|opaque| {
                opaque
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            })
    {
        bail!("OCI token registry identity is not canonical");
    }
    if grant.actions.as_slice() != ["pull"] {
        bail!("OCI token actions must be exactly the sorted pull action");
    }
    Ok(())
}

/// Returns the current Unix time in seconds (native `SystemTime`, or the
/// Worker's JS `Date.now()` clock on wasm32 — see [`crate::clock`]).
fn unix_now() -> Result<i64> {
    Ok(crate::clock::now_unix_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Permission, Principal, Scope};

    const PROJECT_SCOPE: &str = "project:00000000000000000000000000000001";

    fn sample_auth() -> TokenAuth {
        TokenAuth {
            token_id: "tok-1".to_string(),
            owner: Principal::user(42),
            scope: Scope::parse(PROJECT_SCOPE),
            permissions: vec![Permission::Read, Permission::Publish],
        }
    }

    #[test]
    fn mint_and_verify_roundtrip() {
        let keys = JwtKeys::random();
        let token = keys.mint(&sample_auth(), 900).unwrap();
        let claims = keys.verify(&token).unwrap();
        assert_eq!(claims.sub, "tok-1");
        assert_eq!(claims.owner_kind, "user");
        assert_eq!(claims.owner_id, 42);
        assert_eq!(claims.scope, PROJECT_SCOPE);
        assert_eq!(claims.perms, vec!["read", "publish"]);
        assert_eq!(claims.authz_version, AUTHORIZATION_CLAIMS_VERSION);
        assert!(claims.exp > claims.iat);
    }

    #[test]
    fn token_is_three_b64url_segments() {
        let keys = JwtKeys::random();
        let token = keys.mint(&sample_auth(), 900).unwrap();
        let segments: Vec<&str> = token.split('.').collect();
        assert_eq!(segments.len(), 3, "compact JWS has three segments");
        // The header decodes to the fixed HS256 header.
        assert_eq!(B64.decode(segments[0]).unwrap(), HEADER_JSON);
    }

    #[test]
    fn tampered_token_is_rejected() {
        let keys = JwtKeys::random();
        let token = keys.mint(&sample_auth(), 900).unwrap();
        // Flip the last character of the signature segment.
        let mut bytes = token.into_bytes();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let tampered = String::from_utf8(bytes).unwrap();
        assert!(keys.verify(&tampered).is_err());
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let signer = JwtKeys::random();
        let other = JwtKeys::random();
        let token = signer.mint(&sample_auth(), 900).unwrap();
        assert!(other.verify(&token).is_err());
    }

    #[test]
    fn expired_token_is_rejected() {
        let keys = JwtKeys::random();
        // A negative TTL yields an exp well in the past (beyond any
        // residual leeway).
        let token = keys.mint(&sample_auth(), -120).unwrap();
        assert!(keys.verify(&token).is_err());
    }

    #[test]
    fn obsolete_authorization_epoch_is_rejected() {
        let keys = JwtKeys::random();
        let now = unix_now().unwrap();
        let claims = Claims {
            sub: "tok-1".to_string(),
            owner_kind: "user".to_string(),
            owner_id: 42,
            scope: PROJECT_SCOPE.to_string(),
            perms: vec!["read".to_string()],
            authz_version: "obsolete-path-scope-v0".to_string(),
            iat: now,
            exp: now + 900,
        };
        let claims_json = serde_json::to_vec(&claims).unwrap();
        let signing_input = format!("{}.{}", B64.encode(HEADER_JSON), B64.encode(claims_json));
        let token = format!(
            "{signing_input}.{}",
            B64.encode(keys.sign(signing_input.as_bytes()))
        );

        assert!(keys.verify(&token).is_err());
    }

    #[test]
    fn malformed_token_is_rejected() {
        let keys = JwtKeys::random();
        assert!(keys.verify("not-a-jwt").is_err());
        assert!(keys.verify("only.two").is_err());
        assert!(keys.verify("a.b.c.d").is_err());
    }

    fn sample_oci_grant() -> OciTokenGrant {
        OciTokenGrant {
            subject: "token:tok-1".to_string(),
            authority: "containers.example:8443".to_string(),
            registry_stable_id: "registry:0123456789abcdef0123456789abcdef".to_string(),
            repository: RepositoryName::parse("aos").unwrap(),
            actions: vec!["pull".to_string()],
        }
    }

    #[test]
    fn oci_tokens_are_exactly_repository_and_authority_bound() {
        let keys = JwtKeys::from_secret(b"oci-token-test-secret");
        let grant = sample_oci_grant();
        let token = keys.mint_oci(&grant, 300).unwrap();

        let claims = keys
            .verify_oci(
                &token,
                &grant.authority,
                &grant.registry_stable_id,
                &grant.repository,
                "pull",
            )
            .unwrap();
        assert_eq!(claims.repository, grant.repository);
        assert!(keys
            .verify_oci(
                &token,
                "other.example",
                &grant.registry_stable_id,
                &grant.repository,
                "pull"
            )
            .is_err());
        assert!(keys
            .verify_oci(
                &token,
                &grant.authority,
                &grant.registry_stable_id,
                &RepositoryName::parse("other").unwrap(),
                "pull"
            )
            .is_err());
    }

    #[test]
    fn ordinary_and_oci_tokens_are_domain_separated() {
        let keys = JwtKeys::from_secret(b"domain-separation-test-secret");
        let hub = keys.mint(&sample_auth(), 300).unwrap();
        let grant = sample_oci_grant();
        let oci = keys.mint_oci(&grant, 300).unwrap();

        assert!(keys.verify(&oci).is_err());
        assert!(keys
            .verify_oci(
                &hub,
                &grant.authority,
                &grant.registry_stable_id,
                &grant.repository,
                "pull"
            )
            .is_err());
    }

    #[test]
    fn oci_grants_reject_broader_actions_and_lifetimes() {
        let keys = JwtKeys::random();
        let mut grant = sample_oci_grant();
        grant.actions.push("push".to_string());
        assert!(keys.mint_oci(&grant, 300).is_err());
        grant.actions = vec!["pull".to_string()];
        assert!(keys.mint_oci(&grant, 901).is_err());
        assert!(keys.mint_oci(&grant, 0).is_err());
        grant.authority = "EXAMPLE.test".to_string();
        assert!(keys.mint_oci(&grant, 300).is_err());
        grant.authority = "example.test".to_string();
        grant.registry_stable_id = "registry:ABCDEF0123456789ABCDEF0123456789".to_string();
        assert!(keys.mint_oci(&grant, 300).is_err());
    }
}
