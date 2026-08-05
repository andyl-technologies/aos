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

/// HMAC-SHA256 keyed by the JWT signing secret.
type HmacSha256 = Hmac<Sha256>;

/// base64url, no padding — the JWT segment encoding (RFC 7515).
const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// The fixed compact-JWS header for an HS256 token.
const HEADER_JSON: &[u8] = br#"{"alg":"HS256","typ":"JWT"}"#;

/// Authorization-model epoch embedded in every newly minted access token.
///
/// Verification rejects any other value, including tokens minted before the
/// stable-scope cutover. Increment this whenever claim interpretation or the
/// authorization graph changes incompatibly.
pub const AUTHORIZATION_CLAIMS_VERSION: &str = "stable-scope-1";

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
        let mut parts = token.split('.');
        let (Some(header_b64), Some(claims_b64), Some(sig_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            bail!("invalid JWT: expected three dot-separated segments");
        };
        // The header is fixed for the tokens this hub mints; reject anything
        // whose alg/typ we did not produce (an `alg:none` downgrade or an
        // unexpected algorithm never reaches the signature check).
        let header = B64
            .decode(header_b64)
            .context("invalid JWT header base64")?;
        if header != HEADER_JSON {
            bail!("invalid JWT: unexpected header (only HS256 is accepted)");
        }
        // Verify the signature over `header.claims` in constant time.
        let signing_input = format!("{header_b64}.{claims_b64}");
        let signature = B64
            .decode(sig_b64)
            .context("invalid JWT signature base64")?;
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.secret)
            .unwrap_or_else(|_| unreachable!("HMAC-SHA256 accepts any key length"));
        mac.update(signing_input.as_bytes());
        mac.verify_slice(&signature)
            .map_err(|_| anyhow::anyhow!("invalid JWT signature"))?;
        // Signature verified: decode the claims and enforce expiry.
        let claims_bytes = B64
            .decode(claims_b64)
            .context("invalid JWT claims base64")?;
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
            authz_version: "path-scope-legacy".to_string(),
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
}
