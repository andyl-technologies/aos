//! Short-lived HS256 JWTs minted from a validated provisioning token.
//!
//! A client exchanges its long-lived provisioning secret at
//! `POST /oauth2/token` for one of these access tokens; the JWT then rides
//! every machine-path request in `Authorization: Bearer`. The token is
//! self-describing — it carries the owner, the scope path, and the explicit
//! permission verbs — so the gate ([`crate::auth::extract`]) can decide
//! without a database round-trip on the hot path.
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
//!   "scope":      "acme/infra/prod",       path-prefix the token is bound to
//!   "perms":      ["read","publish"],      permission verbs (snake-case)
//!   "iat":        1718200000,              issued-at, Unix seconds
//!   "exp":        1718200900               expiry, Unix seconds
//! }
//! ```
//!
//! The secret is an HS256 symmetric key ([`JwtKeys`]); supply a stable key
//! in production so tokens survive a restart, or let [`JwtKeys::random`]
//! generate an ephemeral 32-byte key for tests and dev mode.

use anyhow::{Context, Result};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::db::TokenAuth;

/// The HS256-signed claims carried by a hub access token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Token id (UUID) of the provisioning token this JWT was minted from.
    pub sub: String,
    /// Owning principal kind: `"user"` or `"service_account"`.
    pub owner_kind: String,
    /// Owning principal's row id.
    pub owner_id: i64,
    /// The scope path the token is bound to (`""` for instance root).
    pub scope: String,
    /// Permission verbs the token grants, as snake-case wire names.
    pub perms: Vec<String>,
    /// Issued-at timestamp (Unix seconds).
    pub iat: i64,
    /// Expiry timestamp (Unix seconds).
    pub exp: i64,
}

/// An HS256 signing key for minting and verifying access tokens.
///
/// Clone-cheap: it holds the raw key bytes plus the derived
/// encode/decode keys. Construct from a configured secret with
/// [`JwtKeys::from_secret`] or generate an ephemeral one with
/// [`JwtKeys::random`].
#[derive(Clone)]
pub struct JwtKeys {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl JwtKeys {
    /// Builds a key set from raw HS256 secret bytes.
    #[must_use]
    pub fn from_secret(secret: &[u8]) -> JwtKeys {
        JwtKeys {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
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

    /// Mints a signed access token for a validated provisioning token.
    ///
    /// The claims copy the owner, scope, and permission verbs from `auth`;
    /// the token is issued now and expires `ttl_secs` later.
    ///
    /// # Errors
    ///
    /// Returns an error if the system clock is before the Unix epoch or
    /// JWT encoding fails.
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
            iat: now,
            exp: now + ttl_secs,
        };
        encode(&Header::new(Algorithm::HS256), &claims, &self.encoding).context("encoding JWT")
    }

    /// Verifies a JWT and returns its claims.
    ///
    /// The signature is checked with HS256 and the `exp` claim is enforced.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid, the token is expired,
    /// or the claims cannot be deserialized.
    pub fn verify(&self, token: &str) -> Result<Claims> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        // Enforce `exp` strictly: no clock-skew leeway, so a token whose
        // expiry has passed is rejected the instant it lapses.
        validation.leeway = 0;
        let data = decode::<Claims>(token, &self.decoding, &validation).context("invalid JWT")?;
        Ok(data.claims)
    }
}

/// Returns the current Unix time in seconds.
fn unix_now() -> Result<i64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock before Unix epoch")?
        .as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Permission, Principal, Scope};

    fn sample_auth() -> TokenAuth {
        TokenAuth {
            token_id: "tok-1".to_string(),
            owner: Principal::user(42),
            scope: Scope::parse("acme/infra/prod"),
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
        assert_eq!(claims.scope, "acme/infra/prod");
        assert_eq!(claims.perms, vec!["read", "publish"]);
        assert!(claims.exp > claims.iat);
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
}
