//! Loads trusted static workload issuer policy without inline signing secrets.
//!
//! Configuration supplies public authority, private-file location and finite
//! lifetime bounds. Native opening separately checks the real signing file.
//! Job claims remain trusted provisioning inputs; this configuration implements
//! no remote authentication endpoint or unauthenticated job-selection API.
//!
//! ```toml
//! role = "serve"
//! store = "bucket(file:///var/lib/terrane)"
//! [static_workload_issuers.ci]
//! issuer = "ci"
//! key_id = "2026-10"
//! public_key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
//! signing_key_file = "/var/lib/terrane/authority/ci.seed"
//! owner_uid = 840
//! maximum_lifetime_seconds = 900
//! lifetime_margin_seconds = 30
//! ```

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use super::ConfigError;

/// Loads exact trusted GCE assignments and their configured workload grants.
pub mod gcp;

#[cfg(all(feature = "std", unix))]
mod open;

#[cfg(all(feature = "std", unix))]
pub use open::IssuerOpenError;

/// Supplies independently trusted public authority and private signing-file policy.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticWorkloadIssuer {
    /// Names the authority recorded in issued workload tokens.
    pub issuer: String,
    /// Identifies this public signing-key generation within the issuer.
    pub key_id: String,
    /// Encodes the independent Ed25519 public key as 64 lowercase hex digits.
    pub public_key: String,
    /// Locates an absolute native file containing only the raw 32-byte seed.
    pub signing_key_file: String,
    /// Requires the actual private signing file to have this Unix owner.
    pub owner_uid: u32,
    /// Caps each token's lifetime from the actual minting clock in seconds.
    pub maximum_lifetime_seconds: u64,
    /// Bounds additional seconds beyond the trusted job's expected end.
    pub lifetime_margin_seconds: u64,
    /// Excludes this key at and after this Unix timestamp, when configured.
    pub retirement: Option<u64>,
}

impl StaticWorkloadIssuer {
    #[cfg(feature = "std")]
    fn policy(&self) -> Result<crate::workload::IssuerPolicy, ConfigError> {
        use terrane_format::auth::IssuerKey;

        let public_key = public_key(&self.public_key)?;
        crate::workload::IssuerPolicy::new(
            IssuerKey {
                issuer: self.issuer.clone(),
                key_id: self.key_id.clone(),
                public_key,
                retirement: self.retirement,
            },
            self.maximum_lifetime_seconds,
            self.lifetime_margin_seconds,
        )
        .map_err(|_| ConfigError::Invalid("invalid static workload issuer lifetime or identity"))
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if !super::absolute_path(&self.signing_key_file)
            || self.signing_key_file == "/"
            || self.owner_uid == u32::MAX
        {
            return Err(ConfigError::Invalid(
                "invalid static workload signing-file policy",
            ));
        }
        #[cfg(feature = "std")]
        {
            self.policy()?;
            Ok(())
        }
        #[cfg(not(feature = "std"))]
        {
            Err(ConfigError::Invalid(
                "static workload issuers require std support",
            ))
        }
    }
}

pub(super) fn validate(
    issuers: &BTreeMap<String, StaticWorkloadIssuer>,
) -> Result<(), ConfigError> {
    let mut authorities = BTreeSet::new();
    for (name, issuer) in issuers {
        if name.is_empty() || !authorities.insert((&issuer.issuer, &issuer.key_id)) {
            return Err(ConfigError::Invalid(
                "ambiguous static workload issuer configuration",
            ));
        }
        issuer.validate()?;
    }
    Ok(())
}

#[cfg(feature = "std")]
fn public_key(encoded: &str) -> Result<[u8; 32], ConfigError> {
    let invalid =
        || ConfigError::Invalid("static workload public key requires 64 lowercase hex digits");
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid());
    }
    let mut key = [0; 32];
    let (pairs, _) = encoded.as_bytes().as_chunks::<2>();
    for (target, pair) in key.iter_mut().zip(pairs) {
        let digit = |byte| {
            if byte <= b'9' {
                byte - b'0'
            } else {
                byte - b'a' + 10
            }
        };
        *target = (digit(pair[0]) << 4) | digit(pair[1]);
    }
    Ok(key)
}
