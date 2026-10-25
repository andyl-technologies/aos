//! Reopens explicitly trusted local repositories without creating authority.
//!
//! Only an exact `bucket(file:///...)` store leaf is implemented. Composite or
//! remote expressions are rejected before credential I/O. Reopening uses the
//! existing protected authority and immutable genesis; it never creates seeds,
//! tokens, grants, or a replacement chunk profile.
//!
//! ```toml
//! [local_repository]
//! authority_directory = "/var/lib/terrane/authority"
//! issuer = "operator"
//! key_id = "current"
//! owner_uid = 1001
//! store_name = "local"
//! domain = "private:owner"
//! default_private_domain = "private:owner"
//! current_reference = "refs/heads/_/main"
//! policy_authority = "refs/heads/_/main"
//! acl = [{ principal = "owner", verbs = ["read"] }]
//! [local_repository.timing]
//! maximum_ms = 30000
//! grace_ms = 60000
//! margin_ms = 10000
//! ```

use serde::Deserialize;
use terrane_format::{
    properties::Domain,
    refs::{RefClass, RefName},
};

use super::ConfigError;

/// Holds all explicit trust inputs needed to reopen an existing local repository.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedLocalRepository {
    /// Absolute protected sibling authority directory containing existing records.
    pub authority_directory: String,
    /// Trusted issuer name, independent of loaded token claims.
    pub issuer: String,
    /// Trusted issuer rotation key identifier.
    pub key_id: String,
    /// Expected owner of both authority and bucket state.
    pub owner_uid: u32,
    /// Explicit authority store name used by recorded policy interpretation.
    pub store_name: String,
    /// Canonical disclosure domain physically assigned to the bucket.
    pub domain: String,
    /// Canonical private default for original policy interpretation.
    pub default_private_domain: String,
    /// Existing head authenticated during reopening, never derived from exposures.
    pub current_reference: String,
    /// Separate trusted current policy reference for fixed-commit requests.
    pub policy_authority: Option<String>,
    /// Explicit trusted bootstrap ACL; an empty list grants nothing.
    pub acl: Vec<TrustedAclEntry>,
    /// Explicit publication timing relative to collection grace.
    pub timing: LocalCommitTiming,
}

/// Holds one configured bootstrap ACL entry without manufacturing capabilities.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedAclEntry {
    /// Existing principal or group label.
    pub principal: String,
    /// Registered verbs; an empty list is an explicit deny entry.
    pub verbs: Vec<TrustedAclVerb>,
}

/// Selects an existing registered authorization verb in the TOML ACL.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum TrustedAclVerb {
    /// Reads reachable content and metadata.
    Read,
    /// Forks the source reference.
    Fork,
    /// Advances the matched reference.
    Commit,
    /// Creates a tag of reachable content.
    Tag,
    /// Changes authority-bearing policy.
    Admin,
}

/// Holds explicit inputs to the existing publication timing validator.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalCommitTiming {
    /// Maximum publication duration in milliseconds.
    pub maximum_ms: u64,
    /// Collection grace window in milliseconds.
    pub grace_ms: u64,
    /// Reserved safety margin within collection grace, in milliseconds.
    pub margin_ms: u64,
}

impl TrustedLocalRepository {
    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        if !super::absolute_path(&self.authority_directory)
            || self.issuer.is_empty()
            || self.key_id.is_empty()
            || self.owner_uid == u32::MAX
            || self.store_name.is_empty()
            || Domain::parse(&self.domain).is_err()
            || !matches!(
                Domain::parse(&self.default_private_domain),
                Ok(Domain::Private(_))
            )
            || !head_reference(&self.current_reference)
            || self
                .policy_authority
                .as_ref()
                .is_some_and(|reference| !head_reference(reference))
            || self.acl.iter().any(|entry| entry.principal.is_empty())
        {
            return Err(ConfigError::Invalid(
                "invalid trusted local repository configuration",
            ));
        }
        #[cfg(feature = "std")]
        {
            self.timing.validated()?;
            Ok(())
        }
        #[cfg(not(feature = "std"))]
        {
            Err(ConfigError::Invalid(
                "local repositories require std support",
            ))
        }
    }
}

fn head_reference(reference: &str) -> bool {
    RefName::parse(reference).is_ok_and(|name| name.class() == RefClass::Heads)
        && terrane_format::bucket::BucketKey::parse(reference).is_ok()
}

impl LocalCommitTiming {
    #[cfg(feature = "std")]
    fn validated(&self) -> Result<crate::ref_advance::CommitTiming, ConfigError> {
        use std::time::Duration;
        crate::ref_advance::CommitTiming::new(
            Duration::from_millis(self.maximum_ms),
            Duration::from_millis(self.grace_ms),
            Duration::from_millis(self.margin_ms),
        )
        .map_err(|_| ConfigError::Invalid("invalid local repository publication timing"))
    }
}

#[cfg(all(feature = "std", unix))]
mod maintenance;
#[cfg(all(feature = "std", unix))]
mod open;
#[cfg(all(feature = "std", unix))]
pub use open::LocalOpenError;
