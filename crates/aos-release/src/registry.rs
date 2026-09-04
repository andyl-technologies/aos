//! Closed registry identities and release-channel policy.
//!
//! `andyl/main` and `andyl/testing` are separate security and lifecycle
//! domains. Mutable channels classify releases inside a registry; they do not
//! replace that boundary. A destructive testing-root reset advances the
//! registry identity (`andyl/testing-v2`, `andyl/testing-v3`, and so on), so an
//! old image cannot silently accept a replacement out-of-band root.

use anyhow::{Result, bail};

use crate::plan::ReleaseClass;

/// Supported production registry identity.
pub const MAIN_REGISTRY: &str = "andyl/main";
/// First-epoch experimental registry identity.
pub const TESTING_REGISTRY: &str = "andyl/testing";

/// Operational lifecycle attached to a supported registry identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryTier {
    /// Supported release candidates and production releases.
    Production,
    /// Disposable experimental edge releases.
    Testing,
}

/// Validated release policy for one exact registry identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryPolicy {
    tier: RegistryTier,
    root_epoch: u64,
}

impl RegistryPolicy {
    /// Returns the registry's support tier.
    #[must_use]
    pub const fn tier(self) -> RegistryTier {
        self.tier
    }

    /// Returns the out-of-band trust-root epoch.
    #[must_use]
    pub const fn root_epoch(self) -> u64 {
        self.root_epoch
    }

    /// Validates a release class and its intended channel against this registry.
    ///
    /// # Errors
    ///
    /// Returns an error when an experimental edge release targets main, a
    /// supported release targets testing, or a channel crosses the registry's
    /// lifecycle boundary.
    pub fn require_release(self, class: ReleaseClass, channels: &[String]) -> Result<()> {
        let class_allowed = match self.tier {
            RegistryTier::Production => matches!(
                class,
                ReleaseClass::Candidate | ReleaseClass::Stable | ReleaseClass::Emergency
            ),
            RegistryTier::Testing => class == ReleaseClass::Edge,
        };
        if !class_allowed {
            bail!("release class is not authorized by the selected registry tier");
        }

        for channel in channels {
            let channel_allowed = match self.tier {
                RegistryTier::Production => matches!(channel.as_str(), "candidate" | "stable"),
                RegistryTier::Testing => channel == "edge",
            };
            if !channel_allowed {
                bail!("release channel is not authorized by the selected registry tier");
            }
        }
        Ok(())
    }
}

/// Validates and classifies an exact signed registry identity.
///
/// # Errors
///
/// Returns an error for an unknown registry or a malformed testing-root epoch.
pub fn registry_policy(identity: &str) -> Result<RegistryPolicy> {
    if identity == MAIN_REGISTRY {
        return Ok(RegistryPolicy {
            tier: RegistryTier::Production,
            root_epoch: 1,
        });
    }
    if identity == TESTING_REGISTRY {
        return Ok(RegistryPolicy {
            tier: RegistryTier::Testing,
            root_epoch: 1,
        });
    }
    if let Some(epoch) = identity.strip_prefix("andyl/testing-v") {
        if epoch.is_empty()
            || !epoch.bytes().all(|byte| byte.is_ascii_digit())
            || (epoch.len() > 1 && epoch.starts_with('0'))
        {
            bail!("testing registry epochs must use canonical decimal notation");
        }
        let root_epoch = epoch
            .parse::<u64>()
            .map_err(|_| anyhow::anyhow!("testing registry root epoch is malformed"))?;
        if root_epoch < 2 {
            bail!("testing registry epochs after the first begin at v2");
        }
        return Ok(RegistryPolicy {
            tier: RegistryTier::Testing,
            root_epoch,
        });
    }
    bail!("unsupported AOS release registry: {identity}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registries_are_separate_lifecycle_domains() {
        let main = registry_policy(MAIN_REGISTRY).unwrap();
        let testing = registry_policy(TESTING_REGISTRY).unwrap();

        assert!(
            main.require_release(ReleaseClass::Stable, &["stable".to_owned()])
                .is_ok()
        );
        assert!(
            testing
                .require_release(ReleaseClass::Edge, &["edge".to_owned()])
                .is_ok()
        );
        assert!(
            main.require_release(ReleaseClass::Edge, &["edge".to_owned()])
                .is_err()
        );
        assert!(
            testing
                .require_release(ReleaseClass::Stable, &["stable".to_owned()])
                .is_err()
        );
    }

    #[test]
    fn testing_root_resets_advance_the_registry_identity() {
        assert_eq!(registry_policy(TESTING_REGISTRY).unwrap().root_epoch(), 1);
        assert_eq!(registry_policy("andyl/testing-v2").unwrap().root_epoch(), 2);
        assert_eq!(
            registry_policy("andyl/testing-v19").unwrap().root_epoch(),
            19
        );
        assert!(registry_policy("andyl/testing-v1").is_err());
        assert!(registry_policy("andyl/testing-v02").is_err());
        assert!(registry_policy("andyl/testing-v+2").is_err());
        assert!(registry_policy("andyl/testing-v+02").is_err());
        assert!(registry_policy("andyl/nightly").is_err());
    }
}
