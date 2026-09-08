//! Closed registry identities and release-channel policy.
//!
//! `andyl/main` and `andyl/testing` are separate security and assurance
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

/// Pipeline assurance attached to a supported registry identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryTier {
    /// Strictly assured releases in every software channel.
    Production,
    /// Releases from the experimental build and publication pipeline.
    Testing,
}

/// Validated release policy for one exact registry identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryPolicy {
    tier: RegistryTier,
    root_epoch: u64,
}

impl RegistryPolicy {
    /// Returns the registry's pipeline assurance tier.
    #[must_use]
    pub const fn tier(self) -> RegistryTier {
        self.tier
    }

    /// Returns the out-of-band trust-root epoch.
    #[must_use]
    pub const fn root_epoch(self) -> u64 {
        self.root_epoch
    }

    /// Reports whether every release requires production pipeline assurance.
    #[must_use]
    pub const fn requires_production_assurance(self) -> bool {
        matches!(self.tier, RegistryTier::Production)
    }

    /// Validates channel names independently of the registry's assurance tier.
    ///
    /// # Errors
    /// Returns an error for a channel other than edge, candidate, or stable.
    pub fn require_release(self, _class: ReleaseClass, channels: &[String]) -> Result<()> {
        for channel in channels {
            if !matches!(channel.as_str(), "edge" | "candidate" | "stable") {
                bail!("unsupported release channel");
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
    fn registry_assurance_is_independent_of_software_maturity() {
        for registry in [MAIN_REGISTRY, TESTING_REGISTRY, "andyl/testing-v2"] {
            let policy = registry_policy(registry).unwrap();
            assert_eq!(
                policy.requires_production_assurance(),
                registry == MAIN_REGISTRY
            );
            for class in [
                ReleaseClass::Edge,
                ReleaseClass::Candidate,
                ReleaseClass::Stable,
                ReleaseClass::Emergency,
            ] {
                for channel in ["edge", "candidate", "stable"] {
                    assert!(policy.require_release(class, &[channel.into()]).is_ok());
                }
                assert!(policy.require_release(class, &["unknown".into()]).is_err());
            }
        }
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
