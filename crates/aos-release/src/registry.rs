//! Closed registry identities and release-channel policy.
//!
//! `andyl/main` and `andyl/testing` are separate security and assurance
//! domains. Mutable channels classify releases inside a registry; they do not
//! replace that boundary. A destructive testing-root reset advances the
//! registry identity (`andyl/testing-v2`, `andyl/testing-v3`, and so on), so an
//! old image cannot silently accept a replacement out-of-band root.
//!
//! Channels have a *kind*: `edge`, `candidate`, or `stable`. A per-train
//! channel such as `stable-2026.3` has kind `stable`; the kind is the prefix
//! before the first `-`. The testing tier carries only `edge`; the production
//! tier carries `candidate` and `stable` and never `edge`.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::artifact::require_identifier;

/// Supported production registry identity.
pub const MAIN_REGISTRY: &str = "andyl/main";
/// First-epoch experimental registry identity.
pub const TESTING_REGISTRY: &str = "andyl/testing";

/// Every channel kind, in maturity order.
pub const CHANNEL_KINDS: [&str; 3] = ["edge", "candidate", "stable"];

/// Pipeline assurance attached to a supported registry identity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RegistryTier {
    /// Strictly assured releases in every software channel.
    Production,
    /// Releases from the experimental build and publication pipeline.
    Testing,
}

impl RegistryTier {
    /// Returns the exact public spelling used by contracts and plans.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Testing => "testing",
        }
    }

    /// Returns the channel kinds a registry of this tier may carry.
    #[must_use]
    pub const fn allowed_channel_kinds(self) -> &'static [&'static str] {
        match self {
            Self::Testing => &["edge"],
            Self::Production => &["candidate", "stable"],
        }
    }
}

impl std::fmt::Display for RegistryTier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
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

    /// Returns the channel kinds this registry may carry.
    #[must_use]
    pub const fn allowed_channel_kinds(self) -> &'static [&'static str] {
        self.tier.allowed_channel_kinds()
    }

    /// Requires every channel name to have a kind this registry carries.
    ///
    /// # Errors
    /// Returns an error for a malformed channel name or a channel kind outside
    /// the tier's closed set, such as `edge` on `andyl/main`.
    pub fn require_release(self, channels: &[String]) -> Result<()> {
        for channel in channels {
            let kind = channel_kind(channel)?;
            if !self.allowed_channel_kinds().contains(&kind) {
                bail!(
                    "channel {channel} ({kind}) is not carried by the {} registry tier",
                    self.tier
                );
            }
        }
        Ok(())
    }
}

/// Returns the kind of a channel name: the prefix before its first `-`.
///
/// # Errors
/// Returns an error for a malformed channel identifier or a kind other than
/// `edge`, `candidate`, or `stable`.
pub fn channel_kind(channel: &str) -> Result<&str> {
    require_identifier(channel, "release channel")?;
    let kind = channel.split_once('-').map_or(channel, |(kind, _)| kind);
    if !CHANNEL_KINDS.contains(&kind) {
        bail!("unsupported release channel kind: {channel}");
    }
    Ok(kind)
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
    fn testing_carries_edge_only_and_production_never_carries_edge() {
        for registry in [TESTING_REGISTRY, "andyl/testing-v2"] {
            let policy = registry_policy(registry).unwrap();
            assert!(!policy.requires_production_assurance());
            assert!(policy.require_release(&["edge".into()]).is_ok());
            assert!(policy.require_release(&["candidate".into()]).is_err());
            assert!(policy.require_release(&["stable".into()]).is_err());
        }

        let main = registry_policy(MAIN_REGISTRY).unwrap();
        assert!(main.requires_production_assurance());
        assert!(main.require_release(&["edge".into()]).is_err());
        assert!(
            main.require_release(&["candidate".into(), "stable".into(), "stable-2026.3".into()])
                .is_ok()
        );
        assert!(main.require_release(&["unknown".into()]).is_err());
    }

    #[test]
    fn channel_kind_is_the_prefix_before_the_first_dash() {
        assert_eq!(channel_kind("edge").unwrap(), "edge");
        assert_eq!(channel_kind("stable-2026.3").unwrap(), "stable");
        assert_eq!(channel_kind("candidate-2026.10").unwrap(), "candidate");
        assert!(channel_kind("nightly").is_err());
        assert!(channel_kind("stable 2026").is_err());
        assert!(channel_kind("").is_err());
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

    #[test]
    fn registry_tier_uses_kebab_case_on_the_wire() {
        assert_eq!(
            serde_json::to_string(&RegistryTier::Production).unwrap(),
            "\"production\""
        );
        let parsed: RegistryTier = serde_json::from_str("\"testing\"").unwrap();
        assert_eq!(parsed, RegistryTier::Testing);
    }
}
