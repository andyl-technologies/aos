//! Release-destination checks for the client profile baked into disk and OCI images.
//!
//! The Nix `aos.release` projection supplies this JSON contract:
//!
//! ```json
//! {
//!   "enabled": true,
//!   "tier": "testing",
//!   "registry": "andyl/testing",
//!   "rootEpoch": 1,
//!   "clientName": "andyl-testing",
//!   "url": "https://cdn.aos.andyl.org/andyl/testing/",
//!   "channel": "edge",
//!   "trustKeys": ["andyl-testing:Ed25519:<OpenSSH public-key blob>"],
//!   "warning": "Experimental image; not for production workloads."
//! }
//! ```
//!
//! The profile is checked against the release plan before its artifacts are
//! built or signed. Selecting a testing system variant cannot silently redirect
//! an image's package manager to main, or authorize publishing that image there.

use anyhow::{Context as _, Result, bail};
use serde::Deserialize;

use crate::plan::ReleaseClass;
use crate::registry::{RegistryTier, registry_policy};

/// Evaluated client and support identity shared by a system's release artifacts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactProfile {
    /// Declares that the selected system is a public release artifact profile.
    pub enabled: bool,
    /// Selects the `production` or `testing` support tier.
    pub tier: String,
    /// Exact destination registry identity.
    pub registry: String,
    /// Trust-root epoch encoded in the registry identity.
    pub root_epoch: u64,
    /// Slash-free APM registry alias and trust-key prefix.
    pub client_name: String,
    /// Canonical registry URL installed in the package-manager configuration.
    pub url: String,
    /// Default update channel installed in both artifact forms.
    pub channel: String,
    /// Ed25519 public trust lines installed for the selected registry alias.
    pub trust_keys: Vec<String>,
    /// User-visible lifecycle notice, required for testing artifacts.
    pub warning: String,
}

impl ArtifactProfile {
    /// Requires this artifact's client configuration to match its release destination.
    ///
    /// # Errors
    /// Returns an error for a disabled profile, a registry or tier crossover,
    /// an incompatible channel or root epoch, a different client URL or alias,
    /// absent or malformed trust keys, or an absent testing warning.
    pub fn require_release(&self, registry: &str, class: ReleaseClass) -> Result<()> {
        if !self.enabled {
            bail!("selected system does not enable a public release artifact profile");
        }
        if self.registry != registry {
            bail!("artifact client registry differs from the release destination");
        }

        let policy = registry_policy(registry)?;
        let expected_tier = match policy.tier() {
            RegistryTier::Production => "production",
            RegistryTier::Testing => "testing",
        };
        if self.tier != expected_tier || self.root_epoch != policy.root_epoch() {
            bail!("artifact support tier or trust-root epoch differs from its registry");
        }
        policy.require_release(class, std::slice::from_ref(&self.channel))?;

        let expected_alias = match policy.tier() {
            RegistryTier::Production => "andyl".to_owned(),
            RegistryTier::Testing => registry.replace('/', "-"),
        };
        if self.client_name != expected_alias
            || self.url != format!("https://cdn.aos.andyl.org/{registry}/")
        {
            bail!("artifact package-manager alias or URL differs from its registry");
        }
        if self.trust_keys.is_empty() {
            bail!("release artifacts require a baked registry trust key");
        }
        for line in &self.trust_keys {
            let (alias, _) = aos_registry_surface::sshsig::trusted_key_ed25519(line)
                .context("artifact registry trust key is invalid")?;
            if alias != expected_alias {
                bail!("artifact trust-key alias differs from its registry");
            }
        }
        if policy.tier() == RegistryTier::Testing && self.warning.trim().is_empty() {
            bail!("testing artifacts require a user-visible lifecycle warning");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(registry: &str) -> ArtifactProfile {
        let testing = registry != "andyl/main";
        let alias = if testing {
            registry.replace('/', "-")
        } else {
            "andyl".into()
        };
        let key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]).verifying_key();
        ArtifactProfile {
            enabled: true,
            tier: if testing { "testing" } else { "production" }.into(),
            registry: registry.into(),
            root_epoch: registry_policy(registry).unwrap().root_epoch(),
            client_name: alias.clone(),
            url: format!("https://cdn.aos.andyl.org/{registry}/"),
            channel: if testing { "edge" } else { "stable" }.into(),
            trust_keys: vec![aos_registry_surface::sshsig::trusted_key_line(&alias, &key)],
            warning: "Experimental image; not for production workloads.".into(),
        }
    }

    #[test]
    fn artifact_destinations_cannot_cross_registry_or_epoch_boundaries() {
        for (registry, class) in [
            ("andyl/main", ReleaseClass::Stable),
            ("andyl/testing", ReleaseClass::Edge),
            ("andyl/testing-v2", ReleaseClass::Edge),
        ] {
            let artifact = profile(registry);
            assert!(artifact.require_release(registry, class).is_ok());
            for other in ["andyl/main", "andyl/testing", "andyl/testing-v2"] {
                if other != registry {
                    assert!(artifact.require_release(other, class).is_err());
                }
            }
        }
    }

    #[test]
    fn every_registry_can_bake_every_software_channel() {
        for registry in ["andyl/main", "andyl/testing", "andyl/testing-v2"] {
            for (class, channel) in [
                (ReleaseClass::Edge, "edge"),
                (ReleaseClass::Candidate, "candidate"),
                (ReleaseClass::Stable, "stable"),
            ] {
                let mut artifact = profile(registry);
                artifact.channel = channel.into();
                assert!(artifact.require_release(registry, class).is_ok());
            }
        }
    }

    #[test]
    fn testing_clients_cannot_fall_back_to_main_or_drop_their_warning() {
        let valid = profile("andyl/testing");
        for change in [
            |profile: &mut ArtifactProfile| {
                profile.url = "https://cdn.aos.andyl.org/andyl/main/".into()
            },
            |profile: &mut ArtifactProfile| {
                profile.url = "https://aos.andyl.org/andyl/testing/".into()
            },
            |profile: &mut ArtifactProfile| profile.client_name = "andyl".into(),
            |profile: &mut ArtifactProfile| profile.channel = "unknown".into(),
            |profile: &mut ArtifactProfile| profile.tier = "production".into(),
            |profile: &mut ArtifactProfile| profile.root_epoch = 2,
            |profile: &mut ArtifactProfile| profile.warning.clear(),
            |profile: &mut ArtifactProfile| profile.trust_keys.clear(),
            |profile: &mut ArtifactProfile| {
                profile.trust_keys = self::profile("andyl/main").trust_keys
            },
            |profile: &mut ArtifactProfile| profile.enabled = false,
        ] {
            let mut invalid = valid.clone();
            change(&mut invalid);
            assert!(
                invalid
                    .require_release("andyl/testing", ReleaseClass::Edge)
                    .is_err()
            );
        }
    }
}
