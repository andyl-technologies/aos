//! Release-destination checks for the client profile baked into disk and OCI images.
//!
//! The Nix `aos.release` projection supplies this JSON contract:
//!
//! ```json
//! {
//!   "enabled": true,
//!   "tier": "testing",
//!   "registry": "andyl/experimental",
//!   "rootEpoch": 1,
//!   "clientName": "andyl-experimental",
//!   "registryOrigin": "https://cdn.aos.andyl.org",
//!   "hubUrl": "https://aos.andyl.org",
//!   "url": "https://cdn.aos.andyl.org/andyl/experimental/",
//!   "channel": "edge",
//!   "trustKeys": ["andyl-experimental:Ed25519:<OpenSSH public-key blob>"],
//!   "rootOwnerSigners": ["andyl-experimental-provenance-v1"],
//!   "warning": "Experimental image; not for production workloads."
//! }
//! ```
//!
//! The profile is checked against the release plan before its artifacts are
//! built or signed. Selecting a testing system variant cannot silently redirect
//! an image's package manager to main, or authorize publishing that image there.

use anyhow::{Context as _, Result, bail};
use serde::Deserialize;

use crate::registry::{RegistryTier, channel_kind, registry_policy};

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
    /// HTTPS delivery origin of the deployment receiving the artifacts.
    #[serde(default = "production_registry_origin")]
    pub registry_origin: String,
    /// HTTPS control origin of the deployment receiving the artifacts.
    #[serde(default = "production_hub_url")]
    pub hub_url: String,
    /// Canonical registry URL installed in the package-manager configuration.
    pub url: String,
    /// Default update channel installed in both artifact forms.
    pub channel: String,
    /// Ed25519 public trust lines installed for the selected registry alias.
    pub trust_keys: Vec<String>,
    /// Provenance key ids the baked package manager trusts for shared-root
    /// ownership; every id must be a provenance signer the plan can use.
    #[serde(default)]
    pub root_owner_signers: Vec<String>,
    /// User-visible lifecycle notice, required for testing and `edge` artifacts.
    pub warning: String,
}

impl ArtifactProfile {
    /// Requires this artifact's client configuration to match its release destination.
    ///
    /// The baked default channel must have a kind the registry tier carries:
    /// `edge` only for testing registries, any kind for `andyl/main`. Testing
    /// artifacts and `edge` artifacts on any registry must carry a lifecycle
    /// warning, because neither comes with a support promise.
    ///
    /// # Errors
    /// Returns an error for a disabled profile, a registry or tier crossover,
    /// a channel kind outside the tier, a different root epoch, a different
    /// client URL or alias, absent or malformed trust keys, or an absent
    /// warning on a testing or `edge` artifact.
    pub fn require_release(&self, registry: &str) -> Result<()> {
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
        policy.require_release(std::slice::from_ref(&self.channel))?;

        let expected_alias = match policy.tier() {
            RegistryTier::Production => "andyl".to_owned(),
            RegistryTier::Testing => registry.replace('/', "-"),
        };
        if self.client_name != expected_alias
            || self.url != format!("{}/{registry}/", self.registry_origin)
        {
            bail!("artifact package-manager alias or URL differs from its registry");
        }
        require_https_origin(&self.registry_origin)?;
        require_https_origin(&self.hub_url)?;

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
        let unsupported_stream =
            policy.tier() == RegistryTier::Testing || channel_kind(&self.channel)? == "edge";
        if unsupported_stream && self.warning.trim().is_empty() {
            bail!("testing and edge artifacts require a user-visible lifecycle warning");
        }
        Ok(())
    }

    /// Requires every baked root-owner signer to be a planned provenance key.
    ///
    /// The package manager grants shared-root ownership to packages whose
    /// provenance is signed by these ids, so an image must not trust an id
    /// the release cannot sign with: that would either bake a dead trust
    /// entry or, worse, trust a key outside the release's signer roster.
    ///
    /// # Errors
    /// Returns an error when a baked id is not among `provenance_key_ids`.
    pub fn require_root_owner_signers(&self, provenance_key_ids: &[String]) -> Result<()> {
        for signer in &self.root_owner_signers {
            if !provenance_key_ids.contains(signer) {
                bail!("artifact root-owner signer '{signer}' is not a planned provenance key");
            }
        }
        Ok(())
    }

    /// Requires the baked Hub origin to match the selected publication deployment.
    ///
    /// # Errors
    /// Returns an error for an invalid origin or a different publication destination.
    pub fn require_hub(&self, origin: &str) -> Result<()> {
        require_https_origin(&self.hub_url)?;
        require_https_origin(origin)?;
        if self.hub_url != origin {
            bail!("artifact Hub origin differs from the publication deployment");
        }
        Ok(())
    }
}

fn production_registry_origin() -> String {
    "https://cdn.aos.andyl.org".into()
}

fn production_hub_url() -> String {
    "https://aos.andyl.org".into()
}

// Match the Nix profile's HTTPS origin grammar without accepting credentials,
// paths, or query components as part of a deployment identity.
fn require_https_origin(origin: &str) -> Result<()> {
    let authority = origin
        .strip_prefix("https://")
        .context("release deployment origins require HTTPS")?;
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    if host.is_empty()
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        bail!("release deployment origin has an invalid hostname");
    }
    if let Some(port) = port {
        let port = port.parse::<u16>().context("invalid release origin port")?;
        if port == 0 {
            bail!("release origin port must be positive");
        }
    }
    Ok(())
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
            registry_origin: production_registry_origin(),
            hub_url: production_hub_url(),
            url: format!("https://cdn.aos.andyl.org/{registry}/"),
            channel: if testing { "edge" } else { "stable" }.into(),
            trust_keys: vec![aos_registry_surface::sshsig::trusted_key_line(&alias, &key)],
            root_owner_signers: vec![format!("{alias}-provenance-v1")],
            warning: "Experimental image; not for production workloads.".into(),
        }
    }

    #[test]
    fn root_owner_signers_decode_by_default_and_must_be_planned_provenance_keys() {
        let value = serde_json::json!({
            "enabled": true,
            "tier": "testing",
            "registry": "andyl/experimental",
            "rootEpoch": registry_policy("andyl/experimental").unwrap().root_epoch(),
            "clientName": "andyl-experimental",
            "url": "https://cdn.aos.andyl.org/andyl/experimental/",
            "channel": "edge",
            "trustKeys": profile("andyl/experimental").trust_keys,
            "warning": "Experimental image; not for production workloads."
        });
        let decoded: ArtifactProfile = serde_json::from_value(value).unwrap();
        assert!(decoded.root_owner_signers.is_empty());
        assert!(decoded.require_root_owner_signers(&[]).is_ok());

        let artifact = profile("andyl/experimental");
        let planned = vec!["andyl-experimental-provenance-v1".to_owned()];
        assert!(artifact.require_root_owner_signers(&planned).is_ok());
        assert!(artifact.require_root_owner_signers(&[]).is_err());
        assert!(
            artifact
                .require_root_owner_signers(&["andyl-main-provenance-v1".to_owned()])
                .is_err()
        );
    }

    #[test]
    fn artifact_destinations_cannot_cross_registry_or_epoch_boundaries() {
        for registry in ["andyl/main", "andyl/experimental", "andyl/experimental-v2"] {
            let artifact = profile(registry);
            assert!(artifact.require_release(registry).is_ok());
            for other in ["andyl/main", "andyl/experimental", "andyl/experimental-v2"] {
                if other != registry {
                    assert!(artifact.require_release(other).is_err());
                }
            }
        }
    }

    #[test]
    fn baked_channels_follow_the_registry_tier() {
        for (registry, channel, allowed) in [
            ("andyl/experimental", "edge", true),
            ("andyl/experimental", "candidate", false),
            ("andyl/experimental-v2", "stable", false),
            ("andyl/main", "edge", true),
            ("andyl/main", "candidate", true),
            ("andyl/main", "stable", true),
            ("andyl/main", "stable-2026.3", true),
        ] {
            let mut artifact = profile(registry);
            artifact.channel = channel.into();
            assert_eq!(
                artifact.require_release(registry).is_ok(),
                allowed,
                "{registry} {channel}"
            );
        }
    }

    #[test]
    fn main_edge_artifacts_keep_their_warning_while_supported_channels_may_drop_it() {
        let mut edge = profile("andyl/main");
        edge.channel = "edge".into();
        assert!(edge.require_release("andyl/main").is_ok());
        edge.warning.clear();
        assert!(edge.require_release("andyl/main").is_err());

        let mut stable = profile("andyl/main");
        stable.warning.clear();
        assert!(stable.require_release("andyl/main").is_ok());
    }

    #[test]
    fn testing_clients_cannot_fall_back_to_main_or_drop_their_warning() {
        let valid = profile("andyl/experimental");
        for change in [
            |profile: &mut ArtifactProfile| {
                profile.url = "https://cdn.aos.andyl.org/andyl/main/".into()
            },
            |profile: &mut ArtifactProfile| {
                profile.url = "https://aos.andyl.org/andyl/experimental/".into()
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
            assert!(invalid.require_release("andyl/experimental").is_err());
        }
    }
}
