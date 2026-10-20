//! Installed package and boot generation state.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Opaque retained state emitted and interpreted by the selected boot provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootProviderState {
    /// Provider-owned schema identifier for the opaque evidence value.
    pub schema: String,
    /// Provider-owned retained state or checked observation evidence.
    pub evidence: serde_json::Value,
}

/// Identifies the exact authenticated native module library carried by an image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleLibraryIdentity {
    /// Locates the immutable library artifact root.
    pub store_path: String,
    /// Contains the admitted NAR identity as `sha256:<lowercase-hex>`.
    pub nar_hash: String,
    /// Contains the admitted NAR byte length.
    pub nar_size: u64,
}

/// One authenticated image-generation independent of its boot implementation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageGeneration {
    /// Image-generation number (names the `image-gen-N/` directory).
    pub number: u32,
    /// Immutable locator for the selected provider's boot-artifact contract.
    pub boot_artifact_contract: String,
    /// Opaque generation state retained by the selected boot provider.
    pub boot_provider_state: BootProviderState,
    /// Store path of the sysroot toplevel this image was built from.
    pub toplevel: String,
    /// Sysroot package name used for provenance.
    pub package_name: String,
    /// Sysroot package version.
    pub version: String,
    /// Authenticated `/var` format contract carried by this image.
    pub state_version: String,
    /// Exact native ability executor store path carried by this image.
    pub native_executor_ref: String,
    /// Source registry the sysroot package was installed from.
    pub registry: String,
    /// Resolved kernel store path (kernel-change detection across generations).
    #[serde(default)]
    pub kernel_path: Option<String>,
    /// Pins the exact admitted native module library used for image evaluation.
    pub module_library: ModuleLibraryIdentity,
    /// Locates the immutable native host evaluation input descriptor.
    pub evaluation_descriptor: String,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
}

/// Describes the durable phase or terminal result of a qualified image rollout.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageRolloutStatus {
    /// The candidate is the counted next-boot selection.
    Staged,
    /// The candidate booted and is awaiting strict configuration health.
    CandidateBooted,
    /// The candidate passed strict activation and native ability health.
    Succeeded,
    /// The candidate failed strict health and the prior image returned.
    HealthFailed,
    /// Counted boots exhausted before candidate activation; the prior image returned.
    BootFailed,
}

/// Records one state-compatible, drained image rollout.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageRollout {
    /// Versioned schema for durable boot-side interpretation.
    pub schema: String,
    /// Image generation selected as the rollout candidate.
    pub candidate: u32,
    /// Known-good image generation retained for fallback.
    pub prior: u32,
    /// Exact `/var` format contract shared by candidate and prior.
    pub state_version: String,
    /// Current rollout phase or terminal result.
    pub status: ImageRolloutStatus,
}

/// Persistent state for the image-generation axis
/// stored at `/var/lib/profiles/image/state.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageGenerationState {
    /// Provider-neutral state schema written by this release.
    pub schema: String,
    /// The image-gen the live kernel booted (cross-checked against
    /// `/etc/os-release`, never trusted from the network).
    pub running: u32,
    /// A staged image-generation that has not yet been observed running.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<u32>,
    /// Opaque selected-provider state for selection, recovery, and boot evidence.
    pub boot_provider_state: BootProviderState,
    /// Qualified rollout currently crossing the reboot boundary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_rollout: Option<ImageRollout>,
    /// Most recently completed qualified rollout outcome.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_rollout: Option<ImageRollout>,
    /// All recorded image-generations, in creation order.
    #[serde(default)]
    pub generations: Vec<ImageGeneration>,
}

impl ImageGenerationState {
    /// Looks up the currently-running image-generation record, if recorded.
    pub fn running_generation(&self) -> Option<&ImageGeneration> {
        self.generations.iter().find(|g| g.number == self.running)
    }

    /// Validates the provider-neutral identity envelope and generation graph.
    ///
    /// Provider-owned evidence remains opaque here. The selected provider
    /// validates that evidence against its declared schema before acting on it.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported state schema, malformed contract or
    /// provider-schema identities, non-object provider evidence, duplicate
    /// generations, or state references to absent generations.
    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema != "aos.image-generation-state/v1" {
            bail!("unsupported image generation state schema {}", self.schema);
        }
        validate_boot_provider_state(&self.boot_provider_state)?;

        let mut generation_numbers = BTreeSet::new();
        for generation in &self.generations {
            if !generation_numbers.insert(generation.number) {
                bail!("duplicate image generation {}", generation.number);
            }
            validate_image_store_root(&generation.boot_artifact_contract).with_context(|| {
                format!(
                    "validating image generation {} boot-artifact contract",
                    generation.number
                )
            })?;
            validate_boot_provider_state(&generation.boot_provider_state)?;
            for root in [
                &generation.toplevel,
                &generation.native_executor_ref,
                &generation.module_library.store_path,
            ] {
                validate_image_store_root(root)?;
            }
            let descriptor = std::path::Path::new(&generation.evaluation_descriptor);
            let (root, suffix) = aos_deployment::nix::store_root_and_suffix(descriptor)?;
            if suffix.as_os_str().is_empty()
                || root.join(&suffix) != descriptor
                || generation.evaluation_descriptor.contains("//")
                || generation
                    .evaluation_descriptor
                    .split('/')
                    .any(|part| part == "." || part == "..")
            {
                bail!("native image evaluation descriptor is not a canonical store member");
            }
            aos_core::Sha256Digest::parse(&generation.module_library.nar_hash)
                .context("native module library requires a canonical SHA-256 NAR identity")?;
            if generation.module_library.nar_size == 0 {
                bail!("native module library NAR size is empty");
            }
        }

        if self.generations.is_empty() {
            if self.running != 0 || self.pending.is_some() {
                bail!(
                    "empty image state must use running generation zero and no pending generation"
                );
            }
            return Ok(());
        }
        if !generation_numbers.contains(&self.running) {
            bail!("running image generation {} is absent", self.running);
        }
        if let Some(pending) = self.pending
            && !generation_numbers.contains(&pending)
        {
            bail!("pending image generation {pending} is absent");
        }
        for rollout in self.active_rollout.iter().chain(&self.last_rollout) {
            if !generation_numbers.contains(&rollout.candidate)
                || !generation_numbers.contains(&rollout.prior)
            {
                bail!("image rollout references an absent generation");
            }
        }
        Ok(())
    }
}

fn validate_image_store_root(value: &str) -> Result<()> {
    let path = std::path::Path::new(value);
    let (root, suffix) = aos_deployment::nix::store_root_and_suffix(path)?;
    if !suffix.as_os_str().is_empty() || root != path || value.contains("//") {
        bail!("image identity does not name a canonical native store root");
    }
    Ok(())
}

fn validate_boot_provider_state(state: &BootProviderState) -> Result<()> {
    let schema = state.schema.as_bytes();
    if schema.is_empty()
        || schema.len() > 200
        || !schema.iter().all(|byte| byte.is_ascii_graphic())
        || !state.schema.contains('/')
    {
        bail!("boot-provider state schema is not a bounded portable identifier");
    }
    if !state.evidence.is_object() {
        bail!("boot-provider evidence must be a JSON object");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    /// The image-generation axis round-trips provider-neutral identity and opaque provider state.
    #[test]
    fn image_generation_state_round_trip() {
        let state = ImageGenerationState {
            schema: "aos.image-generation-state/v1".into(),
            running: 1,
            pending: Some(2),
            boot_provider_state: BootProviderState {
                schema: "aos.test.boot-state/v1".into(),
                evidence: serde_json::json!({"selected": 2}),
            },
            active_rollout: Some(ImageRollout {
                schema: "aos.image-rollout/v1".into(),
                candidate: 2,
                prior: 1,
                state_version: "7".into(),
                status: ImageRolloutStatus::Staged,
            }),
            last_rollout: None,
            generations: vec![
                ImageGeneration {
                    number: 1,
                    boot_artifact_contract:
                        "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-boot-contract-1".into(),
                    boot_provider_state: BootProviderState {
                        schema: "aos.test.boot-generation-state/v1".into(),
                        evidence: serde_json::json!({"installed-entry": "entry-1"}),
                    },
                    toplevel: "/nix/store/top1-server".into(),
                    package_name: "server".into(),
                    version: "2026.06.1".into(),
                    state_version: "7".into(),
                    native_executor_ref: "/nix/store/executor-1".into(),
                    registry: "core".into(),
                    kernel_path: Some("/nix/store/k1-linux".into()),
                    module_library: ModuleLibraryIdentity {
                        store_path: "/nix/store/11111111111111111111111111111111-module-library"
                            .into(),
                        nar_hash: format!("sha256:{}", "0".repeat(64)),
                        nar_size: 1,
                    },
                    evaluation_descriptor:
                        "/nix/store/22222222222222222222222222222222-evaluation/evaluation.json"
                            .into(),
                    created_at: "2026-06-01T00:00:00Z".into(),
                },
                ImageGeneration {
                    number: 2,
                    boot_artifact_contract:
                        "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-boot-contract-2".into(),
                    boot_provider_state: BootProviderState {
                        schema: "aos.test.boot-generation-state/v1".into(),
                        evidence: serde_json::json!({"installed-entry": "entry-2"}),
                    },
                    toplevel: "/nix/store/top2-server".into(),
                    package_name: "server".into(),
                    version: "2026.06.2".into(),
                    state_version: "7".into(),
                    native_executor_ref: "/nix/store/executor-2".into(),
                    registry: "core".into(),
                    kernel_path: Some("/nix/store/k2-linux".into()),
                    module_library: crate::types::ModuleLibraryIdentity {
                        store_path: "/nix/store/11111111111111111111111111111111-module-library"
                            .into(),
                        nar_hash: format!("sha256:{}", "0".repeat(64)),
                        nar_size: 1,
                    },
                    evaluation_descriptor:
                        "/nix/store/22222222222222222222222222222222-evaluation/evaluation.json"
                            .into(),
                    created_at: "2026-06-02T00:00:00Z".into(),
                },
            ],
        };
        let json = serde_json::to_string(&state).unwrap();
        let parsed: ImageGenerationState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.running, 1);
        assert_eq!(parsed.pending, Some(2));
        assert_eq!(
            parsed.active_rollout.as_ref().map(|rollout| rollout.status),
            Some(ImageRolloutStatus::Staged)
        );
        let running = parsed.running_generation().unwrap();
        assert_eq!(running.module_library.nar_size, 1);
        assert!(running.evaluation_descriptor.ends_with("/evaluation.json"));
        assert_eq!(
            parsed.generations[1].boot_provider_state.evidence["installed-entry"],
            "entry-2"
        );

        for required in ["state_version", "native_executor_ref"] {
            let mut incomplete = serde_json::to_value(&state).unwrap();
            incomplete["generations"][0]
                .as_object_mut()
                .unwrap()
                .remove(required);

            let error = serde_json::from_value::<ImageGenerationState>(incomplete)
                .expect_err("the final image-generation identity must be complete");
            assert!(error.to_string().contains(required));
        }
    }
}
