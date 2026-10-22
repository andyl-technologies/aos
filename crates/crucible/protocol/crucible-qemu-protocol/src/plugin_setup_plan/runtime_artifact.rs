//! Assembles plan thirteen with a separate immutable runtime-pair tail.
//!
//! ```text
//! CRUCSU13 | schema13/header56/total/A/S/W/Startup128/Purpose2520/Publisher736/zero
//! runtime192:u32 | zero:u32
//! App | Selectable | Workspace? | Startup | CRUCPUR8 | CRUCPSP3 | CRUCRTA1
//! ```
//!
//! Bytes authenticate no carrier, sealed alias, loaded image or retained owner.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use crate::deferred_cleanup::{DEFERRED_CLEANUP_PURPOSE_BYTES, DeferredCleanupPurpose};
use crate::runtime_artifact::{RUNTIME_ARTIFACT_PAIR_BYTES, RuntimeArtifactPair};

/// Retains plan-thirteen observations without issuing or funding runtime owners.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeArtifactPlanParts {
    /// Decoded app-random configuration.
    pub app_random: AppRandomBranchPlan,
    /// Decoded selectable catalog configuration.
    pub selectable: SelectableCatalogPlan,
    /// Exact physical publisher and dormant delegation observations.
    pub publisher: DeferredCleanupPurpose,
    /// Immutable file identities correlated with the same Source assignment.
    pub runtime: RuntimeArtifactPair,
}

impl PluginSetupPlan {
    /// Reports plan thirteen's extent before assembly or physical carrier birth.
    ///
    /// # Errors
    /// Refuses malformed nested plans, arithmetic overflow or the unchanged cap.
    pub fn preexec_runtime_artifact_encoded_len(
        &self,
        has_workspace: bool,
    ) -> Result<usize, PluginSetupPlanError> {
        checked_extent(self.preexec_deferred_cleanup_encoded_len(has_workspace)?)
    }

    /// Encodes plan thirteen with the exact separate runtime tail and binding.
    ///
    /// Nested app and selectable bodies allocate their existing outputs. The
    /// actual caller must fund simultaneous assembly before calling this codec.
    ///
    /// # Errors
    /// Refuses missing startup, malformed sections, foreign Source/process/account
    /// observations, unsupported artifact identities or excessive aggregate size.
    pub fn encode_preexec_runtime_artifact(
        &self,
        purpose: &[u8; PROCESS_PURPOSE_BYTES],
        workspace: Option<&[u8; DEVICE_DIGEST_PURPOSE_BYTES]>,
        publisher: &DeferredCleanupPurpose,
        runtime: &RuntimeArtifactPair,
    ) -> Result<Vec<u8>, PluginSetupPlanError> {
        let startup = self.startup_operation.as_ref().ok_or_else(invalid)?;
        preexec::validate_binding(startup, purpose, workspace.map(|bytes| bytes.as_slice()))?;
        super::deferred_cleanup::validate_source_binding(publisher, purpose)?;
        validate_binding(runtime, &publisher.publisher)?;
        let subscription = publisher.encode().map_err(|_| invalid())?;
        let artifacts = runtime.encode().map_err(|_| invalid())?;
        let total = self.preexec_runtime_artifact_encoded_len(workspace.is_some())?;

        let app = self.app_random_branch_plan.encode();
        let selectable = self
            .selectable_catalog_plan
            .encode()
            .map_err(|source| PluginSetupPlanError::Selectable { source })?;
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(b"CRUCSU13");
        // The unchanged aggregate cap bounds all framed lengths below u32::MAX.
        for word in [
            13,
            56,
            total as u32,
            app.len() as u32,
            selectable.len() as u32,
            workspace.map_or(0, |_| DEVICE_DIGEST_PURPOSE_BYTES as u32),
            STARTUP_OPERATION_BYTES as u32,
            PROCESS_PURPOSE_BYTES as u32,
            DEFERRED_CLEANUP_PURPOSE_BYTES as u32,
            0,
            RUNTIME_ARTIFACT_PAIR_BYTES as u32,
            0,
        ] {
            bytes.extend_from_slice(&word.to_be_bytes());
        }
        bytes.extend_from_slice(&app);
        bytes.extend_from_slice(&selectable);
        if let Some(workspace) = workspace {
            bytes.extend_from_slice(workspace);
        }
        bytes.extend_from_slice(&startup.encode());
        bytes.extend_from_slice(purpose);
        bytes.extend_from_slice(&subscription);
        bytes.extend_from_slice(&artifacts);
        Ok(bytes)
    }

    /// Decodes only plan thirteen with both independently validated tails.
    ///
    /// # Errors
    /// Refuses mixed editions, changed Source/account/process parents, malformed
    /// sections, excessive length, truncation and trailing bytes.
    pub fn decode_preexec_runtime_artifact_parts(
        bytes: &[u8],
    ) -> Result<RuntimeArtifactPlanParts, PluginSetupPlanError> {
        let (app_random, selectable) =
            preexec::decode_edition(bytes, preexec::Edition::RuntimeArtifact)?;
        let runtime_start = bytes.len() - RUNTIME_ARTIFACT_PAIR_BYTES;
        let publisher_start = runtime_start - DEFERRED_CLEANUP_PURPOSE_BYTES;
        let publisher = DeferredCleanupPurpose::decode(&bytes[publisher_start..runtime_start])
            .map_err(|_| invalid())?;
        let runtime =
            RuntimeArtifactPair::decode(&bytes[runtime_start..]).map_err(|_| invalid())?;
        Ok(RuntimeArtifactPlanParts {
            app_random,
            selectable,
            publisher,
            runtime,
        })
    }
}

pub(super) fn validate_binding(
    runtime: &RuntimeArtifactPair,
    publisher: &crate::publisher_subscription::PublisherPurpose,
) -> Result<(), PluginSetupPlanError> {
    if runtime.process_generation != publisher.process_generation
        || runtime.account_generation != publisher.account_generation
        || runtime.source_assignment != publisher.reservation
    {
        return Err(invalid());
    }
    Ok(())
}

fn checked_extent(ordinary: usize) -> Result<usize, PluginSetupPlanError> {
    let extra = 8 + RUNTIME_ARTIFACT_PAIR_BYTES;
    ordinary
        .checked_add(extra)
        .filter(|total| *total <= PLUGIN_SETUP_PLAN_MAX_BYTES)
        .ok_or(PluginSetupPlanError::PlanTooLarge {
            bytes: ordinary.saturating_add(extra),
            maximum: PLUGIN_SETUP_PLAN_MAX_BYTES,
        })
}

fn invalid() -> PluginSetupPlanError {
    PluginSetupPlanError::InvalidPreexecSection {
        section: "runtime-artifact assignment",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_extent_preserves_the_unchanged_aggregate_cap() {
        let extra = 8 + RUNTIME_ARTIFACT_PAIR_BYTES;
        assert_eq!(
            checked_extent(PLUGIN_SETUP_PLAN_MAX_BYTES - extra),
            Ok(PLUGIN_SETUP_PLAN_MAX_BYTES)
        );
        assert!(checked_extent(PLUGIN_SETUP_PLAN_MAX_BYTES - extra + 1).is_err());
        assert!(checked_extent(usize::MAX).is_err());
    }
}
