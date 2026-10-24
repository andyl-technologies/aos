//! Assembles the distinct plan-fourteen containing-process transfer description.
//!
//! ```text
//! CRUCSU14 | schema14/header64/total/A/S/W/Startup128/Purpose2520/Publisher736/zero
//! runtime192:u32 | zero:u32 | native1472:u32 | zero:u32
//! App | Selectable | Workspace? | Startup | CRUCPUR8 | CRUCPSP3 | CRUCRTA1 | CRUCNPL1
//! ```
//!
//! This codec performs no resource-phase negotiation or containing-owner adoption.
//! Actual launchers must fund assembly and authenticate the additional sealed
//! carrier under a separately selected transport before performing any effects.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use crate::deferred_cleanup::{DEFERRED_CLEANUP_PURPOSE_BYTES, DeferredCleanupPurpose};
use crate::native_transfer::{NATIVE_TRANSFER_BYTES, NativeTransfer};
use crate::runtime_artifact::{RUNTIME_ARTIFACT_PAIR_BYTES, RuntimeArtifactPair};

/// Retains independently checked plan-fourteen descriptions without issuing owners.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeTransferPlanParts {
    /// Decoded app-random configuration.
    pub app_random: AppRandomBranchPlan,
    /// Decoded selectable catalog configuration.
    pub selectable: SelectableCatalogPlan,
    /// Exact physical publisher and dormant delegation descriptions.
    pub publisher: DeferredCleanupPurpose,
    /// Exact immutable runtime file identities.
    pub runtime: RuntimeArtifactPair,
    /// Correlated containing-process transfer material; no loan is issued.
    pub transfer: NativeTransfer,
}

impl PluginSetupPlan {
    /// Reports plan fourteen's extent under the unchanged aggregate limit.
    ///
    /// # Errors
    /// Refuses invalid nested plans, checked overflow or excessive total size.
    pub fn preexec_native_transfer_encoded_len(
        &self,
        has_workspace: bool,
    ) -> Result<usize, PluginSetupPlanError> {
        checked_extent(self.preexec_runtime_artifact_encoded_len(has_workspace)?)
    }

    /// Encodes the distinct plan-fourteen runtime and containing-transfer tails.
    ///
    /// The caller must fund simultaneous nested-plan outputs and final assembly
    /// before invoking this codec. Encoding authenticates no payer or launcher.
    ///
    /// # Errors
    /// Refuses missing startup, invalid sections, foreign process/account/Source
    /// descriptions, inconsistent runtime digests or an excessive aggregate size.
    pub fn encode_preexec_native_transfer(
        &self,
        purpose: &[u8; PROCESS_PURPOSE_BYTES],
        workspace: Option<&[u8; DEVICE_DIGEST_PURPOSE_BYTES]>,
        publisher: &DeferredCleanupPurpose,
        runtime: &RuntimeArtifactPair,
        transfer: &NativeTransfer,
    ) -> Result<Vec<u8>, PluginSetupPlanError> {
        let startup = self.startup_operation.as_ref().ok_or_else(invalid)?;
        preexec::validate_binding(startup, purpose, workspace.map(|bytes| bytes.as_slice()))?;
        super::deferred_cleanup::validate_source_binding(publisher, purpose)?;
        super::runtime_artifact::validate_binding(runtime, &publisher.publisher)?;
        transfer
            .corroborate_runtime(runtime)
            .map_err(|_| invalid())?;
        let publisher = publisher.encode().map_err(|_| invalid())?;
        let runtime = runtime.encode().map_err(|_| invalid())?;
        let transfer = transfer.encode().map_err(|_| invalid())?;
        let total = self.preexec_native_transfer_encoded_len(workspace.is_some())?;

        let app = self.app_random_branch_plan.encode();
        let selectable = self
            .selectable_catalog_plan
            .encode()
            .map_err(|source| PluginSetupPlanError::Selectable { source })?;
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(b"CRUCSU14");
        // The aggregate cap keeps every framed length representable as u32.
        for word in [
            14,
            64,
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
            NATIVE_TRANSFER_BYTES as u32,
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
        bytes.extend_from_slice(&publisher);
        bytes.extend_from_slice(&runtime);
        bytes.extend_from_slice(&transfer);
        Ok(bytes)
    }

    /// Decodes only plan fourteen with both separately validated final tails.
    ///
    /// # Errors
    /// Refuses mixed editions, malformed framing, uncorrelated native/runtime
    /// descriptions, changed containing parents, truncation or trailing bytes.
    pub fn decode_preexec_native_transfer_parts(
        bytes: &[u8],
    ) -> Result<NativeTransferPlanParts, PluginSetupPlanError> {
        let (app_random, selectable) =
            preexec::decode_edition(bytes, preexec::Edition::NativeTransfer)?;
        let transfer_start = bytes.len() - NATIVE_TRANSFER_BYTES;
        let runtime_start = transfer_start - RUNTIME_ARTIFACT_PAIR_BYTES;
        let publisher_start = runtime_start - DEFERRED_CLEANUP_PURPOSE_BYTES;
        let publisher = DeferredCleanupPurpose::decode(&bytes[publisher_start..runtime_start])
            .map_err(|_| invalid())?;
        let runtime = RuntimeArtifactPair::decode(&bytes[runtime_start..transfer_start])
            .map_err(|_| invalid())?;
        let transfer = NativeTransfer::decode(&bytes[transfer_start..]).map_err(|_| invalid())?;
        Ok(NativeTransferPlanParts {
            app_random,
            selectable,
            publisher,
            runtime,
            transfer,
        })
    }
}

fn checked_extent(ordinary: usize) -> Result<usize, PluginSetupPlanError> {
    let extra = 8 + NATIVE_TRANSFER_BYTES;
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
        section: "native-transfer assignment",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_extent_preserves_the_unchanged_aggregate_cap() {
        let extra = 8 + NATIVE_TRANSFER_BYTES;
        assert_eq!(
            checked_extent(PLUGIN_SETUP_PLAN_MAX_BYTES - extra),
            Ok(PLUGIN_SETUP_PLAN_MAX_BYTES)
        );
        assert!(checked_extent(PLUGIN_SETUP_PLAN_MAX_BYTES - extra + 1).is_err());
        assert!(checked_extent(usize::MAX).is_err());
    }
}
