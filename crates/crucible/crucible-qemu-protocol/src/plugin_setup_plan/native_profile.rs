//! Frames plan fifteen's correlated native transfer, manifest and probe tails.
//!
//! ```text
//! CRUCSU15 | schema15/header80 | unchanged Plan13 fields through byte55
//! native1472:u32 | zero:u32 | manifest-length:u32 | probe3584:u32 | zero[8]
//! App | Selectable | Workspace? | Startup | Purpose3 | Runtime192
//! Native1472 | exact-manifest | Probe3584
//! ```
//!
//! Borrowed descriptions establish neither paid receiving storage nor launcher,
//! producer, containing-loan or reap authority. Negative probe histories remain
//! valid descriptions and never become completed qualification through framing.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use crate::deferred_cleanup::{DEFERRED_CLEANUP_PURPOSE_BYTES, DeferredCleanupPurpose};
use crate::native_transfer::manifest::{NATIVE_PROFILE_MANIFEST_MAX_BYTES, NativeProfileManifest};
use crate::native_transfer::probe::{NATIVE_PROBE_REPORT_BYTES, NativeProbeReport};
use crate::native_transfer::{NATIVE_TRANSFER_BYTES, NativeTransfer};
use crate::runtime_artifact::{RUNTIME_ARTIFACT_PAIR_BYTES, RuntimeArtifactPair};

/// Groups the independent descriptions required to assemble plan fifteen.
#[derive(Clone, Copy, Debug)]
pub struct NativeProfilePlanInputs<'a> {
    /// Borrows the containing physical publisher and dormant delegation purpose.
    pub publisher: &'a DeferredCleanupPurpose,
    /// Borrows the exact immutable runtime file descriptions.
    pub runtime: &'a RuntimeArtifactPair,
    /// Borrows the containing-process transfer description without adopting it.
    pub transfer: &'a NativeTransfer,
    /// Borrows the complete manifest, including exact launch bytes.
    pub manifest: NativeProfileManifest<'a>,
    /// Borrows the factual probe report, including partial or negative results.
    pub probe: NativeProbeReport<'a>,
}

/// Retains checked plan-fifteen sections while borrowing its variable tails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeProfilePlanParts<'a> {
    /// Retains the decoded app-random configuration.
    pub app_random: AppRandomBranchPlan,
    /// Retains the decoded selectable catalog configuration.
    pub selectable: SelectableCatalogPlan,
    /// Retains the containing physical publisher and dormant delegation purpose.
    pub publisher: DeferredCleanupPurpose,
    /// Retains the exact runtime file descriptions.
    pub runtime: RuntimeArtifactPair,
    /// Retains the correlated transfer description without issuing a loan.
    pub transfer: NativeTransfer,
    /// Borrows the complete manifest directly from the original carrier.
    pub manifest: NativeProfileManifest<'a>,
    /// Borrows the unchanged factual report directly from the original carrier.
    pub probe: NativeProbeReport<'a>,
}

impl PluginSetupPlan {
    /// Reports plan fifteen's extent under the unchanged aggregate limit.
    ///
    /// # Errors
    /// Refuses an excessive manifest, invalid nested plan, arithmetic overflow
    /// or an aggregate extent exceeding the existing plan cap.
    pub fn preexec_native_profile_encoded_len(
        &self,
        has_workspace: bool,
        manifest_len: usize,
    ) -> Result<usize, PluginSetupPlanError> {
        checked_extent(
            self.preexec_native_transfer_encoded_len(has_workspace)?,
            manifest_len,
        )
    }

    /// Encodes the distinct plan-fifteen header and exact correlated tails.
    ///
    /// The caller must fund simultaneous nested assembly and final output
    /// before invocation. This operation authenticates no receiving aliases,
    /// compiled producer, payer, launcher or matching reap holder.
    ///
    /// # Errors
    /// Refuses malformed or foreign containing identities, inconsistent complete
    /// digests, producer contracts or runtime artifacts, and excessive totals.
    pub fn encode_preexec_native_profile(
        &self,
        purpose: &[u8; PROCESS_PURPOSE_BYTES],
        workspace: Option<&[u8; DEVICE_DIGEST_PURPOSE_BYTES]>,
        inputs: NativeProfilePlanInputs<'_>,
    ) -> Result<Vec<u8>, PluginSetupPlanError> {
        inputs
            .probe
            .corroborate_transfer(inputs.transfer, &inputs.manifest, inputs.runtime)
            .map_err(|_| invalid())?;
        let total = self.preexec_native_profile_encoded_len(
            workspace.is_some(),
            inputs.manifest.as_bytes().len(),
        )?;
        let prior = self.encode_preexec_native_transfer(
            purpose,
            workspace,
            inputs.publisher,
            inputs.runtime,
            inputs.transfer,
        )?;

        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(&prior[..64]);
        bytes[..8].copy_from_slice(b"CRUCSU15");
        bytes[8..12].copy_from_slice(&15_u32.to_be_bytes());
        bytes[12..16].copy_from_slice(&80_u32.to_be_bytes());
        bytes[16..20].copy_from_slice(&(total as u32).to_be_bytes());
        bytes.extend_from_slice(&(inputs.manifest.as_bytes().len() as u32).to_be_bytes());
        bytes.extend_from_slice(&(NATIVE_PROBE_REPORT_BYTES as u32).to_be_bytes());
        bytes.extend_from_slice(&[0; 8]);
        bytes.extend_from_slice(&prior[64..]);
        bytes.extend_from_slice(inputs.manifest.as_bytes());
        bytes.extend_from_slice(inputs.probe.as_bytes());
        Ok(bytes)
    }

    /// Decodes only plan fifteen and preserves borrowed negative probe facts.
    ///
    /// # Errors
    /// Refuses older or mixed editions, malformed nested sections, foreign
    /// containing identities, inconsistent full digests, truncation or surplus.
    pub fn decode_preexec_native_profile_parts(
        bytes: &[u8],
    ) -> Result<NativeProfilePlanParts<'_>, PluginSetupPlanError> {
        let (app_random, selectable) =
            preexec::decode_edition(bytes, preexec::Edition::NativeProfile)?;
        // The edition parser already checked the complete extent equation before
        // any of these exact, bounded tail offsets can be used.
        let probe_start = bytes.len() - NATIVE_PROBE_REPORT_BYTES;
        let manifest_start = probe_start - read_u32(bytes, 64)? as usize;
        let transfer_start = manifest_start - NATIVE_TRANSFER_BYTES;
        let runtime_start = transfer_start - RUNTIME_ARTIFACT_PAIR_BYTES;
        let publisher_start = runtime_start - DEFERRED_CLEANUP_PURPOSE_BYTES;

        Ok(NativeProfilePlanParts {
            app_random,
            selectable,
            publisher: DeferredCleanupPurpose::decode(&bytes[publisher_start..runtime_start])
                .map_err(|_| invalid())?,
            runtime: RuntimeArtifactPair::decode(&bytes[runtime_start..transfer_start])
                .map_err(|_| invalid())?,
            transfer: NativeTransfer::decode(&bytes[transfer_start..manifest_start])
                .map_err(|_| invalid())?,
            manifest: NativeProfileManifest::decode(&bytes[manifest_start..probe_start])
                .map_err(|_| invalid())?,
            probe: NativeProbeReport::decode(&bytes[probe_start..]).map_err(|_| invalid())?,
        })
    }
}

fn checked_extent(ordinary: usize, manifest_len: usize) -> Result<usize, PluginSetupPlanError> {
    if manifest_len > NATIVE_PROFILE_MANIFEST_MAX_BYTES {
        return Err(invalid());
    }
    let extra = 16 + manifest_len + NATIVE_PROBE_REPORT_BYTES;
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
        section: "complete native-profile assignment",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_extent_consumes_existing_capacity_without_raising_the_cap() {
        let manifest_len = NATIVE_PROFILE_MANIFEST_MAX_BYTES;
        let extra = 16 + manifest_len + NATIVE_PROBE_REPORT_BYTES;
        assert_eq!(
            checked_extent(PLUGIN_SETUP_PLAN_MAX_BYTES - extra, manifest_len),
            Ok(PLUGIN_SETUP_PLAN_MAX_BYTES)
        );
        assert!(checked_extent(PLUGIN_SETUP_PLAN_MAX_BYTES - extra + 1, manifest_len).is_err());
        assert!(checked_extent(usize::MAX, manifest_len).is_err());
        assert!(checked_extent(0, manifest_len + 1).is_err());
        assert!(checked_extent(0, usize::MAX).is_err());
    }
}
