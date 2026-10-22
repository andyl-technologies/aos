//! Assembles plan twelve with exact dormant Cleanup delegation observations.
//!
//! ```text
//! CRUCSU12 | schema12/header48/total/A/S/W/Startup128/Purpose2520/Publisher736/zero
//! App | Selectable | Workspace? | Startup | CRUCPUR8 | CRUCPSP3
//! ```
//!
//! Parsing authenticates no carrier and creates no retained issuer, resource
//! child or entered interval. Actual installation must select those owners.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use crate::deferred_cleanup::{DEFERRED_CLEANUP_PURPOSE_BYTES, DeferredCleanupPurpose};

/// Retains plan-twelve data without issuing a delegation or selecting a carrier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeferredCleanupPlanParts {
    /// Decoded app-random configuration.
    pub app_random: AppRandomBranchPlan,
    /// Decoded selectable catalog configuration.
    pub selectable: SelectableCatalogPlan,
    /// Exact physical publisher and future-entry delegation observations.
    pub publisher: DeferredCleanupPurpose,
}

impl PluginSetupPlan {
    /// Reports plan twelve's extent before assembly or physical carrier birth.
    ///
    /// # Errors
    /// Refuses overflow, malformed nested plans or the unchanged aggregate cap.
    pub fn preexec_deferred_cleanup_encoded_len(
        &self,
        has_workspace: bool,
    ) -> Result<usize, PluginSetupPlanError> {
        checked_extent(self.preexec_encoded_len(has_workspace)?)
    }

    /// Encodes plan twelve with one final output allocation and exact binding.
    ///
    /// Nested encoders also allocate their existing app and selectable bodies.
    /// The actual issuer must fund their simultaneous peak before calling.
    /// Assembly grants no authority and does not enable profile negotiation.
    ///
    /// # Errors
    /// Refuses missing startup, mismatched Source assignment or process purpose,
    /// malformed delegation, nested encoding errors or excessive aggregate size.
    pub fn encode_preexec_deferred_cleanup(
        &self,
        purpose: &[u8; PROCESS_PURPOSE_BYTES],
        workspace: Option<&[u8; DEVICE_DIGEST_PURPOSE_BYTES]>,
        publisher: &DeferredCleanupPurpose,
    ) -> Result<Vec<u8>, PluginSetupPlanError> {
        let startup = self.startup_operation.as_ref().ok_or_else(invalid)?;
        preexec::validate_binding(startup, purpose, workspace.map(|bytes| bytes.as_slice()))?;
        validate_source_binding(publisher, purpose)?;
        let subscription = publisher.encode().map_err(|_| invalid())?;
        let total = self.preexec_deferred_cleanup_encoded_len(workspace.is_some())?;

        let app = self.app_random_branch_plan.encode();
        let selectable = self
            .selectable_catalog_plan
            .encode()
            .map_err(|source| PluginSetupPlanError::Selectable { source })?;
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(b"CRUCSU12");
        // The unchanged aggregate cap bounds every framed length below u32::MAX.
        for word in [
            12,
            48,
            total as u32,
            app.len() as u32,
            selectable.len() as u32,
            workspace.map_or(0, |_| DEVICE_DIGEST_PURPOSE_BYTES as u32),
            STARTUP_OPERATION_BYTES as u32,
            PROCESS_PURPOSE_BYTES as u32,
            DEFERRED_CLEANUP_PURPOSE_BYTES as u32,
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
        Ok(bytes)
    }

    /// Decodes only plan twelve and the matching schema-three delegation.
    ///
    /// # Errors
    /// Refuses mixed editions, malformed lengths, truncation, trailing data,
    /// invalid nested records or changed Source and parent correspondence.
    pub fn decode_preexec_deferred_cleanup_parts(
        bytes: &[u8],
    ) -> Result<DeferredCleanupPlanParts, PluginSetupPlanError> {
        let (app_random, selectable) =
            preexec::decode_edition(bytes, preexec::Edition::DeferredCleanup)?;
        let publisher =
            DeferredCleanupPurpose::decode(&bytes[bytes.len() - DEFERRED_CLEANUP_PURPOSE_BYTES..])
                .map_err(|_| invalid())?;
        Ok(DeferredCleanupPlanParts {
            app_random,
            selectable,
            publisher,
        })
    }
}

/// Checks delegation coordinates against the same fixed Source assignment.
///
/// # Errors
/// Refuses changed publisher, Source issuer or local process resource parents.
pub(super) fn validate_source_binding(
    publisher: &DeferredCleanupPurpose,
    purpose: &[u8],
) -> Result<(), PluginSetupPlanError> {
    super::publisher::validate_binding(&publisher.publisher, purpose)?;
    let delegation = &publisher.delegation;
    if delegation.source_capability != publisher.publisher.capability
        || delegation.source_reservation != publisher.publisher.reservation
        || purpose[800..808] != delegation.source_issuer_incarnation.to_be_bytes()
        || delegation.resource.identity != delegation.source_reservation
        || delegation.resource.incarnation != delegation.process_incarnation
    {
        return Err(invalid());
    }
    Ok(())
}

fn checked_extent(ordinary: usize) -> Result<usize, PluginSetupPlanError> {
    ordinary
        .checked_add(8 + DEFERRED_CLEANUP_PURPOSE_BYTES)
        .filter(|total| *total <= PLUGIN_SETUP_PLAN_MAX_BYTES)
        .ok_or(PluginSetupPlanError::PlanTooLarge {
            bytes: ordinary.saturating_add(8 + DEFERRED_CLEANUP_PURPOSE_BYTES),
            maximum: PLUGIN_SETUP_PLAN_MAX_BYTES,
        })
}

fn invalid() -> PluginSetupPlanError {
    PluginSetupPlanError::InvalidPreexecSection {
        section: "deferred Cleanup assignment",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delegation_extent_preserves_the_unchanged_aggregate_cap() {
        let extra = 8 + DEFERRED_CLEANUP_PURPOSE_BYTES;
        assert_eq!(
            checked_extent(PLUGIN_SETUP_PLAN_MAX_BYTES - extra),
            Ok(PLUGIN_SETUP_PLAN_MAX_BYTES)
        );
        assert!(checked_extent(PLUGIN_SETUP_PLAN_MAX_BYTES - extra + 1).is_err());
        assert!(checked_extent(usize::MAX).is_err());
    }
}
