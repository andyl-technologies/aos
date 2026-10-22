//! Assembles matched publisher plans without creating physical role custody.
//!
//! ```text
//! CRUCSUP9 | BE schema9/header48/total/A/S/W/Startup128/Purpose2520 |
//! Publisher224/zero:u32 | App | Selectable | Workspace? | Startup |
//! CRUCPUR8[2520] | CRUCPSP1[224]
//! ```
//!
//! The existing aggregate cap includes the new header and purpose; this
//! transport preparation never advertises activation or installs an issuer.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use crate::publisher_subscription::{PUBLISHER_PURPOSE_BYTES, PublisherPurpose};

impl PluginSetupPlan {
    /// Reports the matched publisher carrier length before encoding or birth.
    ///
    /// # Errors
    /// Refuses overflow or an extent exceeding the unchanged aggregate cap.
    pub fn preexec_publisher_encoded_len(
        &self,
        has_workspace: bool,
    ) -> Result<usize, PluginSetupPlanError> {
        with_publisher_extent(self.preexec_encoded_len(has_workspace)?, true)
    }

    /// Encodes plan nine from already-issued process and publisher material.
    ///
    /// Only structural correspondence is checked. Actual producers must pay
    /// for, retain and authenticate every physical role before transmission.
    /// The existing plan-eight encoder continues to emit its exact edition.
    ///
    /// # Errors
    /// Refuses missing startup, mismatched purposes, invalid nested plans or
    /// an extent exceeding the unchanged aggregate cap.
    pub fn encode_preexec_publisher(
        &self,
        purpose: &[u8; PROCESS_PURPOSE_BYTES],
        workspace: Option<&[u8; DEVICE_DIGEST_PURPOSE_BYTES]>,
        publisher: &PublisherPurpose,
    ) -> Result<Vec<u8>, PluginSetupPlanError> {
        let startup = self
            .startup_operation
            .as_ref()
            .ok_or_else(invalid_publisher)?;
        preexec::validate_binding(startup, purpose, workspace.map(|bytes| bytes.as_slice()))?;
        validate_binding(publisher, purpose)?;
        let publisher_bytes = publisher.encode().map_err(|_| invalid_publisher())?;

        self.encode_body(
            workspace.copied(),
            Some(startup.encode()),
            Some(purpose),
            Some(&publisher_bytes),
        )
    }

    /// Decodes only the matched plan-nine carrier and its publisher facts.
    ///
    /// This does not accept plan eight as a fallback. Neither the returned
    /// plans nor copied publisher facts issue a session or operation.
    ///
    /// # Errors
    /// Refuses another edition, noncanonical framing, nested data, publisher
    /// geometry or correspondence with the existing process purpose.
    pub fn decode_preexec_publisher_parts(
        bytes: &[u8],
    ) -> Result<(AppRandomBranchPlan, SelectableCatalogPlan, PublisherPurpose), PluginSetupPlanError>
    {
        let (app, selectable) = preexec::decode_profile(bytes, true)?;
        // The checked profile has already established this exact final tail.
        let publisher = PublisherPurpose::decode(&bytes[bytes.len() - PUBLISHER_PURPOSE_BYTES..])
            .map_err(|_| invalid_publisher())?;

        Ok((app, selectable, publisher))
    }
}

pub(super) fn with_publisher_extent(
    ordinary: usize,
    publisher: bool,
) -> Result<usize, PluginSetupPlanError> {
    let total = ordinary
        .checked_add(if publisher {
            8 + PUBLISHER_PURPOSE_BYTES
        } else {
            0
        })
        .ok_or(PluginSetupPlanError::PlanTooLarge {
            bytes: usize::MAX,
            maximum: PLUGIN_SETUP_PLAN_MAX_BYTES,
        })?;
    if total > PLUGIN_SETUP_PLAN_MAX_BYTES {
        return Err(PluginSetupPlanError::PlanTooLarge {
            bytes: total,
            maximum: PLUGIN_SETUP_PLAN_MAX_BYTES,
        });
    }

    Ok(total)
}

pub(super) fn validate_binding(
    publisher: &PublisherPurpose,
    purpose: &[u8],
) -> Result<(), PluginSetupPlanError> {
    if purpose.len() != PROCESS_PURPOSE_BYTES
        || purpose[88..96] != publisher.account_generation.to_be_bytes()
        || purpose[96..104] != publisher.process_generation.to_be_bytes()
        || purpose[184..216] != publisher.capability
        || purpose[816..848] != publisher.reservation
    {
        return Err(invalid_publisher());
    }

    Ok(())
}

fn invalid_publisher() -> PluginSetupPlanError {
    PluginSetupPlanError::InvalidPreexecSection {
        section: "publisher purpose",
    }
}
