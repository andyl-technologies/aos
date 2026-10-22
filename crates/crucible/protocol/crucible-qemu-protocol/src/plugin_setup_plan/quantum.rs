//! Assembles the separate plan-ten Quantum negotiation carrier.
//!
//! ```text
//! CRUCSU10 | schema10/header48/total/A/S/W/Startup128/Purpose2520/Publisher224/zero
//! App | Selectable | Workspace? | Startup | CRUCPUR8[2520] | CRUCPSP2[224]
//! ```
//!
//! Parsing verifies exact syntax and correspondence. It creates no sealed-file,
//! endpoint, Source, operation, resource or independent terminal owner.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use crate::publisher_subscription::{PUBLISHER_PURPOSE_BYTES, quantum::QuantumPublisherPurpose};

impl PluginSetupPlan {
    /// Encodes the distinct plan-ten carrier with a Quantum-only Purpose2.
    ///
    /// Its extent is identical to the plan-nine carrier and shares the same
    /// aggregate cap. Actual constructors must fund every assembly allocation.
    ///
    /// # Errors
    /// Refuses missing startup, invalid nested data, changed original/process
    /// correspondence, invalid Purpose2 or an extent exceeding the fixed cap.
    pub fn encode_preexec_quantum(
        &self,
        purpose: &[u8; PROCESS_PURPOSE_BYTES],
        workspace: Option<&[u8; DEVICE_DIGEST_PURPOSE_BYTES]>,
        publisher: &QuantumPublisherPurpose,
    ) -> Result<Vec<u8>, PluginSetupPlanError> {
        let startup = self.startup_operation.as_ref().ok_or_else(invalid)?;
        preexec::validate_binding(startup, purpose, workspace.map(|bytes| bytes.as_slice()))?;
        super::publisher::validate_binding(&publisher.session, purpose)?;
        let subscription = publisher.encode().map_err(|_| invalid())?;

        // The shared assembler owns the unchanged body framing and allocation.
        // Select the distinct outer edition before exposing any result.
        let mut bytes = self.encode_body(
            workspace.copied(),
            Some(startup.encode()),
            Some(purpose),
            Some(&subscription),
        )?;
        bytes[..8].copy_from_slice(b"CRUCSU10");
        bytes[8..12].copy_from_slice(&10_u32.to_be_bytes());
        Ok(bytes)
    }

    /// Decodes only plan ten and its matched Quantum-only Purpose2.
    ///
    /// No earlier carrier is accepted as a fallback. Every identity remains
    /// observational until the actual retained owners authenticate it.
    ///
    /// # Errors
    /// Refuses other or mixed editions, truncation, trailing data, malformed
    /// sections, changed original/process correspondence or an oversized plan.
    pub fn decode_preexec_quantum_parts(
        bytes: &[u8],
    ) -> Result<
        (
            AppRandomBranchPlan,
            SelectableCatalogPlan,
            QuantumPublisherPurpose,
        ),
        PluginSetupPlanError,
    > {
        let (app, selectable) = preexec::decode_edition(bytes, preexec::Edition::Quantum)?;
        let subscription =
            QuantumPublisherPurpose::decode(&bytes[bytes.len() - PUBLISHER_PURPOSE_BYTES..])
                .map_err(|_| invalid())?;
        Ok((app, selectable, subscription))
    }
}

fn invalid() -> PluginSetupPlanError {
    PluginSetupPlanError::InvalidPreexecSection {
        section: "Quantum publisher purpose",
    }
}
