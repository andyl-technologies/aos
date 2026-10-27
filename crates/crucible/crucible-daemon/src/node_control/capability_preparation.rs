//! Correlates control edition seven with original authored capability custody.

use super::*;
use crate::node_observed_executor::{CapabilityPreparationRecord, CapabilityPreparationRequest};

impl NodeControlRequest {
    /// Builds an explicit capability request without altering earlier wire editions.
    ///
    /// # Errors
    /// Refuses invalid request IDs or bounded authored requirements and candidates.
    pub fn capability_preparation(
        request_id: &str,
        request: CapabilityPreparationRequest,
    ) -> Result<Self, NodeControlError> {
        let request = Self {
            format: "crucible.node-control".into(),
            version: 7,
            request_id: Id::new(request_id)?,
            command: NodeControlCommand::CapabilityPreparation {
                request: Box::new(request),
            },
        };

        request.validate()?;
        Ok(request)
    }

    /// Builds an original receipt lookup without native allocation or dispatch.
    ///
    /// # Errors
    /// Refuses invalid request IDs or noncanonical execution nonces.
    pub fn capability_preparation_status(
        request_id: &str,
        execution: String,
    ) -> Result<Self, NodeControlError> {
        let request = Self {
            format: "crucible.node-control".into(),
            version: 7,
            request_id: Id::new(request_id)?,
            command: NodeControlCommand::CapabilityPreparationStatus { execution },
        };

        request.validate()?;
        Ok(request)
    }
}

/// Decodes original capability receipts only from their explicit transport edition.
///
/// # Errors
/// Refuses wrong editions/results, malformed canonical receipts or wire refusals.
pub fn decode_capability_preparation(
    reply: &NodeControlReply,
) -> Result<CapabilityPreparationRecord, NodeControlError> {
    if reply.version != 7 {
        return Err(refused(
            "capability receipt requires explicit control edition seven",
        ));
    }
    let NodeControlResult::CapabilityPreparation { record } = &reply.result else {
        return Err(refused(
            "capability actor refused or returned another result",
        ));
    };
    CapabilityPreparationRecord::from_canonical_bytes(record.as_slice()).map_err(refused)
}
