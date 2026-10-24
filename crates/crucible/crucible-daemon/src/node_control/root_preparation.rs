//! Correlates control edition nine with original authored root custody.

use super::*;
use crate::node_observed_executor::{RootPreparationRecord, RootPreparationRequest};

impl NodeControlRequest {
    /// Builds a data-only diagnostic read without native dispatch or actor waiting.
    ///
    /// # Errors
    /// Refuses invalid request IDs or noncanonical original execution nonces.
    pub fn root_diagnostic(request_id: &str, execution: String) -> Result<Self, NodeControlError> {
        let request = Self {
            format: "crucible.node-control".into(),
            version: 9,
            request_id: Id::new(request_id)?,
            command: NodeControlCommand::RootDiagnostic { execution },
        };
        request.validate()?;
        Ok(request)
    }

    /// Builds an explicit root request without altering earlier wire editions.
    ///
    /// # Errors
    /// Refuses invalid request IDs, original recipe scopes or complete frame limits.
    pub fn root_preparation(
        request_id: &str,
        request: RootPreparationRequest,
    ) -> Result<Self, NodeControlError> {
        let request = Self {
            format: "crucible.node-control".into(),
            version: 9,
            request_id: Id::new(request_id)?,
            command: NodeControlCommand::RootPreparation {
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
    pub fn root_preparation_status(
        request_id: &str,
        execution: String,
    ) -> Result<Self, NodeControlError> {
        let request = Self {
            format: "crucible.node-control".into(),
            version: 9,
            request_id: Id::new(request_id)?,
            command: NodeControlCommand::RootPreparationStatus { execution },
        };

        request.validate()?;
        Ok(request)
    }
}

/// Decodes original root receipts only from their explicit transport edition.
///
/// # Errors
/// Refuses wrong editions/results, malformed canonical receipts or wire refusals.
pub fn decode_root_preparation(
    reply: &NodeControlReply,
) -> Result<RootPreparationRecord, NodeControlError> {
    if reply.version != 9 {
        return Err(refused(
            "root receipt requires explicit control edition nine",
        ));
    }
    let NodeControlResult::RootPreparation { record } = &reply.result else {
        return Err(refused("root actor refused or returned another result"));
    };
    RootPreparationRecord::from_canonical_bytes(record.as_slice()).map_err(refused)
}

/// Decodes data-only diagnostics only from explicit Root transport edition nine.
///
/// # Errors
/// Refuses other editions, results and noncanonical bounded diagnostic records.
pub fn decode_root_diagnostic(
    reply: &NodeControlReply,
) -> Result<crate::node_observed_executor::RootPreparationDiagnostic, NodeControlError> {
    if reply.version != 9 {
        return Err(refused(
            "Root diagnostic requires explicit control edition nine",
        ));
    }
    let NodeControlResult::RootDiagnostic { record } = &reply.result else {
        return Err(refused(
            "Root original diagnostic was refused or another result returned",
        ));
    };
    crate::node_observed_executor::RootPreparationDiagnostic::from_canonical_bytes(
        record.as_slice(),
    )
    .map_err(refused)
}
