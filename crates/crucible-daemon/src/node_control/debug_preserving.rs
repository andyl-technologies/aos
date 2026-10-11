//! Transports explicit preserving custody under distinct operator edition ten.

use super::{
    NodeControlCommand, NodeControlError, NodeControlReply, NodeControlRequest, NodeControlResult,
    refused,
};
use crate::node_observed_executor::{
    NodePreservingDebugRecord, NodePreservingDebugRequest, NodePreservingDebugResumeRequest,
};
use crucible_node_contract::Id;

impl NodeControlRequest {
    /// Builds an original preserving prepare under explicit transport edition ten.
    ///
    /// # Errors
    /// Refuses malformed exchange IDs, unsupported models or excessive request scope.
    pub fn preserving_debug_prepare(
        request_id: &str,
        request: NodePreservingDebugRequest,
    ) -> Result<Self, NodeControlError> {
        preserving_request(
            request_id,
            NodeControlCommand::PreservingDebugPrepare {
                request: Box::new(request),
            },
        )
    }

    /// Builds an original once-only preserving Resume under explicit edition ten.
    ///
    /// # Errors
    /// Refuses malformed identities, unsafe nonces or invalid suffix bounds.
    pub fn preserving_debug_resume(
        request_id: &str,
        request: NodePreservingDebugResumeRequest,
    ) -> Result<Self, NodeControlError> {
        preserving_request(
            request_id,
            NodeControlCommand::PreservingDebugResume {
                request: Box::new(request),
            },
        )
    }

    /// Builds a read-only original Debug status request under edition ten.
    ///
    /// # Errors
    /// Refuses malformed exchange or execution identities.
    pub fn preserving_debug_status(
        request_id: &str,
        execution: String,
    ) -> Result<Self, NodeControlError> {
        preserving_request(
            request_id,
            NodeControlCommand::PreservingDebugStatus { execution },
        )
    }
}

fn preserving_request(
    request_id: &str,
    command: NodeControlCommand,
) -> Result<NodeControlRequest, NodeControlError> {
    let request = NodeControlRequest {
        format: "crucible.node-control".into(),
        version: 10,
        request_id: Id::new(request_id)?,
        command,
    };
    request.validate()?;
    Ok(request)
}

/// Reads original Debug custody from an explicitly correlated edition-ten reply.
///
/// # Errors
/// Refuses foreign result editions, ordinary state or explicit service refusal.
pub fn decode_preserving_debug_record(
    reply: &NodeControlReply,
) -> Result<NodePreservingDebugRecord, NodeControlError> {
    if reply.version != 10 {
        return Err(refused("Debug result requires transport edition ten"));
    }
    match &reply.result {
        NodeControlResult::PreservingDebugState { record } => Ok(record.as_ref().clone()),
        NodeControlResult::Refused { reason } => Err(refused(reason)),
        _ => Err(refused(
            "reply does not contain original preserving custody",
        )),
    }
}
