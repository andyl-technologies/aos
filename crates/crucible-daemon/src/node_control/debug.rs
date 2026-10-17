//! Explicit edition-eight operator messages for qualified live condition control.

use super::{
    NodeControlCommand, NodeControlError, NodeControlReply, NodeControlRequest, NodeControlResult,
    refused,
};
use crate::node_observed_executor::{
    NodeDebugRecord, NodeDebugResumeRequest, NodeDebugStartRequest,
};
use crucible_node_contract::Id;

impl NodeControlRequest {
    /// Builds an original live Debug start under explicit transport edition eight.
    ///
    /// # Errors
    /// Refuses malformed exchange IDs, unsupported models or excessive request scope.
    pub fn debug_start(
        request_id: &str,
        request: NodeDebugStartRequest,
    ) -> Result<Self, NodeControlError> {
        debug_request(
            request_id,
            NodeControlCommand::DebugStart {
                request: Box::new(request),
            },
        )
    }

    /// Builds an original once-only live resume under explicit edition eight.
    ///
    /// # Errors
    /// Refuses malformed identities, unsafe nonces or invalid suffix bounds.
    pub fn debug_resume(
        request_id: &str,
        request: NodeDebugResumeRequest,
    ) -> Result<Self, NodeControlError> {
        debug_request(
            request_id,
            NodeControlCommand::DebugResume {
                request: Box::new(request),
            },
        )
    }

    /// Builds a read-only original Debug status request under edition eight.
    ///
    /// # Errors
    /// Refuses malformed exchange or execution identities.
    pub fn debug_status(request_id: &str, execution: String) -> Result<Self, NodeControlError> {
        debug_request(request_id, NodeControlCommand::DebugStatus { execution })
    }
}

fn debug_request(
    request_id: &str,
    command: NodeControlCommand,
) -> Result<NodeControlRequest, NodeControlError> {
    let request = NodeControlRequest {
        format: "crucible.node-control".into(),
        version: 8,
        request_id: Id::new(request_id)?,
        command,
    };
    request.validate()?;
    Ok(request)
}

/// Reads original Debug custody from an explicitly correlated edition-eight reply.
///
/// # Errors
/// Refuses foreign result editions, ordinary state or explicit service refusal.
pub fn decode_debug_record(reply: &NodeControlReply) -> Result<NodeDebugRecord, NodeControlError> {
    if reply.version != 8 {
        return Err(refused("Debug result requires transport edition eight"));
    }
    match &reply.result {
        NodeControlResult::DebugState { record } => Ok(record.as_ref().clone()),
        NodeControlResult::Refused { reason } => Err(refused(reason)),
        _ => Err(refused(
            "reply does not contain original live Debug custody",
        )),
    }
}

#[cfg(test)]
#[path = "debug_tests.rs"]
mod tests;
