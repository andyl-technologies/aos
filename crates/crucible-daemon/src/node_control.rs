//! Private, versioned local control for installed node observation actors.
//!
//! One connection carries one bounded canonical JSON exchange:
//!
//! ```text
//! NodeControlV1 = body_length:u32be | canonical_json[body_length]
//! request = {"format":"crucible.node-control", "version":1,
//!            "request_id":"operator/1", "command":{"operation":"status",
//!            "execution":"00112233445566778899aabbccddeeff"}}
//! ```
//!
//! Same-UID kernel credentials and a privately owned socket authorize the local
//! operator. Requests cannot install implementations or mint qualification.
//! Compilation and dispatch belong to the actual daemon's installed catalog.

mod daemon;
#[cfg(test)]
mod tests;
mod transport;

use crucible_campaign::{ExecutionId, observed_node_attempt::ObservedAttemptState};
use crucible_node_contract::{Bytes, Id, canonical};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::node_observed_executor::InstalledNodeSelection;

pub use daemon::{NodeControlDaemon, NodeDaemonPolicy};

/// Bounds each complete local control frame before body allocation.
pub const MAX_NODE_CONTROL_BYTES: usize = 16 * 1024 * 1024;

/// Reports local framing, authentication, installation, or actor refusal.
#[derive(Debug, thiserror::Error)]
pub enum NodeControlError {
    /// The transport, state lock, or installed file failed.
    #[error("node control I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Closed canonical JSON or a public node schema failed validation.
    #[error("node control schema failed: {0}")]
    Schema(#[from] crucible_node_contract::ContractError),
    /// The local operation failed without granting new dispatch authority.
    #[error("node control refused: {0}")]
    Refused(String),
}

/// Carries one explicitly versioned, correlated local operator request.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeControlRequest {
    /// Names the closed local protocol format.
    pub format: String,
    /// Selects the exact supported wire edition.
    pub version: u32,
    /// Correlates the original operator exchange, independently of dispatch.
    pub request_id: Id,
    /// Selects compilation, original execution admission, or retained status.
    pub command: NodeControlCommand,
}

/// Selects a bounded operation on the owning installed node actor.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum NodeControlCommand {
    /// Compiles the exact complete scenario from daemon installation identities.
    Compile {
        /// Selects only implemented profiles already installed by host policy.
        selections: Vec<InstalledNodeSelection>,
    },
    /// Reserves one independent original execution before native activation.
    Observe {
        /// Names the durable observation ledger, one ref segment.
        ledger: String,
        /// Contains an independently selected 16-byte execution nonce in hex.
        execution: String,
        /// Retains the original installed profile selection.
        selections: Vec<InstalledNodeSelection>,
        /// Contains the exact scenario bytes compiled by this daemon edition.
        scenario: Bytes,
        /// Contains the bounded explicit run configuration JSON.
        configuration: Bytes,
    },
    /// Reads existing durable state, never granting native dispatch or resume.
    Status {
        /// Identifies the original execution nonce in hex.
        execution: String,
    },
}

/// Returns a correlated bounded reply without exposing native authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeControlReply {
    /// Names the closed local protocol format.
    pub format: String,
    /// Selects the exact supported wire edition.
    pub version: u32,
    /// Preserves the original operator exchange identity.
    pub request_id: Id,
    /// Retains the canonical compiled scenario, original state, or refusal.
    pub result: NodeControlResult,
}

/// Distinguishes immutable scenario bytes from original execution lifecycle bytes.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum NodeControlResult {
    /// Returns canonical complete authored scenario bytes.
    Compiled {
        /// Binds daemon host and independently admitted native installation.
        scenario: Bytes,
    },
    /// Returns the unchanged versioned observed-attempt lifecycle record.
    State {
        /// Contains the strict existing observed-state binary format.
        state: Bytes,
    },
    /// Refuses the request while preserving original persisted dispatch custody.
    Refused {
        /// Contains a bounded diagnostic and grants no retry authority.
        reason: String,
    },
}

impl NodeControlRequest {
    /// Builds an edition-one correlated request.
    ///
    /// # Errors
    /// Refuses invalid exchange identifiers and unsupported or oversized commands.
    pub fn new(request_id: &str, command: NodeControlCommand) -> Result<Self, NodeControlError> {
        let request = Self {
            format: "crucible.node-control".into(),
            version: 1,
            request_id: Id::new(request_id)?,
            command,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), NodeControlError> {
        if self.format != "crucible.node-control" || self.version != 1 {
            return Err(refused("unsupported local node control edition"));
        }
        match &self.command {
            NodeControlCommand::Compile { selections } => validate_selections(selections),
            NodeControlCommand::Observe {
                ledger,
                execution,
                selections,
                scenario,
                configuration,
            } => {
                validate_selections(selections)?;
                execution_id(execution)?;
                if ledger.is_empty()
                    || ledger.len() > 128
                    || ledger.contains('/')
                    || scenario.as_slice().len() > crate::node_scenario::MAX_NODE_SCENARIO_BYTES
                    || configuration.as_slice().len() > 4096
                {
                    return Err(refused("node admission inputs exceed local bounds"));
                }
                crucible_cas::content_store::RefName::new(format!(
                    "observed-attempt-ledgers/{ledger}"
                ))
                .map_err(|_| refused("node observation ledger is not a safe ref segment"))?;
                crate::node_scenario::NodeScenario::from_json(scenario.as_slice())
                    .map_err(refused)?;
                crate::node_scenario::NodeRunConfiguration::from_json(configuration.as_slice())
                    .map_err(refused)?;
                Ok(())
            }
            NodeControlCommand::Status { execution } => execution_id(execution).map(|_| ()),
        }
    }
}

impl NodeControlCommand {
    /// Retains exact authored scenario and configuration bytes for one original admission.
    #[must_use]
    pub fn observe(
        ledger: String,
        execution: String,
        selections: Vec<InstalledNodeSelection>,
        scenario: Vec<u8>,
        configuration: Vec<u8>,
    ) -> Self {
        Self::Observe {
            ledger,
            execution,
            selections,
            scenario: Bytes::new(scenario),
            configuration: Bytes::new(configuration),
        }
    }
}

/// Decodes bounded closed profile selections before requesting daemon compilation.
///
/// # Errors
/// Refuses malformed JSON, duplicate keys, unsupported fields or oversized rosters.
pub fn decode_node_selections(
    bytes: &[u8],
) -> Result<Vec<InstalledNodeSelection>, NodeControlError> {
    let value = canonical::parse_json(bytes, 64 * 1024)?;
    let selections: Vec<InstalledNodeSelection> =
        serde_json::from_value(value).map_err(crucible_node_contract::ContractError::from)?;
    validate_selections(&selections)?;
    Ok(selections)
}

/// Performs one bounded exchange against a privately owned same-UID endpoint.
///
/// # Errors
/// Refuses nonprivate endpoints, foreign peer credentials, transport deadlines,
/// changed reply identities, malformed or oversized wire data, or invalid requests.
pub fn request_node_control(
    socket: &Path,
    request: &NodeControlRequest,
) -> Result<NodeControlReply, NodeControlError> {
    request.validate()?;
    transport::exchange(socket, request)
}

/// Decodes the original retained state from a positive local daemon reply.
///
/// # Errors
/// Refuses non-state replies, malformed lifecycle bytes, or actual daemon refusal.
pub fn decode_node_state(
    reply: &NodeControlReply,
) -> Result<ObservedAttemptState, NodeControlError> {
    match &reply.result {
        NodeControlResult::State { state } => {
            ObservedAttemptState::from_canonical_bytes(state.as_slice()).map_err(refused)
        }
        NodeControlResult::Refused { reason } => Err(refused(reason)),
        NodeControlResult::Compiled { .. } => {
            Err(refused("compiled scenario is not execution state"))
        }
    }
}

fn validate_selections(selections: &[InstalledNodeSelection]) -> Result<(), NodeControlError> {
    if selections.is_empty() || selections.len() > 64 {
        return Err(refused("installed node roster is empty or oversized"));
    }
    Ok(())
}

fn execution_id(value: &str) -> Result<ExecutionId, NodeControlError> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(refused(
            "execution nonce requires 32 lowercase hexadecimal digits",
        ));
    }
    let mut bytes = [0; 16];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let digit = |byte: u8| {
            if byte.is_ascii_digit() {
                byte - b'0'
            } else {
                byte - b'a' + 10
            }
        };
        bytes[index] = digit(pair[0]) * 16 + digit(pair[1]);
    }
    ExecutionId::from_bytes(bytes).map_err(refused)
}

fn refused(error: impl std::fmt::Display) -> NodeControlError {
    NodeControlError::Refused(error.to_string().chars().take(4096).collect())
}
