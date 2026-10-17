//! Explicit terminal requests that never equate an execution ceiling with EOF.
//!
//! ```text
//! TerminalStateV1 = {operation:capture|restore|status,execution:nonce32hex,...}
//! capture = {selections,scenario,ceiling_ps,stage:completed|published|acknowledged}
//! restore = {selections,scenario,source,stage}
//! ```
//!
//! Only the installed actor can authenticate whole-world closure and original
//! terminal custody. The selected result stage is preserved by the signed
//! terminal-bearing archive, independently of local transport acknowledgement.

use crucible_node_contract::{Bytes, ContentRef, U64, Validate};
use serde::{Deserialize, Serialize};

use crate::{
    node_observed_executor::{InstalledNodeKind, InstalledNodeSelection},
    node_scenario::{MAX_NODE_SCENARIO_BYTES, NodeScenario},
};

use super::{NodeControlError, execution_id, refused, validate_selections};

/// Selects the original terminal result custody retained at capture.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeTerminalStage {
    /// Retains the completed native report before any durable publication.
    Completed,
    /// Retains durable publication with the original native ACK still pending.
    Published,
    /// Retains complete original publication and native acknowledgement.
    Acknowledged,
}

/// Selects one original terminal operation or unchanged terminal continuation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum NodeTerminalStateRequest {
    /// Executes within a ceiling, authenticates closure, and captures finalization.
    Capture {
        /// Names the independent original operation nonce in lowercase hex.
        execution: String,
        /// Selects independently installed native owners and semantic program.
        selections: Vec<InstalledNodeSelection>,
        /// Retains exact actor-compiled complete scenario bytes.
        scenario: Bytes,
        /// Bounds execution without supplying terminal or EOF authority.
        ceiling_ps: U64,
        /// Selects the original report publication and acknowledgement stage.
        stage: NodeTerminalStage,
    },
    /// Restores only saved original finalization, publication, and ACK custody.
    Restore {
        /// Names a new independent restore nonce.
        execution: String,
        /// Retains the original independently installed implementation roster.
        selections: Vec<InstalledNodeSelection>,
        /// Retains unchanged original actor-compiled scenario bytes.
        scenario: Bytes,
        /// Names the complete signed terminal archive in this private host realm.
        source: ContentRef,
        /// Selects a stage at or after the original retained custody stage.
        stage: NodeTerminalStage,
    },
    /// Reads the original commitment without native allocation or dispatch.
    Status {
        /// Names the original operation nonce.
        execution: String,
    },
}

impl NodeTerminalStateRequest {
    /// Builds a bounded terminal capture without treating its ceiling as EOF.
    ///
    /// # Errors
    /// Refuses malformed identities, unsupported topology or invalid authored bytes.
    pub fn capture(
        execution: String,
        selections: Vec<InstalledNodeSelection>,
        scenario: Vec<u8>,
        ceiling_ps: u64,
        stage: NodeTerminalStage,
    ) -> Result<Self, NodeControlError> {
        let request = Self::Capture {
            execution,
            selections,
            scenario: Bytes::new(scenario),
            ceiling_ps: U64::new(ceiling_ps),
            stage,
        };
        request.validate()?;
        Ok(request)
    }

    /// Builds an unchanged terminal restoration request without native authority.
    ///
    /// # Errors
    /// Refuses malformed identities, unsupported topology, source or scenario bytes.
    pub fn restore(
        execution: String,
        selections: Vec<InstalledNodeSelection>,
        scenario: Vec<u8>,
        source: ContentRef,
        stage: NodeTerminalStage,
    ) -> Result<Self, NodeControlError> {
        let request = Self::Restore {
            execution,
            selections,
            scenario: Bytes::new(scenario),
            source,
            stage,
        };
        request.validate()?;
        Ok(request)
    }

    /// Builds a read-only original terminal status request.
    ///
    /// # Errors
    /// Refuses malformed or zero operation nonces.
    pub fn status(execution: String) -> Result<Self, NodeControlError> {
        let request = Self::Status { execution };
        request.validate()?;
        Ok(request)
    }

    /// Returns the independent original operation nonce.
    #[must_use]
    pub fn execution(&self) -> &str {
        match self {
            Self::Capture { execution, .. }
            | Self::Restore { execution, .. }
            | Self::Status { execution } => execution,
        }
    }

    /// Validates bounded portable inputs without issuing native authority.
    ///
    /// # Errors
    /// Refuses invalid nonces, unsupported topologies, malformed scenario bytes
    /// or source references. Installed program and closure checks occur later.
    pub fn validate(&self) -> Result<(), NodeControlError> {
        execution_id(self.execution())?;
        let (selections, scenario) = match self {
            Self::Capture {
                selections,
                scenario,
                ceiling_ps,
                ..
            } => {
                if ceiling_ps.get() == 0 {
                    return Err(refused("terminal execution ceiling must be positive"));
                }
                (selections, scenario)
            }
            Self::Restore {
                selections,
                scenario,
                source,
                ..
            } => {
                source.validate()?;
                (selections, scenario)
            }
            Self::Status { .. } => return Ok(()),
        };
        validate_selections(selections)?;
        let mut semantic_nodes = 0usize;
        for selection in selections {
            match selection.kind {
                InstalledNodeKind::HostClock => {}
                InstalledNodeKind::HostSemantics { .. } => semantic_nodes += 1,
                _ => {
                    return Err(refused(
                        "terminal topology is not installed for this operation",
                    ));
                }
            }
        }
        if semantic_nodes != 1 || scenario.as_slice().len() > MAX_NODE_SCENARIO_BYTES {
            return Err(refused(
                "terminal operation requires one installed semantic owner",
            ));
        }
        NodeScenario::from_json(scenario.as_slice()).map_err(refused)?;
        Ok(())
    }
}
