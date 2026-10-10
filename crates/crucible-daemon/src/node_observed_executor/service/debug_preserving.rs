//! Owns explicit condition capture and fresh stopped-world operator requests.
//!
//! ```text
//! PreservingDebug.1: original claim -> ACKed Stop -> signed capture
//!                   -> fresh stopped owner -> current reconciliation -> Resume
//! ```
//!
//! Durable status contains original data only. A new request must receive the
//! one common original claim before an owning actor can allocate native state.

pub(super) mod actor;
use super::debug::budget;
mod ledger;
mod worker;

use super::{NodeObservationService, NodeObservationServiceError, refused};
use crate::node_observed_executor::{
    InstalledHostIoProfile, InstalledNodeKind, InstalledNodeSelection,
};
use crucible_node_contract::{Bytes, ContentRef, Id, Position, U64, Validate, canonical};
use serde::{Deserialize, Serialize};

pub(super) use ledger::{Ledger, Reservation};

/// Selects original capture or a separately claimed fresh stopped target.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum NodePreservingDebugAction {
    /// Captures the current original ACKed, unresumed condition Stop.
    Capture {},
    /// Restores the exact capture associated with a retained original route.
    Restore {
        /// Names the original source's common claim and immutable request.
        source_execution: String,
        /// Names the signed capture sealed by that original owning actor.
        capture: ContentRef,
    },
}

/// Retains a complete source-authored preserving world before native admission.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodePreservingDebugRequest {
    /// Names the closed operator request format.
    pub format: String,
    /// Selects the first explicit preserving operator grammar.
    pub version: u32,
    /// Names a fresh original common-route execution claim.
    pub execution: String,
    /// Names all independently installed participants and owners in node order.
    pub selections: Vec<InstalledNodeSelection>,
    /// Retains the exact authored scenario, independently regenerated before work.
    pub scenario: Bytes,
    /// Names the sole installed preserving condition observer.
    pub observer: Id,
    /// Bounds original native work without declaring EOF.
    pub maximum_physical_cut: U64,
    /// Declares finite expanded record credit before preparation.
    pub maximum_record_bytes: U64,
    /// Selects original capture or an independently authenticated fresh target.
    pub action: NodePreservingDebugAction,
}

impl NodePreservingDebugRequest {
    /// Validates the closed three-participant Block recipe before its claim.
    ///
    /// # Errors
    /// Refuses unsupported formats, unsafe identities, incomplete rosters,
    /// unqualified models, excessive bytes or unsupported record credit.
    pub fn validate(&self) -> Result<(), NodeObservationServiceError> {
        super::conditional_preparation::validate_execution(&self.execution)?;
        self.observer.validate().map_err(refused)?;
        if self.format != "crucible.preserving-debug-request"
            || self.version != 1
            || self.selections.len() != 3
            || self
                .selections
                .windows(2)
                .any(|pair| pair[0].node >= pair[1].node)
            || self.maximum_physical_cut.get() == 0
            || !(8 << 20..=64 << 20).contains(&self.maximum_record_bytes.get())
            || self.scenario.as_slice().len() > 1024 * 1024
        {
            return Err(refused(
                "preserving Debug edition or finite geometry differs",
            ));
        }
        let mut observer = 0;
        let mut source = 0;
        let mut block = None;
        let mut source_consumer = None;
        for selection in &self.selections {
            selection.node.validate().map_err(refused)?;
            selection.owner.validate().map_err(refused)?;
            match &selection.kind {
                InstalledNodeKind::HostConditionDebugPreserving { .. }
                    if selection.node == self.observer =>
                {
                    observer += 1
                }
                InstalledNodeKind::HostScripted { profile } => {
                    source += 1;
                    source_consumer = Some(&profile.consumer);
                }
                InstalledNodeKind::HostIo {
                    profile: InstalledHostIoProfile::Block { .. },
                } if block.is_none() => block = Some(&selection.node),
                _ => {
                    return Err(refused(
                        "model is outside preserving Debug's closed Block scope",
                    ));
                }
            }
        }
        if observer != 1 || source != 1 || block.is_none() || source_consumer != block {
            return Err(refused(
                "preserving Debug requires the complete source/Block/observer route",
            ));
        }
        if let NodePreservingDebugAction::Restore {
            source_execution,
            capture,
        } = &self.action
        {
            super::conditional_preparation::validate_execution(source_execution)?;
            capture.validate().map_err(refused)?;
            if source_execution == &self.execution {
                return Err(refused(
                    "fresh target cannot reuse the original source execution",
                ));
            }
        }
        budget::bounded_json(self, 2 * 1024 * 1024)?;
        if encode(self)?.len() > 2 * 1024 * 1024 {
            return Err(refused("preserving Debug request byte ceiling"));
        }
        Ok(())
    }

    /// Decodes bounded duplicate-free request bytes without native authority.
    ///
    /// # Errors
    /// Refuses excessive bytes, duplicate/unknown fields or invalid scope.
    pub fn from_json(bytes: &[u8]) -> Result<Self, NodeObservationServiceError> {
        let request: Self =
            serde_json::from_value(canonical::parse_json(bytes, 2 << 20).map_err(refused)?)
                .map_err(refused)?;
        request.validate()?;
        Ok(request)
    }
}

/// Reserves one unchanged Resume operation for a current stopped owner.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodePreservingDebugResumeRequest {
    /// Names the closed preserving Resume format.
    pub format: String,
    /// Selects the first preserving Resume grammar.
    pub version: u32,
    /// Names the unchanged current owning execution.
    pub execution: String,
    /// Bounds the future suffix after the authentic original cut.
    pub horizon_ps: U64,
}

impl NodePreservingDebugResumeRequest {
    /// Checks finite original Resume scope before durable reservation.
    ///
    /// # Errors
    /// Refuses unsupported editions, unsafe identities or zero horizons.
    pub fn validate(&self) -> Result<(), NodeObservationServiceError> {
        super::conditional_preparation::validate_execution(&self.execution)?;
        if self.format != "crucible.preserving-debug-resume"
            || self.version != 1
            || self.horizon_ps.get() == 0
        {
            return Err(refused(
                "preserving Debug Resume edition or horizon differs",
            ));
        }
        Ok(())
    }

    /// Decodes bounded duplicate-free Resume bytes without granting dispatch.
    ///
    /// # Errors
    /// Refuses malformed, excessive or unsupported requests.
    pub fn from_json(bytes: &[u8]) -> Result<Self, NodeObservationServiceError> {
        let request: Self =
            serde_json::from_value(canonical::parse_json(bytes, 4096).map_err(refused)?)
                .map_err(refused)?;
        request.validate()?;
        Ok(request)
    }
}

/// Retains the original source relation and authentic ACKed Stop capture.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodePreservingDebugCapture {
    /// Names the original common-route execution.
    pub source_execution: String,
    /// Roots its exact original request bytes.
    pub source_request: String,
    /// Names the signed whole-world archive, never a restore permit.
    pub artifact: ContentRef,
    /// Retains the authentic original Stop cut.
    pub cut: Position,
    /// Names the actual original native Stop receipt.
    pub barrier: ContentRef,
    /// Names the original durably committed condition report.
    pub report: ContentRef,
}

/// Reports original operator custody without exposing native permissions.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum NodePreservingDebugState {
    /// Exact request custody is durable, without native admission.
    AwaitingAdmission {},
    /// Original ACKed Stop and capture were reported; status supplies no live owner.
    Stopped {},
    /// One exact original Resume request is durable.
    AwaitingResume {},
    /// Original Resume and suffix completed, published and genuinely reclaimed.
    Resumed {
        /// Roots the authentic unchanged native Resume receipt.
        receipt: ContentRef,
        /// Roots exact native future publications and FIFO/causal context.
        publications: ContentRef,
    },
    /// Original custody requires containment or reconciliation; no redispatch.
    Unknown {
        /// Gives a bounded diagnostic without asserting absence of effects.
        reason: String,
    },
}

/// Retains exact original requests and immutable capture history for status.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodePreservingDebugRecord {
    /// Names the closed durable record format.
    pub format: String,
    /// Selects the first durable preserving record grammar.
    pub version: u32,
    /// Names the unchanged original execution.
    pub execution: String,
    /// Roots exact original prepare request bytes.
    pub request: String,
    /// Roots the optional exact once-only Resume request.
    pub resume_request: Option<String>,
    /// Retains the original source capture across all later transitions.
    pub capture: Option<NodePreservingDebugCapture>,
    /// Reports durable data without returning a live owner.
    pub outcome: NodePreservingDebugState,
}

pub(super) fn encode(value: &impl Serialize) -> Result<Vec<u8>, NodeObservationServiceError> {
    canonical::canonical_json(&serde_json::to_value(value).map_err(refused)?).map_err(refused)
}

impl NodeObservationService {
    /// Reserves original preserving custody before queueing native work.
    ///
    /// # Errors
    /// Refuses changed nonces, foreign captures, unavailable actors or queue credit.
    pub fn prepare_preserving_debug(
        &self,
        request: NodePreservingDebugRequest,
    ) -> Result<NodePreservingDebugRecord, NodeObservationServiceError> {
        self.preserving_prepare(request)
    }

    /// Reserves one current-owner Resume without replacing an original.
    ///
    /// # Errors
    /// Refuses missing stopped custody, changed requests or unavailable actors.
    pub fn resume_preserving_debug(
        &self,
        request: NodePreservingDebugResumeRequest,
    ) -> Result<NodePreservingDebugRecord, NodeObservationServiceError> {
        self.preserving_resume(request)
    }

    /// Reads authenticated retained status without allocating a native world.
    ///
    /// # Errors
    /// Refuses absent, corrupt or incompatible originals.
    pub fn preserving_debug_state(
        &self,
        execution: &str,
    ) -> Result<NodePreservingDebugRecord, NodeObservationServiceError> {
        self.preserving_debug.state(execution)
    }
}

#[cfg(test)]
mod tests;
