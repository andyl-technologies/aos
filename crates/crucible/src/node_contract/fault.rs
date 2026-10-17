//! Explicit recorded coefficient changes under original node operation custody.
//!
//! The request identifies an immutable installed controller decision. It is
//! portable data, not permission to mutate a node. The retaining runtime and
//! causal scheduler issue local authority only at the actual BoundaryControl
//! cursor; the selected native facet authenticates the complete program.
//!
//! The closed request is carried only by the explicit `FaultInjectionV1`
//! operation and its selected preservation edition:
//!
//! ```text
//! {"version":1,"facet_profile":"host/fault-injection-v1","program":{...},"decision":"0","at":{"time_ps":"12",...}}
//! ```

use crucible_node_contract::{ContentRef, Id, Phase, Position, U64, Validate};
use serde::{Deserialize, Serialize};

use super::{OperationFailure, OwnerIdentity, SavedRuntimeActivation};

/// Identifies one immutable authored native coefficient-table transition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaultMutationRequest {
    /// Selects this explicit operation grammar, currently one.
    pub version: u16,
    /// Binds the exact selected native operation facet profile.
    pub facet_profile: Id,
    /// Binds complete canonical independently installed controller bytes.
    pub program: ContentRef,
    /// Identifies the original zero-based decision in the immutable program.
    pub decision: U64,
    /// Retains the actual current BoundaryControl coordinate.
    pub at: Position,
}

impl FaultMutationRequest {
    /// Checks finite syntax without creating dispatch or native authority.
    ///
    /// # Errors
    /// Refuses unknown editions, malformed references/positions, decisions
    /// outside the bounded sixteen-transition grammar and other phases.
    pub fn validate(&self) -> Result<(), OperationFailure> {
        if self.version != 1
            || self.decision.get() >= 16
            || self.at.phase != Phase::BoundaryControl
            || self.program.length.get() == 0
            || self.program.length.get() > 1024 * 1024
        {
            return Err(invalid("fault mutation request has unsupported scope"));
        }
        self.program
            .validate()
            .and_then(|()| self.at.validate())
            .and_then(|()| self.facet_profile.validate())
            .map_err(|error| invalid(&error.to_string()))
    }
}

/// Retains original native application facts without creating fresh authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaultMutationRecord {
    /// Selects the exact native decision-record grammar, currently one.
    pub version: u16,
    /// Retains the original operation identity through query and ACK.
    pub operation: Id,
    /// Retains the authentic original logical participant.
    pub node: Id,
    /// Retains the complete original native owner roster.
    pub owners: Vec<OwnerIdentity>,
    /// Retains original authenticated world context as historical facts.
    pub source: SavedRuntimeActivation,
    /// Retains the exact original selected request.
    pub request: FaultMutationRequest,
    /// Counts original input decisions preceding the mutation.
    pub input_prefix: U64,
    /// Binds the original complete effective table before the change.
    pub previous_table: ContentRef,
    /// Binds the complete selected effective table after the change.
    pub applied_table: ContentRef,
}

fn invalid(reason: &str) -> OperationFailure {
    OperationFailure {
        effects: super::EffectKnowledge::None,
        reason: reason.into(),
    }
}
