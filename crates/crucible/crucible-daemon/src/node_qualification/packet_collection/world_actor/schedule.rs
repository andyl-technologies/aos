//! Validates the complete fixed 27-grant roster before any case or native work.

use std::collections::BTreeSet;

use crucible_engine::node_contract::{ExactBoundaryPolicy, OperationRequest};
use crucible_node_format::{HashRef, Id, Phase, Position, U64, Validate};
use serde::Serialize;

use super::{QualificationError, refused};

/// Freezes one original operation and distinct pre/post-ACK case identities.
#[derive(Serialize)]
pub struct PacketWorldGrant {
    /// Names this once-only original grant without a retry namespace.
    pub operation: Id,
    /// Retains its complete independently authored exact permission.
    pub request: OperationRequest,
    /// Gives this window's exclusive causal horizon.
    pub horizon: U64,
    /// Names the fixed original pre-ACK observation.
    pub before: String,
    /// Names the distinct fixed original post-ACK observation.
    pub after: String,
}

/// Freezes nine full-world windows over three exact independently bound nodes.
///
/// Rows are ordered window-major and then by the full world's participant order.
/// Each owner receives nine grants under one original activation; all 54 case IDs
/// are globally unique. Portable schedule data grants no execution permission.
#[derive(Serialize)]
pub struct PacketWorldSchedule {
    /// Names the exact complete selected node roster in world order.
    pub nodes: [Id; 3],
    /// Binds each exact current installed compatibility body.
    pub bindings: [HashRef; 3],
    /// Contains exactly 27 once-only source-installed grants.
    pub grants: Vec<PacketWorldGrant>,
}

impl PacketWorldSchedule {
    pub(in super::super) fn validate(&self) -> Result<(), QualificationError> {
        if self.grants.len() != 27 || self.nodes.iter().collect::<BTreeSet<_>>().len() != 3 {
            return Err(refused());
        }
        super::super::scope::encoded_size(self, 1024 * 1024)?;
        for node in &self.nodes {
            node.validate()?;
        }
        for binding in &self.bindings {
            binding.validate()?;
        }
        let mut operations = BTreeSet::new();
        let mut cases = BTreeSet::new();
        let mut start = U64::new(0);
        for window in 0..9 {
            let horizon = self.grants[window * 3].horizon;
            if horizon <= start {
                return Err(refused());
            }
            for member in 0..3 {
                let grant = &self.grants[window * 3 + member];
                grant.operation.validate()?;
                if grant.horizon != horizon
                    || grant.request
                        != (OperationRequest::ExactRun {
                            start: Position::new(start, U64::new(0), Phase::BoundaryControl),
                            limit: Position::new(horizon, U64::new(0), Phase::BoundaryControl),
                            boundary_policy: ExactBoundaryPolicy::HorizonPark,
                        })
                    || !operations.insert(&grant.operation)
                    || grant.before
                        != format!("packet-world-window-{window}-owner-{member}-before-ack")
                    || grant.after
                        != format!("packet-world-window-{window}-owner-{member}-after-ack")
                    || !cases.insert(&grant.before)
                    || !cases.insert(&grant.after)
                {
                    return Err(refused());
                }
            }
            start = horizon;
        }
        Ok(())
    }
}
