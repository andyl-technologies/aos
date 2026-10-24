//! Freezes collecting-only connected grants and distinct original witness kinds.
//!
//! This data never creates an operation admission, runtime input batch or native
//! receipt. Actual dispatch retains the ordinary opaque collecting runtime and
//! checks the same installed source roster before and after every authority read.

use std::collections::BTreeSet;

use crucible_engine::node_contract::OperationRequest;
use crucible_node_format::{Id, Phase, U64, Validate};
use serde::Serialize;

use super::{QualificationError, refused};

/// Identifies a source-owned connected witness independently of old output cases.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketConnectedCaseKind {
    /// Retains the original complete input request and native staging receipt.
    Stage,
    /// Retains the original input ACK without prematurely consuming its bytes.
    InputAcknowledgement,
    /// Retains the exact original commit and consumed delivery inventory.
    Commit,
    /// Checks original delivery coordinates and payload custody.
    Delivery,
    /// Checks reactive state before exclusive publication visibility.
    Reaction,
    /// Checks original committed publication and its native producer bound.
    Publication,
    /// Retains pending original state before native retirement.
    BeforeRetirement,
    /// Checks finite containment and retained evidence after retirement.
    AfterRetirement,
    /// Refuses a cut beyond the actual unadvanced original producer frontier.
    SlowProducerRefusal,
    /// Checks finite phase closure over the declared zero-delay chain.
    ZeroDelayClosure,
    /// Checks positive-delay delivery without carrying the old microstep forward.
    PositiveDelayCoordinate,
    /// Checks the durable original root before granting any next publication.
    DurableRoot,
}

/// Selects one exact original collecting grant before native launch.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PacketConnectedGrant {
    /// Names the original participant receiving this grant.
    pub node: Id,
    /// Names the once-only original operation; IDs are unique across the world.
    pub operation: Id,
    /// Retains the complete exact request, including its exclusive full cut.
    pub request: OperationRequest,
}

/// Selects one distinct connected witness without supplying a Passed report.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PacketConnectedCase {
    /// Names the unique case within this complete population.
    pub id: String,
    /// Selects the closed original source interpretation.
    pub kind: PacketConnectedCaseKind,
    /// Names the original source participant whose custody must be checked.
    pub node: Id,
    /// Names the original grant, or no grant for input/containment witnesses.
    pub operation: Option<Id>,
}

/// Retains the complete finite connected scene, never a selected pair or singleton.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PacketConnectedSchedule {
    /// Preserves producer, relay and sink in the exact installed coordinator order.
    pub nodes: [Id; 3],
    /// Retains at most 64 globally unique original exact grants.
    pub grants: Vec<PacketConnectedGrant>,
    /// Retains every distinct original connected witness, initially NotExecuted.
    pub cases: Vec<PacketConnectedCase>,
}

impl PacketConnectedSchedule {
    /// Checks complete membership, bounded cuts and all source-owned witness kinds.
    ///
    /// This permits only the separately declared collecting scene. It cannot
    /// authenticate an actual operation, input cut, result or accepted class.
    ///
    /// # Errors
    /// Refuses incomplete/repeated participants or cases, foreign grant routes,
    /// unsupported requests, excessive full cuts or absent required witnesses.
    pub fn validate(&self) -> Result<(), QualificationError> {
        super::super::scope::encoded_size(self, 1024 * 1024)?;
        if self.nodes.iter().collect::<BTreeSet<_>>().len() != 3
            || self.grants.is_empty()
            || self.grants.len() > 64
            || self.cases.len() < 12
            || self.cases.len() > 128
        {
            return Err(refused());
        }
        let mut operations = BTreeSet::new();
        for grant in &self.grants {
            let (start, limit) = match &grant.request {
                OperationRequest::ExactRun { start, limit, .. } => (start, limit),
                OperationRequest::BoundarySettle { start, limit }
                    if start.time_ps == limit.time_ps =>
                {
                    (start, limit)
                }
                _ => return Err(refused()),
            };
            start.validate()?;
            limit.validate()?;
            if !self.nodes.contains(&grant.node)
                || !operations.insert(&grant.operation)
                || start >= limit
                || start.microstep > U64::new(16)
                || limit.microstep > U64::new(16)
                || start.phase == Phase::BoundaryControl && start.microstep != U64::new(0)
            {
                return Err(refused());
            }
        }
        let mut identifiers = BTreeSet::new();
        let mut kinds = BTreeSet::new();
        for case in &self.cases {
            if case.id.is_empty()
                || case.id.len() > 128
                || !case.id.starts_with("packet-connected-")
                || !identifiers.insert(&case.id)
                || !self.nodes.contains(&case.node)
                || case.operation.as_ref().is_some_and(|operation| {
                    !self
                        .grants
                        .iter()
                        .any(|grant| &grant.operation == operation && grant.node == case.node)
                })
            {
                return Err(refused());
            }
            kinds.insert(case.kind);
        }
        use PacketConnectedCaseKind::*;
        if kinds
            != BTreeSet::from([
                Stage,
                InputAcknowledgement,
                Commit,
                Delivery,
                Reaction,
                Publication,
                BeforeRetirement,
                AfterRetirement,
                SlowProducerRefusal,
                ZeroDelayClosure,
                PositiveDelayCoordinate,
                DurableRoot,
            ])
        {
            return Err(refused());
        }
        Ok(())
    }
}
