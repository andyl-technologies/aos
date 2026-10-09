//! Opaque coordinator grants and validated runtime completion observations.

use std::time::Duration;

use crucible_node_contract::{Id, Position};

use crate::node_contract::{
    ExactBoundaryPolicy, OperationRequest, ProgressEvidence, WorldActivation,
};

use super::NativeSchedulingObservation;

/// Carries exact execution permission derived from the activated causal graph.
///
/// Grants have no public constructor, clone operation or serialized authority.
/// Issuance retains the owner reservation even if the caller drops this value.
#[derive(Debug)]
pub struct ExactGrant {
    pub(crate) activation: WorldActivation,
    pub(crate) node: Id,
    pub(crate) operation: Id,
    pub(crate) permission: ExactPermission,
    pub(crate) input_batch: Option<Id>,
}

#[derive(Debug)]
pub(crate) enum ExactPermission {
    Run {
        start: Position,
        limit: Position,
        boundary_policy: ExactBoundaryPolicy,
    },
    Settlement {
        start: Position,
        limit: Position,
    },
}

/// Carries one immutable quantized input cut and its original output window.
#[derive(Debug)]
pub struct QuantizedGrant {
    pub(crate) activation: WorldActivation,
    pub(crate) node: Id,
    pub(crate) operation: Id,
    pub(crate) window: Id,
    pub(crate) start: Position,
    pub(crate) end: Position,
    pub(crate) input_batch: Id,
    pub(crate) host_budget: Duration,
}

/// Selects one causally admitted execution permission without widening its mode.
#[derive(Debug)]
pub enum ExecutionAdmission {
    /// Authorizes qualified half-open exact execution or boundary settlement.
    Exact(ExactGrant),
    /// Authorizes one complete fixed input batch and original output window.
    Quantized(QuantizedGrant),
}

impl ExecutionAdmission {
    /// Returns the immutable logical node receiving this permission.
    pub fn node(&self) -> &Id {
        match self {
            Self::Exact(grant) => &grant.node,
            Self::Quantized(grant) => &grant.node,
        }
    }

    /// Returns the original operation identity retained across completion.
    pub fn operation(&self) -> &Id {
        match self {
            Self::Exact(grant) => &grant.operation,
            Self::Quantized(grant) => &grant.operation,
        }
    }

    /// Returns the ordered start coordinate without establishing actual progress.
    pub fn start(&self) -> Position {
        match self {
            Self::Exact(grant) => match grant.permission {
                ExactPermission::Run { start, .. } | ExactPermission::Settlement { start, .. } => {
                    start
                }
            },
            Self::Quantized(grant) => grant.start,
        }
    }

    /// Returns the exclusive exact ceiling or quantized publication boundary.
    pub fn limit(&self) -> Position {
        match self {
            Self::Exact(grant) => match grant.permission {
                ExactPermission::Run { limit, .. } | ExactPermission::Settlement { limit, .. } => {
                    limit
                }
            },
            Self::Quantized(grant) => grant.end,
        }
    }

    pub(crate) fn activation(&self) -> &WorldActivation {
        match self {
            Self::Exact(grant) => &grant.activation,
            Self::Quantized(grant) => &grant.activation,
        }
    }

    pub(crate) fn input_batch(&self) -> Option<&Id> {
        match self {
            Self::Exact(grant) => grant.input_batch.as_ref(),
            Self::Quantized(grant) => Some(&grant.input_batch),
        }
    }

    pub(crate) fn request(&self) -> OperationRequest {
        match self {
            Self::Exact(grant) => match grant.permission {
                ExactPermission::Run {
                    start,
                    limit,
                    boundary_policy,
                } => OperationRequest::ExactRun {
                    start,
                    limit,
                    boundary_policy,
                },
                ExactPermission::Settlement { start, limit } => {
                    OperationRequest::BoundarySettle { start, limit }
                }
            },
            Self::Quantized(grant) => OperationRequest::QuantumBegin {
                window: grant.window.clone(),
                start: grant.start,
                end: grant.end,
                input_batch: grant.input_batch.clone(),
                host_budget: grant.host_budget,
            },
        }
    }
}

/// Carries a native completion validated by the retaining node runtime.
///
/// Reading a provider result or constructing a portable receipt does not create
/// this authority. Only the runtime that owns the original operation can mint it.
#[derive(Debug)]
pub struct SchedulingReceipt {
    pub(crate) activation: WorldActivation,
    pub(crate) node: Id,
    pub(crate) operation: Id,
    pub(crate) progress: ProgressEvidence,
    pub(crate) retained_outputs: Vec<Id>,
    pub(crate) observation: Option<NativeSchedulingObservation>,
}

impl SchedulingReceipt {
    pub(crate) fn new(
        activation: WorldActivation,
        node: Id,
        operation: Id,
        progress: ProgressEvidence,
        retained_outputs: Vec<Id>,
        observation: Option<NativeSchedulingObservation>,
    ) -> Self {
        Self {
            activation,
            node,
            operation,
            progress,
            retained_outputs,
            observation,
        }
    }

    /// Returns the immutable original operation identity.
    pub fn operation(&self) -> &Id {
        &self.operation
    }

    /// Returns the actual reached-position or original-window closure evidence.
    pub fn progress(&self) -> &ProgressEvidence {
        &self.progress
    }
}

/// Carries the coordinator's validated publication and original custody decision.
///
/// This token cannot be constructed from output identifiers supplied by a caller.
/// The runtime consumes it before releasing the matching native operation.
#[derive(Debug)]
pub struct SchedulingCommit {
    pub(crate) activation: WorldActivation,
    pub(crate) node: Id,
    pub(crate) operation: Id,
    pub(crate) retained_outputs: Vec<Id>,
}

impl SchedulingCommit {
    pub(crate) fn retained_copy(&self) -> Self {
        Self {
            activation: self.activation.clone(),
            node: self.node.clone(),
            operation: self.operation.clone(),
            retained_outputs: self.retained_outputs.clone(),
        }
    }

    /// Returns the original operation whose obligations were committed.
    pub fn operation(&self) -> &Id {
        &self.operation
    }

    /// Returns the original inventory acknowledged by the coordinator.
    pub fn retained_outputs(&self) -> &[Id] {
        &self.retained_outputs
    }

    pub(crate) fn activation(&self) -> &WorldActivation {
        &self.activation
    }

    pub(crate) fn node(&self) -> &Id {
        &self.node
    }
}
