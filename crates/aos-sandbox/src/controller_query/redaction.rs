//! Redaction-by-construction controller query records.
//!
//! Public projection returns only the already checked generated protobuf
//! resource. Operator projection is a distinct non-serializable type carrying
//! protected diagnostics. There is no optional diagnostics field that a public
//! serializer can accidentally flatten.

use aos_proto::aos::sandbox::v1::{Operation, Sandbox, SandboxPhase};

use super::observation::{
    CheckedOperationObservationV1, CheckedSandboxObservationV1, GuardianEvidenceV1,
    OwnershipEvidenceV1,
};
use super::operator::OperatorDiagnosticsV1;
use super::resource::PublicConditionCodeV1;

/// Reports a contradiction between public placement and controller authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("controller authority state contradicts public sandbox placement")]
pub struct InvalidControllerProjection;

/// Identifies controller knowledge about assignment ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlacementAuthorityStateV1 {
    /// No assignment exists and the public resource has no placement tuple.
    Unassigned,
    /// Placement is selected but ownership/guardian authority is not active.
    AssignedAwaitingOwnership,
    /// Ownership and the fail-stop guardian are independently proven active.
    Owned,
    /// Authority was lost and containment is observed for the retained assignment.
    Fenced,
}

/// Retains checked public and protected sandbox query state.
#[derive(Clone, Debug, PartialEq)]
pub struct ControllerSandboxQueryV1 {
    public: CheckedSandboxObservationV1,
    authority: PlacementAuthorityStateV1,
    operator: OperatorDiagnosticsV1,
}

impl ControllerSandboxQueryV1 {
    /// Constructs a controller sandbox query after authority correlation.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidControllerProjection`] for partial or contradictory
    /// placement, including Ready without owned placement, Deleted with retained
    /// placement, or assigned-awaiting-ownership without its public condition.
    pub fn new(
        public: CheckedSandboxObservationV1,
        authority: PlacementAuthorityStateV1,
        operator: OperatorDiagnosticsV1,
    ) -> Result<Self, InvalidControllerProjection> {
        let resource = public.resource();
        let evidence_matches = matches!(
            (
                authority,
                public.additive().ownership(),
                public.additive().guardian()
            ),
            (
                PlacementAuthorityStateV1::Unassigned,
                OwnershipEvidenceV1::Unassigned,
                GuardianEvidenceV1::Disarmed
            ) | (
                PlacementAuthorityStateV1::AssignedAwaitingOwnership,
                OwnershipEvidenceV1::AwaitingOwnership(_),
                GuardianEvidenceV1::Arming(_)
            ) | (
                PlacementAuthorityStateV1::Owned,
                OwnershipEvidenceV1::Owned(_),
                GuardianEvidenceV1::Armed(_)
            ) | (
                PlacementAuthorityStateV1::Fenced,
                OwnershipEvidenceV1::Expired(_),
                GuardianEvidenceV1::Contained(_)
            )
        );
        let valid = evidence_matches
            && public
                .additive()
                .correlates_to_placement(resource.placement())
            && authority_phase_allowed(authority, resource.phase())
            && match authority {
                PlacementAuthorityStateV1::Unassigned => !resource.has_placement(),
                PlacementAuthorityStateV1::AssignedAwaitingOwnership => {
                    resource.has_placement()
                        && public
                            .has_current_true_condition(PublicConditionCodeV1::OwnershipPending)
                }
                PlacementAuthorityStateV1::Owned => resource.has_placement(),
                PlacementAuthorityStateV1::Fenced => {
                    resource.has_placement()
                        && public.has_current_true_condition(PublicConditionCodeV1::Fenced)
                }
            };
        if !valid
            || (resource.phase() == SandboxPhase::SANDBOX_PHASE_READY
                && authority != PlacementAuthorityStateV1::Owned)
            || (resource.phase() == SandboxPhase::SANDBOX_PHASE_DELETED
                && authority != PlacementAuthorityStateV1::Unassigned)
        {
            return Err(InvalidControllerProjection);
        }
        Ok(Self {
            public,
            authority,
            operator,
        })
    }

    /// Returns the correlated placement-authority state.
    #[must_use]
    pub const fn authority(&self) -> PlacementAuthorityStateV1 {
        self.authority
    }
}

fn authority_phase_allowed(authority: PlacementAuthorityStateV1, phase: SandboxPhase) -> bool {
    use PlacementAuthorityStateV1 as A;
    use SandboxPhase as P;

    matches!(
        (authority, phase),
        (
            A::Unassigned,
            P::SANDBOX_PHASE_REQUESTED
                | P::SANDBOX_PHASE_PREPARING
                | P::SANDBOX_PHASE_STOPPED
                | P::SANDBOX_PHASE_HIBERNATED
                | P::SANDBOX_PHASE_DELETING
                | P::SANDBOX_PHASE_DELETED
                | P::SANDBOX_PHASE_ERROR
        ) | (
            A::AssignedAwaitingOwnership,
            P::SANDBOX_PHASE_REQUESTED | P::SANDBOX_PHASE_PREPARING | P::SANDBOX_PHASE_ERROR
        ) | (
            A::Owned,
            P::SANDBOX_PHASE_STARTING
                | P::SANDBOX_PHASE_READY
                | P::SANDBOX_PHASE_FREEZING
                | P::SANDBOX_PHASE_FROZEN
                | P::SANDBOX_PHASE_STOPPING
                | P::SANDBOX_PHASE_ERROR
        ) | (
            A::Fenced,
            P::SANDBOX_PHASE_STOPPING | P::SANDBOX_PHASE_ERROR | P::SANDBOX_PHASE_LOST
        )
    )
}

/// Retains checked public and protected operation query state.
#[derive(Clone, Debug, PartialEq)]
pub struct ControllerOperationQueryV1 {
    public: CheckedOperationObservationV1,
    operator: OperatorDiagnosticsV1,
}

impl ControllerOperationQueryV1 {
    /// Constructs a controller operation query with separated surfaces.
    #[must_use]
    pub const fn new(
        public: CheckedOperationObservationV1,
        operator: OperatorDiagnosticsV1,
    ) -> Self {
        Self { public, operator }
    }
}

/// Stores the protected operator sandbox projection.
#[derive(Clone, Debug, PartialEq)]
pub struct OperatorSandboxProjectionV1 {
    public: Sandbox,
    authority: PlacementAuthorityStateV1,
    diagnostics: OperatorDiagnosticsV1,
}

impl OperatorSandboxProjectionV1 {
    /// Returns the established public protobuf portion.
    #[must_use]
    pub const fn public(&self) -> &Sandbox {
        &self.public
    }

    /// Returns the correlated placement-authority state.
    #[must_use]
    pub const fn authority(&self) -> PlacementAuthorityStateV1 {
        self.authority
    }

    /// Returns protected diagnostics to an already authorized operator path.
    #[must_use]
    pub const fn diagnostics(&self) -> &OperatorDiagnosticsV1 {
        &self.diagnostics
    }
}

/// Stores the protected operator operation projection.
#[derive(Clone, Debug, PartialEq)]
pub struct OperatorOperationProjectionV1 {
    public: Operation,
    diagnostics: OperatorDiagnosticsV1,
}

impl OperatorOperationProjectionV1 {
    /// Returns the established public protobuf portion.
    #[must_use]
    pub const fn public(&self) -> &Operation {
        &self.public
    }

    /// Returns protected diagnostics to an already authorized operator path.
    #[must_use]
    pub const fn diagnostics(&self) -> &OperatorDiagnosticsV1 {
        &self.diagnostics
    }
}

/// Constructs a public sandbox response using established ProtoJSON semantics.
#[must_use]
pub fn redact_sandbox_for_public(query: &ControllerSandboxQueryV1) -> Sandbox {
    query.public.resource().as_proto().clone()
}

/// Constructs a protected operator sandbox projection.
#[must_use]
pub fn project_sandbox_for_operator(
    query: &ControllerSandboxQueryV1,
) -> OperatorSandboxProjectionV1 {
    OperatorSandboxProjectionV1 {
        public: query.public.resource().as_proto().clone(),
        authority: query.authority,
        diagnostics: query.operator.clone(),
    }
}

/// Constructs a public operation response using established ProtoJSON semantics.
#[must_use]
pub fn redact_operation_for_public(query: &ControllerOperationQueryV1) -> Operation {
    query.public.resource().as_proto().clone()
}

/// Constructs a protected operator operation projection.
#[must_use]
pub fn project_operation_for_operator(
    query: &ControllerOperationQueryV1,
) -> OperatorOperationProjectionV1 {
    OperatorOperationProjectionV1 {
        public: query.public.resource().as_proto().clone(),
        diagnostics: query.operator.clone(),
    }
}
