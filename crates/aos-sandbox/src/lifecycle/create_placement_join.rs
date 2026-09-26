//! Non-authorizing Create placement evidence from protected, distinct sources.
//!
//! The join preserves the original lifecycle operation, a structural
//! assignment, and carrier-authenticated node observation. It does not reserve
//! capacity or prove the policy compiler's Create publication, specification,
//! manifest, quota, current lease, or exclusive aggregate accounting.

use aos_sandbox_core::{
    AssignmentEpoch, NodeId, ObjectDigest, OperationId, ProjectId, ResourceVector, SandboxId,
};

use crate::multi_node::{CarrierValidatedCapabilityObservationV1, NodeAdmissionStateV1};
use crate::runtime_authority::{RuntimeAuthorityBindingV1, RuntimeAuthorityStateV1};

use super::{CurrentLifecycleOperationV1, LifecycleIntentV1};

/// Reports why protected Create placement observations cannot be joined.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CreatePlacementJoinErrorV1 {
    /// The operation is not Create or names a different assignment/project.
    #[error("Create operation and current assignment differ")]
    AssignmentMismatch,
    /// The node observation names another node or is not accepting placement.
    #[error("node observation cannot admit this assignment")]
    NodeMismatch,
    /// The authenticated observation is outside its verifier interval.
    #[error("node observation is not current")]
    ObservationExpired,
    /// The assignment exceeds the node's total allocatable vector.
    #[error("assignment exceeds observed allocatable capacity")]
    CapacityExceeded,
}

/// Binds Create planning observations without granting a capacity reservation.
///
/// In particular, `NodeCapabilitySnapshotV1::reserved` is node-reported
/// observation, not an exclusive controller aggregate. A future reservation
/// owner must join the original policy Create publication and independently
/// commit/replay its complete aggregate under current authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreatePlacementObservationJoinV1 {
    operation: OperationId,
    sandbox: SandboxId,
    project: ProjectId,
    node: NodeId,
    epoch: AssignmentEpoch,
    assignment_digest: ObjectDigest,
    observation_digest: ObjectDigest,
    requested: ResourceVector,
    observation_valid_until_unix_seconds: u64,
}

impl CreatePlacementObservationJoinV1 {
    /// Joins one protected Create operation to a structural assignment and node observation.
    ///
    /// This value remains non-authorizing even when all three inputs match.
    /// The caller must separately prove the current ownership lease, exact
    /// policy Create publication, and exclusive durable aggregate reservation.
    ///
    /// # Errors
    ///
    /// Returns [`CreatePlacementJoinErrorV1`] for a mismatched Create,
    /// assignment, or node; expired observation; or impossible capacity.
    pub fn from_observations(
        operation: &CurrentLifecycleOperationV1<'_>,
        assignment: &RuntimeAuthorityBindingV1,
        observation: &CarrierValidatedCapabilityObservationV1,
        coordinator_unix_seconds: u64,
    ) -> Result<Self, CreatePlacementJoinErrorV1> {
        let LifecycleIntentV1::Create { sandbox } = operation.operation().intent() else {
            return Err(CreatePlacementJoinErrorV1::AssignmentMismatch);
        };
        let manifest = assignment.manifest().manifest();
        let snapshot = observation.snapshot();

        validate_join_shape(
            *sandbox,
            operation.operation().project(),
            assignment.state(),
            manifest.sandbox(),
            manifest.project(),
            manifest.node(),
            snapshot.node(),
            snapshot.admission(),
            observation.is_current_at(coordinator_unix_seconds),
            manifest.reservations(),
            snapshot.allocatable(),
        )?;

        Ok(Self {
            operation: operation.operation().operation_id(),
            sandbox: *sandbox,
            project: manifest.project(),
            node: manifest.node(),
            epoch: manifest.epoch(),
            assignment_digest: assignment.assignment_digest(),
            observation_digest: observation.evidence_binding_digest(),
            requested: manifest.reservations(),
            observation_valid_until_unix_seconds: observation.valid_until_unix_seconds(),
        })
    }

    /// Returns the original protected public Create operation.
    #[must_use]
    pub const fn operation(self) -> OperationId {
        self.operation
    }

    /// Returns the exact assigned sandbox.
    #[must_use]
    pub const fn sandbox(self) -> SandboxId {
        self.sandbox
    }

    /// Returns the operation and assignment's common project.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the assigned node.
    #[must_use]
    pub const fn node(self) -> NodeId {
        self.node
    }

    /// Returns the assignment epoch, not a lease or reservation generation.
    #[must_use]
    pub const fn epoch(self) -> AssignmentEpoch {
        self.epoch
    }

    /// Returns the exact canonical assignment commitment.
    #[must_use]
    pub const fn assignment_digest(self) -> ObjectDigest {
        self.assignment_digest
    }

    /// Returns the authenticated carrier observation commitment.
    #[must_use]
    pub const fn observation_digest(self) -> ObjectDigest {
        self.observation_digest
    }

    /// Returns the assignment's requested resource vector, not an accepted reservation.
    #[must_use]
    pub const fn requested(self) -> ResourceVector {
        self.requested
    }

    /// Returns the observation's verifier currentness deadline.
    #[must_use]
    pub const fn observation_valid_until_unix_seconds(self) -> u64 {
        self.observation_valid_until_unix_seconds
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_join_shape(
    create_sandbox: SandboxId,
    create_project: ProjectId,
    assignment_state: RuntimeAuthorityStateV1,
    assignment_sandbox: SandboxId,
    assignment_project: ProjectId,
    assignment_node: NodeId,
    observed_node: NodeId,
    observed_admission: NodeAdmissionStateV1,
    observation_current: bool,
    requested: ResourceVector,
    allocatable: ResourceVector,
) -> Result<(), CreatePlacementJoinErrorV1> {
    if assignment_state != RuntimeAuthorityStateV1::Bound
        || create_sandbox != assignment_sandbox
        || create_project != assignment_project
    {
        return Err(CreatePlacementJoinErrorV1::AssignmentMismatch);
    }
    if assignment_node != observed_node || observed_admission != NodeAdmissionStateV1::Accepting {
        return Err(CreatePlacementJoinErrorV1::NodeMismatch);
    }
    if !observation_current {
        return Err(CreatePlacementJoinErrorV1::ObservationExpired);
    }
    if !requested.is_within(allocatable) {
        return Err(CreatePlacementJoinErrorV1::CapacityExceeded);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use aos_sandbox_core::ResourceDimension;

    use super::*;

    #[test]
    fn join_shape_rejects_identity_expiry_and_capacity_substitutions() {
        let sandbox = SandboxId::from_bytes([1; 16]);
        let project = ProjectId::from_bytes([2; 16]);
        let node = NodeId::from_bytes([3; 16]);
        let requested = ResourceVector::new([1; ResourceDimension::COUNT]);
        let allocatable = ResourceVector::new([2; ResourceDimension::COUNT]);
        let check = |sandbox, project, state, node, admission, current, requested| {
            validate_join_shape(
                sandbox,
                project,
                state,
                SandboxId::from_bytes([1; 16]),
                ProjectId::from_bytes([2; 16]),
                NodeId::from_bytes([3; 16]),
                node,
                admission,
                current,
                requested,
                allocatable,
            )
        };

        assert_eq!(
            check(
                sandbox,
                project,
                RuntimeAuthorityStateV1::Bound,
                node,
                NodeAdmissionStateV1::Accepting,
                true,
                requested
            ),
            Ok(())
        );
        assert_eq!(
            check(
                SandboxId::from_bytes([4; 16]),
                project,
                RuntimeAuthorityStateV1::Bound,
                node,
                NodeAdmissionStateV1::Accepting,
                true,
                requested
            ),
            Err(CreatePlacementJoinErrorV1::AssignmentMismatch)
        );
        assert_eq!(
            check(
                sandbox,
                ProjectId::from_bytes([4; 16]),
                RuntimeAuthorityStateV1::Bound,
                node,
                NodeAdmissionStateV1::Accepting,
                true,
                requested
            ),
            Err(CreatePlacementJoinErrorV1::AssignmentMismatch)
        );
        assert_eq!(
            check(
                sandbox,
                project,
                RuntimeAuthorityStateV1::Revoked,
                node,
                NodeAdmissionStateV1::Accepting,
                true,
                requested
            ),
            Err(CreatePlacementJoinErrorV1::AssignmentMismatch)
        );
        assert_eq!(
            check(
                sandbox,
                project,
                RuntimeAuthorityStateV1::Bound,
                NodeId::from_bytes([5; 16]),
                NodeAdmissionStateV1::Accepting,
                true,
                requested
            ),
            Err(CreatePlacementJoinErrorV1::NodeMismatch)
        );
        assert_eq!(
            check(
                sandbox,
                project,
                RuntimeAuthorityStateV1::Bound,
                node,
                NodeAdmissionStateV1::Cordoned,
                true,
                requested
            ),
            Err(CreatePlacementJoinErrorV1::NodeMismatch)
        );
        assert_eq!(
            check(
                sandbox,
                project,
                RuntimeAuthorityStateV1::Bound,
                node,
                NodeAdmissionStateV1::Accepting,
                false,
                requested
            ),
            Err(CreatePlacementJoinErrorV1::ObservationExpired)
        );
        assert_eq!(
            check(
                sandbox,
                project,
                RuntimeAuthorityStateV1::Bound,
                node,
                NodeAdmissionStateV1::Accepting,
                true,
                ResourceVector::new([3; ResourceDimension::COUNT])
            ),
            Err(CreatePlacementJoinErrorV1::CapacityExceeded)
        );
    }
}
