//! Closed public Sandbox successor for a verified Storage Repair.
//!
//! A physical Storage resource digest is never a public Sandbox version. The
//! terminal owner must independently verify and retain V3 physical proof before
//! using this builder in an atomic public-ledger and protected-head transition.

use aos_proto::aos::sandbox::v1::Sandbox;
use aos_sandbox_core::{OperationId, ProjectId};

use crate::OperationCompilationError;
use crate::controller_query::{CheckedSandboxResourceV1, PublicOperationMethodV1};
use crate::controller_service::public_projection::{
    PublicProjectionPlanV1, PublicProjectionResourceV1,
};

/// Prepares the only public Sandbox fields a Storage Repair may advance.
///
/// The predecessor must be fully observed at the physical generation signed
/// by Storage. Repair does not claim a new observation, phase, condition, or
/// physical generation. The new public version uses the established Controller
/// operation/generation/request derivation, independently of Storage's digest.
///
/// # Errors
///
/// Rejects a stale predecessor, unobserved desired generation, exhausted
/// generation, invalid successor, or invalid projection ownership.
#[allow(dead_code, reason = "public operator Repair route remains closed")]
pub(crate) fn repair_sandbox_successor_projection_v1(
    predecessor: &CheckedSandboxResourceV1,
    project: ProjectId,
    operation: OperationId,
    request_digest: [u8; 32],
    expected_version: &[u8],
    verified_physical_generation: u64,
) -> Result<PublicProjectionPlanV1, OperationCompilationError> {
    let sandbox = next_repaired_sandbox(
        predecessor,
        project,
        operation,
        request_digest,
        expected_version,
        verified_physical_generation,
    )?;
    PublicProjectionPlanV1::new(
        project,
        operation,
        PublicProjectionResourceV1::Sandbox(sandbox),
    )
    .map_err(|_| OperationCompilationError::Rejected)
}

fn next_repaired_sandbox(
    predecessor: &CheckedSandboxResourceV1,
    project: ProjectId,
    operation: OperationId,
    request_digest: [u8; 32],
    expected_version: &[u8],
    verified_physical_generation: u64,
) -> Result<Sandbox, OperationCompilationError> {
    let mut sandbox = predecessor.as_proto().clone();
    let desired = sandbox
        .desired
        .as_option_mut()
        .ok_or(OperationCompilationError::Rejected)?;
    let observed = sandbox
        .observed
        .as_option()
        .ok_or(OperationCompilationError::Rejected)?;
    if sandbox.project_id.as_slice() != project.as_bytes()
        || sandbox.resource_version != expected_version
        || desired.generation != verified_physical_generation
        || observed.desired_generation != verified_physical_generation
        || request_digest == [0; 32]
        || verified_physical_generation == 0
    {
        return Err(OperationCompilationError::Rejected);
    }

    let generation = desired
        .generation
        .checked_add(1)
        .ok_or(OperationCompilationError::Rejected)?;
    desired.generation = generation;
    sandbox.resource_version = super::super::public_mutation::resource_version(
        operation,
        PublicOperationMethodV1::OperatorRecover,
        generation,
        request_digest,
    );

    CheckedSandboxResourceV1::try_from(sandbox)
        .map(CheckedSandboxResourceV1::into_proto)
        .map_err(|_| OperationCompilationError::Rejected)
}

#[cfg(test)]
mod tests {
    use aos_proto::aos::sandbox::v1::{
        DesiredLifecycle, ObjectDescriptor, SandboxDesiredState, SandboxObservedState,
        SandboxPhase, Timestamp,
    };

    use super::*;

    fn descriptor(media_type: &str, digest: u8) -> ObjectDescriptor {
        ObjectDescriptor {
            media_type: media_type.to_owned(),
            sha256: vec![digest; 32],
            encoded_size: 1,
            ..Default::default()
        }
    }

    fn predecessor() -> CheckedSandboxResourceV1 {
        let policy = descriptor("application/vnd.aos.sandbox.policy.v1+cbor", 5);
        let sandbox = Sandbox {
            sandbox_id: vec![1; 16],
            project_id: vec![2; 16],
            resource_version: vec![3; 32],
            desired: Some(SandboxDesiredState {
                specification: Some(descriptor("application/vnd.aos.sandbox.spec.v1+cbor", 4))
                    .into(),
                requested_policy: Some(policy.clone()).into(),
                lifecycle: DesiredLifecycle::DESIRED_LIFECYCLE_STOPPED.into(),
                generation: 7,
                ..Default::default()
            })
            .into(),
            observed: Some(SandboxObservedState {
                phase: SandboxPhase::SANDBOX_PHASE_REQUESTED.into(),
                desired_generation: 7,
                observation_sequence: 9,
                ..Default::default()
            })
            .into(),
            effective_policy: Some(policy).into(),
            created_at: Some(Timestamp {
                seconds: 100,
                ..Default::default()
            })
            .into(),
            updated_at: Some(Timestamp {
                seconds: 101,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        CheckedSandboxResourceV1::try_from(sandbox).unwrap()
    }

    #[test]
    fn repair_successor_advances_only_desired_identity() {
        let predecessor = predecessor();
        let plan = repair_sandbox_successor_projection_v1(
            &predecessor,
            ProjectId::from_bytes([2; 16]),
            OperationId::from_bytes([6; 16]),
            [7; 32],
            &[3; 32],
            7,
        )
        .unwrap();
        let successor = next_repaired_sandbox(
            &predecessor,
            ProjectId::from_bytes([2; 16]),
            OperationId::from_bytes([6; 16]),
            [7; 32],
            &[3; 32],
            7,
        )
        .unwrap();
        let before = predecessor.as_proto();

        assert!(!plan.desired_key().is_empty());
        assert!(!plan.desired_value().is_empty());
        assert_eq!(successor.desired.as_option().unwrap().generation, 8);
        assert_eq!(successor.observed, before.observed);
        assert_eq!(successor.effective_policy, before.effective_policy);
        assert_eq!(successor.updated_at, before.updated_at);
        assert_eq!(
            successor.resource_version,
            super::super::super::public_mutation::resource_version(
                OperationId::from_bytes([6; 16]),
                PublicOperationMethodV1::OperatorRecover,
                8,
                [7; 32],
            )
        );
    }

    #[test]
    fn repair_successor_rejects_stale_observation_and_generation() {
        let predecessor = predecessor();
        let mut stale = predecessor.as_proto().clone();
        stale.desired.as_option_mut().unwrap().generation = 8;
        let stale = CheckedSandboxResourceV1::try_from(stale).unwrap();

        for (resource, generation) in [(&predecessor, 6), (&stale, 7)] {
            assert!(
                next_repaired_sandbox(
                    resource,
                    ProjectId::from_bytes([2; 16]),
                    OperationId::from_bytes([6; 16]),
                    [7; 32],
                    &[3; 32],
                    generation,
                )
                .is_err()
            );
        }
        assert!(
            next_repaired_sandbox(
                &predecessor,
                ProjectId::from_bytes([2; 16]),
                OperationId::from_bytes([6; 16]),
                [7; 32],
                &[9; 32],
                7,
            )
            .is_err()
        );
    }
}
