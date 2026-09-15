//! Tests retention-policy binding on materialized-start resume.

use super::*;

pub(super) fn assert_retention_policy_materialized_start(
    assignment: &SubmitAttemptRequest,
    prior_execution: ExecutionId,
    checkpoint: ExactCheckpointId,
    configuration: ConfigurationArtifactId,
) {
    let policy_basis = AttemptRetentionPolicyBasis::new(
        CampaignSnapshotId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignSnapshot,
            3,
            b"materialized-start-policy-snapshot",
        ))
        .expect("policy snapshot"),
        AttemptAdmissionId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignFact,
            3,
            b"materialized-start-policy-admission",
        ))
        .expect("policy admission"),
        CampaignPolicyId::from_content_id(ContentId::for_bytes(
            ObjectKind::Policy,
            4,
            b"materialized-start-policy",
        ))
        .expect("policy"),
    );
    let policy_assignment = SubmitAttemptRequest::new(
        assignment.assignment(),
        assignment.daemon_epoch(),
        assignment.lineage(),
        assignment.attempt(),
        assignment.resources(),
        assignment.retention(),
        crate::AttemptRetentionPolicyDisposition::Required(policy_basis),
    )
    .expect("policy-bound fresh assignment");
    let policy_resume = ResumeAttemptExecutionRequest::new_from_materialized_start(
        &policy_assignment,
        prior_execution,
        checkpoint,
        configuration,
    )
    .expect("policy-bound materialized-start resume");
    let policy_bytes = policy_resume.canonical_bytes();
    assert_eq!(&policy_bytes[..4], &6_u32.to_be_bytes());
    let decoded_policy_resume = ResumeAttemptExecutionRequest::from_canonical_bytes(&policy_bytes)
        .expect("decode policy-bound materialized-start resume");
    assert_eq!(decoded_policy_resume, policy_resume);
    assert_eq!(
        decoded_policy_resume.retention_policy(),
        crate::AttemptRetentionPolicyDisposition::Required(policy_basis)
    );
    assert_eq!(
        decoded_policy_resume
            .assignment_request()
            .expect("reconstruct fresh policy-bound assignment"),
        policy_assignment
    );
    assert_eq!(
        decoded_policy_resume.prior_execution_basis_digest(),
        attempt_execution_basis_digest_with_retention_policy(
            assignment.lineage(),
            assignment.attempt(),
            assignment.resources(),
            assignment.retention(),
            AttemptStartMode::CaptureMaterializedStart { configuration },
            crate::AttemptRetentionPolicyDisposition::Disabled,
        )
    );
    assert_eq!(
        decoded_policy_resume.execution_basis_digest(),
        policy_assignment.execution_basis_digest()
    );
}
