//! Produces real compiler claims through genuine durable framing.
//!
//! Synthetic inputs and prerequisite evidence remain test-only. Pure compilation
//! and claim extraction do not establish installed Root or publication authority.

use aos_sandbox_core::model::CacheDomainKind;

use super::*;

pub(in crate::policy_compiler) struct FixturePublicationV1 {
    pub(in crate::policy_compiler) project: ProjectId,
    pub(in crate::policy_compiler) sandbox: SandboxId,
    pub(in crate::policy_compiler) candidate: ObjectDigest,
    pub(in crate::policy_compiler) input: ObjectDigest,
    pub(in crate::policy_compiler) diagnostics: ObjectDigest,
    pub(in crate::policy_compiler) prerequisites: PolicyPublicationPrerequisitesV1,
    pub(in crate::policy_compiler) body: Vec<u8>,
    pub(in crate::policy_compiler) policy: Vec<u8>,
}

pub(in crate::policy_compiler) fn publication(domain: CacheDomainKind) -> FixturePublicationV1 {
    compiled_publication_from_input(compiler_input(4096, domain, Vec::new()))
}

/// Reuses the real pure compiler fixture, not an installed input authority.
pub(in crate::policy_compiler) fn compiled_publication() -> FixturePublicationV1 {
    let verified = super::candidate_tests::fixture(4096);
    compiled_publication_from_verified(verified)
}

pub(in crate::policy_compiler) fn compiler_input(
    amount: u64,
    domain: CacheDomainKind,
    grants: Vec<aos_sandbox_core::Grant>,
) -> PolicyCompilerInputV1 {
    super::candidate_tests::compiler_input(amount, domain, grants)
}

pub(in crate::policy_compiler) fn compiled_publication_from_input(
    input: PolicyCompilerInputV1,
) -> FixturePublicationV1 {
    compiled_publication_from_verified(super::candidate_tests::fixture_from_input(input))
}

fn compiled_publication_from_verified(
    verified: VerifiedPolicyPublicationV1,
) -> FixturePublicationV1 {
    let diagnostics = digest_bytes(DIAGNOSTICS_DOMAIN, &verified.diagnostics);
    let body = encode_candidate_payload(1, verified.body_fields(), diagnostics).unwrap();
    let policy = verified.candidate.portable().policy_bytes().to_vec();
    FixturePublicationV1 {
        project: verified.project,
        sandbox: verified.sandbox,
        candidate: verified.candidate.commitment().digest(),
        input: verified.normalized_input,
        diagnostics,
        prerequisites: verified.prerequisites,
        body,
        policy,
    }
}

pub(in crate::policy_compiler) fn replay_validator(
    fixture: &FixturePublicationV1,
) -> PolicyCompilerReplayValidatorV1 {
    PolicyCompilerReplayValidatorV1 {
        authenticated_prerequisites: BTreeMap::from([(
            fixture.prerequisites.digest(),
            fixture.prerequisites.clone(),
        )]),
    }
}

pub(in crate::policy_compiler) fn commit(journal: &mut Journal, fixture: &FixturePublicationV1) {
    let validator = replay_validator(fixture);
    let candidate = policy_reducer_envelope(
        policy_key(
            PolicyCompilerJournalRecordKindV1::Candidate,
            fixture.project,
            fixture.sandbox,
            fixture.candidate,
        )
        .unwrap(),
        1,
        None,
        &fixture.body,
        &validator,
    )
    .unwrap();
    let current = policy_reducer_envelope(
        policy_current_key(fixture.project, fixture.sandbox).unwrap(),
        1,
        None,
        &encode_current_payload(
            fixture.project,
            fixture.sandbox,
            1,
            fixture.candidate,
            fixture.input,
            fixture.diagnostics,
            &fixture.prerequisites,
        ),
        &validator,
    )
    .unwrap();
    let mut adapter =
        ProtectedDomainJournalV1::<PolicyCompilerJournalSchemaV1>::claim_with_validator(
            journal, validator,
        )
        .unwrap();
    let prepared = adapter.plan([11; 16], vec![candidate, current]).unwrap();
    assert!(matches!(
        adapter.commit(prepared).unwrap(),
        DomainCommitOutcomeV1::Applied(_)
    ));
}
