//! Produces synthetic canonical claims through genuine durable framing.
//!
//! The synthetic prerequisite map and arbitrary candidate commitment are
//! deliberately not Root/compiler authority. Consumers test claim extraction
//! only; a live worker producer must independently authenticate compilation.

use aos_sandbox_core::CacheDomainId;
use aos_sandbox_core::model::{
    CacheDomain, CacheDomainKind, OptimizationProfile, Policy, ResourceProfile, RevocationMode,
    RevocationPolicy,
};

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
    let project = ProjectId::from_bytes([1; 16]);
    let sandbox = SandboxId::from_bytes([2; 16]);
    let candidate = ObjectDigest::from_bytes([3; 32]);
    let input = ObjectDigest::from_bytes([4; 32]);
    let diagnostics = ObjectDigest::from_bytes([5; 32]);
    let prerequisites = PolicyPublicationPrerequisitesV1::new(
        ObjectDigest::from_bytes([6; 32]),
        ObjectDigest::from_bytes([7; 32]),
        ObjectDigest::from_bytes([8; 32]),
        ObjectDigest::from_bytes([9; 32]),
        1,
    )
    .unwrap();
    let policy = encode_policy(
        &Policy::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            ResourceProfile::new(Vec::new()).unwrap(),
            Vec::new(),
            CacheDomain::new(domain, CacheDomainId::from_bytes([10; 16])),
            RevocationPolicy::new(RevocationMode::Freeze, 1),
            None,
            Vec::new(),
        )
        .unwrap(),
    );
    let outputs = [
        policy.clone(),
        encode_optimization(&OptimizationProfile::new(Vec::new()).unwrap()),
        super::super::model::canonical_bytes(
            b"aos.sandbox.portable-namespace-graph.v1",
            &(
                super::super::namespace::NamespaceGraphSchemaV1::V1,
                Vec::<super::super::namespace::NamespaceRuleV1>::new(),
            ),
        )
        .unwrap(),
        super::super::model::canonical_bytes(
            b"aos.sandbox.portable-advisory-program.v1",
            &Vec::<super::super::advisory::AdvisoryDecisionV1>::new(),
        )
        .unwrap(),
    ];

    let mut body = Vec::new();
    body.extend_from_slice(CANDIDATE_MAGIC);
    body.extend_from_slice(&2_u16.to_be_bytes());
    body.extend_from_slice(project.as_bytes());
    body.extend_from_slice(sandbox.as_bytes());
    for digest in [candidate, input, diagnostics, prerequisites.digest()] {
        body.extend_from_slice(digest.as_bytes());
    }
    append_prerequisite_tuple(&mut body, &prerequisites);
    body.extend_from_slice(&1_u64.to_be_bytes());
    for (index, bytes) in outputs.iter().enumerate() {
        let media = match index {
            0 => PortableMediaType::Policy,
            1 => PortableMediaType::Optimization,
            _ => PortableMediaType::Content,
        };
        let descriptor = descriptor_for_bytes(MediaType::new(media.as_str()).unwrap(), bytes);
        body.push(index as u8 + 1);
        body.extend_from_slice(descriptor.digest().as_bytes());
        body.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    }
    assert_eq!(body.len(), 478);
    for bytes in &outputs {
        body.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        body.extend_from_slice(bytes);
    }
    validate_candidate_payload(&body).unwrap();
    FixturePublicationV1 {
        project,
        sandbox,
        candidate,
        input,
        diagnostics,
        prerequisites,
        body,
        policy,
    }
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
    let body = encode_candidate_payload(1, &verified, diagnostics).unwrap();
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

pub(in crate::policy_compiler) fn commit(journal: &mut Journal, fixture: &FixturePublicationV1) {
    let validator = PolicyCompilerReplayValidatorV1 {
        authenticated_prerequisites: BTreeMap::from([(
            fixture.prerequisites.digest(),
            fixture.prerequisites.clone(),
        )]),
    };
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
