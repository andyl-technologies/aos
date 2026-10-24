//! Produces real compiler claims through genuine durable framing.
//!
//! Synthetic inputs and prerequisite evidence remain test-only. Pure compilation
//! and claim extraction do not establish installed Root or publication authority.

use aos_sandbox_model::model::CacheDomainKind;

use super::*;

/// Retains complete synthetic comparison records for native fixture tests.
pub struct FixturePublicationV1 {
    /// Names the synthetic project used by these comparison records.
    pub project: ProjectId,
    /// Names the synthetic sandbox used by these comparison records.
    pub sandbox: SandboxId,
    /// Commits the complete compiled candidate.
    pub candidate: ObjectDigest,
    /// Commits the normalized original compiler input.
    pub input: ObjectDigest,
    /// Commits the complete canonical diagnostics.
    pub diagnostics: ObjectDigest,
    /// Retains synthetic prerequisite comparison DATA.
    pub prerequisites: PolicyPublicationPrerequisitesV1,
    /// Contains the complete canonical Candidate V3 body.
    pub body: Vec<u8>,
    /// Contains the exact compiled Policy output bytes.
    pub policy: Vec<u8>,
}

/// Compiles one synthetic complete publication for the selected cache domain.
///
/// # Panics
///
/// Panics when the fixture's model, native opening or durable commit is invalid.
pub fn publication(domain: CacheDomainKind) -> FixturePublicationV1 {
    compiled_publication_from_input(compiler_input(4096, domain, Vec::new()))
}

/// Reuses the real pure compiler fixture, not an installed input authority.
///
/// # Panics
///
/// Panics when the fixture's model, native opening or durable commit is invalid.
pub fn compiled_publication() -> FixturePublicationV1 {
    let verified = super::candidate_tests::fixture(4096);
    compiled_publication_from_verified(verified)
}

/// Builds a synthetic authenticated model input for fixture comparison.
///
/// # Panics
///
/// Panics when the fixture's model, native opening or durable commit is invalid.
pub fn compiler_input(
    amount: u64,
    domain: CacheDomainKind,
    grants: Vec<aos_sandbox_model::Grant>,
) -> PolicyCompilerInputV1 {
    super::candidate_tests::compiler_input(amount, domain, grants)
}

/// Compiles complete comparison records from the supplied fixture input.
///
/// # Panics
///
/// Panics when the fixture's model, native opening or durable commit is invalid.
pub fn compiled_publication_from_input(
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

pub(in crate::native) fn replay_validator(
    fixture: &FixturePublicationV1,
) -> PolicyCompilerReplayValidatorV1 {
    PolicyCompilerReplayValidatorV1 {
        authenticated_prerequisites: BTreeMap::from([(
            fixture.prerequisites.digest(),
            fixture.prerequisites.clone(),
        )]),
    }
}

pub(in crate::native) fn commit(journal: &mut Journal, fixture: &FixturePublicationV1) {
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

/// Opens the real fixed-basename fixture state writer.
///
/// # Panics
///
/// Panics when the fixture's model, native opening or durable commit is invalid.
pub fn open(root: &std::path::Path) -> super::state_readback::PolicyCompilerStateReadbackOwnerV1 {
    use std::os::unix::fs::MetadataExt as _;

    super::state_readback::PolicyCompilerStateReadbackOwnerV1::open_fixture_at_uid(
        root, std::fs::metadata(root).unwrap().uid(),
    ).unwrap()
}

/// Commits complete canonical fixture records through the same held ordinary owner.
///
/// # Panics
///
/// Panics when the fixture's model, native opening or durable commit is invalid.
pub fn commit_fixture(
    owner: &mut super::state_readback::PolicyCompilerStateReadbackOwnerV1,
    publication: &FixturePublicationV1,
) -> u64 {
    commit(&mut owner.journal, publication);
    owner.journal.snapshot_sequence()
}
