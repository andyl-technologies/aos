//! Checks genuine compiler publication through native commit and cold replay.
//!
//! Fixture inputs supply test-only claims; journal replay grants no Root admission.

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use super::candidate_tests::compile_fixture;
use super::*;

#[test]
fn canonical_output_full_publication_survives_protected_commit_and_cold_replay() {
    let verified = compile_fixture(4096, Some(32), true);
    let diagnostics = encode_diagnostics_payload(
        verified.project,
        verified.sandbox,
        verified.candidate.commitment().digest(),
        &verified.diagnostics,
    )
    .unwrap();
    let diagnostics_digest = digest_bytes(DIAGNOSTICS_DOMAIN, &diagnostics);
    let candidate =
        encode_candidate_payload(1, verified.body_fields(), diagnostics_digest).unwrap();
    let current = encode_current_payload(
        verified.project,
        verified.sandbox,
        1,
        verified.candidate.commitment().digest(),
        verified.normalized_input,
        diagnostics_digest,
        &verified.prerequisites,
    );
    let validator = PolicyCompilerReplayValidatorV1 {
        authenticated_prerequisites: BTreeMap::from([(
            verified.prerequisites.digest(),
            verified.prerequisites.clone(),
        )]),
    };
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let uid = directory.path().metadata().unwrap().uid();
    let mut journal = Journal::open_fixture_ordinary_policy_v1(directory.path(), uid).unwrap();
    {
        let envelopes = [
            (PolicyCompilerJournalRecordKindV1::Candidate, &candidate),
            (PolicyCompilerJournalRecordKindV1::Diagnostics, &diagnostics),
        ]
        .into_iter()
        .map(|(kind, body)| {
            policy_reducer_envelope(
                policy_key(
                    kind,
                    verified.project,
                    verified.sandbox,
                    verified.candidate.commitment().digest(),
                )
                .unwrap(),
                1,
                None,
                body,
                &validator,
            )
            .unwrap()
        })
        .chain(std::iter::once(
            policy_reducer_envelope(
                policy_current_key(verified.project, verified.sandbox).unwrap(),
                1,
                None,
                &current,
                &validator,
            )
            .unwrap(),
        ))
        .collect();
        let mut adapter =
            ProtectedDomainJournalV1::<PolicyCompilerJournalSchemaV1>::claim_with_validator(
                &mut journal,
                validator.clone(),
            )
            .unwrap();
        let prepared = adapter.plan([90; 16], envelopes).unwrap();
        assert!(matches!(
            adapter.commit(prepared).unwrap(),
            DomainCommitOutcomeV1::Applied(_)
        ));
        validate_policy_projection(&adapter.replay().unwrap(), &validator).unwrap();
    }
    let sequence = journal.snapshot_sequence();
    drop(journal);
    let mut journal = Journal::open_fixture_ordinary_policy_v1(directory.path(), uid).unwrap();
    assert_eq!(journal.snapshot_sequence(), sequence);
    let adapter = ProtectedDomainJournalV1::<PolicyCompilerJournalSchemaV1>::claim_with_validator(
        &mut journal,
        validator.clone(),
    )
    .unwrap();
    let projection = adapter.replay().unwrap();
    validate_policy_projection(&projection, &validator).unwrap();
    for record in projection.records() {
        let body = policy_body(record, &validator).unwrap();
        match record.key().kind() {
            PolicyCompilerJournalRecordKindV1::Candidate => assert_eq!(body, candidate),
            PolicyCompilerJournalRecordKindV1::Diagnostics => {
                assert_eq!(body, diagnostics);
                assert_eq!(
                    decode_diagnostics_payload(body).unwrap(),
                    verified.diagnostics
                );
            }
            PolicyCompilerJournalRecordKindV1::Current => assert_eq!(body, current),
            _ => panic!("unexpected record"),
        }
    }
}
