//! Tests canonical claims and physical writer custody, not Root authority.

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use aos_sandbox_core::format::descriptor_for_bytes;
use aos_sandbox_core::model::CacheDomainKind;

use super::*;
use crate::JournalTransaction;
use crate::policy_compiler::protected_journal::{
    candidate_output_bytes, resolved_policy_fixture as fixture, validate_candidate_payload,
};

pub(in crate::policy_compiler) fn open(root: &Path) -> PolicyCompilerStateReadbackOwnerV1 {
    PolicyCompilerStateReadbackOwnerV1 {
        journal: Journal::open_protected_at_uid(
            root,
            POLICY_STATE_JOURNAL,
            policy_state_journal_limits(),
            fs::metadata(root).unwrap().uid(),
        )
        .unwrap()
        .0,
        location: PolicyStateLocationV1 {
            fixture_root: Some(root.to_path_buf()),
        },
    }
}

pub(in crate::policy_compiler) fn commit_fixture(
    owner: &mut PolicyCompilerStateReadbackOwnerV1,
    publication: &fixture::FixturePublicationV1,
) -> u64 {
    fixture::commit(&mut owner.journal, publication);
    owner.journal.snapshot_sequence()
}

#[test]
fn held_policy_claim_all_four_domains_retain_exact_outputs_and_writer() {
    for domain in [
        CacheDomainKind::Private,
        CacheDomainKind::TrustDomain,
        CacheDomainKind::Public,
        CacheDomainKind::Project,
    ] {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut owner = open(root.path());
        let publication = fixture::publication(domain);
        fixture::commit(&mut owner.journal, &publication);
        let sequence = owner.journal.snapshot_sequence();

        owner
            .with_current_policy_claim(publication.project, publication.sandbox, |claim| {
                claim.recheck().unwrap();
                assert_eq!(claim.target(), (publication.project, publication.sandbox));
                assert_eq!(claim.policy().cache_domain().kind(), domain);
                assert_eq!(claim.policy_bytes(), publication.policy);
                assert_eq!(
                    claim.policy_descriptor().digest(),
                    descriptor_for_bytes(
                        claim.policy_descriptor().media_type().clone(),
                        &publication.policy,
                    )
                    .digest()
                );
                assert_eq!(claim.candidate(), (publication.candidate, 1));
                assert_eq!(claim.normalized_input(), publication.input);
                assert_eq!(claim.diagnostics(), publication.diagnostics);
                assert_eq!(claim.prerequisites(), &publication.prerequisites);
                assert_eq!(claim.outputs().len(), 4);
                assert!(
                    Journal::open_protected_at_uid(
                        root.path(),
                        POLICY_STATE_JOURNAL,
                        policy_state_journal_limits(),
                        fs::metadata(root.path()).unwrap().uid()
                    )
                    .is_err()
                );
            })
            .unwrap();
        assert_eq!(owner.journal.snapshot_sequence(), sequence);
        drop(owner);

        open(root.path())
            .with_current_policy_claim(publication.project, publication.sandbox, |claim| {
                assert_eq!(claim.policy_bytes(), publication.policy)
            })
            .unwrap();
    }
}

#[test]
fn held_policy_claim_v3_reuses_exact_compiler_outputs_and_cold_evidence() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut owner = open(root.path());
    let publication = fixture::compiled_publication();
    fixture::commit(&mut owner.journal, &publication);
    let sequence = owner.journal.snapshot_sequence();

    for cold in [false, true] {
        if cold {
            drop(owner);
            owner = open(root.path());
        }
        owner
            .with_current_policy_claim(publication.project, publication.sandbox, |claim| {
                assert_eq!(claim.candidate_bytes(), publication.body);
                assert_eq!(claim.policy_bytes(), publication.policy);
                let fields = candidate_output_bytes(claim.candidate_bytes()).unwrap();
                for (descriptor, bytes) in claim.outputs().iter().zip(fields) {
                    assert_eq!(descriptor.encoded_size(), bytes.len() as u64);
                    assert_eq!(
                        descriptor_for_bytes(descriptor.media_type().clone(), bytes),
                        *descriptor
                    );
                }
            })
            .unwrap();
        assert_eq!(owner.journal.snapshot_sequence(), sequence);
    }
}

#[test]
fn shared_v3_checks_refuse_substitution_without_mutating_held_claims() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut owner = open(root.path());
    let publication = fixture::compiled_publication();
    fixture::commit(&mut owner.journal, &publication);
    let sequence = owner.journal.snapshot_sequence();
    // Descriptor table and preimage substitutions preserve canonical framing
    // but cannot survive the shared V3 whole-candidate consistency check.
    for offset in [315, 356, 397, 438, 478, 510, 542, 574, 606] {
        let mut changed = publication.body.clone();
        changed[offset] ^= 1;
        assert!(candidate_output_bytes(&changed).is_err());
        assert!(validate_candidate_payload(&changed).is_err());
    }
    assert_eq!(owner.journal.snapshot_sequence(), sequence);
    owner
        .with_current_policy_claim(publication.project, publication.sandbox, |claim| {
            assert_eq!(claim.candidate_bytes(), publication.body);
        })
        .unwrap();
}

// Repairs only outer DATA framing after removing the retired plan-less body.
// Structural decoding below proves that refusal is semantic, not a bad checksum.
fn legacy_candidate_records(
    journal: &Journal,
    publication: &fixture::FixturePublicationV1,
) -> Vec<crate::JournalRecord> {
    use aos_sandbox_protocol::domain_ledger::records::ProtectedDomainSchemaV1;
    use sha2::{Digest as _, Sha256};

    let key = policy_key(
        PolicyCompilerJournalRecordKindV1::Candidate,
        publication.project,
        publication.sandbox,
        publication.candidate,
    )
    .unwrap();
    let member = journal
        .get(crate::RecordNamespace::PublisherPolicy, key.as_bytes())
        .unwrap();
    let envelope = &member[68..member.len() - 32];
    let payload = &envelope[56..envelope.len() - 32];
    let domain = PolicyCompilerJournalSchemaV1::HASH_DOMAIN;
    let body_digest = |body: &[u8]| -> [u8; 32] {
        Sha256::new()
            .chain_update(domain)
            .chain_update(b"canonical-reducer-body\0")
            .chain_update([1])
            .chain_update(body)
            .finalize()
            .into()
    };
    let mut legacy = publication.body[..478].to_vec();
    legacy[8..10].copy_from_slice(&2_u16.to_be_bytes());
    legacy.extend_from_slice(&publication.body[638..]);

    let count = usize::from(u16::from_be_bytes(payload[14..16].try_into().unwrap()));
    let mut companions = payload[20..20 + count * 32]
        .chunks_exact(32)
        .map(|bytes| <[u8; 32]>::try_from(bytes).unwrap())
        .collect::<Vec<_>>();
    let original = body_digest(&publication.body);
    let replacement = body_digest(&legacy);
    assert_eq!(
        companions
            .iter()
            .filter(|digest| **digest == original)
            .count(),
        1
    );
    for digest in &mut companions {
        if *digest == original {
            *digest = replacement;
        }
    }
    companions.sort_unstable();
    let mut repaired_payload = payload[..20].to_vec();
    repaired_payload[16..20].copy_from_slice(&(legacy.len() as u32).to_be_bytes());
    for digest in companions {
        repaired_payload.extend_from_slice(&digest);
    }
    repaired_payload.extend_from_slice(&legacy);
    let checksum = Sha256::new()
        .chain_update(domain)
        .chain_update(b"reducer-payload\0")
        .chain_update(&repaired_payload)
        .finalize();
    repaired_payload.extend_from_slice(&checksum);

    let checksum = Sha256::new()
        .chain_update(domain)
        .chain_update(b"envelope\0")
        .chain_update((key.as_bytes().len() as u32).to_be_bytes())
        .chain_update(key.as_bytes())
        .chain_update(&envelope[12..52])
        .chain_update((repaired_payload.len() as u64).to_be_bytes())
        .chain_update(&repaired_payload)
        .finalize();
    let mut repaired_envelope = envelope[..56].to_vec();
    repaired_envelope[52..56].copy_from_slice(&(repaired_payload.len() as u32).to_be_bytes());
    repaired_envelope.extend_from_slice(&repaired_payload);
    repaired_envelope.extend_from_slice(&checksum);
    let mut repaired_member = member[..68].to_vec();
    repaired_member[64..68].copy_from_slice(&(repaired_envelope.len() as u32).to_be_bytes());
    repaired_member.extend_from_slice(&repaired_envelope);
    let current_key = policy_current_key(publication.project, publication.sandbox).unwrap();
    let current = journal
        .get(
            crate::RecordNamespace::AuthorityPublication,
            current_key.as_bytes(),
        )
        .unwrap();
    assert_eq!(&member[28..32], &[0, 0, 0, 2]);
    assert_eq!(&current[28..32], &[0, 1, 0, 2]);
    assert_eq!(&member[12..28], &current[12..28]);
    let set_digest = Sha256::new()
        .chain_update(domain)
        .chain_update(b"transaction-set\0")
        .chain_update(&member[12..28])
        .chain_update(2_u64.to_be_bytes())
        .chain_update([crate::RecordNamespace::PublisherPolicy as u8])
        .chain_update((key.as_bytes().len() as u32).to_be_bytes())
        .chain_update(key.as_bytes())
        .chain_update(checksum)
        .chain_update([crate::RecordNamespace::AuthorityPublication as u8])
        .chain_update((current_key.as_bytes().len() as u32).to_be_bytes())
        .chain_update(current_key.as_bytes())
        .chain_update(&current[current.len() - 64..current.len() - 32])
        .finalize();
    let mut repaired_current = current[..current.len() - 32].to_vec();
    for bytes in [&mut repaired_member, &mut repaired_current] {
        bytes[32..64].copy_from_slice(&set_digest);
        let checksum = Sha256::new()
            .chain_update(domain)
            .chain_update(b"durable-member\0")
            .chain_update(&*bytes)
            .finalize();
        bytes.extend_from_slice(&checksum);
    }
    vec![
        crate::JournalRecord::put(
            crate::RecordNamespace::PublisherPolicy,
            key.as_bytes().to_vec(),
            repaired_member,
        ),
        crate::JournalRecord::put(
            crate::RecordNamespace::AuthorityPublication,
            current_key.as_bytes().to_vec(),
            repaired_current,
        ),
    ]
}

#[test]
fn retired_candidate_v2_refuses_live_and_cold_claims_without_rewriting_bytes() {
    use crate::protected_domain_journal::{
        ProtectedDomainJournalErrorV1, ProtectedDomainJournalV1,
        protected_current_record_candidates_v1,
    };

    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut owner = open(root.path());
    let publication = fixture::publication(CacheDomainKind::Public);
    fixture::commit(&mut owner.journal, &publication);
    owner
        .with_current_policy_claim(publication.project, publication.sandbox, |_| ())
        .unwrap();
    let control = ProtectedDomainJournalV1::<PolicyCompilerJournalSchemaV1>::claim_with_validator(
        &mut owner.journal,
        fixture::replay_validator(&publication),
    )
    .unwrap();
    control
        .replay()
        .expect("the V3 control has an authenticated complete transaction group");
    drop(control);
    let legacy = legacy_candidate_records(&owner.journal, &publication);
    owner
        .journal
        .commit(&JournalTransaction::new([14; 16], legacy).unwrap())
        .unwrap();
    let retained = fs::read(root.path().join(POLICY_STATE_JOURNAL)).unwrap();
    let sequence = owner.journal.snapshot_sequence();
    let mut expected = publication.body[..478].to_vec();
    expected[8..10].copy_from_slice(&2_u16.to_be_bytes());
    expected.extend_from_slice(&publication.body[638..]);

    for cold in [false, true] {
        if cold {
            drop(owner);
            owner = open(root.path());
        }
        let candidates =
            protected_current_record_candidates_v1::<PolicyCompilerJournalSchemaV1>(&owner.journal)
                .expect("retired body retains valid outer framing");
        assert!(
            candidates
                .iter()
                .any(|record| record.body() == expected)
        );
        assert!(matches!(
            owner.with_current_policy_claim(publication.project, publication.sandbox, |_| {
                panic!("retired Candidate must not dispatch")
            }),
            Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication)
        ));
        let replay = crate::policy_compiler::PolicyCompilerProtectedJournalV1::claim(
            &mut owner.journal,
            fixture::replay_validator(&publication),
        )
        .unwrap();
        assert!(matches!(
            replay.replay(),
            Err(PolicyCompilerJournalErrorV1::Journal(
                ProtectedDomainJournalErrorV1::NonCanonicalRecord,
            ))
        ));
        drop(replay);
        assert_eq!(owner.journal.snapshot_sequence(), sequence);
        assert_eq!(
            fs::read(root.path().join(POLICY_STATE_JOURNAL)).unwrap(),
            retained
        );
    }
}

#[test]
fn held_policy_claim_refuses_missing_foreign_and_malformed_current() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut owner = open(root.path());
    let publication = fixture::publication(CacheDomainKind::Private);
    assert!(
        owner
            .with_current_policy_claim(publication.project, publication.sandbox, |_| panic!(
                "missing claim must not dispatch"
            ))
            .is_err()
    );
    fixture::commit(&mut owner.journal, &publication);
    assert!(
        owner
            .with_current_policy_claim(
                ProjectId::from_bytes([12; 16]),
                publication.sandbox,
                |_| panic!("foreign claim must not dispatch")
            )
            .is_err()
    );

    let key = policy_current_key(publication.project, publication.sandbox).unwrap();
    let mut bytes = owner
        .journal
        .get(crate::RecordNamespace::AuthorityPublication, key.as_bytes())
        .unwrap()
        .to_vec();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    owner
        .journal
        .commit(
            &JournalTransaction::new(
                [13; 16],
                vec![crate::JournalRecord::put(
                    crate::RecordNamespace::AuthorityPublication,
                    key.as_bytes().to_vec(),
                    bytes,
                )],
            )
            .unwrap(),
        )
        .unwrap();
    assert!(
        owner
            .with_current_policy_claim(publication.project, publication.sandbox, |_| panic!(
                "malformed claim must not dispatch"
            ))
            .is_err()
    );
}

#[test]
fn held_policy_claim_canonical_parser_rejects_hash_size_version_and_truncation() {
    let fixture = fixture::publication(CacheDomainKind::Public);
    for offset in [8, 314, 315, 347, 478, fixture.body.len() - 1] {
        let mut bytes = fixture.body.clone();
        bytes[offset] ^= 1;
        assert!(validate_candidate_payload(&bytes).is_err());
    }
    assert!(validate_candidate_payload(&fixture.body[..fixture.body.len() - 1]).is_err());
    let mut appended = fixture.body.clone();
    appended.push(0);
    assert!(validate_candidate_payload(&appended).is_err());
}

#[test]
fn held_policy_claim_refuses_changed_state_names_before_and_after_callback() {
    for after in [false, true] {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut owner = open(root.path());
        let publication = fixture::publication(CacheDomainKind::TrustDomain);
        fixture::commit(&mut owner.journal, &publication);
        let sequence = owner.journal.snapshot_sequence();
        let original = root.path().join(POLICY_STATE_JOURNAL);
        let moved = root.path().join("moved.journal");
        if !after {
            fs::rename(&original, &moved).unwrap();
        }
        let mut called = false;
        assert!(
            owner
                .with_current_policy_claim(publication.project, publication.sandbox, |_| {
                    called = true;
                    fs::rename(&original, &moved).unwrap();
                })
                .is_err()
        );
        assert_eq!(called, after);
        assert_eq!(owner.journal.snapshot_sequence(), sequence);
    }
}

#[test]
fn existing_only_state_open_never_creates_repairs_or_replaces_the_writer() {
    fn existing(
        root: &Path,
    ) -> Result<PolicyCompilerStateReadbackOwnerV1, PolicyCompilerJournalErrorV1> {
        // The existing fixture route shares the final-name/replay core but
        // omits production root ancestry; this is not installed qualification.
        let journal = Journal::open_existing_protected_at_uid(
            root,
            POLICY_STATE_JOURNAL,
            policy_state_journal_limits(),
            fs::metadata(root).unwrap().uid(),
        )?
        .0;
        Ok(PolicyCompilerStateReadbackOwnerV1 {
            journal,
            location: PolicyStateLocationV1 {
                fixture_root: Some(root.to_owned()),
            },
        })
    }
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(existing(root.path()).is_err());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    let mut initial = open(root.path());
    let publication = fixture::compiled_publication();
    fixture::commit(&mut initial.journal, &publication);
    assert!(existing(root.path()).is_err());
    drop(initial);
    let original_bytes = fs::read(root.path().join(POLICY_STATE_JOURNAL)).unwrap();
    let mut owner = existing(root.path()).unwrap();
    owner
        .with_current_policy_claim(publication.project, publication.sandbox, |claim| {
            assert_eq!(claim.candidate_bytes(), publication.body);
            assert!(existing(root.path()).is_err());
        })
        .unwrap();
    drop(owner);
    assert_eq!(
        fs::read(root.path().join(POLICY_STATE_JOURNAL)).unwrap(),
        original_bytes
    );
    let mut torn = original_bytes.clone();
    torn.push(0x7f);
    fs::write(root.path().join(POLICY_STATE_JOURNAL), &torn).unwrap();
    assert!(existing(root.path()).is_err());
    assert_eq!(
        fs::read(root.path().join(POLICY_STATE_JOURNAL)).unwrap(),
        torn
    );
}
