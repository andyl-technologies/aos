//! Pure wire, persistence-order, fork, denial and clock regressions.

use std::cell::RefCell;

use anyhow::{ensure, Result};
use ed25519_dalek::{Signer, SigningKey};

use super::*;
use crate::storage_authority::{
    canonical_digest, control::StorageAuthorityPublication, ApproveStorageAuthorityAlias,
    AssociateStorageAuthorityBinding, AttestStorageAuthorityExclusivity,
    CreatePhysicalStorageAuthority, PhysicalStorageAuthorityId, SetStorageAuthorityAdmission,
    StorageAuthorityAdmissionState, StorageAuthorityAliasSpec, StorageAuthorityCredentialMember,
    StorageAuthorityHost,
};

const EXECUTOR: &str = "qualified-executor";
const KEY_ID: &str = "external-issuer-one";

fn integer(value: i64) -> LeaseInteger {
    LeaseInteger::new(value).unwrap()
}
fn clock(value: i64) -> LeaseClock {
    LeaseClock {
        observed_at: value,
        uncertainty: 2,
    }
}

fn profile() -> LeaseTimingProfile {
    // Fixture-only example; these values are not a qualified deployment default.
    LeaseTimingProfile {
        profile_id: "fixture-reviewed-clock".into(),
        review_digest: "9".repeat(64),
        maximum_lifetime: integer(30),
        maximum_clock_uncertainty: integer(2),
    }
}

fn publication() -> StorageAuthorityPublication {
    let authority_id =
        PhysicalStorageAuthorityId::parse("00000000-0000-4000-8000-000000000001").unwrap();
    let authority = CreatePhysicalStorageAuthority {
        authority_id: authority_id.clone(),
        guard_namespace_id: "permanent-guard-namespace".into(),
        physical_resource_evidence_digest: "1".repeat(64),
        qualification_digest: "2".repeat(64),
        qualified_managed_prefix: "managed".into(),
    };
    let alias = ApproveStorageAuthorityAlias {
        alias_id: "alias-one".into(),
        authority_id: authority_id.clone(),
        spec: StorageAuthorityAliasSpec {
            host: StorageAuthorityHost::Dns("objects.example.invalid".into()),
            port: 443,
            bucket: "qualified-bucket".into(),
        },
        equivalence_evidence_digest: "3".repeat(64),
    };
    let association = AssociateStorageAuthorityBinding {
        association_id: "association-one".into(),
        authority_id: authority_id.clone(),
        alias_id: alias.alias_id.clone(),
        binding_id: 9_007_199_254_740_993,
        binding_stable_id: "binding-one".into(),
        binding_resource_version: 9_007_199_254_740_995,
        binding_write_revision: 9_007_199_254_740_997,
        binding_prefix: "managed/binding".into(),
    };
    let credentials = ["delete", "list", "read", "write"]
        .into_iter()
        .map(|purpose| StorageAuthorityCredentialMember {
            association_id: association.association_id.clone(),
            purpose: purpose.into(),
            generation: 9_007_199_254_741_001,
            secret_version_ref: format!("secret://fixture/{purpose}/immutable-v1"),
            credential_fingerprint: "4".repeat(64),
        })
        .collect();
    let attestation = AttestStorageAuthorityExclusivity {
        attestation_id: "attestation-one".into(),
        authority_id: authority_id.clone(),
        managed_prefix: "managed".into(),
        qualification_digest: authority.qualification_digest.clone(),
        provider_policy_evidence_digest: "5".repeat(64),
        executor_identity: EXECUTOR.into(),
        credentials,
        valid_until: 1000,
    };
    let admission = SetStorageAuthorityAdmission {
        authority_id,
        expected_generation: 0,
        expected_digest: None,
        guard_namespace_id: authority.guard_namespace_id.clone(),
        state: StorageAuthorityAdmissionState::Admitted,
        attestation_id: Some(attestation.attestation_id.clone()),
        association_ids: vec![association.association_id.clone()],
    };
    let digest = canonical_digest(&admission).unwrap();
    let publication = StorageAuthorityPublication {
        authority,
        aliases: vec![alias],
        associations: vec![association],
        attestation: Some(attestation),
        admission,
        generation: 1,
        digest,
    };
    publication
        .validate(&publication.authority.guard_namespace_id, EXECUTOR)
        .unwrap();
    publication
}

fn next_publication(
    previous: &StorageAuthorityPublication,
    state: StorageAuthorityAdmissionState,
) -> StorageAuthorityPublication {
    let mut next = publication();
    next.generation = previous.generation + 1;
    next.admission.expected_generation = previous.generation;
    next.admission.expected_digest = Some(previous.digest.clone());
    next.admission.state = state;
    if state != StorageAuthorityAdmissionState::Admitted {
        next.aliases.clear();
        next.associations.clear();
        next.attestation = None;
        next.admission.attestation_id = None;
        next.admission.association_ids.clear();
    }
    next.digest = canonical_digest(&next.admission).unwrap();
    next.validate(&next.authority.guard_namespace_id, EXECUTOR)
        .unwrap();
    next
}

fn cohort(publication: &StorageAuthorityPublication) -> LeaseCohort {
    LeaseCohort::from_publication(
        publication,
        EXECUTOR,
        "association-one",
        LeasePurpose::Write,
        "managed/binding/objects",
        vec![LeaseEffect::Put, LeaseEffect::MultipartComplete],
    )
    .unwrap()
}

fn journal(publication: &StorageAuthorityPublication) -> EpochLeaseIssuerJournal {
    EpochLeaseIssuerJournal::initialize_fresh_namespace(
        publication,
        EXECUTOR,
        BoundedLeaseRevocationPolicy {
            timing_profile: profile(),
        },
        clock(100),
    )
    .unwrap()
}

fn keys() -> (EpochLeaseSigningKey, EpochLeaseVerifier) {
    let secret = [7u8; 32];
    let public = SigningKey::from_bytes(&secret).verifying_key().to_bytes();
    (
        EpochLeaseSigningKey::from_bytes(KEY_ID.into(), &secret).unwrap(),
        EpochLeaseVerifier::from_bytes(KEY_ID.into(), &public).unwrap(),
    )
}

fn cas(current: &RefCell<EpochLeaseIssuerJournal>, transition: &IssuerTransition) -> Result<()> {
    ensure!(
        *current.borrow() == transition.expected,
        "live durable CAS mismatch"
    );
    *current.borrow_mut() = transition.next.clone();
    Ok(())
}

async fn durable_cas(
    current: &RefCell<EpochLeaseIssuerJournal>,
    transition: IssuerTransition,
) -> Result<()> {
    cas(current, &transition)
}

async fn issue(
    publication: &StorageAuthorityPublication,
    current: &RefCell<EpochLeaseIssuerJournal>,
    at: i64,
) -> Vec<u8> {
    issue_cohort(publication, current, cohort(publication), at).await
}

async fn issue_cohort(
    publication: &StorageAuthorityPublication,
    current: &RefCell<EpochLeaseIssuerJournal>,
    selected: LeaseCohort,
    at: i64,
) -> Vec<u8> {
    let prepared = current
        .borrow()
        .prepare_issue(publication, selected, KEY_ID, 900, clock(at))
        .unwrap();
    prepared
        .commit_and_sign(
            &keys().0,
            |transition| durable_cas(current, transition),
            || Ok(clock(at)),
        )
        .await
        .unwrap()
}

fn fresh_floor(publication: &StorageAuthorityPublication) -> EpochLeaseFloor {
    EpochLeaseFloor::initialize_fresh_guard(
        publication.authority.clone(),
        EXECUTOR.into(),
        "managed/binding/objects/blob".into(),
        &profile(),
        clock(100),
    )
    .unwrap()
}

fn validate(
    bytes: &[u8],
    publication: &StorageAuthorityPublication,
    floor: &EpochLeaseFloor,
    at: i64,
) -> Result<ValidatedEpochLease> {
    keys().1.validate_lease(
        bytes,
        &cohort(publication),
        &profile(),
        floor,
        "managed/binding/objects/blob",
        LeaseEffect::Put,
        clock(at),
    )
}

#[tokio::test]
async fn canonical_exact_integer_roundtrip_and_pinned_lease_validation() {
    let publication = publication();
    let current = RefCell::new(journal(&publication));
    let bytes = issue(&publication, &current, 100).await;
    let verified = validate(&bytes, &publication, &fresh_floor(&publication), 101).unwrap();
    assert_eq!(verified.payload.not_after, integer(130));
    assert_eq!(verified.payload.lease_sequence, integer(1));
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains("\"binding_id\":\"9007199254740993\""));
    assert!(text.contains("\"generation\":\"9007199254741001\""));
    assert_eq!(current.borrow().largest_issued_expiry, integer(130));
    let encoded = serde_json::to_vec(&*current.borrow()).unwrap();
    assert_eq!(
        serde_json::from_slice::<EpochLeaseIssuerJournal>(&encoded).unwrap(),
        *current.borrow()
    );
}

#[tokio::test]
async fn integer_refuses_lossy_or_noncanonical_forms() {
    for value in ["0", "9007199254740993", "9223372036854775807"] {
        let number: LeaseInteger = serde_json::from_str(&format!("\"{value}\"")).unwrap();
        assert_eq!(
            serde_json::to_string(&number).unwrap(),
            format!("\"{value}\"")
        );
    }
    for value in [
        "0",
        "1",
        "\"01\"",
        "\"+1\"",
        "\"-1\"",
        "\"-0\"",
        "\"1.0\"",
        "\"9223372036854775808\"",
    ] {
        assert!(
            serde_json::from_str::<LeaseInteger>(value).is_err(),
            "accepted {value}"
        );
    }
}

#[tokio::test]
async fn closed_canonical_parser_rejects_duplicates_unknown_fields_whitespace_and_oversize() {
    let publication = publication();
    let bytes = issue(&publication, &RefCell::new(journal(&publication)), 100).await;
    let text = String::from_utf8(bytes.clone()).unwrap();
    for changed in [
        text.replacen(
            "\"protocol_version\":1",
            "\"protocol_version\":1,\"protocol_version\":1",
            1,
        ),
        text.replacen(
            "\"protocol_version\":1",
            "\"protocol_version\":1,\"unexpected\":true",
            1,
        ),
        text.replacen(
            "\"association_id\":",
            "\"unexpected\":true,\"association_id\":",
            1,
        ),
        format!(" {text}"),
        text.replacen(
            "\"binding_id\":\"9007199254740993\"",
            "\"binding_id\":9007199254740993",
            1,
        ),
        text.replacen("\"protocol_version\":1", "\"protocol_version\":2", 1),
        text.replacen("\"put\"", "\"arbitrary_code\"", 1),
    ] {
        assert!(validate(
            changed.as_bytes(),
            &publication,
            &fresh_floor(&publication),
            101
        )
        .is_err());
    }
    assert!(keys()
        .1
        .verify(&vec![b' '; MAX_EPOCH_LEASE_BYTES + 1])
        .unwrap_err()
        .to_string()
        .contains("too large"));
}

#[tokio::test]
async fn verifier_rejects_wrong_external_pin_tampering_and_other_signature_domain() {
    let publication = publication();
    let bytes = issue(&publication, &RefCell::new(journal(&publication)), 100).await;
    let (_, verifier) = keys();
    let other = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
    assert!(EpochLeaseVerifier::from_bytes(KEY_ID.into(), &other)
        .unwrap()
        .verify(&bytes)
        .is_err());
    assert!(EpochLeaseVerifier::from_bytes(
        "other-key".into(),
        &SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes()
    )
    .unwrap()
    .verify(&bytes)
    .is_err());
    let payload = verifier.verify(&bytes).unwrap();
    let mut wrong_domain = b"aos.external-authority-denial.v1\0".to_vec();
    wrong_domain.extend(serde_json::to_vec(&payload).unwrap());
    let signature = SigningKey::from_bytes(&[7; 32]).sign(&wrong_domain);
    let tampered = format!(
        "{{\"payload\":{},\"signature\":\"{}\"}}",
        serde_json::to_string(&payload).unwrap(),
        hex::encode(signature.to_bytes())
    );
    // This envelope is otherwise canonical and reaches signature verification.
    assert!(verifier
        .verify(tampered.as_bytes())
        .unwrap_err()
        .to_string()
        .contains("signature"));
    let text = String::from_utf8(bytes)
        .unwrap()
        .replace("\"not_after\":\"130\"", "\"not_after\":\"129\"");
    assert!(verifier.verify(text.as_bytes()).is_err());
    assert!(format!("{:?}", keys().0).contains("[REDACTED]"));
}

#[tokio::test]
async fn issuance_requires_exact_publication_and_credential_not_cached_projection() {
    let publication = publication();
    let journal = journal(&publication);
    let mut fork = publication.clone();
    fork.aliases[0].equivalence_evidence_digest = "6".repeat(64);
    assert!(journal
        .prepare_issue(&fork, cohort(&fork), KEY_ID, 130, clock(100))
        .is_err());
    for field in 0..6 {
        let mut changed = cohort(&publication);
        match field {
            0 => changed.credential.secret_version_ref.push_str("-swapped"),
            1 => changed.credential.credential_fingerprint = "6".repeat(64),
            2 => changed.credential.generation = integer(2),
            3 => changed.association.binding_write_revision = integer(2),
            4 => changed.alias.spec.bucket = "different-bucket".into(),
            _ => changed.executor_identity = "other-executor".into(),
        }
        assert!(journal
            .prepare_issue(&publication, changed, KEY_ID, 130, clock(100))
            .is_err());
    }
}

#[tokio::test]
async fn purpose_prefix_effect_and_list_credential_are_separate() {
    let publication = publication();
    for prefix in [
        "managed/binding-other",
        "managed/binding/../escape",
        "/managed/binding",
        "managed//binding",
    ] {
        assert!(LeaseCohort::from_publication(
            &publication,
            EXECUTOR,
            "association-one",
            LeasePurpose::Write,
            prefix,
            vec![LeaseEffect::Put]
        )
        .is_err());
    }
    for effects in [
        vec![],
        vec![LeaseEffect::Put, LeaseEffect::Put],
        vec![LeaseEffect::MultipartComplete, LeaseEffect::Put],
        vec![LeaseEffect::ConditionalDelete],
    ] {
        assert!(LeaseCohort::from_publication(
            &publication,
            EXECUTOR,
            "association-one",
            LeasePurpose::Write,
            "managed/binding",
            effects
        )
        .is_err());
    }
    assert!(LeaseCohort::from_publication(
        &publication,
        EXECUTOR,
        "association-one",
        LeasePurpose::List,
        "managed/binding",
        vec![LeaseEffect::List]
    )
    .is_ok());
    assert!(LeaseCohort::from_publication(
        &publication,
        EXECUTOR,
        "association-one",
        LeasePurpose::Read,
        "managed/binding",
        vec![LeaseEffect::List]
    )
    .is_err());
}

#[tokio::test]
async fn local_validation_pins_domain_cohort_profile_and_canonical_full_key() {
    let publication = publication();
    let bytes = issue(&publication, &RefCell::new(journal(&publication)), 100).await;
    let floor = fresh_floor(&publication);
    let (_, verifier) = keys();
    for full_key in [
        "managed/binding/objects-other/blob",
        "managed/binding/objects/../blob",
        "",
        "managed/binding/objects//blob",
    ] {
        assert!(verifier
            .validate_lease(
                &bytes,
                &cohort(&publication),
                &profile(),
                &floor,
                full_key,
                LeaseEffect::Put,
                clock(101)
            )
            .is_err());
    }
    assert!(verifier
        .validate_lease(
            &bytes,
            &cohort(&publication),
            &profile(),
            &floor,
            "managed/binding/objects/blob",
            LeaseEffect::ConditionalDelete,
            clock(101)
        )
        .is_err());
    let mut profile = profile();
    profile.maximum_lifetime = integer(31);
    assert!(verifier
        .validate_lease(
            &bytes,
            &cohort(&publication),
            &profile,
            &floor,
            "managed/binding/objects/blob",
            LeaseEffect::Put,
            clock(101)
        )
        .is_err());
    let mut floor = floor;
    floor.authority.guard_namespace_id = "rotated-namespace".into();
    assert!(validate(&bytes, &publication, &floor, 101).is_err());
}

#[tokio::test]
async fn persistence_failure_returns_no_token_and_no_observation_or_signature_release() {
    let publication = publication();
    let journal = journal(&publication);
    let prepared = journal
        .prepare_issue(&publication, cohort(&publication), KEY_ID, 130, clock(100))
        .unwrap();
    let mut observed = false;
    let result = prepared
        .commit_and_sign(
            &keys().0,
            |_| async { anyhow::bail!("durable write failed") },
            || {
                observed = true;
                Ok(clock(100))
            },
        )
        .await;
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("durable write failed"));
    assert!(!observed);
}

#[tokio::test]
async fn lost_return_or_final_expiry_keeps_committed_sequence_and_expiry() {
    let publication = publication();
    let current = RefCell::new(journal(&publication));
    let prepared = current
        .borrow()
        .prepare_issue(&publication, cohort(&publication), KEY_ID, 130, clock(100))
        .unwrap();
    assert!(prepared
        .commit_and_sign(
            &keys().0,
            |transition| durable_cas(&current, transition),
            || Ok(clock(130))
        )
        .await
        .is_err());
    assert_eq!(current.borrow().last_sequence, integer(1));
    assert_eq!(current.borrow().largest_issued_expiry, integer(130));
    let discarded = issue(&publication, &current, 101).await;
    assert!(!discarded.is_empty());
    assert_eq!(current.borrow().last_sequence, integer(2));
    assert_eq!(current.borrow().largest_issued_expiry, integer(131));
    let denied = next_publication(&publication, StorageAuthorityAdmissionState::Blocked);
    let transition = current
        .borrow()
        .prepare_publication(&denied, clock(102))
        .unwrap();
    assert_eq!(transition.next.last_sequence, integer(2));
    assert_eq!(transition.next.largest_issued_expiry, integer(131));
}

#[tokio::test]
async fn denial_winning_before_issue_cas_prevents_any_token() {
    let publication = publication();
    let current = RefCell::new(journal(&publication));
    let prepared = current
        .borrow()
        .prepare_issue(&publication, cohort(&publication), KEY_ID, 130, clock(100))
        .unwrap();
    let denied = next_publication(&publication, StorageAuthorityAdmissionState::Blocked);
    let deny_transition = current
        .borrow()
        .prepare_publication(&denied, clock(101))
        .unwrap();
    cas(&current, &deny_transition).unwrap();
    assert!(prepared
        .commit_and_sign(
            &keys().0,
            |transition| durable_cas(&current, transition),
            || Ok(clock(101))
        )
        .await
        .is_err());
    assert_eq!(current.borrow().last_sequence, integer(0));
}

#[tokio::test]
async fn denial_between_issue_commit_and_return_preserves_expiry_and_refuses_final_cas() {
    let publication = publication();
    let current = RefCell::new(journal(&publication));
    let prepared = current
        .borrow()
        .prepare_issue(&publication, cohort(&publication), KEY_ID, 130, clock(100))
        .unwrap();
    let denied = next_publication(&publication, StorageAuthorityAdmissionState::Blocked);
    let result = prepared
        .commit_and_sign(
            &keys().0,
            |transition| durable_cas(&current, transition),
            || {
                let deny_transition = current.borrow().prepare_publication(&denied, clock(101))?;
                cas(&current, &deny_transition)?;
                Ok(clock(101))
            },
        )
        .await;
    assert!(result.is_err());
    assert_eq!(
        current.borrow().state,
        StorageAuthorityAdmissionState::Blocked
    );
    assert_eq!(current.borrow().last_sequence, integer(1));
    assert_eq!(current.borrow().largest_issued_expiry, integer(130));
}

#[tokio::test]
async fn final_clock_floor_is_durable_before_return_and_callback_failure_retains_history() {
    let publication = publication();
    let current = RefCell::new(journal(&publication));
    let prepared = current
        .borrow()
        .prepare_issue(&publication, cohort(&publication), KEY_ID, 130, clock(100))
        .unwrap();
    let mut commits = 0;
    let bytes = prepared
        .commit_and_sign(
            &keys().0,
            |transition| {
                commits += 1;
                durable_cas(&current, transition)
            },
            || Ok(clock(103)),
        )
        .await
        .unwrap();
    assert_eq!(commits, 2);
    assert_eq!(current.borrow().clock_floor, integer(103));
    assert!(validate(&bytes, &publication, &fresh_floor(&publication), 103).is_ok());
    let prepared = current
        .borrow()
        .prepare_issue(&publication, cohort(&publication), KEY_ID, 133, clock(103))
        .unwrap();
    let mut commits = 0;
    assert!(prepared
        .commit_and_sign(
            &keys().0,
            |transition| {
                commits += 1;
                std::future::ready(if commits == 2 {
                    Err(anyhow::anyhow!("final persistence failed"))
                } else {
                    cas(&current, &transition)
                })
            },
            || Ok(clock(104))
        )
        .await
        .is_err());
    assert_eq!(current.borrow().last_sequence, integer(2));
    assert_eq!(current.borrow().largest_issued_expiry, integer(133));
}

#[tokio::test]
async fn same_epoch_overlap_reuses_older_tokens_without_regressing_maximum_after_restart() {
    let publication = publication();
    let current = RefCell::new(journal(&publication));
    let first = issue(&publication, &current, 100).await;
    let second = issue(&publication, &current, 101).await;
    let validated = validate(&second, &publication, &fresh_floor(&publication), 102).unwrap();
    let stored = serde_json::to_vec(&validated.next_floor).unwrap();
    let restarted: EpochLeaseFloor = serde_json::from_slice(&stored).unwrap();
    assert!(validate(&second, &publication, &restarted, 103).is_ok());
    let older = validate(&first, &publication, &restarted, 103).unwrap();
    assert_eq!(older.next_floor.lease_sequence, restarted.lease_sequence);
    assert_eq!(older.next_floor.payload_digest, restarted.payload_digest);
    assert_eq!(older.next_floor.clock_floor, integer(103));
    let older_restarted: EpochLeaseFloor =
        serde_json::from_slice(&serde_json::to_vec(&older.next_floor).unwrap()).unwrap();
    assert!(validate(&first, &publication, &older_restarted, 104).is_ok());
    assert!(validate(&second, &publication, &older_restarted, 104).is_ok());
    let mut fork = validated.payload;
    fork.not_after = integer(130);
    let fork = keys().0.sign(fork).unwrap();
    assert!(validate(&fork, &publication, &restarted, 103)
        .unwrap_err()
        .to_string()
        .contains("same-sequence"));
}

#[tokio::test]
async fn simultaneous_read_and_write_cohorts_reuse_cached_tokens_in_either_order() {
    let publication = publication();
    let current = RefCell::new(journal(&publication));
    let write = cohort(&publication);
    let read = LeaseCohort::from_publication(
        &publication,
        EXECUTOR,
        "association-one",
        LeasePurpose::Read,
        "managed/binding/objects",
        vec![LeaseEffect::Head, LeaseEffect::Read],
    )
    .unwrap();
    let tokens = [
        issue_cohort(&publication, &current, write.clone(), 100).await,
        issue_cohort(&publication, &current, read.clone(), 101).await,
    ];
    let selected = [&write, &read];
    let effects = [LeaseEffect::Put, LeaseEffect::Head];
    let verifier = keys().1;

    for order in [[0, 1, 0, 1], [1, 0, 1, 0]] {
        let mut floor = fresh_floor(&publication);
        for (step, index) in order.into_iter().enumerate() {
            floor = verifier
                .validate_lease(
                    &tokens[index],
                    selected[index],
                    &profile(),
                    &floor,
                    "managed/binding/objects/blob",
                    effects[index],
                    clock(102 + step as i64),
                )
                .unwrap()
                .next_floor;
        }
        assert_eq!(floor.lease_sequence, integer(2));
        assert_eq!(
            floor.payload_digest,
            Some(verifier.verify(&tokens[1]).unwrap().digest().unwrap())
        );
    }

    assert!(verifier
        .validate_lease(
            &tokens[0],
            &read,
            &profile(),
            &fresh_floor(&publication),
            "managed/binding/objects/blob",
            LeaseEffect::Head,
            clock(102),
        )
        .is_err());
}

#[tokio::test]
async fn overlapping_effect_cohorts_and_out_of_order_renewals_keep_one_maximum_witness() {
    let publication = publication();
    let current = RefCell::new(journal(&publication));
    let narrow = LeaseCohort::from_publication(
        &publication,
        EXECUTOR,
        "association-one",
        LeasePurpose::Write,
        "managed/binding/objects/blob",
        vec![LeaseEffect::Put],
    )
    .unwrap();
    let broad = cohort(&publication);
    let tokens = [
        issue_cohort(&publication, &current, narrow.clone(), 100).await,
        issue_cohort(&publication, &current, broad.clone(), 101).await,
        issue_cohort(&publication, &current, narrow.clone(), 102).await,
    ];
    let selected = [&narrow, &broad, &narrow];
    let verifier = keys().1;
    let maximum_digest = verifier.verify(&tokens[2]).unwrap().digest().unwrap();

    for order in [[2, 0, 1, 2, 0, 1], [0, 2, 1, 0, 1, 2], [1, 0, 2, 1, 2, 0]] {
        let mut floor = fresh_floor(&publication);
        let mut observed_maximum = 0;
        for (step, index) in order.into_iter().enumerate() {
            floor = verifier
                .validate_lease(
                    &tokens[index],
                    selected[index],
                    &profile(),
                    &floor,
                    "managed/binding/objects/blob",
                    LeaseEffect::Put,
                    clock(103 + step as i64),
                )
                .unwrap()
                .next_floor;
            observed_maximum = observed_maximum.max(index as i64 + 1);
            assert_eq!(floor.lease_sequence, integer(observed_maximum));
        }
        assert_eq!(
            floor.payload_digest.as_deref(),
            Some(maximum_digest.as_str())
        );
    }
    // Reusing issued bytes did not ask the issuer to refresh them.
    assert_eq!(current.borrow().last_sequence, integer(3));
}

#[tokio::test]
async fn newer_admitted_epoch_requires_strict_sequence_advance_then_allows_overlap() {
    let publication = publication();
    let current = RefCell::new(journal(&publication));
    let old = issue(&publication, &current, 100).await;
    let latest_old = issue(&publication, &current, 101).await;
    let old_floor = validate(&latest_old, &publication, &fresh_floor(&publication), 102)
        .unwrap()
        .next_floor;
    let denied = next_publication(&publication, StorageAuthorityAdmissionState::Blocked);
    let transition = current
        .borrow()
        .prepare_publication(&denied, clock(103))
        .unwrap();
    cas(&current, &transition).unwrap();
    let denied_floor = old_floor
        .observe_trusted_denial(&denied, &profile(), clock(103))
        .unwrap();
    let renewed = next_publication(&denied, StorageAuthorityAdmissionState::Admitted);
    let transition = current
        .borrow()
        .prepare_publication(&renewed, clock(133))
        .unwrap();
    cas(&current, &transition).unwrap();
    let first = issue(&renewed, &current, 133).await;
    let second = issue(&renewed, &current, 134).await;

    // Correct signatures cannot hide a reset or reused issuer counter on an
    // observed epoch advance. These payloads are not produced by the live CAS.
    for sequence in [1, 2] {
        let mut forged = keys().1.verify(&first).unwrap();
        forged.lease_sequence = integer(sequence);
        let bytes = keys().0.sign(forged).unwrap();
        for floor in [&old_floor, &denied_floor] {
            assert!(validate(&bytes, &renewed, floor, 135)
                .unwrap_err()
                .to_string()
                .contains("does not advance"));
        }
    }

    let first_floor = validate(&first, &renewed, &denied_floor, 135)
        .unwrap()
        .next_floor;
    assert_eq!(first_floor.lease_sequence, integer(3));
    let maximum = validate(&second, &renewed, &first_floor, 136)
        .unwrap()
        .next_floor;
    let reused = validate(&first, &renewed, &maximum, 137)
        .unwrap()
        .next_floor;
    assert_eq!(reused.lease_sequence, integer(4));
    assert_eq!(reused.payload_digest, maximum.payload_digest);
    assert!(validate(&old, &publication, &reused, 137).is_err());
    assert!(!reused.denied);
}

#[tokio::test]
async fn lower_sequence_reuse_preserves_expiry_clock_and_epoch_fork_checks() {
    let publication = publication();
    let current = RefCell::new(journal(&publication));
    let first = issue(&publication, &current, 100).await;
    let second = issue(&publication, &current, 101).await;
    let maximum = validate(&second, &publication, &fresh_floor(&publication), 102)
        .unwrap()
        .next_floor;
    let before = maximum.clone();
    assert!(validate(&first, &publication, &maximum, 101).is_err());
    assert!(validate(&first, &publication, &maximum, 128).is_err());
    assert!(validate(&second, &publication, &maximum, 128).is_ok());

    let mut forked = publication.clone();
    forked
        .attestation
        .as_mut()
        .unwrap()
        .provider_policy_evidence_digest = "6".repeat(64);
    let mut forged = keys().1.verify(&first).unwrap();
    forged.cohort = cohort(&forked);
    let bytes = keys().0.sign(forged).unwrap();
    assert!(validate(&bytes, &forked, &maximum, 103)
        .unwrap_err()
        .to_string()
        .contains("same-generation"));
    assert_eq!(maximum, before);
}

#[tokio::test]
async fn exact_generation_floor_refuses_publication_forks_and_known_denial() {
    let publication = publication();
    let bytes = issue(&publication, &RefCell::new(journal(&publication)), 100).await;
    let observed = validate(&bytes, &publication, &fresh_floor(&publication), 101)
        .unwrap()
        .next_floor;
    let mut forked_publication = publication.clone();
    forked_publication
        .attestation
        .as_mut()
        .unwrap()
        .provider_policy_evidence_digest = "6".repeat(64);
    let mut fork = keys().1.verify(&bytes).unwrap();
    fork.cohort = cohort(&forked_publication);
    let fork_bytes = keys().0.sign(fork).unwrap();
    assert!(validate(&fork_bytes, &forked_publication, &observed, 102)
        .unwrap_err()
        .to_string()
        .contains("same-generation"));
    let denied = next_publication(&publication, StorageAuthorityAdmissionState::Blocked);
    let denied_floor = observed
        .observe_trusted_denial(&denied, &profile(), clock(102))
        .unwrap();
    assert!(validate(&bytes, &publication, &denied_floor, 103).is_err());
    // An untouched guard may still admit an authentic unexpired old token.
    assert!(validate(&bytes, &publication, &fresh_floor(&publication), 103).is_ok());
}

#[tokio::test]
async fn renewal_requires_denial_and_cutoff_and_never_resets_sequence_or_retirement() {
    let publication = publication();
    let current = RefCell::new(journal(&publication));
    let old = issue(&publication, &current, 100).await;
    let unguarded_renewal =
        next_publication(&publication, StorageAuthorityAdmissionState::Admitted);
    assert!(current
        .borrow()
        .prepare_publication(&unguarded_renewal, clock(140))
        .is_err());
    let denied = next_publication(&publication, StorageAuthorityAdmissionState::Blocked);
    let transition = current
        .borrow()
        .prepare_publication(&denied, clock(101))
        .unwrap();
    cas(&current, &transition).unwrap();
    let renewed = next_publication(&denied, StorageAuthorityAdmissionState::Admitted);
    assert!(current
        .borrow()
        .prepare_publication(&renewed, clock(131))
        .is_err());
    let transition = current
        .borrow()
        .prepare_publication(&renewed, clock(132))
        .unwrap();
    cas(&current, &transition).unwrap();
    let new = issue(&renewed, &current, 132).await;
    assert_eq!(keys().1.verify(&new).unwrap().lease_sequence, integer(2));
    let observed = validate(&new, &renewed, &fresh_floor(&publication), 133)
        .unwrap()
        .next_floor;
    assert!(validate(&old, &publication, &observed, 133).is_err());
    let retired = next_publication(&renewed, StorageAuthorityAdmissionState::Retired);
    let transition = current
        .borrow()
        .prepare_publication(&retired, clock(134))
        .unwrap();
    cas(&current, &transition).unwrap();
    let reopen = next_publication(&retired, StorageAuthorityAdmissionState::Admitted);
    assert!(current
        .borrow()
        .prepare_publication(&reopen, clock(200))
        .is_err());
}

#[tokio::test]
async fn uncertainty_rollback_expiry_and_cutoff_are_fail_closed_and_distinct() {
    let publication = publication();
    let current = RefCell::new(journal(&publication));
    let bytes = issue(&publication, &current, 100).await;
    let floor = fresh_floor(&publication);
    assert!(validate(&bytes, &publication, &floor, 127).is_ok());
    assert!(validate(&bytes, &publication, &floor, 128).is_err());
    assert!(validate(&bytes, &publication, &floor, 99).is_err());
    let (_, verifier) = keys();
    for clock in [
        LeaseClock {
            observed_at: 101,
            uncertainty: 3,
        },
        LeaseClock {
            observed_at: 101,
            uncertainty: -1,
        },
        LeaseClock {
            observed_at: i64::MAX,
            uncertainty: 2,
        },
    ] {
        assert!(verifier
            .validate_lease(
                &bytes,
                &cohort(&publication),
                &profile(),
                &floor,
                "managed/binding/objects/blob",
                LeaseEffect::Put,
                clock
            )
            .is_err());
    }
    let retained = current.borrow();
    let policy = &retained.policy;
    assert!(
        !policy
            .admission_cutoff(integer(130), integer(100), clock(131))
            .unwrap()
            .reached
    );
    assert!(
        policy
            .admission_cutoff(integer(130), integer(100), clock(132))
            .unwrap()
            .reached
    );
    assert!(policy
        .admission_cutoff(integer(130), integer(100), clock(99))
        .is_err());
}

#[tokio::test]
async fn lifetime_attestation_and_counter_overflow_never_wrap_or_invent_ttl() {
    let mut publication = publication();
    publication.attestation.as_mut().unwrap().valid_until = 115;
    let current = RefCell::new(journal(&publication));
    let bytes = issue(&publication, &current, 100).await;
    assert_eq!(keys().1.verify(&bytes).unwrap().not_after, integer(115));
    assert!(current
        .borrow()
        .prepare_issue(&publication, cohort(&publication), KEY_ID, 102, clock(100))
        .is_err());
    assert!(current
        .borrow()
        .prepare_issue(&publication, cohort(&publication), KEY_ID, 900, clock(113))
        .is_err());
    let mut exhausted = current.borrow().clone();
    exhausted.last_sequence = integer(i64::MAX);
    assert!(exhausted
        .prepare_issue(&publication, cohort(&publication), KEY_ID, 110, clock(101))
        .unwrap_err()
        .to_string()
        .contains("sequence exhausted"));
    publication.attestation.as_mut().unwrap().valid_until = i64::MAX;
    let journal = journal(&publication);
    assert!(journal
        .prepare_issue(
            &publication,
            cohort(&publication),
            KEY_ID,
            i64::MAX,
            LeaseClock {
                observed_at: i64::MAX - 2,
                uncertainty: 0
            }
        )
        .unwrap_err()
        .to_string()
        .contains("expiry overflow"));
    let mut invalid = profile();
    invalid.maximum_lifetime = integer(0);
    assert!(invalid.validate().is_err());
}

#[tokio::test]
async fn used_namespace_initialization_and_invalid_persistent_floors_are_refused() {
    let publication = publication();
    let denied = next_publication(&publication, StorageAuthorityAdmissionState::Blocked);
    assert!(EpochLeaseIssuerJournal::initialize_fresh_namespace(
        &denied,
        EXECUTOR,
        BoundedLeaseRevocationPolicy {
            timing_profile: profile()
        },
        clock(100)
    )
    .is_err());
    let bytes = issue(&publication, &RefCell::new(journal(&publication)), 100).await;
    let mut floor = fresh_floor(&publication);
    floor.generation = integer(1);
    assert!(validate(&bytes, &publication, &floor, 101).is_err());
}

#[tokio::test]
async fn slow_final_persistence_cannot_return_an_already_expired_token() {
    let publication = publication();
    let current = RefCell::new(journal(&publication));
    let observed = RefCell::new(100);
    let prepared = current
        .borrow()
        .prepare_issue(&publication, cohort(&publication), KEY_ID, 130, clock(100))
        .unwrap();
    let mut commits = 0;
    let result = prepared
        .commit_and_sign(
            &keys().0,
            |transition| {
                commits += 1;
                let result = cas(&current, &transition);
                if commits == 2 {
                    *observed.borrow_mut() = 130;
                }
                std::future::ready(result)
            },
            || Ok(clock(*observed.borrow())),
        )
        .await;
    assert!(result.unwrap_err().to_string().contains("expired"));
    assert_eq!(commits, 2);
    assert_eq!(current.borrow().largest_issued_expiry, integer(130));
    assert_eq!(current.borrow().last_sequence, integer(1));
}

#[tokio::test]
async fn terminal_retirement_survives_serialization_and_refuses_later_signed_epochs() {
    let publication = publication();
    let bytes = issue(&publication, &RefCell::new(journal(&publication)), 100).await;
    let floor = validate(&bytes, &publication, &fresh_floor(&publication), 101)
        .unwrap()
        .next_floor;
    let retired = next_publication(&publication, StorageAuthorityAdmissionState::Retired);
    let retired_floor = floor
        .observe_trusted_denial(&retired, &profile(), clock(102))
        .unwrap();
    let restarted: EpochLeaseFloor =
        serde_json::from_slice(&serde_json::to_vec(&retired_floor).unwrap()).unwrap();
    assert!(restarted.retired);
    assert!(validate(&bytes, &publication, &restarted, 103).is_err());
    let reopened = next_publication(&retired, StorageAuthorityAdmissionState::Admitted);
    let mut forged = keys().1.verify(&bytes).unwrap();
    forged.cohort = cohort(&reopened);
    forged.lease_sequence = integer(2);
    let signed = keys().0.sign(forged).unwrap();
    assert!(validate(&signed, &reopened, &restarted, 103)
        .unwrap_err()
        .to_string()
        .contains("retirement"));
    let later_denied = next_publication(&retired, StorageAuthorityAdmissionState::Blocked);
    assert!(restarted
        .observe_trusted_denial(&later_denied, &profile(), clock(103))
        .is_err());
    assert!(
        restarted
            .observe_trusted_denial(&retired, &profile(), clock(103))
            .unwrap()
            .retired
    );
}

#[tokio::test]
async fn verifier_independently_rejects_attestation_expiry_and_sequence_fork_after_renewal() {
    let publication = publication();
    let bytes = issue(&publication, &RefCell::new(journal(&publication)), 100).await;
    let mut payload = keys().1.verify(&bytes).unwrap();
    payload.cohort.attestation_valid_until = integer(129);
    assert!(keys().0.sign(payload).is_err());
    let current = RefCell::new(journal(&publication));
    let first = issue(&publication, &current, 100).await;
    let first_floor = validate(&first, &publication, &fresh_floor(&publication), 101)
        .unwrap()
        .next_floor;
    let denied = next_publication(&publication, StorageAuthorityAdmissionState::Blocked);
    let transition = current
        .borrow()
        .prepare_publication(&denied, clock(101))
        .unwrap();
    cas(&current, &transition).unwrap();
    let renewed = next_publication(&denied, StorageAuthorityAdmissionState::Admitted);
    let transition = current
        .borrow()
        .prepare_publication(&renewed, clock(132))
        .unwrap();
    cas(&current, &transition).unwrap();
    let next = issue(&renewed, &current, 132).await;
    assert!(validate(&next, &renewed, &first_floor, 133).is_ok());
}

#[tokio::test]
async fn shorter_new_lease_never_shrinks_denial_cutoff_and_wrong_key_never_commits() {
    let publication = publication();
    let current = RefCell::new(journal(&publication));
    let _ = issue(&publication, &current, 100).await;
    let prepared = current
        .borrow()
        .prepare_issue(&publication, cohort(&publication), KEY_ID, 120, clock(101))
        .unwrap();
    let bytes = prepared
        .commit_and_sign(
            &keys().0,
            |transition| durable_cas(&current, transition),
            || Ok(clock(101)),
        )
        .await
        .unwrap();
    assert_eq!(keys().1.verify(&bytes).unwrap().not_after, integer(120));
    assert_eq!(current.borrow().largest_issued_expiry, integer(130));
    let prepared = current
        .borrow()
        .prepare_issue(&publication, cohort(&publication), KEY_ID, 130, clock(102))
        .unwrap();
    let wrong_key = EpochLeaseSigningKey::from_bytes("different-key".into(), &[8; 32]).unwrap();
    assert!(prepared
        .commit_and_sign(
            &wrong_key,
            |_| -> std::future::Ready<Result<()>> { panic!("wrong key must not commit") },
            || panic!("wrong key must not observe")
        )
        .await
        .is_err());
}

async fn commit_then_hold(
    current: &RefCell<EpochLeaseIssuerJournal>,
    calls: &std::cell::Cell<usize>,
    hold_at: usize,
    transition: IssuerTransition,
) -> Result<()> {
    calls.set(calls.get() + 1);
    cas(current, &transition)?;
    if calls.get() == hold_at {
        std::future::pending::<()>().await;
    }
    Ok(())
}

#[tokio::test]
async fn cancellation_during_either_ack_retains_possible_commit_without_token() {
    use std::future::Future;

    for hold_at in [1, 2] {
        let publication = publication();
        let current = RefCell::new(journal(&publication));
        let calls = std::cell::Cell::new(0);
        let prepared = current
            .borrow()
            .prepare_issue(&publication, cohort(&publication), KEY_ID, 130, clock(100))
            .unwrap();
        let signer = keys().0;
        let mut future = Box::pin(prepared.commit_and_sign(
            &signer,
            |transition| commit_then_hold(&current, &calls, hold_at, transition),
            || Ok(clock(100)),
        ));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(future.as_mut().poll(&mut context).is_pending());
        assert_eq!(calls.get(), hold_at);
        assert_eq!(current.borrow().last_sequence, integer(1));
        assert_eq!(current.borrow().largest_issued_expiry, integer(130));
        drop(future);
        let denied = next_publication(&publication, StorageAuthorityAdmissionState::Blocked);
        let transition = current
            .borrow()
            .prepare_publication(&denied, clock(101))
            .unwrap();
        cas(&current, &transition).unwrap();
        assert_eq!(current.borrow().largest_issued_expiry, integer(130));
    }
}

async fn commit_then_lose_ack(
    current: &RefCell<EpochLeaseIssuerJournal>,
    transition: IssuerTransition,
) -> Result<()> {
    cas(current, &transition)?;
    anyhow::bail!("durable commit acknowledgment lost")
}

#[tokio::test]
async fn lost_first_ack_retains_cutoff_and_exposes_no_signature() {
    let publication = publication();
    let current = RefCell::new(journal(&publication));
    let prepared = current
        .borrow()
        .prepare_issue(&publication, cohort(&publication), KEY_ID, 130, clock(100))
        .unwrap();
    let result = prepared
        .commit_and_sign(
            &keys().0,
            |transition| commit_then_lose_ack(&current, transition),
            || panic!("must not sign/observe before acknowledgment"),
        )
        .await;
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("acknowledgment lost"));
    assert_eq!(current.borrow().last_sequence, integer(1));
    assert_eq!(current.borrow().largest_issued_expiry, integer(130));
}

async fn yielding_cas(
    current: &RefCell<EpochLeaseIssuerJournal>,
    transition: IssuerTransition,
) -> Result<()> {
    cas(current, &transition)?;
    tokio::task::yield_now().await;
    Ok(())
}

#[tokio::test]
async fn live_denial_during_first_await_refuses_second_cas_without_losing_cutoff() {
    use std::future::Future;

    let publication = publication();
    let current = RefCell::new(journal(&publication));
    let prepared = current
        .borrow()
        .prepare_issue(&publication, cohort(&publication), KEY_ID, 130, clock(100))
        .unwrap();
    let signer = keys().0;
    let mut future = Box::pin(prepared.commit_and_sign(
        &signer,
        |transition| yielding_cas(&current, transition),
        || Ok(clock(101)),
    ));
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(future.as_mut().poll(&mut context).is_pending());
    let denied = next_publication(&publication, StorageAuthorityAdmissionState::Blocked);
    let transition = current
        .borrow()
        .prepare_publication(&denied, clock(101))
        .unwrap();
    cas(&current, &transition).unwrap();
    assert!(future
        .await
        .unwrap_err()
        .to_string()
        .contains("CAS mismatch"));
    assert_eq!(
        current.borrow().state,
        StorageAuthorityAdmissionState::Blocked
    );
    assert_eq!(current.borrow().largest_issued_expiry, integer(130));
}

#[path = "control_tests.rs"]
mod control_tests;
