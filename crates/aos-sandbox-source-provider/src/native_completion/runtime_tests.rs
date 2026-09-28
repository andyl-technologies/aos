//! Protected Requested/challenge ordering cuts with canonical signed fixtures.
//!
//! These tests exercise real protected append/readback/reopen and exact nonce
//! recovery. Their local token fixture does not qualify the production whole
//! authority graph, original FD transport, or installed positive bridge.

use std::os::unix::fs::PermissionsExt as _;

use aos_sandbox::{Journal, JournalLimits};
use aos_sandbox_core::{RawClockProvenance, RawPairedClockSample};
use aos_sandbox_source_provider_protocol::*;
use ed25519_dalek::{Signer as _, SigningKey};

use super::*;
use crate::ledger::model::DecodedRecordV1;
use crate::ledger::native_completion::NativeAcquireClockAnchorV1;

fn digest(byte: u8) -> ObjectDigest {
    ObjectDigest::from_bytes([byte; 32])
}

fn requested(nonce: [u8; 32], issued: i64) -> NativeAcquireCompletionRecordV2 {
    requested_with_session(nonce, issued, digest(1))
}

pub(crate) fn requested_with_session(
    nonce: [u8; 32],
    issued: i64,
    session_binding: ObjectDigest,
) -> NativeAcquireCompletionRecordV2 {
    requested_with_boot(nonce, issued, session_binding, [6; 16])
}

pub(crate) fn requested_with_boot(
    nonce: [u8; 32],
    issued: i64,
    session_binding: ObjectDigest,
    boot_id: [u8; 16],
) -> NativeAcquireCompletionRecordV2 {
    let mut template = Vec::new();
    for tag in 1_u8..=27 {
        let value = match tag {
            1 => b"AOSMSEM1".to_vec(),
            2 => 1_u16.to_be_bytes().to_vec(),
            _ => vec![tag, tag + 1],
        };
        template.push(tag);
        template.extend_from_slice(&(value.len() as u32).to_be_bytes());
        template.extend_from_slice(&value);
    }
    let template_digest = prospective_mount_apply_template_digest_v1(&template).unwrap();
    let binding = b"native-requested-first-fixture".to_vec();
    let binding_digest = digest_logical_binding_bytes(&binding);
    let root = AcquireSourceRequestV1::new_v2(
        session_binding,
        2,
        [3; 16],
        4,
        template,
        template_digest,
        SourceUseV1::MountCreate,
        [5; 16],
        boot_id,
        [7; 16],
        8,
        digest(9),
        binding,
        binding_digest,
        issued + 600,
        60,
        digest(10),
        false,
        0,
        false,
    )
    .unwrap();
    let key = SigningKey::from_bytes(&[51; 32]);
    let root_signer = SourceProviderSigningKeyV1::for_signing_key(
        [7; 16],
        8,
        digest(9),
        [11; 16],
        12,
        SourceProviderKeyUsageV1::RootMountRecord,
        &key,
    )
    .unwrap();
    let signed_root = sign_request(
        SourceProviderMethod::Acquire,
        encode_acquire_request(&root),
        root_signer,
        &key,
    )
    .unwrap();
    let snapshot = ZfsHeldSnapshotProofV1::new(
        [13; 32],
        14,
        15,
        16,
        17,
        [18; 16],
        19,
        digest(20),
        digest(21),
        digest(22),
    )
    .unwrap();
    let catalog = ProviderHeldSnapshotCatalogV1::new(
        23,
        digest(24),
        vec![
            ProviderHeldSnapshotRowV1::new(
                binding_digest,
                [25; 32],
                26,
                digest(27),
                28,
                digest(29),
                snapshot,
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let claims = StorageZfsHoldTransportRequestV1::new(
        1,
        nonce,
        source_provider_request_attempt_digest_v1(
            signed_root.signer(),
            SourceProviderMethod::Acquire,
            root.request_id(),
        ),
        [33; 16],
        root.holder_authority_id(),
        root.session_binding(),
        root.acquisition_id(),
        binding_digest,
        digest(34),
        issued,
        issued + 60,
        catalog,
    )
    .unwrap();
    let provider_key = SigningKey::from_bytes(&[54; 32]);
    let signer = SourceProviderSigningKeyV1::for_signing_key(
        [33; 16],
        35,
        digest(36),
        [37; 16],
        38,
        SourceProviderKeyUsageV1::ProviderOutcome,
        &provider_key,
    )
    .unwrap();
    let signed = SignedStorageNativeAcquireRequestV2::sign(
        StorageNativeAcquireRequestV2::new(claims, signed_root).unwrap(),
        signer,
        &provider_key,
    )
    .unwrap();
    let initial = RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
        root.boot_id(),
        issued,
        1_000_000_000,
    )
    .unwrap();
    let anchor = NativeAcquireClockAnchorV1::new_untrusted(initial, &signed).unwrap();
    NativeAcquireCompletionRecordV2::requested(signed, digest(39), anchor).unwrap()
}

fn challenge_proposal(record: &NativeAcquireCompletionRecordV2) -> ChallengeRecordV1 {
    ChallengeRecordV1::new(
        record.provider_id,
        record.holder_id,
        record.session_binding,
        record.attempt_digest,
        record.acquisition_id,
        record.binding_digest,
        record.publication_head,
        record.challenge_issued_seconds,
        record.challenge_valid_until_seconds,
    )
}

pub(crate) fn prepared(
    requested: &NativeAcquireCompletionRecordV2,
) -> NativeAcquireCompletionRecordV2 {
    let descriptor = SourceRootObservationV1::new([6; 16], 72, 73, 74, true, true, true).unwrap();
    prepared_with_descriptor(requested, descriptor).0
}

pub(crate) fn prepared_with_descriptor(
    requested: &NativeAcquireCompletionRecordV2,
    descriptor: SourceRootObservationV1,
) -> (
    NativeAcquireCompletionRecordV2,
    VerifiedStorageNativeAcquireV3,
) {
    let signed = requested.canonical_request.as_ref().unwrap();
    let catalog = signed.request().claims().catalog();
    let (resource, snapshot) = catalog
        .select_under_head(
            catalog.generation(),
            catalog.digest(),
            catalog.namespace_digest(),
            requested.binding_digest,
        )
        .unwrap();
    let signer = StorageZfsHoldSignerV1::new([61; 16], 62, digest(63), [64; 16], 65).unwrap();
    let key = SigningKey::from_bytes(&[66; 32]);
    let head =
        StorageZfsHoldHeadV1::new(67, digest(68), 62, digest(63), 69, digest(70), digest(71))
            .unwrap();
    let receipt = StorageZfsHoldReceiptV1::new(
        requested.challenge,
        requested.attempt_digest,
        requested.binding_digest,
        resource,
        snapshot,
        head,
        requested.challenge_issued_seconds,
        requested.challenge_valid_until_seconds,
    )
    .unwrap();
    let unsigned = SignedStorageZfsHoldReceiptV1::new(receipt.clone(), signer, [0; 64]);
    let receipt = SignedStorageZfsHoldReceiptV1::new(
        receipt,
        signer,
        key.sign(&unsigned.signing_message()).to_bytes(),
    );
    let topology =
        storage_native_nonrecursive_topology_v1(signed, &receipt, &descriptor, 2, 75).unwrap();
    let acceptance = StorageNativeAcceptanceV3::new(
        [76; 16],
        signed.digest(),
        receipt.digest(),
        descriptor.clone(),
        topology,
    )
    .unwrap();
    let reply = StorageNativeAcquireReplyV3::new(
        SignedStorageNativeAcceptanceV3::sign(acceptance, signer, &key),
        receipt,
    )
    .unwrap();
    let original_key = SigningKey::from_bytes(&[51; 32]).verifying_key().to_bytes();
    let provider_key = SigningKey::from_bytes(&[54; 32]).verifying_key().to_bytes();
    let verified = reply
        .verify_for(StorageNativeAcquireVerificationV3 {
            request: signed,
            provider_signer: signed.signer(),
            provider_key: &provider_key,
            root_signer: signed.request().signed_root_request().signer(),
            root_key: &original_key,
            storage_verifier: StorageZfsHoldVerifierV1::new(signer, key.verifying_key().to_bytes())
                .unwrap(),
            expected_receipt: reply.receipt().receipt(),
            observed_descriptor: &descriptor,
            descriptor_roles: &[SourceProviderDescriptorRole::SourceRoot],
            now_seconds: requested.challenge_issued_seconds + 1,
        })
        .unwrap();
    (
        requested.prepare_accepted(reply, &verified).unwrap(),
        verified,
    )
}

fn fixture_directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn provider_journal(directory: &std::path::Path) -> Journal {
    Journal::open_protected_at_uid(
        directory,
        "requested-cut.journal",
        JournalLimits::default(),
        rustix::process::geteuid().as_raw(),
    )
    .unwrap()
    .0
}

fn retain_requested(journal: &mut Journal, row: &NativeAcquireCompletionRecordV2) {
    let mut owner = journal
        .claim_protected_authority(RecordNamespace::SourceProviderAuthority)
        .unwrap();
    let transaction = JournalTransaction::new(
        [71; 16],
        vec![JournalRecord::put(
            RecordNamespace::SourceProviderAuthority,
            native_completion_key_v2(row.acquisition_id),
            crate::format::encode_native_completion_v2(row),
        )],
    )
    .unwrap();
    let preflight = owner
        .preflight_transactions(std::slice::from_ref(&transaction))
        .unwrap();
    owner
        .validate_preflight_for_effect(&preflight, std::slice::from_ref(&transaction))
        .unwrap();
    owner.commit(&transaction).unwrap();
    // This is a journal-cut fixture, not a bypass of from_owner_readback's
    // production session/graph/capacity/clock qualification.
}

fn read_requested(
    journal: &mut Journal,
    acquisition: ObjectDigest,
) -> NativeAcquireCompletionRecordV2 {
    let owner = journal
        .claim_protected_authority(RecordNamespace::SourceProviderAuthority)
        .unwrap();
    let key = native_completion_key_v2(acquisition);
    let bytes = owner.get(&key).unwrap().unwrap();
    let DecodedRecordV1::NativeCompletion(row) = crate::format::decode_record(&key, bytes).unwrap()
    else {
        panic!("wrong typed native family");
    };
    assert_eq!(crate::format::encode_native_completion_v2(&row), bytes);
    row
}

#[test]
fn native_requested_first_crash_recovers_exact_original_nonce_and_clock() {
    let provider_directory = fixture_directory();
    let challenge_directory = fixture_directory();
    let now = current_seconds().unwrap();
    let prototype = requested([1; 32], now);
    let mut provider = provider_journal(provider_directory.path());
    let mut challenges =
        ProtectedZfsHoldChallengesV1::open_fixture(challenge_directory.path()).unwrap();
    let staged = challenges.stage(challenge_proposal(&prototype)).unwrap();
    let row = requested(staged.record().challenge.nonce(), now);
    assert!(
        challenges
            .retained_for_attempt(row.provider_id, row.holder_id, row.attempt_digest)
            .unwrap()
            .is_none()
    );

    retain_requested(&mut provider, &row);
    assert_eq!(read_requested(&mut provider, row.acquisition_id), row);
    // Crash AFTER Requested readback, BEFORE challenge append. The original
    // proposal survives solely in the protected native row, not an in-memory
    // staging token. Neither journal claims cross-journal atomicity.
    drop(staged);
    drop(challenges);
    drop(provider);
    let mut provider = provider_journal(provider_directory.path());
    let recovered = read_requested(&mut provider, row.acquisition_id);
    assert_eq!(recovered.original_clock, row.original_clock);
    let token = RetainedNativeChallengeRequestV1 { record: &recovered };
    let mut challenges =
        ProtectedZfsHoldChallengesV1::open_fixture(challenge_directory.path()).unwrap();
    let issued = challenges
        .ensure_for_retained_request(&token, None)
        .unwrap();
    require_exact_challenge(&recovered, issued).unwrap();
    assert_eq!(issued.challenge.nonce(), row.challenge);

    drop(challenges);
    let mut challenges =
        ProtectedZfsHoldChallengesV1::open_fixture(challenge_directory.path()).unwrap();
    assert_eq!(
        challenges
            .ensure_for_retained_request(&token, None)
            .unwrap(),
        issued
    );
    assert!(challenges.stage(challenge_proposal(&recovered)).is_err());
    assert_eq!(read_requested(&mut provider, row.acquisition_id), recovered);
}

#[test]
fn native_staging_has_no_append_and_changed_requested_nonce_cannot_reissue() {
    let directory = fixture_directory();
    let now = current_seconds().unwrap();
    let prototype = requested([1; 32], now);
    let mut challenges = ProtectedZfsHoldChallengesV1::open_fixture(directory.path()).unwrap();
    let staged = challenges.stage(challenge_proposal(&prototype)).unwrap();
    let row = requested(staged.record().challenge.nonce(), now);
    // Production constructs this only after full protected owner readback.
    // This local fixture isolates exact challenge binding and append behavior.
    let token = RetainedNativeChallengeRequestV1 { record: &row };
    let issued = challenges
        .ensure_for_retained_request(&token, Some(staged))
        .unwrap();
    let changed = requested([42; 32], now);
    assert!(
        challenges
            .ensure_for_retained_request(
                &RetainedNativeChallengeRequestV1 { record: &changed },
                None
            )
            .is_err()
    );
    assert_eq!(
        challenges
            .retained_for_attempt(row.provider_id, row.holder_id, row.attempt_digest)
            .unwrap(),
        Some(issued)
    );

    let mut changed = row.clone();
    changed.session_binding = digest(42);
    assert!(
        challenges
            .ensure_for_retained_request(
                &RetainedNativeChallengeRequestV1 { record: &changed },
                None
            )
            .is_err()
    );
    let mut missing_clock = row;
    missing_clock.original_clock = None;
    // The actual owner constructor refuses this historical row even if its
    // exact challenge exists; no new anchor can be inferred from wall bounds.
    assert!(
        challenges
            .ensure_for_retained_request(
                &RetainedNativeChallengeRequestV1 {
                    record: &missing_clock
                },
                None
            )
            .is_err()
    );
}

#[test]
fn native_requested_expired_missing_challenge_cannot_issue_or_renew() {
    let directory = fixture_directory();
    let expired = requested([1; 32], current_seconds().unwrap() - 61);
    let token = RetainedNativeChallengeRequestV1 { record: &expired };
    let mut challenges = ProtectedZfsHoldChallengesV1::open_fixture(directory.path()).unwrap();
    assert!(
        challenges
            .ensure_for_retained_request(&token, None)
            .is_err()
    );
    assert!(
        challenges
            .retained_for_attempt(
                expired.provider_id,
                expired.holder_id,
                expired.attempt_digest
            )
            .unwrap()
            .is_none()
    );
}

#[test]
fn native_staged_drop_before_requested_leaves_no_durable_nonce() {
    let directory = fixture_directory();
    let row = requested([1; 32], current_seconds().unwrap());
    let mut challenges = ProtectedZfsHoldChallengesV1::open_fixture(directory.path()).unwrap();
    let staged = challenges.stage(challenge_proposal(&row)).unwrap();
    drop(staged);
    drop(challenges);
    let mut challenges = ProtectedZfsHoldChallengesV1::open_fixture(directory.path()).unwrap();
    assert!(
        challenges
            .retained_for_attempt(row.provider_id, row.holder_id, row.attempt_digest)
            .unwrap()
            .is_none()
    );
}

#[test]
fn native_valid_historical_v6_prepared_and_active_fail_runtime_anchor_gate() {
    let row = prepared(&requested([1; 32], current_seconds().unwrap()));
    for phase in [
        NativeAcquireCompletionStateV2::Prepared,
        NativeAcquireCompletionStateV2::Active,
    ] {
        let mut historical = row.advance(phase).unwrap();
        historical.original_clock = None;
        let key = native_completion_key_v2(historical.acquisition_id);
        let bytes = crate::format::encode_native_completion_v2(&historical);
        assert_eq!(&bytes[8..10], &6_u16.to_be_bytes());
        let DecodedRecordV1::NativeCompletion(decoded) =
            crate::format::decode_record(&key, &bytes).unwrap()
        else {
            panic!("wrong historical family");
        };
        decoded.validate_canonical_artifacts().unwrap();
        // The SAME runtime gate is invoked before resume/sign, Requested
        // recovery and private clock restoration; no malformed fixture or
        // expired signature is responsible for this explicit refusal.
        assert!(super::super::clock::retained_clock_anchor(&decoded).is_err());
    }
}

#[test]
fn native_prepared_spend_crash_keeps_same_nonce_receipt_and_anchor() {
    let directory = fixture_directory();
    let now = current_seconds().unwrap();
    let mut challenges = ProtectedZfsHoldChallengesV1::open_fixture(directory.path()).unwrap();
    let prototype = requested([1; 32], now);
    let staged = challenges.stage(challenge_proposal(&prototype)).unwrap();
    let row = requested(staged.record().challenge.nonce(), now);
    let issued = challenges
        .ensure_for_retained_request(
            &RetainedNativeChallengeRequestV1 { record: &row },
            Some(staged),
        )
        .unwrap();
    let prepared = prepared(&row);
    challenges.spend(issued, prepared.receipt_digest).unwrap();
    drop(challenges);

    let mut challenges = ProtectedZfsHoldChallengesV1::open_fixture(directory.path()).unwrap();
    let token = RetainedNativeChallengeRequestV1 { record: &prepared };
    let spent = challenges
        .ensure_for_retained_request(&token, None)
        .unwrap();
    require_exact_challenge(&prepared, spent).unwrap();
    assert_eq!(spent.spent_receipt(), Some(prepared.receipt_digest));
    challenges.spend(spent, prepared.receipt_digest).unwrap();
    assert_eq!(prepared.original_clock, row.original_clock);
    assert!(challenges.stage(challenge_proposal(&row)).is_err());

    let empty_directory = fixture_directory();
    let mut absent = ProtectedZfsHoldChallengesV1::open_fixture(empty_directory.path()).unwrap();
    assert!(absent.ensure_for_retained_request(&token, None).is_err());
}
