//! Genuine protected-writer metadata cuts and descriptor-free delivery fixtures.

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use aos_sandbox::{Journal, JournalLimits};
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_source_provider_protocol::{
    SIGNED_STORAGE_NATIVE_ACCEPTANCE_READBACK_BYTES_V1,
    SignedStorageNativeAcceptanceReadbackQueryV1, SignedStorageNativeAcceptanceReadbackV1,
    SignedStorageNativeAcquireRequestV2, SourceProviderKeyUsageV1, SourceProviderSigningKeyV1,
    StorageNativeAcceptanceReadbackQueryV1, StorageNativeAcceptanceV3,
};
use ed25519_dalek::SigningKey;
use tempfile::TempDir;

use super::*;
use crate::live_export_request_trust::StorageLiveExportRequestTrustV1;

const JOURNALS: [&str; 3] = [
    "storage-state.journal",
    "storage-workspaces.journal",
    "storage-native-issuance.journal",
];

fn digest(byte: u8) -> ObjectDigest {
    ObjectDigest::from_bytes([byte; 32])
}

fn provider_key(seed: [u8; 32], generation: u64) -> SourceProviderSigningKeyV1 {
    SourceProviderSigningKeyV1::for_signing_key(
        [30; 16],
        1,
        digest(33),
        [34; 16],
        generation,
        SourceProviderKeyUsageV1::ProviderOutcome,
        &SigningKey::from_bytes(&seed),
    )
    .unwrap()
}

fn signed_query(
    original: &SignedStorageNativeAcquireRequestV2,
    seed: [u8; 32],
    generation: u64,
) -> SignedStorageNativeAcceptanceReadbackQueryV1 {
    let query =
        StorageNativeAcceptanceReadbackQueryV1::new(30, digest(90), [91; 32], original).unwrap();
    SignedStorageNativeAcceptanceReadbackQueryV1::sign(
        query,
        provider_key(seed, generation),
        &SigningKey::from_bytes(&seed),
    )
    .unwrap()
}

fn runtime_fixture(
    directory: &TempDir,
    retirement: Option<bool>,
) -> (
    StorageBrokerRuntime,
    SignedStorageNativeAcquireRequestV2,
    Option<StorageNativeAcceptanceV3>,
) {
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let uid = fs::metadata(directory.path()).unwrap().uid();
    let mut runtime = crate::broker::native_runtime_fixture_for_test(directory, directory);
    for name in &JOURNALS[..2] {
        for path in [
            directory.path().join(name),
            directory.path().join(format!("{name}.lock")),
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    // Reopen the same canonical primary/workspace bytes under genuine private
    // UID writer custody. Only their root-owned ancestry is a test boundary;
    // actual location, owner, lock, name, health, and replay checks remain live.
    runtime.coordinator = runtime
        .coordinator
        .into_protected_metadata_fixture(directory.path(), uid)
        .unwrap();
    runtime.workspaces = Some(
        runtime
            .workspaces
            .take()
            .unwrap()
            .into_protected_metadata_fixture(directory.path(), uid)
            .unwrap(),
    );
    let mut issuance = crate::native_issuance::native_issuance_fixture_for_test(directory.path());
    let (request, acceptance) = match retirement {
        Some(retired) => {
            let (request, acceptance) =
                crate::native_issuance::populate_native_metadata_fixture_for_test(
                    &mut issuance,
                    retired,
                );
            (request, Some(acceptance))
        }
        None => (
            crate::native_issuance::native_metadata_request_fixture_for_test(),
            None,
        ),
    };
    runtime.native_issuance = Some(issuance);
    runtime.held_reader_state_directory = Some(directory.path().to_owned());
    runtime.native_readback_fixture_uid = Some(uid);
    runtime.readiness = StorageRuntimeReadiness::Ready;
    (runtime, request, acceptance)
}

fn journal_bytes(directory: &TempDir) -> Vec<Vec<u8>> {
    JOURNALS
        .iter()
        .map(|name| fs::read(directory.path().join(name)).unwrap())
        .collect()
}

fn read_metadata(
    runtime: &mut StorageBrokerRuntime,
    query: &SignedStorageNativeAcceptanceReadbackQueryV1,
    trust: &StorageLiveExportRequestTrustV1,
    key: &StorageZfsHoldKeyV1,
) -> SignedStorageNativeAcceptanceReadbackV1 {
    let authenticated = trust.verify_native_readback(query).unwrap();
    let mut packet = Vec::new();
    runtime
        .with_native_acceptance_readback_v1(&authenticated, key, |bytes| {
            packet = bytes.to_vec();
            Ok(())
        })
        .unwrap();
    let reply = SignedStorageNativeAcceptanceReadbackV1::from_canonical_bytes(&packet).unwrap();
    reply.verify_for(query, key.verifier()).unwrap();
    reply
}

#[test]
fn native_metadata_found_and_tombstone_hold_all_three_writers_through_zero_fd_send() {
    for retired in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let trust_directory = tempfile::tempdir().unwrap();
        let (mut runtime, original, acceptance) = runtime_fixture(&directory, Some(retired));
        let trust =
            StorageLiveExportRequestTrustV1::native_fixture_for_test(trust_directory.path());
        let query = signed_query(&original, [32; 32], 1);
        let authenticated = trust.verify_native_readback(&query).unwrap();
        let expected_sequence = runtime
            .native_issuance
            .as_mut()
            .unwrap()
            .readback_acceptance(&authenticated)
            .unwrap()
            .sequence();
        let key = StorageZfsHoldKeyV1::synthetic_key_for_test();
        let before = journal_bytes(&directory);
        let (left, right) = rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::SEQPACKET,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        let mut sender = DescriptorSubjectSocket::from_owned(left).unwrap();
        let mut receiver = DescriptorSubjectSocket::from_owned(right).unwrap();

        runtime
            .with_native_acceptance_readback_v1(&authenticated, &key, |bytes| {
                let uid = fs::metadata(directory.path()).unwrap().uid();
                for name in JOURNALS {
                    assert!(matches!(
                        Journal::open_protected_at_uid(
                            directory.path(),
                            name,
                            JournalLimits::default(),
                            uid,
                        ),
                        Err(aos_sandbox::JournalError::AlreadyLocked)
                    ));
                }
                assert_eq!(journal_bytes(&directory), before);
                sender.send(bytes).map_err(|_| ())
            })
            .unwrap();
        let record = receiver
            .receive(SIGNED_STORAGE_NATIVE_ACCEPTANCE_READBACK_BYTES_V1, 0)
            .unwrap();
        assert!(record.descriptors().is_empty());
        let reply = SignedStorageNativeAcceptanceReadbackV1::from_canonical_bytes(record.payload())
            .unwrap();
        reply.verify_for(&query, key.verifier()).unwrap();
        assert_eq!(reply.acceptance(), acceptance.as_ref());
        // Each transition writes Begin/Put/Commit; a new journal starts at 1.
        assert_eq!(expected_sequence, if retired { 7 } else { 4 });
        assert_eq!(reply.observed_issuance_sequence(), expected_sequence);
        assert_eq!(journal_bytes(&directory), before);
        assert_eq!(runtime.native_escrow.count_for_test(), 0);
        assert!(runtime.native_fixture.is_none());
    }
}

#[test]
fn native_metadata_not_found_is_reobserved_without_an_admission_fence() {
    let directory = tempfile::tempdir().unwrap();
    let trust_directory = tempfile::tempdir().unwrap();
    let (mut runtime, original, _) = runtime_fixture(&directory, None);
    let trust = StorageLiveExportRequestTrustV1::native_fixture_for_test(trust_directory.path());
    let query = signed_query(&original, [32; 32], 1);
    let key = StorageZfsHoldKeyV1::synthetic_key_for_test();
    let before = journal_bytes(&directory);
    let missing = read_metadata(&mut runtime, &query, &trust, &key);
    assert!(missing.acceptance().is_none());
    assert_eq!(journal_bytes(&directory), before);

    // An observation cannot reserve this key or fence later owner admission.
    // The cfg(test) prepared row remains unrelated to a public Acquire gate.
    let (retained, acceptance) = crate::native_issuance::populate_native_metadata_fixture_for_test(
        runtime.native_issuance.as_mut().unwrap(),
        false,
    );
    assert_eq!(retained, original);
    let found = read_metadata(&mut runtime, &query, &trust, &key);
    assert_eq!(found.acceptance(), Some(&acceptance));
    assert!(found.observed_issuance_sequence() > missing.observed_issuance_sequence());
}

#[test]
fn native_metadata_occupied_holder_or_signed_request_mismatch_never_returns_not_found() {
    let directory = tempfile::tempdir().unwrap();
    let trust_directory = tempfile::tempdir().unwrap();
    let (mut runtime, original, _) = runtime_fixture(&directory, Some(false));
    let trust = StorageLiveExportRequestTrustV1::native_fixture_for_test(trust_directory.path());
    let key = StorageZfsHoldKeyV1::synthetic_key_for_test();
    let query = signed_query(&original, [32; 32], 1);
    let before = journal_bytes(&directory);

    for offset in [104, 152] {
        let mut bytes = query.to_canonical_bytes();
        bytes[offset] ^= 1;
        let decoded =
            SignedStorageNativeAcceptanceReadbackQueryV1::from_canonical_bytes(&bytes).unwrap();
        let conflicting = SignedStorageNativeAcceptanceReadbackQueryV1::sign(
            decoded.query().clone(),
            provider_key([32; 32], 1),
            &SigningKey::from_bytes(&[32; 32]),
        )
        .unwrap();
        let authenticated = trust.verify_native_readback(&conflicting).unwrap();
        assert!(matches!(
            runtime
                .native_issuance
                .as_mut()
                .unwrap()
                .readback_acceptance(&authenticated),
            Err(crate::native_issuance::StorageNativeIssuanceErrorV1::Conflict)
        ));
        assert!(
            runtime
                .with_native_acceptance_readback_v1(&authenticated, &key, |_| {
                    panic!("conflicting occupied row must not send any metadata")
                })
                .is_err()
        );
        assert_eq!(journal_bytes(&directory), before);
        assert_eq!(runtime.native_escrow.count_for_test(), 0);
    }
}

#[test]
fn native_metadata_signer_refuses_an_observation_from_another_signed_query() {
    let directory = tempfile::tempdir().unwrap();
    let trust_directory = tempfile::tempdir().unwrap();
    let (mut runtime, original, _) = runtime_fixture(&directory, Some(false));
    let trust = StorageLiveExportRequestTrustV1::native_fixture_for_test(trust_directory.path());
    let query = signed_query(&original, [32; 32], 1);
    let authenticated = trust.verify_native_readback(&query).unwrap();
    let observed = runtime
        .native_issuance
        .as_mut()
        .unwrap()
        .readback_acceptance(&authenticated)
        .unwrap();
    let other = SignedStorageNativeAcceptanceReadbackQueryV1::sign(
        StorageNativeAcceptanceReadbackQueryV1::new(31, digest(90), [92; 32], &original).unwrap(),
        provider_key([32; 32], 1),
        &SigningKey::from_bytes(&[32; 32]),
    )
    .unwrap();
    let other_authenticated = trust.verify_native_readback(&other).unwrap();
    let key = StorageZfsHoldKeyV1::synthetic_key_for_test();
    let before = journal_bytes(&directory);

    assert!(
        key.sign_native_acceptance_readback(&other_authenticated, &observed)
            .is_err()
    );
    assert_eq!(journal_bytes(&directory), before);
    assert_eq!(runtime.native_escrow.count_for_test(), 0);
}

#[test]
fn native_metadata_current_rotated_envelope_preserves_historical_unsigned_acceptance() {
    let directory = tempfile::tempdir().unwrap();
    let old_trust_directory = tempfile::tempdir().unwrap();
    let new_trust_directory = tempfile::tempdir().unwrap();
    let (mut runtime, original, acceptance) = runtime_fixture(&directory, Some(true));
    let old_trust =
        StorageLiveExportRequestTrustV1::native_fixture_for_test(old_trust_directory.path());
    let new_trust = StorageLiveExportRequestTrustV1::native_provider_fixture_for_test(
        new_trust_directory.path(),
        [92; 32],
        2,
    );
    let old_query = signed_query(&original, [32; 32], 1);
    let new_query = signed_query(&original, [92; 32], 2);
    assert!(new_trust.verify_native_readback(&old_query).is_err());
    assert!(old_trust.verify_native_readback(&new_query).is_err());
    // The original Provider/Root signatures are historical. Only today's
    // independently pinned ProviderOutcome authorizes this metadata query.
    assert!(new_trust.verify_native(&original).is_err());
    let old_key = StorageZfsHoldKeyV1::synthetic_key_for_test();
    let new_key = StorageZfsHoldKeyV1::synthetic_rotated_key_for_test([93; 32], 6);
    let before = journal_bytes(&directory);
    let old_reply = read_metadata(&mut runtime, &old_query, &old_trust, &old_key);
    let new_reply = read_metadata(&mut runtime, &new_query, &new_trust, &new_key);

    assert_ne!(
        old_reply.to_canonical_bytes(),
        new_reply.to_canonical_bytes()
    );
    assert_eq!(old_reply.acceptance(), acceptance.as_ref());
    assert_eq!(new_reply.acceptance(), acceptance.as_ref());
    assert!(
        new_reply
            .verify_for(&new_query, old_key.verifier())
            .is_err()
    );
    assert_eq!(journal_bytes(&directory), before);
    assert_eq!(runtime.native_escrow.count_for_test(), 0);
}

#[test]
fn native_metadata_each_unsafe_or_replaced_owner_journal_name_denies_without_mutation() {
    let directory = tempfile::tempdir().unwrap();
    let trust_directory = tempfile::tempdir().unwrap();
    let (mut runtime, original, _) = runtime_fixture(&directory, Some(false));
    let trust = StorageLiveExportRequestTrustV1::native_fixture_for_test(trust_directory.path());
    let query = signed_query(&original, [32; 32], 1);
    let authenticated = trust.verify_native_readback(&query).unwrap();
    let key = StorageZfsHoldKeyV1::synthetic_key_for_test();
    let before = journal_bytes(&directory);

    for name in JOURNALS {
        for basename in [name.to_owned(), format!("{name}.lock")] {
            let path = directory.path().join(&basename);
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(
                runtime
                    .with_native_acceptance_readback_v1(&authenticated, &key, |_| {
                        panic!("unsafe owner cut must not send")
                    })
                    .is_err()
            );
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

            let retained = directory.path().join(format!("{basename}.retained"));
            fs::rename(&path, &retained).unwrap();
            fs::write(&path, fs::read(&retained).unwrap()).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(
                runtime
                    .with_native_acceptance_readback_v1(&authenticated, &key, |_| {
                        panic!("same-byte replacement is not the held owner name")
                    })
                    .is_err()
            );
            fs::remove_file(&path).unwrap();
            fs::rename(&retained, &path).unwrap();
            assert_eq!(journal_bytes(&directory), before);
        }
    }
    assert_eq!(runtime.native_escrow.count_for_test(), 0);
    read_metadata(&mut runtime, &query, &trust, &key);
}

#[test]
fn native_metadata_replaced_state_directory_or_current_trust_refuses_delivery() {
    let directory = tempfile::tempdir().unwrap();
    let retained_directory = tempfile::tempdir().unwrap();
    let trust_directory = tempfile::tempdir().unwrap();
    let (mut runtime, original, _) = runtime_fixture(&directory, Some(false));
    let trust = StorageLiveExportRequestTrustV1::native_fixture_for_test(trust_directory.path());
    let query = signed_query(&original, [32; 32], 1);
    let authenticated = trust.verify_native_readback(&query).unwrap();
    let key = StorageZfsHoldKeyV1::synthetic_key_for_test();
    let before = journal_bytes(&directory);
    let retained = retained_directory.path().join("state");
    fs::rename(directory.path(), &retained).unwrap();
    fs::create_dir(directory.path()).unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        runtime
            .with_native_acceptance_readback_v1(&authenticated, &key, |_| {
                panic!("replacement state directory must not send")
            })
            .is_err()
    );
    fs::remove_dir(directory.path()).unwrap();
    fs::rename(retained, directory.path()).unwrap();

    let trust_path = trust_directory
        .path()
        .join("storage-live-export-request-trust-v1");
    let original_trust = fs::read(&trust_path).unwrap();
    fs::set_permissions(&trust_path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        runtime
            .with_native_acceptance_readback_v1(&authenticated, &key, |_| {
                panic!("unsafe current Provider pin must not send")
            })
            .is_err()
    );
    fs::set_permissions(&trust_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(fs::read(trust_path).unwrap(), original_trust);
    assert_eq!(journal_bytes(&directory), before);
    assert_eq!(runtime.native_escrow.count_for_test(), 0);
}

#[test]
fn native_metadata_send_failure_changes_neither_rows_nor_original_root_escrow() {
    let directory = tempfile::tempdir().unwrap();
    let trust_directory = tempfile::tempdir().unwrap();
    let (mut runtime, original, acceptance) = runtime_fixture(&directory, Some(false));
    let trust = StorageLiveExportRequestTrustV1::native_fixture_for_test(trust_directory.path());
    let query = signed_query(&original, [32; 32], 1);
    let authenticated = trust.verify_native_readback(&query).unwrap();
    let key = StorageZfsHoldKeyV1::synthetic_key_for_test();
    let before = journal_bytes(&directory);
    assert!(
        runtime
            .with_native_acceptance_readback_v1(&authenticated, &key, |_| Err(()))
            .is_err()
    );
    assert_eq!(journal_bytes(&directory), before);
    assert_eq!(runtime.native_escrow.count_for_test(), 0);
    assert_eq!(runtime.readiness, StorageRuntimeReadiness::Ready);
    assert_eq!(
        read_metadata(&mut runtime, &query, &trust, &key).acceptance(),
        acceptance.as_ref()
    );
}
