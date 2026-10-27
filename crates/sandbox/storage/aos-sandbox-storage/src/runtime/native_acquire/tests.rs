//! Focused signed intent, cold-custody fencing, and stable original replay checks.

use aos_sandbox_source_provider_protocol::{
    SignedStorageNativeAcceptanceV3, SignedStorageZfsHoldReceiptV1, SourceProviderKeyUsageV1,
    SourceProviderSigningKeyV1, SourceRootObservationV1, StorageZfsHoldHeadV1,
    StorageZfsHoldReceiptV1, StorageZfsHoldSignerV1, storage_native_nonrecursive_topology_v1,
};
use ed25519_dalek::{Signer as _, SigningKey};

use super::*;

fn digest(byte: u8) -> ObjectDigest {
    ObjectDigest::from_bytes([byte; 32])
}

fn request() -> SignedStorageNativeAcquireRequestV2 {
    crate::native_issuance::native_request_fixture_for_test().0
}

fn clock(wall: i64, boot: u8) -> RawPairedClockSample {
    RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted([90; 16]).unwrap(),
        [boot; 16],
        wall,
        1,
    )
    .unwrap()
}

fn reply(
    request: &SignedStorageNativeAcquireRequestV2,
    mount_id: u64,
) -> StorageNativeAcquireReplyV3 {
    let claims = request.request().claims();
    let catalog = claims.catalog();
    let (resource, snapshot) = catalog
        .select_under_head(
            catalog.generation(),
            catalog.digest(),
            catalog.namespace_digest(),
            claims.selection().0,
        )
        .unwrap();
    let signer = StorageZfsHoldSignerV1::new([91; 16], 1, digest(92), [93; 16], 1).unwrap();
    let key = SigningKey::from_bytes(&[94; 32]);
    let (challenge, attempt) = claims.attempt();
    let receipt = StorageZfsHoldReceiptV1::new(
        challenge,
        attempt,
        claims.selection().0,
        resource,
        snapshot,
        StorageZfsHoldHeadV1::new(1, digest(95), 1, digest(92), 1, digest(96), digest(97)).unwrap(),
        100,
        150,
    )
    .unwrap();
    let unsigned = SignedStorageZfsHoldReceiptV1::new(receipt.clone(), signer, [0; 64]);
    let receipt = SignedStorageZfsHoldReceiptV1::new(
        receipt,
        signer,
        key.sign(&unsigned.signing_message()).to_bytes(),
    );
    let descriptor =
        SourceRootObservationV1::new([26; 16], 100, 101, mount_id, true, true, true).unwrap();
    let topology =
        storage_native_nonrecursive_topology_v1(request, &receipt, &descriptor, 1, 0).unwrap();
    let acceptance = StorageNativeAcceptanceV3::new(
        [98; 16],
        request.digest(),
        receipt.digest(),
        descriptor,
        topology,
    )
    .unwrap();
    StorageNativeAcquireReplyV3::new(
        SignedStorageNativeAcceptanceV3::sign(acceptance, signer, &key),
        receipt,
    )
    .unwrap()
}

#[test]
fn native_request_binds_independent_pinned_provider_and_root_signatures() {
    let request = request();
    let provider_key = SigningKey::from_bytes(&[32; 32]);
    let root_key = SigningKey::from_bytes(&[28; 32]);
    let provider = SourceProviderSigningKeyV1::for_signing_key(
        [30; 16],
        1,
        digest(33),
        [34; 16],
        1,
        SourceProviderKeyUsageV1::ProviderOutcome,
        &provider_key,
    )
    .unwrap();
    let root = SourceProviderSigningKeyV1::for_signing_key(
        [22; 16],
        1,
        digest(23),
        [29; 16],
        1,
        SourceProviderKeyUsageV1::RootMountRecord,
        &root_key,
    )
    .unwrap();
    let provider_public = provider_key.verifying_key().to_bytes();
    let root_public = root_key.verifying_key().to_bytes();
    assert!(
        request
            .verify(&provider, &provider_public, &root, &root_public)
            .is_ok()
    );
    assert!(
        request
            .verify(&provider, &root_public, &root, &root_public)
            .is_err()
    );
    assert!(
        request
            .verify(&provider, &provider_public, &root, &provider_public)
            .is_err()
    );
}

#[test]
fn native_entry_clock_sampling_stall_does_not_extend_original_deadline() {
    let kernel_boottime = std::cell::Cell::new(1);
    let sample = super::super::paired_clock_sample_from_kernel_readers(
        || Ok([26; 16]),
        || Ok(kernel_boottime.get()),
        || {
            // Model a stall after capturing the integer wall observation but
            // before the reader returns. A later BOOTTIME anchor would extend
            // expiry by this entire delay, beyond the one-second guard.
            kernel_boottime.set(kernel_boottime.get() + 10_000_000_000);
            100
        },
    )
    .unwrap();

    assert_eq!(sample.boottime_nanoseconds(), 1);
    assert_eq!(kernel_boottime.get(), 10_000_000_001);
    assert_eq!(
        original_fail_stop_deadline(&request(), sample).unwrap(),
        49_000_000_001
    );
}

#[test]
fn original_expiry_is_conservatively_bound_to_boot_time_and_never_renewed() {
    let request = request();
    let deadline = original_fail_stop_deadline(&request, clock(100, 26)).unwrap();
    assert_eq!(deadline, 49_000_000_001);
    assert!(original_fail_stop_deadline(&request, clock(149, 26)).is_err());
    assert!(original_fail_stop_deadline(&request, clock(150, 26)).is_err());
    // A live retry uses the saved deadline; it never replaces it with the
    // later wall sample's prospective interval after a clock rollback.
    assert!(original_fail_stop_deadline(&request, clock(99, 26)).is_err());
}

#[test]
fn worker_measurement_cannot_extend_entry_deadline_after_wall_rollback() {
    let request = request();
    let initial = clock(120, 26);
    let deadline = original_fail_stop_deadline(&request, initial).unwrap();
    let rolled_back = RawPairedClockSample::new_untrusted(
        initial.provenance(),
        [26; 16],
        101,
        initial.boottime_nanoseconds() + 10_000_000_000,
    )
    .unwrap();
    assert!(validate_original_clock(&request, initial, rolled_back, deadline).is_err());
    let after_deadline =
        RawPairedClockSample::new_untrusted(initial.provenance(), [26; 16], 149, deadline).unwrap();
    assert!(validate_original_clock(&request, initial, after_deadline, deadline).is_err());
}

#[test]
fn native_delivery_clock_rejects_foreign_boot_and_expired_original_request() {
    let request = request();
    assert!(validate_native_request_clock(&request, clock(100, 26)).is_ok());
    for sample in [clock(99, 26), clock(150, 26), clock(110, 27)] {
        assert!(validate_native_request_clock(&request, sample).is_err());
    }
}

#[test]
fn accepted_cold_row_is_unavailable_never_a_new_measurement() {
    let original = reply(&request(), 102);
    let acceptance = original.acceptance().acceptance();
    assert_eq!(
        native_custody_action(Some(acceptance), None).unwrap(),
        NativeCustodyActionV2::Unavailable
    );
    assert_eq!(
        native_custody_action(None, None).unwrap(),
        NativeCustodyActionV2::MeasureNew
    );
    assert!(native_custody_action(None, Some(&original)).is_err());
}

#[test]
fn exact_live_retry_requires_original_acceptance_and_not_equal_content_remount() {
    let request = request();
    let original = reply(&request, 102);
    let remounted = reply(&request, 103);
    let accepted = original.acceptance().acceptance();
    assert_eq!(
        native_custody_action(Some(accepted), Some(&original)).unwrap(),
        NativeCustodyActionV2::ReplayOriginal
    );
    assert!(native_custody_action(Some(accepted), Some(&remounted)).is_err());
    assert_eq!(
        original.to_canonical_bytes(),
        original.clone().to_canonical_bytes()
    );
}

#[test]
fn delivery_ambiguity_has_no_retirement_or_cold_remount_transition() {
    let original = reply(&request(), 102);
    let retained = original.acceptance().acceptance().clone();
    // Transport failure does not change the committed acceptance or reply.
    for _ in 0..2 {
        assert_eq!(
            native_custody_action(Some(&retained), Some(&original)).unwrap(),
            NativeCustodyActionV2::ReplayOriginal
        );
    }
    // Only local escrow was lost; Provider custody is not asserted absent.
    assert_eq!(
        native_custody_action(Some(&retained), None).unwrap(),
        NativeCustodyActionV2::Unavailable
    );
}

fn synthetic_runtime(
    primary: &tempfile::TempDir,
    workspace: &tempfile::TempDir,
    issuance: &tempfile::TempDir,
    physical: &tempfile::TempDir,
) -> StorageBrokerRuntime {
    let (_, cut) = crate::native_issuance::native_request_fixture_for_test();
    let mount = rustix::fs::open(
        physical.path(),
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    let stat = fstat(mount.as_fd()).unwrap();
    let mount_id = MountId::from_fd(mount.as_fd()).unwrap().get();
    let measured = crate::process::HeldSnapshotReaderObservationV1 {
        content_digest: digest(17),
        tree_digest: digest(104),
        tree_size: 1,
        mount_id,
        root_device: stat.st_dev,
        root_inode: stat.st_ino,
        nodes: 1,
        file_bytes: 0,
        mounted_snapshot_guid: cut.snapshot.guid(),
        identity: crate::held_snapshot_tree::HeldSnapshotIdentityObservationV1 {
            root_attributes: PortableRootAttributesV1::new(0, 0, 0o755).unwrap(),
            maximum_portable_uid: 0,
            maximum_portable_gid: 0,
            distinct_inode_count: 1,
            directory_entry_count: 0,
            identity_tree_digest: digest(16),
        },
    };
    // This is deliberately NOT ZFS or read-only evidence. cfg(test) alone
    // substitutes physical checks to exercise real durable ordering, signing,
    // descriptor transfer, escrow retry and non-release cold recovery.
    let held = StorageHeldSnapshotReadbackWithMountV1 {
        readback: StorageHeldSnapshotReadbackV1 {
            cut: cut.clone(), pool_guid: 44,
            policy_head: crate::resolver::protected_catalog::StorageResolverPolicyCatalogBindingV1::from_parts_for_test(1, digest(105)),
            physical_observation_digest: digest(106), measured_tree: measured,
            post_measurement_observation_digest: digest(107),
        },
        mount, synthetic_fixture: Some([26; 16]),
    };
    let mut runtime = crate::broker::native_runtime_fixture_for_test(primary, workspace);
    runtime.native_issuance = Some(crate::native_issuance::native_issuance_fixture_for_test(
        issuance.path(),
    ));
    runtime.readiness = StorageRuntimeReadiness::Ready;
    runtime.native_fixture = Some(SyntheticNativeRuntimeV2 {
        held: Some(held),
        reply_override: None,
        cut,
        clock: clock(110, 26),
        measurements: 0,
        stale_cut: false,
    });
    runtime
}

#[test]
fn real_owner_accepts_before_send_retains_ambiguous_original_and_retransfers_same_fd() {
    use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;

    let primary = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let issuance = tempfile::tempdir().unwrap();
    let physical = tempfile::tempdir().unwrap();
    let trust_directory = tempfile::tempdir().unwrap();
    let mut runtime = synthetic_runtime(&primary, &workspace, &issuance, &physical);
    let request = request();
    let trust =
        crate::live_export_request_trust::StorageLiveExportRequestTrustV1::native_fixture_for_test(
            trust_directory.path(),
        );
    let authenticated = trust.verify_native(&request).unwrap();
    let key = StorageZfsHoldKeyV1::synthetic_key_for_test();
    let mut first_packet = Vec::new();
    let mut first_identity = (0, 0, 0);
    let ambiguous = runtime
        .with_native_acquire_delivery_v2(&authenticated, &key, |packet, mount, _| {
            let decoded = StorageNativeAcquireReplyV3::from_canonical_bytes(packet).unwrap();
            let accepted = decoded.acceptance().acceptance().to_canonical_bytes();
            let journal =
                std::fs::read(issuance.path().join("storage-native-issuance.journal")).unwrap();
            assert!(
                journal
                    .windows(accepted.len())
                    .any(|window| window == accepted)
            );
            assert!(
                crate::native_issuance::try_native_issuance_fixture_for_test(issuance.path())
                    .is_err()
            );
            assert!(
                crate::StorageTransactionStore::open_for_test(
                    primary.path(),
                    crate::state::StorageStateKey::new([51; 16], [52; 32]).unwrap(),
                    0
                )
                .is_err()
            );
            assert!(
                crate::workspace_catalog::PendingStorageWorkspaceCatalogV1::open_for_test(
                    workspace.path(),
                    crate::StorageIdentityPoolV1::new(65_536, 65_536 * 4).unwrap()
                )
                .is_err()
            );
            let stat = fstat(mount).unwrap();
            first_identity = (
                stat.st_dev,
                stat.st_ino,
                MountId::from_fd(mount).unwrap().get(),
            );
            first_packet = packet.to_vec();
            Err(())
        })
        .unwrap();
    assert_eq!(ambiguous, StorageNativeDeliveryOutcomeV2::SendAmbiguous);
    assert_eq!(runtime.native_fixture.as_ref().unwrap().measurements, 1);
    assert_eq!(runtime.native_escrow.originals.len(), 1);

    let conflict = crate::native_issuance::conflicting_native_request_fixture_for_test();
    let conflicting_auth = trust.verify_native(&conflict).unwrap();
    assert!(
        runtime
            .with_native_acquire_delivery_v2(&conflicting_auth, &key, |_, _, _| panic!(
                "conflicting attempt must not send"
            ))
            .is_err()
    );
    assert_eq!(runtime.native_fixture.as_ref().unwrap().measurements, 1);

    let (left, right) = rustix::net::socketpair(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::SEQPACKET,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();
    let mut sender = DescriptorSubjectSocket::from_owned(left).unwrap();
    let mut receiver = DescriptorSubjectSocket::from_owned(right).unwrap();
    let delivered = runtime
        .with_native_acquire_delivery_v2(&authenticated, &key, |packet, mount, _| {
            assert_eq!(packet, first_packet);
            assert!(
                crate::native_issuance::try_native_issuance_fixture_for_test(issuance.path())
                    .is_err()
            );
            sender
                .send_with_descriptors(packet, &[mount])
                .map_err(|_| ())
        })
        .unwrap();
    assert_eq!(delivered, StorageNativeDeliveryOutcomeV2::Delivered);
    let record = receiver.receive(first_packet.len(), 1).unwrap();
    assert_eq!(record.payload(), first_packet);
    assert_eq!(record.descriptors().len(), 1);
    let received = record.descriptors()[0].as_fd();
    let stat = fstat(received).unwrap();
    assert_eq!(
        (
            stat.st_dev,
            stat.st_ino,
            MountId::from_fd(received).unwrap().get()
        ),
        first_identity
    );
    assert_eq!(runtime.native_fixture.as_ref().unwrap().measurements, 1);

    runtime.native_fixture.as_mut().unwrap().stale_cut = true;
    assert!(
        runtime
            .with_native_acquire_delivery_v2(&authenticated, &key, |_, _, _| panic!(
                "stale cut must not send"
            ))
            .is_err()
    );
    assert_eq!(runtime.native_escrow.originals.len(), 1);
    runtime.native_fixture.as_mut().unwrap().stale_cut = false;

    // Simulate Storage-local escrow loss only. Provider-held FDs may survive;
    // no absence assertion or retirement can be inferred from this transition.
    runtime.native_escrow.originals.clear();
    assert_eq!(
        runtime
            .with_native_acquire_delivery_v2(&authenticated, &key, |_, _, _| panic!(
                "cold row must not send"
            ))
            .unwrap(),
        StorageNativeDeliveryOutcomeV2::Unavailable
    );
    assert_eq!(runtime.native_fixture.as_ref().unwrap().measurements, 1);
    let cut = runtime.native_fixture.as_ref().unwrap().cut.clone();
    assert!(matches!(
        runtime.native_issuance.as_mut().unwrap().check_release(
            &crate::CatalogPlanV1::ReleaseHold {
                snapshot: cut.snapshot,
                hold_id: cut.hold_id,
            }
        ),
        Err(crate::native_issuance::StorageNativeIssuanceErrorV1::HoldInUse)
    ));
}

#[test]
fn native_v3_replay_rejects_locally_signed_counts_not_from_original_readback() {
    let primary = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let issuance = tempfile::tempdir().unwrap();
    let physical = tempfile::tempdir().unwrap();
    let trust_directory = tempfile::tempdir().unwrap();
    let mut runtime = synthetic_runtime(&primary, &workspace, &issuance, &physical);
    let held = runtime
        .native_fixture
        .as_ref()
        .unwrap()
        .held
        .as_ref()
        .unwrap();
    let request = request();
    let trust =
        crate::live_export_request_trust::StorageLiveExportRequestTrustV1::native_fixture_for_test(
            trust_directory.path(),
        );
    let authenticated = trust.verify_native(&request).unwrap();
    let key = StorageZfsHoldKeyV1::synthetic_key_for_test();
    let now = clock(110, 26);
    let original = key
        .sign_native_reply(&authenticated, held, [80; 16], now)
        .unwrap();
    key.verify_native_reply(&authenticated, held, &original, now)
        .unwrap();
    let accepted = original.acceptance().acceptance();
    let topology = accepted.topology();
    assert_eq!((topology.entry_count(), topology.byte_count()), (1, 0));
    assert_eq!(
        (topology.maximum_depth(), topology.observed_submounts()),
        (1, 0)
    );
    assert_eq!(
        topology.authority_id(),
        original.receipt().signer().authority().0
    );
    assert_eq!(topology.generation(), held.readback.cut.authority_sequence);

    // Both variants are valid, genuinely signed scalar profiles with the
    // exact original receipt/FD. Protocol verification cannot recover the
    // measured counts from the physical digest; the owner must rejoin them.
    let mut substituted = None;
    for (nodes, bytes) in [(2, 0), (2, 1)] {
        let topology = storage_native_nonrecursive_topology_v1(
            &request,
            original.receipt(),
            accepted.descriptor(),
            nodes,
            bytes,
        )
        .unwrap();
        let forged = StorageNativeAcceptanceV3::new(
            accepted.issuance_id(),
            accepted.request_digest(),
            accepted.receipt_digest(),
            accepted.descriptor().clone(),
            topology,
        )
        .unwrap();
        let forged = StorageNativeAcquireReplyV3::new(
            SignedStorageNativeAcceptanceV3::sign(
                forged,
                original.receipt().signer(),
                &SigningKey::from_bytes(&[7; 32]),
            ),
            original.receipt().clone(),
        )
        .unwrap();
        authenticated
            .verify_reply(
                &forged,
                key.verifier(),
                original.receipt().receipt(),
                accepted.descriptor(),
                now.wall_seconds(),
            )
            .unwrap();

        assert!(
            key.verify_native_reply(&authenticated, held, &forged, now)
                .is_err()
        );
        substituted = Some(forged);
    }
    runtime.native_fixture.as_mut().unwrap().reply_override = substituted;
    assert!(
        runtime
            .with_native_acquire_delivery_v2(&authenticated, &key, |_, _, _| {
                panic!("substituted counts must fail before descriptor send")
            })
            .is_err()
    );
    assert!(
        runtime
            .native_issuance
            .as_mut()
            .unwrap()
            .retained_acceptance(&request)
            .unwrap()
            .is_none()
    );
    assert!(runtime.native_escrow.originals.is_empty());
}
