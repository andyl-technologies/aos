//! Actual installed production actor preservation and original-request retry proof.

// Panics identify failure of actual source custody, fresh native reconstruction or ACK.
// crucible-lint: allow panic-shortcut -- These service tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{os::unix::fs::PermissionsExt, sync::Arc, time::Duration};

use crucible::node_contract::{ActivationRecord, SavedRuntimeActivation, SavedRuntimeResult};
use crucible_cas::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend,
};

use super::{
    control::{InstalledGem5Isa, NativeCapturePoint, NativeWorldOutcome, NativeWorldRequest},
    custody::Gem5CustodyQueue,
    ledger::activation_ref,
    ledger_tests::PanicCompletionRefs,
    service::NativeWorldService,
};
use crate::supervision::ProcessDeadline;

#[test]
#[ignore = "requires the source-installed closed gem5 profile and real native image tools"]
fn production_native_actor_preserves_pending_source_and_completes_two_fresh_worlds() {
    let directory = tempfile::tempdir().unwrap().keep();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let realm = directory.join("realm");
    std::fs::create_dir(&realm).unwrap();
    std::fs::set_permissions(&realm, std::fs::Permissions::from_mode(0o700)).unwrap();
    let blobs = Arc::new(DirectoryBlobBackend::new(
        "native-actor",
        directory.join("blobs"),
    ));
    let refs = Arc::new(DirectoryRefBackend::new(directory.join("refs")));
    let service = NativeWorldService::start(realm.clone(), 4, blobs.clone(), refs.clone()).unwrap();
    let capture = NativeWorldRequest::Capture {
        execution: "102132435465768798a9bacbdcedfe0f".into(),
        isa: InstalledGem5Isa::X86_64,
        point: NativeCapturePoint::Pending,
    };
    let reserved = service.submit(capture.clone()).unwrap();
    assert!(matches!(
        reserved.state,
        NativeWorldOutcome::Reserved { .. }
    ));
    let original = completed(&service, capture.execution());
    let NativeWorldOutcome::Completed {
        artifact,
        original: source_operation,
        activation: source_activation,
        ..
    } = &original.state
    else {
        panic!("source capture did not complete");
    };
    assert_eq!(source_operation.result, SavedRuntimeResult::Pending);
    assert_eq!(
        service.submit(capture.clone()).unwrap().request,
        original.request
    );
    assert!(
        service
            .submit(NativeWorldRequest::Capture {
                execution: capture.execution().into(),
                isa: InstalledGem5Isa::Aarch64,
                point: NativeCapturePoint::Pending,
            })
            .is_err()
    );
    let retention = service.retention_owner();
    drop(service);
    wait_retired(&retention);
    assert_eq!(
        std::fs::read_dir(&realm)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().len() == 32)
            .count(),
        0
    );

    // The same installed actor API reopens its signed archive after complete
    // source-owner retirement. No original native operational namespace remains.
    let service = NativeWorldService::start(realm.clone(), 4, blobs, refs).unwrap();
    let mut results = Vec::new();
    for execution in [
        "2031425364758697a8b9cadbecfd0e1f",
        "30415263748596a7b8c9daebfc0d1e2f",
    ] {
        service
            .submit(NativeWorldRequest::Restore {
                execution: execution.into(),
                isa: InstalledGem5Isa::X86_64,
                source: artifact.clone(),
                complete_original: true,
            })
            .unwrap();
        results.push(completed(&service, execution));
    }
    let mut publications = Vec::new();
    let mut owners = Vec::new();
    for result in &results {
        let NativeWorldOutcome::Completed {
            original,
            activation,
            completion_evidence,
            ..
        } = &result.state
        else {
            panic!("fresh native restoration did not complete");
        };
        assert_eq!(original.operation, source_operation.operation);
        assert_eq!(original.request, source_operation.request);
        assert!(original.scheduling_commit.is_some());
        assert!(completion_evidence.is_some());
        let SavedRuntimeResult::Acknowledged(outcome) = &original.result else {
            panic!("original native output was not acknowledged");
        };
        let publication = &outcome.scheduling.as_ref().unwrap().publications[0];
        assert_eq!(publication.payload_bytes.len(), 8);
        assert_eq!(publication.payload_bytes, known_guest_checksum());
        publications.push(publication.clone());
        owners.push(activation.owners.clone());
        assert_ne!(activation.owners, source_activation.owners);
    }
    assert_eq!(publications[0], publications[1]);
    assert_ne!(owners[0], owners[1]);
    assert!(service.retention_owner().retention_roots().unwrap().len() >= 10);
    let retention = service.retention_owner();
    drop(service);
    wait_retired(&retention);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "requires the source-installed closed gem5 profile and real native image tools"]
fn native_backend_panic_retains_original_capsule_and_queued_reservations() {
    let directory = tempfile::tempdir().unwrap().keep();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let realm = directory.join("realm");
    std::fs::create_dir(&realm).unwrap();
    std::fs::set_permissions(&realm, std::fs::Permissions::from_mode(0o700)).unwrap();
    let blobs = Arc::new(DirectoryBlobBackend::new(
        "native-backend-panic",
        directory.join("blobs"),
    ));
    let refs = Arc::new(PanicCompletionRefs::new(DirectoryRefBackend::new(
        directory.join("refs"),
    )));
    let native = Gem5CustodyQueue::installed(8).unwrap();
    let before = native.reserved_owners();
    let service = NativeWorldService::start(realm.clone(), 4, blobs.clone(), refs.clone()).unwrap();
    let mut requests = Vec::new();
    for execution in [
        "405162738495a6b7c8d9eafb0c1d2e3f",
        "5061728394a5b6c7d8e9fa0b1c2d3e4f",
    ] {
        let request = NativeWorldRequest::Capture {
            execution: execution.into(),
            isa: InstalledGem5Isa::X86_64,
            point: NativeCapturePoint::Pending,
        };
        assert!(matches!(
            service.submit(request.clone()).unwrap().state,
            NativeWorldOutcome::Reserved {}
        ));
        requests.push(request);
    }
    let retention = service.retention_owner();
    wait_retired(&retention);
    assert!(refs.panicked(), "failure must follow actual native capture");

    // The original published activation is independently read from its durable
    // root. This data-only record queries the queue's real kernel proof; it does
    // not construct any live execution or preparation authority.
    let identity = refs
        .read_ref(&activation_ref(requests[0].execution()).unwrap())
        .unwrap()
        .unwrap();
    let bytes = blobs
        .read(identity, None)
        .unwrap()
        .read_all(1024 * 1024)
        .unwrap();
    let record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let activation: SavedRuntimeActivation =
        serde_json::from_value(record["activation"].clone()).unwrap();
    let original = ActivationRecord {
        generation: activation.generation,
        activation_id: activation.activation_id,
        world_binding_hash: activation.world_binding_hash,
        owners: activation.owners,
        boundary: activation.boundary,
    };
    assert!(native.original_group_reclaimed(&original).unwrap());
    assert_eq!(native.reserved_owners(), before + 1);
    for request in &requests {
        assert!(matches!(
            service
                .submit(NativeWorldRequest::Status {
                    execution: request.execution().into(),
                })
                .unwrap()
                .state,
            NativeWorldOutcome::Reserved {}
        ));
    }
    assert!(retention.retention_roots().unwrap().len() >= 6);
    assert_eq!(
        std::fs::read_dir(&realm)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().len() == 32)
            .count(),
        0,
    );
    drop(service);

    // Reopening cannot turn either the original effecting request or its queued
    // neighbor into a new BEGIN. The complete original capsule remains retained.
    let service = NativeWorldService::start(realm, 4, blobs, refs).unwrap();
    for request in requests {
        assert!(matches!(
            service.submit(request).unwrap().state,
            NativeWorldOutcome::Reserved {}
        ));
    }
    assert_eq!(native.reserved_owners(), before + 1);
    let retention = service.retention_owner();
    drop(service);
    wait_retired(&retention);
    std::fs::remove_dir_all(directory).unwrap();
}

fn completed(service: &NativeWorldService, execution: &str) -> super::control::NativeWorldRecord {
    let deadline = ProcessDeadline::after(Duration::from_secs(240)).unwrap();
    loop {
        let record = service
            .submit(NativeWorldRequest::Status {
                execution: execution.into(),
            })
            .unwrap();
        if !matches!(record.state, NativeWorldOutcome::Reserved { .. }) {
            assert!(
                matches!(record.state, NativeWorldOutcome::Completed { .. }),
                "{record:?}"
            );
            return record;
        }
        assert!(
            !deadline.expired(),
            "original native actor exceeded operational wait"
        );
        deadline.pause(Duration::from_millis(10));
    }
}

fn wait_retired(retention: &super::service::NativeWorldRetention) {
    let deadline = ProcessDeadline::after(Duration::from_secs(60)).unwrap();
    while !retention.is_retired() {
        assert!(
            !deadline.expired(),
            "original native actor did not prove authentic group retirement"
        );
        deadline.pause(Duration::from_millis(10));
    }
}

// Computes the measured freestanding guest's integer/memory checksum without
// reading its native event journal or either reconstructed child's output.
fn known_guest_checksum() -> [u8; 8] {
    let mut arena = vec![0_u64; 262_144 / 8];
    let mut state = 3_u32;
    let mut answer = 0_u64;
    for _ in 0..20_000 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let index = (state & 262_136) as usize / 8;
        arena[index] ^= u64::from(state);
        answer = answer.wrapping_add(arena[index]);
        if state & 1 != 0 {
            answer = answer.wrapping_add(19);
        }
    }
    answer.to_le_bytes()
}
