//! Actual mapped transport custody tests with model-only initialization evidence.

// crucible-lint: allow panic-shortcut -- Test-only mapped-custody assertions panic on an unmet original-owner invariant.
#![allow(clippy::unwrap_used)]

use std::io::Write;
use std::os::fd::AsFd;
use std::sync::atomic::{AtomicU64, Ordering};

use crucible_protocol::node_control::NativeInitializationAcknowledgement;
use crucible_shmem::{FrameEntry, RegionAllocation, RegionConfig, SLOT_NET_ROUTER};

use super::*;
use crate::runtime::worker_quiescence::{WORKER_REQUIRED, WORKER_RUN_CONTROL, WORKER_TEARDOWN};

static NEXT_MAPPING: AtomicU64 = AtomicU64::new(0);

pub(crate) fn mapped(vm_count: u32) -> MappedSetupRegion {
    let allocation = RegionAllocation::new_model(RegionConfig::new(vm_count, 4)).unwrap();
    let suffix = NEXT_MAPPING.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "crucible-preparation-fifo-{}-{suffix}",
        std::process::id()
    ));
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    std::fs::remove_file(path).unwrap();
    file.set_len(allocation.layout().region_size).unwrap();
    file.write_all(&allocation.setup_region_bytes().unwrap())
        .unwrap();
    crucible_shmem::mmap_setup_region(file.as_fd(), allocation.layout().region_size).unwrap()
}

pub(crate) fn initializer(acknowledge: bool) -> Arc<InitializationCustody> {
    let (custody, command, receipt) = super::super::initialization_custody::tests::fixture();
    custody.retain(command.clone()).unwrap();
    custody.record_receipt(receipt).unwrap();
    if acknowledge {
        custody
            .acknowledge(&NativeInitializationAcknowledgement {
                prepared_scope_hash: custody.scope,
                initialization_commitment: custody.commitment,
                sequence: command.sequence,
                command_digest: command.identity_digest().unwrap(),
            })
            .unwrap();
    }
    Arc::new(custody)
}

#[test]
fn applied_without_actual_ack_cannot_hold_or_capture_preparation_transport() {
    let region = mapped(1);
    let callbacks = Arc::new(LiveCallbackQuiescence::new());
    let workers = LiveWorkerQuiescence::new(WORKER_REQUIRED);
    let mut custody = NativePreparationFifoCustody::new(
        initializer(false),
        Arc::clone(&callbacks),
        Arc::clone(&workers),
        &region,
        MAXIMUM_IMAGE_BYTES,
    )
    .unwrap();

    assert!(custody.try_retain().unwrap().is_none());
    assert!(custody.original.is_none());
    assert!(custody.image.is_none());
    assert!(!callbacks.snapshot().hot_fork_held);
    assert!(!workers.snapshot().held);
    assert_eq!(region.hot_fork_ring_io_snapshot().unwrap().held_rings(), 0);
}

#[test]
fn admitted_callback_returns_into_same_ack_owned_partial_hold_before_image() {
    let region = mapped(1);
    let callbacks = Arc::new(LiveCallbackQuiescence::new());
    let workers = LiveWorkerQuiescence::new(WORKER_REQUIRED);
    let _run = workers.idle(WORKER_RUN_CONTROL);
    let _teardown = workers.idle(WORKER_TEARDOWN);
    let callback = callbacks.enter().unwrap();
    let mut custody = NativePreparationFifoCustody::new(
        initializer(true),
        Arc::clone(&callbacks),
        Arc::clone(&workers),
        &region,
        MAXIMUM_IMAGE_BYTES,
    )
    .unwrap();

    assert!(custody.try_retain().unwrap().is_none());
    let original_owner = std::ptr::from_ref(custody.original.as_ref().unwrap());
    assert!(callbacks.enter().is_none());
    assert!(workers.snapshot().held);
    assert!(region.hot_fork_ring_io_snapshot().unwrap().quiescent());
    drop(callback);

    let original_image = custody
        .try_retain()
        .unwrap()
        .unwrap()
        .canonical_bytes()
        .unwrap();
    assert_eq!(
        std::ptr::from_ref(custody.original.as_ref().unwrap()),
        original_owner
    );
    assert_eq!(
        custody
            .try_retain()
            .unwrap()
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        original_image
    );
    drop(custody);
    assert!(callbacks.enter().is_none());
    assert!(workers.snapshot().held);
    assert!(region.hot_fork_ring_io_snapshot().unwrap().quiescent());
}

#[test]
fn full_queue_bytes_remain_historical_and_original_fault_never_reopens_holds() {
    let mut region = mapped(1);
    let input = FrameEntry::new(23, 0, 7, b"original staged bytes").unwrap();
    let output = FrameEntry::new(29, 0, 8, b"original retained output").unwrap();
    let pair = region
        .node_directed_ring_pair_mut(0, SLOT_NET_ROUTER as u32, 0, 0, SLOT_NET_ROUTER as u32)
        .unwrap();
    pair.first
        .header
        .enqueue(pair.first.entries, &input)
        .unwrap();
    pair.second
        .header
        .enqueue(pair.second.entries, &output)
        .unwrap();
    let initialization = initializer(true);
    let callbacks = Arc::new(LiveCallbackQuiescence::new());
    let workers = LiveWorkerQuiescence::new(WORKER_REQUIRED);
    let _run = workers.idle(WORKER_RUN_CONTROL);
    let _teardown = workers.idle(WORKER_TEARDOWN);
    let mut custody = NativePreparationFifoCustody::new(
        Arc::clone(&initialization),
        Arc::clone(&callbacks),
        Arc::clone(&workers),
        &region,
        MAXIMUM_IMAGE_BYTES,
    )
    .unwrap();

    let image = custody
        .try_retain()
        .unwrap()
        .unwrap()
        .canonical_bytes()
        .unwrap();
    let same_image = custody.image.as_ref().map(std::ptr::from_ref).unwrap();
    assert_eq!(
        region
            .capture_hot_fork_ring_image(image.len())
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        image
    );
    assert_eq!(
        custody.try_retain().unwrap().map(std::ptr::from_ref),
        Some(same_image)
    );
    initialization.fail();

    assert!(custody.try_retain().is_err());
    assert!(custody.failed);
    assert_eq!(
        custody.image.as_ref().unwrap().canonical_bytes().unwrap(),
        image
    );
    assert!(custody.try_retain().is_err());
    assert!(callbacks.enter().is_none());
    assert!(workers.snapshot().held);
}

#[test]
fn failed_copy_keeps_original_ack_and_all_holds_without_claiming_an_image() {
    let region = mapped(1);
    let callbacks = Arc::new(LiveCallbackQuiescence::new());
    let workers = LiveWorkerQuiescence::new(WORKER_REQUIRED);
    let _run = workers.idle(WORKER_RUN_CONTROL);
    let _teardown = workers.idle(WORKER_TEARDOWN);
    let mut custody = NativePreparationFifoCustody::new(
        initializer(true),
        Arc::clone(&callbacks),
        Arc::clone(&workers),
        &region,
        1,
    )
    .unwrap();

    assert!(custody.try_retain().is_err());
    assert!(custody.original.is_some());
    assert!(custody.image.is_none());
    assert!(custody.failed);
    drop(custody);
    assert!(callbacks.enter().is_none());
    assert!(workers.snapshot().held);
    assert!(region.hot_fork_ring_io_snapshot().unwrap().quiescent());
}

#[test]
fn invalid_credit_and_shared_mapping_refuse_before_holding_actual_owners() {
    let region = mapped(2);
    let callbacks = Arc::new(LiveCallbackQuiescence::new());
    let workers = LiveWorkerQuiescence::new(WORKER_REQUIRED);
    for maximum in [0, MAXIMUM_IMAGE_BYTES, MAXIMUM_IMAGE_BYTES + 1] {
        assert!(
            NativePreparationFifoCustody::new(
                initializer(true),
                Arc::clone(&callbacks),
                Arc::clone(&workers),
                &region,
                maximum,
            )
            .is_err()
        );
    }

    assert!(!callbacks.snapshot().hot_fork_held);
    assert!(!workers.snapshot().held);
    assert_eq!(region.hot_fork_ring_io_snapshot().unwrap().held_rings(), 0);
}

#[test]
fn runtime_owned_mapping_moves_without_self_reference_and_foreign_retry_stays_tainted() {
    struct RuntimeMappingOwner {
        state: NativePreparationFifoState,
        region: MappedSetupRegion,
    }

    let region = mapped(1);
    let foreign_region = mapped(1);
    let initialization = initializer(true);
    let callbacks = Arc::new(LiveCallbackQuiescence::new());
    let workers = LiveWorkerQuiescence::new(WORKER_REQUIRED);
    let _run = workers.idle(WORKER_RUN_CONTROL);
    let _teardown = workers.idle(WORKER_TEARDOWN);
    let state = NativePreparationFifoState::new(
        initialization,
        Arc::clone(&callbacks),
        Arc::clone(&workers),
        &region,
        64 * 1024 * 1024,
    )
    .unwrap();
    let mut runtime = Box::new(RuntimeMappingOwner { state, region });

    let original = runtime
        .state
        .try_retain(&runtime.region)
        .unwrap()
        .unwrap()
        .canonical_bytes()
        .unwrap();
    let original_address = runtime
        .state
        .image
        .as_ref()
        .map(std::ptr::from_ref)
        .unwrap();
    assert_eq!(
        runtime
            .state
            .try_retain(&runtime.region)
            .unwrap()
            .map(std::ptr::from_ref),
        Some(original_address)
    );

    assert!(runtime.state.try_retain(&foreign_region).is_err());
    assert!(runtime.state.failed);
    assert_eq!(
        runtime
            .state
            .image
            .as_ref()
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        original
    );
    assert!(runtime.state.try_retain(&runtime.region).is_err());
    assert_eq!(
        foreign_region
            .hot_fork_ring_io_snapshot()
            .unwrap()
            .held_rings(),
        0
    );
    assert!(callbacks.enter().is_none());
    assert!(workers.snapshot().held);
}

#[test]
fn pending_original_ack_recovers_into_same_runtime_custody_without_early_holds() {
    let region = mapped(1);
    let (initialization, command, receipt) = super::super::initialization_custody::tests::fixture();
    initialization.retain(command.clone()).unwrap();
    initialization.record_receipt(receipt).unwrap();
    let initialization = Arc::new(initialization);
    let callbacks = Arc::new(LiveCallbackQuiescence::new());
    let workers = LiveWorkerQuiescence::new(WORKER_REQUIRED);
    let _run = workers.idle(WORKER_RUN_CONTROL);
    let _teardown = workers.idle(WORKER_TEARDOWN);
    let mut state = NativePreparationFifoState::new(
        Arc::clone(&initialization),
        Arc::clone(&callbacks),
        Arc::clone(&workers),
        &region,
        MAXIMUM_IMAGE_BYTES,
    )
    .unwrap();

    assert!(state.try_retain(&region).unwrap().is_none());
    assert!(state.original.is_none());
    assert!(!callbacks.snapshot().hot_fork_held);
    assert!(!workers.snapshot().held);
    initialization
        .acknowledge(&NativeInitializationAcknowledgement {
            prepared_scope_hash: initialization.scope,
            initialization_commitment: initialization.commitment,
            sequence: command.sequence,
            command_digest: command.identity_digest().unwrap(),
        })
        .unwrap();

    let original = state
        .try_retain(&region)
        .unwrap()
        .unwrap()
        .canonical_bytes()
        .unwrap();
    assert!(state.original.is_some());
    assert!(callbacks.enter().is_none());
    assert!(workers.snapshot().held);
    assert_eq!(
        state
            .try_retain(&region)
            .unwrap()
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        original
    );
}
