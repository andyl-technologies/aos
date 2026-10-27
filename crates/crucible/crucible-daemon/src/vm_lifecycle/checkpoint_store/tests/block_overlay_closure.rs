//! Verifies that block overlay chunks travel through the closure by reference.

use super::*;
use crucible_device::{
    BaseImage, BlockDevice, BlockLatency, BlockPageStore, BlockRequest, IoCore, OVERLAY_CHUNK_BYTES,
};

const DEVICE_LENGTH: usize = 2 * OVERLAY_CHUNK_BYTES as usize + 4096;

fn base() -> BaseImage {
    BaseImage::new(
        (0..DEVICE_LENGTH)
            .map(|index| (index % 239) as u8)
            .collect(),
    )
}

fn image(device: &BlockDevice) -> Vec<u8> {
    let mut bytes = Vec::new();
    device
        .materialize_to(&mut bytes)
        .expect("materialize block device");
    bytes
}

/// Builds a file-backed device with writes touching all three chunks.
fn written_device(store_directory: &Path) -> BlockDevice {
    let store = BlockPageStore::from_unnamed_file(
        tempfile::tempfile_in(store_directory).expect("create page store file"),
    )
    .expect("adopt page store");
    let core = IoCore::new(crucible_qemu_shmem::SLOT_BLK_IO as u32, 8, 8).expect("block core");
    let mut device = BlockDevice::new_with_store(core, base(), BlockLatency::default(), store);
    let writes = [
        (0_u64, vec![0x11; 96]),
        (OVERLAY_CHUNK_BYTES - 8, vec![0x22; 16]),
        (2 * OVERLAY_CHUNK_BYTES, vec![0; 64]),
    ];
    let mut tick = 0;
    for (request_id, (offset, data)) in writes.into_iter().enumerate() {
        let request_id = u32::try_from(request_id).expect("small request id");
        device
            .submit(tick, &BlockRequest::write(request_id, offset, data))
            .expect("submit block write");
        tick = device.core().next_exact_local_event().unwrap_or(tick);
        device.advance_to(tick).expect("complete block write");
        while device
            .core_mut()
            .pop_response()
            .expect("pop block response")
            .is_some()
        {}
    }
    device
}

#[test]
fn failed_node_block_overlay_chunks_round_trip_through_the_closure() {
    let root = tempfile::tempdir().expect("create checkpoint store");
    let pages = tempfile::tempdir().expect("create page store directory");
    let disk = crucible_engine::WorldIoNode::block(
        NodeId {
            name: String::from("disk-a"),
        },
        NodeId {
            name: String::from("vm-a"),
        },
        crucible_engine::WorldIoCoreConfig::new(),
        crucible_engine::ContentAddressedBlobRef::from_hash(ContentHash {
            bytes: base().hash(),
        }),
        DEVICE_LENGTH as u64,
        crucible_engine::WorldBlockLatency::new(100, 200, 30, 40, 2),
    );
    let (source, mut checkpoint, node, _) =
        build_one_node_raw_checkpoint_with_io(root.path(), None, vec![disk]);
    checkpoint.targets.remove(&node);
    checkpoint
        .node_service_states
        .insert(node.clone(), ProductionNodeServiceState::PermanentlyFailed);

    let device = written_device(pages.path());
    let snapshot = device.snapshot();
    let expected_image = image(&device);
    let host_io = QemuHostIoCheckpoint::with_block_snapshot_for_test(
        ContentHash::from_bytes(b"failed block host binding"),
        ContentHash::from_bytes(b"failed block storage device"),
        snapshot.clone(),
    )
    .expect("block host continuation");
    let named: Vec<ContentHash> = snapshot
        .overlay_chunk_identities()
        .expect("identify chunks")
        .into_iter()
        .map(|bytes| ContentHash { bytes })
        .collect();
    // Each touched chunk holds a copied-up page, including base bytes, so all
    // three chunks have objects; the straddling write touched chunks 0 and 1.
    assert_eq!(named.len(), 3);
    let failed = ProductionFailedNodeState::new(
        &node,
        host_io,
        FingerprintSample {
            node: node.clone(),
            at: VirtualTime { ticks: 5 },
            fingerprint: ExecutionFingerprint {
                hash: ContentHash::from_bytes(b"failed block fingerprint"),
            },
        },
    )
    .expect("failed-node authority");
    checkpoint.failed_host_io.insert(node.clone(), failed);
    let fault_runtime = ProductionFaultRuntime::new(
        source.plan().fault_signals().clone(),
        None,
        SignalBoundarySnapshot::default(),
        source.scenario_def().id(),
        super::super::super::fault_implementation::test_host_manifests(),
        &QemuNodeSet::new(),
    )
    .expect("fault runtime");
    checkpoint.fault_checkpoint = Some(
        fault_runtime
            .checkpoint(&mut QemuNodeSet::new())
            .expect("fault checkpoint"),
    );

    let prepared = prepare_exact_checkpoint_set(
        root.path(),
        source.scenario_def().id(),
        source.plan().fault_signals().resource_limits(),
        &mut checkpoint,
    )
    .expect("prepare block closure");
    let identity = prepared.identity();
    prepared.publish().expect("publish block closure");

    let scenario = source.scenario_def();
    let objects = object_parent(root.path(), scenario.id());
    let manifest = fs::read(
        closure_parent(root.path(), scenario.id())
            .join(identity.to_hex())
            .join(MANIFEST_FILE),
    )
    .expect("read manifest");
    let manifest = decode::decode_manifest_with_limits(
        &manifest,
        source.plan().fault_signals().resource_limits(),
    )
    .expect("decode manifest");
    assert_eq!(manifest.block_overlay_chunks, named);
    assert!(manifest_object_identities(&manifest).is_superset(&named.iter().copied().collect()));
    for chunk in &named {
        let bytes = fs::read(object_path(&objects, *chunk)).expect("chunk object");
        assert_eq!(ContentHash::from_bytes(&bytes), *chunk);
        assert!(bytes.len() as u64 <= OVERLAY_CHUNK_BYTES);
    }

    // The loaded continuation names the same chunks and restores the exact
    // disk image and checkpoint bytes into a fresh page store.
    let restored = load_exact_checkpoint_set(root.path(), &scenario, &source, identity)
        .expect("load block closure");
    let loaded = restored
        .failed_host_io
        .get(&node)
        .and_then(|failed| failed.host_io.block())
        .expect("loaded block continuation")
        .device_snapshot();
    assert_eq!(loaded, &snapshot);
    let rebuilt = BlockDevice::restore(loaded, base(), &BlockPageStore::memory())
        .expect("restore loaded block snapshot");
    assert_eq!(image(&rebuilt), expected_image);
    assert_eq!(
        rebuilt
            .snapshot()
            .to_canonical_bytes()
            .expect("encode rebuilt"),
        snapshot.to_canonical_bytes().expect("encode original")
    );

    // An altered chunk is admitted by length but refused when restored.
    let victim = object_path(&objects, named[0]);
    let original = fs::read(&victim).expect("read victim chunk");
    let mut altered = original.clone();
    altered[0] ^= 0xff;
    fs::write(&victim, &altered).expect("alter chunk");
    let tampered = load_exact_checkpoint_set(root.path(), &scenario, &source, identity)
        .expect("length-valid chunk still loads");
    let tampered = tampered
        .failed_host_io
        .get(&node)
        .and_then(|failed| failed.host_io.block())
        .expect("tampered block continuation")
        .device_snapshot();
    assert!(BlockDevice::validate_restore(tampered, &base()).is_err());
    assert!(BlockDevice::restore(tampered, base(), &BlockPageStore::memory()).is_err());

    // A missing chunk fails the load itself.
    fs::remove_file(&victim).expect("remove chunk");
    assert!(load_exact_checkpoint_set(root.path(), &scenario, &source, identity).is_err());
}
