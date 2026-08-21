//! VM snapshot codec tests.

use std::collections::BTreeMap;

use crucible::CheckpointKind;

use super::*;

#[test]
fn production_envelope_reports_typed_aggregate_limit() {
    let snapshot = snapshot_fixture("typed-limit");
    assert!(matches!(
        encode_snapshot(&snapshot, 64),
        Err(QemuVmSnapshotCodecError::ResourceLimit {
            field: "QEMU VM snapshot nested bytes",
            configured: 64,
            hard: 68_719_476_736,
            ..
        })
    ));
}

#[test]
fn production_envelope_rejects_pre_policy_version() {
    let snapshot = snapshot_fixture("old-policy-version");
    let mut bytes = snapshot
        .to_canonical_bytes()
        .unwrap_or_else(|error| panic!("encode current snapshot: {error}"));
    bytes[..MAGIC.len()].copy_from_slice(b"crucible.qemu-vm-snapshot.v1\0");

    assert_eq!(
        QemuVmSnapshot::from_canonical_bytes(&bytes),
        Err(QemuVmSnapshotCodecError::Version)
    );
}

#[test]
fn production_envelope_round_trips_full_network_frame_capacity() {
    const MAX_QUEUE_FRAMES: usize = 1_048_576;

    let mut snapshot = snapshot_fixture("full-network-capacity");
    snapshot.node.network_transport = crate::QemuNetworkTransportCheckpoint {
        inbound: crate::checkpoint::tests::synthetic_compact_ring(
            MAX_QUEUE_FRAMES,
            0,
            crucible_shmem::SLOT_NET_ROUTER as u32,
        ),
        outbound: crucible_shmem::SpscRingSnapshot { frames: Vec::new() },
        queue_capacity: MAX_QUEUE_FRAMES as u32,
        router_slot: crucible_shmem::SLOT_NET_ROUTER as u32,
        next_router_inbound_sequence: MAX_QUEUE_FRAMES as u64,
        next_host_outbound_sequence: 0,
        next_plugin_outbound_sequence: 0,
    };
    snapshot.identity = canonical_snapshot_identity(
        &snapshot.checkpoint,
        &snapshot.host_io,
        &snapshot.node,
        snapshot.replay_oracle_validation,
        snapshot.live_capture,
    )
    .unwrap_or_else(|error| panic!("authenticate full-capacity snapshot: {error}"));

    let bytes = snapshot
        .to_canonical_bytes()
        .unwrap_or_else(|error| panic!("encode full-capacity VM snapshot: {error}"));
    let restored = QemuVmSnapshot::from_canonical_bytes(&bytes)
        .unwrap_or_else(|error| panic!("decode full-capacity VM snapshot: {error}"));
    assert_eq!(
        restored.node.network_transport.inbound.frames.len(),
        MAX_QUEUE_FRAMES
    );
    assert_eq!(restored, snapshot);
}

fn snapshot_fixture(label: &str) -> QemuVmSnapshot {
    let definition =
        crucible::ScenarioDef::from_canonical_material("crucible.test.qemu.snapshot-codec", label);
    let configuration = crucible::Configuration::genesis(definition);
    let checkpoint = Checkpoint::from_recorded_configuration(
        &configuration,
        None,
        crucible::VirtualTime::default(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .unwrap_or_else(|error| panic!("build canonical checkpoint: {error}"));
    QemuVmSnapshot::diskless(checkpoint, QemuReplayOracleValidation::NotRun)
        .unwrap_or_else(|error| panic!("build diskless snapshot: {error}"))
}
