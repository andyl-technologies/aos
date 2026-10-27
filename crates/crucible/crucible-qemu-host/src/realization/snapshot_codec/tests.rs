//! VM snapshot codec tests.

use std::collections::BTreeMap;

use crucible_engine::CheckpointKind;

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
fn production_envelope_rejects_an_unsupported_version() {
    let snapshot = snapshot_fixture("unsupported-version");
    let mut bytes = snapshot
        .to_canonical_bytes()
        .unwrap_or_else(|error| panic!("encode current snapshot: {error}"));
    bytes[..MAGIC.len()].copy_from_slice(b"crucible.qemu-vm-snapshot.v?\0");

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
            crucible_qemu_shmem::SLOT_NET_ROUTER as u32,
        ),
        outbound: crucible_qemu_shmem::SpscRingSnapshot { frames: Vec::new() },
        queue_capacity: MAX_QUEUE_FRAMES as u32,
        router_slot: crucible_qemu_shmem::SLOT_NET_ROUTER as u32,
        next_router_inbound_sequence: MAX_QUEUE_FRAMES as u64,
        next_host_outbound_sequence: 0,
        next_plugin_outbound_sequence: 0,
    };
    snapshot.identity = canonical_snapshot_identity(
        &snapshot.checkpoint,
        &snapshot.host_io,
        &snapshot.node,
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
    let definition = crucible_engine::ScenarioDef::from_canonical_material(
        "crucible.test.qemu.snapshot-codec",
        label,
    );
    let configuration = crucible_engine::Configuration::genesis(definition);
    let checkpoint = Checkpoint::from_recorded_configuration(
        &configuration,
        None,
        crucible_engine::VirtualTime::default(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .unwrap_or_else(|error| panic!("build canonical checkpoint: {error}"));
    QemuVmSnapshot::diskless(checkpoint)
        .unwrap_or_else(|error| panic!("build diskless snapshot: {error}"))
}

#[test]
fn streamed_envelope_matches_the_buffered_encoding() {
    let snapshot = snapshot_fixture("streamed-envelope");
    let buffered = snapshot
        .to_canonical_bytes()
        .unwrap_or_else(|error| panic!("encode buffered snapshot: {error}"));

    let mut streamed = Vec::new();
    let length = snapshot
        .write_canonical_with_limit(MAX_BYTES, &mut streamed)
        .unwrap_or_else(|error| panic!("stream snapshot: {error}"));

    assert_eq!(streamed, buffered);
    assert_eq!(length, buffered.len() as u64);
}

#[test]
fn streamed_envelope_reports_the_buffered_errors() {
    let snapshot = snapshot_fixture("streamed-limit");
    let exact = snapshot
        .to_canonical_bytes()
        .unwrap_or_else(|error| panic!("encode snapshot: {error}"))
        .len() as u64;

    // A nested-bound failure, the fixed-envelope failure one byte short, and
    // success at the exact length agree on both paths.
    for maximum in [64, exact - 1, exact] {
        let buffered = encode_snapshot(&snapshot, maximum).map(|bytes| bytes.len() as u64);
        let streamed = snapshot.write_canonical_with_limit(maximum, &mut std::io::sink());
        assert_eq!(streamed, buffered, "ceiling {maximum}");
    }

    let mut forged = snapshot.clone();
    forged.identity = ContentHash::default();
    assert_eq!(
        forged.write_canonical_with_limit(MAX_BYTES, &mut std::io::sink()),
        Err(QemuVmSnapshotCodecError::Identity)
    );
}

#[test]
fn streamed_envelope_surfaces_writer_failures() {
    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::StorageFull))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let snapshot = snapshot_fixture("streamed-writer-failure");
    assert_eq!(
        snapshot.write_canonical_with_limit(MAX_BYTES, &mut FailingWriter),
        Err(QemuVmSnapshotCodecError::Write {
            kind: std::io::ErrorKind::StorageFull,
        })
    );
}

#[test]
fn decoding_compares_a_streamed_re_encoding_with_the_input() {
    let snapshot = snapshot_fixture("canonical-comparison");
    let bytes = snapshot
        .to_canonical_bytes()
        .unwrap_or_else(|error| panic!("encode snapshot: {error}"));
    assert_eq!(QemuVmSnapshot::from_canonical_bytes(&bytes), Ok(snapshot));

    let mut short = CanonicalComparison::new(&bytes);
    short
        .write_all(&bytes[..bytes.len() - 1])
        .unwrap_or_else(|error| panic!("compare prefix: {error}"));
    assert!(!short.matched(), "a short stream must not match");

    let mut flipped = bytes.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    let mut differing = CanonicalComparison::new(&flipped);
    differing
        .write_all(&bytes)
        .unwrap_or_else(|error| panic!("compare bytes: {error}"));
    assert!(!differing.matched(), "a differing byte must not match");

    let mut long = CanonicalComparison::new(&bytes);
    long.write_all(&bytes)
        .unwrap_or_else(|error| panic!("compare bytes: {error}"));
    long.write_all(b"x")
        .unwrap_or_else(|error| panic!("compare tail: {error}"));
    assert!(!long.matched(), "a long stream must not match");
}
