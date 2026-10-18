//! Canonical I/O-core snapshot codec regressions.

use super::*;

#[test]
fn io_core_snapshot_rejects_unsupported_version() {
    let core =
        IoCore::new(1, 2, 2).unwrap_or_else(|error| panic!("build I/O-core fixture: {error}"));
    let mut bytes = core
        .snapshot()
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("encode I/O-core fixture: {error}"));
    let version_index = b"crucible.io-core-snapshot.v".len();
    assert_eq!(bytes[version_index], b'5');
    bytes[version_index] = b'4';
    assert_eq!(
        IoCoreSnapshot::from_canonical_bytes(&bytes),
        Err(IoCoreSnapshotCodecError::Version)
    );
}

#[test]
fn io_core_snapshot_rejects_wrong_clock_scale() {
    let core = IoCore::new(1, 2, 2).unwrap_or_else(|error| panic!("build I/O core: {error}"));
    let mut snapshot = core.snapshot();
    snapshot.ticks_per_ns = 1;

    assert_eq!(
        snapshot.canonical_bytes(),
        Err(IoCoreSnapshotCodecError::Invalid("ticks per nanosecond"))
    );
    assert!(matches!(
        IoCore::restore(&snapshot),
        Err(DeviceError::ClockScaleMismatch { .. })
    ));
}

#[test]
fn io_core_snapshot_reports_offending_capacity() {
    let core =
        IoCore::new(1, 2, 2).unwrap_or_else(|error| panic!("build I/O-core fixture: {error}"));
    let mut snapshot = core.snapshot();
    snapshot.inbox_capacity = HARD_IO_CORE_CHECKPOINT_ENTRIES as u64 + 1;
    assert_eq!(
        snapshot.canonical_bytes(),
        Err(IoCoreSnapshotCodecError::ResourceLimit {
            field: "inbox",
            current: 0,
            requested: HARD_IO_CORE_CHECKPOINT_ENTRIES as u64 + 1,
            configured: HARD_IO_CORE_CHECKPOINT_ENTRIES as u64,
            hard: HARD_IO_CORE_CHECKPOINT_ENTRIES as u64,
        })
    );
}

#[test]
fn io_core_snapshot_enforces_authored_aggregate_limit() {
    let core =
        IoCore::new(1, 2, 2).unwrap_or_else(|error| panic!("build I/O-core fixture: {error}"));
    let snapshot = core.snapshot();
    let bytes = snapshot
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("encode I/O-core fixture: {error}"));
    let maximum = u64::try_from(bytes.len() - 1)
        .unwrap_or_else(|_| panic!("I/O-core fixture length should fit u64"));

    assert!(matches!(
        snapshot.canonical_bytes_with_limit(maximum),
        Err(IoCoreSnapshotCodecError::ResourceLimit {
            field: "I/O-core snapshot bytes",
            current,
            requested,
            configured,
            hard: HARD_IO_CORE_CHECKPOINT_BYTES,
        }) if current.saturating_add(requested) > maximum && configured == maximum
    ));
    assert_eq!(
        IoCoreSnapshot::from_canonical_bytes_with_limit(&bytes, maximum),
        Err(IoCoreSnapshotCodecError::ResourceLimit {
            field: "I/O-core snapshot bytes",
            current: 0,
            requested: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            configured: maximum,
            hard: HARD_IO_CORE_CHECKPOINT_BYTES,
        })
    );
}

fn admission_fixture() -> IoCoreSnapshot {
    let mut core = IoCore::new(1, 2, 2).expect("build I/O-core admission fixture");
    core.enqueue_request(Request::new(10, 3, b"pending".to_vec()))
        .expect("enqueue I/O-core admission fixture");
    core.snapshot()
}

#[test]
fn io_core_borrowed_admission_covers_table_payload_and_validation_output() {
    let snapshot = admission_fixture();
    let bytes = snapshot
        .canonical_bytes()
        .expect("encode admission fixture");
    let mut allocations = Vec::new();
    let restored = IoCoreSnapshot::from_canonical_bytes_with_admission(
        &bytes,
        HARD_IO_CORE_CHECKPOINT_BYTES,
        &mut |requested| {
            allocations.push(requested);
            Ok(())
        },
    )
    .expect("decode admitted I/O-core fixture");

    assert_eq!(restored, snapshot);
    assert_eq!(
        allocations,
        [
            std::mem::size_of::<Request>() as u64,
            7,
            0,
            0,
            bytes.len() as u64,
        ]
    );
}

#[test]
fn io_core_table_refusal_precedes_malformed_member() {
    let bytes = admission_fixture()
        .canonical_bytes()
        .expect("encode table refusal fixture");
    let table_end = IO_CORE_SNAPSHOT_MAGIC.len() + 44 + 4;
    let refusal = IoCoreSnapshotCodecError::Invalid("authored admission refusal");
    let mut requests = Vec::new();
    let error = IoCoreSnapshot::from_canonical_bytes_with_admission(
        &bytes[..table_end],
        HARD_IO_CORE_CHECKPOINT_BYTES,
        &mut |requested| {
            requests.push(requested);
            Err(refusal.clone())
        },
    )
    .expect_err("refuse table before reading its malformed first member");

    assert_eq!(error, refusal);
    assert_eq!(requests, [std::mem::size_of::<Request>() as u64]);
}

#[test]
fn io_core_truncated_payload_is_rejected_before_owning_admission() {
    let bytes = admission_fixture()
        .canonical_bytes()
        .expect("encode payload refusal fixture");
    let payload_start = IO_CORE_SNAPSHOT_MAGIC.len() + 44 + 4 + 16;
    let mut requests = Vec::new();
    let error = IoCoreSnapshot::from_canonical_bytes_with_admission(
        &bytes[..payload_start + 1],
        HARD_IO_CORE_CHECKPOINT_BYTES,
        &mut |requested| {
            requests.push(requested);
            Ok(())
        },
    )
    .expect_err("reject truncated payload before copying it");

    assert_eq!(
        error,
        IoCoreSnapshotCodecError::Malformed("request payload")
    );
    assert_eq!(requests, [std::mem::size_of::<Request>() as u64]);
}

#[test]
fn io_core_validation_output_refusal_prevents_snapshot_acceptance() {
    let bytes = admission_fixture()
        .canonical_bytes()
        .expect("encode validation output refusal fixture");
    let refusal = IoCoreSnapshotCodecError::Invalid("authored output refusal");
    let mut requests = Vec::new();
    let error = IoCoreSnapshot::from_canonical_bytes_with_admission(
        &bytes,
        HARD_IO_CORE_CHECKPOINT_BYTES,
        &mut |requested| {
            requests.push(requested);
            if requests.len() == 5 {
                Err(refusal.clone())
            } else {
                Ok(())
            }
        },
    )
    .expect_err("refuse canonical validation output before accepting the snapshot");

    assert_eq!(error, refusal);
    assert_eq!(requests.last(), Some(&(bytes.len() as u64)));
}
