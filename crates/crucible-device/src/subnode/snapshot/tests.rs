//! Canonical I/O-core snapshot codec regressions.

use super::*;

#[test]
fn io_core_snapshot_rejects_prior_version() {
    let core =
        IoCore::new(8, 1, 2, 2).unwrap_or_else(|error| panic!("build I/O-core fixture: {error}"));
    let mut bytes = core
        .snapshot()
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("encode I/O-core fixture: {error}"));
    let version_index = b"crucible.io-core-snapshot.v".len();
    assert_eq!(bytes[version_index], b'2');
    bytes[version_index] = b'1';
    assert_eq!(
        IoCoreSnapshot::from_canonical_bytes(&bytes),
        Err(IoCoreSnapshotCodecError::Version)
    );
}

#[test]
fn io_core_snapshot_reports_offending_capacity() {
    let core =
        IoCore::new(8, 1, 2, 2).unwrap_or_else(|error| panic!("build I/O-core fixture: {error}"));
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
        IoCore::new(8, 1, 2, 2).unwrap_or_else(|error| panic!("build I/O-core fixture: {error}"));
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
