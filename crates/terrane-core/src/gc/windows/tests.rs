//! Checks pure window arithmetic and legacy tombstone byte compatibility.

use super::*;

#[test]
fn gc_windows_compare_strict_grace_and_inclusive_deletion_without_overflow() -> Result<(), GcError>
{
    let windows = Windows::new(6, 24, 24, 30)?;

    assert_eq!(
        (
            windows.commit(),
            windows.grace(),
            windows.deletion(),
            windows.retention()
        ),
        (6, 24, 24, 30)
    );
    assert!(!windows.sweep_age(100, 76));
    assert!(windows.sweep_age(100, 75));
    assert!(!windows.sweep_age(100, 101));
    assert!(windows.deletion_age(100, 76));
    assert!(!windows.deletion_age(100, 77));
    assert!(!windows.deletion_age(100, 101));
    assert!(windows.commit_allowed(100, 94));
    assert!(!windows.commit_allowed(100, 93));
    assert!(!windows.commit_allowed(100, 101));

    assert_eq!(Windows::new(24, 24, 24, 48), Err(GcError::Window));
    assert_eq!(Windows::new(6, 24, 23, 30), Err(GcError::Window));
    assert_eq!(Windows::new(6, 24, 24, 29), Err(GcError::Window));
    assert_eq!(
        Windows::new(1, u64::MAX, u64::MAX, u64::MAX),
        Err(GcError::Exhausted)
    );
    Ok(())
}

#[test]
fn gc_retains_uses_log_commit_and_lease_times_for_their_registered_modes() -> Result<(), GcError> {
    let windows = Windows::new(6, 24, 24, 30)?;
    let times = RetentionTimes {
        now: 100,
        commit: 50,
        reflog: 90,
        lease_expiry: Some(101),
    };

    assert!(retains(Retention::Gc, times, windows));
    assert!(!retains(Retention::Ttl(30), times, windows));
    assert!(retains(Retention::Forever, times, windows));
    assert!(retains(Retention::Lease, times, windows));
    assert!(!retains(
        Retention::Lease,
        RetentionTimes {
            lease_expiry: Some(100),
            ..times
        },
        windows
    ));
    assert!(!retains(
        Retention::Lease,
        RetentionTimes {
            lease_expiry: None,
            ..times
        },
        windows
    ));
    Ok(())
}

#[test]
fn gc_tombstone_matches_bucket_codec_and_independent_registered_map() -> Result<(), GcError> {
    let record = Tombstone {
        pack: [0; 16],
        cycle: 1,
        timestamp: 2,
        removed: 3,
        epoch: 4,
    };
    let mut expected = alloc::vec![0xa5, 1, 0x50];
    expected.extend([0; 16]);
    expected.extend([2, 1, 3, 2, 4, 3, 5, 4]);

    assert_eq!(record.encode(), expected);
    assert_eq!(Tombstone::decode(&expected)?, record);
    let bucket_record = crate::bucket::Tombstone::decode(&expected).map_err(|_| GcError::Schema)?;
    assert_eq!(bucket_record.pack_id, record.pack);
    assert_eq!(bucket_record.cycle, record.cycle);
    assert_eq!(bucket_record.epoch, record.epoch);
    assert_eq!(bucket_record.tombstoned_at, record.timestamp);
    assert_eq!(bucket_record.removed_entries, record.removed);
    assert_eq!(bucket_record.encode(), expected);

    for length in 0..expected.len() {
        assert!(Tombstone::decode(&expected[..length]).is_err());
    }
    expected.push(0);
    assert!(Tombstone::decode(&expected).is_err());
    Ok(())
}

#[test]
fn gc_checkpoint_integrity_digest_uses_raw_blake3_without_content_domain() {
    assert_eq!(
        checkpoint_digest(b""),
        [
            0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc,
            0xc9, 0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca,
            0xe4, 0x1f, 0x32, 0x62
        ]
    );
}
