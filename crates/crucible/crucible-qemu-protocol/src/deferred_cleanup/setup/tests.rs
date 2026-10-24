//! Exercises the exact new frame, incarnation footer and workspace contracts.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use crate::DeviceDigestWorkspaceBinding;

fn setup() -> DeferredCleanupSetup {
    DeferredCleanupSetup {
        publisher: PublisherSetup {
            region_len: 4096,
            process_generation: 3,
            device_digest_workspace: None,
            lender_generation: 4,
            device: 0,
            inode: 0,
            producer_event: 5,
            receiver_event: 6,
        },
        delegation_incarnation: 7,
    }
}

#[test]
fn setup_nine_keeps_exact_physical_body_and_incarnation_footer() {
    let value = setup();
    let bytes = value.encode().unwrap();
    let ordinary = value.publisher.encode().unwrap();

    assert_eq!(&bytes[..5], &[0, 0, 0, 121, 0x19]);
    assert_eq!(&bytes[5..109], &ordinary[5..109]);
    assert_eq!(&bytes[109..117], &[0, 0, 0, 3, 0, 0, 0, 2]);
    assert_eq!(&bytes[117..], &7_u64.to_be_bytes());
    assert_eq!(DeferredCleanupSetup::decode(&bytes), Ok(value));
    assert!(PublisherSetup::decode(&bytes).is_err());
    assert!(DeferredCleanupSetup::decode(&ordinary).is_err());
    for tag in [0x16, 0x17, 0x18, 0x1a] {
        let mut changed = bytes;
        changed[4] = tag;
        assert!(DeferredCleanupSetup::decode(&changed).is_err());
    }
}

#[test]
fn setup_nine_refuses_all_truncations_trailing_data_and_changed_selectors() {
    let bytes = setup().encode().unwrap();
    for length in 0..bytes.len() {
        assert!(DeferredCleanupSetup::decode(&bytes[..length]).is_err());
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(DeferredCleanupSetup::decode(&trailing).is_err());
    for offset in (0..5).chain(13..21).chain(69..77).chain(109..117) {
        let mut changed = bytes;
        changed[offset] ^= 1;
        assert!(
            DeferredCleanupSetup::decode(&changed).is_err(),
            "offset {offset}"
        );
    }
}

#[test]
fn setup_nine_refuses_absent_or_exhausted_incarnations_and_equal_events() {
    let bytes = setup().encode().unwrap();
    for offset in [21, 61, 93, 101, 117] {
        for invalid in [0, u64::MAX] {
            let mut changed = bytes;
            changed[offset..offset + 8].copy_from_slice(&invalid.to_be_bytes());
            assert!(
                DeferredCleanupSetup::decode(&changed).is_err(),
                "offset {offset}"
            );
        }
    }
    let mut changed = setup();
    changed.publisher.receiver_event = changed.publisher.producer_event;
    assert!(changed.encode().is_err());
    changed = setup();
    changed.delegation_incarnation = u64::MAX;
    assert!(changed.encode().is_err());
}

#[test]
fn setup_nine_binds_optional_workspace_and_rejects_absent_workspace_payload() {
    let mut value = setup();
    value.publisher.device_digest_workspace = Some(DeviceDigestWorkspaceBinding {
        account_generation: 8,
        workspace_generation: 9,
        device: 0,
        inode: 0,
    });
    let bytes = value.encode().unwrap();
    assert_eq!(DeferredCleanupSetup::decode(&bytes), Ok(value));
    for offset in [29, 37] {
        for invalid in [0, u64::MAX] {
            let mut changed = bytes;
            changed[offset..offset + 8].copy_from_slice(&invalid.to_be_bytes());
            assert!(DeferredCleanupSetup::decode(&changed).is_err());
        }
    }
    let absent = setup().encode().unwrap();
    for offset in 29..61 {
        let mut changed = absent;
        changed[offset] = 1;
        assert!(
            DeferredCleanupSetup::decode(&changed).is_err(),
            "offset {offset}"
        );
    }
}
