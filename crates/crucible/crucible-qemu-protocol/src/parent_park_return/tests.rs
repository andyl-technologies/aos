//! Checks exact public framing without inventing a Source or physical owner.
// SPDX-License-Identifier: MIT OR Apache-2.0

// crucible-lint: allow panic-shortcut -- fixed byte fixtures panic at the mismatched field.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::boundary_action::ActionReturn;

fn returned() -> ParentParkReturn {
    ParentParkReturn {
        binding: ActionBinding {
            cap: [1; 32],
            reservation: [2; 32],
            account_generation: 3,
            process_generation: 4,
            loan_sequence: 6,
            token: 0,
            capture: None,
            park_request: Some(7),
            frontier: 8,
        },
        first: -5,
        post: -110,
        physical_resolution_mask: PARENT_PARK_PHYSICAL_RESOLUTION_ALL,
        publication_count: 4,
        pair_view_return_mask: 15,
        original_statuses: [-125, -62],
        operation_status: -12,
        return_status: -4,
        stopped_generation: 19,
        native_generation: 23,
    }
}

#[test]
fn terminal_bytes_preserve_every_independent_public_field() {
    let record = returned();
    let bytes = record.encode().unwrap();

    assert_eq!(bytes.len(), 184);
    assert_eq!(&bytes[..8], b"CRUCPRR2");
    assert_eq!(&bytes[16..48], &[1; 32]);
    assert_eq!(&bytes[48..80], &[2; 32]);
    for (offset, value) in [
        (8, 2_u32),
        (12, 184),
        (120, (-5_i32) as u32),
        (124, (-110_i32) as u32),
        (128, 2),
        (132, 255),
        (136, 4),
        (140, 15),
        (144, (-125_i32) as u32),
        (148, (-62_i32) as u32),
        (152, (-12_i32) as u32),
        (156, (-4_i32) as u32),
    ] {
        assert_eq!(&bytes[offset..offset + 4], &value.to_be_bytes());
    }
    for (offset, value) in [
        (80, 3_u64),
        (88, 4),
        (96, 7),
        (104, 8),
        (112, 6),
        (160, 19),
        (168, 23),
    ] {
        assert_eq!(&bytes[offset..offset + 8], &value.to_be_bytes());
    }
    assert_eq!(&bytes[176..], &[0; 8]);
    assert_eq!(ParentParkReturn::decode(&bytes).unwrap(), record);
    assert!(ActionReturn::decode(&bytes).is_err());
}

#[test]
fn physical_return_does_not_require_operation_or_original_success() {
    let mut record = returned();
    for count in [0, 2, 3, 4] {
        record.publication_count = count;
        record.pair_view_return_mask = 0;
        record.native_generation = 0;
        assert_eq!(
            ParentParkReturn::decode(&record.encode().unwrap()).unwrap(),
            record
        );
    }
    assert_eq!(record.first, -5);
    assert_eq!(record.post, -110);
    assert_eq!(record.original_statuses, [-125, -62]);
}

#[test]
fn every_request_selector_is_preserved_and_control_selectors_are_refused() {
    let valid = returned();
    let mut invalid = valid;
    invalid.binding.cap = [0; 32];
    assert!(invalid.encode().is_err());
    invalid = valid;
    invalid.binding.reservation = [0; 32];
    assert!(invalid.encode().is_err());
    invalid = valid;
    invalid.binding.account_generation = 0;
    assert!(invalid.encode().is_err());
    invalid = valid;
    invalid.binding.process_generation = 0;
    assert!(invalid.encode().is_err());
    for sequence in [0, 1, u64::MAX] {
        invalid = valid;
        invalid.binding.loan_sequence = sequence;
        assert!(invalid.encode().is_err());
    }
    for correlation in [None, Some(0), Some(u64::MAX)] {
        invalid = valid;
        invalid.binding.park_request = correlation;
        assert!(invalid.encode().is_err());
    }
    invalid = valid;
    invalid.binding.token = 2;
    assert!(invalid.encode().is_err());
    invalid = valid;
    invalid.binding.capture = Some(1);
    assert!(invalid.encode().is_err());
}

#[test]
fn every_missing_native_resource_bit_refuses_terminal_encoding() {
    for bit in 0..8 {
        let mut invalid = returned();
        invalid.physical_resolution_mask &= !(1 << bit);
        assert!(invalid.encode().is_err());
    }
    let mut invalid = returned();
    invalid.physical_resolution_mask |= 1 << 8;
    assert!(invalid.encode().is_err());
}

#[test]
fn statuses_views_and_generations_have_independent_validation() {
    let valid = returned();
    for status_index in 0..6 {
        let mut invalid = valid;
        match status_index {
            0 => invalid.first = 1,
            1 => invalid.post = 1,
            2 => invalid.original_statuses[0] = 1,
            3 => invalid.original_statuses[1] = 1,
            4 => invalid.operation_status = 1,
            5 => invalid.return_status = 1,
            _ => unreachable!(),
        }
        assert!(invalid.encode().is_err());
    }
    for count in [1, 5, u32::MAX] {
        let mut invalid = valid;
        invalid.publication_count = count;
        assert!(invalid.encode().is_err());
    }
    for mask in [1, 3, 7, 16, u32::MAX] {
        let mut invalid = valid;
        invalid.pair_view_return_mask = mask;
        assert!(invalid.encode().is_err());
    }
    let mut invalid = valid;
    invalid.publication_count = 0;
    assert!(invalid.encode().is_err());
    for stopped in [0, u64::MAX] {
        invalid = valid;
        invalid.stopped_generation = stopped;
        assert!(invalid.encode().is_err());
    }
    invalid = valid;
    invalid.native_generation = u64::MAX;
    assert!(invalid.encode().is_err());
}

#[test]
fn obsolete_pending_reserved_and_geometry_bytes_are_refused() {
    let valid = returned().encode().unwrap();
    for length in [0, 8, 128, 183] {
        assert!(ParentParkReturn::decode(&valid[..length]).is_err());
    }
    let mut oversized = valid.to_vec();
    oversized.push(0);
    assert!(ParentParkReturn::decode(&oversized).is_err());
    for (offset, value) in [(8, 1_u32), (12, 192), (128, 0), (128, 1), (128, 3)] {
        let mut invalid = valid;
        invalid[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        assert!(ParentParkReturn::decode(&invalid).is_err());
    }
    for magic in [b"CRUCPRR1", b"CRUCRET1"] {
        let mut invalid = valid;
        invalid[..8].copy_from_slice(magic);
        assert!(ParentParkReturn::decode(&invalid).is_err());
    }
    for offset in 176..184 {
        let mut invalid = valid;
        invalid[offset] = 1;
        assert!(ParentParkReturn::decode(&invalid).is_err());
    }
}
