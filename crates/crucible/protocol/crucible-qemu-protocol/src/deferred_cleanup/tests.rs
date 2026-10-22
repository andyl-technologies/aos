//! Checks immutable wire geometry, independent correlation and partial debt.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use crate::boundary_action::{ActionBinding, ActionObservation, ActionParent};

fn capability() -> DeferredCleanupCapability {
    let owner = |byte, incarnation| DeferredCleanupIdentity {
        identity: [byte; 32],
        incarnation,
    };
    DeferredCleanupCapability {
        issuer: owner(1, 11),
        reservation: owner(2, 12),
        recipient: owner(3, 13),
        resource: owner(4, 14),
        outer: owner(5, 15),
        command_sequence: 22,
        command_incarnation: 16,
        ticket_serial: 17,
        funding: DeferredCleanupFunding {
            control: 1,
            journals: 2,
            stack: 3,
            native: 4,
            allocator: 5,
            guards: 6,
        },
        profile: [6; 32],
        duration_ns: 1000,
        required_units: 9,
    }
}

fn request() -> DeferredCleanupRequest {
    let capability = capability();
    DeferredCleanupRequest {
        sequence: 24,
        reservation: capability.reservation,
        recipient_incarnation: capability.recipient.incarnation,
        command_sequence: capability.command_sequence,
        ticket_serial: capability.ticket_serial,
        termination_incarnation: 18,
        reason: DeferredCleanupReason::Normal,
    }
}

fn entry() -> DeferredCleanupEntry {
    DeferredCleanupEntry {
        sequence: 26,
        reservation: capability().reservation,
        request_sequence: request().sequence,
        entered_incarnation: None,
        facts: DeferredCleanupEntryFacts {
            attempted: true,
            returned: false,
            interval_born: false,
            output_captured: false,
            post_attempted: false,
            post_returned: false,
            uncertain: true,
        },
        first_status: 0,
        post_status: 0,
        cohort: None,
    }
}

fn cohort() -> ActionObservation {
    ActionObservation {
        binding: ActionBinding {
            cap: [7; 32],
            reservation: [8; 32],
            account_generation: 1,
            process_generation: 1,
            loan_sequence: 2,
            token: 0,
            capture: None,
            park_request: None,
            frontier: 1,
        },
        primary_count: 1,
        row_count: 1,
        borrowed_mask: 1,
        projected_mask: 1,
        cohort_current: true,
        parents: [
            ActionParent {
                cap: [9; 32],
                operation: 19,
                class: 13,
                started_revision: 1,
                policy_revision: 1,
                outer_revision: 1,
                started_ns: 1,
                progress_ns: 1,
                total_end_ns: 1001,
                poll_ns: 1,
                required: 1,
                ..ActionParent::default()
            },
            ActionParent::default(),
            ActionParent::default(),
            ActionParent::default(),
        ],
    }
}

#[test]
fn dormant_capability_has_exact_public_offsets_and_no_interval() {
    let observation = capability();
    let bytes = observation.encode().unwrap();

    assert_eq!(
        &bytes[..32],
        &[
            67, 82, 85, 67, 68, 67, 80, 49, 0, 0, 0, 1, 0, 0, 1, 128, 0, 0, 0, 3, 0, 0, 0, 1, 0, 0,
            0, 0, 0, 0, 0, 1,
        ]
    );
    for (offset, byte, incarnation) in [
        (32, 1, 11_u64),
        (72, 2, 12),
        (112, 3, 13),
        (176, 4, 14),
        (216, 5, 15),
    ] {
        assert_eq!(&bytes[offset..offset + 32], &[byte; 32]);
        assert_eq!(&bytes[offset + 32..offset + 40], &incarnation.to_be_bytes());
    }
    for (offset, value) in [
        (152, 22_u64),
        (160, 16),
        (168, 17),
        (256, 21),
        (264, 1),
        (272, 2),
        (280, 3),
        (288, 4),
        (328, 1000),
        (336, 9),
        (344, 5),
        (352, 6),
    ] {
        assert_eq!(&bytes[offset..offset + 8], &value.to_be_bytes());
    }
    assert_eq!(&bytes[296..328], &[6; 32]);
    assert_eq!(&bytes[360..], &[0; 24]);
    assert_eq!(DeferredCleanupCapability::decode(&bytes), Ok(observation));
}

#[test]
fn capability_refuses_all_truncations_padding_and_inconsistent_funding() {
    let original = capability().encode().unwrap();
    for length in 0..original.len() {
        assert!(
            DeferredCleanupCapability::decode(&original[..length]).is_err(),
            "length {length}"
        );
    }
    let mut extended = original.to_vec();
    extended.push(0);
    assert!(DeferredCleanupCapability::decode(&extended).is_err());

    for offset in [24, 25, 26, 27].into_iter().chain(360..384) {
        let mut bytes = original;
        bytes[offset] = 1;
        assert!(
            DeferredCleanupCapability::decode(&bytes).is_err(),
            "padding {offset}"
        );
    }
    for offset in [64, 104, 144, 160, 208, 248] {
        for value in [0, u64::MAX] {
            let mut bytes = original;
            put64(&mut bytes, offset, value);
            assert!(DeferredCleanupCapability::decode(&bytes).is_err());
        }
    }
    for offset in [264, 272, 280, 288, 344, 352] {
        for value in [0, u64::MAX, 99] {
            let mut bytes = original;
            put64(&mut bytes, offset, value);
            assert!(DeferredCleanupCapability::decode(&bytes).is_err());
        }
    }
    for (offset, value) in [
        (152, 23),
        (168, u64::MAX / 8 + 1),
        (328, i64::MAX as u64 + 1),
        (336, u64::MAX),
        (256, 22),
    ] {
        let mut bytes = original;
        put64(&mut bytes, offset, value);
        assert!(DeferredCleanupCapability::decode(&bytes).is_err());
    }
}

#[test]
fn future_limits_accept_the_exact_nonwrapping_boundary() {
    let mut observation = capability();
    observation.issuer.incarnation = u64::MAX - 1;
    observation.command_sequence = u64::MAX - 1;
    observation.ticket_serial = u64::MAX / 8;
    observation.duration_ns = i64::MAX as u64;
    observation.required_units = u64::MAX - 1;

    let bytes = observation.encode().unwrap();
    assert_eq!(DeferredCleanupCapability::decode(&bytes), Ok(observation));
    observation.funding.control = u64::MAX;
    assert!(observation.encode().is_err());
}

#[test]
fn requests_preserve_each_actual_termination_reason_and_immutable_correlation() {
    for (index, reason) in [
        DeferredCleanupReason::Normal,
        DeferredCleanupReason::Longjmp,
        DeferredCleanupReason::Atomic,
        DeferredCleanupReason::Refusal,
        DeferredCleanupReason::Revocation,
    ]
    .into_iter()
    .enumerate()
    {
        let mut observation = request();
        observation.reason = reason;

        let bytes = observation.encode().unwrap();
        assert_eq!(&bytes[..8], b"CRUCDRQ1");
        assert_eq!(&bytes[96..100], &((index + 1) as u32).to_be_bytes());
        assert_eq!(DeferredCleanupRequest::decode(&bytes), Ok(observation));
        assert!(observation.validate_for(&capability()).is_ok());
    }
    for mutate in [0, 1, 2, 3, 4] {
        let mut other = request();
        match mutate {
            0 => other.reservation.identity[0] ^= 1,
            1 => other.reservation.incarnation += 1,
            2 => other.recipient_incarnation += 1,
            3 => other.command_sequence += 2,
            _ => other.ticket_serial += 1,
        }
        assert!(other.encode().is_ok());
        assert!(other.validate_for(&capability()).is_err());
    }
}

#[test]
fn requests_refuse_reserved_bytes_unknown_reasons_and_wrong_extent() {
    let original = request().encode().unwrap();
    for length in 0..original.len() {
        assert!(DeferredCleanupRequest::decode(&original[..length]).is_err());
    }
    for offset in 100..128 {
        let mut bytes = original;
        bytes[offset] = 1;
        assert!(DeferredCleanupRequest::decode(&bytes).is_err());
    }
    for reason in [0, 6, u32::MAX] {
        let mut bytes = original;
        put32(&mut bytes, 96, reason);
        assert!(DeferredCleanupRequest::decode(&bytes).is_err());
    }
}

#[test]
fn captured_without_born_and_interrupted_factory_capture_retain_partial_facts() {
    let mut observation = entry();
    observation.facts.output_captured = true;
    observation.facts.post_attempted = true;
    observation.facts.post_returned = true;
    observation.post_status = -5;

    let bytes = observation.encode().unwrap();
    assert_eq!(bytes[87], 121);
    assert_eq!(DeferredCleanupEntry::decode(&bytes), Ok(observation));
    assert!(observation.validate_for(&capability(), &request()).is_ok());
    assert!(observation.entered_incarnation.is_none());
    assert!(observation.cohort.is_none());
    assert!(!observation.facts.returned);
}

#[test]
fn negative_factory_and_post_cannot_erase_a_born_interval() {
    let mut observation = entry();
    observation.facts.returned = true;
    observation.facts.interval_born = true;
    observation.facts.output_captured = true;
    observation.facts.post_attempted = true;
    observation.facts.post_returned = true;
    observation.entered_incarnation = Some(19);
    observation.cohort = Some(cohort());
    observation.first_status = -12;
    observation.post_status = -116;

    let bytes = observation.encode().unwrap();
    assert_eq!(&bytes[128..136], b"CRUCACT2");
    assert_eq!(DeferredCleanupEntry::decode(&bytes), Ok(observation));
    observation.facts.interval_born = false;
    assert!(observation.encode().is_err());
}

#[test]
fn noncurrent_partial_preparation_remains_reportable_as_debt() {
    let mut partial = cohort();
    partial.cohort_current = false;
    partial.row_count = 2;
    partial.parents[0].preparation = 2;

    let mut observation = entry();
    observation.facts.interval_born = true;
    observation.facts.output_captured = true;
    observation.entered_incarnation = Some(19);
    observation.cohort = Some(partial);
    let bytes = observation.encode().unwrap();

    assert_eq!(DeferredCleanupEntry::decode(&bytes), Ok(observation));
    observation.cohort.as_mut().unwrap().cohort_current = true;
    assert!(observation.encode().is_err());
}

#[test]
fn entries_refuse_unknown_facts_unreturned_statuses_and_unbound_output() {
    let original = entry().encode().unwrap();
    for length in 0..original.len() {
        assert!(DeferredCleanupEntry::decode(&original[..length]).is_err());
    }
    for offset in (80..84).chain(96..128).chain(128..1024) {
        let mut bytes = original;
        bytes[offset] = 1;
        assert!(
            DeferredCleanupEntry::decode(&bytes).is_err(),
            "offset {offset}"
        );
    }
    for facts in [0, 128, 1 | 4, 1 | 32] {
        let mut bytes = original;
        put32(&mut bytes, 84, facts);
        assert!(DeferredCleanupEntry::decode(&bytes).is_err());
    }
    for offset in [88, 92] {
        let mut bytes = original;
        put32(&mut bytes, offset, (-5_i32) as u32);
        assert!(DeferredCleanupEntry::decode(&bytes).is_err());
    }
    let mut other = entry();
    other.request_sequence += 2;
    assert!(other.encode().is_ok());
    assert!(other.validate_for(&capability(), &request()).is_err());
}
