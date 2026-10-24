//! Exercises schema separation, independent role updates and partial journals.
//!
//! These are syntax controls. Their copied observations create no operation,
//! resource, recipient, entered cleanup interval or physical-return authority.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use super::super::{
    PUBLISHER_RETURN_BYTES, PublisherLoanIdentity, PublisherOutcome, PublisherPublication,
    PublisherReturn, PublisherStopMode, PublisherTerminal,
};
use crate::boundary_action::{ActionBinding, ActionParent};

fn publication() -> QuantumPublisherPublication {
    let mut parents = [ActionParent::default(); 4];
    for (index, parent) in parents.iter_mut().enumerate() {
        *parent = ActionParent {
            cap: [2; 32],
            operation: index as u64 + 1,
            class: [1, 13, 12, 12][index],
            role: u32::from(index >= 2),
            started_revision: 1,
            policy_revision: 1,
            outer_revision: 1,
            origin_ns: 10,
            started_ns: 20,
            progress_ns: 30,
            total_end_ns: 1_000,
            poll_ns: 5,
            required: 1,
            preparation: if index < 2 { index as u32 + 3 } else { 0 },
            ..ActionParent::default()
        };
    }

    QuantumPublisherPublication {
        sequence: 4,
        offer_generation: 3,
        ticket_serial: 5,
        work_permission: PublisherPermission::Borrowable,
        standing_sequence: 2,
        cohort: ActionObservation {
            binding: ActionBinding {
                cap: [2; 32],
                reservation: [3; 32],
                account_generation: 1,
                process_generation: 1,
                loan_sequence: 2,
                token: 0,
                capture: None,
                park_request: None,
                frontier: 9,
            },
            primary_count: 2,
            row_count: 4,
            borrowed_mask: 15,
            projected_mask: 15,
            cohort_current: true,
            parents,
        },
        command: PublisherCommand {
            scheduler_generation: 2,
            initial_raw_icount: 4,
            maximum_raw_icount: 8,
            logical_tick_ceiling: 400,
            native_monotonic_ns_ceiling: 900,
            stop: PublisherStopMode::RetiredCeiling,
            frontier: 9,
        },
        roles: QuantumPublisherRoleMap {
            work_mask: 5,
            cleanup_mask: 10,
            cleanup_permission: PublisherPermission::Borrowable,
            cleanup_loan_generation: 7,
            cleanup_entry_incarnation: 11,
        },
    }
}

fn receiver() -> QuantumPublisherReturn {
    QuantumPublisherReturn {
        common: PublisherReturn {
            sequence: 6,
            loan: PublisherLoanIdentity {
                ticket_serial: 5,
                offer_generation: 3,
                command_sequence: 4,
            },
            local_serial: 1,
            first: -1,
            post: -2,
            returned_view_mask: 15,
            physical_child_mask: 0x7f,
            outcome: PublisherOutcome::None,
            final_raw_icount: 7,
        },
        returned_work_mask: 5,
        returned_cleanup_mask: 10,
        cleanup_loan_generation: 7,
        cleanup_entry_incarnation: 11,
        terminal_return_serial: 13,
    }
}

fn terminal() -> QuantumPublisherTerminal {
    QuantumPublisherTerminal {
        common: PublisherTerminal {
            sequence: 8,
            loan: receiver().common.loan,
            receiver_return_sequence: 6,
            first: -3,
            post: -4,
            consumed_mask: 15,
            born_mask: 15,
            command_consumption_generation: 17,
        },
        consumed_work_mask: 5,
        consumed_cleanup_mask: 10,
        cleanup_loan_generation: 7,
        cleanup_entry_incarnation: 11,
        terminal_return_serial: 13,
    }
}

fn hex(text: &str) -> Vec<u8> {
    text.split_whitespace()
        .flat_map(|word| {
            assert_eq!(word.len() % 2, 0);
            (0..word.len())
                .step_by(2)
                .map(|index| u8::from_str_radix(&word[index..index + 2], 16).unwrap())
        })
        .collect()
}

#[test]
fn header_editions_refuse_each_other_and_preserve_exact_identity_validation() {
    let header = QuantumPublisherHeader {
        identity: PublisherHeader {
            lender_generation: 1,
            account_generation: 2,
            process_generation: 3,
            capability: [4; 32],
            reservation: [5; 32],
            node_index: 0,
            node_count: 1,
        },
    };
    let bytes = header.encode().unwrap();

    assert_eq!(&bytes[..16], hex("43525543504c4d32 00000002 00001000"));
    assert_eq!(QuantumPublisherHeader::decode(&bytes), Ok(header));
    assert!(PublisherHeader::decode(&bytes).is_err());
    assert!(QuantumPublisherHeader::decode(&header.identity.encode().unwrap()).is_err());
    for offset in (0..16).chain(24..32).chain(120..256) {
        let mut mutated = bytes;
        mutated[offset] ^= 1;
        assert!(
            QuantumPublisherHeader::decode(&mutated).is_err(),
            "offset {offset}"
        );
    }
    for length in 0..bytes.len() {
        assert!(QuantumPublisherHeader::decode(&bytes[..length]).is_err());
    }
    assert!(QuantumPublisherHeader::decode(&[bytes.as_slice(), &[0]].concat()).is_err());
}

#[test]
fn paired_publication_matches_independent_role_bytes_and_refuses_legacy_decoding() {
    let publication = publication();
    let bytes = publication.encode().unwrap();

    assert_eq!(
        &bytes[64..112],
        hex("00000001 00000000 00000001 00000005 0000000a 00000000
             0000000000000001 0000000000000007 000000000000000b")
    );
    assert_eq!(QuantumPublisherPublication::decode(&bytes), Ok(publication));
    assert!(PublisherPublication::decode(&bytes).is_err());
    let mut legacy_cohort = publication.cohort;
    legacy_cohort.primary_count = 1;
    legacy_cohort.row_count = 1;
    legacy_cohort.borrowed_mask = 1;
    legacy_cohort.projected_mask = 1;
    legacy_cohort.parents[0].preparation = 0;
    legacy_cohort.parents[1..].fill(ActionParent::default());
    let legacy = PublisherPublication {
        sequence: publication.sequence,
        offer_generation: publication.offer_generation,
        ticket_serial: publication.ticket_serial,
        permission: publication.work_permission,
        standing_sequence: publication.standing_sequence,
        cohort: legacy_cohort,
        command: Some(publication.command),
    };
    assert!(QuantumPublisherPublication::decode(&legacy.encode().unwrap()).is_err());

    for offset in (40..76).chain(84..88).chain(112..128).chain(1152..1536) {
        let mut mutated = bytes;
        mutated[offset] ^= 1;
        assert!(
            QuantumPublisherPublication::decode(&mutated).is_err(),
            "offset {offset}"
        );
    }
    for length in 0..bytes.len() {
        assert!(QuantumPublisherPublication::decode(&bytes[..length]).is_err());
    }
    assert!(QuantumPublisherPublication::decode(&[bytes.as_slice(), &[0]].concat()).is_err());
    for offset in [24, 88] {
        for value in [0, 4, u64::MAX] {
            let mut mutated = bytes;
            mutated[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
            assert!(QuantumPublisherPublication::decode(&mutated).is_err());
        }
    }
    for offset in [96, 104] {
        for value in [0, u64::MAX] {
            let mut mutated = bytes;
            mutated[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
            assert!(QuantumPublisherPublication::decode(&mutated).is_err());
        }
    }
}

#[test]
fn exact_role_constraints_refuse_cross_primary_missing_or_unused_parents() {
    for index in 0..2 {
        for class in 0..14 {
            let mut invalid = publication();
            invalid.cohort.parents[index].class = class;
            if class != [1, 13][index] {
                assert!(invalid.encode().is_err());
            }
        }
    }
    let mut shared = publication();
    shared.cohort.parents[1].preparation = 3;
    shared.cohort.parents[3] = ActionParent::default();
    shared.cohort.row_count = 3;
    shared.cohort.borrowed_mask = 7;
    shared.cohort.projected_mask = 7;
    shared.roles.cleanup_mask = 6;
    assert_eq!(
        QuantumPublisherPublication::decode(&shared.encode().unwrap()),
        Ok(shared)
    );

    let mut independent = publication();
    independent.cohort.parents[0].preparation = 0;
    independent.cohort.parents[1].preparation = 0;
    independent.cohort.parents[2..].fill(ActionParent::default());
    independent.cohort.row_count = 2;
    independent.cohort.borrowed_mask = 3;
    independent.cohort.projected_mask = 3;
    independent.roles.work_mask = 1;
    independent.roles.cleanup_mask = 2;
    assert_eq!(
        QuantumPublisherPublication::decode(&independent.encode().unwrap()),
        Ok(independent)
    );

    for (work, cleanup) in [(1, 10), (5, 2), (7, 10), (5, 11), (13, 10), (5, 0x1a)] {
        let mut invalid = publication();
        invalid.roles.work_mask = work;
        invalid.roles.cleanup_mask = cleanup;
        assert!(invalid.encode().is_err());
    }
    let mut invalid = publication();
    invalid.cohort.parents[1].operation = invalid.cohort.parents[0].operation;
    assert!(invalid.encode().is_err());
    let mut invalid = publication();
    invalid.cohort.parents[1].total_end_ns = 0;
    assert!(invalid.encode().is_err());
    for (born, projected, current) in [(7, 7, true), (15, 7, true), (15, 15, false)] {
        let mut invalid = publication();
        invalid.cohort.borrowed_mask = born;
        invalid.cohort.projected_mask = projected;
        invalid.cohort.cohort_current = current;
        assert!(invalid.encode().is_err());
    }
}

#[test]
fn work_revocation_preserves_cleanup_permission_and_neither_can_be_restored() {
    let original = publication();
    let mut revoked = original;
    revoked.work_permission = PublisherPermission::Revoked;

    assert!(revoked.validate_permission_update(&original).is_ok());
    assert_eq!(
        revoked.roles.cleanup_permission,
        PublisherPermission::Borrowable
    );
    assert!(original.validate_permission_update(&revoked).is_err());
    let mut terminal = revoked;
    terminal.work_permission = PublisherPermission::Terminal;
    terminal.roles.cleanup_permission = PublisherPermission::Terminal;
    assert!(terminal.validate_permission_update(&revoked).is_ok());
    assert!(revoked.validate_permission_update(&terminal).is_err());

    let original_bytes = original.encode().unwrap();
    for offset in (0..24).chain(32..88).chain(96..1152) {
        let mut mutated = original_bytes;
        mutated[offset] ^= 1;
        if let Ok(changed) = QuantumPublisherPublication::decode(&mutated) {
            assert!(
                changed.validate_permission_update(&original).is_err(),
                "offset {offset}"
            );
        }
    }
}

#[test]
fn separate_return_and_consumption_bytes_preserve_negative_first_and_post() {
    let publication = publication();
    let receiver = receiver();
    let terminal = terminal();
    let returned = receiver.encode(&publication).unwrap();
    let consumed = terminal.encode(&publication, &receiver).unwrap();
    let extension = hex("00000005 0000000a 0000000000000007
                         000000000000000b 000000000000000d");

    assert_eq!(&returned[88..120], extension);
    assert_eq!(&consumed[64..96], extension);
    assert_eq!(
        QuantumPublisherReturn::decode(&returned, &publication),
        Ok(receiver)
    );
    assert_eq!(
        QuantumPublisherTerminal::decode(&consumed, &publication, &receiver),
        Ok(terminal)
    );
    assert_eq!((receiver.common.first, receiver.common.post), (-1, -2));
    assert_eq!((terminal.common.first, terminal.common.post), (-3, -4));
    assert!(PublisherReturn::decode(&returned).is_err());
    assert!(PublisherTerminal::decode(&consumed).is_err());
    assert!(
        QuantumPublisherReturn::decode(&receiver.common.encode().unwrap(), &publication).is_err()
    );
    assert!(
        QuantumPublisherTerminal::decode(
            &terminal.common.encode().unwrap(),
            &publication,
            &receiver
        )
        .is_err()
    );
}

#[test]
fn partial_journals_keep_debt_and_reject_foreign_roles_and_correlations() {
    let mut publication = publication();
    publication.work_permission = PublisherPermission::Terminal;
    let mut receiver = receiver();
    receiver.returned_cleanup_mask = 0;
    receiver.common.returned_view_mask = 5;
    receiver.common.physical_child_mask = 0;
    let mut terminal = terminal();
    terminal.consumed_cleanup_mask = 0;
    terminal.common.consumed_mask = 5;
    terminal.common.command_consumption_generation = 0;

    let returned = receiver.encode(&publication).unwrap();
    let consumed = terminal.encode(&publication, &receiver).unwrap();
    assert_eq!(
        QuantumPublisherReturn::decode(&returned, &publication),
        Ok(receiver)
    );
    assert_eq!(
        QuantumPublisherTerminal::decode(&consumed, &publication, &receiver),
        Ok(terminal)
    );
    for length in 0..returned.len() {
        assert!(QuantumPublisherReturn::decode(&returned[..length], &publication).is_err());
    }
    for length in 0..consumed.len() {
        assert!(
            QuantumPublisherTerminal::decode(&consumed[..length], &publication, &receiver).is_err()
        );
    }
    assert!(
        QuantumPublisherReturn::decode(&[returned.as_slice(), &[0]].concat(), &publication)
            .is_err()
    );
    assert!(
        QuantumPublisherTerminal::decode(
            &[consumed.as_slice(), &[0]].concat(),
            &publication,
            &receiver
        )
        .is_err()
    );
    for offset in [88, 92, 96, 104, 112] {
        let mut mutated = returned;
        mutated[offset + if offset < 96 { 3 } else { 7 }] ^= 1;
        // A journal serial is not syntax-authenticated by the publication, but
        // changing it must break the matching producer consumption record.
        if let Ok(changed) = QuantumPublisherReturn::decode(&mutated, &publication) {
            assert!(terminal.encode(&publication, &changed).is_err());
        }
    }
    for offset in [8, 16, 24, 32, 64, 68, 72, 80, 88] {
        let mut mutated = consumed;
        mutated[offset + if [64, 68].contains(&offset) { 3 } else { 7 }] ^= 1;
        assert!(QuantumPublisherTerminal::decode(&mutated, &publication, &receiver).is_err());
    }
    for offset in 120..PUBLISHER_RETURN_BYTES {
        let mut mutated = returned;
        mutated[offset] = 1;
        assert!(QuantumPublisherReturn::decode(&mutated, &publication).is_err());
    }
    for offset in 96..super::super::PUBLISHER_TERMINAL_BYTES {
        let mut mutated = consumed;
        mutated[offset] = 1;
        assert!(QuantumPublisherTerminal::decode(&mutated, &publication, &receiver).is_err());
    }
}
