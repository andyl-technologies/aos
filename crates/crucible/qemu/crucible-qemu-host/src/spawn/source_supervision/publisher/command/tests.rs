//! Exercises actual mapped command words without issuing Source authority.
//!
//! The component owns real kernel roles but no paid Source, operation lender,
//! Native recipient, completion witness, or physical-return authorization.
// SPDX-License-Identifier: Apache-2.0

use crucible_host_resources::test_support::TestAllocationObserver;
use crucible_qemu_protocol::boundary_action::{ActionBinding, ActionObservation, ActionParent};
use crucible_qemu_protocol::publisher_subscription::{PublisherCommand, PublisherStopMode};

use super::*;
use super::super::tests::{header, physical_fixture};

fn publication() -> PublisherPublication {
    let mut parents = [ActionParent::default(); 4];
    parents[0] = ActionParent {
        cap: [7; 32],
        operation: 9,
        class: 1,
        origin_ns: 100,
        started_ns: 110,
        progress_ns: 110,
        poll_ns: 1,
        required: 1,
        ..ActionParent::default()
    };

    PublisherPublication {
        sequence: 2,
        offer_generation: 1,
        ticket_serial: 1,
        permission: PublisherPermission::Borrowable,
        standing_sequence: 8,
        cohort: ActionObservation {
            binding: ActionBinding {
                cap: [1; 32],
                reservation: [2; 32],
                account_generation: 3,
                process_generation: 7,
                loan_sequence: 2,
                token: 0,
                capture: None,
                park_request: None,
                frontier: 19,
            },
            primary_count: 1,
            row_count: 1,
            borrowed_mask: 1,
            projected_mask: 1,
            cohort_current: true,
            parents,
        },
        command: Some(PublisherCommand {
            scheduler_generation: 4,
            initial_raw_icount: 10,
            maximum_raw_icount: 20,
            logical_tick_ceiling: 20_000,
            native_monotonic_ns_ceiling: 0,
            stop: PublisherStopMode::RetiredCeiling,
            frontier: 19,
        }),
    }
}

fn ready_session() -> SessionBody<()> {
    let mut body = physical_fixture();
    body.construct_with(|| Ok(()), header()).unwrap();
    // Exercise the physical component after its export cut. This field does
    // not supply a real remote borrower or a production cleanup receipt.
    body.exported = true;
    body
}

fn region_bytes(body: &SessionBody<()>) -> [u8; PUBLISHER_REGION_BYTES] {
    let mut bytes = [0; PUBLISHER_REGION_BYTES];
    assert_eq!(
        rustix::io::pread(body.roles[0].as_ref().unwrap(), &mut bytes, 0).unwrap(),
        bytes.len()
    );
    bytes
}

fn ticket(body: &SessionBody<()>) -> PublisherTicket {
    PublisherTicket::decode(u64::from_be(
        body.command_words().unwrap()[TICKET_WORD].load(Ordering::SeqCst),
    ))
    .unwrap()
}

fn replace_ticket(body: &SessionBody<()>, serial: u64, phase: PublisherTicketPhase) {
    let encoded = PublisherTicket { serial, phase }.encode().unwrap();
    body.command_words().unwrap()[TICKET_WORD].store(encoded.to_be(), Ordering::SeqCst);
}

#[test]
fn actual_command_mapping_publishes_exact_offer_before_issued_ticket_without_notification() {
    let mut body = ready_session();
    let before = region_bytes(&body);
    let expected = publication();

    let (identity, allocations) =
        TestAllocationObserver::count(|| body.publish_command_offer(expected).unwrap());

    assert_eq!(allocations.allocations, 0);
    assert_eq!(allocations.reallocations, 0);
    assert!(!allocations.overflow);
    assert_eq!(identity.command_sequence, 2);
    assert_eq!(identity.offer_generation, 1);
    assert_eq!(identity.ticket_serial, 1);
    let bytes = region_bytes(&body);
    assert_eq!(&bytes[..256], &before[..256]);
    assert_eq!(
        PublisherPublication::decode(&bytes[256..1792]).unwrap(),
        expected
    );
    assert_eq!(ticket(&body).phase, PublisherTicketPhase::Issued);
    assert!(bytes[1800..].iter().all(|byte| *byte == 0));

    let offer = body.command.offer.as_ref().unwrap();
    assert!(offer.publication_attempted && offer.publication_committed);
    assert!(offer.ticket_attempted && offer.ticket_issued);
    assert!(!offer.withdrawal_attempted);
    for event in &body.roles[1..] {
        let mut value = [0; 8];
        assert_eq!(
            rustix::io::read(event.as_ref().unwrap(), &mut value),
            Err(rustix::io::Errno::AGAIN)
        );
    }
    assert!(body.return_physical(true));
}

#[test]
fn invalid_command_preflight_preserves_actual_region_and_cannot_retry_birth() {
    for changed in 0..14 {
        let mut body = ready_session();
        let before = region_bytes(&body);
        let mut offer = publication();
        match changed {
            0 => offer.sequence = 4,
            1 => offer.offer_generation = 2,
            2 => offer.ticket_serial = 2,
            3 => offer.permission = PublisherPermission::Revoked,
            4 => offer.command = None,
            5 => offer.cohort.cohort_current = false,
            6 => offer.cohort.row_count = 0,
            7 => offer.cohort.borrowed_mask = 0,
            8 => offer.cohort.projected_mask = 0,
            9 => offer.cohort.parents[0].state = 3,
            10 => offer.cohort.binding.cap = [8; 32],
            11 => offer.cohort.binding.reservation = [8; 32],
            12 => offer.cohort.binding.account_generation = 4,
            13 => offer.cohort.binding.process_generation = 8,
            _ => unreachable!(),
        }

        assert!(body.publish_command_offer(offer).is_err(), "case {changed}");
        assert!(body.command.offer.is_none(), "case {changed}");
        assert!(body.command.first.is_some(), "case {changed}");
        assert!(body.publish_command_offer(publication()).is_err());
        assert_eq!(region_bytes(&body), before, "case {changed}");
        assert!(body.return_physical(true));
    }
}

#[test]
fn occupied_actual_publication_or_ticket_refuses_without_overwriting_any_word() {
    for occupied in [PUBLICATION_WORD, TICKET_WORD] {
        let mut body = ready_session();
        body.command_words().unwrap()[occupied].store(9_u64.to_be(), Ordering::SeqCst);
        let before = region_bytes(&body);

        assert!(body.publish_command_offer(publication()).is_err());

        assert_eq!(region_bytes(&body), before);
        assert!(body.command.offer.is_none());
        assert!(body.command.first.is_some());
        assert!(body.return_physical(true));
    }
}

#[test]
fn actual_withdrawal_is_once_only_and_keeps_immutable_offer_retained() {
    let mut body = ready_session();
    body.publish_command_offer(publication()).unwrap();
    let before = region_bytes(&body);

    let (won, allocations) =
        TestAllocationObserver::count(|| body.withdraw_command_offer().unwrap());

    assert!(won);
    assert_eq!(allocations.allocations, 0);
    assert_eq!(allocations.reallocations, 0);
    assert!(!allocations.overflow);
    assert_eq!(ticket(&body).phase, PublisherTicketPhase::Withdrawn);
    assert_eq!(&region_bytes(&body)[256..1792], &before[256..1792]);
    assert!(body.command.offer.as_ref().unwrap().withdrawn);
    assert!(body.withdraw_command_offer().is_err());
    assert!(body.publish_command_offer(publication()).is_err());
    assert_eq!(ticket(&body).phase, PublisherTicketPhase::Withdrawn);
    assert!(!body.return_physical(false));
    assert!(body.return_physical(true));
}

#[test]
fn acquired_actual_ticket_wins_withdrawal_without_rewriting_receiver_phase() {
    for phase in [
        PublisherTicketPhase::Acquired,
        PublisherTicketPhase::ReturnRequested,
    ] {
        let mut body = ready_session();
        body.publish_command_offer(publication()).unwrap();
        replace_ticket(&body, 1, phase);
        let before = region_bytes(&body);

        assert!(!body.withdraw_command_offer().unwrap());

        assert_eq!(region_bytes(&body), before);
        let offer = body.command.offer.as_ref().unwrap();
        assert!(offer.withdrawal_attempted);
        assert!(!offer.withdrawn);
        assert!(body.withdraw_command_offer().is_err());
        assert_eq!(region_bytes(&body), before);
        assert!(body.return_physical(true));
    }
}

#[test]
fn foreign_serial_or_impossible_receiver_phase_retains_first_withdrawal_refusal() {
    for (serial, phase) in [
        (2, PublisherTicketPhase::Acquired),
        (1, PublisherTicketPhase::Withdrawn),
        (1, PublisherTicketPhase::Consumed),
        (1, PublisherTicketPhase::Closed),
    ] {
        let mut body = ready_session();
        body.publish_command_offer(publication()).unwrap();
        replace_ticket(&body, serial, phase);
        let before = region_bytes(&body);

        assert!(body.withdraw_command_offer().is_err());

        assert!(matches!(
            body.command.first,
            Some(OperationFailure::Geometry)
        ));
        assert!(body.command.offer.as_ref().unwrap().withdrawal_attempted);
        assert!(!body.command.offer.as_ref().unwrap().withdrawn);
        assert_eq!(region_bytes(&body), before);
        assert!(body.withdraw_command_offer().is_err());
        assert_eq!(region_bytes(&body), before);
        assert!(body.return_physical(true));
    }
}

#[test]
fn uncertain_actual_mapping_blocks_command_and_preserves_physical_custody() {
    let mut body = ready_session();
    let before = region_bytes(&body);
    body.mapping_return_uncertain = true;

    assert!(body.publish_command_offer(publication()).is_err());

    assert!(body.command.offer.is_none());
    assert_eq!(region_bytes(&body), before);
    assert!(!body.return_physical(true));
    // No munmap was attempted by this injected component cut. Dispose only
    // this known-live fixture; production never clears uncertain disposition.
    body.mapping_return_uncertain = false;
    assert!(body.return_physical(true));
}
