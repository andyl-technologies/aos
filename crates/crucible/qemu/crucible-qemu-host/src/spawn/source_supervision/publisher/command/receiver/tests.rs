//! Falsifies bounded cuts against actual kernel-backed receiver words.
//!
//! Fixture writes model protocol observations, not an authentic Native peer.
//! These controls never authorize a Source loan return or terminal transition.

use super::*;
use super::super::tests::{publication, ready_session, region_bytes, replace_ticket, ticket};
use crucible_host_resources::test_support::TestAllocationObserver;
use crucible_qemu_protocol::publisher_subscription::PublisherOutcome;

fn returned() -> PublisherReturn {
    PublisherReturn {
        sequence: 2,
        loan: PublisherLoanIdentity {
            ticket_serial: 1,
            offer_generation: 1,
            command_sequence: 2,
        },
        local_serial: 7,
        first: -libc::EIO,
        post: -libc::ESTALE,
        returned_view_mask: 0,
        physical_child_mask: 0,
        outcome: PublisherOutcome::None,
        final_raw_icount: 13,
    }
}

fn write_return(body: &SessionBody<()>, bytes: &[u8; PUBLISHER_RETURN_BYTES]) {
    for (index, chunk) in bytes.as_chunks::<8>().0.iter().enumerate() {
        body.command_words().unwrap()[RETURN_WORD + index]
            .store(u64::from_ne_bytes(*chunk), Ordering::SeqCst);
    }
}

#[test]
fn actual_return_snapshot_retains_negative_posts_without_consuming_ticket_or_notifying() {
    for revoked in [false, true] {
        for (views, children) in [(0, 0), (1, 3), (1, 127)] {
            let mut body = ready_session();
            body.publish_command_offer(publication()).unwrap();
            let mut expected = returned();
            expected.returned_view_mask = views;
            expected.physical_child_mask = children;
            let bytes = expected.encode().unwrap();
            write_return(&body, &bytes);
            replace_ticket(&body, 1, PublisherTicketPhase::ReturnRequested);
            if revoked {
                body.revoke_command_offer().unwrap();
            }
            let before = region_bytes(&body);

            let (observed, allocations) =
                TestAllocationObserver::count(|| body.observe_command_return());

            assert_eq!(observed.unwrap(), Some(expected));
            assert_eq!(allocations.allocations, 0);
            assert_eq!(allocations.reallocations, 0);
            assert!(!allocations.overflow);
            assert_eq!(body.command.receiver.as_ref().unwrap().bytes, bytes);
            assert_eq!(body.command.receiver.as_ref().unwrap().record, expected);
            assert_eq!(body.observe_command_return().unwrap(), Some(expected));
            assert_eq!(region_bytes(&body), before);
            assert_eq!(ticket(&body).phase, PublisherTicketPhase::ReturnRequested);
            for event in &body.roles[1..] {
                let mut value = [0; 8];
                assert_eq!(
                    rustix::io::read(event.as_ref().unwrap(), &mut value),
                    Err(rustix::io::Errno::AGAIN)
                );
            }
            assert!(!body.return_physical(false));
            assert!(body.return_physical(true));
        }
    }
}

#[test]
fn populated_return_without_actual_request_retains_no_receiver_or_birth_privilege() {
    for phase in [
        PublisherTicketPhase::Issued,
        PublisherTicketPhase::Acquired,
        PublisherTicketPhase::Withdrawn,
    ] {
        let mut body = ready_session();
        body.publish_command_offer(publication()).unwrap();
        write_return(&body, &returned().encode().unwrap());
        if phase == PublisherTicketPhase::Withdrawn {
            assert!(body.withdraw_command_offer().unwrap());
        } else {
            replace_ticket(&body, 1, phase);
        }
        let before = region_bytes(&body);

        assert_eq!(body.observe_command_return().unwrap(), None);

        assert!(body.command.receiver.is_none());
        assert_eq!(region_bytes(&body), before);
        assert!(!body.return_physical(false));
        assert!(body.return_physical(true));
    }
    let mut body = ready_session();
    assert!(body.observe_command_return().is_err());
    assert!(body.command.first.is_some());
    assert!(body.publish_command_offer(publication()).is_err());
    assert!(body.command.offer.is_none());
    assert!(body.return_physical(true));
}

#[test]
fn changed_return_bytes_never_replace_the_first_retained_receiver_record() {
    for changed in [0, 8, 16, 24, 32, 40, 44, 48, 52, 56, 64, 88, 503] {
        let mut body = ready_session();
        body.publish_command_offer(publication()).unwrap();
        let expected = returned();
        let original = expected.encode().unwrap();
        write_return(&body, &original);
        replace_ticket(&body, 1, PublisherTicketPhase::ReturnRequested);
        assert_eq!(body.observe_command_return().unwrap(), Some(expected));
        let mut changed_bytes = original;
        changed_bytes[changed] ^= 1;
        write_return(&body, &changed_bytes);
        let before = region_bytes(&body);

        assert!(body.observe_command_return().is_err(), "byte {changed}");

        assert_eq!(body.command.receiver.as_ref().unwrap().record, expected);
        assert_eq!(body.command.receiver.as_ref().unwrap().bytes, original);
        assert!(body.command.first.is_some());
        assert_eq!(region_bytes(&body), before);
        assert!(!body.return_physical(false));
        assert!(body.return_physical(true));
    }
}

#[test]
fn invalid_actual_sequence_or_ticket_refuses_without_record_or_mapped_mutation() {
    for changed in 0..8 {
        let mut body = ready_session();
        body.publish_command_offer(publication()).unwrap();
        write_return(&body, &returned().encode().unwrap());
        replace_ticket(&body, 1, PublisherTicketPhase::ReturnRequested);
        match changed {
            0..=2 => {
                let sequence: u64 = [0, 1, u64::MAX][changed];
                body.command_words().unwrap()[RETURN_WORD]
                    .store(sequence.to_be(), Ordering::SeqCst);
            }
            3 => replace_ticket(&body, 2, PublisherTicketPhase::ReturnRequested),
            4 => replace_ticket(&body, 1, PublisherTicketPhase::Consumed),
            5 => replace_ticket(&body, 1, PublisherTicketPhase::Closed),
            6 => replace_ticket(&body, 1, PublisherTicketPhase::Withdrawn),
            7 => {
                let mut record = returned();
                record.returned_view_mask = 2;
                write_return(&body, &record.encode().unwrap());
            }
            _ => unreachable!(),
        }
        let before = region_bytes(&body);

        assert!(body.observe_command_return().is_err(), "case {changed}");

        assert!(body.command.receiver.is_none());
        assert!(body.command.first.is_some());
        assert_eq!(region_bytes(&body), before);
        assert!(!body.return_physical(false));
        assert!(body.return_physical(true));
    }
}

#[test]
fn independent_final_sequence_and_ticket_cuts_refuse_actual_changes_after_copy() {
    for changed in [RETURN_WORD, TICKET_WORD] {
        let mut body = ready_session();
        body.publish_command_offer(publication()).unwrap();
        write_return(&body, &returned().encode().unwrap());
        replace_ticket(&body, 1, PublisherTicketPhase::ReturnRequested);

        let result = body.observe_command_return_with(|words| {
            words[changed].fetch_add(2_u64.to_be(), Ordering::SeqCst);
        });

        assert!(result.is_err());
        assert!(body.command.receiver.is_none());
        assert!(!body.return_physical(false));
        assert!(body.return_physical(true));
    }
}

#[test]
fn revocation_and_return_observation_run_independently_after_either_refusal() {
    for refuse_revocation in [false, true] {
        for refuse_observation in [false, true] {
            let mut body = ready_session();
            body.publish_command_offer(publication()).unwrap();
            let expected = returned();
            write_return(&body, &expected.encode().unwrap());
            replace_ticket(&body, 1, PublisherTicketPhase::ReturnRequested);
            if refuse_revocation {
                body.command_words().unwrap()[PUBLICATION_WORD]
                    .store(3_u64.to_be(), Ordering::SeqCst);
            }
            if refuse_observation {
                body.command_words().unwrap()[RETURN_WORD].store(3_u64.to_be(), Ordering::SeqCst);
            }
            let before = region_bytes(&body);
            body.command.first = Some(OperationFailure::Kernel(rustix::io::Errno::IO));

            let (result, allocations) =
                TestAllocationObserver::count(|| body.revoke_command_and_observe_return());

            assert_eq!(result.is_err(), refuse_revocation || refuse_observation);
            assert_eq!(allocations.allocations, 0);
            assert_eq!(allocations.reallocations, 0);
            assert!(!allocations.overflow);
            assert_eq!(
                body.command.offer.as_ref().unwrap().revoked,
                !refuse_revocation
            );
            assert_eq!(body.command.receiver.is_some(), !refuse_observation);
            assert_eq!(body.command.revocation_first.is_some(), refuse_revocation);
            assert_eq!(
                body.command.return_observation_first.is_some(),
                refuse_observation
            );
            if let Some(retained) = &body.command.receiver {
                assert_eq!(retained.record, expected);
            }
            assert!(matches!(
                body.command.first,
                Some(OperationFailure::Kernel(rustix::io::Errno::IO))
            ));
            assert_eq!(ticket(&body).phase, PublisherTicketPhase::ReturnRequested);
            let after = region_bytes(&body);
            if refuse_revocation {
                assert_eq!(after, before);
            } else {
                assert_eq!(&after[TICKET_WORD * 8..], &before[TICKET_WORD * 8..]);
            }
            assert!(!body.return_physical(false));
            assert!(body.return_physical(true));
        }
    }
}
