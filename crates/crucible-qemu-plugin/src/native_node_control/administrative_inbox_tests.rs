//! Raw custody tests; no native registration or qualification is inferred.

// crucible-lint: allow panic-shortcut -- These administrative inbox tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used)]

use super::super::administrative_mailbox::NativeAdministrativeClass;
use super::*;
use crate::runtime::worker_quiescence::WORKER_NATIVE_CONTROL;
use crucible_protocol::node_control::{NativeControlEdition, encode_frame_for_edition};

fn query() -> NativeFrame {
    NativeFrame::QueryAdministration {
        prepared_scope_hash: [1; 32],
        administration_commitment: [2; 32],
    }
}

#[test]
fn refused_preflight_preserves_original_socket_and_unread_packet() {
    let (host, native) =
        NativeChannel::supervised_pair_for_edition(NativeControlEdition::Administration).unwrap();
    assert!(host.send(&query()).unwrap());
    let mut endpoint = Some(native);
    assert!(
        NativeAdministrativeInbox::from_pinned_endpoint(&mut endpoint, [1; 32], false, 0, 8192)
            .is_err()
    );
    assert_eq!(endpoint.as_ref().unwrap().receive().unwrap(), Some(query()));
}

#[test]
fn sole_inbox_retains_exact_packet_and_distinct_modeled_roster() {
    let (host, native) =
        NativeChannel::supervised_pair_for_edition(NativeControlEdition::Administration).unwrap();
    let mut endpoint = Some(native);
    let inbox =
        NativeAdministrativeInbox::from_pinned_endpoint(&mut endpoint, [1; 32], false, 8, 65536)
            .unwrap();
    assert!(endpoint.is_none());
    assert_eq!(
        inbox.modeled_workers().worker_mask() & WORKER_NATIVE_CONTROL,
        0
    );
    assert!(host.send(&query()).unwrap());
    assert_eq!(
        inbox.receive_one().unwrap(),
        NativeAdministrativeReceive::Retained(1, NativeAdministrativeClass::ReadOriginal)
    );
    assert_eq!(
        inbox.original(1).unwrap(),
        encode_frame_for_edition(NativeControlEdition::Administration, &query()).unwrap()
    );
    assert_eq!(inbox.original_frame(1).unwrap(), query());
    assert_eq!(
        inbox.receive_one().unwrap(),
        NativeAdministrativeReceive::Empty
    );
    assert!(inbox.original_frame(2).is_err());
}

#[test]
fn exhausted_reply_credit_leaves_next_complete_packet_unread() {
    let (host, native) =
        NativeChannel::supervised_pair_for_edition(NativeControlEdition::Administration).unwrap();
    let mut endpoint = Some(native);
    let inbox =
        NativeAdministrativeInbox::from_pinned_endpoint(&mut endpoint, [1; 32], false, 1, 8192)
            .unwrap();
    assert!(host.send(&query()).unwrap());
    assert!(host.send(&query()).unwrap());
    assert_eq!(
        inbox.receive_one().unwrap(),
        NativeAdministrativeReceive::Retained(1, NativeAdministrativeClass::ReadOriginal)
    );
    assert_eq!(
        inbox.receive_one().unwrap(),
        NativeAdministrativeReceive::Backpressure
    );
    assert_eq!(
        inbox.receive_one().unwrap(),
        NativeAdministrativeReceive::Backpressure
    );
    assert_eq!(inbox.original_frame(1).unwrap(), query());
}

#[test]
fn manifest_descriptor_remains_available_while_reader_holds_mailbox() {
    let (_, native) =
        NativeChannel::supervised_pair_for_edition(NativeControlEdition::Administration).unwrap();
    let mut endpoint = Some(native);
    let inbox =
        NativeAdministrativeInbox::from_pinned_endpoint(&mut endpoint, [1; 32], false, 8, 65536)
            .unwrap();
    let original = inbox.descriptor().unwrap();
    let held = inbox.test_hold_mailbox();

    // The installer observes the original owned endpoint, without borrowing
    // the reader's mutable receive/reply ledger or making another receiver.
    assert_eq!(inbox.descriptor().unwrap(), original);
    drop(held);
}

#[test]
fn poisoned_reader_custody_refuses_the_retained_manifest_descriptor() {
    let (_, native) =
        NativeChannel::supervised_pair_for_edition(NativeControlEdition::Administration).unwrap();
    let mut endpoint = Some(native);
    let inbox =
        NativeAdministrativeInbox::from_pinned_endpoint(&mut endpoint, [1; 32], false, 8, 65536)
            .unwrap();
    let failure = std::panic::catch_unwind(|| {
        let _held = inbox.test_hold_mailbox();
        panic!("intentional original inbox custody failure");
    });

    assert!(failure.is_err());
    assert!(matches!(
        inbox.descriptor(),
        Err(NativeAdministrativeInboxError::Poisoned)
    ));
}

#[test]
fn busy_validation_preserves_the_original_reply_credit_and_packet() {
    let (host, native) =
        NativeChannel::supervised_pair_for_edition(NativeControlEdition::Administration).unwrap();
    let mut endpoint = Some(native);
    let inbox =
        NativeAdministrativeInbox::from_pinned_endpoint(&mut endpoint, [1; 32], false, 8, 65536)
            .unwrap();
    assert!(host.send(&query()).unwrap());
    assert_eq!(
        inbox.receive_one().unwrap(),
        NativeAdministrativeReceive::Retained(1, NativeAdministrativeClass::ReadOriginal)
    );
    let original = inbox.original(1).unwrap();
    let credit = inbox.reserve_construction_reply(1).unwrap();
    let held = inbox.test_hold_mailbox();

    assert!(matches!(
        inbox.validate_unpublished_credit(&credit),
        Err(NativeAdministrativeInboxError::Busy)
    ));

    drop(held);
    assert!(inbox.validate_unpublished_credit(&credit).is_ok());
    assert!(inbox.validate_unpublished_credit(&credit).is_ok());
    assert_eq!(inbox.original(1).unwrap(), original);
    assert_eq!(inbox.original_frame(1).unwrap(), query());
}
