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
