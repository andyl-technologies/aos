//! Real datagram and immutable original administrative custody regressions.

// crucible-lint: allow panic-shortcut -- These administrative mailbox tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::net::UnixDatagram;

use crucible_node_contract::{HashRef, Id, Phase, Position, U64};
use crucible_protocol::node_control::{
    NativeControlEdition, NativeCpuParkFacts, OwnerScope, ReceiptAcknowledgement,
};

use super::*;

fn preparation() -> NativePreparation {
    let id = |value| Id::new(value).unwrap();
    let hash = |domain: &str| HashRef {
        algorithm: "blake3-256".into(),
        domain: domain.into(),
        digest: "01".repeat(32),
    };
    NativePreparation {
        scope: OwnerScope {
            session: id("session/a"),
            incarnation: id("incarnation/a"),
            activation: id("activation/a"),
            node: id("node/a"),
            owner: id("owner/a"),
            world_generation: U64::new(1),
            owner_generation: U64::new(1),
            world_binding: hash("cnp.world-binding.v1"),
            owner_binding: hash("cnp.owner-binding.v1"),
        },
        boundary: Position {
            time_ps: U64::new(0),
            microstep: U64::new(0),
            phase: Phase::BoundaryControl,
        },
        maximum_commands: U64::new(8),
    }
}

fn pair(
    maximum_records: usize,
    maximum_bytes: usize,
) -> (NativeChannel, NativeAdministrativeMailbox) {
    let (host, provider) =
        NativeChannel::supervised_pair_for_edition(NativeControlEdition::OwnedCustody).unwrap();
    let mut provider = Some(provider);
    let mailbox = NativeAdministrativeMailbox::from_prepared(
        &mut provider,
        &preparation(),
        maximum_records,
        maximum_bytes,
    )
    .unwrap();
    assert!(provider.is_none());
    (host, mailbox)
}

#[test]
fn invalid_preflight_preserves_same_endpoint_and_unread_original_packet() {
    let (host, provider) =
        NativeChannel::supervised_pair_for_edition(NativeControlEdition::OwnedCustody).unwrap();
    let descriptor = provider.prepared_descriptor().as_raw_fd();
    let mut provider = Some(provider);
    assert!(host.send(&query()).unwrap());

    assert!(
        NativeAdministrativeMailbox::from_prepared(&mut provider, &preparation(), 0, 8192,)
            .is_err()
    );
    let retained = provider.as_ref().unwrap();
    assert_eq!(retained.prepared_descriptor().as_raw_fd(), descriptor);
    assert_eq!(retained.receive().unwrap(), Some(query()));

    let mut malformed = preparation();
    malformed.maximum_commands = U64::new(0);
    assert!(host.send(&query()).unwrap());
    assert!(
        NativeAdministrativeMailbox::from_prepared(&mut provider, &malformed, 4, 8192,).is_err()
    );
    assert_eq!(provider.as_ref().unwrap().receive().unwrap(), Some(query()));
}

#[test]
fn initial_preparation_is_retained_with_reply_credit_before_factory_validation() {
    let (host, endpoint) =
        NativeChannel::supervised_pair_for_edition(NativeControlEdition::OwnedCustody).unwrap();
    let mut endpoint = Some(endpoint);
    let scope = preparation().scope.identity_digest().unwrap();
    let mut mailbox =
        NativeAdministrativeMailbox::from_pinned_endpoint(&mut endpoint, scope, 4, 8192).unwrap();
    let original = NativeFrame::Prepare(Box::new(preparation()));
    assert!(host.send(&original).unwrap());

    assert_eq!(
        mailbox.receive().unwrap(),
        NativeAdministrativeReceive::Retained(1, NativeAdministrativeClass::Preparation,)
    );
    assert_eq!(mailbox.decode_original(1).unwrap(), original);
    let retained = mailbox.records.get(&1).unwrap();
    assert!(retained.reply_reserved);
    assert!(retained.reply_storage.capacity() >= MAXIMUM_PACKET_BYTES);
    assert!(endpoint.is_none());
    assert_eq!(
        mailbox.receive().unwrap(),
        NativeAdministrativeReceive::Empty
    );
}

fn query() -> NativeFrame {
    NativeFrame::QueryCpuPark(preparation().scope.identity_digest().unwrap())
}

fn reply() -> NativeFrame {
    // Codec fixture data only; this never qualifies a real CPU or node.
    NativeFrame::CpuPark(NativeCpuParkFacts {
        coverage: 1,
        cpu_count: 1,
        current_ps: U64::new(0),
        retired_count: U64::new(0),
        next_service_deadline_ps: None,
        pending_service_credit_ps: U64::new(0),
        prepared_scope_hash: preparation().scope.identity_digest().unwrap(),
        roster_sha256: [7; 32],
    })
}

#[test]
fn original_query_and_reply_bytes_survive_lost_credit_handle_and_repeated_send() {
    let (host, mut mailbox) = pair(8, 16 * 1024);
    host.send(&query()).unwrap();
    assert_eq!(
        mailbox.receive().unwrap(),
        NativeAdministrativeReceive::Retained(1, NativeAdministrativeClass::ReadOriginal)
    );
    let request = encode_frame_for_edition(host.edition(), &query()).unwrap();
    assert_eq!(mailbox.original(1).unwrap(), request);

    let first = mailbox.reserve_reply(1).unwrap();
    let retained = mailbox.retained_bytes;
    drop(first);
    assert!(mailbox.records.get(&1).unwrap().reply_reserved);
    let recovered = mailbox.reserve_reply(1).unwrap();
    assert_eq!(mailbox.retained_bytes, retained);
    mailbox.retain_reply(recovered, &reply()).unwrap();
    let snapshot = mailbox.snapshot(MAXIMUM_MAILBOX_BYTES).unwrap();
    assert!(
        snapshot
            .windows(request.len())
            .any(|bytes| bytes == request)
    );
    assert!(mailbox.snapshot(snapshot.len() - 1).is_err());
    assert_eq!(
        snapshot.len(),
        95 + 18
            + request.len()
            + encode_frame_for_edition(host.edition(), &reply())
                .unwrap()
                .len()
    );

    assert!(mailbox.send_reply(1).unwrap());
    assert_eq!(host.receive().unwrap(), Some(reply()));
    assert!(mailbox.send_reply(1).unwrap());
    assert_eq!(host.receive().unwrap(), Some(reply()));
    assert_eq!(mailbox.snapshot(snapshot.len()).unwrap(), snapshot);
    assert!(mailbox.reserve_reply(1).is_err());
}

#[test]
fn reply_credit_exhaustion_keeps_the_complete_request_unread() {
    let (host, mut mailbox) = pair(1, 2048);
    host.send(&query()).unwrap();
    assert_eq!(
        mailbox.receive().unwrap(),
        NativeAdministrativeReceive::Backpressure
    );
    assert_eq!(mailbox.channel.receive().unwrap(), Some(query()));
    assert!(mailbox.records.is_empty());
    assert_eq!(mailbox.retained_bytes, 0);
}

#[test]
fn identity_exhaustion_retains_original_record_and_reply_credit() {
    let (host, mut mailbox) = pair(1, 16 * 1024);
    host.send(&query()).unwrap();
    host.send(&query()).unwrap();
    mailbox.receive().unwrap();
    assert!(mailbox.records.get(&1).unwrap().reply_reserved);
    let retained_bytes = mailbox.retained_bytes;
    mailbox.reserve_reply(1).unwrap();
    assert_eq!(mailbox.retained_bytes, retained_bytes);

    assert_eq!(
        mailbox.receive().unwrap(),
        NativeAdministrativeReceive::Backpressure
    );
    assert_eq!(mailbox.channel.receive().unwrap(), Some(query()));
    assert_eq!(mailbox.records.len(), 1);
}

#[test]
fn malformed_complete_wire_is_retained_before_decoder_refusal() {
    let (sender, provider) = UnixDatagram::pair().unwrap();
    let provider = NativeChannel::from_prepared_socket_for_edition(
        provider,
        NativeControlEdition::OwnedCustody,
    )
    .unwrap();
    let mut provider = Some(provider);
    let mut mailbox =
        NativeAdministrativeMailbox::from_prepared(&mut provider, &preparation(), 4, 8192).unwrap();
    let original = b"original invalid datagram";
    sender.send(original).unwrap();
    assert!(matches!(
        mailbox.receive(),
        Err(NativeAdministrativeError::Malformed)
    ));
    assert_eq!(mailbox.original(1), Some(original.as_slice()));
    assert!(mailbox.failed);
    assert!(matches!(
        mailbox.receive(),
        Err(NativeAdministrativeError::Conflict)
    ));
    assert!(
        mailbox
            .snapshot(8192)
            .unwrap()
            .windows(original.len())
            .any(|bytes| bytes == original)
    );
}

#[test]
fn oversize_packet_remains_whole_in_kernel_custody() {
    let (sender, provider) = UnixDatagram::pair().unwrap();
    let provider = NativeChannel::from_prepared_socket_for_edition(
        provider,
        NativeControlEdition::OwnedCustody,
    )
    .unwrap();
    let mut provider = Some(provider);
    let mut mailbox =
        NativeAdministrativeMailbox::from_prepared(&mut provider, &preparation(), 4, 8192).unwrap();
    let original = vec![41_u8; MAXIMUM_PACKET_BYTES + 1];
    sender.send(&original).unwrap();
    assert!(matches!(
        mailbox.receive(),
        Err(NativeAdministrativeError::Oversized)
    ));
    assert!(mailbox.records.is_empty());
    let mut actual = vec![0_u8; original.len()];
    // SAFETY: the unit fixture deliberately observes the same still-owned
    // endpoint after refusal. The vector covers the entire original datagram.
    let length = unsafe {
        libc::recv(
            mailbox.channel.prepared_descriptor().as_raw_fd(),
            actual.as_mut_ptr().cast(),
            actual.len(),
            libc::MSG_DONTWAIT,
        )
    };
    assert_eq!(length as usize, original.len());
    assert_eq!(actual, original);
}

#[test]
fn foreign_reply_credit_and_changed_ack_are_refused_without_overwriting_history() {
    let (host, mut mailbox) = pair(4, 16 * 1024);
    let (other_host, mut other) = pair(4, 16 * 1024);
    host.send(&query()).unwrap();
    other_host.send(&query()).unwrap();
    mailbox.receive().unwrap();
    other.receive().unwrap();
    let foreign = other.reserve_reply(1).unwrap();
    assert!(mailbox.retain_reply(foreign, &reply()).is_err());
    assert!(mailbox.records.get(&1).unwrap().reply.is_none());

    let ack = ReceiptAcknowledgement {
        sequence: U64::new(1),
        command_digest: [3; 32],
        authorization_digest: [9; 32],
    };
    host.send(&NativeFrame::Acknowledge(ack.clone())).unwrap();
    assert_eq!(
        mailbox.receive().unwrap(),
        NativeAdministrativeReceive::Retained(2, NativeAdministrativeClass::AcknowledgeOriginal)
    );
    let credit = mailbox.reserve_reply(2).unwrap();
    let mut changed = ack.clone();
    changed.authorization_digest = [8; 32];
    assert!(
        mailbox
            .retain_reply(credit, &NativeFrame::Acknowledged(changed))
            .is_err()
    );
    assert!(mailbox.records.get(&2).unwrap().reply.is_none());
    let recovered = mailbox.reserve_reply(2).unwrap();
    mailbox
        .retain_reply(recovered, &NativeFrame::Acknowledged(ack.clone()))
        .unwrap();
    assert!(mailbox.send_reply(2).unwrap());
    assert_eq!(
        host.receive().unwrap(),
        Some(NativeFrame::Acknowledged(ack))
    );
}

#[test]
fn foreign_scope_is_retained_as_invalid_and_never_processed_as_query() {
    let (host, mut mailbox) = pair(4, 8192);
    let foreign = NativeFrame::QueryCpuPark([19; 32]);
    host.send(&foreign).unwrap();
    assert!(matches!(
        mailbox.receive(),
        Err(NativeAdministrativeError::Malformed)
    ));
    assert_eq!(
        mailbox.original(1).unwrap(),
        encode_frame_for_edition(host.edition(), &foreign).unwrap()
    );
    assert!(mailbox.reserve_reply(1).is_err());
}
