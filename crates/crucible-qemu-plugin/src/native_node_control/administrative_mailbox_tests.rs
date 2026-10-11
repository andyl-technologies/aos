//! Real datagram and immutable original administrative custody regressions.

// crucible-lint: allow panic-shortcut -- These administrative mailbox tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::net::UnixDatagram;

use crucible_node_contract::{HashRef, Id, Phase, Position, U64};
use crucible_protocol::node_control::{
    NativeControlEdition, NativeCpuParkFacts, OwnerScope, ReceiptAcknowledgement,
};

use super::*;

fn original_effect_pair() -> (
    NativeChannel,
    NativeAdministrativeMailbox,
    crucible_protocol::node_control::NativeEffectCompute,
    crucible_protocol::node_control::NativeEffectProgress,
) {
    use crucible_protocol::node_control::{
        NativeEffectCompute, NativeEffectProgress, NativeEffectProgressStatus,
    };
    let plan = preparation();
    let limit = Position {
        time_ps: U64::new(110),
        ..plan.boundary
    };
    let mut command = crucible_protocol::node_control::ExecutionCommand {
        sequence: U64::new(1),
        input_batch_hash: plan.scope.world_binding.clone(),
        scope: plan.scope,
        operation: Id::new("operation/1").unwrap(),
        grant: Id::new("grant/1").unwrap(),
        input_epoch: Id::new("input/epoch").unwrap(),
        input_batch: Id::new("batch/1").unwrap(),
        closed_input_prefix: limit,
        authorization_digest: [7; 32],
        kind: crucible_protocol::node_control::ExecutionKind::ExactRun {
            start: plan.boundary,
            limit,
            boundary_policy: crucible_protocol::node_control::BoundaryPolicy::HorizonPark,
        },
    };
    let batch = crucible_node_contract::InputBatch {
        schema_version: 1,
        execution_owner_id: command.scope.owner.clone(),
        input_epoch: command.input_epoch.clone(),
        batch_id: command.input_batch.clone(),
        batch_sequence: U64::new(1),
        events: Vec::new(),
        extensions: Default::default(),
    };
    command.input_batch_hash = batch.identity().unwrap();
    let original = NativeEffectCompute {
        command,
        effect_preparation: [8; 32],
        maximum_callbacks: 64,
        maximum_service_span: U64::new(1),
        input_batch_sequence: U64::new(1),
    };
    let evaluated = Position {
        time_ps: U64::new(50),
        microstep: U64::new(0),
        phase: Phase::Reaction,
    };
    let result = NativeEffectProgress {
        scope: original.command.scope.identity_digest().unwrap(),
        effect_preparation: original.effect_preparation,
        grant_digest: original.command.authorization_digest,
        command_digest: original.command.identity_digest().unwrap(),
        sequence: original.command.sequence,
        cut_id: U64::new(1),
        raw_before: U64::new(0),
        raw_after: U64::new(1),
        evaluated,
        evaluation_id: U64::new(1),
        evaluation_generation: U64::new(26),
        resulting: evaluated,
        returned_service_count: U64::new(1),
        status: NativeEffectProgressStatus::PartialPrefix,
        end_result: 0,
    };
    result.validate_against(&original).unwrap();
    let (host, native) =
        NativeChannel::supervised_pair_for_edition(NativeControlEdition::FiniteEffect).unwrap();
    let mut endpoint = Some(native);
    let mailbox =
        NativeAdministrativeMailbox::from_pinned_endpoint(&mut endpoint, result.scope, 8, 65536)
            .unwrap();
    (host, mailbox, original, result)
}

#[test]
fn original_effect_progress_uses_retained_credit_and_identical_cached_bytes() {
    // The result is modeled; actual datagrams and reservation custody exercise
    // publication only, without manufacturing source execution authority.
    let (host, mut mailbox, original, result) = original_effect_pair();
    let request = NativeFrame::EffectCompute(Box::new(original));
    let reply = NativeFrame::EffectProgress(Box::new(result.clone()));
    assert!(host.send(&request).unwrap());
    assert!(matches!(
        mailbox.receive().unwrap(),
        NativeAdministrativeReceive::Retained(1, NativeAdministrativeClass::Modeled)
    ));
    let bytes = mailbox.original(1).unwrap().to_vec();
    let credit = mailbox.reserve_construction_reply(1).unwrap();

    mailbox.retain_reply(credit, &reply).unwrap();
    assert!(mailbox.send_reply(1).unwrap());
    assert_eq!(host.receive().unwrap(), Some(reply.clone()));
    assert!(mailbox.send_reply(1).unwrap());
    assert_eq!(host.receive().unwrap(), Some(reply));
    assert_eq!(mailbox.original(1).unwrap(), bytes);

    let mut changed = result;
    changed.evaluation_generation = U64::new(27);
    let credit = NativeAdministrativeReplyCredit {
        owner: Arc::clone(&mailbox.owner),
        cursor: 1,
    };
    assert!(
        mailbox
            .retain_reply(credit, &NativeFrame::EffectProgress(Box::new(changed)))
            .is_err()
    );
    assert!(mailbox.failed);
    assert!(host.receive().unwrap().is_none());
    assert_eq!(mailbox.original(1).unwrap(), bytes);
}

#[test]
fn original_effect_progress_refuses_foreign_grant_command_scope_and_counts() {
    for field in 0..7 {
        let (host, mut mailbox, original, mut result) = original_effect_pair();
        match field {
            0 => result.command_digest[0] ^= 1,
            1 => result.grant_digest[0] ^= 1,
            2 => result.effect_preparation[0] ^= 1,
            3 => result.scope[0] ^= 1,
            4 => result.sequence = U64::new(2),
            5 => result.returned_service_count = U64::new(2),
            _ => result.evaluated.time_ps = U64::new(120),
        }
        assert!(
            host.send(&NativeFrame::EffectCompute(Box::new(original)))
                .unwrap()
        );
        assert!(matches!(
            mailbox.receive().unwrap(),
            NativeAdministrativeReceive::Retained(1, _)
        ));
        let bytes = mailbox.original(1).unwrap().to_vec();
        let credit = mailbox.reserve_construction_reply(1).unwrap();

        assert!(
            mailbox
                .retain_reply(credit, &NativeFrame::EffectProgress(Box::new(result)))
                .is_err()
        );
        assert!(host.receive().unwrap().is_none());
        assert!(mailbox.records.get(&1).unwrap().reply.is_none());
        assert_eq!(mailbox.original(1).unwrap(), bytes);
    }
}

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

#[test]
fn unpublished_reply_credit_revalidates_actual_backing_without_consuming_original() {
    let (host, mut mailbox, original, result) = original_effect_pair();
    let request = NativeFrame::EffectCompute(Box::new(original));
    assert!(host.send(&request).unwrap());
    assert!(matches!(
        mailbox.receive().unwrap(),
        NativeAdministrativeReceive::Retained(1, _)
    ));
    let bytes = mailbox.original(1).unwrap().to_vec();
    let credit = mailbox.reserve_construction_reply(1).unwrap();

    assert!(mailbox.validate_unpublished_credit(&credit).is_ok());
    assert!(mailbox.validate_unpublished_credit(&credit).is_ok());
    assert_eq!(mailbox.original(1).unwrap(), bytes);
    let foreign = NativeAdministrativeReplyCredit {
        owner: Arc::new(()),
        cursor: 1,
    };
    assert!(mailbox.validate_unpublished_credit(&foreign).is_err());
    let missing = NativeAdministrativeReplyCredit {
        owner: Arc::clone(&mailbox.owner),
        cursor: 2,
    };
    assert!(mailbox.validate_unpublished_credit(&missing).is_err());

    let backing = std::mem::take(&mut mailbox.records.get_mut(&1).unwrap().reply_storage);
    assert!(mailbox.validate_unpublished_credit(&credit).is_err());
    mailbox.records.get_mut(&1).unwrap().reply_storage = backing;
    assert!(mailbox.validate_unpublished_credit(&credit).is_ok());
    mailbox
        .retain_reply(credit, &NativeFrame::EffectProgress(Box::new(result)))
        .unwrap();
    let historical = NativeAdministrativeReplyCredit {
        owner: Arc::clone(&mailbox.owner),
        cursor: 1,
    };
    assert!(mailbox.validate_unpublished_credit(&historical).is_err());
    assert_eq!(mailbox.original(1).unwrap(), bytes);
}
