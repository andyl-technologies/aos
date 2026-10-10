//! Real datagram construction-reducer tests with model-only native source facts.
//!
//! These tests establish original transport/journal custody, not native device
//! qualification, construction callback safety or a whole-node Ready guarantee.

use super::super::administrative_mailbox::NativeAdministrativeReceive;
use super::super::initialization_custody::tests::fixture;
use super::*;
use crucible_protocol::node_control::{
    NativeChannel, NativeControlEdition, NativeInitializationAcknowledgement,
};

fn inbox(initializer: &InitializationCustody) -> (NativeChannel, Arc<NativeAdministrativeInbox>) {
    let (host, channel) =
        NativeChannel::supervised_pair_for_edition(NativeControlEdition::Construction).unwrap();
    let mut channel = Some(channel);
    let inbox = NativeAdministrativeInbox::from_pinned_endpoint(
        &mut channel,
        initializer.scope,
        false,
        16,
        128 * 1024,
    )
    .unwrap();
    assert!(channel.is_none());
    (host, Arc::new(inbox))
}

fn receive(host: &NativeChannel, actor: &NativeAdministrativeInbox, frame: &NativeFrame) -> u64 {
    assert!(host.send(frame).unwrap());
    let NativeAdministrativeReceive::Retained(cursor, _) = actor.receive_one().unwrap() else {
        panic!("the original datagram must have retained custody");
    };
    cursor
}

#[test]
fn acknowledged_successor_query_waits_in_original_custody_until_native_cache_exists() {
    extern "C" fn no_query(
        _scope: *const u8,
        _sequence: u64,
        _cut: *const u8,
        _output: *mut super::super::preparation_successor_abi::NativePreparationSuccessorAbi,
    ) -> i32 {
        -libc::ENOTSUP
    }
    extern "C" fn no_read(
        _scope: *const u8,
        _sequence: u64,
        _digest: *const u8,
        _offset: u64,
        _output: *mut u8,
        _capacity: u32,
        _copied: *mut u32,
    ) -> i32 {
        -libc::ENOTSUP
    }
    let (initializer, command, native_receipt) = fixture();
    initializer.retain(command.clone()).unwrap();
    let receipt = initializer.record_receipt(native_receipt).unwrap();
    initializer
        .acknowledge(&NativeInitializationAcknowledgement {
            prepared_scope_hash: initializer.scope,
            initialization_commitment: initializer.commitment,
            sequence: command.sequence,
            command_digest: command.identity_digest().unwrap(),
        })
        .unwrap();
    let initializer = Arc::new(initializer);
    let (host, actor) = inbox(&initializer);
    let successor = Arc::new(PreparationSuccessorCustody::new(no_query, no_read));
    let reducer = NativeConstructionReducer::new(
        Arc::clone(&actor),
        Arc::clone(&initializer),
        Some(successor),
        8,
    )
    .unwrap();
    let frame = NativeFrame::QueryPreparationSuccessor(
        crucible_protocol::node_control::NativePreparationSuccessorQuery {
            prepared_scope_hash: initializer.scope,
            initialization_sequence: receipt.sequence,
            original_cut_digest: receipt.original_cut_digest,
            offset: crucible_node_contract::U64::new(0),
        },
    );
    let cursor = receive(&host, &actor, &frame);

    assert!(!reducer.try_admit(&actor, cursor).unwrap());
    assert!(!reducer.recover().unwrap());
    assert!(!reducer.try_admit(&actor, cursor).unwrap());
    assert_eq!(host.receive().unwrap(), None);
    assert_eq!(actor.original_frame(cursor).unwrap(), frame);
    assert!(initializer.permits_execution_transport());
    let retained = reducer.state.lock().unwrap();
    assert!(!retained.failed);
    assert_eq!(retained.requests.len(), 1);
    assert_eq!(
        retained.requests[0].credit.as_ref().unwrap().cursor(),
        cursor
    );
    assert!(!retained.requests[0].replied);
    assert!(!retained.requests[0].published);
}

#[test]
fn real_original_storage_precedes_home_command_and_lost_reply_recovers_without_rerun() {
    let (initializer, command, raw_receipt) = fixture();
    let initializer = Arc::new(initializer);
    let (host, actor) = inbox(&initializer);
    let reducer =
        NativeConstructionReducer::new(Arc::clone(&actor), Arc::clone(&initializer), None, 8)
            .unwrap();
    let frame = NativeFrame::Initialize(Box::new(command.clone()));
    let cursor = receive(&host, &actor, &frame);

    reducer.admit(&actor, cursor).unwrap();

    assert_eq!(actor.original_frame(cursor).unwrap(), frame);
    let state = reducer.state.lock().unwrap();
    assert_eq!(state.requests[0].credit.as_ref().unwrap().cursor(), cursor);
    assert!(!state.requests[0].replied);
    drop(state);
    assert_eq!(
        initializer.command().unwrap().sequence,
        command.sequence.get()
    );
    assert_eq!(host.receive().unwrap(), None);
    assert!(!initializer.permits_execution_transport());

    let receipt = initializer.record_receipt(raw_receipt).unwrap();
    reducer.recover().unwrap();
    let expected = NativeFrame::InitializationStopped(Box::new(receipt));
    assert_eq!(host.receive().unwrap(), Some(expected.clone()));
    assert!(initializer.command().is_none());

    // A lost response is recovered from retained bytes under the same cursor.
    reducer.admit(&actor, cursor).unwrap();
    assert_eq!(host.receive().unwrap(), Some(expected.clone()));
    assert!(initializer.command().is_none());
    let retry = receive(&host, &actor, &frame);
    reducer.admit(&actor, retry).unwrap();
    assert_eq!(host.receive().unwrap(), Some(expected));
    assert!(initializer.command().is_none());
}

#[test]
fn original_ack_is_journal_checked_and_recovers_same_reply_without_second_effect() {
    let (initializer, command, raw_receipt) = fixture();
    let initializer = Arc::new(initializer);
    let (host, actor) = inbox(&initializer);
    let reducer =
        NativeConstructionReducer::new(Arc::clone(&actor), Arc::clone(&initializer), None, 8)
            .unwrap();
    let initialize = NativeFrame::Initialize(Box::new(command.clone()));
    let cursor = receive(&host, &actor, &initialize);
    reducer.admit(&actor, cursor).unwrap();
    initializer.record_receipt(raw_receipt).unwrap();
    reducer.recover().unwrap();
    host.receive().unwrap();
    assert!(!initializer.permits_execution_transport());
    let ack = NativeInitializationAcknowledgement {
        prepared_scope_hash: initializer.scope,
        initialization_commitment: initializer.commitment,
        sequence: command.sequence,
        command_digest: command.identity_digest().unwrap(),
    };
    let frame = NativeFrame::AcknowledgeInitialization(ack.clone());
    let cursor = receive(&host, &actor, &frame);

    reducer.admit(&actor, cursor).unwrap();

    assert!(initializer.permits_execution_transport());
    let expected = NativeFrame::InitializationAcknowledged(ack);
    assert_eq!(host.receive().unwrap(), Some(expected.clone()));
    reducer.admit(&actor, cursor).unwrap();
    assert_eq!(host.receive().unwrap(), Some(expected));
    assert!(initializer.command().is_none());
}

#[test]
fn failed_transition_retains_request_credit_and_closes_reducer_without_home_permission() {
    let (initializer, command, _) = fixture();
    let initializer = Arc::new(initializer);
    let (host, actor) = inbox(&initializer);
    let reducer =
        NativeConstructionReducer::new(Arc::clone(&actor), Arc::clone(&initializer), None, 8)
            .unwrap();
    let ack = NativeInitializationAcknowledgement {
        prepared_scope_hash: initializer.scope,
        initialization_commitment: initializer.commitment,
        sequence: command.sequence,
        command_digest: command.identity_digest().unwrap(),
    };
    let frame = NativeFrame::AcknowledgeInitialization(ack);
    let cursor = receive(&host, &actor, &frame);

    assert!(reducer.admit(&actor, cursor).is_err());

    assert_eq!(actor.original_frame(cursor).unwrap(), frame);
    let state = reducer.state.lock().unwrap();
    assert!(state.failed);
    assert!(state.requests[0].credit.is_some());
    drop(state);
    assert!(!initializer.permits_execution_transport());
    assert!(initializer.command().is_none());
    assert_eq!(host.receive().unwrap(), None);
}

#[test]
fn ledger_credit_refusal_preserves_original_packet_without_native_admission() {
    let (initializer, command, _) = fixture();
    let initializer = Arc::new(initializer);
    let (host, actor) = inbox(&initializer);
    let reducer =
        NativeConstructionReducer::new(Arc::clone(&actor), Arc::clone(&initializer), None, 1)
            .unwrap();
    let query = NativeFrame::QueryInitialization(
        crucible_protocol::node_control::NativeInitializationQuery {
            prepared_scope_hash: initializer.scope,
            initialization_commitment: initializer.commitment,
        },
    );
    let cursor = receive(&host, &actor, &query);
    reducer.admit(&actor, cursor).unwrap();
    host.receive().unwrap();
    let frame = NativeFrame::Initialize(Box::new(command));
    let cursor = receive(&host, &actor, &frame);

    assert!(reducer.admit(&actor, cursor).is_err());

    assert_eq!(actor.original_frame(cursor).unwrap(), frame);
    assert!(initializer.command().is_none());
    assert!(!initializer.permits_execution_transport());
}

#[test]
fn identical_scope_on_another_actual_inbox_does_not_adopt_original_native_custody() {
    let (initializer, command, _) = fixture();
    let initializer = Arc::new(initializer);
    let (_, original) = inbox(&initializer);
    let (foreign_host, foreign) = inbox(&initializer);
    let reducer =
        NativeConstructionReducer::new(Arc::clone(&original), Arc::clone(&initializer), None, 8)
            .unwrap();
    let cursor = receive(
        &foreign_host,
        &foreign,
        &NativeFrame::Initialize(Box::new(command)),
    );

    assert!(reducer.admit(&foreign, cursor).is_err());

    assert!(initializer.command().is_none());
    assert!(reducer.state.lock().unwrap().requests.is_empty());
    assert!(foreign.original(cursor).is_ok());
}

#[test]
fn busy_original_packet_stays_pending_before_command_or_credit_admission() {
    let (initializer, command, _) = fixture();
    let initializer = Arc::new(initializer);
    let (host, actor) = inbox(&initializer);
    let reducer =
        NativeConstructionReducer::new(Arc::clone(&actor), Arc::clone(&initializer), None, 8)
            .unwrap();
    let frame = NativeFrame::Initialize(Box::new(command));
    let cursor = receive(&host, &actor, &frame);
    let original_bytes = actor.original(cursor).unwrap();
    let held = actor.test_hold_mailbox();

    assert!(!reducer.try_admit(&actor, cursor).unwrap());
    assert!(reducer.state.lock().unwrap().requests.is_empty());
    assert!(initializer.command().is_none());
    assert!(host.receive().unwrap().is_none());
    drop(held);

    assert_eq!(actor.original(cursor).unwrap(), original_bytes);
    assert!(reducer.try_admit(&actor, cursor).unwrap());
    assert_eq!(reducer.state.lock().unwrap().requests[0].cursor, cursor);
    assert!(initializer.command().is_some());
    assert!(host.receive().unwrap().is_none());
}

#[test]
fn native_reply_seam_does_not_wait_for_busy_inbox_or_abandon_original_credit() {
    let (initializer, command, raw_receipt) = fixture();
    let initializer = Arc::new(initializer);
    let (host, actor) = inbox(&initializer);
    let reducer =
        NativeConstructionReducer::new(Arc::clone(&actor), Arc::clone(&initializer), None, 8)
            .unwrap();
    let cursor = receive(&host, &actor, &NativeFrame::Initialize(Box::new(command)));
    reducer.admit(&actor, cursor).unwrap();
    let receipt = initializer.record_receipt(raw_receipt).unwrap();
    let locked_inbox = actor.test_hold_mailbox();

    reducer.recover().unwrap();

    let state = reducer.state.lock().unwrap();
    assert!(state.requests[0].credit.is_some());
    assert!(!state.requests[0].replied);
    assert!(!state.failed);
    drop(state);
    assert!(initializer.command().is_none());
    assert_eq!(host.receive().unwrap(), None);
    drop(locked_inbox);

    reducer.recover().unwrap();
    assert_eq!(
        host.receive().unwrap(),
        Some(NativeFrame::InitializationStopped(Box::new(receipt)))
    );
    assert!(initializer.command().is_none());
}

#[test]
fn socket_backpressure_retries_only_cached_original_receipt() {
    let (initializer, command, raw_receipt) = fixture();
    let initializer = Arc::new(initializer);
    let (host, actor) = inbox(&initializer);
    let reducer =
        NativeConstructionReducer::new(Arc::clone(&actor), Arc::clone(&initializer), None, 8)
            .unwrap();
    let cursor = receive(&host, &actor, &NativeFrame::Initialize(Box::new(command)));
    reducer.admit(&actor, cursor).unwrap();
    let receipt = initializer.record_receipt(raw_receipt).unwrap();
    assert!(reducer.recover().unwrap());
    let expected = NativeFrame::InitializationStopped(Box::new(receipt));
    assert_eq!(host.receive().unwrap(), Some(expected.clone()));

    let mut queued = 0;
    while actor.send_reply(cursor).unwrap() {
        queued += 1;
        assert!(
            queued < 4096,
            "the actual Unix datagram buffer must be bounded"
        );
    }
    assert!(queued > 0);
    reducer.state.lock().unwrap().requests[0].published = false;

    assert!(!reducer.recover().unwrap());

    let state = reducer.state.lock().unwrap();
    assert!(state.requests[0].replied);
    assert!(!state.requests[0].published);
    assert!(!state.failed);
    drop(state);
    assert!(initializer.command().is_none());
    for _ in 0..queued {
        assert_eq!(host.receive().unwrap(), Some(expected.clone()));
    }
    assert_eq!(host.receive().unwrap(), None);

    assert!(reducer.recover().unwrap());
    assert_eq!(host.receive().unwrap(), Some(expected));
    assert!(initializer.command().is_none());
}

#[test]
fn busy_native_journal_retains_original_cursor_without_duplicate_home_admission() {
    let (initializer, command, _) = fixture();
    let initializer = Arc::new(initializer);
    let (host, actor) = inbox(&initializer);
    let reducer =
        NativeConstructionReducer::new(Arc::clone(&actor), Arc::clone(&initializer), None, 8)
            .unwrap();
    let frame = NativeFrame::Initialize(Box::new(command.clone()));
    let cursor = receive(&host, &actor, &frame);
    let native_journal_borrow = reducer.state.lock().unwrap();

    assert!(!reducer.try_admit(&actor, cursor).unwrap());

    assert_eq!(actor.original_frame(cursor).unwrap(), frame);
    assert!(native_journal_borrow.requests.is_empty());
    assert!(!native_journal_borrow.failed);
    assert!(initializer.command().is_none());
    drop(native_journal_borrow);

    assert!(reducer.try_admit(&actor, cursor).unwrap());
    assert_eq!(reducer.state.lock().unwrap().requests.len(), 1);
    assert_eq!(
        initializer.command().unwrap().sequence,
        command.sequence.get()
    );
    assert!(reducer.try_admit(&actor, cursor).unwrap());
    assert_eq!(reducer.state.lock().unwrap().requests.len(), 1);
}
