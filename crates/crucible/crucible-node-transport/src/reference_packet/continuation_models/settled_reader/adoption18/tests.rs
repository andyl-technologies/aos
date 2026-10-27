//! Exercises actual decoded-field custody and fresh socket ownership transfer.

// crucible-lint: allow panic-shortcut -- actual model transfer controls assert retained ownership.
#![expect(
    clippy::unwrap_used,
    reason = "actual paired model and socket observations"
)]

use super::super::super::*;
use super::*;
use crate::protocol_snapshot::owned11::{json_value::HistoricalJsonLimits, typed::Ledger};
use crate::retained_metadata::records::{MetadataRecordBank, ValidatedMetadataRecords};
use std::os::fd::AsRawFd;

fn original() -> (PacketProgram, UnixDatagram) {
    let (effect, peer) = UnixDatagram::pair().unwrap();
    let events = [(4, 5, "before"), (8, 9, "after")]
        .into_iter()
        .map(|(evaluation, completion, payload)| {
            let mut bytes = Vec::with_capacity(31);
            bytes.extend_from_slice(payload.as_bytes());
            PacketEvent {
                id: Id::new(payload).unwrap(),
                evaluation: Position::new(U64::new(evaluation), U64::new(0), Phase::Reaction),
                completion: Position::new(U64::new(completion), U64::new(0), Phase::Publication),
                payload: Some(Bytes::new(bytes)),
            }
        })
        .collect();
    (PacketProgram::new(events, effect).unwrap(), peer)
}

fn decode(actual: &PacketProgram) -> PacketSettledModel17Data {
    let input = serde_json::to_vec(&("producer", actual.borrowed_settled_model_data())).unwrap();
    let mut bank = MetadataRecordBank::reserve(1024).unwrap();
    let mut observer = MetadataObserver::recording(&mut bank);
    observer.observe(actual).unwrap();
    let facts = observer.finish();
    let encoded = serde_json::to_vec(&bank).unwrap();
    let rows =
        ValidatedMetadataRecords::validate(&encoded, facts.capacity_records, 64 * 1024 * 1024)
            .unwrap();
    let limits = HistoricalJsonLimits {
        maximum_input_bytes: 65_536,
        maximum_nodes: 8192,
        maximum_depth: 64,
        maximum_owned_backing_bytes: 64 * 1024 * 1024,
        maximum_tree_entries: 4096,
    };
    let mut preflight = Ledger::new(rows.rows(), limits);
    assert!(
        super::super::read_settled_model17_data(&input, &mut preflight, false)
            .unwrap()
            .is_none()
    );
    assert!(preflight.rows.next().is_none());
    let mut build = Ledger::new(rows.rows(), limits);
    let decoded = super::super::read_settled_model17_data(&input, &mut build, true)
        .unwrap()
        .unwrap();
    assert!(build.rows.next().is_none());
    decoded.authenticate_current_data().unwrap();
    decoded
}

fn definition(actual: &PacketProgram) -> PacketConnectedSourceProgram {
    PacketConnectedSourceProgram::Producer {
        program: actual.definition(),
    }
}

#[test]
fn producer_transfer_preserves_original_backing_grants_and_actual_continuation() {
    let (mut actual, old_peer) = original();
    actual.open_gate().unwrap();
    let operation = Id::new("original-operation").unwrap();
    let start = actual.reached;
    let cut = Position::new(U64::new(6), U64::new(0), Phase::BoundaryControl);
    actual.execute(operation.clone(), start, cut).unwrap();
    let mut trace = [0; 32];
    let count = old_peer.recv(&mut trace).unwrap();
    assert_eq!(&trace[..count], b"\x01before");
    actual
        .retire(&operation, &[Id::new("before").unwrap()])
        .unwrap();
    let mut model = Some(decode(&actual));
    let CurrentModel::Producer(state) = &model.as_ref().unwrap().state else {
        panic!("expected producer");
    };
    let events_pointer = state.events.as_ptr();
    let payload_pointer = state.events[1]
        .payload
        .as_ref()
        .unwrap()
        .as_slice()
        .as_ptr();
    let events_capacity = state.events.capacity();
    let outputs_capacity = state.outputs.capacity();
    let payload_capacity = state.events[1]
        .payload
        .as_ref()
        .unwrap()
        .allocation_capacity();

    let mut attempt = None;
    CurrentModel18Adoption::prepare_into(&mut model, &definition(&actual), &mut attempt).unwrap();
    assert!(model.is_none());
    let attempt = attempt.as_mut().unwrap();
    let bytes = attempt.retained_requested_storage_data(usize::MAX).unwrap();
    assert_eq!(
        attempt.retained_requested_storage_data(bytes).unwrap(),
        bytes
    );
    assert!(attempt.retained_requested_storage_data(bytes - 1).is_err());
    let (effect, fresh_peer) = UnixDatagram::pair().unwrap();
    let descriptor = effect.as_raw_fd();
    let mut effect = Some(effect);
    attempt.bind_effect_socket(&mut effect).unwrap();
    assert!(effect.is_none());
    assert_eq!(
        attempt.retained_requested_storage_data(usize::MAX).unwrap(),
        bytes
    );
    let mut output = None;
    attempt.take_completed_into(&mut output).unwrap();
    assert!(attempt.take_completed_into(&mut None).is_err());
    let Some(CurrentModel18Program::Producer(mut restored)) = output else {
        panic!("expected original producer transfer");
    };

    assert_eq!(restored.effect_socket.as_raw_fd(), descriptor);
    assert_eq!(restored.events.as_ptr(), events_pointer);
    assert_eq!(restored.events.capacity(), events_capacity);
    assert_eq!(restored.outputs.capacity(), outputs_capacity);
    assert_eq!(
        restored.events[1]
            .payload
            .as_ref()
            .unwrap()
            .as_slice()
            .as_ptr(),
        payload_pointer
    );
    assert_eq!(
        restored.events[1]
            .payload
            .as_ref()
            .unwrap()
            .allocation_capacity(),
        payload_capacity
    );
    assert_eq!(restored.inventory(), actual.inventory());
    assert_eq!(restored.grants, actual.grants);
    assert_eq!(restored.retired, actual.retired);
    assert_eq!(restored.gate_closed, actual.gate_closed);
    restored
        .retire(&operation, &[Id::new("before").unwrap()])
        .unwrap();
    assert!(restored.retire(&operation, &[]).is_err());
    let next = Id::new("continued-operation").unwrap();
    let start = restored.reached;
    let limit = Position::new(U64::new(10), U64::new(0), Phase::BoundaryControl);
    restored.execute(next, start, limit).unwrap();
    let count = fresh_peer.recv(&mut trace).unwrap();
    assert_eq!(&trace[..count], b"\x01after");
    assert_eq!(restored.next_event, 2);
    assert_eq!(restored.packet_effects, 2);
}

#[test]
fn refused_definition_retains_model_and_socket_and_cannot_replace_attempt() {
    let (actual, _peer) = original();
    let mut wrong = actual.definition();
    wrong.events[0].payload = None;
    let mut model = Some(decode(&actual));
    let mut attempt = None;
    assert!(
        CurrentModel18Adoption::prepare_into(
            &mut model,
            &PacketConnectedSourceProgram::Producer { program: wrong },
            &mut attempt,
        )
        .is_err()
    );
    assert!(model.is_none());
    let retained = attempt.as_ref().unwrap();
    assert!(retained.failed);
    assert!(retained.model.is_some());
    let bytes = retained
        .retained_requested_storage_data(usize::MAX)
        .unwrap();
    let mut replacement = Some(decode(&actual));
    assert!(
        CurrentModel18Adoption::prepare_into(&mut replacement, &definition(&actual), &mut attempt)
            .is_err()
    );
    assert!(replacement.is_some());
    let (socket, _peer) = UnixDatagram::pair().unwrap();
    let descriptor = socket.as_raw_fd();
    let mut socket = Some(socket);
    assert!(
        attempt
            .as_mut()
            .unwrap()
            .bind_effect_socket(&mut socket)
            .is_err()
    );
    assert_eq!(socket.as_ref().unwrap().as_raw_fd(), descriptor);
    assert_eq!(
        attempt
            .as_ref()
            .unwrap()
            .retained_requested_storage_data(usize::MAX)
            .unwrap(),
        bytes
    );
}

#[test]
fn failed_socket_original_survives_transfer_without_replaying_uncertain_effect() {
    let (mut actual, peer) = original();
    drop(peer);
    actual.open_gate().unwrap();
    let operation = Id::new("uncertain-original").unwrap();
    let start = actual.reached;
    let limit = Position::new(U64::new(6), U64::new(0), Phase::BoundaryControl);
    assert!(actual.execute(operation.clone(), start, limit).is_err());
    assert!(actual.failed);
    assert!(!actual.grants[&operation].complete);
    let mut model = Some(decode(&actual));
    assert!(
        model
            .as_ref()
            .unwrap()
            .authenticate_settled_adoption_eligibility_data()
            .is_err()
    );
    let mut attempt = None;
    CurrentModel18Adoption::prepare_into(&mut model, &definition(&actual), &mut attempt).unwrap();
    assert!(model.is_none());
    let attempt = attempt.as_mut().unwrap();
    let (socket, fresh_peer) = UnixDatagram::pair().unwrap();
    fresh_peer.set_nonblocking(true).unwrap();
    attempt.bind_effect_socket(&mut Some(socket)).unwrap();
    let mut completed = None;
    attempt.take_completed_into(&mut completed).unwrap();
    let Some(CurrentModel18Program::Producer(mut restored)) = completed else {
        panic!("expected failed producer history");
    };
    assert!(restored.failed);
    assert_eq!(restored.grants, actual.grants);
    assert_eq!(restored.retired, actual.retired);
    assert_eq!(restored.inventory(), actual.inventory());
    assert!(restored.execute(operation.clone(), start, limit).is_err());
    assert!(
        restored
            .execute(Id::new("replacement-operation").unwrap(), start, limit)
            .is_err()
    );
    assert_eq!(restored.grants, actual.grants);
    assert_eq!(restored.next_event, 0);
    assert_eq!(restored.packet_effects, 0);
    let mut bytes = [0; 32];
    assert_eq!(
        fresh_peer.recv(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn absent_input_retains_spent_attempt_without_taking_socket() {
    let (actual, _peer) = original();
    let mut model = None;
    let mut attempt = None;
    assert!(
        CurrentModel18Adoption::prepare_into(&mut model, &definition(&actual), &mut attempt)
            .is_err()
    );
    let failed = attempt.as_mut().unwrap();
    assert!(failed.failed);
    assert!(failed.model.is_none());
    let (socket, _peer) = UnixDatagram::pair().unwrap();
    let mut socket = Some(socket);
    assert!(failed.bind_effect_socket(&mut socket).is_err());
    assert!(socket.is_some());
    let mut replacement = Some(decode(&actual));
    assert!(
        CurrentModel18Adoption::prepare_into(&mut replacement, &definition(&actual), &mut attempt)
            .is_err()
    );
    assert!(replacement.is_some());
}

#[test]
fn absent_socket_foreign_origin_and_occupied_transfer_preserve_original_slots() {
    let (actual, _peer) = original();
    let mut model = Some(decode(&actual));
    let mut attempt = None;
    CurrentModel18Adoption::prepare_into(&mut model, &definition(&actual), &mut attempt).unwrap();
    let attempt = attempt.as_mut().unwrap();
    assert!(attempt.bind_effect_socket(&mut None).is_err());
    assert!(attempt.model.is_some());
    let (socket, _peer) = UnixDatagram::pair().unwrap();
    let mut socket = Some(socket);
    let original_pid = attempt.creator;
    attempt.creator = original_pid.wrapping_add(1);
    assert!(attempt.bind_effect_socket(&mut socket).is_err());
    assert!(socket.is_some());
    assert!(attempt.retained_requested_storage_data(usize::MAX).is_err());
    attempt.creator = original_pid;
    let original_thread = attempt.thread;
    attempt.thread = std::thread::spawn(|| std::thread::current().id())
        .join()
        .unwrap();
    assert!(attempt.bind_effect_socket(&mut socket).is_err());
    assert!(socket.is_some());
    attempt.thread = original_thread;
    attempt.bind_effect_socket(&mut socket).unwrap();
    let (second, _peer) = UnixDatagram::pair().unwrap();
    let mut second = Some(second);
    assert!(attempt.bind_effect_socket(&mut second).is_err());
    assert!(second.is_some());
    let (other, _peer) = original();
    let mut output = Some(CurrentModel18Program::Producer(other));
    assert!(attempt.take_completed_into(&mut output).is_err());
    assert!(attempt.completed.is_some());
    assert!(!attempt.transferred);
    output = None;
    attempt.take_completed_into(&mut output).unwrap();
    assert!(attempt.transferred);
    assert!(attempt.completed.is_none());
    assert!(output.is_some());
}

#[test]
fn adoption18_construction_prices_actual_backing_and_repeats_at_its_whole_limit() {
    let (actual, _peer) = original();
    let decoded = decode(&actual);
    let before = serde_json::to_vec(&decoded.borrowed_program17_data()).unwrap();
    assert_eq!(
        decoded
            .adoption18_quote_formatter_temporary_data(0)
            .unwrap(),
        0
    );
    let row = decoded.adoption18_construction_data(usize::MAX).unwrap();
    let terms = row.requested_terms_data();
    assert_eq!(terms.iter().sum::<usize>(), row.requested_bytes());
    assert_eq!(terms[0], size_of::<Option<CurrentModel18Adoption>>());
    assert_eq!(
        terms[1],
        decoded.retained_requested_storage_data(usize::MAX).unwrap()
            - size_of::<PacketSettledModel17Data>()
    );
    assert!(terms[2] > 0);
    assert!(terms[3] > size_of::<PacketProgram>());
    assert!(terms[4] > 0);
    assert_eq!(
        decoded
            .adoption18_construction_data(row.requested_bytes())
            .unwrap(),
        row
    );
    assert!(
        decoded
            .adoption18_construction_data(row.requested_bytes() - 1)
            .is_err()
    );
    assert_eq!(
        serde_json::to_vec(&decoded.borrowed_program17_data()).unwrap(),
        before
    );

    let mut model = Some(decoded);
    let mut attempt = None;
    CurrentModel18Adoption::prepare_into(&mut model, &definition(&actual), &mut attempt).unwrap();
    assert!(
        attempt
            .as_ref()
            .unwrap()
            .retained_requested_storage_data(usize::MAX)
            .unwrap()
            <= terms[0] + terms[1]
    );
}

#[test]
fn adoption18_construction_tracks_spare_backing_and_complete_event_population() {
    let (mut actual, _peer) = original();
    let before = decode(&actual)
        .adoption18_construction_data(usize::MAX)
        .unwrap();
    let mut payload = Vec::with_capacity(4097);
    payload.extend_from_slice(b"after");
    actual.events[1].payload = Some(Bytes::new(payload));
    let spare = decode(&actual)
        .adoption18_construction_data(usize::MAX)
        .unwrap();
    assert!(spare.requested_terms_data()[1] >= before.requested_terms_data()[1] + 4097 - 31);
    assert_eq!(
        spare.requested_terms_data()[2],
        before.requested_terms_data()[2]
    );

    actual.events.push(PacketEvent {
        id: Id::new("third-event").unwrap(),
        evaluation: Position::new(U64::new(12), U64::new(0), Phase::Reaction),
        completion: Position::new(U64::new(13), U64::new(0), Phase::Publication),
        payload: None,
    });
    let larger = decode(&actual)
        .adoption18_construction_data(usize::MAX)
        .unwrap();
    assert!(larger.requested_terms_data()[2] > spare.requested_terms_data()[2]);
    assert!(larger.requested_bytes() > spare.requested_bytes());
}
