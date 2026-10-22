//! Exercises actual socket receipt, retained failures and closed parser admission.

use super::super::tests::{published, response, scope, seal};
use super::*;
use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::native_import18_bootstrap_response_decode_quote_data;
use std::{io::Write, os::unix::net::UnixStream};

fn row() -> Row {
    Connection::<UnixStream>::original_bootstrap_raw_response_construction_data(65536, usize::MAX)
        .unwrap()
}

#[test]
fn complete_raw_response_preserves_literal_and_dom_before_actual_sdk_settlement() {
    let (_lease, mut connection, mut peer, original, request) = published();
    let response = response(&original, &request);
    let mut body = vec![b' '; 8192];
    body.extend_from_slice(&serde_json::to_vec_pretty(&response).unwrap());
    let row = row();
    let pending_pointer = connection
        .guard
        .pending_requests()
        .next()
        .unwrap()
        .request_id
        .0
        .as_ref()
        .unwrap()
        .as_str()
        .as_ptr();
    peer.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
    peer.write_all(&body).unwrap();
    let mut output = None;

    connection
        .receive_original_bootstrap_response_into_data(&original, &row, usize::MAX, &mut output)
        .unwrap();

    let raw = output.as_ref().unwrap();
    let history = raw.borrowed_history_data().unwrap();
    assert!(history.complete && history.preflighted && history.parsed && !history.failed);
    assert_eq!(history.body, body);
    assert_eq!(history.body_received, body.len());
    assert_eq!(history.header_received, 4);
    assert_eq!(history.value, Some(&response));
    assert_eq!(raw.frame.as_ref().unwrap().bytes.capacity(), 65536);
    assert!(raw.retained_requested_bytes_data().unwrap() <= row.axes[0]);
    assert_eq!(connection.guard.pending_requests().next(), Some(&original));
    let bank = connection.original_frames.as_ref().unwrap().borrow();
    let frame = bank.frame(history.slot.unwrap()).unwrap();
    assert!(frame.complete);
    assert_eq!(frame.transferred, body.len() + 4);
    assert_eq!(&frame.bytes[4..], body);
    drop(bank);

    let mut decoded = None;
    let mut retained_request = None;
    connection
        .decode_original_bootstrap_raw_into_data(
            &original,
            raw.frame.as_ref().unwrap(),
            &native_import18_bootstrap_response_decode_quote_data(usize::MAX).unwrap(),
            usize::MAX,
            (&mut decoded, &mut retained_request),
        )
        .unwrap();
    assert_eq!(retained_request.as_ref(), Some(&original));
    assert_eq!(
        retained_request
            .as_ref()
            .unwrap()
            .request_id
            .0
            .as_ref()
            .unwrap()
            .as_str()
            .as_ptr(),
        pending_pointer
    );
    assert!(connection.guard.pending_requests().next().is_none());
}

#[test]
fn every_incomplete_header_and_body_prefix_remains_in_the_same_failed_owner() {
    for prefix in [0, 1, 3, 4, 9] {
        let (_lease, mut connection, mut peer, original, _) = published();
        let mut wire = 16u32.to_be_bytes().to_vec();
        wire.extend_from_slice(b"incomplete body!");
        peer.write_all(&wire[..prefix]).unwrap();
        drop(peer);
        let mut output = None;

        assert!(
            connection
                .receive_original_bootstrap_response_into_data(
                    &original,
                    &row(),
                    usize::MAX,
                    &mut output
                )
                .is_err()
        );

        let raw = output.as_ref().unwrap();
        let history = raw.borrowed_history_data().unwrap();
        assert!(history.failed && !history.complete && !history.preflighted && !history.parsed);
        assert_eq!(history.header_received, prefix.min(4));
        assert_eq!(history.body_received, prefix.saturating_sub(4));
        assert!(history.value.is_none());
        assert_eq!(raw.body.capacity(), 65536);
        assert!(raw.retained_requested_bytes_data().unwrap() <= row().axes[0]);
        let bank = connection.original_frames.as_ref().unwrap().borrow();
        let frame = bank.frame(history.slot.unwrap()).unwrap();
        assert_eq!(frame.bytes, &wire[..prefix]);
        assert!(!frame.complete);
        assert_eq!(connection.guard.pending_requests().next(), Some(&original));
        let pointer = raw.body.as_ptr();
        drop(bank);

        assert!(
            connection
                .receive_original_bootstrap_response_into_data(
                    &original,
                    &row(),
                    usize::MAX,
                    &mut output
                )
                .is_err()
        );
        assert_eq!(output.as_ref().unwrap().body.as_ptr(), pointer);
        assert_eq!(
            output.as_ref().unwrap().body_received,
            prefix.saturating_sub(4)
        );
    }
}

#[test]
fn invalid_closed_raw_keeps_complete_physical_bytes_without_constructing_a_tree() {
    for body in [
        b"{\"protocol\":\"CNP/1\"}".to_vec(),
        format!("{{\"protocol\":\"{}\"}}", "x".repeat(60000)).into_bytes(),
    ] {
        let (_lease, mut connection, mut peer, original, _) = published();
        peer.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
        peer.write_all(&body).unwrap();
        let mut output = None;

        assert!(
            connection
                .receive_original_bootstrap_response_into_data(
                    &original,
                    &row(),
                    usize::MAX,
                    &mut output
                )
                .is_err()
        );

        let raw = output.as_ref().unwrap();
        let history = raw.borrowed_history_data().unwrap();
        assert!(history.failed && history.complete && !history.preflighted && !history.parsed);
        assert_eq!(history.body, body);
        assert!(history.value.is_none());
        assert_eq!(connection.guard.pending_requests().next(), Some(&original));
        assert!(raw.retained_requested_bytes_data().unwrap() <= row().axes[0]);
    }
}

#[test]
fn unpublished_original_refuses_before_allocating_or_reading_the_body_bank() {
    let (_lease, mut connection, _peer) = scope();
    let (original, _, _, _, _) = seal(&mut connection);
    let before = connection.original_bootstrap_model_storage_data();
    let mut output = None;

    assert!(
        connection
            .receive_original_bootstrap_response_into_data(
                &original,
                &row(),
                usize::MAX,
                &mut output
            )
            .is_err()
    );

    let raw = output.as_ref().unwrap();
    assert!(raw.failed);
    assert_eq!(raw.body.capacity(), 0);
    assert!(raw.slot.is_none());
    assert_eq!(connection.original_bootstrap_model_storage_data(), before);
    assert_eq!(connection.guard.pending_requests().next(), Some(&original));
}

#[test]
fn exact_raw_restriction_prices_the_real_bank_independently_of_closed_parser_demand() {
    let row = row();
    let exact = sum(&row.axes).unwrap();
    assert_eq!(
        Connection::<UnixStream>::original_bootstrap_raw_response_construction_data(65536, exact)
            .unwrap(),
        row
    );
    assert!(
        Connection::<UnixStream>::original_bootstrap_raw_response_construction_data(
            65536,
            exact - 1
        )
        .is_err()
    );
    assert!(
        Connection::<UnixStream>::original_bootstrap_raw_response_construction_data(0, usize::MAX)
            .is_err()
    );
    let smaller = Connection::<UnixStream>::original_bootstrap_raw_response_construction_data(
        1024,
        usize::MAX,
    )
    .unwrap();
    assert_eq!(row.axes[0] - smaller.axes[0], 65536 - 1024);
    assert_eq!(&row.axes[1..], &smaller.axes[1..]);
}

#[test]
fn combined_raw_sdk_and_real_incident_census_uses_the_actual_largest_tree_layout() {
    use crate::retained_metadata::requested_metadata_backing_storage_data;
    use std::cell::RefCell;
    struct Recording(RefCell<Option<ConnectionIncident>>);
    impl ConnectionSupervisor for Recording {
        fn quarantine(&self, incident: ConnectionIncident) {
            *self.0.borrow_mut() = Some(incident);
        }
    }
    let (_lease, mut connection, mut peer) = scope();
    let recorder = Rc::new(Recording(RefCell::new(None)));
    connection.supervisor = recorder.clone();
    let mut observer = MetadataObserver::new();
    connection
        .guard
        .observe_owned_metadata(&mut observer)
        .unwrap();
    let baseline = requested_metadata_backing_storage_data(&observer.finish()).unwrap();
    let (original, request, proof, literal, slot) = seal(&mut connection);
    connection
        .publish_original_bootstrap_data(&original, &request, &proof, &literal, slot)
        .unwrap();
    peer.read_exact(&mut vec![0; literal.len() + 4]).unwrap();
    let body = serde_json::to_vec(&response(&original, &request)).unwrap();
    peer.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
    peer.write_all(&body).unwrap();
    let mut output = None;
    let row = row();
    connection
        .receive_original_bootstrap_response_into_data(&original, &row, usize::MAX, &mut output)
        .unwrap();

    connection.contain_original_bootstrap_data();

    let incident = recorder.0.borrow();
    let incident = incident.as_ref().unwrap();
    assert_eq!(incident.outgoing, vec![original.clone()]);
    let raw = output.as_ref().unwrap();
    let mut observer = MetadataObserver::new();
    connection
        .guard
        .observe_owned_metadata(&mut observer)
        .unwrap();
    raw.observe_retained_into_data(&mut observer).unwrap();
    observer.observe(&incident.session).unwrap();
    observer.observe(&incident.incarnation).unwrap();
    observer.observe(&incident.connection).unwrap();
    observer.observe(&incident.outgoing).unwrap();
    observer.observe(&incident.incoming).unwrap();
    let facts = observer.finish();
    assert!(facts.maximum_tree_key_value_bytes >= size_of::<Id>() + size_of::<Envelope>());
    let actual = size_of::<Raw>()
        + size_of::<ConnectionIncident>()
        + requested_metadata_backing_storage_data(&facts).unwrap()
        - baseline;
    assert!(
        actual <= row.axes[0],
        "actual {actual}, quote {:?}",
        row.axes
    );
}
