//! Measures actual SDK and incident clones after an original socket failure.

use super::super::tests::{proposal, scope};
use super::*;
use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};
use std::{cell::RefCell, os::unix::net::UnixStream, rc::Rc};

struct Recording(RefCell<Option<ConnectionIncident>>);

impl ConnectionSupervisor for Recording {
    fn quarantine(&self, incident: ConnectionIncident) {
        *self.0.borrow_mut() = Some(incident);
    }
}

fn sdk_backing(connection: &Connection<UnixStream>) -> usize {
    let mut observer = MetadataObserver::new();
    connection
        .guard
        .observe_owned_metadata(&mut observer)
        .unwrap();
    requested_metadata_backing_storage_data(&observer.finish()).unwrap()
}

#[test]
fn independent_seal_quote_covers_actual_sdk_and_later_failure_clones() {
    let (_lease, mut connection, peer) = scope();
    let recorder = Rc::new(Recording(RefCell::new(None)));
    connection.supervisor = recorder.clone();
    let (mut original, request, proof) = proposal(&connection);
    original.request_id =
        crate::envelope::Nullable(Some(Id::new("r".repeat(MAX_ID_BYTES)).unwrap()));
    let row =
        Connection::<UnixStream>::original_bootstrap_sealing_construction_data(usize::MAX).unwrap();
    let mut slot = None;
    connection
        .reserve_original_bootstrap_data(&original, &request, 65536, &mut slot)
        .unwrap();
    original.extensions.insert(
        crate::reference_packet::service::complete_restore::import18::bootstrap_ack::NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF.into(),
        serde_json::to_value(&proof).unwrap(),
    );
    let literal = canonical::canonical_json(&serde_json::to_value(&original).unwrap()).unwrap();
    let before = sdk_backing(&connection);

    connection
        .seal_original_bootstrap_data(&original, &request, &proof, &literal, slot)
        .unwrap();

    let after_seal = sdk_backing(&connection);
    let sdk_delta = after_seal.checked_sub(before).unwrap();
    assert!(sdk_delta > 0);
    let pending = connection.guard.pending_requests().next().unwrap();
    assert_eq!(pending, &original);
    let pending_id = pending.request_id.0.as_ref().unwrap().as_str().as_ptr();
    assert_ne!(
        pending_id,
        original.request_id.0.as_ref().unwrap().as_str().as_ptr()
    );
    drop(peer);

    assert!(
        connection
            .publish_original_bootstrap_data(&original, &request, &proof, &literal, slot)
            .is_err()
    );

    assert!(connection.fenced);
    assert_eq!(sdk_backing(&connection), after_seal);
    assert_eq!(connection.guard.pending_requests().next(), Some(&original));
    let saved = recorder.0.borrow();
    let incident = saved.as_ref().unwrap();
    assert_eq!(incident.outgoing, vec![original.clone()]);
    assert!(incident.incoming.is_empty());
    assert_ne!(
        incident.outgoing[0]
            .request_id
            .0
            .as_ref()
            .unwrap()
            .as_str()
            .as_ptr(),
        pending_id
    );
    let mut observer = MetadataObserver::new();
    connection
        .guard
        .observe_owned_metadata(&mut observer)
        .unwrap();
    observer.observe(&incident.session).unwrap();
    observer.observe(&incident.incarnation).unwrap();
    observer.observe(&incident.connection).unwrap();
    observer.observe(&incident.outgoing).unwrap();
    observer.observe(&incident.incoming).unwrap();
    let combined = size_of::<ConnectionIncident>()
        + requested_metadata_backing_storage_data(&observer.finish()).unwrap();
    assert!(
        combined - before <= row[0],
        "SDK delta {sdk_delta}, combined {combined}, baseline {before}, row {row:?}"
    );
}

#[test]
fn exact_seal_restriction_is_independent_of_the_negotiated_frame_ceiling() {
    let row =
        Connection::<UnixStream>::original_bootstrap_sealing_construction_data(usize::MAX).unwrap();
    let exact = sum(&row).unwrap();

    assert_eq!(
        Connection::<UnixStream>::original_bootstrap_sealing_construction_data(exact).unwrap(),
        row
    );
    assert!(
        Connection::<UnixStream>::original_bootstrap_sealing_construction_data(exact - 1).is_err()
    );
    let projection = native_import18_bootstrap_envelope_projection_data(usize::MAX).unwrap();
    assert!(projection.maximum_encoded_bytes_data()[0] < 65536);
    assert!(row[0] >= projection.retained_value_backing_bytes_data()[0] * 2);
}
