//! Exercises original Session deadlines with real sockets and inert lease DATA.
//!
//! Model Hello records and fixed-width MAC bytes issue no genuine Source phase.

use super::*;
use crate::connection::ConnectionIncident;
use crate::envelope::{Method, Nullable};
use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::*;
use crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow;
use crate::transport::original_frames::OriginalFrameReservation;
use crucible_node_format::Bytes;
use std::io::Read;
use std::os::unix::net::UnixStream;

struct Supervisor;

impl ConnectionSupervisor for Supervisor {
    fn quarantine(&self, _: ConnectionIncident) {}
}

struct RefusingSchemas;

impl BodySchemaVerifier for RefusingSchemas {
    fn verify(
        &self,
        _: &ConnectionAuthority,
        _: &Envelope,
        _: &ReceivedBody,
    ) -> Result<(), ProviderError> {
        Err(refused())
    }
}

fn scope() -> (Handshake, ClientSession, UnixStream) {
    let (lease, authority, selection, installed) =
        Connection::<DeadlineStream>::original_bootstrap_model_controller_data();
    let (mut session, peer) =
        ClientSession::controller_fixture(authority, Rc::new(Supervisor), Rc::new(RefusingSchemas))
            .unwrap();
    session.seed_owned11_model_hello().unwrap();
    session
        .connection
        .install_native5_controller_codec(
            &mut Some(OriginalFrameReservation::reserve(262144, 8).unwrap()),
            selection,
            installed,
        )
        .unwrap();
    (lease, session, peer)
}

fn proposal(
    session: &ClientSession,
) -> (
    Envelope,
    PacketNativeImport18BootstrapRequest,
    PacketNativeImport18BootstrapAckProof,
) {
    let request = PacketNativeImport18BootstrapRequest {
        schema: NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA.into(),
        recipe_identity: Bytes::new(vec![1; 32]),
        initial_funding: PacketNativeStartupAllocationRow {
            retained_requested_bytes: U64::new(1),
            maximum_simultaneous_transient_bytes: U64::new(2),
            declared_counter_scratch_bytes: U64::new(3),
        },
    };
    let mut original = crate::envelope::tests::request();
    original.method = Method::NativeImport18Bootstrap;
    original.sequence = U64::new(2);
    original.session_id = Nullable(Some(session.authority.session_id().clone()));
    original.incarnation_id = Nullable(Some(session.authority.incarnation_id().clone()));
    original.node_id = Nullable(None);
    original.execution_owner_id = Nullable(None);
    original.capture_owner_id = Nullable(None);
    original.operation_id = Nullable(None);
    original.body = serde_json::to_value(&request)
        .unwrap()
        .as_object()
        .unwrap()
        .clone();
    original.extensions.clear();
    let proof = PacketNativeImport18BootstrapAckProof {
        schema: NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF.into(),
        algorithm: "blake3-keyed-canonical/1".into(),
        context_digest: Bytes::new(vec![2; 32]),
        mac: Bytes::new(vec![3; 32]),
    };
    (original, request, proof)
}

struct Sealed {
    original: Envelope,
    request: PacketNativeImport18BootstrapRequest,
    proof: PacketNativeImport18BootstrapAckProof,
    bytes: Vec<u8>,
    slot: Option<usize>,
    cut: OperationalDeadline,
}

fn seal(session: &mut ClientSession) -> Sealed {
    let cut = session.original_bootstrap_hello_cut_data().unwrap();
    let (mut original, request, proof) = proposal(session);
    let mut slot = None;
    session
        .reserve_original_bootstrap_data(&original, &request, cut, 65536, &mut slot)
        .unwrap();
    original.extensions.insert(
        NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF.into(),
        serde_json::to_value(&proof).unwrap(),
    );
    let bytes = canonical::canonical_json(&serde_json::to_value(&original).unwrap()).unwrap();
    session
        .seal_original_bootstrap_data(&original, &request, &proof, (&bytes, slot), cut)
        .unwrap();
    Sealed {
        original,
        request,
        proof,
        bytes,
        slot,
        cut,
    }
}

fn publish(session: &mut ClientSession, peer: &mut UnixStream, sealed: &Sealed) {
    session
        .publish_original_bootstrap_data(
            &sealed.original,
            &sealed.request,
            &sealed.proof,
            (&sealed.bytes, sealed.slot),
            sealed.cut,
        )
        .unwrap();
    let mut bytes = vec![0; sealed.bytes.len() + 4];
    peer.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes[4..], sealed.bytes);
}

fn response(sealed: &Sealed) -> Value {
    let mut response = sealed.original.clone();
    response.message = MessageKind::Response;
    response.body = serde_json::json!({"status":"completed", "operation_state":"completed", "extensions":{}, "result": {
        "schema":NATIVE_IMPORT18_BOOTSTRAP_RESULT_SCHEMA, "state":"bootstrap_only", "recipe_identity":sealed.request.recipe_identity, "initial_funding":sealed.request.initial_funding,
    }}).as_object().unwrap().clone();
    response.extensions.clear();
    // The decoder validates only grammar. A real Source independently verifies MACs.
    response.extensions.insert(NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT.into(), serde_json::json!({
        "schema":NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT, "algorithm":"blake3-keyed-canonical/1", "state":"bootstrap_only",
        "context_digest":Bytes::new(vec![2;32]), "assigned_response":Bytes::new(vec![3;32]), "mac":Bytes::new(vec![4;32]),
    }));
    serde_json::to_value(response).unwrap()
}

#[test]
fn dedicated_session_keeps_the_same_hello_cut_through_actual_request_and_response() {
    let (_lease, mut session, mut peer) = scope();
    let sealed = seal(&mut session);
    assert_eq!(session.sequence.get(), 2);
    assert_eq!(session.deadline.original_cut(), sealed.cut);

    publish(&mut session, &mut peer, &sealed);
    assert_eq!(session.sequence.get(), 3);
    let response = response(&sealed);
    crate::transport::write_frame(&mut peer, &response, 65536).unwrap();
    let mut raw = None;
    session
        .receive_original_bootstrap_raw_into_data(&sealed.original, sealed.cut, 65536, &mut raw)
        .unwrap();
    let row = native_import18_bootstrap_response_decode_quote_data(usize::MAX).unwrap();
    let mut decoded = None;
    let mut original = None;
    session
        .decode_original_bootstrap_raw_into_data(
            &sealed.original,
            sealed.cut,
            raw.as_ref().unwrap(),
            &row,
            usize::MAX,
            (&mut decoded, &mut original),
        )
        .unwrap();

    assert_eq!(session.sequence.get(), 3);
    assert_eq!(session.deadline.original_cut(), sealed.cut);
    assert_eq!(original.as_ref().unwrap(), &sealed.original);
    assert_eq!(raw.as_ref().unwrap().value, response);
    assert!(decoded.as_ref().unwrap().borrowed_history_data().decoded);
    session
        .authenticate_original_bootstrap_effect_cut_data(sealed.cut, 3)
        .unwrap();
    assert!(session.original_bootstrap_hello_cut_data().is_err());
}

#[test]
fn replacement_or_foreign_initial_cut_refuses_before_reserving_or_writing() {
    for fault in 0..5 {
        let (mut lease, mut session, mut peer) = scope();
        let mut cut = session.original_bootstrap_hello_cut_data().unwrap();
        let (original, request, _) = proposal(&session);
        let mut missing_hello = None;
        match fault {
            0 => session.deadline.reset(Duration::from_secs(60)).unwrap(),
            1 => cut = OperationalDeadline::after(Duration::from_secs(60)).unwrap(),
            2 => missing_hello = session.original_ack_hello.take(),
            3 => session.sequence = U64::new(3),
            4 => lease.contain(),
            _ => unreachable!(),
        }
        let mut slot = None;

        assert!(
            session
                .reserve_original_bootstrap_data(&original, &request, cut, 65536, &mut slot)
                .is_err(),
            "fault {fault}"
        );
        assert!(slot.is_none());
        assert!(
            session
                .connection
                .authenticate_original_bootstrap_endpoint_data()
                .is_err()
        );
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        drop(missing_hello);
    }
}

#[test]
fn renewed_budget_after_sealing_preserves_the_unsent_original_and_session_sequence() {
    let (_lease, mut session, mut peer) = scope();
    let sealed = seal(&mut session);
    let before = session.connection.original_bootstrap_model_storage_data();
    session.deadline.reset(Duration::from_secs(60)).unwrap();

    assert!(
        session
            .publish_original_bootstrap_data(
                &sealed.original,
                &sealed.request,
                &sealed.proof,
                (&sealed.bytes, sealed.slot),
                sealed.cut
            )
            .is_err()
    );
    assert_eq!(session.sequence.get(), 2);
    assert_eq!(
        session.connection.original_bootstrap_model_storage_data(),
        before
    );
    assert_eq!(peer.read(&mut [0]).unwrap(), 0);
}

#[test]
fn failed_publication_keeps_the_original_cut_and_spent_session_sequence() {
    let (_lease, mut session, peer) = scope();
    let sealed = seal(&mut session);
    drop(peer);

    assert!(
        session
            .publish_original_bootstrap_data(
                &sealed.original,
                &sealed.request,
                &sealed.proof,
                (&sealed.bytes, sealed.slot),
                sealed.cut
            )
            .is_err()
    );
    assert_eq!(session.sequence.get(), 3);
    assert_eq!(session.deadline.original_cut(), sealed.cut);
    assert!(
        session
            .publish_original_bootstrap_data(
                &sealed.original,
                &sealed.request,
                &sealed.proof,
                (&sealed.bytes, sealed.slot),
                sealed.cut
            )
            .is_err()
    );
    assert_eq!(session.sequence.get(), 3);
}

#[test]
fn renewed_budget_after_publication_refuses_read_without_losing_the_original() {
    let (_lease, mut session, mut peer) = scope();
    let sealed = seal(&mut session);
    publish(&mut session, &mut peer, &sealed);
    let before = session.connection.original_bootstrap_model_storage_data();
    session.deadline.reset(Duration::from_secs(60)).unwrap();
    let mut raw = None;

    assert!(
        session
            .receive_original_bootstrap_raw_into_data(&sealed.original, sealed.cut, 65536, &mut raw)
            .is_err()
    );
    assert!(raw.is_none());
    assert_eq!(session.sequence.get(), 3);
    assert_eq!(
        session.connection.original_bootstrap_model_storage_data(),
        before
    );
    assert_eq!(peer.read(&mut [0]).unwrap(), 0);
}

#[test]
fn renewed_budget_after_raw_read_keeps_actual_raw_and_refuses_decoding() {
    let (_lease, mut session, mut peer) = scope();
    let sealed = seal(&mut session);
    publish(&mut session, &mut peer, &sealed);
    let response = response(&sealed);
    crate::transport::write_frame(&mut peer, &response, 65536).unwrap();
    let mut raw = None;
    session
        .receive_original_bootstrap_raw_into_data(&sealed.original, sealed.cut, 65536, &mut raw)
        .unwrap();
    let before = session.connection.original_bootstrap_model_storage_data();
    let pointer = raw.as_ref().unwrap().bytes.as_ptr();
    session.deadline.reset(Duration::from_secs(60)).unwrap();
    let row = native_import18_bootstrap_response_decode_quote_data(usize::MAX).unwrap();
    let mut decoded = None;
    let mut original = None;

    assert!(
        session
            .decode_original_bootstrap_raw_into_data(
                &sealed.original,
                sealed.cut,
                raw.as_ref().unwrap(),
                &row,
                usize::MAX,
                (&mut decoded, &mut original)
            )
            .is_err()
    );
    assert!(decoded.is_none());
    assert!(original.is_none());
    assert_eq!(raw.as_ref().unwrap().value, response);
    assert_eq!(raw.as_ref().unwrap().bytes.as_ptr(), pointer);
    assert_eq!(
        session.connection.original_bootstrap_model_storage_data(),
        before
    );
    assert_eq!(session.sequence.get(), 3);
}

#[test]
fn terminal_cut_checks_run_after_success_and_preserve_the_original_failure() {
    for failed in [false, true] {
        let (_lease, mut session, mut peer) = scope();
        let sealed = seal(&mut session);
        let before = session.connection.original_bootstrap_model_storage_data();
        session.deadline.reset(Duration::from_secs(60)).unwrap();
        let original = if failed {
            Err(ProviderError::Correlation("original transport failure"))
        } else {
            Ok(())
        };

        let result = session.finish_original_bootstrap_effect_data(original, sealed.cut, 2);

        assert!(result.is_err());
        if failed {
            assert!(matches!(
                result,
                Err(ProviderError::Correlation("original transport failure"))
            ));
        }
        assert!(
            session
                .connection
                .authenticate_original_bootstrap_endpoint_data()
                .is_err()
        );
        assert_eq!(
            session.connection.original_bootstrap_model_storage_data(),
            before
        );
        assert_eq!(session.sequence.get(), 2);
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }
}

#[test]
fn occupied_raw_destination_refuses_before_a_later_cut_check_or_reader_effect() {
    let (_lease, mut session, mut peer) = scope();
    let sealed = seal(&mut session);
    publish(&mut session, &mut peer, &sealed);
    let response = response(&sealed);
    crate::transport::write_frame(&mut peer, &response, 65536).unwrap();
    let mut raw = None;
    session
        .receive_original_bootstrap_raw_into_data(&sealed.original, sealed.cut, 65536, &mut raw)
        .unwrap();
    let pointer = raw.as_ref().unwrap().bytes.as_ptr();
    let before = session.connection.original_bootstrap_model_storage_data();
    session.deadline.reset(Duration::from_secs(60)).unwrap();

    assert!(
        session
            .receive_original_bootstrap_raw_into_data(&sealed.original, sealed.cut, 65536, &mut raw)
            .is_err()
    );
    assert_eq!(raw.as_ref().unwrap().value, response);
    assert_eq!(raw.as_ref().unwrap().bytes.as_ptr(), pointer);
    assert_eq!(
        session.connection.original_bootstrap_model_storage_data(),
        before
    );
    session
        .connection
        .authenticate_original_bootstrap_endpoint_data()
        .unwrap();
    assert_eq!(session.sequence.get(), 3);
}
