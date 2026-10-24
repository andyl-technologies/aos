//! Checks canonical digest correspondence through the actual SDK socket path.
//!
//! The existing negotiation fixture and proof/receipt DATA are inert. These
//! controls construct no private Source, genuine Recipe, Initial or native grant.

use super::*;
use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::*;
use crucible_node_format::{Id, canonical};
use std::io::Read;

#[test]
fn url_safe_digest_octets_survive_assignment_publication_and_actual_sdk_settlement() {
    for octet in [0, 62, 127, 239, 251, 255] {
        let (_lease, mut connection, mut peer) = super::super::tests::scope();
        let (_, mut request, mut proof) = super::super::tests::proposal(&connection);
        request.recipe_identity = Bytes::new(vec![octet; 32]);
        proof.context_digest = Bytes::new(vec![octet; 32]);
        proof.mac = Bytes::new(vec![octet; 32]);
        let row = native_import18_bootstrap_assignment_quote_data(usize::MAX).unwrap();
        let request_id = Id::new("canonical-bootstrap").unwrap();
        let mut assignment = None;

        native_import18_bootstrap_assignment_into_data(
            [
                connection.authority.session_id(),
                connection.authority.incarnation_id(),
                &request_id,
            ],
            &request,
            &row,
            usize::MAX,
            &mut assignment,
        )
        .unwrap();
        let mut original = assignment
            .as_ref()
            .unwrap()
            .borrowed_history_data()
            .original
            .unwrap()
            .clone();
        native_import18_bootstrap_ack_assigned_request_digest(&original, 65536).unwrap();
        let mut slot = None;
        connection
            .reserve_original_bootstrap_data(&original, &request, 65536, &mut slot)
            .unwrap();
        original.extensions.insert(
            NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF.into(),
            serde_json::to_value(&proof).unwrap(),
        );
        let bytes = canonical::canonical_json(&serde_json::to_value(&original).unwrap()).unwrap();
        connection
            .seal_original_bootstrap_data(&original, &request, &proof, &bytes, slot)
            .unwrap();
        connection
            .publish_original_bootstrap_data(&original, &request, &proof, &bytes, slot)
            .unwrap();

        let mut header = [0; 4];
        peer.read_exact(&mut header).unwrap();
        let mut received = vec![0; u32::from_be_bytes(header) as usize];
        peer.read_exact(&mut received).unwrap();
        assert_eq!(received, bytes);

        let mut response = super::super::tests::response(&original, &request);
        for field in ["context_digest", "assigned_response", "mac"] {
            response["extensions"][NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT][field] =
                serde_json::to_value(Bytes::new(vec![octet; 32])).unwrap();
        }
        crate::transport::write_frame(&mut peer, &response, 65536).unwrap();
        let mut raw = None;
        connection
            .receive_original_bootstrap_raw_into_data(&original, 65536, &mut raw)
            .unwrap();
        let quote = native_import18_bootstrap_response_decode_quote_data(usize::MAX).unwrap();
        let mut decoded = None;
        let mut moved_request = None;
        connection
            .decode_original_bootstrap_raw_into_data(
                &original,
                raw.as_ref().unwrap(),
                &quote,
                usize::MAX,
                (&mut decoded, &mut moved_request),
            )
            .unwrap();

        let owner = decoded.as_ref().unwrap();
        let history = owner.borrowed_history_data();
        assert!(history.decoded);
        assert!(!history.failed);
        assert_eq!(history.request.unwrap(), &request);
        assert_eq!(history.receipt.unwrap().mac.as_slice(), &[octet; 32]);
        assert_eq!(moved_request.as_ref(), Some(&original));
        assert!(connection.guard.pending_requests().next().is_none());
        assert!(!connection.fenced);
        assert!(
            owner.retained_requested_bytes_data().unwrap() <= quote.requested_storage_data()[0]
        );
    }
}

#[test]
fn borrowed_wire_refuses_standard_alphabet_in_each_digest_position() {
    let (_lease, connection, _peer) = super::super::tests::scope();
    let (mut original, mut request, mut proof) = super::super::tests::proposal(&connection);
    request.recipe_identity = Bytes::new(vec![0xfb; 32]);
    proof.context_digest = Bytes::new(vec![0xff; 32]);
    proof.mac = Bytes::new(vec![0xfb; 32]);
    original.body = serde_json::to_value(&request)
        .unwrap()
        .as_object()
        .unwrap()
        .clone();
    authenticate_data(&connection.authority, &original, &request, None).unwrap();
    original.extensions.insert(
        NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF.into(),
        serde_json::to_value(&proof).unwrap(),
    );
    authenticate_data(&connection.authority, &original, &request, Some(&proof)).unwrap();

    let standard = base64::engine::general_purpose::STANDARD_NO_PAD;
    for field in ["recipe_identity", "context_digest", "mac"] {
        let mut changed = original.clone();
        if field == "recipe_identity" {
            changed
                .body
                .insert(field.into(), Value::String(standard.encode([0xfb; 32])));
        } else {
            let octet = if field == "context_digest" {
                0xff
            } else {
                0xfb
            };
            changed
                .extensions
                .get_mut(NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF)
                .unwrap()[field] = Value::String(standard.encode([octet; 32]));
        }

        assert!(
            authenticate_data(&connection.authority, &changed, &request, Some(&proof)).is_err()
        );
    }
    assert!(connection.guard.unused());
}
