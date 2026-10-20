//! Exercises portable DATA correspondence without fabricating a native issuer.

use super::*;
use crate::envelope::{MessageKind, Method};
use serde_json::json;

fn bytes(value: u8) -> Bytes {
    Bytes::new(vec![value; 32])
}

fn context() -> PacketNativeImport17Context {
    PacketNativeImport17Context {
        schema: "source-owned.packet-native-import-context/17".to_owned(),
        algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.to_owned(),
        peer: PacketNativeImport17PeerContext::Prepare(PacketCompleteRestorePrepareContext {
            schema: "source-owned.packet-complete-restore-prepare-context/12".to_owned(),
            algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.to_owned(),
            source_birth: bytes(1),
            kernel_binding: bytes(2),
            policy_binding: bytes(3),
            host_registration: bytes(4),
            native_registration: bytes(5),
            hello_request: bytes(6),
            hello_response: bytes(7),
            assigned_prepare: bytes(8),
            prepare_request: bytes(9),
            input_roster: bytes(10),
        }),
        import_binding_digest: bytes(11),
        assigned_original_digest: bytes(8),
    }
}

fn original() -> Envelope {
    let reference = canonical::content_ref(b"{}", "application/json").unwrap();
    let world = canonical::hash("cnp.world-binding.v1", b"world").unwrap();
    let owner = canonical::hash("cnp.owner-binding.v1", b"owner").unwrap();
    let mut original = crate::envelope::tests::request();
    original.method = Method::Begin;
    original.body = json!({
        "kind":"prepare_restore",
        "binding_hash":owner,
        "owner_generation":"1",
        "activation_id":null,
        "world_generation":"1",
        "arguments":{
            "transaction_id":"import17/transaction",
            "capture_manifest":reference,
            "expected_world_binding_hash":world,
            "expected_owner_binding_hash":owner,
            "destination_owner_ids":["owner-1"]
        },
        "extensions":{}
    })
    .as_object()
    .unwrap()
    .clone();
    // The assignment guard only checks exact key ownership and baseline Begin
    // shape. Payload correspondence is separately tested by typed context joins.
    original.extensions.insert(
        PacketNativeImport17Phase::Prepare
            .request_extension()
            .to_owned(),
        json!({"inert":"prepare"}),
    );
    original.extensions.insert(
        NATIVE_IMPORT17_EXTENSION.to_owned(),
        json!({"inert":"binding"}),
    );
    original
}

fn binding() -> PacketNativeImport17Binding {
    let reference = canonical::content_ref(b"{}", "application/json").unwrap();
    PacketNativeImport17Binding {
        schema: NATIVE_IMPORT17_EXTENSION.to_owned(),
        prepare_digest: bytes(1),
        native_before: reference.clone(),
        controller17: reference.clone(),
        source17: reference.clone(),
        node25: reference.clone(),
        geometry_identity: bytes(2),
        role_extents: [U64::new(2); 5],
        limits: PacketNativeImport17Limits {
            role_maximums: [U64::new(65536); 5],
            immutable_objects: 128.into(),
            immutable_bytes: 65536.into(),
            immutable_depth: 16.into(),
            maximum_nodes: 65536.into(),
            maximum_requested_bytes: (64 * 1024 * 1024).into(),
            maximum_target_requested_bytes: (8 * 1024 * 1024).into(),
            maximum_before_bytes: 65536.into(),
        },
        normalization: reference,
        normalization_maximum: 65536.into(),
    }
}

#[test]
fn proof_binds_import_and_every_peer_field_under_only_the_new_domain() {
    let mut context = context();
    let proof = native_import17_proof_data(&[12; 32], &context).unwrap();

    verify_native_import17_proof_data(&[12; 32], &context, &proof).unwrap();
    assert!(verify_native_import17_proof_data(&[13; 32], &context, &proof).is_err());
    assert!(
        proof
            .validate_data(PacketNativeImport17Phase::Commit)
            .is_err()
    );
    context.import_binding_digest = bytes(14);
    assert!(verify_native_import17_proof_data(&[12; 32], &context, &proof).is_err());

    let context = self::context();
    let PacketNativeImport17PeerContext::Prepare(peer) = &context.peer else {
        panic!("typed DATA fixture has Prepare vocabulary");
    };
    let old = super::super::transfer::complete_restore_prepare_proof_data(&[12; 32], peer).unwrap();
    assert_ne!(old.schema, proof.schema);
    assert_ne!(old.mac, proof.mac);
}

#[test]
fn assignment_binds_full_envelope_and_retains_exact_three_key_guard() {
    let phase = PacketNativeImport17Phase::Prepare;
    let mut original = original();
    let digest = native_import17_assigned_request_digest(&original, phase, 65536).unwrap();
    let before = original.clone();
    original
        .extensions
        .insert(phase.proof_extension().to_owned(), json!({"inert":"proof"}));

    assert_eq!(
        native_import17_assigned_request_digest(&original, phase, 65536).unwrap(),
        digest
    );
    assert!(
        super::super::transfer::complete_restore_transfer_assigned_request_digest(
            &original,
            PacketCompleteRestoreTransferPhase::Prepare,
            65536
        )
        .is_err()
    );
    original.sequence = 2.into();
    assert_ne!(
        native_import17_assigned_request_digest(&original, phase, 65536).unwrap(),
        digest
    );
    original.sequence = before.sequence;
    original
        .extensions
        .get_mut(NATIVE_IMPORT17_EXTENSION)
        .unwrap()["inert"] = json!("other");
    assert_ne!(
        native_import17_assigned_request_digest(&original, phase, 65536).unwrap(),
        digest
    );

    original.extensions.insert(
        PacketNativeImport17Phase::Commit
            .proof_extension()
            .to_owned(),
        json!({}),
    );
    assert!(native_import17_assigned_request_digest(&original, phase, 65536).is_err());
    assert_eq!(before.extensions.len(), 2);
    assert!(!before.extensions.contains_key(phase.proof_extension()));
}

#[test]
fn response_hash_requires_same_original_and_only_new_receipt() {
    let phase = PacketNativeImport17Phase::Prepare;
    let mut original = original();
    let mut response = original.clone();
    response.message = MessageKind::Response;
    response.sequence = 4.into();
    response.extensions.clear();
    response.body.clear();

    assert!(native_import17_assigned_response_digest(&original, &response, phase, 65536).is_err());
    original
        .extensions
        .insert(phase.proof_extension().to_owned(), json!({"inert":"proof"}));
    let digest =
        native_import17_assigned_response_digest(&original, &response, phase, 65536).unwrap();
    response.extensions.insert(
        phase.receipt_extension().to_owned(),
        json!({"inert":"receipt"}),
    );
    assert_eq!(
        native_import17_assigned_response_digest(&original, &response, phase, 65536).unwrap(),
        digest
    );
    response.sequence = 5.into();
    assert_ne!(
        native_import17_assigned_response_digest(&original, &response, phase, 65536).unwrap(),
        digest
    );
    response.extensions.insert(
        PacketCompleteRestoreTransferPhase::Prepare
            .receipt_extension()
            .to_owned(),
        json!({}),
    );
    assert!(native_import17_assigned_response_digest(&original, &response, phase, 65536).is_err());
}

#[test]
fn binding_digest_covers_complete_geometry_and_refuses_unknown_fields() {
    let mut binding = binding();
    binding.validate_data().unwrap();
    let digest = binding.digest_data().unwrap();
    binding.limits.maximum_target_requested_bytes = (4 * 1024 * 1024).into();
    assert_ne!(binding.digest_data().unwrap(), digest);
    binding.normalization_maximum = 32768.into();
    let normalized_digest = binding.digest_data().unwrap();
    assert_ne!(normalized_digest, digest);

    let mut value = serde_json::to_value(&binding).unwrap();
    value["unsupported"] = json!(true);
    assert!(serde_json::from_value::<PacketNativeImport17Binding>(value).is_err());
    binding.role_extents[0] = 65537.into();
    assert!(binding.validate_data().is_err());
    assert_eq!(binding.native_before.length, U64::new(2));
    assert_eq!(binding.normalization.length, U64::new(2));
}

#[test]
fn complete_import_schema_requires_definition_not_only_label() {
    let mut schema = native_import17_schema_data().unwrap();
    authenticate_native_import17_schema_data(&schema).unwrap();
    schema.definition = canonical::content_ref(b"{}", "application/json").unwrap();
    assert!(authenticate_native_import17_schema_data(&schema).is_err());

    let (temporary, scratch) = native_import17_contract_storage_data(usize::MAX).unwrap();
    let exact = temporary.checked_add(scratch).unwrap();
    assert_eq!(
        native_import17_contract_storage_data(exact).unwrap(),
        (temporary, scratch)
    );
    assert!(native_import17_contract_storage_data(exact - 1).is_err());
}
