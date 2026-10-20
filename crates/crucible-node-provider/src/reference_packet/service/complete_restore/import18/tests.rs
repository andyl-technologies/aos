//! Checks the required successor discriminators without constructing authority.

use super::*;

fn fixture() -> PacketNativeImport18Binding {
    let reference = canonical::content_ref(b"{}", "application/json").unwrap();
    let source_family = PacketNativeImport18SourceFamily::Captured17;
    let semantic_spend_family = PacketNativeImport18SemanticSpendFamily::Complete18;
    PacketNativeImport18Binding {
        native_family: PacketNativeImport18NativeFamily::Snapshot17,
        schema: NATIVE_IMPORT18_EXTENSION.to_owned(),
        prepare_digest: Bytes::new(vec![0; 32]),
        native_before: reference.clone(),
        controller17: reference.clone(),
        source_family,
        source17: canonical::content_ref(b"{}", source_family.media_type_data()).unwrap(),
        node25: reference.clone(),
        geometry_identity: Bytes::new(vec![0; 32]),
        role_extents: [U64::new(2); 5],
        limits: PacketNativeImport17Limits {
            role_maximums: [U64::new(32); 5],
            immutable_objects: U64::new(32),
            immutable_bytes: U64::new(32),
            immutable_depth: U64::new(4),
            maximum_nodes: U64::new(32),
            maximum_requested_bytes: U64::new(4096),
            maximum_target_requested_bytes: U64::new(4096),
            maximum_before_bytes: U64::new(32),
        },
        normalization: reference,
        normalization_maximum: U64::new(32),
        semantic_spend_family,
        semantic_spend: canonical::content_ref(b"{}", semantic_spend_family.media_type_data())
            .unwrap(),
        semantic_spend_maximum: U64::new(32),
    }
}

#[test]
fn both_discriminators_are_required_and_unknown_fields_refuse() {
    let binding = fixture();
    let value = serde_json::to_value(&binding).unwrap();

    for field in ["native_family", "source_family", "semantic_spend_family"] {
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<PacketNativeImport18Binding>(missing).is_err());
    }
    let mut extra = value;
    extra
        .as_object_mut()
        .unwrap()
        .insert("source_version".to_owned(), 17.into());
    assert!(serde_json::from_value::<PacketNativeImport18Binding>(extra).is_err());
}

#[test]
fn changing_family_never_reinterprets_the_same_reference() {
    let mut binding = fixture();
    let original = binding.semantic_spend.clone();
    binding.validate_data().unwrap();

    binding.semantic_spend_family = PacketNativeImport18SemanticSpendFamily::Legacy17;

    assert!(binding.validate_data().is_err());
    assert_eq!(binding.semantic_spend, original);
    assert_eq!(
        binding.source_family,
        PacketNativeImport18SourceFamily::Captured17
    );
}

#[test]
fn old_binding_schema_is_not_an_import18_alias() {
    let mut binding = fixture();
    binding.schema = super::super::import17::NATIVE_IMPORT17_EXTENSION.to_owned();

    assert!(binding.validate_data().is_err());
}

fn original() -> Envelope {
    let reference = canonical::content_ref(b"{}", "application/json").unwrap();
    let world = canonical::hash("cnp.world-binding.v1", b"world").unwrap();
    let owner = canonical::hash("cnp.owner-binding.v1", b"owner").unwrap();
    let mut original = crate::envelope::tests::request();
    original.method = crate::envelope::Method::Begin;
    original.body = serde_json::json!({
        "kind":"prepare_restore",
        "binding_hash":owner,
        "owner_generation":"1",
        "activation_id":null,
        "world_generation":"1",
        "arguments":{
            "transaction_id":"import18/transaction",
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
        PacketNativeImport18Phase::Prepare
            .request_extension()
            .to_owned(),
        serde_json::json!({"inert":"prepare"}),
    );
    original.extensions.insert(
        NATIVE_IMPORT18_EXTENSION.to_owned(),
        serde_json::json!({"inert":"binding"}),
    );
    original
}

#[test]
fn successor_assignment_excludes_only_proof18_and_refuses_old_keys() {
    let phase = PacketNativeImport18Phase::Prepare;
    let mut original = original();
    let digest = native_import18_assigned_request_digest(&original, phase, 65536).unwrap();
    original.extensions.insert(
        phase.proof_extension().to_owned(),
        serde_json::json!({"inert":"proof"}),
    );

    assert_eq!(
        native_import18_assigned_request_digest(&original, phase, 65536).unwrap(),
        digest
    );
    assert!(
        super::super::import17::native_import17_assigned_request_digest(
            &original,
            phase.payload_phase_data(),
            65536
        )
        .is_err()
    );

    original.extensions.insert(
        phase.payload_phase_data().proof_extension().to_owned(),
        serde_json::json!({"inert":"old-proof"}),
    );
    assert!(native_import18_assigned_request_digest(&original, phase, 65536).is_err());
    assert!(original.extensions.contains_key(phase.proof_extension()));
    assert!(
        original
            .extensions
            .contains_key(phase.payload_phase_data().proof_extension())
    );
}
