//! Exact definition and role tests; no source qualification is issued here.

use super::*;

fn reference(bytes: &[u8], media: &str) -> ContentRef {
    canonical::content_ref(bytes, media).unwrap()
}

fn definition(handler: &[u8]) -> InputLineageDefinition {
    InputLineageDefinition::build(
        reference(b"namespace publication data", "application/json"),
        reference(handler, "application/json"),
        reference(b"exact Event core definition", "text/plain"),
        reference(b"exact InputBatch core definition", "text/plain"),
        reference(b"exact StopReceipt core definition", "text/plain"),
    )
    .unwrap()
}

#[test]
fn exact_definition_preserves_nullable_semver_and_every_original_body() {
    let definition = definition(b"original handler source closure");
    definition.declaration().validate().unwrap();
    definition.selection().validate().unwrap();
    assert_eq!(definition.selection().semantic_version.prerelease, None);
    assert_eq!(definition.selection().semantic_version.build, None);
    assert_eq!(
        definition.selection().schema_digest,
        definition.declaration().schema.definition.hash
    );
    for (reference, bytes) in definition.objects() {
        reference.verify(bytes).unwrap();
    }
    let (_, declaration) = definition.objects().last().unwrap();
    let parsed = canonical::parse_json(declaration, 65_536).unwrap();
    assert_eq!(
        parsed["semantic_version"]["prerelease"],
        serde_json::Value::Null
    );
    assert_eq!(parsed["semantic_version"]["build"], serde_json::Value::Null);
}

#[test]
fn dynamic_inventory_and_durable_handler_roles_stay_distinct() {
    let definition = definition(b"original handler source closure");
    let inventory = reference(b"exact manifest", INPUT_LINEAGE_MEDIA_TYPE);
    let dynamic = definition.input_application(inventory.clone()).unwrap();
    assert_eq!(dynamic.selection, *definition.selection());
    assert_eq!(
        dynamic.parameters,
        json!({"kind":"input","inventory":inventory})
    );
    assert_eq!(
        definition.durable_application().parameters,
        json!({"kind":"selection","handler":definition.handler()})
    );
    assert!(
        definition
            .input_application(reference(b"exact manifest", "application/json"))
            .is_err()
    );
}

#[test]
fn actual_handler_substitution_changes_durable_application_without_retagging() {
    let original = definition(b"original handler");
    let changed = definition(b"different handler");
    // The published specification is stable, but its admitted application binds
    // the actual independently measured handler closure as separate raw data.
    assert_eq!(original.selection(), changed.selection());
    assert_ne!(
        original.durable_application(),
        changed.durable_application()
    );
    assert_ne!(original.handler(), changed.handler());
}

#[test]
fn oversized_input_role_refuses_before_any_manifest_decoding() {
    let definition = definition(b"handler");
    let mut inventory = reference(b"extent data", INPUT_LINEAGE_MEDIA_TYPE);
    inventory.length = U64::new(16 * 1024 * 1024 + 1);
    assert!(definition.input_application(inventory).is_err());
}

#[test]
fn durable_selection_does_not_claim_a_containing_lane() {
    let definition = definition(b"exact handler");
    for clause in &definition.declaration().applicability {
        match clause.location {
            ExtensionLocation::FacetSelection | ExtensionLocation::BindingCompatibility => {
                assert_eq!(clause.direction, None);
            }
            ExtensionLocation::InputBatch | ExtensionLocation::MethodArguments => {
                assert_eq!(clause.direction, Some(Direction::Input));
            }
            _ => panic!("undeclared lineage location"),
        }
    }
}

#[test]
fn containing_application_credit_stays_separate_from_manifest_body_credit() {
    let definition = definition(b"exact installed handler");
    assert_eq!(
        definition.declaration().limits.maximum_message_bytes,
        U64::new(1024 * 1024)
    );
    assert_eq!(
        definition.declaration().limits.maximum_objects,
        U64::new(4096)
    );
    assert_eq!(
        definition.declaration().limits.maximum_allocation_bytes,
        U64::new(64 * 1024 * 1024)
    );

    // This checks reference geometry only, never materialization or source trust.
    let mut inventory = reference(b"original manifest", INPUT_LINEAGE_MEDIA_TYPE);
    inventory.length = U64::new(16 * 1024 * 1024);
    let application = definition.input_application(inventory.clone()).unwrap();
    assert_eq!(
        application.parameters,
        json!({"kind":"input","inventory":inventory})
    );
    let bytes = canonical::canonical_json(&serde_json::to_value(application).unwrap()).unwrap();
    assert!(bytes.len() < definition.declaration().limits.maximum_message_bytes.get() as usize);
}

#[test]
fn typed_peer_definition_has_a_distinct_published_version_and_closed_bodies()
-> Result<(), ProviderError> {
    let namespace = canonical::content_ref(b"namespace data", "application/json")?;
    let handler = canonical::content_ref(b"handler data", "application/json")?;
    let event = canonical::content_ref(b"Event definition", "text/plain")?;
    let input = canonical::content_ref(b"InputBatch definition", "text/plain")?;
    let receipt = canonical::content_ref(b"StopReceipt definition", "text/plain")?;
    let old = InputLineageDefinition::build(
        namespace.clone(),
        handler.clone(),
        event.clone(),
        input.clone(),
        receipt.clone(),
    )?;
    let typed =
        InputLineageDefinition::build_negotiated(namespace, handler, event, input, receipt)?;

    assert_eq!(old.selection().semantic_version.minor, U64::new(0));
    assert_eq!(typed.selection().semantic_version.minor, U64::new(1));
    assert_ne!(old.selection().declaration, typed.selection().declaration);
    assert_eq!(
        old.selection().schema_digest,
        typed.selection().schema_digest
    );
    let typed_feature = Id::new(crate::handshake::EXTENSION_NEGOTIATION_V1)?;
    assert!(!old.declaration().required_features.contains(&typed_feature));
    assert!(
        typed
            .declaration()
            .required_features
            .contains(&typed_feature)
    );
    for (reference, bytes) in typed.objects() {
        reference.verify(bytes)?;
        assert_ne!(reference, &old.selection().declaration);
        assert_ne!(reference, &old.declaration().specification);
        assert_ne!(reference, &old.declaration().conformance);
    }
    assert_eq!(old.declaration().limits, typed.declaration().limits);
    Ok(())
}
