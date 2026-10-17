//! Exercises actual known registry owners through historical archive reconstruction.
//!
//! Hello authentication is the existing modeled verifier. These controls exercise
//! data preservation and creator/registry association; they grant no source,
//! native restoration, semantic Capture or fresh-world permission.

use super::*;
use crate::protocol_snapshot::owned11::{
    aliases::HistoricalAliasSummary, host_registry::ValidatedHostExtensionRegistry,
    json_value::HistoricalJsonLimits, outer::OwnedProtocol11DataLimits,
};
use crate::retained_metadata::{aliases::MetadataAliasBank, records::MetadataRecordBank};

struct RegistryFixture {
    handshake: ExtensionHandshake,
    authority: ConnectionAuthority,
    owner: OriginalExtensionRegistryOwner,
    schema_capacity: usize,
}

fn registry_fixture() -> RegistryFixture {
    let (original, schema_capacity) = configured_with_schema_spare_capacity(9);
    let mut original = Some(original);
    let mut handshake =
        ExtensionHandshake::from_original_empty_registry_retained(&mut original).unwrap();
    assert!(original.is_none());
    let owner = handshake.retain_original_registry_metadata_owner().unwrap();
    let (mut request, mut response) = pair(false, "registry-hello/1");
    request.extensions.insert(
        EXTENSION_NEGOTIATION_V1.into(),
        serde_json::to_value(ExtensionOfferV1 {
            format: U64::new(1),
            required: vec![],
            optional: vec![],
        })
        .unwrap(),
    );
    response.extensions.insert(
        EXTENSION_NEGOTIATION_V1.into(),
        serde_json::to_value(ExtensionSelectionV1 {
            format: U64::new(1),
            selected: vec![],
        })
        .unwrap(),
    );
    let authority = handshake
        .admit_envelopes(
            &request,
            &response,
            id("registry-connection/1"),
            &mut Verifier::default(),
        )
        .unwrap();
    RegistryFixture {
        handshake,
        authority,
        owner,
        schema_capacity,
    }
}

fn data_limits() -> OwnedProtocol11DataLimits {
    OwnedProtocol11DataLimits {
        json: HistoricalJsonLimits {
            maximum_input_bytes: 32768,
            maximum_nodes: 8192,
            maximum_depth: 64,
            maximum_owned_backing_bytes: 32768,
            maximum_tree_entries: 1024,
        },
        content: crate::client::compact_metadata8::CompactMetadata8Limits {
            content: crate::client::compact_cursor::CompactContentLimits {
                max_input_bytes: 32768,
                max_rows: 1024,
                max_groups: 1024,
                max_first_group_capacity_bytes: 32768,
            },
            maximum_metadata_capacity_bytes: 32768,
        },
        maximum_metadata_rows: 1024,
        maximum_literal_backing_bytes: 0,
    }
}

#[test]
fn known_registry_archive_preserves_spare_capacity_and_decodes_after_original_owner_drop() {
    let fixture = registry_fixture();
    let schema_capacity = fixture.schema_capacity;
    let mut records = MetadataRecordBank::reserve(1024).unwrap();
    let mut aliases = MetadataAliasBank::reserve(1024).unwrap();
    let mut encoded = Vec::with_capacity(32768);
    {
        let view = fixture
            .handshake
            .original_complete_registry_view(&fixture.authority, &fixture.owner)
            .unwrap();
        view.encode_complete_data_into(&mut records, &mut aliases, &mut encoded)
            .unwrap();
        assert_eq!(aliases.retained_rows(), 11);
    }
    let reference = canonical::content_ref(&encoded, "application/json").unwrap();
    drop(fixture);

    let mut summaries = [HistoricalAliasSummary::default(); 5];
    let mut plan =
        ValidatedHostExtensionRegistry::validate(&encoded, data_limits(), &mut summaries).unwrap();
    assert_eq!(plan.allocation_demand().alias_groups, 5);
    assert_eq!(plan.allocation_demand().alias_rows, 11);
    let mut encoded_bank = Some(Vec::with_capacity(encoded.len()));
    let mut sealed = None;
    plan.reconstruct_sealed_into(&reference, &mut encoded_bank, &mut sealed)
        .unwrap();
    assert!(encoded_bank.is_none());
    let sealed = sealed.as_ref().unwrap();
    assert_eq!(sealed.encoded_body(), encoded);
    assert_eq!(sealed.body_reference(), &reference);
    let historical = sealed.historical().unwrap();
    assert_eq!(
        historical
            .negotiation_data()
            .policy
            .required_schemas
            .capacity(),
        schema_capacity
    );
    assert!(historical.selected_data().is_empty());
    assert_eq!(
        historical.creator_data().process_id_data(),
        std::process::id()
    );
}

#[test]
fn registry_encoder_counts_one_short_before_copy_and_foreign_known_owner_refuses() {
    let fixture = registry_fixture();
    let foreign = registry_fixture();
    assert!(
        fixture
            .handshake
            .original_complete_registry_view(&fixture.authority, &foreign.owner,)
            .is_err()
    );
    let view = fixture
        .handshake
        .original_complete_registry_view(&fixture.authority, &fixture.owner)
        .unwrap();
    let mut encoded = Vec::with_capacity(32768);
    view.encode_complete_data_into(
        &mut MetadataRecordBank::reserve(1024).unwrap(),
        &mut MetadataAliasBank::reserve(1024).unwrap(),
        &mut encoded,
    )
    .unwrap();

    let mut one_short = Vec::with_capacity(encoded.len() - 1);
    assert_eq!(one_short.capacity(), encoded.len() - 1);
    let mut short_records = MetadataRecordBank::reserve(1024).unwrap();
    let mut short_aliases = MetadataAliasBank::reserve(1024).unwrap();
    assert!(
        view.encode_complete_data_into(&mut short_records, &mut short_aliases, &mut one_short,)
            .is_err()
    );
    assert!(one_short.is_empty());
    assert!(!short_records.rows().is_empty());
    assert_eq!(short_aliases.retained_rows(), 11);

    let mut exact = Vec::with_capacity(encoded.len());
    assert_eq!(exact.capacity(), encoded.len());
    view.encode_complete_data_into(
        &mut MetadataRecordBank::reserve(1024).unwrap(),
        &mut MetadataAliasBank::reserve(1024).unwrap(),
        &mut exact,
    )
    .unwrap();
    assert_eq!(exact, encoded);
}

#[test]
fn erased_empty_roster_does_not_substitute_known_registry_owner() {
    let installed = Rc::new(Installed {
        supported: vec![],
        required: vec![],
        calls: Cell::new(0),
        deny: false,
    });
    let unknown = ExtensionHandshake::new(configured(), installed).unwrap();
    assert!(unknown.retain_original_registry_metadata_owner().is_err());
}
