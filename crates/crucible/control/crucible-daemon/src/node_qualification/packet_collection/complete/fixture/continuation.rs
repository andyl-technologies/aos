//! Builds immutable continuation declarations before participant identities.
//!
//! These helpers produce contract DATA only; they issue no ticket or live right.

// crucible-lint: allow panic-shortcut -- Invalid static fixture contracts are assertion failures.
#![allow(clippy::unwrap_used)]

use super::id;
use crucible_node_format::{ProviderManifest, Validate};
use crucible_node_transport::reference_packet::{
    continuation_contracts::{
        PacketNative5CompleteRestoreDeclaration,
        complete_packet_fresh_restore_allocation_declaration,
    },
    service::{
        PacketNative5ConfirmationSelection,
        ack_emitter::PacketNative5AckEmitterSelection,
        capture_allocation::PacketNative5CaptureAllocationSelection,
        complete_restore::{
            PacketNative5CompleteRestoreSelection, PacketNative5RestoreInputEmitterSelection,
            activation::{
                PACKET_RESTORATION_ACTIVATION_FEATURE, restoration_activation_contract_data,
                restoration_activation_schema,
                upload::{
                    PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE,
                    restoration_activation_upload_contract_data,
                    restoration_activation_upload_schema,
                },
            },
            restoration_observe::{
                PACKET_RESTORATION_OBSERVE_FEATURE, restoration_observe_contract_data,
                restoration_observe_schema,
            },
        },
        fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection,
        native_snapshot::{native_owned14_snapshot_contract, native_owned14_snapshot_schema},
        native_startup::{
            PACKET_RESTORATION_SUFFIX_FEATURE, restoration_suffix_contract_data,
            restoration_suffix_schema,
        },
    },
};

pub(in super::super) fn restore_declaration(
    provider: &ProviderManifest,
    confirmation: Option<&PacketNative5ConfirmationSelection>,
    ack: Option<&PacketNative5AckEmitterSelection>,
) -> PacketNative5CompleteRestoreDeclaration {
    let mut declaration = complete_packet_fresh_restore_allocation_declaration(
        provider,
        confirmation,
        ack,
        Some(&PacketNative5CompleteRestoreSelection::SourceSignedTransfer12),
        Some(&PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12),
        Some(&PacketNative5CaptureAllocationSelection::OriginalObserve12),
        Some(&PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13),
    )
    .unwrap();

    // Original execution keeps its observation declaration and startup15. The
    // same immutable suffix grammar is available to a distinct ticketed target;
    // merely listing it here never selects the suffix constructor.
    let definitions = [
        (
            native_owned14_snapshot_schema().unwrap(),
            native_owned14_snapshot_contract().unwrap(),
        ),
        (
            restoration_activation_schema().unwrap(),
            restoration_activation_contract_data().to_vec(),
        ),
        (
            restoration_activation_upload_schema().unwrap(),
            restoration_activation_upload_contract_data().to_vec(),
        ),
        (
            restoration_observe_schema().unwrap(),
            restoration_observe_contract_data().to_vec(),
        ),
        (
            restoration_suffix_schema().unwrap(),
            restoration_suffix_contract_data().to_vec(),
        ),
    ];
    for (schema, bytes) in definitions {
        schema.definition.verify(&bytes).unwrap();
        let formats = &mut declaration.peer.provider.implementation.formats;
        if let Some(previous) = formats.iter().find(|one| one.id == schema.id) {
            assert_eq!(previous, &schema);
        } else {
            formats.push(schema.clone());
        }
        declaration.restoration.push((schema, bytes));
    }
    for feature in [
        PACKET_RESTORATION_ACTIVATION_FEATURE,
        PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE,
        PACKET_RESTORATION_OBSERVE_FEATURE,
        PACKET_RESTORATION_SUFFIX_FEATURE,
    ] {
        let features = &mut declaration.peer.provider.extensions_supported;
        let feature = id(feature);
        if !features.contains(&feature) {
            features.push(feature);
        }
    }
    declaration
        .peer
        .provider
        .implementation
        .formats
        .sort_by(|a, b| a.id.cmp(&b.id));
    declaration.peer.provider.extensions_supported.sort();
    declaration.peer.provider.validate().unwrap();
    declaration
}

/// Adds the compiled settled17 family before provider and binding hashes exist.
pub(in super::super) fn with_settled17_declaration(
    mut declaration: PacketNative5CompleteRestoreDeclaration,
) -> PacketNative5CompleteRestoreDeclaration {
    use crucible_node_transport::reference_packet::service::complete_restore::settled_recapture::{
        restored_settled_capture_declared_contracts_data,
        restored_settled_capture_declared_features_data,
    };
    for (schema, bytes) in restored_settled_capture_declared_contracts_data().unwrap() {
        schema.definition.verify(bytes).unwrap();
        let formats = &mut declaration.peer.provider.implementation.formats;
        if let Some(previous) = formats.iter().find(|one| one.id == schema.id) {
            assert_eq!(previous, &schema);
        } else {
            formats.push(schema.clone());
        }
        declaration.restoration.push((schema, bytes.to_vec()));
    }
    for feature in restored_settled_capture_declared_features_data() {
        let feature = id(feature);
        let features = &mut declaration.peer.provider.extensions_supported;
        if !features.contains(&feature) {
            features.push(feature);
        }
    }
    declaration
        .peer
        .provider
        .implementation
        .formats
        .sort_by(|a, b| a.id.cmp(&b.id));
    declaration.peer.provider.extensions_supported.sort();
    declaration.peer.provider.validate().unwrap();
    declaration
}

/// Adds full import18 DATA before provider, binding and World identities exist.
pub(in super::super) fn with_import18_declaration(
    declaration: PacketNative5CompleteRestoreDeclaration,
) -> PacketNative5CompleteRestoreDeclaration {
    use crucible_node_transport::reference_packet::service::complete_restore::import18::{
        native_import18_contract_data, native_import18_declared_features_data,
        native_import18_restored_record_contract_data, native_import18_restored_record_schema_data,
        native_import18_schema_data, native_import18_stage_contract_data,
        native_import18_stage_schema_data,
    };

    let mut declaration = with_settled17_declaration(declaration);
    for (schema, bytes) in [
        (
            native_import18_schema_data().unwrap(),
            native_import18_contract_data().unwrap(),
        ),
        (
            native_import18_stage_schema_data().unwrap(),
            native_import18_stage_contract_data().unwrap(),
        ),
        (
            native_import18_restored_record_schema_data().unwrap(),
            native_import18_restored_record_contract_data().unwrap(),
        ),
    ] {
        schema.definition.verify(&bytes).unwrap();
        declaration
            .peer
            .provider
            .implementation
            .formats
            .push(schema.clone());
        declaration.restoration.push((schema, bytes));
    }
    for feature in native_import18_declared_features_data() {
        declaration
            .peer
            .provider
            .extensions_supported
            .push(id(feature));
    }
    declaration
        .peer
        .provider
        .implementation
        .formats
        .sort_by(|a, b| a.id.cmp(&b.id));
    declaration.peer.provider.extensions_supported.sort();
    declaration.peer.provider.validate().unwrap();
    declaration
}
