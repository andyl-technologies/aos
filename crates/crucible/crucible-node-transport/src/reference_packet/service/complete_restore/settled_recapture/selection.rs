//! Checks immutable complete definitions and actual negotiated recapture support.

use super::*;
use crate::reference_packet::service::{
    restored_input_reactive17 as input, restored_settled_capture as capture,
    restored_settled_confirmation as confirmation,
};
use crate::{handshake::ConnectionAuthority, reference_packet::control::PacketControlSelection};

pub(super) const FEATURES: [&str; 6] = [
    PACKET_RESTORED_SETTLED_RECAPTURE_FEATURE,
    PACKET_RESTORED_SETTLED_INPUT_REACTIVE_FEATURE,
    input::RESTORED_INPUT_REACTIVE17_FEATURE,
    capture::RESTORED_SETTLED_CAPTURE_FEATURE,
    capture::upload::RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE,
    confirmation::PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_FEATURE,
];

/// Authenticates both immutable rosters and every negotiated Capture17 contract.
///
/// This predicate creates no Capture permission, original request or live
/// decoder. The actual Source marker, private startup17 carrier, issuer and
/// complete current-owner census remain independent required conjunctions.
///
/// # Errors
/// Refuses missing inherited observation support, empty binding rosters,
/// changed or duplicate definitions, or absent or duplicate selected features.
pub fn authenticate_restored_settled_capture_selection_data(
    selection: &PacketControlSelection,
    authority: &ConnectionAuthority,
) -> Result<(), ProviderError> {
    super::super::restoration_observe::authenticate_restoration_observe_selection_data(
        selection, authority,
    )?;
    authenticate_formats(&selection.provider.implementation.formats)?;
    if selection.realization.bindings.is_empty() {
        return Err(invalid());
    }
    for binding in &selection.realization.bindings {
        authenticate_formats(&binding.compatibility.implementation.formats)?;
    }

    for expected in FEATURES {
        for features in [
            selection.provider.extensions_supported.as_slice(),
            authority.selected_features().as_slice(),
        ] {
            let mut found = false;
            for feature in features {
                if feature.as_str() == expected {
                    if found {
                        return Err(invalid());
                    }
                    found = true;
                }
            }
            if !found {
                return Err(invalid());
            }
        }
        if !authority.envelope_extensions().contains(expected) {
            return Err(invalid());
        }
    }
    authority.ensure_live()
}

/// Authenticates complete declared capability rosters before launch selection.
///
/// This comparison deliberately does not select startup17 or issue Capture
/// permission. Original Capture15 and future17 targets may share these exact
/// immutable capabilities while signed archive keys select historical decoders.
///
/// # Errors
/// Refuses a missing, duplicated or substituted full definition or feature.
pub fn authenticate_restored_settled_capture_immutable_declaration_data(
    provider_formats: &[SchemaRef],
    binding_formats: &[SchemaRef],
    provider_features: &[Id],
) -> Result<(), ProviderError> {
    authenticate_formats(provider_formats)?;
    authenticate_formats(binding_formats)?;
    for expected in FEATURES {
        let mut found = false;
        for feature in provider_features {
            if feature.as_str() == expected {
                if found {
                    return Err(invalid());
                }
                found = true;
            }
        }
        if !found {
            return Err(invalid());
        }
    }
    Ok(())
}

fn authenticate_formats(formats: &[SchemaRef]) -> Result<(), ProviderError> {
    for expected in [
        PACKET_RESTORED_SETTLED_RECAPTURE_FEATURE,
        capture::RESTORED_SETTLED_CAPTURE_FEATURE,
        capture::upload::RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE,
        confirmation::PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_FEATURE,
        PACKET_RESTORED_SETTLED_NATIVE_SNAPSHOT,
        "source-owned.packet-restored-settled-startup/17",
        COORDINATOR_CHECKPOINT17_SCHEMA,
        input::RESTORED_INPUT_REACTIVE17_FEATURE,
    ] {
        let mut matched = None;
        for schema in formats {
            if schema.id.as_str() == expected && matched.replace(schema).is_some() {
                return Err(invalid());
            }
        }
        let actual = matched.ok_or_else(invalid)?;
        match expected {
            PACKET_RESTORED_SETTLED_RECAPTURE_FEATURE => {
                authenticate_restored_settled_recapture_schema_data(actual)?;
            }
            capture::RESTORED_SETTLED_CAPTURE_FEATURE => {
                capture::authenticate_restored_settled_capture_schema_data(actual)?;
            }
            capture::upload::RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE => {
                capture::upload::authenticate_restored_settled_capture_upload_schema_data(actual)?;
            }
            confirmation::PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_FEATURE => {
                confirmation::authenticate_restored_settled_after_confirmation_schema_data(actual)?;
            }
            PACKET_RESTORED_SETTLED_NATIVE_SNAPSHOT => {
                crate::reference_packet::service::native_snapshot::authenticate_native_restored_settled17_snapshot_schema_data(actual)?;
            }
            "source-owned.packet-restored-settled-startup/17" => {
                crate::reference_packet::service::native_startup::authenticate_restored_settled_startup_schema_data(actual)?;
            }
            COORDINATOR_CHECKPOINT17_SCHEMA => {
                authenticate_coordinator_checkpoint17_schema_data(actual)?
            }
            input::RESTORED_INPUT_REACTIVE17_FEATURE => {
                input::authenticate_restored_input_reactive17_schema_data(actual)?
            }
            _ => return Err(invalid()),
        }
    }
    Ok(())
}

/// Reports the defining borrowed full-selection and schema-comparison views.
///
/// The getter provides fixed accounting DATA, never negotiated authority or
/// credit for artifacts, serializers, owner walks or native actions.
pub fn restored_settled_capture_selection_counter_scratch_data() -> usize {
    use std::mem::{size_of, size_of_val};

    let terms = [
        super::super::restoration_observe::restoration_observe_protocol_counter_scratch_data(),
        restored_settled_recapture_schema_counter_scratch_data(),
        coordinator_checkpoint17_schema_counter_scratch_data(),
        input::restored_input_reactive17_contract_counter_scratch_data(),
        capture::restored_settled_capture_schema_counter_scratch_data(),
        capture::upload::restored_settled_capture_upload_schema_counter_scratch_data(),
        confirmation::restored_settled_after_confirmation_schema_counter_scratch_data(),
        crate::reference_packet::service::native_snapshot::native_restored_settled17_snapshot_counter_scratch_data(),
        size_of::<[&str; 8]>(),
        size_of::<std::array::IntoIter<&str, 8>>(),
        crate::reference_packet::service::native_startup::restored_settled_startup_schema_counter_scratch_data(),
        size_of::<&PacketControlSelection>(),
        size_of::<&ConnectionAuthority>(),
        size_of::<&[SchemaRef]>(),
        size_of::<std::slice::Iter<'static, SchemaRef>>(),
        size_of::<Option<&SchemaRef>>(),
        size_of::<Result<&SchemaRef, ProviderError>>(),
        size_of::<std::slice::Iter<'static, crucible_node_format::NodeBinding>>(),
        size_of::<&crucible_node_format::NodeBinding>(),
        size_of::<[&[Id]; 2]>(),
        size_of::<std::array::IntoIter<&[Id], 2>>(),
        size_of::<&[Id]>(),
        size_of::<std::slice::Iter<'static, Id>>(),
        size_of::<&Id>(),
        size_of::<&SchemaRef>(),
        size_of::<&str>(),
        size_of::<bool>(),
        size_of::<[&str; 6]>(),
        size_of::<std::array::IntoIter<&str, 6>>(),
        size_of::<Result<(), ProviderError>>(),
    ];
    size_of_val(&terms)
        + size_of::<std::slice::Iter<'static, usize>>()
        + terms.iter().sum::<usize>()
}
