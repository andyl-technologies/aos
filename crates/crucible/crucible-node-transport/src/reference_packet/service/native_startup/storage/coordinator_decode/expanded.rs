//! Completes coordinator construction DATA for nested Value reparses.
//!
//! The original manual parser preserves literal keys. Its subsequent owned
//! Value deserializer can invoke the locked RawValue adapter at Value fields.
//! This supplement separately prices those parsers and every later typed,
//! clone and canonical population reached by the real coordinator validator.
//! It changes no decoder, marker semantics, grammar, byte limit or permission.

use super::*;
use crate::protocol_snapshot::raw_value_reparse::{
    JsonValueReparseConstructionData, quote_raw_json_data, raw_scanner_counter_scratch_data,
};
use crate::reference_packet::continuation_models::serde_partials::{self, DecoderPartial};
use crate::retained_metadata::serialization_storage::{
    original_json_value_storage_extent_counter_scratch_data,
    original_json_value_storage_extent_data, original_json_value_storage_population_data,
    original_serialization_tree_node_counter_scratch_data,
    original_serialization_tree_node_requested_bytes_data,
};
use serde_json::Value;

/// Separates retained result, disposable work and input-dependent parser views.
pub(in crate::reference_packet::service::native_startup::storage) struct ConstructionData {
    pub(in crate::reference_packet::service::native_startup::storage) retained: usize,
    pub(in crate::reference_packet::service::native_startup::storage) transient: usize,
    pub(in crate::reference_packet::service::native_startup::storage) additional_scratch: usize,
}

/// Names the concrete extra populations reached after a Value reset.
///
/// Each class is a real call site or disjoint loop population. They are summed
/// conservatively, although many finish before the next starts. A population
/// uses the whole additional event budget because markers can occur at any of
/// these Value roots. Each World identity also calls World validation again;
/// its population includes those scalar key copies as well as its DOM/JCS.
/// Connection policies include both static-content JCS and distinct field
/// clone/from_value calls. Guarantee populations likewise include the static
/// JCS comparison and later typed GuaranteeProfile adapter. Those subwindows
/// are sequential; each population includes independent DOM, typed, formatting
/// and output banks, while all earlier retained outputs remain charged.
/// No unrelated Control/model root supplies an element size.
#[derive(Clone, Copy)]
enum Population {
    WorldDecode,
    WorldValidationKeys,
    WorldIdentityBeforeRoster,
    WorldIdentityNative0,
    WorldIdentityNative1,
    WorldIdentityNative2,
    NativeProviderValidation,
    NativeRealizationValidation,
    NativeRealizeValidation,
    NativeOwnerClones,
    NativeDescriptorValues,
    NativeBindingValues,
    NativeOwnerDomainValues,
    NativeProfileValues,
    HostOwnerClone,
    HostDescriptorValue,
    HostBindingValue,
    HostDomainValue,
    HostConfiguration,
    ActivationScalars,
    ConnectionPolicies,
    GuaranteesNative0,
    GuaranteesNative1,
    GuaranteesNative2,
    GuaranteesHostNode,
    GuaranteesHostSelection,
    StaticOwnership,
    StaticCoordinator,
    NativePortConfiguration,
    NativeBindingIdentity,
    HostBindingIdentity,
    HostDescriptorIdentity,
}

const POPULATIONS: [Population; 32] = [
    Population::WorldDecode,
    Population::WorldValidationKeys,
    Population::WorldIdentityBeforeRoster,
    Population::WorldIdentityNative0,
    Population::WorldIdentityNative1,
    Population::WorldIdentityNative2,
    Population::NativeProviderValidation,
    Population::NativeRealizationValidation,
    Population::NativeRealizeValidation,
    Population::NativeOwnerClones,
    Population::NativeDescriptorValues,
    Population::NativeBindingValues,
    Population::NativeOwnerDomainValues,
    Population::NativeProfileValues,
    Population::HostOwnerClone,
    Population::HostDescriptorValue,
    Population::HostBindingValue,
    Population::HostDomainValue,
    Population::HostConfiguration,
    Population::ActivationScalars,
    Population::ConnectionPolicies,
    Population::GuaranteesNative0,
    Population::GuaranteesNative1,
    Population::GuaranteesNative2,
    Population::GuaranteesHostNode,
    Population::GuaranteesHostSelection,
    Population::StaticOwnership,
    Population::StaticCoordinator,
    Population::NativePortConfiguration,
    Population::NativeBindingIdentity,
    Population::HostBindingIdentity,
    Population::HostDescriptorIdentity,
];

pub(in super::super) fn construction_storage_data(
    bytes: &[u8],
    maximum: usize,
) -> Result<ConstructionData, ProviderError> {
    if bytes.is_empty()
        || bytes.len()
            > crate::reference_packet::coordinator::PACKET_NATIVE5_COORDINATOR_INSTALLATION_BYTES
    {
        return Err(refused());
    }
    // The public fixed counter must precede this borrowed canonical-raw64 scan.
    let raw = quote_raw_json_data(bytes, maximum)?;
    let axes = raw.requested_storage_data();
    if axes == (0, 0, 0) {
        return Ok(ConstructionData {
            retained: backing(bytes, maximum)?,
            transient: sum(
                &[
                    quote(bytes, maximum)?,
                    diagnostic_storage_data(bytes.len(), maximum)?,
                ],
                maximum,
            )?,
            additional_scratch: 0,
        });
    }
    let (nodes, members, text) = raw.expanded_json_extents_data();
    let extra = population_storage_data(nodes, members, text, maximum)?;
    let retained = sum(&[backing(bytes, maximum)?, axes.0], maximum)?;

    // Ordinary structural fields retain their precise existing quote. A reset
    // can instead supply the entire template or a field hidden inside its text.
    // In that case the old raw field selector cannot see the accepted post-reset
    // shape. Price complete original occurrences too; do not turn an unsupported
    // raw selector into zero work or widen the actual DTO decoder.
    let baseline = match quote(bytes, maximum) {
        Ok(actual) => actual,
        Err(_) => {
            let original = original_json_value_storage_extent_data(bytes.len())?;
            let full = population_storage_data(
                checked_add(original.maximum_value_nodes, nodes)?,
                checked_add(original.maximum_object_members, members)?,
                checked_add(original.maximum_decoded_string_bytes, text)?,
                maximum,
            )?;
            let mut total = decode_value(bytes, maximum)?;
            for _actual in POPULATIONS {
                total = sum(&[total, full], maximum)?;
            }
            sum(&[total, identity_rows(maximum)?,
                crate::reference_packet::continuation_contracts::complete_coordinator_contract_storage_data(maximum)?], maximum)?
        }
    };
    let mut transient = sum(
        &[
            baseline,
            axes.0,
            axes.1,
            diagnostic_storage_data(checked_add(bytes.len(), text)?, maximum)?,
        ],
        maximum,
    )?;
    let mut additional_scratch = axes.2;
    for _actual in POPULATIONS {
        // The owned subtree can enter another from_value adapter. Preserve a
        // full independent Raw parser window for every actual consumer; the
        // generic helper's extra layers do not fund typed or canonical work.
        transient = sum(&[transient, extra, axes.0, axes.1], maximum)?;
        additional_scratch = sum(&[additional_scratch, axes.2], maximum)?;
    }
    sum(&[retained, transient, additional_scratch], maximum)?;
    Ok(ConstructionData {
        retained,
        transient,
        additional_scratch,
    })
}

fn population_storage_data(
    nodes: usize,
    members: usize,
    text: usize,
    maximum: usize,
) -> Result<usize, ProviderError> {
    if nodes == 0 && members == 0 && text == 0 {
        return Ok(0);
    }
    // Raw4 supplies additional decoded events. Reuse the defining JSON layout
    // arithmetic directly; converting requested heap back to encoded bytes would
    // lose both the event proof and useful small-marker geometry.
    let value = original_json_value_storage_population_data(nodes, members, text)?;
    let slot = maximum_array_element_layout_data();
    let typed_arrays = checked_mul(checked_mul(8, nodes)?, slot)?;
    let typed_tree_node = original_serialization_tree_node_requested_bytes_data::<String, Value>()?;
    let typed_maps = checked_mul(checked_mul(2, members)?, typed_tree_node)?;
    let typed_strings = checked_add(checked_mul(8, text)?, checked_mul(32, nodes)?)?;
    // Struct serializers can emit required/default fields absent from an input
    // map. Bound these from the ACTUAL rooted DTO derive DAG, not Control50.
    let (fields, field_text) = emitted_fields_data();
    let emitted_nodes = checked_add(nodes, checked_mul(nodes, fields)?)?;
    let emitted_members = checked_add(members, checked_mul(nodes, fields)?)?;
    let emitted_text = checked_add(text, checked_mul(nodes, field_text)?)?;
    let emitted =
        original_json_value_storage_population_data(emitted_nodes, emitted_members, emitted_text)?;
    sum(
        &[
            value.value_dom_requested_bytes,
            value.canonical_work_requested_bytes,
            value.canonical_output_requested_bytes,
            typed_arrays,
            typed_maps,
            typed_strings,
            emitted.value_dom_requested_bytes,
            emitted.canonical_work_requested_bytes,
            emitted.canonical_output_requested_bytes,
        ],
        maximum,
    )
}

fn maximum_array_element_layout_data() -> usize {
    let content = size_of::<serde::__private228::de::Content<'static>>();
    let pair = size_of::<(
        serde::__private228::de::Content<'static>,
        serde::__private228::de::Content<'static>,
    )>();
    <PacketNative5CoordinatorInstallation as DecoderPartial>::TYPED_LAYOUT
        .0
        .max(<WorldBinding as DecoderPartial>::TYPED_LAYOUT.0)
        .max(<GuaranteeProfile as DecoderPartial>::TYPED_LAYOUT.0)
        .max(content)
        .max(pair)
}

fn emitted_fields_data() -> (usize, usize) {
    serde_partials::maximum_fields_data(
        <PacketNative5CoordinatorInstallation as DecoderPartial>::EMITTED_FIELDS,
        serde_partials::maximum_fields_data(
            <WorldBinding as DecoderPartial>::EMITTED_FIELDS,
            <GuaranteeProfile as DecoderPartial>::EMITTED_FIELDS,
        ),
    )
}

fn diagnostic_storage_data(text: usize, maximum: usize) -> Result<usize, ProviderError> {
    let names = <PacketNative5CoordinatorInstallation as DecoderPartial>::DIAGNOSTIC_NAMES_BYTES
        .max(<WorldBinding as DecoderPartial>::DIAGNOSTIC_NAMES_BYTES)
        .max(<GuaranteeProfile as DecoderPartial>::DIAGNOSTIC_NAMES_BYTES);
    // One actual serde error can quote arbitrary supplied key/string text plus
    // the reached complete type/field/variant list. Six bytes per UTF8 byte
    // covers debug quoting; the formatter's geometric bank requests are separate.
    let display = checked_add(checked_mul(6, text)?, names)?;
    let display = checked_add(display, serde_partials::diagnostic_format_text_bytes_data())?;
    let display = checked_add(display, size_of::<[u8; 20]>())?;
    sum(
        &[
            checked_add(checked_mul(8, display)?, 256)?,
            serde_partials::diagnostic_error_impl_allocation_upper_bytes_data(),
        ],
        maximum,
    )
}

fn checked_add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(refused)
}

fn checked_mul(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(refused)
}

// These tuples name caller-owned scalar views independently of the callee's
// counter. Alternative branches are summed conservatively; no compiler-frame
// copy factor or unrelated decoder state supplies these direct controls.
type QuoteScalarViews = (
    usize,                 // maximum
    (usize, usize, usize), // copied Raw axes
    (usize, usize, usize), // additional nodes, members and text
    usize,                 // extra population
    usize,                 // retained
    usize,                 // baseline
    usize,                 // fallback full population
    usize,                 // fallback total
    usize,                 // transient
    usize,                 // additional scratch
);

type PopulationScalarViews = (
    usize,          // nodes
    usize,          // members
    usize,          // text
    usize,          // maximum
    usize,          // concrete slot
    usize,          // typed arrays
    usize,          // typed tree node
    usize,          // typed maps
    usize,          // typed strings
    (usize, usize), // emitted fields and key text
    usize,          // emitted nodes
    usize,          // emitted members
    usize,          // emitted text
);

type DiagnosticScalarViews = (
    usize, // input text
    usize, // maximum
    usize, // complete diagnostic names
    usize, // display before fixed literals
    usize, // display after fixed literals
    usize, // display after scalar formatting
);

pub(super) fn counter_scratch_data() -> usize {
    <PacketNative5CoordinatorInstallation as DecoderPartial>::partial_counter_data()
        + <WorldBinding as DecoderPartial>::partial_counter_data()
        + <GuaranteeProfile as DecoderPartial>::partial_counter_data()
        + raw_scanner_counter_scratch_data()
        + original_json_value_storage_extent_counter_scratch_data()
        + original_serialization_tree_node_counter_scratch_data()
        + size_of::<ConstructionData>()
        + size_of::<Result<ConstructionData, ProviderError>>()
        + size_of::<JsonValueReparseConstructionData>()
        + size_of::<Result<JsonValueReparseConstructionData, ProviderError>>()
        + size_of::<Population>()
        + size_of::<[Population; 32]>()
        + size_of::<std::array::IntoIter<Population, 32>>()
        + size_of::<[usize; 3]>()
        + size_of::<[usize; 4]>()
        + size_of::<[usize; 9]>()
        + size_of::<(usize, usize)>()
        + size_of::<
            Result<
                crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData,
                ProviderError,
            >,
        >()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<&[u8]>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Option<usize>>()
        + size_of::<QuoteScalarViews>()
        + size_of::<PopulationScalarViews>()
        + size_of::<DiagnosticScalarViews>()
        // Explicit caller values survive nested extent-helper invocations.
        + size_of::<crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData>() // value
        + size_of::<crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData>() // emitted
        + size_of::<crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData>() // fallback original
        + size_of::<usize>() // Content slot
        + size_of::<usize>() // map-pair slot
        + size_of::<[u8; 20]>()
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn complete_scope() -> (PacketControlSelection, Value) {
        let (_, _, local, original) =
            crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
        (
            local,
            canonical::parse_json(original.bytes.as_slice(), original.bytes.as_slice().len())
                .unwrap(),
        )
    }

    #[test]
    fn complete_row_covers_actual_retained_decode_and_exact_boundary() -> TestResult {
        let (local, original) = complete_scope();
        let raw = canonical::canonical_json(&original)?;
        let row = PacketNative5CoordinatorInstallation::decode_construction_storage_data(
            &raw,
            usize::MAX,
        )?;
        let complete = PacketNative5CoordinatorInstallation::decode(&raw, &local)?;
        let facts = crate::retained_metadata::observe_retained_native_coordinator(&complete)?;
        assert!(row[0] >= requested_metadata_backing_storage_data(&facts)?);
        let total = row
            .into_iter()
            .try_fold(0usize, usize::checked_add)
            .unwrap();
        assert_eq!(
            PacketNative5CoordinatorInstallation::decode_construction_storage_data(&raw, total)?,
            row
        );
        assert!(
            PacketNative5CoordinatorInstallation::decode_construction_storage_data(&raw, total - 1)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn literal_reserved_extension_is_preserved_within_conservative_construction_rows() -> TestResult
    {
        let (_, mut original) = complete_scope();
        let payload = serde_json::json!({"nested":[0,1,{"kept":"actual"}]});
        let literal =
            serde_json::json!({"$serde_json::private::RawValue": serde_json::to_string(&payload)?});
        let expected = literal.clone();
        original["participants"][0]["provider"]["extensions"]["coordinator-quote-control"] =
            literal;
        let raw = canonical::canonical_json(&original)?;
        let local: PacketControlSelection =
            serde_json::from_value(original["participants"][0].clone())?;
        let row = PacketNative5CoordinatorInstallation::decode_construction_storage_data(
            &raw,
            usize::MAX,
        )?;
        let extra = quote_raw_json_data(&raw, usize::MAX)?;
        assert!(extra.detected_strings_data() > 0);
        assert!(
            row[2]
                > PacketNative5CoordinatorInstallation::decode_construction_counter_scratch_data()
        );
        let complete = PacketNative5CoordinatorInstallation::decode(&raw, &local)?;
        // The real schema decoder preserves literal extension data. Other
        // coordinator consumers still use ordinary Value decoding, so the
        // shared conservative reset supplement remains independently charged.
        assert_eq!(
            complete.participants[0].provider.extensions["coordinator-quote-control"],
            expected
        );
        let facts = crate::retained_metadata::observe_retained_native_coordinator(&complete)?;
        assert!(row[0] >= requested_metadata_backing_storage_data(&facts)?);
        Ok(())
    }

    #[test]
    fn malformed_normalized_world_is_funded_then_refused_by_real_decoder() -> TestResult {
        let (local, mut original) = complete_scope();
        original["template"]["world"] = serde_json::json!({
            "$serde_json::private::RawValue": "{\"unknown_world_field\":[]}"
        });
        let raw = canonical::canonical_json(&original)?;
        let row = PacketNative5CoordinatorInstallation::decode_construction_storage_data(
            &raw,
            usize::MAX,
        )?;
        assert!(row[1] > 0 && row[2] > 0);
        assert!(PacketNative5CoordinatorInstallation::decode(&raw, &local).is_err());
        Ok(())
    }

    #[test]
    fn event_layout_covers_actual_owned_tree_and_canonical_output() -> TestResult {
        fn count(value: &Value, nodes: &mut usize, members: &mut usize, text: &mut usize) {
            *nodes += 1;
            match value {
                Value::Array(values) => {
                    for value in values {
                        count(value, nodes, members, text);
                    }
                }
                Value::Object(values) => {
                    for (key, value) in values {
                        *nodes += 1;
                        *members += 1;
                        *text += key.len();
                        count(value, nodes, members, text);
                    }
                }
                Value::String(value) => *text += value.len(),
                _ => {}
            }
        }

        let value = serde_json::json!({
            "array": [null, true, 1, -1.25, [], {}],
            "escaped": "line\nquote\"unicode💡"
        });
        let (mut nodes, mut members, mut text) = (0, 0, 0);
        count(&value, &mut nodes, &mut members, &mut text);
        let row = original_json_value_storage_population_data(nodes, members, text)?;
        let mut actual = MetadataObserver::new();
        actual.observe(&value)?;
        let backing = requested_metadata_backing_storage_data(&actual.finish())?;
        let encoded = canonical::canonical_json(&value)?;
        assert!(row.value_dom_requested_bytes >= backing);
        assert!(row.maximum_canonical_encoded_bytes >= encoded.len());
        assert!(row.canonical_output_requested_bytes >= encoded.capacity());

        assert!(original_json_value_storage_population_data(0, 0, 0).is_err());
        assert!(original_json_value_storage_population_data(1, 2, 0).is_err());
        assert!(original_json_value_storage_population_data(usize::MAX, 0, 1).is_err());
        Ok(())
    }
}
