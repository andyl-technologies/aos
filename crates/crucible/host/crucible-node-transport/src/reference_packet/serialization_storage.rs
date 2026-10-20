//! Quotes the actual native model and Control snapshot serializer phases.
//!
//! The shared SDK visitor counts closed Serialize/DOM/parser/canonical terms.
//! Native code contributes its actual model wrapper and the independently
//! coexisting buffers in capture_model and capture_control_state. These are
//! requested-storage data, not Source permission or physical peak evidence.

use crate::{ProviderError, retained_metadata::RetainedProtocolMetadataFacts};
use serde::Serialize;
use std::mem::size_of;

use crate::retained_metadata::serialization_storage::OriginalSerializationStorageProjection;
pub(crate) use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData as NativeSerializationStorageData,
    actual_serialization_storage_data,
};

/// Encodes an already admitted closed producer into one reserved output bank.
///
/// The owning caller authenticates the real producer and admits its complete
/// temporary phase before this call. This data comparison cannot supply that
/// authority. The actual serializer is recounted before constructing its DOM;
/// the canonical writer then refuses any growth beyond the reserved extent.
pub(crate) fn encode_original_precharged_serialization(
    value: &impl Serialize,
    admitted: &NativeSerializationStorageData,
) -> Result<Vec<u8>, ProviderError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(admitted.maximum_encoded_bytes)
        .map_err(|_| ProviderError::ResourceExhausted("native precharged canonical producer"))?;
    encode_original_precharged_serialization_into(value, admitted, &mut bytes)?;
    Ok(bytes)
}

/// Writes into an already retained bank after reconciling every named phase.
///
/// A refused or interrupted writer leaves initialized bytes in the caller's
/// original bank. This performs no reserve and grants no construction credit.
///
/// # Errors
/// Refuses a nonempty or undersized bank, an actual serialization component
/// above its admitted bound, or failed serialization/canonical output.
pub(crate) fn encode_original_precharged_serialization_into(
    value: &impl Serialize,
    admitted: &NativeSerializationStorageData,
    bytes: &mut Vec<u8>,
) -> Result<(), ProviderError> {
    let exhausted = || ProviderError::ResourceExhausted("native precharged canonical producer");
    if !bytes.is_empty() || bytes.capacity() < admitted.maximum_encoded_bytes {
        return Err(exhausted());
    }
    let maximum = admitted.requested_total()?;
    let actual = actual_serialization_storage_data(value, Default::default(), maximum)?;
    for (actual, bound) in [
        (actual.maximum_encoded_bytes, admitted.maximum_encoded_bytes),
        (
            actual.dom_and_canonical_scratch_bytes,
            admitted.dom_and_canonical_scratch_bytes,
        ),
        (
            actual.retained_value_backing_bytes,
            admitted.retained_value_backing_bytes,
        ),
        (
            actual.projected_parser_requested_bytes,
            admitted.projected_parser_requested_bytes,
        ),
        (
            actual.canonical_output_requested_bytes,
            admitted.canonical_output_requested_bytes,
        ),
        (
            actual.serializer_temporary_requested_bytes,
            admitted.serializer_temporary_requested_bytes,
        ),
        (
            actual.declared_counter_scratch_bytes,
            admitted.declared_counter_scratch_bytes,
        ),
        (actual.sequence_elements, admitted.sequence_elements),
        (actual.sequence_containers, admitted.sequence_containers),
        (
            actual.serialized_value_nodes,
            admitted.serialized_value_nodes,
        ),
        (
            actual.serialized_capacity_records,
            admitted.serialized_capacity_records,
        ),
    ] {
        if actual > bound {
            return Err(exhausted());
        }
    }
    let dom = serde_json::to_value(value).map_err(crucible_node_format::ContractError::from)?;
    let mut writer = OriginalCanonicalBankWriter {
        bytes,
        maximum: admitted.maximum_encoded_bytes,
    };
    crucible_node_format::canonical::canonical_json_to_writer(&dom, &mut writer)?;
    Ok(())
}

struct OriginalCanonicalBankWriter<'a> {
    bytes: &'a mut Vec<u8>,
    maximum: usize,
}

impl std::io::Write for OriginalCanonicalBankWriter<'_> {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        let length = self
            .bytes
            .len()
            .checked_add(input.len())
            .filter(|length| *length <= self.maximum && *length <= self.bytes.capacity())
            .ok_or(std::io::ErrorKind::OutOfMemory)?;
        self.bytes.extend_from_slice(input);
        debug_assert_eq!(self.bytes.len(), length);
        Ok(input.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Bounds the pinned JSON phases from independently proved serializer events.
///
/// Every container/entry is conservatively charged as both an array and a map;
/// keys and strings cannot own more initialized UTF-8 bytes than the complete
/// serialized extent. The event counts must originate a closed serializer
/// grammar, not typed metadata visits or a byte-count conversion. Custom Bytes
/// and compact serializer scratch are supplied separately by that producer.
pub(crate) fn closed_event_serialization_storage_data(
    maximum_encoded_bytes: usize,
    serialized_value_nodes: usize,
    serialized_capacity_records: usize,
    serializer_temporary_requested_bytes: usize,
    maximum: usize,
) -> Result<NativeSerializationStorageData, ProviderError> {
    use crate::retained_metadata::serialization_storage::original_serialization_tree_node_requested_bytes_data;
    use serde_json::Value;
    let fail = || ProviderError::ResourceExhausted("native closed serializer event layout");
    let add = |left: usize, right: usize| left.checked_add(right).ok_or_else(fail);
    let multiply = |left: usize, right: usize| left.checked_mul(right).ok_or_else(fail);
    let sum = |terms: &[usize]| {
        terms
            .iter()
            .try_fold(0usize, |total, next| add(total, *next))
    };
    if serialized_value_nodes == 0 || serialized_capacity_records > serialized_value_nodes {
        return Err(fail());
    }
    let dom_tree = original_serialization_tree_node_requested_bytes_data::<String, Value>()?;
    let sort_tree =
        original_serialization_tree_node_requested_bytes_data::<Vec<u16>, (&str, &Value)>()?;
    // The same pinned min-capacity/geometric array growth used by the shared
    // actual visitor covers both unknown sequence hints and parser arrays.
    let array_slots = multiply(
        add(
            multiply(4, serialized_value_nodes)?,
            multiply(4, serialized_capacity_records)?,
        )?,
        size_of::<Value>(),
    )?;
    let dom_and_canonical_scratch_bytes = sum(&[
        array_slots,
        multiply(serialized_value_nodes, add(dom_tree, sort_tree)?)?,
        maximum_encoded_bytes,               // independently owned DOM strings
        multiply(4, maximum_encoded_bytes)?, // pinned escaped-string writer growth
        multiply(8, maximum_encoded_bytes)?, // UTF-16 key sort banks
        multiply(serialized_capacity_records, 20 + 256 + 16)?,
    ])?;
    let projected_parser_requested_bytes = sum(&[
        array_slots,
        multiply(serialized_value_nodes, dom_tree)?,
        multiply(4, maximum_encoded_bytes)?,
        multiply(32, serialized_capacity_records)?,
    ])?;
    let result = NativeSerializationStorageData {
        dom_and_canonical_scratch_bytes,
        // Each actual object root is a backing-bearing serialized event.
        // The independently proved capacity-record count bounds those roots,
        // including empty maps. Parser children and the Value root remain
        // separate; canonical/sort/output work is never used as backing.
        retained_value_backing_bytes: sum(&[
            projected_parser_requested_bytes,
            multiply(serialized_capacity_records, dom_tree)?,
            size_of::<Value>(),
        ])?,
        projected_parser_requested_bytes,
        canonical_output_requested_bytes: add(multiply(4, maximum_encoded_bytes)?, 256)?,
        serializer_temporary_requested_bytes,
        declared_counter_scratch_bytes: size_of::<NativeSerializationStorageData>()
            + size_of::<[usize; 12]>(),
        maximum_encoded_bytes,
        sequence_elements: serialized_value_nodes,
        sequence_containers: serialized_capacity_records,
        serialized_value_nodes,
        serialized_capacity_records,
    };
    if result.requested_total()? > maximum {
        return Err(fail());
    }
    Ok(result)
}

/// Combines independently counted closed children without constructing their DOM.
///
/// Each child includes its own punctuation, output growth and counter header;
/// retaining them all overcounts coexistence rather than refunding an alias.
pub(crate) fn sum_serialization_storage_data(
    children: &[&NativeSerializationStorageData],
    maximum: usize,
) -> Result<NativeSerializationStorageData, ProviderError> {
    let fail = || ProviderError::ResourceExhausted("native composed serialization layout");
    let add = |left: usize, right: usize| left.checked_add(right).ok_or_else(fail);
    let mut result = NativeSerializationStorageData {
        dom_and_canonical_scratch_bytes: 0,
        // This accumulator contains no child until the checked loop below.
        retained_value_backing_bytes: 0,
        projected_parser_requested_bytes: 0,
        canonical_output_requested_bytes: 0,
        serializer_temporary_requested_bytes: 0,
        declared_counter_scratch_bytes: size_of::<NativeSerializationStorageData>(),
        maximum_encoded_bytes: 0,
        sequence_elements: 0,
        sequence_containers: 0,
        serialized_value_nodes: 0,
        serialized_capacity_records: 0,
    };
    for child in children {
        macro_rules! component {
            ($field:ident) => {
                result.$field = add(result.$field, child.$field)?;
            };
        }
        component!(dom_and_canonical_scratch_bytes);
        component!(retained_value_backing_bytes);
        component!(projected_parser_requested_bytes);
        component!(canonical_output_requested_bytes);
        component!(serializer_temporary_requested_bytes);
        component!(declared_counter_scratch_bytes);
        component!(maximum_encoded_bytes);
        component!(sequence_elements);
        component!(sequence_containers);
        component!(serialized_value_nodes);
        component!(serialized_capacity_records);
    }
    if result.requested_total()? > maximum {
        return Err(fail());
    }
    Ok(result)
}

/// Quotes only the fixed native model wrapper surrounding its actual state.
///
/// The configuration reference has the actual capture_model algorithm/domain/
/// media grammar and fixed digest extent. Its length is bounded as a decimal
/// U64 without constructing a fake semantic hash or reference owner.
pub(crate) fn model_wrapper_storage_data(
    cursor: crucible_node_format::Position,
    capacities: &[usize; 6],
    maximum: usize,
) -> Result<NativeSerializationStorageData, ProviderError> {
    let mut projection = OriginalSerializationStorageProjection::new(maximum)?;
    projection.add_object()?;
    for key in [
        "schema",
        "kind",
        "captured_process",
        "configuration",
        "cut",
        "capacities",
        "state",
    ] {
        projection.add_field(key)?;
    }
    projection.add_string("source-owned.packet-native-model/5")?;
    projection.add_string_extent("producer".len().max("reactive".len()))?;
    projection.add_string_extent(20)?;
    projection.add_value(&cursor)?;
    projection.add_object()?;
    for (key, capacity) in [
        "events",
        "reactions",
        "delivered_inputs",
        "publications",
        "outputs",
        "stages",
    ]
    .into_iter()
    .zip(capacities)
    {
        projection.add_field(key)?;
        projection.add_value(capacity)?;
    }
    projection.add_object()?;
    for key in ["hash", "length", "media_type"] {
        projection.add_field(key)?;
    }
    projection.add_string_extent(20)?;
    projection.add_string("application/json")?;
    projection.add_object()?;
    for key in ["algorithm", "domain", "digest"] {
        projection.add_field(key)?;
    }
    projection.add_string("blake3-256")?;
    projection.add_string("cnp.blob.v1")?;
    projection.add_string_extent(64)?;
    projection.finish(maximum)
}

pub(crate) struct NativeModelCaptureEncodingData {
    pub(crate) requested_bytes: usize,
    pub(crate) maximum_encoded_bytes: usize,
    // These independently measured child costs are needed when Control parses
    // the model bytes and clones that Value into its separate full-root DOM.
    pub(crate) copied_value_requested_bytes: usize,
    pub(crate) parsed_value_requested_bytes: usize,
    pub(crate) canonical_output_requested_bytes: usize,
    pub(crate) serialized_value_nodes: usize,
    pub(crate) serialized_capacity_records: usize,
}

pub(crate) fn model_encoding_storage_data(
    definition: &impl Serialize,
    state: &impl Serialize,
    cursor: crucible_node_format::Position,
    capacities: [usize; 6],
    actual_fields: RetainedProtocolMetadataFacts,
    maximum: usize,
) -> Result<NativeModelCaptureEncodingData, ProviderError> {
    let fail = || ProviderError::ResourceExhausted("native complete model encoding storage");
    let definition = actual_serialization_storage_data(definition, actual_fields, maximum)?;
    let state = actual_serialization_storage_data(state, actual_fields, maximum)?;
    let wrapper = model_wrapper_storage_data(cursor, &capacities, maximum)?;
    // The exact configuration ContentRef owns algorithm/domain/digest/media
    // strings while definition bytes and the state DOM still coexist.
    let reference_strings =
        "blake3-256".len() + "cnp.blob.v1".len() + 2 * blake3::OUT_LEN + "application/json".len();
    let requested = [
        definition.requested_total()?,
        state.requested_total()?,
        wrapper.requested_total()?,
        reference_strings,
        size_of::<crucible_node_format::ContentRef>(),
        size_of::<[usize; 6]>(),
    ]
    .into_iter()
    .try_fold(0usize, |sum, next| sum.checked_add(next).ok_or_else(fail))?;
    let encoded = state
        .maximum_encoded_bytes
        .checked_add(wrapper.maximum_encoded_bytes)
        .ok_or_else(fail)?;
    if requested > maximum {
        return Err(fail());
    }
    Ok(NativeModelCaptureEncodingData {
        requested_bytes: requested,
        maximum_encoded_bytes: encoded,
        copied_value_requested_bytes: state
            .dom_and_canonical_scratch_bytes
            .checked_add(wrapper.dom_and_canonical_scratch_bytes)
            .ok_or_else(fail)?,
        parsed_value_requested_bytes: state
            .projected_parser_requested_bytes
            .checked_add(wrapper.projected_parser_requested_bytes)
            .ok_or_else(fail)?,
        canonical_output_requested_bytes: encoded
            .checked_mul(4)
            .and_then(|bytes| bytes.checked_add(256))
            .ok_or_else(fail)?,
        serialized_value_nodes: state
            .serialized_value_nodes
            .checked_add(wrapper.serialized_value_nodes)
            .ok_or_else(fail)?,
        serialized_capacity_records: state
            .serialized_capacity_records
            .checked_add(wrapper.serialized_capacity_records)
            .ok_or_else(fail)?,
    })
}

/// Reports the coexisting requested storage in the real Control snapshot path.
///
/// This is a current stopped-state data quote. Registration/cache/publication
/// growth caused by the future actual Capture is a separate named conjunction.
pub(crate) struct NativeControlCaptureEncodingData {
    pub(crate) requested_bytes: usize,
    pub(crate) maximum_encoded_bytes: usize,
    pub(crate) serialized_value_nodes: usize,
    pub(crate) serialized_capacity_records: usize,
}

impl NativeControlCaptureEncodingData {
    pub(crate) fn from_original_parts(
        model: NativeModelCaptureEncodingData,
        control: NativeSerializationStorageData,
        borrowed_row_requested_bytes: usize,
        content_references: usize,
        maximum: usize,
    ) -> Result<Self, ProviderError> {
        let fail = || ProviderError::ResourceExhausted("native full Control encoding storage");
        // ContentRef::verify produces one independent algorithm/domain/digest
        // HashRef during each validation. Native admitted content uses the
        // canonical fixed blob domain. Those temporary owned strings coexist
        // with the complete model and borrowed rows. The final output ref and
        // model verify create two more actual fixed-domain hash results.
        let hash_result = "blake3-256".len() + "cnp.blob.v1".len() + 2 * blake3::OUT_LEN;
        let hashes = content_references
            .checked_add(3)
            .and_then(|count| count.checked_mul(hash_result))
            .ok_or_else(fail)?;
        let requested = [
            // Definition bytes, model state/wrapper DOM, canonical/output
            // banks and their serialization scratch are retained as quoted.
            model.requested_bytes,
            // parse_json(model.bytes()) owns an independent full model Value.
            model.parsed_value_requested_bytes,
            // to_value(SnapshotView) clones that model into the full root DOM.
            model.copied_value_requested_bytes,
            // The full root canonical output includes this independent model
            // body even while the original model encoded bank is still live.
            model.canonical_output_requested_bytes,
            // The final parse_json(full canonical bytes) creates a second full
            // model child while both old Value and full root DOM still live.
            model.parsed_value_requested_bytes,
            control.requested_total()?,
            borrowed_row_requested_bytes,
            hashes,
            size_of::<NativeControlCaptureEncodingData>(),
            size_of::<crate::reference_packet::control::PacketOriginalControlSnapshot>(),
        ]
        .into_iter()
        .try_fold(0usize, |sum, next| sum.checked_add(next).ok_or_else(fail))?;
        let encoded = model
            .maximum_encoded_bytes
            .checked_add(control.maximum_encoded_bytes)
            .ok_or_else(fail)?;
        if requested > maximum {
            return Err(fail());
        }
        Ok(Self {
            requested_bytes: requested,
            maximum_encoded_bytes: encoded,
            serialized_value_nodes: model
                .serialized_value_nodes
                .checked_add(control.serialized_value_nodes)
                .ok_or_else(fail)?,
            serialized_capacity_records: model
                .serialized_capacity_records
                .checked_add(control.serialized_capacity_records)
                .ok_or_else(fail)?,
        })
    }
}

#[cfg(test)]
mod tests;
