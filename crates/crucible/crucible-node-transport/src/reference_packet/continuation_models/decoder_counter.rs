//! Declares concrete model/owned-JSON decoder controls without decoding DATA.
//!
//! Private serde_json 1.0.150 states are bounded from their actual fields and
//! alignment. No unrelated public deserializer or fabricated JSON probe stands
//! in for them. This changes no decoder or successful input grammar.

use super::serde_partials::{DecoderPartial, decoder_struct};
use super::*;
use serde_json::Value;
use std::collections::{BTreeMap, btree_map};
use std::mem::size_of;

decoder_struct!(ModelRecord {
    schema,
    kind,
    captured_process,
    configuration,
    cut,
    capacities,
    state
});
decoder_struct!(ModelCapacities {
    events,
    reactions,
    delivered_inputs,
    publications,
    outputs,
    stages
});
impl DecoderPartial for PacketModelKind {
    const DIAGNOSTIC_NAMES_BYTES: usize =
        super::serde_partials::model_kind_diagnostic_name_bytes_data();

    fn partial_counter_data() -> usize {
        size_of::<Self>() + size_of::<Result<Self, serde_json::Error>>()
    }
}

/// Names ordinary model decoding and its actual derived field partials.
pub(in crate::reference_packet) fn model_decoder_counter_scratch_data() -> usize {
    owned_json_decoder_counter_scratch_data()
        + size_of::<PacketDecodedModelSnapshot>()
        + size_of::<Result<PacketDecodedModelSnapshot, ProviderError>>()
        + size_of::<ModelRecord>()
        + size_of::<ModelCapacities>()
        + size_of::<&[u8]>()
        + size_of::<&ContentRef>()
        + size_of::<ContentRef>()
        + size_of::<Value>()
        + size_of::<Vec<u8>>()
        + size_of::<Result<ModelRecord, serde_json::Error>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<usize>()
        + ModelRecord::partial_counter_data()
}

/// Names concrete owned serde states and bounded parser/JCS controls.
pub(in crate::reference_packet) fn owned_json_decoder_counter_scratch_data() -> usize {
    crate::protocol_snapshot::serde_decode_layout::owned_value_counter_scratch_data()
        + size_of::<Result<(), ContractError>>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + returned_size(blake3::Hash::to_hex)
        + size_of::<[u8; 4]>()
        + size_of::<[u8; 8]>()
        + canonical::json_parse_counter_scratch_bytes_data()
        + canonical::canonical_number_counter_scratch_bytes_data()
        + canonical_writer_views_data()
}

fn returned_size<T>(_: fn(&blake3::Hash) -> T) -> usize {
    size_of::<T>()
}

fn canonical_writer_views_data() -> usize {
    65 * canonical_value_writer_frame_data() + 65 * size_of::<Result<(), ContractError>>()
}

/// Names one real Value serializer and canonical recursive writer activation.
pub(in crate::reference_packet) fn canonical_value_writer_frame_data() -> usize {
    type Serializer = serde_json::value::Serializer;
    type Sequence = <Serializer as serde::Serializer>::SerializeSeq;
    type MapWriter = <Serializer as serde::Serializer>::SerializeMap;
    type TupleVariant = <Serializer as serde::Serializer>::SerializeTupleVariant;
    type StructVariant = <Serializer as serde::Serializer>::SerializeStructVariant;
    size_of::<&Value>()
        + size_of::<&mut Vec<u8>>()
        + size_of::<usize>()
        + size_of::<BTreeMap<Vec<u16>, (&str, &Value)>>()
        + size_of::<
            std::iter::Enumerate<
                btree_map::Values<'static, Vec<u16>, (&'static str, &'static Value)>,
            >,
        >()
        + size_of::<std::iter::Enumerate<std::slice::Iter<'static, Value>>>()
        + size_of::<serde_json::map::Iter<'static>>()
        + size_of::<std::str::EncodeUtf16<'static>>()
        + size_of::<String>()
        + size_of::<Result<String, serde_json::Error>>()
        + size_of::<Result<(), std::io::Error>>()
        + size_of::<serde_json::Serializer<&mut Vec<u8>>>()
        + size_of::<Serializer>()
        + size_of::<Sequence>()
        + size_of::<Result<Sequence, serde_json::Error>>()
        + size_of::<MapWriter>()
        + size_of::<Result<MapWriter, serde_json::Error>>()
        + size_of::<TupleVariant>()
        + size_of::<Result<TupleVariant, serde_json::Error>>()
        + size_of::<StructVariant>()
        + size_of::<Result<StructVariant, serde_json::Error>>()
        + size_of::<Value>()
        + size_of::<Result<Value, serde_json::Error>>()
        + size_of::<Result<(), ContractError>>()
}

/// Returns actual model typed slots, generated fields and buffered-tag levels.
pub(in crate::reference_packet) const fn model_decoder_geometry_data()
-> ((usize, usize, usize, usize), (usize, usize), usize) {
    (
        ModelRecord::TYPED_LAYOUT,
        ModelRecord::EMITTED_FIELDS,
        ModelRecord::BUFFERED_TAG_LEVELS,
    )
}

/// Names static diagnostic labels in the actual private model DTO graph.
pub(in crate::reference_packet) const fn model_decoder_diagnostic_name_bytes_data() -> usize {
    ModelRecord::DIAGNOSTIC_NAMES_BYTES
}
