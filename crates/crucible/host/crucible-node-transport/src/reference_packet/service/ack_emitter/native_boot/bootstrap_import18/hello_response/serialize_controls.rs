//! Names concrete serializer states and the complete initial result field DAG.
//!
//! Associated serde JSON types name the actual allocating compound states.
//! Sibling fields reuse their maximum child window; only a root-to-leaf path
//! coexists. These logical requested controls make no compiler-frame or ABI
//! claim. JSON extensions use the same checked 64-container plus scalar profile.

use crate::handshake::{HelloResult, Limits, ResumedOperation};
use crucible_node_format::{
    ArtifactIdentity, Bytes, ContentRef, FacetSelection, HashRef, Id, ImplementationIdentity,
    NodeManifest, ProviderManifest, SchemaRef, U64,
};
use serde::Serializer;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::mem::size_of;

type JsonSerializer = serde_json::value::Serializer;
type MapState = <JsonSerializer as Serializer>::SerializeMap;
type StructState = <JsonSerializer as Serializer>::SerializeStruct;
type SequenceState = <JsonSerializer as Serializer>::SerializeSeq;
type TupleState = <JsonSerializer as Serializer>::SerializeTuple;
type TupleStructState = <JsonSerializer as Serializer>::SerializeTupleStruct;
type TupleVariantState = <JsonSerializer as Serializer>::SerializeTupleVariant;
type StructVariantState = <JsonSerializer as Serializer>::SerializeStructVariant;

trait Controls {
    const DATA: usize;
}

const fn maximum(values: &[usize]) -> usize {
    let mut largest = 0;
    let mut index = 0;
    while index < values.len() {
        if values[index] > largest {
            largest = values[index];
        }
        index += 1;
    }
    largest
}

const fn window<T>() -> usize {
    size_of::<&T>() + size_of::<JsonSerializer>()
        + size_of::<MapState>() + size_of::<StructState>()
        + size_of::<SequenceState>() + size_of::<TupleState>()
        + size_of::<TupleStructState>() + size_of::<TupleVariantState>()
        + size_of::<StructVariantState>()
        + size_of::<Value>() + size_of::<Result<Value, serde_json::Error>>()
        + size_of::<Result<(), serde_json::Error>>()
        + size_of::<&'static str>() * 3 // field, variant and internal tag names
        + size_of::<u32>() // concrete serde variant index
        + size_of::<usize>() * 2
}

impl Controls for String {
    const DATA: usize = window::<Self>()
        + size_of::<String>()
        + size_of::<Vec<u8>>()
        + size_of::<&str>()
        + size_of::<&[u8]>();
}

impl Controls for Id {
    const DATA: usize = window::<Self>() + String::DATA;
}

impl Controls for Bytes {
    const DATA: usize = window::<Self>()
        + String::DATA
        + size_of::<&[u8]>()
        + size_of::<Vec<u8>>()
        + size_of::<Result<String, std::string::FromUtf8Error>>();
}

impl Controls for U64 {
    const DATA: usize = window::<Self>()
        + size_of::<[u8; 20]>()
        + size_of::<Result<&'static str, std::str::Utf8Error>>()
        + String::DATA;
}

impl Controls for u16 {
    const DATA: usize = window::<Self>();
}

impl<T: Controls + 'static> Controls for Vec<T> {
    const DATA: usize = window::<Self>()
        + size_of::<std::slice::Iter<'static, T>>()
        + size_of::<Option<&'static T>>()
        + T::DATA;
}

impl<T: Controls + 'static> Controls for BTreeMap<String, T> {
    const DATA: usize = window::<Self>()
        + size_of::<std::collections::btree_map::Iter<'static, String, T>>()
        + size_of::<Option<(&'static String, &'static T)>>()
        + maximum(&[String::DATA, T::DATA]);
}

impl Controls for Value {
    const DATA: usize = 65
        * (window::<Self>()
            + size_of::<serde_json::map::Iter<'static>>()
            + size_of::<std::slice::Iter<'static, Value>>()
            + size_of::<Option<(&'static String, &'static Value)>>()
            + size_of::<Option<&'static Value>>())
        + String::DATA;
}

impl Controls for Map<String, Value> {
    const DATA: usize = window::<Self>()
        + size_of::<serde_json::map::Iter<'static>>()
        + size_of::<Option<(&'static String, &'static Value)>>()
        + Value::DATA;
}

const fn field_data<S, T: Controls>(_: fn(&S) -> &T) -> usize {
    T::DATA
}

macro_rules! fields {
    ($type:ident { $($field:ident),+ $(,)? }) => {
        impl Controls for $type {
            const DATA: usize = window::<Self>() + maximum(&[
                $(field_data(|value: &Self| &value.$field),)+
            ]);
        }

        const _: fn(&$type) = |value| {
            let $type { $($field: _,)+ } = value;
        };
    };
}

fields!(HashRef {
    algorithm,
    domain,
    digest
});
fields!(ContentRef {
    hash,
    length,
    media_type
});
fields!(SchemaRef {
    id,
    version,
    definition,
    extensions
});
fields!(ArtifactIdentity {
    id,
    role,
    content,
    extensions
});
fields!(ImplementationIdentity {
    schema_version,
    implementation_id,
    artifacts,
    model_definitions,
    formats,
    extensions,
});
fields!(FacetSelection {
    id,
    version,
    configuration_ref,
    guarantees_ref,
    extensions
});
fields!(NodeManifest {
    schema_version,
    profile_id,
    roles,
    configuration_schema,
    allowed_combinations_ref,
    port_templates_ref,
    state_formats,
    operation_facets,
    extensions,
});
fields!(ProviderManifest {
    schema_version,
    provider_id,
    implementation,
    protocol_versions,
    supported_profiles,
    extensions_supported,
    qualification_refs,
    extensions,
});
fields!(Limits {
    frame_bytes,
    nesting,
    requests,
    journal_entries,
    blob_chunk_bytes
});

/// Names the real provider Serialize field DAG used during pure future quoting.
pub(super) const fn provider_data() -> usize {
    ProviderManifest::DATA
}

/// Names the same concrete result serializer, with its checked empty resumption.
pub(super) fn result_data() -> usize {
    // These are actual borrowed field types. The enclosing constructor verifies
    // the two 32-byte challenges and empty resumption branch before Serialize.
    // Each Bytes formatter owns one separately funded 43-byte temporary String.
    window::<HelloResult>()
        + maximum(&[
            field_data(|value: &HelloResult| &value.version),
            field_data(|value: &HelloResult| &value.session_id),
            field_data(|value: &HelloResult| &value.incarnation_id),
            field_data(|value: &HelloResult| &value.controller_nonce),
            field_data(|value: &HelloResult| &value.provider_nonce),
            field_data(|value: &HelloResult| &value.selected_features),
            field_data(|value: &HelloResult| &value.limits),
            field_data(|value: &HelloResult| &value.provider_identity),
            window::<Vec<ResumedOperation>>(),
            window::<crate::envelope::Nullable<Bytes>>(),
        ])
        + Bytes::borrowed_serialization_counter_scratch_data()
}

/// Names the actual internally tagged Completed branch and borrowed result map.
pub(super) const fn completed_data() -> usize {
    window::<crate::bodies::ResponseShape>() + Map::<String, Value>::DATA
}

/// Names the empty actual selection serializer and its two concrete fields.
pub(super) const fn selection_data() -> usize {
    window::<crate::handshake::ExtensionSelectionV1>()
        + U64::DATA
        + window::<Vec<crucible_node_format::ExtensionSelection>>()
}
