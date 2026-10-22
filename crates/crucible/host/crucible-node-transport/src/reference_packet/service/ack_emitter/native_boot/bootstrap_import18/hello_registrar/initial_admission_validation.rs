//! Prices closed initial Hello validation and complete typed value comparison.
//!
//! Original claims exclude resumption before the SDK starts. Validation follows
//! the actual HelloRequest/HelloResult and complete provider field DAG. Sorted
//! keys borrow their rosters; only the protocol-version set and its individual
//! Id-validation String copy allocate. This is one SDK phase, not admission.

use super::super::hello_response;
use super::clone_controls;
use crate::ProviderError;
use crate::handshake::{HelloRequest, HelloResult, Limits};
use crate::retained_metadata::requested_storage::tree_storage_data;
use crucible_node_format::{
    ArtifactIdentity, ContentRef, ContractError, ExtensionSelection, FacetSelection, HashRef, Id,
    IdFromOwnedError, ImplementationIdentity, MAX_ARRAY_ELEMENTS, MAX_ID_BYTES, NodeManifest,
    ProviderManifest, SchemaRef,
};
use serde_json::Value;
use std::mem::{align_of, size_of};

// These reasons close the actual initial validators, including Id's owned
// adapter. They exclude arbitrary callback diagnostics and resumed operations.
const REASONS: [&str; REASON_COUNT] = [
    "require bounded nonempty version advertisement",
    "expected 1–128 bounded ASCII identifier bytes",
    "duplicate protocol version",
    "baseline requires offered CNP/1",
    "array exceeds 65536 elements",
    "set must be strictly sorted with no duplicates",
    "controller must require cnp.core/1",
    "hello challenge and admission token require exactly 32 octets",
    "require positive receiving ceilings within baseline hard caps",
    "unsupported baseline protocol",
    "challenge values require exactly 32 octets",
    "manifest does not offer selected CNP/1 version",
    "baseline hello must select core feature",
    "resume selection requires exactly one 32-byte token",
    "require bounded strictly sorted operation records",
    "expected baseline version 1",
    "unsupported hash algorithm",
    "expected 1–128 ASCII bytes",
    "expected 64 lowercase hexadecimal characters",
    "content must use cnp.blob.v1",
    "expected 1–128 printable ASCII bytes",
    "zero schema/facet edition is forbidden",
    "expected bounded exact SemVer identifiers",
    "expected exact schema content identity",
    "expected owner-controlled namespaced identifier",
    "unsupported negotiation edition",
    "require a bounded roster with unique sorted identifiers",
    "offer repeats an identifier or exceeds its aggregate bound",
];
const REASON_COUNT: usize = 28;

type TransientFields = [usize; 9];
type ValueLayerFields = [usize; 38];

/// Prices the temporary borrowed-version tree, key clone and closed failures.
///
/// The caller separately adds the container insertion/destruction windows and
/// all owning SDK output. Original wire inspection has already established
/// valid version identifiers and the bounded nonempty initial profile.
///
/// # Errors
/// Refuses zero framing, unsupported tree geometry, overflow or an independent
/// complete-peak restriction.
pub(super) fn construction_data(frame: usize, maximum: usize) -> Result<[usize; 3], ProviderError> {
    if frame == 0 || maximum == 0 {
        return Err(refused());
    }

    // Quotes, a nonempty ASCII byte and comma require four bytes per entry,
    // apart from each array's final comma. The complete frame bounds this one
    // array independently of the two other request arrays.
    let entries = frame.checked_add(3).ok_or_else(refused)? / 4;
    let tree = tree_storage_data(
        1,
        entries.min(MAX_ARRAY_ELEMENTS),
        size_of::<&String>(),
        align_of::<&String>(),
    )?;
    let diagnostic = REASONS
        .iter()
        .map(|reason| reason.len())
        .max()
        .ok_or_else(refused)?;
    let clone = clone_controls::string_data()?;
    let transient_fields: TransientFields = [
        tree,
        MAX_ID_BYTES,  // one original valid version cloned for Id::new
        "CNP/1".len(), // actual temporary String in the baseline set lookup
        diagnostic,
        clone[0],
        IdFromOwnedError::construction_transient_bytes_data(),
        size_of::<String>() * 3,
        size_of::<ContractError>() * 3,
        size_of::<ProviderError>() * 3,
    ];
    let transient = total(&transient_fields)?;
    let scratch = total(&[
        counter_scratch_data(),
        clone[1],
        IdFromOwnedError::construction_counter_scratch_bytes_data(),
        closed_value_counter_scratch_data()?,
    ])?;
    let row = [diagnostic, transient, scratch];
    if total(&row)? > maximum {
        return Err(refused());
    }

    Ok(row)
}

/// Names concrete validation/equality adapters over the complete closed DAG.
///
/// Borrowed key windows, primitive byte comparisons and paired JSON iterators
/// own no heap. The same provider field path bounds the verifier's full
/// Implementation/ContentRef comparisons. JSON recurses only within its
/// existing 64-container plus scalar profile; sibling windows run in turn.
///
/// # Errors
/// Refuses checked composition overflow.
pub(in super::super) fn closed_value_counter_scratch_data() -> Result<usize, ProviderError> {
    let fields: ValueLayerFields = [
        roster_data::<String>(),
        roster_data::<Id>(),
        roster_data::<SchemaRef>(),
        roster_data::<ArtifactIdentity>(),
        roster_data::<ContentRef>(),
        roster_data::<NodeManifest>(),
        roster_data::<FacetSelection>(),
        roster_data::<ExtensionSelection>(),
        roster_data::<Value>(),
        size_of::<&HelloRequest>() * 2,
        size_of::<&HelloResult>() * 2,
        size_of::<&ProviderManifest>() * 2,
        size_of::<&ImplementationIdentity>() * 2,
        size_of::<&HashRef>() * 2,
        size_of::<(&Id, u16)>() * 2,
        size_of::<(&String, &String)>() * 2,
        size_of::<std::collections::btree_map::Iter<'static, String, Value>>() * 2,
        size_of::<
            std::iter::Zip<
                std::collections::btree_map::Iter<'static, String, Value>,
                std::collections::btree_map::Iter<'static, String, Value>,
            >,
        >(),
        size_of::<Option<((&String, &Value), (&String, &Value))>>(),
        size_of::<std::str::Bytes<'static>>() * 4,
        size_of::<std::str::Split<'static, char>>(),
        size_of::<[(&str, &Option<String>, bool); 2]>(),
        size_of::<std::array::IntoIter<(&str, &Option<String>, bool), 2>>(),
        size_of::<&str>() * 8,
        size_of::<&[u8]>() * 4,
        size_of::<std::slice::Iter<'static, u8>>() * 2,
        size_of::<Option<u8>>() * 4,
        size_of::<std::ops::RangeInclusive<u8>>(),
        size_of::<std::cmp::Ordering>() * 2,
        size_of::<Result<usize, usize>>(),
        size_of::<Result<(), ContractError>>() * 4,
        size_of::<Result<(), ProviderError>>() * 2,
        size_of::<ContractError>() * 2,
        size_of::<usize>() * 8,
        size_of::<u64>() * 2,
        size_of::<u16>() * 2,
        size_of::<bool>() * 6,
        Limits::validation_counter_scratch_data(),
    ];
    let layer = total(&fields)?;
    layer
        .checked_mul(hello_response::initial_result_comparison_depth_data())
        .ok_or_else(refused)
}

const fn roster_data<T: 'static>() -> usize {
    size_of::<&[T]>() * 2
        + size_of::<std::slice::Iter<'static, T>>() * 2
        + size_of::<std::slice::Windows<'static, T>>() * 2
        + size_of::<std::iter::Zip<std::slice::Iter<'static, T>, std::slice::Iter<'static, T>>>()
        + size_of::<Option<(&T, &T)>>()
        + size_of::<Option<&T>>() * 2
        + size_of::<Option<&[T]>>() * 2
}

/// Names the supplier's arrays, iteration and checked result controls.
pub(super) fn counter_scratch_data() -> usize {
    clone_controls::quote_counter_scratch_data()
        + size_of::<TransientFields>()
        + size_of::<ValueLayerFields>()
        + size_of::<[usize; 4]>()
        + size_of::<std::slice::Iter<'static, &'static str>>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<[usize; 3]>() * 2
        + size_of::<[usize; 2]>()
        + size_of::<usize>() * 9
        + size_of::<Option<usize>>() * 3
        + size_of::<Result<usize, ProviderError>>() * 4
        + size_of::<Result<[usize; 3], ProviderError>>()
}

fn total(fields: &[usize]) -> Result<usize, ProviderError> {
    fields.iter().try_fold(0usize, |sum, field| {
        sum.checked_add(*field).ok_or_else(refused)
    })
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("original import18 initial SDK validation")
}
