//! Prices the actual temporary owners in closed baseline body validation.
//!
//! Producer-sequence validation inserts borrowed keys into a set. Input result
//! correspondence instead collects cloned IDs into a set, then consumes that
//! set into a Vec for comparison. Error/Notification detail validators use a
//! canonical sink; its formatter and key ordering still require temporary work.

use super::*;
use crate::retained_metadata::{
    requested_storage::tree_storage_data,
    serialization_storage::{
        OriginalJsonValueStorageExtentData,
        original_json_value_storage_extent_counter_scratch_data,
        original_json_value_storage_extent_data,
    },
};
use crucible_node_format::{ContentRef, Id, U64, canonical};
use std::{collections::BTreeSet, mem::align_of};

/// Bounds the real validation owners independently of decoded field backing.
///
/// # Errors
/// Refuses unsupported pinned layouts or checked requested-storage overflow.
pub(super) fn storage_data(frame: usize) -> Result<usize, ProviderError> {
    // Each unique set entry needs its own input syntax. F is a conservative
    // population bound for both sets, with no reliance on successful decoding.
    let sets = add(
        tree_storage_data(1, frame, size_of::<(&Id, U64)>(), align_of::<(&Id, U64)>())?,
        tree_storage_data(1, frame, size_of::<Id>(), align_of::<Id>())?,
    )?;

    // BTreeSet::from_iter may first collect/sort a complete Vec, and the later
    // into_iter().collect comparison has a separate output Vec. Include each
    // complete bank's cumulative geometric requests and minimum reservation.
    let slots = add(multiply(8, frame)?, 4)?;
    let id_vectors = multiply(2, multiply(slots, size_of::<Id>())?)?;

    // Independent strings belong to the input-result ID clones, Capture's
    // adjacent full-reference sort keys, and ErrorRecord's cloned code. Each
    // population is bounded by its original complete frame, even on refusal.
    let cloned_validation_text = multiply(3, frame)?;
    let canonical_work =
        original_json_value_storage_extent_data(frame)?.canonical_work_requested_bytes;
    [sets, id_vectors, cloned_validation_text, canonical_work]
        .into_iter()
        .try_fold(0usize, add)
}

/// Names set, collection/sort, canonical and validation-iterator controls.
pub(super) fn counter_scratch_data() -> usize {
    canonical::canonical_json_counter_scratch_bytes_data()
        + original_json_value_storage_extent_counter_scratch_data()
        + size_of::<OriginalJsonValueStorageExtentData>()
        + size_of::<Result<OriginalJsonValueStorageExtentData, ProviderError>>()
        + size_of::<BTreeSet<(&Id, U64)>>()
        + size_of::<BTreeSet<Id>>()
        + size_of::<std::collections::btree_set::IntoIter<Id>>()
        + size_of::<std::collections::btree_set::Iter<'static, (&'static Id, U64)>>()
        + size_of::<std::slice::Iter<'static, crucible_node_format::Event>>()
        + size_of::<std::slice::Windows<'static, ContentRef>>()
        + size_of::<Vec<Id>>()
        + size_of::<Option<Id>>()
        + size_of::<(&Id, U64)>()
        + 2 * size_of::<(String, String)>()
        + size_of::<std::io::Sink>()
        + 2 * size_of::<[u8; 4096]>()
        + size_of::<[usize; 4]>()
        + size_of::<std::array::IntoIter<usize, 4>>()
        + size_of::<Result<(), crucible_node_format::ContractError>>()
        + size_of::<Result<usize, ProviderError>>()
        + 8 * size_of::<usize>()
}
