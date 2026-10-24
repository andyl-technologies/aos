//! Bounds fresh JSON clones retained beneath one canonical-byte ceiling.
//!
//! The pinned Clone implementations copy live String and Vec elements and the
//! existing nonempty BTree nodes. Parser growth, original spare capacity and
//! canonical construction remain separately priced owners and work windows.

use super::{ProviderError, map_node_bytes_for};
use std::mem::{align_of, size_of};

/// Bounds retained backing of fresh clones of independently owned JSON roots.
///
/// The complete canonical encodings of all roots must share the supplied byte
/// ceiling. Each root contributes its own lexical rounding and inline header.
/// This prices only the resulting fresh clones: it cannot bound a parser, an
/// arbitrary existing Value, a custom Clone implementation or cumulative
/// construction requests. Original owners and temporary work remain independent.
///
/// The pinned String and Vec clones request their live element lengths. The
/// pinned BTree clone copies each existing node once and returns an unallocated
/// map for an empty source. Every node of a nonempty BTree owns at least one
/// entry, so one maximum internal-node layout per member covers its clone.
/// Array slots, map nodes and decoded strings share a structural lower bound
/// on the complete canonical encoding. The quote prices its bytes at the most
/// expensive corresponding backing rate, plus independent root headers.
/// These are requested-layout bounds, without an allocator-residency claim.
///
/// Admit the fixed counter before using this inert DATA quote. No allocation,
/// journal credit, Source currentness or permission follows from the result.
///
/// # Errors
/// Refuses zero byte/document ceilings, unsupported pinned Value/tree layouts
/// or checked arithmetic overflow. The aggregate byte ceiling is never
/// multiplied by the number of documents.
pub fn original_json_value_clone_storage_forest_data(
    maximum_canonical_bytes: usize,
    maximum_documents: usize,
) -> Result<usize, ProviderError> {
    if maximum_canonical_bytes == 0 || maximum_documents == 0 {
        return Err(exhausted());
    }

    // The selected 64-bit profile uses BTree-backed objects and inline finite
    // numbers. An arbitrary-precision Number can retain a lexical spelling
    // longer than its canonical output; an ordered-map feature has other nodes.
    // Neither configuration can borrow this pinned clone proof.
    type ValueMap = serde_json::Map<String, serde_json::Value>;
    type ValueTree = std::collections::BTreeMap<String, serde_json::Value>;
    if size_of::<usize>() != 8
        || size_of::<serde_json::Number>() != 16
        || size_of::<ValueMap>() != size_of::<ValueTree>()
        || align_of::<ValueMap>() != align_of::<ValueTree>()
    {
        return Err(exhausted());
    }

    let documents = maximum_documents.min(maximum_canonical_bytes);
    let node = map_node_bytes_for::<String, serde_json::Value>().map_err(|_| exhausted())?;

    // For canonical length L, array elements A, object members M and decoded
    // string/key bytes S, structural induction gives L >= 1 + 2A + 5M + S.
    // A nonempty array contributes its brackets, separators and each child's
    // one-byte minimum. An object also contributes quotes and a colon per key.
    // Empty containers and escaped strings only increase the remaining slack.
    // The same byte cannot independently fund both a maximal array and map.
    let array_byte_cost = size_of::<serde_json::Value>().div_ceil(2);
    let map_byte_cost = node.div_ceil(5);
    let byte_cost = array_byte_cost.max(map_byte_cost).max(1);
    let backing = multiply(maximum_canonical_bytes, byte_cost)?;
    let roots = multiply(documents, size_of::<serde_json::Value>())?;
    add(backing, roots)
}

/// Names fixed clone-forest, checked arithmetic and pinned layout controls.
pub const fn original_json_value_clone_storage_forest_counter_scratch_data() -> usize {
    24 * size_of::<usize>()
        + size_of::<std::alloc::Layout>()
        + 4 * size_of::<Result<usize, ProviderError>>()
        + 4 * size_of::<bool>()
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(exhausted)
}

fn multiply(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(exhausted)
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("fresh JSON clone forest storage")
}
