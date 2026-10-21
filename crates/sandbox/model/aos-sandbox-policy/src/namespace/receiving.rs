//! Prices the existing portable namespace ordering model and direct DAG.
//!
//! The caller supplies actual encoded-cell extent before the strict decoder.
//! Direct edges consume encoded cells; propagated sets contain only the closed
//! class vocabularies. This does not allocate, validate or compile a namespace.

use super::*;
use aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1 as nodes;
use std::mem::size_of;

fn cells<T>(bytes: usize) -> Option<usize> {
    bytes.checked_mul(4)?.checked_mul(size_of::<T>())
}

fn rule_heap(bytes: usize) -> Option<usize> {
    cells::<aos_sandbox_model::PathName>(bytes)?
        .checked_add(cells::<ResourceId>(bytes)?)?
        .checked_add(bytes.checked_mul(4)?)
}

/// Bounds the input ordering rules and their actual validation/DAG scratch.
///
/// It includes all cloned rule backing and uses the same concrete map/set key
/// and value types as canonical_dag; no transitive ResourceId graph is invented.
pub(crate) fn portable_order_receiving_bytes_v1(encoded_bytes: usize) -> Option<usize> {
    let n = encoded_bytes;
    let input = cells::<NamespaceRuleV1>(n)?.checked_add(rule_heap(n)?)?;
    let sequence = cells::<NamespaceRuleV1>(n)?
        .checked_add(rule_heap(n)?)?
        .checked_add(cells::<ResourceId>(n)?)?
        .checked_add(nodes::<ResourceId, ()>(n)?)?
        .checked_add(nodes::<AttachmentSlotId, ()>(n)?)?;
    let source_classes = [
        NamespaceSourceClassV1::Immutable,
        NamespaceSourceClassV1::Live,
        NamespaceSourceClassV1::PrivateDelta,
        NamespaceSourceClassV1::Service,
    ]
    .len();
    let execution_classes = [
        NamespaceExecutionClassV1::DataOnly,
        NamespaceExecutionClassV1::VerifiedPackageOrTool,
    ]
    .len();
    let dag = nodes::<ResourceId, Vec<ResourceId>>(n)?
        .checked_mul(2)?
        .checked_add(nodes::<ResourceId, NamespaceRuleV1>(n)?)?
        .checked_add(nodes::<ResourceId, usize>(n)?)?
        .checked_add(nodes::<ResourceId, ()>(n)?)?
        .checked_add(nodes::<ResourceId, u16>(n)?)?
        .checked_add(nodes::<ResourceId, BTreeSet<NamespaceSourceClassV1>>(n)?)?
        .checked_add(nodes::<ResourceId, BTreeSet<NamespaceExecutionClassV1>>(n)?)?
        .checked_add(nodes::<NamespaceSourceClassV1, ()>(
            n.checked_mul(source_classes)?,
        )?)?
        .checked_add(nodes::<NamespaceExecutionClassV1, ()>(
            n.checked_mul(execution_classes)?,
        )?)?
        // Definitions and dependents each own one direct-edge vector plane.
        .checked_add(cells::<ResourceId>(n)?.checked_mul(2)?)?
        // Original rule-map values and final ordered rules retain independent
        // clones of nested paths/input lists while the borrowed input stays.
        .checked_add(rule_heap(n)?.checked_mul(2)?)?
        .checked_add(cells::<NamespaceRuleV1>(n)?)?;
    let controls = size_of::<DagAnalysisV1>()
        .checked_mul(2)?
        .checked_add(size_of::<Result<DagAnalysisV1, NamespaceCompilationError>>())?
        .checked_add(size_of::<(
            BTreeMap<ResourceId, Vec<ResourceId>>,
            BTreeMap<ResourceId, NamespaceRuleV1>,
            BTreeMap<ResourceId, usize>,
            BTreeSet<ResourceId>,
            BTreeMap<ResourceId, u16>,
            BTreeSet<NamespaceSourceClassV1>,
            BTreeSet<NamespaceExecutionClassV1>,
            Vec<ResourceId>,
            BTreeSet<AttachmentSlotId>,
        )>())?;
    input.checked_add(sequence.max(dag))?.checked_add(controls)
}

/// Bounds only actual keyed namespace indices and direct-edge entries.
///
/// The two sequence sets are alternatives to eight ResourceId-keyed DAG
/// maps/sets plus definitions/dependents direct-edge lists. Closed class enum
/// values, vector slots and control fields create no additional names.
pub(crate) fn portable_order_metadata_entries_v1(encoded_bytes: usize) -> Option<usize> {
    let sequence = encoded_bytes.checked_mul(2)?;
    let dag_indices = encoded_bytes.checked_mul(8)?;
    let direct_edges = encoded_bytes.checked_mul(2)?;
    Some(sequence.max(dag_indices.checked_add(direct_edges)?))
}
