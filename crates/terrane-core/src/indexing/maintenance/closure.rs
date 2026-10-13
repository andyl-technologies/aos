//! Advances exact ordinary physical reachability with add-before-remove edges.
//!
//! Each reached incoming edge requests exactly one get and one insert/remove.
//! Existing records terminate descent; no map visitor or whole-closure scan is
//! used. For a 256-bit digest key, AVL minimum populations satisfy
//! N(h) = 1 + N(h-1) + N(h-2), hence N(h) >= 2^(h/2)-1 and h <= 514.
//! A get/insert probes at most h nodes; removal's successor path gives at most
//! 2h probes. Rebalancing makes at most five copied nodes per visited level.
//! Thus each incoming edge costs at most 1028 probes and 5140 path copies,
//! independently of retained snapshot count. Reports expose actual operations,
//! maximum height, probes and copies rather than charging these maxima to B.
//!
//! A newly emitted Node has an actual canonical encoding in its owning stream;
//! each extracted outgoing reference occupies bytes in that encoding. Retired
//! Nodes occur in inspected old divergence streams (or their changed-root
//! completion); their outgoing references are old input items. The fixed Node
//! byte cap bounds record extraction for intermediate/root outputs. Consequently
//! emitted/retired metadata is linear in actual stream items and encoding bytes,
//! with the explicit digest-width constants above, plus changed-root work.

use alloc::{rc::Rc, vec::Vec};

use super::{Error, MapWork, StagingWork, persistent::Map, temporary::Ordered};
use crate::{
    identity::Digest,
    indexing::carrier::{GapBinding, SemanticContext, classify_entry},
    tree_builder::StoredNode,
    tree_format::NodeItems,
};

/// Retains a physical Node, extracted outgoing edges and incoming-edge count.
#[derive(Clone, Debug)]
pub(super) struct Record<'a> {
    /// Canonical physical Node retained by the reachable closure.
    pub(super) node: Rc<StoredNode<'a>>,
    edges: Rc<Vec<Digest>>,
    references: usize,
}

/// Counts reachability-map changes and outgoing-edge traversal.
#[derive(Default)]
pub(super) struct Work {
    /// Balanced-map operations, with overflow checked separately by the caller.
    pub(super) maps: MapWork,
    /// Outgoing edges traversed while installing or retiring physical records.
    pub(super) edges: usize,
    /// Previously absent physical records installed.
    pub(super) added: usize,
    /// Physical records retired after their last incoming reference.
    pub(super) removed: usize,
}

/// Extracts physical, continuation and gap edges into an unreferenced record.
///
/// # Errors
/// Rejects leaf entries outside the closed carrier shape or malformed gap bindings.
pub(super) fn record(
    node: Rc<StoredNode<'_>>,
    context: SemanticContext,
) -> Result<(Record<'_>, StagingWork), Error> {
    let mut edges = Vec::new();
    match node.items() {
        NodeItems::Internal(children) => edges.extend(children.iter().map(|child| child.child)),
        NodeItems::Leaf(items) => {
            for item in items {
                if let Some(route) = classify_entry(context, &item.entry)?.route() {
                    edges.push(route);
                }
            }
        }
    }
    if let Some(properties) = &node.node().props {
        for property in properties {
            if property.name == "index-gaps" {
                edges.push(GapBinding::decode_binding(property.value)?.node());
            }
        }
    }
    let work = StagingWork {
        nodes: 1,
        rows: match node.items() {
            NodeItems::Leaf(items) => items.len(),
            _ => 0,
        },
        edges: edges.len(),
    };
    Ok((
        Record {
            node,
            edges: Rc::new(edges),
            references: 0,
        },
        work,
    ))
}

/// Extracts and stages a physical record by identity, replacing any prior record.
///
/// # Errors
/// Rejects invalid carrier entries or gap bindings during edge extraction.
/// Staging-map counter overflow is deferred to its `work` check.
pub(super) fn stage<'a>(
    node: Rc<StoredNode<'a>>,
    context: SemanticContext,
    staged: &mut Ordered<Digest, Record<'a>>,
) -> Result<StagingWork, Error> {
    let identity = node.identity();
    let (record, work) = record(node, context)?;
    staged.insert(identity, record);
    Ok(work)
}

/// Adds an incoming reference, installing absent records from staging.
///
/// Installation stops at an existing record; outgoing edges belong to the
/// physical object once, while every incoming physical/logical edge counts.
/// Map-count overflow is deferred to the caller's map-work check.
///
/// # Errors
/// Rejects missing staged records or reference, installation or edge-count overflow.
/// Earlier closure changes and work charges remain applied on failure.
pub(super) fn add<'a>(
    digest: Digest,
    closure: &mut Map<Digest, Record<'a>>,
    staged: &Ordered<Digest, Record<'a>>,
    work: &mut Work,
) -> Result<(), Error> {
    if let Some(mut record) = closure.get(&digest, &mut work.maps).cloned() {
        record.references = record.references.checked_add(1).ok_or(Error::Limit)?;
        closure.insert(digest, record, &mut work.maps);
        return Ok(());
    }
    let mut record = staged.get(&digest).cloned().ok_or(Error::Transition)?;
    record.references = 1;
    let edges = Rc::clone(&record.edges);
    closure.insert(digest, record, &mut work.maps);
    super::accounting::add(&mut work.added, 1)?;
    for edge in edges.iter() {
        super::accounting::add(&mut work.edges, 1)?;
        add(*edge, closure, staged, work)?;
    }
    Ok(())
}

/// Removes an incoming reference and recursively retires unreferenced records.
///
/// Map-count overflow is deferred to the caller's map-work check.
///
/// # Errors
/// Rejects absent closure records or retirement/traversal-count overflow.
/// Earlier closure changes and work charges remain applied on failure.
pub(super) fn remove(
    digest: Digest,
    closure: &mut Map<Digest, Record<'_>>,
    work: &mut Work,
) -> Result<(), Error> {
    let mut record = closure
        .get(&digest, &mut work.maps)
        .cloned()
        .ok_or(Error::Transition)?;
    if record.references > 1 {
        record.references -= 1;
        closure.insert(digest, record, &mut work.maps);
        return Ok(());
    }
    closure.remove(&digest, &mut work.maps);
    super::accounting::add(&mut work.removed, 1)?;
    for edge in record.edges.iter() {
        super::accounting::add(&mut work.edges, 1)?;
        remove(*edge, closure, work)?;
    }
    Ok(())
}
