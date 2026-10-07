//! Reconstructs borrowed namespace trees and checks their physical geometry.

use super::*;
use terrane_core::identity::{IdentityKind, TERRANE_V1};
use terrane_core::tree_format::{LeafItem, MAX_TREE_LEVEL, NodeItems, TreeUse, decode_node_for};

/// Reports one source reconstruction call separately from raw loading.
///
/// Counts describe actual events, not total CPU or allocation costs. Every call
/// to `sources` pays and reports these operations again.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Reconstruction {
    /// Raw source Nodes decoded in their actual root/internal placement.
    pub node_decodes: usize,
    /// Identity checks on supplied source Nodes, including repeated visits.
    pub identity_checks: usize,
    /// Source root trees rebuilt from their complete sorted leaf sequence.
    pub trees: usize,
    /// Leaf items passed to canonical construction.
    pub entries: usize,
    /// Canonical reconstructed Nodes compared with supplied physical bytes.
    pub compared_nodes: usize,
}

/// Holds caller-owned Trees borrowing only the loaded raw namespace bytes.
pub struct Sources<'value> {
    /// Independently addressed, canonically reconstructed namespace roots.
    pub trees: BTreeMap<Digest, Tree<'value>>,
    /// Operations performed by this reconstruction call.
    pub work: Reconstruction,
}

impl Loaded {
    /// Reconstructs namespace roots with their original immutable properties.
    ///
    /// Exact canonical root identities and Node bytes verify original boundary
    /// choices and grouping. Direct traversal additionally checks child levels,
    /// counts, weights, separators and disjoint key placement before rebuilding.
    /// Every invocation performs reconstruction and returns its own report.
    ///
    /// # Errors
    /// Rejects absent bytes, wrong identities, malformed root/internal placement,
    /// levels, child summaries, ordering, tree constraints or canonical boundaries.
    pub fn sources(&self) -> Result<Sources<'_>, Error> {
        self.source.sources()
    }
}

impl LoadedSource {
    /// Reconstructs the reached namespace with its original bytes and properties.
    ///
    /// Canonical rebuilding verifies grouping and boundaries after traversal
    /// checks physical levels, counts, weights, separators and key placement.
    /// Returned Trees borrow only this independently owned raw namespace. Every
    /// call repeats reconstruction and reports its work separately from loading,
    /// source preparation, index verification and initialization/rebuilding.
    ///
    /// # Errors
    /// Rejects absent bytes, wrong identities, malformed root/internal placement,
    /// levels, child summaries, ordering, tree constraints or canonical boundaries.
    pub fn sources(&self) -> Result<Sources<'_>, Error> {
        let mut trees = BTreeMap::new();
        let mut work = Reconstruction::default();
        for root in &self.roots {
            let mut entries = Vec::new();
            collect(
                &self.namespace,
                *root,
                true,
                self.minimum,
                &mut Vec::new(),
                &mut entries,
                &mut work,
            )?;
            let bytes = self
                .namespace
                .get(root)
                .ok_or_else(|| invalid(*root, evaluation::Error::MissingSource))?;
            increment(&mut work.node_decodes, 1, *root)?;
            let node = decode_node_for(bytes, true, self.minimum, TreeUse::Ordinary)
                .map_err(|error| invalid(*root, error))?;
            increment(&mut work.trees, 1, *root)?;
            increment(&mut work.entries, entries.len(), *root)?;
            let tree = Tree::build(entries, node.props, self.minimum, TreeUse::Ordinary)
                .map_err(|error| invalid(*root, error))?;
            if tree.root_identity() != *root {
                return Err(invalid(*root, evaluation::Error::Relationship));
            }
            for canonical in tree.nodes() {
                increment(&mut work.compared_nodes, 1, *root)?;
                if self.namespace.get(&canonical.identity()).map(Vec::as_slice)
                    != Some(canonical.encoded())
                {
                    return Err(invalid(
                        canonical.identity(),
                        evaluation::Error::Relationship,
                    ));
                }
            }
            trees.insert(*root, tree);
        }
        Ok(Sources { trees, work })
    }
}

struct Summary {
    level: u8,
    count: u64,
    weight: u64,
    first: Option<Vec<u8>>,
    last: Option<Vec<u8>>,
}

fn collect<'value>(
    bytes: &'value BTreeMap<Digest, Vec<u8>>,
    root: Digest,
    is_root: bool,
    minimum: u64,
    active: &mut Vec<Digest>,
    entries: &mut Vec<LeafItem<'value>>,
    work: &mut Reconstruction,
) -> Result<Summary, Error> {
    if active.len() > usize::from(MAX_TREE_LEVEL) || active.contains(&root) {
        return Err(invalid(root, evaluation::Error::Limit));
    }
    let raw = bytes
        .get(&root)
        .ok_or_else(|| invalid(root, evaluation::Error::MissingSource))?;
    increment(&mut work.identity_checks, 1, root)?;
    let digest = TERRANE_V1
        .calculate(IdentityKind::Node, raw)
        .and_then(|identity| identity.terrane_v1_digest())
        .map_err(|_| invalid(root, evaluation::Error::Source))?;
    if digest != root {
        return Err(invalid(root, evaluation::Error::Relationship));
    }
    increment(&mut work.node_decodes, 1, root)?;
    let node = decode_node_for(raw, is_root, minimum, TreeUse::Ordinary)
        .map_err(|error| invalid(root, error))?;
    active.push(root);
    let mut summary = Summary {
        level: node.level,
        count: 0,
        weight: raw.len() as u64,
        first: None,
        last: None,
    };
    match node.items {
        NodeItems::Leaf(items) => {
            summary.count = items.len() as u64;
            summary.first = items.first().map(|item| item.key.clone());
            summary.last = items.last().map(|item| item.key.clone());
            entries.extend(items);
        }
        NodeItems::Internal(children) => {
            for child in children {
                let actual = collect(bytes, child.child, false, minimum, active, entries, work)?;
                if actual.level.checked_add(1) != Some(node.level)
                    || actual.count != child.count
                    || actual.weight != child.weight
                    || actual.last.as_deref() != Some(child.last_key.as_slice())
                    || actual.first.is_none()
                    || summary
                        .last
                        .as_ref()
                        .zip(actual.first.as_ref())
                        .is_some_and(|(last, first)| last >= first)
                {
                    return Err(invalid(root, evaluation::Error::Relationship));
                }
                if summary.first.is_none() {
                    summary.first = actual.first;
                }
                summary.last = actual.last;
                summary.count = summary
                    .count
                    .checked_add(actual.count)
                    .ok_or_else(|| invalid(root, evaluation::Error::Limit))?;
                summary.weight = summary
                    .weight
                    .checked_add(actual.weight)
                    .ok_or_else(|| invalid(root, evaluation::Error::Limit))?;
            }
        }
    }
    active.pop();
    Ok(summary)
}
