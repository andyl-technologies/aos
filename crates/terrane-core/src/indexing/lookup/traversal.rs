//! Walks actual local routes and measures physical namespace key resolution.
//!
//! Each hop retains its own local key and graft entry. Shared routes are visited
//! independently per occurrence; only active branches participate in cycle checks.

use super::{Candidate, Error, Work, cache_position, increment};
use crate::identity::Digest;
use crate::tree_builder::Tree;
use crate::tree_format::{
    ContentRef, Entry, EntryKind, MAX_GRAFT_DEPTH, MAX_TREE_LEVEL, NodeItems,
};
use alloc::vec::Vec;

/// Retains one actual ordered local graft hop and its independent source root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hop<'query, 'value> {
    /// Namespace root in which this local graft key was resolved.
    pub source_root: Digest,
    /// Root-local graft key, never a composed path.
    pub key: Vec<u8>,
    /// Actual source graft target, independently selecting the next namespace.
    pub target: Digest,
    /// Child auxiliary route selected by the forwarding carrier.
    pub route: Digest,
    /// Actual source entry, preserving graft properties and provenance.
    pub entry: &'query Entry<'value>,
}

/// Retains an actual immutable terminal file for independent current checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Occurrence<'query, 'value> {
    /// Actual ordered graft occurrences leading to the terminal source root.
    pub hops: Vec<Hop<'query, 'value>>,
    /// Independent namespace root containing the actual file entry.
    pub source_root: Digest,
    /// Terminal root-local file key.
    pub key: Vec<u8>,
    /// Actual tagged Chunk or Manifest content reference.
    pub content: ContentRef,
    /// Actual immutable file size, checked under the prepared geometry.
    pub size: u64,
    /// Actual canonical inline value, or actual immutable absence.
    pub value: Option<&'value [u8]>,
    /// Complete actual source entry, retaining metadata for independent checks.
    pub entry: &'query Entry<'value>,
}

/// Contains terminal occurrences and their measured P and W traversal events.
pub struct Occurrences<'query, 'value> {
    /// All actual occurrences, preserving shared siblings and ordered hops.
    pub rows: Vec<Occurrence<'query, 'value>>,
    /// Traversal counters; candidate discovery is separately reported.
    pub work: Work,
}

impl<'query, 'data, 'value> Candidate<'query, 'data, 'value> {
    /// Exports the complete immutable present or missing occurrence route.
    ///
    /// This full traversal reports P terminal occurrences and the cache, route,
    /// source, validation and copying operations defined by [`Work`]. It performs no full namespace walk
    /// or producer, current authority or trust decision.
    ///
    /// # Errors
    /// Refuses invalid actual terminal/forwarding relationships, cycles,
    /// independent tree-height/graft-depth limits and counter overflow.
    pub fn occurrences(&self) -> Result<Occurrences<'query, 'value>, Error> {
        let mut walker = Walker {
            candidate: self,
            output: Occurrences {
                rows: Vec::new(),
                work: Work::default(),
            },
            hops: Vec::new(),
            active: Vec::new(),
            stop_after_first: false,
        };
        walker.route(self.prepared.owner(), self.route)?;
        Ok(walker.output)
    }

    /// Probes the first immutable occurrence without walking later siblings.
    ///
    /// This does not close coverage gaps or make a current policy decision.
    /// Its counters report only the route prefix and source resolutions visited.
    ///
    /// # Errors
    /// Reports the same relationship, traversal-limit and overflow errors as
    /// [`Self::occurrences`].
    pub fn first_occurrence(&self) -> Result<OccurrenceProbe<'query, 'value>, Error> {
        let mut walker = Walker {
            candidate: self,
            output: Occurrences {
                rows: Vec::new(),
                work: Work::default(),
            },
            hops: Vec::new(),
            active: Vec::new(),
            stop_after_first: true,
        };
        walker.route(self.prepared.owner(), self.route)?;
        Ok(OccurrenceProbe {
            occurrence: walker.output.rows.pop(),
            work: walker.output.work,
        })
    }
}

/// Reports one early immutable occurrence probe with its actual work.
pub struct OccurrenceProbe<'query, 'value> {
    /// First actual terminal occurrence, if present.
    pub occurrence: Option<Occurrence<'query, 'value>>,
    /// Actual prefix traversal events, including at most one P.
    pub work: Work,
}

struct Walker<'candidate, 'query, 'data, 'value> {
    candidate: &'candidate Candidate<'query, 'data, 'value>,
    output: Occurrences<'query, 'value>,
    hops: Vec<Hop<'query, 'value>>,
    active: Vec<Digest>,
    stop_after_first: bool,
}

impl<'query, 'data, 'value> Walker<'_, 'query, 'data, 'value> {
    fn route(&mut self, source_root: Digest, route: Digest) -> Result<(), Error> {
        if self.active.len() > MAX_GRAFT_DEPTH
            || active_contains(
                &self.active,
                source_root,
                &mut self.output.work.source_cycle_comparisons,
            )?
        {
            return Err(Error::Limit);
        }
        self.active.push(source_root);
        increment(&mut self.output.work.source_roots, 1)?;
        increment(&mut self.output.work.source_cache_lookups, 1)?;
        let prepared = self.candidate.prepared;
        let position = cache_position(
            &prepared.trees,
            source_root,
            &mut self.output.work.source_cache_comparisons,
        )?
        .ok_or(Error::MissingSource)?;
        let tree = prepared.trees[position].1;
        self.node(source_root, tree, route, &mut Vec::new())?;
        self.active.pop();
        Ok(())
    }

    fn node(
        &mut self,
        source_root: Digest,
        tree: &'query Tree<'value>,
        digest: Digest,
        active: &mut Vec<Digest>,
    ) -> Result<(), Error> {
        if active.len() > usize::from(MAX_TREE_LEVEL)
            || active_contains(
                active,
                digest,
                &mut self.output.work.route_cycle_comparisons,
            )?
        {
            return Err(Error::Limit);
        }
        increment(&mut self.output.work.route_nodes, 1)?;
        active.push(digest);
        increment(&mut self.output.work.physical_cache_lookups, 1)?;
        let nodes = &self.candidate.prepared.nodes;
        let position = cache_position(
            nodes,
            digest,
            &mut self.output.work.physical_cache_comparisons,
        )?
        .ok_or(Error::MissingNode)?;
        let node = &nodes[position].1;
        match &node.items {
            NodeItems::Internal(children) => {
                for child in children {
                    increment(&mut self.output.work.route_edges, 1)?;
                    self.node(source_root, tree, child.child, active)?;
                    if self.stop_after_first && !self.output.rows.is_empty() {
                        break;
                    }
                }
            }
            NodeItems::Leaf(rows) => {
                for row in rows {
                    increment(&mut self.output.work.route_rows, 1)?;
                    self.row(source_root, tree, row)?;
                    if self.stop_after_first && !self.output.rows.is_empty() {
                        break;
                    }
                }
            }
        }
        active.pop();
        Ok(())
    }

    fn row(
        &mut self,
        source_root: Digest,
        tree: &'query Tree<'value>,
        row: &crate::tree_format::LeafItem<'data>,
    ) -> Result<(), Error> {
        let prepared = self.candidate.prepared;
        let role = if self.candidate.value.is_some() {
            super::Role::PresentRoute
        } else {
            super::Role::MissingRoute
        };
        increment(&mut self.output.work.carrier_checks, 1)?;
        let carrier = super::validate_row(prepared.context, role, &row.key, &row.entry)?;
        increment(&mut self.output.work.object_checks, 1)?;
        if carrier.object() != self.candidate.object {
            return Err(Error::Relationship);
        }
        let entry = resolve(tree, &row.key, &mut self.output.work)?;
        match (&entry.kind, carrier.route()) {
            (EntryKind::Tree { root: target, .. }, Some(route)) => {
                increment(&mut self.output.work.hop_records_copied, 1)?;
                let key = copy_key(&row.key, &mut self.output.work)?;
                self.hops.push(Hop {
                    source_root,
                    key,
                    target: *target,
                    route,
                    entry,
                });
                self.route(*target, route)?;
                self.hops.pop();
            }
            (EntryKind::File { content, size, .. }, None) => {
                let object = match content {
                    ContentRef::Inline(object) | ContentRef::Manifest(object) => *object,
                };
                increment(&mut self.output.work.object_checks, 1)?;
                if object != self.candidate.object {
                    return Err(Error::Relationship);
                }
                let mut value = None;
                for attribute in &entry.attrs {
                    increment(&mut self.output.work.attribute_name_probes, 1)?;
                    if attribute.name == prepared.attribute() {
                        value = Some(attribute.value);
                        break;
                    }
                }
                increment(&mut self.output.work.terminal_value_checks, 1)?;
                if value != self.candidate.value {
                    return Err(Error::Relationship);
                }
                increment(&mut self.output.work.occurrences, 1)?;
                let mut hops = Vec::with_capacity(self.hops.len());
                for hop in &self.hops {
                    increment(&mut self.output.work.hop_records_copied, 1)?;
                    hops.push(Hop {
                        source_root: hop.source_root,
                        key: copy_key(&hop.key, &mut self.output.work)?,
                        target: hop.target,
                        route: hop.route,
                        entry: hop.entry,
                    });
                }
                let key = copy_key(&row.key, &mut self.output.work)?;
                self.output.rows.push(Occurrence {
                    hops,
                    source_root,
                    key,
                    content: *content,
                    size: *size,
                    value,
                    entry,
                });
            }
            _ => return Err(Error::Relationship),
        }
        Ok(())
    }
}

fn active_contains(
    active: &[Digest],
    wanted: Digest,
    comparisons: &mut usize,
) -> Result<bool, Error> {
    for digest in active {
        increment(comparisons, 1)?;
        if *digest == wanted {
            return Ok(true);
        }
    }
    Ok(false)
}

fn copy_key(key: &[u8], work: &mut Work) -> Result<Vec<u8>, Error> {
    increment(&mut work.key_bytes_copied, key.len())?;
    Ok(key.to_vec())
}

fn resolve<'query, 'value>(
    tree: &'query Tree<'value>,
    key: &[u8],
    work: &mut Work,
) -> Result<&'query Entry<'value>, Error> {
    let mut node = tree.root();
    loop {
        increment(&mut work.source_nodes, 1)?;
        match node.items() {
            NodeItems::Leaf(items) => {
                let mut low = 0;
                let mut high = items.len();
                while low < high {
                    let middle = low + (high - low) / 2;
                    increment(&mut work.source_comparisons, 1)?;
                    match items[middle].key.as_slice().cmp(key) {
                        core::cmp::Ordering::Less => low = middle + 1,
                        core::cmp::Ordering::Greater => high = middle,
                        core::cmp::Ordering::Equal => return Ok(&items[middle].entry),
                    }
                }
                return Err(Error::Relationship);
            }
            NodeItems::Internal(items) => {
                let mut low = 0;
                let mut high = items.len();
                while low < high {
                    let middle = low + (high - low) / 2;
                    increment(&mut work.source_comparisons, 1)?;
                    if items[middle].last_key.as_slice() < key {
                        low = middle + 1;
                    } else {
                        high = middle;
                    }
                }
                node = node
                    .children()
                    .get(low)
                    .ok_or(Error::Relationship)?
                    .as_ref();
            }
        }
    }
}
