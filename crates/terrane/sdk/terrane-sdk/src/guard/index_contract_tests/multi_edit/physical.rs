//! Predicts physical regions from immutable inputs using direct canonical serialization.
//!
//! This reference model uses no Tree editing, discovery or maintenance routine.
//! It independently merges literal rows and child spans, applies TREE-22 arithmetic,
//! and sums the exact item, frontier, encoding and hashing schedule at each old level.

use std::collections::BTreeSet;

use super::{MINIMUM, TestResult};
use terrane_format::{
    cbor,
    identity::{Digest, IdentityKind, TERRANE_V1},
    indexing::maintenance::{BatchWork, StagingWork},
    tree_builder::{BoundaryRegion, StreamWork, Tree, Work},
    tree_format::{self, ChildRef, Entry, LeafItem, Node, NodeItems, TreeUse},
};

/// Retains exact independent region endpoints and physical costs for one sorted batch.
pub(super) struct ExpectedBatch {
    /// Counts independently changed logical rows in the sorted batch.
    pub(super) edits: usize,
    /// Records the actual old canonical root level.
    pub(super) old_level: u8,
    /// Predicts exclusive per-level boundary regions and every physical counter.
    pub(super) regions: Vec<BoundaryRegion>,
    /// Counts all independently serialized emitted metadata, including repeated outputs.
    pub(super) staging: StagingWork,
    /// Retains independently serialized emitted identities before reachability filtering.
    pub(super) candidates: BTreeSet<Digest>,
}

#[derive(Clone)]
struct Span {
    first: Vec<u8>,
    last: Vec<u8>,
    nodes: Vec<ChildRef>,
}

struct Chunker<'a> {
    level: u8,
    usage: TreeUse,
    leaves: Vec<LeafItem<'a>>,
    children: Vec<ChildRef>,
    size: usize,
    nodes: Vec<ChildRef>,
    work: StreamWork,
    staging: StagingWork,
}

/// Returns the independently calculated little-endian TREE-21 item hash.
pub(super) fn hash(bytes: &[u8]) -> u64 {
    let hash = blake3::hash(bytes);
    let bytes = hash.as_bytes();
    u64::from(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Encodes one literal full or prefix-compressed leaf item.
///
/// # Errors
/// Preserves canonical Entry encoding failures.
pub(super) fn leaf_bytes(item: &LeafItem<'_>, previous: &[u8]) -> TestResult<Vec<u8>> {
    let shared = previous
        .iter()
        .zip(&item.key)
        .take_while(|(left, right)| left == right)
        .count();
    let mut bytes = Vec::new();
    cbor::write_array(&mut bytes, 3);
    cbor::write_bytes(&mut bytes, &item.key[shared..]);
    cbor::write_uint(&mut bytes, shared as u64);
    bytes.extend(tree_format::encode_entry(&item.entry, MINIMUM)?);
    Ok(bytes)
}

fn child_bytes(child: &ChildRef) -> Vec<u8> {
    let mut bytes = Vec::new();
    cbor::write_array(&mut bytes, 4);
    cbor::write_bytes(&mut bytes, &child.last_key);
    cbor::write_bytes(&mut bytes, &child.child);
    cbor::write_uint(&mut bytes, child.count);
    cbor::write_uint(&mut bytes, child.weight);
    bytes
}

/// Sums the seven canonical item, comparison, frontier and byte units.
pub(super) fn sum(work: StreamWork) -> usize {
    work.item_reads
        + work.comparisons
        + work.frontier_checks
        + work.item_bytes_encoded
        + work.node_bytes_encoded
        + work.item_bytes_hashed
        + work.node_bytes_hashed
}

fn components(work: StreamWork) -> [usize; 7] {
    [
        work.item_reads,
        work.comparisons,
        work.frontier_checks,
        work.item_bytes_encoded,
        work.node_bytes_encoded,
        work.item_bytes_hashed,
        work.node_bytes_hashed,
    ]
}

/// Checks every canonical field is attributed exactly once, including non-B phases.
///
/// # Panics
/// Panics for omitted or duplicated stream work, or an unexpected adoption pass.
pub(super) fn assert_partition(work: &Work) {
    let mut total = [0; 7];
    for phase in work
        .regions
        .iter()
        .map(|region| region.work)
        .chain(work.new_levels.iter().map(|level| level.work))
        .chain([work.completion, work.root_properties, work.preparation])
    {
        for (total, amount) in total.iter_mut().zip(components(phase)) {
            *total += amount;
        }
    }
    assert_eq!(
        total,
        components(work.stream),
        "complete fieldwise canonical conservation"
    );
    assert_eq!(
        work.adoption,
        StreamWork::default(),
        "these entry batches perform no subtree adoption"
    );
}

impl<'a> Chunker<'a> {
    fn new(level: u8, usage: TreeUse) -> Self {
        Self {
            level,
            usage,
            leaves: Vec::new(),
            children: Vec::new(),
            size: 0,
            nodes: Vec::new(),
            work: StreamWork::default(),
            staging: StagingWork::default(),
        }
    }

    fn empty(&self) -> bool {
        self.leaves.is_empty() && self.children.is_empty()
    }

    // 0: retain; 1: close after; 2: split before. This expands TREE-22 rather
    // than using boundary::decide or any writer-provided boundary result.
    fn decision(&mut self, length: usize, canonical: &[u8]) -> TestResult<u8> {
        self.work.frontier_checks += 1;
        if canonical.len() > 65536 || length > 65536 {
            return Err("oversized independent canonical item".into());
        }
        let size = self.size + length;
        if size > 65536 {
            return Ok(2);
        }
        if size == 65536 {
            return Ok(1);
        }
        if size < 4096 {
            return Ok(0);
        }
        self.work.item_bytes_hashed += canonical.len();
        let base = if size >= 32768 {
            1_u64 << 24
        } else {
            (1_u64 << 20) + (size as u64 - 4096) * ((1 << 24) - (1 << 20)) / 28672
        };
        Ok(u8::from(
            hash(canonical) < (base * length as u64 / 8).min(1 << 32),
        ))
    }

    fn leaf(&mut self, item: LeafItem<'a>) -> TestResult {
        let canonical = leaf_bytes(&item, &[])?;
        let previous = self
            .leaves
            .last()
            .map_or(&[][..], |item| item.key.as_slice());
        let stored = leaf_bytes(&item, previous)?;
        self.work.item_reads += 1;
        self.work.item_bytes_encoded += canonical.len() + stored.len();
        let mut length = stored.len();
        let mut decision = self.decision(length, &canonical)?;
        if decision == 2 {
            self.close()?;
            length = canonical.len();
            decision = self.decision(length, &canonical)?;
        }
        self.leaves.push(item);
        self.size += length;
        if decision == 1 {
            self.close()?;
        }
        Ok(())
    }

    fn child(&mut self, child: ChildRef) -> TestResult {
        let bytes = child_bytes(&child);
        self.work.item_reads += 1;
        self.work.item_bytes_encoded += bytes.len();
        let mut decision = self.decision(bytes.len(), &bytes)?;
        if decision == 2 {
            self.close()?;
            decision = self.decision(bytes.len(), &bytes)?;
        }
        self.children.push(child);
        self.size += bytes.len();
        if decision == 1 {
            self.close()?;
        }
        Ok(())
    }

    fn close(&mut self) -> TestResult {
        if self.empty() {
            return Ok(());
        }
        self.staging.nodes += 1;
        self.staging.rows += self.leaves.len();
        self.staging.edges += self.children.len()
            + self
                .leaves
                .iter()
                .filter(|item| {
                    item.entry
                        .attrs
                        .iter()
                        .any(|attribute| attribute.name == "index.occurrences")
                })
                .count();
        let (last_key, count, descendants, items) = if self.level == 0 {
            let last_key = self.leaves.last().ok_or("empty leaf")?.key.clone();
            let count = self.leaves.len() as u64;
            (
                last_key,
                count,
                0,
                NodeItems::Leaf(std::mem::take(&mut self.leaves)),
            )
        } else {
            let last_key = self.children.last().ok_or("empty parent")?.last_key.clone();
            let count = self.children.iter().map(|child| child.count).sum();
            let weight = self.children.iter().map(|child| child.weight).sum();
            (
                last_key,
                count,
                weight,
                NodeItems::Internal(std::mem::take(&mut self.children)),
            )
        };
        let bytes = tree_format::encode_node_for(
            &Node {
                level: self.level,
                items,
                props: None,
            },
            false,
            MINIMUM,
            self.usage,
        )?;
        self.work.node_bytes_encoded += bytes.len();
        self.work.node_bytes_hashed += bytes.len() + b"terrane-node-v1\0".len();
        let child: Digest = TERRANE_V1
            .calculate(IdentityKind::Node, &bytes)?
            .terrane_v1_digest()?;
        self.nodes.push(ChildRef {
            last_key,
            child,
            count,
            weight: descendants + bytes.len() as u64,
        });
        self.size = 0;
        Ok(())
    }
}

fn retain_outputs(expected: &mut ExpectedBatch, chunker: &Chunker<'_>) {
    expected.staging.nodes += chunker.staging.nodes;
    expected.staging.rows += chunker.staging.rows;
    expected.staging.edges += chunker.staging.edges;
    expected
        .candidates
        .extend(chunker.nodes.iter().map(|node| node.child));
}

fn seek(nodes: &[&terrane_format::tree_builder::StoredNode<'_>], key: &[u8]) -> usize {
    nodes
        .iter()
        .position(|node| node.last_key().is_some_and(|last| last >= key))
        .unwrap_or(nodes.len() - 1)
        .saturating_sub(1)
}

/// Predicts the exact canonical batch schedule from old/new immutable data.
///
/// # Errors
/// Preserves independent serialization, identity and stream consistency failures.
/// # Panics
/// Panics if independently rebuilt resynchronization boundaries disagree.
pub(super) fn expected<'a>(
    old: &Tree<'a>,
    new: &Tree<'a>,
    edits: &[(Vec<u8>, Option<Entry<'a>>)],
) -> TestResult<ExpectedBatch> {
    let mut result = ExpectedBatch {
        edits: edits.len(),
        old_level: old.root().level(),
        regions: Vec::new(),
        staging: StagingWork::default(),
        candidates: BTreeSet::new(),
    };
    let old_leaves = old
        .nodes()
        .filter(|node| node.level() == 0)
        .collect::<Vec<_>>();
    let mut ordered = old_leaves;
    ordered.sort_by(|left, right| left.first_key().cmp(&right.first_key()));
    let mut spans = Vec::new();
    let mut position = 0;
    let mut start = seek(&ordered, &edits[0].0);
    loop {
        let first = ordered[start].last_key().unwrap_or_default().to_vec();
        let mut last = first.clone();
        let mut chunker = Chunker::new(0, old.usage());
        let mut recovered = false;
        let mut next = None;
        for (offset, node) in ordered[start..].iter().enumerate() {
            let node_index = start + offset;
            let NodeItems::Leaf(items) = &node.node().items else {
                return Err("expected leaf".into());
            };
            last = node.last_key().unwrap_or_default().to_vec();
            chunker.work.comparisons += 1;
            for item in items {
                chunker.work.item_reads += 1;
                let mut consumed = false;
                while let Some((key, value)) = edits.get(position) {
                    chunker.work.comparisons += 1;
                    if key > &item.key {
                        break;
                    }
                    if let Some(entry) = value {
                        chunker.leaf(LeafItem {
                            key: key.clone(),
                            entry: entry.clone(),
                        })?;
                    }
                    position += 1;
                    chunker.work.comparisons += 1;
                    if key == &item.key {
                        consumed = true;
                        break;
                    }
                }
                if !consumed {
                    chunker.leaf(item.clone())?;
                }
            }
            let tail = node_index + 1 == ordered.len();
            if tail {
                for (key, entry) in &edits[position..] {
                    if let Some(entry) = entry {
                        chunker.leaf(LeafItem {
                            key: key.clone(),
                            entry: entry.clone(),
                        })?;
                    }
                }
                position = edits.len();
            }
            chunker.work.frontier_checks += 1;
            if chunker.empty() {
                if let Some((key, _)) = edits.get(position) {
                    chunker.work.frontier_checks += 1;
                    chunker.work.comparisons += 1;
                    let probed = seek(&ordered, key);
                    if ordered[probed].last_key().unwrap_or_default() > last.as_slice() {
                        next = Some(probed);
                        recovered = !tail;
                        break;
                    }
                } else {
                    recovered = !tail;
                    break;
                }
            }
        }
        chunker.close()?;
        retain_outputs(&mut result, &chunker);
        result.regions.push(BoundaryRegion {
            level: 0,
            invalidated: first.clone(),
            resynchronized: recovered.then(|| last.clone()),
            last: last.clone(),
            work: chunker.work,
        });
        spans.push(Span {
            first,
            last,
            nodes: chunker.nodes,
        });
        let Some(next) = next else {
            break;
        };
        start = next;
    }
    for level in 1..=old.root().level() {
        let mut nodes = old
            .nodes()
            .filter(|node| node.level() == level)
            .collect::<Vec<_>>();
        nodes.sort_by(|left, right| left.first_key().cmp(&right.first_key()));
        let mut replacements = Vec::new();
        let mut position = 0;
        let mut inserted = false;
        let mut start = seek(&nodes, &spans[0].first);
        loop {
            let first = nodes[start]
                .last_key()
                .ok_or("empty parent boundary")?
                .to_vec();
            let mut last = first.clone();
            let mut recovered = false;
            let mut next = None;
            let mut chunker = Chunker::new(level, old.usage());
            for node in &nodes[start..] {
                last = node.last_key().ok_or("missing parent boundary")?.to_vec();
                let NodeItems::Internal(children) = &node.node().items else {
                    return Err("expected child refs".into());
                };
                for child in children {
                    chunker.work.item_reads += 1;
                    while let Some(span) = spans.get(position) {
                        chunker.work.comparisons += 1;
                        if child.last_key <= span.last {
                            break;
                        }
                        if !inserted {
                            return Err("replacement span skipped".into());
                        }
                        position += 1;
                        inserted = false;
                    }
                    let span = spans.get(position);
                    chunker.work.comparisons += usize::from(span.is_some());
                    if span.is_some_and(|span| child.last_key >= span.first) {
                        if !inserted {
                            for child in &spans[position].nodes {
                                chunker.child(child.clone())?;
                            }
                            inserted = true;
                        }
                    } else {
                        chunker.child(child.clone())?;
                    }
                }
                if let Some(span) = spans.get(position) {
                    chunker.work.comparisons += usize::from(inserted);
                    if inserted && last >= span.last {
                        position += 1;
                        inserted = false;
                    }
                }
                chunker.work.frontier_checks += 1;
                if chunker.empty() {
                    if let Some(span) = spans.get(position) {
                        chunker.work.frontier_checks += 1;
                        chunker.work.comparisons += 1;
                        let probed = seek(&nodes, &span.first);
                        if nodes[probed].last_key().ok_or("probe key")? > last.as_slice() {
                            next = Some(probed);
                            chunker.work.comparisons += 1;
                            recovered = node.last_key() != old.root().last_key();
                            break;
                        }
                    } else {
                        chunker.work.comparisons += 1;
                        recovered = node.last_key() != old.root().last_key();
                        break;
                    }
                }
            }
            chunker.close()?;
            retain_outputs(&mut result, &chunker);
            result.regions.push(BoundaryRegion {
                level,
                invalidated: first.clone(),
                resynchronized: recovered.then(|| last.clone()),
                last: last.clone(),
                work: chunker.work,
            });
            replacements.push(Span {
                first,
                last,
                nodes: chunker.nodes,
            });
            let Some(next) = next else {
                break;
            };
            start = next;
        }
        assert_eq!(position, spans.len());
        spans = replacements;
    }
    if new.is_empty() {
        // Empty completion belongs to its own phase, outside old-level B.
        result.staging.nodes += 1;
        result.candidates.insert(new.root_identity());
    }
    // Canonical emitted leaf outputs must occur in the independently rebuilt
    // final tree; no measured writer output is an input to this reference model.
    for region in result
        .regions
        .iter()
        .filter(|region| region.resynchronized.is_some())
    {
        assert!(
            new.nodes().any(|node| node.level() == region.level
                && node.last_key() == Some(region.last.as_slice())),
            "independently canonical recovered boundary"
        );
    }
    Ok(result)
}

/// Compares native batches with independently derived exact per-level costs.
///
/// # Panics
/// Panics if any endpoint, physical counter or overlapping batch region differs.
pub(super) fn assert_batch(actual: &BatchWork, expected: &ExpectedBatch) {
    assert_eq!(actual.edits, expected.edits);
    assert_eq!(
        actual.work.regions, expected.regions,
        "exact independent region endpoints and physical stream schedule at every old level"
    );
    let actual_cost = actual
        .work
        .regions
        .iter()
        .map(|region| sum(region.work))
        .sum::<usize>();
    let expected_cost = expected
        .regions
        .iter()
        .map(|region| sum(region.work))
        .sum::<usize>();
    assert_eq!(actual_cost, expected_cost);
    for level in 0..=expected.old_level {
        let regions = expected
            .regions
            .iter()
            .filter(|region| region.level == level)
            .collect::<Vec<_>>();
        assert!(!regions.is_empty());
        for pair in regions.windows(2) {
            assert!(
                pair[0].last < pair[1].invalidated,
                "shared physical suffix cannot restart in another region"
            );
        }
    }
}

/// Sums the independently replayed additional canonical work at every old level.
pub(super) fn boundary_cost(expected: &ExpectedBatch) -> usize {
    expected.regions.iter().map(|region| sum(region.work)).sum()
}
