//! Computes namespace divergence costs directly from immutable physical frontiers.
//!
//! This reference traversal never invokes discovery and never reads its report.
//! Each reached occurrence has a separate active boundary at each physical level;
//! equal immutable nodes and aligned canonical cuts close that level's attribution.

use std::cmp::Ordering;

use super::{Model, TestResult, tree};
use terrane_format::{
    identity::Digest,
    indexing::{
        incremental::{DiscoveryWork, PhysicalEvent, PhysicalEventKind},
        maintenance::UpdateWork,
    },
    tree_builder::StoredNode,
    tree_format::{EntryKind, LeafItem, NodeItems, TreeUse},
};

mod events;

#[derive(Clone, Copy)]
enum Part<'tree, 'value> {
    Node(&'tree StoredNode<'value>),
    Item(&'tree LeafItem<'value>),
}

/// Independent complete traversal totals, separating divergence from ordinary work.
#[derive(Clone, Default)]
pub(super) struct Expected {
    /// Counts item, comparison and frontier units owned by divergent regions (B).
    pub(super) boundary: usize,
    /// Counts those same units outside divergent region ownership.
    pub(super) ordinary: usize,
    /// Counts every physical Node open, including repeated graft occurrences.
    pub(super) node_reads: usize,
    /// Counts equal immutable frontiers skipped without exposing their entries.
    pub(super) skipped: usize,
    streams: Vec<events::ExpectedStream>,
}

impl Expected {
    fn combine(&mut self, other: Self) {
        self.boundary += other.boundary;
        self.ordinary += other.ordinary;
        self.node_reads += other.node_reads;
        self.skipped += other.skipped;
    }
}

struct Cost {
    active: Vec<bool>,
    work: Expected,
}

impl Cost {
    fn new() -> Self {
        Self {
            active: vec![false; 256],
            work: Expected::default(),
        }
    }

    fn charge(&mut self, level: u8, amount: usize) {
        if self.active[usize::from(level)] {
            self.work.boundary += amount;
        } else {
            self.work.ordinary += amount;
        }
    }

    fn owner(&mut self, level: u8) -> bool {
        self.charge(level, 1);
        self.active[usize::from(level)]
    }

    fn open(&mut self, level: u8) {
        self.charge(level, 1);
        assert!(!self.active[usize::from(level)]);
        self.active[usize::from(level)] = true;
    }

    fn close(&mut self, level: u8) {
        self.charge(level, 1);
        self.active[usize::from(level)] = false;
    }
}

impl Part<'_, '_> {
    fn level(self) -> u8 {
        match self {
            Self::Node(node) => node.level(),
            Self::Item(_) => 0,
        }
    }

    fn first(self, cost: &mut Cost) -> Vec<u8> {
        match self {
            Self::Item(item) => {
                cost.charge(0, 1);
                item.key.clone()
            }
            Self::Node(node) => first(node, cost),
        }
    }
}

fn first(node: &StoredNode<'_>, cost: &mut Cost) -> Vec<u8> {
    // Node opens are observable but explicitly excluded from normative B units.
    cost.work.node_reads += 1;
    match node.items() {
        NodeItems::Leaf(items) => {
            if let Some(item) = items.first() {
                cost.charge(0, 1);
                item.key.clone()
            } else {
                Vec::new()
            }
        }
        NodeItems::Internal(_) => {
            if let Some(child) = node.children().first() {
                cost.charge(node.level(), 1);
                first(child, cost)
            } else {
                Vec::new()
            }
        }
    }
}

fn expand<'tree, 'value>(parts: &mut Vec<Part<'tree, 'value>>, cost: &mut Cost) {
    if let Some(Part::Node(node)) = parts.pop() {
        cost.work.node_reads += 1;
        match node.items() {
            NodeItems::Leaf(items) => {
                cost.charge(0, items.len());
                parts.extend(items.iter().rev().map(Part::Item));
            }
            NodeItems::Internal(children) => {
                cost.charge(node.level(), children.len());
                parts.extend(node.children().iter().rev().map(|child| Part::Node(child)));
            }
        }
    }
}

fn next<'tree, 'value>(
    parts: &mut Vec<Part<'tree, 'value>>,
    cost: &mut Cost,
) -> Option<&'tree LeafItem<'value>> {
    loop {
        match parts.last().copied()? {
            Part::Node(_) => expand(parts, cost),
            Part::Item(item) => {
                parts.pop();
                return Some(item);
            }
        }
    }
}

fn changed(
    old: &Model,
    left: Option<&LeafItem<'_>>,
    new: &Model,
    right: Option<&LeafItem<'_>>,
    cost: &mut Cost,
) -> TestResult<Expected> {
    cost.charge(0, 1);
    match (
        left.map(|item| &item.entry.kind),
        right.map(|item| &item.entry.kind),
    ) {
        (Some(EntryKind::Tree { root: left, .. }), Some(EntryKind::Tree { root: right, .. })) => {
            expected_cost(old, *left, new, *right)
        }
        (Some(EntryKind::Tree { .. }), _) | (_, Some(EntryKind::Tree { .. })) => {
            Err("fixture adds or removes unsupported whole graft population".into())
        }
        _ => Ok(Expected::default()),
    }
}

/// Derives exact additional namespace work from independently decoded old/new roots.
///
/// # Errors
/// Preserves independent decoding and canonical reconstruction failures.
/// # Panics
/// Panics if a physical level opens two simultaneous connected regions.
pub(super) fn expected(
    old: &Model,
    old_root: Digest,
    new: &Model,
    new_root: Digest,
) -> TestResult<Expected> {
    let mut result = expected_cost(old, old_root, new, new_root)?;
    result.streams = events::expected(old, old_root, new, new_root)?;
    Ok(result)
}

fn expected_cost(
    old: &Model,
    old_root: Digest,
    new: &Model,
    new_root: Digest,
) -> TestResult<Expected> {
    if old_root == new_root {
        return Ok(Expected {
            ordinary: 1,
            skipped: 1,
            ..Expected::default()
        });
    }
    let before = tree(&old.sources, old_root, TreeUse::Ordinary)?;
    let after = tree(&new.sources, new_root, TreeUse::Ordinary)?;
    let mut left = vec![Part::Node(before.root())];
    let mut right = vec![Part::Node(after.root())];
    let mut cost = Cost::new();
    let mut descendants = Expected::default();
    // The initial paired-root check precedes either divergent frontier.
    cost.charge(before.root().level().min(after.root().level()), 1);
    let old_properties = before.props().unwrap_or_default();
    let new_properties = after.props().unwrap_or_default();
    // This fixture changes binding values but never adds/removes property names.
    // Each side is read once; every paired binding compares its name and value.
    assert_eq!(
        old_properties.iter().map(|p| p.name).collect::<Vec<_>>(),
        new_properties.iter().map(|p| p.name).collect::<Vec<_>>()
    );
    cost.charge(
        0,
        old_properties.len() + new_properties.len() + 2 * old_properties.len(),
    );
    for root in [before.root(), after.root()] {
        cost.work.node_reads += 1;
        if root.count() != 0 {
            cost.charge(root.level(), 1);
        }
    }
    if before.root().level() != after.root().level() {
        cost.open(before.root().level());
        cost.open(after.root().level());
    }
    loop {
        match (left.last().copied(), right.last().copied()) {
            (None, None) => break,
            (None, Some(_)) => {
                if let Some(item) = next(&mut right, &mut cost) {
                    descendants.combine(changed(old, None, new, Some(item), &mut cost)?);
                }
            }
            (Some(_), None) => {
                if let Some(item) = next(&mut left, &mut cost) {
                    descendants.combine(changed(old, Some(item), new, None, &mut cost)?);
                }
            }
            (Some(a), Some(b)) => {
                cost.charge(a.level().min(b.level()), 1);
                match a.level().cmp(&b.level()) {
                    Ordering::Less => {
                        expand(&mut right, &mut cost);
                        continue;
                    }
                    Ordering::Greater => {
                        expand(&mut left, &mut cost);
                        continue;
                    }
                    Ordering::Equal => {}
                }
                if let (Part::Node(a), Part::Node(b)) = (a, b) {
                    if a.identity() == b.identity() {
                        cost.work.skipped += 1;
                        if cost.owner(a.level()) {
                            cost.close(a.level());
                        }
                        left.pop();
                        right.pop();
                        continue;
                    }
                    if a.last_key() != b.last_key() && !cost.owner(a.level()) {
                        cost.open(a.level());
                    }
                }
                cost.charge(a.level().min(b.level()), 1);
                let first_a = a.first(&mut cost);
                let first_b = b.first(&mut cost);
                let ordering = first_a.cmp(&first_b);
                if let (Part::Node(a), Part::Node(b)) = (a, b)
                    && a.last_key() == b.last_key()
                    && first_a == first_b
                    && cost.owner(a.level())
                {
                    cost.close(a.level());
                }
                match ordering {
                    Ordering::Less => match a {
                        Part::Node(_) => expand(&mut left, &mut cost),
                        Part::Item(item) => {
                            left.pop();
                            descendants.combine(changed(old, Some(item), new, None, &mut cost)?);
                        }
                    },
                    Ordering::Greater => match b {
                        Part::Node(_) => expand(&mut right, &mut cost),
                        Part::Item(item) => {
                            right.pop();
                            descendants.combine(changed(old, None, new, Some(item), &mut cost)?);
                        }
                    },
                    Ordering::Equal => match (a, b) {
                        (Part::Node(_), Part::Node(_)) => {
                            expand(&mut left, &mut cost);
                            expand(&mut right, &mut cost);
                        }
                        (Part::Node(_), _) => expand(&mut left, &mut cost),
                        (_, Part::Node(_)) => expand(&mut right, &mut cost),
                        (Part::Item(a), Part::Item(b)) => {
                            left.pop();
                            right.pop();
                            cost.charge(0, 1);
                            if a.entry != b.entry {
                                descendants.combine(changed(
                                    old,
                                    Some(a),
                                    new,
                                    Some(b),
                                    &mut cost,
                                )?);
                            }
                        }
                    },
                }
            }
        }
    }
    for level in 0..=before.root().level().max(after.root().level()) {
        cost.owner(level);
    }
    cost.work.combine(descendants);
    Ok(cost.work)
}

fn components(work: DiscoveryWork) -> [usize; 8] {
    [
        work.node_reads,
        work.item_reads,
        work.child_reads,
        work.comparisons,
        work.frontier_checks,
        work.skipped_subtrees,
        work.boundary_checks,
        work.property_reads,
    ]
}

fn accumulate(work: &mut DiscoveryWork, event: &PhysicalEvent) {
    match event.kind {
        PhysicalEventKind::NodeRead => work.node_reads += event.amount,
        PhysicalEventKind::ItemRead => work.item_reads += event.amount,
        PhysicalEventKind::ChildRead => work.child_reads += event.amount,
        PhysicalEventKind::Comparison => work.comparisons += event.amount,
        PhysicalEventKind::FrontierCheck => work.frontier_checks += event.amount,
        PhysicalEventKind::SkippedSubtree => work.skipped_subtrees += event.amount,
        PhysicalEventKind::BoundaryCheck => work.boundary_checks += event.amount,
        PhysicalEventKind::PropertyRead => work.property_reads += event.amount,
    }
}

/// Checks complete event conservation and independently predicted source traversal.
///
/// # Panics
/// Panics for lost, duplicated, misattributed or unexpectedly enumerated work.
pub(super) fn assert_work(work: &UpdateWork, expected: &Expected) {
    events::assert_streams(&work.streams, &expected.streams);
    let mut total = DiscoveryWork::default();
    let mut boundary = 0;
    let mut ordinary = 0;
    for stream in &work.streams {
        let mut prefix = DiscoveryWork::default();
        for event in &stream.events {
            let before = components(prefix);
            accumulate(&mut prefix, event);
            accumulate(&mut total, event);
            if let Some(index) = event.boundary {
                let region = &work.boundaries[index];
                assert_eq!(stream.old_root, Some(region.old.source));
                assert_eq!(stream.new_root, Some(region.new.source));
                assert_eq!(stream.old_hops.as_ref(), Some(&region.old_hops));
                assert_eq!(stream.new_hops.as_ref(), Some(&region.new_hops));
                assert!(event.level == region.old.level || event.level == region.new.level);
                for ((start, end), (before, after)) in components(region.start)
                    .into_iter()
                    .zip(components(region.end))
                    .zip(before.into_iter().zip(components(prefix)))
                {
                    assert!(start <= before, "event precedes its exclusive region");
                    assert!(after <= end, "event exceeds its exclusive region");
                }
            }
            if !matches!(
                event.kind,
                PhysicalEventKind::NodeRead | PhysicalEventKind::SkippedSubtree
            ) {
                if event.boundary.is_some() {
                    boundary += event.amount;
                } else {
                    ordinary += event.amount;
                }
            }
        }
        assert_eq!(
            prefix, stream.work,
            "each stream conserves every event field"
        );
    }
    assert_eq!(
        total, work.discovery,
        "all occurrence streams are conserved"
    );
    assert_eq!(
        work.initialization,
        Default::default(),
        "no hidden initial enumeration"
    );
    assert_eq!(boundary, expected.boundary);
    assert_eq!(
        ordinary, expected.ordinary,
        "ordinary work cannot conceal a full scan"
    );
    assert_eq!(total.node_reads, expected.node_reads);
    assert_eq!(total.skipped_subtrees, expected.skipped);
}
