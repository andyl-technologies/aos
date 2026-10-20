//! Predicts ordinary discovery events for exact immutable source occurrences.
//!
//! Inputs are independently built namespace bytes, never discovery reports or
//! writer outputs. Literal frontiers determine reads, comparisons and equal
//! skips; graft keys and each side's source root determine occurrence addresses.
//! Divergent physical levels only classify events as ordinary or boundary work.
//! The separate scalar boundary oracle remains responsible for normative B.

use std::cmp::Ordering;

use super::super::{Model, TestResult, tree};
use terrane_format::{
    identity::Digest,
    indexing::incremental::{Address, DiscoveryWork, Hop, PhysicalEventKind, StreamWork},
    tree_builder::StoredNode,
    tree_format::{EntryKind, LeafItem, NodeItems, TreeUse},
};

/// Predicts one reached source pair and its exact root-local occurrence context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ExpectedStream {
    /// Independently selected previous source root.
    pub(super) old_root: Digest,
    /// Independently selected replacement source root.
    pub(super) new_root: Digest,
    /// Previous ordered graft keys, retaining each containing source root.
    pub(super) old_hops: Address,
    /// Replacement ordered graft keys, retaining each containing source root.
    pub(super) new_hops: Address,
    /// Fieldwise totals of all events outside divergent boundary ownership.
    pub(super) ordinary: DiscoveryWork,
    /// All physical Node opens, including those owned by divergent boundaries.
    pub(super) node_reads: usize,
    /// All equal immutable skips, including boundary-owned recovery skips.
    pub(super) skipped: usize,
}

#[derive(Clone, Copy)]
enum Part<'tree, 'value> {
    Node(&'tree StoredNode<'value>),
    Item(&'tree LeafItem<'value>),
}

impl Part<'_, '_> {
    fn level(self) -> u8 {
        match self {
            Self::Node(node) => node.level(),
            Self::Item(_) => 0,
        }
    }

    fn first(self, counts: &mut Counts) -> Vec<u8> {
        match self {
            Self::Node(node) => first(node, counts),
            Self::Item(item) => {
                counts.charge(0, PhysicalEventKind::ItemRead, 1);
                item.key.clone()
            }
        }
    }
}

struct Counts {
    // A height-change region spans two levels and cannot recover at an
    // equal-height interior pair. Single-level regions can recover normally.
    active: Vec<Option<(u8, u8)>>,
    ordinary: DiscoveryWork,
    node_reads: usize,
    skipped: usize,
}

impl Counts {
    fn new() -> Self {
        Self {
            active: vec![None; 256],
            ordinary: DiscoveryWork::default(),
            node_reads: 0,
            skipped: 0,
        }
    }

    fn charge(&mut self, level: u8, kind: PhysicalEventKind, amount: usize) {
        match kind {
            PhysicalEventKind::NodeRead => self.node_reads += amount,
            PhysicalEventKind::SkippedSubtree => self.skipped += amount,
            _ => {}
        }
        if self.active[usize::from(level)].is_none() {
            add(&mut self.ordinary, kind, amount);
        }
    }

    fn owner(&mut self, level: u8) -> Option<(u8, u8)> {
        self.charge(level, PhysicalEventKind::BoundaryCheck, 1);
        self.active[usize::from(level)]
    }

    fn open(&mut self, level: u8, pair: (u8, u8)) {
        self.charge(level, PhysicalEventKind::BoundaryCheck, 1);
        assert!(self.active[usize::from(level)].is_none());
        self.active[usize::from(level)] = Some(pair);
    }

    fn recover(&mut self, level: u8) {
        if self.owner(level) == Some((level, level)) {
            self.charge(level, PhysicalEventKind::BoundaryCheck, 1);
            self.active[usize::from(level)] = None;
        }
    }
}

fn add(work: &mut DiscoveryWork, kind: PhysicalEventKind, amount: usize) {
    match kind {
        PhysicalEventKind::NodeRead => work.node_reads += amount,
        PhysicalEventKind::ItemRead => work.item_reads += amount,
        PhysicalEventKind::ChildRead => work.child_reads += amount,
        PhysicalEventKind::Comparison => work.comparisons += amount,
        PhysicalEventKind::FrontierCheck => work.frontier_checks += amount,
        PhysicalEventKind::SkippedSubtree => work.skipped_subtrees += amount,
        PhysicalEventKind::BoundaryCheck => work.boundary_checks += amount,
        PhysicalEventKind::PropertyRead => work.property_reads += amount,
    }
}

fn first(node: &StoredNode<'_>, counts: &mut Counts) -> Vec<u8> {
    counts.charge(node.level(), PhysicalEventKind::NodeRead, 1);
    match node.items() {
        NodeItems::Leaf(items) => match items.first() {
            Some(item) => {
                counts.charge(0, PhysicalEventKind::ItemRead, 1);
                item.key.clone()
            }
            None => Vec::new(),
        },
        NodeItems::Internal(_) => match node.children().first() {
            Some(child) => {
                counts.charge(node.level(), PhysicalEventKind::ChildRead, 1);
                first(child, counts)
            }
            None => Vec::new(),
        },
    }
}

fn expand<'tree, 'value>(parts: &mut Vec<Part<'tree, 'value>>, counts: &mut Counts) {
    let Some(Part::Node(node)) = parts.pop() else {
        return;
    };
    counts.charge(node.level(), PhysicalEventKind::NodeRead, 1);
    match node.items() {
        NodeItems::Leaf(items) => {
            counts.charge(0, PhysicalEventKind::ItemRead, items.len());
            parts.extend(items.iter().rev().map(Part::Item));
        }
        NodeItems::Internal(children) => {
            counts.charge(node.level(), PhysicalEventKind::ChildRead, children.len());
            parts.extend(node.children().iter().rev().map(|child| Part::Node(child)));
        }
    }
}

fn next<'tree, 'value>(
    parts: &mut Vec<Part<'tree, 'value>>,
    counts: &mut Counts,
) -> Option<&'tree LeafItem<'value>> {
    loop {
        match parts.last().copied()? {
            Part::Node(_) => expand(parts, counts),
            Part::Item(item) => {
                parts.pop();
                return Some(item);
            }
        }
    }
}

fn address(hops: &Address, root: Digest, key: &[u8]) -> Address {
    let mut result = hops.clone();
    result.push(Hop {
        source: root,
        key: key.to_vec(),
    });
    result
}

struct Inputs<'model> {
    old: &'model Model,
    new: &'model Model,
}

impl Inputs<'_> {
    fn changed(
        &self,
        left: Option<&LeafItem<'_>>,
        right: Option<&LeafItem<'_>>,
        context: &ExpectedStream,
        counts: &mut Counts,
        streams: &mut Vec<ExpectedStream>,
    ) -> TestResult {
        if let (
            Some(LeafItem {
                key: old_key,
                entry: old,
                ..
            }),
            Some(LeafItem {
                key: new_key,
                entry: new,
                ..
            }),
        ) = (left, right)
            && let (EntryKind::Tree { root: old, .. }, EntryKind::Tree { root: new, .. }) =
                (&old.kind, &new.kind)
        {
            self.pair(
                *old,
                *new,
                address(&context.old_hops, context.old_root, old_key),
                address(&context.new_hops, context.new_root, new_key),
                streams,
            )?;
        } else if left.is_some_and(|item| matches!(item.entry.kind, EntryKind::Tree { .. }))
            || right.is_some_and(|item| matches!(item.entry.kind, EntryKind::Tree { .. }))
        {
            return Err("fixture adds or removes unsupported whole graft population".into());
        }
        counts.charge(0, PhysicalEventKind::Comparison, 1);
        Ok(())
    }

    fn pair(
        &self,
        old_root: Digest,
        new_root: Digest,
        old_hops: Address,
        new_hops: Address,
        streams: &mut Vec<ExpectedStream>,
    ) -> TestResult {
        let before = tree(&self.old.sources, old_root, TreeUse::Ordinary)?;
        let after = tree(&self.new.sources, new_root, TreeUse::Ordinary)?;
        let mut counts = Counts::new();
        let mut context = ExpectedStream {
            old_root,
            new_root,
            old_hops,
            new_hops,
            ordinary: DiscoveryWork::default(),
            node_reads: 0,
            skipped: 0,
        };
        counts.charge(
            before.root().level().min(after.root().level()),
            PhysicalEventKind::FrontierCheck,
            1,
        );
        if old_root == new_root {
            counts.charge(before.root().level(), PhysicalEventKind::SkippedSubtree, 1);
        } else {
            let old_properties = before.props().unwrap_or_default();
            let new_properties = after.props().unwrap_or_default();
            // The population fixture retains the canonical property-name set.
            assert_eq!(
                old_properties.iter().map(|p| p.name).collect::<Vec<_>>(),
                new_properties.iter().map(|p| p.name).collect::<Vec<_>>()
            );
            counts.charge(
                before.root().level(),
                PhysicalEventKind::PropertyRead,
                old_properties.len(),
            );
            counts.charge(
                after.root().level(),
                PhysicalEventKind::PropertyRead,
                new_properties.len(),
            );
            counts.charge(
                before.root().level().min(after.root().level()),
                PhysicalEventKind::Comparison,
                2 * old_properties.len(),
            );
            for root in [before.root(), after.root()] {
                counts.charge(root.level(), PhysicalEventKind::NodeRead, 1);
                match root.items() {
                    NodeItems::Leaf(items) if !items.is_empty() => {
                        counts.charge(0, PhysicalEventKind::ItemRead, 1)
                    }
                    NodeItems::Internal(items) if !items.is_empty() => {
                        counts.charge(root.level(), PhysicalEventKind::ChildRead, 1)
                    }
                    _ => {}
                }
            }
            let levels = (before.root().level(), after.root().level());
            if levels.0 != levels.1 {
                counts.open(levels.0, levels);
                counts.open(levels.1, levels);
            }

            let mut left = vec![Part::Node(before.root())];
            let mut right = vec![Part::Node(after.root())];
            while let (Some(a), Some(b)) = (left.last().copied(), right.last().copied()) {
                let level = a.level().min(b.level());
                counts.charge(level, PhysicalEventKind::FrontierCheck, 1);
                match a.level().cmp(&b.level()) {
                    Ordering::Less => {
                        expand(&mut right, &mut counts);
                        continue;
                    }
                    Ordering::Greater => {
                        expand(&mut left, &mut counts);
                        continue;
                    }
                    Ordering::Equal => {}
                }
                if let (Part::Node(a), Part::Node(b)) = (a, b) {
                    if a.identity() == b.identity() {
                        counts.charge(a.level(), PhysicalEventKind::SkippedSubtree, 1);
                        counts.recover(a.level());
                        left.pop();
                        right.pop();
                        continue;
                    }
                    if a.last_key() != b.last_key() && counts.owner(a.level()).is_none() {
                        counts.open(a.level(), (a.level(), b.level()));
                    }
                }
                counts.charge(level, PhysicalEventKind::Comparison, 1);
                let first_a = a.first(&mut counts);
                let first_b = b.first(&mut counts);
                let ordering = first_a.cmp(&first_b);
                if let (Part::Node(a), Part::Node(b)) = (a, b)
                    && a.last_key() == b.last_key()
                    && first_a == first_b
                {
                    counts.recover(a.level());
                }
                match ordering {
                    Ordering::Less => match a {
                        Part::Node(_) => expand(&mut left, &mut counts),
                        Part::Item(item) => {
                            left.pop();
                            self.changed(Some(item), None, &context, &mut counts, streams)?;
                        }
                    },
                    Ordering::Greater => match b {
                        Part::Node(_) => expand(&mut right, &mut counts),
                        Part::Item(item) => {
                            right.pop();
                            self.changed(None, Some(item), &context, &mut counts, streams)?;
                        }
                    },
                    Ordering::Equal => match (a, b) {
                        (Part::Node(_), Part::Node(_)) => {
                            expand(&mut left, &mut counts);
                            expand(&mut right, &mut counts);
                        }
                        (Part::Node(_), _) => expand(&mut left, &mut counts),
                        (_, Part::Node(_)) => expand(&mut right, &mut counts),
                        (Part::Item(a), Part::Item(b)) => {
                            left.pop();
                            right.pop();
                            counts.charge(0, PhysicalEventKind::Comparison, 1);
                            if a.entry != b.entry {
                                self.changed(Some(a), Some(b), &context, &mut counts, streams)?;
                            }
                        }
                    },
                }
            }
            while let Some(item) = next(&mut left, &mut counts) {
                self.changed(Some(item), None, &context, &mut counts, streams)?;
            }
            while let Some(item) = next(&mut right, &mut counts) {
                self.changed(None, Some(item), &context, &mut counts, streams)?;
            }
            for level in 0..=levels.0.max(levels.1) {
                let _ = counts.owner(level);
            }
        }
        context.ordinary = counts.ordinary;
        context.node_reads = counts.node_reads;
        context.skipped = counts.skipped;
        streams.push(context);
        Ok(())
    }
}

/// Predicts all reached paired occurrences from independent immutable inputs.
///
/// Repeated graft targets remain distinct streams through their exact hops.
/// Separate calls may use different genuine previous roots; no previous context
/// is inferred from the new root or from a reported stream.
///
/// # Errors
/// Preserves input decoding/reconstruction failures and rejects whole graft
/// additions/removals unsupported by this population fixture.
/// # Panics
/// Panics if fixture property names differ or a level has two active regions.
pub(super) fn expected(
    old: &Model,
    old_root: Digest,
    new: &Model,
    new_root: Digest,
) -> TestResult<Vec<ExpectedStream>> {
    let mut streams = Vec::new();
    Inputs { old, new }.pair(old_root, new_root, Vec::new(), Vec::new(), &mut streams)?;
    Ok(streams)
}

/// Checks fieldwise ordinary costs and exact independently reached occurrences.
///
/// # Panics
/// Panics for unmatched or duplicate occurrence descriptors, incorrect ordinary
/// event-field totals, or physical Node reads and equal skips that differ from
/// the immutable-input oracle.
pub(super) fn assert_streams(actual: &[StreamWork], expected: &[ExpectedStream]) {
    assert_eq!(
        actual.len(),
        expected.len(),
        "exact independently reached occurrence count"
    );
    let mut matched = vec![false; expected.len()];
    for stream in actual {
        let positions = expected
            .iter()
            .enumerate()
            .filter(|(_, predicted)| {
                stream.old_root == Some(predicted.old_root)
                    && stream.new_root == Some(predicted.new_root)
                    && stream.old_hops.as_ref() == Some(&predicted.old_hops)
                    && stream.new_hops.as_ref() == Some(&predicted.new_hops)
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        assert_eq!(positions.len(), 1, "exact immutable occurrence descriptor");
        let index = positions[0];
        assert!(!matched[index], "duplicate immutable occurrence stream");
        matched[index] = true;
        let mut ordinary = DiscoveryWork::default();
        let mut node_reads = 0;
        let mut skipped = 0;
        for event in &stream.events {
            if event.boundary.is_none() {
                add(&mut ordinary, event.kind, event.amount);
            }
            match event.kind {
                PhysicalEventKind::NodeRead => node_reads += event.amount,
                PhysicalEventKind::SkippedSubtree => skipped += event.amount,
                _ => {}
            }
        }
        assert_eq!(
            ordinary, expected[index].ordinary,
            "independent fieldwise ordinary traversal for exact occurrence"
        );
        assert_eq!(
            node_reads, expected[index].node_reads,
            "independent physical Node opens for exact occurrence"
        );
        assert_eq!(
            skipped, expected[index].skipped,
            "independent equal immutable skips for exact occurrence"
        );
    }
    assert!(
        matched.into_iter().all(|present| present),
        "every independently reached occurrence is represented"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use terrane_format::indexing::incremental::PhysicalEvent;

    fn stream(key: &[u8], kind: PhysicalEventKind) -> (ExpectedStream, StreamWork) {
        let hops = vec![Hop {
            source: [0x11; 32],
            key: key.to_vec(),
        }];
        let mut work = DiscoveryWork::default();
        add(&mut work, kind, 1);
        let expected = ExpectedStream {
            old_root: [0x22; 32],
            new_root: [0x33; 32],
            old_hops: hops.clone(),
            new_hops: hops.clone(),
            ordinary: work,
            node_reads: usize::from(kind == PhysicalEventKind::NodeRead),
            skipped: usize::from(kind == PhysicalEventKind::SkippedSubtree),
        };
        let actual = StreamWork {
            old_root: Some(expected.old_root),
            new_root: Some(expected.new_root),
            old_hops: Some(hops.clone()),
            new_hops: Some(hops),
            events: vec![PhysicalEvent {
                level: 0,
                kind,
                amount: 1,
                boundary: None,
            }],
            work,
        };
        (expected, actual)
    }

    #[test]
    fn repeated_targets_with_distinct_hops_match_independently_of_order() {
        let (first, first_actual) = stream(b"first", PhysicalEventKind::ItemRead);
        let (second, second_actual) = stream(b"second", PhysicalEventKind::Comparison);

        assert_streams(&[second_actual, first_actual], &[first, second]);
    }

    #[test]
    fn swapping_ordinary_costs_between_occurrences_is_rejected() {
        let (first, mut first_actual) = stream(b"first", PhysicalEventKind::ItemRead);
        let (second, mut second_actual) = stream(b"second", PhysicalEventKind::Comparison);
        // All aggregate field totals remain identical, but their exact
        // occurrence ownership is no longer justified by immutable inputs.
        std::mem::swap(&mut first_actual.events, &mut second_actual.events);
        std::mem::swap(&mut first_actual.work, &mut second_actual.work);

        let result = std::panic::catch_unwind(|| {
            assert_streams(&[first_actual, second_actual], &[first, second]);
        });

        assert!(result.is_err());
    }

    #[test]
    fn duplicate_occurrence_cannot_replace_an_equal_cost_sibling() {
        let (first, first_actual) = stream(b"first", PhysicalEventKind::ItemRead);
        let (second, _) = stream(b"second", PhysicalEventKind::ItemRead);

        let result = std::panic::catch_unwind(|| {
            assert_streams(&[first_actual.clone(), first_actual], &[first, second]);
        });

        assert!(result.is_err());
    }

    #[test]
    fn distinct_previous_root_contexts_are_not_conflated() {
        let (first, first_actual) = stream(b"shared", PhysicalEventKind::SkippedSubtree);
        let (mut second, mut second_actual) = stream(b"shared", PhysicalEventKind::SkippedSubtree);
        second.old_root = [0x44; 32];
        second.old_hops[0].source = [0x55; 32];
        second_actual.old_root = Some(second.old_root);
        second_actual.old_hops = Some(second.old_hops.clone());

        assert_streams(
            &[second_actual.clone(), first_actual.clone()],
            &[second.clone(), first.clone()],
        );
        // New-root equality cannot justify substituting a different old context.
        second_actual.old_root = first_actual.old_root;
        second_actual.old_hops = first_actual.old_hops.clone();
        let result = std::panic::catch_unwind(|| {
            assert_streams(&[second_actual, first_actual], &[second, first]);
        });

        assert!(result.is_err());
    }

    #[test]
    fn boundary_owned_node_opens_are_checked_for_the_exact_occurrence() {
        let (mut expected, mut actual) = stream(b"shared", PhysicalEventKind::NodeRead);
        expected.ordinary = DiscoveryWork::default();
        actual.events[0].boundary = Some(0);
        assert_streams(
            std::slice::from_ref(&actual),
            std::slice::from_ref(&expected),
        );
        actual.events[0].amount += 1;

        let result = std::panic::catch_unwind(|| {
            assert_streams(&[actual], &[expected]);
        });

        assert!(result.is_err());
    }
}
