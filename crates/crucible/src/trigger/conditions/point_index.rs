//! Observable facts indexed by the condition prefix's latest virtual time.
//!
//! Condition leaves are true at an evaluation point when a matching event
//! occurred exactly at that point's virtual time, and a coverage leaf further
//! requires that its block was not covered earlier. Scanning the whole
//! observable history for those facts made every evaluation proportional to
//! the attempt length.
//!
//! The index keeps the events at the latest time the prefix reached plus one
//! fold of earlier coverage. Every entry in a checked prefix is at or before
//! its final entry's time, so once the prefix first reaches time `T`, every
//! later event at `T` arrives after that moment; the events at `T` are
//! therefore exactly those appended since the latest time last advanced
//! (RFC-0020 section 15.4).
//!
//! A query for an earlier time than the indexed one returns `None`. Only
//! rewound evaluation points ask such questions, and they fall back to the
//! retained history.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::*;

/// Events at the latest time and coverage folded from earlier times.
///
/// Both parts are shared, so cloning a prefix copies only two pointers;
/// appends copy a part only when another prefix still shares it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PointObservationIndex {
    at: VirtualTime,
    events_at: Arc<Vec<ObservableEvent>>,
    coverage_before: Arc<CoverageBlocks>,
}

impl PointObservationIndex {
    /// Folds one checked batch whose final entry is at `latest`.
    ///
    /// `latest` never decreases across batches of a checked prefix, and every
    /// event in the batch is at or before it.
    pub(super) fn observe(&mut self, latest: VirtualTime, events: &[ObservableEvent]) {
        if latest > self.at {
            let retired = std::mem::take(Arc::make_mut(&mut self.events_at));
            self.retire_coverage(&retired);
            self.at = latest;
        }

        for event in events {
            if event.at() == self.at {
                Arc::make_mut(&mut self.events_at).push(event.clone());
            } else {
                self.retire_coverage(std::slice::from_ref(event));
            }
        }
    }

    /// Returns the events at virtual time `at`, when the index can answer.
    ///
    /// A time after the indexed one has no events yet. An earlier time is not
    /// indexed and returns `None`.
    pub(crate) fn events_at(&self, at: VirtualTime) -> Option<&[ObservableEvent]> {
        if at == self.at {
            Some(self.events_at.as_slice())
        } else if at > self.at {
            Some(&[])
        } else {
            None
        }
    }

    /// Reports whether a block covering `address` on `node` ran before `at`.
    ///
    /// An earlier time than the indexed one is not indexed and returns `None`.
    pub(crate) fn coverage_seen_before(
        &self,
        node: &NodeId,
        address: u64,
        at: VirtualTime,
    ) -> Option<bool> {
        if at < self.at {
            return None;
        }
        let earlier = self.coverage_before.contains(node, address);
        let at_indexed_time = at > self.at
            && self.events_at.iter().any(|event| {
                coverage_event_matches(
                    event.payload(),
                    node,
                    ResolvedCodePoint::guest_address(address),
                )
            });
        Some(earlier || at_indexed_time)
    }

    fn retire_coverage(&mut self, events: &[ObservableEvent]) {
        let blocks = events.iter().filter_map(|event| match event.payload() {
            ObservableEventPayload::CoverageBlock {
                node,
                guest_pc,
                block_len,
                ..
            } => Some((node, *guest_pc, *block_len)),
            _ => None,
        });
        let mut blocks = blocks.peekable();
        if blocks.peek().is_none() {
            return;
        }
        let coverage = Arc::make_mut(&mut self.coverage_before);
        for (node, guest_pc, block_len) in blocks {
            coverage.insert(node, guest_pc, block_len);
        }
    }
}

/// Returns the observable events at virtual time `at`.
///
/// The index answers for the latest time; a rewound time falls back to
/// filtering the retained history.
pub(crate) fn observable_events_at<'a>(
    index: &'a PointObservationIndex,
    history: &'a crate::History<ObservableEvent>,
    at: VirtualTime,
) -> Box<dyn Iterator<Item = &'a ObservableEvent> + 'a> {
    match index.events_at(at) {
        Some(events) => Box::new(events.iter()),
        None => Box::new(history.iter().filter(move |event| event.at() == at)),
    }
}

/// Reports whether a block covering `address` on `node` ran before `at`.
///
/// The index answers for the latest time; a rewound time falls back to
/// scanning the retained history.
pub(crate) fn coverage_seen_before(
    index: &PointObservationIndex,
    history: &crate::History<ObservableEvent>,
    node: &NodeId,
    address: u64,
    at: VirtualTime,
) -> bool {
    index
        .coverage_seen_before(node, address, at)
        .unwrap_or_else(|| {
            history.iter().any(|event| {
                event.at() < at
                    && coverage_event_matches(
                        event.payload(),
                        node,
                        ResolvedCodePoint::guest_address(address),
                    )
            })
        })
}

/// Distinct covered blocks per node, keyed by start address.
///
/// The fold is bounded by the number of distinct translated blocks, not by
/// how often they run. Each start keeps its longest observed length.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct CoverageBlocks {
    nodes: BTreeMap<NodeId, NodeCoverageBlocks>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct NodeCoverageBlocks {
    longest: u32,
    starts: BTreeMap<u64, u32>,
}

impl CoverageBlocks {
    fn insert(&mut self, node: &NodeId, guest_pc: u64, block_len: u32) {
        if block_len == 0 {
            return;
        }
        if !self.nodes.contains_key(node) {
            self.nodes
                .insert(node.clone(), NodeCoverageBlocks::default());
        }
        let Some(blocks) = self.nodes.get_mut(node) else {
            return;
        };
        blocks.longest = blocks.longest.max(block_len);
        let length = blocks.starts.entry(guest_pc).or_default();
        *length = (*length).max(block_len);
    }

    /// Reports whether any retained block contains `address`.
    ///
    /// Only starts within the longest block length below `address` can
    /// contain it, so the lookup reads a bounded range of starts.
    fn contains(&self, node: &NodeId, address: u64) -> bool {
        let Some(blocks) = self.nodes.get(node) else {
            return false;
        };
        let lowest = address.saturating_sub(u64::from(blocks.longest));
        blocks
            .starts
            .range(lowest..=address)
            .any(|(start, length)| block_contains_address(*start, *length, address))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str) -> NodeId {
        NodeId {
            name: name.to_owned(),
        }
    }

    fn coverage(at: u64, node_name: &str, guest_pc: u64, block_len: u32) -> ObservableEvent {
        ObservableEvent {
            at: VirtualTime { ticks: at },
            payload: ObservableEventPayload::CoverageBlock {
                execution_icount: Icount { retired: 0 },
                node: node(node_name),
                guest_pc,
                block_len,
            },
        }
    }

    #[test]
    fn events_at_follow_the_latest_time_across_batches() {
        let mut index = PointObservationIndex::default();
        index.observe(
            VirtualTime { ticks: 5 },
            &[coverage(3, "a", 0x10, 4), coverage(5, "a", 0x20, 4)],
        );
        index.observe(VirtualTime { ticks: 5 }, &[coverage(5, "a", 0x30, 4)]);

        let at_five = index.events_at(VirtualTime { ticks: 5 });
        assert_eq!(
            at_five,
            Some([coverage(5, "a", 0x20, 4), coverage(5, "a", 0x30, 4)].as_slice())
        );
        assert_eq!(index.events_at(VirtualTime { ticks: 6 }), Some(&[][..]));
        assert_eq!(index.events_at(VirtualTime { ticks: 4 }), None);

        index.observe(VirtualTime { ticks: 9 }, &[coverage(7, "a", 0x40, 4)]);
        assert_eq!(index.events_at(VirtualTime { ticks: 9 }), Some(&[][..]));
    }

    #[test]
    fn coverage_before_the_point_excludes_blocks_at_the_point() {
        let mut index = PointObservationIndex::default();
        index.observe(
            VirtualTime { ticks: 5 },
            &[coverage(3, "a", 0x10, 4), coverage(5, "a", 0x20, 4)],
        );

        let at = VirtualTime { ticks: 5 };
        assert_eq!(index.coverage_seen_before(&node("a"), 0x13, at), Some(true));
        assert_eq!(
            index.coverage_seen_before(&node("a"), 0x14, at),
            Some(false)
        );
        assert_eq!(
            index.coverage_seen_before(&node("a"), 0x21, at),
            Some(false)
        );
        assert_eq!(
            index.coverage_seen_before(&node("b"), 0x13, at),
            Some(false)
        );
        assert_eq!(
            index.coverage_seen_before(&node("a"), 0x21, VirtualTime { ticks: 6 }),
            Some(true)
        );
        assert_eq!(
            index.coverage_seen_before(&node("a"), 0x13, VirtualTime { ticks: 4 }),
            None
        );

        index.observe(VirtualTime { ticks: 8 }, &[]);
        assert_eq!(
            index.coverage_seen_before(&node("a"), 0x21, VirtualTime { ticks: 8 }),
            Some(true)
        );
    }
}
