//! The in-flight response queue ordered by `delivery_icount`.
//!
//! A sub-node holds the responses it has *computed* (payload and
//! `delivery_icount` fixed) but not yet *delivered* (the consumer clock has not
//! reached `delivery_icount`). This module owns [`InflightQueue`], which keeps
//! those [`PendingResponse`]s ordered so that:
//!
//! - the head's `delivery_icount` is the sub-node's `next_exact_local_event`
//!   ([IO-31]) — what the scheduler reads to bound the requester's horizon;
//! - draining at a limit emits exactly the responses whose
//!   `delivery_icount <= limit`, in the deterministic total order
//!   `(delivery_icount, src_node, seq)` ([IO-10], [SHM-34]).
//!
//! The order key reuses [`crucible_shmem::FrameDeliveryKey`] so a sub-node and
//! the shmem transport agree byte-for-byte on coincident-delivery tie-breaking.

use crucible_shmem::FrameDeliveryKey;

use crate::request::Response;

/// A response computed-but-not-yet-delivered, tagged with its exact delivery.
///
/// `key` carries the deterministic `(delivery_icount, src_node, seq)` order
/// position; `response` is the COMPUTEd payload whose visibility is gated until
/// the consumer reaches `key.delivery_icount`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingResponse {
    /// The deterministic delivery-order key (icount + source + sequence).
    pub key: FrameDeliveryKey,
    /// The COMPUTEd response whose visibility is gated on `key.delivery_icount`.
    pub response: Response,
}

impl PendingResponse {
    /// Creates a pending response from its delivery key and COMPUTEd payload.
    #[must_use]
    pub fn new(key: FrameDeliveryKey, response: Response) -> Self {
        Self { key, response }
    }

    /// Creates a pending response from explicit canonical delivery-key fields.
    #[must_use]
    pub fn from_parts(
        delivery_icount: u64,
        src_node: u32,
        sequence: u32,
        response: Response,
    ) -> Self {
        Self::new(
            FrameDeliveryKey {
                delivery_icount,
                src_node,
                seq: sequence,
            },
            response,
        )
    }

    /// Returns the exact icount at which this response becomes visible.
    #[must_use]
    pub fn delivery_icount(&self) -> u64 {
        self.key.delivery_icount
    }
}

/// An ordered queue of in-flight responses keyed by delivery position.
///
/// Entries are kept sorted by [`FrameDeliveryKey`] (`delivery_icount`, then
/// `src_node`, then `seq`) so the head is always the next event and draining is
/// a prefix scan. The queue never reorders or re-times an entry: a late-arriving
/// computation with an earlier `delivery_icount` is inserted at its correct
/// position, preserving the global delivery order ([IO-32]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InflightQueue {
    /// Entries sorted ascending by [`FrameDeliveryKey`]. Kept private so the
    /// sort invariant cannot be broken from outside.
    entries: Vec<PendingResponse>,
}

impl InflightQueue {
    /// Creates an empty in-flight queue.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Returns the number of in-flight responses.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when no responses are in flight.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Inserts a pending response, preserving the delivery-order invariant.
    ///
    /// The entry is placed at the position dictated by its [`FrameDeliveryKey`],
    /// so the queue stays sorted even when responses are COMPUTEd out of
    /// delivery order. Equal keys preserve insertion order (a stable position
    /// just after any existing equal key), though distinct frames never share a
    /// key in practice.
    pub fn insert(&mut self, pending: PendingResponse) {
        let pos = self
            .entries
            .partition_point(|existing| existing.key <= pending.key);
        self.entries.insert(pos, pending);
    }

    /// Returns the head's `delivery_icount`: the sub-node's next exact event.
    ///
    /// This is what the scheduler reads to bound the requester's horizon
    /// ([IO-3], [IO-31]). Returns `None` when nothing is in flight.
    #[must_use]
    pub fn next_exact_local_event(&self) -> Option<u64> {
        self.entries.first().map(PendingResponse::delivery_icount)
    }

    /// Returns a read-only view of the queued entries in delivery order.
    #[must_use]
    pub fn entries(&self) -> &[PendingResponse] {
        &self.entries
    }

    /// Removes and returns every response with `delivery_icount <= limit`.
    ///
    /// Returned responses are in deterministic delivery order
    /// (`delivery_icount`, `src_node`, `seq`). Responses whose delivery is still
    /// in the future are retained. This is the DELIVER step of the lifecycle:
    /// the consumer clock has reached `limit`, so every due response is made
    /// visible at exactly its delivery icount.
    pub fn drain_due(&mut self, limit_icount: u64) -> Vec<PendingResponse> {
        let split = self
            .entries
            .partition_point(|entry| entry.delivery_icount() <= limit_icount);
        // The future tail stays in `self.entries`; the due prefix is returned.
        let future = self.entries.split_off(split);
        core::mem::replace(&mut self.entries, future)
    }

    /// Removes and returns every in-flight response in delivery order.
    ///
    /// Crash fault handling uses this to void a target node's computed-but-not-
    /// delivered responses while recording the deterministic discard set.
    pub fn drain_all(&mut self) -> Vec<PendingResponse> {
        core::mem::take(&mut self.entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::ResponseStatus;

    fn pending(delivery_icount: u64, src_node: u32, seq: u32) -> PendingResponse {
        PendingResponse::new(
            FrameDeliveryKey {
                delivery_icount,
                src_node,
                seq,
            },
            Response::new(seq, ResponseStatus::Ok, Vec::new()),
        )
    }

    #[test]
    fn insert_keeps_delivery_order_regardless_of_compute_order() {
        let mut queue = InflightQueue::new();
        queue.insert(pending(30, 1, 0));
        queue.insert(pending(10, 1, 0));
        queue.insert(pending(20, 1, 0));
        let order: Vec<u64> = queue
            .entries()
            .iter()
            .map(|e| e.delivery_icount())
            .collect();
        assert_eq!(order, vec![10, 20, 30]);
        assert_eq!(queue.next_exact_local_event(), Some(10));
    }

    #[test]
    fn coincident_deliveries_break_ties_by_src_then_seq() {
        let mut queue = InflightQueue::new();
        queue.insert(pending(10, 2, 0));
        queue.insert(pending(10, 1, 1));
        queue.insert(pending(10, 1, 0));
        let keys: Vec<(u32, u32)> = queue
            .entries()
            .iter()
            .map(|e| (e.key.src_node, e.key.seq))
            .collect();
        assert_eq!(keys, vec![(1, 0), (1, 1), (2, 0)]);
    }

    #[test]
    fn drain_due_emits_only_due_in_order_and_retains_future() {
        let mut queue = InflightQueue::new();
        queue.insert(pending(10, 1, 0));
        queue.insert(pending(20, 1, 1));
        queue.insert(pending(30, 1, 2));

        let due = queue.drain_due(20);
        let due_icounts: Vec<u64> = due.iter().map(|e| e.delivery_icount()).collect();
        assert_eq!(due_icounts, vec![10, 20]);
        assert_eq!(queue.next_exact_local_event(), Some(30));
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn drain_due_below_head_emits_nothing() {
        let mut queue = InflightQueue::new();
        queue.insert(pending(50, 1, 0));
        let due = queue.drain_due(49);
        assert!(due.is_empty());
        assert_eq!(queue.len(), 1);
    }
}
