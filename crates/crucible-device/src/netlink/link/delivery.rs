//! Network-link delivery, in-flight draining, snapshot, and restore operations.

use super::*;

impl NetLink {
    /// Advances the clock to `limit` and returns every delivery due by then.
    ///
    /// Drains exactly the in-flight frames whose `delivery_icount <= limit`, in
    /// deterministic `(delivery_icount, src_node, seq)` order. The clock advances
    /// to `limit` (never backward).
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::ClockRegression`] when `limit` is below the current
    /// icount.
    pub fn advance_to(&mut self, limit: u64) -> Result<Vec<Delivery>, DeviceError> {
        self.clock.advance_to(limit)?;
        let due = self.inflight.drain_due(limit);
        Ok(due.into_iter().map(Self::pending_to_delivery).collect())
    }

    /// Pops the earliest in-flight frame whose delivery is at or before `limit`.
    ///
    /// A streaming alternative to [`NetLink::advance_to`] that returns one
    /// delivery at a time without advancing the clock. Returns `None` when the
    /// head is past `limit` or the queue is empty.
    pub fn next_delivery(&mut self, limit: u64) -> Option<Delivery> {
        match self.inflight.next_exact_local_event() {
            Some(head) if head <= limit => {
                let mut due = self.inflight.drain_due(head);
                // `drain_due(head)` may return several coincident frames; re-queue
                // all but the first so callers see exactly one per call.
                if due.is_empty() {
                    return None;
                }
                let first = due.remove(0);
                for pending in due {
                    self.inflight.insert(pending);
                }
                Some(Self::pending_to_delivery(first))
            }
            _ => None,
        }
    }

    /// Removes every resolved frame that has not yet reached the receiver.
    ///
    /// The returned deliveries retain their exact scheduled keys and payloads
    /// so the owning adapter can record complete transition evidence. This is
    /// an explicit modeled link-state transition; ordinary delivery continues
    /// to use [`Self::advance_to`] or [`Self::next_delivery`].
    pub fn drop_inflight(&mut self) -> Vec<Delivery> {
        self.inflight
            .drain_all()
            .into_iter()
            .map(Self::pending_to_delivery)
            .collect()
    }

    /// Converts a reused [`PendingResponse`] back into a [`Delivery`].
    pub(super) fn pending_to_delivery(pending: PendingResponse) -> Delivery {
        Delivery {
            key: pending.key,
            frame_id: pending.response.request_id,
            payload: pending.response.payload,
        }
    }

    /// Captures the link's deterministic state for snapshot/restore ([IO-23]).
    ///
    /// Holds the clock cursor, the base latency, floor, fault table, sequence
    /// counter, the pending-recompute flag, the RNG cursor, and the
    /// in-flight deliveries with their exact icounts. Restoring via
    /// [`NetLink::restore`] reproduces a byte-identical state.
    #[must_use]
    pub fn snapshot(&self) -> LinkSnapshot {
        LinkSnapshot {
            current_icount: self.clock.current_icount(),
            shift_bits: self.clock.shift_bits(),
            src_node: self.src_node,
            base_latency_ns: self.base_latency_ns,
            floor_ns: self.floor_ns,
            faults: self.faults.clone(),
            next_seq: self.next_seq,
            lookahead_recompute_pending: self.lookahead_recompute_pending,
            rng_position: self.rng_position,
            inflight: self.inflight.entries().to_vec(),
        }
    }

    /// Reconstructs a link from a captured snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::Clock`] when the snapshot's shift is invalid, and
    /// [`DeviceError::LinkLatencyBelowFloor`] when the captured base latency is
    /// below the captured floor (a corrupt snapshot).
    pub fn restore(snapshot: &LinkSnapshot) -> Result<Self, DeviceError> {
        if snapshot.floor_ns == 0 || snapshot.base_latency_ns < snapshot.floor_ns {
            return Err(DeviceError::LinkLatencyBelowFloor {
                base_latency_ns: snapshot.base_latency_ns,
                floor_ns: snapshot.floor_ns,
            });
        }
        let mut clock = VirtualClock::new(snapshot.shift_bits)?;
        clock.advance_to(snapshot.current_icount)?;
        let mut inflight = InflightQueue::new();
        for pending in &snapshot.inflight {
            inflight.insert(pending.clone());
        }
        Ok(Self {
            clock,
            inflight,
            src_node: snapshot.src_node,
            base_latency_ns: snapshot.base_latency_ns,
            floor_ns: snapshot.floor_ns,
            faults: snapshot.faults.clone(),
            next_seq: snapshot.next_seq,
            lookahead_recompute_pending: snapshot.lookahead_recompute_pending,
            rng_position: snapshot.rng_position,
        })
    }
}
