//! Node publications bound to the scheduler advance they answer.
//!
//! The plugin answers an advance that ends at its own coordinate with a
//! publication that retires nothing and keeps an idle boundary there. Such an
//! answer leaves every field but `publish_gen` as it was, so a host that has
//! since published a newer advance would read it as that advance's report.
//! The writer here checks, inside the open node publication, that the live
//! advance is still the one the caller answers. When the host has replaced
//! it, the writer rolls `publish_gen` back to the even value it opened from
//! and writes nothing:
//!
//! ```text
//! writer (plugin)                         host
//! gen N -> N+1 (odd)          (SeqCst)    store advance S'   (release)
//! load advance               (SeqCst)
//!   == S : store fields, gen N+1 -> N+2, signal waiters
//!   != S : gen N+1 -> N, no field written, no signal
//! ```
//!
//! A reader never returns a snapshot while `publish_gen` is odd, and a
//! rolled-back publication changed no field, so a coherent reader either
//! retries or observes the unchanged slot at generation N. Generations a
//! reader returns therefore never decrease.
//!
//! The check narrows, but does not close, the race against a host advance
//! published after the check: such an answer still lands. The plugin's own
//! claim of an advance already answered at a control boundary is what keeps
//! a stale answer from being made at all.

use super::*;

impl NodeSlot {
    /// Republishes the reached icount without demoting an idle boundary there,
    /// only while `advance_sequence` is still the published advance.
    ///
    /// Returns `false` and leaves the slot unchanged, at its previous
    /// publication generation, when the host has published a different
    /// advance. Otherwise this publishes as
    /// [`Self::publish_reached_icount_retaining_idle`] does and returns `true`.
    ///
    /// # Errors
    ///
    /// Returns [`NodeSlotError`] when the reached icount exceeds the published
    /// ceiling.
    pub fn publish_reached_icount_retaining_idle_for_advance(
        &self,
        reached_icount: u64,
        advance_sequence: u64,
    ) -> Result<bool, NodeSlotError> {
        self.check_node_may_advance_to(reached_icount)?;
        let current_ns = icount_to_virtual_ns(reached_icount);
        let idle_here = self.status.load(Ordering::Acquire) == STATUS_IDLE
            && self.current_icount.load(Ordering::Acquire) == reached_icount;
        let status = if idle_here {
            STATUS_IDLE
        } else {
            STATUS_RUNNING
        };

        // Sequentially consistent on both the open and the advance load, so
        // either this load sees the host's newer advance or the host's later
        // coherent read waits for this publication to close.
        let opened = self.publish_gen.fetch_add(1, Ordering::SeqCst);
        if self.advance_publication_sequence.load(Ordering::SeqCst) != advance_sequence {
            // Only the plugin writes node publications, one at a time, so the
            // odd value is still ours. Restoring the even value it opened
            // from publishes nothing.
            self.publish_gen.store(opened, Ordering::Release);
            return Ok(false);
        }
        self.current_icount.store(reached_icount, Ordering::Release);
        self.current_ns.store(current_ns, Ordering::Release);
        self.status.store(status, Ordering::Release);
        self.close_node_publication();
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::thread;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A slot left idle at its own coordinate 50 under advance `sequence`.
    fn marker_slot() -> Result<(NodeSlot, u64), Box<dyn std::error::Error>> {
        let slot = NodeSlot::new(KIND_VM);
        slot.publish_scheduler_advance(
            authorize_advance_ceiling(0, 50, None)?,
            AdvanceStopCondition::Ceiling,
        )?;
        slot.publish_reached_icount(50)?;
        let _wait = slot.publish_idle(50, 50)?;
        let sequence = slot.snapshot().advance_publication_sequence;
        Ok((slot, sequence))
    }

    #[test]
    fn an_answer_to_the_live_advance_keeps_the_idle_marker() -> TestResult {
        let (slot, sequence) = marker_slot()?;
        let before = slot.snapshot();

        assert!(slot.publish_reached_icount_retaining_idle_for_advance(50, sequence)?);

        let after = slot.snapshot();
        assert_eq!(after.publish_gen, before.publish_gen + 2);
        assert_eq!(after.status, STATUS_IDLE);
        assert_eq!(after.idle_wake_icount, 50);
        Ok(())
    }

    #[test]
    fn an_answer_to_a_replaced_advance_publishes_nothing() -> TestResult {
        let (slot, sequence) = marker_slot()?;
        slot.publish_scheduler_advance(
            authorize_advance_ceiling(50, 200, None)?,
            AdvanceStopCondition::Ceiling,
        )?;
        let before = slot.snapshot();
        let signal = slot.host_publication_signal.load(Ordering::SeqCst);

        assert!(!slot.publish_reached_icount_retaining_idle_for_advance(50, sequence)?);

        assert_eq!(slot.snapshot(), before);
        assert_eq!(slot.host_publication_signal.load(Ordering::SeqCst), signal);
        Ok(())
    }

    #[test]
    fn readers_racing_rolled_back_answers_never_see_a_generation_go_backwards() -> TestResult {
        let (slot, sequence) = marker_slot()?;
        slot.publish_scheduler_advance(
            authorize_advance_ceiling(50, 200, None)?,
            AdvanceStopCondition::Ceiling,
        )?;
        let live = slot.snapshot().advance_publication_sequence;
        let slot = Arc::new(slot);
        let done = Arc::new(AtomicBool::new(false));

        let reader = {
            let slot = Arc::clone(&slot);
            let done = Arc::clone(&done);
            thread::spawn(move || -> Result<u64, String> {
                let mut last: Option<NodeSlotSnapshot> = None;
                let mut observed = 0_u64;
                while !done.load(Ordering::Acquire) {
                    let Some(snapshot) = slot.try_snapshot() else {
                        continue;
                    };
                    if snapshot.publish_gen % 2 != 0 {
                        return Err(format!("odd generation {}", snapshot.publish_gen));
                    }
                    if let Some(previous) = &last {
                        if snapshot.publish_gen < previous.publish_gen {
                            return Err(format!(
                                "generation went back from {} to {}",
                                previous.publish_gen, snapshot.publish_gen
                            ));
                        }
                        // An unchanged generation is an unchanged slot.
                        if snapshot.publish_gen == previous.publish_gen && snapshot != *previous {
                            return Err(format!(
                                "generation {} names two slot states",
                                snapshot.publish_gen
                            ));
                        }
                    }
                    last = Some(snapshot);
                    observed += 1;
                }
                Ok(observed)
            })
        };

        // Stale answers roll back; every 64th answer is to the live advance
        // and really publishes, so the reader sees generations move on too.
        for round in 0..200_000_u32 {
            let answered = if round % 64 == 63 { live } else { sequence };
            let published = slot.publish_reached_icount_retaining_idle_for_advance(50, answered)?;
            assert_eq!(published, answered == live);
        }
        done.store(true, Ordering::Release);

        let observed = reader.join().map_err(|_| "reader panicked")??;
        assert!(observed > 0);
        Ok(())
    }
}
