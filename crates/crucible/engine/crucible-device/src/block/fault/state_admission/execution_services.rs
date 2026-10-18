//! Read-only classification of actual modeled storage dispatch ownership.

use super::*;

/// Separates unresolved storage work from registered future modeled dispatch.
///
/// This summary grants no execution authority. Its enclosing owner must retain
/// the complete canonical state and prevent every mutation until release.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlockExecutionServiceSummary {
    /// Counts unresolved, unregistered, or currently runnable operations.
    pub pending_work: u64,
    /// Counts actual operations with registered future dispatch ownership.
    pub queued_events: u64,
    /// Bounds the earliest registered modeled dispatch; zero is not absence.
    pub input_deadline: Option<u64>,
}

impl BlockExecutionServiceSummary {
    fn register(&mut self, deadline: Option<u64>, now_tick: u64) -> Result<(), DeviceError> {
        if let Some(deadline) = deadline.filter(|deadline| *deadline > now_tick) {
            self.queued_events = self
                .queued_events
                .checked_add(1)
                .ok_or_else(accounting_error)?;
            self.input_deadline = Some(
                self.input_deadline
                    .map_or(deadline, |prior| prior.min(deadline)),
            );
        } else {
            self.pending_work = self
                .pending_work
                .checked_add(1)
                .ok_or_else(accounting_error)?;
        }
        Ok(())
    }
}

fn accounting_error() -> DeviceError {
    DeviceError::InvalidBlockFaultDirective {
        reason: "execution service event accounting overflow",
    }
}

impl BlockFaultState {
    /// Classifies every retained dispatch phase at the supplied logical tick.
    ///
    /// Immutable cache/controller history is state, not runnable work. Each live
    /// phase is examined directly; a single earliest event cannot certify other
    /// unregistered work. Due events must settle before a grant is admitted.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] if exact event counts overflow.
    pub fn execution_service_summary(
        &self,
        now_tick: u64,
    ) -> Result<BlockExecutionServiceSummary, DeviceError> {
        let mut summary = BlockExecutionServiceSummary::default();
        for _ in self.pending.values() {
            summary.register(None, now_tick)?;
        }
        let live_service_jobs = self
            .service
            .live_job_keys()
            .into_iter()
            .collect::<BTreeSet<_>>();
        let mut expected_service_jobs = BTreeSet::new();
        for (sequence, pending) in &self.service_pending {
            expected_service_jobs.extend(
                pending
                    .remaining_contributors
                    .iter()
                    .map(|contributor| (*contributor, *sequence)),
            );
            let registered = !pending.remaining_contributors.is_empty()
                && pending
                    .remaining_contributors
                    .iter()
                    .all(|contributor| live_service_jobs.contains(&(*contributor, *sequence)));
            summary.register(
                registered
                    .then(|| self.service.next_completion_ticks())
                    .flatten(),
                now_tick,
            )?;
        }
        for _ in live_service_jobs.difference(&expected_service_jobs) {
            summary.register(None, now_tick)?;
        }
        for pending in self.execution_pending.values() {
            summary.register(Some(pending.opportunity.ready_ticks), now_tick)?;
        }
        for pending in self.request_persistence_pending.values() {
            summary.register(Some(pending.opportunity.ready_ticks), now_tick)?;
        }
        let persistence_deadline = self.next_persistence_deadline_ticks();
        for pending in self.delivery_pending.values() {
            let deadline = if pending
                .opportunity
                .required_durable_frontier
                .is_none_or(|frontier| self.actual_durable_frontier >= frontier)
            {
                Some(pending.opportunity.ready_ticks)
            } else {
                persistence_deadline
            };
            summary.register(deadline, now_tick)?;
        }
        for sequence in self.media_queue.keys() {
            let deadline = self
                .persistence
                .is_ready_at(*sequence, u64::MAX)
                .then(|| self.persistence.deadline_ticks(*sequence))
                .flatten();
            summary.register(deadline, now_tick)?;
        }
        for directive in self.pending_persistence_media.values() {
            summary.register(Some(directive.opportunity.ready_ticks), now_tick)?;
        }
        for completion in self.retained_completions.values() {
            summary.register(Some(completion.timeout_ticks), now_tick)?;
        }
        if let Some(deadline) = self.array_rebuild.next_ready_ticks {
            let cursor = self.array_rebuild;
            let registered = cursor
                .scheduled_member
                .zip(cursor.scheduled_start_byte)
                .zip(cursor.scheduled_generation)
                .is_some_and(|((member, start), generation)| {
                    self.array_dirty_ranges
                        .get(&(member, start))
                        .is_some_and(|range| range.generation == generation)
                });
            summary.register(registered.then_some(deadline), now_tick)?;
        }
        Ok(summary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_request_job_cannot_borrow_a_contributors_unrelated_future_deadline() {
        let mut state = BlockFaultState::write_through(4096);
        let contributor = [7; 32];
        let rule = ResolvedBlockServiceRule {
            contributor,
            bytes_per_second: 512,
            iops: None,
            queue_depth: 4,
            discipline: crate::block::service::BlockServiceDiscipline::Fifo,
            classes: Vec::new(),
            rebuild_shares_service: false,
        };
        state
            .service
            .admit(
                BlockServiceJob {
                    sequence: 1,
                    operation: crate::block::BlockOp::Read,
                    bytes: 512,
                    admitted_ticks: 0,
                },
                &[rule],
            )
            .unwrap_or_else(|error| panic!("actual fixture operation failed: {error:?}"));
        let request = BlockRequest::read(7, 0, 512);
        let mut directive = ResolvedBlockFaultDirective::fault_free(&request, 4096);
        directive.request_sequence = 9;
        state.service_pending.insert(
            9,
            BlockServicePendingRequest {
                request,
                request_icount: 0,
                directive,
                remaining_contributors: BTreeSet::from([contributor]),
                finished_ticks: 0,
            },
        );

        assert!(state.service.continuations().contains_key(&contributor));
        assert!(
            state
                .service
                .next_completion_ticks()
                .is_some_and(|deadline| deadline > 0)
        );
        let missing = state
            .execution_service_summary(0)
            .unwrap_or_else(|error| panic!("actual fixture operation failed: {error:?}"));
        assert_eq!(missing.pending_work, 2);
        assert_eq!(missing.queued_events, 0);
        assert_eq!(missing.input_deadline, None);

        let mut pending = state
            .service_pending
            .remove(&9)
            .unwrap_or_else(|| panic!("required actual fixture entry is missing"));
        pending.directive.request_sequence = 1;
        state.service_pending.insert(1, pending);
        let registered = state
            .execution_service_summary(0)
            .unwrap_or_else(|error| panic!("actual fixture operation failed: {error:?}"));
        assert_eq!(registered.pending_work, 0);
        assert_eq!(registered.queued_events, 1);
        assert_eq!(
            registered.input_deadline,
            state.service.next_completion_ticks()
        );
    }

    #[test]
    fn unknown_and_due_items_cannot_hide_behind_another_future_event() {
        let mut summary = BlockExecutionServiceSummary::default();
        summary
            .register(Some(80), 20)
            .unwrap_or_else(|error| panic!("actual fixture operation failed: {error:?}"));
        summary
            .register(None, 20)
            .unwrap_or_else(|error| panic!("actual fixture operation failed: {error:?}"));
        summary
            .register(Some(20), 20)
            .unwrap_or_else(|error| panic!("actual fixture operation failed: {error:?}"));
        summary
            .register(Some(0), 20)
            .unwrap_or_else(|error| panic!("actual fixture operation failed: {error:?}"));
        assert_eq!(summary.pending_work, 3);
        assert_eq!(summary.queued_events, 1);
        assert_eq!(summary.input_deadline, Some(80));
    }

    #[test]
    fn actual_rebuild_registration_binds_payload_generation_and_due_coordinate() {
        let mut state = BlockFaultState::write_through(4096);
        state.array_rebuild.next_ready_ticks = Some(90);
        assert_eq!(
            state
                .execution_service_summary(20)
                .unwrap_or_else(|error| panic!("actual fixture operation failed: {error:?}"))
                .pending_work,
            1
        );

        state.array_dirty_ranges.insert(
            (1, 512),
            BlockArrayDirtyRange {
                member_ordinal: 1,
                start_byte: 512,
                bytes: vec![7; 512],
                generation: 4,
                dirty_ticks: 10,
            },
        );
        state.array_rebuild.scheduled_member = Some(1);
        state.array_rebuild.scheduled_start_byte = Some(512);
        state.array_rebuild.scheduled_generation = Some(4);
        let future = state
            .execution_service_summary(20)
            .unwrap_or_else(|error| panic!("actual fixture operation failed: {error:?}"));
        assert_eq!(future.pending_work, 0);
        assert_eq!(future.queued_events, 1);
        assert_eq!(future.input_deadline, Some(90));
        assert_eq!(
            state
                .execution_service_summary(90)
                .unwrap_or_else(|error| panic!("actual fixture operation failed: {error:?}"))
                .pending_work,
            1
        );

        state.array_rebuild.scheduled_generation = Some(3);
        assert_eq!(
            state
                .execution_service_summary(20)
                .unwrap_or_else(|error| panic!("actual fixture operation failed: {error:?}"))
                .pending_work,
            1
        );
    }
}
