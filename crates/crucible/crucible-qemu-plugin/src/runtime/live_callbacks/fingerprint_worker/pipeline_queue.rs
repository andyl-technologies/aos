//! Tracks two paid owning jobs independently from one pending queue position.
//!
//! Indices describe local placement only. Native serial-bearing receipts supply
//! actual ownership; this queue issues no Source, worker, workspace or time grant.
// SPDX-License-Identifier: GPL-2.0-only

pub(super) const WORK_CELLS: usize = 2;

#[derive(Debug)]
pub(super) struct PipelineQueue {
    pub(super) pending: Option<usize>,
    pub(super) active: Option<usize>,
    pub(super) submitting: Option<usize>,
    pub(super) taking: Option<usize>,
    completed: [Option<usize>; WORK_CELLS],
}

impl PipelineQueue {
    pub(super) const fn new() -> Self {
        Self {
            pending: None,
            active: None,
            submitting: None,
            taking: None,
            completed: [None; WORK_CELLS],
        }
    }

    pub(super) fn reserve(&mut self, index: usize) -> bool {
        if index >= WORK_CELLS
            || self.pending.is_some()
            || self.submitting.is_some()
            || self.taking.is_some()
            || self.active == Some(index)
            || self.completed.contains(&Some(index))
        {
            return false;
        }
        self.submitting = Some(index);
        true
    }

    pub(super) fn publish(&mut self, index: usize, born: bool) -> bool {
        if self.submitting != Some(index) || self.pending.is_some() {
            return false;
        }
        self.submitting = None;
        if born {
            self.pending = Some(index);
        }
        true
    }

    pub(super) fn take(&mut self) -> Option<usize> {
        if self.active.is_some() {
            return None;
        }
        let index = self.pending.take()?;
        self.active = Some(index);
        self.taking = Some(index);
        Some(index)
    }

    pub(super) fn taken(&mut self, index: usize) -> bool {
        if self.taking != Some(index) || self.active != Some(index) {
            return false;
        }
        self.taking = None;
        true
    }

    pub(super) fn complete(&mut self, index: usize) -> bool {
        if self.active != Some(index)
            || self.taking.is_some()
            || self.completed.contains(&Some(index))
        {
            return false;
        }
        let Some(empty) = self.completed.iter_mut().find(|entry| entry.is_none()) else {
            return false;
        };
        *empty = Some(index);
        self.active = None;
        true
    }

    pub(super) fn cancel_pending(&mut self) -> bool {
        let Some(index) = self.pending else {
            return true;
        };
        let Some(empty) = self.completed.iter_mut().find(|entry| entry.is_none()) else {
            return false;
        };
        *empty = Some(index);
        self.pending = None;
        true
    }

    /// Reports a local interval in which the born worker may still access a job.
    pub(super) fn worker_handoff_pending(&self, index: usize) -> bool {
        self.active == Some(index) || self.taking == Some(index)
    }

    /// Clears placement only after exact native Work and Material return.
    pub(super) fn retired(&mut self, index: usize) {
        if self.pending == Some(index) {
            self.pending = None;
        }
        if self.active == Some(index) {
            self.active = None;
        }
        if self.taking == Some(index) {
            self.taking = None;
        }
        if self.submitting == Some(index) {
            self.submitting = None;
        }
        self.returned(index);
    }

    pub(super) fn completed(&self) -> [Option<usize>; WORK_CELLS] {
        self.completed
    }

    pub(super) fn returned(&mut self, index: usize) -> bool {
        let Some(position) = self
            .completed
            .iter()
            .position(|entry| *entry == Some(index))
        else {
            return false;
        };
        for next in position + 1..WORK_CELLS {
            self.completed[next - 1] = self.completed[next];
        }
        self.completed[WORK_CELLS - 1] = None;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_does_not_block_the_queued_job_or_recycle_its_owner() {
        let mut queue = PipelineQueue::new();
        assert!(queue.reserve(0));
        assert!(queue.publish(0, true));
        assert_eq!(queue.take(), Some(0));
        assert!(!queue.reserve(1));
        assert!(queue.taken(0));
        assert!(queue.reserve(1));
        assert!(queue.publish(1, true));
        assert!(queue.complete(0));

        assert_eq!(queue.take(), Some(1));
        assert!(queue.taken(1));
        assert!(!queue.reserve(0));
        assert!(queue.returned(0));
        assert!(queue.reserve(0));
        assert!(queue.publish(0, true));
        assert_eq!(queue.active, Some(1));
        assert_eq!(queue.pending, Some(0));
    }

    #[test]
    fn two_completions_survive_until_their_independent_main_returns() {
        let mut queue = PipelineQueue::new();
        for index in 0..WORK_CELLS {
            assert!(queue.reserve(index));
            assert!(queue.publish(index, true));
            assert_eq!(queue.take(), Some(index));
            assert!(queue.taken(index));
            assert!(queue.complete(index));
        }

        assert_eq!(queue.completed(), [Some(0), Some(1)]);
        assert!(!queue.reserve(0));
        assert!(queue.returned(0));
        assert_eq!(queue.completed(), [Some(1), None]);
        assert!(queue.returned(1));
        assert_eq!(queue.completed(), [None, None]);
    }

    #[test]
    fn terminal_return_keeps_other_local_placements_intact() {
        let mut queue = PipelineQueue::new();
        assert!(queue.reserve(0));
        assert!(queue.publish(0, true));
        assert_eq!(queue.take(), Some(0));
        assert!(queue.taken(0));
        assert!(queue.reserve(1));
        assert!(queue.publish(1, true));
        assert!(queue.cancel_pending());

        queue.retired(0);
        assert!(queue.active.is_none());
        assert_eq!(queue.completed(), [Some(1), None]);
        queue.retired(1);
        assert_eq!(queue.completed(), [None, None]);
    }

    #[test]
    fn local_worker_handoff_spans_both_unlocked_job_windows() {
        let mut queue = PipelineQueue::new();
        assert!(queue.reserve(0));
        assert!(queue.publish(0, true));
        assert_eq!(queue.take(), Some(0));

        // Selection precedes the worker's first job-mutex acquisition.
        assert!(queue.worker_handoff_pending(0));
        assert!(!queue.worker_handoff_pending(1));
        assert!(queue.taken(0));

        // Native completion alone changes no local placement. This remains
        // true after the worker unlocks its job and before local publication.
        assert!(queue.worker_handoff_pending(0));
        assert!(queue.complete(0));
        assert!(!queue.worker_handoff_pending(0));
        assert_eq!(queue.completed(), [Some(0), None]);
    }

    #[test]
    fn failed_birth_releases_only_its_local_reservation() {
        let mut queue = PipelineQueue::new();
        assert!(queue.reserve(0));
        assert!(!queue.publish(1, true));
        assert!(queue.publish(0, false));
        assert!(queue.pending.is_none());
        assert!(queue.reserve(1));
        assert!(queue.publish(1, true));
        assert!(queue.cancel_pending());
        assert_eq!(queue.completed(), [Some(1), None]);
    }
}
