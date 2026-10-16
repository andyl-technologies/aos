//! Queried promotion payloads and their visible thread-start handoff.
//!
//! The owned worker, shared pool handle and supplied name buffer are measured
//! before Main admission. Standard-library thread/stack controls remain separate.

use super::*;

/// Visible promotion thread payload; standard-library thread controls are separate.
pub(in crate::executor_pool) struct PromotionThreadCapture<L, V, P> {
    pub(in crate::executor_pool) shared: std::sync::Arc<SharedExecutor<L, V>>,
    pub(in crate::executor_pool) worker: P,
}

impl<L, V, P> PromotionThreadCapture<L, V, P>
where
    L: AssignmentLedger + Send + 'static,
    V: AttemptAdmissionValidator + Send + Sync + 'static,
    P: LocalCheckpointPromotionWorker,
{
    pub(in crate::executor_pool) fn run(self) {
        let _completion = crate::executor_pool::WorkerCompletion::new(&self.shared.completion);
        promotion_worker_loop(self.shared, self.worker);
    }
}

/// Measures visible worker-vector, construction and thread-capture overlap.
///
/// This excludes private standard-library thread/stack allocations; it does not
/// establish whole-thread funding or a stack-capacity bound.
pub(crate) fn promotion_control_bytes<L, V, P>(count: usize) -> Option<u64> {
    use std::alloc::Layout;
    if count > MAX_LOCAL_CHECKPOINT_PROMOTION_WORKERS {
        return None;
    }
    if count == 0 {
        return Some(0);
    }
    let vector = Layout::array::<P>(count).ok()?.size();
    let captures = Layout::array::<PromotionThreadCapture<L, V, P>>(count)
        .ok()?
        .size();
    let mut names = 0usize;
    for slot in 0..count {
        names = names.checked_add(promotion_thread_name_bytes(slot))?;
    }
    vector
        .checked_add(captures)?
        .checked_add(names)?
        .checked_add(std::mem::size_of::<P>())?
        .checked_add(std::mem::size_of::<Vec<P>>())?
        .try_into()
        .ok()
}

fn promotion_thread_name_bytes(slot: usize) -> usize {
    let mut value = slot;
    let mut digits = 1;
    while value >= 10 {
        value /= 10;
        digits += 1;
    }
    "crucible-checkpoint-promotion-".len() + digits
}

pub(in crate::executor_pool) fn promotion_thread_name(slot: usize) -> String {
    use std::fmt::Write;
    let mut name = String::with_capacity(promotion_thread_name_bytes(slot));
    // Writing an integer into an owned String has no external failure source.
    let _ = write!(&mut name, "crucible-checkpoint-promotion-{slot}");
    name
}
