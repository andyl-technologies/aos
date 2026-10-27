//! Retains the unique wait owner and remaining borrowers of an unreaped child.
//!
//! The containing cleanup allocation funds this recipient before process birth.
//! A single consuming claim prevents a second child from sharing its return slot.

use super::*;

/// Reserves the containing launch's sole unreaped-child recipient.
#[derive(Debug)]
pub(crate) struct UnreapedChildRetention {
    cleanup: LaunchCleanup,
}

impl LaunchCleanup {
    /// Claims the already allocated return recipient before process birth.
    pub(crate) fn claim_child_return(&self) -> Option<UnreapedChildRetention> {
        self.inner
            .child_return_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;
        Some(UnreapedChildRetention {
            cleanup: self.clone(),
        })
    }

    /// Borrows the actual retained child without creating wait authority.
    #[cfg(test)]
    pub(crate) fn retained_unreaped_child(&self) -> Option<&Mutex<crate::node::AbandonedChild>> {
        self.inner.abandoned_child.get()
    }
}

impl UnreapedChildRetention {
    /// Moves the real wait owner and borrowers without allocating or waiting.
    pub(crate) fn retain(self, child: crate::node::AbandonedChild) {
        // This uncloneable token is the only publisher. Worker and pre-exec
        // delivery have separate recipients and cannot contend for this slot.
        self.cleanup
            .inner
            .abandoned_child
            .get_or_init(|| Mutex::new(child));
        // Keep this actual containing owner until process exit. Neither local
        // handle destruction nor a kill request proves that the child returned.
        std::mem::forget(self);
    }
}
