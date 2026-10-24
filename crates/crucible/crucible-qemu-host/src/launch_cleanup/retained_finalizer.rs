//! Keeps final accounting alive through cleanup and erased cause observers.
//!
//! All observers use this private owner. No raw strong or weak alias escapes;
//! the final observer extracts the record only after deallocating its header.

use std::alloc::Layout;
use std::fmt;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use super::CleanupFinalizer;

/// Shares the same prepaid finalizer without exposing its reference counters.
pub(super) struct RetainedCleanupFinalizer {
    shared: Option<Arc<dyn ClosedFinalizer>>,
}

impl RetainedCleanupFinalizer {
    /// Allocates only after the containing caller admits the complete peak.
    pub(super) fn new(record: CleanupFinalizer) -> Self {
        Self {
            shared: Some(Arc::new(record)),
        }
    }

    /// Covers allocation, construction/extraction overlap and the owner handle.
    pub(super) fn allocation_peak_bytes() -> Option<u64> {
        let (allocation, _) = Layout::new::<[AtomicUsize; 2]>()
            .extend(Layout::new::<CleanupFinalizer>())
            .ok()?;
        allocation
            .pad_to_align()
            .size()
            .checked_add(std::mem::size_of::<CleanupFinalizer>())?
            .checked_add(std::mem::size_of::<Self>())?
            .try_into()
            .ok()
    }

    fn shared(&self) -> &Arc<dyn ClosedFinalizer> {
        match &self.shared {
            Some(shared) => shared,
            None => unreachable!("a live cleanup observer owns its original record"),
        }
    }
}

impl Clone for RetainedCleanupFinalizer {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
        }
    }
}

impl Deref for RetainedCleanupFinalizer {
    type Target = CleanupFinalizer;

    fn deref(&self) -> &Self::Target {
        self.shared().finalizer()
    }
}

impl fmt::Debug for RetainedCleanupFinalizer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.shared().fmt(formatter)
    }
}

impl Drop for RetainedCleanupFinalizer {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.take() {
            // Every observer consumes its Arc through into_inner. With no Weak
            // aliases, exactly one concurrent final observer frees the header
            // before record Drop can retire custody or refund its control loan.
            shared.close();
        }
    }
}

// The private dispatch boundary keeps accounting custody independent of the
// recursive physical borrower graph. Only this concrete finalizer implements
// it, and every alias takes the same header-before-payload destruction path.
trait ClosedFinalizer: fmt::Debug + Send + Sync {
    fn finalizer(&self) -> &CleanupFinalizer;
    fn close(self: Arc<Self>);
}

impl ClosedFinalizer for CleanupFinalizer {
    fn finalizer(&self) -> &CleanupFinalizer {
        self
    }

    fn close(self: Arc<Self>) {
        drop(Arc::into_inner(self));
    }
}
