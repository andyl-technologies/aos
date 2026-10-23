//! Keeps final cleanup custody funded through its shared allocation's free.
//!
//! All observers use this private owner. No raw strong or weak alias escapes;
//! the final observer extracts the record only after deallocating its header.

use std::alloc::Layout;
use std::fmt;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use super::CleanupRecord;

/// Shares the same prepaid record without exposing its reference counters.
pub(super) struct RetainedCleanupRecord {
    shared: Option<Arc<CleanupRecord>>,
}

impl RetainedCleanupRecord {
    /// Allocates only after the containing caller admits the complete peak.
    pub(super) fn new(record: CleanupRecord) -> Self {
        Self {
            shared: Some(Arc::new(record)),
        }
    }

    /// Covers allocation, construction/extraction overlap and the owner handle.
    pub(super) fn allocation_peak_bytes() -> Option<u64> {
        let (allocation, _) = Layout::new::<[AtomicUsize; 2]>()
            .extend(Layout::new::<CleanupRecord>())
            .ok()?;
        allocation
            .pad_to_align()
            .size()
            .checked_add(std::mem::size_of::<CleanupRecord>())?
            .checked_add(std::mem::size_of::<Self>())?
            .try_into()
            .ok()
    }

    /// Compares existing allocation identities without granting cleanup.
    pub(super) fn same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(self.shared(), other.shared())
    }

    fn shared(&self) -> &Arc<CleanupRecord> {
        match &self.shared {
            Some(shared) => shared,
            None => unreachable!("a live cleanup observer owns its original record"),
        }
    }
}

impl Clone for RetainedCleanupRecord {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
        }
    }
}

impl Deref for RetainedCleanupRecord {
    type Target = CleanupRecord;

    fn deref(&self) -> &Self::Target {
        self.shared()
    }
}

impl fmt::Debug for RetainedCleanupRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.shared().fmt(formatter)
    }
}

impl Drop for RetainedCleanupRecord {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.take() {
            // Every observer consumes its Arc through into_inner. With no Weak
            // aliases, exactly one concurrent final observer frees the header
            // before record Drop can retire custody or refund its control loan.
            drop(Arc::into_inner(shared));
        }
    }
}
