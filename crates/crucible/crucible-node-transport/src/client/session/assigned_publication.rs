//! Borrows a planned publication and its existing physical deadline.
//!
//! This input view authenticates neither the planned frame nor a successful
//! write. The owning Session still checks the exact original sequence, cut,
//! selected codec and literal slot before publishing or retaining a response.

use super::*;
use crate::operational_time::OperationalDeadline;

/// Borrows the original inputs retained by one assigned publication owner.
pub(in crate::client) struct OriginalAssignedPublicationData<'a> {
    /// Borrows the complete assigned original, including its proof extension.
    pub(in crate::client) original: &'a Envelope,
    /// Borrows the canonical bytes already retained by that same assignment.
    pub(in crate::client) bytes: &'a [u8],
    /// Names its existing literal reservation without authenticating that slot.
    pub(in crate::client) slot: Option<usize>,
    /// Retains the original physical cut without starting another deadline.
    pub(in crate::client) cut: OperationalDeadline,
}

impl ClientSession {
    /// Counts caller and callee input headers beside the earlier field controls.
    pub(in crate::client) const fn original_assigned_publication_counter_scratch_data() -> usize {
        2 * std::mem::size_of::<OriginalAssignedPublicationData<'static>>()
            + std::mem::size_of::<usize>()
    }
}
