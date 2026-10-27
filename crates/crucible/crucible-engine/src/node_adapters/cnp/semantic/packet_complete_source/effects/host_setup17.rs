//! Counts the reader's actual private receiver group without touching a socket.

use super::*;
use crate::node_contract::RuntimeError;

impl PacketCompleteEffectReceiverReader {
    /// Counts the actual receiver allocation retained by this consuming role.
    ///
    /// The containing reader header is part of its caller-owned setup slot.
    /// This observes the real private Rc, including when a separate inspection
    /// alias differs. It allocates nothing and performs no descriptor operation;
    /// frontier/currentness and actual group association remain separate guards.
    ///
    /// # Errors
    /// Refuses a foreign process/thread or a requested extent above `maximum`.
    pub fn original_retained_requested_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let Self { group } = self;
        group.original_retained_requested_storage_precredit_data(maximum)
    }
}
