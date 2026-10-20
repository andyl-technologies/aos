//! Projects logical connection facts from the enclosing checked native17 graph.
//!
//! This module owns no old transport heap. Complete grammar, capacity and alias
//! validation belongs to the outer plan; these comparisons close its semantic
//! joins before that plan can be returned. Historical facts issue no capability.

mod authority;
pub(crate) mod bytes;
mod connection;
mod tokens;

pub(crate) use authority::BorrowedAuthority17Lineage;
pub(crate) use connection::{
    BorrowedCorrelationLedger17, BorrowedNativeConnection17LogicalData,
    borrow_native17_connection_logical_data,
};
pub(crate) use tokens::{BorrowedAdmission17Kind, BorrowedAdmission17Lineage};

/// Quotes explicit comparison and global pin-ID scratch without target heaps.
pub(crate) const fn native17_logical_projection_scratch_data() -> usize {
    bytes::comparison_scratch_data() + std::mem::size_of::<[u64; 2048]>()
}

use super::*;

impl<S: ProviderStream> Connection<S> {
    /// Checks a genuine current connection without draining any protocol work.
    ///
    /// # Errors
    /// Refuses revoked/fenced state, a pending assigned response, incomplete
    /// literal transport, unavailable immutable codec or a different actual cut.
    pub(crate) fn authenticate_native17_logical_capture_cut_data(
        &self,
        cut: crate::protocol_snapshot::ProtocolCaptureCut,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        if self.fenced || self.role != EndpointRole::Provider {
            return Err(invalid());
        }
        self.authority.ensure_live()?;
        self.ensure_no_pending_native_restore_response()?;
        self.native5_codec
            .as_ref()
            .ok_or_else(invalid)?
            .validate_installation(&self.authority)?;
        let frames = self.original_frames.as_ref().ok_or_else(invalid)?;
        if !frames.try_borrow().map_err(|_| invalid())?.complete() {
            return Err(invalid());
        }
        self.guard.protocol_cut(cut)
    }
}

pub(crate) mod custody;

#[cfg(test)]
mod tests;

impl<S: ProviderStream> Connection<S> {
    /// Checks the exact current Capture or Poll lent by the private action cut.
    ///
    /// # Errors
    /// Refuses failed/foreign authority, unresolved correlations, incomplete
    /// literal transport or a different actual current typed request.
    pub(crate) fn authenticate_native17_current_action_cut_data(
        &self,
        current: &crate::reference_packet::service::native_startup::NativeRestoredSettledActionCurrent17<'_>,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        if self.fenced || self.role != EndpointRole::Provider {
            return Err(invalid());
        }
        self.authority.ensure_live()?;
        self.ensure_no_pending_native_restore_response()?;
        self.native5_codec
            .as_ref()
            .ok_or_else(invalid)?
            .validate_installation(&self.authority)?;
        let frames = self.original_frames.as_ref().ok_or_else(invalid)?;
        if !frames.try_borrow().map_err(|_| invalid())?.complete() {
            return Err(invalid());
        }
        let original = current.current_capture_cut_original17_data()?;
        if original.session_id.0.as_ref() != Some(self.authority.session_id())
            || original.incarnation_id.0.as_ref() != Some(self.authority.incarnation_id())
        {
            return Err(invalid());
        }
        self.guard
            .authenticate_native17_current_action_cut_data(current)
    }
}
