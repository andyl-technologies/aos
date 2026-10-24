//! Lends exact Initial15 Control custody at the installed Window's cold cut.
//!
//! This metadata borrower requires an already constructed genuine ColdGroup. It
//! cannot fund an earlier native process birth or alter a sealed startup carrier.
//! It performs no parser, hash, serializer or schema factory. Later prospective
//! visitors independently admit the defining decoder and their formatter work.

use super::*;
use crucible_node_transport::envelope::Envelope;

#[path = "future_control/attempt.rs"]
mod attempt;
pub(crate) use attempt::{
    OriginalInitial15FutureControlAttempt, OriginalInitial15FutureControlConstructionData,
};

/// Borrows one actual completed old-family member without decoding a new model.
///
/// Keeping the original ColdOwner loan retains its real native Ref guards. The
/// completed Source/Window remains responsible for full scope/currentness around
/// each later callback; these bytes do not issue a native allocation or grant.
pub(crate) struct OriginalInitial15FutureControlLoan<'a> {
    group: &'a OriginalRestorationColdGroup,
    owner: OriginalRestorationColdOwnerView<'a>,
    control: &'a ContentRef,
    control_bytes: &'a [u8],
    capture_original: &'a Envelope,
    capture_terminal: &'a Envelope,
}

impl<'a> OriginalInitial15FutureControlLoan<'a> {
    pub(super) fn authenticate_source_data(&self) -> Result<(), RuntimeError> {
        self.group.origin()?;
        self.owner
            .source
            .storage_origin_with_error::<RuntimeError>()
    }

    /// Borrows exact verified Control identity and the same retained body.
    pub(crate) fn control_data(&self) -> (&ContentRef, &[u8]) {
        (self.control, self.control_bytes)
    }

    /// Borrows the actual completed historical Capture literal pair.
    pub(crate) fn capture_pair_data(&self) -> (&Envelope, &Envelope) {
        (self.capture_original, self.capture_terminal)
    }

    /// Borrows the actual completed original member and native/registry loans.
    pub(crate) fn owner_data(&self) -> &OriginalRestorationColdOwnerView<'a> {
        &self.owner
    }
}

impl OriginalRestorationColdGroup {
    /// Lends actual archived Control and completed SDK/native correspondence.
    ///
    /// The original grouped constructor already validated these immutable bytes
    /// and complete Capture pair. This lender checks real actor/SourceRc/ticket
    /// and dictionary membership before and after the borrowed lookup. It never
    /// reparses or hashes Control, never turns an equal reference into authority
    /// and never supplies a decoded-model permission from configured limits.
    ///
    /// # Errors
    /// Refuses foreign or incomplete cold custody, missing original literals or
    /// body, changed literal request identity, or inconsistent cached lengths.
    pub(crate) fn original_initial15_future_control_data<'a>(
        &'a self,
        index: usize,
        source: &Rc<PacketCompleteSemanticSource>,
        ticket: &crate::node_state::CompleteOriginalNativeTicket,
    ) -> Result<OriginalInitial15FutureControlLoan<'a>, RuntimeError> {
        let owner = self.original_owner_data(index, source, ticket)?;
        let control = &owner.journal.native_control;
        let control_bytes = self
            .archive
            .content()
            .get(control)
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if u64::try_from(control_bytes.len()).map_err(|_| RuntimeError::ResourceLimit)?
            != control.length.get()
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let host = owner
            .host
            .historical()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let capture_id = &owner.journal.confirmation.capture.capture_request_id;
        let pair = host
            .custody
            .controller
            .get(capture_id)
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let terminal = pair
            .response
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if pair.request.request_id.0.as_ref() != Some(capture_id)
            || terminal.request_id.0.as_ref() != Some(capture_id)
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        self.origin()?;
        Ok(OriginalInitial15FutureControlLoan {
            group: self,
            control,
            control_bytes,
            capture_original: &pair.request,
            capture_terminal: terminal,
            owner,
        })
    }

    /// Names actual fixed borrower and original cold custody guard controls.
    pub(crate) fn original_initial15_future_control_counter_scratch_data() -> usize {
        Self::counter_scratch_data()
            + size_of::<OriginalInitial15FutureControlLoan<'static>>()
            + size_of::<Result<OriginalInitial15FutureControlLoan<'static>, RuntimeError>>()
            + size_of::<&ContentRef>()
            + size_of::<&[u8]>()
            + size_of::<&Envelope>() * 2
            + size_of::<Result<u64, std::num::TryFromIntError>>()
            + size_of::<Result<&HistoricalControllerState, crucible_node_transport::ProviderError>>(
            )
            + size_of::<Option<&crucible_node_transport::client::ClientOriginal>>()
    }
}
