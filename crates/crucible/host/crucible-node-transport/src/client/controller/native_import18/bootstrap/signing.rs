//! Lends the actual unsigned assignment under unchanged original signing guards.
//!
//! The genuine Source independently admits its complete holder and callback
//! construction, retains each signing output and supplies its private purpose,
//! birth, kernel and lease conjunction. A successful loan issues no proof.

use super::*;
use crate::client::ClientSession;

impl CnpController {
    /// Lends the reserved unsigned original without lending a mutable endpoint.
    ///
    /// The Source funds the actual callback and retains its outputs before
    /// returning either result. Current Controller/Hello/typed-input guards and
    /// the actual unrenewed SDK/slot cut bracket that callback. The Copy result
    /// cannot return the borrowed original or an owning protocol object.
    ///
    /// # Errors
    /// Refuses a failed/incomplete owner, different original Controller or Hello,
    /// changed inputs, expired/replaced cut, altered literal or callback refusal.
    pub fn with_original_native_import18_bootstrap_unsigned_data<R: Copy>(
        &self,
        hello: &OriginalHelloJournal,
        owner: &OriginalNativeImport18Bootstrap,
        inspect: impl FnOnce(
            &Envelope,
            &PacketNativeImport18BootstrapRequest,
        ) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        authenticate_owner(self, hello, owner)?;
        let original = owner
            .assignment
            .as_ref()
            .ok_or_else(invalid)?
            .borrowed_history_data()
            .original
            .ok_or_else(invalid)?;
        let request = owner.request.as_ref().ok_or_else(invalid)?;
        let result = self.session.with_original_bootstrap_unsigned_data(
            original,
            request,
            owner.cut.ok_or_else(invalid)?,
            owner.literal_slot,
            |original| inspect(original, request),
        );
        let terminal = authenticate_owner(self, hello, owner);
        let output = result?;
        terminal?;
        Ok(output)
    }

    /// Names the actual immutable signing loan and concrete Copy result controls.
    ///
    /// Callback construction, retained outputs and private Source guards remain
    /// independently funded by the defining Source; this quote supplies no credit.
    pub fn original_native_import18_bootstrap_unsigned_loan_counter_scratch_data<R: Copy>() -> usize
    {
        Self::original_native_import18_bootstrap_counter_scratch_data()
            + ClientSession::original_bootstrap_unsigned_loan_counter_scratch_data::<R>()
            + size_of::<&Self>()
            + size_of::<&OriginalHelloJournal>()
            + size_of::<&OriginalNativeImport18Bootstrap>()
            + size_of::<&Envelope>()
            + size_of::<&PacketNativeImport18BootstrapRequest>()
            + size_of::<OperationalDeadline>()
            + size_of::<R>()
            + size_of::<Result<R, ProviderError>>()
            + size_of::<[Result<(), ProviderError>; 2]>()
    }
}

fn authenticate_owner(
    controller: &CnpController,
    hello: &OriginalHelloJournal,
    owner: &OriginalNativeImport18Bootstrap,
) -> Result<(), ProviderError> {
    let cut = controller
        .session
        .authenticate_original_bootstrap_effect_cut_data(owner.cut.ok_or_else(invalid)?, 2);
    let identity = authenticate_identity(controller, hello, owner);
    cut?;
    identity
}

fn authenticate_identity(
    controller: &CnpController,
    hello: &OriginalHelloJournal,
    owner: &OriginalNativeImport18Bootstrap,
) -> Result<(), ProviderError> {
    owner.row.controller.ensure_current()?;
    if owner.failed
        || !owner.retained
        || !owner.reservation_started
        || !owner.reserved
        || owner.literal_slot.is_none()
        || !Rc::ptr_eq(&owner.row.controller, &controller.protocol_owner)
        || owner.row.hello != controller.original_canonical_ack_hello_frame_digests(hello)?
        || owner.row.input_identity
            != storage::input_identity_data(
                owner.request_id.as_ref().ok_or_else(invalid)?,
                owner.request.as_ref().ok_or_else(invalid)?,
            )?
    {
        return Err(invalid());
    }
    let assignment = owner
        .assignment
        .as_ref()
        .ok_or_else(invalid)?
        .borrowed_history_data();
    if !assignment.assigned || assignment.failed || assignment.original.is_none() {
        return Err(invalid());
    }
    Ok(())
}
