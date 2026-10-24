//! Borrows normalization under the capsule's actual pending assignment frontier.
//!
//! The original FreshQuery is only current before assignment. This separate
//! DATA loan proves the retained unsigned or sealed literal and its current
//! Session cut; it never resets a query or infers completion of seven uploads.

use super::*;
use std::mem::size_of;

impl CnpController {
    /// Names actual selection, cut, literal-bank and borrowed-return controls.
    pub fn original_native_import18_assigned_normalization_counter_scratch_data() -> usize {
        type PendingData<'a> = (
            Stage,
            Option<&'a Envelope>,
            &'a [u8],
            Option<usize>,
            Option<OperationalDeadline>,
        );

        Self::original_native_import18_assignment_counter_scratch_data()
            + crate::connection::native_import18::pending_assignment_counter_scratch_data()
            + size_of::<PacketNativeImport18Phase>()
            + size_of::<Stage>()
            + size_of::<Option<Stage>>()
            + size_of::<Result<PacketNativeImport18Phase, ProviderError>>()
            + size_of::<PendingData<'static>>()
            + size_of::<(&OriginalNativeImport18Assignment, &CnpController)>()
            + size_of::<bool>()
            + size_of::<(&ContentRef, &[u8])>()
            + size_of::<Result<(&ContentRef, &[u8]), ProviderError>>()
            + size_of::<Result<(usize, usize), ProviderError>>()
            + size_of::<Result<u64, std::num::TryFromIntError>>()
    }

    /// Quotes the compiled selection factory before the assigned DATA lender.
    ///
    /// The caller admits the fixed declaration above before this allocation-free
    /// geometry lookup, then admits its returned T/S before borrowing the tuple.
    /// No actual schema factory, serialization, query or authority grant runs here.
    ///
    /// # Errors
    /// Refuses checked fixed-contract geometry overflow.
    pub fn original_native_import18_assigned_normalization_prewalk_data()
    -> Result<(usize, usize), ProviderError> {
        let (temporary, _) = native_import18_contract_storage_data(usize::MAX)?;
        Ok((
            temporary,
            Self::original_native_import18_assigned_normalization_counter_scratch_data(),
        ))
    }
}

impl OriginalNativeImport18Assignment {
    /// Borrows exact retained normalization during one current pending assignment.
    ///
    /// The caller funds the defining prewalk first. This checks the same actual
    /// Controller/Rc/emitter/full selected contract, private phase, Session cut
    /// and literal reservation. Unsigned has no bytes or attempted publication;
    /// sealed has exact framed bytes and the actual pending original. A Source
    /// still needs its genuine Window phase claim and native keyed proof.
    ///
    /// A completed Prepare establishes no later signing frontier. This supplier
    /// does not issue Commit; the actual Held18 body and phase producer are
    /// separate required dependencies, and the FreshQuery is never reused.
    ///
    /// # Errors
    /// Refuses another actor/emitter/selection, incomplete or failed assignment,
    /// completed-only state, expired/advanced cut, or a changed/attempted literal.
    pub fn assigned_normalization_data<'a>(
        &'a self,
        controller: &'a CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<(&'a ContentRef, &'a [u8]), ProviderError> {
        self.authenticate(controller, emitter)?;
        let result = (|| {
            let owner = &self.prepare;
            if !matches!(owner.stage, Stage::Unsigned | Stage::Sealed) {
                return Err(invalid());
            }
            let (stage, original, bytes, slot, cut) = (
                owner.stage,
                owner.original.as_ref(),
                owner.bytes.as_slice(),
                owner.literal_slot,
                owner.cut,
            );
            let original = original.ok_or_else(invalid)?;
            controller
                .session
                .authenticate_original_ack_admit_cut(original.sequence, cut.ok_or_else(invalid)?)?;
            controller
                .session
                .authenticate_pending_native_import18_data(
                    original,
                    bytes,
                    slot,
                    stage == Stage::Sealed,
                )?;
            // The normalization copy was verified before the private phase could
            // become Unsigned; no public mutable loan exists thereafter.
            if self.normalization.is_empty()
                || u64::try_from(self.normalization.len()).map_err(|_| credit())?
                    != self.binding.normalization.length.get()
            {
                return Err(invalid());
            }
            Ok((&self.binding.normalization, self.normalization.as_slice()))
        })();
        // Keep the actual original actor/emitter postfence on both outcomes.
        emitter.authenticate_original(controller)?;
        self.controller.ensure_current()?;
        result
    }
}
