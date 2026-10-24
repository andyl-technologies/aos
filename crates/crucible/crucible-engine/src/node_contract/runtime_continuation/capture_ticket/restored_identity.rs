//! Authenticates actual ticket custody before the independent settled Source loan.
//!
//! This identity check never substitutes for authenticate_scope: the Source
//! separately validates Runtime7 and its canonical object under admitted credit.

use super::*;

impl OriginalLineageOwnerCaptureTicket<'_> {
    pub(crate) fn authenticate_original_restored_identity_data(
        &self,
        activation: &WorldActivation,
        source: &OriginalLineageRuntimeRecord,
        runtime_object: &InputPayload,
        owner: &OwnerIdentity,
        participants: &[Id],
    ) -> Result<(), RuntimeError> {
        let original = self.attempt;
        if original.process != std::process::id() || original.thread != thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        original.original.authenticate_runtime_authority(
            &original.activation.record().world_binding_hash,
            &activation.authority,
        )?;
        if !original.active.get()
            || !self.owner.submitted.get()
            || !activation.same_authority(&original.activation)
            || activation.record() != original.activation.record()
            || owner != &self.owner.owner
            || participants != self.owner.participants
            || !original
                .owners
                .iter()
                .any(|reservation| std::ptr::eq(reservation, self.owner))
            || source.capture_cut != original.cut
            || source.capture_ordinal != original.ordinal
            || runtime_object.reference != original.runtime_object.reference
            || runtime_object.bytes != original.runtime_object.bytes
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(crate) fn original_restored_identity_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<&Self>()
            + size_of::<&OriginalLineageCaptureAttempt>()
            + size_of::<std::slice::Iter<'static, OriginalCaptureOwnerReservation>>()
            + size_of::<Option<&OriginalCaptureOwnerReservation>>()
            + size_of::<&WorldActivation>()
            + size_of::<&OriginalLineageRuntimeRecord>()
            + size_of::<&InputPayload>()
            + size_of::<&OwnerIdentity>()
            + size_of::<&[Id]>()
            + size_of::<Result<(), RuntimeError>>()
    }
}
