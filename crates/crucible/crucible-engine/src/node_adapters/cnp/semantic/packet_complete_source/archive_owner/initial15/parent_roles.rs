//! Borrows original Capture roles from the same retained administrative record.
//!
//! The journal reference comes from the authenticated parent's actual Settled
//! owner. Re-encoding a typed journal would create different evidence custody.

use super::*;

impl OriginalInitial15ArchivedOwnerRead<'_> {
    /// Borrows the actual original administrative owner's complete journal ref.
    ///
    /// # Errors
    /// Refuses another actor, incomplete base, ambiguous original owner or a
    /// changed participant, native snapshot, semantic cut or journal role.
    pub(crate) fn journal_reference_data(&self) -> Result<&ContentRef, OperationFailure> {
        self.authenticate_data()?;
        let journal = self.journal_data()?;
        let administrative = self
            .group
            .administrative
            .as_ref()
            .ok_or_else(|| refused("initial15 administrative journal absent"))?;
        let [attempt] = administrative.attempts.as_slice() else {
            return Err(refused("initial15 administrative Capture is not unique"));
        };
        let mut owners = attempt
            .owners
            .iter()
            .filter(|record| record.owner.owner == journal.owner);
        let owner = owners
            .next()
            .ok_or_else(|| refused("initial15 administrative source owner absent"))?;
        let crate::node_contract::OriginalCaptureOwnerState::Settled {
            snapshot,
            journal: reference,
        } = &owner.state
        else {
            return Err(refused("initial15 administrative source is not Settled"));
        };
        if owners.next().is_some()
            || owner.participants != journal.participants
            || snapshot != &journal.native_snapshot
            || attempt.cut != journal.cut
            || attempt.ordinal != journal.ordinal
        {
            return Err(refused("initial15 administrative source roles differ"));
        }
        Ok(reference)
    }
}

impl OriginalInitial15ArchivedOwnerRead<'_> {
    /// Borrows the authentic original program and immutable selection DATA.
    ///
    /// # Errors
    /// Refuses another actor or an incomplete independently read base.
    pub(crate) fn original_launch_data(
        &self,
    ) -> Result<&PacketNative5SourceLaunch, OperationFailure> {
        self.authenticate_data()?;
        self.group.launches[self.index]
            .as_ref()
            .ok_or_else(|| refused("initial15 original launch absent"))
    }

    /// Reports original generic operation and input association counts.
    ///
    /// These are generic lifetime associations, not Source17 Producer attempts.
    /// A first Source17 generation has no inherited Producer-attempt owner.
    ///
    /// # Errors
    /// Refuses incomplete originals, overflow or a violated original shared cap.
    pub(crate) fn original_generic_counts_data(&self) -> Result<(usize, usize), OperationFailure> {
        let (_, semantic) = self.semantic_data()?;
        let common = semantic.source_common_data();
        let operations = common.operations.len();
        let inputs = common.inputs.len();
        let total = operations
            .checked_add(inputs)
            .ok_or_else(|| refused("initial15 generic association count overflow"))?;
        let (maximum, _, _, _) = self.original_semantic_caps_data()?;
        if total > maximum {
            return Err(refused(
                "initial15 original generic association cap exceeded",
            ));
        }
        Ok((operations, inputs))
    }
}
