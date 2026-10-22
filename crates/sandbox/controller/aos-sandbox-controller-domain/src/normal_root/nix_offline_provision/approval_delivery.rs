//! Retains the distinct V6 startup for signed offline approval DATA delivery.
//!
//! The shared original launch engine still verifies PID 1, immutable images,
//! the exact selected unit, confinement and stopped runtime owners. V6 selects
//! a separate immutable profile format and exactly two additional credentials.
//! It grants no hardware startup loan, hierarchy authorization or TPM access.

use super::{
    Error, OfflineNixPrepareStartupErrorV3, OfflineNixPrepareStartupV3, OfflinePrepareModeV3,
};

/// Retains one actual V6 approval-delivery launch and every original failure.
///
/// The owner performs no protected I/O until capture. Keep it resident with
/// its borrowing native attempt through explicit exit on failure or unwind.
pub struct OfflineNixApprovalDeliveryStartupV6 {
    original: OfflineNixPrepareStartupV3,
}

impl OfflineNixApprovalDeliveryStartupV6 {
    /// Creates empty custody without selecting or approving a proposal.
    #[must_use]
    pub fn new() -> Self {
        Self {
            original: OfflineNixPrepareStartupV3::new(),
        }
    }

    /// Captures only the genuine V6 initialization-approval delivery unit.
    ///
    /// # Errors
    /// Retains the first actual launch, image, manager or credential mismatch.
    /// Repeated and interrupted capture remain fenced.
    pub fn capture_initialize_approval(&mut self) -> Result<(), &OfflineNixPrepareStartupErrorV3> {
        self.original
            .capture_mode(OfflinePrepareModeV3::ImportInitializeApprovalV6)
    }

    /// Captures only the genuine V6 recovery-approval delivery unit.
    ///
    /// # Errors
    /// Rejects changed, repeated or interrupted launch and delivery originals.
    /// Admission neither renews a job deadline nor approves a recovery effect.
    pub fn capture_recovery_approval(&mut self) -> Result<(), &OfflineNixPrepareStartupErrorV3> {
        self.original
            .capture_mode(OfflinePrepareModeV3::ImportRecoveryApprovalV6)
    }

    /// Borrows the actual admitted V6 original after a fresh complete recheck.
    ///
    /// # Errors
    /// Fences an absent, wrong-purpose, interrupted, failed or changed owner.
    pub fn borrow_original(
        &mut self,
    ) -> Result<OfflineNixApprovalDeliveryOriginV6<'_>, &OfflineNixPrepareStartupErrorV3> {
        let Some(mode) = self
            .original
            .mode
            .filter(|mode| mode.approval_delivery_v6())
        else {
            let _ = self.original.refuse();
            return Err(self.original.failure.get_or_insert(Error::Fenced));
        };
        if self.original.recheck_mode(mode).is_err() {
            return Err(self.original.failure.get_or_insert(Error::Fenced));
        }

        Ok(OfflineNixApprovalDeliveryOriginV6 {
            original: &mut self.original,
        })
    }

    /// Borrows the retained first failure without releasing original custody.
    pub fn failure(&self) -> Option<&OfflineNixPrepareStartupErrorV3> {
        self.original.failure()
    }
}

impl Default for OfflineNixApprovalDeliveryStartupV6 {
    fn default() -> Self {
        Self::new()
    }
}

/// Lends the actual V6 launch to its fixed approval-file delivery owner.
///
/// This loan has no public constructor, clone, raw file or hardware conversion.
/// Its signed proposal bytes remain DATA until independently compared by the
/// later hardware owner with that owner's actual installation and history.
pub struct OfflineNixApprovalDeliveryOriginV6<'startup> {
    original: &'startup mut OfflineNixPrepareStartupV3,
}

impl OfflineNixApprovalDeliveryOriginV6<'_> {
    /// Rechecks the same selected V6 unit, process, image and credential originals.
    ///
    /// # Errors
    /// Retains actual observation failures and fences a changed or failed owner.
    pub fn recheck(&mut self) -> Result<(), &OfflineNixPrepareStartupErrorV3> {
        match self.original.mode {
            Some(mode) if mode.approval_delivery_v6() => self.original.recheck_mode(mode),
            _ => self.original.refuse(),
        }
    }

    /// Borrows the original public node and independent approval-key delivery.
    ///
    /// # Errors
    /// Rejects a fenced owner or missing original credential bytes.
    pub fn public_originals(&self) -> Result<(&[u8; 16], &[u8; 48]), Error> {
        self.require_usable()?;
        let (node, approval) = self.original.credentials.public_originals()?;
        Ok((
            node.try_into().map_err(|_| Error::Rejected)?,
            approval.try_into().map_err(|_| Error::Rejected)?,
        ))
    }

    /// Borrows the two independently delivered signed proposal DATA records.
    ///
    /// # Errors
    /// Rejects a fenced owner or a different closed credential recipe.
    pub fn approved_data_originals(&self) -> Result<(&[u8; 1332], &[u8; 304]), Error> {
        self.require_usable()?;
        self.original
            .credentials
            .approval_delivery_originals_v6()
            .map_err(Error::Io)
    }

    /// Reports whether the actual immutable selected command delivers recovery DATA.
    #[must_use]
    pub fn is_recovery_proposal(&self) -> bool {
        self.original.mode == Some(OfflinePrepareModeV3::ImportRecoveryApprovalV6)
    }

    /// Borrows the actual startup cause without releasing its original custody.
    pub fn failure(&self) -> Option<&OfflineNixPrepareStartupErrorV3> {
        self.original.failure()
    }

    fn require_usable(&self) -> Result<(), Error> {
        if !self.original.usable
            || !self
                .original
                .mode
                .is_some_and(OfflinePrepareModeV3::approval_delivery_v6)
        {
            return Err(Error::Fenced);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_delivery_cannot_borrow_an_empty_or_other_purpose_startup() {
        for mode in [
            None,
            Some(OfflinePrepareModeV3::PrepareKeys),
            Some(OfflinePrepareModeV3::InspectApprovedJob),
            Some(OfflinePrepareModeV3::Initialize),
            Some(OfflinePrepareModeV3::Recover),
        ] {
            let mut startup = OfflineNixApprovalDeliveryStartupV6::new();
            startup.original.mode = mode;

            assert!(startup.borrow_original().is_err());
            assert!(matches!(startup.failure(), Some(Error::Fenced)));
        }
    }

    #[test]
    fn interrupted_approval_delivery_cannot_reenter_or_borrow() {
        let mut startup = OfflineNixApprovalDeliveryStartupV6::new();
        startup.original.attempted = true;
        startup.original.mode = Some(OfflinePrepareModeV3::ImportInitializeApprovalV6);

        assert!(startup.capture_initialize_approval().is_err());
        assert!(startup.capture_recovery_approval().is_err());
        assert!(startup.borrow_original().is_err());
        assert!(matches!(startup.failure(), Some(Error::Fenced)));
    }
}
