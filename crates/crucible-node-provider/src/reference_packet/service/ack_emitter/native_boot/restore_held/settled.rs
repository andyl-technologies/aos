//! Borrows authenticated local evidence edges without serializing live rights.

use super::*;
use serde::{Serialize, Serializer, ser::SerializeStruct};

struct EvidenceHistory<'a>(&'a NativeRestoredControlEvidence);

impl Serialize for EvidenceHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let NativeRestoredControlEvidence {
            boot,
            attempt,
            hold,
        } = self.0;
        let owner = boot.try_borrow().map_err(serde::ser::Error::custom)?;
        let flight = attempt.try_borrow().map_err(serde::ser::Error::custom)?;
        owner.ensure_origin().map_err(serde::ser::Error::custom)?;
        flight.ensure_origin().map_err(serde::ser::Error::custom)?;
        if owner
            .restoration
            .as_ref()
            .is_none_or(|actual| !Rc::ptr_eq(actual, attempt))
            || flight
                .physical_hold
                .as_ref()
                .is_none_or(|actual| !Rc::ptr_eq(actual, hold))
        {
            return Err(serde::ser::Error::custom(
                "restored evidence historical edge differs",
            ));
        }
        // Complete owners are encoded once in native17. These closed roles
        // preserve the real shared edges; a cold reader obtains no Rc or gate.
        let mut state = serializer.serialize_struct("RestoredControlEvidenceHistory", 4)?;
        state.serialize_field(
            "schema",
            "source-private.native-restored-control-evidence-history/17",
        )?;
        state.serialize_field("boot_role", "native-boot")?;
        state.serialize_field("commit_role", "native-complete-restore-commit")?;
        state.serialize_field("hold_role", "native-complete-restore-physical-hold")?;
        state.end()
    }
}

impl NativeRestoredControlEvidence {
    /// Borrows all three actual evidence edges after their defining local checks.
    pub(crate) fn borrowed_settled_history_data(&self) -> impl Serialize + '_ {
        EvidenceHistory(self)
    }

    /// Checks the actual Control hold edge, without issuing an adoption permit.
    ///
    /// # Errors
    /// Refuses a hold from another restoration attempt.
    pub(crate) fn authenticate_settled_history_hold_data(
        &self,
        actual: &Rc<PacketCompleteRestorePhysicalHold>,
    ) -> Result<(), ProviderError> {
        if !Rc::ptr_eq(actual, &self.hold) {
            return Err(refused());
        }
        Ok(())
    }

    /// Counts this defining view and retained dynamic-borrow/result headers.
    pub(crate) const fn settled_history_counter_scratch_data() -> usize {
        std::mem::size_of::<EvidenceHistory<'static>>()
            + std::mem::size_of::<std::cell::Ref<'static, NativeAckBoot>>()
            + std::mem::size_of::<std::cell::Ref<'static, NativeCompleteRestoreAttempt>>()
            + std::mem::size_of::<Result<(), ProviderError>>()
    }
}

impl NativeRestoredControlEvidence {
    /// Appends all three actual evidence edges without resetting aggregate banks.
    ///
    /// # Errors
    /// Refuses foreign or borrowed owners, another attempt/Hold, or exhausted banks.
    pub(crate) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            boot,
            attempt,
            hold,
        } = self;
        let owner = boot.try_borrow().map_err(|_| borrowed())?;
        let flight = attempt.try_borrow().map_err(|_| borrowed())?;
        owner.ensure_origin()?;
        flight.ensure_origin()?;
        if owner
            .restoration
            .as_ref()
            .is_none_or(|actual| !Rc::ptr_eq(actual, attempt))
            || flight
                .physical_hold
                .as_ref()
                .is_none_or(|actual| !Rc::ptr_eq(actual, hold))
        {
            return Err(refused());
        }
        use crate::retained_metadata::aliases::MetadataSharedKind;
        observer.shared_original(MetadataSharedKind::NativeBoot, boot.as_ref())?;
        observer.shared_original(
            MetadataSharedKind::NativeRestoreCommitAttempt,
            attempt.as_ref(),
        )?;
        observer.shared_original(
            MetadataSharedKind::NativeRestoredPhysicalHold,
            hold.as_ref(),
        )
    }
}
