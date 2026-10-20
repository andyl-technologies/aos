//! Retains Mount16 bookends against the fixed opener's actual transferred writer.
//!
//! The same completed opener privately binds its existing instance Arc. These
//! native observations supply no Session, table, semantic or financial grant.

use super::*;

#[derive(Clone, Copy)]
enum First {
    Before,
    After,
    Reentry,
}

/// Retains before and independently owed after observations of one Mount writer.
#[must_use = "retain both native outcomes through the actual Mount16 posts"]
pub struct MountInventoryJournalCurrentnessOriginalV2 {
    entered: bool,
    before: MountJournalCurrentnessOriginalsV1,
    after: MountJournalCurrentnessOriginalsV1,
    before_result: Option<Result<(), JournalError>>,
    after_result: Option<Result<(), JournalError>>,
    reentry: Option<JournalError>,
    first: Option<First>,
}

impl Default for MountInventoryJournalCurrentnessOriginalV2 {
    fn default() -> Self {
        Self {
            entered: false,
            before: MountJournalCurrentnessOriginalsV1::new(),
            after: MountJournalCurrentnessOriginalsV1::new(),
            before_result: None,
            after_result: None,
            reentry: None,
            first: None,
        }
    }
}

impl MountInventoryJournalCurrentnessOriginalV2 {
    /// Borrows the actual selected native or original-association refusal.
    #[must_use]
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Before => self.before.failure().or_else(|| {
                self.before_result
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            }),
            First::After => self.after.failure().or_else(|| {
                self.after_result
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            }),
            First::Reentry => self.reentry.as_ref().map(|cause| cause as _),
        }
    }

    /// Requires both actual observations without issuing any native authority.
    ///
    /// # Errors
    /// Refuses missing, repeated, foreign or failed original bookends.
    pub fn require_complete_v2(&self) -> Result<(), JournalError> {
        if self.first.is_none()
            && self.entered
            && matches!(self.before_result, Some(Ok(())))
            && matches!(self.after_result, Some(Ok(())))
        {
            Ok(())
        } else {
            Err(MechanicalError::ProtectedBoundary.into())
        }
    }
}

impl MountStateCapturedJournalOpenV4 {
    /// Prices both actual observations before the first inventory bookend.
    ///
    /// # Errors
    /// Refuses checked overflow in the real native and inline representations.
    pub fn inventory_currentness_receiving_demand_v2(
        &self,
    ) -> Result<ResourceVector, JournalError> {
        let one = MountJournalCurrentnessOriginalsV1::fixed_demand_v1(Path::new(DIRECTORY), NAME)?;
        let bytes = std::mem::size_of::<MountInventoryJournalCurrentnessOriginalV2>()
            .checked_mul(2)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(MechanicalError::JournalTooLarge)?;
        one.checked_add(one)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
            .map_err(Into::into)
    }

    /// Observes this exact transferred Journal under the genuine paid inventory.
    ///
    /// # Errors
    /// Retains reentry, a foreign original, unhealthy custody or native refusal.
    pub fn observe_inventory_currentness_before_v2(
        &self,
        journal: &MountJournalV1,
        original: &mut MountInventoryJournalCurrentnessOriginalV2,
    ) -> Result<(), JournalError> {
        if original.before_result.is_some() || original.entered {
            original
                .reentry
                .get_or_insert(MechanicalError::ProtectedBoundary.into());
            original.first.get_or_insert(First::Reentry);
            return Err(MechanicalError::ProtectedBoundary.into());
        }
        original.entered = true;
        original.before_result = Some((|| {
            self.require_same_journal(journal)?;
            if self.failure().is_some() {
                return Err(MechanicalError::ProtectedBoundary.into());
            }
            journal.validate_held_owned_at_for_uid_retaining(
                DIRECTORY,
                NAME,
                0,
                &mut original.before,
            )
        })());
        if matches!(original.before_result, Some(Ok(()))) {
            Ok(())
        } else {
            original.first.get_or_insert(First::Before);
            Err(MechanicalError::ProtectedBoundary.into())
        }
    }

    /// Attempts both already-paid native posts despite a failed primary.
    ///
    /// # Errors
    /// Retains changed original association, reentry or either native refusal.
    pub fn observe_inventory_currentness_after_owed_v2(
        &self,
        journal: &MountJournalV1,
        original: &mut MountInventoryJournalCurrentnessOriginalV2,
    ) -> Result<(), JournalError> {
        if original.before_result.is_none() || original.after_result.is_some() {
            original
                .reentry
                .get_or_insert(MechanicalError::ProtectedBoundary.into());
            original.first.get_or_insert(First::Reentry);
            return Err(MechanicalError::ProtectedBoundary.into());
        }
        original.after_result = Some((|| {
            self.require_same_journal(journal)?;
            if !original.entered {
                return Err(MechanicalError::ProtectedBoundary.into());
            }
            original.after.begin(false)?;
            let directory = journal
                .native
                .read_view_v1()
                .observe_directory_binding_into(Path::new(DIRECTORY), 0, &mut original.after);
            // Names are independently observed against the actual held
            // directory even when the fresh path traversal already failed.
            let names = journal
                .native
                .read_view_v1()
                .observe_names_into(&mut original.after);
            original.after.finish(directory.and(names))
        })());
        if matches!(original.after_result, Some(Ok(()))) {
            Ok(())
        } else {
            original.first.get_or_insert(First::After);
            Err(MechanicalError::ProtectedBoundary.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untransferred_opener_cannot_adopt_an_ordinary_writer_or_heal_its_refusal() {
        let directory = tempfile::tempdir().unwrap();
        let (journal, _) =
            MountJournalV1::open(directory.path().join(NAME), JournalLimits::default()).unwrap();
        let opener = MountStateCapturedJournalOpenV4::new();
        let mut original = MountInventoryJournalCurrentnessOriginalV2::default();

        assert!(
            opener
                .observe_inventory_currentness_before_v2(&journal, &mut original)
                .is_err()
        );
        let first = original.failure_v2().unwrap() as *const dyn Error;

        assert!(
            opener
                .observe_inventory_currentness_after_owed_v2(&journal, &mut original)
                .is_err()
        );
        assert!(std::ptr::addr_eq(
            first,
            original.failure_v2().unwrap() as *const dyn Error
        ));
        assert!(original.require_complete_v2().is_err());
        assert!(
            opener
                .observe_inventory_currentness_before_v2(&journal, &mut original)
                .is_err()
        );
        assert!(std::ptr::addr_eq(
            first,
            original.failure_v2().unwrap() as *const dyn Error
        ));
    }
}
