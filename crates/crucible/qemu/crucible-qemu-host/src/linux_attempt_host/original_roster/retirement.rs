//! Retires an exclusive native roster before returning its original pairs.
//!
//! Final retirement accepts no caller cleanup assertion. Every live slot and
//! control must already have completed its physical close. Normal rosters seal
//! their funded upgrade gate and exclude real strong borrowers; an independent
//! Main charge keeps the entire Arc allocation paid through final Weak closure.
//! Legacy rosters require strong and weak uniqueness. Paired credit moves into
//! the prepaid external facade before the actual body dies. A late Original
//! refusal keeps those same pairs there.

use super::*;

impl OriginalNativeAccountRoster {
    /// Checks real closed slots without freeing this retained roster or credit.
    ///
    /// # Errors
    /// Refuses competing access, poison, live Source/Target custody or original.
    pub(in crate::linux_attempt_host) fn verify_quiescent(
        &self,
    ) -> Result<(), OriginalActorAccountError> {
        if let Some(held) = self.held.as_ref() {
            let state = held
                .try_lock()
                .map_err(|_| OriginalActorAccountError::Unavailable)?;
            for slot in &state.slots {
                verify_closed_slot(slot)?;
                if let Some(credit) = slot.credit.as_ref() {
                    credit.verify_quiescent_custody()?;
                }
            }
        }
        for credit in self.retiring_credits.iter().flatten() {
            credit.verify_quiescent_custody()?;
        }
        Ok(())
    }

    /// Frees the closed roster before releasing its original native pairs.
    ///
    /// This closes only native roster custody. It does not certify retirement
    /// of the actor process, its SQLite heap, Source, namespace or parent owner.
    /// Repeating a successful close has no effects. Refusal retains the same
    /// roster or external pairs; it does not reopen any slot or birth.
    ///
    /// # Errors
    /// Refuses real strong borrowers, unfunded weak bindings, poisoned or
    /// contended bookkeeping, live native slots or controls, and the retained
    /// Original before pair release.
    pub fn try_close(&mut self) -> Result<(), OriginalActorAccountError> {
        self.retry_failed_launch_bodies()?;
        self.retire_with_post_free(|| {})
    }

    pub(super) fn retry_failed_launch_bodies(&self) -> Result<(), OriginalActorAccountError> {
        let Some(held) = self.held.as_ref() else {
            return Ok(());
        };
        let count = held
            .try_lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?
            .slots
            .len();
        let mut returned = true;
        for index in 0..count {
            let retained = {
                let state = held
                    .try_lock()
                    .map_err(|_| OriginalActorAccountError::Unavailable)?;
                state
                    .slots
                    .get(index)
                    .and_then(|slot| slot.source_controller.as_ref())
                    .cloned()
            };
            // No roster lock crosses process/RAM work or destroys its aliases.
            if let Some(retained) = retained {
                returned &= retained.retry_physical_cleanup();
            }
        }
        // Body return alone does not free the shared failure report or attest
        // Source account closure. Existing exact alias/control checks follow.
        if returned {
            Ok(())
        } else {
            Err(OriginalActorAccountError::Unavailable)
        }
    }

    fn retire_with_post_free(
        &mut self,
        post_free: impl FnOnce(),
    ) -> Result<(), OriginalActorAccountError> {
        if let Some(held) = self.held.as_mut() {
            if self.retiring_credits.iter().any(Option::is_some) {
                return Err(OriginalActorAccountError::Unavailable);
            }
            held.retire_body(
                |state| {
                    for slot in &state.slots {
                        verify_closed_slot(slot)?;
                        if let Some(credit) = &slot.credit {
                            credit.require_return_phase()?;
                        }
                    }
                    Ok(())
                },
                |state| {
                    for (slot, retained) in state.slots.iter_mut().zip(&mut self.retiring_credits) {
                        *retained = slot.credit.take();
                    }
                },
            )?;
            // The same pairs are now outside the allocation they financed.
            drop(self.held.take());
            post_free();
        }

        for retained in &mut self.retiring_credits {
            if let Some(credit) = retained {
                let result = credit.retire_after_control_free();
                if credit.is_physically_returned() {
                    *retained = None;
                }
                result?;
            }
            *retained = None;
        }
        Ok(())
    }

    pub(in crate::linux_attempt_host) fn is_physically_returned(&self) -> bool {
        self.held.is_none() && self.retiring_credits.iter().all(Option::is_none)
    }
}

fn verify_closed_slot(slot: &NativeSlot) -> Result<(), OriginalActorAccountError> {
    if slot.fork_target.is_owned()
        || slot.active.is_some()
        || slot.node_bindings_live != 0
        || slot
            .digest_purposes
            .iter()
            .any(device_digest::DigestPurposeState::is_live)
        || slot.launch_in_flight
        || slot.launch_abandoned
        || slot.launch_refusal.is_some()
        || slot.control.is_some()
        || slot.cleanup.is_some()
        || slot.unsettled.is_some()
    {
        return Err(OriginalActorAccountError::Unavailable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_host_resources::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };

    #[test]
    fn contended_cleanup_retains_the_same_binding_and_paired_credit()
    -> Result<(), Box<dyn std::error::Error>> {
        let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
        let original = Arc::new(supervisor.begin(HostOperationClass::Preparation)?);
        let (credit, resident, metadata) = OriginalNativeAccountCredit::mechanism_credit(original)?;
        let (mut roster, binding) =
            OriginalNativeAccountRoster::publish([Some(credit), None, None, None], 1)?;
        let held = binding
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let state = held
            .lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let credit = state.slots[0]
            .credit
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let address = std::ptr::from_ref(credit);

        // This is the actual binding's mutex, held in this same thread. A
        // blocking entry cannot reach the original-bound retirement checks.
        let error = roster
            .retry_unsettled()
            .expect_err("contended cleanup must refuse");
        let QemuVmRealizationError::ModelCopy { source } = error else {
            panic!("preserve the original typed roster refusal");
        };
        assert!(matches!(
            source.downcast_ref::<OriginalActorAccountError>(),
            Some(OriginalActorAccountError::Unavailable)
        ));
        assert!(std::ptr::eq(
            &**roster
                .held
                .as_ref()
                .ok_or(OriginalActorAccountError::Unavailable)?,
            &*held
        ));
        assert_eq!(
            std::ptr::from_ref(
                state.slots[0]
                    .credit
                    .as_ref()
                    .ok_or(OriginalActorAccountError::Unavailable)?
            ),
            address
        );
        assert!(OriginalNativeAccountCredit::reserve_mechanism_pair(&resident, &metadata).is_err());
        drop(source);
        drop(state);

        roster.retry_unsettled()?;
        roster.verify_quiescent()?;
        assert!(
            roster.try_close().is_err(),
            "the real binding still blocks release"
        );
        drop(held);
        drop(binding);
        roster.try_close()?;
        assert!(roster.is_physically_returned());
        drop(OriginalNativeAccountCredit::reserve_mechanism_pair(
            &resident, &metadata,
        )?);
        roster.try_close()?;
        Ok(())
    }

    #[test]
    fn quiescence_observation_preserves_real_roster_credit_and_factory_binding()
    -> Result<(), Box<dyn std::error::Error>> {
        let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
        let original = Arc::new(supervisor.begin(HostOperationClass::Preparation)?);
        let (credit, resident, metadata) = OriginalNativeAccountCredit::mechanism_credit(original)?;
        let (mut roster, binding) =
            OriginalNativeAccountRoster::publish([Some(credit), None, None, None], 1)?;

        roster.verify_quiescent()?;
        assert!(roster.held.is_some());
        assert!(roster.try_close().is_err());
        assert!(OriginalNativeAccountCredit::reserve_mechanism_pair(&resident, &metadata).is_err());

        let attempt = binding.claim(1, 512 << 20, 1 << 30)?;
        assert!(roster.verify_quiescent().is_err());
        drop(attempt);
        assert!(roster.verify_quiescent().is_err());
        drop(binding);
        assert!(roster.try_close().is_err());
        Ok(())
    }

    #[test]
    fn weak_factory_binding_blocks_credit_release_until_actual_roster_free()
    -> Result<(), Box<dyn std::error::Error>> {
        let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
        let original = Arc::new(supervisor.begin(HostOperationClass::Preparation)?);
        let (credit, resident, metadata) = OriginalNativeAccountCredit::mechanism_credit(original)?;
        let (mut roster, binding) =
            OriginalNativeAccountRoster::publish([Some(credit), None, None, None], 1)?;

        assert!(roster.try_close().is_err());
        assert!(OriginalNativeAccountCredit::reserve_mechanism_pair(&resident, &metadata).is_err());
        drop(binding);
        roster.try_close()?;

        assert!(roster.held.is_none());
        assert!(roster.retiring_credits.iter().all(Option::is_none));
        let released = OriginalNativeAccountCredit::reserve_mechanism_pair(&resident, &metadata)?;
        drop(released);
        roster.try_close()?;
        Ok(())
    }

    #[test]
    fn cancellation_after_roster_free_retains_the_same_external_pairs()
    -> Result<(), Box<dyn std::error::Error>> {
        let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
        let original = Arc::new(supervisor.begin(HostOperationClass::Preparation)?);
        let (credit, resident, metadata) = OriginalNativeAccountCredit::mechanism_credit(original)?;
        let (mut roster, binding) =
            OriginalNativeAccountRoster::publish([Some(credit), None, None, None], 1)?;
        drop(binding);

        let result = roster.retire_with_post_free(|| {
            assert!(supervisor.cancel().is_ok());
        });
        assert!(matches!(
            result,
            Err(OriginalActorAccountError::Supervision(_))
        ));
        assert!(roster.held.is_none());
        assert!(roster.retiring_credits[0].is_some());
        drop(roster);

        assert!(OriginalNativeAccountCredit::reserve_mechanism_pair(&resident, &metadata).is_err());
        Ok(())
    }

    #[test]
    fn an_abandoned_active_slot_refuses_even_after_all_aliases_drop()
    -> Result<(), Box<dyn std::error::Error>> {
        let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
        let original = Arc::new(supervisor.begin(HostOperationClass::Preparation)?);
        let (credit, resident, metadata) = OriginalNativeAccountCredit::mechanism_credit(original)?;
        let (mut roster, binding) =
            OriginalNativeAccountRoster::publish([Some(credit), None, None, None], 1)?;
        let attempt = binding.claim(1, 512 << 20, 1 << 30)?;
        drop(attempt);
        drop(binding);

        assert!(roster.try_close().is_err());
        assert!(roster.held.is_some());
        assert!(OriginalNativeAccountCredit::reserve_mechanism_pair(&resident, &metadata).is_err());
        Ok(())
    }
}
