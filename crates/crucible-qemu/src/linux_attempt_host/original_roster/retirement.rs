//! Retires an exclusive native roster before returning its original pairs.
//!
//! Final retirement accepts no caller cleanup assertion. Every live slot and
//! control must already have completed its physical close, and atomic Arc
//! uniqueness excludes both strong owners and weak factory bindings. Paired
//! credit moves into the externally prepaid roster facade before that Arc is
//! freed. A late original refusal keeps those same pairs there.

use super::*;

impl OriginalNativeAccountRoster {
    /// Frees the closed roster before releasing its original native pairs.
    ///
    /// This closes only native roster custody. It does not certify retirement
    /// of the actor process, its SQLite heap, Source, namespace or parent owner.
    /// Repeating a successful close has no effects. Refusal retains the same
    /// roster or external pairs; it does not reopen any slot or birth.
    ///
    /// # Errors
    /// Refuses remaining strong or weak bindings, poisoned bookkeeping, live
    /// native slots or controls, and the retained original before pair release.
    pub fn try_close(&mut self) -> Result<(), OriginalActorAccountError> {
        self.retire_with_post_free(|| {})
    }

    fn retire_with_post_free(
        &mut self,
        post_free: impl FnOnce(),
    ) -> Result<(), OriginalActorAccountError> {
        if let Some(held) = self.held.as_mut() {
            if self.retiring_credits.iter().any(Option::is_some) {
                return Err(OriginalActorAccountError::Unavailable);
            }
            let state = Arc::get_mut(held)
                .ok_or(OriginalActorAccountError::Unavailable)?
                .get_mut()
                .map_err(|_| OriginalActorAccountError::Unavailable)?;
            for slot in &state.slots {
                verify_closed_slot(slot)?;
                if let Some(credit) = &slot.credit {
                    credit.require_original()?;
                }
            }

            for (slot, retained) in state.slots.iter_mut().zip(&mut self.retiring_credits) {
                *retained = slot.credit.take();
            }
            // The same pairs are now outside the allocation they financed.
            drop(self.held.take());
            post_free();
        }

        for retained in &mut self.retiring_credits {
            if let Some(credit) = retained {
                credit.retire_after_control_free()?;
            }
            *retained = None;
        }
        Ok(())
    }
}

fn verify_closed_slot(slot: &NativeSlot) -> Result<(), OriginalActorAccountError> {
    if slot.active.is_some()
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
    use crucible_linux_resource::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };

    #[test]
    fn weak_factory_binding_blocks_credit_release_until_actual_roster_free()
    -> Result<(), Box<dyn std::error::Error>> {
        let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
        let original = Arc::new(supervisor.begin(HostOperationClass::Preparation)?);
        let (credit, resident, metadata) = OriginalNativeAccountCredit::mechanism_credit(original)?;
        let (mut roster, binding) =
            OriginalNativeAccountRoster::publish([Some(credit), None, None, None], 1)?;

        assert!(roster.try_close().is_err());
        assert!(
            resident
                .reserve_native_pair(&metadata, 69, 1056, 1536 << 20, 512 << 20)
                .is_err()
        );
        drop(binding);
        roster.try_close()?;

        assert!(roster.held.is_none());
        assert!(roster.retiring_credits.iter().all(Option::is_none));
        let released = resident.reserve_native_pair(&metadata, 69, 1056, 1536 << 20, 512 << 20)?;
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

        assert!(
            resident
                .reserve_native_pair(&metadata, 69, 1056, 1536 << 20, 512 << 20)
                .is_err()
        );
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
        assert!(
            resident
                .reserve_native_pair(&metadata, 69, 1056, 1536 << 20, 512 << 20)
                .is_err()
        );
        Ok(())
    }
}
