//! Keeps the independently owed Output sample distinct from action currentness.
//!
//! The actual lifecycle original prepays this sample before entering the
//! action. Its old initial-post reservoir remains available for that action's
//! separate bookend. Only the already armed sample can run after primary
//! poison; no healthy admission, new payment or native work can be reentered.

use super::*;

#[derive(Clone, Copy)]
enum First {
    Binding,
    ObserverPreparation,
    Names,
    Observer,
}

/// Retains one same-F Output post which is armed before the primary action.
///
/// Vacant construction admits nothing. The actual entered Storage lifecycle
/// alone binds its existing original and Output Journal identities and pays the
/// distinct native observer. A failed original never permits replacement.
#[must_use = "finish the prearmed post while all actual Output/action owners remain held"]
pub struct StorageOutputOwedAfterOriginalV1 {
    lifetime: Option<ObserverLifetime>,
    output: Option<crate::journal::StorageNativeOpeningOwnerLinkV1>,
    preparation: Option<Result<(), StorageReceivingClosedV1>>,
    binding: Option<Result<(), StorageReceivingClosedV1>>,
    names: Option<Result<(), StorageReceivingClosedV1>>,
    result: Option<Result<(), StorageReceivingClosedV1>>,
    first: Option<First>,
    entered: bool,
    armed: bool,
    names_entered: bool,
}

impl StorageOutputOwedAfterOriginalV1 {
    /// Creates vacant custody without observing, paying or admitting work.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            lifetime: None,
            output: None,
            preparation: None,
            binding: None,
            names: None,
            result: None,
            first: None,
            entered: false,
            armed: false,
            names_entered: false,
        }
    }

    /// Borrows only this original post's earliest retained refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        fn cause(slot: &Option<Result<(), StorageReceivingClosedV1>>)
            -> Option<&(dyn Error + 'static)>
        {
            slot.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        match self.first? {
            First::Binding => cause(&self.binding),
            First::ObserverPreparation => cause(&self.preparation),
            First::Names => cause(&self.names),
            First::Observer => cause(&self.result),
        }
    }
}

impl Default for StorageOutputOwedAfterOriginalV1 {
    fn default() -> Self { Self::new() }
}

impl Drop for StorageOutputOwedAfterOriginalV1 {
    fn drop(&mut self) {
        if self.armed || self.first.is_some() {
            // The real service terminates explicitly on a retained failure.
            // Unwind cannot silently discard an owed or negative native owner.
            std::process::abort();
        }
    }
}


impl StorageLifecycleSessionLoanV1<'_, '_> {
    /// Arms the same independent Output post from this paid Session Domain.
    ///
    /// # Errors
    /// Retains a repeated, foreign, unpaid or failed original and its debt.
    pub fn arm_output_owed_after_v1(&mut self, session: &crate::Journal,
        socket: &SeqpacketSocket, output: &crate::Journal, source: &std::path::Path,
        original: &mut StorageOutputOwedAfterOriginalV1) -> Result<(), StorageReceivingClosedV1> {
        if original.entered || original.first.is_some() { return Err(StorageReceivingClosedV1); }
        let binding = self.receiving.require_lifecycle_domain_current_v1(session, socket);
        self.receiving.arm_output_owed_after_v1_inner_v3(binding, output, source, original)
    }

    /// Observes only the actual prearmed Output names, including after poison.
    ///
    /// # Errors
    /// Retains substituted, repeated or failed native/name observations.
    pub fn observe_output_owed_names_once_v1(&mut self, original: &mut StorageOutputOwedAfterOriginalV1,
        output: &crate::Journal, names: &mut crate::journal::ProtectedJournalCurrentnessOriginalsV1,
        health: &mut Option<Result<(), crate::JournalError>>) -> Result<(), crate::JournalError> {
        self.receiving.observe_output_owed_names_once_v1_inner_v3(original, output, names, health)
    }

    /// Finishes only this original's independently prearmed Output observer.
    ///
    /// # Errors
    /// Retains missing debt, mismatched owner, or actual native/post refusal.
    pub fn finish_output_owed_after_once_v1(&mut self, original: &mut StorageOutputOwedAfterOriginalV1)
        -> Result<(), StorageReceivingClosedV1> {
        self.receiving.finish_output_owed_after_once_v1_inner_v3(original)
    }

    /// Borrows the same original financial/native Output cause.
    #[must_use]
    pub fn output_owed_after_failure_v1<'cause>(&'cause self, original: &'cause StorageOutputOwedAfterOriginalV1)
        -> Option<&'cause (dyn Error + 'static)> {
        self.receiving.output_owed_after_failure_v1_inner_v3(original)
    }

    /// Closes this original after its retained Output sample refused.
    pub fn close_output_owed_currentness_v1(&mut self) {
        self.receiving.close_output_owed_currentness_v1_inner_v3();
    }
}

impl super::super::StoragePrepareReceivingLoanV1<'_> {
    /// Arms a distinct Output post from this same current paid operation.
    ///
    /// The caller separately prepays its concrete Output native sampler. This
    /// method fixes the actual Journal and original lifetime and charges the
    /// sole existing native service-observer recipe before primary growth.
    ///
    /// # Errors
    /// Refuses another Session, Output writer/source, prior pending post,
    /// repeated entry, earlier refusal or same-ledger capacity exhaustion.
    pub(in crate::normal_root::storage_worker_origin::receiving) fn arm_output_owed_after_v1_inner_v3(
        &mut self,
        binding: Result<(), StorageReceivingClosedV1>,
        output: &crate::Journal,
        source: &std::path::Path,
        original: &mut StorageOutputOwedAfterOriginalV1,
    ) -> Result<(), StorageReceivingClosedV1> {
        if original.entered || original.first.is_some() {
            return Err(StorageReceivingClosedV1);
        }
        original.entered = true;
        original.binding = Some(binding.and_then(|_| self.require_retained_output_journal_v1(output, source)));
        if !matches!(original.binding, Some(Ok(()))) {
            original.first = Some(First::Binding);
            return Err(StorageReceivingClosedV1);
        }
        let receiving = self.receiving()?;
        original.lifetime = Some(receiving.lifetime.clone());
        original.output = Some(output.held_session_owner_link_v1());
        if receiving.lifecycle.output_after_pending {
            original.binding = Some(Err(StorageReceivingClosedV1));
            original.first = Some(First::Binding);
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        if receiving.output_after_local_reservation.is_none() {
            // This distinct reservoir shares the exact existing fixed native
            // names. Its bytes/files/tasks remain co-live with action failure;
            // no second charge is made for those already paid namespaces.
            receiving.output_after_local_demand = Some(super::super::observer_operation::independent_local_post_demand_v1()
                .map(|demand| demand.with(D::MetadataEntries, 0)));
            let Some(Ok(local)) = receiving.output_after_local_demand.as_ref().copied() else {
                original.preparation = Some(Err(StorageReceivingClosedV1));
                original.first = Some(First::ObserverPreparation);
                receiving.first.get_or_insert(Failure::OutputAfter);
                return Err(StorageReceivingClosedV1);
            };
            receiving.output_after_local_reservation = Some(receiving.reserve(local));
            if !matches!(receiving.output_after_local_reservation, Some(Ok(()))) {
                original.preparation = Some(Err(StorageReceivingClosedV1));
                original.first = Some(First::ObserverPreparation);
                return Err(StorageReceivingClosedV1);
            }
        }
        original.preparation = Some(receiving.output_after.prepare_once_v1(&mut receiving.ledger, &receiving.lifetime));
        if !matches!(original.preparation, Some(Ok(()))) {
            original.first = Some(First::ObserverPreparation);
            receiving.first.get_or_insert(Failure::OutputAfter);
            return Err(StorageReceivingClosedV1);
        }
        original.armed = true;
        receiving.lifecycle.output_after_pending = true;
        Ok(())
    }

    /// Observes only the same prearmed Output writer's actual names after action.
    ///
    /// Health refusal is retained first, but does not suppress the independent
    /// actual name observation. No new service interval is armed here.
    ///
    /// # Errors
    /// Refuses another original/writer, repeat entry, unarmed debt, or actual
    /// journal-health and retained native name failures.
    pub(in crate::normal_root::storage_worker_origin::receiving) fn observe_output_owed_names_once_v1_inner_v3(
        &mut self,
        original: &mut StorageOutputOwedAfterOriginalV1,
        output: &crate::Journal,
        names: &mut crate::journal::ProtectedJournalCurrentnessOriginalsV1,
        health: &mut Option<Result<(), crate::JournalError>>,
    ) -> Result<(), crate::JournalError> {
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.original.recipient.as_mut()
        else { return Err(crate::JournalError::ProtectedBoundary); };
        if !original.armed || original.names_entered || health.is_some()
            || !receiving.lifecycle.output_after_pending
            || !original.lifetime.as_ref().is_some_and(|lifetime| lifetime.same_original(&receiving.lifetime))
            || !original.output.as_ref().is_some_and(|held| held.same_journal(output))
        {
            original.names = Some(Err(StorageReceivingClosedV1));
            original.first.get_or_insert(First::Names);
            return Err(crate::JournalError::ProtectedBoundary);
        }
        original.names_entered = true;
        *health = Some(output.ensure_healthy());
        let observed = output.observe_held_names_post_retaining_v1(names);
        let healthy = !matches!(health, Some(Err(_)));
        original.names = Some(if healthy && observed.is_ok() { Ok(()) } else { Err(StorageReceivingClosedV1) });
        if !healthy || observed.is_err() { original.first.get_or_insert(First::Names); }
        if !healthy { Err(crate::JournalError::Poisoned) } else { observed }
    }

    /// Finishes only the exact observer paid before this operation's action.
    ///
    /// This reaches the same real currentness engine after primary poison and
    /// cannot clear the original's first refusal or admit another operation.
    ///
    /// # Errors
    /// Refuses missing/repeated debt, substituted original lifetime, unfinished
    /// Output names, or actual native/service/containment post failure.
    pub(in crate::normal_root::storage_worker_origin::receiving) fn finish_output_owed_after_once_v1_inner_v3(
        &mut self,
        original: &mut StorageOutputOwedAfterOriginalV1,
    ) -> Result<(), StorageReceivingClosedV1> {
        let Some(StorageResourceRecipientCustodyV1::Receiving { component, receiving }) =
            self.original.recipient.as_mut()
        else { return Err(StorageReceivingClosedV1); };
        if !original.armed || !receiving.lifecycle.output_after_pending
            || !original.lifetime.as_ref().is_some_and(|lifetime| lifetime.same_original(&receiving.lifetime))
        { return Err(StorageReceivingClosedV1); }
        original.armed = false;
        receiving.lifecycle.output_after_pending = false;
        let initial = receiving.before.as_ref().and_then(|result| result.as_ref().ok());
        original.result = Some(match initial {
            Some(initial) => receiving.output_after.observe_prepared_once_v1(
                &receiving.lifetime, &self.original.custody, component, initial, &receiving.containment,
            ),
            None => Err(StorageReceivingClosedV1),
        });
        if !matches!(original.result, Some(Ok(()))) || !original.names_entered {
            original.first.get_or_insert(First::Observer);
        }
        if original.first.is_some() {
            receiving.first.get_or_insert(Failure::OutputAfter);
            self.original.open = false;
            return Err(StorageReceivingClosedV1);
        }
        Ok(())
    }

    /// Borrows this exact final post's original financial or native refusal.
    ///
    /// An unrelated later service failure cannot replace a source, credential
    /// or name primary retained by the actual Output sampler.
    #[must_use]
    pub(in crate::normal_root::storage_worker_origin::receiving) fn output_owed_after_failure_v1_inner_v3<'cause>(
        &'cause self,
        original: &'cause StorageOutputOwedAfterOriginalV1,
    ) -> Option<&'cause (dyn Error + 'static)> {
        let StorageResourceRecipientCustodyV1::Receiving { receiving, .. } =
            self.original.recipient.as_ref()? else { return None; };
        if !original.lifetime.as_ref().is_some_and(|lifetime| lifetime.same_original(&receiving.lifetime)) {
            return original.failure();
        }
        match original.first? {
            First::ObserverPreparation => receiving.output_after_local_demand.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error)
                .or_else(|| receiving.ledger.failure().map(|cause| cause as &dyn Error))
                .or_else(|| receiving.output_after.failure()).or_else(|| original.failure()),
            First::Observer => receiving.output_after.failure().or_else(|| original.failure()),
            _ => original.failure(),
        }
    }

    /// Closes the actual original after its retained Output sampler refused.
    ///
    /// This negative-only transition issues no IO, rearms nothing and leaves
    /// its already prepaid independent service observation available.
    pub(in crate::normal_root::storage_worker_origin::receiving) fn close_output_owed_currentness_v1_inner_v3(&mut self) {
        self.close_output_currentness_v1();
    }
}
