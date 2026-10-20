//! Retains the completion interval paid before the final Root exchange.
//!
//! Slots2/3 use the same Producer engine as provisioning slots0/1. The actual
//! completed native original is rejoined after the upper typed ACK gate. No
//! post-ACK method starts a financial turn or raises its paid bound.

use super::*;

#[derive(Clone, Copy)]
enum FirstV1 { Admission, Profile, ArmBefore, ArmAfter, Entry, Before, ProfileBefore, After, ProfileAfter, Launch }

#[derive(Debug, thiserror::Error)]
#[error("the original completion native interval remains closed")]
struct ClosedV1;

/// Owns a prearmed same-C completion interval across the final Root exchange.
///
/// The genuine active native original alone constructs this destination. Each
/// Producer executes and disposes synchronously on its actual thread; only
/// owned results and immutable anchors cross the asynchronous handoff. This
/// mechanical owner authenticates neither an ACK nor a semantic append.
#[must_use = "retain the destination and finish every prearmed native post"]
pub struct ControllerCreateProvisioningCompletionDestinationV1 {
    original: Arc<ControllerReceivingOriginalV1>,
    identity: Arc<ControllerWriterIdentityV1>,
    turn_identity: Option<Arc<std::sync::atomic::AtomicBool>>,
    fixed: Result<ResourceVector, ControllerBankLaunchErrorV1>,
    admission: Result<(), ControllerBankLaunchErrorV1>,
    profile: Option<ProvisioningProfileOriginalV1>,
    before: ControllerWriterNameSampleV1,
    after: ControllerWriterNameSampleV1,
    arm_before: Option<Result<(), ControllerBankLaunchErrorV1>>,
    arm_after: Option<Result<(), ControllerBankLaunchErrorV1>>,
    entry: Option<Result<(), ControllerBankLaunchErrorV1>>,
    before_result: Option<Result<(), ControllerBankLaunchErrorV1>>,
    profile_before: Option<Result<(), ControllerProfileErrorV1>>,
    after_result: Option<Result<(), ControllerBankLaunchErrorV1>>,
    profile_after: Option<Result<(), ControllerProfileErrorV1>>,
    launch: Option<Result<(), ControllerBankLaunchErrorV1>>,
    first: Option<FirstV1>,
    finished: bool,
}

impl ControllerCreateProvisioningCompletionDestinationV1 {
    /// Prices the actual owner, two names and two complete Producers.
    ///
    /// # Errors
    /// Refuses absent original profile custody or checked geometry overflow.
    pub fn receiving_demand_v1(profile: &ControllerSelfProfileOriginalV1)
        -> Result<ResourceVector, ControllerBankLaunchErrorV1> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes)
            .checked_add(ControllerWriterNameSampleV1::fixed_demand_v1()?)?
            .checked_add(ControllerWriterNameSampleV1::fixed_demand_v1()?)?
            .checked_add(profile.provisioning_completion_receiving_demand_v1()?)?)
    }

    fn same_writer<P>(&self, writer: &ControllerCoordinatorWriterV1<P>) -> bool {
        Arc::ptr_eq(&self.identity, writer.fixed.identity())
            && writer.fixed.has_original(&self.original)
    }

    fn require_original_v1<P>(&self, completed: &ControllerCreateProvisioningReceivingV1,
        writer: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if !self.same_writer(writer) || !Arc::ptr_eq(&self.original, &completed.original)
            || !matches!((&self.turn_identity, &completed.turn_identity),
                (Some(held), Some(actual)) if Arc::ptr_eq(held, actual)) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        completed.require_completed_original_v1(writer, launch, profile)
    }

    /// Enters the prearmed interval beside the actual completed native original.
    ///
    /// The upper Bank first checks its typed Root completion and ordinal. This
    /// adds no semantic permission: it joins the same native turn, C, physical
    /// writer, confirmed launch and profile, then uses the existing engines.
    ///
    /// # Errors
    /// Retains changed custody, reentry, names or actual Producer refusal.
    pub fn enter_after_completed_original_once_v1<P>(&mut self,
        completed: &ControllerCreateProvisioningReceivingV1,
        writer: &mut ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.entry.is_some() || self.finished || self.after_result.is_some() || self.profile_after.is_some() {
            self.first.get_or_insert(FirstV1::Entry);
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.entry = Some((|| {
            if self.first.is_some() { return Err(ControllerBankLaunchErrorV1::Conflict); }
            self.require_original_v1(completed, writer, launch, profile)?;
            self.profile.as_ref().ok_or(ControllerBankLaunchErrorV1::Conflict)?.require_same_profile(profile)?;
            Ok(())
        })());
        if !matches!(self.entry, Some(Ok(()))) {
            self.first.get_or_insert(FirstV1::Entry);
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }

        self.before_result = Some(writer.fixed.finish_owed_name_sample(&mut self.before));
        if !matches!(self.before_result, Some(Ok(()))) {
            self.first.get_or_insert(FirstV1::Before);
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.profile_before = Some(match self.profile.as_mut() {
            Some(held) => held.before_once(profile),
            None => Err(ControllerProfileErrorV1::Service),
        });
        if !matches!(self.profile_before, Some(Ok(()))) {
            self.first.get_or_insert(FirstV1::ProfileBefore);
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(())
    }

    /// Rejoins the same completed original during the already-paid body.
    ///
    /// # Errors
    /// Refuses missing/failed entry, completed interval or foreign custody.
    pub fn require_current_v1<P>(&self, completed: &ControllerCreateProvisioningReceivingV1,
        writer: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.first.is_some() || self.finished || self.after_result.is_some()
            || !matches!(self.entry, Some(Ok(())))
            || !matches!(self.before_result, Some(Ok(())))
            || !matches!(self.profile_before, Some(Ok(()))) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.require_original_v1(completed, writer, launch, profile)?;
        self.profile.as_ref().ok_or(ControllerBankLaunchErrorV1::Conflict)?.require_active(profile)?;
        Ok(())
    }

    /// Runs the independent prearmed names and Producer after any body result.
    ///
    /// Healthy entry and upper ACK success do not gate these owed observations.
    /// Changed/ambiguous results fence the same C writer; actual results and
    /// native partials stay resident. Native completion grants no semantic CAS.
    ///
    /// # Errors
    /// Retains earlier refusal, missing entry, failed posts or changed launch.
    pub fn finish_native_once<P>(&mut self, writer: &mut ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.after_result.is_some() || self.profile_after.is_some() || self.finished
            || !self.same_writer(writer)
            || self.profile.as_ref().is_some_and(|held| held.require_same_profile(profile).is_err()) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        if matches!(self.arm_after, Some(Ok(()))) {
            self.after_result = Some(writer.fixed.finish_owed_name_sample(&mut self.after));
            if !matches!(self.after_result, Some(Ok(()))) { self.first.get_or_insert(FirstV1::After); }
        }
        if let Some(held) = self.profile.as_mut() {
            self.profile_after = Some(held.after_once(profile));
            if !matches!(self.profile_after, Some(Ok(()))) { self.first.get_or_insert(FirstV1::ProfileAfter); }
        }
        self.launch = Some(launch.require_current_recipient(&writer.fixed));
        if !matches!(self.launch, Some(Ok(()))) { self.first.get_or_insert(FirstV1::Launch); }
        if self.first.is_some() || !matches!(self.entry, Some(Ok(())))
            || !matches!(self.before_result, Some(Ok(())))
            || !matches!(self.profile_before, Some(Ok(())))
            || !matches!(self.after_result, Some(Ok(())))
            || !matches!(self.profile_after, Some(Ok(()))) {
            self.first.get_or_insert(FirstV1::Entry);
            writer.fixed.fence();
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.before.dispose_after_complete_interval();
        self.after.dispose_after_complete_interval();
        // Only this actual positively disposed owner releases the original's
        // pending completion obligation. No public completion flag is accepted.
        self.turn_identity.as_ref().ok_or(ControllerBankLaunchErrorV1::Conflict)?
            .store(true, std::sync::atomic::Ordering::Release);
        self.finished = true;
        Ok(())
    }

    /// Rejoins the whole positively disposed completion interval without IO.
    ///
    /// # Errors
    /// Refuses unfinished/failed names, Producer, launch or original custody.
    pub fn require_completed_original_v1<P>(&self,
        completed: &ControllerCreateProvisioningReceivingV1,
        writer: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if !self.finished || self.first.is_some()
            || !self.before.has_disposed_complete_interval_v1()
            || !self.after.has_disposed_complete_interval_v1() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.require_original_v1(completed, writer, launch, profile)?;
        self.profile.as_ref().ok_or(ControllerBankLaunchErrorV1::Conflict)?.require_completed_v1(profile)?;
        Ok(())
    }

    /// Borrows the actual first retained native or profile cause.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let selected = match self.first? {
            FirstV1::Admission => error(&self.fixed).or_else(|| error(&self.admission)),
            FirstV1::Profile | FirstV1::ProfileBefore | FirstV1::ProfileAfter => self.profile.as_ref().and_then(ProvisioningProfileOriginalV1::failure),
            FirstV1::ArmBefore => self.arm_before.as_ref().and_then(error),
            FirstV1::ArmAfter => self.arm_after.as_ref().and_then(error),
            FirstV1::Entry => self.entry.as_ref().and_then(error),
            FirstV1::Before => self.before.failure().or_else(|| self.before_result.as_ref().and_then(error)),
            FirstV1::After => self.after.failure().or_else(|| self.after_result.as_ref().and_then(error)),
            FirstV1::Launch => self.launch.as_ref().and_then(error),
        };
        selected.or(Some(&ClosedV1 as &(dyn Error + 'static)))
    }

    /// Borrows the rich profile view only at its selected original frontier.
    #[must_use]
    pub fn profile_failure_view_v1(&self)
        -> Option<crate::controller_receiving::profile::ControllerProfileFailureViewV1<'_>> {
        if !matches!(self.first, Some(FirstV1::Profile | FirstV1::ProfileBefore | FirstV1::ProfileAfter)) { return None; }
        Some(crate::controller_receiving::profile::ControllerProfileFailureViewV1::from_baseline_v1(
            self.profile.as_ref()?.failure_view()?,
        ))
    }
}

impl ControllerCreateProvisioningReceivingV1 {
    /// Prepays and arms one completion destination before the final exchange.
    ///
    /// The whole return retains an admission refusal. The trusted upper Bank
    /// includes every future Source/C append representation and traffic bound
    /// in `complete`; nothing may raise or rearm this destination after ACK.
    /// This is a native mechanism, not an ACK or append permission factory.
    #[must_use]
    pub fn prearm_completion_destination_once_v1<P>(&mut self,
        writer: &mut ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1, complete: ResourceVector,
    ) -> ControllerCreateProvisioningCompletionDestinationV1 {
        let repeated = self.completion_claimed;
        self.completion_claimed = true;
        let fixed = ControllerCreateProvisioningCompletionDestinationV1::receiving_demand_v1(profile);
        let admission = (|| {
            if repeated { return Err(ControllerBankLaunchErrorV1::Conflict); }
            self.require_current_v1(writer, launch, profile)?;
            let fixed = *fixed.as_ref().map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
            self.require_complete_representation_v1(writer, launch, profile, complete.checked_add(fixed)?)
        })();
        let first = admission.is_err().then_some(FirstV1::Admission);
        let mut destination = ControllerCreateProvisioningCompletionDestinationV1 {
            original: Arc::clone(&self.original), identity: Arc::clone(&self.identity),
            turn_identity: self.turn_identity.as_ref().map(Arc::clone), fixed, admission,
            profile: None, before: ControllerWriterNameSampleV1::new(), after: ControllerWriterNameSampleV1::new(),
            arm_before: None, arm_after: None, entry: None, before_result: None, profile_before: None,
            after_result: None, profile_after: None, launch: None, first, finished: false,
        };
        if destination.admission.is_ok() {
            destination.profile = ProvisioningProfileOriginalV1::prepare_completion_v1(profile, &self.original);
            if destination.profile.as_ref().is_none_or(|held| held.failure().is_some()) {
                destination.first = Some(FirstV1::Profile);
                return destination;
            }
            destination.arm_before = Some(writer.fixed.begin_name_sample(&mut destination.before));
            if !matches!(destination.arm_before, Some(Ok(()))) { destination.first.get_or_insert(FirstV1::ArmBefore); }
            destination.arm_after = Some(writer.fixed.begin_name_sample(&mut destination.after));
            if !matches!(destination.arm_after, Some(Ok(()))) { destination.first.get_or_insert(FirstV1::ArmAfter); }
        }
        destination
    }
}

impl Drop for ControllerCreateProvisioningCompletionDestinationV1 {
    fn drop(&mut self) {
        if !self.finished {
            // Match the same C native original: abandonment must not discard
            // an owed/failed native prefix while its service continues.
            std::process::abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_completion_destination_crosses_the_runtime_async_handoff() {
        fn requires_send<T: Send>() {}
        requires_send::<ControllerCreateProvisioningCompletionDestinationV1>();
    }
}
