//! Reuses fixed Producer pairs for provisioning and its prearmed completion.
//!
//! Slots0/1 serve the native turn; slots2/3 are separately paid and prearmed
//! before the final exchange for its completion. Each
//! Producer completes in one synchronous call using the ordinary private
//! thread dispatch and native engine. No thread-bound scope crosses an await;
//! the separate owed destination remains available after primary poison.

use super::*;

pub(in crate::controller_receiving) struct ProvisioningProfilePoolV1 {
    pub(super) states: [Mutex<ProfileState>; 4],
    controls: [Mutex<Option<ControllerControlScopeV1>>; 4],
}

impl ControllerBaselineProfileV1 {
    pub(in crate::controller_receiving) fn provisioning_demand_v1(&self)
        -> Result<ResourceVector, ControllerReceivingErrorV1>
    {
        let files = self.state.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?.files;
        let bytes = std::mem::size_of::<ProvisioningProfilePoolV1>().checked_mul(3)
            .ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
        let bytes = u64::try_from(bytes).map_err(|_| ControllerReceivingErrorV1::EnrollmentUnavailable)?;
        let one = Self::scope_demand(ScopeKind::Producer, files)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes).checked_add(one)?.checked_add(one)?)
    }

    pub(in crate::controller_receiving) fn prepare_provisioning_v1(
        &self, original: &Arc<ControllerReceivingOriginalV1>, first_slot: usize,
    ) -> Result<(), ControllerProfileErrorV1> {
        if !matches!(first_slot, 0 | 2) || !Arc::ptr_eq(&self.original, original) || self.is_nested()? {
            return Err(ControllerProfileErrorV1::Service);
        }
        let files = self.state.try_lock().map_err(|_| ControllerProfileErrorV1::Service)?.files;
        if self.provisioning_scopes.get().is_none() {
            // The actual same-C complete owner paid the whole body and its
            // construction overlap before this permanent shared allocation.
            let pool = ProvisioningProfilePoolV1 {
                states: std::array::from_fn(|_| Mutex::new(ProfileState::new())),
                controls: std::array::from_fn(|_| Mutex::new(None)),
            };
            self.provisioning_scopes.set(Box::new(pool)).map_err(|_| ControllerProfileErrorV1::Service)?;
        }
        let pool = self.provisioning_scopes.get().ok_or(ControllerProfileErrorV1::Service)?;
        // Only fully settled previous Producers leave empty states/controls.
        // A failed scope retains its exact native owners and blocks reuse.
        for index in first_slot..first_slot + 2 {
            let mut state = pool.states[index].try_lock().map_err(|_| ControllerProfileErrorV1::Service)?;
            let control = pool.controls[index].try_lock().map_err(|_| ControllerProfileErrorV1::Service)?;
            if state.scope.is_some() || state.failed_entry.is_some() || control.is_some() {
                return Err(ControllerProfileErrorV1::Service);
            }
            state.files = files;
        }
        let demand = Self::scope_demand(ScopeKind::Producer, files)
            .map_err(|_| ControllerProfileErrorV1::Service)?;
        for index in first_slot..first_slot + 2 {
            let mut control = pool.controls[index].try_lock().map_err(|_| ControllerProfileErrorV1::Service)?;
            *control = Some(if first_slot == 0 {
                original.arm_create_provisioning_control_v1(demand)
            } else {
                original.arm_create_provisioning_completion_control_v1(demand)
            });
        }
        Ok(())
    }

    pub(super) fn take_provisioning_control_v1(&self, slot: usize)
        -> Result<ControllerControlScopeV1, ControllerReceivingErrorV1>
    {
        let pool = self.provisioning_scopes.get().ok_or(ControllerReceivingErrorV1::Conflict)?;
        let mut control = pool.controls.get(slot).ok_or(ControllerReceivingErrorV1::Conflict)?
            .try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?
            .take().ok_or(ControllerReceivingErrorV1::Conflict)?;
        // Always return this whole owner, including failed preparation/read,
        // into ProfileScope before its caller interprets require_before.
        let _entered = control.start_prearmed_provisioning_v1();
        Ok(control)
    }

    pub(in crate::controller_receiving) fn run_provisioning_v1(
        &self, profile: &ControllerSelfProfileOriginalV1, slot: usize,
    ) -> Result<([u8; 16], [u8; 16]), ControllerProfileErrorV1> {
        if slot >= 4 || !profile.has_same_baseline_original(&self.original)
            || !matches!(profile.provisioning_scope_owner_v1(), Some(actual) if std::ptr::eq(actual.as_ref(), self))
        { return Err(ControllerProfileErrorV1::Service); }
        {
            let mut dispatch = self.provisioning_dispatch.try_lock().map_err(|_| ControllerProfileErrorV1::Service)?;
            if dispatch.is_some() { return Err(ControllerProfileErrorV1::Service); }
            *dispatch = Some((std::thread::current().id(), slot));
        }
        let entered = self.enter_receiving_dispatch();
        let returned = match entered {
            Ok(()) => {
                // Same Producer/local/property/control/Ended implementation;
                // a complete positive call really disposes its native scope.
                let returned = self.run_producer(|| profile.require_resource_producer());
                self.leave_receiving_dispatch();
                returned
            }
            Err(cause) => Err(cause),
        };
        match self.provisioning_dispatch.try_lock() {
            Ok(mut dispatch) => *dispatch = None,
            Err(_) => std::process::abort(),
        }
        returned
    }

    pub(in crate::controller_receiving) fn provisioning_failure_view_v1(
        &self, slot: usize,
    ) -> Option<BaselineFailureView<'_>> {
        let state = self.provisioning_scopes.get()?.states.get(slot)?.try_lock().ok()?;
        let view = BaselineFailureView { state };
        view.cause().is_some().then_some(view)
    }
}

/// Owns actual shared scope custody while the semantic body yields elsewhere.
pub(in crate::controller_receiving) struct ProvisioningProfileOriginalV1 {
    baseline: Arc<ControllerBaselineProfileV1>,
    first_slot: usize,
    preparation: Result<(), ControllerProfileErrorV1>,
    before: Option<Result<([u8; 16], [u8; 16]), ControllerProfileErrorV1>>,
    after: Option<Result<([u8; 16], [u8; 16]), ControllerProfileErrorV1>>,
}

impl ProvisioningProfileOriginalV1 {
    pub(in crate::controller_receiving) fn prepare(profile: &ControllerSelfProfileOriginalV1,
        original: &Arc<ControllerReceivingOriginalV1>,
    ) -> Option<Self> {
        Self::prepare_pair_v1(profile, original, 0)
    }

    pub(in crate::controller_receiving) fn prepare_completion_v1(profile: &ControllerSelfProfileOriginalV1,
        original: &Arc<ControllerReceivingOriginalV1>,
    ) -> Option<Self> {
        Self::prepare_pair_v1(profile, original, 2)
    }

    fn prepare_pair_v1(profile: &ControllerSelfProfileOriginalV1,
        original: &Arc<ControllerReceivingOriginalV1>, first_slot: usize,
    ) -> Option<Self> {
        let baseline = Arc::clone(profile.provisioning_scope_owner_v1()?);
        let preparation = baseline.prepare_provisioning_v1(original, first_slot);
        Some(Self { baseline, first_slot, preparation, before: None, after: None })
    }

    pub(in crate::controller_receiving) fn require_same_profile(&self,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerReceivingErrorV1> {
        if !matches!(profile.provisioning_scope_owner_v1(), Some(actual) if Arc::ptr_eq(&self.baseline, actual)) {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        Ok(())
    }

    pub(in crate::controller_receiving) fn before_once(&mut self, profile: &ControllerSelfProfileOriginalV1)
        -> Result<(), ControllerProfileErrorV1>
    {
        if self.preparation.is_err() || self.before.is_some() || self.require_same_profile(profile).is_err() {
            return Err(ControllerProfileErrorV1::Service);
        }
        self.before = Some(self.baseline.run_provisioning_v1(profile, self.first_slot));
        if matches!(self.before, Some(Ok(_))) { Ok(()) } else { Err(ControllerProfileErrorV1::Service) }
    }

    pub(in crate::controller_receiving) fn require_active(&self, profile: &ControllerSelfProfileOriginalV1)
        -> Result<(), ControllerReceivingErrorV1>
    {
        self.require_same_profile(profile)?;
        if self.preparation.is_err() || !matches!(self.before, Some(Ok(_))) || self.after.is_some() {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        Ok(())
    }

    // Comparison DATA is borrowed only while the actual paid native turn
    // remains active. The Recover Session retains that outer post obligation.
    pub(in crate::controller_receiving) fn active_pair_data_v1(
        &self, profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<([u8; 16], [u8; 16]), ControllerReceivingErrorV1> {
        self.require_active(profile)?;
        self.before.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or(ControllerReceivingErrorV1::Conflict)
    }

    pub(in crate::controller_receiving) fn require_completed_v1(&self,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerReceivingErrorV1> {
        self.require_same_profile(profile)?;
        if self.preparation.is_err() || !matches!(self.before, Some(Ok(_)))
            || !matches!(self.after, Some(Ok(_)))
        {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        let pool = self.baseline.provisioning_scopes.get()
            .ok_or(ControllerReceivingErrorV1::Conflict)?;
        if self.baseline.provisioning_dispatch.try_lock()
            .map_err(|_| ControllerReceivingErrorV1::Conflict)?.is_some()
        {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        for index in self.first_slot..self.first_slot + 2 {
            let state = pool.states[index].try_lock()
                .map_err(|_| ControllerReceivingErrorV1::Conflict)?;
            let control = pool.controls[index].try_lock()
                .map_err(|_| ControllerReceivingErrorV1::Conflict)?;
            if state.scope.is_some() || state.failed_entry.is_some() || control.is_some() {
                return Err(ControllerReceivingErrorV1::Conflict);
            }
        }
        Ok(())
    }

    pub(in crate::controller_receiving) fn after_once(&mut self, profile: &ControllerSelfProfileOriginalV1)
        -> Result<(), ControllerProfileErrorV1>
    {
        if self.preparation.is_err() || self.after.is_some() || self.require_same_profile(profile).is_err() {
            return Err(ControllerProfileErrorV1::Service);
        }
        self.after = Some(self.baseline.run_provisioning_v1(profile, self.first_slot + 1));
        if matches!(self.after, Some(Ok(_))) { Ok(()) } else { Err(ControllerProfileErrorV1::Service) }
    }

    pub(in crate::controller_receiving) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.preparation.as_ref().err().map(|cause| cause as _)
            .or_else(|| self.before.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.after.as_ref()?.as_ref().err().map(|cause| cause as _))
    }

    pub(in crate::controller_receiving) fn failure_view(&self) -> Option<BaselineFailureView<'_>> {
        if self.preparation.is_err() { return None; }
        let slot = if self.before.as_ref().is_some_and(Result::is_err) { self.first_slot }
            else if self.after.as_ref().is_some_and(Result::is_err) { self.first_slot + 1 }
            else { return None; };
        self.baseline.provisioning_failure_view_v1(slot)
    }
}

impl ControllerBaselineProfileV1 {
    pub(in crate::controller_receiving) fn provisioning_completion_demand_v1(&self)
        -> Result<ResourceVector, ControllerReceivingErrorV1> {
        let files = self.state.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?.files;
        let one = Self::scope_demand(ScopeKind::Producer, files)?;
        let bytes = std::mem::size_of::<ProvisioningProfileOriginalV1>().checked_mul(2)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
        one.checked_add(one)?.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes)).map_err(Into::into)
    }
}
