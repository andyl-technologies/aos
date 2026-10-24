//! Funds the actual Mount/Network bootstrap and its independent native posts.

use std::error::Error;

use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_model::component_receiving::complete_bound_delta_v1;

use super::fixed_service_currentness::FixedServiceCurrentnessSampleV1;
use super::fixed_service_operation::FixedServiceOperationClosedV4 as Closed;
use super::fixed_service_receiving::{FixedServiceReceivingCaptureV1, FixedServiceRoleV1};
use super::representation::RepresentationDemandDebitV1;

#[derive(Clone, Copy)]
enum Failure { Before, Funding, Body, After, Order }

pub(super) struct FixedServiceStartupOriginalV4 {
    committed: ResourceVector,
    additive_geometry: Option<Result<ResourceVector, AccountingError>>,
    before: FixedServiceCurrentnessSampleV1<Closed>,
    before_result: Option<Result<(), Closed>>,
    after: FixedServiceCurrentnessSampleV1<Closed>,
    after_result: Option<Result<(), Closed>>,
    body: Option<Result<(), Closed>>,
    first: Option<Failure>,
    finished: bool,
    closed: Closed,
}

impl FixedServiceStartupOriginalV4 {
    fn new(committed: ResourceVector) -> Self {
        Self { committed, additive_geometry: None, before: Default::default(), before_result: None,
            after: Default::default(), after_result: None, body: None,
            first: None, finished: false, closed: Closed }
    }

    fn native_demand(role: FixedServiceRoleV1) -> Result<ResourceVector, AccountingError> {
        let sample = FixedServiceCurrentnessSampleV1::<Closed>::dynamic_demand()?;
        let bytes = std::mem::size_of::<Self>().checked_add(2 * std::mem::size_of::<usize>())
            .and_then(|bytes| bytes.checked_mul(2)).and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
        let native = sample.checked_add(sample)?.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))?;
        if matches!(role, FixedServiceRoleV1::Network) {
            let aggregate = FixedServiceCurrentnessSampleV1::<Closed>::network_aggregate_dynamic_demand_v4()?;
            native.checked_add(aggregate)?.checked_add(aggregate)
        } else { Ok(native) }
    }

    pub(super) fn committed_files(&self) -> u64 { self.committed.get(D::OpenFiles) }

    pub(super) fn before_complete(&self) -> bool {
        self.first.is_none() && matches!(self.before_result, Some(Ok(())))
    }

    pub(super) fn complete(&self) -> bool {
        self.finished && self.first.is_none()
            && matches!(self.before_result, Some(Ok(())))
            && matches!(self.after_result, Some(Ok(()))) && matches!(self.body, Some(Ok(())))
    }
}

impl FixedServiceReceivingCaptureV1<Closed> {
    /// Checks the same genuine Mount startup before a closed native preparation.
    ///
    /// This passive rejoin performs no IO and grants no endpoint or effect.
    ///
    /// # Errors
    /// Refuses another role, missing native before, completed startup or poison.
    pub fn require_mount_startup_current_v4(&self) -> Result<(), Closed> {
        self.require_role_startup_current(FixedServiceRoleV1::Mount)
    }

    /// Checks the same genuine Network startup before its native preparation.
    ///
    /// # Errors
    /// Refuses another role, missing native before, completed startup or poison.
    pub fn require_network_startup_current_v4(&self) -> Result<(), Closed> {
        self.require_role_startup_current(FixedServiceRoleV1::Network)
    }

    pub(super) fn require_boot_preparation_startup_current_v1(&self) -> Result<(), Closed> {
        self.require_role_startup_current(FixedServiceRoleV1::BootPreparation)
    }

    /// Borrows this same image-enrolled Network service's invocation identity.
    ///
    /// The value supplies per-service catalog instance DATA, not a secret,
    /// operation, native descriptor or receiving permission. It is available
    /// only inside the genuinely entered unfinished Network startup interval.
    ///
    /// # Errors
    /// Refuses another role, absent/failed native startup or a reserved identity.
    #[doc(hidden)]
    pub fn network_startup_invocation_data_v4(&self) -> Result<[u8; 16], Closed> {
        self.require_network_startup_current_v4()?;
        let invocation = self.enrollment.as_ref().ok_or(Closed)?.recipient_invocation;
        if invocation == [0; 16] { return Err(Closed); }
        Ok(invocation)
    }

    fn require_role_startup_current(&self, role: FixedServiceRoleV1) -> Result<(), Closed> {
        if self.role != role || self.operation_closed || self.operation_active
            || self.require_permanent_fd_coverage_v1().is_err()
            || self.enrollment.is_none()
            || !self.service_startup.as_ref().is_some_and(|owner| owner.before_complete() && !owner.finished)
            || self.representation.as_ref().is_none_or(|ledger| ledger.failure().is_some())
        { return Err(Closed); }
        Ok(())
    }

    /// Admits cumulative startup cost DATA on the actual Mount/Network F owner.
    ///
    /// The complete shape includes every external config/Journal/Store native
    /// prefix, model and real namespace. This helper separately joins its own
    /// compiled native posts and the original listener duplicate. It issues no
    /// endpoint, role, request or effect authority.
    ///
    /// # Errors
    /// Retains arithmetic or same-ledger refusal before allocation/native IO.
    /// Later refusal cannot suppress already armed independent startup posts.
    pub fn require_startup_representation_v4(&mut self, complete: ResourceVector) -> Result<(), Closed> {
        if self.operation_active || self.operation_closed
            || !matches!(self.role, FixedServiceRoleV1::Mount | FixedServiceRoleV1::Network
                | FixedServiceRoleV1::BootPreparation)
            || self.require_permanent_fd_coverage_v1().is_err()
            || self.service_startup.as_ref().is_some_and(|owner| owner.finished || owner.first.is_some())
        { self.operation_closed = true; return Err(Closed); }
        self.startup_admission = Some((|| {
            let requirement = FixedServiceStartupOriginalV4::native_demand(self.role)?.checked_add(complete)?;
            let previous = self.service_startup.as_ref().map_or(ResourceVector::ZERO, |owner| owner.committed);
            let (high, _) = complete_bound_delta_v1(previous, requirement)?;
            let attempted = self.fixed_startup_demand()?.get(D::OpenFiles)
                .checked_add(self.operation_files).and_then(|files| files.checked_add(high.get(D::OpenFiles)))
                .ok_or(AccountingError::ArithmeticOverflow { dimension: D::OpenFiles })?;
            let limit = self.permanent_open_files().map_err(|_| AccountingError::ArithmeticOverflow { dimension: D::OpenFiles })?;
            if attempted > limit { return Err(AccountingError::LimitExceeded { dimension: D::OpenFiles, limit, attempted }); }
            Ok(high)
        })());
        let high = match self.startup_admission.as_ref().and_then(|value| value.as_ref().ok()).copied() {
            Some(high) => high,
            None => { self.operation_closed = true; return Err(Closed); }
        };
        let previous = self.service_startup.as_ref().map_or(ResourceVector::ZERO, |owner| owner.committed);
        let delta = high.checked_sub(previous).map_err(|_| Closed)?;
        if !self.representation.as_mut().is_some_and(|ledger| ledger.reserve(delta.with(D::OpenFiles, 0)).is_ok()) {
            self.operation_closed = true;
            return Err(Closed);
        }
        match self.service_startup.as_mut() {
            Some(owner) => owner.committed = high,
            None => self.service_startup = Some(Box::new(FixedServiceStartupOriginalV4::new(high))),
        }
        Ok(())
    }

    /// Adds a co-live startup contribution to this same original's full bound.
    ///
    /// The prior committed external shape stays in the sum. The existing
    /// startup gate joins its native before/after backing exactly once; no
    /// account, role, native work or disposal credit follows from this DATA.
    ///
    /// # Errors
    /// Retains checked arithmetic or the same original ledger refusal before
    /// any caller allocation or native entry. A refused addition stays closed.
    pub fn require_additional_startup_representation_v4(
        &mut self, additional: ResourceVector,
    ) -> Result<(), Closed> {
        let Some(owner) = self.service_startup.as_mut() else {
            return self.require_startup_representation_v4(additional);
        };
        if owner.finished || owner.first.is_some() || self.operation_active || self.operation_closed {
            owner.first.get_or_insert(Failure::Order);
            self.operation_closed = true;
            return Err(Closed);
        }
        owner.additive_geometry = Some((|| {
            owner.committed.checked_sub(FixedServiceStartupOriginalV4::native_demand(self.role)?)?
                .checked_add(additional)
        })());
        let complete = match owner.additive_geometry.as_ref().and_then(|value| value.as_ref().ok()).copied() {
            Some(complete) => complete,
            None => {
                owner.first.get_or_insert(Failure::Funding);
                self.operation_closed = true;
                return Err(Closed);
            }
        };
        self.require_startup_representation_v4(complete)
    }

    /// Enters the already paid native startup bookend before config/Journal IO.
    ///
    /// # Errors
    /// Retains the actual native failure and closes positive operation entry.
    pub fn begin_startup_native_once_v4(&mut self) -> Result<(), Closed> {
        if self.operation_closed || self.require_permanent_fd_coverage_v1().is_err() { return Err(Closed); }
        let owner = self.service_startup.as_mut().ok_or(Closed)?;
        if owner.finished || owner.before_result.is_some() {
            owner.first.get_or_insert(Failure::Order);
            self.operation_closed = true;
            return Err(Closed);
        }
        owner.before_result = Some(observe_fields(&mut self.process, self.cgroup.as_ref(), &self.limits,
            self.process_before.as_ref(), self.membership.as_ref(), self.startup_currentness.captured_context(), self.network_aggregate.as_deref(), &mut owner.before));
        if !matches!(owner.before_result, Some(Ok(()))) {
            owner.first.get_or_insert(Failure::Before);
            self.operation_closed = true;
            return Err(Closed);
        }
        Ok(())
    }

    /// Runs both owed startup destinations and retains the actual body outcome.
    ///
    /// A caller always invokes this after successful initial admission, even
    /// when later debit/config/Journal/Store work failed. No native after checks
    /// a healthy financial guard. All observations stay on the same Common.
    ///
    /// # Errors
    /// Refuses missing/unfunded/repeated entry and keeps the earliest failure.
    pub fn finish_startup_native_once_v4(&mut self, body: Result<(), Closed>) -> Result<(), Closed> {
        let owner = self.service_startup.as_mut().ok_or(Closed)?;
        if owner.finished { owner.first.get_or_insert(Failure::Order); self.operation_closed = true; return Err(Closed); }
        owner.finished = true;
        if self.startup_admission.as_ref().is_some_and(Result::is_err)
            || self.representation.as_ref().is_some_and(|ledger| ledger.failure().is_some())
        { owner.first.get_or_insert(Failure::Funding); }
        owner.body = Some(body);
        if body.is_err() { owner.first.get_or_insert(Failure::Body); }
        if owner.before_result.is_none() {
            owner.before_result = Some(observe_fields(&mut self.process, self.cgroup.as_ref(), &self.limits,
                self.process_before.as_ref(), self.membership.as_ref(), self.startup_currentness.captured_context(), self.network_aggregate.as_deref(), &mut owner.before));
            if !matches!(owner.before_result, Some(Ok(()))) { owner.first.get_or_insert(Failure::Before); }
        }
        owner.after_result = Some(observe_fields(&mut self.process, self.cgroup.as_ref(), &self.limits,
            self.process_before.as_ref(), self.membership.as_ref(), self.startup_currentness.captured_context(), self.network_aggregate.as_deref(), &mut owner.after));
        if !matches!(owner.after_result, Some(Ok(()))) { owner.first.get_or_insert(Failure::After); }
        if !owner.complete() { self.operation_closed = true; return Err(Closed); }
        Ok(())
    }

    /// Borrows the first actual startup cause without reentering its readers.
    pub fn service_startup_failure_v4(&self) -> Option<&(dyn Error + 'static)> {
        let funding = || self.service_startup.as_ref()
            .and_then(|owner| owner.additive_geometry.as_ref())
            .and_then(|value| value.as_ref().err()).map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| self.startup_admission.as_ref().and_then(|value| value.as_ref().err())
            .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.representation.as_ref().and_then(|ledger| ledger.failure()).map(|cause| cause as _));
        if let Some(owner) = self.service_startup.as_ref() {
            match owner.first? {
                Failure::Before => owner.before.failure(),
                Failure::After => owner.after.failure(),
                Failure::Funding => funding(),
                _ => None,
            }.or(Some(&owner.closed))
        } else { funding() }
    }
}

// This is the exact existing currentness sampler, with no alternate observer.
fn observe_fields(
    process: &mut aos_sandbox_linux::pidfd::CurrentSelfPidFdCustodyV1,
    anchor: Option<&aos_sandbox_linux::cgroup::RetainedCgroupAnchor>,
    limits: &super::receiving_limits::ReceivingContainmentReadbackV1,
    identity: Option<&Result<aos_sandbox_linux::pidfd::PidFdProcessIdentity, aos_linux_descriptors::Error>>,
    info: Option<&Result<aos_linux_descriptors::pidfd::PidFdInfo, Closed>>,
    context: Option<&[u8]>,
    aggregate: Option<&super::network_receiving_aggregate::NetworkReceivingAggregateOriginalV4>,
    destination: &mut FixedServiceCurrentnessSampleV1<Closed>,
) -> Result<(), Closed> {
    let identity = identity.and_then(|value| value.as_ref().ok()).copied().ok_or(Closed)?;
    let info = info.and_then(|value| value.as_ref().ok()).copied().ok_or(Closed)?;
    match aggregate {
        Some(aggregate) => destination.observe_network_aggregate_once_v4(process, anchor.ok_or(Closed)?,
            limits, info, identity, context, false, aggregate),
        None => destination.observe_once(process, anchor.ok_or(Closed)?, limits, info, identity, context, false),
    }
}
