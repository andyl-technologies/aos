//! Joins the enrolled Network main to its fixed, independently limited aggregate.
//!
//! The origin continues to name the real daemon cgroup. A separate fixed native
//! capture proves the immutable aggregate and resolves that exact main beneath
//! it. The same F controls apply to both; retaining a relation creates no bank,
//! worker scope, physical credit or permission to issue an effect.

use std::error::Error;
use std::path::Path;

use aos_sandbox_core::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::cgroup::{CgroupV2Root, NetworkReceivingAggregateCgroupReadbackV4,
    RetainedCgroupAnchor, WorkerCgroupOpeningV1, WorkerCgroupOpeningRefusalV1};

use super::fixed_service_operation::FixedServiceOperationClosedV4 as Closed;
use super::receiving_limits::{ReceivingContainmentCurrentnessV1, ReceivingContainmentReadbackV1};

#[derive(Clone, Copy)]
enum First { Fixed, Descendant, Binding, InitialControls, FinalControls, ParentAfter, Order }

pub(super) struct NetworkReceivingAggregateOriginalV4 {
    fixed: NetworkReceivingAggregateCgroupReadbackV4,
    fixed_result: Option<Result<(), aos_sandbox_linux::Error>>,
    pair: Option<(CgroupV2Root, RetainedCgroupAnchor)>,
    main: WorkerCgroupOpeningV1,
    descendant: Option<Result<(), WorkerCgroupOpeningRefusalV1>>,
    binding: Option<Result<(), Closed>>,
    parent_after: Option<Result<(), WorkerCgroupOpeningRefusalV1>>,
    limits: ReceivingContainmentReadbackV1,
    result: Option<Result<(), Closed>>,
    first: Option<First>,
    closed: Closed,
    entered: bool,
}

impl NetworkReceivingAggregateOriginalV4 {
    pub(super) fn new() -> Self {
        Self { fixed: NetworkReceivingAggregateCgroupReadbackV4::new(), fixed_result: None,
            pair: None, main: WorkerCgroupOpeningV1::new(), descendant: None,
            binding: None, parent_after: None, limits: Default::default(), result: None,
            first: None, closed: Closed, entered: false }
    }

    pub(super) fn receiving_demand_v4() -> Result<ResourceVector, AccountingError> {
        let overflow = || AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes };
        let (fixed, files, names) = NetworkReceivingAggregateCgroupReadbackV4::receiving_obligations_v4()
            .ok_or_else(overflow)?;
        let fixed_residual = fixed.checked_sub(2 * std::mem::size_of::<NetworkReceivingAggregateCgroupReadbackV4>())
            .ok_or_else(overflow)?;
        let main_residual = WorkerCgroupOpeningV1::dominant_requested_bytes_v1()
            .and_then(|bytes| bytes.checked_sub(std::mem::size_of::<WorkerCgroupOpeningV1>())).ok_or_else(overflow)?;
        let controls = ReceivingContainmentReadbackV1::fixed_demand();
        let controls_residual = controls.get(D::MemoryBytes)
            .checked_sub(std::mem::size_of::<ReceivingContainmentReadbackV1>() as u64).ok_or_else(overflow)?;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<usize>()))
            .and_then(|bytes| bytes.checked_add(fixed_residual))
            .and_then(|bytes| bytes.checked_add(main_residual))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .and_then(|bytes| bytes.checked_add(controls_residual)).ok_or_else(overflow)?;
        let files = u64::try_from(files.checked_add(WorkerCgroupOpeningV1::MAXIMUM_RETAINED_FILES_V1)
            .ok_or_else(overflow)?).map_err(|_| overflow())?.checked_add(controls.get(D::OpenFiles)).ok_or_else(overflow)?;
        // The descendant names its literal child and the child/parent
        // cgroup.procs entries. Fields, retries and unused population slots
        // contribute no namespace entries; controls are separately named.
        let names = u64::try_from(names.checked_add(3)
            .ok_or_else(overflow)?).map_err(|_| overflow())?.checked_add(controls.get(D::MetadataEntries)).ok_or_else(overflow)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes).with(D::OpenFiles, files)
            .with(D::MetadataEntries, names))
    }

    pub(super) fn capture_once_v4(&mut self, enrolled_main: &RetainedCgroupAnchor,
        same_f: ResourceVector) -> Result<(), Closed> {
        if self.entered { self.first.get_or_insert(First::Order); return Err(Closed); }
        self.entered = true;
        self.result = Some(self.capture_inner_v4(enrolled_main, same_f));
        if matches!(self.result, Some(Ok(()))) { Ok(()) } else { Err(Closed) }
    }

    fn capture_inner_v4(&mut self, enrolled_main: &RetainedCgroupAnchor,
        same_f: ResourceVector) -> Result<(), Closed> {
        self.fixed_result = Some(self.fixed.capture_once());
        if !matches!(self.fixed_result, Some(Ok(()))) { self.first = Some(First::Fixed); return Err(Closed); }
        self.pair = self.fixed.take_validated_pair();
        let (_, aggregate) = self.pair.as_ref().ok_or(Closed)?;
        self.descendant = Some(self.main.capture_descendant_once(aggregate, Path::new("aos-netd.service")));
        if !matches!(self.descendant, Some(Ok(()))) { self.first = Some(First::Descendant); }
        if self.first.is_none() {
            self.binding = Some(match self.main.anchor() {
                Some(main) if main.kernel_id() == enrolled_main.kernel_id() => Ok(()),
                _ => Err(Closed),
            });
            if !matches!(self.binding, Some(Ok(()))) { self.first = Some(First::Binding); }
        }
        if self.first.is_none() {
            self.limits.capture(aggregate, same_f);
            if self.limits.require_initial().is_err() { self.first = Some(First::InitialControls); }
            // The independent controls after remains owed after failed capture.
            self.limits.recheck(aggregate);
            if self.limits.require_current().is_err() { self.first.get_or_insert(First::FinalControls); }
        }
        self.parent_after = Some(self.main.observe_owed_parent_once_v1(aggregate));
        if !matches!(self.parent_after, Some(Ok(()))) { self.first.get_or_insert(First::ParentAfter); }
        if self.first.is_some() { Err(Closed) } else { Ok(()) }
    }

    pub(super) fn require_current_data_v4(&self) -> Result<(), Closed> {
        if self.first.is_some() || !matches!(self.result, Some(Ok(())))
            || !matches!(self.binding, Some(Ok(()))) || !matches!(self.parent_after, Some(Ok(())))
            || self.pair.is_none() || self.limits.require_current().is_err()
        { Err(Closed) } else { Ok(()) }
    }

    pub(super) fn anchor_v4(&self) -> Result<&RetainedCgroupAnchor, Closed> {
        self.require_current_data_v4()?;
        self.pair.as_ref().map(|(_, anchor)| anchor).ok_or(Closed)
    }

    // A prepaid inventory after must still observe this SAME retained native
    // anchor after an earlier body/refusal. Its loan separately checks exact
    // original role, recipient, operation and both saved anchor identities.
    pub(super) fn retained_inventory_anchor_v4(&self) -> Option<&RetainedCgroupAnchor> {
        self.pair.as_ref().map(|(_, anchor)| anchor)
    }

    pub(super) fn observe_current_into_v4(&self, sample: &mut ReceivingContainmentCurrentnessV1)
        -> Result<(), Closed> {
        let anchor = self.pair.as_ref().map(|(_, anchor)| anchor).ok_or(Closed)?;
        self.limits.observe_current_into(anchor, sample);
        self.require_current_data_v4()?;
        sample.require_current().map_err(|_| Closed)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Fixed => self.fixed.failure(),
            First::Descendant | First::ParentAfter => self.main.failure(),
            First::InitialControls | First::FinalControls => self.limits.failure(),
            First::Binding | First::Order => None,
        }.or(Some(&self.closed))
    }
}
