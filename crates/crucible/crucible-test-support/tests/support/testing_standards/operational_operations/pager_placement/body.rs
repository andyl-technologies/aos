//! Binds paid request storage and its closed placement/teardown journals.

use super::super::Companion;

pub(in super::super) const JOURNAL: Companion = Companion {
    path: "crates/crucible/crucible-qemu-plugin/src/paged_ram/engine/service/capture_work.rs",
    required: &[
        (
            r#"struct FaultWorkAllocation {
    pause: FaultPause,
    lifecycle: std::sync::atomic::AtomicU8,
    placement: AtomicBool,
    scratch_returned: AtomicBool,
    end_pending: AtomicBool,
    end_failed: AtomicBool,
    end: Mutex<physical_end::PhysicalEndCustody>,
    dispatch: PlacementDispatchJournal,
    work: Mutex<FaultWork>,
}

/// Retains actual placement call history independently of signed late failures.
///
/// These facts never issue Source or native physical-return authority. In
/// particular, a negative end records uncertainty rather than continued physical
/// exclusion. The existing body owns this inline history through failed Drop.
#[derive(Default)]
pub(in crate::paged_ram::engine) struct PlacementDispatchJournal {
    pub(in crate::paged_ram::engine) runner_entered: AtomicBool,
    pub(in crate::paged_ram::engine) runner_returned: AtomicBool,
    pub(in crate::paged_ram::engine) runner_status: std::sync::atomic::AtomicI32,
    pub(in crate::paged_ram::engine) callback_entered: AtomicBool,
    pub(in crate::paged_ram::engine) callback_returned: AtomicBool,
    pub(in crate::paged_ram::engine) callback_post_failed: AtomicBool,
    pub(in crate::paged_ram::engine) callback_status: std::sync::atomic::AtomicI32,
    pub(in crate::paged_ram::engine) begin_entered: AtomicBool,
    pub(in crate::paged_ram::engine) begin_returned: AtomicBool,
    pub(in crate::paged_ram::engine) begin_status: std::sync::atomic::AtomicI32,
    pub(in crate::paged_ram::engine) token: AtomicU64,
    pub(in crate::paged_ram::engine) end_entered: AtomicBool,
    pub(in crate::paged_ram::engine) end_returned: AtomicBool,
    pub(in crate::paged_ram::engine) end_status: std::sync::atomic::AtomicI32,
    pub(in crate::paged_ram::engine) action_completed: AtomicBool,
    pub(in crate::paged_ram::engine) settled: AtomicBool,
    first_negative: std::sync::atomic::AtomicI32,
}"#,
            1,
        ),
        (
            r#"pub(in crate::paged_ram::engine) fn reset(&self) -> Result<(), RamError> {
        if self.unresolved() {
            return Err(RamError::Invariant(
                "prior placement dispatch remains unsettled",
            ));
        }
        for flag in [
            &self.runner_entered,
            &self.runner_returned,
            &self.callback_entered,
            &self.callback_returned,
            &self.callback_post_failed,
            &self.begin_entered,
            &self.begin_returned,
            &self.end_entered,
            &self.end_returned,
            &self.action_completed,
            &self.settled,
        ] {
            flag.store(false, Ordering::Release);
        }
        for status in [
            &self.runner_status,
            &self.callback_status,
            &self.begin_status,
            &self.end_status,
            &self.first_negative,
        ] {
            status.store(0, Ordering::Release);
        }
        self.token.store(0, Ordering::Release);
        Ok(())
    }"#,
            1,
        ),
        (
            r#"pub(in crate::paged_ram::engine) fn record_first_negative(&self, status: i32) {
        if status < 0 {
            let _ = self.first_negative.compare_exchange(
                0,
                status,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
    }"#,
            1,
        ),
        (
            r#"pub(in crate::paged_ram::engine) fn retry_before_action(
        &self,
        status: i32,
        token: u64,
    ) -> bool {
        token == 0
            && !self.callback_post_failed.load(Ordering::Acquire)
            && !self.end_entered.load(Ordering::Acquire)
            && !self.action_completed.load(Ordering::Acquire)
            && matches!(status, value if value == -libc::EAGAIN || value == -libc::EBUSY)
    }"#,
            1,
        ),
        (
            r#"pub(in crate::paged_ram::engine) fn unresolved(&self) -> bool {
        self.runner_entered.load(Ordering::Acquire) && !self.settled.load(Ordering::Acquire)
    }"#,
            1,
        ),
    ],
};

pub(in super::super) const WORK_OWNER: Companion = Companion {
    path: "crates/crucible/crucible-qemu-plugin/src/paged_ram/engine/service/capture_work.rs",
    required: &[
        (
            r#"pub(super) struct ClaimedFault {
    event: FaultEvent,
    operation: Option<Box<dyn SourceOperation>>,
}

/// Owns the physical buffer even when no operation could be admitted.
pub(in crate::paged_ram::engine) struct FaultWork {
    claimed: Option<ClaimedFault>,
    receipt: FaultReceipt,
    scratch: [u8; PAGE_BYTES],
    eviction: Option<eviction::EvictionJournal>,
    failed: bool,
}"#,
            1,
        ),
        (
            r#"pub(super) fn claim(
        &mut self,
        event: FaultEvent,
        operations: &dyn SourceOperationFactory,
    ) -> Result<(), RamError> {
        if self.claimed.is_some() || self.eviction.is_some() || self.failed {
            return Err(RamError::Invariant("fault request remains unsettled"));
        }
        self.claimed = Some(ClaimedFault {
            event,
            operation: None,
        });
        let operation = match operations.begin(SourceOperationClass::PageIn) {
            Ok(operation) => operation,
            Err(error) => {
                let error = RamError::from(error);
                self.fail();
                return Err(error);
            }
        };
        let claim = self
            .claimed
            .as_mut()
            .ok_or("claimed fault disappeared during admission")?;
        claim.operation = Some(operation);
        Ok(())
    }"#,
            1,
        ),
        (
            r#"pub(super) fn settled(&mut self) -> Result<(), RamError> {
        if self.failed
            || self.eviction.is_some()
            || self
                .claimed
                .as_ref()
                .is_none_or(|claim| claim.operation.is_none())
        {
            return Err(RamError::Invariant("fault request cannot be settled"));
        }
        let operation = self
            .claimed
            .as_ref()
            .and_then(|claim| claim.operation.as_deref())
            .ok_or("fault operation disappeared before completion")?;
        if let Err(error) = operation.complete() {
            let error = RamError::from(error);
            self.fail();
            return Err(error);
        }
        self.claimed.take();
        self.receipt.clear_after_settlement();
        self.scratch.fill(0);
        Ok(())
    }"#,
            1,
        ),
        (
            r#"fn unresolved(&self) -> bool {
        self.claimed.is_some() || self.receipt.retained() || self.eviction.is_some() || self.failed
    }"#,
            1,
        ),
        (
            r#"pub(in crate::paged_ram::engine) fn return_at_boundary(self) -> Result<(), RamError> {
        if self.work.unresolved() {
            return Err(RamError::Invariant(
                "placement fault work remains unsettled",
            ));
        }
        let Self { work, returned } = self;
        drop(work);
        returned.store(true, Ordering::Release);
        Ok(())
    }"#,
            1,
        ),
        (
            r#"pub(in crate::paged_ram::engine) fn prepare(budget: &MetadataBudget) -> Result<Self, RamError> {
        let extent = Self::required_metadata_bytes()?;
        let reservation = budget.reserve_bytes(extent)?;
        let end = physical_end::PhysicalEndCustody::new()?;
        let body = Box::new(FaultWorkAllocation {
            pause: FaultPause::default(),
            lifecycle: std::sync::atomic::AtomicU8::new(physical_end::LIFECYCLE_IDLE),
            placement: AtomicBool::new(false),
            scratch_returned: AtomicBool::new(false),
            end_pending: AtomicBool::new(false),
            end_failed: AtomicBool::new(false),
            end: Mutex::new(end),
            dispatch: PlacementDispatchJournal::default(),
            work: Mutex::new(FaultWork {
                claimed: None,
                receipt: FaultReceipt::default(),
                scratch: [0; PAGE_BYTES],
                eviction: None,
                failed: false,
            }),
        });
        Ok(Self {
            body: Some(body),
            reservation: Some(reservation),
        })
    }"#,
            1,
        ),
        (
            r#"pub(in crate::paged_ram::engine) fn required_metadata_bytes() -> Result<u64, RamError> {
        u64::try_from(std::mem::size_of::<FaultWorkAllocation>())
            .map_err(|_| RamError::Invariant("fault work metadata extent overflow"))
    }"#,
            1,
        ),
        (
            r#"pub(in crate::paged_ram::engine) fn check_settled(&self) -> Result<(), RamError> {
        let body = self.body.as_ref().ok_or("fault work body absent")?;
        if body.lifecycle.load(Ordering::Acquire) != physical_end::LIFECYCLE_IDLE
            || body.placement.load(Ordering::Acquire)
            || body.end_pending.load(Ordering::Acquire)
            || body.end_failed.load(Ordering::Acquire)
            || body.dispatch.unresolved()
            || body.end.try_lock().map_or(true, |custody| custody.unresolved())
            || self.try_lock()?.unresolved()
        {
            return Err(RamError::Invariant("fault work remains unsettled"));
        }
        Ok(())
    }"#,
            1,
        ),
        (
            r#"pub(in crate::paged_ram::engine) fn placement_work<'a>(
        &'a self,
        placement: &super::super::placement::PhysicalPlacement<'_>,
    ) -> Result<PlacementWork<'a>, RamError> {
        if !std::ptr::eq(self, &placement.service.capture_work) {
            return Err(RamError::Invariant("placement fault-work owner changed"));
        }
        let status = (placement.service.native.validate)(placement.token, placement.generation);
        if status != 0 {
            return Err(RamError::Native {
                operation: "placement scratch physical owner",
                status,
            });
        }
        let body = self.body.as_ref().ok_or("fault work body absent")?;
        if body.pause.held() {
            return Err(RamError::Invariant("capture retains fault work"));
        }
        body.placement
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| RamError::Invariant("placement fault work remains held"))?;
        body.scratch_returned.store(false, Ordering::Release);
        let work = self.try_lock()?;
        if body.pause.held() || work.unresolved() {
            return Err(RamError::Invariant(
                "placement fault work remains unsettled",
            ));
        }
        Ok(PlacementWork {
            work,
            returned: &body.scratch_returned,
        })
    }"#,
            1,
        ),
        (
            r#"pub(super) fn try_lock_for_fault(&self) -> Result<Option<MutexGuard<'_, FaultWork>>, RamError> {
        let body = self.body.as_ref().ok_or("fault work body absent")?;
        if body.placement.load(Ordering::Acquire) {
            return Ok(None);
        }
        match body.work.try_lock() {
            Ok(_work) if body.placement.load(Ordering::Acquire) => Ok(None),
            Ok(work) => Ok(Some(work)),
            Err(TryLockError::WouldBlock) if body.placement.load(Ordering::Acquire) => Ok(None),
            Err(_) => Err(RamError::Invariant("fault work custody unavailable")),
        }
    }"#,
            1,
        ),
        (
            r#"fn drop(&mut self) {
        let unresolved = self.body.as_ref().is_some_and(|body| {
            body.pause.held()
                || body.lifecycle.load(Ordering::Acquire) != physical_end::LIFECYCLE_IDLE
                || body.placement.load(Ordering::Acquire)
                || body.end_pending.load(Ordering::Acquire)
                || body.end_failed.load(Ordering::Acquire)
                || body.dispatch.unresolved()
                || body.end.try_lock().map_or(true, |custody| custody.unresolved())
                || body.work.try_lock().map_or(true, |work| work.unresolved())
        });
        if unresolved {
            // No caller here proves physical process retirement. Preserve the
            // existing allocation and original claim, with its same credit.
            // Kernel teardown at real process exit is the final containment cut.
            if let Some(body) = self.body.take() {
                std::mem::forget(body);
            }
            if let Some(reservation) = self.reservation.take() {
                std::mem::forget(reservation);
            }
            return;
        }
        drop(self.body.take());
        drop(self.reservation.take());
    }"#,
            1,
        ),
    ],
};
