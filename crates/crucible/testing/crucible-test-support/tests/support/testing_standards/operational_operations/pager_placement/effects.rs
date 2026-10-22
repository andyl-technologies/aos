//! Binds same-operation dispatch and physical action before typed deferral.

use super::super::Companion;

pub(in super::super) const DISPATCH: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-plugin/src/paged_ram/engine/placement.rs",
    required: &[
        (
            r#"fn dispatch(&mut self) -> Result<(), RamError> {
        let complete_here = self.operation.is_none();
        let operation: Arc<dyn SourceOperation> = match self.operation.as_ref() {
            Some(operation) => operation.clone(),
            None => Arc::from(
                self.service
                    .operations
                    .begin(SourceOperationClass::Quiescence)?,
            ),
        };
        self.operation = Some(operation.clone());
        let service = self.service.clone();
        let journal = service.capture_work.placement_dispatch()?;
        self.check_budget()?;
        journal.reset()?;
        loop {
            self.check_budget()?;
            journal.callback_entered.store(false, Ordering::Release);
            journal.callback_returned.store(false, Ordering::Release);
            journal.runner_returned.store(false, Ordering::Release);
            journal.runner_entered.store(true, Ordering::Release);
            let status = (self.service.native.run)(physical_placement, (self as *mut Self).cast());
            journal.runner_status.store(status, Ordering::Release);
            journal.runner_returned.store(true, Ordering::Release);
            journal.record_first_negative(status);
            if status == 0 {
                if !journal.callback_returned.load(Ordering::Acquire)
                    || journal.callback_status.load(Ordering::Acquire) != 0
                    || !journal.action_completed.load(Ordering::Acquire)
                {
                    self.service.failed.store(true, Ordering::Release);
                    return Err(RamError::Invariant("placement runner omitted completed callback"));
                }
                break;
            }
            if journal.retry_before_action(status, self.token) {
                if !complete_here {
                    // No RAM action/end was admitted. Scheduling retains the
                    // same Original; only this pre-entry dispatch has returned.
                    journal.settled.store(true, Ordering::Release);
                    let first = self.error.take().unwrap_or(RamError::Native {
                        operation: "paused placement requires mainloop progress",
                        status,
                    });
                    return Err(match first {
                        RamError::Native { operation, status }
                            if status == -libc::EAGAIN || status == -libc::EBUSY =>
                        {
                            RamError::PlacementDeferred { operation, status }
                        }
                        first => first,
                    });
                }
                self.error = None;
                let slice = operation
                    .wait_slice()?
                    .min(std::time::Duration::from_millis(10));
                std::thread::sleep(slice);
                continue;
            }
            self.service.failed.store(true, Ordering::Release);
            let first = self.error.take().unwrap_or(RamError::Native {
                operation: "physical placement dispatch",
                status,
            });
            // Scheduling's outer refusal route must see the same no-replay
            // disposition. Preserve the native first cause and raw status.
            return Err(match first {
                RamError::Native { operation, status } => {
                    RamError::PlacementNotRetryable { operation, status }
                }
                first => first,
            });
        }
        self.check_budget()?;
        if complete_here {
            operation.complete()?;
        }
        if !self.activate {
            self.publish_placement(complete_here)?;
            self.check_policy_generation()?;
            *self
                .service
                .resident_observation
                .try_lock()
                .map_err(|_| "resident observation publication unavailable")? =
                self.resident_observation;
        }
        journal.settled.store(true, Ordering::Release);
        Ok(())
    }"#,
            1,
        ),
        (
            r#"fn run(
        &mut self,
        action: &service::capture_work::physical_end::PhysicalActionAdmission<'_>,
    ) -> Result<(), RamError> {
        self.check_budget()?;
        let mut locks = self.prepare_locks()?;
        let result = self.run_with_locks(&mut locks, action);
        if let Err(error) = &result {
            let retry = match (error, self.service.capture_work.placement_dispatch()) {
                (RamError::Native { status, .. }, Ok(journal)) => {
                    journal.retry_before_action(*status, self.token)
                }
                _ => false,
            };
            if !retry {
                self.service.lifetime.failed(error.clone());
                if self.token != 0 {
                    if let Err(post) = self
                        .service
                        .capture_work
                        .retain_physical_action_failure(self.token, error)
                    {
                        self.service.lifetime.cleanup_failed(post);
                    }
                }
            }
        }
        if result.is_err() && self.token != 0 && locks.is_some() {
            // End may have partially returned physical borrowers. Retain the
            // exact verification FD and cleanup identity until independent
            // disposition is known; a signed failure does not prove exclusion.
            match self.owner.retained_lock_transition.try_lock() {
                Ok(mut retained) if retained.is_none() => *retained = locks.take(),
                _ => std::mem::forget(locks.take()),
            }
        }
        result
    }"#,
            1,
        ),
        (
            r#"fn run_with_locks(
        &mut self,
        locks: &mut Option<super::strict_placement::LockTransition>,
        action: &service::capture_work::physical_end::PhysicalActionAdmission<'_>,
    ) -> Result<(), RamError> {
        let native = self.service.native;
        let service = self.service.clone();
        let journal = service.capture_work.placement_dispatch()?;
        let born = self
            .service
            .capture_work
            .begin_physical(&service, self.generation, action)?;
        self.token = born.token;
        let status = born.status;
        if status != 0 || self.token == 0 {
            return Err(RamError::Native {
                operation: "physical placement exclusion",
                status,
            });
        }
        self.check_budget()?;
        let status = (native.validate)(self.token, self.generation);
        if status != 0 {
            return Err(RamError::Native {
                operation: "physical placement validation",
                status,
            });
        }
        if self.activate {
            // Original anonymous RAM may still have empty PTEs. Missing-fault
            // registration must not reinterpret that untouched original state
            // as a recoverable cold page without any preservation authority.
            // Resolve original PTEs and private COW before registering, while
            // complete physical exclusion and the full interval peak are held.
            for arena in &self.service.arenas {
                if arena.placement != ArenaPlacement::Pageable {
                    continue;
                }
                for page in 0..arena.native.mapping_length / PAGE_BYTES as u64 {
                    self.check_budget()?;
                    let address = arena.native.host_address + page * PAGE_BYTES as u64;
                    prefault_original_page(address);
                    self.progress_work()?;
                }
            }
            let status = (native.pin)(self.token, self.generation);
            if status != 0 {
                return Err(RamError::Native {
                    operation: "initial arena topology pin",
                    status,
                });
            }
            self.service.registration.retain_until_process_exit();
            for arena in &self.service.arenas {
                self.check_budget()?;
                if arena.placement != ArenaPlacement::Pageable {
                    continue;
                }
                // SAFETY: the certificate retains stable private anonymous RAM
                // and excludes every admitted physical borrower/accessor.
                unsafe {
                    self.service
                        .registration
                        .register(arena.native.host_address, arena.native.mapping_length)
                }?;
                self.service.registration.protect(
                    arena.native.host_address,
                    arena.native.mapping_length,
                    true,
                )?;
                self.progress_work()?;
            }
            self.service.destructive.store(true, Ordering::Release);
            self.service.activated.store(true, Ordering::Release);
        } else {
            self.apply_placement(locks)?;
        }
        self.check_budget()?;
        let ended = self.service.capture_work.end_physical(native, self.token)?;
        let token = self.token;
        // Only the actual producer's return_complete consumes identity. The
        // signed end and observer results remain separately owned in the body.
        if ended.returned {
            self.token = 0;
            self.service.retained_token.store(0, Ordering::Release);
        }
        if let Some(error) = ended.failure.as_ref() {
            self.service.failed.store(true, Ordering::Release);
            self.service.lifetime.failed(error.clone());
        }
        let gate_return = if ended.returned {
            self.service.capture_work.return_gate_after_end(token)
        } else {
            Ok(())
        };
        if let Some(error) = ended.failure {
            return Err(error);
        }
        gate_return?;
        journal.action_completed.store(true, Ordering::Release);
        Ok(())
    }"#,
            1,
        ),
        (
            r#"pub(super) fn reclaim_pages(&mut self) -> Result<(), RamError> {
        let service = self.service.clone();
        let mut work = service.capture_work.placement_work(self)?;
        self.reclaim_pages_with_work(&mut work)?;
        // The same prepaid scratch is exclusive through this journal/sample.
        // A retained journal forbids reuse even after its actor has returned.
        self.resident_observation = Some(self.sample_residency(work.idle_scratch()?)?);
        work.return_at_boundary()
    }"#,
            1,
        ),
        (
            r#"pub(super) fn check_budget(&self) -> Result<(), RamError> {
        let operation = self
            .operation
            .as_ref()
            .ok_or("physical placement supervisor absent")?;
        check_placement_operation(
            operation.as_ref(),
            &self.owner.failed,
            &self.service.failed,
            &self.service.stop,
        )
    }"#,
            1,
        ),
        (
            r#"fn check_placement_operation(
    operation: &dyn SourceOperation,
    owner_failed: &AtomicBool,
    service_failed: &AtomicBool,
    stopping: &AtomicBool,
) -> Result<(), RamError> {
    let check_health = || {
        if owner_failed.load(Ordering::Acquire) || service_failed.load(Ordering::Acquire) {
            return Err(RamError::Invariant("physical placement authority failed"));
        }
        if stopping.load(Ordering::Acquire) {
            return Err(RamError::Invariant("physical placement worker is stopping"));
        }
        Ok(())
    };

    check_health()?;
    operation.wait_slice()?;
    check_health()
}"#,
            1,
        ),
        (
            r#"extern "C" fn physical_placement(opaque: *mut c_void) -> c_int {
    // SAFETY: the synchronous native runner lends this exclusive context until
    // completion and never publishes its process-private pointer.
    let placement = unsafe { &mut *opaque.cast::<PhysicalPlacement<'_>>() };
    let service = placement.service.clone();
    let journal = match service.capture_work.placement_dispatch() {
        Ok(journal) => journal,
        Err(error) => {
            placement.error = Some(error);
            return -libc::EIO;
        }
    };
    journal.callback_entered.store(true, Ordering::Release);
    let action = service.capture_work.admit_physical_action();
    let result = match action.as_ref() {
        Ok(action) => placement.run(action),
        Err(error) => Err(error.clone()),
    };
    let mut status = match result {
        Ok(()) => 0,
        Err(error) => {
            let retry = match &error {
                RamError::Native { status, .. }
                    if journal.retry_before_action(*status, placement.token) =>
                {
                    Some(*status)
                }
                _ => None,
            };
            if retry.is_none() {
                placement
                    .owner
                    .retain_operational_failure(SourceOperationClass::Quiescence, &error);
                placement.service.failed.store(true, Ordering::Release);
            }
            placement.error = Some(error);
            retry.unwrap_or(-libc::EIO)
        }
    };
    journal.callback_status.store(status, Ordering::Release);
    journal.record_first_negative(status);
    if let Ok(action) = action {
        if let Err(post) = action.finish() {
            service.failed.store(true, Ordering::Release);
            service.lifetime.cleanup_failed(post.clone());
            if placement.error.is_none() {
                placement.error = Some(post);
            }
            status = -libc::EIO;
            journal.callback_status.store(status, Ordering::Release);
        }
    }
    journal.callback_returned.store(true, Ordering::Release);
    journal.record_first_negative(status);
    status
}"#,
            1,
        ),
        (
            r#"pub(super) fn progress_work(&self) -> Result<(), RamError> {
        let completed = self
            .completed_work
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| "physical placement work authority exhausted")?
            + 1;
        self.operation
            .as_ref()
            .ok_or("physical placement supervisor absent")?
            .progress(completed)?;
        Ok(())
    }"#,
            1,
        ),
    ],
};

pub(in super::super) const EVICTION: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-plugin/src/paged_ram/engine/service/capture_work/eviction.rs",
    required: &[
        (
            r#"enum Effect {
    #[default]
    NotStarted,
    Started,
    Complete,
    // Refusal can include partial effects; it is never evidence of no mutation.
    Failed(RamError),
}"#,
            1,
        ),
        (
            r#"fn finish(&mut self, result: Result<(), RamError>) -> Result<(), RamError> {
        *self = match &result {
            Ok(()) => Self::Complete,
            Err(error) => Self::Failed(error.clone()),
        };
        result
    }"#,
            1,
        ),
        (
            r#"pub(super) struct EvictionJournal {
    coordinate: usize,
    address: u64,
    selected: PageState,
    protection: Effect,
    preservation: Effect,
    preserved: Option<PageRecord>,
    published: bool,
    discard: Effect,
    residency_returned: bool,
    writeback: Option<Box<dyn SourceOperation>>,
    writeback_post: Effect,
    writeback_completion: Effect,
    first_failure: Option<RamError>,
}"#,
            1,
        ),
        (
            r#"fn selected_state<'a>(
        &self,
        states: &'a mut PageStates,
    ) -> Result<&'a mut PageState, RamError> {
        let state = states
            .get_mut(self.coordinate)
            .ok_or("eviction page is absent or fenced")?;
        if !self.selected.resident || !state.resident || state.version != self.selected.version {
            return Err(RamError::Invariant(
                "eviction page changed under physical owner",
            ));
        }
        Ok(state)
    }"#,
            1,
        ),
        (
            r#"fn run(
        &mut self,
        placement: &PhysicalPlacement<'_>,
        scratch: &mut [u8; PAGE_BYTES],
    ) -> Result<(), RamError> {
        let service = &placement.service;
        {
            let mut states = service
                .states
                .try_lock()
                .map_err(|_| "eviction state unavailable")?;
            self.selected_state(&mut states)?;
        }

        self.protection = Effect::Started;
        self.protection.finish(
            service
                .registration
                .protect(self.address, PAGE_BYTES as u64, true)
                .map_err(Into::into),
        )?;
        {
            let mut states = service
                .states
                .try_lock()
                .map_err(|_| "eviction state unavailable")?;
            self.selected_state(&mut states)?.writable = false;
        }
        placement.check_budget()?;

        self.preservation = Effect::Started;
        let preservation = self.preserve(placement, scratch);
        self.finish_preservation(preservation, &service.counters)?;
        placement.check_budget()?;
        {
            let mut states = service
                .states
                .try_lock()
                .map_err(|_| "eviction state unavailable")?;
            // Preserve the original lease in `selected` until settlement; the
            // new immutable record is visible before any resident PTE removal.
            self.selected_state(&mut states)?.preserved = self.preserved.clone();
            self.published = true;
        }
        placement.check_budget()?;
        let status = (service.native.validate)(placement.token, placement.generation);
        if status != 0 {
            return Err(RamError::Native {
                operation: "eviction physical owner before discard",
                status,
            });
        }

        self.discard = Effect::Started;
        // SAFETY: this exact mapping remains owned by the validated native
        // physical certificate. WP completed and preservation is authenticated.
        let discarded = unsafe { discard_page(self.address) }.map_err(RamError::from);
        self.discard.finish(discarded)?;
        {
            let mut states = service
                .states
                .try_lock()
                .map_err(|_| "eviction state unavailable")?;
            // Only successful physical discard can return this residency slot.
            // Full guest-RAM entitlement remains held; shared COW backing may
            // still exist and this does not refund a Source/process debit.
            self.selected_state(&mut states)?.resident = false;
            self.residency_returned = true;
        }
        count_completed(&service.counters.physical_discards)?;
        if let Some(operation) = self.writeback.as_ref() {
            self.writeback_completion = Effect::Started;
            self.writeback_completion
                .finish(operation.complete().map_err(Into::into))?;
        }
        placement.progress_work()?;
        Ok(())
    }"#,
            1,
        ),
        (
            r#"fn finish_preservation(
        &mut self,
        result: Result<(), RamError>,
        counters: &PagingCounters,
    ) -> Result<(), RamError> {
        // Save the actual preservation result before entering the Original's
        // independent post, including pacing/I/O failures after its birth.
        let preservation = self.preservation.finish(result);
        let post = if let Some(operation) = self.writeback.as_ref() {
            self.writeback_post = Effect::Started;
            self.writeback_post
                .finish(operation.wait_slice().map(|_| ()).map_err(Into::into))
        } else {
            Ok(())
        };
        let counted = if preservation.is_ok() && self.writeback.is_some() {
            count_completed(&counters.preserved_writes)
        } else {
            Ok(())
        };

        // A later post/counter refusal cannot replace preservation's first
        // cause. Neither failed preservation nor failed post permits complete.
        preservation?;
        post?;
        counted
    }"#,
            1,
        ),
        (
            r#"fn preserve(
        &mut self,
        placement: &PhysicalPlacement<'_>,
        scratch: &mut [u8; PAGE_BYTES],
    ) -> Result<(), RamError> {
        let service = &placement.service;
        // The sealed original source already owns version one's exact bytes.
        if self.selected.version == 1
            && self.selected.preserved.is_none()
            && service.source.is_some()
        {
            return Ok(());
        }
        if let Some(record) = self.selected.preserved.as_ref().filter(|record| {
            record.page_version() == self.selected.version
                && record.valid_length() as usize == PAGE_BYTES
        }) {
            self.preserved = Some(record.clone());
            return Ok(());
        }

        // Publish the actual Original before pacing, copying or backing I/O.
        // A later refusal retains it in this journal instead of dropping it.
        self.writeback = Some(service.operations.begin(SourceOperationClass::Writeback)?);
        let operation = self
            .writeback
            .as_deref()
            .ok_or("eviction Writeback disappeared")?;
        pace_writeback(operation, placement.writeback_rate)?;
        // SAFETY: physical exclusion owns a resident page; synchronous WP has
        // completed. No concurrent actor can clear WP while this body is held.
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.address as *const u8,
                scratch.as_mut_ptr(),
                PAGE_BYTES,
            );
        }
        self.preserved = Some(
            service
                .spill
                .try_lock()
                .map_err(|_| "spill authority unavailable")?
                .preserve(scratch, PAGE_BYTES as u32, self.selected.version)
                .map_err(|error| placement.owner.writeback_failure(error.into()))?,
        );
        // PreservedPages returns only after actual write, sync_data and digest
        // verification. Keep that returned lease before inspecting supervision.
        Ok(())
    }"#,
            1,
        ),
        (
            r#"fn check_settled(&self) -> Result<(), RamError> {
        if let Some(error) = self.first_failure.as_ref() {
            return Err(error.clone());
        }
        self.protection.check_complete()?;
        self.preservation.check_complete()?;
        self.discard.check_complete()?;
        if !self.published || !self.residency_returned {
            return Err(RamError::Invariant(
                "eviction publication remains unsettled",
            ));
        }
        if self.writeback.is_some() {
            self.writeback_post.check_complete()?;
            self.writeback_completion.check_complete()?;
        }
        Ok(())
    }"#,
            1,
        ),
        (
            r#"pub(in crate::paged_ram::engine) fn evict_at_boundary(
        &mut self,
        placement: &PhysicalPlacement<'_>,
        arena: &Arena,
        page: usize,
        coordinate: usize,
        selected: PageState,
    ) -> Result<(), RamError> {
        if self.unresolved() {
            return Err(RamError::Invariant("eviction fault work remains unsettled"));
        }
        let status = (placement.service.native.validate)(placement.token, placement.generation);
        if status != 0 {
            return Err(RamError::Native {
                operation: "eviction physical owner",
                status,
            });
        }
        if arena.placement != ArenaPlacement::Pageable
            || page as u64 >= arena.native.mapping_length / PAGE_BYTES as u64
            || arena.page_start.checked_add(page) != Some(coordinate)
            || !placement
                .service
                .arenas
                .iter()
                .any(|owned| std::ptr::eq(owned, arena))
        {
            return Err(RamError::Invariant("eviction mapping owner changed"));
        }
        let address = arena.native.host_address + page as u64 * PAGE_BYTES as u64;
        self.eviction = Some(EvictionJournal::new(coordinate, address, selected));
        let journal = self.eviction.as_mut().ok_or("eviction journal absent")?;
        let result = journal
            .run(placement, &mut self.scratch)
            .and_then(|()| journal.check_settled());
        if let Err(error) = result {
            if journal.first_failure.is_none() {
                journal.first_failure = Some(error.clone());
            }
            self.fail();
            return Err(error);
        }
        self.eviction.take();
        self.scratch.fill(0);
        Ok(())
    }"#,
            1,
        ),
    ],
};
