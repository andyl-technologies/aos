//! Process-lifetime live coverage callback ownership.

use super::*;

pub(super) static LIVE_COVERAGE_STATE: AtomicPtr<LiveCoverageInner> =
    AtomicPtr::new(std::ptr::null_mut());

/// Resets the live producer state for one authenticated restore generation.
///
/// The logical-time restore callback invokes this operation while QEMU is
/// stopped and before it release-publishes the matching restore
/// acknowledgement. A disabled coverage configuration is an idempotent no-op.
/// Enabled coverage clears both the QEMU per-vCPU conditional scoreboard and
/// the plugin's process-local novelty map, then discards setup-era ring entries
/// at the consumer's current cursor. Translated callbacks retain the same
/// scoreboard allocation and therefore become eligible again without dangling
/// their generated-code metadata.
///
/// # Errors
///
/// Returns [`CoverageError`] when `generation` is zero or reused, QEMU reports
/// no configured vCPU, callback teardown has begun, or the shared coverage ring
/// is malformed.
pub(crate) fn reset_live_coverage_for_restore(generation: u32) -> Result<(), CoverageError> {
    if generation == 0 {
        return Err(CoverageError::InvalidRestoreGeneration { generation });
    }
    let state = LIVE_COVERAGE_STATE.load(Ordering::Acquire);
    if state.is_null() {
        return Ok(());
    }
    // SAFETY: the registration owner publishes one pinned state for the
    // process lifetime. The logical restore callback runs under the validated
    // single-threaded RR model while QEMU is stopped, so no translation or
    // execution callback can mutate this state concurrently.
    let state = unsafe { &mut *state };
    let Some(_in_flight) = state.quiescence.enter() else {
        return Err(CoverageError::RestoreDuringTeardown);
    };
    if state.restore_generation != 0 {
        return Err(CoverageError::RestoreGenerationReused {
            applied: state.restore_generation,
            requested: generation,
        });
    }

    let vcpu_count = (state.apis.num_vcpus)();
    let vcpu_count = u32::try_from(vcpu_count)
        .map_err(|_error| CoverageError::InvalidLiveVcpuCount { vcpu_count })?;
    if vcpu_count == 0 {
        return Err(CoverageError::InvalidLiveVcpuCount { vcpu_count: 0 });
    }
    let map_entries = state.callback.map_entries();
    let (header, entries) = state.sink.ring_parts();
    // Validate and empty the old generation before changing process-local
    // novelty state. The authenticated pause excludes both SPSC peers here.
    header
        .discard_coverage_at_restore(entries)
        .map_err(|source| CoverageError::RestoreRing { source })?;
    state.map.reset();
    for vcpu_index in 0..vcpu_count {
        for map_index in 0..map_entries {
            (state.apis.u64_set)(
                QemuPluginU64 {
                    score: state.novelty_scoreboard,
                    offset: map_index * std::mem::size_of::<u64>(),
                },
                vcpu_index,
                0,
            );
        }
    }
    state.restore_generation = generation;
    Ok(())
}

#[derive(Debug)]
struct LiveCoverageBlock {
    state: *mut LiveCoverageInner,
    instruction_count: u64,
    guest_pc: u64,
    block_len: u32,
    seen_entry: QemuPluginU64,
    _pin: PhantomPinned,
}

/// Pinned raw view of one ABI-validated plugin-to-host coverage ring.
#[derive(Debug)]
pub(crate) struct LiveCoverageShmemProducer {
    header: *const RingHeader,
    entries: *mut CoverageEntry,
    capacity: usize,
}

impl LiveCoverageShmemProducer {
    /// Builds a producer view retained by the process-lifetime callback owner.
    ///
    /// # Safety
    ///
    /// `header` and the `capacity` entries starting at `entries` must remain
    /// mapped, aligned, and exclusively producer-owned until the coverage
    /// callback owner is destroyed. The host may access the same objects only as
    /// the SPSC consumer through [`RingHeader::dequeue_coverage`].
    pub(crate) unsafe fn from_raw_parts(
        header: *const RingHeader,
        entries: *mut CoverageEntry,
        capacity: usize,
    ) -> Self {
        Self {
            header,
            entries,
            capacity,
        }
    }

    const fn capacity(&self) -> usize {
        self.capacity
    }

    fn ring_parts(&mut self) -> (&RingHeader, &mut [CoverageEntry]) {
        // SAFETY: construction requires both raw ranges to remain valid and
        // producer-exclusive for this owner's lifetime. The validated sim RR
        // execution model serializes every callback invocation.
        unsafe {
            (
                &*self.header,
                std::slice::from_raw_parts_mut(self.entries, self.capacity),
            )
        }
    }

    #[cfg(test)]
    pub(super) fn drain(&mut self) -> Result<Vec<CoverageObservation>, CoverageSinkError> {
        let (header, entries) = self.ring_parts();
        let mut observations = Vec::new();
        while let Some(entry) = header
            .dequeue_coverage(entries)
            .map_err(|error| CoverageSinkError::new(error.to_string()))?
        {
            let entry = entry
                .validate()
                .map_err(|error| CoverageSinkError::new(error.to_string()))?;
            let map_index = usize::try_from(entry.map_index())
                .map_err(|error| CoverageSinkError::new(error.to_string()))?;
            observations.push(CoverageObservation {
                current_icount: entry.current_icount(),
                vcpu_index: entry.vcpu_index(),
                guest_pc: entry.guest_pc(),
                block_len: entry.block_len(),
                map_index,
                was_new: true,
            });
        }
        Ok(observations)
    }
}

impl CoverageSink for LiveCoverageShmemProducer {
    fn record_coverage(
        &mut self,
        observation: &CoverageObservation,
    ) -> Result<(), CoverageSinkError> {
        if !observation.was_new() {
            return Ok(());
        }
        let entry = CoverageEntry::new(
            observation.current_icount(),
            observation.vcpu_index(),
            observation.guest_pc(),
            observation.block_len(),
            observation.map_index() as u64,
        )
        .map_err(|_error| CoverageSinkError::from_static("invalid live coverage entry"))?;
        let (header, entries) = self.ring_parts();
        header.enqueue_coverage(entries, entry).map_err(|error| {
            if matches!(error, SpscRingError::QueueFull { .. }) {
                CoverageSinkError::from_static("live coverage queue is full")
            } else {
                CoverageSinkError::from_static("live coverage queue rejected entry")
            }
        })
    }
}

#[derive(Debug)]
pub(super) struct LiveCoverageInner {
    quiescence: Arc<LiveCallbackQuiescence>,
    _plugin_id: QemuPluginId,
    apis: QemuBasicBlockCoverageApis,
    callback: CoverageCallback,
    map: CoverageMap,
    novelty_scoreboard: *mut QemuPluginScoreboard,
    sink: LiveCoverageShmemProducer,
    restore_generation: u32,
    // Each QEMU callback retains a pointer to one entry independently of outer
    // collection growth. Pinning makes that address-lifetime contract explicit.
    translated_blocks: Vec<Pin<Box<LiveCoverageBlock>>>,
    whitebox_translation: Option<LiveTbTranslationConsumer>,
    _pin: PhantomPinned,
}

/// Process-lifetime owner for QEMU basic-block coverage callbacks.
///
/// The owner exists only for `coverage=on`. It keeps every per-translation
/// metadata allocation stable for as long as QEMU can execute the translated
/// block. The active runtime intentionally retains this owner for process
/// lifetime; QEMU destroys generated callbacks before the flush hook releases
/// their userdata and removes all plugin callbacks before unloading the plugin.
/// The shared output ring retains each newly reached map entry exactly once, so
/// it is bounded by the configured map size without silent eviction.
pub(crate) struct LiveBasicBlockCoverage {
    state: Pin<Box<LiveCoverageInner>>,
}

impl LiveBasicBlockCoverage {
    /// Registers the translation callback and takes ownership of its live state.
    ///
    /// # Errors
    ///
    /// Returns [`CoverageError`] when the configured map is invalid, the current
    /// output ring does not match it, or another live owner is already published.
    #[cfg(test)]
    pub(crate) fn register(
        plugin_id: QemuPluginId,
        callback: CoverageCallback,
        apis: QemuBasicBlockCoverageApis,
        sink: LiveCoverageShmemProducer,
        quiescence: Arc<LiveCallbackQuiescence>,
    ) -> Result<Self, CoverageError> {
        Self::register_with_whitebox(plugin_id, callback, apis, sink, quiescence, None)
    }

    /// Registers coverage and an optional earlier white-box translation consumer.
    ///
    /// # Errors
    ///
    /// Returns [`CoverageError`] when the configured map is invalid, the current
    /// output ring does not match it, allocation fails, or another live owner is
    /// already published.
    pub(crate) fn register_with_whitebox(
        plugin_id: QemuPluginId,
        callback: CoverageCallback,
        apis: QemuBasicBlockCoverageApis,
        sink: LiveCoverageShmemProducer,
        quiescence: Arc<LiveCallbackQuiescence>,
        whitebox_translation: Option<LiveTbTranslationConsumer>,
    ) -> Result<Self, CoverageError> {
        let map_entries = callback.map_entries();
        if sink.capacity() != map_entries {
            return Err(CoverageError::CoverageQueueCapacityMismatch {
                map_entries,
                queue_capacity: sink.capacity(),
            });
        }
        let map = CoverageMap::new(map_entries)?;
        let scoreboard_size = map_entries
            .checked_mul(std::mem::size_of::<u64>())
            .ok_or(CoverageError::NoveltyScoreboardSizeOverflow { map_entries })?;
        let novelty_scoreboard = (apis.scoreboard_new)(scoreboard_size);
        if novelty_scoreboard.is_null() {
            return Err(CoverageError::NoveltyScoreboardAllocation { scoreboard_size });
        }
        let mut state = Box::pin(LiveCoverageInner {
            quiescence,
            _plugin_id: plugin_id,
            apis,
            callback,
            map,
            novelty_scoreboard,
            sink,
            restore_generation: 0,
            translated_blocks: Vec::new(),
            whitebox_translation,
            _pin: PhantomPinned,
        });
        // SAFETY: obtaining the address does not move the pinned state. QEMU's
        // validated single-threaded round-robin mode serializes every access to
        // the published pointer for the process-lifetime owner.
        let state_ptr = unsafe { state.as_mut().get_unchecked_mut() } as *mut LiveCoverageInner;
        if LIVE_COVERAGE_STATE
            .compare_exchange(
                std::ptr::null_mut(),
                state_ptr,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            (apis.scoreboard_free)(novelty_scoreboard);
            return Err(CoverageError::LiveRegistrationAlreadyExists { plugin_id });
        }
        (apis.register_flush_cb)(plugin_id, live_coverage_flush, state_ptr.cast());
        (apis.register_tb_trans_cb)(
            plugin_id,
            Some(live_coverage_tb_translate),
            state_ptr.cast(),
        );
        Ok(Self { state })
    }

    #[cfg(test)]
    pub(super) fn drain_observations(&mut self) -> Vec<CoverageObservation> {
        // SAFETY: this test helper is called only after synchronous fake
        // callback invocation while the test holds the sole owner.
        unsafe { self.state.as_mut().get_unchecked_mut() }
            .sink
            .drain()
            .unwrap_or_else(|error| panic!("coverage test ring should drain: {error}"))
    }

    #[cfg(test)]
    pub(super) fn map_entries(&self) -> Vec<u8> {
        self.state.as_ref().get_ref().map.entries().to_vec()
    }

    #[cfg(test)]
    pub(super) fn translated_block_count(&self) -> usize {
        self.state.as_ref().get_ref().translated_blocks.len()
    }
}

impl Drop for LiveBasicBlockCoverage {
    fn drop(&mut self) {
        let state_ptr = std::ptr::from_ref(self.state.as_ref().get_ref()).cast_mut();
        if LIVE_COVERAGE_STATE
            .compare_exchange(
                state_ptr,
                std::ptr::null_mut(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            abort_live_coverage_callback(CoverageError::LiveRegistrationOwnershipLost);
        }
        (self.state.as_ref().get_ref().apis.scoreboard_free)(
            self.state.as_ref().get_ref().novelty_scoreboard,
        );
    }
}

extern "C" fn live_coverage_tb_translate(tb: *mut QemuPluginTb, userdata: *mut c_void) {
    if tb.is_null() {
        abort_live_coverage_callback(CoverageError::NullTranslatedBlock);
    }
    let state = userdata.cast::<LiveCoverageInner>();
    if state.is_null() || LIVE_COVERAGE_STATE.load(Ordering::Acquire) != state {
        return;
    }
    // SAFETY: registration publishes a fully initialized pinned state and the
    // plugin rejects QEMU modes that could invoke these callbacks concurrently.
    let state = unsafe { &mut *state };
    let Some(_in_flight) = state.quiescence.enter() else {
        // Teardown closed callback admission before this translation began.
        return;
    };
    // White-box translation installs exact-deadline and doorbell execution
    // callbacks before coverage adds its conditional observation callback.
    if let Some(whitebox) = state.whitebox_translation {
        whitebox.dispatch(tb);
    }
    let instruction_count = (state.apis.tb_n_insns)(tb.cast_const());
    if instruction_count == 0 {
        abort_live_coverage_callback(CoverageError::EmptyTranslatedBlock);
    }
    let instruction_count_u64 = match u64::try_from(instruction_count) {
        Ok(instruction_count) => instruction_count,
        Err(_error) => {
            abort_live_coverage_callback(CoverageError::TranslatedBlockInstructionCountOverflow)
        }
    };
    let guest_pc = (state.apis.tb_vaddr)(tb.cast_const());
    let map_index = fold_basic_block_pc(guest_pc, state.callback.map_entries());
    let block_len = (0..instruction_count).try_fold(0_usize, |length, index| {
        let insn = (state.apis.tb_get_insn)(tb.cast_const(), index);
        if insn.is_null() {
            return Err(CoverageError::NullTranslatedInstruction { index });
        }
        length
            .checked_add((state.apis.insn_size)(insn.cast_const()))
            .ok_or(CoverageError::TranslatedBlockLengthOverflow)
    });
    let block_len = match block_len.and_then(|length| {
        u32::try_from(length).map_err(|_error| CoverageError::TranslatedBlockLengthOverflow)
    }) {
        Ok(block_len) if block_len != 0 => block_len,
        Ok(block_len) => {
            abort_live_coverage_callback(CoverageError::InvalidBlockLength { block_len })
        }
        Err(error) => abort_live_coverage_callback(error),
    };

    let seen_entry = QemuPluginU64 {
        score: state.novelty_scoreboard,
        offset: map_index * std::mem::size_of::<u64>(),
    };
    let metadata = Box::pin(LiveCoverageBlock {
        state: std::ptr::from_mut(state),
        instruction_count: instruction_count_u64,
        guest_pc,
        block_len,
        seen_entry,
        _pin: PhantomPinned,
    });
    let userdata = std::ptr::from_ref(metadata.as_ref().get_ref())
        .cast_mut()
        .cast::<c_void>();
    state.translated_blocks.push(metadata);
    (state.apis.register_tb_exec_cond_cb)(
        tb,
        Some(live_coverage_tb_exec),
        QEMU_PLUGIN_CB_NO_REGS,
        QEMU_PLUGIN_COND_EQ,
        seen_entry,
        0,
        userdata,
    );
}

extern "C" fn live_coverage_tb_exec(vcpu_index: c_uint, userdata: *mut c_void) {
    if userdata.is_null() {
        abort_live_coverage_callback(CoverageError::NullExecutionUserdata);
    }
    // SAFETY: `live_coverage_tb_translate` registers only pointers to boxed
    // `LiveCoverageBlock` values retained until QEMU first destroys every
    // dynamic callback that can refer to them. QEMU invokes this callback with
    // that exact userdata.
    let block = unsafe { &*userdata.cast::<LiveCoverageBlock>() };
    if block.state.is_null() || LIVE_COVERAGE_STATE.load(Ordering::Acquire) != block.state {
        return;
    }
    // SAFETY: translation metadata points back to the same pinned owner and
    // the validated execution model serializes translation and execution.
    let state = unsafe { &mut *block.state };
    let Some(_in_flight) = state.quiescence.enter() else {
        return;
    };
    (state.apis.u64_set)(block.seen_entry, vcpu_index, 1);
    // QEMU 11 emits the standard TB execution callback after `gen_tb_start`
    // subtracts the full TB reservation. The helper observes
    // `committed + budget - remaining` without committing it, then subtracts
    // this TB's instruction count to recover the exact entry boundary.
    let mut current_icount = 0_u64;
    let status = (state.apis.icount_at_tb_entry)(
        block.instruction_count,
        std::ptr::from_mut(&mut current_icount),
    );
    if status != 0 {
        abort_live_coverage_callback(CoverageError::TbEntryIcountUnavailable {
            instruction_count: block.instruction_count,
            status,
        });
    }
    let event =
        CoverageBlockEvent::new(current_icount, vcpu_index, block.guest_pc, block.block_len);
    let callback = state.callback;
    let LiveCoverageInner { map, sink, .. } = state;
    if let Err(error) = callback.record_basic_block(map, sink, event) {
        abort_live_coverage_callback(error);
    }
}

extern "C" fn live_coverage_flush(userdata: *mut c_void) {
    let state = userdata.cast::<LiveCoverageInner>();
    if state.is_null() || LIVE_COVERAGE_STATE.load(Ordering::Acquire) != state {
        return;
    }
    // SAFETY: QEMU 11's `plugins/core.c:qemu_plugin_flush_cb` removes and resets
    // the dynamic-callback array table before `QEMU_PLUGIN_EV_FLUSH`, while
    // `accel/tcg/tb-maint.c:tb_flush` runs the operation in a serial context or
    // dispatches it through `async_safe_run_on_cpu`. Consequently no generated
    // code can retain the userdata freed here, and the validated execution
    // model prevents concurrent access to the owner.
    let state = unsafe { &mut *state };
    let Some(_in_flight) = state.quiescence.enter() else {
        // Production retains the owner and its translated metadata through
        // process exit. Closing admission therefore rejects a late flush
        // without unpublishing or freeing callback-addressable state.
        return;
    };
    state.translated_blocks.clear();
}

fn abort_live_coverage_callback(error: CoverageError) -> ! {
    // Callback failures are fatal invariants. Do not format, allocate, lock, or
    // perform diagnostic I/O on this FFI path, and never unwind into QEMU.
    let _error = error;
    std::process::abort();
}
