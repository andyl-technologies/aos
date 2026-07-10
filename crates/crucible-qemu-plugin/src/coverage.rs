//! Optional TCG-exec basic-block coverage callback core.
//!
//! Coverage is a registration-time opt-in. When disabled, the registration plan
//! installs no TCG-exec callback, leaving the hot execution path without a
//! per-block branch. When enabled, the safe callback body folds each executed
//! guest basic-block PC into a fixed-size map and records an observational event.

use std::borrow::Cow;
use std::marker::PhantomPinned;
use std::os::raw::{c_int, c_uint, c_void};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicPtr, Ordering};

use crucible_protocol::{
    PluginBasicBlockCoverageObservation, PluginBasicBlockCoverageObservationError,
};
use crucible_shmem::{CoverageEntry, RingHeader, SpscRingError};
use thiserror::Error;

use crate::runtime::callback_quiescence::LiveCallbackQuiescence;
use crate::{PluginSwitch, QemuPluginId};

/// QEMU runtime hook retained for non-coverage post-exec integration.
pub const QEMU_PLUGIN_REGISTER_TCG_EXEC_CB_SYMBOL: &str = "qemu_plugin_register_tcg_exec_cb";
/// QEMU capability label for registering the translation callback.
pub const QEMU_PLUGIN_REGISTER_VCPU_TB_TRANS_CB_SYMBOL: &str =
    "qemu_plugin_register_vcpu_tb_trans_cb";
/// QEMU capability label for registering a translated-block execution callback.
pub const QEMU_PLUGIN_REGISTER_VCPU_TB_EXEC_CB_SYMBOL: &str =
    "qemu_plugin_register_vcpu_tb_exec_cb";
/// QEMU capability label for observing the exact icount at TB entry.
pub const QEMU_PLUGIN_ICOUNT_AT_TB_ENTRY_SYMBOL: &str = "qemu_plugin_icount_at_tb_entry";
/// QEMU capability label for observing translation-cache flushes.
pub const QEMU_PLUGIN_REGISTER_FLUSH_CB_SYMBOL: &str = "qemu_plugin_register_flush_cb";
/// QEMU capability label for reading a translated block's start address.
pub const QEMU_PLUGIN_TB_VADDR_SYMBOL: &str = "qemu_plugin_tb_vaddr";
/// QEMU capability label for reading a translated block's instruction count.
pub const QEMU_PLUGIN_TB_N_INSNS_SYMBOL: &str = "qemu_plugin_tb_n_insns";
/// QEMU capability label for retrieving one translated instruction.
pub const QEMU_PLUGIN_TB_GET_INSN_SYMBOL: &str = "qemu_plugin_tb_get_insn";
/// QEMU capability label for reading a translated instruction's byte length.
pub const QEMU_PLUGIN_INSN_SIZE_SYMBOL: &str = "qemu_plugin_insn_size";
/// Default number of entries in the fixed-size coverage map.
pub const DEFAULT_COVERAGE_MAP_ENTRIES: usize = 65_536;

/// Opaque translated-block handle owned by QEMU.
#[repr(C)]
pub struct QemuPluginTb {
    _private: [u8; 0],
}

/// Opaque translated-instruction handle owned by QEMU.
#[repr(C)]
pub struct QemuPluginInsn {
    _private: [u8; 0],
}

/// QEMU callback invoked when one translation block is created.
pub type QemuVcpuTbTransCbFn = extern "C" fn(plugin_id: QemuPluginId, tb: *mut QemuPluginTb);
/// QEMU callback invoked when one translated block executes.
pub type QemuVcpuTbExecCbFn = extern "C" fn(vcpu_index: c_uint, userdata: *mut c_void);
/// QEMU callback invoked after dynamic callbacks have been removed for a flush.
pub type QemuPluginSimpleCbFn = extern "C" fn(plugin_id: QemuPluginId);
/// QEMU function that registers the plugin-wide translation callback.
pub type QemuRegisterVcpuTbTransCbFn =
    extern "C" fn(plugin_id: QemuPluginId, callback: Option<QemuVcpuTbTransCbFn>);
/// QEMU function that registers an execution callback on one translated block.
pub type QemuRegisterVcpuTbExecCbFn = extern "C" fn(
    tb: *mut QemuPluginTb,
    callback: Option<QemuVcpuTbExecCbFn>,
    flags: c_int,
    userdata: *mut c_void,
);
/// QEMU function that registers a plugin-wide translation-cache flush callback.
pub type QemuRegisterFlushCbFn =
    extern "C" fn(plugin_id: QemuPluginId, callback: QemuPluginSimpleCbFn);
/// QEMU function that reads a translated block's start address.
pub type QemuTbVaddrFn = extern "C" fn(tb: *const QemuPluginTb) -> u64;
/// QEMU function that reads a translated block's instruction count.
pub type QemuTbNInsnsFn = extern "C" fn(tb: *const QemuPluginTb) -> usize;
/// QEMU function that retrieves an instruction from a translated block.
pub type QemuTbGetInsnFn =
    extern "C" fn(tb: *const QemuPluginTb, index: usize) -> *mut QemuPluginInsn;
/// QEMU function that reads a translated instruction's byte length.
pub type QemuInsnSizeFn = extern "C" fn(insn: *const QemuPluginInsn) -> usize;
/// QEMU function that observes the exact pre-execution icount for one TB.
pub type QemuIcountAtTbEntryFn = extern "C" fn(tb_insns: u64, entry_icount: *mut u64) -> c_int;

const QEMU_PLUGIN_CB_NO_REGS: c_int = 0;

/// Registration-time-fixed coverage callback state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PluginCoverage {
    mode: PluginSwitch,
    map_entries: usize,
}

impl PluginCoverage {
    /// Builds coverage state from the parsed `coverage` switch.
    #[must_use]
    pub const fn new(mode: PluginSwitch, map_entries: usize) -> Self {
        Self { mode, map_entries }
    }

    /// Builds coverage state with the default map size.
    #[must_use]
    pub const fn with_default_map(mode: PluginSwitch) -> Self {
        Self::new(mode, DEFAULT_COVERAGE_MAP_ENTRIES)
    }

    /// Returns the launch-time coverage switch.
    #[must_use]
    pub const fn mode(self) -> PluginSwitch {
        self.mode
    }

    /// Returns the fixed coverage map entry count.
    #[must_use]
    pub const fn map_entries(self) -> usize {
        self.map_entries
    }

    /// Builds the callback registration plan for the current switch state.
    ///
    /// Off-mode returns [`CoverageRegistrationPlan::Disabled`] before validating
    /// coverage-only configuration or requiring QEMU coverage capabilities.
    ///
    /// # Errors
    ///
    /// Returns [`CoverageError::InvalidMapEntries`] when coverage is enabled
    /// with a zero or non-power-of-two map. Returns
    /// [`CoverageError::CapabilityUnavailable`] when QEMU's TCG-exec callback
    /// registration export is absent.
    pub fn registration_plan(
        self,
        capabilities: CoverageCapabilities,
    ) -> Result<CoverageRegistrationPlan, CoverageError> {
        if !self.mode.is_on() {
            return Ok(CoverageRegistrationPlan::Disabled);
        }

        validate_map_entries(self.map_entries)?;
        if !capabilities.basic_block_callbacks() {
            return Err(CoverageError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_REGISTER_VCPU_TB_TRANS_CB_SYMBOL,
            });
        }

        Ok(CoverageRegistrationPlan::Install {
            map_entries: self.map_entries,
        })
    }
}

/// Handles one safe coverage TCG-exec callback body.
///
/// # Errors
///
/// Returns [`CoverageError`] when map validation fails, event validation fails, or
/// the observational sink cannot record the coverage event.
pub fn handle_coverage_exec_callback<S>(
    callback: &CoverageCallback,
    map: &mut CoverageMap,
    sink: &mut S,
    event: CoverageBlockEvent,
) -> Result<CoverageObservation, CoverageError>
where
    S: CoverageSink + ?Sized,
{
    callback.record_basic_block(map, sink, event)
}

/// Complete QEMU API used by live basic-block coverage callbacks.
#[derive(Clone, Copy, Debug)]
pub struct QemuBasicBlockCoverageApis {
    register_tb_trans_cb: QemuRegisterVcpuTbTransCbFn,
    register_tb_exec_cb: QemuRegisterVcpuTbExecCbFn,
    tb_vaddr: QemuTbVaddrFn,
    tb_n_insns: QemuTbNInsnsFn,
    tb_get_insn: QemuTbGetInsnFn,
    insn_size: QemuInsnSizeFn,
    icount_at_tb_entry: QemuIcountAtTbEntryFn,
    register_flush_cb: QemuRegisterFlushCbFn,
}

impl QemuBasicBlockCoverageApis {
    /// Builds a complete QEMU basic-block callback API table.
    #[must_use]
    // crucible-lint: allow rust-allow -- the constructor mirrors eight independent QEMU callback ABI exports.
    #[allow(
        clippy::too_many_arguments,
        reason = "the constructor mirrors the eight independent QEMU callback ABI exports"
    )]
    pub const fn new(
        register_tb_trans_cb: QemuRegisterVcpuTbTransCbFn,
        register_tb_exec_cb: QemuRegisterVcpuTbExecCbFn,
        tb_vaddr: QemuTbVaddrFn,
        tb_n_insns: QemuTbNInsnsFn,
        tb_get_insn: QemuTbGetInsnFn,
        insn_size: QemuInsnSizeFn,
        icount_at_tb_entry: QemuIcountAtTbEntryFn,
        register_flush_cb: QemuRegisterFlushCbFn,
    ) -> Self {
        Self {
            register_tb_trans_cb,
            register_tb_exec_cb,
            tb_vaddr,
            tb_n_insns,
            tb_get_insn,
            insn_size,
            icount_at_tb_entry,
            register_flush_cb,
        }
    }
}

/// QEMU capabilities needed by the optional coverage hook.
#[derive(Clone, Copy, Debug, Default)]
pub struct CoverageCapabilities {
    basic_block_callbacks: Option<QemuBasicBlockCoverageApis>,
}

impl CoverageCapabilities {
    /// Returns an empty capability set.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            basic_block_callbacks: None,
        }
    }

    /// Returns capabilities sufficient for coverage registration.
    #[must_use]
    pub const fn basic_blocks(apis: QemuBasicBlockCoverageApis) -> Self {
        Self {
            basic_block_callbacks: Some(apis),
        }
    }

    /// Returns whether QEMU can register live basic-block callbacks.
    #[must_use]
    pub const fn basic_block_callbacks(self) -> bool {
        self.basic_block_callbacks.is_some()
    }

    /// Returns QEMU's live basic-block callback API table, if available.
    #[must_use]
    pub const fn basic_block_apis(self) -> Option<QemuBasicBlockCoverageApis> {
        self.basic_block_callbacks
    }
}

/// A registration decision for the optional coverage hook.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoverageRegistrationPlan {
    /// Coverage mode is off and no TCG-exec callback is installed.
    Disabled,
    /// Coverage mode is on and the TCG-exec callback must be installed.
    Install {
        /// Number of entries in the fixed-size coverage map.
        map_entries: usize,
    },
}

impl CoverageRegistrationPlan {
    /// Returns whether this plan installs a TCG-exec callback.
    #[must_use]
    pub const fn installs_callback(self) -> bool {
        matches!(self, Self::Install { .. })
    }

    /// Returns whether the hot execution path has zero per-block coverage overhead.
    #[must_use]
    pub const fn hot_path_has_zero_coverage_overhead(self) -> bool {
        matches!(self, Self::Disabled)
    }

    /// Returns the callback token for an enabled coverage registration plan.
    ///
    /// # Errors
    ///
    /// Returns [`CoverageError::CallbackWhileDisabled`] when called for
    /// [`CoverageRegistrationPlan::Disabled`].
    pub const fn require_callback(self) -> Result<CoverageCallback, CoverageError> {
        match self {
            Self::Disabled => Err(CoverageError::CallbackWhileDisabled),
            Self::Install { map_entries } => Ok(CoverageCallback { map_entries }),
        }
    }
}

/// Proof that the TCG-exec callback was registered for coverage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoverageCallback {
    map_entries: usize,
}

impl CoverageCallback {
    /// Returns the fixed coverage map entry count.
    #[must_use]
    pub const fn map_entries(self) -> usize {
        self.map_entries
    }

    /// Records one executed guest basic block.
    ///
    /// The map update and observational sink write are deterministic functions
    /// of the callback metadata. No scheduler, virtual-time, injection state, or
    /// coverage on/off switch is read or written from this hot callback body.
    ///
    /// # Errors
    ///
    /// Returns [`CoverageError`] when the coverage map has the wrong size, the
    /// event is invalid, or the observational sink rejects the event.
    pub fn record_basic_block<S>(
        self,
        map: &mut CoverageMap,
        sink: &mut S,
        event: CoverageBlockEvent,
    ) -> Result<CoverageObservation, CoverageError>
    where
        S: CoverageSink + ?Sized,
    {
        validate_map_entries(self.map_entries)?;
        if map.len() != self.map_entries {
            return Err(CoverageError::MapSizeMismatch {
                expected: self.map_entries,
                actual: map.len(),
            });
        }
        if event.block_len() == 0 {
            return Err(CoverageError::InvalidBlockLength {
                block_len: event.block_len(),
            });
        }

        let map_index = fold_basic_block_pc(event.guest_pc(), self.map_entries);
        let was_new = map.mark(map_index)?;
        let observation = CoverageObservation {
            current_icount: event.current_icount(),
            vcpu_index: event.vcpu_index(),
            guest_pc: event.guest_pc(),
            block_len: event.block_len(),
            map_index,
            was_new,
        };
        sink.record_coverage(&observation)
            .map_err(|source| CoverageError::Sink { map_index, source })?;
        Ok(observation)
    }
}

/// A fixed-size basic-block coverage map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverageMap {
    entries: Vec<u8>,
}

impl CoverageMap {
    /// Builds a zeroed fixed-size coverage map.
    ///
    /// # Errors
    ///
    /// Returns [`CoverageError::InvalidMapEntries`] when `entries` is zero or
    /// not a power of two.
    pub fn new(entries: usize) -> Result<Self, CoverageError> {
        validate_map_entries(entries)?;
        Ok(Self {
            entries: vec![0; entries],
        })
    }

    /// Returns the number of map entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the map has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the raw coverage counters.
    #[must_use]
    pub fn entries(&self) -> &[u8] {
        &self.entries
    }

    fn mark(&mut self, index: usize) -> Result<bool, CoverageError> {
        let Some(entry) = self.entries.get_mut(index) else {
            return Err(CoverageError::MapIndexOutOfBounds {
                index,
                entries: self.entries.len(),
            });
        };
        let was_new = *entry == 0;
        *entry = entry.saturating_add(1);
        Ok(was_new)
    }
}

static LIVE_COVERAGE_STATE: AtomicPtr<LiveCoverageInner> = AtomicPtr::new(std::ptr::null_mut());

#[derive(Debug)]
struct LiveCoverageBlock {
    state: *mut LiveCoverageInner,
    instruction_count: u64,
    guest_pc: u64,
    block_len: u32,
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
    fn drain(&mut self) -> Result<Vec<CoverageObservation>, CoverageSinkError> {
        let (header, entries) = self.ring_parts();
        let mut observations = Vec::new();
        loop {
            let Some(entry) = header
                .dequeue_coverage(entries)
                .map_err(|error| CoverageSinkError::new(error.to_string()))?
            else {
                break;
            };
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
struct LiveCoverageInner {
    quiescence: Arc<LiveCallbackQuiescence>,
    plugin_id: QemuPluginId,
    apis: QemuBasicBlockCoverageApis,
    callback: CoverageCallback,
    map: CoverageMap,
    sink: LiveCoverageShmemProducer,
    // crucible-lint: allow rust-allow -- boxed entries keep QEMU userdata stable when the outer vector grows.
    #[allow(
        clippy::vec_box,
        reason = "QEMU retains stable userdata addresses while the outer vector may grow"
    )]
    translated_blocks: Vec<Box<LiveCoverageBlock>>,
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
    /// Returns [`CoverageError`] when the configured map is invalid, the ABI-v2
    /// output ring does not match it, or another live owner is already published.
    pub(crate) fn register(
        plugin_id: QemuPluginId,
        callback: CoverageCallback,
        apis: QemuBasicBlockCoverageApis,
        sink: LiveCoverageShmemProducer,
        quiescence: Arc<LiveCallbackQuiescence>,
    ) -> Result<Self, CoverageError> {
        let map_entries = callback.map_entries();
        if sink.capacity() != map_entries {
            return Err(CoverageError::CoverageQueueCapacityMismatch {
                map_entries,
                queue_capacity: sink.capacity(),
            });
        }
        let mut state = Box::pin(LiveCoverageInner {
            quiescence,
            plugin_id,
            apis,
            callback,
            map: CoverageMap::new(map_entries)?,
            sink,
            translated_blocks: Vec::new(),
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
            return Err(CoverageError::LiveRegistrationAlreadyExists { plugin_id });
        }
        (apis.register_flush_cb)(plugin_id, live_coverage_flush);
        (apis.register_tb_trans_cb)(plugin_id, Some(live_coverage_tb_translate));
        Ok(Self { state })
    }

    #[cfg(test)]
    fn drain_observations(&mut self) -> Vec<CoverageObservation> {
        // SAFETY: this test helper is called only after synchronous fake
        // callback invocation while the test holds the sole owner.
        unsafe { self.state.as_mut().get_unchecked_mut() }
            .sink
            .drain()
            .unwrap_or_else(|error| panic!("coverage test ring should drain: {error}"))
    }

    #[cfg(test)]
    fn map_entries(&self) -> Vec<u8> {
        self.state.as_ref().get_ref().map.entries().to_vec()
    }

    #[cfg(test)]
    fn translated_block_count(&self) -> usize {
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
    }
}

extern "C" fn live_coverage_tb_translate(plugin_id: QemuPluginId, tb: *mut QemuPluginTb) {
    if tb.is_null() {
        abort_live_coverage_callback(CoverageError::NullTranslatedBlock);
    }
    let state = LIVE_COVERAGE_STATE.load(Ordering::Acquire);
    if state.is_null() {
        return;
    }
    // SAFETY: registration publishes a fully initialized pinned state and the
    // plugin rejects QEMU modes that could invoke these callbacks concurrently.
    let state = unsafe { &mut *state };
    let Some(_in_flight) = state.quiescence.enter() else {
        // Teardown closed callback admission before this translation began.
        return;
    };
    if state.plugin_id != plugin_id {
        abort_live_coverage_callback(CoverageError::PluginIdMismatch {
            expected: state.plugin_id,
            actual: plugin_id,
        });
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

    let mut metadata = Box::new(LiveCoverageBlock {
        state: std::ptr::from_mut(state),
        instruction_count: instruction_count_u64,
        guest_pc,
        block_len,
    });
    let userdata = std::ptr::from_mut(metadata.as_mut()).cast::<c_void>();
    state.translated_blocks.push(metadata);
    (state.apis.register_tb_exec_cb)(
        tb,
        Some(live_coverage_tb_exec),
        QEMU_PLUGIN_CB_NO_REGS,
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
    // QEMU 10 emits the standard TB execution callback after `gen_tb_start`
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

extern "C" fn live_coverage_flush(plugin_id: QemuPluginId) {
    let state = LIVE_COVERAGE_STATE.load(Ordering::Acquire);
    if state.is_null() {
        return;
    }
    // SAFETY: QEMU 10's `plugins/core.c:qemu_plugin_flush_cb` removes and resets
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
    if state.plugin_id != plugin_id {
        abort_live_coverage_callback(CoverageError::PluginIdMismatch {
            expected: state.plugin_id,
            actual: plugin_id,
        });
    }
    state.translated_blocks.clear();
}

fn abort_live_coverage_callback(error: CoverageError) -> ! {
    // Callback failures are fatal invariants. Do not format, allocate, lock, or
    // perform diagnostic I/O on this FFI path, and never unwind into QEMU.
    let _error = error;
    std::process::abort();
}

/// One executed guest basic-block event from QEMU's TCG-exec callback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoverageBlockEvent {
    current_icount: u64,
    vcpu_index: u32,
    guest_pc: u64,
    block_len: u32,
}

impl CoverageBlockEvent {
    /// Builds a coverage event from QEMU callback metadata.
    #[must_use]
    pub const fn new(current_icount: u64, vcpu_index: u32, guest_pc: u64, block_len: u32) -> Self {
        Self {
            current_icount,
            vcpu_index,
            guest_pc,
            block_len,
        }
    }

    /// Returns the exact icount at which coverage was observed.
    #[must_use]
    pub const fn current_icount(self) -> u64 {
        self.current_icount
    }

    /// Returns the vCPU that executed the block.
    #[must_use]
    pub const fn vcpu_index(self) -> u32 {
        self.vcpu_index
    }

    /// Returns the guest program counter for the executed block.
    #[must_use]
    pub const fn guest_pc(self) -> u64 {
        self.guest_pc
    }

    /// Returns the translated block length supplied by QEMU.
    #[must_use]
    pub const fn block_len(self) -> u32 {
        self.block_len
    }
}

/// An observational coverage entry derived from one executed basic block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoverageObservation {
    current_icount: u64,
    vcpu_index: u32,
    guest_pc: u64,
    block_len: u32,
    map_index: usize,
    was_new: bool,
}

impl CoverageObservation {
    /// Returns the exact icount at which coverage was observed.
    #[must_use]
    pub const fn current_icount(self) -> u64 {
        self.current_icount
    }

    /// Returns the vCPU that executed the block.
    #[must_use]
    pub const fn vcpu_index(self) -> u32 {
        self.vcpu_index
    }

    /// Returns the guest program counter for the executed block.
    #[must_use]
    pub const fn guest_pc(self) -> u64 {
        self.guest_pc
    }

    /// Returns the translated block length supplied by QEMU.
    #[must_use]
    pub const fn block_len(self) -> u32 {
        self.block_len
    }

    /// Returns the fixed-map entry updated by this observation.
    #[must_use]
    pub const fn map_index(self) -> usize {
        self.map_index
    }

    /// Returns whether this block set a previously empty map entry.
    #[must_use]
    pub const fn was_new(self) -> bool {
        self.was_new
    }

    /// Converts this callback observation into the host/plugin protocol payload.
    ///
    /// # Errors
    ///
    /// Returns [`CoverageError::ProtocolObservation`] when the observation cannot
    /// be represented on the protocol boundary.
    pub fn to_protocol_observation(
        self,
    ) -> Result<PluginBasicBlockCoverageObservation, CoverageError> {
        PluginBasicBlockCoverageObservation::new(
            self.current_icount,
            self.vcpu_index,
            self.guest_pc,
            self.block_len,
            self.map_index as u64,
            self.was_new,
        )
        .map_err(|source| CoverageError::ProtocolObservation { source })
    }
}

/// A sink for observational coverage entries.
pub trait CoverageSink {
    /// Records one coverage observation.
    ///
    /// # Errors
    ///
    /// Returns [`CoverageSinkError`] when the event-log path cannot accept the
    /// coverage entry and must fail loudly.
    fn record_coverage(
        &mut self,
        observation: &CoverageObservation,
    ) -> Result<(), CoverageSinkError>;
}

/// A loud coverage-sink failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("coverage sink failed: {message}")]
pub struct CoverageSinkError {
    message: Cow<'static, str>,
}

impl CoverageSinkError {
    /// Builds a coverage-sink error.
    #[must_use]
    pub fn new(message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Builds a borrowed coverage-sink error without allocating.
    #[must_use]
    pub const fn from_static(message: &'static str) -> Self {
        Self {
            message: Cow::Borrowed(message),
        }
    }

    /// Returns the backend diagnostic.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// An error produced by coverage hook handling.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CoverageError {
    /// The required QEMU TCG-exec callback registration export is unavailable.
    #[error("required coverage capability {symbol} is unavailable")]
    CapabilityUnavailable {
        /// The missing capability label.
        symbol: &'static str,
    },
    /// A live callback owner was already registered for this QEMU plugin ID.
    #[error("live coverage callbacks are already registered for plugin {plugin_id}")]
    LiveRegistrationAlreadyExists {
        /// Conflicting QEMU plugin identifier.
        plugin_id: QemuPluginId,
    },
    /// The process-lifetime owner no longer matched the published callback state.
    #[error("live coverage callback ownership was lost before teardown")]
    LiveRegistrationOwnershipLost,
    /// The shared-memory queue does not match the fixed coverage map.
    #[error("coverage map has {map_entries} entries but plugin-to-host queue has {queue_capacity}")]
    CoverageQueueCapacityMismatch {
        /// Registration-time coverage-map cardinality.
        map_entries: usize,
        /// Mapped plugin-to-host queue capacity.
        queue_capacity: usize,
    },
    /// The setup mapping could not expose the assigned VM's coverage queue.
    #[error("mapped plugin-to-host coverage queue is invalid")]
    MappedCoverageQueue {
        /// Mapped shared-memory access failure.
        #[source]
        source: crucible_shmem::MappedSetupRegionAccessError,
    },
    /// QEMU invoked the translation callback without a translated-block handle.
    #[error("QEMU invoked coverage translation with a null block handle")]
    NullTranslatedBlock,
    /// QEMU invoked the singleton translation callback for another plugin ID.
    #[error("coverage callback plugin ID mismatch: expected {expected}, got {actual}")]
    PluginIdMismatch {
        /// Registered QEMU plugin identifier.
        expected: QemuPluginId,
        /// Identifier supplied to the callback.
        actual: QemuPluginId,
    },
    /// QEMU supplied a translation block without instructions.
    #[error("QEMU supplied an empty translated block")]
    EmptyTranslatedBlock,
    /// QEMU returned a null instruction handle for a valid block index.
    #[error("QEMU returned a null translated instruction at index {index}")]
    NullTranslatedInstruction {
        /// Index whose instruction handle was null.
        index: usize,
    },
    /// Summing translated instruction sizes overflowed the protocol block length.
    #[error("translated block length does not fit the coverage protocol")]
    TranslatedBlockLengthOverflow,
    /// QEMU's translated-block instruction count did not fit the public ABI.
    #[error("translated block instruction count does not fit the coverage ABI")]
    TranslatedBlockInstructionCountOverflow,
    /// QEMU could not provide an exact, non-mutating TB-entry icount.
    #[error(
        "exact TB-entry icount is unavailable for {instruction_count} instructions (status {status})"
    )]
    TbEntryIcountUnavailable {
        /// Instruction count supplied when the execution callback was registered.
        instruction_count: u64,
        /// Status returned by QEMU's exact-entry helper.
        status: c_int,
    },
    /// QEMU invoked a block execution callback without its registered metadata.
    #[error("QEMU invoked coverage execution with null userdata")]
    NullExecutionUserdata,
    /// The fixed coverage map size is invalid.
    #[error("coverage map entries {entries} must be a nonzero power of two")]
    InvalidMapEntries {
        /// Rejected entry count.
        entries: usize,
    },
    /// A coverage callback fired even though coverage mode is disabled.
    #[error("coverage callback fired while coverage mode is disabled")]
    CallbackWhileDisabled,
    /// The callback was handed a map whose size differs from registration state.
    #[error("coverage map size mismatch: expected {expected} entries, got {actual}")]
    MapSizeMismatch {
        /// Registration-time entry count.
        expected: usize,
        /// Supplied map entry count.
        actual: usize,
    },
    /// The computed coverage map index is outside the map.
    #[error("coverage map index {index} is outside {entries} entries")]
    MapIndexOutOfBounds {
        /// Computed index.
        index: usize,
        /// Map entry count.
        entries: usize,
    },
    /// QEMU supplied an impossible basic-block length.
    #[error("coverage block length {block_len} is invalid")]
    InvalidBlockLength {
        /// Rejected block length.
        block_len: u32,
    },
    /// Recording the observational coverage entry failed.
    #[error("coverage event for map index {map_index} could not be recorded: {source}")]
    Sink {
        /// Coverage map index.
        map_index: usize,
        /// Sink failure.
        source: CoverageSinkError,
    },
    /// The callback observation could not be represented for the host.
    #[error("coverage protocol observation could not be built: {source}")]
    ProtocolObservation {
        /// Protocol boundary validation failure.
        source: PluginBasicBlockCoverageObservationError,
    },
}

/// Folds a guest basic-block PC into a fixed-size coverage map.
///
/// # Panics
///
/// Panics if `map_entries` is not a nonzero power of two. Production callers use
/// [`PluginCoverage::registration_plan`] and [`CoverageMap::new`] to validate
/// the map size before callback execution.
#[must_use]
pub fn fold_basic_block_pc(guest_pc: u64, map_entries: usize) -> usize {
    assert!(
        map_entries.is_power_of_two(),
        "coverage map size must be a power of two"
    );
    let folded = guest_pc ^ guest_pc.rotate_right(17) ^ (guest_pc >> 32);
    (folded as usize) & (map_entries - 1)
}

fn validate_map_entries(entries: usize) -> Result<(), CoverageError> {
    if entries == 0 || !entries.is_power_of_two() {
        Err(CoverageError::InvalidMapEntries { entries })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
