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

use crucible_shmem::{CoverageEntry, RingHeader, SpscRingError};
use thiserror::Error;

use crate::runtime::callback_quiescence::LiveCallbackQuiescence;
use crate::{PluginSwitch, QemuPluginId};

/// QEMU runtime hook retained for non-coverage post-exec integration.
/// QEMU capability label for registering the translation callback.
pub const QEMU_PLUGIN_REGISTER_VCPU_TB_TRANS_CB_SYMBOL: &str =
    "qemu_plugin_register_vcpu_tb_trans_cb";
/// QEMU capability label for registering a conditional translated-block callback.
pub const QEMU_PLUGIN_REGISTER_VCPU_TB_EXEC_COND_CB_SYMBOL: &str =
    "qemu_plugin_register_vcpu_tb_exec_cond_cb";
/// QEMU capability label for allocating a per-vCPU scoreboard.
pub const QEMU_PLUGIN_SCOREBOARD_NEW_SYMBOL: &str = "qemu_plugin_scoreboard_new";
/// QEMU capability label for releasing a per-vCPU scoreboard.
pub const QEMU_PLUGIN_SCOREBOARD_FREE_SYMBOL: &str = "qemu_plugin_scoreboard_free";
/// QEMU capability label for updating a per-vCPU scoreboard entry.
pub const QEMU_PLUGIN_U64_SET_SYMBOL: &str = "qemu_plugin_u64_set";
/// QEMU capability label for observing the configured vCPU count.
pub const QEMU_PLUGIN_NUM_VCPUS_SYMBOL: &str = "qemu_plugin_num_vcpus";
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

/// Opaque QEMU per-vCPU scoreboard handle.
#[repr(C)]
pub struct QemuPluginScoreboard {
    _private: [u8; 0],
}

/// QEMU scoreboard entry passed to conditional callback registration.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct QemuPluginU64 {
    score: *mut QemuPluginScoreboard,
    offset: usize,
}

/// QEMU callback invoked when one translation block is created.
pub(crate) type QemuVcpuTbTransCbFn = extern "C" fn(tb: *mut QemuPluginTb, userdata: *mut c_void);

/// One translation consumer retained by a process-lifetime callback owner.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LiveTbTranslationConsumer {
    callback: QemuVcpuTbTransCbFn,
    userdata: *mut c_void,
}

impl LiveTbTranslationConsumer {
    /// Captures a callback and the exact userdata owned by its live subsystem.
    pub(crate) const fn new(callback: QemuVcpuTbTransCbFn, userdata: *mut c_void) -> Self {
        Self { callback, userdata }
    }

    /// Returns the callback address held by the consumer.
    pub(crate) const fn callback(self) -> QemuVcpuTbTransCbFn {
        self.callback
    }

    /// Returns the exact subsystem-owned userdata paired with the callback.
    pub(crate) const fn userdata(self) -> *mut c_void {
        self.userdata
    }

    fn dispatch(self, tb: *mut QemuPluginTb) {
        (self.callback)(tb, self.userdata);
    }
}

/// QEMU callback invoked when one translated block executes.
pub type QemuVcpuTbExecCbFn = extern "C" fn(vcpu_index: c_uint, userdata: *mut c_void);
/// QEMU callback invoked after dynamic callbacks have been removed for a flush.
pub(crate) type QemuPluginSimpleCbFn = extern "C" fn(userdata: *mut c_void);
/// QEMU function that registers the plugin-wide translation callback.
pub(crate) type QemuRegisterVcpuTbTransCbFn = extern "C" fn(
    plugin_id: QemuPluginId,
    callback: Option<QemuVcpuTbTransCbFn>,
    userdata: *mut c_void,
);
/// QEMU function that registers a conditionally executed block callback.
pub type QemuRegisterVcpuTbExecCondCbFn = extern "C" fn(
    tb: *mut QemuPluginTb,
    callback: Option<QemuVcpuTbExecCbFn>,
    flags: c_int,
    condition: c_int,
    entry: QemuPluginU64,
    immediate: u64,
    userdata: *mut c_void,
);
/// QEMU function that registers a plugin-wide translation-cache flush callback.
pub type QemuRegisterFlushCbFn =
    extern "C" fn(plugin_id: QemuPluginId, callback: QemuPluginSimpleCbFn, userdata: *mut c_void);
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
/// QEMU function that allocates one scoreboard element per vCPU.
pub type QemuPluginScoreboardNewFn =
    extern "C" fn(element_size: usize) -> *mut QemuPluginScoreboard;
/// QEMU function that releases a scoreboard after generated callbacks are gone.
pub type QemuPluginScoreboardFreeFn = extern "C" fn(score: *mut QemuPluginScoreboard);
/// QEMU function that writes one scoreboard entry for a selected vCPU.
pub type QemuPluginU64SetFn = extern "C" fn(entry: QemuPluginU64, vcpu_index: c_uint, value: u64);
/// QEMU function that returns the configured number of vCPUs.
pub type QemuPluginNumVcpusFn = extern "C" fn() -> c_int;

const QEMU_PLUGIN_CB_NO_REGS: c_int = 0;
const QEMU_PLUGIN_COND_EQ: c_int = 2;

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
    register_tb_exec_cond_cb: QemuRegisterVcpuTbExecCondCbFn,
    tb_vaddr: QemuTbVaddrFn,
    tb_n_insns: QemuTbNInsnsFn,
    tb_get_insn: QemuTbGetInsnFn,
    insn_size: QemuInsnSizeFn,
    icount_at_tb_entry: QemuIcountAtTbEntryFn,
    register_flush_cb: QemuRegisterFlushCbFn,
    scoreboard_new: QemuPluginScoreboardNewFn,
    scoreboard_free: QemuPluginScoreboardFreeFn,
    u64_set: QemuPluginU64SetFn,
    num_vcpus: QemuPluginNumVcpusFn,
}

impl QemuBasicBlockCoverageApis {
    /// Builds a complete QEMU basic-block callback API table.
    #[must_use]
    // crucible-lint: allow rust-allow -- the constructor mirrors twelve independent QEMU callback ABI exports.
    #[allow(
        clippy::too_many_arguments,
        reason = "the constructor mirrors twelve independent QEMU callback ABI exports"
    )]
    pub const fn new(
        register_tb_trans_cb: QemuRegisterVcpuTbTransCbFn,
        register_tb_exec_cond_cb: QemuRegisterVcpuTbExecCondCbFn,
        tb_vaddr: QemuTbVaddrFn,
        tb_n_insns: QemuTbNInsnsFn,
        tb_get_insn: QemuTbGetInsnFn,
        insn_size: QemuInsnSizeFn,
        icount_at_tb_entry: QemuIcountAtTbEntryFn,
        register_flush_cb: QemuRegisterFlushCbFn,
        scoreboard_new: QemuPluginScoreboardNewFn,
        scoreboard_free: QemuPluginScoreboardFreeFn,
        u64_set: QemuPluginU64SetFn,
        num_vcpus: QemuPluginNumVcpusFn,
    ) -> Self {
        Self {
            register_tb_trans_cb,
            register_tb_exec_cond_cb,
            tb_vaddr,
            tb_n_insns,
            tb_get_insn,
            insn_size,
            icount_at_tb_entry,
            register_flush_cb,
            scoreboard_new,
            scoreboard_free,
            u64_set,
            num_vcpus,
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

    fn reset(&mut self) {
        self.entries.fill(0);
    }
}

mod live;

#[cfg(test)]
use live::LIVE_COVERAGE_STATE;
pub(crate) use live::{
    LiveBasicBlockCoverage, LiveCoverageShmemProducer, reset_live_coverage_for_restore,
};

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
    /// The logical restore transaction supplied the reserved zero generation.
    #[error("coverage restore generation {generation} is invalid")]
    InvalidRestoreGeneration {
        /// Rejected generation.
        generation: u32,
    },
    /// A second logical restore attempted to reuse one process coverage owner.
    #[error("coverage restore generation {requested} follows already-applied generation {applied}")]
    RestoreGenerationReused {
        /// Previously applied generation.
        applied: u32,
        /// Newly requested generation.
        requested: u32,
    },
    /// Coverage reset was requested after callback admission closed.
    #[error("coverage restore reset was requested during callback teardown")]
    RestoreDuringTeardown,
    /// QEMU reported an invalid live vCPU count for scoreboard reset.
    #[error("QEMU reported invalid live vCPU count {vcpu_count} for coverage restore")]
    InvalidLiveVcpuCount {
        /// Rejected count returned by QEMU.
        vcpu_count: c_int,
    },
    /// The shared coverage ring could not be reset at the paused boundary.
    #[error("coverage restore ring reset failed")]
    RestoreRing {
        /// Shared-memory ring failure.
        #[source]
        source: SpscRingError,
    },
    /// The shared-memory queue does not match the fixed coverage map.
    #[error("coverage map has {map_entries} entries but plugin-to-host queue has {queue_capacity}")]
    CoverageQueueCapacityMismatch {
        /// Registration-time coverage-map cardinality.
        map_entries: usize,
        /// Mapped plugin-to-host queue capacity.
        queue_capacity: usize,
    },
    /// The configured coverage map cannot fit in QEMU's scoreboard element size.
    #[error("coverage novelty scoreboard size overflowed for {map_entries} entries")]
    NoveltyScoreboardSizeOverflow {
        /// Registration-time coverage-map cardinality.
        map_entries: usize,
    },
    /// QEMU could not allocate the fixed per-vCPU novelty scoreboard.
    #[error("QEMU could not allocate a {scoreboard_size}-byte coverage novelty scoreboard")]
    NoveltyScoreboardAllocation {
        /// Requested bytes per vCPU.
        scoreboard_size: usize,
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
