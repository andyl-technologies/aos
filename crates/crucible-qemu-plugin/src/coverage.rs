//! Optional TCG-exec basic-block coverage callback core.
//!
//! Coverage is a registration-time opt-in. When disabled, the registration plan
//! installs no TCG-exec callback, leaving the hot execution path without a
//! per-block branch. When enabled, the safe callback body folds each executed
//! guest basic-block PC into a fixed-size map and records an observational event.

use std::os::raw::{c_uint, c_void};

use crucible_protocol::{
    PluginBasicBlockCoverageObservation, PluginBasicBlockCoverageObservationError,
};
use thiserror::Error;

use crate::{PluginSwitch, QemuRegisterTcgExecCbFn};

/// QEMU capability label for registering the TCG-exec coverage callback.
pub const QEMU_PLUGIN_REGISTER_TCG_EXEC_CB_SYMBOL: &str = "qemu_plugin_register_tcg_exec_cb";
/// Default number of entries in the fixed-size coverage map.
pub const DEFAULT_COVERAGE_MAP_ENTRIES: usize = 65_536;

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
        if !capabilities.register_tcg_exec_cb() {
            return Err(CoverageError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_REGISTER_TCG_EXEC_CB_SYMBOL,
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

/// QEMU capabilities needed by the optional coverage hook.
#[derive(Clone, Copy, Debug, Default)]
pub struct CoverageCapabilities {
    register_tcg_exec_cb: Option<QemuRegisterTcgExecCbFn>,
}

impl CoverageCapabilities {
    /// Returns an empty capability set.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            register_tcg_exec_cb: None,
        }
    }

    /// Returns capabilities sufficient for coverage registration.
    #[must_use]
    pub const fn tcg_exec(register_tcg_exec_cb: QemuRegisterTcgExecCbFn) -> Self {
        Self {
            register_tcg_exec_cb: Some(register_tcg_exec_cb),
        }
    }

    /// Returns whether QEMU can register the TCG-exec callback.
    #[must_use]
    pub const fn register_tcg_exec_cb(self) -> bool {
        self.register_tcg_exec_cb.is_some()
    }

    /// Returns QEMU's TCG-exec callback registration function, if available.
    #[must_use]
    pub const fn register_tcg_exec_cb_fn(self) -> Option<QemuRegisterTcgExecCbFn> {
        self.register_tcg_exec_cb
    }
}

/// Minimal QEMU-facing TCG-exec callback registered by T-PATCH-11.
///
/// This callback proves that QEMU can call back into the plugin after
/// `tcg_cpu_exec` with the current vCPU and raw icount. The later coverage gate
/// owns the richer basic-block event path that supplies guest PC and block
/// length to [`handle_coverage_exec_callback`].
pub extern "C" fn crucible_qemu_plugin_coverage_exec_cb(
    vcpu_index: c_uint,
    icount: u64,
    userdata: *mut c_void,
) {
    let _ = (vcpu_index, icount, userdata);
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
    message: String,
}

impl CoverageSinkError {
    /// Builds a coverage-sink error.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
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
mod tests {
    use super::*;

    fn coverage_callback(coverage: PluginCoverage) -> CoverageCallback {
        let plan = coverage
            .registration_plan(CoverageCapabilities::tcg_exec(test_register_tcg_exec_cb))
            .unwrap_or_else(|error| panic!("enabled coverage should register: {error}"));
        plan.require_callback()
            .unwrap_or_else(|error| panic!("enabled coverage should expose callback: {error}"))
    }

    #[test]
    fn coverage_registration_off_mode_installs_no_callback_and_ignores_map_config() {
        let coverage = PluginCoverage::new(PluginSwitch::Off, 0);

        let plan = match coverage.registration_plan(CoverageCapabilities::none()) {
            Ok(plan) => plan,
            Err(error) => panic!("off-mode should not validate coverage config: {error}"),
        };

        assert_eq!(plan, CoverageRegistrationPlan::Disabled);
        assert!(!plan.installs_callback());
        assert!(plan.hot_path_has_zero_coverage_overhead());
        assert_eq!(
            plan.require_callback(),
            Err(CoverageError::CallbackWhileDisabled)
        );
    }

    #[test]
    fn coverage_registration_on_mode_requires_tcg_exec_capability() {
        let coverage = PluginCoverage::new(PluginSwitch::On, 1024);

        assert_eq!(
            coverage.registration_plan(CoverageCapabilities::none()),
            Err(CoverageError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_REGISTER_TCG_EXEC_CB_SYMBOL,
            })
        );
        let plan = coverage
            .registration_plan(CoverageCapabilities::tcg_exec(test_register_tcg_exec_cb))
            .unwrap_or_else(|error| panic!("coverage registration should succeed: {error}"));
        assert_eq!(
            plan,
            CoverageRegistrationPlan::Install { map_entries: 1024 }
        );
        assert_eq!(
            plan.require_callback()
                .unwrap_or_else(|error| panic!("enabled plan should expose callback: {error}"))
                .map_entries(),
            1024
        );
    }

    #[test]
    fn coverage_registration_rejects_invalid_enabled_map_size() {
        assert_eq!(
            PluginCoverage::new(PluginSwitch::On, 0)
                .registration_plan(CoverageCapabilities::tcg_exec(test_register_tcg_exec_cb)),
            Err(CoverageError::InvalidMapEntries { entries: 0 })
        );
        assert_eq!(
            PluginCoverage::new(PluginSwitch::On, 1000)
                .registration_plan(CoverageCapabilities::tcg_exec(test_register_tcg_exec_cb)),
            Err(CoverageError::InvalidMapEntries { entries: 1000 })
        );
    }

    #[test]
    fn coverage_exec_callback_folds_basic_block_pc_and_records_observation() {
        let callback = coverage_callback(PluginCoverage::new(PluginSwitch::On, 1024));
        let mut map = CoverageMap::new(1024)
            .unwrap_or_else(|error| panic!("coverage map should build: {error}"));
        let mut sink = RecordingCoverageSink::default();
        let event = CoverageBlockEvent::new(77, 2, 0x4010, 16);
        let expected_index = fold_basic_block_pc(0x4010, 1024);

        let observation = match handle_coverage_exec_callback(&callback, &mut map, &mut sink, event)
        {
            Ok(observation) => observation,
            Err(error) => panic!("coverage event should record: {error}"),
        };

        assert_eq!(observation.current_icount(), 77);
        assert_eq!(observation.vcpu_index(), 2);
        assert_eq!(observation.guest_pc(), 0x4010);
        assert_eq!(observation.block_len(), 16);
        assert_eq!(observation.map_index(), expected_index);
        assert!(observation.was_new());
        assert_eq!(map.entries()[expected_index], 1);
        assert_eq!(sink.observations, vec![observation]);
    }

    #[test]
    fn coverage_exec_callback_uses_saturating_counters_without_new_signal_on_repeat() {
        let callback = coverage_callback(PluginCoverage::new(PluginSwitch::On, 16));
        let mut map = CoverageMap::new(16)
            .unwrap_or_else(|error| panic!("coverage map should build: {error}"));
        let mut sink = RecordingCoverageSink::default();
        let event = CoverageBlockEvent::new(77, 0, 0x4010, 8);
        let index = fold_basic_block_pc(0x4010, 16);

        let first = callback
            .record_basic_block(&mut map, &mut sink, event)
            .unwrap_or_else(|error| panic!("first coverage event should record: {error}"));
        let second = callback
            .record_basic_block(&mut map, &mut sink, event)
            .unwrap_or_else(|error| panic!("second coverage event should record: {error}"));

        assert!(first.was_new());
        assert!(!second.was_new());
        assert_eq!(map.entries()[index], 2);
        assert_eq!(sink.observations, vec![first, second]);
    }

    #[test]
    fn coverage_disabled_plan_cannot_build_hot_callback_and_does_not_touch_map() {
        let coverage = PluginCoverage::new(PluginSwitch::Off, 16);
        let plan = coverage
            .registration_plan(CoverageCapabilities::tcg_exec(test_register_tcg_exec_cb))
            .unwrap_or_else(|error| panic!("off-mode coverage should not validate caps: {error}"));
        let map = CoverageMap::new(16)
            .unwrap_or_else(|error| panic!("coverage map should build: {error}"));
        let sink = RecordingCoverageSink::default();

        assert_eq!(
            plan.require_callback(),
            Err(CoverageError::CallbackWhileDisabled)
        );
        assert!(map.entries().iter().all(|entry| *entry == 0));
        assert!(sink.observations.is_empty());
    }

    #[test]
    fn coverage_exec_callback_rejects_wrong_map_size_before_recording() {
        let callback = coverage_callback(PluginCoverage::new(PluginSwitch::On, 32));
        let mut map = CoverageMap::new(16)
            .unwrap_or_else(|error| panic!("coverage map should build: {error}"));
        let mut sink = RecordingCoverageSink::default();

        assert_eq!(
            callback.record_basic_block(
                &mut map,
                &mut sink,
                CoverageBlockEvent::new(1, 0, 0x4010, 8),
            ),
            Err(CoverageError::MapSizeMismatch {
                expected: 32,
                actual: 16,
            })
        );
        assert!(map.entries().iter().all(|entry| *entry == 0));
        assert!(sink.observations.is_empty());
    }

    extern "C" fn test_register_tcg_exec_cb(
        _callback: Option<crate::QemuTcgExecCbFn>,
        _userdata: *mut std::os::raw::c_void,
    ) {
    }

    #[test]
    fn coverage_exec_callback_rejects_zero_length_basic_block() {
        let callback = coverage_callback(PluginCoverage::new(PluginSwitch::On, 16));
        let mut map = CoverageMap::new(16)
            .unwrap_or_else(|error| panic!("coverage map should build: {error}"));
        let mut sink = RecordingCoverageSink::default();

        assert_eq!(
            callback.record_basic_block(
                &mut map,
                &mut sink,
                CoverageBlockEvent::new(1, 0, 0x4010, 0),
            ),
            Err(CoverageError::InvalidBlockLength { block_len: 0 })
        );
        assert!(map.entries().iter().all(|entry| *entry == 0));
        assert!(sink.observations.is_empty());
    }

    #[test]
    fn coverage_exec_callback_exports_protocol_basic_block_observation() {
        let callback = coverage_callback(PluginCoverage::new(PluginSwitch::On, 1024));
        let mut map = CoverageMap::new(1024)
            .unwrap_or_else(|error| panic!("coverage map should build: {error}"));
        let mut sink = RecordingCoverageSink::default();

        let plugin_observation = handle_coverage_exec_callback(
            &callback,
            &mut map,
            &mut sink,
            CoverageBlockEvent::new(77, 2, 0x4010, 16),
        )
        .unwrap_or_else(|error| panic!("plugin callback should record coverage: {error}"));
        let protocol_observation =
            plugin_observation
                .to_protocol_observation()
                .unwrap_or_else(|error| {
                    panic!("plugin observation should export to protocol: {error}")
                });

        assert_eq!(protocol_observation.current_icount(), 77);
        assert_eq!(protocol_observation.vcpu_index(), 2);
        assert_eq!(protocol_observation.guest_pc(), 0x4010);
        assert_eq!(protocol_observation.block_len(), 16);
        assert_eq!(
            protocol_observation.map_index(),
            fold_basic_block_pc(0x4010, 1024) as u64
        );
        assert!(protocol_observation.was_new());
    }

    #[derive(Default)]
    struct RecordingCoverageSink {
        observations: Vec<CoverageObservation>,
    }

    impl CoverageSink for RecordingCoverageSink {
        fn record_coverage(
            &mut self,
            observation: &CoverageObservation,
        ) -> Result<(), CoverageSinkError> {
            self.observations.push(*observation);
            Ok(())
        }
    }
}
