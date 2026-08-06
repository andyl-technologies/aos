//! Guest workload parameters, fixtures, and black-box configuration.

use super::*;
/// Default app-random draw cap for scenarios that do not opt into a tighter cap.
pub const DEFAULT_APP_RANDOM_DRAW_CAP: u64 = u64::MAX;

/// Kernel command-line key that selects a supported in-guest workload binary.
///
/// The value is part of [`WorldNode::cmdline`], so changing the selected
/// workload changes the world's content address and the enclosing
/// [`ScenarioDef`].
pub const WORKLOAD_SCENARIO_PARAMETER: &str = "crucible.workload";

pub(super) const WORKLOAD_SCENARIO_PARAMETER_PREFIX: &str = "crucible.workload=";

/// Kernel command-line key that delivers an explicit in-guest workload seed.
///
/// The seed is delivered as plain scenario configuration on
/// [`WorldNode::cmdline`]. This black-box path is sufficient without the
/// optional guest-host channel, and changing the value changes the world's
/// content address and the enclosing [`ScenarioDef`].
pub const WORKLOAD_SEED_SCENARIO_PARAMETER: &str = "wseed";

pub(super) const WORKLOAD_SEED_SCENARIO_PARAMETER_PREFIX: &str = "wseed=";

/// Kernel command-line key that selects a classic in-guest load pattern.
///
/// The pattern is plain scenario configuration on [`WorldNode::cmdline`]. It
/// changes the world content address and scenario identity without introducing a
/// host-side load-generation subsystem.
pub const WORKLOAD_LOAD_PATTERN_SCENARIO_PARAMETER: &str = "load_pattern";

pub(super) const WORKLOAD_LOAD_PATTERN_SCENARIO_PARAMETER_PREFIX: &str = "load_pattern=";

/// Kernel command-line key that selects how a spike pattern is expressed.
///
/// The mode is a scenario parameter consumed by the in-guest workload. A spike
/// can also be represented by starting a declared baked node through the
/// ordinary [`Plan`] event-graph control path.
pub const WORKLOAD_SPIKE_MODE_SCENARIO_PARAMETER: &str = "spike_mode";

pub(super) const WORKLOAD_SPIKE_MODE_SCENARIO_PARAMETER_PREFIX: &str = "spike_mode=";

/// Kernel command-line key that declares the clock driving load variation.
///
/// Time-varying load shapes use this scenario parameter to make the clock source
/// explicit. The only supported value is virtual time; host wall-clock time is
/// not an admissible load-shape input.
pub const WORKLOAD_TIME_SOURCE_SCENARIO_PARAMETER: &str = "load_time_source";

pub(super) const WORKLOAD_TIME_SOURCE_SCENARIO_PARAMETER_PREFIX: &str = "load_time_source=";

/// Kernel command-line key that declares a structured workload config tree.
///
/// The value is a content-addressed, read-only tree reference. It is still plain
/// scenario configuration on [`WorldNode::cmdline`], and the referenced content
/// hash therefore contributes to the world's canonical material.
pub const WORKLOAD_CONFIG_TREE_SCENARIO_PARAMETER: &str = "wcfg";

pub(super) const WORKLOAD_CONFIG_TREE_SCENARIO_PARAMETER_PREFIX: &str = "wcfg=";

/// Whether explicit workload seeds can be delivered without white-box support.
pub const WORKLOAD_SEED_BLACK_BOX_CONFIG_SUFFICES: bool = true;

/// Whether explicit workload seeds require the optional guest-host channel.
pub const WORKLOAD_SEED_REQUIRES_WHITE_BOX: bool = false;

/// Whether load-pattern configuration can be delivered without white-box support.
pub const WORKLOAD_LOAD_PATTERN_BLACK_BOX_CONFIG_SUFFICES: bool = true;

/// Whether load-pattern configuration requires the optional guest-host channel.
pub const WORKLOAD_LOAD_PATTERN_REQUIRES_WHITE_BOX: bool = false;

/// Whether time-varying load shapes must derive from virtual time.
pub const WORKLOAD_TIME_VARIATION_REQUIRES_VIRTUAL_TIME: bool = true;

/// Whether load shapes may derive their variation from the host wall clock.
pub const WORKLOAD_HOST_WALL_CLOCK_LOAD_SHAPES_ALLOWED: bool = false;

/// Whether workload parameters are immutable scenario-definition material.
pub const WORKLOAD_PARAMETERS_ARE_SCENARIO_CONFIG: bool = true;

/// Whether structured workload config trees are served read-only to the guest.
pub const WORKLOAD_CONFIG_TREES_ARE_READ_ONLY: bool = true;

/// Whether workload parameterization may use host runtime pokes after boot.
pub const WORKLOAD_PARAMETER_HOST_RUNTIME_POKES_ALLOWED: bool = false;

/// Whether 9p workload config trees use path-hashed QIDs.
pub const WORKLOAD_CONFIG_TREE_DETERMINISTIC_QIDS: bool = true;

/// Whether 9p workload config-tree directory enumeration is sorted.
pub const WORKLOAD_CONFIG_TREE_SORTED_ENUMERATION: bool = true;

/// Whether Crucible's application traffic originates inside guest VMs.
///
/// This constant is deliberately true: the engine observes and steers guest
/// execution, but it does not synthesize application records and feed them into a
/// guest from the host.
pub const APPLICATION_TRAFFIC_ORIGINATES_IN_GUEST: bool = true;

/// The engine's role in the workload model.
///
/// Crucible is allowed to observe frames, I/O, console output, and lifecycle
/// state, and to steer the world through faults and virtual-time events. It is
/// not a participant that originates application-level traffic.
pub const WORKLOAD_ENGINE_ROLE: WorkloadEngineRole = WorkloadEngineRole::ObservationAndSteeringOnly;

/// A supported guest binary that can produce workload traffic or I/O.
///
/// The selection is delivered as a scenario parameter on the guest command line;
/// the binary itself remains ordinary guest content referenced by the kernel,
/// root image, or initrd.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GuestWorkloadBinary {
    /// An HTTP daemon that serves request traffic in-guest.
    Httpd,
    /// A client request loop that drives request traffic in-guest.
    ClientLoop,
    /// A benchmark driver that produces load or storage I/O in-guest.
    Benchmark,
}

impl GuestWorkloadBinary {
    /// The closed set of guest workload binaries supported by the model.
    pub const SUPPORTED: [Self; 3] = [Self::Httpd, Self::ClientLoop, Self::Benchmark];

    /// Returns the scenario-parameter value for this workload binary.
    #[must_use]
    pub const fn scenario_parameter_value(self) -> &'static str {
        match self {
            Self::Httpd => "httpd",
            Self::ClientLoop => "httpget",
            Self::Benchmark => "bench",
        }
    }

    /// Returns the human-readable workload name used by diagnostics and docs.
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Httpd => "httpd",
            Self::ClientLoop => "client loop",
            Self::Benchmark => "benchmark",
        }
    }

    /// Parses a workload binary from a scenario-parameter value.
    #[must_use]
    pub fn from_scenario_parameter_value(value: &str) -> Option<Self> {
        match value {
            "httpd" => Some(Self::Httpd),
            "httpget" => Some(Self::ClientLoop),
            "bench" => Some(Self::Benchmark),
            _ => None,
        }
    }

    /// Parses the first supported workload selection from a kernel command line.
    #[must_use]
    pub fn from_cmdline(cmdline: &str) -> Option<Self> {
        parse_guest_workload_parameter(cmdline)
    }

    /// Renders this workload as a kernel command-line scenario parameter.
    #[must_use]
    pub fn scenario_parameter(self) -> String {
        format!(
            "{WORKLOAD_SCENARIO_PARAMETER}={}",
            self.scenario_parameter_value()
        )
    }

    /// Returns `base_cmdline` with this workload selected by scenario parameter.
    ///
    /// Existing `crucible.workload=...` tokens are replaced so the command line
    /// carries one stable workload selection. Whitespace is normalized by kernel
    /// argument tokenization.
    #[must_use]
    pub fn selected_cmdline(self, base_cmdline: &str) -> String {
        cmdline_with_guest_workload(base_cmdline, self)
    }
}

/// An explicit seed consumed by a selected in-guest workload.
///
/// The seed is a scenario parameter, not a host-side delivery channel. Rendering
/// it into a node command line makes it part of the canonical world and scenario
/// identity, while leaving the optional white-box guest-host channel disabled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GuestWorkloadSeed {
    pub(super) seed: Seed,
}

impl GuestWorkloadSeed {
    /// Builds an explicit workload seed from a 256-bit scenario seed value.
    #[must_use]
    pub fn from_seed(seed: Seed) -> Self {
        Self { seed }
    }

    /// Builds an explicit workload seed from a small deterministic integer.
    ///
    /// This is a convenience constructor for examples and tests. The integer is
    /// encoded by [`Seed::from_u64`].
    #[must_use]
    pub fn from_u64(value: u64) -> Self {
        Self::from_seed(Seed::from_u64(value))
    }

    /// Returns the underlying 256-bit workload seed.
    #[must_use]
    pub fn seed(self) -> Seed {
        self.seed
    }

    /// Parses a workload seed from a `wseed` scenario-parameter value.
    #[must_use]
    pub fn from_scenario_parameter_value(value: &str) -> Option<Self> {
        parse_seed_ref(value).ok().map(Self::from_seed)
    }

    /// Parses the first valid workload seed from a kernel command line.
    #[must_use]
    pub fn from_cmdline(cmdline: &str) -> Option<Self> {
        parse_guest_workload_seed_parameter(cmdline)
    }

    /// Returns the value used by the workload-seed scenario parameter.
    #[must_use]
    pub fn scenario_parameter_value(self) -> String {
        format_seed_ref(self.seed)
    }

    /// Renders this seed as a workload-seed scenario parameter.
    #[must_use]
    pub fn scenario_parameter(self) -> String {
        format!(
            "{WORKLOAD_SEED_SCENARIO_PARAMETER}={}",
            self.scenario_parameter_value()
        )
    }

    /// Returns `base_cmdline` with this explicit workload seed selected.
    ///
    /// Existing `wseed=...` tokens are replaced so the command line carries one
    /// stable black-box workload-seed configuration value.
    #[must_use]
    pub fn selected_cmdline(self, base_cmdline: &str) -> String {
        cmdline_with_guest_workload_seed(base_cmdline, self)
    }
}

/// A supported scalar workload-parameter key carried on the guest command line.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GuestWorkloadParameterKey {
    /// Request target, such as `server:8080`.
    Target,
    /// Generic request or operation rate.
    Rate,
    /// Request or operation rate per second.
    RatePerSec,
    /// Baseline request or operation rate per second.
    BaseRatePerSec,
    /// Peak request or operation rate per second.
    PeakRatePerSec,
    /// Burst request or operation rate per second.
    BurstRatePerSec,
    /// Total request or operation count.
    Count,
    /// Payload size in bytes.
    PayloadSize,
    /// Payload size in bytes, spelled with an explicit unit.
    PayloadSizeBytes,
    /// Initial key cardinality.
    InitialKeys,
    /// Key cardinality growth rate per second.
    KeyGrowthPerSec,
    /// Maximum key cardinality.
    KeyCap,
}

impl GuestWorkloadParameterKey {
    /// The supported scalar workload-parameter vocabulary.
    pub const SUPPORTED: [Self; 12] = [
        Self::Target,
        Self::Rate,
        Self::RatePerSec,
        Self::BaseRatePerSec,
        Self::PeakRatePerSec,
        Self::BurstRatePerSec,
        Self::Count,
        Self::PayloadSize,
        Self::PayloadSizeBytes,
        Self::InitialKeys,
        Self::KeyGrowthPerSec,
        Self::KeyCap,
    ];

    /// Returns the guest command-line key for this workload parameter.
    #[must_use]
    pub const fn cmdline_key(self) -> &'static str {
        match self {
            Self::Target => "target",
            Self::Rate => "rate",
            Self::RatePerSec => "rate_per_sec",
            Self::BaseRatePerSec => "base_rate_per_sec",
            Self::PeakRatePerSec => "peak_rate_per_sec",
            Self::BurstRatePerSec => "burst_rate_per_sec",
            Self::Count => "count",
            Self::PayloadSize => "payload_size",
            Self::PayloadSizeBytes => "payload_size_bytes",
            Self::InitialKeys => "initial_keys",
            Self::KeyGrowthPerSec => "key_growth_per_sec",
            Self::KeyCap => "key_cap",
        }
    }

    /// Returns the human-readable parameter name used by diagnostics and docs.
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Target => "target",
            Self::Rate | Self::RatePerSec => "request rate",
            Self::BaseRatePerSec => "base request rate",
            Self::PeakRatePerSec => "peak request rate",
            Self::BurstRatePerSec => "burst request rate",
            Self::Count => "request count",
            Self::PayloadSize | Self::PayloadSizeBytes => "payload size",
            Self::InitialKeys => "initial key cardinality",
            Self::KeyGrowthPerSec => "key cardinality growth rate",
            Self::KeyCap => "key cardinality cap",
        }
    }

    /// Parses a workload-parameter key from a command-line key.
    #[must_use]
    pub fn from_cmdline_key(key: &str) -> Option<Self> {
        match key {
            "target" => Some(Self::Target),
            "rate" => Some(Self::Rate),
            "rate_per_sec" => Some(Self::RatePerSec),
            "base_rate_per_sec" => Some(Self::BaseRatePerSec),
            "peak_rate_per_sec" => Some(Self::PeakRatePerSec),
            "burst_rate_per_sec" => Some(Self::BurstRatePerSec),
            "count" => Some(Self::Count),
            "payload_size" => Some(Self::PayloadSize),
            "payload_size_bytes" => Some(Self::PayloadSizeBytes),
            "initial_keys" => Some(Self::InitialKeys),
            "key_growth_per_sec" => Some(Self::KeyGrowthPerSec),
            "key_cap" => Some(Self::KeyCap),
            _ => None,
        }
    }
}

/// A single scalar workload parameter delivered through the guest command line.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GuestWorkloadScalarParameter {
    pub(super) key: GuestWorkloadParameterKey,
    pub(super) value: String,
}

impl GuestWorkloadScalarParameter {
    /// Builds a scalar workload parameter.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::WorkloadParameterInvalidValue`] when `value` is
    /// empty or contains command-line whitespace.
    pub fn new(
        key: GuestWorkloadParameterKey,
        value: impl Into<String>,
    ) -> Result<Self, EngineError> {
        let value = value.into();
        if !valid_guest_workload_parameter_value(&value) {
            return Err(EngineError::WorkloadParameterInvalidValue {
                parameter: key.cmdline_key().to_owned(),
                value,
            });
        }
        Ok(Self { key, value })
    }

    /// Returns this parameter's key.
    #[must_use]
    pub const fn key(&self) -> GuestWorkloadParameterKey {
        self.key
    }

    /// Returns this parameter's command-line value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Renders this parameter as `key=value`.
    #[must_use]
    pub fn scenario_parameter(&self) -> String {
        format!("{}={}", self.key.cmdline_key(), self.value)
    }

    /// Returns `base_cmdline` with this scalar workload parameter selected.
    ///
    /// Existing tokens for the same supported scalar key are replaced so the
    /// command line carries one stable parameter value.
    #[must_use]
    pub fn selected_cmdline(&self, base_cmdline: &str) -> String {
        cmdline_with_guest_workload_scalar_parameter(base_cmdline, self)
    }
}

/// The immutable channel used for a structured workload config tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GuestWorkloadConfigTreeDelivery {
    /// The config is baked into the read-only root image.
    ReadOnlyRootfs,
    /// The config is served by the read-only deterministic 9p sub-node.
    ReadOnlyNineP,
}

impl GuestWorkloadConfigTreeDelivery {
    /// The supported structured workload-config delivery channels.
    pub const SUPPORTED: [Self; 2] = [Self::ReadOnlyRootfs, Self::ReadOnlyNineP];

    /// Returns the scenario-parameter value for this delivery channel.
    #[must_use]
    pub const fn scenario_parameter_value(self) -> &'static str {
        match self {
            Self::ReadOnlyRootfs => "readonly_rootfs",
            Self::ReadOnlyNineP => "readonly_9p",
        }
    }

    /// Returns whether this delivery channel is read-only to the guest.
    #[must_use]
    pub const fn is_read_only(self) -> bool {
        true
    }

    /// Parses a delivery channel from a scenario-parameter value.
    #[must_use]
    pub fn from_scenario_parameter_value(value: &str) -> Option<Self> {
        match value {
            "readonly_rootfs" => Some(Self::ReadOnlyRootfs),
            "readonly_9p" => Some(Self::ReadOnlyNineP),
            _ => None,
        }
    }
}

/// A content-addressed workload config tree delivered read-only to the guest.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GuestWorkloadConfigTreeRef {
    pub(super) delivery: GuestWorkloadConfigTreeDelivery,
    pub(super) export: ContentAddressedBlobRef,
    pub(super) mount: String,
}

impl GuestWorkloadConfigTreeRef {
    /// Builds a read-only rootfs-backed workload config-tree reference.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::WorkloadConfigTreeInvalidMount`] when `mount` is
    /// not an absolute portable guest path.
    pub fn read_only_rootfs(
        export: ContentAddressedBlobRef,
        mount: impl Into<String>,
    ) -> Result<Self, EngineError> {
        Self::new(
            GuestWorkloadConfigTreeDelivery::ReadOnlyRootfs,
            export,
            mount,
        )
    }

    /// Builds a read-only 9p-backed workload config-tree reference.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::WorkloadConfigTreeInvalidMount`] when `mount` is
    /// not an absolute portable guest path.
    pub fn read_only_ninep(
        export: ContentAddressedBlobRef,
        mount: impl Into<String>,
    ) -> Result<Self, EngineError> {
        Self::new(
            GuestWorkloadConfigTreeDelivery::ReadOnlyNineP,
            export,
            mount,
        )
    }

    fn new(
        delivery: GuestWorkloadConfigTreeDelivery,
        export: ContentAddressedBlobRef,
        mount: impl Into<String>,
    ) -> Result<Self, EngineError> {
        let mount = mount.into();
        if !valid_guest_mount_path(&mount) {
            return Err(EngineError::WorkloadConfigTreeInvalidMount { mount });
        }
        Ok(Self {
            delivery,
            export,
            mount,
        })
    }

    /// Returns the read-only delivery channel for this config tree.
    #[must_use]
    pub const fn delivery(&self) -> GuestWorkloadConfigTreeDelivery {
        self.delivery
    }

    /// Returns the content-addressed exported config tree.
    #[must_use]
    pub const fn export(&self) -> ContentAddressedBlobRef {
        self.export
    }

    /// Returns the guest mount path for this config tree.
    #[must_use]
    pub fn mount(&self) -> &str {
        &self.mount
    }

    /// Parses a config-tree reference from a scenario-parameter value.
    #[must_use]
    pub fn from_scenario_parameter_value(value: &str) -> Option<Self> {
        parse_guest_workload_config_tree_value(value)
    }

    /// Parses the first valid config-tree reference from a command line.
    #[must_use]
    pub fn from_cmdline(cmdline: &str) -> Option<Self> {
        parse_guest_workload_config_tree_parameter(cmdline)
    }

    /// Returns the stable value used by `wcfg`.
    #[must_use]
    pub fn scenario_parameter_value(&self) -> String {
        format!(
            "{},export={},mount={}",
            self.delivery.scenario_parameter_value(),
            self.export.to_uri(),
            self.mount
        )
    }

    /// Renders this config-tree reference as a workload scenario parameter.
    #[must_use]
    pub fn scenario_parameter(&self) -> String {
        format!(
            "{WORKLOAD_CONFIG_TREE_SCENARIO_PARAMETER}={}",
            self.scenario_parameter_value()
        )
    }

    /// Returns `base_cmdline` with this config-tree reference selected.
    ///
    /// Existing `wcfg=...` tokens are replaced so the command line carries one
    /// stable content-addressed structured workload-config reference.
    #[must_use]
    pub fn selected_cmdline(&self, base_cmdline: &str) -> String {
        cmdline_with_guest_workload_config_tree(base_cmdline, self)
    }
}

/// A classic application load pattern expressed by an in-guest workload.
///
/// This is a scenario-parameter vocabulary. The engine does not synthesize
/// application records for these patterns; it only observes and steers the
/// declared world through ordinary plan primitives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GuestWorkloadPattern {
    /// A loop with a stable configured in-guest request or operation rate.
    Steady,
    /// A rate spike expressed by guest virtual time or a planned node start.
    Spike,
    /// A key-space policy that grows cardinality from guest virtual time.
    CardinalityGrowth,
    /// A workload observed under a correlated fault campaign in the plan.
    CorrelatedFailure,
}

impl GuestWorkloadPattern {
    /// The supported in-guest load-pattern vocabulary.
    pub const SUPPORTED: [Self; 4] = [
        Self::Steady,
        Self::Spike,
        Self::CardinalityGrowth,
        Self::CorrelatedFailure,
    ];

    /// Returns the scenario-parameter value for this load pattern.
    #[must_use]
    pub const fn scenario_parameter_value(self) -> &'static str {
        match self {
            Self::Steady => "steady",
            Self::Spike => "spike",
            Self::CardinalityGrowth => "cardinality_growth",
            Self::CorrelatedFailure => "correlated_failure",
        }
    }

    /// Returns the human-readable load-pattern name used by diagnostics and docs.
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Steady => "steady",
            Self::Spike => "spike",
            Self::CardinalityGrowth => "cardinality growth",
            Self::CorrelatedFailure => "correlated failure",
        }
    }

    /// Parses a load pattern from a scenario-parameter value.
    #[must_use]
    pub fn from_scenario_parameter_value(value: &str) -> Option<Self> {
        match value {
            "steady" => Some(Self::Steady),
            "spike" => Some(Self::Spike),
            "cardinality_growth" => Some(Self::CardinalityGrowth),
            "correlated_failure" => Some(Self::CorrelatedFailure),
            _ => None,
        }
    }

    /// Parses the first supported load pattern from a kernel command line.
    #[must_use]
    pub fn from_cmdline(cmdline: &str) -> Option<Self> {
        parse_guest_workload_pattern_parameter(cmdline)
    }

    /// Renders this pattern as a workload scenario parameter.
    #[must_use]
    pub fn scenario_parameter(self) -> String {
        format!(
            "{WORKLOAD_LOAD_PATTERN_SCENARIO_PARAMETER}={}",
            self.scenario_parameter_value()
        )
    }

    /// Returns `base_cmdline` with this load pattern selected.
    ///
    /// Existing `load_pattern=...` tokens are replaced so the command line
    /// carries one stable load-pattern selection.
    #[must_use]
    pub fn selected_cmdline(self, base_cmdline: &str) -> String {
        cmdline_with_guest_workload_pattern(base_cmdline, self)
    }
}

/// The way an in-guest spike pattern is parameterized.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GuestWorkloadSpikeMode {
    /// The guest changes its operation rate as a function of virtual time.
    VirtualTimeRate,
    /// A declared burst node is started through an event-graph `StartNode`.
    StartNodeBurst,
}

impl GuestWorkloadSpikeMode {
    /// The supported spike-expression vocabulary.
    pub const SUPPORTED: [Self; 2] = [Self::VirtualTimeRate, Self::StartNodeBurst];

    /// Returns the scenario-parameter value for this spike mode.
    #[must_use]
    pub const fn scenario_parameter_value(self) -> &'static str {
        match self {
            Self::VirtualTimeRate => "virtual_time_rate",
            Self::StartNodeBurst => "start_node_burst",
        }
    }

    /// Returns the human-readable spike-mode name used by diagnostics and docs.
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::VirtualTimeRate => "virtual-time rate",
            Self::StartNodeBurst => "StartNode burst",
        }
    }

    /// Parses a spike mode from a scenario-parameter value.
    #[must_use]
    pub fn from_scenario_parameter_value(value: &str) -> Option<Self> {
        match value {
            "virtual_time_rate" => Some(Self::VirtualTimeRate),
            "start_node_burst" => Some(Self::StartNodeBurst),
            _ => None,
        }
    }

    /// Parses the first supported spike mode from a kernel command line.
    #[must_use]
    pub fn from_cmdline(cmdline: &str) -> Option<Self> {
        parse_guest_workload_spike_mode_parameter(cmdline)
    }

    /// Renders this mode as a workload scenario parameter.
    #[must_use]
    pub fn scenario_parameter(self) -> String {
        format!(
            "{WORKLOAD_SPIKE_MODE_SCENARIO_PARAMETER}={}",
            self.scenario_parameter_value()
        )
    }

    /// Returns `base_cmdline` with this spike mode selected.
    ///
    /// Existing `spike_mode=...` tokens are replaced so the command line carries
    /// one stable spike-mode selection.
    #[must_use]
    pub fn selected_cmdline(self, base_cmdline: &str) -> String {
        cmdline_with_guest_workload_spike_mode(base_cmdline, self)
    }
}

/// The clock source that drives a time-varying in-guest load shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GuestWorkloadTimeSource {
    /// The load shape derives from guest-visible virtual time or VT-scheduled events.
    VirtualTime,
}

impl GuestWorkloadTimeSource {
    /// The supported load-shape time-source vocabulary.
    pub const SUPPORTED: [Self; 1] = [Self::VirtualTime];

    /// Returns the scenario-parameter value for this time source.
    #[must_use]
    pub const fn scenario_parameter_value(self) -> &'static str {
        match self {
            Self::VirtualTime => "virtual_time",
        }
    }

    /// Returns the human-readable time-source name used by diagnostics and docs.
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::VirtualTime => "virtual time",
        }
    }

    /// Parses a load-shape time source from a scenario-parameter value.
    #[must_use]
    pub fn from_scenario_parameter_value(value: &str) -> Option<Self> {
        match value {
            "virtual_time" => Some(Self::VirtualTime),
            _ => None,
        }
    }

    /// Parses the first supported load-shape time source from a command line.
    #[must_use]
    pub fn from_cmdline(cmdline: &str) -> Option<Self> {
        parse_guest_workload_time_source_parameter(cmdline)
    }

    /// Renders this time source as a workload scenario parameter.
    #[must_use]
    pub fn scenario_parameter(self) -> String {
        format!(
            "{WORKLOAD_TIME_SOURCE_SCENARIO_PARAMETER}={}",
            self.scenario_parameter_value()
        )
    }

    /// Returns `base_cmdline` with this load-shape time source selected.
    ///
    /// Existing `load_time_source=...` tokens are replaced so the command line
    /// carries one stable clock-source declaration.
    #[must_use]
    pub fn selected_cmdline(self, base_cmdline: &str) -> String {
        cmdline_with_guest_workload_time_source(base_cmdline, self)
    }
}

/// A load-pattern fixture assembled from guest program configuration and a plan.
///
/// Fixtures are intentionally small examples of guest-program-plus-scenario-
/// parameter constructions. They do not introduce a host application traffic
/// generator; spike bursts and correlated failures use existing [`Plan`]
/// primitives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestWorkloadLoadPatternFixture {
    pub(super) pattern: GuestWorkloadPattern,
    pub(super) spike_mode: Option<GuestWorkloadSpikeMode>,
    pub(super) time_source: Option<GuestWorkloadTimeSource>,
    pub(super) world: World,
    pub(super) plan: Plan,
}

impl GuestWorkloadLoadPatternFixture {
    /// Builds the steady-load fixture.
    ///
    /// # Errors
    ///
    /// Returns a world validation error if the fixture topology or reserved
    /// command-line parameters are invalid.
    pub fn steady() -> Result<Self, EngineError> {
        let cmdline = workload_pattern_cmdline(
            "console=ttyS0 rate_per_sec=100",
            GuestWorkloadPattern::Steady,
            None,
            None,
        );
        let world = World::from_nodes(vec![workload_pattern_node("client", cmdline)])?;
        Ok(Self {
            pattern: GuestWorkloadPattern::Steady,
            spike_mode: None,
            time_source: None,
            world,
            plan: Plan::empty(),
        })
    }

    /// Builds the virtual-time-rate spike fixture.
    ///
    /// # Errors
    ///
    /// Returns a world validation error if the fixture topology or reserved
    /// command-line parameters are invalid.
    pub fn spike_virtual_time_rate() -> Result<Self, EngineError> {
        let cmdline = workload_pattern_cmdline(
            concat!(
                "console=ttyS0 base_rate_per_sec=10 peak_rate_per_sec=500 ",
                "spike_at_ticks=50 spike_duration_ticks=10"
            ),
            GuestWorkloadPattern::Spike,
            Some(GuestWorkloadSpikeMode::VirtualTimeRate),
            Some(GuestWorkloadTimeSource::VirtualTime),
        );
        let world = World::from_nodes(vec![workload_pattern_node("client", cmdline)])?;
        Ok(Self {
            pattern: GuestWorkloadPattern::Spike,
            spike_mode: Some(GuestWorkloadSpikeMode::VirtualTimeRate),
            time_source: Some(GuestWorkloadTimeSource::VirtualTime),
            world,
            plan: Plan::empty(),
        })
    }

    /// Builds the planned `StartNode` burst spike fixture.
    ///
    /// # Errors
    ///
    /// Returns a world or event-graph validation error if the fixture topology,
    /// reserved command-line parameters, or planned start action are invalid.
    pub fn spike_start_node_burst() -> Result<Self, EngineError> {
        let steady_cmdline = workload_pattern_cmdline(
            "console=ttyS0 base_rate_per_sec=10",
            GuestWorkloadPattern::Spike,
            Some(GuestWorkloadSpikeMode::StartNodeBurst),
            Some(GuestWorkloadTimeSource::VirtualTime),
        );
        let burst_cmdline = workload_pattern_cmdline(
            "console=ttyS0 burst_rate_per_sec=500",
            GuestWorkloadPattern::Spike,
            Some(GuestWorkloadSpikeMode::StartNodeBurst),
            Some(GuestWorkloadTimeSource::VirtualTime),
        );
        let burst_node = NodeId {
            name: String::from("client-burst"),
        };
        let world = World::from_nodes(vec![
            workload_pattern_node("client-steady", steady_cmdline),
            workload_pattern_node("client-burst", burst_cmdline),
        ])?;
        let graph = EventGraph::new_for_world(
            vec![Event::once(
                EventId::from_name("start-burst-at-vt"),
                Some(Predicate::at(VirtualTime { ticks: 50 })),
                Action::start_node(burst_node),
            )],
            &world,
        )
        .map_err(event_graph_plan_error)?;
        let plan = Plan::from_event_graph_for_world(&world, graph)?;
        Ok(Self {
            pattern: GuestWorkloadPattern::Spike,
            spike_mode: Some(GuestWorkloadSpikeMode::StartNodeBurst),
            time_source: Some(GuestWorkloadTimeSource::VirtualTime),
            world,
            plan,
        })
    }

    /// Builds the cardinality-growth fixture.
    ///
    /// # Errors
    ///
    /// Returns a world validation error if the fixture topology or reserved
    /// command-line parameters are invalid.
    pub fn cardinality_growth() -> Result<Self, EngineError> {
        let cmdline = workload_pattern_cmdline(
            concat!(
                "console=ttyS0 initial_keys=8 key_growth_per_sec=4 ",
                "key_cap=1024"
            ),
            GuestWorkloadPattern::CardinalityGrowth,
            None,
            Some(GuestWorkloadTimeSource::VirtualTime),
        );
        let world = World::from_nodes(vec![workload_pattern_node("client", cmdline)])?;
        Ok(Self {
            pattern: GuestWorkloadPattern::CardinalityGrowth,
            spike_mode: None,
            time_source: Some(GuestWorkloadTimeSource::VirtualTime),
            world,
            plan: Plan::empty(),
        })
    }

    /// Builds the correlated-failure-campaign fixture.
    ///
    /// # Errors
    ///
    /// Returns a world or fault-plan validation error if the fixture topology,
    /// reserved command-line parameters, or fault campaign is invalid.
    pub fn correlated_failure_campaign() -> Result<Self, EngineError> {
        let left = workload_pattern_node(
            "client-a",
            workload_pattern_cmdline(
                "console=ttyS0 rate_per_sec=50",
                GuestWorkloadPattern::CorrelatedFailure,
                None,
                None,
            ),
        );
        let right = workload_pattern_node(
            "client-b",
            workload_pattern_cmdline(
                "console=ttyS0 rate_per_sec=50",
                GuestWorkloadPattern::CorrelatedFailure,
                None,
                None,
            ),
        );
        let link = LinkDef::new(left.id.clone(), right.id.clone())?;
        let world = World::from_nodes_and_links(vec![left, right], vec![link])?;
        Ok(Self {
            pattern: GuestWorkloadPattern::CorrelatedFailure,
            spike_mode: None,
            time_source: None,
            world,
            plan: Plan::empty(),
        })
    }

    /// Returns the fixture's load pattern.
    #[must_use]
    pub fn pattern(&self) -> GuestWorkloadPattern {
        self.pattern
    }

    /// Returns the fixture's spike mode, when the pattern is a spike fixture.
    #[must_use]
    pub fn spike_mode(&self) -> Option<GuestWorkloadSpikeMode> {
        self.spike_mode
    }

    /// Returns the fixture's load-shape time source, when the pattern varies over time.
    #[must_use]
    pub fn time_source(&self) -> Option<GuestWorkloadTimeSource> {
        self.time_source
    }

    /// Returns the content-addressed world assembled by this fixture.
    #[must_use]
    pub fn world(&self) -> &World {
        &self.world
    }

    /// Returns the plan assembled by this fixture.
    #[must_use]
    pub fn plan(&self) -> &Plan {
        &self.plan
    }

    /// Builds a scenario definition for this fixture with empty properties.
    ///
    /// # Errors
    ///
    /// Returns a plan validation error if the fixture plan no longer layers over
    /// its world.
    pub fn scenario_def(&self, seed: Seed) -> Result<ScenarioDef, EngineError> {
        self.world.scenario_def_with_plan_properties_and_seed(
            &self.plan,
            &Properties::empty(),
            seed,
        )
    }
}

/// The role Crucible plays for application workload traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WorkloadEngineRole {
    /// The engine only observes black-box effects and steers via model-level controls.
    ObservationAndSteeringOnly,
}

impl WorkloadEngineRole {
    /// Returns whether this role originates application-level traffic.
    #[must_use]
    pub const fn originates_application_traffic(self) -> bool {
        match self {
            Self::ObservationAndSteeringOnly => false,
        }
    }

    /// Returns whether this role permits a host-side traffic injector.
    #[must_use]
    pub const fn permits_host_side_traffic_injector(self) -> bool {
        match self {
            Self::ObservationAndSteeringOnly => false,
        }
    }
}
