//! QEMU determinism-boundary validation.
//!
//! RFC-0010 T-QEMU-10 ties together three already separate QEMU contracts:
//! deterministic launch configuration, simulation-mode inertness, and the
//! black-box execution-fingerprint definition consumed by
//! `gate:single-vm-fingerprint`. This module records that boundary as a small
//! typed validator, so the host cannot silently move hermeticity into guest
//! content, omit fingerprint state, or drop the per-elimination regression
//! matrix.

use std::collections::BTreeSet;

use crucible::ContentHash;
use thiserror::Error;

use crate::{
    DeterministicLaunchProfile, DiskImageMode, GuestBackingStateMode, GuestCoreContentMode,
    IcountShiftSetting, InputPolicy, LaunchProfileCandidate, QEMU_PLUGIN_CONTROL_FD,
    QEMU_PLUGIN_SHMEM_FD, QEMU_PLUGIN_WAKE_FD, QemuControlPlaneInertnessError,
    QemuControlPlaneInertnessReport, QemuControlPlaneObservation, QemuSimulationMode,
    SingleVmFingerprintEventBoundary, SingleVmFingerprintGateError, SingleVmFingerprintRunInputs,
    SingleVmFingerprintScenario, SingleVmHostProfile, assert_qemu_control_plane_inert,
};

/// Default fixed icount cadence for QEMU execution-fingerprint samples.
pub const QEMU_EXECUTION_FINGERPRINT_CADENCE_ICOUNT: u64 = 4096;

/// Components required in every QEMU black-box execution fingerprint.
pub const REQUIRED_QEMU_FINGERPRINT_COMPONENTS: [QemuFingerprintStateComponent; 4] = [
    QemuFingerprintStateComponent::AggregateIcount,
    QemuFingerprintStateComponent::ArchitecturalRegisters,
    QemuFingerprintStateComponent::GuestMemory,
    QemuFingerprintStateComponent::DeviceState,
];

/// Event boundaries that force a QEMU execution-fingerprint sample.
pub const REQUIRED_QEMU_FINGERPRINT_EVENT_BOUNDARIES: [SingleVmFingerprintEventBoundary; 3] = [
    SingleVmFingerprintEventBoundary::HorizonAdvance,
    SingleVmFingerprintEventBoundary::FrameDelivery,
    SingleVmFingerprintEventBoundary::FaultActivation,
];

/// Host-controlled entropy eliminations that must each have a negative micro-test.
pub const REQUIRED_QEMU_ENTROPY_ELIMINATIONS: [QemuEntropyElimination; 10] = [
    QemuEntropyElimination::SimTcgIcountSingleThread,
    QemuEntropyElimination::CpuModelEntropyPin,
    QemuEntropyElimination::FixedRtcVirtualClock,
    QemuEntropyElimination::GuestEntropyFwCfgSeed,
    QemuEntropyElimination::QemuRunSeed,
    QemuEntropyElimination::NoInteractiveInput,
    QemuEntropyElimination::CopyOnWriteBacking,
    QemuEntropyElimination::IdleWarpSuppression,
    QemuEntropyElimination::DeviceCompletionDelivery,
    QemuEntropyElimination::SimModeInertness,
];

const FINGERPRINT_DEFINITION_DOMAIN: &str = "crucible.qemu.execution-fingerprint-definition.v1";

/// One state component included in the QEMU execution fingerprint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum QemuFingerprintStateComponent {
    /// Aggregate node icount at the sample point.
    AggregateIcount,
    /// Architectural register digest gathered without guest cooperation.
    ArchitecturalRegisters,
    /// Guest-memory digest gathered through host/plugin introspection.
    GuestMemory,
    /// Device-state digest gathered through host/plugin introspection.
    DeviceState,
}

impl QemuFingerprintStateComponent {
    /// Returns the stable material token for this component.
    #[must_use]
    pub const fn material_token(self) -> &'static str {
        match self {
            Self::AggregateIcount => "aggregate-icount",
            Self::ArchitecturalRegisters => "architectural-registers",
            Self::GuestMemory => "guest-memory",
            Self::DeviceState => "device-state",
        }
    }
}

/// The fixed QEMU execution-fingerprint definition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuExecutionFingerprintDefinition {
    cadence_icount: u64,
    components: Vec<QemuFingerprintStateComponent>,
    event_boundaries: Vec<SingleVmFingerprintEventBoundary>,
    plugin_introspection: bool,
    guest_cooperation: bool,
}

impl QemuExecutionFingerprintDefinition {
    /// Builds a validated QEMU execution-fingerprint definition.
    ///
    /// The definition is canonicalized before validation so equivalent caller
    /// orderings produce the same content-addressed digest.
    ///
    /// # Errors
    ///
    /// Returns [`QemuDeterminismBoundaryError`] when the cadence is zero, a
    /// required state component or event boundary is absent, plugin
    /// introspection is disabled, or guest cooperation is required.
    pub fn new(
        cadence_icount: u64,
        components: impl IntoIterator<Item = QemuFingerprintStateComponent>,
        event_boundaries: impl IntoIterator<Item = SingleVmFingerprintEventBoundary>,
        plugin_introspection: bool,
        guest_cooperation: bool,
    ) -> Result<Self, QemuDeterminismBoundaryError> {
        let mut components = components.into_iter().collect::<Vec<_>>();
        components.sort();
        components.dedup();

        let mut event_boundaries = event_boundaries.into_iter().collect::<Vec<_>>();
        event_boundaries.sort_by_key(|boundary| event_boundary_order(*boundary));
        event_boundaries.dedup_by_key(|boundary| event_boundary_order(*boundary));

        let definition = Self {
            cadence_icount,
            components,
            event_boundaries,
            plugin_introspection,
            guest_cooperation,
        };
        validate_fingerprint_definition(&definition)?;
        Ok(definition)
    }

    /// Builds the canonical black-box plugin-backed fingerprint definition.
    ///
    /// # Errors
    ///
    /// Returns [`QemuDeterminismBoundaryError`] if the supplied cadence is zero.
    pub fn black_box_plugin(cadence_icount: u64) -> Result<Self, QemuDeterminismBoundaryError> {
        Self::new(
            cadence_icount,
            REQUIRED_QEMU_FINGERPRINT_COMPONENTS,
            REQUIRED_QEMU_FINGERPRINT_EVENT_BOUNDARIES,
            true,
            false,
        )
    }

    /// Returns the fixed periodic sample cadence in aggregate node icount.
    #[must_use]
    pub const fn cadence_icount(&self) -> u64 {
        self.cadence_icount
    }

    /// Returns the canonical state components included in every sample.
    #[must_use]
    pub fn components(&self) -> &[QemuFingerprintStateComponent] {
        &self.components
    }

    /// Returns the event boundaries that force a fingerprint sample.
    #[must_use]
    pub fn event_boundaries(&self) -> &[SingleVmFingerprintEventBoundary] {
        &self.event_boundaries
    }

    /// Returns whether samples are gathered through plugin introspection.
    #[must_use]
    pub const fn plugin_introspection(&self) -> bool {
        self.plugin_introspection
    }

    /// Returns whether the definition requires guest cooperation.
    #[must_use]
    pub const fn guest_cooperation(&self) -> bool {
        self.guest_cooperation
    }

    /// Returns canonical material for the fingerprint-definition digest.
    #[must_use]
    pub fn canonical_material(&self) -> String {
        let mut lines = vec![
            "crucible.qemu.execution-fingerprint-definition.v1".to_owned(),
            format!("cadence_icount={}", self.cadence_icount),
            "sample_trigger=periodic-icount-cadence".to_owned(),
            format!("plugin_introspection={}", self.plugin_introspection),
            format!("guest_cooperation={}", self.guest_cooperation),
        ];
        for (index, component) in self.components.iter().enumerate() {
            lines.push(format!("component[{index}]={}", component.material_token()));
        }
        for (index, boundary) in self.event_boundaries.iter().enumerate() {
            lines.push(format!(
                "event_boundary[{index}]={}",
                event_boundary_token(*boundary)
            ));
        }
        lines.join("\n")
    }

    /// Returns the content-addressed fingerprint-definition digest.
    #[must_use]
    pub fn definition_digest(&self) -> [u8; 32] {
        ContentHash::from_canonical_material(
            FINGERPRINT_DEFINITION_DOMAIN,
            &self.canonical_material(),
        )
        .bytes
    }

    /// Builds a single-VM gate scenario using this fingerprint definition.
    ///
    /// # Errors
    ///
    /// Returns [`QemuDeterminismBoundaryError`] when the single-VM scenario
    /// rejects the scenario id, digest, horizon, or host profile.
    pub fn single_vm_scenario(
        &self,
        id: impl Into<String>,
        run_horizon_icount: u64,
        run_inputs: SingleVmFingerprintRunInputs,
        host_profile: SingleVmHostProfile,
    ) -> Result<SingleVmFingerprintScenario, QemuDeterminismBoundaryError> {
        SingleVmFingerprintScenario::new(
            id,
            self.definition_digest().to_vec(),
            run_horizon_icount,
            run_inputs,
            host_profile,
        )
        .map_err(|source| QemuDeterminismBoundaryError::FingerprintScenario { source })
    }
}

/// A host-controlled entropy elimination covered by a regression micro-test.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum QemuEntropyElimination {
    /// TCG-derived sim, fixed icount, sleep-off, align-off, and single-thread
    /// execution are pinned.
    SimTcgIcountSingleThread,
    /// The CPU model is fixed and hardware entropy instructions are disabled.
    CpuModelEntropyPin,
    /// The RTC base is fixed and its clock source is virtual time.
    FixedRtcVirtualClock,
    /// Guest-visible boot entropy is supplied entirely host-side by a
    /// content-addressed fw_cfg random-seed and a seeded builtin RNG device, so
    /// determinism holds for any unmodified guest without cmdline shaping.
    GuestEntropyFwCfgSeed,
    /// QEMU-internal pseudo-randomness is seeded from scenario material.
    QemuRunSeed,
    /// Host interactive input devices are absent.
    NoInteractiveInput,
    /// Guest writes go through copy-on-write overlays only.
    CopyOnWriteBacking,
    /// Idle warp is suppressed while the plugin owns QEMU virtual time.
    IdleWarpSuppression,
    /// Device-completion delivery is deterministic: every completion interrupt
    /// lands at a fixed icount rather than at a host-timing-dependent one. How
    /// each device family achieves this differs  --  virtio-blk/9p completions are
    /// pinned by the crucible blk/9p shmem substrate (patches 0015-0019), which
    /// keeps the stock async virtqueue kick, whereas virtio-rng has no such
    /// anchor, so the crucible-det-rng-delivery and (virtio-rng-scoped)
    /// crucible-det-virtio-ioeventfd patches deliver its entropy completion
    /// synchronously on the requesting vCPU thread at the request icount rather
    /// than from a host-scheduled bottom half. Upstream icount otherwise leaves
    /// async device-completion delivery host-timing-dependent, so the byte-pure
    /// seeded entropy would arrive at a nondeterministic instruction.
    DeviceCompletionDelivery,
    /// Simulation mechanisms are absent or inert when simulation mode is off.
    SimModeInertness,
}

impl QemuEntropyElimination {
    /// Returns the stable material token for this elimination.
    #[must_use]
    pub const fn material_token(self) -> &'static str {
        match self {
            Self::SimTcgIcountSingleThread => "sim-tcg-icount-single-thread",
            Self::CpuModelEntropyPin => "cpu-model-entropy-pin",
            Self::FixedRtcVirtualClock => "fixed-rtc-virtual-clock",
            Self::GuestEntropyFwCfgSeed => "guest-entropy-fw-cfg-seed",
            Self::QemuRunSeed => "qemu-run-seed",
            Self::NoInteractiveInput => "no-interactive-input",
            Self::CopyOnWriteBacking => "copy-on-write-backing",
            Self::IdleWarpSuppression => "idle-warp-suppression",
            Self::DeviceCompletionDelivery => "device-completion-delivery",
            Self::SimModeInertness => "sim-mode-inertness",
        }
    }
}

/// Closed negative mutation used to prove an entropy elimination is enforced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum QemuEntropyEliminationNegativeCase {
    /// Select stock TCG, MTTCG, or adaptive icount execution.
    UseNonSimOrAdaptiveIcount,
    /// Use host CPU identity or CPU entropy instructions.
    UseHostCpuEntropy,
    /// Use a host-driven RTC clock or base.
    UseHostRtc,
    /// Remove the fw_cfg seed or use an unseeded virtio-rng device.
    RemoveGuestEntropySeed,
    /// Diverge QEMU's run seed from the scenario seed.
    DivergeRunSeed,
    /// Enable host interactive input.
    EnableHostInteractiveInput,
    /// Allow writable guest backing state.
    AllowWritableBacking,
    /// Re-enable idle warp while plugin time control is active.
    EnableIdleWarp,
    /// Deliver device completions from a host-scheduled bottom half instead of
    /// synchronously at the request icount.
    UseAsyncDeviceCompletion,
    /// Activate plugin/control-plane state while simulation mode is off.
    ActivateSimControlWhileOff,
}

impl QemuEntropyEliminationNegativeCase {
    /// Returns the stable material token for this negative mutation.
    #[must_use]
    pub const fn material_token(self) -> &'static str {
        match self {
            Self::UseNonSimOrAdaptiveIcount => "use-non-sim-or-adaptive-icount",
            Self::UseHostCpuEntropy => "use-host-cpu-entropy",
            Self::UseHostRtc => "use-host-rtc",
            Self::RemoveGuestEntropySeed => "remove-guest-entropy-seed",
            Self::DivergeRunSeed => "diverge-run-seed",
            Self::EnableHostInteractiveInput => "enable-host-interactive-input",
            Self::AllowWritableBacking => "allow-writable-backing",
            Self::EnableIdleWarp => "enable-idle-warp",
            Self::UseAsyncDeviceCompletion => "use-async-device-completion",
            Self::ActivateSimControlWhileOff => "activate-sim-control-while-off",
        }
    }
}

/// One executable negative regression test for a QEMU entropy elimination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuEntropyEliminationMicrotest {
    /// Entropy elimination being tested.
    pub elimination: QemuEntropyElimination,
    /// Gate that turns red when the elimination is removed.
    pub gate: &'static str,
    /// Closed negative mutation executed by the boundary validator.
    pub negative_case: QemuEntropyEliminationNegativeCase,
}

impl QemuEntropyEliminationMicrotest {
    /// Builds a micro-test declaration with an executable negative case.
    #[must_use]
    pub const fn new(
        elimination: QemuEntropyElimination,
        gate: &'static str,
        negative_case: QemuEntropyEliminationNegativeCase,
    ) -> Self {
        Self {
            elimination,
            gate,
            negative_case,
        }
    }
}

/// Returns the canonical QEMU entropy-elimination micro-test matrix.
#[must_use]
pub fn qemu_entropy_elimination_microtests() -> Vec<QemuEntropyEliminationMicrotest> {
    vec![
        QemuEntropyEliminationMicrotest::new(
            QemuEntropyElimination::SimTcgIcountSingleThread,
            "gate:layer0-determinism",
            QemuEntropyEliminationNegativeCase::UseNonSimOrAdaptiveIcount,
        ),
        QemuEntropyEliminationMicrotest::new(
            QemuEntropyElimination::CpuModelEntropyPin,
            "gate:layer0-determinism",
            QemuEntropyEliminationNegativeCase::UseHostCpuEntropy,
        ),
        QemuEntropyEliminationMicrotest::new(
            QemuEntropyElimination::FixedRtcVirtualClock,
            "gate:layer0-determinism",
            QemuEntropyEliminationNegativeCase::UseHostRtc,
        ),
        QemuEntropyEliminationMicrotest::new(
            QemuEntropyElimination::GuestEntropyFwCfgSeed,
            "gate:layer0-determinism",
            QemuEntropyEliminationNegativeCase::RemoveGuestEntropySeed,
        ),
        QemuEntropyEliminationMicrotest::new(
            QemuEntropyElimination::QemuRunSeed,
            "gate:layer0-determinism",
            QemuEntropyEliminationNegativeCase::DivergeRunSeed,
        ),
        QemuEntropyEliminationMicrotest::new(
            QemuEntropyElimination::NoInteractiveInput,
            "gate:layer0-determinism",
            QemuEntropyEliminationNegativeCase::EnableHostInteractiveInput,
        ),
        QemuEntropyEliminationMicrotest::new(
            QemuEntropyElimination::CopyOnWriteBacking,
            "gate:layer0-determinism",
            QemuEntropyEliminationNegativeCase::AllowWritableBacking,
        ),
        QemuEntropyEliminationMicrotest::new(
            QemuEntropyElimination::IdleWarpSuppression,
            "gate:layer0-determinism",
            QemuEntropyEliminationNegativeCase::EnableIdleWarp,
        ),
        QemuEntropyEliminationMicrotest::new(
            QemuEntropyElimination::DeviceCompletionDelivery,
            "gate:layer0-determinism",
            QemuEntropyEliminationNegativeCase::UseAsyncDeviceCompletion,
        ),
        QemuEntropyEliminationMicrotest::new(
            QemuEntropyElimination::SimModeInertness,
            "gate:qemu-inert",
            QemuEntropyEliminationNegativeCase::ActivateSimControlWhileOff,
        ),
    ]
}

/// Successful QEMU determinism-boundary validation report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuDeterminismBoundaryReport {
    /// Simulation mode whose inertness was checked.
    pub simulation_mode: QemuSimulationMode,
    /// Fixed fingerprint cadence in aggregate node icount.
    pub fingerprint_cadence_icount: u64,
    /// Content-addressed fingerprint definition digest.
    pub fingerprint_definition_digest: [u8; 32],
    /// Canonical fingerprint components.
    pub fingerprint_components: Vec<QemuFingerprintStateComponent>,
    /// Number of entropy-elimination micro-tests checked.
    pub microtest_count: usize,
    /// Covered entropy eliminations.
    pub covered_entropy_eliminations: Vec<QemuEntropyElimination>,
    /// Control-plane inertness evidence.
    pub inertness: QemuControlPlaneInertnessReport,
}

/// Errors returned by QEMU determinism-boundary validation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum QemuDeterminismBoundaryError {
    /// The launch profile omitted a required content-addressed hermeticity line.
    #[error("QEMU launch boundary material is missing `{missing}`")]
    LaunchBoundaryMissing {
        /// Missing canonical launch material fragment.
        missing: &'static str,
    },
    /// The fingerprint cadence was zero.
    #[error("QEMU fingerprint cadence must be non-zero")]
    InvalidFingerprintCadence,
    /// The fingerprint definition did not use plugin introspection.
    #[error("QEMU fingerprint must be gathered through plugin introspection")]
    PluginIntrospectionDisabled,
    /// The fingerprint definition required guest cooperation.
    #[error("QEMU fingerprint must be black-box and require no guest cooperation")]
    GuestCooperationRequired,
    /// A required fingerprint state component was absent.
    #[error("QEMU fingerprint is missing component {component:?}")]
    MissingFingerprintComponent {
        /// Missing component.
        component: QemuFingerprintStateComponent,
    },
    /// A required event boundary was absent.
    #[error("QEMU fingerprint is missing event boundary {boundary}")]
    MissingFingerprintEventBoundary {
        /// Missing boundary token.
        boundary: &'static str,
    },
    /// Building a single-VM scenario from this boundary failed.
    #[error("QEMU fingerprint scenario rejected boundary definition: {source}")]
    FingerprintScenario {
        /// Underlying scenario validation error.
        source: SingleVmFingerprintGateError,
    },
    /// Sim-mode inertness failed.
    #[error("QEMU sim-mode inertness failed: {source}")]
    Inertness {
        /// Underlying inertness error.
        source: QemuControlPlaneInertnessError,
    },
    /// The boundary was validated without simulation mode enabled.
    #[error("QEMU determinism boundary must validate sim-mode activation")]
    SimModeActivationDisabled,
    /// The sim-on launch arguments did not carry required plugin activation material.
    #[error("QEMU sim-mode launch activation is missing `{missing}`")]
    SimModeActivationMissing {
        /// Missing launch-argument fragment.
        missing: &'static str,
    },
    /// A required entropy-elimination micro-test was absent.
    #[error("missing QEMU entropy-elimination micro-test for {elimination:?}")]
    MissingMicrotest {
        /// Missing elimination.
        elimination: QemuEntropyElimination,
    },
    /// An entropy-elimination micro-test was declared more than once.
    #[error("duplicate QEMU entropy-elimination micro-test for {elimination:?}")]
    DuplicateMicrotest {
        /// Duplicated elimination.
        elimination: QemuEntropyElimination,
    },
    /// An entropy-elimination micro-test did not name a gate.
    #[error("QEMU entropy-elimination micro-test for {elimination:?} has empty gate name")]
    EmptyMicrotestGate {
        /// Elimination with the invalid test declaration.
        elimination: QemuEntropyElimination,
    },
    /// An entropy-elimination micro-test used the wrong gate.
    #[error("QEMU entropy-elimination {elimination:?} is covered by wrong gate `{gate}`")]
    WrongMicrotestGate {
        /// Elimination with the invalid test declaration.
        elimination: QemuEntropyElimination,
        /// Declared gate.
        gate: &'static str,
    },
    /// An entropy-elimination micro-test used the wrong negative mutation.
    #[error("QEMU entropy-elimination {elimination:?} uses wrong negative case {actual:?}")]
    WrongMicrotestNegativeCase {
        /// Elimination with the invalid test declaration.
        elimination: QemuEntropyElimination,
        /// Expected negative mutation.
        expected: QemuEntropyEliminationNegativeCase,
        /// Declared negative mutation.
        actual: QemuEntropyEliminationNegativeCase,
    },
    /// A negative micro-test did not fail when the elimination was removed.
    #[error("QEMU negative micro-test {negative_case:?} for {elimination:?} did not fail")]
    NegativeMicrotestDidNotFail {
        /// Elimination with the invalid test declaration.
        elimination: QemuEntropyElimination,
        /// Negative mutation that unexpectedly passed.
        negative_case: QemuEntropyEliminationNegativeCase,
    },
}

/// Validates the QEMU determinism boundary for one launch/fingerprint plan.
///
/// # Errors
///
/// Returns [`QemuDeterminismBoundaryError`] when launch material omits a
/// hermeticity pin, sim-mode inertness fails, the fingerprint definition omits
/// required black-box state, or the per-elimination micro-test matrix is
/// incomplete.
pub fn validate_qemu_determinism_boundary(
    launch_profile: &DeterministicLaunchProfile,
    control_plane: QemuControlPlaneObservation,
    fingerprint_definition: &QemuExecutionFingerprintDefinition,
    microtests: &[QemuEntropyEliminationMicrotest],
) -> Result<QemuDeterminismBoundaryReport, QemuDeterminismBoundaryError> {
    validate_launch_boundary_material(launch_profile)?;
    validate_fingerprint_definition(fingerprint_definition)?;
    validate_sim_mode_activation(&control_plane)?;
    let inertness = assert_qemu_control_plane_inert(control_plane)
        .map_err(|source| QemuDeterminismBoundaryError::Inertness { source })?;
    let covered_entropy_eliminations = validate_microtests(launch_profile, microtests)?;

    Ok(QemuDeterminismBoundaryReport {
        simulation_mode: inertness.simulation_mode,
        fingerprint_cadence_icount: fingerprint_definition.cadence_icount(),
        fingerprint_definition_digest: fingerprint_definition.definition_digest(),
        fingerprint_components: fingerprint_definition.components().to_vec(),
        microtest_count: microtests.len(),
        covered_entropy_eliminations,
        inertness,
    })
}

fn validate_launch_boundary_material(
    launch_profile: &DeterministicLaunchProfile,
) -> Result<(), QemuDeterminismBoundaryError> {
    let material = launch_profile.scenario_hash_material();
    validate_launch_boundary_material_text(&material)?;
    validate_canonical_launch_args(&launch_profile.canonical_qemu_args())?;
    Ok(())
}

fn validate_launch_boundary_material_text(
    material: &str,
) -> Result<(), QemuDeterminismBoundaryError> {
    for required in [
        "accelerator=sim,thread=single",
        "accelerator_family=tcg-derived-sim",
        "simulation_mode=on",
        "stock_tcg_crucible_runtime=forbidden",
        "icount_shift=",
        "rr_switch_quantum=",
        "rr_switch_quantum_units=node-icount",
        "cpu_model=",
        "rtc_clock=vm",
        "guest_time_sources=rtc,tsc,timer-devices:icount-derived-virtual-time",
        "idle_warp_under_time_control=suppressed",
        "device_completion_delivery=synchronous-at-request-icount",
        "guest_entropy_seed_source=scenario-seed",
        "qemu_run_seed_controls=guest-random,glib-global-prng,rng-builtin",
        "kernel_cmdline=",
        "input_policy=no-interactive-input",
        "guest_on_disk_mutation_policy=forbidden-by-launch-profile",
        "guest_core_content=host-side-only",
    ] {
        if !material.contains(required) {
            return Err(QemuDeterminismBoundaryError::LaunchBoundaryMissing { missing: required });
        }
    }
    Ok(())
}

fn validate_canonical_launch_args(args: &[String]) -> Result<(), QemuDeterminismBoundaryError> {
    require_option_value(
        args,
        "-fw_cfg",
        |value| value == "name=opt/crucible/seed,file=crucible-guest-entropy-seed.bin",
        "guest entropy fw_cfg seed",
    )?;
    require_option_value(
        args,
        "-object",
        |value| value == "rng-builtin,id=crucible-rng0",
        "deterministic rng object",
    )?;
    require_option_value(
        args,
        "-device",
        |value| value == "virtio-rng-pci,rng=crucible-rng0",
        "seeded virtio-rng device",
    )?;
    // The guest kernel command line is not part of the launch determinism
    // boundary: determinism is delivered host-side by the seeded fw_cfg
    // random-seed and builtin RNG device, so any unmodified guest cmdline is
    // legal and no `-append` flags are required.
    Ok(())
}

fn validate_sim_mode_activation(
    observation: &QemuControlPlaneObservation,
) -> Result<(), QemuDeterminismBoundaryError> {
    if observation.simulation_mode != QemuSimulationMode::On {
        return Err(QemuDeterminismBoundaryError::SimModeActivationDisabled);
    }
    let plugin_arg = find_option_value(&observation.qemu_args, "-plugin")
        .ok_or(QemuDeterminismBoundaryError::SimModeActivationMissing { missing: "-plugin" })?;
    require_plugin_fd_option(plugin_arg, "simfd", QEMU_PLUGIN_CONTROL_FD, "plugin simfd")?;
    require_plugin_fd_option(
        plugin_arg,
        "shmemfd",
        QEMU_PLUGIN_SHMEM_FD,
        "plugin shmemfd",
    )?;
    require_plugin_fd_option(plugin_arg, "wakefd", QEMU_PLUGIN_WAKE_FD, "plugin wakefd")?;
    require_plugin_option(
        plugin_arg,
        "whitebox",
        "on",
        "plugin whitebox introspection",
    )?;
    Ok(())
}

fn validate_fingerprint_definition(
    definition: &QemuExecutionFingerprintDefinition,
) -> Result<(), QemuDeterminismBoundaryError> {
    if definition.cadence_icount == 0 {
        return Err(QemuDeterminismBoundaryError::InvalidFingerprintCadence);
    }
    if !definition.plugin_introspection {
        return Err(QemuDeterminismBoundaryError::PluginIntrospectionDisabled);
    }
    if definition.guest_cooperation {
        return Err(QemuDeterminismBoundaryError::GuestCooperationRequired);
    }

    for component in REQUIRED_QEMU_FINGERPRINT_COMPONENTS {
        if !definition.components.contains(&component) {
            return Err(QemuDeterminismBoundaryError::MissingFingerprintComponent { component });
        }
    }
    for boundary in REQUIRED_QEMU_FINGERPRINT_EVENT_BOUNDARIES {
        if !definition.event_boundaries.contains(&boundary) {
            return Err(
                QemuDeterminismBoundaryError::MissingFingerprintEventBoundary {
                    boundary: event_boundary_token(boundary),
                },
            );
        }
    }

    Ok(())
}

fn validate_microtests(
    launch_profile: &DeterministicLaunchProfile,
    microtests: &[QemuEntropyEliminationMicrotest],
) -> Result<Vec<QemuEntropyElimination>, QemuDeterminismBoundaryError> {
    let mut seen = BTreeSet::new();
    for microtest in microtests {
        if !seen.insert(microtest.elimination) {
            return Err(QemuDeterminismBoundaryError::DuplicateMicrotest {
                elimination: microtest.elimination,
            });
        }
        if microtest.gate.is_empty() {
            return Err(QemuDeterminismBoundaryError::EmptyMicrotestGate {
                elimination: microtest.elimination,
            });
        }
        if microtest.gate != expected_microtest_gate(microtest.elimination) {
            return Err(QemuDeterminismBoundaryError::WrongMicrotestGate {
                elimination: microtest.elimination,
                gate: microtest.gate,
            });
        }
        let expected_case = expected_negative_case(microtest.elimination);
        if microtest.negative_case != expected_case {
            return Err(QemuDeterminismBoundaryError::WrongMicrotestNegativeCase {
                elimination: microtest.elimination,
                expected: expected_case,
                actual: microtest.negative_case,
            });
        }
        run_negative_microtest(launch_profile, *microtest)?;
    }

    for elimination in REQUIRED_QEMU_ENTROPY_ELIMINATIONS {
        if !seen.contains(&elimination) {
            return Err(QemuDeterminismBoundaryError::MissingMicrotest { elimination });
        }
    }

    Ok(seen.into_iter().collect())
}

fn run_negative_microtest(
    launch_profile: &DeterministicLaunchProfile,
    microtest: QemuEntropyEliminationMicrotest,
) -> Result<(), QemuDeterminismBoundaryError> {
    match microtest.negative_case {
        QemuEntropyEliminationNegativeCase::UseNonSimOrAdaptiveIcount => {
            expect_candidate_rejected(
                LaunchProfileCandidate::default().with_accelerator("tcg,thread=single"),
                microtest,
            )?;
            expect_candidate_rejected(
                LaunchProfileCandidate::default().with_accelerator("sim,thread=multi"),
                microtest,
            )?;
            expect_candidate_rejected(
                LaunchProfileCandidate::default().with_icount_shift(IcountShiftSetting::Auto),
                microtest,
            )
        }
        QemuEntropyEliminationNegativeCase::UseHostCpuEntropy => expect_candidate_rejected(
            LaunchProfileCandidate::default().with_cpu_model("host"),
            microtest,
        ),
        QemuEntropyEliminationNegativeCase::UseHostRtc => expect_candidate_rejected(
            LaunchProfileCandidate::default().with_rtc_clock("host"),
            microtest,
        ),
        QemuEntropyEliminationNegativeCase::RemoveGuestEntropySeed => {
            let mut without_fw_cfg = launch_profile.canonical_qemu_args();
            remove_option_pair(&mut without_fw_cfg, "-fw_cfg");
            expect_launch_args_rejected(&without_fw_cfg, microtest)?;

            let mut unseeded_rng = launch_profile.canonical_qemu_args();
            replace_option_value(&mut unseeded_rng, "-device", "virtio-rng-pci,rng=host-rng0");
            expect_launch_args_rejected(&unseeded_rng, microtest)
        }
        QemuEntropyEliminationNegativeCase::DivergeRunSeed => expect_candidate_rejected(
            LaunchProfileCandidate {
                run_seed: 7,
                ..LaunchProfileCandidate::default()
            },
            microtest,
        ),
        QemuEntropyEliminationNegativeCase::EnableHostInteractiveInput => {
            expect_candidate_rejected(
                LaunchProfileCandidate::default().with_input_policy(InputPolicy::HostInteractive),
                microtest,
            )
        }
        QemuEntropyEliminationNegativeCase::AllowWritableBacking => {
            expect_candidate_rejected(
                LaunchProfileCandidate::default()
                    .with_disk_image_mode(DiskImageMode::WritableBacking),
                microtest,
            )?;
            expect_candidate_rejected(
                LaunchProfileCandidate::default()
                    .with_guest_backing_state(GuestBackingStateMode::HostMutableGenesis),
                microtest,
            )?;
            expect_candidate_rejected(
                LaunchProfileCandidate::default()
                    .with_guest_core_content(GuestCoreContentMode::GuestInjectedContent),
                microtest,
            )
        }
        QemuEntropyEliminationNegativeCase::EnableIdleWarp => {
            let material = launch_profile.scenario_hash_material().replace(
                "idle_warp_under_time_control=suppressed",
                "idle_warp_under_time_control=host-warp-enabled",
            );
            expect_launch_material_rejected(&material, microtest)
        }
        QemuEntropyEliminationNegativeCase::UseAsyncDeviceCompletion => {
            let material = launch_profile.scenario_hash_material().replace(
                "device_completion_delivery=synchronous-at-request-icount",
                "device_completion_delivery=host-async-bottom-half",
            );
            expect_launch_material_rejected(&material, microtest)
        }
        QemuEntropyEliminationNegativeCase::ActivateSimControlWhileOff => {
            let result = assert_qemu_control_plane_inert(QemuControlPlaneObservation {
                qemu_args: vec![String::from("-plugin")],
                ..QemuControlPlaneObservation::sim_off(launch_profile)
            });
            if result.is_ok() {
                Err(QemuDeterminismBoundaryError::NegativeMicrotestDidNotFail {
                    elimination: microtest.elimination,
                    negative_case: microtest.negative_case,
                })
            } else {
                Ok(())
            }
        }
    }
}

fn expect_candidate_rejected(
    candidate: LaunchProfileCandidate,
    microtest: QemuEntropyEliminationMicrotest,
) -> Result<(), QemuDeterminismBoundaryError> {
    if candidate.try_into_deterministic().is_ok() {
        Err(QemuDeterminismBoundaryError::NegativeMicrotestDidNotFail {
            elimination: microtest.elimination,
            negative_case: microtest.negative_case,
        })
    } else {
        Ok(())
    }
}

fn expect_launch_args_rejected(
    args: &[String],
    microtest: QemuEntropyEliminationMicrotest,
) -> Result<(), QemuDeterminismBoundaryError> {
    if validate_canonical_launch_args(args).is_ok() {
        Err(QemuDeterminismBoundaryError::NegativeMicrotestDidNotFail {
            elimination: microtest.elimination,
            negative_case: microtest.negative_case,
        })
    } else {
        Ok(())
    }
}

fn expect_launch_material_rejected(
    material: &str,
    microtest: QemuEntropyEliminationMicrotest,
) -> Result<(), QemuDeterminismBoundaryError> {
    if validate_launch_boundary_material_text(material).is_ok() {
        Err(QemuDeterminismBoundaryError::NegativeMicrotestDidNotFail {
            elimination: microtest.elimination,
            negative_case: microtest.negative_case,
        })
    } else {
        Ok(())
    }
}

fn expected_negative_case(
    elimination: QemuEntropyElimination,
) -> QemuEntropyEliminationNegativeCase {
    match elimination {
        QemuEntropyElimination::SimTcgIcountSingleThread => {
            QemuEntropyEliminationNegativeCase::UseNonSimOrAdaptiveIcount
        }
        QemuEntropyElimination::CpuModelEntropyPin => {
            QemuEntropyEliminationNegativeCase::UseHostCpuEntropy
        }
        QemuEntropyElimination::FixedRtcVirtualClock => {
            QemuEntropyEliminationNegativeCase::UseHostRtc
        }
        QemuEntropyElimination::GuestEntropyFwCfgSeed => {
            QemuEntropyEliminationNegativeCase::RemoveGuestEntropySeed
        }
        QemuEntropyElimination::QemuRunSeed => QemuEntropyEliminationNegativeCase::DivergeRunSeed,
        QemuEntropyElimination::NoInteractiveInput => {
            QemuEntropyEliminationNegativeCase::EnableHostInteractiveInput
        }
        QemuEntropyElimination::CopyOnWriteBacking => {
            QemuEntropyEliminationNegativeCase::AllowWritableBacking
        }
        QemuEntropyElimination::IdleWarpSuppression => {
            QemuEntropyEliminationNegativeCase::EnableIdleWarp
        }
        QemuEntropyElimination::DeviceCompletionDelivery => {
            QemuEntropyEliminationNegativeCase::UseAsyncDeviceCompletion
        }
        QemuEntropyElimination::SimModeInertness => {
            QemuEntropyEliminationNegativeCase::ActivateSimControlWhileOff
        }
    }
}

fn expected_microtest_gate(elimination: QemuEntropyElimination) -> &'static str {
    match elimination {
        QemuEntropyElimination::SimModeInertness => "gate:qemu-inert",
        _ => "gate:layer0-determinism",
    }
}

fn require_option_value(
    args: &[String],
    option: &'static str,
    predicate: impl Fn(&str) -> bool,
    missing: &'static str,
) -> Result<(), QemuDeterminismBoundaryError> {
    if option_values(args, option)
        .iter()
        .any(|value| predicate(value))
    {
        Ok(())
    } else {
        Err(QemuDeterminismBoundaryError::LaunchBoundaryMissing { missing })
    }
}

fn find_option_value<'a>(args: &'a [String], option: &'static str) -> Option<&'a str> {
    option_values(args, option).into_iter().next()
}

fn require_plugin_fd_option(
    plugin_arg: &str,
    key: &str,
    expected_fd: i32,
    missing: &'static str,
) -> Result<(), QemuDeterminismBoundaryError> {
    require_plugin_option(plugin_arg, key, &expected_fd.to_string(), missing)
}

fn require_plugin_option(
    plugin_arg: &str,
    key: &str,
    expected_value: &str,
    missing: &'static str,
) -> Result<(), QemuDeterminismBoundaryError> {
    if plugin_option_matches(plugin_arg, key, expected_value) {
        Ok(())
    } else {
        Err(QemuDeterminismBoundaryError::SimModeActivationMissing { missing })
    }
}

fn plugin_option_matches(plugin_arg: &str, key: &str, expected_value: &str) -> bool {
    plugin_arg
        .split(',')
        .filter_map(|argument| argument.split_once('='))
        .any(|(argument_key, argument_value)| {
            argument_key == key && argument_value == expected_value
        })
}

fn option_values<'a>(args: &'a [String], option: &'static str) -> Vec<&'a str> {
    let mut values = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let argument = &args[index];
        if argument == option {
            if let Some(value) = args.get(index + 1) {
                values.push(value.as_str());
            }
            index += 2;
        } else if let Some(value) = argument
            .strip_prefix(option)
            .and_then(|suffix| suffix.strip_prefix('='))
        {
            values.push(value);
            index += 1;
        } else {
            index += 1;
        }
    }
    values
}

fn remove_option_pair(args: &mut Vec<String>, option: &str) {
    let mut index = 0;
    while index < args.len() {
        if args[index] == option {
            args.drain(index..usize::min(index + 2, args.len()));
        } else {
            index += 1;
        }
    }
}

fn replace_option_value(args: &mut [String], option: &str, replacement: &str) {
    let mut index = 0;
    while index + 1 < args.len() {
        if args[index] == option {
            args[index + 1] = replacement.to_owned();
            return;
        }
        index += 1;
    }
}

fn event_boundary_order(boundary: SingleVmFingerprintEventBoundary) -> u8 {
    match boundary {
        SingleVmFingerprintEventBoundary::HorizonAdvance => 0,
        SingleVmFingerprintEventBoundary::FrameDelivery => 1,
        SingleVmFingerprintEventBoundary::FaultActivation => 2,
    }
}

fn event_boundary_token(boundary: SingleVmFingerprintEventBoundary) -> &'static str {
    match boundary {
        SingleVmFingerprintEventBoundary::HorizonAdvance => "horizon-advance",
        SingleVmFingerprintEventBoundary::FrameDelivery => "frame-delivery",
        SingleVmFingerprintEventBoundary::FaultActivation => "fault-activation",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DiskImageMode, GuestBackingStateMode, GuestCoreContentMode, IcountShiftSetting,
        InputPolicy, LaunchProfileCandidate, LaunchProfileError, QemuControlPlaneInertnessError,
        QemuLaunchArtifact, QemuLaunchPluginConfig, QemuLaunchPluginSwitch, QemuVmLaunchConfig,
        validate_x86_whitebox_hmp_mtree,
    };

    #[test]
    fn qemu_determinism_boundary_accepts_canonical_contract() {
        let profile = default_profile();
        let definition = default_definition();
        let microtests = qemu_entropy_elimination_microtests();

        let report = validate_qemu_determinism_boundary(
            &profile,
            sim_on_observation(&profile),
            &definition,
            &microtests,
        );

        match report {
            Ok(report) => {
                assert_eq!(report.simulation_mode, QemuSimulationMode::On);
                assert_eq!(
                    report.fingerprint_cadence_icount,
                    QEMU_EXECUTION_FINGERPRINT_CADENCE_ICOUNT
                );
                assert_eq!(
                    report.fingerprint_components,
                    REQUIRED_QEMU_FINGERPRINT_COMPONENTS
                );
                assert_eq!(
                    report.microtest_count,
                    REQUIRED_QEMU_ENTROPY_ELIMINATIONS.len()
                );
                assert_eq!(
                    report.covered_entropy_eliminations,
                    REQUIRED_QEMU_ENTROPY_ELIMINATIONS
                );
            }
            Err(error) => panic!("canonical QEMU boundary should validate: {error}"),
        }
    }

    #[test]
    fn qemu_determinism_boundary_rejects_missing_sim_mode_launch_activation() {
        let profile = default_profile();
        let definition = default_definition();
        let microtests = qemu_entropy_elimination_microtests();
        let result = validate_qemu_determinism_boundary(
            &profile,
            QemuControlPlaneObservation::sim_off(&profile),
            &definition,
            &microtests,
        );

        assert!(matches!(
            result,
            Err(QemuDeterminismBoundaryError::SimModeActivationDisabled)
        ));

        let result = validate_qemu_determinism_boundary(
            &profile,
            QemuControlPlaneObservation::sim_on_protocol_contract(),
            &definition,
            &microtests,
        );

        assert!(matches!(
            result,
            Err(QemuDeterminismBoundaryError::SimModeActivationMissing { missing: "-plugin" })
        ));
    }

    #[test]
    fn qemu_determinism_boundary_rejects_non_inert_sim_on_runtime_control_traffic() {
        let profile = default_profile();
        let definition = default_definition();
        let microtests = qemu_entropy_elimination_microtests();
        let result = validate_qemu_determinism_boundary(
            &profile,
            QemuControlPlaneObservation {
                runtime_control_frame_count: 1,
                ..sim_on_observation(&profile)
            },
            &definition,
            &microtests,
        );

        assert!(matches!(
            result,
            Err(QemuDeterminismBoundaryError::Inertness {
                source: QemuControlPlaneInertnessError::ControlFrameObservedDuringRun { count: 1 }
            })
        ));
    }

    #[test]
    fn qemu_execution_fingerprint_definition_is_content_addressed() {
        let definition = default_definition();
        let reordered = QemuExecutionFingerprintDefinition::new(
            QEMU_EXECUTION_FINGERPRINT_CADENCE_ICOUNT,
            [
                QemuFingerprintStateComponent::DeviceState,
                QemuFingerprintStateComponent::AggregateIcount,
                QemuFingerprintStateComponent::GuestMemory,
                QemuFingerprintStateComponent::ArchitecturalRegisters,
            ],
            [
                SingleVmFingerprintEventBoundary::FaultActivation,
                SingleVmFingerprintEventBoundary::HorizonAdvance,
                SingleVmFingerprintEventBoundary::FrameDelivery,
            ],
            true,
            false,
        );
        let changed_cadence = QemuExecutionFingerprintDefinition::black_box_plugin(
            QEMU_EXECUTION_FINGERPRINT_CADENCE_ICOUNT * 2,
        );

        match (reordered, changed_cadence) {
            (Ok(reordered), Ok(changed_cadence)) => {
                assert_eq!(
                    definition.definition_digest(),
                    reordered.definition_digest()
                );
                assert_ne!(
                    definition.definition_digest(),
                    changed_cadence.definition_digest()
                );
                assert!(
                    definition
                        .canonical_material()
                        .contains("component[3]=device-state")
                );
                assert!(
                    definition
                        .canonical_material()
                        .contains("event_boundary[1]=frame-delivery")
                );
            }
            (Err(error), _) | (_, Err(error)) => {
                panic!("test fingerprint definition should validate: {error}")
            }
        }
    }

    #[test]
    fn qemu_execution_fingerprint_definition_builds_single_vm_scenario() {
        let definition = default_definition();
        let scenario = definition.single_vm_scenario(
            "qemu-boundary-smoke",
            8192,
            SingleVmFingerprintRunInputs::new(
                [0x10; 32],
                "console=ttyS0",
                [0x20; 32],
                [0x30; 32],
                [0x40; 32],
            )
            .unwrap_or_else(|error| panic!("test run inputs should validate: {error}")),
            SingleVmHostProfile::phase1_adversarial(),
        );

        match scenario {
            Ok(scenario) => {
                assert_eq!(scenario.id(), "qemu-boundary-smoke");
                assert_eq!(
                    scenario.fingerprint_definition_digest(),
                    definition.definition_digest()
                );
                assert_eq!(scenario.run_horizon_icount(), 8192);
            }
            Err(error) => panic!("boundary scenario should validate: {error}"),
        }
    }

    #[test]
    fn qemu_boundary_rejects_fingerprint_without_black_box_device_state() {
        let result = QemuExecutionFingerprintDefinition::new(
            QEMU_EXECUTION_FINGERPRINT_CADENCE_ICOUNT,
            [
                QemuFingerprintStateComponent::AggregateIcount,
                QemuFingerprintStateComponent::ArchitecturalRegisters,
                QemuFingerprintStateComponent::GuestMemory,
            ],
            REQUIRED_QEMU_FINGERPRINT_EVENT_BOUNDARIES,
            true,
            false,
        );

        assert!(matches!(
            result,
            Err(QemuDeterminismBoundaryError::MissingFingerprintComponent {
                component: QemuFingerprintStateComponent::DeviceState
            })
        ));
    }

    #[test]
    fn qemu_boundary_rejects_guest_cooperating_or_non_plugin_fingerprint() {
        assert!(matches!(
            QemuExecutionFingerprintDefinition::new(
                QEMU_EXECUTION_FINGERPRINT_CADENCE_ICOUNT,
                REQUIRED_QEMU_FINGERPRINT_COMPONENTS,
                REQUIRED_QEMU_FINGERPRINT_EVENT_BOUNDARIES,
                true,
                true,
            ),
            Err(QemuDeterminismBoundaryError::GuestCooperationRequired)
        ));
        assert!(matches!(
            QemuExecutionFingerprintDefinition::new(
                QEMU_EXECUTION_FINGERPRINT_CADENCE_ICOUNT,
                REQUIRED_QEMU_FINGERPRINT_COMPONENTS,
                REQUIRED_QEMU_FINGERPRINT_EVENT_BOUNDARIES,
                false,
                false,
            ),
            Err(QemuDeterminismBoundaryError::PluginIntrospectionDisabled)
        ));
        assert!(matches!(
            QemuExecutionFingerprintDefinition::black_box_plugin(0),
            Err(QemuDeterminismBoundaryError::InvalidFingerprintCadence)
        ));
    }

    #[test]
    fn qemu_boundary_rejects_incomplete_or_non_failing_microtest_matrix() {
        let profile = default_profile();
        let mut missing = qemu_entropy_elimination_microtests();
        missing.retain(|test| test.elimination != QemuEntropyElimination::GuestEntropyFwCfgSeed);
        assert!(matches!(
            validate_microtests(&profile, &missing),
            Err(QemuDeterminismBoundaryError::MissingMicrotest {
                elimination: QemuEntropyElimination::GuestEntropyFwCfgSeed
            })
        ));

        let mut wrong_case = qemu_entropy_elimination_microtests();
        if let Some(test) = wrong_case
            .iter_mut()
            .find(|test| test.elimination == QemuEntropyElimination::CpuModelEntropyPin)
        {
            test.negative_case = QemuEntropyEliminationNegativeCase::UseHostRtc;
        }
        assert!(matches!(
            validate_microtests(&profile, &wrong_case),
            Err(QemuDeterminismBoundaryError::WrongMicrotestNegativeCase {
                elimination: QemuEntropyElimination::CpuModelEntropyPin,
                expected: QemuEntropyEliminationNegativeCase::UseHostCpuEntropy,
                actual: QemuEntropyEliminationNegativeCase::UseHostRtc,
            })
        ));
    }

    #[test]
    fn qemu_boundary_rejects_wrong_microtest_gate_or_duplicates() {
        let profile = default_profile();
        let mut wrong_gate = qemu_entropy_elimination_microtests();
        if let Some(test) = wrong_gate
            .iter_mut()
            .find(|test| test.elimination == QemuEntropyElimination::SimModeInertness)
        {
            test.gate = "gate:layer0-determinism";
        }
        assert!(matches!(
            validate_microtests(&profile, &wrong_gate),
            Err(QemuDeterminismBoundaryError::WrongMicrotestGate {
                elimination: QemuEntropyElimination::SimModeInertness,
                gate: "gate:layer0-determinism",
            })
        ));

        let mut duplicated = qemu_entropy_elimination_microtests();
        duplicated.push(QemuEntropyEliminationMicrotest::new(
            QemuEntropyElimination::CpuModelEntropyPin,
            "gate:layer0-determinism",
            QemuEntropyEliminationNegativeCase::UseHostCpuEntropy,
        ));
        assert!(matches!(
            validate_microtests(&profile, &duplicated),
            Err(QemuDeterminismBoundaryError::DuplicateMicrotest {
                elimination: QemuEntropyElimination::CpuModelEntropyPin
            })
        ));
    }

    #[test]
    fn qemu_entropy_elimination_negative_cases_are_backed_by_launch_or_inertness_checks() {
        let profile = default_profile();
        for microtest in qemu_entropy_elimination_microtests() {
            if let Err(error) = run_negative_microtest(&profile, microtest) {
                panic!(
                    "negative case {} for {:?} should fail closed: {error}",
                    microtest.negative_case.material_token(),
                    microtest.elimination
                );
            }
        }

        assert_eq!(
            LaunchProfileCandidate::default()
                .with_accelerator("sim,thread=multi")
                .try_into_deterministic(),
            Err(LaunchProfileError::AcceleratorNotSingleThreadSim {
                accelerator: String::from("sim,thread=multi"),
            })
        );
        assert_eq!(
            LaunchProfileCandidate::default()
                .with_accelerator("tcg,thread=single")
                .try_into_deterministic(),
            Err(LaunchProfileError::AcceleratorNotSingleThreadSim {
                accelerator: String::from("tcg,thread=single"),
            })
        );
        assert_eq!(
            LaunchProfileCandidate::default()
                .with_icount_shift(IcountShiftSetting::Auto)
                .try_into_deterministic(),
            Err(LaunchProfileError::IcountShiftAuto)
        );
        assert_eq!(
            LaunchProfileCandidate::default()
                .with_cpu_model("host")
                .try_into_deterministic(),
            Err(LaunchProfileError::CpuModelUsesHost)
        );
        assert_eq!(
            LaunchProfileCandidate::default()
                .with_rtc_clock("host")
                .try_into_deterministic(),
            Err(LaunchProfileError::RtcClockNotVm {
                clock: String::from("host"),
            })
        );
        assert_eq!(
            LaunchProfileCandidate {
                run_seed: 7,
                ..LaunchProfileCandidate::default()
            }
            .try_into_deterministic(),
            Err(LaunchProfileError::RunSeedDiffersFromScenarioSeed {
                scenario_seed: 0x0010_c001,
                run_seed: 7,
            })
        );
        assert_eq!(
            LaunchProfileCandidate::default()
                .with_input_policy(InputPolicy::HostInteractive)
                .try_into_deterministic(),
            Err(LaunchProfileError::InteractiveInputEnabled {
                policy: InputPolicy::HostInteractive,
            })
        );
        assert_eq!(
            LaunchProfileCandidate::default()
                .with_disk_image_mode(DiskImageMode::WritableBacking)
                .try_into_deterministic(),
            Err(LaunchProfileError::DiskImageMutatesBacking {
                mode: DiskImageMode::WritableBacking,
            })
        );
        assert_eq!(
            LaunchProfileCandidate::default()
                .with_guest_backing_state(GuestBackingStateMode::HostMutableGenesis)
                .try_into_deterministic(),
            Err(LaunchProfileError::GuestBackingStateNotByteIdentical {
                mode: GuestBackingStateMode::HostMutableGenesis,
            })
        );
        assert_eq!(
            LaunchProfileCandidate::default()
                .with_guest_core_content(GuestCoreContentMode::GuestInjectedContent)
                .try_into_deterministic(),
            Err(LaunchProfileError::GuestCoreContentRequired {
                mode: GuestCoreContentMode::GuestInjectedContent,
            })
        );

        let material = profile.scenario_hash_material();
        let mut warp_enabled_material = material.replace(
            "idle_warp_under_time_control=suppressed",
            "idle_warp_under_time_control=host-warp-enabled",
        );
        assert!(validate_launch_boundary_material_text(&warp_enabled_material).is_err());
        warp_enabled_material = material.replace(
            "guest_entropy_seed_source=scenario-seed",
            "guest_entropy_seed_source=host-random",
        );
        assert!(validate_launch_boundary_material_text(&warp_enabled_material).is_err());

        let mut without_fw_cfg = profile.canonical_qemu_args();
        remove_option_pair(&mut without_fw_cfg, "-fw_cfg");
        assert!(validate_canonical_launch_args(&without_fw_cfg).is_err());
        let mut unseeded_rng = profile.canonical_qemu_args();
        replace_option_value(&mut unseeded_rng, "-device", "virtio-rng-pci,rng=host-rng0");
        assert!(validate_canonical_launch_args(&unseeded_rng).is_err());
        assert!(matches!(
            assert_qemu_control_plane_inert(QemuControlPlaneObservation {
                qemu_args: vec![String::from("-plugin")],
                ..QemuControlPlaneObservation::sim_off(&profile)
            }),
            Err(QemuControlPlaneInertnessError::ControlPlaneArgumentWhenSimulationOff { .. })
        ));
    }

    #[test]
    fn qemu_boundary_rejects_sim_on_without_whitebox_plugin_introspection() {
        let profile = default_profile();
        let definition = default_definition();
        let microtests = qemu_entropy_elimination_microtests();
        let mut observation = sim_on_observation(&profile);
        replace_option_value(
            &mut observation.qemu_args,
            "-plugin",
            &plugin_config(QemuLaunchPluginSwitch::Off).qemu_plugin_argument(),
        );

        let result =
            validate_qemu_determinism_boundary(&profile, observation, &definition, &microtests);

        assert!(matches!(
            result,
            Err(QemuDeterminismBoundaryError::SimModeActivationMissing {
                missing: "plugin whitebox introspection"
            })
        ));
    }

    #[test]
    fn qemu_boundary_rejects_prefix_matched_plugin_activation_values() {
        let profile = default_profile();
        let definition = default_definition();
        let microtests = qemu_entropy_elimination_microtests();
        let mut observation = sim_on_observation(&profile);
        replace_option_value(
            &mut observation.qemu_args,
            "-plugin",
            "/nix/store/22222222222222222222222222222222-crucible-qemu-plugin/lib/libcrucible_qemu_plugin.so,simfd=30,shmemfd=40,wakefd=50,whitebox=only",
        );

        let result =
            validate_qemu_determinism_boundary(&profile, observation, &definition, &microtests);

        assert!(matches!(
            result,
            Err(QemuDeterminismBoundaryError::SimModeActivationMissing {
                missing: "plugin simfd"
            })
        ));

        let mut observation = sim_on_observation(&profile);
        replace_option_value(
            &mut observation.qemu_args,
            "-plugin",
            "/nix/store/22222222222222222222222222222222-crucible-qemu-plugin/lib/libcrucible_qemu_plugin.so,simfd=3,shmemfd=4,wakefd=5,whitebox=only",
        );

        let result =
            validate_qemu_determinism_boundary(&profile, observation, &definition, &microtests);

        assert!(matches!(
            result,
            Err(QemuDeterminismBoundaryError::SimModeActivationMissing {
                missing: "plugin whitebox introspection"
            })
        ));
    }

    fn default_profile() -> DeterministicLaunchProfile {
        match DeterministicLaunchProfile::conservative_default() {
            Ok(profile) => profile,
            Err(error) => panic!("default deterministic launch profile failed: {error}"),
        }
    }

    fn default_definition() -> QemuExecutionFingerprintDefinition {
        match QemuExecutionFingerprintDefinition::black_box_plugin(
            QEMU_EXECUTION_FINGERPRINT_CADENCE_ICOUNT,
        ) {
            Ok(definition) => definition,
            Err(error) => panic!("default fingerprint definition failed: {error}"),
        }
    }

    fn sim_on_observation(profile: &DeterministicLaunchProfile) -> QemuControlPlaneObservation {
        let command = profile.qemu_launch_command(
            default_vm_config(),
            default_qemu_binary(),
            plugin_config(QemuLaunchPluginSwitch::On),
        );
        let command = match command {
            Ok(command) => command,
            Err(error) => panic!("default sim-on QEMU launch command failed: {error}"),
        };
        QemuControlPlaneObservation {
            qemu_args: command.args().to_vec(),
            ..QemuControlPlaneObservation::sim_on_protocol_contract()
        }
    }

    fn plugin_config(whitebox: QemuLaunchPluginSwitch) -> QemuLaunchPluginConfig {
        let config = QemuLaunchPluginConfig::new(
            "/nix/store/22222222222222222222222222222222-crucible-qemu-plugin/lib/libcrucible_qemu_plugin.so",
            0,
        )
        .with_whitebox(whitebox);
        if whitebox == QemuLaunchPluginSwitch::Off {
            return config;
        }
        let validation = validate_x86_whitebox_hmp_mtree(
            "FlatView #2\n AS \"I/O\", root: io\n  00000000000000e0-00000000000000ef (prio 0, i/o): io @00000000000000e0\n",
        )
        .unwrap_or_else(|error| panic!("test white-box setup validation failed: {error}"));
        config.with_whitebox_setup(validation)
    }

    fn default_vm_config() -> QemuVmLaunchConfig {
        QemuVmLaunchConfig::new(
            "vm-a",
            artifact(
                "kernel",
                "/nix/store/33333333333333333333333333333333-crucible-kernel/bzImage",
            ),
            artifact(
                "root-image",
                "/nix/store/44444444444444444444444444444444-crucible-root/root.qcow2",
            ),
        )
    }

    fn default_qemu_binary() -> &'static str {
        "/nix/store/11111111111111111111111111111111-aos-qemu/bin/qemu-system-x86_64"
    }

    fn artifact(domain: &str, path: &str) -> QemuLaunchArtifact {
        QemuLaunchArtifact::new(ContentHash::from_canonical_material(domain, path), path)
    }
}
