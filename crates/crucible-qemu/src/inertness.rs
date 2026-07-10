//! QEMU control-plane inertness assertions.
//!
//! RFC-0010 PROTO-24 requires the QEMU control channel to be absent when
//! simulation mode is off and determinism-neutral when simulation mode is on.
//! This module records that boundary as a host-side assertion that can be used
//! before process launch and by phase gates.

use crucible_protocol::{
    ControlTag, RUNTIME_DATA_PLANE_CONTRACT, RuntimeDataPlane, RuntimeDataPlaneContract,
};
use thiserror::Error;

use crate::DeterministicLaunchProfile;

const SIM_OFF_FORBIDDEN_ARG_FRAGMENTS: [&str; 7] = [
    "-plugin",
    "crucible-control-fd=",
    "crucible-control-socket=",
    "crucible-sim=on",
    "crucible-simulation=on",
    "control-socket=",
    "sim-mode=on",
];

/// QEMU simulation activation state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuSimulationMode {
    /// Simulation mode is disabled and QEMU must run without Crucible control I/O.
    Off,
    /// Simulation mode is enabled and setup/shutdown control I/O may exist.
    On,
}

/// Timing relevance and run-phase availability for one control-frame tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuControlFrameClass {
    /// Control-frame tag being classified.
    pub tag: ControlTag,
    /// Whether the frame carries virtual time, wall-clock time, or runtime payload data.
    pub timing_significant: bool,
    /// Whether the frame is allowed between setup acknowledgement and quit.
    pub allowed_during_run: bool,
}

/// Static classification of the sim-on lifecycle control frames.
pub const SIM_ON_CONTROL_FRAME_CLASSES: [QemuControlFrameClass; 5] = [
    QemuControlFrameClass {
        tag: ControlTag::Hello,
        timing_significant: false,
        allowed_during_run: false,
    },
    QemuControlFrameClass {
        tag: ControlTag::HelloAck,
        timing_significant: false,
        allowed_during_run: false,
    },
    QemuControlFrameClass {
        tag: ControlTag::Setup,
        timing_significant: false,
        allowed_during_run: false,
    },
    QemuControlFrameClass {
        tag: ControlTag::SetupAck,
        timing_significant: false,
        allowed_during_run: false,
    },
    QemuControlFrameClass {
        tag: ControlTag::Quit,
        timing_significant: false,
        allowed_during_run: false,
    },
];

/// Observed or planned QEMU control-plane state for one launch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuControlPlaneObservation {
    /// Simulation activation state for this launch.
    pub simulation_mode: QemuSimulationMode,
    /// QEMU argument vector that will be passed to the child.
    pub qemu_args: Vec<String>,
    /// Whether the host created a Crucible control socket.
    pub control_socket_created: bool,
    /// Number of control frames sent in any phase.
    pub sent_control_frame_count: usize,
    /// Number of control frames observed during the run phase.
    pub runtime_control_frame_count: usize,
    /// Protocol data-plane split used by the launch.
    pub runtime_contract: RuntimeDataPlaneContract,
    /// Whether any control payload carries timing-significant data.
    pub timing_significant_control_payloads: bool,
}

impl QemuControlPlaneObservation {
    /// Builds the expected sim-off observation from the canonical launch profile.
    #[must_use]
    pub fn sim_off(profile: &DeterministicLaunchProfile) -> Self {
        Self {
            simulation_mode: QemuSimulationMode::Off,
            qemu_args: profile.canonical_sim_off_qemu_args(),
            control_socket_created: false,
            sent_control_frame_count: 0,
            runtime_control_frame_count: 0,
            runtime_contract: RUNTIME_DATA_PLANE_CONTRACT,
            timing_significant_control_payloads: false,
        }
    }

    /// Builds the expected sim-on protocol observation.
    #[must_use]
    pub fn sim_on_protocol_contract() -> Self {
        Self {
            simulation_mode: QemuSimulationMode::On,
            qemu_args: Vec::new(),
            control_socket_created: true,
            sent_control_frame_count: SIM_ON_CONTROL_FRAME_CLASSES.len(),
            runtime_control_frame_count: 0,
            runtime_contract: RUNTIME_DATA_PLANE_CONTRACT,
            timing_significant_control_payloads: false,
        }
    }
}

/// Validated QEMU control-plane inertness report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuControlPlaneInertnessReport {
    /// Simulation activation state that was checked.
    pub simulation_mode: QemuSimulationMode,
    /// Whether the host created a Crucible control socket.
    pub control_socket_created: bool,
    /// Number of control frames sent in any phase.
    pub sent_control_frame_count: usize,
    /// Number of control frames observed during the run phase.
    pub runtime_control_frame_count: usize,
    /// Runtime data-plane selected by the protocol contract.
    pub runtime_data_plane: RuntimeDataPlane,
    /// Whether control frames carry runtime frame payloads.
    pub control_channel_carries_runtime_frames: bool,
    /// Whether control frames carry frame delivery instruction counts.
    pub control_channel_carries_delivery_icounts: bool,
    /// Whether the control channel is silent between setup acknowledgement and quit.
    pub control_channel_silent_between_setup_ack_and_quit: bool,
    /// Whether any control payload carries timing-significant data.
    pub timing_significant_control_payloads: bool,
}

/// Error returned when a QEMU control-plane observation violates inertness.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum QemuControlPlaneInertnessError {
    /// A sim-off QEMU argument enables the Crucible control plane.
    #[error("sim-off launch argument enables Crucible control I/O: {argument}")]
    ControlPlaneArgumentWhenSimulationOff {
        /// Argument that enables a plugin or control channel.
        argument: String,
    },
    /// A sim-off launch created a control socket.
    #[error("sim-off launch created a Crucible control socket")]
    ControlSocketCreatedWhenSimulationOff,
    /// A sim-off launch sent at least one control frame.
    #[error("sim-off launch sent {count} control frames")]
    ControlFrameSentWhenSimulationOff {
        /// Number of frames sent while simulation mode was off.
        count: usize,
    },
    /// A sim-on launch used a runtime data plane other than shared memory.
    #[error("sim-on runtime data plane is not shared memory: {data_plane:?}")]
    RuntimeDataPlaneNotSharedMemory {
        /// Observed runtime data plane.
        data_plane: RuntimeDataPlane,
    },
    /// A sim-on launch carried runtime frame payloads on the control channel.
    #[error("sim-on control channel carries runtime frame payloads")]
    ControlChannelCarriesRuntimeFrames,
    /// A sim-on launch carried frame delivery instruction counts on the control channel.
    #[error("sim-on control channel carries delivery instruction counts")]
    ControlChannelCarriesDeliveryIcounts,
    /// A sim-on launch did not keep the control channel silent during the run.
    #[error("sim-on control channel is not silent during the run")]
    ControlChannelNotSilentDuringRun,
    /// A sim-on observation saw control frames during the run phase.
    #[error("sim-on run phase observed {count} control frames")]
    ControlFrameObservedDuringRun {
        /// Number of run-phase control frames observed.
        count: usize,
    },
    /// A sim-on observation carried timing-significant control payloads.
    #[error("sim-on control channel carried timing-significant payloads")]
    TimingSignificantControlPayloads,
    /// A lifecycle control tag was classified as timing-significant.
    #[error("sim-on lifecycle tag {tag:?} was classified as timing-significant")]
    TimingSignificantLifecycleTag {
        /// Control tag that was classified as timing-significant.
        tag: ControlTag,
    },
    /// A lifecycle control tag was allowed during the run phase.
    #[error("sim-on lifecycle tag {tag:?} was allowed during the run phase")]
    LifecycleTagAllowedDuringRun {
        /// Control tag that was allowed during the run phase.
        tag: ControlTag,
    },
}

/// Validates QEMU control-plane inertness for one launch observation.
///
/// # Errors
///
/// Returns [`QemuControlPlaneInertnessError`] when sim-off launch state creates
/// a control channel or sends frames, or when sim-on protocol state allows
/// timing-significant or run-phase control-channel traffic.
pub fn assert_qemu_control_plane_inert(
    observation: QemuControlPlaneObservation,
) -> Result<QemuControlPlaneInertnessReport, QemuControlPlaneInertnessError> {
    match observation.simulation_mode {
        QemuSimulationMode::Off => validate_sim_off(&observation)?,
        QemuSimulationMode::On => validate_sim_on(&observation)?,
    }

    Ok(QemuControlPlaneInertnessReport {
        simulation_mode: observation.simulation_mode,
        control_socket_created: observation.control_socket_created,
        sent_control_frame_count: observation.sent_control_frame_count,
        runtime_control_frame_count: observation.runtime_control_frame_count,
        runtime_data_plane: observation.runtime_contract.runtime_data_plane,
        control_channel_carries_runtime_frames: observation
            .runtime_contract
            .control_channel_carries_runtime_frames,
        control_channel_carries_delivery_icounts: observation
            .runtime_contract
            .control_channel_carries_delivery_icounts,
        control_channel_silent_between_setup_ack_and_quit: observation
            .runtime_contract
            .control_channel_silent_between_setup_ack_and_quit,
        timing_significant_control_payloads: observation.timing_significant_control_payloads,
    })
}

fn validate_sim_off(
    observation: &QemuControlPlaneObservation,
) -> Result<(), QemuControlPlaneInertnessError> {
    if let Some(argument) = sim_off_control_argument(&observation.qemu_args) {
        return Err(
            QemuControlPlaneInertnessError::ControlPlaneArgumentWhenSimulationOff {
                argument: argument.to_owned(),
            },
        );
    }
    if observation.control_socket_created {
        return Err(QemuControlPlaneInertnessError::ControlSocketCreatedWhenSimulationOff);
    }
    if observation.sent_control_frame_count != 0 {
        return Err(
            QemuControlPlaneInertnessError::ControlFrameSentWhenSimulationOff {
                count: observation.sent_control_frame_count,
            },
        );
    }
    Ok(())
}

fn validate_sim_on(
    observation: &QemuControlPlaneObservation,
) -> Result<(), QemuControlPlaneInertnessError> {
    if observation.runtime_contract.runtime_data_plane != RuntimeDataPlane::SharedMemory {
        return Err(
            QemuControlPlaneInertnessError::RuntimeDataPlaneNotSharedMemory {
                data_plane: observation.runtime_contract.runtime_data_plane,
            },
        );
    }
    if observation
        .runtime_contract
        .control_channel_carries_runtime_frames
    {
        return Err(QemuControlPlaneInertnessError::ControlChannelCarriesRuntimeFrames);
    }
    if observation
        .runtime_contract
        .control_channel_carries_delivery_icounts
    {
        return Err(QemuControlPlaneInertnessError::ControlChannelCarriesDeliveryIcounts);
    }
    if !observation
        .runtime_contract
        .control_channel_silent_between_setup_ack_and_quit
    {
        return Err(QemuControlPlaneInertnessError::ControlChannelNotSilentDuringRun);
    }
    if observation.runtime_control_frame_count != 0 {
        return Err(
            QemuControlPlaneInertnessError::ControlFrameObservedDuringRun {
                count: observation.runtime_control_frame_count,
            },
        );
    }
    if observation.timing_significant_control_payloads {
        return Err(QemuControlPlaneInertnessError::TimingSignificantControlPayloads);
    }
    for frame_class in SIM_ON_CONTROL_FRAME_CLASSES {
        if frame_class.timing_significant {
            return Err(
                QemuControlPlaneInertnessError::TimingSignificantLifecycleTag {
                    tag: frame_class.tag,
                },
            );
        }
        if frame_class.allowed_during_run {
            return Err(
                QemuControlPlaneInertnessError::LifecycleTagAllowedDuringRun {
                    tag: frame_class.tag,
                },
            );
        }
    }
    Ok(())
}

fn sim_off_control_argument(args: &[String]) -> Option<&str> {
    args.windows(2)
        .find_map(|window| {
            let selects_sim = match window[0].as_str() {
                "-accel" => window[1]
                    .split(',')
                    .next()
                    .is_some_and(|accelerator| accelerator.eq_ignore_ascii_case("sim")),
                "-machine" | "-M" => window[1].split(',').any(|option| {
                    option.split_once('=').is_some_and(|(key, value)| {
                        key.eq_ignore_ascii_case("accel") && value.eq_ignore_ascii_case("sim")
                    })
                }),
                _ => false,
            };
            selects_sim.then_some(window[1].as_str())
        })
        .or_else(|| {
            args.iter().find_map(|arg| {
                SIM_OFF_FORBIDDEN_ARG_FRAGMENTS
                    .iter()
                    .any(|fragment| arg == fragment || arg.contains(fragment))
                    .then_some(arg.as_str())
            })
        })
}
