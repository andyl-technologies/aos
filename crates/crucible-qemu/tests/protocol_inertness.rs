//! Checks QEMU control-plane inertness for RFC-0010 PROTO-24.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible_protocol::{ALL_CONTROL_TAGS, RuntimeDataPlane, RuntimeDataPlaneContract};
use crucible_qemu::{
    DeterministicLaunchProfile, QemuControlPlaneInertnessError, QemuControlPlaneObservation,
    QemuSimulationMode, SIM_ON_CONTROL_FRAME_CLASSES, assert_qemu_control_plane_inert,
};

fn default_profile() -> DeterministicLaunchProfile {
    match DeterministicLaunchProfile::conservative_default() {
        Ok(profile) => profile,
        Err(error) => panic!("default deterministic launch profile failed: {error}"),
    }
}

fn assert_inert(
    observation: QemuControlPlaneObservation,
) -> crucible_qemu::QemuControlPlaneInertnessReport {
    match assert_qemu_control_plane_inert(observation) {
        Ok(report) => report,
        Err(error) => panic!("inertness assertion should pass: {error}"),
    }
}

fn assert_not_inert(observation: QemuControlPlaneObservation) -> QemuControlPlaneInertnessError {
    match assert_qemu_control_plane_inert(observation) {
        Ok(report) => panic!("inertness assertion should fail, got report: {report:?}"),
        Err(error) => error,
    }
}

#[test]
fn sim_mode_off_creates_no_control_socket_and_sends_no_frames() {
    let profile = default_profile();
    let observation = QemuControlPlaneObservation::sim_off(&profile);

    assert!(
        !observation
            .qemu_args
            .iter()
            .any(|arg| arg == "-plugin" || arg.contains("control-socket=")),
        "sim-off canonical QEMU args must not enable plugin/control I/O"
    );
    assert!(
        observation
            .qemu_args
            .windows(2)
            .any(|window| { window == ["-accel", "tcg,thread=single"] })
    );
    assert!(
        !observation
            .qemu_args
            .windows(2)
            .any(|window| { window == ["-accel", "sim,thread=single"] })
    );

    let report = assert_inert(observation);
    assert_eq!(report.simulation_mode, QemuSimulationMode::Off);
    assert!(!report.control_socket_created);
    assert_eq!(report.sent_control_frame_count, 0);
}

#[test]
fn sim_mode_off_rejects_control_plane_activation() {
    let profile = default_profile();

    for forbidden_arg in [
        "-plugin",
        "path=plugin.so,crucible-control-fd=7",
        "path=plugin.so,crucible-control-socket=/tmp/crucible.sock",
        "path=plugin.so,crucible-sim=on",
        "path=plugin.so,crucible-simulation=on",
        "control-socket=/tmp/crucible.sock",
        "sim-mode=on",
    ] {
        assert_eq!(
            assert_not_inert(QemuControlPlaneObservation {
                qemu_args: vec![String::from(forbidden_arg)],
                ..QemuControlPlaneObservation::sim_off(&profile)
            }),
            QemuControlPlaneInertnessError::ControlPlaneArgumentWhenSimulationOff {
                argument: String::from(forbidden_arg),
            },
            "sim-off launch must reject {forbidden_arg}"
        );
    }
    assert_eq!(
        assert_not_inert(QemuControlPlaneObservation {
            qemu_args: vec![String::from("-accel"), String::from("sim,thread=single"),],
            ..QemuControlPlaneObservation::sim_off(&profile)
        }),
        QemuControlPlaneInertnessError::ControlPlaneArgumentWhenSimulationOff {
            argument: String::from("sim,thread=single"),
        }
    );
    for machine_flag in ["-machine", "-M"] {
        assert_eq!(
            assert_not_inert(QemuControlPlaneObservation {
                qemu_args: vec![
                    String::from(machine_flag),
                    String::from("q35,usb=off,accel=sim"),
                ],
                ..QemuControlPlaneObservation::sim_off(&profile)
            }),
            QemuControlPlaneInertnessError::ControlPlaneArgumentWhenSimulationOff {
                argument: String::from("q35,usb=off,accel=sim"),
            },
            "sim-off launch must reject the {machine_flag} accelerator form"
        );
    }
    assert_eq!(
        assert_not_inert(QemuControlPlaneObservation {
            control_socket_created: true,
            ..QemuControlPlaneObservation::sim_off(&profile)
        }),
        QemuControlPlaneInertnessError::ControlSocketCreatedWhenSimulationOff
    );
    assert_eq!(
        assert_not_inert(QemuControlPlaneObservation {
            sent_control_frame_count: 1,
            ..QemuControlPlaneObservation::sim_off(&profile)
        }),
        QemuControlPlaneInertnessError::ControlFrameSentWhenSimulationOff { count: 1 }
    );
}

#[test]
fn sim_mode_on_control_channel_is_timing_neutral_and_silent_during_run() {
    let report = assert_inert(QemuControlPlaneObservation::sim_on_protocol_contract());
    let mut classified_tags = SIM_ON_CONTROL_FRAME_CLASSES.map(|frame_class| frame_class.tag);
    let mut registry_tags = ALL_CONTROL_TAGS;
    classified_tags.sort_by_key(|tag| tag.wire_value());
    registry_tags.sort_by_key(|tag| tag.wire_value());

    assert_eq!(report.simulation_mode, QemuSimulationMode::On);
    assert!(report.control_socket_created);
    assert_eq!(report.runtime_data_plane, RuntimeDataPlane::SharedMemory);
    assert!(!report.control_channel_carries_runtime_frames);
    assert!(!report.control_channel_carries_delivery_icounts);
    assert!(report.control_channel_silent_between_setup_ack_and_quit);
    assert_eq!(report.runtime_control_frame_count, 0);
    assert!(!report.timing_significant_control_payloads);
    assert_eq!(
        classified_tags, registry_tags,
        "sim-on inertness table must classify every registered control tag"
    );
    assert!(
        SIM_ON_CONTROL_FRAME_CLASSES
            .iter()
            .all(|frame_class| !frame_class.timing_significant && !frame_class.allowed_during_run),
        "sim-on lifecycle frames must remain setup/shutdown-only and timing-neutral"
    );
}

#[test]
fn sim_mode_on_rejects_timing_significant_or_run_phase_control_traffic() {
    assert_eq!(
        assert_not_inert(QemuControlPlaneObservation {
            runtime_contract: RuntimeDataPlaneContract {
                runtime_data_plane: RuntimeDataPlane::SharedMemory,
                control_channel_carries_runtime_frames: true,
                control_channel_carries_delivery_icounts: false,
                control_channel_silent_between_setup_ack_and_quit: true,
            },
            ..QemuControlPlaneObservation::sim_on_protocol_contract()
        }),
        QemuControlPlaneInertnessError::ControlChannelCarriesRuntimeFrames
    );
    assert_eq!(
        assert_not_inert(QemuControlPlaneObservation {
            runtime_contract: RuntimeDataPlaneContract {
                runtime_data_plane: RuntimeDataPlane::SharedMemory,
                control_channel_carries_runtime_frames: false,
                control_channel_carries_delivery_icounts: true,
                control_channel_silent_between_setup_ack_and_quit: true,
            },
            ..QemuControlPlaneObservation::sim_on_protocol_contract()
        }),
        QemuControlPlaneInertnessError::ControlChannelCarriesDeliveryIcounts
    );
    assert_eq!(
        assert_not_inert(QemuControlPlaneObservation {
            runtime_contract: RuntimeDataPlaneContract {
                runtime_data_plane: RuntimeDataPlane::SharedMemory,
                control_channel_carries_runtime_frames: false,
                control_channel_carries_delivery_icounts: false,
                control_channel_silent_between_setup_ack_and_quit: false,
            },
            ..QemuControlPlaneObservation::sim_on_protocol_contract()
        }),
        QemuControlPlaneInertnessError::ControlChannelNotSilentDuringRun
    );
    assert_eq!(
        assert_not_inert(QemuControlPlaneObservation {
            runtime_control_frame_count: 1,
            ..QemuControlPlaneObservation::sim_on_protocol_contract()
        }),
        QemuControlPlaneInertnessError::ControlFrameObservedDuringRun { count: 1 }
    );
    assert_eq!(
        assert_not_inert(QemuControlPlaneObservation {
            timing_significant_control_payloads: true,
            ..QemuControlPlaneObservation::sim_on_protocol_contract()
        }),
        QemuControlPlaneInertnessError::TimingSignificantControlPayloads
    );
}
