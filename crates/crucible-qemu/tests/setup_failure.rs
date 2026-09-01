//! Checks setup-failure abort handling.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::VecDeque;
use std::error::Error;
use std::io::{self, Write};
use std::process::Command;
use std::time::Duration;

use crucible_protocol::{
    CONTROL_PROTOCOL_MIN_VERSION, CONTROL_PROTOCOL_VERSION, DescriptorHandoverError, FrameIoError,
    HandshakeError, PluginMsg, SchedulableNodeSetup, SetupCompletionError, host_validate_setup_ack,
};
use crucible_qemu::{
    QemuChildWait, QemuNodeSetup, QemuReap, QemuSetupAbortError, QemuSetupDriver,
    QemuSetupFailureKind, QemuSetupFailureSource, QemuShutdownPolicy, QemuShutdownRung,
    QemuShutdownTarget, QemuShutdownTargetError, UnixQemuChildShutdownTarget,
    complete_qemu_node_setup, validate_qemu_setup_region_header,
};
use crucible_shmem::{
    ABI_VERSION, RegionConfig, RegionHeader, RegionHeaderSnapshot, RegionLayout,
    RegionSetupValidationError,
};

#[test]
fn setup_driver_failures_abort_escalate_reap_and_never_schedule() -> Result<(), Box<dyn Error>> {
    for (source, reason) in proto21_failure_sources() {
        let mut target = ScriptedSetupTarget::with_failure(source);

        let outcome = complete_qemu_node_setup(&mut target, QemuShutdownPolicy::fast_test())?;

        match outcome {
            QemuNodeSetup::Failed(ref failed) => {
                assert_eq!(failed.reason(), &reason);
                assert!(!failed.can_schedule());
                assert!(failed.shutdown_report().reaped);
                assert!(!failed.shutdown_report().leaked);
            }
            QemuNodeSetup::Schedulable(setup) => {
                panic!("failed setup unexpectedly became schedulable: {setup:?}");
            }
        }
        assert!(!outcome.can_schedule());
        assert_eq!(
            target.shutdown_actions,
            [
                QemuShutdownRung::ControlQuit,
                QemuShutdownRung::QmpQuit,
                QemuShutdownRung::Sigterm,
                QemuShutdownRung::Sigkill,
                QemuShutdownRung::Reap,
            ],
        );
    }

    Ok(())
}

#[test]
fn setup_driver_returns_schedulable_token_only_after_all_setup_steps() -> Result<(), Box<dyn Error>>
{
    let mut target = ScriptedSetupTarget::ready();

    let outcome = complete_qemu_node_setup(&mut target, QemuShutdownPolicy::fast_test())?;

    match outcome {
        QemuNodeSetup::Schedulable(setup) => {
            assert!(setup.can_schedule());
            assert_eq!(setup.region().abi_version, ABI_VERSION);
            assert_eq!(setup.setup_ack().setup_ack_status(), 0);
        }
        QemuNodeSetup::Failed(ref failed) => {
            panic!("valid setup unexpectedly failed: {failed:?}");
        }
    }
    assert!(outcome.can_schedule());
    assert_eq!(
        target.setup_steps,
        ["handshake", "descriptors", "region", "setup_ack"],
    );
    assert!(target.shutdown_actions.is_empty());

    Ok(())
}

#[test]
fn setup_failure_classifies_proto21_handshake_errors() {
    assert_eq!(
        QemuSetupFailureKind::from_handshake_error(&HandshakeError::ProtocolVersionNoOverlap {
            plugin_max: CONTROL_PROTOCOL_MIN_VERSION - 1,
            host_min: CONTROL_PROTOCOL_MIN_VERSION,
            host_max: CONTROL_PROTOCOL_VERSION,
        }),
        Some(QemuSetupFailureKind::NoProtocolVersionOverlap {
            plugin_max: CONTROL_PROTOCOL_MIN_VERSION - 1,
            host_min: CONTROL_PROTOCOL_MIN_VERSION,
            host_max: CONTROL_PROTOCOL_VERSION,
        }),
    );
    assert_eq!(
        QemuSetupFailureKind::from_handshake_error(&HandshakeError::AbiMismatch {
            plugin_abi: 2,
            host_abi: 1,
        }),
        Some(QemuSetupFailureKind::AbiMismatch {
            plugin_abi: 2,
            host_abi: 1,
        }),
    );
    assert_eq!(
        QemuSetupFailureKind::from_handshake_error(&HandshakeError::InvalidSlot {
            slot_index: 4,
            node_count: 4,
        }),
        Some(QemuSetupFailureKind::BadSlot {
            slot_index: 4,
            node_count: 4,
        }),
    );
    assert_eq!(
        QemuSetupFailureKind::from_handshake_error(&HandshakeError::Io {
            source: FrameIoError::TruncatedLengthPrefix,
        }),
        Some(QemuSetupFailureKind::PrematureSocketClose),
    );
}

#[test]
fn setup_failure_classifies_descriptor_setup_ack_and_real_region_failures()
-> Result<(), Box<dyn Error>> {
    assert_eq!(
        QemuSetupFailureKind::from_descriptor_handover_error(
            &DescriptorHandoverError::WrongDescriptorCount { count: 1 },
        ),
        Some(QemuSetupFailureKind::WrongFdCount { count: 1 }),
    );
    assert_eq!(
        QemuSetupFailureKind::from_descriptor_handover_error(
            &DescriptorHandoverError::PeerClosed {
                operation: "receive setup frame prefix",
            },
        ),
        Some(QemuSetupFailureKind::PrematureSocketClose),
    );
    assert_eq!(
        QemuSetupFailureKind::from_setup_completion_error(&SetupCompletionError::NonZeroSetupAck {
            status: 7,
        }),
        Some(QemuSetupFailureKind::NonZeroSetupAck { status: 7 }),
    );
    assert_eq!(
        QemuSetupFailureKind::from_setup_completion_error(&SetupCompletionError::Io {
            source: FrameIoError::TruncatedPayload { length: 1 },
        }),
        Some(QemuSetupFailureKind::PrematureSocketClose),
    );

    let short_region = short_region_error();
    assert_eq!(
        QemuSetupFailureKind::from_region_validation_error(&short_region),
        QemuSetupFailureKind::ShortOrInvalidRegion,
    );

    let invalid_abi_marker = invalid_abi_marker_error()?;
    assert_eq!(
        QemuSetupFailureKind::from_region_validation_error(&invalid_abi_marker),
        QemuSetupFailureKind::ShortOrInvalidRegion,
    );

    let layout = valid_layout()?;
    let valid_region =
        validate_qemu_setup_region_header(valid_snapshot(layout), layout.region_size)?;
    assert_eq!(valid_region.region_len, layout.region_size);
    assert_eq!(valid_region.abi_version, ABI_VERSION);

    Ok(())
}

#[test]
fn setup_abort_error_preserves_failure_reason_when_child_leaks() {
    let mut target =
        ScriptedSetupTarget::with_failure(SetupCompletionError::NonZeroSetupAck { status: 9 });
    target.reap_result = QemuReap::StillAlive;
    target.wait_results = VecDeque::from([
        QemuChildWait::StillRunning,
        QemuChildWait::StillRunning,
        QemuChildWait::StillRunning,
        QemuChildWait::StillRunning,
    ]);

    let result = complete_qemu_node_setup(&mut target, QemuShutdownPolicy::fast_test());

    match result {
        Err(QemuSetupAbortError::Shutdown {
            reason: actual,
            source,
        }) => {
            assert_eq!(actual, QemuSetupFailureKind::NonZeroSetupAck { status: 9 });
            assert!(source.to_string().contains("remained live"));
        }
        other => panic!("expected setup shutdown failure, got {other:?}"),
    }
}

#[test]
fn setup_driver_reaps_real_child_and_never_schedules() -> Result<(), Box<dyn Error>> {
    let child = Command::new("sleep").arg("60").spawn()?;
    let mut target =
        ProcessSetupTarget::new(child, SetupCompletionError::NonZeroSetupAck { status: 11 });
    let mut policy = QemuShutdownPolicy::fast_test();
    policy.sigterm_wait = Duration::from_secs(2);
    policy.reap_wait = Duration::from_secs(1);

    let outcome = complete_qemu_node_setup(&mut target, policy)?;

    match outcome {
        QemuNodeSetup::Failed(ref failed) => {
            assert_eq!(
                failed.reason(),
                &QemuSetupFailureKind::NonZeroSetupAck { status: 11 },
            );
            assert!(!failed.can_schedule());
            assert!(failed.shutdown_report().reaped);
            assert!(!failed.shutdown_report().leaked);
        }
        QemuNodeSetup::Schedulable(setup) => {
            panic!("failed setup unexpectedly became schedulable: {setup:?}");
        }
    }
    assert!(!outcome.can_schedule());
    assert!(target.reaped());

    Ok(())
}

#[test]
fn setup_driver_reaps_real_qemu_child_for_invalid_region_when_env_set() -> Result<(), Box<dyn Error>>
{
    let Some(qemu) = std::env::var_os("CRUCIBLE_QEMU_SETUP_FAILURE_TEST_BINARY") else {
        return Ok(());
    };
    let child = Command::new(qemu)
        .args([
            "-nodefaults",
            "-no-user-config",
            "-display",
            "none",
            "-machine",
            "none",
            "-S",
            "-monitor",
            "none",
            "-serial",
            "none",
        ])
        .spawn()?;
    let mut target = ProcessSetupTarget::new(child, short_region_error());
    let mut policy = QemuShutdownPolicy::fast_test();
    policy.sigterm_wait = Duration::from_secs(2);
    policy.reap_wait = Duration::from_secs(1);

    let outcome = complete_qemu_node_setup(&mut target, policy)?;

    match outcome {
        QemuNodeSetup::Failed(ref failed) => {
            assert_eq!(failed.reason(), &QemuSetupFailureKind::ShortOrInvalidRegion);
            assert!(!failed.can_schedule());
            assert!(failed.shutdown_report().reaped);
            assert!(!failed.shutdown_report().leaked);
        }
        QemuNodeSetup::Schedulable(setup) => {
            panic!("failed setup unexpectedly became schedulable: {setup:?}");
        }
    }
    assert!(!outcome.can_schedule());
    assert!(target.reaped());

    Ok(())
}

fn proto21_failure_sources() -> Vec<(QemuSetupFailureSource, QemuSetupFailureKind)> {
    vec![
        (
            HandshakeError::ProtocolVersionNoOverlap {
                plugin_max: 0,
                host_min: 1,
                host_max: 1,
            }
            .into(),
            QemuSetupFailureKind::NoProtocolVersionOverlap {
                plugin_max: 0,
                host_min: 1,
                host_max: 1,
            },
        ),
        (
            HandshakeError::AbiMismatch {
                plugin_abi: 2,
                host_abi: 1,
            }
            .into(),
            QemuSetupFailureKind::AbiMismatch {
                plugin_abi: 2,
                host_abi: 1,
            },
        ),
        (
            HandshakeError::InvalidSlot {
                slot_index: 2,
                node_count: 2,
            }
            .into(),
            QemuSetupFailureKind::BadSlot {
                slot_index: 2,
                node_count: 2,
            },
        ),
        (
            DescriptorHandoverError::WrongDescriptorCount { count: 3 }.into(),
            QemuSetupFailureKind::WrongFdCount { count: 3 },
        ),
        (
            short_region_error().into(),
            QemuSetupFailureKind::ShortOrInvalidRegion,
        ),
        (
            SetupCompletionError::NonZeroSetupAck { status: 1 }.into(),
            QemuSetupFailureKind::NonZeroSetupAck { status: 1 },
        ),
        (
            SetupCompletionError::Io {
                source: FrameIoError::TruncatedLengthPrefix,
            }
            .into(),
            QemuSetupFailureKind::PrematureSocketClose,
        ),
    ]
}

fn valid_layout() -> Result<RegionLayout, Box<dyn Error>> {
    Ok(RegionLayout::for_config(RegionConfig::new(1, 64, 3))?)
}

fn valid_snapshot(layout: RegionLayout) -> RegionHeaderSnapshot {
    RegionHeader::new(layout).snapshot()
}

fn short_region_error() -> RegionSetupValidationError {
    let minimum_len = 8;
    match validate_qemu_setup_region_header(
        RegionHeaderSnapshot {
            magic: 0,
            abi_version: 0,
            node_count: 0,
            queue_capacity: 0,
            ring_count: 0,
            ring_hdr_off: 0,
            ring_data_off: 0,
            entry_stride: 0,
            region_size: 0,
            icount_shift: 0,
            pause_requested: 0,
            shutdown_requested: 0,
            fault_payload_arena_bytes: 0,
        },
        minimum_len - 1,
    ) {
        Err(error) => error,
        Ok(region) => panic!("short setup region unexpectedly validated: {region:?}"),
    }
}

fn invalid_abi_marker_error() -> Result<RegionSetupValidationError, Box<dyn Error>> {
    let layout = valid_layout()?;
    let mut snapshot = valid_snapshot(layout);
    snapshot.abi_version = ABI_VERSION + 1;
    Ok(
        match validate_qemu_setup_region_header(snapshot, layout.region_size) {
            Err(error) => error,
            Ok(region) => panic!("invalid ABI marker unexpectedly validated: {region:?}"),
        },
    )
}

#[derive(Debug)]
struct ScriptedSetupTarget {
    setup_steps: Vec<&'static str>,
    shutdown_actions: Vec<QemuShutdownRung>,
    failure: Option<QemuSetupFailureSource>,
    wait_results: VecDeque<QemuChildWait>,
    reap_result: QemuReap,
}

impl ScriptedSetupTarget {
    fn ready() -> Self {
        Self {
            setup_steps: Vec::new(),
            shutdown_actions: Vec::new(),
            failure: None,
            wait_results: VecDeque::from([QemuChildWait::Exited]),
            reap_result: QemuReap::Reaped,
        }
    }

    fn with_failure(failure: impl Into<QemuSetupFailureSource>) -> Self {
        Self {
            setup_steps: Vec::new(),
            shutdown_actions: Vec::new(),
            failure: Some(failure.into()),
            wait_results: VecDeque::from([
                QemuChildWait::StillRunning,
                QemuChildWait::StillRunning,
                QemuChildWait::StillRunning,
                QemuChildWait::Exited,
            ]),
            reap_result: QemuReap::Reaped,
        }
    }

    fn failure(&self) -> Option<&QemuSetupFailureSource> {
        self.failure.as_ref()
    }
}

impl QemuSetupDriver for ScriptedSetupTarget {
    fn accept_handshake(&mut self) -> Result<(), HandshakeError> {
        self.setup_steps.push("handshake");
        match self.failure() {
            Some(QemuSetupFailureSource::Handshake(error)) => Err(error.clone()),
            _ => Ok(()),
        }
    }

    fn receive_setup_descriptors(&mut self) -> Result<(), DescriptorHandoverError> {
        self.setup_steps.push("descriptors");
        match self.failure() {
            Some(QemuSetupFailureSource::DescriptorHandover(error)) => Err(error.clone()),
            _ => Ok(()),
        }
    }

    fn validate_setup_region(
        &mut self,
    ) -> Result<crucible_shmem::ValidatedSetupRegion, RegionSetupValidationError> {
        self.setup_steps.push("region");
        match self.failure() {
            Some(QemuSetupFailureSource::RegionValidation(error)) => Err(error.clone()),
            _ => {
                let layout = RegionLayout::for_config(RegionConfig::new(1, 64, 3))
                    .map_err(|_| RegionSetupValidationError::GeometryOverflow)?;
                validate_qemu_setup_region_header(valid_snapshot(layout), layout.region_size)
            }
        }
    }

    fn accept_setup_ack(&mut self) -> Result<SchedulableNodeSetup, SetupCompletionError> {
        self.setup_steps.push("setup_ack");
        match self.failure() {
            Some(QemuSetupFailureSource::SetupCompletion(error)) => Err(error.clone()),
            _ => host_validate_setup_ack(PluginMsg::SetupAck { status: 0 }),
        }
    }
}

impl QemuShutdownTarget for ScriptedSetupTarget {
    fn send_control_quit(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.shutdown_actions.push(QemuShutdownRung::ControlQuit);
        Ok(())
    }

    fn send_qmp_quit(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.shutdown_actions.push(QemuShutdownRung::QmpQuit);
        Ok(())
    }

    fn send_sigterm(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.shutdown_actions.push(QemuShutdownRung::Sigterm);
        Ok(())
    }

    fn send_sigkill(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.shutdown_actions.push(QemuShutdownRung::Sigkill);
        Ok(())
    }

    fn wait_for_exit(
        &mut self,
        _rung: QemuShutdownRung,
        _timeout: Duration,
    ) -> Result<QemuChildWait, QemuShutdownTargetError> {
        Ok(self
            .wait_results
            .pop_front()
            .unwrap_or(QemuChildWait::StillRunning))
    }

    fn reap(&mut self, _timeout: Duration) -> Result<QemuReap, QemuShutdownTargetError> {
        self.shutdown_actions.push(QemuShutdownRung::Reap);
        Ok(self.reap_result)
    }
}

#[derive(Debug)]
struct ProcessSetupTarget {
    shutdown: UnixQemuChildShutdownTarget<FailingWriter, FailingWriter>,
    failure: QemuSetupFailureSource,
}

impl ProcessSetupTarget {
    fn new(child: std::process::Child, failure: impl Into<QemuSetupFailureSource>) -> Self {
        Self {
            shutdown: UnixQemuChildShutdownTarget::new(child, FailingWriter, FailingWriter),
            failure: failure.into(),
        }
    }

    fn reaped(&self) -> bool {
        self.shutdown.reaped()
    }
}

impl QemuSetupDriver for ProcessSetupTarget {
    fn accept_handshake(&mut self) -> Result<(), HandshakeError> {
        match &self.failure {
            QemuSetupFailureSource::Handshake(error) => Err(error.clone()),
            _ => Ok(()),
        }
    }

    fn receive_setup_descriptors(&mut self) -> Result<(), DescriptorHandoverError> {
        match &self.failure {
            QemuSetupFailureSource::DescriptorHandover(error) => Err(error.clone()),
            _ => Ok(()),
        }
    }

    fn validate_setup_region(
        &mut self,
    ) -> Result<crucible_shmem::ValidatedSetupRegion, RegionSetupValidationError> {
        match &self.failure {
            QemuSetupFailureSource::RegionValidation(error) => Err(error.clone()),
            _ => {
                let layout = RegionLayout::for_config(RegionConfig::new(1, 64, 3))
                    .map_err(|_| RegionSetupValidationError::GeometryOverflow)?;
                validate_qemu_setup_region_header(valid_snapshot(layout), layout.region_size)
            }
        }
    }

    fn accept_setup_ack(&mut self) -> Result<SchedulableNodeSetup, SetupCompletionError> {
        match &self.failure {
            QemuSetupFailureSource::SetupCompletion(error) => Err(error.clone()),
            _ => host_validate_setup_ack(PluginMsg::SetupAck { status: 0 }),
        }
    }
}

impl QemuShutdownTarget for ProcessSetupTarget {
    fn send_control_quit(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.shutdown.send_control_quit()
    }

    fn send_qmp_quit(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.shutdown.send_qmp_quit()
    }

    fn send_sigterm(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.shutdown.send_sigterm()
    }

    fn send_sigkill(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.shutdown.send_sigkill()
    }

    fn wait_for_exit(
        &mut self,
        rung: QemuShutdownRung,
        timeout: Duration,
    ) -> Result<QemuChildWait, QemuShutdownTargetError> {
        self.shutdown.wait_for_exit(rung, timeout)
    }

    fn reap(&mut self, timeout: Duration) -> Result<QemuReap, QemuShutdownTargetError> {
        self.shutdown.reap(timeout)
    }
}

#[derive(Debug)]
struct FailingWriter;

impl Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
