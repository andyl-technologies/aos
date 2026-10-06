//! Fail-closed setup tests at the production launch cleanup boundary.

#![cfg(target_os = "linux")]

use std::error::Error;
use std::path::PathBuf;
use std::process::Command;
use std::thread;

use crucible_protocol::{
    ControlLifecycleIoError, SETUP_ACK_STATUS_SETUP_FAILED, SetupCompletionError,
};
use crucible_shmem::{RegionConfig, RegionLayout};

use super::*;
use crate::host_setup::{complete_qemu_host_plugin_setup, tests::plugin_peer_reject_setup};
use crate::spawn::create_test_spawn_resource_pair;
use crate::{QemuFaultCapabilityRequirement, QemuHostPluginSetupError, QemuNodeChild};

#[test]
fn invalid_region_setup_reaps_real_child_before_scheduler_admission() -> Result<(), Box<dyn Error>>
{
    let config = RegionConfig::new(1, 4);
    let layout = RegionLayout::for_config(config)?;
    let (resources, _plugin_socket) = create_test_spawn_resource_pair(layout.region_size + 4096)?;
    let (child, process_id) = sleeping_test_child()?;

    let error = complete_host_setup_or_reap(child, || {
        complete_qemu_host_plugin_setup(
            resources.into_setup_resources(),
            config,
            0,
            &QemuFaultCapabilityRequirement::abi_boundary_v1(),
        )
    })
    .err()
    .ok_or("invalid region length unexpectedly completed setup")?;

    assert!(matches!(
        error,
        QemuLiveNodeStepGateError::HostSetup {
            source: QemuHostPluginSetupError::RegionLengthMismatch {
                spawn_region_len,
                layout_region_len,
            },
        } if spawn_region_len == layout.region_size + 4096
            && layout_region_len == layout.region_size
    ));
    assert_child_reaped(process_id)?;

    Ok(())
}

#[test]
fn nonready_ack_after_descriptor_handoff_reaps_real_child_before_scheduler_admission()
-> Result<(), Box<dyn Error>> {
    let config = RegionConfig::new(1, 4);
    let layout = RegionLayout::for_config(config)?;
    let (resources, plugin_socket) = create_test_spawn_resource_pair(layout.region_size)?;
    let plugin_peer = thread::spawn(move || plugin_peer_reject_setup(plugin_socket, false));
    let (child, process_id) = sleeping_test_child()?;

    let error = complete_host_setup_or_reap(child, || {
        complete_qemu_host_plugin_setup(
            resources.into_setup_resources(),
            config,
            0,
            &QemuFaultCapabilityRequirement::abi_boundary_v1(),
        )
    })
    .err()
    .ok_or("non-ready setup acknowledgement unexpectedly reached scheduler admission")?;

    assert!(matches!(
        error,
        QemuLiveNodeStepGateError::HostSetup {
            source: QemuHostPluginSetupError::Control {
                source: ControlLifecycleIoError::SetupCompletion {
                    source: SetupCompletionError::NonZeroSetupAck {
                        status: SETUP_ACK_STATUS_SETUP_FAILED,
                    },
                },
            },
        }
    ));
    assert_child_reaped(process_id)?;
    plugin_peer
        .join()
        .map_err(|_panic| "plugin setup peer panicked")??;

    Ok(())
}

#[test]
fn ram_admission_failure_preserves_original_cause_after_real_child_reap()
-> Result<(), Box<dyn Error>> {
    let (child, process_id) = sleeping_test_child()?;
    let primary = QemuLiveNodeStepGateError::RamAdmission {
        operation: "authenticate independent RAM controller",
        source: crucible_protocol::ram_control::RamControlError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "original descriptor-bound controller reset",
        )),
    };

    let error = reap_failed_live_node_child(child, primary);

    let source = error
        .source()
        .and_then(|source| source.downcast_ref::<crucible_protocol::ram_control::RamControlError>())
        .ok_or("reaping must preserve the typed RAM transport cause")?;
    assert!(matches!(
        source,
        crucible_protocol::ram_control::RamControlError::Io(io)
            if io.kind() == std::io::ErrorKind::ConnectionReset
    ));
    assert_child_reaped(process_id)?;
    Ok(())
}

fn sleeping_test_child() -> Result<(QemuNodeChild, u32), Box<dyn Error>> {
    let child = QemuNodeChild::new(Command::new("sleep").arg("60").spawn()?);
    let process_id = child.process_id();
    Ok((child, process_id))
}

fn assert_child_reaped(process_id: u32) -> Result<(), Box<dyn Error>> {
    if PathBuf::from("/proc").join(process_id.to_string()).exists() {
        return Err(format!("failed setup child {process_id} still exists after cleanup").into());
    }
    Ok(())
}
