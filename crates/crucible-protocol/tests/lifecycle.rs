//! Checks the normal control lifecycle and run-phase control-channel silence.

#![forbid(unsafe_code)]

#[cfg(unix)]
use std::error::Error;
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::net::UnixStream;

use crucible_protocol::{
    ControlDirection, ControlLifecycle, ControlLifecycleError, ControlLifecycleEvent,
    ControlLifecycleIoError, ControlLifecycleState, ControlLifecycleStream, ControlTag,
    HandshakeError, HostHandshakeConfig, HostMsg, NORMAL_CONTROL_LIFECYCLE, NegotiatedHandshake,
    PluginHandshakeConfig, PluginMsg, RUNTIME_DATA_PLANE_CONTRACT, RuntimeDataPlane,
    SETUP_ACK_STATUS_READY, SETUP_ACK_STATUS_SETUP_FAILED, control_decode_host_msg,
    control_encode_host_msg, control_encode_plugin_msg, read_control_frame,
    validate_complete_control_lifecycle, validate_control_lifecycle_trace,
};
#[cfg(unix)]
use crucible_protocol::{ReceivedSetup, ReceivedSetupDescriptors, SetupDescriptorFds};

#[test]
fn normal_lifecycle_connects_handshakes_runs_via_shmem_and_quits() {
    assert_eq!(
        validate_complete_control_lifecycle(NORMAL_CONTROL_LIFECYCLE),
        Ok(())
    );
    assert_eq!(
        validate_control_lifecycle_trace(NORMAL_CONTROL_LIFECYCLE),
        Ok(ControlLifecycleState::QuitSent)
    );
    assert_eq!(
        RUNTIME_DATA_PLANE_CONTRACT.runtime_data_plane,
        RuntimeDataPlane::SharedMemory
    );
    const {
        assert!(RUNTIME_DATA_PLANE_CONTRACT.control_channel_silent_between_setup_ack_and_quit);
    }
}

#[test]
fn lifecycle_events_are_derived_from_decoded_control_messages() {
    assert_eq!(
        ControlLifecycleEvent::from_plugin_msg(&PluginMsg::Hello {
            proto_version: 1,
            abi_version: 1,
        }),
        ControlLifecycleEvent::PluginHello
    );
    assert_eq!(
        ControlLifecycleEvent::from_plugin_msg(&PluginMsg::SetupAck {
            status: SETUP_ACK_STATUS_READY,
        }),
        ControlLifecycleEvent::PluginSetupAck {
            status: SETUP_ACK_STATUS_READY,
        }
    );
    assert_eq!(
        ControlLifecycleEvent::from_host_msg(&HostMsg::HelloAck {
            proto_version: 1,
            abi_version: 1,
            slot_index: 0,
            node_count: 2,
        }),
        ControlLifecycleEvent::HostHelloAck
    );
    assert_eq!(
        ControlLifecycleEvent::from_host_msg(&HostMsg::Setup { region_len: 4096 }),
        ControlLifecycleEvent::HostSetup
    );
    assert_eq!(
        ControlLifecycleEvent::from_host_msg(&HostMsg::Quit),
        ControlLifecycleEvent::HostQuit
    );
}

#[cfg(unix)]
#[test]
fn lifecycle_stream_wires_real_frames_setup_descriptors_and_run_silence()
-> Result<(), Box<dyn Error>> {
    let (host_socket, mut plugin_socket) = UnixStream::pair()?;
    let mut host = ControlLifecycleStream::connected_unix_stream(host_socket)?;

    plugin_socket.write_all(&control_encode_plugin_msg(&PluginMsg::Hello {
        proto_version: 1,
        abi_version: 1,
    }))?;
    assert_eq!(
        host.host_accept_handshake(HostHandshakeConfig {
            proto_version: 1,
            abi_version: 1,
            slot_index: 0,
            node_count: 1,
        })?,
        NegotiatedHandshake {
            proto_version: 1,
            abi_version: 1,
            slot_index: 0,
            node_count: 1,
        }
    );
    assert_eq!(host.state(), ControlLifecycleState::HelloAcknowledged);
    assert!(matches!(
        control_decode_host_msg(&read_control_frame(&mut plugin_socket)?)?,
        HostMsg::HelloAck { .. }
    ));

    let shmem = File::open("/dev/null")?;
    let wake = File::open("/dev/zero")?;
    host.host_send_setup_with_descriptors(
        4096,
        SetupDescriptorFds {
            shmem_fd: shmem.as_raw_fd(),
            wake_fd: wake.as_raw_fd(),
        },
    )?;
    let ReceivedSetup {
        region_len,
        descriptors: ReceivedSetupDescriptors { .. },
    } = crucible_protocol::recv_setup_with_descriptors(plugin_socket.as_raw_fd())?;
    assert_eq!(region_len, 4096);
    assert_eq!(host.state(), ControlLifecycleState::SetupSent);

    plugin_socket.write_all(&control_encode_plugin_msg(&PluginMsg::SetupAck {
        status: SETUP_ACK_STATUS_READY,
    }))?;
    let setup = host.host_accept_setup_ack()?;
    assert!(setup.can_schedule());
    assert_eq!(host.state(), ControlLifecycleState::SetupAcknowledged);

    host.enter_run_via_shared_memory()?;
    assert_eq!(host.state(), ControlLifecycleState::RunningViaSharedMemory);

    plugin_socket.write_all(&control_encode_plugin_msg(&PluginMsg::Hello {
        proto_version: 1,
        abi_version: 1,
    }))?;
    assert_eq!(
        host.host_read_run_control_frame(),
        Err(ControlLifecycleIoError::Lifecycle {
            source: ControlLifecycleError::ControlFrameDuringRun {
                tag: ControlTag::Hello,
                direction: ControlDirection::PluginToHost,
            },
        })
    );
    assert_eq!(host.state(), ControlLifecycleState::RunningViaSharedMemory);

    host.host_send_quit()?;
    assert_eq!(
        control_decode_host_msg(&read_control_frame(&mut plugin_socket)?)?,
        HostMsg::Quit
    );
    assert_eq!(host.state(), ControlLifecycleState::QuitSent);

    Ok(())
}

#[cfg(unix)]
#[test]
fn lifecycle_stream_does_not_advance_after_invalid_hello_ack() -> Result<(), Box<dyn Error>> {
    let (mut host_socket, plugin_socket) = UnixStream::pair()?;
    let mut plugin = ControlLifecycleStream::connected_unix_stream(plugin_socket)?;

    host_socket.write_all(&control_encode_host_msg(&HostMsg::HelloAck {
        proto_version: 1,
        abi_version: 2,
        slot_index: 0,
        node_count: 1,
    }))?;

    assert_eq!(
        plugin.plugin_start_handshake(PluginHandshakeConfig {
            proto_version: 1,
            abi_version: 1,
        }),
        Err(ControlLifecycleIoError::Handshake {
            source: HandshakeError::AbiMismatch {
                plugin_abi: 1,
                host_abi: 2,
            },
        })
    );
    assert_eq!(plugin.state(), ControlLifecycleState::HelloSent);

    assert_eq!(
        plugin.plugin_recv_setup_with_descriptors().err(),
        Some(ControlLifecycleIoError::Lifecycle {
            source: ControlLifecycleError::UnexpectedEvent {
                state: ControlLifecycleState::HelloSent,
                event: ControlLifecycleEvent::HostSetup,
            },
        })
    );

    Ok(())
}

#[cfg(unix)]
#[test]
fn plugin_setup_io_is_bounded_to_setup_and_rejected_during_run() -> Result<(), Box<dyn Error>> {
    let (peer_socket, plugin_socket) = UnixStream::pair()?;
    let mut connected = ControlLifecycleStream::connected_unix_stream(plugin_socket)?;
    assert!(matches!(
        connected.plugin_setup_io_mut(),
        Err(ControlLifecycleIoError::Lifecycle {
            source: ControlLifecycleError::UnexpectedEvent {
                state: ControlLifecycleState::Connected,
                event: ControlLifecycleEvent::HostSetup,
            },
        })
    ));
    drop(peer_socket);

    let (mut peer_socket, plugin_socket) = UnixStream::pair()?;
    let mut setup = plugin_setup_lifecycle_stream(plugin_socket, &mut peer_socket)?;
    setup.plugin_setup_io_mut()?.write_all(&[])?;
    setup.plugin_send_ready_setup_ack()?;
    let _ = read_control_frame(&mut peer_socket)?;
    setup.enter_run_via_shared_memory()?;
    assert!(matches!(
        setup.plugin_setup_io_mut(),
        Err(ControlLifecycleIoError::Lifecycle {
            source: ControlLifecycleError::UnexpectedEvent {
                state: ControlLifecycleState::RunningViaSharedMemory,
                event: ControlLifecycleEvent::HostSetup,
            },
        })
    ));
    Ok(())
}

#[cfg(unix)]
#[test]
fn plugin_ready_commit_records_exact_setup_transition() -> Result<(), Box<dyn Error>> {
    let (mut peer_socket, plugin_socket) = UnixStream::pair()?;
    let mut plugin = plugin_setup_lifecycle_stream(plugin_socket, &mut peer_socket)?;

    plugin
        .plugin_setup_io_mut()?
        .write_all(&control_encode_plugin_msg(&PluginMsg::SetupAck {
            status: SETUP_ACK_STATUS_READY,
        }))?;
    plugin.plugin_commit_ready_setup_ack()?;
    assert_eq!(plugin.state(), ControlLifecycleState::SetupAcknowledged);
    assert!(plugin.plugin_commit_ready_setup_ack().is_err());
    plugin.enter_run_via_shared_memory()?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn plugin_failure_ack_writes_nonready_bytes_without_entering_run() -> Result<(), Box<dyn Error>> {
    let (mut peer_socket, plugin_socket) = UnixStream::pair()?;
    let mut plugin = plugin_setup_lifecycle_stream(plugin_socket, &mut peer_socket)?;

    plugin.plugin_send_setup_failure_ack()?;
    assert_eq!(
        crucible_protocol::control_decode_plugin_msg(&read_control_frame(&mut peer_socket)?)?,
        PluginMsg::SetupAck {
            status: SETUP_ACK_STATUS_SETUP_FAILED,
        }
    );
    assert_eq!(plugin.state(), ControlLifecycleState::SetupSent);
    assert!(plugin.enter_run_via_shared_memory().is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn lifecycle_stream_splits_host_faults_from_plugin_quit_acceptance() -> Result<(), Box<dyn Error>> {
    let (mut peer_socket, host_socket) = UnixStream::pair()?;
    let mut host = host_running_lifecycle_stream(host_socket, &mut peer_socket)?;

    peer_socket.write_all(&control_encode_host_msg(&HostMsg::Quit))?;
    assert_eq!(
        host.host_read_run_control_frame(),
        Err(ControlLifecycleIoError::Lifecycle {
            source: ControlLifecycleError::ControlFrameDuringRun {
                tag: ControlTag::Quit,
                direction: ControlDirection::HostToPlugin,
            },
        })
    );
    assert_eq!(host.state(), ControlLifecycleState::RunningViaSharedMemory);

    let (mut host_socket, plugin_socket) = UnixStream::pair()?;
    let mut plugin = plugin_running_lifecycle_stream(plugin_socket, &mut host_socket)?;

    host_socket.write_all(&control_encode_host_msg(&HostMsg::Quit))?;
    assert_eq!(
        plugin.plugin_read_run_control_frame(),
        Ok(ControlLifecycleState::QuitSent)
    );
    assert_eq!(plugin.state(), ControlLifecycleState::QuitSent);

    Ok(())
}

#[test]
fn run_phase_accepts_only_shmem_until_quit() {
    let mut lifecycle = ControlLifecycle::new();
    for event in [
        ControlLifecycleEvent::ConnectUnixStreamSocketPair,
        ControlLifecycleEvent::PluginHello,
        ControlLifecycleEvent::HostHelloAck,
        ControlLifecycleEvent::HostSetup,
        ControlLifecycleEvent::PluginSetupAck {
            status: SETUP_ACK_STATUS_READY,
        },
        ControlLifecycleEvent::RunViaSharedMemory,
    ] {
        assert!(lifecycle.observe(event).is_ok());
    }

    assert_eq!(
        lifecycle.observe(ControlLifecycleEvent::RunViaSharedMemory),
        Ok(ControlLifecycleState::RunningViaSharedMemory)
    );

    for (event, tag) in [
        (ControlLifecycleEvent::PluginHello, ControlTag::Hello),
        (ControlLifecycleEvent::HostHelloAck, ControlTag::HelloAck),
        (ControlLifecycleEvent::HostSetup, ControlTag::Setup),
        (
            ControlLifecycleEvent::PluginSetupAck {
                status: SETUP_ACK_STATUS_READY,
            },
            ControlTag::SetupAck,
        ),
    ] {
        assert_eq!(
            lifecycle.observe(event),
            Err(ControlLifecycleError::ControlFrameDuringRun {
                tag,
                direction: tag.direction(),
            })
        );
        assert_eq!(
            lifecycle.state(),
            ControlLifecycleState::RunningViaSharedMemory
        );
    }

    assert_eq!(
        lifecycle.observe(ControlLifecycleEvent::HostQuit),
        Ok(ControlLifecycleState::QuitSent)
    );
}

#[test]
fn lifecycle_rejects_non_ready_setup_ack_before_run() {
    assert_eq!(
        validate_control_lifecycle_trace([
            ControlLifecycleEvent::ConnectUnixStreamSocketPair,
            ControlLifecycleEvent::PluginHello,
            ControlLifecycleEvent::HostHelloAck,
            ControlLifecycleEvent::HostSetup,
            ControlLifecycleEvent::PluginSetupAck { status: 7 },
        ]),
        Err(ControlLifecycleError::NonReadySetupAck { status: 7 })
    );
}

#[test]
fn lifecycle_rejects_out_of_order_and_incomplete_traces() {
    assert_eq!(
        validate_control_lifecycle_trace([
            ControlLifecycleEvent::ConnectUnixStreamSocketPair,
            ControlLifecycleEvent::HostSetup,
        ]),
        Err(ControlLifecycleError::UnexpectedEvent {
            state: ControlLifecycleState::Connected,
            event: ControlLifecycleEvent::HostSetup,
        })
    );
    assert_eq!(
        validate_control_lifecycle_trace([
            ControlLifecycleEvent::ConnectUnixStreamSocketPair,
            ControlLifecycleEvent::PluginHello,
            ControlLifecycleEvent::HostHelloAck,
            ControlLifecycleEvent::HostSetup,
            ControlLifecycleEvent::PluginSetupAck {
                status: SETUP_ACK_STATUS_READY,
            },
            ControlLifecycleEvent::HostQuit,
        ]),
        Err(ControlLifecycleError::UnexpectedEvent {
            state: ControlLifecycleState::SetupAcknowledged,
            event: ControlLifecycleEvent::HostQuit,
        })
    );
    assert_eq!(
        validate_complete_control_lifecycle([
            ControlLifecycleEvent::ConnectUnixStreamSocketPair,
            ControlLifecycleEvent::PluginHello,
            ControlLifecycleEvent::HostHelloAck,
            ControlLifecycleEvent::HostSetup,
            ControlLifecycleEvent::PluginSetupAck {
                status: SETUP_ACK_STATUS_READY,
            },
        ]),
        Err(ControlLifecycleError::IncompleteLifecycle {
            state: ControlLifecycleState::SetupAcknowledged,
        })
    );
}

#[test]
fn lifecycle_control_tags_preserve_registered_direction() {
    assert_eq!(
        ControlLifecycleEvent::PluginHello.control_tag(),
        Some(ControlTag::Hello)
    );
    assert_eq!(
        ControlLifecycleEvent::HostQuit.control_tag(),
        Some(ControlTag::Quit)
    );
    assert_eq!(
        ControlLifecycleEvent::RunViaSharedMemory.control_tag(),
        None
    );
    assert_eq!(
        ControlTag::Hello.direction(),
        ControlDirection::PluginToHost
    );
    assert_eq!(ControlTag::Quit.direction(), ControlDirection::HostToPlugin);
}

#[cfg(unix)]
fn host_running_lifecycle_stream(
    stream: UnixStream,
    peer: &mut UnixStream,
) -> Result<ControlLifecycleStream<UnixStream>, Box<dyn Error>> {
    let mut host = ControlLifecycleStream::connected_unix_stream(stream)?;

    peer.write_all(&control_encode_plugin_msg(&PluginMsg::Hello {
        proto_version: 1,
        abi_version: 1,
    }))?;
    host.host_accept_handshake(HostHandshakeConfig {
        proto_version: 1,
        abi_version: 1,
        slot_index: 0,
        node_count: 1,
    })?;
    let _ = read_control_frame(peer)?;

    let shmem = File::open("/dev/null")?;
    let wake = File::open("/dev/zero")?;
    host.host_send_setup_with_descriptors(
        4096,
        SetupDescriptorFds {
            shmem_fd: shmem.as_raw_fd(),
            wake_fd: wake.as_raw_fd(),
        },
    )?;
    let _ = crucible_protocol::recv_setup_with_descriptors(peer.as_raw_fd())?;

    peer.write_all(&control_encode_plugin_msg(&PluginMsg::SetupAck {
        status: SETUP_ACK_STATUS_READY,
    }))?;
    let _ = host.host_accept_setup_ack()?;
    host.enter_run_via_shared_memory()?;

    Ok(host)
}

#[cfg(unix)]
fn plugin_running_lifecycle_stream(
    stream: UnixStream,
    peer: &mut UnixStream,
) -> Result<ControlLifecycleStream<UnixStream>, Box<dyn Error>> {
    let mut plugin = plugin_setup_lifecycle_stream(stream, peer)?;

    plugin.plugin_send_ready_setup_ack()?;
    let _ = read_control_frame(peer)?;
    plugin.enter_run_via_shared_memory()?;

    Ok(plugin)
}

#[cfg(unix)]
fn plugin_setup_lifecycle_stream(
    stream: UnixStream,
    peer: &mut UnixStream,
) -> Result<ControlLifecycleStream<UnixStream>, Box<dyn Error>> {
    let mut plugin = ControlLifecycleStream::connected_unix_stream(stream)?;

    peer.write_all(&control_encode_host_msg(&HostMsg::HelloAck {
        proto_version: 1,
        abi_version: 1,
        slot_index: 0,
        node_count: 1,
    }))?;
    plugin.plugin_start_handshake(PluginHandshakeConfig {
        proto_version: 1,
        abi_version: 1,
    })?;
    let _ = read_control_frame(peer)?;

    let shmem = File::open("/dev/null")?;
    let wake = File::open("/dev/zero")?;
    crucible_protocol::send_setup_with_descriptors(
        peer.as_raw_fd(),
        4096,
        SetupDescriptorFds {
            shmem_fd: shmem.as_raw_fd(),
            wake_fd: wake.as_raw_fd(),
        },
    )?;
    let _ = plugin.plugin_recv_setup_with_descriptors()?;

    Ok(plugin)
}
