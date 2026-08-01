//! Checks real plugin lifecycle streams as node control channels.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

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

#[cfg(unix)]
use crucible_protocol::{
    ControlLifecycleState, ControlLifecycleStream, HostHandshakeConfig, HostMsg, PluginMsg,
    SETUP_ACK_STATUS_READY, SetupDescriptorFds, control_decode_host_msg, control_encode_plugin_msg,
    read_control_frame,
};
#[cfg(unix)]
use crucible_qemu::QemuPluginIpcControlChannel;

#[cfg(unix)]
#[test]
fn lifecycle_stream_plugin_control_sends_quit_and_advances_state() -> Result<(), Box<dyn Error>> {
    let (host_socket, mut plugin_socket) = UnixStream::pair()?;
    let mut host = running_host_lifecycle_stream(host_socket, &mut plugin_socket)?;

    QemuPluginIpcControlChannel::send_quit(&mut host)?;

    assert_eq!(host.state(), ControlLifecycleState::QuitSent);
    assert_eq!(
        control_decode_host_msg(&read_control_frame(&mut plugin_socket)?)?,
        HostMsg::Quit
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn lifecycle_stream_plugin_control_rejects_quit_before_run() -> Result<(), Box<dyn Error>> {
    let (host_socket, _plugin_socket) = UnixStream::pair()?;
    let mut host = ControlLifecycleStream::connected_unix_stream(host_socket)?;

    let error = match QemuPluginIpcControlChannel::send_quit(&mut host) {
        Ok(()) => panic!("quit before run should fail"),
        Err(error) => error,
    };

    assert_eq!(error.operation, "send plugin control Quit");
    assert_eq!(error.message, "control lifecycle violation");
    assert_eq!(host.state(), ControlLifecycleState::Connected);
    Ok(())
}

#[cfg(unix)]
fn running_host_lifecycle_stream(
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
    let _hello_ack = read_control_frame(peer)?;

    let shmem = File::open("/dev/null")?;
    let wake = File::open("/dev/zero")?;
    host.host_send_setup_with_descriptors(
        4096,
        SetupDescriptorFds {
            shmem_fd: shmem.as_raw_fd(),
            wake_fd: wake.as_raw_fd(),
        },
    )?;
    let _setup = crucible_protocol::recv_setup_with_descriptors(peer.as_raw_fd())?;

    peer.write_all(&control_encode_plugin_msg(&PluginMsg::SetupAck {
        status: SETUP_ACK_STATUS_READY,
    }))?;
    let _setup_ack = host.host_accept_setup_ack()?;
    host.enter_run_via_shared_memory()?;

    Ok(host)
}
