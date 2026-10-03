//! Root-controller-only fixture transport with per-packet kernel credentials.

use std::io::{IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use aos_sandbox_network::NetworkNamespaceStoreName;
use rustix::fs::{Mode, OFlags};
use rustix::net::sockopt::{Timeout, set_socket_passcred, set_socket_timeout};
use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
    SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketAddrUnix, SocketFlags, SocketType,
    accept_with, bind, connect, listen, recv, recvmsg, send, sendmsg, socket_with,
};

const MAXIMUM_COMMAND_BYTES: usize = 256;
const MAXIMUM_RESPONSE_BYTES: usize = 1_024;
const MAXIMUM_CONTROL_DESCRIPTORS: usize = 2;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

/// Owns the fixed test-only control listener.
pub(crate) struct ControlListener {
    descriptor: OwnedFd,
}

impl ControlListener {
    /// Binds one root-only Unix sequence-packet endpoint.
    pub(crate) fn bind(path: &Path) -> Result<Self> {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("remove stale fixture control socket"),
        }

        let descriptor = socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .context("create fixture control socket")?;
        set_socket_passcred(&descriptor, true).context("enable control packet credentials")?;
        bind(
            &descriptor,
            &SocketAddrUnix::new(path).context("encode fixture control socket path")?,
        )
        .context("bind fixture control socket")?;
        rustix::fs::chmod(path, Mode::RUSR | Mode::WUSR)
            .context("restrict fixture control socket")?;
        listen(&descriptor, 4).context("listen on fixture control socket")?;
        Ok(Self { descriptor })
    }

    /// Accepts one close-on-exec root controller connection.
    pub(crate) fn accept(&self) -> Result<ControlConnection> {
        let descriptor = accept_with(&self.descriptor, SocketFlags::CLOEXEC)
            .context("accept fixture control connection")?;
        set_socket_timeout(&descriptor, Timeout::Recv, Some(CONTROL_TIMEOUT))
            .context("set fixture control receive timeout")?;
        set_socket_timeout(&descriptor, Timeout::Send, Some(CONTROL_TIMEOUT))
            .context("set fixture control send timeout")?;
        Ok(ControlConnection { descriptor })
    }
}

/// Owns one accepted, single-command fixture connection.
pub(crate) struct ControlConnection {
    descriptor: OwnedFd,
}

impl ControlConnection {
    /// Receives one bounded, root-authenticated fixed command.
    pub(crate) fn receive(&self) -> Result<ControlCommand> {
        let mut payload = [0_u8; MAXIMUM_COMMAND_BYTES];
        let mut iov = [IoSliceMut::new(&mut payload)];
        let mut control_space = [MaybeUninit::uninit();
            rustix::cmsg_space!(ScmRights(MAXIMUM_CONTROL_DESCRIPTORS), ScmCredentials(1))];
        let mut control = RecvAncillaryBuffer::new(&mut control_space);
        let message = recvmsg(
            &self.descriptor,
            &mut iov,
            &mut control,
            RecvFlags::TRUNC | RecvFlags::CMSG_CLOEXEC,
        )
        .context("receive fixture control command")?;
        if message.bytes == 0 {
            bail!("empty control command");
        }
        if message.bytes > payload.len()
            || message
                .flags
                .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        {
            bail!("truncated control command or ancillary table");
        }

        let mut credentials = None;
        let mut descriptors = Vec::new();
        for ancillary in control.drain() {
            match ancillary {
                RecvAncillaryMessage::ScmCredentials(received) if credentials.is_none() => {
                    credentials = Some(received);
                }
                RecvAncillaryMessage::ScmRights(received) => descriptors.extend(received),
                _ => bail!("duplicate or unsupported control ancillary message"),
            }
        }
        let credentials = credentials.context("control command omitted kernel credentials")?;
        if !credentials.uid.is_root() || !credentials.gid.is_root() {
            bail!("control command is not from root:root");
        }
        if descriptors.len() > MAXIMUM_CONTROL_DESCRIPTORS {
            bail!("control command exceeds the descriptor bound");
        }

        let command = std::str::from_utf8(&payload[..message.bytes])
            .context("control command is not UTF-8")?;
        parse_command(command, descriptors)
    }

    /// Returns one bounded response without descriptors.
    pub(crate) fn respond(&self, response: &[u8]) -> Result<()> {
        if response.is_empty() || response.len() > MAXIMUM_RESPONSE_BYTES {
            bail!("fixture control response is outside its bound");
        }
        let written = send(&self.descriptor, response, SendFlags::NOSIGNAL)
            .context("send fixture control response")?;
        if written != response.len() {
            bail!("fixture control response was partially written");
        }
        Ok(())
    }
}

/// Names one closed fixture action and its exact descriptor ownership.
pub(crate) enum ControlCommand {
    Ping,
    Store {
        name: NetworkNamespaceStoreName,
        descriptor: OwnedFd,
    },
    Remove {
        name: NetworkNamespaceStoreName,
    },
    CapacityProbe {
        first_name: NetworkNamespaceStoreName,
        first_descriptor: OwnedFd,
        second_name: NetworkNamespaceStoreName,
        second_descriptor: OwnedFd,
    },
}

fn parse_command(command: &str, mut descriptors: Vec<OwnedFd>) -> Result<ControlCommand> {
    if command == "PING" {
        require_descriptor_count(&descriptors, 0)?;
        return Ok(ControlCommand::Ping);
    }
    if let Some(value) = command.strip_prefix("STORE ") {
        require_descriptor_count(&descriptors, 1)?;
        let name = NetworkNamespaceStoreName::parse(value).context("invalid STORE name")?;
        let descriptor = descriptors
            .pop()
            .context("validated STORE descriptor disappeared")?;
        return Ok(ControlCommand::Store { name, descriptor });
    }
    if let Some(value) = command.strip_prefix("REMOVE ") {
        require_descriptor_count(&descriptors, 0)?;
        let name = NetworkNamespaceStoreName::parse(value).context("invalid REMOVE name")?;
        return Ok(ControlCommand::Remove { name });
    }
    if let Some(value) = command.strip_prefix("CAPACITY ") {
        require_descriptor_count(&descriptors, 2)?;
        let (first, second) = value
            .split_once(' ')
            .context("CAPACITY requires exactly two names")?;
        if second.contains(' ') {
            bail!("CAPACITY requires exactly two names");
        }
        let first_name =
            NetworkNamespaceStoreName::parse(first).context("invalid first CAPACITY name")?;
        let second_name =
            NetworkNamespaceStoreName::parse(second).context("invalid second CAPACITY name")?;
        let second_descriptor = descriptors
            .pop()
            .context("validated second CAPACITY descriptor disappeared")?;
        let first_descriptor = descriptors
            .pop()
            .context("validated first CAPACITY descriptor disappeared")?;
        return Ok(ControlCommand::CapacityProbe {
            first_name,
            first_descriptor,
            second_name,
            second_descriptor,
        });
    }
    bail!("control command is outside the closed language")
}

fn require_descriptor_count(descriptors: &[OwnedFd], expected: usize) -> Result<()> {
    if descriptors.len() != expected {
        bail!(
            "control command descriptor count is {}, expected {expected}",
            descriptors.len()
        );
    }
    Ok(())
}

/// Sends one raw command and the requested descriptor paths from the controller.
pub(crate) fn send_control_command(
    socket_path: &Path,
    command: &str,
    descriptor_paths: &[PathBuf],
) -> Result<String> {
    if descriptor_paths.len() > MAXIMUM_CONTROL_DESCRIPTORS {
        bail!("client descriptor count exceeds the fixed bound");
    }
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .context("create fixture client socket")?;
    connect(
        &socket,
        &SocketAddrUnix::new(socket_path).context("encode fixture control address")?,
    )
    .context("connect to fixture control socket")?;
    let descriptors = descriptor_paths
        .iter()
        .map(|path| {
            rustix::fs::open(path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
                .with_context(|| format!("open descriptor path {}", path.display()))
        })
        .collect::<Result<Vec<_>>>()?;
    send_command(socket.as_fd(), command.as_bytes(), &descriptors)?;

    let mut response = [0_u8; MAXIMUM_RESPONSE_BYTES];
    let (received, _) = recv(&socket, &mut response, RecvFlags::TRUNC)
        .context("receive fixture control response")?;
    if received == 0 || received > response.len() {
        bail!("fixture control response is empty or truncated");
    }
    String::from_utf8(response[..received].to_vec()).context("fixture response is not UTF-8")
}

fn send_command(socket: BorrowedFd<'_>, payload: &[u8], descriptors: &[OwnedFd]) -> Result<()> {
    let iov = [IoSlice::new(payload)];
    let borrowed = descriptors.iter().map(|fd| fd.as_fd()).collect::<Vec<_>>();
    let mut control_space =
        [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAXIMUM_CONTROL_DESCRIPTORS))];
    let mut control = SendAncillaryBuffer::new(&mut control_space);
    if !borrowed.is_empty() && !control.push(SendAncillaryMessage::ScmRights(&borrowed)) {
        bail!("fixture client ancillary buffer is exhausted");
    }
    let written = sendmsg(socket, &iov, &mut control, SendFlags::NOSIGNAL)
        .context("send fixture control command")?;
    if written != payload.len() {
        bail!("fixture control command was partially written");
    }
    Ok(())
}
