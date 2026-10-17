//! One-exchange, absolute-deadline frames and private same-UID Unix transport.

use std::{
    fs,
    io::{Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt},
        net::UnixStream,
    },
    path::Path,
    time::{Duration, Instant},
};

use crucible_node_contract::canonical;
use serde::{Serialize, de::DeserializeOwned};

use super::{
    MAX_NODE_CONTROL_BYTES, NodeControlError, NodeControlReply, NodeControlRequest, refused,
};

pub(super) const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(3);

pub(super) fn exchange(
    socket: &Path,
    request: &NodeControlRequest,
) -> Result<NodeControlReply, NodeControlError> {
    private_directory(
        socket
            .parent()
            .ok_or_else(|| refused("socket has no private parent"))?,
    )?;
    let metadata = fs::symlink_metadata(socket)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(refused("node control socket is not privately owned"));
    }

    let native = rustix::net::socket_with(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::STREAM,
        rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK,
        None,
    )
    .map_err(std::io::Error::from)?;
    let address = rustix::net::SocketAddrUnix::new(socket).map_err(std::io::Error::from)?;
    rustix::net::connect(&native, &address).map_err(std::io::Error::from)?;
    let mut stream = UnixStream::from(native);
    stream.set_nonblocking(false)?;
    same_uid(&stream)?;

    let deadline = operational_now() + EXCHANGE_TIMEOUT;
    write(&mut stream, request, deadline)?;
    let reply: NodeControlReply = read(&mut stream, deadline)?;
    if reply.format != request.format
        || reply.version != request.version
        || reply.request_id != request.request_id
    {
        return Err(refused(
            "node control reply changed original exchange identity",
        ));
    }
    Ok(reply)
}

pub(super) fn same_uid(stream: &UnixStream) -> Result<(), NodeControlError> {
    let peer = rustix::net::sockopt::socket_peercred(stream).map_err(std::io::Error::from)?;
    if peer.uid != rustix::process::geteuid() {
        return Err(refused("node control peer has a foreign UID"));
    }
    Ok(())
}

pub(super) fn private_directory(path: &Path) -> Result<(), NodeControlError> {
    let metadata = fs::symlink_metadata(path)?;
    if !path.is_absolute()
        || !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(refused(
            "node state/socket parent must be an absolute private owned directory",
        ));
    }
    Ok(())
}

pub(super) fn read<T: DeserializeOwned>(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<T, NodeControlError> {
    let mut header = [0; 4];
    read_exact(stream, &mut header, deadline)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_NODE_CONTROL_BYTES {
        return Err(refused(
            "node control declared frame exceeds finite ceiling",
        ));
    }
    let mut bytes = vec![0; length];
    read_exact(stream, &mut bytes, deadline)?;
    let value = canonical::parse_json(&bytes, MAX_NODE_CONTROL_BYTES)?;
    if canonical::canonical_json(&value)? != bytes {
        return Err(refused("node control frame is not canonical JSON"));
    }
    super::original_lineage::precredit(&value)?;
    serde_json::from_value(value)
        .map_err(crucible_node_contract::ContractError::from)
        .map_err(NodeControlError::from)
}

pub(super) fn write<T: Serialize>(
    stream: &mut UnixStream,
    value: &T,
    deadline: Instant,
) -> Result<(), NodeControlError> {
    let value = serde_json::to_value(value).map_err(crucible_node_contract::ContractError::from)?;
    let bytes = canonical::canonical_json(&value)?;
    if bytes.len() > MAX_NODE_CONTROL_BYTES {
        return Err(refused("node control reply exceeds finite ceiling"));
    }
    write_all(stream, &(bytes.len() as u32).to_be_bytes(), deadline)?;
    write_all(stream, &bytes, deadline)
}

fn read_exact(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> Result<(), NodeControlError> {
    while !bytes.is_empty() {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        let count = stream.read(bytes)?;
        if count == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
        }
        bytes = &mut bytes[count..];
    }
    Ok(())
}

fn write_all(
    stream: &mut UnixStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> Result<(), NodeControlError> {
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        let count = stream.write(bytes)?;
        if count == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into());
        }
        bytes = &bytes[count..];
    }
    Ok(())
}

fn remaining(deadline: Instant) -> Result<Duration, NodeControlError> {
    deadline
        .checked_duration_since(operational_now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::TimedOut).into())
}

// crucible-lint: allow rust-allow -- operational I/O deadlines never enter modeled clocks or canonical identities.
// crucible-lint: allow clippy-disallowed-method -- Real connection deadlines bound host socket waiting and never enter simulation state.
#[allow(clippy::disallowed_methods)]
pub(super) fn operational_now() -> Instant {
    Instant::now()
}
