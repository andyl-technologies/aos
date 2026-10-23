//! Qualifies the original FUSE transport in a disposable native guest.
//!
//! The supervisor mounts the actual device opened by this unprivileged actor.
//! A minimal empty directory supplies kernel traffic only; it grants no Terrane
//! repository, exposure, backing or production mount-broker authority.

use rustix::net::{self, SendAncillaryBuffer, SendAncillaryMessage};
use std::{
    fs::OpenOptions,
    io::{self, IoSlice},
    mem::MaybeUninit,
    num::NonZeroU64,
    os::{fd::AsFd, unix::fs::OpenOptionsExt},
    sync::Arc,
    time::Duration,
};
use terrane_linux::{
    fuse_connection::Connection,
    fuse_directory,
    fuse_protocol::{self, Reply, Request},
    inode_policy::InodeTable,
    quota_confinement,
    structural_index::{self, Index},
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const LIMIT: usize = 262144;
const DEADLINE: Duration = Duration::from_secs(5);

fn main() -> Result {
    let mode = std::env::args().nth(1).ok_or("missing fixture mode")?;
    if !matches!(mode.as_str(), "serve" | "timeout" | "cancel") {
        return Err("invalid fixture mode".into());
    }

    // The fresh worker opens its own device before confinement. The supervisor
    // receives a mount-only alias and closes it before sending the ready byte.
    let device = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open("/dev/fuse")?;
    let rights = [device.as_fd()];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !ancillary.push(SendAncillaryMessage::ScmRights(&rights))
        || net::sendmsg(
            io::stdout().as_fd(),
            &[IoSlice::new(b"DEVICE")],
            &mut ancillary,
            net::SendFlags::NOSIGNAL,
        )? != 6
    {
        return Err("cannot transfer original mount alias".into());
    }
    let mut ready = [0; 1];
    if rustix::io::read(io::stdout(), &mut ready)? != 1 || ready != *b"M" {
        return Err("supervisor did not mount and close its device alias".into());
    }
    let flags = rustix::fs::fcntl_getfl(io::stdout())?;
    rustix::fs::fcntl_setfl(io::stdout(), flags | rustix::fs::OFlags::NONBLOCK)?;

    let confinement = Arc::new(quota_confinement::install_worker_network(device.as_fd())?);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let mut connection = Connection::new(device.into(), confinement, LIMIT, LIMIT)?;
        let control = tokio::io::unix::AsyncFd::new(io::stdout())?;
        let mut input = vec![0; LIMIT];
        let mut output = vec![0; LIMIT];
        let mut directory_page = vec![0; LIMIT - 16];
        // This empty metadata fixture is not an authenticated repository view.
        // It exercises the production encoder against actual kernel READDIR.
        let directory_bytes = structural_index::compile([7; 32], &[], 1, 4096)?;
        let directory = Index::open(&directory_bytes)?;
        let mut inodes = InodeTable::with_reserved_capacity(1, 4096)?;
        let root = directory.lookup(b"").ok_or("empty index lost root")?;
        let root_inode = u64::from(inodes.touch_entry(root)?.1.number());

        // Invalid arguments must fail before accepting or consuming real INIT.
        let error = connection
            .receive(&mut input, Duration::ZERO)
            .await
            .err()
            .ok_or("zero deadline unexpectedly accepted")?;
        if error.kind() != io::ErrorKind::InvalidInput {
            return Err("invalid deadline unexpectedly closed original device".into());
        }
        let request = connection.receive(&mut input, DEADLINE).await?;
        if request.opcode() != 26 || request.body_u32(0)? != 7 || request.body_u32(4)? < 40 {
            return Err("actual kernel did not negotiate FUSE 7.40".into());
        }
        let mut initialization = [0; 64];
        initialization[..4].copy_from_slice(&7_u32.to_ne_bytes());
        initialization[4..8].copy_from_slice(&40_u32.to_ne_bytes());
        initialization[16..18].copy_from_slice(&8_u16.to_ne_bytes());
        initialization[18..20].copy_from_slice(&4_u16.to_ne_bytes());
        initialization[20..24].copy_from_slice(&131072_u32.to_ne_bytes());
        initialization[24..28].copy_from_slice(&1_u32.to_ne_bytes());
        send(
            &mut connection,
            &mut output,
            request,
            Some(&initialization),
            0,
        )
        .await?;
        notify(b"READY")?;

        if mode != "serve" {
            if mode == "timeout" {
                let error = connection
                    .receive(&mut input, Duration::from_millis(100))
                    .await
                    .err()
                    .ok_or("idle original kernel connection did not time out")?;
                if error.kind() != io::ErrorKind::TimedOut {
                    return Err(format!("unexpected idle receive failure: {error}").into());
                }
            } else if tokio::time::timeout(
                Duration::from_millis(100),
                connection.receive(&mut input, DEADLINE),
            )
            .await
            .is_ok()
            {
                return Err("idle original kernel receive was not cancelled".into());
            }
            if connection
                .receive(&mut input, DEADLINE)
                .await
                .err()
                .is_none_or(|error| error.kind() != io::ErrorKind::BrokenPipe)
            {
                return Err("failed original connection remained reusable".into());
            }
            notify(b"CLOSED")?;
            return Ok(());
        }

        loop {
            let received = tokio::select! {
                result = connection.receive(&mut input, DEADLINE) => result,
                result = stopped(&control) => {
                    result?;
                    drop(connection);
                    notify(b"STOPPED")?;
                    return Ok(());
                }
            };
            let request = match received {
                Ok(request) => request,
                Err(error) if error.raw_os_error() == Some(libc::ENODEV) => {
                    stopped(&control).await?;
                    break;
                }
                Err(error) => return Err(error.into()),
            };
            // FORGET and BATCH_FORGET never receive replies, even for nonzero IDs.
            if matches!(request.opcode(), 2 | 42) {
                continue;
            }
            let mut attributes = [0; 104];
            let mut opened = [0; 16];
            let (body, errno) = match (request.opcode(), request.node()) {
                (3, 1) => {
                    // attr_out's validity header precedes the 88-byte fuse_attr.
                    attributes[16..24].copy_from_slice(&root_inode.to_ne_bytes());
                    attributes[76..80].copy_from_slice(&(libc::S_IFDIR | 0o555).to_ne_bytes());
                    attributes[80..84].copy_from_slice(&2_u32.to_ne_bytes());
                    attributes[96..100].copy_from_slice(&4096_u32.to_ne_bytes());
                    (Some(attributes.as_slice()), 0)
                }
                (27, 1) => {
                    opened[..8].copy_from_slice(&1_u64.to_ne_bytes());
                    (Some(opened.as_slice()), 0)
                }
                (28, 1) => {
                    if request.body().len() != 40 {
                        return Err("actual READDIR body has unexpected length".into());
                    }
                    let cookie = request.body_u64(8)?;
                    let requested = request.body_u32(16)? as usize;
                    let capacity = requested.min(directory_page.len());
                    let length = fuse_directory::read(
                        directory,
                        b"",
                        cookie,
                        &mut inodes,
                        &mut directory_page[..capacity],
                    )?;
                    (Some(&directory_page[..length]), 0)
                }
                (29 | 34, 1) | (38, _) => (Some([].as_slice()), 0),
                (1, _) => (None, libc::ENOENT),
                _ => (None, libc::ENOSYS),
            };
            send(&mut connection, &mut output, request, body, errno).await?;
        }
        notify(b"STOPPED")?;
        Ok(())
    })
}

async fn send(
    connection: &mut Connection,
    output: &mut [u8],
    request: Request<'_>,
    body: Option<&[u8]>,
    errno: i32,
) -> Result {
    let unique = NonZeroU64::new(request.unique()).ok_or("reply request has zero identifier")?;
    let bytes = match body {
        Some(body) => fuse_protocol::reply(output, unique, body)?,
        None => fuse_protocol::error_reply(output, unique, errno)?,
    };
    connection
        .send(Reply::parse(bytes, LIMIT)?, DEADLINE)
        .await?;
    Ok(())
}

fn notify(message: &[u8]) -> Result {
    if rustix::io::write(io::stdout(), message)? != message.len() {
        return Err("fixture supervisor message was truncated".into());
    }
    Ok(())
}

/// Waits for the supervisor's explicit acknowledgement of completed unmount.
async fn stopped(control: &tokio::io::unix::AsyncFd<io::Stdout>) -> io::Result<()> {
    let mut message = [0; 1];
    loop {
        let mut readiness = control.readable().await?;
        match readiness.try_io(|control| {
            rustix::io::read(control.get_ref(), &mut message).map_err(io::Error::from)
        }) {
            Ok(Ok(1)) if message == *b"U" => return Ok(()),
            Ok(Ok(_)) => return Err(io::ErrorKind::InvalidData.into()),
            Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
            Ok(Err(error)) => return Err(error),
            Err(_) => continue,
        }
    }
}
