//! Qualifies the original FUSE transport in a disposable native guest.
//!
//! The supervisor mounts the actual device opened by this unprivileged actor.
//! Synthetic checked metadata supplies kernel traffic only; it grants no Terrane
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
use terrane_format::{
    tree_builder::Tree,
    tree_format::{
        Attribute, ContentRef, Entry as TreeEntry, EntryKind, ExtendedAttribute, LeafItem, TreeUse,
    },
};
use terrane_linux::{
    fuse_connection::Connection,
    fuse_dispatch::{Limits as MetadataLimits, Metadata, Response},
    fuse_metadata::{CachePolicy, Presentation},
    fuse_protocol::{self, Reply, Request},
    fuse_xattr::Policy as XattrPolicy,
    quota_confinement,
    structural_index::{self, Index, Kind},
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const LIMIT: usize = 262144;
const DEADLINE: Duration = Duration::from_secs(5);

fn main() -> Result {
    let mode = std::env::args().nth(1).ok_or("missing fixture mode")?;
    if !matches!(mode.as_str(), "serve" | "metadata" | "timeout" | "cancel") {
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
        let directory_bytes = metadata_bytes(mode == "metadata")?;
        let directory = Index::open(&directory_bytes)?;
        let mut metadata = Metadata::new(
            directory,
            MetadataLimits {
                namespace_entries: 16,
                namespace_bytes: 4096,
                inodes: 16,
                inode_bytes: 65536,
            },
            CachePolicy::Revalidate,
            if mode == "metadata" {
                XattrPolicy::Recorded
            } else {
                XattrPolicy::Disabled
            },
        )?;

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
        let initialization = fuse_protocol::init::negotiate(
            request,
            fuse_protocol::init::Limits {
                request_bytes: LIMIT,
                readahead_bytes: 65536,
                background_requests: 8,
            },
            fuse_protocol::init::Passthrough::Off,
            false,
        )?;
        if initialization.selected() != Some((40, false)) {
            return Err("actual kernel did not negotiate FUSE 7.40 without passthrough".into());
        }
        send(
            &mut connection,
            &mut output,
            request,
            Some(initialization.body()),
            0,
        )
        .await?;
        notify(b"READY")?;

        if !matches!(mode.as_str(), "serve" | "metadata") {
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
            let mut opened = [0; 16];
            let entry = metadata.entry(request.node());
            let (body, errno) = match metadata.dispatch(
                request,
                |_| Presentation::default(),
                &mut directory_page,
            )? {
                Response::Payload(body) => (Some(body), 0),
                Response::Errno(errno) => (None, errno),
                Response::Unhandled => match (request.opcode(), entry) {
                    (27, Some(entry)) if matches!(entry.kind(), Kind::Directory { .. }) => {
                        opened[..8].copy_from_slice(&request.node().to_ne_bytes());
                        (Some(opened.as_slice()), 0)
                    }
                    (29 | 34, Some(_)) | (38, _) => (Some([].as_slice()), 0),
                    (_, None) => (None, libc::ESTALE),
                    _ => (None, libc::ENOSYS),
                },
            };
            send(&mut connection, &mut output, request, body, errno).await?;
        }
        notify(b"STOPPED")?;
        Ok(())
    })
}

/// Builds synthetic metadata without a repository, content source or exposure.
fn metadata_bytes(populated: bool) -> Result<Vec<u8>> {
    if !populated {
        return Ok(structural_index::compile([7; 32], &[], 1, 4096)?);
    }
    let file = |path: &[u8], link_id| LeafItem {
        key: path.to_vec(),
        entry: TreeEntry {
            kind: EntryKind::File {
                mode: 0o640,
                size: 3,
                content: ContentRef::Inline([2; 32]),
                link_id,
            },
            attrs: vec![
                Attribute {
                    name: "gid",
                    value: &[0x18, 43],
                },
                Attribute {
                    name: "uid",
                    value: &[0x18, 42],
                },
            ],
            attrs_present: true,
            xattrs: vec![
                ExtendedAttribute {
                    name: b"user.\xff",
                    value: b"",
                },
                ExtendedAttribute {
                    name: b"user.note",
                    value: b"raw\0value\xff",
                },
                ExtendedAttribute {
                    name: b"trusted.overlay",
                    value: b"hidden",
                },
                ExtendedAttribute {
                    name: b"security.capability",
                    value: b"hidden",
                },
                ExtendedAttribute {
                    name: b"system.posix_acl_access",
                    value: b"hidden",
                },
            ],
            xattrs_present: true,
            provenance: None,
        },
    };
    let mut directory = file(b"directory", None);
    directory.entry.kind = EntryKind::Directory { mode: 0o750 };
    let mut symlink = file(b"link", None);
    symlink.entry.kind = EntryKind::Symlink {
        target: b"./directory/../a\xff",
    };
    let tree = Tree::build(
        vec![
            file(b"a", Some(b"a")),
            file(b"b", Some(b"a")),
            directory,
            file(b"directory/file", None),
            symlink,
            file(b"\xff", None),
        ],
        None,
        4096,
        TreeUse::Ordinary,
    )?;
    Ok(structural_index::compile_tree(
        &tree,
        &std::collections::BTreeMap::new(),
        16,
        65536,
    )?)
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
