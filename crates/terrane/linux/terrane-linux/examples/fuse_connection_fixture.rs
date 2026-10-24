//! Qualifies the original FUSE transport in a disposable native guest.
//!
//! The supervisor mounts the actual device opened by this unprivileged actor.
//! Synthetic checked metadata supplies kernel traffic only; it grants no Terrane
//! repository, exposure, backing or production mount-broker authority.

use rustix::net::{self, SendAncillaryBuffer, SendAncillaryMessage};
use std::{
    fs::OpenOptions,
    future::{Future, pending},
    io::{self, IoSlice},
    mem::MaybeUninit,
    num::NonZeroU64,
    os::{fd::AsFd, unix::fs::OpenOptionsExt},
    pin::Pin,
    sync::Arc,
    time::Duration,
};
use terrane_format::{
    identity::{IdentityKind, TERRANE_V1},
    tree_builder::Tree,
    tree_format::{
        Attribute, ContentRef, Entry as TreeEntry, EntryKind, ExtendedAttribute, LeafItem, TreeUse,
    },
};
use terrane_linux::{
    fuse_connection::Connection,
    fuse_dispatch::{Limits as MetadataLimits, Metadata, Response},
    fuse_lifetime::{self, Kind as HandleKind},
    fuse_metadata::{CachePolicy, Presentation},
    fuse_open::{self, Enqueued, Outcome, Ticket},
    fuse_protocol::{self, Reply, Request},
    fuse_read::{self, Backing as FallbackBacking},
    fuse_xattr::Policy as XattrPolicy,
    quota_confinement,
    structural_index::{self, Index, Kind},
    worker_channel::{BackingReply, ExposureContext, RequestedBacking, WorkerClient},
};

type Fetch = Pin<Box<dyn Future<Output = (Ticket, WorkerClient, io::Result<BackingReply>, u64)>>>;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const LIMIT: usize = 262144;
const DEADLINE: Duration = Duration::from_secs(5);

fn main() -> Result {
    let mode = std::env::args().nth(1).ok_or("missing fixture mode")?;
    if !matches!(
        mode.as_str(),
        "serve" | "metadata" | "read" | "late" | "large" | "readiness" | "timeout" | "cancel"
    ) {
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
        let directory_bytes = metadata_bytes(&mode)?;
        let directory = Index::open(&directory_bytes)?;
        if mode == "large" && directory.len() <= 16 {
            return Err("large immutable index does not exceed the worker node budget".into());
        }
        let mut metadata = Metadata::new(
            directory,
            MetadataLimits {
                namespace_entries: 16,
                namespace_bytes: 4096,
                inodes: 16,
                inode_bytes: 65536,
            },
            CachePolicy::Revalidate,
            if matches!(mode.as_str(), "metadata" | "read" | "late" | "large") {
                XattrPolicy::Recorded
            } else {
                XattrPolicy::Disabled
            },
        )?;

        let mut backing_client = if matches!(mode.as_str(), "read" | "late") {
            Some(WorkerClient::bind(
                io::stdin().as_fd().try_clone_to_owned()?,
                ExposureContext::new("0123456789abcdef0123456789abcdef", 1, [7; 32])?,
                0,
            )?)
        } else {
            None
        };
        // Original backing custody remains separate from connection-local counts.
        // This synthetic view grants no production repository or broker authority.
        let mut lifetime = fuse_lifetime::Table::new(fuse_lifetime::Limits {
            nodes: 16,
            handles: 16,
            bytes: 4096,
        })?;
        let mut backing: Option<(u64, FallbackBacking)> = None;
        let mut last_file_release: Option<(NonZeroU64, NonZeroU64)> = None;
        let mut read_after_peer_release = false;
        let mut fetch: Option<Fetch> = None;
        let mut opens = fuse_open::Queue::new(fuse_open::Limits {
            nodes: 1,
            waiters: 16,
            bytes: 4096,
        })?;

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
        if mode == "readiness" {
            if connection.try_receive(&mut input)?.is_some() {
                return Err("idle connection unexpectedly consumed a request".into());
            }
            if tokio::time::timeout(Duration::from_millis(100), connection.wait_readable())
                .await
                .is_ok()
            {
                return Err("idle readiness notification unexpectedly completed".into());
            }
        }
        notify(b"READY")?;

        if !matches!(mode.as_str(), "serve" | "metadata" | "read" | "late" | "large" | "readiness") {
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
            while let Some(reply) = opens.next_reply(tokio::time::Instant::now().into_std()) {
                let mut opened = [0; 16];
                let body = if reply.outcome == Outcome::Ready {
                    let handle = lifetime.open(reply.ticket.node(), HandleKind::File)?;
                    Some(fuse_read::open(handle, &mut opened)?)
                } else {
                    None
                };
                lifetime.unpin(reply.ticket.node())?;
                send_unique(&mut connection, &mut output, reply.unique, body, libc::EIO).await?;
                if mode == "late" && reply.outcome == Outcome::IoError {
                    if fetch.is_none() || opens.pending() != 1 {
                        return Err("expired open discarded its original shared fetch".into());
                    }
                    notify(b"OPEN_EXPIRED")?;
                }
            }
            while let Some(node) = lifetime.next_unreferenced() {
                if backing
                    .as_ref()
                    .is_some_and(|(original, _)| *original == node.get())
                {
                    backing = None;
                }
            }
            let open_deadline = opens.next_deadline();
            let readable = tokio::select! {
                result = async {
                    match fetch.as_mut() {
                        Some(fetch) => fetch.await,
                        None => pending().await,
                    }
                } => {
                    let (ticket, client, reply, size) = result;
                    fetch = None;
                    backing_client = Some(client);
                    let file = FallbackBacking::from_reply(reply?, size, 131072)?;
                    backing = Some((ticket.node().get(), file));
                    opens.complete(ticket, Outcome::Ready)?;
                    lifetime.unpin(ticket.node())?;
                    continue;
                },
                () = async {
                    match open_deadline {
                        Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
                        None => pending().await,
                    }
                } => continue,
                result = tokio::time::timeout(DEADLINE, connection.wait_readable()) => {
                    result.map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
                },
                result = stopped(&control) => {
                    result?;
                    if matches!(mode.as_str(), "read" | "late") && !read_after_peer_release {
                        return Err("kernel never read an original handle after peer release".into());
                    }
                    drop(connection);
                    notify(b"STOPPED")?;
                    return Ok(());
                }
            };
            let received = match readable {
                Ok(()) => connection.try_receive(&mut input),
                Err(error) => Err(error),
            };
            let request = match received {
                Ok(Some(request)) => request,
                Ok(None) => continue,
                Err(error) if error.raw_os_error() == Some(libc::ENODEV) => {
                    stopped(&control).await?;
                    break;
                }
                Err(error) => return Err(error.into()),
            };
            let arrived = tokio::time::Instant::now().into_std();
            // FORGET and BATCH_FORGET never receive replies, even for nonzero IDs.
            if matches!(request.opcode(), 2 | 42) {
                lifetime.forget(request, 1024)?;
                continue;
            }
            let node = NonZeroU64::new(request.node());
            if request.opcode() == 28 {
                lifetime.check(
                    NonZeroU64::new(request.body_u64(0)?).ok_or("zero directory handle")?,
                    node.ok_or("zero directory node")?,
                    HandleKind::Directory,
                )?;
            }
            if request.opcode() == 3 && request.body_u32(0)? & 1 != 0 {
                let kind = match metadata.entry(request.node()).map(|entry| entry.kind()) {
                    Some(Kind::Directory { .. }) => HandleKind::Directory,
                    _ => HandleKind::File,
                };
                lifetime.check(
                    NonZeroU64::new(request.body_u64(8)?).ok_or("zero getattr handle")?,
                    node.ok_or("zero getattr node")?,
                    kind,
                )?;
            }
            let mut opened = [0; 16];
            let entry = metadata.entry(request.node());
            let (body, errno) = match metadata.dispatch(
                request,
                |_| Presentation::default(),
                &mut directory_page,
            )? {
                Response::Payload(body) => {
                    if request.opcode() == 1 {
                        let original = u64::from_ne_bytes(body[..8].try_into()?);
                        if let Some(node) = NonZeroU64::new(original) {
                            lifetime.lookup(node)?;
                        }
                    }
                    (Some(body), 0)
                }
                Response::Errno(errno) => (None, errno),
                Response::Unhandled => match (request.opcode(), entry) {
                    (27, Some(entry)) if matches!(entry.kind(), Kind::Directory { .. }) => {
                        if request.body().len() != 8 || request.body_u32(4)? != 0 {
                            return Err("invalid actual OPENDIR".into());
                        }
                        let handle = lifetime
                            .open(node.ok_or("zero directory node")?, HandleKind::Directory)?;
                        opened[..8].copy_from_slice(&handle.get().to_ne_bytes());
                        (Some(opened.as_slice()), 0)
                    }
                    (14, Some(entry)) if matches!(mode.as_str(), "read" | "late") => {
                        if request.body().len() != 8 || request.body_u32(4)? != 0 {
                            return Err("invalid actual fallback OPEN".into());
                        }
                        if request.body_u32(0)? & (libc::O_ACCMODE | libc::O_TRUNC) as u32 != 0 {
                            (None, libc::EROFS)
                        } else if let Kind::File { content, size } = entry.kind() {
                            if backing.is_none() {
                                let node =
                                    NonZeroU64::new(request.node()).ok_or("zero open node")?;
                                let unique = NonZeroU64::new(request.unique())
                                    .ok_or("zero open response ID")?;
                                // The late-completion scenario configures a short open
                                // deadline while retaining the original fetch deadline.
                                let open_deadline = if mode == "late" && opens.pending() == 0 {
                                    Duration::from_millis(200)
                                } else {
                                    DEADLINE
                                };
                                let queued = opens.enqueue(node, unique, arrived, open_deadline)?;
                                lifetime.pin(node)?;
                                match queued {
                                    Enqueued::Start(ticket) => {
                                        lifetime.pin(node)?;
                                        let mut client = backing_client
                                            .take()
                                            .ok_or("missing original backing client")?;
                                        let selection = RequestedBacking::File {
                                            path: entry.path().to_vec(),
                                            content,
                                        };
                                        fetch = Some(Box::pin(async move {
                                            let reply =
                                                client.request_bounded(selection, DEADLINE).await;
                                            (ticket, client, reply, size)
                                        }));
                                    }
                                    Enqueued::Joined(_) => notify(b"COALESCED")?,
                                }
                                continue;
                            }
                            if backing
                                .as_ref()
                                .is_some_and(|(node, _)| *node == request.node())
                            {
                                let handle = lifetime
                                    .open(node.ok_or("zero file node")?, HandleKind::File)?;
                                (Some(fuse_read::open(handle, &mut opened)?), 0)
                            } else {
                                (None, libc::EIO)
                            }
                        } else {
                            (None, libc::EISDIR)
                        }
                    }
                    (15, Some(_)) if matches!(mode.as_str(), "read" | "late") => {
                        let (node, file) =
                            backing.as_ref().ok_or("READ without original backing")?;
                        let node = NonZeroU64::new(*node).ok_or("zero file node")?;
                        let handle =
                            NonZeroU64::new(request.body_u64(0)?).ok_or("zero file handle")?;
                        lifetime.check(handle, node, HandleKind::File)?;
                        let read = fuse_read::Read::parse(request, node, handle)?;
                        let length =
                            file.read(read.offset(), read.length(), &mut directory_page)?;
                        // Monotonic handle IDs distinguish a surviving original
                        // handle from a later reopen served from cached pages.
                        if last_file_release.is_some_and(|(released_node, released_handle)| {
                            released_node == node && handle < released_handle
                        }) {
                            read_after_peer_release = true;
                        }
                        (Some(&directory_page[..length]), 0)
                    }
                    (18 | 29, Some(_)) => {
                        if request.body().len() != 24 || request.body_u32(12)? & !3 != 0 {
                            return Err("invalid actual RELEASE".into());
                        }
                        let kind = if request.opcode() == 18 {
                            HandleKind::File
                        } else {
                            HandleKind::Directory
                        };
                        let handle = NonZeroU64::new(request.body_u64(0)?)
                            .ok_or("zero released handle")?;
                        let node = node.ok_or("zero released node")?;
                        lifetime.close(handle, node, kind)?;
                        if kind == HandleKind::File {
                            last_file_release = Some((node, handle));
                        }
                        (Some([].as_slice()), 0)
                    }
                    (25, Some(_)) if matches!(mode.as_str(), "read" | "late") => {
                        if request.body().len() != 24
                            || request.body_u32(8)? != 0
                            || request.body_u32(12)? != 0
                        {
                            return Err("invalid actual FLUSH".into());
                        }
                        lifetime.check(
                            NonZeroU64::new(request.body_u64(0)?).ok_or("zero flush handle")?,
                            node.ok_or("zero flush node")?,
                            HandleKind::File,
                        )?;
                        (Some([].as_slice()), 0)
                    }
                    (34, Some(_)) => {
                        if request.body().len() != 16
                            || request.body_u32(8)? & !1 != 0
                            || request.body_u32(12)? != 0
                        {
                            return Err("invalid actual FSYNCDIR".into());
                        }
                        lifetime.check(
                            NonZeroU64::new(request.body_u64(0)?).ok_or("zero fsyncdir handle")?,
                            node.ok_or("zero fsyncdir node")?,
                            HandleKind::Directory,
                        )?;
                        (Some([].as_slice()), 0)
                    }
                    (38, _) => (Some([].as_slice()), 0),
                    (_, None) => (None, libc::ESTALE),
                    _ => (None, libc::ENOSYS),
                },
            };
            send(&mut connection, &mut output, request, body, errno).await?;
        }
        if matches!(mode.as_str(), "read" | "late") && !read_after_peer_release {
            return Err("kernel never read an original handle after peer release".into());
        }
        notify(b"STOPPED")?;
        Ok(())
    })
}

/// Builds synthetic metadata without a repository, content source or exposure.
fn metadata_bytes(mode: &str) -> Result<Vec<u8>> {
    if !matches!(mode, "metadata" | "read" | "late" | "large") {
        return Ok(structural_index::compile([7; 32], &[], 1, 4096)?);
    }
    let content: [u8; 32] = TERRANE_V1
        .calculate(IdentityKind::Chunk, b"abc")?
        .digest()
        .try_into()?;
    let file = |path: &[u8], link_id| LeafItem {
        key: path.to_vec(),
        entry: TreeEntry {
            kind: EntryKind::File {
                mode: 0o640,
                size: 3,
                content: ContentRef::Inline(content),
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
    let mut entries = vec![
        file(b"a", Some(b"a")),
        file(b"b", Some(b"a")),
        directory,
        file(b"directory/file", None),
        symlink,
        file(b"\xff", None),
    ];
    if mode == "large" {
        // These paths remain untouched; the worker still has only 16 node slots.
        let untouched = (0..64)
            .map(|number| format!("untouched-{number:02}").into_bytes())
            .collect::<Vec<_>>();
        entries.extend(untouched.iter().map(|path| file(path, None)));
    }
    // The canonical tree builder requires sorted raw keys, including after
    // adding untouched ASCII names before the final non-UTF-8 entry.
    entries.sort_unstable_by(|left, right| left.key.cmp(&right.key));
    let tree = Tree::build(entries, None, 4096, TreeUse::Ordinary)?;
    Ok(structural_index::compile_tree(
        &tree,
        &std::collections::BTreeMap::new(),
        if mode == "large" { 128 } else { 16 },
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
    send_unique(connection, output, unique, body, errno).await
}

async fn send_unique(
    connection: &mut Connection,
    output: &mut [u8],
    unique: NonZeroU64,
    body: Option<&[u8]>,
    errno: i32,
) -> Result {
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

#[cfg(test)]
mod tests {
    //! Checks pure fixture preparation before any device or mount setup.

    #[test]
    fn large_fixture_compiles_before_native_setup() -> super::Result {
        for (mode, count) in [
            ("serve", 1),
            ("metadata", 7),
            ("read", 7),
            ("late", 7),
            ("large", 71),
        ] {
            let bytes = super::metadata_bytes(mode)?;
            let index = super::Index::open(&bytes)?;
            assert_eq!(index.len(), count, "fixture mode {mode}");
            if mode == "large" {
                assert!(index.len() > 16);
                assert!(index.lookup(b"untouched-63").is_some());
                assert!(index.lookup(b"\xff").is_some());
            }
        }
        Ok(())
    }
}
