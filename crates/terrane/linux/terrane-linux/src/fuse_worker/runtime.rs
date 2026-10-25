//! Runs the original connection with bounded metadata and backing state.

use super::*;
use crate::{
    fuse_dispatch::Response,
    fuse_lifetime::Kind as HandleKind,
    fuse_open::{Enqueued, Outcome, Ticket},
    fuse_protocol::Reply,
    fuse_read::{self, Backing as FallbackBacking},
    structural_index::Kind,
    worker_channel::{BackingReply, RequestedBacking},
};
use std::{future::pending, pin::Pin};

type Fetch = Pin<Box<dyn Future<Output = (Ticket, WorkerClient, io::Result<BackingReply>, u64)>>>;

pub(super) async fn run(
    connection: Connection,
    client: WorkerClient,
    index: Index<'_>,
    options: Options,
    presentation: impl FnMut(Entry<'_>) -> Presentation,
    observe: impl FnMut(Event) -> io::Result<()>,
    stop: impl Future<Output = io::Result<()>>,
) -> Result<Exit, Error> {
    options.validate()?;
    tokio::select! {
        biased;
        result = stop => {
            result?;
            Ok(Exit::Stopped)
        },
        result = run_connection(connection, client, index, options, presentation, observe) => result,
    }
}

async fn run_connection(
    mut connection: Connection,
    client: WorkerClient,
    index: Index<'_>,
    options: Options,
    mut presentation: impl FnMut(Entry<'_>) -> Presentation,
    mut observe: impl FnMut(Event) -> io::Result<()>,
) -> Result<Exit, Error> {
    let mut input = buffer(options.protocol.request_bytes)?;
    let mut output = buffer(options.protocol.request_bytes)?;
    let mut directory_page = buffer(options.protocol.request_bytes - 16)?;
    let mut metadata = Metadata::new(index, options.metadata, options.cache, options.xattrs)?;
    let mut lifetime = fuse_lifetime::Table::new(options.lifetime)?;
    let mut backings = fuse_backing::Table::new(options.backings)?;
    let mut opens = fuse_open::Queue::new(options.opens)?;
    let mut backing_client = Some(client);
    let mut fetch: Option<Fetch> = None;
    let mut fault = None;

    // A version retry accepts no filesystem operations. Every selected protocol
    // is published only after its original INIT reply has reached the kernel.
    let minor = loop {
        let request = connection
            .receive(&mut input, options.exchange_deadline)
            .await?;
        let initialized =
            fuse_protocol::init::negotiate(request, options.protocol, options.passthrough, false)?;
        send_unique(
            &mut connection,
            &mut output,
            NonZeroU64::new(request.unique()).ok_or("zero INIT response ID")?,
            Some(initialized.body()),
            0,
            options.exchange_deadline,
        )
        .await?;
        if let Some((minor, false)) = initialized.selected() {
            break minor;
        }
    };
    observe(Event::Ready {
        minor,
        degraded: true,
    })?;
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
            send_unique(
                &mut connection,
                &mut output,
                reply.unique,
                body,
                libc::EIO,
                options.exchange_deadline,
            )
            .await?;
            if reply.outcome == Outcome::IoError {
                observe(Event::OpenFailed {
                    node: reply.ticket.node(),
                })?;
            }
        }

        // Fail each accepted open on the original device before disconnecting.
        // Other queued nodes have no usable channel after a transport fault.
        if let Some(error) = fault.take() {
            return Err(error);
        }
        while let Some(node) = lifetime.next_unreferenced() {
            drop(backings.retire(node)?);
        }
        // The private channel has one original outstanding request. Other
        // canonical nodes retain bounded reservations instead of taking it.
        if fetch.is_none()
            && let Some(ticket) = backings.next_fetch()
        {
            let entry = metadata
                .entry(ticket.node().get())
                .ok_or("queued backing lost its original namespace entry")?;
            let Kind::File { content, size } = entry.kind() else {
                return Err("queued backing is not an original file".into());
            };

            let mut client = backing_client
                .take()
                .ok_or("missing original backing client")?;
            let selection = RequestedBacking::File {
                path: entry.path().to_vec(),
                content,
            };

            let fetch_deadline = options.fetch_deadline;
            fetch = Some(Box::pin(async move {
                let reply = client.request_bounded(selection, fetch_deadline).await;
                (ticket, client, reply, size)
            }));
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
                match reply.map_err(Error::Io).and_then(|reply| {
                    FallbackBacking::from_reply(reply, size, options.read_bytes).map_err(Error::Read)
                }) {
                    Ok(file) => {
                        backings.install(ticket, file).map_err(|rejected| rejected.error)?;
                        opens.complete(ticket, Outcome::Ready)?;
                        lifetime.unpin(ticket.node())?;
                    }
                    Err(error) => {
                        backings.fail(ticket)?;
                        opens.complete(ticket, Outcome::IoError)?;
                        lifetime.unpin(ticket.node())?;
                        while let Some(queued) = backings.next_fetch() {
                            backings.fail(queued)?;
                            opens.complete(queued, Outcome::IoError)?;
                            lifetime.unpin(queued.node())?;
                        }
                        fault = Some(error);
                    }
                }
                continue;
            },
            () = async {
                match open_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
                    None => pending().await,
                }
            } => continue,
            result = async {
                match backing_client.as_mut() {
                    Some(client) => client.wait_idle_fault().await,
                    None => pending().await,
                }
            } => {
                match result {
                    Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                        return Ok(Exit::OwnerDisconnected);
                    }
                    Err(error) => return Err(Error::Io(error)),
                    Ok(()) => return Err("idle backing monitor returned without a fault".into()),
                }
            },
            result = connection.wait_readable() => result,
        };
        let received = match readable {
            Ok(()) => connection.try_receive(&mut input),
            Err(error) => Err(error),
        };
        let request = match received {
            Ok(Some(request)) => request,
            Ok(None) => continue,
            Err(error) if error.raw_os_error() == Some(libc::ENODEV) => {
                return Ok(Exit::Unmounted);
            }
            Err(error) => return Err(error.into()),
        };
        let arrived = tokio::time::Instant::now().into_std();
        // FORGET and BATCH_FORGET never receive replies, even for nonzero IDs.
        if matches!(request.opcode(), 2 | 42) {
            lifetime.forget(request, options.forget_entries)?;
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
        let (body, errno) =
            match metadata.dispatch(request, &mut presentation, &mut directory_page)? {
                Response::Payload(body) => {
                    if request.opcode() == 1 {
                        let original = u64::from_ne_bytes(
                            body.get(..8)
                                .ok_or("short LOOKUP response")?
                                .try_into()
                                .map_err(|_| Error::State("invalid LOOKUP response"))?,
                        );
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
                    (14, Some(entry)) => {
                        if request.body().len() != 8 || request.body_u32(4)? != 0 {
                            return Err("invalid actual fallback OPEN".into());
                        }
                        if request.body_u32(0)? & (libc::O_ACCMODE | libc::O_TRUNC) as u32 != 0 {
                            (None, libc::EROFS)
                        } else if let Kind::File { .. } = entry.kind() {
                            if backings.get(node.ok_or("zero open node")?).is_none() {
                                let node =
                                    NonZeroU64::new(request.node()).ok_or("zero open node")?;
                                let unique = NonZeroU64::new(request.unique())
                                    .ok_or("zero open response ID")?;
                                let queued =
                                    opens.enqueue(node, unique, arrived, options.open_deadline)?;
                                lifetime.pin(node)?;
                                match queued {
                                    Enqueued::Start(ticket) => {
                                        backings.reserve(ticket)?;
                                        lifetime.pin(node)?;
                                        observe(Event::OpenQueued {
                                            node,
                                            shared: false,
                                            waiting_for_channel: fetch.is_some(),
                                        })?;
                                    }
                                    Enqueued::Joined(_) => observe(Event::OpenQueued {
                                        node,
                                        shared: true,
                                        waiting_for_channel: false,
                                    })?,
                                }
                                continue;
                            }
                            let handle =
                                lifetime.open(node.ok_or("zero file node")?, HandleKind::File)?;
                            (Some(fuse_read::open(handle, &mut opened)?), 0)
                        } else {
                            (None, libc::EISDIR)
                        }
                    }
                    (15, Some(_)) => {
                        let node = node.ok_or("zero file node")?;
                        let file = backings.get(node).ok_or("READ without original backing")?;
                        let handle =
                            NonZeroU64::new(request.body_u64(0)?).ok_or("zero file handle")?;
                        lifetime.check(handle, node, HandleKind::File)?;
                        let read = fuse_read::Read::parse(request, node, handle)?;
                        let length =
                            file.read(read.offset(), read.length(), &mut directory_page)?;
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
                        let handle =
                            NonZeroU64::new(request.body_u64(0)?).ok_or("zero released handle")?;
                        let node = node.ok_or("zero released node")?;
                        lifetime.close(handle, node, kind)?;
                        (Some([].as_slice()), 0)
                    }
                    (25, Some(_)) => {
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
                    (20 | 34, Some(_)) => {
                        if request.body().len() != 16
                            || request.body_u32(8)? & !1 != 0
                            || request.body_u32(12)? != 0
                        {
                            return Err("invalid FUSE synchronization request".into());
                        }
                        lifetime.check(
                            NonZeroU64::new(request.body_u64(0)?).ok_or("zero fsyncdir handle")?,
                            node.ok_or("zero fsyncdir node")?,
                            if request.opcode() == 20 {
                                HandleKind::File
                            } else {
                                HandleKind::Directory
                            },
                        )?;
                        (Some([].as_slice()), 0)
                    }
                    (38, _) => (Some([].as_slice()), 0),
                    (_, None) => (None, libc::ESTALE),
                    _ => (None, libc::ENOSYS),
                },
            };
        send_unique(
            &mut connection,
            &mut output,
            NonZeroU64::new(request.unique()).ok_or("zero response ID")?,
            body,
            errno,
            options.exchange_deadline,
        )
        .await?;
    }
}

fn buffer(bytes: usize) -> io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(bytes).map_err(io::Error::other)?;
    buffer.resize(bytes, 0);
    Ok(buffer)
}

async fn send_unique(
    connection: &mut Connection,
    output: &mut [u8],
    unique: NonZeroU64,
    body: Option<&[u8]>,
    errno: i32,
    timeout: Duration,
) -> Result<(), Error> {
    let limit = output.len();
    let bytes = match body {
        Some(body) => fuse_protocol::reply(output, unique, body)?,
        None => fuse_protocol::error_reply(output, unique, errno)?,
    };
    connection
        .send(Reply::parse(bytes, limit)?, timeout)
        .await?;
    Ok(())
}
