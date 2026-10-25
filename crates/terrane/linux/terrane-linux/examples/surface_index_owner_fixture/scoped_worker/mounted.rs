//! Joins signed owner grants and the production worker on an actual guest mount.
//!
//! Only the disposable guest's administrative supervisor mounts. The original
//! worker opens the device, transfers a temporary mount alias and waits for its
//! closure before confinement. Serve retains no device alias or mount authority.

use super::*;
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, SendAncillaryBuffer, SendAncillaryMessage,
};
use std::{
    io::{IoSlice, IoSliceMut},
    mem::MaybeUninit,
};
use terrane_linux::{
    fuse_backing,
    fuse_connection::Connection,
    fuse_dispatch, fuse_lifetime,
    fuse_metadata::{CachePolicy, Presentation},
    fuse_open, fuse_protocol, fuse_worker,
    fuse_xattr::Policy as XattrPolicy,
};

/// Launches the original worker and hands its mount alias to the VM supervisor.
///
/// # Errors
/// Refuses missing administration, original-child binding or device handoff.
pub(crate) fn launch() -> Result<Launched> {
    launch_mode("worker-mounted-child")
}

/// Transfers only the original child's temporary alias before dropping privilege.
///
/// # Errors
/// Refuses invalid sender credentials, another device or incomplete controls.
pub(crate) fn handoff(launched: &Launched) -> Result<()> {
    readable(&launched.control)?;
    let mut bytes = [0; 16];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(253), ScmCredentials(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let received = net::recvmsg(
        &launched.control,
        &mut [IoSliceMut::new(&mut bytes)],
        &mut ancillary,
        net::RecvFlags::DONTWAIT | net::RecvFlags::CMSG_CLOEXEC,
    )?;
    let mut descriptors = Vec::new();
    let mut credentials = None;
    let mut invalid = !received.flags.is_empty();
    for message in ancillary.drain() {
        match message {
            RecvAncillaryMessage::ScmRights(rights) => descriptors.extend(rights),
            RecvAncillaryMessage::ScmCredentials(value) if credentials.is_none() => {
                credentials = Some(value)
            }
            _ => invalid = true,
        }
    }
    if invalid
        || bytes.get(..received.bytes) != Some(b"DEVICE")
        || descriptors.len() != 1
        || credentials.is_none_or(|value| {
            value.pid.as_raw_nonzero().get() as u32 != launched.child.id()
                || value.uid.as_raw() != 848
                || value.gid.as_raw() != 848
        })
    {
        return Err("mounted fixture lost its original worker device handoff".into());
    }
    let device = descriptors.pop().ok_or("missing original mount alias")?;
    let metadata = rustix::fs::fstat(&device)?;
    if rustix::fs::FileType::from_raw_mode(metadata.st_mode)
        != rustix::fs::FileType::CharacterDevice
        || metadata.st_rdev != libc::makedev(10, 229)
    {
        return Err("mounted worker handed off another device".into());
    }
    send_device(io::stdout().as_fd(), device.as_fd())?;
    drop(device);
    expect(io::stdout().as_fd(), b"M")?;
    send(launched.control.as_fd(), b"M")?;
    Ok(())
}

fn send_device(
    channel: std::os::fd::BorrowedFd<'_>,
    device: std::os::fd::BorrowedFd<'_>,
) -> io::Result<()> {
    let rights = [device];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !ancillary.push(SendAncillaryMessage::ScmRights(&rights))
        || net::sendmsg(
            channel,
            &[IoSlice::new(b"DEVICE")],
            &mut ancillary,
            net::SendFlags::NOSIGNAL,
        )? != 6
    {
        return Err(io::Error::other("incomplete original device handoff"));
    }
    Ok(())
}

fn send(channel: std::os::fd::BorrowedFd<'_>, bytes: &[u8]) -> io::Result<()> {
    if net::send(
        channel,
        bytes,
        net::SendFlags::DONTWAIT | net::SendFlags::NOSIGNAL,
    )? != bytes.len()
    {
        return Err(io::Error::other("incomplete mounted fixture control"));
    }
    Ok(())
}

fn expect(channel: std::os::fd::BorrowedFd<'_>, expected: &[u8]) -> Result<()> {
    readable(channel)?;
    let mut bytes = [0; 16];
    let (length, received) = net::recv(
        channel,
        &mut bytes,
        net::RecvFlags::DONTWAIT | net::RecvFlags::TRUNC,
    )?;
    if received != length || bytes.get(..length) != Some(expected) {
        return Err("unexpected mounted fixture control packet".into());
    }
    Ok(())
}

/// Runs genuine owner preparation and disclosure while the guest drives the mount.
///
/// # Errors
/// Preserves signed preparation, owner disclosure, protocol and custody failures.
///
/// # Panics
/// Panics if called from within an asynchronous Tokio execution context.
pub(crate) fn run(
    mut launched: Launched,
    runtime: &tokio::runtime::Runtime,
    owner: &NativeMetadataOwner,
    inputs: &config::Inputs,
) -> Result<()> {
    runtime.block_on(async {
        let fixture = RepositoryFixture::new(&inputs.domain).await?;
        fixture.commit(BODY).await?;
        let target = ViewTarget::Ref(MAIN.parse()?);
        let selection = fixture
            .repository
            .prepare_root_read(
                &target,
                fixture.authority.token(),
                "sdk",
                exposure::limits(),
            )
            .await?;
        let served = owner.prepare_surface_mapping(selection).await?;
        let deadline = exposure::now()? + 90;
        let lease = owner.retain_surface_exposure(&served, deadline).await?;
        let identity = TERRANE_V1.calculate(IdentityKind::Chunk, BODY)?;
        let descriptor = Descriptor::from_identity(&TERRANE_V1, &identity, BODY)?;
        let publication = owner
            .publish_inline(descriptor, [vec![0], BODY.to_vec()].concat())
            .await?;
        let mut channel = launched.bind(&lease)?;
        launched.send_context(&lease, identity.digest().try_into()?)?;

        let request = channel.receive_bounded(Duration::from_secs(10)).await?;
        let selection = fixture
            .repository
            .prepare_root_read(
                &target,
                fixture.authority.token(),
                "sdk",
                exposure::limits(),
            )
            .await?;
        request.grant_index(owner, &served, selection).await?;
        expect(launched.control.as_fd(), b"READY")?;
        send(io::stdout().as_fd(), b"READY")?;

        // Hold the genuine request until the original worker has coalesced both
        // kernel opens and the administrator has observed responsive metadata.
        let request = channel.receive_bounded(Duration::from_secs(10)).await?;
        send(io::stdout().as_fd(), b"FETCH")?;
        expect(launched.control.as_fd(), b"COALESCED")?;
        expect(io::stdout().as_fd(), b"G")?;
        let selection = fixture
            .repository
            .prepare_file_read(
                &View::parse(MAIN)?,
                b"file",
                fixture.authority.token(),
                "sdk",
            )
            .await?;
        request.grant_file(owner, &served, selection, deadline).await?;
        publication.complete_cache_handoff(owner).await?;
        expect(io::stdout().as_fd(), b"D")?;
        if !matches!(channel.receive(), Err(error) if error.kind() == io::ErrorKind::WouldBlock) {
            return Err("mounted worker submitted an unexpected additional backing request".into());
        }

        let before = exposure::snapshot(inputs).await?;
        let original = before
            .exposures
            .iter()
            .find(|row| row.id == lease.id())
            .ok_or("mounted worker lost its durable exposure")?;
        if original.phase != ExposurePhase::Active || original.backings.len() != 2 {
            return Err("mounted reads did not retain their actual index and file bindings".into());
        }
        owner.drain_surface_exposure(&lease).await?;
        send(launched.control.as_fd(), b"S")?;
        expect(launched.control.as_fd(), b"STOPPED")?;
        if !launched.child.wait()?.success() {
            return Err("mounted production worker failed actual drain".into());
        }
        let after = exposure::snapshot(inputs).await?;
        let retained = after
            .exposures
            .iter()
            .find(|row| row.id == lease.id())
            .ok_or("worker stop erased an original exposure obligation")?;
        let original_pins = before
            .pins
            .iter()
            .map(|pin| (&pin.owner, &pin.hash, pin.expires));
        let retained_pins = after
            .pins
            .iter()
            .map(|pin| (&pin.owner, &pin.hash, pin.expires));
        if retained.phase != ExposurePhase::Draining
            || retained.backings != original.backings
            || !original_pins.eq(retained_pins)
        {
            return Err("worker stop inferred physical release from connection closure".into());
        }
        println!("PASS actual signed-owner index and verified backing serve coalesced kernel opens through the production worker");
        println!("PASS durable drain stops the mounted production worker while retaining original physical bindings and pins");
        send(io::stdout().as_fd(), b"DRAINED")?;
        Ok(())
    })
}

/// Runs the production startup and request loop on the child's original device.
///
/// # Errors
/// Refuses failed confinement, authenticated startup, kernel exchanges or drain.
pub(crate) fn child() -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let device = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open("/dev/fuse")?;
    send_device(io::stderr().as_fd(), device.as_fd())?;
    expect(io::stderr().as_fd(), b"M")?;
    let confinement = std::sync::Arc::new(
        terrane_linux::quota_confinement::install_worker_network(device.as_fd())?,
    );
    let (client, _, _) = child_context()?;
    let control = io::stderr().as_fd().try_clone_to_owned()?;
    let flags = rustix::fs::fcntl_getfl(&control)?;
    rustix::fs::fcntl_setfl(&control, flags | rustix::fs::OFlags::NONBLOCK)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let connection = Connection::new(device.into(), confinement, 262144, 262144)?;
        let control = tokio::io::unix::AsyncFd::new(control)?;
        let exit = fuse_worker::serve(
            connection,
            client,
            options(),
            |_| Presentation::default(),
            |event| match event {
                fuse_worker::Event::Ready {
                    minor: 40,
                    degraded: true,
                } => send(control.get_ref().as_fd(), b"READY"),
                fuse_worker::Event::OpenQueued { shared: true, .. } => {
                    send(control.get_ref().as_fd(), b"COALESCED")
                }
                fuse_worker::Event::OpenQueued { .. } => Ok(()),
                _ => Err(io::Error::other("unexpected mounted worker event")),
            },
            async {
                loop {
                    let mut ready = control.readable().await?;
                    match ready.try_io(|fd| {
                        let mut bytes = [0; 16];
                        let (length, received) = net::recv(
                            fd.get_ref(),
                            &mut bytes,
                            net::RecvFlags::DONTWAIT | net::RecvFlags::TRUNC,
                        )?;
                        if received == length && &bytes[..length] == b"S" {
                            Ok(())
                        } else {
                            Err(io::Error::other("invalid mounted worker stop"))
                        }
                    }) {
                        Ok(result) => return result,
                        Err(_) => continue,
                    }
                }
            },
        )
        .await?;
        if exit != fuse_worker::Exit::Stopped {
            return Err("mounted worker stopped before its durable drain".into());
        }
        send(control.get_ref().as_fd(), b"STOPPED")?;
        Ok(())
    })
}

fn options() -> fuse_worker::Options {
    fuse_worker::Options {
        index_bytes: 65536,
        protocol: fuse_protocol::init::Limits {
            request_bytes: 262144,
            readahead_bytes: 65536,
            background_requests: 8,
        },
        read_bytes: 131072,
        metadata: fuse_dispatch::Limits {
            namespace_entries: 16,
            namespace_bytes: 4096,
            inodes: 16,
            inode_bytes: 65536,
        },
        lifetime: fuse_lifetime::Limits {
            nodes: 16,
            handles: 16,
            bytes: 4096,
        },
        opens: fuse_open::Limits {
            nodes: 16,
            waiters: 16,
            bytes: 4096,
        },
        backings: fuse_backing::Limits {
            nodes: 16,
            bytes: 4096,
        },
        forget_entries: 1024,
        cache: CachePolicy::Revalidate,
        xattrs: XattrPolicy::Disabled,
        passthrough: fuse_protocol::init::Passthrough::Off,
        open_deadline: Duration::from_secs(5),
        fetch_deadline: Duration::from_secs(10),
        exchange_deadline: Duration::from_secs(5),
    }
}
