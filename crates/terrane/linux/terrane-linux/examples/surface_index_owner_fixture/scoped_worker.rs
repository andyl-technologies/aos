//! Joins genuine scoped reads and serialized owner Send in a dedicated guest.
//!
//! A fixture launcher starts its original child before irreversibly dropping to
//! serve's identity. Native owner startup follows the ordinary capability-free
//! path. This launcher is not the production broker or a FUSE worker sandbox.
//!
//! The separate private fixture control socket carries exactly 104 public bytes:
//!
//! ```text
//! exposure:32ascii | generation:u64le | root:32 | inline_content:32
//! ```

use super::{
    Result, config, exposure,
    repository_fixture::{MAIN, RepositoryFixture},
};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    net::{self, Shutdown},
    thread::{self, CapabilitySet, CapabilitySets, Gid, Uid},
};
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    os::fd::{AsFd, OwnedFd},
    process::{Child, Command, Stdio},
    time::Duration,
};
use terrane_format::{
    identity::{Descriptor, IdentityKind, TERRANE_V1},
    surface::{View, ViewTarget},
    tree_format::ContentRef,
};
use terrane_linux::{
    host_cache::{NativeExposureLease, NativeMetadataOwner},
    structural_index::Kind,
    worker_channel::{
        self, ExposureContext, PendingBacking, RequestedBacking, WorkerChannel, WorkerClient,
        WorkerIdentity,
    },
};
use terrane_sdk::host::cache::{ExposureBackingKind, ExposurePhase};

const BODY: &[u8] = b"actual scoped worker backing through serialized owner Send";

/// Retains the original child and both private fixture endpoints.
pub(super) struct Launched {
    child: Child,
    channel: Option<OwnedFd>,
    identity: Option<WorkerIdentity>,
    control: File,
    network: bool,
}

impl Drop for Launched {
    fn drop(&mut self) {
        let mut descriptors = [PollFd::new(&self.control, PollFlags::IN)];
        if poll(&mut descriptors, Some(&Timespec::default())).is_ok_and(|count| count != 0) {
            let mut diagnostics = [0; 1024];
            if let Ok(count) = self.control.read(&mut diagnostics)
                && count != 0
            {
                eprintln!(
                    "actual scoped worker: {}",
                    String::from_utf8_lossy(&diagnostics[..count])
                );
            }
        }
        if let Some(channel) = &self.channel {
            let _ = net::shutdown(channel, Shutdown::Both);
        }
        let _ = net::shutdown(&self.control, Shutdown::Both);
        // After the identity drop, only the guest's administrative supervisor
        // can forcibly terminate UID 848. The child independently bounds waits
        // and exits on channel closure; never block this destructor on it.
        let _ = self.child.kill();
        let _ = self.child.try_wait();
    }
}

/// Starts the original worker before permanently dropping fixture privileges.
///
/// # Errors
/// Refuses a nonadministrative or multithreaded launcher, missing native inputs,
/// failed original-child binding and incomplete identity or capability drops.
pub(super) fn launch() -> Result<Launched> {
    launch_mode("worker-child")
}

/// Starts the original child used by the administrative crash supervisor.
///
/// # Errors
/// Preserves the same original-child and irrevocable identity checks as launch.
pub(super) fn launch_crash() -> Result<Launched> {
    launch_mode("worker-crash-child")
}

/// Starts the original child with a real FUSE handle and network confinement.
///
/// # Errors
/// Preserves launcher errors and refuses an unavailable FUSE device.
pub(super) fn launch_network() -> Result<Launched> {
    launch_mode("worker-network-child")
}

fn launch_mode(mode: &str) -> Result<Launched> {
    if rustix::process::geteuid().as_raw() != 0 || fs::read_dir("/proc/self/task")?.count() != 1 {
        return Err("scoped proof launcher requires one administrative thread".into());
    }
    let setpriv =
        std::env::var_os("TERRANE_WORKER_SETPRIV").ok_or("missing AOS-built fixture launcher")?;
    let (serve, worker) = worker_channel::channel_pair()?;
    let (control, child_control) = worker_channel::channel_pair()?;
    let network = mode == "worker-network-child";
    let output = if network {
        Stdio::from(
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/fuse")?,
        )
    } else {
        Stdio::piped()
    };
    let mut child = Command::new(setpriv)
        .args([
            "--reuid=848",
            "--regid=848",
            "--clear-groups",
            "--bounding-set=-all",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--no-new-privs",
        ])
        .arg(std::env::current_exe()?)
        .arg(mode)
        .stdin(Stdio::from(worker))
        .stderr(Stdio::from(child_control))
        .stdout(output)
        .spawn()?;
    let identity = WorkerIdentity::from_child(&mut child, 848)?;
    let launched = Launched {
        child,
        channel: Some(serve),
        identity: Some(identity),
        control: File::from(control),
        network,
    };

    drop_to_serve()?;
    Ok(launched)
}

/// Irreversibly enters the fixture's capability-free serving identity.
pub(super) fn drop_to_serve() -> Result<()> {
    let last: u32 = fs::read_to_string("/proc/sys/kernel/cap_last_cap")?
        .trim()
        .parse()?;
    if last >= 64 {
        return Err("fixture cannot represent the actual kernel capability set".into());
    }
    for bit in 0..=last {
        thread::remove_capability_from_bounding_set(CapabilitySet::from_bits_retain(1 << bit))?;
    }
    thread::set_keep_capabilities(false)?;
    thread::set_thread_groups(&[Gid::from_raw(844), Gid::from_raw(845)])?;
    let gid = Gid::from_raw(840);
    thread::set_thread_res_gid(gid, gid, gid)?;
    let uid = Uid::from_raw(840);
    thread::set_thread_res_uid(uid, uid, uid)?;
    thread::set_capabilities(
        None,
        CapabilitySets {
            effective: CapabilitySet::empty(),
            permitted: CapabilitySet::empty(),
            inheritable: CapabilitySet::empty(),
        },
    )?;
    thread::set_no_new_privs(true)?;
    super::require_empty_capabilities()?;
    Ok(())
}

pub(super) fn readable(file: impl AsFd) -> io::Result<()> {
    let mut descriptors = [PollFd::new(&file, PollFlags::IN)];
    if poll(
        &mut descriptors,
        Some(&Timespec {
            tv_sec: 5,
            tv_nsec: 0,
        }),
    )? == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "scoped worker wait elapsed",
        ));
    }
    Ok(())
}

impl Launched {
    /// Returns the identifier of the original child, without granting authority.
    pub(super) fn child_id(&self) -> u32 {
        self.child.id()
    }

    /// Binds the original endpoint and child to an actual native exposure.
    ///
    /// # Errors
    /// Refuses a consumed endpoint or identity, or an invalid native binding.
    pub(super) fn bind(&mut self, lease: &NativeExposureLease) -> Result<WorkerChannel> {
        Ok(WorkerChannel::bind(
            self.channel
                .take()
                .ok_or("missing original serve endpoint")?,
            self.identity
                .take()
                .ok_or("missing original child identity")?,
            lease.clone(),
        )?)
    }

    /// Sends public fixture context on the separate private control endpoint.
    ///
    /// # Errors
    /// Preserves control transport errors.
    pub(super) fn send_context(
        &mut self,
        lease: &NativeExposureLease,
        content: [u8; 32],
    ) -> Result<()> {
        let mut bootstrap = lease.id().as_bytes().to_vec();
        bootstrap.extend_from_slice(&lease.generation().to_le_bytes());
        bootstrap.extend_from_slice(&lease.key().root());
        bootstrap.extend_from_slice(&content);
        self.control.write_all(&bootstrap)?;
        Ok(())
    }

    /// Reads one bounded original-child acknowledgment.
    ///
    /// # Errors
    /// Refuses timeout, EOF, non-UTF-8 output or a line exceeding 256 bytes.
    pub(super) fn acknowledgment(&mut self) -> Result<String> {
        let output = self
            .child
            .stdout
            .as_mut()
            .ok_or("missing original child output")?;
        let mut line = Vec::new();
        loop {
            readable(&*output)?;
            let mut byte = [0];
            output.read_exact(&mut byte)?;
            line.push(byte[0]);
            if byte[0] == b'\n' {
                return Ok(String::from_utf8(line)?);
            }
            if line.len() >= 256 {
                return Err("original child acknowledgment exceeds bound".into());
            }
        }
    }
}

/// Runs scoped native grants without enlarging other selectors' async frames.
///
/// # Errors
/// Preserves repository, native owner, process and transport failures and refuses
/// mismatched original descriptors, lost physical protection or a new drain grant.
pub(super) fn run(
    launched: Launched,
    runtime: &tokio::runtime::Runtime,
    owner: &NativeMetadataOwner,
    inputs: &config::Inputs,
) -> Result<()> {
    // Keep this large generic future in its own call frame. Constructing it in
    // main reserves its stack space even when a different selector runs.
    runtime.block_on(Box::pin(verify(launched, owner, inputs)))
}

async fn verify(
    mut launched: Launched,
    owner: &NativeMetadataOwner,
    inputs: &config::Inputs,
) -> Result<()> {
    let fixture = RepositoryFixture::new(&inputs.domain).await?;
    eprintln!("SCOPED_WORKER_STAGE signed-commit");
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
    eprintln!("SCOPED_WORKER_STAGE signed-mapping");
    let deadline = exposure::now()? + 90;
    let lease = owner.retain_surface_exposure(&served, deadline).await?;
    let identity = TERRANE_V1.calculate(IdentityKind::Chunk, BODY)?;
    let descriptor = Descriptor::from_identity(&TERRANE_V1, &identity, BODY)?;
    let publication = owner
        .publish_inline(descriptor, [vec![0], BODY.to_vec()].concat())
        .await?;
    let mut channel = WorkerChannel::bind(
        launched
            .channel
            .take()
            .ok_or("missing original serve endpoint")?,
        launched
            .identity
            .take()
            .ok_or("missing original child identity")?,
        lease.clone(),
    )?;
    for timeout in [Duration::ZERO, Duration::from_secs(301)] {
        if !matches!(channel.receive_bounded(timeout).await,
            Err(error) if error.kind() == io::ErrorKind::InvalidInput)
        {
            return Err("invalid worker deadline reached native request consumption".into());
        }
    }
    receive_cancellation(inputs, &mut launched, &lease).await?;

    // This separate private fixture control socket carries public context only.
    // The worker still authenticates the actual serve UID on every data reply.
    let mut bootstrap = lease.id().as_bytes().to_vec();
    bootstrap.extend_from_slice(&lease.generation().to_le_bytes());
    bootstrap.extend_from_slice(&served.key().root());
    bootstrap.extend_from_slice(identity.digest());
    launched.control.write_all(&bootstrap)?;
    let pending = channel.receive_bounded(Duration::from_secs(10)).await?;
    let selection = fixture
        .repository
        .prepare_root_read(
            &target,
            fixture.authority.token(),
            "sdk",
            exposure::limits(),
        )
        .await?;
    pending.grant_index(owner, &served, selection).await?;
    eprintln!("SCOPED_WORKER_STAGE granted-index");

    let pending = channel.receive_bounded(Duration::from_secs(10)).await?;
    let selection = fixture
        .repository
        .prepare_file_read(
            &View::parse(MAIN)?,
            b"file",
            fixture.authority.token(),
            "sdk",
        )
        .await?;
    pending
        .grant_file(owner, &served, selection, deadline)
        .await?;
    publication.complete_cache_handoff(owner).await?;
    eprintln!("SCOPED_WORKER_STAGE granted-file");

    // The third grant finishes its genuine closing Read while still active.
    // Queue actual draining before its final Send through the original owner.
    let pending = channel.receive_bounded(Duration::from_secs(10)).await?;
    let selection = fixture
        .repository
        .prepare_root_read(
            &target,
            fixture.authority.token(),
            "sdk",
            exposure::limits(),
        )
        .await?;
    worker_channel::native_fixture::scoped::require_queued_drain_refusal(
        pending, owner, &served, selection,
    )
    .await?;
    eprintln!("SCOPED_WORKER_STAGE queued-drain-refused-send");
    println!(
        "PASS original owner queue refuses Send ordered after Drain despite completed scoped Read"
    );
    let before = exposure::snapshot(inputs).await?;
    let policy_path = inputs.root.join("state/cache/records.toml");
    let before_bytes = fs::read(&policy_path)?;
    let mut output = String::new();
    if launched.network {
        readable(&launched.control)?;
        (&mut launched.control)
            .take(256)
            .read_to_string(&mut output)?;
    } else {
        launched
            .child
            .stdout
            .take()
            .ok_or("missing original child output")?
            .take(256)
            .read_to_string(&mut output)?;
    }
    if !launched.child.wait()?.success() {
        return Err("actual scoped worker failed retained-reference checks".into());
    }
    let row = before
        .exposures
        .iter()
        .find(|row| row.id == lease.id())
        .ok_or("scoped worker lost original durable exposure")?;
    let index = row
        .backings
        .iter()
        .find(|row| row.kind == ExposureBackingKind::Index)
        .ok_or("scoped worker lost original index binding")?;
    let file = row
        .backings
        .iter()
        .find(|row| row.kind == ExposureBackingKind::Inline)
        .ok_or("scoped worker lost original inline binding")?;
    let expected = format!(
        "ORIGINAL {} {} {} {}\n",
        index.device, index.inode, file.device, file.inode
    );
    if output != expected
        || fs::read(&policy_path)? != before_bytes
        || row.phase != ExposurePhase::Draining
        || !before.pins.iter().any(|pin| {
            pin.owner == row.pin_owner() && pin.hash == file.hash && pin.expires == i64::MAX as u64
        })
    {
        return Err("scoped Send differs from actual original-inode custody".into());
    }
    println!(
        "PASS actual scoped owner Send grants original signed-root index and sealed file to the original worker; draining denies new grants while retained descriptors and mapping remain readable"
    );
    if launched.network {
        println!(
            "PASS original worker retains checked FUSE descriptor and kernel-enforced Unix-only network boundary through actual scoped grants and draining"
        );
    }
    Ok(())
}

/// Checks abandoned channel handoffs against the original child and real lease.
async fn receive_cancellation(
    inputs: &config::Inputs,
    launched: &mut Launched,
    lease: &NativeExposureLease,
) -> Result<()> {
    use std::{
        future::Future,
        task::{Context, Poll, Waker},
    };

    let policy_path = inputs.root.join("state/cache/records.toml");
    let before = fs::read(&policy_path)?;
    for cancel in [false, true] {
        // These unused endpoints model a launcher abandoning its handoff. No
        // request or peer credentials are synthesized; the child and lease are real.
        let (server, peer) = worker_channel::channel_pair()?;
        let identity = WorkerIdentity::from_child(&mut launched.child, 848)?;
        let mut channel = WorkerChannel::bind(server, identity, lease.clone())?;
        let alias = channel.as_fd().try_clone_to_owned()?;
        let timeout = if cancel {
            Duration::from_secs(5)
        } else {
            Duration::from_millis(20)
        };
        let mut receiving = Box::pin(channel.receive_bounded(timeout));

        if cancel {
            let mut context = Context::from_waker(Waker::noop());
            if !matches!(receiving.as_mut().poll(&mut context), Poll::Pending) {
                return Err("idle worker receipt completed before cancellation".into());
            }
        } else if !matches!(receiving.as_mut().await,
            Err(error) if error.kind() == io::ErrorKind::TimedOut)
        {
            return Err("idle worker receipt failed without its exact deadline".into());
        }
        drop(receiving);

        if !matches!(channel.receive(), Err(error) if error.kind() == io::ErrorKind::BrokenPipe) {
            return Err("cancelled worker receipt retained a usable channel".into());
        }
        let mut bytes = [0; 1];
        if net::recv(&peer, &mut bytes, net::RecvFlags::DONTWAIT)?.0 != 0 {
            return Err("cancelled worker receipt retained a live descriptor alias".into());
        }
        drop(alias);
    }
    if fs::read(&policy_path)? != before {
        return Err("idle worker receipt changed original exposure obligations".into());
    }
    println!(
        "PASS bounded worker receipt times out and cancels abandoned handoffs without changing original exposure policy or retaining live socket aliases"
    );
    Ok(())
}

#[allow(clippy::disallowed_methods)]
pub(super) fn reply(pending: &mut PendingBacking<'_>) -> io::Result<worker_channel::BackingReply> {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match pending.receive() {
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(1));
            }
            result => return result,
        }
    }
}

/// Authenticates the original client using bounded public bootstrap context.
///
/// # Errors
/// Refuses another identity, invalid context, expired waits or transport failure.
pub(super) fn child_context() -> Result<(WorkerClient, [u8; 32], ContentRef)> {
    if rustix::process::geteuid().as_raw() != 848 {
        return Err("scoped child requires its distinct worker identity".into());
    }
    let mut control = File::from(io::stderr().as_fd().try_clone_to_owned()?);
    let mut descriptors = [PollFd::new(&control, PollFlags::IN)];
    if poll(
        &mut descriptors,
        Some(&Timespec {
            tv_sec: 30,
            tv_nsec: 0,
        }),
    )? == 0
    {
        return Err("scoped launcher did not deliver bounded public context".into());
    }
    let mut bootstrap = [0; 104];
    control.read_exact(&mut bootstrap)?;
    let root = bootstrap[40..72].try_into()?;
    let content = ContentRef::Inline(bootstrap[72..104].try_into()?);
    let context = ExposureContext::new(
        std::str::from_utf8(&bootstrap[..32])?,
        u64::from_le_bytes(bootstrap[32..40].try_into()?),
        root,
    )?;
    let client = WorkerClient::bind(io::stdin().as_fd().try_clone_to_owned()?, context, 840)?;
    Ok((client, root, content))
}

/// Checks original scoped backing after the actual channel disconnects.
///
/// # Errors
/// Refuses invalid native context, replies, retained mappings or file contents.
pub(super) fn child() -> Result<()> {
    child_body(false)
}

/// Installs confinement before receiving any scoped backing descriptors.
///
/// # Errors
/// Refuses invalid bootstrap descriptors, confinement or scoped read failures.
pub(super) fn child_network() -> Result<()> {
    let installed = terrane_linux::quota_confinement::install_worker_network(io::stdout().as_fd())?;
    child_body(true)?;
    installed.check_current()?;
    Ok(())
}

fn child_body(network: bool) -> Result<()> {
    let (mut client, _, content) = child_context()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let mapping = runtime.block_on(client.request_index_bounded(65536, Duration::from_secs(10)))?;
    let index_stat = rustix::fs::fstat(&mapping)?;
    let prepared_size = match mapping.index().lookup(b"file").map(|entry| entry.kind()) {
        Some(Kind::File {
            content: selected,
            size,
        }) if selected == content && size == BODY.len() as u64 => size,
        _ => return Err("original scoped index does not select the requested file".into()),
    };
    let received = reply(&mut client.request(RequestedBacking::File {
        path: b"file".to_vec(),
        content,
    })?)?;
    let file_stat = rustix::fs::fstat(&received)?;
    let file = terrane_linux::fuse_read::Backing::from_reply(received, prepared_size, 65536)?;
    if !matches!(reply(&mut client.request(RequestedBacking::Index)?),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied)
    {
        return Err("drained worker received a new descriptor or timed out".into());
    }
    let mut actual = vec![0; BODY.len()];
    if file.read(0, BODY.len() as u32, &mut actual)? != BODY.len()
        || actual != BODY
        || !mapping.index().lookup(b"file").is_some_and(|entry| {
            matches!(entry.kind(), Kind::File { content: selected, size }
                if selected == content && size == BODY.len() as u64)
        })
        || TERRANE_V1.calculate(IdentityKind::Chunk, &actual)?.digest()
            != *match &content {
                ContentRef::Inline(hash) => hash,
                ContentRef::Manifest(_) => return Err("unexpected manifest".into()),
            }
    {
        return Err("draining invalidated original scoped backing".into());
    }
    let report = format!(
        "ORIGINAL {} {} {} {}\n",
        index_stat.st_dev, index_stat.st_ino, file_stat.st_dev, file_stat.st_ino
    );
    if network {
        File::from(io::stderr().as_fd().try_clone_to_owned()?).write_all(report.as_bytes())?;
    } else {
        print!("{report}");
    }
    Ok(())
}
