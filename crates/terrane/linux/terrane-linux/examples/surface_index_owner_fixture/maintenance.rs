//! Joins a private GC channel to the genuine serving owner in a native guest.
//!
//! Only the fixture launcher starts administratively. GC uses UID 843 and cannot
//! open the serving role's private snapshot. The parent drops all privileges to
//! UID 840 before ordinary native preparation, confinement and owner startup.

use super::{Result, config, exposure, scoped_worker};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    net::{self, Shutdown},
};
use std::{
    fs::{self, File},
    future::Future,
    io::{self, Read, Write},
    os::fd::AsFd,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
    pin::Pin,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use terrane_linux::{
    host_cache::{NativeExposureReconciliation, NativeMetadataOwner},
    maintenance_channel::{
        self, MaintenanceClient, MaintenanceLimits, MaintenanceListener, MaintenanceRoles,
        MaintenanceServer,
    },
};

const ROLES: MaintenanceRoles = MaintenanceRoles {
    serve_uid: 840,
    gc_uid: 843,
};

pub(super) struct Launched {
    child: Child,
    server: Option<MaintenanceServer>,
    listener: Option<MaintenanceListener>,
    listener_path: Option<PathBuf>,
    listener_inode: Option<(u64, u64)>,
    runtime_service: bool,
    control: File,
}

impl Drop for Launched {
    fn drop(&mut self) {
        let _ = self.control.write_all(&[0]);
        let _ = net::shutdown(&self.control, Shutdown::Both);
        // The unprivileged parent cannot signal another UID. The child has
        // finite waits and exits on control disconnection, also on test failure.
        let _ = self.child.try_wait();
    }
}

pub(super) fn launch(listener: bool) -> Result<Launched> {
    if rustix::process::geteuid().as_raw() != 0 || fs::read_dir("/proc/self/task")?.count() != 1 {
        return Err("maintenance fixture requires one administrative launch thread".into());
    }
    let setpriv =
        std::env::var_os("TERRANE_WORKER_SETPRIV").ok_or("missing AOS-built fixture launcher")?;
    let (serve, gc) = if listener {
        (None, Stdio::null())
    } else {
        let (serve, gc) = maintenance_channel::channel_pair()?;
        (Some(serve), Stdio::from(gc))
    };
    let (control, child_control) = maintenance_channel::channel_pair()?;
    let child = Command::new(setpriv)
        .args([
            "--reuid=843",
            "--regid=843",
            "--clear-groups",
            "--bounding-set=-all",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--no-new-privs",
        ])
        .arg(std::env::current_exe()?)
        .arg(if listener {
            "maintenance-listener-child"
        } else {
            "maintenance-child"
        })
        .stdin(gc)
        .stderr(Stdio::from(child_control))
        .stdout(Stdio::null())
        .spawn()?;
    scoped_worker::drop_to_serve()?;
    let (listener, listener_path, listener_inode) = if listener {
        let path = listener_path()?;
        let listener = MaintenanceListener::bind(&path, ROLES)?;
        verify_listener_refusals(&listener, &path)?;
        let metadata = fs::symlink_metadata(&path)?;
        (
            Some(listener),
            Some(path),
            Some((metadata.dev(), metadata.ino())),
        )
    } else {
        (None, None, None)
    };
    Ok(Launched {
        child,
        server: serve
            .map(|socket| MaintenanceServer::bind(socket, ROLES))
            .transpose()?,
        listener,
        listener_path,
        listener_inode,
        runtime_service: false,
        control: File::from(control),
    })
}

/// Keeps this future in its own boxed call frame, outside fixture main.
pub(super) fn run(
    launched: &mut Launched,
    runtime: &tokio::runtime::Runtime,
    owner: &NativeMetadataOwner,
    inputs: &config::Inputs,
) -> Result<()> {
    runtime.block_on(Box::pin(async {
        if let Some(listener) = launched.listener.take() {
            launched.runtime_service = true;
            let policy = inputs.root.join("state/cache/records.toml");
            let before = fs::read(&policy)?;
            with_service(
                &listener,
                owner,
                MaintenanceLimits {
                    max_connections: 1,
                    max_requests: 1,
                    connection_timeout: Duration::from_secs(2),
                    request_timeout: Duration::from_millis(100),
                },
                launched.expire_idle(),
            ).await?;
            if fs::read(&policy)? != before {
                return Err("idle GC connection changed actual owner policy".into());
            }
            println!("PASS bounded maintenance runtime expires actual idle GC connection without changing owner policy");
            launched.control.write_all(&[4])?;
            if launched.receive_packet::<1>().await? != [4] {
                return Err("GC request timeout acknowledgment differs".into());
            }
            let expired = listener.accept()?.ok_or("timed-out GC connection absent")?;
            drop(expired);
            if fs::read(&policy)? != before {
                return Err("unserved GC request changed actual owner policy".into());
            }
            println!("PASS bounded GC client times out against actual unserved connection without changing owner policy");
            with_service(
                &listener,
                owner,
                MaintenanceLimits {
                    max_connections: 1,
                    max_requests: 64,
                    connection_timeout: Duration::from_secs(30),
                    request_timeout: Duration::from_secs(20),
                },
                index_closure(owner, inputs, launched),
            ).await?;
        } else {
            index_closure(owner, inputs, launched).await?;
        }
        launched.control.write_all(&[0])?;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(status) = launched.child.try_wait()? {
                    if !status.success() {
                        return Err(io::Error::other("actual GC fixture failed"));
                    }
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await??;
        println!(
            "PASS distinct capability-free GC requests original-owner closure without opening private cache state; retained mappings and unrelated obligations survive until authenticated final unmap"
        );
        if let Some(path) = &launched.listener_path {
            let metadata = fs::symlink_metadata(path)?;
            if Some((metadata.dev(), metadata.ino())) != launched.listener_inode
                || metadata.mode() & 0o7777 != 0o660
                || metadata.uid() != ROLES.serve_uid
                || metadata.gid() != ROLES.gc_uid
            {
                return Err("maintenance listener lost its original socket custody".into());
            }
            println!(
                "PASS protected GC listener preserves its original mode-0660 inode and refuses unsafe ancestors, existing names and wrong-role connections"
            );
            println!(
                "PASS bounded maintenance runtime serves actual original-owner reconciliation and shuts down without replacing its protected listener"
            );
            println!("PASS bounded GC client receives actual original-owner closure reports through kernel readiness");
        }
        Ok(())
    }))
}

// Keep the large closure proof out of the service join's nested future frames.
fn index_closure<'owner>(
    owner: &'owner NativeMetadataOwner,
    inputs: &'owner config::Inputs,
    launched: &'owner mut Launched,
) -> Pin<Box<dyn Future<Output = Result<()>> + 'owner>> {
    Box::pin(exposure::verify_index_closure(
        owner,
        inputs,
        Some(launched),
    ))
}

impl Launched {
    pub(super) async fn reconcile(
        &mut self,
        owner: &NativeMetadataOwner,
    ) -> Result<NativeExposureReconciliation> {
        self.control.write_all(&[1])?;
        if self.runtime_service {
            return self.receive_runtime_report().await;
        }
        let report = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if self.server.is_none() {
                    let listener = self
                        .listener
                        .as_ref()
                        .ok_or_else(|| io::Error::other("GC listener absent"))?;
                    self.server = listener.accept()?;
                }
                if let Some(server) = &mut self.server
                    && let Some(report) = server.process_next(owner).await?
                {
                    return Ok::<_, io::Error>(report);
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await??;
        wait_readable(&self.control, 5)?;
        let mut packet = [0; 24];
        self.control.read_exact(&mut packet)?;
        let mut counts = [0_u64; 3];
        for (value, bytes) in counts.iter_mut().zip(packet.as_chunks::<8>().0) {
            *value = u64::from_le_bytes(*bytes);
        }
        if counts
            != [
                u64::try_from(report.checked)?,
                u64::try_from(report.completed)?,
                u64::try_from(report.blocked)?,
            ]
        {
            return Err("GC received another original-owner reconciliation result".into());
        }
        Ok(report)
    }

    async fn receive_runtime_report(&self) -> Result<NativeExposureReconciliation> {
        let packet = self.receive_packet::<24>().await?;
        let mut counts = [0_usize; 3];
        for (target, bytes) in counts.iter_mut().zip(packet.as_chunks::<8>().0) {
            *target = usize::try_from(u64::from_le_bytes(*bytes))?;
        }

        // Counts are observations returned by the actual distinct GC client,
        // not closure evidence. The existing exposure controls check each exact
        // transition against native mappings and the original durable policy.
        Ok(NativeExposureReconciliation {
            checked: counts[0],
            completed: counts[1],
            blocked: counts[2],
        })
    }

    async fn expire_idle(&mut self) -> Result<()> {
        self.control.write_all(&[2])?;
        if self.receive_packet::<1>().await? != [2] {
            return Err("GC idle connection acknowledgment differs".into());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
        self.control.write_all(&[3])?;
        if self.receive_packet::<1>().await? != [3] {
            return Err("GC idle expiry acknowledgment differs".into());
        }
        Ok(())
    }

    async fn receive_packet<const N: usize>(&self) -> Result<[u8; N]> {
        let mut packet = [0; N];
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match net::recv(&self.control, &mut packet, net::RecvFlags::DONTWAIT) {
                    Ok((length, _)) if length == N => return Ok::<_, io::Error>(()),
                    Ok(_) => return Err(io::Error::other("GC runtime report length differs")),
                    Err(error) if error == rustix::io::Errno::WOULDBLOCK => {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        })
        .await??;
        Ok(packet)
    }
}

async fn with_service<T>(
    listener: &MaintenanceListener,
    owner: &NativeMetadataOwner,
    limits: MaintenanceLimits,
    controls: impl Future<Output = Result<T>>,
) -> Result<T> {
    let (shutdown, signal) = tokio::sync::oneshot::channel();
    let controls = async {
        let result = controls.await;
        let _ = shutdown.send(());
        result
    };
    let serving = async {
        listener
            .serve_until(owner, limits, async {
                let _ = signal.await;
            })
            .await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (result, ()) = tokio::try_join!(controls, serving)?;
    Ok(result)
}

// This native-only deadline bounds transport waits and never enters policy state.
#[allow(clippy::disallowed_methods)]
pub(super) fn child(listener: bool) -> Result<()> {
    if rustix::process::geteuid().as_raw() != ROLES.gc_uid {
        return Err("maintenance child requires actual GC identity".into());
    }
    let status = fs::read_to_string("/proc/self/status")?;
    for field in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        if !status
            .lines()
            .any(|line| line == format!("{field}:\t0000000000000000"))
        {
            return Err("GC child retains native capabilities".into());
        }
    }
    let mut client = if listener {
        None
    } else {
        let endpoint = io::stdin().as_fd().try_clone_to_owned()?;
        Some(MaintenanceClient::bind(endpoint, ROLES)?)
    };
    let mut control = File::from(io::stderr().as_fd().try_clone_to_owned()?);
    let mut idle = None;
    let runtime = listener
        .then(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
        })
        .transpose()?;
    loop {
        wait_readable(&control, 25)?;
        let mut operation = [0];
        control.read_exact(&mut operation)?;
        if operation == [0] {
            return Ok(());
        }
        if listener && operation == [2] {
            idle = Some(MaintenanceClient::connect(&listener_path()?, ROLES)?);
            control.write_all(&[2])?;
            continue;
        }
        if listener && operation == [3] {
            let mut idle = idle.take().ok_or("GC idle connection absent")?;
            if !matches!(idle.reconcile_draining(), Err(error) if error.kind() == io::ErrorKind::BrokenPipe)
            {
                return Err("actual idle GC connection survived its deadline".into());
            }
            control.write_all(&[3])?;
            continue;
        }
        if listener && operation == [4] {
            let connection = MaintenanceClient::connect(&listener_path()?, ROLES)?;
            let result = runtime
                .as_ref()
                .ok_or("GC client runtime absent")?
                .block_on(connection.reconcile_draining_once(Duration::from_millis(100)));
            match result {
                Err(error) if error.kind() == io::ErrorKind::TimedOut => {}
                Err(error) => return Err(error.into()),
                Ok(_) => return Err("unserved native GC request succeeded".into()),
            }
            control.write_all(&[4])?;
            continue;
        }
        if operation != [1] {
            return Err("invalid fixture maintenance operation".into());
        }
        let private = config::Inputs::load()?
            .root
            .join("state/cache/records.toml");
        if !matches!(File::open(private), Err(error) if error.kind() == io::ErrorKind::PermissionDenied)
        {
            return Err("GC could open serve-private cache state".into());
        }
        let report = if let Some(runtime) = &runtime {
            let connection = MaintenanceClient::connect(&listener_path()?, ROLES)?;
            runtime.block_on(connection.reconcile_draining_once(Duration::from_secs(5)))?
        } else {
            let mut pending = client
                .as_mut()
                .ok_or("GC channel absent")?
                .reconcile_draining()?;
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if let Some(report) = pending.try_receive()? {
                    break report;
                }
                if Instant::now() >= deadline {
                    return Err("GC reconciliation reply exceeded fixture deadline".into());
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        };
        let mut packet = [0; 24];
        for (target, value) in packet.as_chunks_mut::<8>().0.iter_mut().zip([
            u64::try_from(report.checked)?,
            u64::try_from(report.completed)?,
            u64::try_from(report.blocked)?,
        ]) {
            target.copy_from_slice(&value.to_le_bytes());
        }
        control.write_all(&packet)?;
    }
}

fn listener_path() -> Result<PathBuf> {
    Ok(std::env::var_os("TERRANE_MAINTENANCE_SOCKET")
        .ok_or("missing explicit fixture maintenance listener path")?
        .into())
}

fn verify_listener_refusals(listener: &MaintenanceListener, path: &std::path::Path) -> Result<()> {
    if listener.accept()?.is_some() || MaintenanceListener::bind(path, ROLES).is_ok() {
        return Err(
            "maintenance listener replaced an existing name or accepted an absent peer".into(),
        );
    }
    let socket = net::socket_with(
        net::AddressFamily::UNIX,
        net::SocketType::SEQPACKET,
        net::SocketFlags::CLOEXEC,
        None,
    )?;
    net::connect(&socket, &net::SocketAddrUnix::new(path)?)?;
    if !matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::PermissionDenied) {
        return Err("maintenance listener admitted serve as the GC role".into());
    }

    let parent = path.parent().ok_or("maintenance fixture parent absent")?;
    let writable = parent.join("unprotected");
    fs::create_dir(&writable)?;
    fs::set_permissions(&writable, fs::Permissions::from_mode(0o770))?;
    let refused = MaintenanceListener::bind(&writable.join("refused.sock"), ROLES).is_err();
    let untouched = fs::read_dir(&writable)?.next().is_none();
    fs::remove_dir(&writable)?;
    if !refused || !untouched {
        return Err("maintenance listener mutated a group-writable ancestor".into());
    }
    let alias = parent.join("alias");
    std::os::unix::fs::symlink(parent, &alias)?;
    let refused = MaintenanceListener::bind(&alias.join("refused.sock"), ROLES).is_err();
    fs::remove_file(alias)?;
    if !refused {
        return Err("maintenance listener traversed a symlink ancestor".into());
    }
    Ok(())
}

fn wait_readable(file: impl AsFd, seconds: i64) -> io::Result<()> {
    let mut descriptors = [PollFd::new(&file, PollFlags::IN)];
    if poll(
        &mut descriptors,
        Some(&Timespec {
            tv_sec: seconds,
            tv_nsec: 0,
        }),
    )? == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "GC fixture wait elapsed",
        ));
    }
    Ok(())
}
