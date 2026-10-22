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
    io::{self, Read, Write},
    os::fd::AsFd,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use terrane_linux::{
    host_cache::{NativeExposureReconciliation, NativeMetadataOwner},
    maintenance_channel::{
        self, MaintenanceClient, MaintenanceListener, MaintenanceRoles, MaintenanceServer,
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
        exposure::verify_index_closure(owner, inputs, Some(launched)).await?;
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
        }
        Ok(())
    }))
}

impl Launched {
    pub(super) async fn reconcile(
        &mut self,
        owner: &NativeMetadataOwner,
    ) -> Result<NativeExposureReconciliation> {
        self.control.write_all(&[1])?;
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
    loop {
        wait_readable(&control, 25)?;
        let mut operation = [0];
        control.read_exact(&mut operation)?;
        if operation == [0] {
            return Ok(());
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
        if client.is_none() {
            client = Some(MaintenanceClient::connect(&listener_path()?, ROLES)?);
        }
        let mut pending = client
            .as_mut()
            .ok_or("GC channel absent")?
            .reconcile_draining()?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let report = loop {
            if let Some(report) = pending.try_receive()? {
                break report;
            }
            if Instant::now() >= deadline {
                return Err("GC reconciliation reply exceeded fixture deadline".into());
            }
            std::thread::sleep(Duration::from_millis(1));
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
