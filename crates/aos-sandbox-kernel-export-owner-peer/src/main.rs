//! Closed systemd-activated kernel-export owner peer endpoint.
//!
//! C owns every BPF map transition. This service authenticates the exact
//! Storage process and privately remeasures one AOSKGH01 two-FD packet, then
//! closes both descriptors without responding, staging, or releasing a grant.
//! The companion recovery unit runs C's revoke-or-verified-empty check before
//! this executable starts. No Storage sender is wired to this endpoint yet.

use std::error::Error;
use std::path::Path;

use aos_sandbox_kernel_export_owner_peer::deployment::OwnerPublicVerifiers;
use aos_sandbox_kernel_export_owner_peer::peer::receive_closed_handoff;
use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::inherited_fd::claim_systemd_activation_descriptor_range;
use aos_sandbox_linux::seqpacket::{RecordSubjectListener, SeqpacketError};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fs::{Mode, OFlags, openat};

const LISTENER_NAME: &str = "aos-sandbox-kernel-export-ownerd";
const LISTENER_PATH: &str = "/run/aos/kernel-export-owner/control.sock";
const STORAGE_CGROUP: &str = "/sys/fs/cgroup/aos-control.slice/aos-storaged.service";

fn main() {
    if let Err(error) = run() {
        eprintln!("kernel-export owner peer stopped closed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    // The activation table must be claimed before opening any other FD.
    let mut listener = take_listener()?;
    let _public_verifiers = OwnerPublicVerifiers::from_systemd_credentials()?;
    let storage_cgroup = pinned_storage_cgroup()?;

    loop {
        storage_cgroup.validate_current()?;
        let listener_fd = listener.as_fd();
        let mut readiness = [PollFd::new(&listener_fd, PollFlags::IN)];
        if poll(&mut readiness, None)? == 0 {
            continue;
        }
        if !readiness[0].revents().contains(PollFlags::IN) {
            return Err("owner listener entered an unexpected readiness state".into());
        }

        let mut socket = match listener.accept_descriptor_subject() {
            Ok(socket) => socket,
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => continue,
            Err(error) => return Err(Box::new(error)),
        };
        let child = socket.as_fd()?;
        let mut readiness = [PollFd::new(&child, PollFlags::IN)];
        let deadline = Timespec {
            tv_sec: 2,
            tv_nsec: 0,
        };
        if poll(&mut readiness, Some(&deadline))? == 0
            || !readiness[0].revents().contains(PollFlags::IN)
        {
            continue;
        }
        if let Err(error) = receive_closed_handoff(&mut socket, &storage_cgroup) {
            eprintln!("kernel-export owner peer rejected closed handoff: {error}");
        }
        // The bounded readback owns no transferred FD or map capability.
    }
}

fn take_listener() -> Result<RecordSubjectListener, Box<dyn Error>> {
    let current_pid = u32::try_from(rustix::process::getpid().as_raw_nonzero().get())?;
    if environment_u32("LISTEN_PID")? != current_pid
        || environment_u32("LISTEN_FDS")? != 1
        || std::env::var("LISTEN_FDNAMES")? != LISTENER_NAME
    {
        return Err("owner systemd activation identity differs".into());
    }

    // SAFETY: this is single-threaded process startup before any other FD is
    // opened or represented by a Rust owner. systemd assigned the sole FD 3
    // under the exact PID/count/name contract just checked.
    let mut descriptors = unsafe { claim_systemd_activation_descriptor_range(0, 1)? }
        .into_descriptors()
        .into_iter();
    let fd = descriptors
        .next()
        .ok_or("owner systemd listener descriptor is absent")?;
    let listener = RecordSubjectListener::from_owned(fd)?;
    listener.require_local_filesystem_path(Path::new(LISTENER_PATH))?;
    Ok(listener)
}

fn pinned_storage_cgroup() -> Result<RetainedCgroupAnchor, Box<dyn Error>> {
    let fd = openat(
        rustix::fs::CWD,
        Path::new(STORAGE_CGROUP),
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    let root = CgroupV2Root::from_owned(fd)?;
    let anchor = root.resolve(Path::new("."))?;
    anchor.validate_current()?;
    Ok(anchor)
}

fn environment_u32(name: &'static str) -> Result<u32, Box<dyn Error>> {
    let value = std::env::var(name)?;
    Ok(value.parse()?)
}
