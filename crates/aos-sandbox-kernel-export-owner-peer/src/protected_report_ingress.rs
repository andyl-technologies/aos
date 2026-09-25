//! Fixed, nonauthorizing ingress for a future C-owner PREPARED reporter.
//!
//! The one-shot deployment is unavailable until the reporter's exact descriptor
//! origin and enforcing MAC custody are supplied. This type pins the intended
//! cgroup and checks the listener route, but does not claim that root
//! credentials and mode bits exclude a privileged delegated writer. A
//! successful receive remains a closed point observation.

use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::path::Path;

use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::inherited_fd::claim_systemd_activation_descriptor_range;
use aos_sandbox_linux::seqpacket::RecordSubjectListener;
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fs::{Mode, OFlags, openat};

use crate::OwnerPeerError;
use crate::handoff::DenyStageHandoff;
use crate::prepared_report_carrier::{
    ClosedPreparedReportReadback, REPORT_SOCKET_PATH, receive_closed_prepared_report,
};

const REPORT_LISTENER_NAME: &str = "aos-sandbox-kernel-export-owner-prepared-report";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const REPORTER_CGROUP: &str = "aos-control.slice/aos-sandbox-kernel-export-owner-reporter.service";
const ROUTE_ANCESTORS: [&str; 4] = ["/", "/run", "/run/aos", "/run/aos/kernel-export-owner"];

/// Retains the exact proposed reporter cgroup and systemd report listener.
///
/// This is a transport and physical-readback boundary, not a Stage, ACTIVE,
/// Apply, or sender-MAC authorization. The future deployment must independently
/// protect both the reporter and socket from privileged delegated writers.
pub struct ProtectedPreparedReportIngress {
    listener: RecordSubjectListener,
    reporter_cgroup: RetainedCgroupAnchor,
}

impl ProtectedPreparedReportIngress {
    /// Claims the sole named activation FD and pins the fixed reporter scope.
    ///
    /// Call at single-threaded process startup before opening any other FD.
    /// The listener must already have credential and pidfd reporting enabled
    /// before systemd exposes its pathname to senders.
    ///
    /// # Errors
    ///
    /// Rejects any other activation table, listener path or options, route
    /// owner or mode, non-cgroup filesystem, absent or redirected reporter
    /// service cgroup, and failed kernel readback.
    pub fn from_systemd_activation() -> Result<Self, OwnerPeerError> {
        require_activation_identity(
            std::env::var("LISTEN_PID").ok().as_deref(),
            std::env::var("LISTEN_FDS").ok().as_deref(),
            std::env::var("LISTEN_FDNAMES").ok().as_deref(),
            std::process::id(),
        )?;

        // SAFETY: startup is single-threaded, the exact one-FD activation
        // table was checked, and FD 3 has no existing Rust owner.
        let descriptors = unsafe { claim_systemd_activation_descriptor_range(0, 1) }
            .map_err(|_| OwnerPeerError::Physical)?;
        let listener_fd = descriptors
            .into_descriptors()
            .into_iter()
            .next()
            .ok_or(OwnerPeerError::Physical)?;
        let listener =
            RecordSubjectListener::from_owned(listener_fd).map_err(|_| OwnerPeerError::Physical)?;

        validate_listener_route(
            &listener,
            Path::new(REPORT_SOCKET_PATH),
            0,
            0,
            &ROUTE_ANCESTORS,
        )?;
        let reporter_cgroup =
            pin_reporter_cgroup_at(Path::new(CGROUP_ROOT), Path::new(REPORTER_CGROUP))?;
        Ok(Self {
            listener,
            reporter_cgroup,
        })
    }

    /// Accepts one packet and returns only its closed PREPARED observation.
    ///
    /// # Errors
    ///
    /// Rejects changed route or cgroup custody, a missing or unauthenticated
    /// packet, transferred FDs, and any invalid or stale map observation.
    pub fn receive_once(
        &mut self,
        handoff: &DenyStageHandoff,
    ) -> Result<ClosedPreparedReportReadback, OwnerPeerError> {
        self.reporter_cgroup
            .validate_current()
            .map_err(|_| OwnerPeerError::Physical)?;
        validate_listener_route(
            &self.listener,
            Path::new(REPORT_SOCKET_PATH),
            0,
            0,
            &ROUTE_ANCESTORS,
        )?;

        let mut socket = self
            .listener
            .accept_descriptor_subject()
            .map_err(|error| OwnerPeerError::Transport(error.to_string()))?;
        validate_listener_route(
            &self.listener,
            Path::new(REPORT_SOCKET_PATH),
            0,
            0,
            &ROUTE_ANCESTORS,
        )?;
        let child = socket
            .as_fd()
            .map_err(|error| OwnerPeerError::Transport(error.to_string()))?;
        let mut readiness = [PollFd::new(&child, PollFlags::IN)];
        let deadline = Timespec {
            tv_sec: 1,
            tv_nsec: 0,
        };
        if poll(&mut readiness, Some(&deadline)).map_err(|_| OwnerPeerError::Physical)? == 0
            || !readiness[0].revents().contains(PollFlags::IN)
        {
            return Err(OwnerPeerError::Physical);
        }
        let readback = receive_closed_prepared_report(&mut socket, &self.reporter_cgroup, handoff)?;
        self.reporter_cgroup
            .validate_current()
            .map_err(|_| OwnerPeerError::Physical)?;
        validate_listener_route(
            &self.listener,
            Path::new(REPORT_SOCKET_PATH),
            0,
            0,
            &ROUTE_ANCESTORS,
        )?;
        Ok(readback)
    }
}

fn require_activation_identity(
    pid: Option<&str>,
    count: Option<&str>,
    names: Option<&str>,
    current_pid: u32,
) -> Result<(), OwnerPeerError> {
    let expected_pid = current_pid.to_string();
    if pid != Some(expected_pid.as_str())
        || count != Some("1")
        || names != Some(REPORT_LISTENER_NAME)
    {
        return Err(OwnerPeerError::Physical);
    }
    Ok(())
}

fn pin_reporter_cgroup_at(
    root_path: &Path,
    relative: &Path,
) -> Result<RetainedCgroupAnchor, OwnerPeerError> {
    if relative != Path::new(REPORTER_CGROUP) {
        return Err(OwnerPeerError::Physical);
    }

    let fd = openat(
        rustix::fs::CWD,
        root_path,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| OwnerPeerError::Physical)?;
    let root = CgroupV2Root::from_owned(fd).map_err(|_| OwnerPeerError::Physical)?;
    let anchor = root
        .resolve(relative)
        .map_err(|_| OwnerPeerError::Physical)?;
    anchor
        .validate_current()
        .map_err(|_| OwnerPeerError::Physical)?;
    Ok(anchor)
}

fn validate_listener_route(
    listener: &RecordSubjectListener,
    socket_path: &Path,
    owner_uid: u32,
    owner_gid: u32,
    ancestors: &[&str],
) -> Result<(), OwnerPeerError> {
    listener
        .validate_current()
        .and_then(|()| listener.require_local_filesystem_path(socket_path))
        .map_err(|_| OwnerPeerError::Physical)?;

    for (index, ancestor) in ancestors.iter().enumerate() {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(|_| OwnerPeerError::Physical)?;
        let is_private_directory = index + 1 == ancestors.len();
        if !metadata.file_type().is_dir()
            || metadata.uid() != owner_uid
            || metadata.gid() != owner_gid
            || is_private_directory && metadata.mode() & 0o7777 != 0o700
            || metadata.mode() & 0o022 != 0
        {
            return Err(OwnerPeerError::Physical);
        }
    }

    let socket = std::fs::symlink_metadata(socket_path).map_err(|_| OwnerPeerError::Physical)?;
    if !socket.file_type().is_socket()
        || socket.uid() != owner_uid
        || socket.gid() != owner_gid
        || socket.mode() & 0o7777 != 0o600
    {
        return Err(OwnerPeerError::Physical);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    #[test]
    fn activation_identity_rejects_foreign_and_ambiguous_tables() {
        let pid = std::process::id();
        let correct_pid = pid.to_string();
        assert!(
            require_activation_identity(
                Some(&correct_pid),
                Some("1"),
                Some(REPORT_LISTENER_NAME),
                pid
            )
            .is_ok()
        );
        for (candidate_pid, count, name) in [
            (None, Some("1"), Some(REPORT_LISTENER_NAME)),
            (Some("0"), Some("1"), Some(REPORT_LISTENER_NAME)),
            (
                Some(correct_pid.as_str()),
                Some("2"),
                Some(REPORT_LISTENER_NAME),
            ),
            (Some(correct_pid.as_str()), Some("1"), Some("control")),
        ] {
            assert!(require_activation_identity(candidate_pid, count, name, pid).is_err());
        }
    }

    #[test]
    fn route_rejects_hostile_directory_socket_and_listener() {
        let base = tempfile::tempdir().unwrap();
        let private = base.path().join("private");
        std::fs::create_dir(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket_path = private.join("report.sock");
        let listener = RecordSubjectListener::bind(&socket_path, 1).unwrap();
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let uid = rustix::process::getuid().as_raw();
        let gid = rustix::process::getgid().as_raw();
        let base_name = base.path().to_str().unwrap();
        let private_name = private.to_str().unwrap();
        let ancestors = [base_name, private_name];

        assert!(validate_listener_route(&listener, &socket_path, uid, gid, &ancestors).is_ok());
        assert!(
            validate_listener_route(&listener, &private.join("wrong.sock"), uid, gid, &ancestors)
                .is_err()
        );
        assert!(
            validate_listener_route(
                &listener,
                &socket_path,
                uid.wrapping_add(1),
                gid,
                &ancestors
            )
            .is_err()
        );

        let redirected_directory = base.path().join("redirected");
        std::os::unix::fs::symlink(&private, &redirected_directory).unwrap();
        let redirected_name = redirected_directory.to_str().unwrap();
        assert!(
            validate_listener_route(
                &listener,
                &socket_path,
                uid,
                gid,
                &[base_name, redirected_name]
            )
            .is_err()
        );

        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(validate_listener_route(&listener, &socket_path, uid, gid, &ancestors).is_err());
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();

        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(validate_listener_route(&listener, &socket_path, uid, gid, &ancestors).is_err());
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        std::fs::remove_file(&socket_path).unwrap();
        std::os::unix::fs::symlink(private.join("elsewhere"), &socket_path).unwrap();
        assert!(validate_listener_route(&listener, &socket_path, uid, gid, &ancestors).is_err());
    }

    #[test]
    fn ordinary_or_redirected_cgroup_roots_fail_closed() {
        let base = tempfile::tempdir().unwrap();
        assert!(pin_reporter_cgroup_at(base.path(), Path::new(REPORTER_CGROUP)).is_err());
        assert!(pin_reporter_cgroup_at(base.path(), Path::new("../aos-storaged.service")).is_err());
        assert!(
            pin_reporter_cgroup_at(
                base.path(),
                Path::new("aos-control.slice/aos-storaged.service")
            )
            .is_err()
        );

        let symlink = base.path().join("cgroup");
        std::os::unix::fs::symlink("/sys/fs/cgroup", &symlink).unwrap();
        assert!(pin_reporter_cgroup_at(&symlink, Path::new(REPORTER_CGROUP)).is_err());
        assert_eq!(
            REPORTER_CGROUP,
            "aos-control.slice/aos-sandbox-kernel-export-owner-reporter.service"
        );
    }
}
