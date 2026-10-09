//! One-shot, read-only carrier for a C-owner PREPARED map observation.
//!
//! The fixed report route is separate from Storage's three-FD handoff route.
//! Its listener must be a protected `RecordSubjectListener`, configured before
//! connection enqueue. An independently pinned report-service cgroup, root
//! credentials, and matching live connection/record pidfds correlate the
//! unsigned `AOSKPR01` bytes with one exact connection establisher. A
//! privileged delegated writer could nominate that subject, so protected
//! sender/socket custody is also mandatory. No report sender service or
//! protected listener is deployed, and no point observation grants Stage,
//! ACTIVE, FD release, or Apply authority.

use std::path::Path;

use aos_sandbox_linux::cgroup::RetainedCgroupAnchor;
use aos_sandbox_linux::pidfd::PidFdInfo;
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_linux::seqpacket::{ConnectionPeerIdentity, KernelAuthorizedRecordSubject};

use crate::OwnerPeerError;
use crate::handoff::DenyStageHandoff;
use crate::peer::{verify_root_peer_in_exact_cgroup, verify_root_record_in_exact_cgroup};
use crate::prepared_map_report::{PreparedMapReport, REPORT_BYTES};

/// Fixed, separate endpoint reserved for the privileged C-owner report process.
pub const REPORT_SOCKET_PATH: &str = "/run/aos/kernel-export-owner/prepared-report.sock";

/// Retains only the checked point observation after the channel is closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClosedPreparedReportReadback {
    report: PreparedMapReport,
    connection_process: PidFdInfo,
}

impl ClosedPreparedReportReadback {
    /// Returns the canonical recent PREPARED map tuple observation.
    #[must_use]
    pub const fn report(&self) -> PreparedMapReport {
        self.report
    }

    /// Returns the exact live connection establisher snapshot at reception.
    #[must_use]
    pub const fn connection_process(&self) -> PidFdInfo {
        self.connection_process
    }
}

/// Receives one report on the exact root report route and closes the channel.
///
/// The caller must independently pin the C reporter's exact protected service
/// cgroup and accept `socket` from a `RecordSubjectListener` on the fixed
/// endpoint. Privileged delegated writers must be excluded through separate
/// MAC and socket custody; pidfd subject equality alone cannot exclude them.
/// Neither an arbitrary root process nor the Storage route qualifies.
/// Even an authenticated report is a point-in-time observation, not a held
/// map/Storage currentness barrier or a grant authorization.
///
/// # Errors
///
/// Rejects a different local route, changed or untrusted report process,
/// malformed ancillary data, any transferred FD, an invalid map tuple, or a
/// stale/future kernel-clock observation. The channel closes on every outcome.
pub fn receive_closed_prepared_report(
    socket: &mut DescriptorSubjectSocket,
    report_cgroup: &RetainedCgroupAnchor,
    handoff: &DenyStageHandoff,
) -> Result<ClosedPreparedReportReadback, OwnerPeerError> {
    let result = receive_on_route(
        socket,
        Path::new(REPORT_SOCKET_PATH),
        handoff,
        |peer| verify_root_peer_in_exact_cgroup(report_cgroup, peer),
        |before, peer, subject| {
            verify_root_record_in_exact_cgroup(report_cgroup, before, peer, subject)
        },
    );
    socket.close();
    result
}

fn receive_on_route(
    socket: &mut DescriptorSubjectSocket,
    route: &Path,
    handoff: &DenyStageHandoff,
    verify_peer: impl Fn(&ConnectionPeerIdentity) -> Result<PidFdInfo, OwnerPeerError>,
    verify_record: impl Fn(
        PidFdInfo,
        &ConnectionPeerIdentity,
        &KernelAuthorizedRecordSubject,
    ) -> Result<(), OwnerPeerError>,
) -> Result<ClosedPreparedReportReadback, OwnerPeerError> {
    socket
        .require_local_filesystem_path(route)
        .map_err(|error| OwnerPeerError::Transport(error.to_string()))?;
    let before = verify_peer(socket.peer())?;
    let record = socket
        .receive(REPORT_BYTES, 0)
        .map_err(|error| OwnerPeerError::Transport(error.to_string()))?;
    let record = socket
        .bind_received(record)
        .map_err(|error| OwnerPeerError::Transport(error.to_string()))?;
    verify_record(before, record.peer(), record.subject())?;

    let report = PreparedMapReport::parse_current(record.payload(), handoff)?;
    verify_record(before, record.peer(), record.subject())?;
    Ok(ClosedPreparedReportReadback {
        report,
        connection_process: before,
    })
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd as _;

    use aos_sandbox_linux::seqpacket::RecordSubjectListener;
    use rustix::fs::{Mode, OFlags, open};

    use super::*;
    use crate::origin::tests::fixture;

    fn report_frame() -> (DenyStageHandoff, [u8; REPORT_BYTES]) {
        let source = fixture();
        let handoff = DenyStageHandoff::parse(&source.handoff).unwrap();
        let now = aos_sandbox_linux::seqpacket::bounded::boottime().unwrap();
        let mut report = [0_u8; REPORT_BYTES];
        report[..8].copy_from_slice(b"AOSKPR01");
        report[8..10].copy_from_slice(&1_u16.to_be_bytes());
        report[16..32].copy_from_slice(&handoff.boot_id());
        report[32..40].copy_from_slice(&handoff.clone_mount_id().to_be_bytes());
        report[40..48].copy_from_slice(&1_u64.to_be_bytes());
        let (device, inode) = handoff.clone_root();
        report[48..56].copy_from_slice(&device.to_be_bytes());
        report[56..64].copy_from_slice(&inode.to_be_bytes());
        report[64..72].copy_from_slice(&handoff.cgroup_id().to_be_bytes());
        report[72..104].copy_from_slice(&handoff.handoff_id());
        report[136..140].copy_from_slice(&3_u32.to_be_bytes());
        report[140..144].copy_from_slice(&1_u32.to_be_bytes());
        report[144..152].copy_from_slice(&now.to_be_bytes());
        (handoff, report)
    }

    fn exchange(
        payload: &[u8],
        send_fd: bool,
        expected_route: bool,
        accept_subject: bool,
    ) -> Result<ClosedPreparedReportReadback, OwnerPeerError> {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("report.sock");
        let mut listener = RecordSubjectListener::bind(&path, 1).unwrap();
        let mut sender = DescriptorSubjectSocket::connect(&path).unwrap();
        if send_fd {
            let descriptor = open(Path::new("Cargo.toml"), OFlags::RDONLY, Mode::empty()).unwrap();
            sender
                .send_with_descriptors(payload, &[descriptor.as_fd()])
                .unwrap();
        } else {
            sender.send(payload).unwrap();
        }
        let mut receiver = listener.accept_descriptor_subject().unwrap();
        let (handoff, _) = report_frame();
        let route = if expected_route {
            path.as_path()
        } else {
            directory.path()
        };
        receive_on_route(
            &mut receiver,
            route,
            &handoff,
            |peer| Ok(peer.initial_info()),
            |before, peer, subject| {
                if !accept_subject
                    || subject.initial_info() != before
                    || peer.initial_info() != before
                {
                    return Err(OwnerPeerError::Physical);
                }
                Ok(())
            },
        )
    }

    #[test]
    fn exact_route_subject_and_zero_fd_report_is_a_point_observation() {
        let (_, report) = report_frame();
        let observed = exchange(&report, false, true, true).unwrap();
        assert_eq!(observed.report().epoch(), 1);
        assert_eq!(observed.connection_process().pid(), std::process::id());
    }

    #[test]
    fn wrong_route_subject_fd_and_tuple_fail_closed() {
        let (_, report) = report_frame();
        assert!(exchange(&report, false, false, true).is_err());
        assert!(matches!(
            exchange(&report, false, true, false),
            Err(OwnerPeerError::Physical)
        ));
        assert!(exchange(&report, true, true, true).is_err());
        assert!(matches!(
            exchange(&report[..REPORT_BYTES - 1], false, true, true),
            Err(OwnerPeerError::Noncanonical)
        ));
        let mut wrong_phase = report;
        wrong_phase[143] = 2;
        assert!(matches!(
            exchange(&wrong_phase, false, true, true),
            Err(OwnerPeerError::Noncanonical)
        ));
        let mut stale = report;
        let now = aos_sandbox_linux::seqpacket::bounded::boottime().unwrap();
        stale[144..152].copy_from_slice(&now.saturating_sub(2_000_000_000).to_be_bytes());
        assert!(matches!(
            exchange(&stale, false, true, true),
            Err(OwnerPeerError::NotCurrent)
        ));
    }
}
