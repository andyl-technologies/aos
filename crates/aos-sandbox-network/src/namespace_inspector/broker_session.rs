//! Broker ownership of one published, nonauthorizing inspector exchange.
//!
//! The caller's protected publication precedes this module's socket activation
//! and sole request send. A failed connection, send, timeout, or response
//! consumes the in-memory attempt; the immutable expected record is never
//! removed or reused. PID 1 readback still does not prove the activated socket
//! instance or the deployed MAC policy.
//! This path cannot grant READY or Network Apply authority.

use std::num::NonZeroU32;
use std::path::Path;

use aos_sandbox_linux::cgroup::RetainedCgroupAnchor;
use aos_sandbox_linux::pidfd::{NamespaceFd, PidFd};
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_linux::seqpacket::{KernelAuthorizedRecordSubject, SeqpacketError};
use thiserror::Error;

use super::broker_handoff::PublishedBrokerInspectorHandoffV1;
use super::response_receiver::{InspectorResponseReceiveErrorV1, receive_candidate};
use super::runtime::{
    NamespaceInspectorKernelAuthenticationError, NamespaceInspectorKernelVerifierV1,
    inspector_instance_from_record_subject,
};
use super::{
    InspectorTrustedClockV1, MAXIMUM_INSPECTOR_EXCHANGE_NS, NetworkNamespaceInspectionResponseV1,
    NetworkNamespaceInspectorError, PendingLifecycleWorkerInspectionV1, validate_fresh_time,
};
use crate::inspector_deployment::ProtectedInspectorDeploymentV2;
use crate::systemd_socket_instance::SystemdSocketInstanceV1;

const CONTROL_SOCKET: &str = "/run/aos/sandbox-network-namespace-inspector/control.sock";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AttemptWindow {
    now_ns: u64,
    deadline_ns: u64,
}

/// Reports rejection before or during the sole broker request send.
#[derive(Debug, Error)]
pub(super) enum BrokerInspectorStartError {
    /// The socket, worker, or bounded attempt did not match fixed broker policy.
    #[error("broker inspector attempt identity is invalid")]
    Identity,
    /// The attempt expired before its sole request transfer completed.
    #[error("broker inspector request deadline elapsed")]
    Deadline,
    /// The trusted boot clock rejected the attempt.
    #[error(transparent)]
    Time(#[from] NetworkNamespaceInspectorError),
    /// A Linux pidfd observation failed.
    #[error(transparent)]
    Linux(#[from] aos_sandbox_linux::Error),
    /// The independently provisioned role verifier rejected PID 1.
    #[error(transparent)]
    Authentication(#[from] NamespaceInspectorKernelAuthenticationError),
    /// The fixed socket request could not be transferred exactly once.
    #[error(transparent)]
    Transport(#[from] SeqpacketError),
    /// The existing canonical request codec rejected the pending attempt.
    #[error("broker inspector request encoding failed: {0}")]
    Request(NetworkNamespaceInspectorError),
    /// Bounded socket polling failed.
    #[error("broker inspector request polling failed: {0}")]
    Poll(#[source] std::io::Error),
}

/// Reports rejection after the only broker request send.
#[derive(Debug, Error)]
pub(super) enum BrokerInspectorResponseError {
    /// The response instance did not name this exact broker connector.
    #[error("broker inspector Accept=yes instance does not name its connector")]
    ConnectorMismatch,
    /// The retained broker connector pidfd could not be observed.
    #[error(transparent)]
    Linux(#[from] aos_sandbox_linux::Error),
    /// The broker connector pidfd inode could not be read.
    #[error("broker inspector connector pidfd stat failed: {0}")]
    ConnectorStat(#[source] rustix::io::Errno),
    /// The trusted boot clock rejected the response deadline.
    #[error(transparent)]
    Time(#[from] NetworkNamespaceInspectorError),
    /// The response did not arrive before the attempt deadline.
    #[error("broker inspector response deadline elapsed")]
    Deadline,
    /// Polling the retained socket failed.
    #[error("broker inspector response polling failed: {0}")]
    Poll(#[source] std::io::Error),
    /// The exact socket record, namespace descriptor, or PID 1 query failed.
    #[error(transparent)]
    Receive(#[from] InspectorResponseReceiveErrorV1),
    /// The independently provisioned manager role verifier rejected PID 1.
    #[error(transparent)]
    Authentication(#[from] NamespaceInspectorKernelAuthenticationError),
}

/// Owns the one socket and pending token after exact durable publication.
///
/// Dropping this value abandons the attempt. A retry must construct and publish
/// a fresh nonce; the spent expected record cannot be adopted or overwritten.
#[derive(Debug)]
pub(super) struct PublishedBrokerInspectorAttemptV1 {
    socket: DescriptorSubjectSocket,
    pending: PendingLifecycleWorkerInspectionV1,
    connector: PidFd,
}

/// Retains the correlated response and the inspector's typed namespace FD.
///
/// This value is an observation, not a completed activation or effect permit.
#[derive(Debug)]
pub(super) struct CorrelatedBrokerInspectorResponseV1 {
    pending: PendingLifecycleWorkerInspectionV1,
    response: NetworkNamespaceInspectionResponseV1,
    namespace: NamespaceFd,
    socket: DescriptorSubjectSocket,
    record_subject: KernelAuthorizedRecordSubject,
    connector: PidFd,
}

impl CorrelatedBrokerInspectorResponseV1 {
    /// Borrows the exact pending attempt bound to both retained process subjects.
    pub(super) const fn pending(&self) -> &PendingLifecycleWorkerInspectionV1 {
        &self.pending
    }
}

impl PublishedBrokerInspectorAttemptV1 {
    /// Connects and sends one request after an exact protected publication.
    ///
    /// This consumes the published READY handoff and returns its original
    /// pidfd subject and cgroup with the socket. The worker is checked before
    /// and after the request send; a raw pending record cannot start transport.
    ///
    /// # Errors
    ///
    /// Rejects a foreign socket peer, stale or oversized deadline, changed
    /// worker pidfd, or incomplete send.
    pub(super) fn connect_send_published<'ready>(
        verifier: &NamespaceInspectorKernelVerifierV1,
        published: PublishedBrokerInspectorHandoffV1<'ready>,
        clock: &mut impl InspectorTrustedClockV1,
    ) -> Result<
        (
            Self,
            &'ready KernelAuthorizedRecordSubject,
            &'ready RetainedCgroupAnchor,
        ),
        BrokerInspectorStartError,
    > {
        let (pending, ready_subject, worker_cgroup) = published.into_transport_parts();
        let worker = ready_subject.pidfd();
        validate_worker(&pending, worker)?;
        let deadline = validate_attempt_time(&pending, clock)?.deadline_ns;
        let request = pending
            .encode_request()
            .map_err(BrokerInspectorStartError::Request)?;
        let connector = PidFd::open(
            NonZeroU32::new(std::process::id()).ok_or(BrokerInspectorStartError::Identity)?,
        )?;

        let mut socket = DescriptorSubjectSocket::connect(Path::new(CONTROL_SOCKET))?;
        socket.require_local_filesystem_path(Path::new(CONTROL_SOCKET))?;
        {
            let manager = verifier.authenticate_manager_connection(socket.peer())?;
            manager.authenticated_manager()?;
        }

        socket.provision_packet_capacity(request.len())?;
        loop {
            let window = validate_attempt_time(&pending, clock)?;
            match socket.send_with_descriptors(&request, &[worker.as_fd()]) {
                Ok(()) => break,
                Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                    if !wait_socket(
                        socket.as_fd()?,
                        rustix::event::PollFlags::OUT,
                        deadline - window.now_ns,
                    )
                    .map_err(BrokerInspectorStartError::Poll)?
                    {
                        return Err(BrokerInspectorStartError::Deadline);
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }

        validate_worker(&pending, worker)?;
        validate_attempt_time(&pending, clock)?;
        Ok((
            Self {
                socket,
                pending,
                connector,
            },
            ready_subject,
            worker_cgroup,
        ))
    }

    /// Consumes one response and requeries PID 1 against its exact SCM subject.
    ///
    /// The kernel-nominated response writer supplies only a cgroup locator.
    /// Fresh signed PID 1 readback must confirm that locator and the exact SCM
    /// pidfd. Procfs executable access to a nondumpable inspector is not used;
    /// this candidate still lacks independent accepted-FD and MAC proof.
    ///
    /// # Errors
    ///
    /// Rejects timeout, changed boot, invalid descriptor or response bytes,
    /// changed inspector pidfd, or failed V3 PID 1 requery.
    pub(super) fn receive_and_correlate(
        self,
        deployment: &ProtectedInspectorDeploymentV2,
        verifier: &NamespaceInspectorKernelVerifierV1,
        clock: &mut impl InspectorTrustedClockV1,
    ) -> Result<CorrelatedBrokerInspectorResponseV1, BrokerInspectorResponseError> {
        let Self {
            socket,
            pending,
            connector,
        } = self;
        let now = clock.observe()?;
        validate_fresh_time(&pending.expected, now)?;
        let remaining = pending.expected.deadline_boottime_ns - now.boottime_ns;
        if !wait_socket(
            socket
                .as_fd()
                .map_err(InspectorResponseReceiveErrorV1::from)?,
            rustix::event::PollFlags::IN,
            remaining,
        )
        .map_err(BrokerInspectorResponseError::Poll)?
        {
            return Err(BrokerInspectorResponseError::Deadline);
        }

        let candidate = receive_candidate(socket)?;
        let instance = inspector_instance_from_record_subject(&candidate.record_subject)?;
        require_connector_instance(&instance, &connector)?;
        let unit = format!("aos-sandbox-network-namespace-inspector@{instance}.service");
        let correlated = candidate.correlate(deployment, &unit, pending, clock)?;
        require_connector_instance(&instance, &connector)?;
        let manager = verifier.authenticate_manager_connection(correlated.socket.peer())?;
        manager.authenticated_manager()?;
        let super::response_receiver::CorrelatedInspectorResponseCandidateV1 {
            socket,
            pending,
            response,
            record_subject,
            namespace,
        } = correlated;
        validate_fresh_time(&pending.expected, clock.observe()?)?;
        Ok(CorrelatedBrokerInspectorResponseV1 {
            pending,
            response,
            namespace,
            socket,
            record_subject,
            connector,
        })
    }
}

fn require_connector_instance(
    instance: &str,
    connector: &PidFd,
) -> Result<(), BrokerInspectorResponseError> {
    // The broker can prove its PID/UID/pidfd-inode fields, not the server's
    // accepted-socket cookie or the socket unit's live Accept=yes provenance.
    let parsed = SystemdSocketInstanceV1::parse(instance)
        .map_err(|_| BrokerInspectorResponseError::ConnectorMismatch)?;
    let info = connector.info()?;
    let inode = rustix::fs::fstat(connector.as_fd())
        .map_err(BrokerInspectorResponseError::ConnectorStat)?
        .st_ino;
    if info.pid() != std::process::id()
        || info.thread_group_id() != info.pid()
        || rustix::process::geteuid().as_raw() != 0
        || info
            .credentials()
            .is_none_or(|credentials| credentials.effective_user_id() != 0)
        || !connector.is_alive()?
        || !connector_fields_match(&parsed, info.pid(), inode)
    {
        return Err(BrokerInspectorResponseError::ConnectorMismatch);
    }
    Ok(())
}

fn connector_fields_match(instance: &SystemdSocketInstanceV1, pid: u32, inode: u64) -> bool {
    instance.connecting_pid() == pid
        && instance.connecting_uid() == 0
        && instance.connecting_pidfd_inode() == inode
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use aos_sandbox_core::ObjectDigest;
    use aos_sandbox_linux::pidfd::{NamespaceIdentity, PidFd};
    use aos_sandbox_linux::seqpacket::SeqpacketSocket;

    use super::*;
    use crate::namespace_inspector::{
        ExpectedInspectorAttemptV1, InspectorProcessIdentityV1, InspectorTrustedTimeV1,
    };

    struct FixedClock(InspectorTrustedTimeV1);

    impl InspectorTrustedClockV1 for FixedClock {
        fn observe(&mut self) -> Result<InspectorTrustedTimeV1, NetworkNamespaceInspectorError> {
            Ok(self.0)
        }
    }

    fn pending(worker: &PidFd) -> PendingLifecycleWorkerInspectionV1 {
        let info = worker.info().unwrap();
        let namespace = NamespaceIdentity {
            device: 1,
            inode: 2,
        };
        PendingLifecycleWorkerInspectionV1 {
            expected: ExpectedInspectorAttemptV1 {
                nonce: [1; 32],
                boot_id: [2; 16],
                not_before_boottime_ns: 10,
                deadline_boottime_ns: 100,
                request_id: [3; 16],
                effect_digest: ObjectDigest::from_bytes([4; 32]),
                dispatch_digest: ObjectDigest::from_bytes([5; 32]),
                policy_digest: ObjectDigest::from_bytes([6; 32]),
                process: InspectorProcessIdentityV1 {
                    pid: info.pid(),
                    thread_group_id: info.thread_group_id(),
                    parent_pid: info.parent_pid(),
                    cgroup_id: info.cgroup_id().unwrap_or(0),
                },
                unit_name: "aos-sandbox-network-lifecycle-worker@1.service".to_owned(),
                cgroup:
                    "aos.slice/aos-control.slice/aos-sandbox-network-lifecycle-worker@1.service"
                        .to_owned(),
                launch_contract_digest: ObjectDigest::from_bytes([7; 32]),
                forbidden_host: namespace,
                forbidden_target: NamespaceIdentity {
                    device: 1,
                    inode: 3,
                },
            },
        }
    }

    #[test]
    fn worker_pidfd_substitution_and_changed_process_fields_fail() {
        let worker = PidFd::open(NonZeroU32::new(std::process::id()).unwrap()).unwrap();
        let mut attempt = pending(&worker);
        if attempt.expected.process.cgroup_id != 0 {
            validate_worker(&attempt, &worker).unwrap();
        }

        attempt.expected.process.pid += 1;
        assert!(matches!(
            validate_worker(&attempt, &worker),
            Err(BrokerInspectorStartError::Identity)
        ));
        attempt.expected.process.pid -= 1;
        attempt.expected.process.parent_pid += 1;
        assert!(matches!(
            validate_worker(&attempt, &worker),
            Err(BrokerInspectorStartError::Identity)
        ));
        attempt.expected.process.parent_pid -= 1;
        attempt.expected.process.cgroup_id += 1;
        assert!(matches!(
            validate_worker(&attempt, &worker),
            Err(BrokerInspectorStartError::Identity)
        ));
    }

    #[test]
    fn attempt_deadline_rejects_wrong_boot_expiry_and_oversized_horizon() {
        let worker = PidFd::open(NonZeroU32::new(std::process::id()).unwrap()).unwrap();
        let mut attempt = pending(&worker);
        let mut clock = FixedClock(InspectorTrustedTimeV1 {
            boot_id: [2; 16],
            boottime_ns: 50,
        });
        assert_eq!(
            validate_attempt_time(&attempt, &mut clock).unwrap(),
            AttemptWindow {
                now_ns: 50,
                deadline_ns: 100,
            }
        );

        clock.0.boot_id = [9; 16];
        assert!(matches!(
            validate_attempt_time(&attempt, &mut clock),
            Err(BrokerInspectorStartError::Time(
                NetworkNamespaceInspectorError::Stale
            ))
        ));
        clock.0.boot_id = [2; 16];
        clock.0.boottime_ns = 100;
        assert!(matches!(
            validate_attempt_time(&attempt, &mut clock),
            Err(BrokerInspectorStartError::Time(
                NetworkNamespaceInspectorError::Stale
            ))
        ));

        clock.0.boottime_ns = 50;
        attempt.expected.deadline_boottime_ns = MAXIMUM_INSPECTOR_EXCHANGE_NS + 51;
        assert!(matches!(
            validate_attempt_time(&attempt, &mut clock),
            Err(BrokerInspectorStartError::Identity)
        ));
    }

    #[test]
    fn response_poll_reports_requested_read_event_on_retained_socket() {
        let (mut sender, endpoint) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let receiver = DescriptorSubjectSocket::from_owned(endpoint).unwrap();

        assert!(!wait_socket(receiver.as_fd().unwrap(), rustix::event::PollFlags::IN, 0).unwrap());
        sender.send(b"one response").unwrap();
        assert!(wait_socket(receiver.as_fd().unwrap(), rustix::event::PollFlags::IN, 0).unwrap());
    }

    #[test]
    fn poll_rejects_hangup_only_and_invalid_descriptor_events() {
        use rustix::event::PollFlags;

        assert!(matches!(
            requested_socket_readiness(PollFlags::HUP, PollFlags::IN),
            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe
        ));
        assert!(matches!(
            requested_socket_readiness(PollFlags::HUP | PollFlags::OUT, PollFlags::OUT),
            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe
        ));
        assert!(matches!(
            requested_socket_readiness(PollFlags::ERR | PollFlags::IN, PollFlags::IN),
            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe
        ));
        assert!(matches!(
            requested_socket_readiness(PollFlags::NVAL, PollFlags::IN),
            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe
        ));
        assert!(requested_socket_readiness(PollFlags::IN | PollFlags::HUP, PollFlags::IN).unwrap());
        assert!(!requested_socket_readiness(PollFlags::empty(), PollFlags::IN).unwrap());
    }

    #[test]
    fn accepted_instance_must_name_the_exact_broker_connector() {
        let instance = SystemdSocketInstanceV1::parse("7-9-11_13-0").unwrap();

        assert!(connector_fields_match(&instance, 11, 13));
        assert!(!connector_fields_match(&instance, 12, 13));
        assert!(!connector_fields_match(&instance, 11, 14));
        assert!(!connector_fields_match(
            &SystemdSocketInstanceV1::parse("7-9-11_13-1").unwrap(),
            11,
            13,
        ));
        // The accepted server endpoint's cookie is not observable here.
        assert!(connector_fields_match(
            &SystemdSocketInstanceV1::parse("7-99-11_13-0").unwrap(),
            11,
            13,
        ));
    }
}

fn validate_worker(
    pending: &PendingLifecycleWorkerInspectionV1,
    worker: &PidFd,
) -> Result<(), BrokerInspectorStartError> {
    let info = worker.info()?;
    let expected = pending.expected.process;
    if info.pid() != expected.pid
        || info.thread_group_id() != expected.thread_group_id
        || info.parent_pid() != expected.parent_pid
        || info.cgroup_id() != Some(expected.cgroup_id)
        || !worker.is_alive()?
    {
        return Err(BrokerInspectorStartError::Identity);
    }
    Ok(())
}

fn validate_attempt_time(
    pending: &PendingLifecycleWorkerInspectionV1,
    clock: &mut impl InspectorTrustedClockV1,
) -> Result<AttemptWindow, BrokerInspectorStartError> {
    let now = clock.observe()?;
    validate_fresh_time(&pending.expected, now)?;
    if pending.expected.deadline_boottime_ns - now.boottime_ns > MAXIMUM_INSPECTOR_EXCHANGE_NS {
        return Err(BrokerInspectorStartError::Identity);
    }
    Ok(AttemptWindow {
        now_ns: now.boottime_ns,
        deadline_ns: pending.expected.deadline_boottime_ns,
    })
}

fn wait_socket(
    descriptor: std::os::fd::BorrowedFd<'_>,
    events: rustix::event::PollFlags,
    remaining_ns: u64,
) -> Result<bool, std::io::Error> {
    let timeout = rustix::event::Timespec {
        tv_sec: i64::try_from(remaining_ns / 1_000_000_000).map_err(std::io::Error::other)?,
        tv_nsec: i64::try_from(remaining_ns % 1_000_000_000).map_err(std::io::Error::other)?,
    };
    let mut descriptors = [rustix::event::PollFd::new(&descriptor, events)];
    match rustix::event::poll(&mut descriptors, Some(&timeout)) {
        Ok(0) => Ok(false),
        Ok(_) => requested_socket_readiness(descriptors[0].revents(), events),
        Err(source) => Err(source.into()),
    }
}

fn requested_socket_readiness(
    observed: rustix::event::PollFlags,
    requested: rustix::event::PollFlags,
) -> Result<bool, std::io::Error> {
    use rustix::event::PollFlags;

    if observed.intersects(PollFlags::ERR | PollFlags::NVAL)
        || (observed.contains(PollFlags::HUP)
            && (requested.contains(PollFlags::OUT) || !observed.intersects(requested)))
    {
        return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
    }
    Ok(observed.intersects(requested))
}
