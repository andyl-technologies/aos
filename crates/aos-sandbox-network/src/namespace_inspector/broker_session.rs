//! Broker ownership of one published, nonauthorizing inspector exchange.
//!
//! Publication precedes socket activation and the only request send. A failed
//! connection, send, timeout, or response consumes the in-memory attempt; the
//! immutable expected record is never removed or reused. PID 1 readback still
//! does not prove the activated socket instance or the deployed MAC policy.
//! This path cannot grant READY or Network Apply authority.

use std::path::Path;

use aos_sandbox_linux::pidfd::{NamespaceFd, PidFd};
use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use thiserror::Error;

use super::response_receiver::{InspectorResponseReceiveErrorV1, receive_candidate};
use super::runtime::{
    NamespaceInspectorKernelAuthenticationError, NamespaceInspectorKernelVerifierV1,
};
use super::store::{BrokerExpectedAttemptPublisher, InspectorProtectedStorePublishError};
use super::{
    ExpectedInspectorAttemptV1, InspectorTrustedClockV1, NetworkNamespaceInspectionResponseV1,
    NetworkNamespaceInspectorError, PendingLifecycleWorkerInspectionV1, validate_fresh_time,
};
use crate::inspector_deployment::ProtectedInspectorDeploymentV2;

const CONTROL_SOCKET: &str = "/run/aos/sandbox-network-namespace-inspector/control.sock";
// The fixed inspector unit has RuntimeMaxSec=5s for its entire activation.
const MAXIMUM_EXCHANGE_NS: u64 = 5_000_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AttemptWindow {
    now_ns: u64,
    deadline_ns: u64,
}

/// Reports rejection before or during the sole broker request send.
#[derive(Debug, Error)]
pub(super) enum BrokerInspectorStartError<'root> {
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
    /// Protected publication retained its exact ambiguous recovery evidence.
    #[error("broker inspector expected publication failed: {0}")]
    Publication(InspectorProtectedStorePublishError<'root>),
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
    /// The inspector instance did not match its exact unit name.
    #[error("broker inspector activation identity is invalid")]
    Identity,
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
    /// The independently provisioned role verifier rejected the inspector.
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
}

/// Retains the correlated response and the inspector's typed namespace FD.
///
/// This value is an observation, not a completed activation or effect permit.
#[derive(Debug)]
pub(super) struct CorrelatedBrokerInspectorResponseV1 {
    pending: PendingLifecycleWorkerInspectionV1,
    response: NetworkNamespaceInspectionResponseV1,
    namespace: NamespaceFd,
}

impl PublishedBrokerInspectorAttemptV1 {
    /// Publishes the expected attempt, connects to PID 1, and sends one request.
    ///
    /// The caller must retain the authenticated lifecycle-worker leader while
    /// this method runs. Its exact pidfd identity is rechecked before and after
    /// publication, so a stale or substituted worker cannot receive a request.
    ///
    /// # Errors
    ///
    /// Rejects a foreign socket peer, stale or oversized deadline, changed
    /// worker pidfd, failed protected publication, or incomplete send. A
    /// publication failure preserves its backend recovery evidence.
    pub(super) fn publish_connect_send<'root>(
        publisher: &'root BrokerExpectedAttemptPublisher,
        verifier: &NamespaceInspectorKernelVerifierV1,
        pending: PendingLifecycleWorkerInspectionV1,
        worker: &PidFd,
        clock: &mut impl InspectorTrustedClockV1,
    ) -> Result<Self, BrokerInspectorStartError<'root>> {
        validate_worker(&pending, worker)?;
        let deadline = validate_attempt_time(&pending, clock)?.deadline_ns;
        let request = pending
            .encode_request()
            .map_err(BrokerInspectorStartError::Request)?;

        let mut socket = publish_before_activation(
            &pending.expected,
            |expected| {
                publisher
                    .publish(expected)
                    .map_err(BrokerInspectorStartError::Publication)
            },
            || {
                validate_worker(&pending, worker)?;
                validate_attempt_time(&pending, clock)?;
                DescriptorSubjectSocket::connect(Path::new(CONTROL_SOCKET)).map_err(Into::into)
            },
        )?;
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
        Ok(Self { socket, pending })
    }

    /// Consumes one response and requeries PID 1 against its exact SCM subject.
    ///
    /// The caller must obtain `inspector` and `unit` from an independently
    /// authenticated activation owner. This method does not create that owner
    /// or claim that the response can grant READY or Apply authority.
    ///
    /// # Errors
    ///
    /// Rejects timeout, changed boot, invalid descriptor or response bytes,
    /// changed inspector pidfd, or failed V3 PID 1 requery.
    pub(super) fn receive_and_correlate(
        self,
        deployment: &ProtectedInspectorDeploymentV2,
        verifier: &NamespaceInspectorKernelVerifierV1,
        inspector: &PidFd,
        instance: &str,
        unit: &str,
        clock: &mut impl InspectorTrustedClockV1,
    ) -> Result<CorrelatedBrokerInspectorResponseV1, BrokerInspectorResponseError> {
        let Self { socket, pending } = self;
        if unit != format!("aos-sandbox-network-namespace-inspector@{instance}.service") {
            return Err(BrokerInspectorResponseError::Identity);
        }
        let inspector_role = verifier.authenticate_inspector_pidfd(inspector, instance)?;
        inspector_role.authenticated_inspector()?;
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
        let (pending, response, namespace) =
            candidate.correlate(deployment, inspector, unit, pending, clock)?;
        inspector_role.revalidate_retained()?;
        validate_fresh_time(&pending.expected, clock.observe()?)?;
        Ok(CorrelatedBrokerInspectorResponseV1 {
            pending,
            response,
            namespace,
        })
    }
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
        attempt.expected.deadline_boottime_ns = MAXIMUM_EXCHANGE_NS + 51;
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
    fn failed_or_changed_publication_cannot_activate_inspector() {
        use std::cell::RefCell;

        let worker = PidFd::open(NonZeroU32::new(std::process::id()).unwrap()).unwrap();
        let expected = pending(&worker).expected;
        let events = RefCell::new(Vec::new());

        let activated = publish_before_activation(
            &expected,
            |record| {
                events.borrow_mut().push("publish");
                Ok(record.clone())
            },
            || {
                events.borrow_mut().push("activate");
                Ok(())
            },
        );
        assert!(activated.is_ok());
        assert_eq!(*events.borrow(), ["publish", "activate"]);

        events.borrow_mut().clear();
        let failed: Result<(), _> = publish_before_activation(
            &expected,
            |_| {
                events.borrow_mut().push("publish");
                Err(BrokerInspectorStartError::Identity)
            },
            || {
                events.borrow_mut().push("activate");
                Ok(())
            },
        );
        assert!(matches!(failed, Err(BrokerInspectorStartError::Identity)));
        assert_eq!(*events.borrow(), ["publish"]);

        events.borrow_mut().clear();
        let changed: Result<(), _> = publish_before_activation(
            &expected,
            |record| {
                events.borrow_mut().push("publish");
                let mut changed = record.clone();
                changed.nonce[0] ^= 1;
                Ok(changed)
            },
            || {
                events.borrow_mut().push("activate");
                Ok(())
            },
        );
        assert!(matches!(changed, Err(BrokerInspectorStartError::Identity)));
        assert_eq!(*events.borrow(), ["publish"]);
    }
}

fn publish_before_activation<'root, Activated>(
    expected: &ExpectedInspectorAttemptV1,
    publish: impl FnOnce(
        &ExpectedInspectorAttemptV1,
    ) -> Result<ExpectedInspectorAttemptV1, BrokerInspectorStartError<'root>>,
    activate: impl FnOnce() -> Result<Activated, BrokerInspectorStartError<'root>>,
) -> Result<Activated, BrokerInspectorStartError<'root>> {
    // Connecting activates the Accept=yes inspector. It must never begin its
    // bounded receive before the exact expected record is durable.
    if publish(expected)? != *expected {
        return Err(BrokerInspectorStartError::Identity);
    }
    activate()
}

fn validate_worker(
    pending: &PendingLifecycleWorkerInspectionV1,
    worker: &PidFd,
) -> Result<(), BrokerInspectorStartError<'static>> {
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
) -> Result<AttemptWindow, BrokerInspectorStartError<'static>> {
    let now = clock.observe()?;
    validate_fresh_time(&pending.expected, now)?;
    if pending.expected.deadline_boottime_ns - now.boottime_ns > MAXIMUM_EXCHANGE_NS {
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
