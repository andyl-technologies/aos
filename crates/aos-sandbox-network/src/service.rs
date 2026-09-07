//! Authenticated one-request Network inventory service.
//!
//! The service accepts only record-subject `SOCK_SEQPACKET` connections. Both
//! the hello and request independently carry kernel-validated credentials and
//! a generated pidfd. The first record pins the configured controller
//! execution; the second must reproduce that live process in the same retained
//! cgroup before the protected namespace catalog is observed.
//!
//! Apply is deliberately absent. The sole advertised method is the read-only
//! Network 1.2 authoritative inventory implemented by [`NetworkNamespaceCatalogV1`].

use std::os::fd::BorrowedFd;

use aos_proto::aos::sandbox::local::v1::{Audience, BrokerErrorCode, BrokerMethod};
use aos_sandbox_linux::cgroup::RetainedCgroupAnchor;
use aos_sandbox_linux::pidfd::PidFdInfo;
use aos_sandbox_linux::seqpacket::{
    KernelAuthorizedRecordSubject, RecordSubjectListener, SeqpacketError, SeqpacketSocket,
};
use aos_sandbox_protocol::{
    MAXIMUM_HANDSHAKE_BYTES, PeerCredentials, PeerPolicy, ProtocolValidationError,
    decode_network_resource_inventory_request, encode_error_response_envelope,
    encode_success_response_envelope, failed_server_hello, negotiate_client_hello,
    validate_request_descriptor_roles,
};
use buffa::Message as _;
use rustix::event::{PollFd, PollFlags, Timespec, poll};

use crate::broker::advertised_network_methods;
use crate::namespace_catalog::{NetworkNamespaceCatalogError, NetworkNamespaceCatalogV1};

const EXCHANGE_NANOSECONDS: u64 = 10_000_000_000;

/// Classifies handling of one accepted Network connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkConnectionOutcome {
    /// One authoritative inventory request completed successfully.
    Served,
    /// A record did not name the configured live controller execution.
    PeerRejected,
    /// An authenticated controller sent an invalid request or received a safe error.
    RequestRejected,
    /// The accepted child failed its bounded packet exchange.
    TransportRejected,
}

/// Reports fatal Network service configuration, clock, or transport failure.
#[derive(Debug, thiserror::Error)]
pub enum NetworkServiceError {
    /// The record-subject carrier failed.
    #[error(transparent)]
    Transport(#[from] SeqpacketError),
    /// A retained cgroup or process observation failed.
    #[error(transparent)]
    Kernel(#[from] aos_sandbox_linux::Error),
    /// A protocol value produced internally violated the closed schema.
    #[error(transparent)]
    Protocol(#[from] ProtocolValidationError),
    /// The protected namespace catalog could not be opened or observed.
    #[error(transparent)]
    Catalog(#[from] NetworkNamespaceCatalogError),
    /// A local filesystem, socket, or polling operation failed.
    #[error("Network service kernel I/O failed: {0}")]
    Io(#[from] rustix::io::Errno),
    /// `CLOCK_BOOTTIME` returned an invalid, expired, or overflowing value.
    #[error("Network service CLOCK_BOOTTIME observation is invalid")]
    Clock,
    /// Process startup did not provide the exact fixed activation contract.
    #[error("Network service activation is invalid: {0}")]
    Activation(String),
}

/// Serves authoritative Network inventory to one fixed controller execution.
pub struct NetworkInventoryService {
    catalog: NetworkNamespaceCatalogV1,
    controller_cgroup: RetainedCgroupAnchor,
    peer_policy: PeerPolicy,
}

impl NetworkInventoryService {
    /// Constructs a service around an already validated protected catalog.
    ///
    /// The caller supplies the exact controller-service cgroup selected by
    /// deployment configuration. Its current kernel identity is checked before
    /// the service becomes usable and again before every acceptance.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkServiceError`] when the retained cgroup is no longer
    /// active.
    pub fn new(
        catalog: NetworkNamespaceCatalogV1,
        controller_cgroup: RetainedCgroupAnchor,
        controller_identity: (u32, u32),
    ) -> Result<Self, NetworkServiceError> {
        controller_cgroup.validate_current()?;

        Ok(Self {
            catalog,
            controller_cgroup,
            peer_policy: PeerPolicy {
                uid: controller_identity.0,
                gid: Some(controller_identity.1),
                audience: Audience::AUDIENCE_NODE_CONTROLLER,
            },
        })
    }

    /// Accepts, authenticates, serves, replies, and closes one connection.
    ///
    /// The method waits for the next connection. A child queued before socket
    /// identity options were enabled is rejected without invalidating the
    /// listener. Once accepted, the two-packet exchange has a fixed ten-second
    /// `CLOCK_BOOTTIME` ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkServiceError`] for a corrupted listener, inactive
    /// configured controller cgroup, failed readiness polling, or invalid local
    /// clock. Peer, request, catalog-observation, and accepted-child transport
    /// failures are contained to the connection and reported in the outcome.
    pub fn serve_once(
        &mut self,
        listener: &mut RecordSubjectListener,
    ) -> Result<NetworkConnectionOutcome, NetworkServiceError> {
        self.controller_cgroup.validate_current()?;
        let Some(mut connection) = accept_connection(listener)? else {
            return Ok(NetworkConnectionOutcome::TransportRejected);
        };
        let deadline = boottime()?
            .checked_add(EXCHANGE_NANOSECONDS)
            .ok_or(NetworkServiceError::Clock)?;

        let hello = match receive(&mut connection, MAXIMUM_HANDSHAKE_BYTES, deadline) {
            Ok(record) => record,
            Err(_) => return Ok(NetworkConnectionOutcome::TransportRejected),
        };
        let (hello_bytes, hello_subject) = hello.into_parts();
        let execution = match ControllerExecution::new(
            &self.controller_cgroup,
            self.peer_policy,
            hello_subject,
        ) {
            Ok(execution) => execution,
            Err(()) => return Ok(NetworkConnectionOutcome::PeerRejected),
        };
        let methods = advertised_network_methods();
        let session = match negotiate_client_hello(
            &hello_bytes,
            execution.credentials(),
            self.peer_policy,
            aos_sandbox_core::ProtocolId::NetworkBroker,
            &[],
            &methods,
        ) {
            Ok(session) => session,
            Err(error) => {
                return Ok(send_hello_error(&mut connection, &error, deadline));
            }
        };
        if execution.recheck(&self.controller_cgroup).is_err() {
            return Ok(NetworkConnectionOutcome::PeerRejected);
        }
        if send(
            &mut connection,
            &session.server_hello().encode_to_vec(),
            deadline,
        )
        .is_err()
        {
            return Ok(NetworkConnectionOutcome::TransportRejected);
        }

        let request = match receive(&mut connection, session.maximum_request_bytes(), deadline) {
            Ok(record) => record,
            Err(_) => return Ok(NetworkConnectionOutcome::TransportRejected),
        };
        if execution
            .validate_record(&self.controller_cgroup, self.peer_policy, request.subject())
            .is_err()
        {
            return Ok(NetworkConnectionOutcome::PeerRejected);
        }
        let envelope = match session.decode_request(request.payload(), 0) {
            Ok(envelope) => envelope,
            Err(_) => return Ok(NetworkConnectionOutcome::RequestRejected),
        };
        if envelope.method() != BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES
            || envelope.authorization().is_some()
            || validate_request_descriptor_roles(&envelope, &[]).is_err()
        {
            return Ok(NetworkConnectionOutcome::RequestRejected);
        }

        let now = boottime()?;
        let header = match decode_network_resource_inventory_request(
            envelope.body(),
            execution.credentials(),
            self.peer_policy,
            now,
        ) {
            Ok(header) if session.validate_header(&header).is_ok() => header,
            Ok(_) | Err(_) => return Ok(NetworkConnectionOutcome::RequestRejected),
        };
        if execution.recheck(&self.controller_cgroup).is_err() {
            return Ok(NetworkConnectionOutcome::PeerRejected);
        }

        let response = match self.catalog.inventory_resources() {
            Ok(body) => encode_inventory_response(
                header.request_id(),
                &envelope,
                body,
                header.maximum_response_bytes(),
            ),
            Err(_) => encode_error_response_envelope(
                header.request_id(),
                &envelope,
                BrokerErrorCode::BROKER_ERROR_CODE_INTEGRITY_FAILURE,
                "authoritative Network inventory is unavailable",
                false,
                None,
                &[],
                header.maximum_response_bytes(),
            )
            .map(|bytes| (bytes, NetworkConnectionOutcome::RequestRejected)),
        };
        let Ok((response, outcome)) = response else {
            return Ok(NetworkConnectionOutcome::RequestRejected);
        };
        if execution.recheck(&self.controller_cgroup).is_err() {
            return Ok(NetworkConnectionOutcome::PeerRejected);
        }
        let response_deadline = deadline.min(header.deadline_boottime_nanoseconds());
        if send(&mut connection, &response, response_deadline).is_err() {
            return Ok(NetworkConnectionOutcome::TransportRejected);
        }

        Ok(outcome)
    }
}

fn encode_inventory_response(
    request_id: &[u8; 16],
    request: &aos_sandbox_protocol::ValidatedBrokerRequestEnvelope,
    body: Vec<u8>,
    maximum_bytes: u32,
) -> Result<(Vec<u8>, NetworkConnectionOutcome), ProtocolValidationError> {
    match encode_success_response_envelope(request_id, request, body, &[], &[], maximum_bytes) {
        Ok(bytes) => Ok((bytes, NetworkConnectionOutcome::Served)),
        Err(
            ProtocolValidationError::ResponseTooLarge
            | ProtocolValidationError::InvalidResponseBound,
        ) => encode_error_response_envelope(
            request_id,
            request,
            BrokerErrorCode::BROKER_ERROR_CODE_RESOURCE_EXHAUSTED,
            "complete Network inventory exceeds the response ceiling",
            true,
            None,
            &[],
            maximum_bytes,
        )
        .map(|bytes| (bytes, NetworkConnectionOutcome::RequestRejected)),
        Err(error) => Err(error),
    }
}

fn send_hello_error(
    connection: &mut SeqpacketSocket,
    error: &ProtocolValidationError,
    deadline: u64,
) -> NetworkConnectionOutcome {
    let (code, message, retryable) = match error {
        ProtocolValidationError::AudienceMismatch => (
            BrokerErrorCode::BROKER_ERROR_CODE_WRONG_AUDIENCE,
            "request audience is not served here",
            false,
        ),
        ProtocolValidationError::RequiredFeatureUnavailable(_) => (
            BrokerErrorCode::BROKER_ERROR_CODE_REQUIRED_FEATURE_UNAVAILABLE,
            "required Network semantics are unavailable",
            false,
        ),
        _ => (
            BrokerErrorCode::BROKER_ERROR_CODE_INVALID_REQUEST,
            "Network broker negotiation failed",
            false,
        ),
    };
    let Ok(hello) = failed_server_hello(code, message, retryable, None) else {
        return NetworkConnectionOutcome::TransportRejected;
    };
    if send(connection, &hello.encode_to_vec(), deadline).is_ok() {
        NetworkConnectionOutcome::RequestRejected
    } else {
        NetworkConnectionOutcome::TransportRejected
    }
}

fn accept_connection(
    listener: &mut RecordSubjectListener,
) -> Result<Option<SeqpacketSocket>, NetworkServiceError> {
    loop {
        listener.validate_current()?;
        match listener.accept() {
            Ok(connection) => return Ok(Some(connection)),
            Err(SeqpacketError::WouldBlock) => wait_unbounded(listener.as_fd(), PollFlags::IN)?,
            Err(SeqpacketError::Interrupted) => {}
            // The listener was valid immediately before accept, so this is an
            // old queued child that inherited incomplete identity options.
            Err(SeqpacketError::Kernel(aos_sandbox_linux::Error::InvalidInput {
                field: "record subject options",
                ..
            })) => return Ok(None),
            Err(error) => return Err(error.into()),
        }
    }
}

struct ControllerExecution {
    subject: KernelAuthorizedRecordSubject,
    info: PidFdInfo,
    credentials: PeerCredentials,
}

impl ControllerExecution {
    fn new(
        cgroup: &RetainedCgroupAnchor,
        policy: PeerPolicy,
        subject: KernelAuthorizedRecordSubject,
    ) -> Result<Self, ()> {
        let (info, credentials) = validate_subject(cgroup, policy, &subject)?;

        Ok(Self {
            subject,
            info,
            credentials,
        })
    }

    const fn credentials(&self) -> PeerCredentials {
        self.credentials
    }

    fn recheck(&self, cgroup: &RetainedCgroupAnchor) -> Result<PidFdInfo, ()> {
        let (fresh, credentials) = validate_subject(
            cgroup,
            PeerPolicy {
                uid: self.credentials.uid,
                gid: Some(self.credentials.gid),
                audience: Audience::AUDIENCE_NODE_CONTROLLER,
            },
            &self.subject,
        )?;
        if credentials != self.credentials || !same_process(fresh, self.info) {
            return Err(());
        }

        Ok(fresh)
    }

    fn validate_record(
        &self,
        cgroup: &RetainedCgroupAnchor,
        policy: PeerPolicy,
        subject: &KernelAuthorizedRecordSubject,
    ) -> Result<(), ()> {
        let before = self.recheck(cgroup)?;
        let (current, credentials) = validate_subject(cgroup, policy, subject)?;
        let after = self.recheck(cgroup)?;
        if credentials != self.credentials
            || !same_process(current, before)
            || !same_process(current, after)
        {
            return Err(());
        }

        Ok(())
    }
}

fn validate_subject(
    cgroup: &RetainedCgroupAnchor,
    policy: PeerPolicy,
    subject: &KernelAuthorizedRecordSubject,
) -> Result<(PidFdInfo, PeerCredentials), ()> {
    let observed = subject.credentials();
    if observed.uid() != policy.uid || policy.gid.is_some_and(|gid| observed.gid() != gid) {
        return Err(());
    }
    let info = cgroup
        .verify_exact_membership(subject.pidfd())
        .map_err(|_| ())?;
    let pid = observed.pid().get();
    if info.pid() != pid || info.thread_group_id() != pid || !subject.is_alive().map_err(|_| ())? {
        return Err(());
    }

    Ok((
        info,
        PeerCredentials {
            uid: observed.uid(),
            gid: observed.gid(),
            pid: Some(pid),
        },
    ))
}

fn same_process(left: PidFdInfo, right: PidFdInfo) -> bool {
    left.pid() == right.pid()
        && left.thread_group_id() == right.thread_group_id()
        && left.cgroup_id() == right.cgroup_id()
}

fn boottime() -> Result<u64, NetworkServiceError> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec).map_err(|_| NetworkServiceError::Clock)?;
    let nanoseconds = u64::try_from(now.tv_nsec).map_err(|_| NetworkServiceError::Clock)?;

    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(NetworkServiceError::Clock)
}

fn send(
    socket: &mut SeqpacketSocket,
    payload: &[u8],
    deadline: u64,
) -> Result<(), NetworkServiceError> {
    loop {
        check_deadline(deadline)?;
        match socket.send(payload) {
            Ok(()) => return check_deadline(deadline),
            Err(SeqpacketError::WouldBlock) => {
                wait_until(socket.as_fd()?, PollFlags::OUT, deadline)?;
            }
            Err(SeqpacketError::Interrupted) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn receive(
    socket: &mut SeqpacketSocket,
    maximum_bytes: usize,
    deadline: u64,
) -> Result<aos_sandbox_linux::seqpacket::ReceivedRecord, NetworkServiceError> {
    loop {
        check_deadline(deadline)?;
        match socket.receive(maximum_bytes) {
            Ok(record) => {
                check_deadline(deadline)?;
                return Ok(record);
            }
            Err(SeqpacketError::WouldBlock) => {
                wait_until(socket.as_fd()?, PollFlags::IN, deadline)?;
            }
            Err(SeqpacketError::Interrupted) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn check_deadline(deadline: u64) -> Result<(), NetworkServiceError> {
    if boottime()? >= deadline {
        return Err(NetworkServiceError::Clock);
    }

    Ok(())
}

fn wait_unbounded(fd: BorrowedFd<'_>, events: PollFlags) -> Result<(), NetworkServiceError> {
    let mut descriptors = [PollFd::from_borrowed_fd(fd, events)];
    match poll(&mut descriptors, None) {
        Ok(_) | Err(rustix::io::Errno::INTR) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn wait_until(
    fd: BorrowedFd<'_>,
    events: PollFlags,
    deadline: u64,
) -> Result<(), NetworkServiceError> {
    let remaining = deadline
        .checked_sub(boottime()?)
        .filter(|remaining| *remaining > 0)
        .ok_or(NetworkServiceError::Clock)?;
    let timeout = Timespec {
        tv_sec: i64::try_from(remaining / 1_000_000_000).map_err(|_| NetworkServiceError::Clock)?,
        tv_nsec: i64::try_from(remaining % 1_000_000_000)
            .map_err(|_| NetworkServiceError::Clock)?,
    };
    let mut descriptors = [PollFd::from_borrowed_fd(fd, events)];
    match poll(&mut descriptors, Some(&timeout)) {
        Ok(0) => Err(NetworkServiceError::Clock),
        Ok(_) | Err(rustix::io::Errno::INTR) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "Test fixture failures intentionally panic."
    )]

    use super::*;

    #[test]
    fn only_inventory_is_part_of_the_service_contract() {
        assert_eq!(
            advertised_network_methods(),
            [BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES]
        );
    }

    #[test]
    fn private_catalog_failures_map_to_one_safe_error() {
        let request_id = [7; 16];
        let envelope = aos_proto::aos::sandbox::local::v1::BrokerRequestEnvelope {
            method: BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES.into(),
            body: vec![1],
            ..Default::default()
        };
        let request = aos_sandbox_protocol::decode_request_envelope(
            &envelope.encode_to_vec(),
            aos_sandbox_core::ProtocolId::NetworkBroker,
            0,
        )
        .unwrap();
        let encoded = encode_error_response_envelope(
            &request_id,
            &request,
            BrokerErrorCode::BROKER_ERROR_CODE_INTEGRITY_FAILURE,
            "authoritative Network inventory is unavailable",
            false,
            None,
            &[],
            4096,
        )
        .unwrap();
        let response =
            aos_proto::aos::sandbox::local::v1::BrokerResponseEnvelope::decode_from_slice(&encoded)
                .unwrap();
        let error = response.error.as_option().unwrap();

        assert_eq!(
            error.code.as_known(),
            Some(BrokerErrorCode::BROKER_ERROR_CODE_INTEGRITY_FAILURE)
        );
        assert_eq!(
            error.safe_message,
            "authoritative Network inventory is unavailable"
        );
        assert!(!error.retryable);
    }
}

#[cfg(all(test, feature = "kernel-tests"))]
mod kernel_tests;
