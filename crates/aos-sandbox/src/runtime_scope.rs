//! Authenticated Host 1.0 payload-scope observations over a real local connection.
//!
//! The client authenticates kernel-authorized response subjects, not the Unix
//! listener creator: socket activation commonly makes the latter PID 1. A
//! configured host-service cgroup and credentials bind the hello subject; every
//! later response must name that same live execution through its own pidfd.
//!
//! The host attests its strong payload PID-1, root, and namespace verification.
//! Received pidfd/cgroup types alone do not establish those facts. Direct kernel
//! checks reinforce exact process and subtree membership, but do not authorize
//! a holder mapping, prove current assignment ownership, or grant an endpoint.
//! Descriptor numbers and persisted identifiers never reconstruct this observation.
//!
//! [`CurrentRuntimeScope`] adds protected holder/publication selection, fresh
//! signature verification, and a non-renewable paired-clock bound through the
//! controller API. It retains this complete observation and still grants no
//! endpoint or publication permission.
//!
//! [`CurrentRuntimeGeneration`] consumes that proof through the controller to
//! associate it with a durable, monotone execution number. Protected generation
//! history survives restart and compaction, but neither its replay nor a fresh
//! observation establishes that filesystem attachments have been restored.
//!
//! [`CurrentNamespaceTarget`] adds the separate signed-generation mapping. A
//! changed observed execution allocates an inert successor target first; only a
//! freshly reacquired proof under an assignment naming that target can produce
//! the live value needed by later mount preparation.

use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use aos_proto::aos::sandbox::local::v1::{Audience, BrokerClientHello, BrokerMethod, Feature};
use aos_sandbox_core::{FeatureRef, ProtocolId, ProtocolVersion};
use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::pidfd::{PidFd, PidFdInfo};
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_linux::seqpacket::{KernelAuthorizedRecordSubject, SeqpacketError};
use aos_sandbox_protocol::payload_scope::{
    ValidatedPayloadScopeResponse, decode_payload_scope_request, decode_payload_scope_response,
};
use aos_sandbox_protocol::session::{
    SIGNED_PLAN_LEASE_FEATURE_NAMESPACE, ValidatedUntrustedAuthorizationArtifacts,
};
use aos_sandbox_protocol::{
    AuthorizationArtifactBytes, PeerCredentials, PeerPolicy, ProtocolValidationError,
    ValidatedAssignmentFence, decode_response_envelope, decode_server_hello,
    encode_authorized_request_envelope,
};
use buffa::Message as _;

mod current;
#[cfg(test)]
pub(crate) use current::tests::{ConsumerResourceFixture, consumer_resource_policy};
#[cfg(test)]
pub(crate) use namespace_target::seed_consumer_origin_for_test;
mod generation;
#[cfg(all(test, feature = "kernel-tests"))]
mod kernel_tests;
mod namespace_target;
#[cfg(test)]
mod tests;
mod transport;
mod retaining;
pub use retaining::{RuntimeScopeOpeningOriginalV1, RuntimeScopeObserveOriginalV1, RuntimeScopeAcquireOriginalV1};

#[cfg(all(test, feature = "kernel-tests"))]
pub(crate) use current::tests::CurrentNamespaceFixture;
pub use current::{
    CurrentAssignmentTarget, CurrentRuntimeScope, CurrentRuntimeScopeError,
    OriginalAssignmentCaptureLifetimeV2, ControllerCaptureAssignmentChecksV4,
    CurrentRuntimeScopePolicy, RuntimeScopeHolder,
};
pub(crate) use current::{
    acquire as acquire_current_runtime, acquire_retaining as acquire_current_runtime_retaining, acquire_assignment as acquire_current_assignment,
};
pub(crate) use generation::validate_namespace as validate_generation_namespace;
pub use generation::{CurrentRuntimeGeneration, RuntimeGenerationError};
pub(crate) use namespace_target::{
    ConsumerNamespaceOriginV1, DurableNamespaceTargetReferenceV1, consumer_namespace_origin_data,
    current_consumer_namespace_origin, validate_durable_reference_in_validated_namespace,
    validate_namespace as validate_namespace_target_namespace,
};
pub use namespace_target::{
    CurrentNamespaceTarget, NamespaceTargetAdvanceV1, NamespaceTargetError, NamespaceTargetOutcome,
};

/// Returns current-source reader representation on actual held rows and policy.
///
/// This pure BYTE/cardinality supplier performs no IO, parsing or admission.
/// The actual trusted coordinator must debit its genuine purpose before growth.
#[doc(hidden)]
#[must_use]
pub fn current_source_receiving_demand_v1(
    journal: &crate::Journal, policy: &CurrentRuntimeScopePolicy,
) -> Option<aos_sandbox_core::ResourceVector> {
    current::acquisition_receiving_demand_v1(journal, policy)
}

const CARRIER_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);
const AUTHORITY_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);
const METHOD: BrokerMethod = BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE;
const RESPONSE_BYTES: u32 = 16 * 1024;

/// Selects trusted host-service configuration independently of a socket reply.
pub struct HostServiceIdentity {
    /// Required kernel-authorized service UID.
    pub uid: u32,
    /// Required kernel-authorized service GID.
    pub gid: u32,
    /// Retained exact service cgroup, selected by trusted deployment configuration.
    pub cgroup: RetainedCgroupAnchor,
}

/// Reports bounded transport, protocol, and retained execution observation failures.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeScopeError {
    /// The nominated service subject is outside the configured identity or changed execution.
    #[error("runtime scope reply does not match the pinned host service")]
    HostIdentity,
    /// The actual native cause remains in the selected exchange original.
    #[error("runtime scope native original records a refusal")]
    RetainedNative,
    /// A retained payload changed identity or membership across observations.
    #[error("runtime scope payload identity changed")]
    PayloadIdentity,
    /// The request deadline or fixed exchange duration elapsed, or clock conversion failed.
    #[error("runtime scope exchange deadline elapsed or clock is invalid")]
    Deadline,
    /// A reply descriptor is missing or lacks its required kernel access profile.
    #[error("runtime scope descriptor table or access profile is invalid")]
    Descriptor,
    /// A local descriptor or readiness operation failed.
    #[error("runtime scope I/O failed: {0}")]
    Io(#[from] rustix::io::Errno),
    /// The record-subject carrier rejected the connection or packet.
    #[error(transparent)]
    Transport(#[from] SeqpacketError),
    /// Kernel object validation or membership observation failed.
    #[error(transparent)]
    Kernel(#[from] aos_sandbox_linux::Error),
    /// A negotiated header, authority carrier, or response body failed validation.
    #[error(transparent)]
    Protocol(#[from] ProtocolValidationError),
}

/// Owns one connected channel for a single authenticated Host payload-scope exchange.
pub struct RuntimeScopeClient {
    socket: DescriptorSubjectSocket,
    expected_host: Option<HostServiceIdentity>,
}

impl RuntimeScopeClient {
    /// Opens a fresh descriptor-subject channel to a trusted Host endpoint.
    ///
    /// The path locates the service; the configured cgroup and record subjects
    /// authenticate the actual Host execution. Each client is single-use.
    ///
    /// # Errors
    ///
    /// Rejects an unsafe or unavailable socket, an invalid retained Host
    /// cgroup, or failure to enable kernel record-subject reporting.
    pub fn connect(
        path: &Path,
        expected_host: HostServiceIdentity,
    ) -> Result<Self, RuntimeScopeError> {
        expected_host.cgroup.validate_current()?;
        Ok(Self {
            socket: DescriptorSubjectSocket::connect(path)?,
            expected_host: Some(expected_host),
        })
    }

    /// Configures an exclusively owned connected Unix sequenced-packet channel.
    ///
    /// Credential and pidfd reporting are enabled before any hello is sent.
    /// Service authentication occurs on the actual hello response subject, not
    /// on connection-establisher credentials. Previously queued subjectless
    /// records are rejected. Duplicate socket configuration or competing reads
    /// are outside this ownership contract.
    ///
    /// # Errors
    ///
    /// Rejects an incorrect/unconnected socket, unavailable identity reporting,
    /// or an inaccessible or deactivated configured host cgroup.
    pub fn from_connected(
        fd: OwnedFd,
        expected_host: HostServiceIdentity,
    ) -> Result<Self, RuntimeScopeError> {
        expected_host.cgroup.validate_current()?;
        Ok(Self {
            socket: DescriptorSubjectSocket::from_owned(fd)?,
            expected_host: Some(expected_host),
        })
    }

    /// Opens the same channel while retaining the actual refused native prefix.
    ///
    /// # Errors
    /// Rejects repeated entry, invalid configured cgroup or socket admission.
    /// The first actual cause and all reached native owners remain in `original`.
    #[doc(hidden)]
    pub fn connect_retaining_v1(
        path: &Path,
        expected_host: HostServiceIdentity,
        original: &mut RuntimeScopeOpeningOriginalV1,
    ) -> Result<Self, RuntimeScopeError> {
        if original.attempted { return Err(RuntimeScopeError::RetainedNative); }
        original.attempted = true;
        original.expected = Some(expected_host);
        let expected = original.expected.as_ref().ok_or(RuntimeScopeError::HostIdentity)?;
        original.validation = Some(original.active.capture_active_once(&expected.cgroup).map_err(Into::into));
        if !matches!(original.validation, Some(Ok(()))) {
            return Err(RuntimeScopeError::RetainedNative);
        }
        original.socket = Some(DescriptorSubjectSocket::connect_retaining(path));
        if !matches!(original.socket, Some(Ok(_))) {
            return Err(RuntimeScopeError::RetainedNative);
        }
        let Some(Ok(mut socket)) = original.socket.take() else { std::process::abort(); };
        socket.begin_original_retention_v1();
        Ok(Self { socket, expected_host: original.expected.take() })
    }

    /// Observes one runtime using an exact Host 1.0 body and signed authority quartet.
    ///
    /// The body is bounded and decoded before exchange; the host independently
    /// verifies its authority. This single-use client closes the channel on all
    /// exits. Success retains both the authenticated host subject and received
    /// payload pins, not a reusable decoded-reply authentication token.
    ///
    /// # Errors
    ///
    /// Rejects malformed requests, deadlines, incompatible negotiation, service
    /// substitution, broker denial, inexact response bindings/descriptor roles,
    /// invalid received kernel objects, or failed execution rechecks.
    pub fn observe(
        self,
        request_body: &[u8],
        authorization: AuthorizationArtifactBytes<'_>,
    ) -> Result<ObservedPayloadScope, RuntimeScopeError> {
        self.observe_with_disposition(request_body, authorization, None)
    }

    /// Uses the same exchange while retaining reached inputs through the caller's posts.
    ///
    /// # Errors
    /// Returns the same protocol and currentness refusals; the actual first error
    /// and native prefix remain in `original` on failure.
    #[doc(hidden)]
    pub fn observe_retaining_v1(
        self,
        request_body: &[u8],
        authorization: AuthorizationArtifactBytes<'_>,
        original: &mut RuntimeScopeObserveOriginalV1,
    ) -> Result<ObservedPayloadScope, RuntimeScopeError> {
        if original.attempted { return Err(RuntimeScopeError::RetainedNative); }
        original.attempted = true;
        let result = self.observe_with_disposition(request_body, authorization, Some(&mut *original));
        match result {
            Ok(value) => Ok(value),
            Err(cause) => {
                original.error = Some(cause);
                Err(RuntimeScopeError::RetainedNative)
            }
        }
    }

    fn observe_with_disposition(
        self,
        request_body: &[u8],
        authorization: AuthorizationArtifactBytes<'_>,
        original: Option<&mut RuntimeScopeObserveOriginalV1>,
    ) -> Result<ObservedPayloadScope, RuntimeScopeError> {
        use retaining::{HeldValueV1, ObserveDestinationsV1};
        let mut destinations = ObserveDestinationsV1::new(original);
        let mut membership = destinations.membership.take();
        let mut client = HeldValueV1::new(self, destinations.client.take());
        if destinations.selected { client.get_mut()?.socket.begin_original_retention_v1(); }
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        let request = decode_payload_scope_request(
            request_body,
            PeerCredentials {
                uid,
                gid,
                pid: Some(std::process::id()),
            },
            PeerPolicy {
                uid,
                gid: Some(gid),
                audience: Audience::AUDIENCE_NODE_CONTROLLER,
            },
            transport::boottime()?,
        )?;
        let deadline =
            transport::exchange_deadline(request.header().deadline_boottime_nanoseconds())?;
        let features = [
            FeatureRef::new(SIGNED_PLAN_LEASE_FEATURE_NAMESPACE.to_owned(), 1, 0).map_err(
                |_| ProtocolValidationError::InvalidField("required payload-scope feature"),
            )?,
        ];
        let hello = BrokerClientHello {
            protocol_major: 1,
            protocol_minor: 0,
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            required_features: vec![Feature {
                namespace: SIGNED_PLAN_LEASE_FEATURE_NAMESPACE.to_owned(),
                major: 1,
                minor: 0,
                ..Default::default()
            }],
            maximum_response_bytes: RESPONSE_BYTES,
            required_methods: vec![METHOD.into()],
            ..Default::default()
        };
        let packet = encode_authorized_request_envelope(
            ProtocolId::HostBroker,
            METHOD,
            request_body,
            &[],
            authorization,
        )?;
        transport::send_with_disposition(&mut client.get_mut()?.socket, &hello.encode_to_vec(), deadline, destinations.selected)?;
        let hello = transport::receive_with_disposition(
            &mut client.get_mut()?.socket,
            aos_sandbox_protocol::MAXIMUM_HANDSHAKE_BYTES,
            Some(0),
            deadline,
            destinations.hello_receive.take(),
        )?;
        let hello = HeldValueV1::new(hello, destinations.hello.take());
        let (hello_bytes, subject, _) = hello.take()?.into_parts();
        let hello_bytes = HeldValueV1::new(hello_bytes, destinations.hello_bytes.take());
        let expected = HeldValueV1::new(client.get_mut()?.expected_host.take()
            .ok_or(RuntimeScopeError::HostIdentity)?, destinations.expected_host.take());
        let subject = HeldValueV1::new(subject, destinations.hello_subject.take());
        let info = validate_host_subject_with_disposition(expected.get()?, subject.get()?, membership.as_deref_mut())?;
        let host = HeldValueV1::new(HostExecution {
            expected: expected.take()?, subject: subject.take()?, info,
        }, destinations.host.take());
        let session = decode_server_hello(
            hello_bytes.get()?,
            ProtocolId::HostBroker,
            Audience::AUDIENCE_NODE_CONTROLLER,
            CARRIER_VERSION,
            &features,
            &[METHOD],
            RESPONSE_BYTES,
        )?;
        session.validate_header(request.header())?;
        let decoded = session.decode_request(&packet, 0)?;
        let authorization = decoded
            .authorization()
            .ok_or(ProtocolValidationError::InvalidField(
                "payload-scope authorization",
            ))?
            .clone();

        host.get()?.recheck_with_disposition(membership.as_deref_mut())?;
        transport::send_with_disposition(&mut client.get_mut()?.socket, &packet, deadline, destinations.selected)?;
        let response = transport::receive_with_disposition(
            &mut client.get_mut()?.socket,
            request.header().maximum_response_bytes() as usize,
            None,
            deadline,
            destinations.response_receive.take(),
        )?;
        let response = HeldValueV1::new(response, destinations.response.take());
        host.get()?.validate_response_with_disposition(response.get()?.subject(), membership.as_deref_mut())?;
        let envelope = decode_response_envelope(
            response.get()?.payload(),
            request.header().request_id(),
            METHOD,
            &[],
            response.get()?.descriptors().len(),
            session.maximum_response_bytes(),
            request.header().maximum_response_bytes(),
        )?;
        if let Some(error) = envelope.error() {
            return Err(ProtocolValidationError::BrokerRejected(error.code()).into());
        }
        let metadata = decode_payload_scope_response(
            envelope.body(),
            request.fence(),
            request.runtime_handle(),
        )?;
        let (response_bytes, response_subject, descriptors) = response.take()?.into_parts();
        let _response_bytes = HeldValueV1::keep_selected(response_bytes, destinations.response_bytes.take());
        let _response_subject = HeldValueV1::keep_selected(response_subject, destinations.response_subject.take());
        let descriptors = HeldValueV1::new(descriptors, destinations.descriptors.take());
        if descriptors.get()?.len() != 2 { return Err(RuntimeScopeError::Descriptor); }
        let [payload, cgroup]: [OwnedFd; 2] = descriptors.take()?.try_into()
            .map_err(|_| RuntimeScopeError::Descriptor)?;
        let payload = HeldValueV1::new(payload, destinations.payload_raw.take());
        let cgroup = HeldValueV1::new(cgroup, destinations.cgroup_raw.take());
        if !rustix::fs::fcntl_getfl(cgroup.get()?)?.contains(rustix::fs::OFlags::PATH) {
            return Err(RuntimeScopeError::Descriptor);
        }
        let payload = if let Some(original) = destinations.payload_admission.take() {
            original.capture_once(payload.take()?).map_err(|_| RuntimeScopeError::RetainedNative)?;
            original.take_completed_once().ok_or(RuntimeScopeError::RetainedNative)?
        } else { PidFd::from_owned(payload.take()?)? };
        let payload = HeldValueV1::new(payload, destinations.payload.take());
        let anchor = if let Some(original) = destinations.cgroup_admission.take() {
            original.capture_once(cgroup.take()?).map_err(|_| RuntimeScopeError::RetainedNative)?;
            let (root, anchor) = original.take_completed_once().ok_or(RuntimeScopeError::RetainedNative)?;
            let _root = HeldValueV1::new(root, destinations.cgroup_root.take());
            anchor
        } else { CgroupV2Root::from_owned(cgroup.take()?)?.resolve(Path::new("."))? };
        let anchor = HeldValueV1::new(anchor, destinations.anchor.take());
        let payload_info = observe_payload_with_disposition(payload.get()?, anchor.get()?, metadata.leader_cgroup_hint(), membership.as_deref_mut())?;
        let observed = ObservedPayloadScope {
            host: host.take()?,
            payload: payload.take()?,
            anchor: anchor.take()?,
            metadata,
            payload_info,
            authorization,
            request_deadline_boottime_nanoseconds: request.header().deadline_boottime_nanoseconds(),
        };
        let observed = HeldValueV1::new(observed, destinations.observed.take());
        observed.get()?.recheck_with_disposition(membership.as_deref_mut())?;
        transport::check_deadline(deadline)?;
        observed.take()
    }

}

struct HostExecution {
    expected: HostServiceIdentity,
    subject: KernelAuthorizedRecordSubject,
    info: PidFdInfo,
}

impl HostExecution {
    fn new(
        expected: HostServiceIdentity,
        subject: KernelAuthorizedRecordSubject,
    ) -> Result<Self, RuntimeScopeError> {
        let info = validate_host_subject(&expected, &subject)?;
        Ok(Self {
            expected,
            subject,
            info,
        })
    }

    fn recheck(&self) -> Result<PidFdInfo, RuntimeScopeError> {
        self.recheck_with_disposition(None)
    }

    fn recheck_with_disposition(
        &self, original: Option<&mut retaining::RuntimeScopeMembershipWindowV1>,
    ) -> Result<PidFdInfo, RuntimeScopeError> {
        let fresh = validate_host_subject_with_disposition(&self.expected, &self.subject, original)?;
        if !same_process(fresh, self.info) {
            return Err(RuntimeScopeError::HostIdentity);
        }
        Ok(fresh)
    }

    fn validate_response(
        &self,
        subject: &KernelAuthorizedRecordSubject,
    ) -> Result<(), RuntimeScopeError> {
        self.validate_response_with_disposition(subject, None)
    }

    fn validate_response_with_disposition(
        &self, subject: &KernelAuthorizedRecordSubject,
        mut original: Option<&mut retaining::RuntimeScopeMembershipWindowV1>,
    ) -> Result<(), RuntimeScopeError> {
        let before = self.recheck_with_disposition(original.as_deref_mut())?;
        let response = validate_host_subject_with_disposition(&self.expected, subject, original.as_deref_mut())?;
        let after = self.recheck_with_disposition(original.as_deref_mut())?;
        if !same_process(before, response) || !same_process(after, response) {
            return Err(RuntimeScopeError::HostIdentity);
        }
        Ok(())
    }
}

fn validate_host_subject(
    expected: &HostServiceIdentity,
    subject: &KernelAuthorizedRecordSubject,
) -> Result<PidFdInfo, RuntimeScopeError> {
    validate_host_subject_with_disposition(expected, subject, None)
}

fn validate_host_subject_with_disposition(
    expected: &HostServiceIdentity, subject: &KernelAuthorizedRecordSubject,
    original: Option<&mut retaining::RuntimeScopeMembershipWindowV1>,
) -> Result<PidFdInfo, RuntimeScopeError> {
    let credentials = subject.credentials();
    if credentials.uid() != expected.uid
        || credentials.gid() != expected.gid
        || !subject.is_alive()?
    {
        return Err(RuntimeScopeError::HostIdentity);
    }
    match original {
        Some(original) => original.observe(&expected.cgroup, subject.pidfd(), None),
        None => Ok(expected.cgroup.verify_exact_membership(subject.pidfd())?),
    }
}

fn same_process(left: PidFdInfo, right: PidFdInfo) -> bool {
    left.pid() == right.pid()
        && left.thread_group_id() == right.thread_group_id()
        && left.cgroup_id() == right.cgroup_id()
}

fn observe_payload(
    payload: &PidFd,
    anchor: &RetainedCgroupAnchor,
    hint: &[u8],
) -> Result<PidFdInfo, RuntimeScopeError> {
    observe_payload_with_disposition(payload, anchor, hint, None)
}

fn observe_payload_with_disposition(
    payload: &PidFd, anchor: &RetainedCgroupAnchor, hint: &[u8],
    original: Option<&mut retaining::RuntimeScopeMembershipWindowV1>,
) -> Result<PidFdInfo, RuntimeScopeError> {
    let info = if let Some(original) = original {
        let hint = if hint.is_empty() { None } else { Some(Path::new(std::ffi::OsStr::from_bytes(hint))) };
        original.observe(anchor, payload, hint)?
    } else if hint.is_empty() {
        anchor.verify_exact_membership(payload)?
    } else {
        anchor
            .verify_descendant_membership(payload, Path::new(std::ffi::OsStr::from_bytes(hint)))?
    };
    if info.pid() == 0 || info.pid() != info.thread_group_id() {
        return Err(RuntimeScopeError::PayloadIdentity);
    }
    Ok(info)
}

/// Retains one authenticated host attestation and directly checked payload scope.
///
/// Strong PID-1/root/namespace semantics originate in the authenticated host's
/// protected verification, not in pidfd or cgroup descriptor types. Rechecks
/// observe retained executions; they do not fence later exit or migration,
/// refresh assignment ownership, authorize a holder, or permit endpoint delivery.
///
/// ```compile_fail
/// use aos_sandbox::runtime_scope::ObservedPayloadScope;
/// fn duplicate(proof: &ObservedPayloadScope) -> ObservedPayloadScope { proof.clone() }
/// ```
pub struct ObservedPayloadScope {
    host: HostExecution,
    payload: PidFd,
    anchor: RetainedCgroupAnchor,
    metadata: ValidatedPayloadScopeResponse,
    payload_info: PidFdInfo,
    authorization: ValidatedUntrustedAuthorizationArtifacts,
    request_deadline_boottime_nanoseconds: u64,
}

impl ObservedPayloadScope {
    /// Compares two simultaneously retained live executions, never persisted PIDs.
    pub(crate) fn check_continuity(&self, fresh: &Self) -> Result<(), RuntimeScopeError> {
        let original = self.recheck()?;
        let current = fresh.recheck()?;
        let after = self.recheck()?;
        if !same_process(original, current)
            || !same_process(after, current)
            || self.runtime_handle() != fresh.runtime_handle()
            || self.payload_scope_handle() != fresh.payload_scope_handle()
            || self.fence() != fresh.fence()
            || self.anchor.kernel_id() != fresh.anchor.kernel_id()
            || !same_process(self.host.recheck()?, fresh.host.recheck()?)
        {
            return Err(RuntimeScopeError::PayloadIdentity);
        }
        Ok(())
    }

    /// Borrows the exact authorization quartet sent in the authenticated exchange.
    ///
    /// The host accepted these bytes for this observation. They remain untrusted
    /// inputs to any separate controller decision: callers must verify current
    /// protected publication, ownership, holder mapping, and expiry themselves.
    /// An equal assignment fence alone does not identify the same plan or lease.
    #[must_use]
    pub const fn authorization(&self) -> &ValidatedUntrustedAuthorizationArtifacts {
        &self.authorization
    }

    /// Returns the original request's absolute `CLOCK_BOOTTIME` deadline.
    ///
    /// This preserves the caller's bound, not the shorter transport watchdog or
    /// a verified lease expiry. Execution rechecks do not renew this deadline
    /// or establish that the observation still authorizes an operation.
    #[must_use]
    pub const fn request_deadline_boottime_nanoseconds(&self) -> u64 {
        self.request_deadline_boottime_nanoseconds
    }

    /// Borrows the exact assignment fence echoed by the authenticated host.
    #[must_use]
    pub const fn fence(&self) -> &ValidatedAssignmentFence {
        self.metadata.fence()
    }

    /// Borrows the exact queried runtime handle.
    #[must_use]
    pub const fn runtime_handle(&self) -> &[u8; 32] {
        self.metadata.runtime_handle()
    }

    /// Borrows the host's live pin handle, not an independent authentication token.
    ///
    /// A Host may preserve this physical identity across assignment updates.
    /// That does not preserve the old assignment's authority, runtime alias,
    /// or an issued session; those still require their own currentness checks.
    #[must_use]
    pub const fn payload_scope_handle(&self) -> &[u8; 32] {
        self.metadata.payload_scope_handle()
    }

    /// Borrows the retained payload process for further descriptor-based observations.
    #[must_use]
    pub const fn payload(&self) -> &PidFd {
        &self.payload
    }

    /// Borrows the retained payload subtree without granting holder authority.
    #[must_use]
    pub const fn anchor(&self) -> &RetainedCgroupAnchor {
        &self.anchor
    }

    /// Returns the payload process information observed when this scope was acquired.
    #[must_use]
    pub const fn process_info(&self) -> PidFdInfo {
        self.payload_info
    }

    /// Reobserves the original host and payload executions and retained cgroup scope.
    ///
    /// # Errors
    ///
    /// Rejects host exit/substitution, payload exit or changed identity/membership,
    /// stale cgroups, failed strict hint resolution, or any kernel failure.
    pub fn recheck(&self) -> Result<PidFdInfo, RuntimeScopeError> {
        self.recheck_with_disposition(None)
    }

    fn recheck_with_disposition(
        &self, mut original: Option<&mut retaining::RuntimeScopeMembershipWindowV1>,
    ) -> Result<PidFdInfo, RuntimeScopeError> {
        self.host.recheck_with_disposition(original.as_deref_mut())?;
        let fresh = observe_payload_with_disposition(
            &self.payload,
            &self.anchor,
            self.metadata.leader_cgroup_hint(),
            original.as_deref_mut(),
        )?;
        self.host.recheck_with_disposition(original.as_deref_mut())?;
        if !same_process(fresh, self.payload_info) {
            return Err(RuntimeScopeError::PayloadIdentity);
        }
        Ok(fresh)
    }
}
