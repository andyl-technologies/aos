//! Binds one current namespace target to Mount's descriptor-backed catalog.
//!
//! Callers supply only fence-free Mount intent. The controller derives the
//! current assignment, namespace generation, Host runtime and payload-scope
//! handles, one request identity, and the existing current authorization
//! quartet. Mount acquires all root and namespace descriptors directly from
//! Host and returns only an opaque catalog commitment:
//!
//! ```text
//! CurrentNamespaceTarget + Mount intent
//!     -> authorized Host 1.3 ObserveMountScope packet
//!     -> unauthenticated Mount 1.2 PrepareMountCatalog packet
//!     -> opaque commitment + unchanged exclusive deadline
//! ```
//!
//! The result retains the live target and cannot survive restart. It is not a
//! Mount effect permit; a separately signed Mount Apply plan must bind the
//! returned commitment before dispatch.

use std::os::fd::OwnedFd;

use aos_proto::aos::sandbox::local::v1::{
    ApplyMountRequest, AssignmentFence, Audience, BrokerClientHello, BrokerMethod,
    ObserveMountScopeRequest, PrepareMountCatalogRequest, RequestHeader,
};
use aos_sandbox_core::{ObjectDigest, ProtocolId, ProtocolVersion, RawPairedClockSample};
use aos_sandbox_linux::cgroup::RetainedCgroupAnchor;
use aos_sandbox_linux::pidfd::PidFdInfo;
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_linux::seqpacket::{KernelAuthorizedRecordSubject, SeqpacketError};
use aos_sandbox_protocol::mount_catalog::{
    ValidatedMountCatalogPreparation, decode_mount_catalog_preparation,
    decode_mount_catalog_preparation_response,
};
use aos_sandbox_protocol::mount_scope::decode_mount_scope_request;
use aos_sandbox_protocol::semantics::mount::{
    MountCatalogBindingV1, MountSemanticError, canonical_mount_semantics_v1,
};
use aos_sandbox_protocol::{
    AuthorizationArtifactBytes, PeerCredentials, PeerPolicy, ProtocolValidationError,
    decode_mount_request, decode_response_envelope, decode_server_hello,
    encode_authorized_request_envelope, encode_unauthed_request_envelope,
};
use buffa::Message as _;
use rand::{TryRngCore as _, rngs::OsRng};

use crate::Journal;
use crate::dispatch::BrokerDispatchSemanticIdentityV1;
use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::runtime_scope::{
    CurrentNamespaceTarget, CurrentRuntimeScopeError, NamespaceTargetError,
};
use crate::{BrokerDispatchTemplateError, BrokerDispatchTemplateV1, SignedBrokerPlan};

mod transport;

const MOUNT_VERSION: ProtocolVersion = ProtocolVersion::new(1, 2);
const HOST_VERSION: ProtocolVersion = ProtocolVersion::new(1, 3);
const MOUNT_METHOD: BrokerMethod = BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_CATALOG;
const HOST_METHOD: BrokerMethod = BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE;
const RESPONSE_BYTES: u32 = 16 * 1024;

/// Reports invalid intent, stale live authority, or a rejected Mount exchange.
#[derive(Debug, thiserror::Error)]
pub enum MountCatalogPreparationError {
    /// A caller supplied assignment, deadline, generation, or unknown wire fields.
    #[error("mount catalog intent contains controller-owned context")]
    InvalidIntent,
    /// Kernel randomness for a fresh request identity is unavailable.
    #[error("mount catalog request entropy is unavailable")]
    EntropyUnavailable,
    /// The responding process is not the configured live Mount service execution.
    #[error("mount catalog response does not match the pinned Mount service")]
    MountIdentity,
    /// The request or bounded exchange deadline elapsed or overflowed.
    #[error("mount catalog exchange deadline elapsed or clock is invalid")]
    Deadline,
    /// Current Host authority does not grant this exact RootMount query.
    #[error(transparent)]
    HostAuthority(#[from] CurrentRuntimeScopeError),
    /// The live runtime or signed namespace target is no longer current.
    #[error(transparent)]
    CurrentTarget(#[from] NamespaceTargetError),
    /// The prospective Mount request has no canonical portable meaning.
    #[error(transparent)]
    Semantics(#[from] MountSemanticError),
    /// The signed Mount plan does not contain this exact prepared operation.
    #[error(transparent)]
    DispatchTemplate(#[from] BrokerDispatchTemplateError),
    /// Negotiation, request binding, or the Mount response was rejected.
    #[error(transparent)]
    Protocol(#[from] ProtocolValidationError),
    /// A local socket operation failed.
    #[error("mount catalog I/O failed: {0}")]
    Io(#[from] rustix::io::Errno),
    /// Kernel record-subject validation or packet transfer failed.
    #[error(transparent)]
    Transport(#[from] SeqpacketError),
    /// Kernel service identity or cgroup validation failed.
    #[error(transparent)]
    Kernel(#[from] aos_sandbox_linux::Error),
}

/// Holds one fence-free prospective Mount operation.
///
/// The supplied protobuf must omit its header and assignment fence, set
/// `namespace_generation` to zero, and contain no unknown fields. Its remaining
/// action-specific shape is validated immediately. The controller supplies all
/// omitted context from a live [`CurrentNamespaceTarget`].
#[derive(Clone, Debug, PartialEq)]
pub struct MountCatalogIntentV1 {
    request: ApplyMountRequest,
}

impl MountCatalogIntentV1 {
    /// Validates and retains a caller's fence-free Mount operation.
    ///
    /// # Errors
    ///
    /// Returns [`MountCatalogPreparationError::InvalidIntent`] when the caller
    /// supplies controller-owned context or requests release. Protocol errors
    /// report invalid action shapes, IDs, descriptors, attributes, and source
    /// generations.
    pub fn new(request: ApplyMountRequest) -> Result<Self, MountCatalogPreparationError> {
        if request.header.as_option().is_some()
            || request.fence.as_option().is_some()
            || request.namespace_generation != 0
        {
            return Err(MountCatalogPreparationError::InvalidIntent);
        }

        let mut probe = request.clone();
        probe.header = Some(request_header(
            MOUNT_VERSION,
            Audience::AUDIENCE_NODE_CONTROLLER,
            [1; 16],
            2,
        ))
        .into();
        probe.fence = Some(validation_fence()).into();
        probe.namespace_generation = 1;
        let validated = decode_mount_request(
            &probe.encode_to_vec(),
            PeerCredentials {
                uid: 1,
                gid: 1,
                pid: Some(1),
            },
            PeerPolicy {
                uid: 1,
                gid: Some(1),
                audience: Audience::AUDIENCE_NODE_CONTROLLER,
            },
            1,
        )?;
        if validated.action()
            == aos_proto::aos::sandbox::local::v1::MountAction::MOUNT_ACTION_RELEASE
        {
            return Err(MountCatalogPreparationError::InvalidIntent);
        }

        Ok(Self { request })
    }
}

/// Pins the expected Mount service independently of all socket replies.
pub struct MountServiceIdentity {
    /// Required kernel-authorized Mount service UID.
    pub uid: u32,
    /// Required kernel-authorized Mount service GID.
    pub gid: u32,
    /// Retained exact Mount service cgroup selected by deployment configuration.
    pub cgroup: RetainedCgroupAnchor,
}

/// Owns one connected channel for a single Mount catalog preparation.
pub struct MountCatalogClient {
    socket: DescriptorSubjectSocket,
    expected_mount: MountServiceIdentity,
}

impl MountCatalogClient {
    /// Configures an exclusively owned connected Mount channel before any send.
    ///
    /// The caller selects the service UID, GID, and cgroup from trusted
    /// deployment configuration. The actual hello and response writers are
    /// authenticated through kernel record subjects; listener credentials are
    /// insufficient under socket activation.
    ///
    /// # Errors
    ///
    /// Rejects an inactive service cgroup, incompatible socket, or unavailable
    /// kernel credential and pidfd reporting.
    pub fn from_connected(
        fd: OwnedFd,
        expected_mount: MountServiceIdentity,
    ) -> Result<Self, MountCatalogPreparationError> {
        expected_mount.cgroup.validate_current()?;
        Ok(Self {
            socket: DescriptorSubjectSocket::from_owned(fd)?,
            expected_mount,
        })
    }

    fn prepare(
        mut self,
        body: &[u8],
        request: &ValidatedMountCatalogPreparation,
    ) -> Result<
        aos_sandbox_protocol::mount_catalog::ValidatedMountCatalogPreparationResponse,
        MountCatalogPreparationError,
    > {
        let deadline =
            transport::exchange_deadline(request.header().deadline_boottime_nanoseconds())?;
        let hello = BrokerClientHello {
            protocol_major: 1,
            protocol_minor: 2,
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            maximum_response_bytes: RESPONSE_BYTES,
            required_methods: vec![MOUNT_METHOD.into()],
            ..Default::default()
        };
        let packet = encode_unauthed_request_envelope(ProtocolId::MountBroker, MOUNT_METHOD, body)?;

        transport::send(&mut self.socket, &hello.encode_to_vec(), deadline)?;
        let response = transport::receive(
            &mut self.socket,
            aos_sandbox_protocol::MAXIMUM_HANDSHAKE_BYTES,
            deadline,
        )?;
        let (hello_bytes, subject, _) = response.into_parts();
        let mount = ServiceExecution::new(&self.expected_mount, subject)?;
        let session = decode_server_hello(
            &hello_bytes,
            ProtocolId::MountBroker,
            Audience::AUDIENCE_NODE_CONTROLLER,
            MOUNT_VERSION,
            &[],
            &[MOUNT_METHOD],
            RESPONSE_BYTES,
        )?;
        session.validate_header(request.header())?;
        session.decode_request(&packet, 0)?;

        mount.recheck(&self.expected_mount)?;
        transport::send(&mut self.socket, &packet, deadline)?;
        let response = transport::receive(
            &mut self.socket,
            request.header().maximum_response_bytes() as usize,
            deadline,
        )?;
        mount.validate_response(&self.expected_mount, response.subject())?;
        let envelope = decode_response_envelope(
            response.payload(),
            request.header().request_id(),
            MOUNT_METHOD,
            &[],
            response.descriptors().len(),
            session.maximum_response_bytes(),
            request.header().maximum_response_bytes(),
        )?;
        if let Some(error) = envelope.error() {
            return Err(ProtocolValidationError::BrokerRejected(error.code()).into());
        }
        let result = decode_mount_catalog_preparation_response(envelope.body(), request)?;
        transport::check_deadline(deadline)?;
        Ok(result)
    }
}

/// Retains a live target and one exact Mount catalog commitment.
///
/// Restart, expiry, assignment change, or namespace replacement invalidates
/// this volatile preparation. Its semantic identity is suitable for requesting
/// a separate signed Mount plan, but does not itself authorize dispatch.
///
/// ```compile_fail
/// use aos_sandbox::mount_preparation::PreparedCurrentMountCatalogV1;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<PreparedCurrentMountCatalogV1>();
/// ```
pub struct PreparedCurrentMountCatalogV1 {
    target: CurrentNamespaceTarget,
    body_without_deadline: Vec<u8>,
    semantics: BrokerDispatchSemanticIdentityV1,
    catalog_commitment: ObjectDigest,
    valid_until_boottime_nanoseconds: u64,
}

/// Retains a current catalog and its separately verified signed Mount plan.
///
/// This value is still not a dispatched effect. It keeps the live namespace
/// proof beside the immutable dispatch template so later durable admission can
/// recheck currentness before constructing an attempt.
pub struct PreparedCurrentMountDispatchV1 {
    catalog: PreparedCurrentMountCatalogV1,
    template: BrokerDispatchTemplateV1,
}

impl PreparedCurrentMountDispatchV1 {
    /// Borrows the volatile catalog preparation and live namespace target.
    #[must_use]
    pub const fn catalog(&self) -> &PreparedCurrentMountCatalogV1 {
        &self.catalog
    }

    /// Borrows the exact signed, deadline-free Mount Apply template.
    #[must_use]
    pub const fn template(&self) -> &BrokerDispatchTemplateV1 {
        &self.template
    }

    pub(crate) fn recheck<T>(
        &self,
        journal: &mut Journal,
        clock: &mut T,
    ) -> Result<(), MountCatalogPreparationError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.catalog.recheck(journal, clock)
    }
}

impl PreparedCurrentMountCatalogV1 {
    /// Borrows the current namespace target retained by this preparation.
    #[must_use]
    pub const fn target(&self) -> &CurrentNamespaceTarget {
        &self.target
    }

    /// Returns the opaque Mount-produced catalog commitment.
    #[must_use]
    pub const fn catalog_commitment(&self) -> ObjectDigest {
        self.catalog_commitment
    }

    /// Returns the exclusive deadline inherited from the Host scope query.
    #[must_use]
    pub const fn valid_until_boottime_nanoseconds(&self) -> u64 {
        self.valid_until_boottime_nanoseconds
    }

    /// Returns the deadline-free Apply body to pair with a separately signed plan.
    #[must_use]
    pub fn body_without_deadline(&self) -> &[u8] {
        &self.body_without_deadline
    }

    /// Returns the exact portable grant identity including the catalog commitment.
    #[must_use]
    pub const fn semantics(&self) -> BrokerDispatchSemanticIdentityV1 {
        self.semantics
    }

    pub(crate) fn recheck<T>(
        &self,
        journal: &mut Journal,
        clock: &mut T,
    ) -> Result<(), MountCatalogPreparationError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.target.recheck(journal, clock)?;
        transport::check_deadline(self.valid_until_boottime_nanoseconds)
    }
}

pub(crate) fn prepare_current<T>(
    journal: &mut Journal,
    target: CurrentNamespaceTarget,
    intent: &MountCatalogIntentV1,
    client: MountCatalogClient,
    clock: &mut T,
) -> Result<PreparedCurrentMountCatalogV1, MountCatalogPreparationError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    target.recheck(journal, clock)?;

    let deadline = target
        .runtime_generation()
        .scope()
        .deadline_boottime_nanoseconds();
    let request_id = request_id()?;
    let mut mount_request = intent.request.clone();
    mount_request.header = Some(request_header(
        MOUNT_VERSION,
        Audience::AUDIENCE_NODE_CONTROLLER,
        request_id,
        deadline,
    ))
    .into();
    mount_request.fence = Some(current_fence(&target)).into();
    mount_request.namespace_generation = target.target_generation();

    let observed = target.runtime_generation().scope().observed();
    let host_request = ObserveMountScopeRequest {
        header: Some(request_header(
            HOST_VERSION,
            Audience::AUDIENCE_ROOT_MOUNT,
            request_id,
            deadline,
        ))
        .into(),
        fence: mount_request.fence.clone(),
        runtime_handle: observed.runtime_handle().to_vec(),
        payload_scope_handle: observed.payload_scope_handle().to_vec(),
        ..Default::default()
    };
    let host_body = host_request.encode_to_vec();
    let now = transport::boottime()?;
    let host_checked = decode_mount_scope_request(
        &host_body,
        PeerCredentials {
            uid: 0,
            gid: 0,
            pid: Some(1),
        },
        PeerPolicy {
            uid: 0,
            gid: Some(0),
            audience: Audience::AUDIENCE_ROOT_MOUNT,
        },
        now,
    )?;
    target.runtime_generation().scope().authorize_mount_scope(
        journal,
        &host_checked,
        &host_body,
        clock,
    )?;

    let authorization = observed.authorization();
    let host_packet = encode_authorized_request_envelope(
        ProtocolId::HostBroker,
        HOST_METHOD,
        &host_body,
        &[],
        AuthorizationArtifactBytes {
            broker_plan: authorization.broker_plan(),
            broker_plan_signature: authorization.broker_plan_signature(),
            ownership_lease: authorization.ownership_lease(),
            ownership_lease_signature: authorization.ownership_lease_signature(),
        },
    )?;
    let preparation_body = PrepareMountCatalogRequest {
        header: mount_request.header.clone(),
        mount_request: Some(mount_request.clone()).into(),
        host_request_packet: host_packet,
        ..Default::default()
    }
    .encode_to_vec();
    let credentials = local_credentials();
    let preparation = decode_mount_catalog_preparation(
        &preparation_body,
        credentials,
        PeerPolicy {
            uid: credentials.uid,
            gid: Some(credentials.gid),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        },
        transport::boottime()?,
    )?;

    target.recheck(journal, clock)?;
    let response = client.prepare(&preparation_body, &preparation)?;
    target.recheck(journal, clock)?;

    let binding = MountCatalogBindingV1::from_verified_digest(response.catalog_commitment())?;
    let canonical = canonical_mount_semantics_v1(preparation.mount_request(), Some(binding), &[])?;
    let semantics = BrokerDispatchSemanticIdentityV1::new(
        canonical.verb(),
        canonical.target(),
        canonical.commitment(),
    );
    mount_request
        .header
        .get_or_insert_default()
        .deadline_boottime_nanoseconds = 0;
    let body_without_deadline = mount_request.encode_to_vec();

    let prepared = PreparedCurrentMountCatalogV1 {
        target,
        body_without_deadline,
        semantics,
        catalog_commitment: response.catalog_commitment(),
        valid_until_boottime_nanoseconds: response.valid_until_boottime_nanoseconds(),
    };
    prepared.recheck(journal, clock)?;
    Ok(prepared)
}

pub(crate) fn bind_signed_mount_plan<T>(
    journal: &mut Journal,
    catalog: PreparedCurrentMountCatalogV1,
    signed_plan: SignedBrokerPlan,
    clock: &mut T,
) -> Result<PreparedCurrentMountDispatchV1, MountCatalogPreparationError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    catalog.recheck(journal, clock)?;
    catalog
        .target
        .runtime_generation()
        .scope()
        .verify_mount_plan(journal, &signed_plan, clock)?;
    let template = BrokerDispatchTemplateV1::new(
        signed_plan,
        BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
        catalog.body_without_deadline.clone(),
        Vec::new(),
        catalog.semantics,
    )?;

    let prepared = PreparedCurrentMountDispatchV1 { catalog, template };
    prepared.recheck(journal, clock)?;
    Ok(prepared)
}

fn request_header(
    version: ProtocolVersion,
    audience: Audience,
    request_id: [u8; 16],
    deadline: u64,
) -> RequestHeader {
    RequestHeader {
        protocol_major: u32::from(version.major()),
        protocol_minor: u32::from(version.minor()),
        request_id: request_id.to_vec(),
        audience: audience.into(),
        deadline_boottime_nanoseconds: deadline,
        maximum_response_bytes: RESPONSE_BYTES,
        ..Default::default()
    }
}

fn current_fence(target: &CurrentNamespaceTarget) -> AssignmentFence {
    let binding = target.runtime_generation().scope().binding();
    let manifest = binding.manifest().manifest();
    AssignmentFence {
        sandbox_id: manifest.sandbox().as_bytes().to_vec(),
        incarnation_id: manifest.incarnation().as_bytes().to_vec(),
        assignment_epoch: manifest.epoch().get(),
        desired_generation: manifest.desired_generation().get(),
        assignment_digest: binding.assignment_digest().as_bytes().to_vec(),
        ..Default::default()
    }
}

fn validation_fence() -> AssignmentFence {
    AssignmentFence {
        sandbox_id: vec![1; 16],
        incarnation_id: vec![2; 16],
        assignment_epoch: 1,
        desired_generation: 1,
        assignment_digest: vec![3; 32],
        ..Default::default()
    }
}

fn request_id() -> Result<[u8; 16], MountCatalogPreparationError> {
    let mut request_id = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut request_id)
        .map_err(|_| MountCatalogPreparationError::EntropyUnavailable)?;
    request_id[6] = (request_id[6] & 0x0f) | 0x40;
    request_id[8] = (request_id[8] & 0x3f) | 0x80;
    Ok(request_id)
}

fn local_credentials() -> PeerCredentials {
    PeerCredentials {
        uid: rustix::process::geteuid().as_raw(),
        gid: rustix::process::getegid().as_raw(),
        pid: Some(std::process::id()),
    }
}

struct ServiceExecution {
    subject: KernelAuthorizedRecordSubject,
    info: PidFdInfo,
}

impl ServiceExecution {
    fn new(
        expected: &MountServiceIdentity,
        subject: KernelAuthorizedRecordSubject,
    ) -> Result<Self, MountCatalogPreparationError> {
        let info = validate_service_subject(expected, &subject)?;
        Ok(Self { subject, info })
    }

    fn recheck(
        &self,
        expected: &MountServiceIdentity,
    ) -> Result<PidFdInfo, MountCatalogPreparationError> {
        let fresh = validate_service_subject(expected, &self.subject)?;
        if !same_process(fresh, self.info) {
            return Err(MountCatalogPreparationError::MountIdentity);
        }
        Ok(fresh)
    }

    fn validate_response(
        &self,
        expected: &MountServiceIdentity,
        subject: &KernelAuthorizedRecordSubject,
    ) -> Result<(), MountCatalogPreparationError> {
        let before = self.recheck(expected)?;
        let response = validate_service_subject(expected, subject)?;
        let after = self.recheck(expected)?;
        if !same_process(before, response) || !same_process(after, response) {
            return Err(MountCatalogPreparationError::MountIdentity);
        }
        Ok(())
    }
}

fn validate_service_subject(
    expected: &MountServiceIdentity,
    subject: &KernelAuthorizedRecordSubject,
) -> Result<PidFdInfo, MountCatalogPreparationError> {
    let credentials = subject.credentials();
    if credentials.uid() != expected.uid
        || credentials.gid() != expected.gid
        || !subject.is_alive()?
    {
        return Err(MountCatalogPreparationError::MountIdentity);
    }
    Ok(expected.cgroup.verify_exact_membership(subject.pidfd())?)
}

fn same_process(left: PidFdInfo, right: PidFdInfo) -> bool {
    left.pid() == right.pid()
        && left.thread_group_id() == right.thread_group_id()
        && left.cgroup_id() == right.cgroup_id()
}

#[cfg(test)]
mod tests;
