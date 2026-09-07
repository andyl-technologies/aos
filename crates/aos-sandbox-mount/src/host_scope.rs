//! Authenticated RootMount acquisition of Host-retained payload descriptors.
//!
//! The Host reply attests the exact retained payload root and namespaces after
//! signed query admission. Local checks establish descriptor types, live Host
//! execution, and payload membership. Neither the reply nor its descriptors
//! authorizes a mount effect without independent Mount admission.

use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use aos_proto::aos::sandbox::local::v1::{Audience, BrokerClientHello, BrokerMethod, Feature};
use aos_sandbox_core::{FeatureRef, ProtocolId, ProtocolVersion};
use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::path::{BeneathRoot, ResolvedPath};
use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceKind, PidFd, PidFdInfo};
use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_protocol::mount_scope::{decode_mount_scope_request, decode_mount_scope_response};
use aos_sandbox_protocol::payload_scope::ValidatedPayloadScopeResponse;
use aos_sandbox_protocol::session::SIGNED_PLAN_LEASE_FEATURE_NAMESPACE;
use aos_sandbox_protocol::{
    AuthorizationArtifactBytes, PeerCredentials, PeerPolicy, ProtocolValidationError,
    decode_response_envelope, decode_server_hello, encode_authorized_request_envelope,
};
use buffa::Message as _;

mod execution;
mod transport;

use execution::HostExecution;

const METHOD: BrokerMethod = BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE;
const RESPONSE_BYTES: u32 = 16 * 1024;
const HOST_SOCKET: &str = "/run/aos/sandbox-host/control.sock";
const HOST_SERVICE_CGROUP: &str = "system.slice/aos-sandbox-hostd.service";

/// Reports rejected Host exchanges without turning metadata into mount authority.
#[derive(Debug, thiserror::Error)]
pub enum HostScopeError {
    /// The responding process is not the retained root Host service execution.
    #[error("mount scope reply does not match the retained Host service")]
    HostIdentity,
    /// The retained payload changed execution or cgroup membership.
    #[error("mount scope payload identity changed")]
    PayloadIdentity,
    /// The request or bounded exchange deadline elapsed.
    #[error("mount scope exchange deadline elapsed or clock is invalid")]
    Deadline,
    /// The closed descriptor table or its kernel access profile is invalid.
    #[error("mount scope descriptor table or access profile is invalid")]
    Descriptor,
    /// A local socket or descriptor operation failed.
    #[error("mount scope I/O failed: {0}")]
    Io(#[from] rustix::io::Errno),
    /// Kernel record-subject validation or packet transfer failed.
    #[error(transparent)]
    Transport(#[from] SeqpacketError),
    /// Kernel descriptor or membership validation failed.
    #[error(transparent)]
    Kernel(#[from] aos_sandbox_linux::Error),
    /// Negotiation, request binding, or the broker response was rejected.
    #[error(transparent)]
    Protocol(#[from] ProtocolValidationError),
}

type Result<T> = std::result::Result<T, HostScopeError>;

/// Owns one single-use Host channel with a separately configured service identity.
pub struct HostMountScopeClient {
    socket: DescriptorSubjectSocket,
    expected_host: RetainedCgroupAnchor,
}

impl HostMountScopeClient {
    /// Connects to the fixed deployed Host endpoint with bounded nonblocking I/O.
    ///
    /// The pre-opened cgroup-v2 root selects the fixed Host service independently
    /// of all caller request bytes and socket replies.
    ///
    /// # Errors
    ///
    /// Rejects an absent Host service cgroup, an unavailable endpoint, connection
    /// backpressure, or failure to configure kernel record-subject reporting.
    pub fn connect(cgroup_root: &CgroupV2Root) -> Result<Self> {
        let expected_host = cgroup_root.resolve(Path::new(HOST_SERVICE_CGROUP))?;
        let socket = rustix::net::socket_with(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::SEQPACKET,
            rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK,
            None,
        )?;
        let address = rustix::net::SocketAddrUnix::new(HOST_SOCKET)?;

        rustix::net::connect(&socket, &address)?;

        Self::from_connected(socket, expected_host)
    }

    /// Configures a connected channel before sending any request.
    ///
    /// The trusted caller supplies the fixed Host service cgroup, not a cgroup
    /// nominated by a reply. Root UID/GID are mandatory for every Host response.
    /// The caller must exclusively own socket configuration and consumption,
    /// including any duplicates. Listener-creator credentials do not identify
    /// the actual Host service on a socket-activated endpoint.
    ///
    /// # Errors
    ///
    /// Rejects invalid or inactive cgroups, incompatible sockets, or unavailable
    /// kernel credential/pidfd reporting.
    pub fn from_connected(fd: OwnedFd, expected_host: RetainedCgroupAnchor) -> Result<Self> {
        expected_host.validate_current()?;

        Ok(Self {
            socket: DescriptorSubjectSocket::from_owned(fd)?,
            expected_host,
        })
    }

    /// Acquires the exact signed scope without granting permission to mount it.
    ///
    /// The client consumes its connection on all exits. The returned observation
    /// retains the authenticated Host and payload executions together with all
    /// five descriptors; persisted metadata cannot reconstruct this proof.
    ///
    /// # Errors
    ///
    /// Rejects non-root requests, invalid signed-artifact carriers, old protocols,
    /// deadlines, broker denial, Host substitution, replaced payload scopes,
    /// inexact descriptor roles, or failed kernel checks.
    pub fn observe(
        mut self,
        request_body: &[u8],
        authorization: AuthorizationArtifactBytes<'_>,
    ) -> Result<ObservedMountScope> {
        let request = decode_mount_scope_request(
            request_body,
            PeerCredentials {
                uid: rustix::process::geteuid().as_raw(),
                gid: rustix::process::getegid().as_raw(),
                pid: Some(std::process::id()),
            },
            PeerPolicy {
                uid: 0,
                gid: Some(0),
                audience: Audience::AUDIENCE_ROOT_MOUNT,
            },
            transport::boottime()?,
        )?;
        let deadline =
            transport::exchange_deadline(request.header().deadline_boottime_nanoseconds())?;

        let feature = FeatureRef::new(SIGNED_PLAN_LEASE_FEATURE_NAMESPACE.to_owned(), 1, 0)
            .map_err(|_| ProtocolValidationError::InvalidField("required mount-scope feature"))?;
        let hello = BrokerClientHello {
            protocol_major: 1,
            protocol_minor: 3,
            audience: Audience::AUDIENCE_ROOT_MOUNT.into(),
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

        transport::send(&mut self.socket, &hello.encode_to_vec(), deadline)?;
        let hello = transport::receive(
            &mut self.socket,
            aos_sandbox_protocol::MAXIMUM_HANDSHAKE_BYTES,
            transport::ReplyProfile::Hello,
            deadline,
        )?;
        let (hello_bytes, subject, _) = hello.into_parts();
        let host = HostExecution::new(self.expected_host, subject)?;

        let session = decode_server_hello(
            &hello_bytes,
            ProtocolId::HostBroker,
            Audience::AUDIENCE_ROOT_MOUNT,
            ProtocolVersion::new(1, 3),
            &[feature],
            &[METHOD],
            RESPONSE_BYTES,
        )?;
        session.validate_header(request.header())?;
        session.decode_request(&packet, 0)?;

        host.recheck()?;
        transport::send(&mut self.socket, &packet, deadline)?;
        let response = transport::receive(
            &mut self.socket,
            request.header().maximum_response_bytes() as usize,
            transport::ReplyProfile::Scope,
            deadline,
        )?;
        host.validate_response(response.subject())?;

        let envelope = decode_response_envelope(
            response.payload(),
            request.header().request_id(),
            METHOD,
            &[],
            response.descriptors().len(),
            session.maximum_response_bytes(),
            request.header().maximum_response_bytes(),
        )?;
        if let Some(error) = envelope.error() {
            return Err(ProtocolValidationError::BrokerRejected(error.code()).into());
        }
        let metadata = decode_mount_scope_response(envelope.body(), &request)?;

        let (_, _, descriptors) = response.into_parts();
        let [payload, cgroup, root, mount, user]: [OwnedFd; 5] = descriptors
            .try_into()
            .map_err(|_| HostScopeError::Descriptor)?;
        for descriptor in [&cgroup, &root] {
            if !rustix::fs::fcntl_getfl(descriptor)?.contains(rustix::fs::OFlags::PATH) {
                return Err(HostScopeError::Descriptor);
            }
        }

        let payload = PidFd::from_owned(payload)?;
        let cgroup = CgroupV2Root::from_owned(cgroup)?.resolve(Path::new("."))?;
        let payload_info = observe_payload(&payload, &cgroup, metadata.leader_cgroup_hint())?;
        let observed = ObservedMountScope {
            host,
            payload,
            cgroup,
            payload_info,
            metadata,
            root: BeneathRoot::from_owned(root)?,
            mount: NamespaceFd::from_owned(mount, NamespaceKind::Mount)?,
            user: NamespaceFd::from_owned(user, NamespaceKind::User)?,
            deadline: request.header().deadline_boottime_nanoseconds(),
        };

        observed.recheck()?;
        transport::check_deadline(deadline)?;

        Ok(observed)
    }
}

/// Retains a Host-attested exact root/namespace scope without Mount authority.
pub struct ObservedMountScope {
    host: HostExecution,
    payload: PidFd,
    cgroup: RetainedCgroupAnchor,
    payload_info: PidFdInfo,
    metadata: ValidatedPayloadScopeResponse,
    root: BeneathRoot,
    mount: NamespaceFd,
    user: NamespaceFd,
    deadline: u64,
}

impl ObservedMountScope {
    /// Returns the exact Host-attested assignment, runtime, and retained scope.
    #[must_use]
    pub const fn metadata(&self) -> &ValidatedPayloadScopeResponse {
        &self.metadata
    }

    /// Borrows the Host-attested payload root without granting a mount effect.
    #[must_use]
    pub const fn root(&self) -> &BeneathRoot {
        &self.root
    }

    /// Borrows the Host-attested payload mount namespace.
    #[must_use]
    pub const fn mount_namespace(&self) -> &NamespaceFd {
        &self.mount
    }

    /// Borrows the Host-attested payload user namespace for idmap selection.
    #[must_use]
    pub const fn user_namespace(&self) -> &NamespaceFd {
        &self.user
    }

    /// Returns the exclusive BOOTTIME deadline of the signed Host query.
    #[must_use]
    pub const fn valid_until_boottime_nanoseconds(&self) -> u64 {
        self.deadline
    }

    pub(crate) fn duplicate_resources(&self) -> Result<(ResolvedPath, NamespaceFd, NamespaceFd)> {
        self.recheck()?;

        let root =
            ResolvedPath::from_inherited(rustix::io::fcntl_dupfd_cloexec(self.root.as_fd(), 0)?)?;
        let mount = NamespaceFd::from_owned(
            rustix::io::fcntl_dupfd_cloexec(self.mount.as_fd(), 0)?,
            NamespaceKind::Mount,
        )?;
        let user = NamespaceFd::from_owned(
            rustix::io::fcntl_dupfd_cloexec(self.user.as_fd(), 0)?,
            NamespaceKind::User,
        )?;

        self.recheck()?;
        Ok((root, mount, user))
    }

    /// Rechecks the original Host/payload executions and the query deadline.
    ///
    /// This does not refresh ownership, prove that the payload has not changed
    /// its root/namespaces since Host observation, or authorize a Mount effect.
    /// The mount worker must independently validate its exact signed resources.
    ///
    /// # Errors
    ///
    /// Rejects expiry, Host exit or substitution, payload exit or changed cgroup
    /// membership, stale cgroup anchors, and failed kernel observations.
    pub fn recheck(&self) -> Result<()> {
        transport::check_deadline(self.deadline)?;
        self.host.recheck()?;

        let fresh = observe_payload(
            &self.payload,
            &self.cgroup,
            self.metadata.leader_cgroup_hint(),
        )?;
        if fresh != self.payload_info {
            return Err(HostScopeError::PayloadIdentity);
        }

        self.host.recheck()?;
        transport::check_deadline(self.deadline)
    }
}

fn observe_payload(
    payload: &PidFd,
    cgroup: &RetainedCgroupAnchor,
    hint: &[u8],
) -> Result<PidFdInfo> {
    let info = if hint.is_empty() {
        cgroup.verify_exact_membership(payload)?
    } else {
        cgroup
            .verify_descendant_membership(payload, Path::new(std::ffi::OsStr::from_bytes(hint)))?
    };
    if info.pid() == 0 || info.pid() != info.thread_group_id() {
        return Err(HostScopeError::PayloadIdentity);
    }

    Ok(info)
}
