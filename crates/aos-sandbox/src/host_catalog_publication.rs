//! Authenticated controller dispatch for complete Host launch catalogs.
//!
//! Trusted reconciliation constructs one complete canonical catalog and opens
//! the configured Host socket. The client pins the responding service through
//! per-record kernel credentials, pidfds, and exact cgroup membership before it
//! sends the publication. Host protocol 1.4 then returns the generation and
//! digest of the exact bytes made visible.
//!
//! This module does not derive physical bindings. In particular, accepting a
//! [`HostCatalogPublicationDraftV1`] does not prove its paths, descriptors, or
//! subordinate identities came from authoritative broker inventory; the
//! trusted reconciler owns that prerequisite.

mod transport;

use std::fs::File;
use std::io::Write as _;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

use aos_proto::aos::sandbox::local::v1::{
    Audience, BrokerClientHello, BrokerDescriptorDisposition, BrokerMethod,
    PublishHostCatalogRequest, RequestHeader,
};
use aos_sandbox_core::{ObjectDigest, ProtocolId, ProtocolVersion};
use aos_sandbox_linux::cgroup::RetainedCgroupAnchor;
use aos_sandbox_linux::pidfd::PidFdInfo;
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_linux::seqpacket::{KernelAuthorizedRecordSubject, SeqpacketError};
use aos_sandbox_protocol::host_catalog::{
    HOST_CATALOG_PUBLICATION_DESCRIPTOR_ROLES, HostCatalogPublicationStatusV1,
    MAXIMUM_HOST_CATALOG_BYTES, ValidatedHostCatalogPublicationResponse,
    decode_host_catalog_publication_request, decode_host_catalog_publication_response,
};
use aos_sandbox_protocol::{
    PeerCredentials, PeerPolicy, ProtocolValidationError, decode_response_envelope,
    decode_server_hello, encode_unauthed_request_envelope_with_descriptors,
};
use buffa::Message as _;
use rand::{TryRngCore as _, rngs::OsRng};
use sha2::{Digest as _, Sha256};

const HOST_VERSION: ProtocolVersion = ProtocolVersion::new(1, 4);
const HOST_METHOD: BrokerMethod = BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG;
const RESPONSE_BYTES: u32 = 4 * 1024;

/// Holds a complete proposed catalog and its independently expected receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostCatalogPublicationDraftV1 {
    canonical_catalog: Vec<u8>,
    expected_generation: u64,
    expected_digest: ObjectDigest,
}

impl HostCatalogPublicationDraftV1 {
    /// Constructs a bounded publication draft produced by trusted reconciliation.
    ///
    /// This constructor computes the byte commitment but deliberately does not
    /// interpret the Host-owned catalog schema. Host performs the authoritative
    /// decode and continuity checks. The expected generation must be derived
    /// from the same snapshot and is checked against Host's protected receipt.
    ///
    /// # Errors
    ///
    /// Returns [`HostCatalogPublicationError::InvalidDraft`] when the generation
    /// is zero or the catalog is empty or larger than sixteen MiB.
    pub fn new(
        canonical_catalog: Vec<u8>,
        expected_generation: u64,
    ) -> Result<Self, HostCatalogPublicationError> {
        if expected_generation == 0
            || canonical_catalog.is_empty()
            || canonical_catalog.len() > MAXIMUM_HOST_CATALOG_BYTES
        {
            return Err(HostCatalogPublicationError::InvalidDraft);
        }
        let expected_digest = ObjectDigest::from_bytes(Sha256::digest(&canonical_catalog).into());
        Ok(Self {
            canonical_catalog,
            expected_generation,
            expected_digest,
        })
    }

    /// Returns the complete canonical bytes sent to Host.
    #[must_use]
    pub fn canonical_catalog(&self) -> &[u8] {
        &self.canonical_catalog
    }

    /// Returns the generation trusted reconciliation expects Host to confirm.
    #[must_use]
    pub const fn expected_generation(&self) -> u64 {
        self.expected_generation
    }

    /// Returns the exact SHA-256 commitment expected in Host's receipt.
    #[must_use]
    pub const fn expected_digest(&self) -> ObjectDigest {
        self.expected_digest
    }
}

/// Pins the expected Host service independently of all socket replies.
pub struct HostCatalogServiceIdentity {
    /// Required kernel-authorized Host service UID.
    pub uid: u32,
    /// Required kernel-authorized Host service GID.
    pub gid: u32,
    /// Retained exact Host service cgroup selected by deployment configuration.
    pub cgroup: RetainedCgroupAnchor,
}

/// Owns one connected channel for a single Host catalog publication.
pub struct HostCatalogPublicationClient {
    socket: DescriptorSubjectSocket,
    expected_host: HostCatalogServiceIdentity,
}

impl HostCatalogPublicationClient {
    /// Configures an exclusively owned connected Host channel before any send.
    ///
    /// The caller selects the service UID, GID, and cgroup from trusted
    /// deployment configuration. Every reply is authenticated through the
    /// kernel record subject rather than the delegable connection establisher.
    ///
    /// # Errors
    ///
    /// Returns an error for an inactive service cgroup, incompatible socket, or
    /// unavailable kernel credential and pidfd reporting.
    pub fn from_connected(
        fd: OwnedFd,
        expected_host: HostCatalogServiceIdentity,
    ) -> Result<Self, HostCatalogPublicationError> {
        expected_host.cgroup.validate_current()?;
        Ok(Self {
            socket: DescriptorSubjectSocket::from_owned(fd)?,
            expected_host,
        })
    }

    /// Publishes a complete catalog before the caller-supplied BOOTTIME deadline.
    ///
    /// The exchange is additionally limited to ten seconds. A successful
    /// response must confirm the draft's exact generation and digest; published
    /// and replay outcomes are both idempotent success.
    ///
    /// # Errors
    ///
    /// Returns an error for entropy or deadline failure, service replacement,
    /// transport or protocol rejection, or a response that confirms different
    /// catalog bytes or a different generation.
    pub fn publish(
        mut self,
        draft: &HostCatalogPublicationDraftV1,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<HostCatalogPublicationStatusV1, HostCatalogPublicationError> {
        let deadline = transport::exchange_deadline(deadline_boottime_nanoseconds)?;
        let request_id = request_id()?;
        let catalog_file = SealedCatalogFile::create(draft.canonical_catalog())?;
        let request = PublishHostCatalogRequest {
            header: Some(RequestHeader {
                protocol_major: u32::from(HOST_VERSION.major()),
                protocol_minor: u32::from(HOST_VERSION.minor()),
                request_id: request_id.to_vec(),
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds,
                maximum_response_bytes: RESPONSE_BYTES,
                ..Default::default()
            })
            .into(),
            catalog_generation: draft.expected_generation,
            catalog_bytes: u64::try_from(draft.canonical_catalog.len())
                .map_err(|_| HostCatalogPublicationError::InvalidDraft)?,
            catalog_sha256: draft.expected_digest.as_bytes().to_vec(),
            ..Default::default()
        };
        let body = request.encode_to_vec();
        let credentials = local_credentials();
        let validated_request = decode_host_catalog_publication_request(
            &body,
            credentials,
            PeerPolicy {
                uid: credentials.uid,
                gid: Some(credentials.gid),
                audience: Audience::AUDIENCE_NODE_CONTROLLER,
            },
            transport::boottime()?,
        )?;
        let packet = encode_unauthed_request_envelope_with_descriptors(
            ProtocolId::HostBroker,
            HOST_METHOD,
            &body,
            &HOST_CATALOG_PUBLICATION_DESCRIPTOR_ROLES,
        )?;
        let hello = BrokerClientHello {
            protocol_major: u32::from(HOST_VERSION.major()),
            protocol_minor: u32::from(HOST_VERSION.minor()),
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            maximum_response_bytes: RESPONSE_BYTES,
            required_methods: vec![HOST_METHOD.into()],
            ..Default::default()
        };

        transport::send(&mut self.socket, &hello.encode_to_vec(), deadline)?;
        let response = transport::receive(
            &mut self.socket,
            aos_sandbox_protocol::MAXIMUM_HANDSHAKE_BYTES,
            deadline,
        )?;
        let (hello_bytes, subject, _) = response.into_parts();
        let host = ServiceExecution::new(&self.expected_host, subject)?;
        let session = decode_server_hello(
            &hello_bytes,
            ProtocolId::HostBroker,
            Audience::AUDIENCE_NODE_CONTROLLER,
            HOST_VERSION,
            &[],
            &[HOST_METHOD],
            RESPONSE_BYTES,
        )?;
        session.validate_header(validated_request.header())?;
        let enveloped_request = session.decode_request(&packet, 1)?;

        host.recheck(&self.expected_host)?;
        transport::send_descriptor(&mut self.socket, &packet, catalog_file.as_fd(), deadline)?;
        let response = transport::receive(&mut self.socket, RESPONSE_BYTES as usize, deadline)?;
        host.validate_response(&self.expected_host, response.subject())?;
        let envelope = decode_response_envelope(
            response.payload(),
            &request_id,
            HOST_METHOD,
            enveloped_request.descriptors(),
            response.descriptors().len(),
            session.maximum_response_bytes(),
            RESPONSE_BYTES,
        )?;
        let [disposition] = envelope.request_descriptor_dispositions() else {
            return Err(ProtocolValidationError::DescriptorTableMismatch.into());
        };
        if disposition.role() != HOST_CATALOG_PUBLICATION_DESCRIPTOR_ROLES[0]
            || disposition.disposition()
                != BrokerDescriptorDisposition::BROKER_DESCRIPTOR_DISPOSITION_CLOSED
        {
            return Err(ProtocolValidationError::DescriptorTableMismatch.into());
        }
        if let Some(error) = envelope.error() {
            return Err(ProtocolValidationError::BrokerRejected(error.code()).into());
        }
        let receipt = decode_host_catalog_publication_response(envelope.body())?;
        validate_receipt(draft, receipt)?;
        transport::check_deadline(deadline)?;
        Ok(receipt.status())
    }
}

/// Reports a rejected or indeterminate Host catalog publication.
#[derive(Debug, thiserror::Error)]
pub enum HostCatalogPublicationError {
    /// The proposed bytes or expected generation violate fixed draft bounds.
    #[error("invalid Host catalog publication draft")]
    InvalidDraft,
    /// Kernel randomness for the request identity is unavailable.
    #[error("Host catalog publication request entropy is unavailable")]
    EntropyUnavailable,
    /// The request or bounded exchange deadline elapsed or overflowed.
    #[error("Host catalog publication deadline elapsed or clock is invalid")]
    Deadline,
    /// A response came from an execution other than the configured Host service.
    #[error("Host catalog response does not match the pinned service")]
    HostIdentity,
    /// Host confirmed a different generation or byte commitment.
    #[error("Host catalog publication receipt differs from the proposed snapshot")]
    ReceiptMismatch,
    /// Negotiation, request binding, or Host response validation failed.
    #[error(transparent)]
    Protocol(#[from] ProtocolValidationError),
    /// A local socket operation failed.
    #[error(transparent)]
    Transport(#[from] SeqpacketError),
    /// The sealed catalog transfer file could not be written.
    #[error("Host catalog transfer file failed: {0}")]
    CatalogFile(#[from] std::io::Error),
    /// A polling syscall failed.
    #[error("Host catalog publication I/O failed: {0}")]
    Io(#[from] rustix::io::Errno),
    /// Kernel service identity or cgroup validation failed.
    #[error(transparent)]
    Kernel(#[from] aos_sandbox_linux::Error),
}

struct SealedCatalogFile {
    fd: OwnedFd,
}

impl SealedCatalogFile {
    fn create(bytes: &[u8]) -> Result<Self, HostCatalogPublicationError> {
        let fd = rustix::fs::memfd_create(
            "aos-host-catalog",
            rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
        )?;
        let mut file = File::from(fd);
        file.write_all(bytes)?;
        rustix::fs::fcntl_add_seals(
            &file,
            rustix::fs::SealFlags::SHRINK
                | rustix::fs::SealFlags::GROW
                | rustix::fs::SealFlags::WRITE
                | rustix::fs::SealFlags::SEAL,
        )?;
        Ok(Self { fd: file.into() })
    }

    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

fn validate_receipt(
    draft: &HostCatalogPublicationDraftV1,
    receipt: ValidatedHostCatalogPublicationResponse,
) -> Result<(), HostCatalogPublicationError> {
    if receipt.generation() != draft.expected_generation
        || receipt.catalog_digest() != draft.expected_digest
    {
        return Err(HostCatalogPublicationError::ReceiptMismatch);
    }
    Ok(())
}

fn request_id() -> Result<[u8; 16], HostCatalogPublicationError> {
    let mut request_id = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut request_id)
        .map_err(|_| HostCatalogPublicationError::EntropyUnavailable)?;
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
        expected: &HostCatalogServiceIdentity,
        subject: KernelAuthorizedRecordSubject,
    ) -> Result<Self, HostCatalogPublicationError> {
        let info = validate_service_subject(expected, &subject)?;
        Ok(Self { subject, info })
    }

    fn recheck(
        &self,
        expected: &HostCatalogServiceIdentity,
    ) -> Result<PidFdInfo, HostCatalogPublicationError> {
        let fresh = validate_service_subject(expected, &self.subject)?;
        if !same_process(fresh, self.info) {
            return Err(HostCatalogPublicationError::HostIdentity);
        }
        Ok(fresh)
    }

    fn validate_response(
        &self,
        expected: &HostCatalogServiceIdentity,
        subject: &KernelAuthorizedRecordSubject,
    ) -> Result<(), HostCatalogPublicationError> {
        let before = self.recheck(expected)?;
        let response = validate_service_subject(expected, subject)?;
        let after = self.recheck(expected)?;
        if !same_process(before, response) || !same_process(after, response) {
            return Err(HostCatalogPublicationError::HostIdentity);
        }
        Ok(())
    }
}

fn validate_service_subject(
    expected: &HostCatalogServiceIdentity,
    subject: &KernelAuthorizedRecordSubject,
) -> Result<PidFdInfo, HostCatalogPublicationError> {
    let credentials = subject.credentials();
    if credentials.uid() != expected.uid
        || credentials.gid() != expected.gid
        || !subject.is_alive()?
    {
        return Err(HostCatalogPublicationError::HostIdentity);
    }
    Ok(expected.cgroup.verify_exact_membership(subject.pidfd())?)
}

fn same_process(left: PidFdInfo, right: PidFdInfo) -> bool {
    left.pid() == right.pid()
        && left.thread_group_id() == right.thread_group_id()
        && left.cgroup_id() == right.cgroup_id()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    #[cfg(feature = "kernel-tests")]
    use std::fs::File;
    #[cfg(feature = "kernel-tests")]
    use std::io::IoSliceMut;
    #[cfg(feature = "kernel-tests")]
    use std::mem::MaybeUninit;
    #[cfg(feature = "kernel-tests")]
    use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
    #[cfg(feature = "kernel-tests")]
    use std::path::Path;

    #[cfg(feature = "kernel-tests")]
    use aos_proto::aos::sandbox::local::v1::BrokerDescriptorDisposition;
    use aos_proto::aos::sandbox::local::v1::{
        HostCatalogPublicationStatus, PublishHostCatalogResponse,
    };
    #[cfg(feature = "kernel-tests")]
    use aos_sandbox_linux::cgroup::CgroupV2Root;
    #[cfg(feature = "kernel-tests")]
    use aos_sandbox_linux::immutable_file::SealedMemfdMapping;
    #[cfg(feature = "kernel-tests")]
    use aos_sandbox_protocol::{encode_success_response_envelope, negotiate_client_hello};
    #[cfg(feature = "kernel-tests")]
    use rustix::net::{
        AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
        SendFlags, SocketFlags, SocketType, recvmsg, send, socketpair,
    };

    use super::*;

    #[test]
    fn draft_commits_exact_bytes_and_generation() {
        let draft = HostCatalogPublicationDraftV1::new(b"{\"generation\":7}".to_vec(), 7).unwrap();
        assert_eq!(draft.canonical_catalog(), b"{\"generation\":7}");
        assert_eq!(draft.expected_generation(), 7);
        assert_eq!(
            draft.expected_digest(),
            ObjectDigest::from_bytes(Sha256::digest(draft.canonical_catalog()).into())
        );
    }

    #[test]
    fn receipt_must_confirm_exact_draft() {
        let draft = HostCatalogPublicationDraftV1::new(b"{}".to_vec(), 7).unwrap();
        let matching = decode_host_catalog_publication_response(
            &PublishHostCatalogResponse {
                status: HostCatalogPublicationStatus::HOST_CATALOG_PUBLICATION_STATUS_PUBLISHED
                    .into(),
                generation: 7,
                catalog_sha256: draft.expected_digest().as_bytes().to_vec(),
                ..Default::default()
            }
            .encode_to_vec(),
        )
        .unwrap();
        assert!(validate_receipt(&draft, matching).is_ok());

        let changed = decode_host_catalog_publication_response(
            &PublishHostCatalogResponse {
                status: HostCatalogPublicationStatus::HOST_CATALOG_PUBLICATION_STATUS_REPLAY.into(),
                generation: 8,
                catalog_sha256: draft.expected_digest().as_bytes().to_vec(),
                ..Default::default()
            }
            .encode_to_vec(),
        )
        .unwrap();
        assert!(matches!(
            validate_receipt(&draft, changed),
            Err(HostCatalogPublicationError::ReceiptMismatch)
        ));
    }

    #[cfg(feature = "kernel-tests")]
    #[test]
    fn client_authenticates_host_and_confirms_exact_receipt() {
        let draft = HostCatalogPublicationDraftV1::new(vec![b'x'; 3 * 1024 * 1024], 7).unwrap();
        let expected_digest = draft.expected_digest();
        let expected_bytes = u64::try_from(draft.canonical_catalog().len()).unwrap();
        let (server, endpoint) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        let server_thread = std::thread::spawn(move || {
            let (hello_bytes, hello_descriptors) =
                receive(&server, aos_sandbox_protocol::MAXIMUM_HANDSHAKE_BYTES);
            assert!(hello_descriptors.is_empty());
            let credentials = local_credentials();
            let policy = PeerPolicy {
                uid: credentials.uid,
                gid: Some(credentials.gid),
                audience: Audience::AUDIENCE_NODE_CONTROLLER,
            };
            let session = negotiate_client_hello(
                &hello_bytes,
                credentials,
                policy,
                ProtocolId::HostBroker,
                &[],
                &[HOST_METHOD],
            )
            .unwrap();
            send_packet(server.as_fd(), &session.server_hello().encode_to_vec());

            let (request_bytes, mut descriptors) = receive(
                &server,
                aos_sandbox_protocol::host_catalog::MAXIMUM_HOST_CATALOG_PUBLICATION_PACKET_BYTES,
            );
            let request = session.decode_request(&request_bytes, 1).unwrap();
            let catalog_file = descriptors.pop().unwrap();
            assert!(descriptors.is_empty());
            let publication = PublishHostCatalogRequest::decode_from_slice(request.body()).unwrap();
            assert_eq!(publication.catalog_generation, 7);
            assert_eq!(publication.catalog_bytes, expected_bytes);
            assert_eq!(publication.catalog_sha256, expected_digest.as_bytes());
            SealedMemfdMapping::run(
                catalog_file,
                expected_bytes,
                u64::try_from(MAXIMUM_HOST_CATALOG_BYTES).unwrap(),
                |bytes, _identity| {
                    assert_eq!(
                        ObjectDigest::from_bytes(Sha256::digest(bytes).into()),
                        expected_digest
                    );
                },
            )
            .unwrap();
            let request_id: [u8; 16] = publication
                .header
                .as_option()
                .unwrap()
                .request_id
                .as_slice()
                .try_into()
                .unwrap();
            let response_body = PublishHostCatalogResponse {
                status: HostCatalogPublicationStatus::HOST_CATALOG_PUBLICATION_STATUS_PUBLISHED
                    .into(),
                generation: 7,
                catalog_sha256: expected_digest.as_bytes().to_vec(),
                ..Default::default()
            }
            .encode_to_vec();
            let response = encode_success_response_envelope(
                &request_id,
                &request,
                response_body,
                &[],
                &[BrokerDescriptorDisposition::BROKER_DESCRIPTOR_DISPOSITION_CLOSED],
                RESPONSE_BYTES,
            )
            .unwrap();
            send_packet(server.as_fd(), &response);
        });
        let credentials = local_credentials();
        let client = HostCatalogPublicationClient::from_connected(
            endpoint,
            HostCatalogServiceIdentity {
                uid: credentials.uid,
                gid: credentials.gid,
                cgroup: current_cgroup(),
            },
        )
        .unwrap();
        let deadline = transport::boottime().unwrap() + 5_000_000_000;

        assert_eq!(
            client.publish(&draft, deadline).unwrap(),
            HostCatalogPublicationStatusV1::Published
        );
        server_thread.join().unwrap();
    }

    #[cfg(feature = "kernel-tests")]
    fn current_cgroup() -> RetainedCgroupAnchor {
        let root = CgroupV2Root::from_owned(File::open("/sys/fs/cgroup").unwrap().into()).unwrap();
        let membership = std::fs::read_to_string("/proc/self/cgroup").unwrap();
        let relative = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::/"))
            .unwrap();
        root.resolve(Path::new(if relative.is_empty() { "." } else { relative }))
            .unwrap()
    }

    #[cfg(feature = "kernel-tests")]
    fn receive(socket: &OwnedFd, maximum_bytes: usize) -> (Vec<u8>, Vec<OwnedFd>) {
        loop {
            let mut bytes = vec![0; maximum_bytes];
            let mut vectors = [IoSliceMut::new(&mut bytes)];
            let mut control_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
            let mut control = RecvAncillaryBuffer::new(&mut control_space);
            match recvmsg(
                socket,
                &mut vectors,
                &mut control,
                RecvFlags::TRUNC | RecvFlags::CMSG_CLOEXEC,
            ) {
                Ok(message) => {
                    assert!(
                        !message
                            .flags
                            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
                    );
                    assert!(message.bytes > 0);
                    bytes.truncate(message.bytes);
                    let mut descriptors = Vec::new();
                    for ancillary in control.drain() {
                        match ancillary {
                            RecvAncillaryMessage::ScmRights(received) => {
                                descriptors.extend(received);
                            }
                            _ => panic!("unexpected test ancillary message"),
                        }
                    }
                    return (bytes, descriptors);
                }
                Err(rustix::io::Errno::INTR) => {}
                Err(error) => panic!("server receive failed: {error}"),
            }
        }
    }

    #[cfg(feature = "kernel-tests")]
    fn send_packet(socket: BorrowedFd<'_>, bytes: &[u8]) {
        let written = send(socket, bytes, SendFlags::NOSIGNAL).unwrap();
        assert_eq!(written, bytes.len());
    }
}
