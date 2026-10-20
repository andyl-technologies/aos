//! Authenticated process boundary for one-shot Network mutation workers.
//!
//! The systemd worker begins in a fresh private Network namespace. Its first
//! record transfers that namespace descriptor to the capability-free broker,
//! which proves the descriptor against the worker's kernel-generated pidfd and
//! retains it before sending effect-bearing bytes. The broker then transfers
//! its own host Network namespace in the sole request descriptor role. The
//! worker proves that descriptor against the broker's stable connection pidfd
//! before an authenticated dispatch may reach the kernel mutator.
//!
//! ```text
//! worker -> broker: READY(target-netns fd, cgroup, target identity)
//! broker -> worker: REQUEST(host-netns fd, NetworkPrepareWorkerDispatchV1)
//! worker -> broker: RESULT(request/effect/plan/boot/target identity)
//! broker -> worker: ACK
//! ```
//!
//! The transport result reports completion correlation only. It is never a
//! kernel postcondition and cannot be turned into a committed Network result
//! until the separate observation worker has reproduced the complete state.

pub(crate) mod cgroup_recipe;

use cgroup_recipe::{WorkerCgroupPlacementV4, WorkerCgroupRoleV4};

mod ready_original;
mod negative_v2;
pub(crate) use negative_v2::{NetworkWorkerFailureCauseV2, NetworkWorkerFailurePhaseV2, NetworkWorkerNegativeV2, NETWORK_WORKER_NEGATIVE_BYTES_V2};
mod subject_original;
mod birth_execution;
pub(crate) use birth_execution::NetworkWorkerBirthExecutionOriginalV2;
pub(crate) use subject_original::{NetworkWorkerSubjectOriginalV4, NetworkWorkerExecutionOriginalV4};
pub(crate) use subject_original::validate_observer_local;

use std::os::fd::OwnedFd;

pub(crate) use ready_original::{NetworkWorkerReadyOriginalV4, NetworkWorkerReadyRefusalV4};
use std::path::Path;

use aos_sandbox_model::ObjectDigest;
use aos_sandbox_model::bounded_codec::{BoundedReader, ReadError};
use aos_sandbox_linux::cgroup::RetainedCgroupAnchor;
use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceIdentity, NamespaceKind};
use aos_sandbox_linux::seqpacket::{ConnectionPeerIdentity, KernelAuthorizedRecordSubject};

use crate::systemd_socket_instance::validate_systemd_socket_instance_fields;

const READY_MAGIC: &[u8; 8] = b"AOSNRDY2";
const RESULT_MAGIC: &[u8; 8] = b"AOSNRES2";
const ACK_MAGIC: &[u8; 8] = b"AOSNACK2";
const WIRE_VERSION: u16 = 2;
const MUTATION_ROLE: u8 = 1;
const SUCCESS_RESULT: u8 = 1;
const READY_FIXED_BYTES: usize = 32;
const RESULT_BYTES: usize = 128;
const ACK_BYTES: usize = 10;
const MAXIMUM_CGROUP_BYTES: usize = 512;
const NETD_CGROUP_LEAF: &str = "aos-netd.service";
#[cfg(test)]
const WORKER_CGROUP_PREFIX: &str = "aos.slice/aos-control.slice/aos-sandbox-network-worker@";
#[cfg(test)]
const WORKER_CGROUP_SUFFIX: &str = ".service";

/// Proves the socket connection was accepted by the current systemd manager.
pub(crate) fn validate_systemd_manager_peer(
    peer: &ConnectionPeerIdentity,
    manager: &RetainedCgroupAnchor,
) -> Result<(), NetworkWorkerProcessError> {
    subject_original::validate_manager_local(peer, manager)
}

/// Reports a malformed worker record or a substituted process authority.
#[derive(Debug, thiserror::Error)]
pub enum NetworkWorkerProcessError {
    /// A bounded local record was malformed, unsupported, or noncanonical.
    #[error("Network worker process protocol is invalid: {0}")]
    Protocol(&'static str),
    /// A connection, record, cgroup, or namespace did not name the fixed peer.
    #[error("Network worker process authority did not match")]
    PeerMismatch,
    /// A typed Linux descriptor or retained cgroup check failed.
    #[error(transparent)]
    Linux(#[from] aos_sandbox_linux::Error),
}

/// Carries the worker's fresh target namespace and exact reserved cgroup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NetworkWorkerReadyV1 {
    cgroup: String,
    namespace: NamespaceIdentity,
}

impl NetworkWorkerReadyV1 {
    pub(crate) fn new(
        cgroup: String,
        namespace: NamespaceIdentity,
    ) -> Result<Self, NetworkWorkerProcessError> {
        Self::new_engine(cgroup, namespace, WorkerCgroupPlacementV4::Ordinary)
    }

    /// Constructs READY data for the fixed same-F aggregate placement.
    ///
    /// # Errors
    /// Rejects another unit placement, invalid instance or zero namespace.
    pub(crate) fn new_receiving_v4(
        cgroup: String,
        namespace: NamespaceIdentity,
    ) -> Result<Self, NetworkWorkerProcessError> {
        Self::new_engine(cgroup, namespace, WorkerCgroupPlacementV4::Receiving)
    }

    fn new_engine(
        cgroup: String,
        namespace: NamespaceIdentity,
        placement: WorkerCgroupPlacementV4,
    ) -> Result<Self, NetworkWorkerProcessError> {
        placement.require_path(&cgroup, WorkerCgroupRoleV4::Preparation)?;
        if namespace.device == 0 || namespace.inode == 0 {
            return protocol("ready namespace identity is zero");
        }

        Ok(Self { cgroup, namespace })
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, NetworkWorkerProcessError> {
        cgroup_recipe::require_constructed_ready_path(&self.cgroup, WorkerCgroupRoleV4::Preparation)?;
        let cgroup = self.cgroup.as_bytes();
        let cgroup_length = u16::try_from(cgroup.len())
            .map_err(|_| NetworkWorkerProcessError::Protocol("ready cgroup is too long"))?;
        let total = READY_FIXED_BYTES.checked_add(cgroup.len()).ok_or(
            NetworkWorkerProcessError::Protocol("ready length overflowed"),
        )?;
        if total > READY_FIXED_BYTES + MAXIMUM_CGROUP_BYTES {
            return protocol("ready record is too large");
        }

        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(READY_MAGIC);
        bytes.extend_from_slice(&WIRE_VERSION.to_be_bytes());
        bytes.push(MUTATION_ROLE);
        bytes.push(0);
        bytes.extend_from_slice(&cgroup_length.to_be_bytes());
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(&self.namespace.device.to_be_bytes());
        bytes.extend_from_slice(&self.namespace.inode.to_be_bytes());
        bytes.extend_from_slice(cgroup);
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, NetworkWorkerProcessError> {
        Self::decode_engine(bytes, WorkerCgroupPlacementV4::Ordinary)
    }

    /// Decodes only the receiving placement in the existing canonical V1 wire.
    ///
    /// # Errors
    /// Rejects malformed records and every ordinary or substituted unit path.
    pub(crate) fn decode_receiving_v4(bytes: &[u8]) -> Result<Self, NetworkWorkerProcessError> {
        Self::decode_engine(bytes, WorkerCgroupPlacementV4::Receiving)
    }

    fn decode_engine(
        bytes: &[u8],
        placement: WorkerCgroupPlacementV4,
    ) -> Result<Self, NetworkWorkerProcessError> {
        if bytes.len() < READY_FIXED_BYTES || bytes.len() > READY_FIXED_BYTES + MAXIMUM_CGROUP_BYTES
        {
            return protocol("ready record has an invalid length");
        }
        let mut decoder = BoundedReader::new(bytes, read_error);
        if decoder.array::<8>()? != *READY_MAGIC
            || decoder.u16()? != WIRE_VERSION
            || decoder.u8()? != MUTATION_ROLE
            || decoder.u8()? != 0
        {
            return protocol("ready header is invalid");
        }
        let cgroup_length = usize::from(decoder.u16()?);
        if decoder.array::<2>()? != [0; 2]
            || cgroup_length == 0
            || cgroup_length > MAXIMUM_CGROUP_BYTES
            || bytes.len() != READY_FIXED_BYTES + cgroup_length
        {
            return protocol("ready reserved or length field is invalid");
        }
        let namespace = NamespaceIdentity {
            device: decoder.u64()?,
            inode: decoder.u64()?,
        };
        let cgroup = std::str::from_utf8(decoder.bytes(cgroup_length)?)
            .map_err(|_| NetworkWorkerProcessError::Protocol("ready cgroup is not UTF-8"))?
            .to_owned();
        decoder.finish()?;

        let ready = Self::new_engine(cgroup, namespace, placement)?;
        if ready.encode()? != bytes {
            return protocol("ready record is not canonical");
        }
        Ok(ready)
    }

    pub(crate) fn cgroup(&self) -> &str {
        &self.cgroup
    }

    pub(crate) const fn namespace(&self) -> NamespaceIdentity {
        self.namespace
    }
}

/// Correlates one completed mutation attempt without asserting its postcondition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NetworkWorkerResultV1 {
    request_id: [u8; 16],
    effect_digest: ObjectDigest,
    kernel_plan_digest: ObjectDigest,
    kernel_boot_id: [u8; 16],
    namespace: NamespaceIdentity,
}

impl NetworkWorkerResultV1 {
    pub(crate) fn new(
        request_id: [u8; 16],
        effect_digest: ObjectDigest,
        kernel_plan_digest: ObjectDigest,
        kernel_boot_id: [u8; 16],
        namespace: NamespaceIdentity,
    ) -> Result<Self, NetworkWorkerProcessError> {
        if request_id == [0; 16]
            || effect_digest.as_bytes() == &[0; 32]
            || kernel_plan_digest.as_bytes() == &[0; 32]
            || kernel_boot_id == [0; 16]
            || namespace.device == 0
            || namespace.inode == 0
        {
            return protocol("result contains a reserved identity");
        }
        Ok(Self {
            request_id,
            effect_digest,
            kernel_plan_digest,
            kernel_boot_id,
            namespace,
        })
    }

    pub(crate) fn encode(self) -> [u8; RESULT_BYTES] {
        let mut bytes = [0_u8; RESULT_BYTES];
        bytes[..8].copy_from_slice(RESULT_MAGIC);
        bytes[8..10].copy_from_slice(&WIRE_VERSION.to_be_bytes());
        bytes[10] = SUCCESS_RESULT;
        bytes[12..16].copy_from_slice(&(RESULT_BYTES as u32).to_be_bytes());
        bytes[16..32].copy_from_slice(&self.request_id);
        bytes[32..64].copy_from_slice(self.effect_digest.as_bytes());
        bytes[64..96].copy_from_slice(self.kernel_plan_digest.as_bytes());
        bytes[96..112].copy_from_slice(&self.kernel_boot_id);
        bytes[112..120].copy_from_slice(&self.namespace.device.to_be_bytes());
        bytes[120..128].copy_from_slice(&self.namespace.inode.to_be_bytes());
        bytes
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, NetworkWorkerProcessError> {
        if bytes.len() != RESULT_BYTES {
            return protocol("result length is invalid");
        }
        let mut decoder = BoundedReader::new(bytes, read_error);
        if decoder.array::<8>()? != *RESULT_MAGIC
            || decoder.u16()? != WIRE_VERSION
            || decoder.u8()? != SUCCESS_RESULT
            || decoder.u8()? != 0
            || decoder.u32()? != RESULT_BYTES as u32
        {
            return protocol("result header is invalid");
        }
        let result = Self::new(
            decoder.array()?,
            ObjectDigest::from_bytes(decoder.array()?),
            ObjectDigest::from_bytes(decoder.array()?),
            decoder.array()?,
            NamespaceIdentity {
                device: decoder.u64()?,
                inode: decoder.u64()?,
            },
        )?;
        decoder.finish()?;
        if result.encode().as_slice() != bytes {
            return protocol("result is not canonical");
        }
        Ok(result)
    }

    pub(crate) const fn request_id(self) -> [u8; 16] {
        self.request_id
    }

    pub(crate) const fn effect_digest(self) -> ObjectDigest {
        self.effect_digest
    }

    pub(crate) const fn kernel_plan_digest(self) -> ObjectDigest {
        self.kernel_plan_digest
    }

    pub(crate) const fn kernel_boot_id(self) -> [u8; 16] {
        self.kernel_boot_id
    }

    pub(crate) const fn namespace(self) -> NamespaceIdentity {
        self.namespace
    }
}

pub(crate) const fn acknowledgement() -> [u8; ACK_BYTES] {
    let mut bytes = [0_u8; ACK_BYTES];
    let mut index = 0;
    while index < ACK_MAGIC.len() {
        bytes[index] = ACK_MAGIC[index];
        index += 1;
    }
    bytes[8] = (WIRE_VERSION >> 8) as u8;
    bytes[9] = WIRE_VERSION as u8;
    bytes
}

pub(crate) fn decode_acknowledgement(bytes: &[u8]) -> Result<(), NetworkWorkerProcessError> {
    if bytes == acknowledgement() {
        Ok(())
    } else {
        protocol("acknowledgement is invalid")
    }
}

/// Proves the one request record and host descriptor name the live netd peer.
pub(crate) fn validate_broker_request(
    peer: &ConnectionPeerIdentity,
    subject: &KernelAuthorizedRecordSubject,
    descriptors: Vec<OwnedFd>,
    control_cgroup: &RetainedCgroupAnchor,
    worker_namespace: &NamespaceFd,
) -> Result<NamespaceFd, NetworkWorkerProcessError> {
    if descriptors.len() != 1 {
        return protocol("REQUEST requires exactly one host namespace descriptor");
    }
    validate_broker_subject(peer, subject, control_cgroup)?;

    let mut descriptors = descriptors;
    let descriptor = descriptors
        .pop()
        .ok_or(NetworkWorkerProcessError::Protocol(
            "REQUEST host namespace descriptor is absent",
        ))?;
    let host = NamespaceFd::from_owned(descriptor, NamespaceKind::Network)?;
    let peer_namespace = peer.pidfd().namespace(NamespaceKind::Network)?;
    let subject_namespace = subject.pidfd().namespace(NamespaceKind::Network)?;
    if host.identity() != peer_namespace.identity()
        || host.identity() != subject_namespace.identity()
        || host.identity() == worker_namespace.identity()
        || !peer.is_alive()?
        || !subject.is_alive()?
    {
        return Err(NetworkWorkerProcessError::PeerMismatch);
    }
    Ok(host)
}

/// Proves one descriptor-free record came from the same live netd execution.
pub(crate) fn validate_broker_subject(
    peer: &ConnectionPeerIdentity,
    subject: &KernelAuthorizedRecordSubject,
    control_cgroup: &RetainedCgroupAnchor,
) -> Result<(), NetworkWorkerProcessError> {
    validate_broker_peer(peer, control_cgroup)?;
    validate_same_execution(peer, subject)?;
    Ok(())
}

/// Proves the inherited connection peer is the live fixed netd service.
pub(crate) fn validate_broker_peer(
    peer: &ConnectionPeerIdentity,
    control_cgroup: &RetainedCgroupAnchor,
) -> Result<(), NetworkWorkerProcessError> {
    let credentials = peer.credentials();
    if credentials.uid() != 0 || credentials.gid() != 0 {
        return Err(NetworkWorkerProcessError::PeerMismatch);
    }
    let netd_cgroup = control_cgroup.resolve_descendant(Path::new(NETD_CGROUP_LEAF))?;
    let info = netd_cgroup.verify_exact_membership(peer.pidfd())?;
    if info.pid() != credentials.pid().get() || info.thread_group_id() != credentials.pid().get() {
        return Err(NetworkWorkerProcessError::PeerMismatch);
    }
    netd_cgroup.validate_current()?;
    control_cgroup.validate_current()?;
    Ok(())
}

/// Rechecks that a result subject remains the sole leader of the retained unit.
pub(crate) fn validate_exact_worker_subject(
    subject: &KernelAuthorizedRecordSubject,
    worker_cgroup: &RetainedCgroupAnchor,
) -> Result<(), NetworkWorkerProcessError> {
    subject_original::validate_result_local(subject, worker_cgroup)
}

pub(crate) fn validate_same_worker_execution(
    ready: &KernelAuthorizedRecordSubject,
    result: &KernelAuthorizedRecordSubject,
) -> Result<(), NetworkWorkerProcessError> {
    subject_original::validate_execution_local_v4(ready, result)
}

fn validate_same_execution(
    peer: &ConnectionPeerIdentity,
    subject: &KernelAuthorizedRecordSubject,
) -> Result<(), NetworkWorkerProcessError> {
    let peer_credentials = peer.credentials();
    let record_credentials = subject.credentials();
    if record_credentials.pid() != peer_credentials.pid()
        || record_credentials.uid() != peer_credentials.uid()
        || record_credentials.gid() != peer_credentials.gid()
        || subject.initial_info().pid() != peer.initial_info().pid()
        || subject.initial_info().thread_group_id() != peer.initial_info().thread_group_id()
        || subject.initial_info().cgroup_id() != peer.initial_info().cgroup_id()
    {
        return Err(NetworkWorkerProcessError::PeerMismatch);
    }
    Ok(())
}

fn protocol<T>(message: &'static str) -> Result<T, NetworkWorkerProcessError> {
    Err(NetworkWorkerProcessError::Protocol(message))
}

// Reserved fields remain grammar checks; these records do not use Core zeros.
fn read_error(error: ReadError) -> NetworkWorkerProcessError {
    let message = match error {
        ReadError::LengthOverflow => "record offset overflowed",
        ReadError::TrailingBytes => "record has trailing bytes",
        ReadError::Truncated | ReadError::NonzeroReserved => "record is truncated",
    };
    NetworkWorkerProcessError::Protocol(message)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn ready() -> NetworkWorkerReadyV1 {
        NetworkWorkerReadyV1::new(
            format!("{WORKER_CGROUP_PREFIX}0-984321-543_876-0{WORKER_CGROUP_SUFFIX}"),
            NamespaceIdentity {
                device: 23,
                inode: 29,
            },
        )
        .unwrap()
    }

    fn result() -> NetworkWorkerResultV1 {
        NetworkWorkerResultV1::new(
            [1; 16],
            ObjectDigest::from_bytes([2; 32]),
            ObjectDigest::from_bytes([3; 32]),
            [4; 16],
            NamespaceIdentity {
                device: 5,
                inode: 6,
            },
        )
        .unwrap()
    }

    #[test]
    fn receiving_ready_keeps_v2_geometry_but_requires_its_exact_expected_aggregate() {
        let cgroup = "aoscomponents.slice/aoscomponents-network.slice/aos-sandbox-network-worker@0-984321-543_876-0.service".to_owned();
        let namespace = NamespaceIdentity {
            device: 23,
            inode: 29,
        };
        let selected = NetworkWorkerReadyV1::new_receiving_v4(cgroup.clone(), namespace).unwrap();
        let bytes = selected.encode().unwrap();

        assert_eq!(&bytes[..8], READY_MAGIC);
        assert_eq!(&bytes[8..10], &WIRE_VERSION.to_be_bytes());
        assert_eq!(bytes.len(), READY_FIXED_BYTES + cgroup.len());
        assert_eq!(
            NetworkWorkerReadyV1::decode_receiving_v4(&bytes).unwrap(),
            selected
        );
        assert!(NetworkWorkerReadyV1::decode(&bytes).is_err());
        assert!(NetworkWorkerReadyV1::new(cgroup, namespace).is_err());
        let ordinary = ready().encode().unwrap();
        assert!(NetworkWorkerReadyV1::decode_receiving_v4(&ordinary).is_err());
        assert_eq!(
            NetworkWorkerReadyV1::decode(&ordinary)
                .unwrap()
                .encode()
                .unwrap(),
            ordinary
        );
    }

    #[test]
    fn ready_result_and_ack_round_trip_canonically() {
        let ready = ready();
        assert_eq!(
            NetworkWorkerReadyV1::decode(&ready.encode().unwrap()).unwrap(),
            ready
        );

        let result = result();
        assert_eq!(
            NetworkWorkerResultV1::decode(&result.encode()).unwrap(),
            result
        );
        decode_acknowledgement(&acknowledgement()).unwrap();
    }

    #[test]
    fn v2_worker_records_refuse_the_old_wire_without_a_fallback() {
        let mut old_ready = ready().encode().unwrap();
        old_ready[..8].copy_from_slice(b"AOSNRDY1");
        old_ready[8..10].copy_from_slice(&1_u16.to_be_bytes());
        assert!(NetworkWorkerReadyV1::decode(&old_ready).is_err());

        let mut old_result = result().encode();
        old_result[..8].copy_from_slice(b"AOSNRES1");
        old_result[8..10].copy_from_slice(&1_u16.to_be_bytes());
        assert!(NetworkWorkerResultV1::decode(&old_result).is_err());

        let mut old_ack = acknowledgement();
        old_ack[..8].copy_from_slice(b"AOSNACK1");
        old_ack[8..10].copy_from_slice(&1_u16.to_be_bytes());
        assert!(decode_acknowledgement(&old_ack).is_err());
    }

    #[test]
    fn wrong_roles_reserved_fields_lengths_and_sentinels_fail_closed() {
        let mut wrong_role = ready().encode().unwrap();
        wrong_role[10] = 2;
        let mut reserved_header = ready().encode().unwrap();
        reserved_header[11] = 1;
        let mut reserved_ready = ready().encode().unwrap();
        reserved_ready[14] = 1;
        let mut short_ready = ready().encode().unwrap();
        short_ready.pop();
        let maximum_ready = vec![0; READY_FIXED_BYTES + MAXIMUM_CGROUP_BYTES];
        let overbound_ready = vec![0; READY_FIXED_BYTES + MAXIMUM_CGROUP_BYTES + 1];
        for bytes in [
            wrong_role,
            reserved_header,
            reserved_ready,
            short_ready,
            maximum_ready,
            overbound_ready,
        ] {
            assert!(NetworkWorkerReadyV1::decode(&bytes).is_err());
        }
        assert!(
            NetworkWorkerReadyV1::new(
                ready().cgroup().to_owned(),
                NamespaceIdentity {
                    device: 0,
                    inode: 6,
                },
            )
            .is_err()
        );
        assert!(
            NetworkWorkerReadyV1::new(
                ready().cgroup().to_owned(),
                NamespaceIdentity {
                    device: 5,
                    inode: 0,
                },
            )
            .is_err()
        );

        for offset in [8, 10, 11, 15] {
            let mut wrong_result = result().encode().to_vec();
            wrong_result[offset] ^= 1;
            assert!(NetworkWorkerResultV1::decode(&wrong_result).is_err());
        }
        let mut trailing_result = result().encode().to_vec();
        trailing_result.push(0);
        assert!(NetworkWorkerResultV1::decode(&trailing_result).is_err());
        assert!(
            NetworkWorkerResultV1::new(
                [0; 16],
                ObjectDigest::from_bytes([2; 32]),
                ObjectDigest::from_bytes([3; 32]),
                [4; 16],
                NamespaceIdentity {
                    device: 5,
                    inode: 6,
                },
            )
            .is_err()
        );

        let mut wrong_ack = acknowledgement();
        wrong_ack[9] ^= 1;
        assert!(decode_acknowledgement(&wrong_ack).is_err());
    }

    #[test]
    fn every_short_or_trailing_worker_record_preserves_its_length_diagnostic() {
        let encoded_ready = ready().encode().unwrap();
        for length in 0..encoded_ready.len() {
            let expected = if length < READY_FIXED_BYTES {
                "ready record has an invalid length"
            } else {
                "ready reserved or length field is invalid"
            };
            assert!(matches!(
                NetworkWorkerReadyV1::decode(&encoded_ready[..length]),
                Err(NetworkWorkerProcessError::Protocol(message)) if message == expected
            ));
        }
        let mut trailing_ready = encoded_ready;
        trailing_ready.push(0);
        assert!(matches!(
            NetworkWorkerReadyV1::decode(&trailing_ready),
            Err(NetworkWorkerProcessError::Protocol(
                "ready reserved or length field is invalid"
            ))
        ));

        let encoded_result = result().encode();
        for length in 0..encoded_result.len() {
            assert!(matches!(
                NetworkWorkerResultV1::decode(&encoded_result[..length]),
                Err(NetworkWorkerProcessError::Protocol(
                    "result length is invalid"
                ))
            ));
        }
        let mut trailing_result = encoded_result.to_vec();
        trailing_result.push(0);
        assert!(matches!(
            NetworkWorkerResultV1::decode(&trailing_result),
            Err(NetworkWorkerProcessError::Protocol(
                "result length is invalid"
            ))
        ));
    }

    #[test]
    fn ready_rejects_malformed_fields_before_namespace_validation() {
        let valid = ready().encode().unwrap();
        let cases = [
            (0..1, &[0][..], "ready header is invalid"),
            (
                12..14,
                &[0, 0][..],
                "ready reserved or length field is invalid",
            ),
            (
                14..16,
                &[1, 0][..],
                "ready reserved or length field is invalid",
            ),
            (
                valid.len() - 1..valid.len(),
                &[0xff][..],
                "ready cgroup is not UTF-8",
            ),
        ];

        for (range, replacement, expected) in cases {
            let mut malformed = valid.clone();
            malformed[16..24].fill(0);
            malformed[range].copy_from_slice(replacement);
            assert!(matches!(
                NetworkWorkerReadyV1::decode(&malformed),
                Err(NetworkWorkerProcessError::Protocol(message)) if message == expected
            ));
        }

        let mut zero_namespace = valid;
        zero_namespace[16..24].fill(0);
        assert!(matches!(
            NetworkWorkerReadyV1::decode(&zero_namespace),
            Err(NetworkWorkerProcessError::Protocol(
                "ready namespace identity is zero"
            ))
        ));
    }

    #[test]
    fn only_the_exact_reserved_worker_cgroup_language_is_accepted() {
        assert!(WorkerCgroupPlacementV4::Ordinary.require_path(ready().cgroup(), WorkerCgroupRoleV4::Preparation).is_ok());
        for path in [
            "aos.slice/aos-control.slice/aos-sandbox-network-worker@.service",
            "aos.slice/aos-control.slice/aos-sandbox-network-worker@0-984321-543_876-0.scope",
            "aos.slice/aos-control.slice/other@0-984321-543_876-0.service",
            "aos.slice/aos-control.slice/aos-sandbox-network-worker@0-984321-543_876-0/child.service",
            "aos-control.slice/aos-sandbox-network-worker@0-984321-543_876-0.service",
            "aos.slice/aos-control.slice/aos-sandbox-network-worker@0-984321-0_876-0.service",
            "aos.slice/aos-control.slice/aos-sandbox-network-worker@0-984321-543_0-0.service",
            "aos.slice/aos-control.slice/aos-sandbox-network-worker@00-984321-543_876-0.service",
            "aos.slice/aos-control.slice/aos-sandbox-network-worker@0-0984321-543_876-0.service",
            "aos.slice/aos-control.slice/aos-sandbox-network-worker@0-984321-543-0.service",
            "aos.slice/aos-control.slice/aos-sandbox-network-worker@0-984321-unknown.service",
        ] {
            assert!(WorkerCgroupPlacementV4::Ordinary.require_path(path, WorkerCgroupRoleV4::Preparation).is_err(), "{path}");
        }
    }
}
