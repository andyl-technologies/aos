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

use std::os::fd::OwnedFd;
use std::path::Path;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::cgroup::RetainedCgroupAnchor;
use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceIdentity, NamespaceKind};
use aos_sandbox_linux::seqpacket::{ConnectionPeerIdentity, KernelAuthorizedRecordSubject};

use crate::systemd_socket_instance::validate_systemd_socket_instance_fields;

const READY_MAGIC: &[u8; 8] = b"AOSNRDY1";
const RESULT_MAGIC: &[u8; 8] = b"AOSNRES1";
const ACK_MAGIC: &[u8; 8] = b"AOSNACK1";
const WIRE_VERSION: u16 = 1;
const MUTATION_ROLE: u8 = 1;
const SUCCESS_RESULT: u8 = 1;
const READY_FIXED_BYTES: usize = 32;
const RESULT_BYTES: usize = 128;
const ACK_BYTES: usize = 10;
const MAXIMUM_CGROUP_BYTES: usize = 512;
const CONTROL_SLICE_CGROUP: &str = "aos.slice/aos-control.slice";
const NETD_CGROUP_LEAF: &str = "aos-netd.service";
const WORKER_CGROUP_PREFIX: &str = "aos.slice/aos-control.slice/aos-sandbox-network-worker@";
const WORKER_CGROUP_SUFFIX: &str = ".service";

/// Proves the socket connection was accepted by the current systemd manager.
pub(crate) fn validate_systemd_manager_peer(
    peer: &ConnectionPeerIdentity,
    manager: &RetainedCgroupAnchor,
) -> Result<(), NetworkWorkerProcessError> {
    let credentials = peer.credentials();
    let info = manager.verify_exact_membership(peer.pidfd())?;
    if credentials.pid().get() != 1
        || credentials.uid() != 0
        || credentials.gid() != 0
        || info.pid() != 1
        || info.thread_group_id() != 1
        || !peer.is_alive()?
    {
        return Err(NetworkWorkerProcessError::PeerMismatch);
    }
    manager.validate_current()?;
    Ok(())
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
        validate_worker_cgroup(&cgroup)?;
        if namespace.device == 0 || namespace.inode == 0 {
            return protocol("ready namespace identity is zero");
        }

        Ok(Self { cgroup, namespace })
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, NetworkWorkerProcessError> {
        validate_worker_cgroup(&self.cgroup)?;
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
        if bytes.len() < READY_FIXED_BYTES || bytes.len() > READY_FIXED_BYTES + MAXIMUM_CGROUP_BYTES
        {
            return protocol("ready record has an invalid length");
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take::<8>()? != *READY_MAGIC
            || decoder.u16()? != WIRE_VERSION
            || decoder.byte()? != MUTATION_ROLE
            || decoder.byte()? != 0
        {
            return protocol("ready header is invalid");
        }
        let cgroup_length = usize::from(decoder.u16()?);
        if decoder.take::<2>()? != [0; 2]
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

        let ready = Self::new(cgroup, namespace)?;
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
        let mut decoder = Decoder::new(bytes);
        if decoder.take::<8>()? != *RESULT_MAGIC
            || decoder.u16()? != WIRE_VERSION
            || decoder.byte()? != SUCCESS_RESULT
            || decoder.byte()? != 0
            || decoder.u32()? != RESULT_BYTES as u32
        {
            return protocol("result header is invalid");
        }
        let result = Self::new(
            decoder.take()?,
            ObjectDigest::from_bytes(decoder.take()?),
            ObjectDigest::from_bytes(decoder.take()?),
            decoder.take()?,
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

/// Validates a READY subject and adopts its sole target namespace descriptor.
pub(crate) fn validate_worker_ready(
    ready: &NetworkWorkerReadyV1,
    subject: &KernelAuthorizedRecordSubject,
    descriptors: Vec<OwnedFd>,
    worker_parent: &RetainedCgroupAnchor,
    host_namespace: &NamespaceFd,
) -> Result<(RetainedCgroupAnchor, NamespaceFd), NetworkWorkerProcessError> {
    if descriptors.len() != 1 {
        return protocol("READY requires exactly one namespace descriptor");
    }
    let credentials = subject.credentials();
    if credentials.uid() != 0 || credentials.gid() != 0 {
        return Err(NetworkWorkerProcessError::PeerMismatch);
    }
    let relative = Path::new(ready.cgroup())
        .strip_prefix(CONTROL_SLICE_CGROUP)
        .map_err(|_| NetworkWorkerProcessError::PeerMismatch)?;
    let worker_cgroup = worker_parent.resolve_descendant(relative)?;
    let info = worker_cgroup.verify_exact_membership(subject.pidfd())?;
    if info.pid() != credentials.pid().get() || info.thread_group_id() != credentials.pid().get() {
        return Err(NetworkWorkerProcessError::PeerMismatch);
    }

    let mut descriptors = descriptors;
    let descriptor = descriptors
        .pop()
        .ok_or(NetworkWorkerProcessError::Protocol(
            "READY namespace descriptor is absent",
        ))?;
    let target = NamespaceFd::from_owned(descriptor, NamespaceKind::Network)?;
    let subject_namespace = subject.pidfd().namespace(NamespaceKind::Network)?;
    if target.identity() != ready.namespace()
        || target.identity() != subject_namespace.identity()
        || target.identity() == host_namespace.identity()
        || !subject.is_alive()?
    {
        return Err(NetworkWorkerProcessError::PeerMismatch);
    }
    worker_cgroup.verify_exact_membership(subject.pidfd())?;
    worker_cgroup.validate_current()?;
    worker_parent.validate_current()?;
    Ok((worker_cgroup, target))
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
    let credentials = subject.credentials();
    let info = worker_cgroup.verify_exact_membership(subject.pidfd())?;
    if credentials.uid() != 0
        || credentials.gid() != 0
        || info.pid() != credentials.pid().get()
        || info.thread_group_id() != credentials.pid().get()
    {
        return Err(NetworkWorkerProcessError::PeerMismatch);
    }
    worker_cgroup.validate_current()?;
    Ok(())
}

pub(crate) fn validate_same_worker_execution(
    ready: &KernelAuthorizedRecordSubject,
    result: &KernelAuthorizedRecordSubject,
) -> Result<(), NetworkWorkerProcessError> {
    if !ready.is_alive()?
        || !result.is_alive()?
        || ready.credentials() != result.credentials()
        || ready.initial_info().pid() != result.initial_info().pid()
        || ready.initial_info().thread_group_id() != result.initial_info().thread_group_id()
        || ready.initial_info().cgroup_id() != result.initial_info().cgroup_id()
    {
        return Err(NetworkWorkerProcessError::PeerMismatch);
    }
    Ok(())
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

fn validate_worker_cgroup(path: &str) -> Result<(), NetworkWorkerProcessError> {
    let Some(instance) = path
        .strip_prefix(WORKER_CGROUP_PREFIX)
        .and_then(|value| value.strip_suffix(WORKER_CGROUP_SUFFIX))
    else {
        return Err(NetworkWorkerProcessError::PeerMismatch);
    };
    validate_systemd_socket_instance_fields(instance)
        .map_err(|_| NetworkWorkerProcessError::PeerMismatch)
}

fn protocol<T>(message: &'static str) -> Result<T, NetworkWorkerProcessError> {
    Err(NetworkWorkerProcessError::Protocol(message))
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn byte(&mut self) -> Result<u8, NetworkWorkerProcessError> {
        Ok(self.take::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, NetworkWorkerProcessError> {
        Ok(u16::from_be_bytes(self.take()?))
    }

    fn u32(&mut self) -> Result<u32, NetworkWorkerProcessError> {
        Ok(u32::from_be_bytes(self.take()?))
    }

    fn u64(&mut self) -> Result<u64, NetworkWorkerProcessError> {
        Ok(u64::from_be_bytes(self.take()?))
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], NetworkWorkerProcessError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(NetworkWorkerProcessError::Protocol(
                "record offset overflowed",
            ))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(NetworkWorkerProcessError::Protocol("record is truncated"))?;
        self.offset = end;
        value
            .try_into()
            .map_err(|_| NetworkWorkerProcessError::Protocol("record is truncated"))
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], NetworkWorkerProcessError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(NetworkWorkerProcessError::Protocol(
                "record offset overflowed",
            ))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(NetworkWorkerProcessError::Protocol("record is truncated"))?;
        self.offset = end;
        Ok(value)
    }

    fn finish(self) -> Result<(), NetworkWorkerProcessError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            protocol("record has trailing bytes")
        }
    }
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
    fn only_the_exact_reserved_worker_cgroup_language_is_accepted() {
        assert!(validate_worker_cgroup(ready().cgroup()).is_ok());
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
            assert!(validate_worker_cgroup(path).is_err(), "{path}");
        }
    }
}
