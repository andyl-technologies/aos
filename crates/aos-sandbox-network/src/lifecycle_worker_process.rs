//! Process-authenticated admission records for existing Network resources.
//!
//! The lifecycle worker receives no Network authority or journal MAC key. The
//! broker authenticates the exact lifecycle dispatch before transfer. The
//! worker then correlates canonical bytes and a retyped target namespace with
//! records from the kernel-proved broker execution. Its acknowledgement is not
//! an authorization, effect receipt, or kernel postcondition.

use std::path::Path;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::cgroup::RetainedCgroupAnchor;
use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceIdentity, NamespaceKind};
use aos_sandbox_linux::seqpacket::KernelAuthorizedRecordSubject;

use crate::systemd_socket_instance::validate_systemd_socket_instance_fields;
use crate::worker_process::NetworkWorkerProcessError;

const CHALLENGE_MAGIC: &[u8; 8] = b"AOSNLCH1";
const READY_MAGIC: &[u8; 8] = b"AOSNLBR1";
const ACK_MAGIC: &[u8; 8] = b"AOSNLAD1";
const VERSION: u16 = 1;
const CHALLENGE_KIND: u8 = 1;
const READY_KIND: u8 = 2;
const ACK_KIND: u8 = 3;
const MUTATION_ROLE: u8 = 1;
const CHALLENGE_BYTES: usize = 132;
const READY_FIXED_BYTES: usize = 152;
const ACK_BYTES: usize = 164;
const MAXIMUM_CGROUP_BYTES: usize = 512;
const CONTROL_SLICE_CGROUP: &str = "aos.slice/aos-control.slice";
const LIFECYCLE_WORKER_CGROUP_PREFIX: &str =
    "aos.slice/aos-control.slice/aos-sandbox-network-lifecycle-worker@";
const WORKER_CGROUP_SUFFIX: &str = ".service";

/// Commits one fresh admission exchange to exact lifecycle dispatch bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NetworkLifecycleWorkerChallengeV1 {
    nonce: [u8; 32],
    dispatch_digest: ObjectDigest,
    request_id: [u8; 16],
    effect_digest: ObjectDigest,
}

impl NetworkLifecycleWorkerChallengeV1 {
    pub(crate) fn new(
        nonce: [u8; 32],
        dispatch_digest: ObjectDigest,
        request_id: [u8; 16],
        effect_digest: ObjectDigest,
    ) -> Result<Self, NetworkWorkerProcessError> {
        if nonce == [0; 32]
            || dispatch_digest.as_bytes() == &[0; 32]
            || request_id == [0; 16]
            || effect_digest.as_bytes() == &[0; 32]
        {
            return protocol("lifecycle challenge contains a reserved identity");
        }
        Ok(Self {
            nonce,
            dispatch_digest,
            request_id,
            effect_digest,
        })
    }

    pub(crate) fn encode(self) -> [u8; CHALLENGE_BYTES] {
        let mut bytes = [0_u8; CHALLENGE_BYTES];
        encode_header(&mut bytes, CHALLENGE_MAGIC, CHALLENGE_KIND, CHALLENGE_BYTES);
        bytes[20..52].copy_from_slice(&self.nonce);
        bytes[52..84].copy_from_slice(self.dispatch_digest.as_bytes());
        bytes[84..100].copy_from_slice(&self.request_id);
        bytes[100..132].copy_from_slice(self.effect_digest.as_bytes());
        bytes
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, NetworkWorkerProcessError> {
        validate_header(bytes, CHALLENGE_MAGIC, CHALLENGE_KIND, CHALLENGE_BYTES)?;
        let challenge = Self::new(
            copy_array(&bytes[20..52])?,
            ObjectDigest::from_bytes(copy_array(&bytes[52..84])?),
            copy_array(&bytes[84..100])?,
            ObjectDigest::from_bytes(copy_array(&bytes[100..132])?),
        )?;
        if challenge.encode().as_slice() != bytes {
            return protocol("lifecycle challenge is not canonical");
        }
        Ok(challenge)
    }

    pub(crate) const fn nonce(self) -> [u8; 32] {
        self.nonce
    }

    pub(crate) const fn dispatch_digest(self) -> ObjectDigest {
        self.dispatch_digest
    }

    pub(crate) const fn request_id(self) -> [u8; 16] {
        self.request_id
    }

    pub(crate) const fn effect_digest(self) -> ObjectDigest {
        self.effect_digest
    }
}

/// Correlates the challenged exchange with the worker's fresh bootstrap namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NetworkLifecycleWorkerBootstrapReadyV1 {
    challenge: NetworkLifecycleWorkerChallengeV1,
    bootstrap: NamespaceIdentity,
    cgroup: String,
}

impl NetworkLifecycleWorkerBootstrapReadyV1 {
    pub(crate) fn new(
        challenge: NetworkLifecycleWorkerChallengeV1,
        bootstrap: NamespaceIdentity,
        cgroup: String,
    ) -> Result<Self, NetworkWorkerProcessError> {
        validate_lifecycle_worker_cgroup(&cgroup)?;
        validate_namespace(bootstrap, "lifecycle bootstrap namespace is zero")?;
        Ok(Self {
            challenge,
            bootstrap,
            cgroup,
        })
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, NetworkWorkerProcessError> {
        validate_lifecycle_worker_cgroup(&self.cgroup)?;
        let cgroup = self.cgroup.as_bytes();
        let cgroup_length = u16::try_from(cgroup.len()).map_err(|_| {
            NetworkWorkerProcessError::Protocol("lifecycle READY cgroup is too long")
        })?;
        let total = READY_FIXED_BYTES.checked_add(cgroup.len()).ok_or(
            NetworkWorkerProcessError::Protocol("lifecycle READY length overflowed"),
        )?;
        if cgroup.is_empty() || cgroup.len() > MAXIMUM_CGROUP_BYTES {
            return protocol("lifecycle READY cgroup length is invalid");
        }

        let mut bytes = vec![0_u8; total];
        encode_header(&mut bytes, READY_MAGIC, READY_KIND, total);
        encode_challenge_fields(&mut bytes[20..132], self.challenge);
        bytes[132..140].copy_from_slice(&self.bootstrap.device.to_be_bytes());
        bytes[140..148].copy_from_slice(&self.bootstrap.inode.to_be_bytes());
        bytes[148..150].copy_from_slice(&cgroup_length.to_be_bytes());
        bytes[152..].copy_from_slice(cgroup);
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, NetworkWorkerProcessError> {
        if bytes.len() < READY_FIXED_BYTES || bytes.len() > READY_FIXED_BYTES + MAXIMUM_CGROUP_BYTES
        {
            return protocol("lifecycle READY length is invalid");
        }
        validate_header(bytes, READY_MAGIC, READY_KIND, bytes.len())?;
        let challenge = decode_challenge_fields(&bytes[20..132])?;
        let bootstrap = NamespaceIdentity {
            device: u64::from_be_bytes(copy_array(&bytes[132..140])?),
            inode: u64::from_be_bytes(copy_array(&bytes[140..148])?),
        };
        let cgroup_length = usize::from(u16::from_be_bytes(copy_array(&bytes[148..150])?));
        if bytes[150..152] != [0; 2]
            || cgroup_length == 0
            || cgroup_length > MAXIMUM_CGROUP_BYTES
            || bytes.len() != READY_FIXED_BYTES + cgroup_length
        {
            return protocol("lifecycle READY reserved or cgroup length is invalid");
        }
        let cgroup = std::str::from_utf8(&bytes[152..])
            .map_err(|_| {
                NetworkWorkerProcessError::Protocol("lifecycle READY cgroup is not UTF-8")
            })?
            .to_owned();
        let ready = Self::new(challenge, bootstrap, cgroup)?;
        if ready.encode()? != bytes {
            return protocol("lifecycle READY is not canonical");
        }
        Ok(ready)
    }

    pub(crate) const fn challenge(&self) -> NetworkLifecycleWorkerChallengeV1 {
        self.challenge
    }

    pub(crate) const fn bootstrap(&self) -> NamespaceIdentity {
        self.bootstrap
    }

    pub(crate) fn cgroup(&self) -> &str {
        &self.cgroup
    }
}

/// Correlates admission with the namespace identity measured from the received FD.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NetworkLifecycleWorkerAdmittedV1 {
    challenge: NetworkLifecycleWorkerChallengeV1,
    bootstrap: NamespaceIdentity,
    target: NamespaceIdentity,
}

impl NetworkLifecycleWorkerAdmittedV1 {
    pub(crate) fn new(
        challenge: NetworkLifecycleWorkerChallengeV1,
        bootstrap: NamespaceIdentity,
        target: NamespaceIdentity,
    ) -> Result<Self, NetworkWorkerProcessError> {
        validate_namespace(bootstrap, "lifecycle ACK bootstrap namespace is zero")?;
        validate_namespace(target, "lifecycle ACK target namespace is zero")?;
        if bootstrap == target {
            return Err(NetworkWorkerProcessError::PeerMismatch);
        }
        Ok(Self {
            challenge,
            bootstrap,
            target,
        })
    }

    pub(crate) fn encode(self) -> [u8; ACK_BYTES] {
        let mut bytes = [0_u8; ACK_BYTES];
        encode_header(&mut bytes, ACK_MAGIC, ACK_KIND, ACK_BYTES);
        encode_challenge_fields(&mut bytes[20..132], self.challenge);
        bytes[132..140].copy_from_slice(&self.bootstrap.device.to_be_bytes());
        bytes[140..148].copy_from_slice(&self.bootstrap.inode.to_be_bytes());
        bytes[148..156].copy_from_slice(&self.target.device.to_be_bytes());
        bytes[156..164].copy_from_slice(&self.target.inode.to_be_bytes());
        bytes
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, NetworkWorkerProcessError> {
        validate_header(bytes, ACK_MAGIC, ACK_KIND, ACK_BYTES)?;
        let admitted = Self::new(
            decode_challenge_fields(&bytes[20..132])?,
            NamespaceIdentity {
                device: u64::from_be_bytes(copy_array(&bytes[132..140])?),
                inode: u64::from_be_bytes(copy_array(&bytes[140..148])?),
            },
            NamespaceIdentity {
                device: u64::from_be_bytes(copy_array(&bytes[148..156])?),
                inode: u64::from_be_bytes(copy_array(&bytes[156..164])?),
            },
        )?;
        if admitted.encode().as_slice() != bytes {
            return protocol("lifecycle ACK is not canonical");
        }
        Ok(admitted)
    }

    pub(crate) const fn challenge(self) -> NetworkLifecycleWorkerChallengeV1 {
        self.challenge
    }

    pub(crate) const fn bootstrap(self) -> NamespaceIdentity {
        self.bootstrap
    }

    pub(crate) const fn target(self) -> NamespaceIdentity {
        self.target
    }
}

/// Proves READY came from one live manager-created lifecycle worker.
pub(crate) fn validate_lifecycle_worker_ready(
    ready: &NetworkLifecycleWorkerBootstrapReadyV1,
    subject: &KernelAuthorizedRecordSubject,
    worker_parent: &RetainedCgroupAnchor,
    host: &NamespaceFd,
    target: &NamespaceFd,
) -> Result<(RetainedCgroupAnchor, NamespaceFd), NetworkWorkerProcessError> {
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

    let bootstrap = subject.pidfd().namespace(NamespaceKind::Network)?;
    let identities = [host.identity(), bootstrap.identity(), target.identity()];
    if bootstrap.identity() != ready.bootstrap()
        || identities[0] == identities[1]
        || identities[0] == identities[2]
        || identities[1] == identities[2]
        || !subject.is_alive()?
    {
        return Err(NetworkWorkerProcessError::PeerMismatch);
    }
    worker_cgroup.verify_exact_membership(subject.pidfd())?;
    worker_cgroup.validate_current()?;
    worker_parent.validate_current()?;
    Ok((worker_cgroup, bootstrap))
}

/// Rechecks one later record against the retained READY execution and cgroup.
pub(crate) fn validate_same_lifecycle_worker(
    ready: &KernelAuthorizedRecordSubject,
    later: &KernelAuthorizedRecordSubject,
    worker_cgroup: &RetainedCgroupAnchor,
    bootstrap: &NamespaceFd,
) -> Result<(), NetworkWorkerProcessError> {
    let ready_credentials = ready.credentials();
    let later_credentials = later.credentials();
    if ready_credentials != later_credentials
        || ready.initial_info().pid() != later.initial_info().pid()
        || ready.initial_info().thread_group_id() != later.initial_info().thread_group_id()
        || ready.initial_info().cgroup_id() != later.initial_info().cgroup_id()
        || !ready.is_alive()?
        || !later.is_alive()?
    {
        return Err(NetworkWorkerProcessError::PeerMismatch);
    }
    let info = worker_cgroup.verify_exact_membership(later.pidfd())?;
    if info.pid() != later_credentials.pid().get()
        || info.thread_group_id() != later_credentials.pid().get()
        || later.pidfd().namespace(NamespaceKind::Network)?.identity() != bootstrap.identity()
    {
        return Err(NetworkWorkerProcessError::PeerMismatch);
    }
    worker_cgroup.validate_current()?;
    Ok(())
}

/// Rechecks the READY process, cgroup, and bootstrap namespace before transfer.
pub(crate) fn revalidate_lifecycle_worker_before_dispatch(
    subject: &KernelAuthorizedRecordSubject,
    worker_cgroup: &RetainedCgroupAnchor,
    bootstrap: &NamespaceFd,
) -> Result<(), NetworkWorkerProcessError> {
    validate_same_lifecycle_worker(subject, subject, worker_cgroup, bootstrap)
}

fn validate_lifecycle_worker_cgroup(cgroup: &str) -> Result<(), NetworkWorkerProcessError> {
    let Some(instance) = cgroup
        .strip_prefix(LIFECYCLE_WORKER_CGROUP_PREFIX)
        .and_then(|value| value.strip_suffix(WORKER_CGROUP_SUFFIX))
    else {
        return Err(NetworkWorkerProcessError::PeerMismatch);
    };
    validate_systemd_socket_instance_fields(instance)
        .map_err(|_| NetworkWorkerProcessError::PeerMismatch)
}

fn encode_header(bytes: &mut [u8], magic: &[u8; 8], kind: u8, total: usize) {
    bytes[..8].copy_from_slice(magic);
    bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
    bytes[10] = kind;
    bytes[11] = MUTATION_ROLE;
    bytes[12..16].copy_from_slice(&(total as u32).to_be_bytes());
}

fn validate_header(
    bytes: &[u8],
    magic: &[u8; 8],
    kind: u8,
    total: usize,
) -> Result<(), NetworkWorkerProcessError> {
    if bytes.len() != total
        || bytes.get(..8) != Some(magic.as_slice())
        || bytes.get(8..10) != Some(VERSION.to_be_bytes().as_slice())
        || bytes.get(10) != Some(&kind)
        || bytes.get(11) != Some(&MUTATION_ROLE)
        || bytes.get(12..16) != Some((total as u32).to_be_bytes().as_slice())
        || bytes.get(16..20) != Some([0; 4].as_slice())
    {
        return protocol("lifecycle process header is invalid");
    }
    Ok(())
}

fn encode_challenge_fields(bytes: &mut [u8], challenge: NetworkLifecycleWorkerChallengeV1) {
    bytes[..32].copy_from_slice(&challenge.nonce);
    bytes[32..64].copy_from_slice(challenge.dispatch_digest.as_bytes());
    bytes[64..80].copy_from_slice(&challenge.request_id);
    bytes[80..112].copy_from_slice(challenge.effect_digest.as_bytes());
}

fn decode_challenge_fields(
    bytes: &[u8],
) -> Result<NetworkLifecycleWorkerChallengeV1, NetworkWorkerProcessError> {
    if bytes.len() != 112 {
        return protocol("lifecycle challenge fields have an invalid length");
    }
    NetworkLifecycleWorkerChallengeV1::new(
        copy_array(&bytes[..32])?,
        ObjectDigest::from_bytes(copy_array(&bytes[32..64])?),
        copy_array(&bytes[64..80])?,
        ObjectDigest::from_bytes(copy_array(&bytes[80..112])?),
    )
}

fn validate_namespace(
    namespace: NamespaceIdentity,
    message: &'static str,
) -> Result<(), NetworkWorkerProcessError> {
    if namespace.device == 0 || namespace.inode == 0 {
        protocol(message)
    } else {
        Ok(())
    }
}

fn copy_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], NetworkWorkerProcessError> {
    bytes
        .try_into()
        .map_err(|_| NetworkWorkerProcessError::Protocol("lifecycle process record is truncated"))
}

fn protocol<T>(message: &'static str) -> Result<T, NetworkWorkerProcessError> {
    Err(NetworkWorkerProcessError::Protocol(message))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn challenge() -> NetworkLifecycleWorkerChallengeV1 {
        NetworkLifecycleWorkerChallengeV1::new(
            [1; 32],
            ObjectDigest::from_bytes([2; 32]),
            [3; 16],
            ObjectDigest::from_bytes([4; 32]),
        )
        .unwrap()
    }

    fn cgroup() -> String {
        format!("{LIFECYCLE_WORKER_CGROUP_PREFIX}0-984321-543_876-0{WORKER_CGROUP_SUFFIX}")
    }

    #[test]
    fn challenge_ready_and_admitted_ack_round_trip_canonically() {
        let challenge = challenge();
        assert_eq!(
            NetworkLifecycleWorkerChallengeV1::decode(&challenge.encode()).unwrap(),
            challenge
        );

        let bootstrap = NamespaceIdentity {
            device: 5,
            inode: 6,
        };
        let ready =
            NetworkLifecycleWorkerBootstrapReadyV1::new(challenge, bootstrap, cgroup()).unwrap();
        assert_eq!(
            NetworkLifecycleWorkerBootstrapReadyV1::decode(&ready.encode().unwrap()).unwrap(),
            ready
        );

        let admitted = NetworkLifecycleWorkerAdmittedV1::new(
            challenge,
            bootstrap,
            NamespaceIdentity {
                device: 7,
                inode: 8,
            },
        )
        .unwrap();
        assert_eq!(
            NetworkLifecycleWorkerAdmittedV1::decode(&admitted.encode()).unwrap(),
            admitted
        );
    }

    #[test]
    fn every_header_field_and_reserved_identity_fails_closed() {
        let valid = challenge().encode();
        for offset in 0..20 {
            let mut changed = valid;
            changed[offset] ^= 0x80;
            assert!(NetworkLifecycleWorkerChallengeV1::decode(&changed).is_err());
        }
        for range in [20..52, 52..84, 84..100, 100..132] {
            let mut changed = valid;
            changed[range].fill(0);
            assert!(NetworkLifecycleWorkerChallengeV1::decode(&changed).is_err());
        }
    }

    #[test]
    fn wrong_cgroup_alias_and_equal_namespaces_fail_closed() {
        let namespace = NamespaceIdentity {
            device: 9,
            inode: 10,
        };
        assert!(
            NetworkLifecycleWorkerBootstrapReadyV1::new(
                challenge(),
                namespace,
                "aos.slice/aos-control.slice/aos-sandbox-network-worker@0-1-2_3-0.service"
                    .to_owned(),
            )
            .is_err()
        );
        assert!(NetworkLifecycleWorkerAdmittedV1::new(challenge(), namespace, namespace).is_err());
    }
}
