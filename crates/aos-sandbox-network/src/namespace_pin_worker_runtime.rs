//! One-shot host-mount-namespace worker for Network pin teardown.
//!
//! The capability-free broker authenticates a fresh systemd worker, sends one
//! fixed remove request, and accepts success only after the same process
//! acknowledges the exact request digest and its entire cgroup becomes empty.

use std::os::fd::{AsFd as _, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::Duration;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::pidfd::{NamespaceIdentity, SingleThreadedProcess};
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_linux::seqpacket::{KernelAuthorizedRecordSubject, SeqpacketError};
use sha2::{Digest as _, Sha256};

use crate::namespace_pin::{NetworkNamespacePinMutationError, remove_namespace_pin};
use crate::systemd_socket_instance::validate_systemd_socket_instance_fields;
use crate::worker_process::{
    NetworkWorkerProcessError, acknowledgement, decode_acknowledgement, validate_broker_peer,
    validate_broker_subject, validate_same_worker_execution, validate_systemd_manager_peer,
};
use crate::worker_runtime::{
    NetworkWorkerRuntimeError, current_cgroup, deadline_after, normalized_absolute_path,
    open_cgroup_root, quiesce_worker, receive_record_before, send_record_before,
    wait_for_quiescence,
};

const SYSTEMD_MANAGER_CGROUP: &str = "init.scope";
const CONTROL_SLICE_CGROUP: &str = "aos.slice/aos-control.slice";
const WORKER_CGROUP_PREFIX: &str = "aos.slice/aos-control.slice/aos-sandbox-network-pin-worker@";
const WORKER_CGROUP_SUFFIX: &str = ".service";
const READY_MAGIC: &[u8; 8] = b"AOSNPRD1";
const REQUEST_MAGIC: &[u8; 8] = b"AOSNPRQ1";
const RESPONSE_MAGIC: &[u8; 8] = b"AOSNPRS1";
const WIRE_VERSION: u16 = 1;
const READY_KIND: u8 = 1;
const REQUEST_KIND: u8 = 2;
const RESPONSE_KIND: u8 = 3;
const READY_HEADER_BYTES: usize = 16;
const REQUEST_BYTES: usize = 112;
const RESPONSE_BYTES: usize = 48;
const MAXIMUM_CGROUP_BYTES: usize = 512;
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(5);
const NATURAL_EXIT_TIMEOUT: Duration = Duration::from_secs(1);

/// Reports rejected pin-worker transport, authority, or mutation.
#[derive(Debug, thiserror::Error)]
pub enum NetworkNamespacePinWorkerError {
    /// Fixed framing, identity, or path input was malformed.
    #[error("Network namespace pin worker protocol is invalid: {0}")]
    Protocol(&'static str),
    /// The systemd worker or broker process was substituted.
    #[error(transparent)]
    Process(#[from] NetworkWorkerProcessError),
    /// Shared bounded transport or quiescence failed.
    #[error(transparent)]
    Runtime(#[from] NetworkWorkerRuntimeError),
    /// The descriptor-capable sequenced-packet transport failed.
    #[error(transparent)]
    Transport(#[from] SeqpacketError),
    /// The exact host-visible pin could not be removed safely.
    #[error(transparent)]
    Mutation(#[from] NetworkNamespacePinMutationError),
    /// A namespace, cgroup, or process descriptor operation failed.
    #[error(transparent)]
    Linux(#[from] aos_sandbox_linux::Error),
    /// A direct descriptor operation failed.
    #[error("Network namespace pin worker descriptor operation failed: {0}")]
    Descriptor(#[from] rustix::io::Errno),
}

/// Executes exact namespace-pin teardown through a fresh systemd worker.
pub struct SystemdNetworkNamespacePinExecutor {
    socket_path: PathBuf,
    systemd_manager_cgroup: RetainedCgroupAnchor,
    worker_parent_cgroup: RetainedCgroupAnchor,
    fail_stopped: bool,
}

impl SystemdNetworkNamespacePinExecutor {
    /// Retains the fixed socket and manager/control-slice cgroup roots.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe socket path or unavailable cgroup root.
    pub fn new(
        socket_path: PathBuf,
        cgroup_root: CgroupV2Root,
    ) -> Result<Self, NetworkNamespacePinWorkerError> {
        if !normalized_absolute_path(&socket_path) {
            return Err(NetworkNamespacePinWorkerError::Protocol(
                "unsafe Network namespace pin-worker socket path",
            ));
        }
        Ok(Self {
            socket_path,
            systemd_manager_cgroup: cgroup_root.resolve(Path::new(SYSTEMD_MANAGER_CGROUP))?,
            worker_parent_cgroup: cgroup_root.resolve(Path::new(CONTROL_SLICE_CGROUP))?,
            fail_stopped: false,
        })
    }

    /// Removes one exact namespace pin and proves whole-worker quiescence.
    ///
    /// # Errors
    ///
    /// Returns an error for worker substitution, malformed correlation,
    /// mutation failure, timeout, or unproved cancellation. Failure to prove
    /// cancellation permanently fail-stops this executor.
    pub fn remove_once(
        &mut self,
        request_id: [u8; 16],
        effect_digest: ObjectDigest,
        network_handle: [u8; 32],
        expected: NamespaceIdentity,
    ) -> Result<ObjectDigest, NetworkNamespacePinWorkerError> {
        self.execute_removal(request_id, effect_digest, network_handle, expected, false)
    }

    /// Reconciles one exact namespace pin, accepting already-proved absence.
    ///
    /// # Errors
    ///
    /// Returns the same fail-closed errors as [`Self::remove_once`]. Present
    /// pins must still reproduce `expected` before removal.
    pub fn reconcile_once(
        &mut self,
        request_id: [u8; 16],
        effect_digest: ObjectDigest,
        network_handle: [u8; 32],
        expected: NamespaceIdentity,
    ) -> Result<ObjectDigest, NetworkNamespacePinWorkerError> {
        self.execute_removal(request_id, effect_digest, network_handle, expected, true)
    }

    fn execute_removal(
        &mut self,
        request_id: [u8; 16],
        effect_digest: ObjectDigest,
        network_handle: [u8; 32],
        expected: NamespaceIdentity,
        allow_absent: bool,
    ) -> Result<ObjectDigest, NetworkNamespacePinWorkerError> {
        if self.fail_stopped {
            return protocol("Network namespace pin executor is fail-stopped");
        }
        let request = PinRemovalRequestV1::new(
            request_id,
            effect_digest,
            network_handle,
            expected,
            allow_absent,
        )?;
        let request_bytes = request.encode();
        let request_digest = ObjectDigest::from_bytes(Sha256::digest(&request_bytes).into());
        let mut socket = DescriptorSubjectSocket::connect(&self.socket_path)?;
        validate_systemd_manager_peer(socket.peer(), &self.systemd_manager_cgroup)?;
        let ready = receive_record_before(
            &mut socket,
            READY_HEADER_BYTES + MAXIMUM_CGROUP_BYTES,
            0,
            deadline_after(TRANSFER_TIMEOUT)?,
        )?;
        let ready_payload = PinWorkerReadyV1::decode(ready.payload())?;
        let worker_cgroup = validate_pin_worker_subject(
            ready_payload.cgroup(),
            ready.subject(),
            &self.worker_parent_cgroup,
        )?;
        let population = worker_cgroup.population_monitor()?;

        let exchange = (|| {
            send_record_before(
                &mut socket,
                &request_bytes,
                deadline_after(TRANSFER_TIMEOUT)?,
            )?;
            let response = receive_record_before(
                &mut socket,
                RESPONSE_BYTES,
                0,
                deadline_after(TRANSFER_TIMEOUT)?,
            )?;
            validate_same_worker_execution(ready.subject(), response.subject())?;
            validate_pin_worker_subject_record(response.subject(), &worker_cgroup)?;
            let response_digest = decode_response(response.payload())?;
            if response_digest != request_digest {
                return protocol("Network namespace pin response correlation changed");
            }
            send_record_before(
                &mut socket,
                &acknowledgement(),
                deadline_after(TRANSFER_TIMEOUT)?,
            )?;
            Ok(request_digest)
        })();

        match exchange {
            Ok(digest) => {
                match wait_for_quiescence(ready.subject(), &population, NATURAL_EXIT_TIMEOUT) {
                    Ok(()) => Ok(digest),
                    Err(error) => {
                        if quiesce_worker(ready.subject(), &worker_cgroup, &population).is_err() {
                            self.fail_stopped = true;
                        }
                        Err(error.into())
                    }
                }
            }
            Err(error) => {
                if quiesce_worker(ready.subject(), &worker_cgroup, &population).is_err() {
                    self.fail_stopped = true;
                }
                Err(error)
            }
        }
    }
}

/// Runs one inherited host-mount-namespace pin teardown worker.
///
/// # Errors
///
/// Returns an error unless the broker, exact request, fixed pin, response, and
/// final acknowledgement all validate within the one-record service lifetime.
pub fn run_inherited_network_namespace_pin_worker() -> Result<(), NetworkNamespacePinWorkerError> {
    let worker = SingleThreadedProcess::verify()?;
    worker.disable_core_dumps()?;
    let cgroup_root = open_cgroup_root()?;
    let control_cgroup = cgroup_root.resolve(Path::new(CONTROL_SLICE_CGROUP))?;
    let descriptor: OwnedFd = rustix::io::dup(std::io::stdin().as_fd())?;
    let mut socket = DescriptorSubjectSocket::from_owned(descriptor)?;
    validate_broker_peer(socket.peer(), &control_cgroup)?;

    let ready = PinWorkerReadyV1::new(current_cgroup()?)?;
    send_record_before(
        &mut socket,
        &ready.encode()?,
        deadline_after(TRANSFER_TIMEOUT)?,
    )?;
    let request_record = receive_record_before(
        &mut socket,
        REQUEST_BYTES,
        0,
        deadline_after(TRANSFER_TIMEOUT)?,
    )?;
    validate_broker_subject(socket.peer(), request_record.subject(), &control_cgroup)?;
    let request = PinRemovalRequestV1::decode(request_record.payload())?;
    remove_namespace_pin(
        request.network_handle,
        NamespaceIdentity {
            device: request.namespace_device,
            inode: request.namespace_inode,
        },
        request.allow_absent,
    )?;
    let request_digest = ObjectDigest::from_bytes(Sha256::digest(request_record.payload()).into());
    send_record_before(
        &mut socket,
        &encode_response(request_digest),
        deadline_after(TRANSFER_TIMEOUT)?,
    )?;
    let acknowledgement_record = receive_record_before(
        &mut socket,
        acknowledgement().len(),
        0,
        deadline_after(TRANSFER_TIMEOUT)?,
    )?;
    validate_broker_subject(
        socket.peer(),
        acknowledgement_record.subject(),
        &control_cgroup,
    )?;
    decode_acknowledgement(acknowledgement_record.payload())?;
    Ok(())
}

struct PinWorkerReadyV1 {
    cgroup: String,
}

impl PinWorkerReadyV1 {
    fn new(cgroup: String) -> Result<Self, NetworkNamespacePinWorkerError> {
        validate_pin_worker_cgroup(&cgroup)?;
        Ok(Self { cgroup })
    }

    fn cgroup(&self) -> &str {
        &self.cgroup
    }

    fn encode(&self) -> Result<Vec<u8>, NetworkNamespacePinWorkerError> {
        validate_pin_worker_cgroup(&self.cgroup)?;
        let length = u16::try_from(self.cgroup.len()).map_err(|_| {
            NetworkNamespacePinWorkerError::Protocol("pin-worker cgroup is too long")
        })?;
        let mut bytes = Vec::with_capacity(READY_HEADER_BYTES + self.cgroup.len());
        bytes.extend_from_slice(READY_MAGIC);
        bytes.extend_from_slice(&WIRE_VERSION.to_be_bytes());
        bytes.push(READY_KIND);
        bytes.push(0);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(self.cgroup.as_bytes());
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, NetworkNamespacePinWorkerError> {
        if bytes.len() < READY_HEADER_BYTES
            || bytes.len() > READY_HEADER_BYTES + MAXIMUM_CGROUP_BYTES
            || &bytes[..8] != READY_MAGIC
            || u16::from_be_bytes(copy_array(&bytes[8..10])?) != WIRE_VERSION
            || bytes[10] != READY_KIND
            || bytes[11] != 0
            || bytes[14..16] != [0; 2]
        {
            return protocol("Network namespace pin READY header is invalid");
        }
        let length = usize::from(u16::from_be_bytes(copy_array(&bytes[12..14])?));
        if READY_HEADER_BYTES.checked_add(length) != Some(bytes.len()) {
            return protocol("Network namespace pin READY length differs");
        }
        let cgroup = std::str::from_utf8(&bytes[READY_HEADER_BYTES..])
            .map_err(|_| {
                NetworkNamespacePinWorkerError::Protocol("pin-worker cgroup is not UTF-8")
            })?
            .to_owned();
        Self::new(cgroup)
    }
}

#[derive(Clone, Copy)]
struct PinRemovalRequestV1 {
    request_id: [u8; 16],
    effect_digest: ObjectDigest,
    network_handle: [u8; 32],
    namespace_device: u64,
    namespace_inode: u64,
    allow_absent: bool,
}

impl PinRemovalRequestV1 {
    fn new(
        request_id: [u8; 16],
        effect_digest: ObjectDigest,
        network_handle: [u8; 32],
        namespace: NamespaceIdentity,
        allow_absent: bool,
    ) -> Result<Self, NetworkNamespacePinWorkerError> {
        let request = Self {
            request_id,
            effect_digest,
            network_handle,
            namespace_device: namespace.device,
            namespace_inode: namespace.inode,
            allow_absent,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(self) -> Result<(), NetworkNamespacePinWorkerError> {
        if self.request_id == [0; 16]
            || self.effect_digest.as_bytes() == &[0; 32]
            || self.network_handle == [0; 32]
            || self.namespace_device == 0
            || self.namespace_inode == 0
        {
            return protocol("Network namespace pin request identity is invalid");
        }
        Ok(())
    }

    fn encode(self) -> [u8; REQUEST_BYTES] {
        let mut bytes = [0_u8; REQUEST_BYTES];
        bytes[..8].copy_from_slice(REQUEST_MAGIC);
        bytes[8..10].copy_from_slice(&WIRE_VERSION.to_be_bytes());
        bytes[10] = REQUEST_KIND;
        bytes[11] = u8::from(self.allow_absent);
        bytes[12..16].copy_from_slice(&(REQUEST_BYTES as u32).to_be_bytes());
        bytes[16..32].copy_from_slice(&self.request_id);
        bytes[32..64].copy_from_slice(self.effect_digest.as_bytes());
        bytes[64..96].copy_from_slice(&self.network_handle);
        bytes[96..104].copy_from_slice(&self.namespace_device.to_be_bytes());
        bytes[104..112].copy_from_slice(&self.namespace_inode.to_be_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, NetworkNamespacePinWorkerError> {
        if bytes.len() != REQUEST_BYTES
            || &bytes[..8] != REQUEST_MAGIC
            || u16::from_be_bytes(copy_array(&bytes[8..10])?) != WIRE_VERSION
            || bytes[10] != REQUEST_KIND
            || bytes[11] > 1
            || u32::from_be_bytes(copy_array(&bytes[12..16])?) != REQUEST_BYTES as u32
        {
            return protocol("Network namespace pin request header is invalid");
        }
        let request = Self {
            request_id: copy_array(&bytes[16..32])?,
            effect_digest: ObjectDigest::from_bytes(copy_array(&bytes[32..64])?),
            network_handle: copy_array(&bytes[64..96])?,
            namespace_device: u64::from_be_bytes(copy_array(&bytes[96..104])?),
            namespace_inode: u64::from_be_bytes(copy_array(&bytes[104..112])?),
            allow_absent: bytes[11] == 1,
        };
        request.validate()?;
        if request.encode().as_slice() != bytes {
            return protocol("Network namespace pin request is noncanonical");
        }
        Ok(request)
    }
}

fn encode_response(request_digest: ObjectDigest) -> [u8; RESPONSE_BYTES] {
    let mut bytes = [0_u8; RESPONSE_BYTES];
    bytes[..8].copy_from_slice(RESPONSE_MAGIC);
    bytes[8..10].copy_from_slice(&WIRE_VERSION.to_be_bytes());
    bytes[10] = RESPONSE_KIND;
    bytes[12..16].copy_from_slice(&(RESPONSE_BYTES as u32).to_be_bytes());
    bytes[16..48].copy_from_slice(request_digest.as_bytes());
    bytes
}

fn decode_response(bytes: &[u8]) -> Result<ObjectDigest, NetworkNamespacePinWorkerError> {
    if bytes.len() != RESPONSE_BYTES
        || &bytes[..8] != RESPONSE_MAGIC
        || u16::from_be_bytes(copy_array(&bytes[8..10])?) != WIRE_VERSION
        || bytes[10] != RESPONSE_KIND
        || bytes[11] != 0
        || u32::from_be_bytes(copy_array(&bytes[12..16])?) != RESPONSE_BYTES as u32
    {
        return protocol("Network namespace pin response is invalid");
    }
    let digest = ObjectDigest::from_bytes(copy_array(&bytes[16..48])?);
    if digest.as_bytes() == &[0; 32] || encode_response(digest).as_slice() != bytes {
        return protocol("Network namespace pin response digest is invalid");
    }
    Ok(digest)
}

fn validate_pin_worker_subject(
    cgroup: &str,
    subject: &KernelAuthorizedRecordSubject,
    worker_parent: &RetainedCgroupAnchor,
) -> Result<RetainedCgroupAnchor, NetworkNamespacePinWorkerError> {
    validate_pin_worker_cgroup(cgroup)?;
    let relative = Path::new(cgroup)
        .strip_prefix(CONTROL_SLICE_CGROUP)
        .map_err(|_| NetworkWorkerProcessError::PeerMismatch)?;
    let worker_cgroup = worker_parent.resolve_descendant(relative)?;
    validate_pin_worker_subject_record(subject, &worker_cgroup)?;
    worker_parent.validate_current()?;
    Ok(worker_cgroup)
}

fn validate_pin_worker_subject_record(
    subject: &KernelAuthorizedRecordSubject,
    worker_cgroup: &RetainedCgroupAnchor,
) -> Result<(), NetworkNamespacePinWorkerError> {
    let credentials = subject.credentials();
    let info = worker_cgroup.verify_exact_membership(subject.pidfd())?;
    if credentials.uid() != 0
        || credentials.gid() != 0
        || info.pid() != credentials.pid().get()
        || info.thread_group_id() != credentials.pid().get()
        || !subject.is_alive()?
    {
        return Err(NetworkWorkerProcessError::PeerMismatch.into());
    }
    worker_cgroup.validate_current()?;
    Ok(())
}

fn validate_pin_worker_cgroup(cgroup: &str) -> Result<(), NetworkNamespacePinWorkerError> {
    let Some(instance) = cgroup
        .strip_prefix(WORKER_CGROUP_PREFIX)
        .and_then(|value| value.strip_suffix(WORKER_CGROUP_SUFFIX))
    else {
        return Err(NetworkWorkerProcessError::PeerMismatch.into());
    };
    validate_systemd_socket_instance_fields(instance)
        .map_err(|_| NetworkWorkerProcessError::PeerMismatch)?;
    Ok(())
}

fn copy_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], NetworkNamespacePinWorkerError> {
    bytes
        .try_into()
        .map_err(|_| NetworkNamespacePinWorkerError::Protocol("pin-worker record is truncated"))
}

fn protocol<T>(message: &'static str) -> Result<T, NetworkNamespacePinWorkerError> {
    Err(NetworkNamespacePinWorkerError::Protocol(message))
}
