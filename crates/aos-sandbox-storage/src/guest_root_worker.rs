//! One-shot root publisher for an admitted Storage guest-root effect.
//!
//! The worker accepts exactly one descriptor-free AOSGRW01 request from the
//! live root `aos-storaged` service cgroup. It independently opens protected
//! authority, checks the immutable journal attempt and signed effect records,
//! and derives the fixed workspace slot from the authenticated handle. Its
//! separate root-owned replay claim is durable before any copied byte.
//!
//! ```text
//! AOSGRW01 | version:u16=1 | effect-operation[16]
//!          | attempt-len:u16 | effect-len:u16 | operation-fence-len:u16
//!          | AOSGRA01 | sealed-effect | sealed-operation-fence
//! AOSGPR01 | AOSGRP01
//! ```

use std::fs;
use std::os::fd::AsRawFd as _;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use aos_sandbox_agent::guest_root_marker::publish_guest_root_marker_before_v1;
use aos_sandbox_agent::guest_root_populate::populate_fresh_guest_root_before_v1;
use aos_sandbox_agent::guest_root_publication::GuestRootPublicationProofV1;
use aos_sandbox_broker::{BrokerEffectIntentV1, BrokerEffectStatusV1};
use aos_sandbox_core::{BrokerGrantTarget, BrokerVerb};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::cgroup::{
    CgroupPopulationMonitor, CgroupPopulationState, CgroupV2Root, RetainedCgroupAnchor,
};
use aos_sandbox_linux::inventory::MountId;
use aos_sandbox_linux::seqpacket::KernelAuthorizedRecordSubject;
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_protocol::semantics::storage_guest_root::CanonicalStorageGuestRootArgumentsV1;
use sha2::{Digest as _, Sha256};

use crate::authorization::{StorageAuthorityV1, StorageProtectedConfigurationV1};
use crate::guest_root_attempt::{
    GUEST_ROOT_ATTEMPT_RECORD_BYTES, GuestRootAttemptPhaseV1, GuestRootPublicationAttemptV1,
};
use crate::guest_root_inventory::ProtectedGuestRootTemplateV1;
use crate::pin_observer::{WorkspacePinHostCustody, open_workspace_slot};
use crate::pin_worker::{
    boottime_now_nanoseconds, ensure_before_deadline, verify_same_live_subject,
};
use crate::pin_worker_runtime::{
    ReplayLedger, current_cgroup, quiesce_cgroup, quiesce_worker, receive_packet_before,
    send_packet_before, transfer_deadline, verify_exact_worker_subject, verify_storaged_subject,
    verify_systemd_peer, wait_for_worker_quiescence,
};
use crate::process::open_cgroup_root;
use crate::runtime::trusted_paired_clock_sample;
use crate::workspace_pin::workspace_pin_path;
use crate::{StorageAdmissionError, StorageStateKey, ZfsWorkerError};

const REQUEST_MAGIC: &[u8; 8] = b"AOSGRW01";
const RESULT_MAGIC: &[u8; 8] = b"AOSGPR01";
const READY_MAGIC: &[u8; 8] = b"AOSGRD01";
const ACK_MAGIC: &[u8; 8] = b"AOSGACK1";
const HEALTH_REQUEST_MAGIC: &[u8; 8] = b"AOSGRH01";
const HEALTH_RESULT_MAGIC: &[u8; 8] = b"AOSGRHOK";
const VERSION: u16 = 1;
const REQUEST_PREFIX_BYTES: usize = 8 + 2 + 16 + 2 + 2 + 2;
const MAXIMUM_PACKET_BYTES: usize = 8192;
const STORAGED_CGROUP: &str = "aos.slice/aos-control.slice/aos-storaged.service";
const WORKER_CGROUP_PREFIX: &str = "aos.slice/aos-control.slice/aos-sandbox-guest-root-publisher@";
const WORKER_CGROUP_SUFFIX: &str = ".service";
const CONTROL_SLICE_CGROUP: &str = "aos.slice/aos-control.slice";
const SYSTEMD_MANAGER_CGROUP: &str = "init.scope";
const WORKER_CGROUP_BASENAME_PREFIX: &str = "aos-sandbox-guest-root-publisher@";
const MAXIMUM_RECOVERED_WORKERS: usize = 128;

/// Invokes only the fixed root-owned one-shot publisher and retains its cgroup to exit.
pub(crate) struct SystemdGuestRootPublisherClientV1 {
    socket_path: PathBuf,
    systemd_manager: RetainedCgroupAnchor,
    worker_parent: RetainedCgroupAnchor,
    fail_stopped: bool,
}

impl SystemdGuestRootPublisherClientV1 {
    pub(crate) fn new(
        socket_path: PathBuf,
        cgroup_root: CgroupV2Root,
    ) -> Result<Self, ZfsWorkerError> {
        if socket_path != Path::new("/run/aos/sandbox-guest-root-publisher/control.sock") {
            return Err(ZfsWorkerError::Authority);
        }
        Ok(Self {
            socket_path,
            systemd_manager: cgroup_root.resolve(Path::new(SYSTEMD_MANAGER_CGROUP))?,
            worker_parent: cgroup_root.resolve(Path::new(CONTROL_SLICE_CGROUP))?,
            fail_stopped: false,
        })
    }

    pub(crate) fn publish(
        &mut self,
        request: &[u8],
        expected_proof: GuestRootPublicationProofV1,
        effect_deadline: u64,
    ) -> Result<GuestRootPublicationProofV1, ZfsWorkerError> {
        if self.fail_stopped || decode_request(request)?.effect_operation == [0; 16] {
            return Err(ZfsWorkerError::Authority);
        }
        ensure_before_deadline(effect_deadline)?;
        let mut socket = DescriptorSubjectSocket::connect(&self.socket_path)?;
        verify_systemd_peer(socket.peer(), &self.systemd_manager)?;

        let ready = receive_packet_before(&mut socket, 520, effect_deadline)?;
        if !ready.descriptors().is_empty() {
            return Err(ZfsWorkerError::PeerMismatch);
        }
        let worker_path = decode_ready(ready.payload())?;
        let worker_cgroup = self.worker_parent.resolve_descendant(Path::new(
            worker_path
                .strip_prefix("aos.slice/aos-control.slice/")
                .ok_or(ZfsWorkerError::PeerMismatch)?,
        ))?;
        verify_exact_worker_subject(ready.subject(), &worker_cgroup)?;
        let population = worker_cgroup.population_monitor()?;

        // Response transfer may finish after the effect deadline; the worker
        // checks that deadline before each mutation and before marker publish.
        let response_deadline = effect_deadline
            .checked_add(Duration::from_secs(5).as_nanos() as u64)
            .ok_or(ZfsWorkerError::Authority)?;
        let exchange = (|| {
            send_packet_before(&mut socket, request, effect_deadline)?;
            let response = receive_packet_before(&mut socket, 274, response_deadline)?;
            verify_same_live_subject(ready.subject(), response.subject())?;
            verify_exact_worker_subject(response.subject(), &worker_cgroup)?;
            if !response.descriptors().is_empty() {
                return Err(ZfsWorkerError::PeerMismatch);
            }
            let proof = decode_result(response.payload())?;
            if proof != expected_proof {
                return Err(ZfsWorkerError::Authority);
            }
            send_packet_before(&mut socket, ACK_MAGIC, response_deadline)?;
            Ok(proof)
        })();

        self.finish_exchange(exchange, ready.subject(), &worker_cgroup, &population)
    }

    /// Proves the installed fixed service can start with its protected inputs.
    ///
    /// The health packet contains no authority and the worker returns before
    /// opening a workspace slot or attempting any filesystem mutation.
    pub(crate) fn probe(&mut self) -> Result<(), ZfsWorkerError> {
        if self.fail_stopped {
            return Err(ZfsWorkerError::Authority);
        }
        let mut socket = DescriptorSubjectSocket::connect(&self.socket_path)?;
        verify_systemd_peer(socket.peer(), &self.systemd_manager)?;
        // Template verification scans the complete pinned package before the
        // worker sends READY; it is bounded separately from packet transfer.
        let ready_deadline = boottime_now_nanoseconds()?
            .checked_add(Duration::from_secs(60).as_nanos() as u64)
            .ok_or(ZfsWorkerError::Authority)?;
        let ready = receive_packet_before(&mut socket, 520, ready_deadline)?;
        if !ready.descriptors().is_empty() {
            return Err(ZfsWorkerError::PeerMismatch);
        }
        let worker_path = decode_ready(ready.payload())?;
        let worker_cgroup = self.worker_parent.resolve_descendant(Path::new(
            worker_path
                .strip_prefix("aos.slice/aos-control.slice/")
                .ok_or(ZfsWorkerError::PeerMismatch)?,
        ))?;
        verify_exact_worker_subject(ready.subject(), &worker_cgroup)?;
        let population = worker_cgroup.population_monitor()?;
        let deadline = transfer_deadline()?;

        let exchange = (|| {
            send_packet_before(&mut socket, HEALTH_REQUEST_MAGIC, deadline)?;
            let response = receive_packet_before(&mut socket, HEALTH_RESULT_MAGIC.len(), deadline)?;
            verify_same_live_subject(ready.subject(), response.subject())?;
            verify_exact_worker_subject(response.subject(), &worker_cgroup)?;
            if !response.descriptors().is_empty() || response.payload() != HEALTH_RESULT_MAGIC {
                return Err(ZfsWorkerError::PeerMismatch);
            }
            send_packet_before(&mut socket, ACK_MAGIC, deadline)?;
            Ok(())
        })();
        self.finish_exchange(exchange, ready.subject(), &worker_cgroup, &population)
    }

    fn finish_exchange<T>(
        &mut self,
        exchange: Result<T, ZfsWorkerError>,
        subject: &KernelAuthorizedRecordSubject,
        worker_cgroup: &RetainedCgroupAnchor,
        population: &CgroupPopulationMonitor,
    ) -> Result<T, ZfsWorkerError> {
        match exchange {
            Ok(proof) => {
                if let Err(error) =
                    wait_for_worker_quiescence(subject, population, Duration::from_secs(1))
                {
                    if quiesce_worker(subject, worker_cgroup, population).is_err() {
                        self.fail_stopped = true;
                    }
                    return Err(ZfsWorkerError::Quiescence(format!(
                        "guest-root publisher did not exit cleanly: {error}"
                    )));
                }
                Ok(proof)
            }
            Err(error) => {
                if let Err(cancellation) = quiesce_worker(subject, worker_cgroup, population) {
                    self.fail_stopped = true;
                    return Err(ZfsWorkerError::Quiescence(format!(
                        "guest-root publisher cancellation failed after {error}: {cancellation}"
                    )));
                }
                Err(error)
            }
        }
    }

    /// Cancels publisher remnants before the journal can admit another effect.
    pub(crate) fn recover_quiescence(&mut self) -> Result<(), ZfsWorkerError> {
        if self.fail_stopped {
            return Err(ZfsWorkerError::Authority);
        }
        let recovery = (|| {
            for _ in 0..2 {
                for worker in self.recovered_workers()? {
                    let population = worker.population_monitor()?;
                    quiesce_cgroup(&worker, &population)?;
                }
            }
            for worker in self.recovered_workers()? {
                if worker.population_monitor()?.state()? == CgroupPopulationState::Populated {
                    return Err(ZfsWorkerError::Quiescence(
                        "a recovered guest-root publisher remained populated".to_owned(),
                    ));
                }
            }
            Ok(())
        })();
        if recovery.is_err() {
            self.fail_stopped = true;
        }
        recovery
    }

    fn recovered_workers(&self) -> Result<Vec<RetainedCgroupAnchor>, ZfsWorkerError> {
        let directory = PathBuf::from(format!(
            "/proc/self/fd/{}",
            self.worker_parent.as_fd().as_raw_fd()
        ));
        let mut names = Vec::new();
        for entry in fs::read_dir(directory)? {
            let name = entry?
                .file_name()
                .into_string()
                .map_err(|_| ZfsWorkerError::PeerMismatch)?;
            if name.starts_with(WORKER_CGROUP_BASENAME_PREFIX)
                && name.ends_with(WORKER_CGROUP_SUFFIX)
            {
                validate_worker_cgroup(&format!("{CONTROL_SLICE_CGROUP}/{name}"))?;
                names.push(name);
                if names.len() > MAXIMUM_RECOVERED_WORKERS {
                    return Err(ZfsWorkerError::Quiescence(
                        "guest-root publisher recovery count exceeded ceiling".to_owned(),
                    ));
                }
            }
        }
        names.sort_unstable();
        names
            .into_iter()
            .map(|name| {
                self.worker_parent
                    .resolve_descendant(Path::new(&name))
                    .map_err(Into::into)
            })
            .collect()
    }
}

fn validate_worker_cgroup(cgroup: &str) -> Result<(), ZfsWorkerError> {
    let instance = cgroup
        .strip_prefix(WORKER_CGROUP_PREFIX)
        .and_then(|value| value.strip_suffix(WORKER_CGROUP_SUFFIX))
        .filter(|value| !value.is_empty() && value.len() <= 255 && !value.contains('/'))
        .ok_or(ZfsWorkerError::PeerMismatch)?;
    if instance == "." || instance == ".." || cgroup.len() > 512 {
        return Err(ZfsWorkerError::PeerMismatch);
    }
    Ok(())
}

pub(crate) struct GuestRootWorkerRequestV1<'a> {
    effect_operation: [u8; 16],
    attempt: &'a [u8],
    sealed_effect: &'a [u8],
    sealed_operation_fence: &'a [u8],
}

pub(crate) fn encode_request(
    effect_operation: [u8; 16],
    attempt: &[u8],
    sealed_effect: &[u8],
    sealed_operation_fence: &[u8],
) -> Result<Vec<u8>, ZfsWorkerError> {
    if effect_operation == [0; 16]
        || attempt.len() != GUEST_ROOT_ATTEMPT_RECORD_BYTES
        || attempt.get(26..42) != Some(effect_operation.as_slice())
        || sealed_effect.is_empty()
        || sealed_operation_fence.is_empty()
    {
        return Err(ZfsWorkerError::Protocol(
            "guest root worker request is invalid",
        ));
    }
    let effect_len = u16::try_from(sealed_effect.len())
        .map_err(|_| ZfsWorkerError::Protocol("guest root worker effect is oversized"))?;
    let fence_len = u16::try_from(sealed_operation_fence.len())
        .map_err(|_| ZfsWorkerError::Protocol("guest root worker fence is oversized"))?;
    let total =
        REQUEST_PREFIX_BYTES + attempt.len() + usize::from(effect_len) + usize::from(fence_len);
    if total > MAXIMUM_PACKET_BYTES {
        return Err(ZfsWorkerError::Protocol(
            "guest root worker request is oversized",
        ));
    }
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(REQUEST_MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&effect_operation);
    bytes.extend_from_slice(&(attempt.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&effect_len.to_be_bytes());
    bytes.extend_from_slice(&fence_len.to_be_bytes());
    bytes.extend_from_slice(attempt);
    bytes.extend_from_slice(sealed_effect);
    bytes.extend_from_slice(sealed_operation_fence);
    Ok(bytes)
}

pub(crate) fn decode_request(bytes: &[u8]) -> Result<GuestRootWorkerRequestV1<'_>, ZfsWorkerError> {
    if bytes.len() < REQUEST_PREFIX_BYTES + GUEST_ROOT_ATTEMPT_RECORD_BYTES + 2
        || bytes.len() > MAXIMUM_PACKET_BYTES
        || &bytes[..8] != REQUEST_MAGIC
        || bytes[8..10] != VERSION.to_be_bytes()
    {
        return Err(ZfsWorkerError::Protocol(
            "guest root worker request is malformed",
        ));
    }
    let effect_operation: [u8; 16] = bytes[10..26]
        .try_into()
        .map_err(|_| ZfsWorkerError::Protocol("guest root operation is invalid"))?;
    let attempt_len = u16::from_be_bytes([bytes[26], bytes[27]]) as usize;
    let effect_len = u16::from_be_bytes([bytes[28], bytes[29]]) as usize;
    let fence_len = u16::from_be_bytes([bytes[30], bytes[31]]) as usize;
    if effect_operation == [0; 16]
        || attempt_len != GUEST_ROOT_ATTEMPT_RECORD_BYTES
        || effect_len == 0
        || fence_len == 0
        || bytes.len() != REQUEST_PREFIX_BYTES + attempt_len + effect_len + fence_len
    {
        return Err(ZfsWorkerError::Protocol(
            "guest root worker lengths are invalid",
        ));
    }
    let attempt_end = REQUEST_PREFIX_BYTES + attempt_len;
    let effect_end = attempt_end + effect_len;
    let attempt = &bytes[REQUEST_PREFIX_BYTES..attempt_end];
    if attempt.get(26..42) != Some(effect_operation.as_slice()) {
        return Err(ZfsWorkerError::Protocol(
            "guest root attempt location is invalid",
        ));
    }
    Ok(GuestRootWorkerRequestV1 {
        effect_operation,
        attempt,
        sealed_effect: &bytes[attempt_end..effect_end],
        sealed_operation_fence: &bytes[effect_end..],
    })
}

fn authenticate_request(
    authority: &StorageAuthorityV1,
    key: &StorageStateKey,
    request: GuestRootWorkerRequestV1<'_>,
    template: &ProtectedGuestRootTemplateV1,
) -> Result<(GuestRootPublicationAttemptV1, BrokerEffectIntentV1), ZfsWorkerError> {
    let attempt = key
        .open_guest_root_publication_attempt(request.effect_operation, request.attempt)
        .map_err(|_| ZfsWorkerError::Authority)?;
    let effect = authority
        .open_admission_intent(&attempt.request_id, request.sealed_effect)
        .map_err(|_| ZfsWorkerError::Authority)?;
    let fence = authority
        .open_operation_fence(&attempt.effect_operation, request.sealed_operation_fence)
        .map_err(|_| ZfsWorkerError::Authority)?;
    let assignment = fence.assignment();
    let proof = attempt.expected_proof;
    let semantics = CanonicalStorageGuestRootArgumentsV1::from_protected_assignment(
        assignment,
        attempt.effect_operation,
        proof.workspace_handle,
        proof.creation_operation,
    )
    .map_err(|_| ZfsWorkerError::Authority)?;
    if attempt.phase != GuestRootAttemptPhaseV1::Ambiguous
        || effect.status() != BrokerEffectStatusV1::Pending
        || effect.request_id() != &attempt.request_id
        || effect.verb() != BrokerVerb::StoragePopulateGuestRoot
        || effect.target() != BrokerGrantTarget::Assignment
        || effect.request_digest() != semantics.argument_commitment().digest()
        || effect.plan_digest() != fence.plan_digest()
        || effect.lease_digest() != fence.local_lease_record().lease_digest()
        || effect.effect_deadline_boottime_nanoseconds()
            != attempt.effect_deadline_boottime_nanoseconds
        || effect.host_boot_id() != &attempt.kernel_boot
        || Sha256::digest(request.sealed_effect).as_slice() != attempt.sealed_effect_digest
        || Sha256::digest(request.sealed_operation_fence).as_slice()
            != attempt.operation_fence_digest
        || assignment.sandbox().as_bytes() != &proof.sandbox
        || assignment.incarnation().as_bytes() != &proof.incarnation
        || assignment.epoch().get() != proof.assignment_epoch
        || assignment.digest().as_bytes() != &proof.assignment_digest
        || template.package_binding() != &proof.package_binding
        || template.root_tree_digest() != &proof.root_tree_digest
        || KernelBootId::current()
            .map_err(|_| ZfsWorkerError::Authority)?
            .into_bytes()
            != attempt.kernel_boot
    {
        return Err(ZfsWorkerError::Authority);
    }
    authority
        .check_current_fence(&fence)
        .map_err(|_| ZfsWorkerError::Authority)?;
    Ok((attempt, effect))
}

fn verify_current_slot(
    custody: &WorkspacePinHostCustody,
    attempt: &GuestRootPublicationAttemptV1,
) -> Result<PathBuf, ZfsWorkerError> {
    let slot = open_workspace_slot(custody.pin_root(), &attempt.expected_proof.workspace_handle)
        .map_err(|_| ZfsWorkerError::Authority)?
        .ok_or(ZfsWorkerError::Authority)?;
    let stat = rustix::fs::fstat(slot.as_fd())?;
    if stat.st_dev != attempt.root_device
        || stat.st_ino != attempt.root_inode
        || stat.st_uid != 0
        || stat.st_mode & 0o022 != 0
        || MountId::from_fd(slot.as_fd())? == MountId::from_fd(custody.pin_root().as_fd())?
    {
        return Err(ZfsWorkerError::Authority);
    }
    let path = PathBuf::from(workspace_pin_path(&attempt.expected_proof.workspace_handle));
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_dir()
        || metadata.dev() != attempt.root_device
        || metadata.ino() != attempt.root_inode
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err(ZfsWorkerError::Authority);
    }
    Ok(path)
}

fn before_deadline(deadline: u64) -> bool {
    boottime_now_nanoseconds().is_ok_and(|now| now < deadline)
}

fn publish_authenticated(
    authority: &StorageAuthorityV1,
    replay: &ReplayLedger,
    template: &ProtectedGuestRootTemplateV1,
    custody: &WorkspacePinHostCustody,
    attempt: GuestRootPublicationAttemptV1,
    effect: &BrokerEffectIntentV1,
) -> Result<GuestRootPublicationProofV1, ZfsWorkerError> {
    let deadline = attempt.effect_deadline_boottime_nanoseconds;
    let _serialization = replay.lock(deadline)?;
    let workspace = verify_current_slot(custody, &attempt)?;
    let mut clock =
        || trusted_paired_clock_sample().map_err(|_| StorageAdmissionError::VerificationFailed);
    authority
        .check_before_effect(effect, &mut clock)
        .map_err(|_| ZfsWorkerError::Authority)?;
    let _replay_claim = replay.claim(attempt.effect_operation)?;
    ensure_before_deadline(deadline)?;
    populate_fresh_guest_root_before_v1(template.root(), &workspace, || before_deadline(deadline))
        .map_err(|_| ZfsWorkerError::Authority)?;
    verify_current_slot(custody, &attempt)?;
    ensure_before_deadline(deadline)?;
    publish_guest_root_marker_before_v1(
        template.root(),
        &workspace,
        attempt.expected_proof,
        || before_deadline(deadline),
    )
    .map_err(|_| ZfsWorkerError::Authority)?;
    verify_current_slot(custody, &attempt)?;
    Ok(attempt.expected_proof)
}

fn encode_ready(cgroup: &str) -> Result<Vec<u8>, ZfsWorkerError> {
    validate_worker_cgroup(cgroup)?;
    let mut bytes = Vec::with_capacity(READY_MAGIC.len() + cgroup.len());
    bytes.extend_from_slice(READY_MAGIC);
    bytes.extend_from_slice(cgroup.as_bytes());
    Ok(bytes)
}

pub(crate) fn decode_ready(bytes: &[u8]) -> Result<&str, ZfsWorkerError> {
    if bytes.len() <= READY_MAGIC.len() || !bytes.starts_with(READY_MAGIC) {
        return Err(ZfsWorkerError::PeerMismatch);
    }
    let cgroup = std::str::from_utf8(&bytes[READY_MAGIC.len()..])
        .map_err(|_| ZfsWorkerError::PeerMismatch)?;
    validate_worker_cgroup(cgroup)?;
    Ok(cgroup)
}

pub(crate) fn decode_result(bytes: &[u8]) -> Result<GuestRootPublicationProofV1, ZfsWorkerError> {
    if bytes.len() != 8 + 266 || !bytes.starts_with(RESULT_MAGIC) {
        return Err(ZfsWorkerError::Protocol(
            "guest root worker result is invalid",
        ));
    }
    GuestRootPublicationProofV1::decode(&bytes[8..]).map_err(|_| ZfsWorkerError::Authority)
}

/// Runs one fixed, inherited, root-only guest-root publication transaction.
///
/// # Errors
///
/// Returns an error unless the live broker subject, protected signed effect,
/// durable attempt, pinned template, exact mount slot, deadline, and replay
/// claim all validate. No caller-provided command, path, or FD is accepted.
pub fn run_inherited_guest_root_publisher(
    template_output: &Path,
    authority_directory: &Path,
    replay_directory: &Path,
) -> Result<(), ZfsWorkerError> {
    if !rustix::process::getuid().is_root() || !rustix::process::geteuid().is_root() {
        return Err(ZfsWorkerError::Authority);
    }
    let template = ProtectedGuestRootTemplateV1::open(template_output)
        .map_err(|_| ZfsWorkerError::Authority)?;
    let protected = StorageProtectedConfigurationV1::from_protected_directory(authority_directory)
        .map_err(|_| ZfsWorkerError::Authority)?;
    let (authority, key, _) = protected.into_parts();
    let replay = ReplayLedger::open(replay_directory)?;
    let custody = WorkspacePinHostCustody::retain_initial_root_owned()
        .map_err(|_| ZfsWorkerError::Authority)?;
    let storaged = open_cgroup_root()?.resolve(Path::new(STORAGED_CGROUP))?;
    let descriptor: OwnedFd = rustix::io::dup(std::io::stdin().as_fd())?;
    let mut socket = DescriptorSubjectSocket::from_owned(descriptor)?;

    let ready_deadline = transfer_deadline()?;
    send_packet_before(
        &mut socket,
        &encode_ready(&current_cgroup()?)?,
        ready_deadline,
    )?;
    let received = receive_packet_before(&mut socket, MAXIMUM_PACKET_BYTES, ready_deadline)?;
    verify_storaged_subject(received.subject(), &storaged)?;
    if !received.descriptors().is_empty() {
        return Err(ZfsWorkerError::Protocol(
            "guest root worker forbids descriptors",
        ));
    }
    if received.payload() == HEALTH_REQUEST_MAGIC {
        send_packet_before(&mut socket, HEALTH_RESULT_MAGIC, ready_deadline)?;
        let acknowledgement = receive_packet_before(&mut socket, ACK_MAGIC.len(), ready_deadline)?;
        verify_same_live_subject(received.subject(), acknowledgement.subject())?;
        verify_storaged_subject(acknowledgement.subject(), &storaged)?;
        if !acknowledgement.descriptors().is_empty() || acknowledgement.payload() != ACK_MAGIC {
            return Err(ZfsWorkerError::PeerMismatch);
        }
        return Ok(());
    }
    let request = decode_request(received.payload())?;
    let (attempt, effect) = authenticate_request(&authority, &key, request, &template)?;
    let proof = publish_authenticated(&authority, &replay, &template, &custody, attempt, &effect)?;

    let mut response = Vec::with_capacity(8 + 266);
    response.extend_from_slice(RESULT_MAGIC);
    response.extend_from_slice(&proof.encode().map_err(|_| ZfsWorkerError::Authority)?);
    let response_deadline = transfer_deadline()?;
    send_packet_before(&mut socket, &response, response_deadline)?;
    let acknowledgement = receive_packet_before(&mut socket, ACK_MAGIC.len(), response_deadline)?;
    verify_same_live_subject(received.subject(), acknowledgement.subject())?;
    verify_storaged_subject(acknowledgement.subject(), &storaged)?;
    if !acknowledgement.descriptors().is_empty() || acknowledgement.payload() != ACK_MAGIC {
        return Err(ZfsWorkerError::Protocol(
            "guest root worker acknowledgement is invalid",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_rejects_substituted_or_oversized_authority() {
        let mut attempt = vec![0; GUEST_ROOT_ATTEMPT_RECORD_BYTES];
        attempt[26..42].copy_from_slice(&[1; 16]);
        let encoded = encode_request([1; 16], &attempt, &[2; 32], &[3; 32]).unwrap();
        assert_eq!(decode_request(&encoded).unwrap().effect_operation, [1; 16]);
        assert!(encode_request([4; 16], &attempt, &[2; 32], &[3; 32]).is_err());
        let mut malformed = encoded;
        malformed[26..28].copy_from_slice(&1_u16.to_be_bytes());
        assert!(decode_request(&malformed).is_err());
    }

    #[test]
    fn ready_cgroup_is_single_fixed_systemd_instance() {
        let valid = "aos.slice/aos-control.slice/aos-sandbox-guest-root-publisher@9.service";
        assert_eq!(decode_ready(&encode_ready(valid).unwrap()).unwrap(), valid);

        for invalid in [
            "aos.slice/aos-control.slice/aos-sandbox-guest-root-publisher@.service",
            "aos.slice/aos-control.slice/aos-sandbox-guest-root-publisher@../x.service",
            "aos.slice/aos-control.slice/aos-sandbox-guest-root-publisher@x/y.service",
            "aos.slice/aos-control.slice/aos-sandbox-workspace-pin-worker@9.service",
        ] {
            assert!(encode_ready(invalid).is_err());
        }
    }

    #[test]
    fn health_packet_cannot_decode_as_publication_request() {
        assert!(decode_request(HEALTH_REQUEST_MAGIC).is_err());
        assert_ne!(HEALTH_REQUEST_MAGIC, RESULT_MAGIC);
        assert_ne!(HEALTH_RESULT_MAGIC, RESULT_MAGIC);
    }
}
