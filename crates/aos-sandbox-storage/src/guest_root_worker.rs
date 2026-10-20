//! One-shot root publisher for an admitted Storage guest-root effect.
//!
//! The worker accepts exactly one descriptor-free AOSGRW02 request from the
//! live root `aos-storaged` service cgroup. It independently opens protected
//! authority, checks the immutable journal attempt and signed effect records,
//! and derives the fixed workspace slot from the authenticated handle. Its
//! separate root-owned replay claim is durable before any copied byte.
//!
//! ```text
//! AOSGRW02 | version:u16=2 | effect-operation[16]
//!          | attempt-len:u16 | effect-len:u16 | operation-fence-len:u16
//!          | AOSGRA02 | sealed-effect | sealed-operation-fence
//! AOSGPR01 | AOSGRP01
//! ```

use std::fs;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use aos_sandbox_guest_root_realization::guest_root_label::label_copied_guest_executables_before_v1;
use aos_sandbox_guest_root_realization::guest_root_marker::{
    publish_guest_root_marker_before_v1, read_guest_root_marker_v1,
};
use aos_sandbox_guest_root_realization::guest_root_populate::populate_fresh_guest_root_before_v1;
use aos_sandbox_agent::guest_root_publication::GuestRootPublicationProofV1;
use aos_sandbox_broker::BrokerEffectIntentV1;
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::inventory::MountId;
use aos_sandbox_linux::seqpacket::KernelAuthorizedRecordSubject;
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;

use crate::authorization::{StorageAuthorityV1, StorageProtectedConfigurationV1};
use crate::guest_root_attempt::{
    GUEST_ROOT_ATTEMPT_RECORD_BYTES, GuestRootAttemptPhaseV2, GuestRootPublicationAttemptV2,
};
use crate::guest_root_inventory::ProtectedGuestRootTemplateV1;
use crate::pin_observer::{WorkspacePinHostCustody, open_workspace_slot};
use crate::pin_worker::{
    boottime_now_nanoseconds, ensure_before_deadline, verify_same_live_subject,
};
use crate::pin_worker_runtime::{
    ReplayLedger, current_cgroup, receive_packet_before,
    send_packet_before, transfer_deadline, verify_storaged_subject,
};
use crate::process::open_cgroup_root;
use crate::runtime::trusted_paired_clock_sample;
use crate::workspace_pin::workspace_pin_path;
use crate::{StorageAdmissionError, StorageStateKey, ZfsWorkerError};

const REQUEST_MAGIC: &[u8; 8] = b"AOSGRW02";
const RESULT_MAGIC: &[u8; 8] = b"AOSGPR01";
pub(crate) const ACK_MAGIC: &[u8; 8] = b"AOSGACK1";
pub(crate) const HEALTH_REQUEST_MAGIC: &[u8; 8] = b"AOSGRH01";
pub(crate) const HEALTH_RESULT_MAGIC: &[u8; 8] = b"AOSGRHOK";
const VERSION: u16 = 2;
const REQUEST_PREFIX_BYTES: usize = 8 + 2 + 16 + 2 + 2 + 2;
const MAXIMUM_PACKET_BYTES: usize = 8192;
const STORAGED_CGROUP: &str = "aos.slice/aos-control.slice/aos-storaged.service";

pub(crate) struct GuestRootWorkerRequestV1<'a> {
    effect_operation: [u8; 16],
    attempt: &'a [u8],
    sealed_effect: &'a [u8],
    sealed_operation_fence: &'a [u8],
}

impl GuestRootWorkerRequestV1<'_> {
    pub(crate) const fn effect_operation(&self) -> [u8; 16] { self.effect_operation }
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
) -> Result<(GuestRootPublicationAttemptV2, BrokerEffectIntentV1), ZfsWorkerError> {
    let attempt = key
        .open_guest_root_publication_attempt(request.effect_operation, request.attempt)
        .map_err(|_| ZfsWorkerError::Authority)?;
    let effect = attempt.require_authority_v2(
        authority, request.sealed_effect, request.sealed_operation_fence,
    ).map_err(|_| ZfsWorkerError::Authority)?;
    let proof = attempt.expected_proof;
    if attempt.phase != GuestRootAttemptPhaseV2::Ambiguous
        || template.package_binding() != &proof.package_binding
        || template.root_tree_digest() != &proof.root_tree_digest
        || KernelBootId::current().map_err(|_| ZfsWorkerError::Authority)?.into_bytes()
            != attempt.kernel_boot
    {
        return Err(ZfsWorkerError::Authority);
    }
    Ok((attempt, effect))
}

fn verify_current_slot(
    custody: &WorkspacePinHostCustody,
    attempt: &GuestRootPublicationAttemptV2,
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
    attempt: GuestRootPublicationAttemptV2,
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
    let marker = workspace.join("etc/aos/sandbox-guest-root/publication-v1");
    match fs::symlink_metadata(&marker) {
        Ok(_) => {
            // Rebinding an already published root is observation-only. Check
            // the complete old creation proof/tree/labels before any copying
            // or labeling; a conflicting marker never permits repair.
            read_guest_root_marker_v1(template.root(), &workspace, attempt.expected_proof)
                .map_err(|_| ZfsWorkerError::Authority)?;
            verify_current_slot(custody, &attempt)?;
            ensure_before_deadline(deadline)?;
            return Ok(attempt.expected_proof);
        }
        Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => {}
        Err(cause) => return Err(cause.into()),
    }
    populate_fresh_guest_root_before_v1(template.root(), &workspace, || before_deadline(deadline))
        .map_err(|_| ZfsWorkerError::Authority)?;
    verify_current_slot(custody, &attempt)?;
    ensure_before_deadline(deadline)?;
    label_copied_guest_executables_before_v1(&workspace, || before_deadline(deadline))
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
    crate::process::worker_aggregate::with_worker_aggregate_v1(|aggregate| {
        run_inherited_guest_root_publisher_inner_v2(template_output, authority_directory, replay_directory, aggregate)
    })
}

fn run_inherited_guest_root_publisher_inner_v2(
    template_output: &Path,
    authority_directory: &Path,
    replay_directory: &Path,
    mut aggregate: Option<&mut crate::process::worker_aggregate::WorkerAggregateV1>,
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
    let storaged = match aggregate.as_deref_mut() {
        Some(original) => original.take_main()?,
        None => open_cgroup_root()?.resolve(Path::new(STORAGED_CGROUP))?,
    };
    let descriptor: OwnedFd = rustix::io::dup(std::io::stdin().as_fd())?;
    let mut socket = DescriptorSubjectSocket::from_owned(descriptor)?;

    let ready_deadline = transfer_deadline()?;
    send_packet_before(
        &mut socket,
        &crate::pin_worker_runtime::encode_selected_ready_v1(
            &current_cgroup()?, crate::pin_worker_runtime::WorkspacePinServiceRole::GuestRootPublication31,
        )?,
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
    let aggregate = aggregate.as_deref_mut().ok_or(ZfsWorkerError::Authority)?;
    let mut execution = aggregate.borrow_guest_root_execution_scope_v2(&current_cgroup()?)?;
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
    execution.complete_after_ack_v1();
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
        let valid = "aos.slice/aos-control.slice/aos-control-storage.slice/aos-sandbox-guest-root-publisher@9.service";
        assert_eq!(crate::pin_worker_runtime::decode_selected_ready_v1(&crate::pin_worker_runtime::encode_selected_ready_v1(valid, crate::pin_worker_runtime::WorkspacePinServiceRole::GuestRootPublication31).unwrap(), crate::pin_worker_runtime::WorkspacePinServiceRole::GuestRootPublication31).unwrap(), valid);

        for invalid in [
            "aos.slice/aos-control.slice/aos-control-storage.slice/aos-sandbox-guest-root-publisher@.service",
            "aos.slice/aos-control.slice/aos-control-storage.slice/aos-sandbox-guest-root-publisher@../x.service",
            "aos.slice/aos-control.slice/aos-control-storage.slice/aos-sandbox-guest-root-publisher@x/y.service",
            "aos.slice/aos-control.slice/aos-sandbox-workspace-pin-worker@9.service",
        ] {
            assert!(crate::pin_worker_runtime::encode_selected_ready_v1(invalid, crate::pin_worker_runtime::WorkspacePinServiceRole::GuestRootPublication31).is_err());
        }
    }

    #[test]
    fn health_packet_cannot_decode_as_publication_request() {
        assert!(decode_request(HEALTH_REQUEST_MAGIC).is_err());
        assert_ne!(HEALTH_REQUEST_MAGIC, RESULT_MAGIC);
        assert_ne!(HEALTH_RESULT_MAGIC, RESULT_MAGIC);
    }
}
