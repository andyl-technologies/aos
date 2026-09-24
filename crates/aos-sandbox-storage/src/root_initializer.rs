//! Separate, socket-activated Create root initializer and one-mount custody wire.
//!
//! The existing pin worker keeps its replay claim and serialization lock. This
//! process independently authenticates the complete protected pin request and
//! exact worker cgroup, observes the dataset GUID, then creates and normalizes
//! one detached mount. The only returned capability is one SCM_RIGHTS mount FD.
//!
//! ```text
//! worker -> initializer: AOSZPRD1 READY(effect cgroup)
//! worker -> initializer: AOSZPFR1 framed protected pin request + mount-ns,pin-root FDs
//! initializer -> worker: AOSZRIN1 | version:u16 | attempt-id:16 | request-digest:32
//!                       | mount-id:u64 | root-dev:u64 | root-ino:u64
//!                       | uid:u32 | gid:u32 | mode:u32 + one detached-mount FD
//! worker -> initializer: AOSZPACK ACK
//! ```

use std::os::fd::{AsFd as _, OwnedFd};
use std::path::{Path, PathBuf};

use aos_sandbox_linux::mount::{DetachedMount, FileSystemContext, MountAttributes};
use aos_sandbox_linux::path::ResolvedPath;
use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceKind, SingleThreadedProcess};
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use rustix::fs::{Mode, OFlags};
use sha2::{Digest as _, Sha256};

use crate::authorization::StorageProtectedConfigurationV1;
use crate::pin_observer::{observe_workspace_pin, validate_host_scope};
use crate::pin_worker::{decode_request, receive_request_before, verify_same_live_subject};
use crate::pin_worker_runtime::{
    CONTROL_SLICE_CGROUP, ReplayLedger, WorkspacePinServiceRole, check_immediately_before_effect,
    check_immediately_before_repair_effect, current_cgroup, decode_ready, encode_ready,
    enforce_workspace_root_policy, map_observer_error, observe_dataset_until,
    observe_exact_repair_dataset_until, portable_root_attributes, receive_packet_before,
    send_packet_before, send_packet_with_descriptor_before, transfer_deadline,
    verify_worker_subject,
};
use crate::process::{PinnedExecutable, open_cgroup_root};
use crate::root_policy::WorkspaceRootPolicyV1;
use crate::workspace_pin::{
    WorkspaceDatasetObservationV1, WorkspacePinActionV1, WorkspacePinObservationV1,
};
use crate::workspace_repair_worker::{
    decode_request as decode_repair_request, is_repair_worker_request,
};
use crate::{ZfsHelperContract, ZfsTransaction, ZfsWorkerError};

const RESULT_MAGIC: &[u8; 8] = b"AOSZRIN1";
const RESULT_VERSION: u16 = 1;
pub(crate) const RESULT_BYTES: usize = 94;
const REQUEST_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.storage.root-initializer-request.v1\0";
const ACK: &[u8; 10] = b"AOSZPACK\0\x01";

/// Binds one detached mount to the exact protected request and expected root.
pub(crate) struct InitializerResultV1 {
    attempt_id: [u8; 16],
    request_digest: [u8; 32],
    mount_id: u64,
    root_device: u64,
    root_inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

impl InitializerResultV1 {
    fn from_mount(
        attempt_id: [u8; 16],
        request: &[u8],
        mount: &DetachedMount,
    ) -> Result<Self, ZfsWorkerError> {
        let metadata = rustix::fs::fstat(mount.as_fd())?;
        let attributes = portable_root_attributes(&metadata)?;
        Ok(Self {
            attempt_id,
            request_digest: request_digest(request),
            mount_id: mount.mount_id().get(),
            root_device: metadata.st_dev,
            root_inode: metadata.st_ino,
            uid: attributes.uid(),
            gid: attributes.gid(),
            mode: u32::from(attributes.mode()),
        })
    }

    pub(crate) fn encode(&self) -> [u8; RESULT_BYTES] {
        let mut bytes = [0_u8; RESULT_BYTES];
        bytes[..8].copy_from_slice(RESULT_MAGIC);
        bytes[8..10].copy_from_slice(&RESULT_VERSION.to_be_bytes());
        bytes[10..26].copy_from_slice(&self.attempt_id);
        bytes[26..58].copy_from_slice(&self.request_digest);
        bytes[58..66].copy_from_slice(&self.mount_id.to_be_bytes());
        bytes[66..74].copy_from_slice(&self.root_device.to_be_bytes());
        bytes[74..82].copy_from_slice(&self.root_inode.to_be_bytes());
        bytes[82..86].copy_from_slice(&self.uid.to_be_bytes());
        bytes[86..90].copy_from_slice(&self.gid.to_be_bytes());
        bytes[90..94].copy_from_slice(&self.mode.to_be_bytes());
        bytes
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, ZfsWorkerError> {
        if bytes.len() != RESULT_BYTES
            || &bytes[..8] != RESULT_MAGIC
            || bytes[8..10] != RESULT_VERSION.to_be_bytes()
        {
            return Err(ZfsWorkerError::Protocol(
                "root initializer result header is invalid",
            ));
        }
        let mut attempt_id = [0; 16];
        attempt_id.copy_from_slice(&bytes[10..26]);
        let mut request_digest = [0; 32];
        request_digest.copy_from_slice(&bytes[26..58]);
        Ok(Self {
            attempt_id,
            request_digest,
            mount_id: u64::from_be_bytes(
                bytes[58..66]
                    .try_into()
                    .map_err(|_| ZfsWorkerError::Authority)?,
            ),
            root_device: u64::from_be_bytes(
                bytes[66..74]
                    .try_into()
                    .map_err(|_| ZfsWorkerError::Authority)?,
            ),
            root_inode: u64::from_be_bytes(
                bytes[74..82]
                    .try_into()
                    .map_err(|_| ZfsWorkerError::Authority)?,
            ),
            uid: u32::from_be_bytes(
                bytes[82..86]
                    .try_into()
                    .map_err(|_| ZfsWorkerError::Authority)?,
            ),
            gid: u32::from_be_bytes(
                bytes[86..90]
                    .try_into()
                    .map_err(|_| ZfsWorkerError::Authority)?,
            ),
            mode: u32::from_be_bytes(
                bytes[90..94]
                    .try_into()
                    .map_err(|_| ZfsWorkerError::Authority)?,
            ),
        })
    }

    pub(crate) fn verify(
        &self,
        attempt_id: [u8; 16],
        request: &[u8],
        policy: WorkspaceRootPolicyV1,
        mount: &DetachedMount,
    ) -> Result<(), ZfsWorkerError> {
        let metadata = rustix::fs::fstat(mount.as_fd())?;
        let attributes = portable_root_attributes(&metadata)?;
        let mount_flags = rustix::fs::fstatvfs(mount.as_fd())?.f_flag;
        let secured_mount = mount_flags.contains(
            rustix::fs::StatVfsMountFlags::NOSUID | rustix::fs::StatVfsMountFlags::NODEV,
        ) && !mount_flags.contains(rustix::fs::StatVfsMountFlags::RDONLY);
        if self.attempt_id != attempt_id
            || self.request_digest != request_digest(request)
            || self.mount_id == 0
            || self.mount_id != mount.mount_id().get()
            || self.root_device == 0
            || self.root_inode == 0
            || self.root_device != metadata.st_dev
            || self.root_inode != metadata.st_ino
            || self.uid != attributes.uid()
            || self.gid != attributes.gid()
            || self.mode != u32::from(attributes.mode())
            || attributes != policy.root_attributes()
            || !secured_mount
        {
            return Err(ZfsWorkerError::Authority);
        }
        Ok(())
    }
}

pub(crate) fn request_digest(request: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(REQUEST_DIGEST_DOMAIN);
    hash.update(request);
    hash.finalize().into()
}

fn dataset_matches_expected(
    observed: &WorkspaceDatasetObservationV1,
    expected_name: &str,
    expected_guid: u64,
) -> bool {
    matches!(
        observed,
        WorkspaceDatasetObservationV1::Exact { name, guid }
            if name == expected_name && *guid == expected_guid
    )
}

/// Runs one root-owned initializer instance from its systemd socket.
///
/// # Errors
///
/// Fails closed on non-worker subjects, invalid protected Create authority,
/// wrong host custody, absent/mismatched dataset, or incomplete FD handoff.
pub fn run_inherited_workspace_root_initializer(
    configured_zfs: PathBuf,
    authority_directory: &Path,
    replay_directory: &Path,
) -> Result<(), ZfsWorkerError> {
    let contract = ZfsHelperContract::new(configured_zfs)
        .map_err(|error| ZfsWorkerError::Executable(error.to_string()))?;
    let executable_pin = PinnedExecutable::open(&contract)?;
    let protected = StorageProtectedConfigurationV1::from_protected_directory(authority_directory)
        .map_err(|_| ZfsWorkerError::Authority)?;
    let replay = ReplayLedger::open(replay_directory)?;
    let parent = open_cgroup_root()?.resolve(Path::new(CONTROL_SLICE_CGROUP))?;
    let single_threaded = SingleThreadedProcess::verify()?;
    let descriptor: OwnedFd = rustix::io::dup(std::io::stdin().as_fd())?;
    let mut socket = DescriptorSubjectSocket::from_owned(descriptor)?;

    let deadline = transfer_deadline()?;
    send_packet_before(
        &mut socket,
        &encode_ready(&current_cgroup()?, WorkspacePinServiceRole::Initializer)?,
        deadline,
    )?;
    let worker_ready = receive_packet_before(&mut socket, 4096, deadline)?;
    let worker_path = decode_ready(worker_ready.payload(), WorkspacePinServiceRole::Effect)?;
    let worker_cgroup = verify_worker_subject(
        worker_ready.subject(),
        &parent,
        Path::new(worker_path),
        WorkspacePinServiceRole::Effect,
    )?;
    let received = receive_request_before(&mut socket, deadline)?;
    verify_same_live_subject(worker_ready.subject(), &received.subject)?;
    crate::pin_worker_runtime::verify_exact_worker_subject(&received.subject, &worker_cgroup)?;
    let repair = if is_repair_worker_request(&received.bytes) {
        Some(protected.authenticate_workspace_pin_repair_worker_request(
            &contract,
            decode_repair_request(&received.bytes)?,
        )?)
    } else {
        None
    };
    let ordinary = if repair.is_none() {
        Some(protected.authenticate_workspace_pin_worker_request(
            &contract,
            decode_request(&received.bytes)?,
        )?)
    } else {
        None
    };
    let attempt = repair
        .as_ref()
        .map(|request| request.attempt())
        .or_else(|| ordinary.as_ref().map(|request| request.attempt()))
        .ok_or(ZfsWorkerError::Authority)?;
    if attempt.action() != WorkspacePinActionV1::Ensure
        || !attempt.root_policy().is_create_initialize()
    {
        return Err(ZfsWorkerError::Authority);
    }
    let [mount_namespace, pin_root]: [OwnedFd; 2] = received
        .descriptors
        .try_into()
        .map_err(|_| ZfsWorkerError::Protocol("root initializer descriptor roles are invalid"))?;
    let mount_namespace = NamespaceFd::from_owned(mount_namespace, NamespaceKind::Mount)?;
    let pin_root = ResolvedPath::from_inherited(pin_root)?;
    mount_namespace.enter(&single_threaded)?;
    validate_host_scope(attempt, &mount_namespace, &pin_root).map_err(map_observer_error)?;
    executable_pin.validate_current(&contract)?;

    let catalog = repair
        .as_ref()
        .map(|request| request.catalog())
        .or_else(|| ordinary.as_ref().map(|request| &request.request().catalog))
        .ok_or(ZfsWorkerError::Authority)?;
    let transaction = ZfsTransaction::from_catalog(catalog.plan().operation(), catalog)?;
    let (dataset, _) = if repair.is_some() {
        observe_exact_repair_dataset_until(
            &contract,
            &transaction,
            attempt.dataset_name(),
            attempt.dataset_guid(),
            attempt.effect_deadline_boottime_nanoseconds(),
        )?
    } else {
        observe_dataset_until(
            &contract,
            &transaction,
            attempt,
            false,
            attempt.effect_deadline_boottime_nanoseconds(),
        )?
    };
    if !dataset_matches_expected(&dataset, attempt.dataset_name(), attempt.dataset_guid())
        || observe_workspace_pin(attempt, &dataset, &mount_namespace, &pin_root)
            .map_err(map_observer_error)?
            != WorkspacePinObservationV1::Absent
    {
        return Err(ZfsWorkerError::Authority);
    }
    // The pin worker must already have fsynced this attempt's one-use claim.
    // The initializer never creates or repairs replay state.
    replay.require_claimed(attempt.attempt_id())?;

    if let Some(authenticated) = repair.as_ref() {
        check_immediately_before_repair_effect(&protected, authenticated)?;
    } else if let Some(authenticated) = ordinary.as_ref() {
        check_immediately_before_effect(&protected, authenticated)?;
    } else {
        return Err(ZfsWorkerError::Authority);
    }

    let mut filesystem = FileSystemContext::open("zfs")?;
    filesystem.set_string("source", attempt.dataset_name())?;
    let detached = filesystem.create()?.mount()?;
    detached.set_attributes(false, MountAttributes::secure_writable(), None)?;
    let root = rustix::fs::openat(
        detached.as_fd(),
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    enforce_workspace_root_policy(&root, attempt.root_policy())?;
    executable_pin.validate_current(&contract)?;

    let result = InitializerResultV1::from_mount(attempt.attempt_id(), &received.bytes, &detached)?;
    let response_deadline = transfer_deadline()?;
    send_packet_with_descriptor_before(
        &mut socket,
        &result.encode(),
        detached.as_fd(),
        response_deadline,
    )?;
    let acknowledgement = receive_packet_before(&mut socket, ACK.len(), response_deadline)?;
    verify_same_live_subject(&received.subject, acknowledgement.subject())?;
    crate::pin_worker_runtime::verify_exact_worker_subject(
        acknowledgement.subject(),
        &worker_cgroup,
    )?;
    if acknowledgement.payload() != ACK {
        return Err(ZfsWorkerError::Protocol(
            "root initializer acknowledgement is invalid",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn socket_pair() -> (DescriptorSubjectSocket, DescriptorSubjectSocket) {
        let (left, right) = rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::SEQPACKET,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        (
            DescriptorSubjectSocket::from_owned(left).unwrap(),
            DescriptorSubjectSocket::from_owned(right).unwrap(),
        )
    }

    #[test]
    fn result_wire_rejects_noncanonical_header_and_length() {
        let result = InitializerResultV1 {
            attempt_id: [7; 16],
            request_digest: request_digest(b"protected request"),
            mount_id: 31,
            root_device: 41,
            root_inode: 59,
            uid: 0,
            gid: 0,
            mode: 0o755,
        };
        let bytes = result.encode();
        assert_eq!(InitializerResultV1::decode(&bytes).unwrap().encode(), bytes);
        assert!(InitializerResultV1::decode(&bytes[..RESULT_BYTES - 1]).is_err());
        let mut changed = bytes;
        changed[8] = 1;
        assert!(InitializerResultV1::decode(&changed).is_err());
    }

    #[test]
    fn request_digest_binds_every_byte() {
        assert_ne!(request_digest(b"request-a"), request_digest(b"request-b"));
    }

    #[test]
    fn exact_dataset_rejects_name_and_guid_substitution() {
        let observed = WorkspaceDatasetObservationV1::Exact {
            name: "tank/aos/workspace".to_owned(),
            guid: 23,
        };
        assert!(dataset_matches_expected(
            &observed,
            "tank/aos/workspace",
            23
        ));
        assert!(!dataset_matches_expected(&observed, "tank/aos/other", 23));
        assert!(!dataset_matches_expected(
            &observed,
            "tank/aos/workspace",
            24
        ));
    }

    #[test]
    fn initializer_reply_requires_exactly_one_descriptor() {
        let (mut receiver, mut sender) = socket_pair();
        sender.send(b"missing descriptor").unwrap();
        let deadline = crate::pin_worker::boottime_now_nanoseconds().unwrap() + 1_000_000_000;
        assert!(
            crate::pin_worker_runtime::receive_packet_with_descriptor_before(
                &mut receiver,
                RESULT_BYTES,
                deadline,
            )
            .is_err()
        );

        let (mut receiver, mut sender) = socket_pair();
        let first = tempfile::tempfile().unwrap();
        let second = tempfile::tempfile().unwrap();
        sender
            .send_with_descriptors(b"extra descriptor", &[first.as_fd(), second.as_fd()])
            .unwrap();
        assert!(
            crate::pin_worker_runtime::receive_packet_with_descriptor_before(
                &mut receiver,
                RESULT_BYTES,
                deadline,
            )
            .is_err()
        );
    }

    #[test]
    fn lost_initializer_reply_never_yields_a_mount() {
        let (mut receiver, sender) = socket_pair();
        drop(sender);
        let deadline = crate::pin_worker::boottime_now_nanoseconds().unwrap() + 1_000_000_000;
        assert!(
            crate::pin_worker_runtime::receive_packet_with_descriptor_before(
                &mut receiver,
                RESULT_BYTES,
                deadline,
            )
            .is_err()
        );
    }
}
