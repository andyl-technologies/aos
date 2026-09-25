//! One-shot, confined physical measurement of a Storage-held ZFS snapshot.
//!
//! The request is selected by the protected Storage owner, never by a public
//! broker method. The reader mounts only that snapshot in its private mount
//! namespace, applies read-only, nodev, nosuid, and noexec attributes while
//! detached, and returns a bounded physical measurement without a descriptor,
//! signature, or SourceRoot receipt.
//!
//! ```text
//! AOSHSR01 request = version:u16 | snapshot-guid:u64 | pool-guid:u64 |
//!                    cut-digest:32 | nonce:16 | name-length:u16 | snapshot-name
//! AOSHSM01 result  = version:u16 | request-digest:32 | content-digest:32 |
//!                    tree-digest:32 | tree-size:u64 | mount-id:u64 |
//!                    root-device:u64 | root-inode:u64 | nodes:u32 | file-bytes:u64 |
//!                    mounted-snapshot-guid:u64
//! ```

use std::os::fd::{AsFd as _, OwnedFd};
use std::path::Path;
use std::time::Duration;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::inventory::MountId;
use aos_sandbox_linux::seqpacket::{KernelAuthorizedRecordSubject, SeqpacketSocket};
use rustix::fs::{Mode, OFlags, StatVfsMountFlags};
use sha2::{Digest as _, Sha256};

use crate::ResolvedSnapshot;
use crate::held_snapshot_tree::measure_bound_detached_snapshot;

use super::{
    Deadline, ZfsWorkerError, current_cgroup_path, decode_ack, decode_ready_frame, encode_ack,
    encode_ready_frame, open_cgroup_root, quiesce_worker, receive_before, send_before,
    verify_same_live_subject, verify_same_subject, verify_storaged_peer,
    verify_systemd_activation_peer, wait_for_worker_quiescence,
};

const REQUEST_MAGIC: &[u8; 8] = b"AOSHSR01";
const RESULT_MAGIC: &[u8; 8] = b"AOSHSM01";
const READY_MAGIC: &[u8; 8] = b"AOSHSRD1";
const VERSION: u16 = 1;
const REQUEST_DOMAIN: &[u8] = b"aos.sandbox.storage.held-snapshot-reader.v1\0";
const SOCKET_PATH: &str = "/run/aos/sandbox-held-snapshot-reader/control.sock";
const NAMESPACE_MARKER: &str = "/run/aos-held-reader-namespace";
const TMPFS_MAGIC: u64 = 0x0102_1994;
const STORAGED_CGROUP: &str = "aos.slice/aos-control.slice/aos-storaged.service";
const READER_CGROUP_PREFIX: &str = "aos.slice/aos-control.slice/aos-sandbox-held-snapshot-reader@";
const READER_CGROUP_SUFFIX: &str = ".service";
const RESULT_BYTES: usize = 158;
const MAXIMUM_REQUEST_BYTES: usize = 1024;
const MAXIMUM_READY_BYTES: usize = 512;
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(45);

/// Retains a measured byte identity and mount identity, without authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HeldSnapshotReaderObservationV1 {
    pub(crate) content_digest: ObjectDigest,
    pub(crate) tree_digest: ObjectDigest,
    pub(crate) tree_size: u64,
    pub(crate) mount_id: u64,
    pub(crate) root_device: u64,
    pub(crate) root_inode: u64,
    pub(crate) nodes: u32,
    pub(crate) file_bytes: u64,
    /// Zero until the mounted descriptor itself proves the immutable ZFS GUID.
    pub(crate) mounted_snapshot_guid: u64,
}

/// Authenticates the fixed one-shot reader and proves its whole-unit exit.
pub(crate) struct SystemdHeldSnapshotReaderV1 {
    manager: RetainedCgroupAnchor,
    worker_parent: RetainedCgroupAnchor,
    fail_stopped: bool,
}

impl SystemdHeldSnapshotReaderV1 {
    pub(crate) fn new(cgroup_root: CgroupV2Root) -> Result<Self, ZfsWorkerError> {
        Ok(Self {
            manager: cgroup_root.resolve(Path::new("init.scope"))?,
            worker_parent: cgroup_root.resolve(Path::new("aos.slice/aos-control.slice"))?,
            fail_stopped: false,
        })
    }

    pub(crate) fn measure(
        &mut self,
        snapshot: &ResolvedSnapshot,
        expected_pool_guid: u64,
        protected_cut_digest: ObjectDigest,
        nonce: [u8; 16],
    ) -> Result<HeldSnapshotReaderObservationV1, ZfsWorkerError> {
        if self.fail_stopped {
            return Err(ZfsWorkerError::Quiescence(
                "held snapshot reader is fail-stopped".to_owned(),
            ));
        }
        let request = encode_request(snapshot, expected_pool_guid, protected_cut_digest, nonce)?;
        let request_digest = digest_request(&request);
        let deadline = Deadline::after(EXCHANGE_TIMEOUT);
        let mut socket = SeqpacketSocket::connect(Path::new(SOCKET_PATH))?;
        socket
            .peer()
            .require_peer_filesystem_path(socket.as_fd()?, Path::new(SOCKET_PATH))?;
        verify_systemd_activation_peer(socket.peer(), &self.manager)?;

        let ready = receive_before(&mut socket, MAXIMUM_READY_BYTES, deadline)?;
        let (ready_payload, reader_subject) = ready.into_parts();
        let reader_cgroup = self.verify_reader(&reader_subject, decode_ready(&ready_payload)?)?;
        let population = reader_cgroup.population_monitor()?;
        let exchange = (|| {
            send_before(&mut socket, &request, deadline)?;
            let response = receive_before(&mut socket, RESULT_BYTES, deadline)?;
            verify_same_live_subject(&reader_subject, response.subject())?;
            reader_cgroup.verify_exact_membership(response.subject().pidfd())?;
            let measured = decode_result(response.payload(), request_digest, snapshot.guid())?;
            send_before(&mut socket, &encode_ack(), deadline)?;
            Ok(measured)
        })();

        match exchange {
            Ok(measured) => {
                if wait_for_worker_quiescence(&reader_subject, &population, Duration::from_secs(1))
                    .is_ok()
                {
                    return Ok(measured);
                }
                if quiesce_worker(&reader_subject, &reader_cgroup, &population).is_err() {
                    self.fail_stopped = true;
                }
                Err(ZfsWorkerError::Quiescence(
                    "held snapshot reader did not exit cleanly".to_owned(),
                ))
            }
            Err(error) => {
                if quiesce_worker(&reader_subject, &reader_cgroup, &population).is_err() {
                    self.fail_stopped = true;
                    return Err(ZfsWorkerError::Quiescence(
                        "held snapshot reader cancellation was not proved".to_owned(),
                    ));
                }
                Err(error)
            }
        }
    }

    fn verify_reader(
        &self,
        subject: &KernelAuthorizedRecordSubject,
        path: &str,
    ) -> Result<RetainedCgroupAnchor, ZfsWorkerError> {
        let instance = path
            .strip_prefix(READER_CGROUP_PREFIX)
            .and_then(|suffix| suffix.strip_suffix(READER_CGROUP_SUFFIX))
            .ok_or(ZfsWorkerError::PeerMismatch)?;
        if instance.is_empty() || instance.len() > 255 || instance.contains('/') {
            return Err(ZfsWorkerError::PeerMismatch);
        }
        let relative = path
            .strip_prefix("aos.slice/aos-control.slice/")
            .ok_or(ZfsWorkerError::PeerMismatch)?;
        let cgroup = self.worker_parent.resolve_descendant(Path::new(relative))?;
        let observed = cgroup.verify_exact_membership(subject.pidfd())?;
        let credentials = subject.credentials();
        if credentials.uid() != 0
            || credentials.gid() != 0
            || observed.pid() != credentials.pid().get()
            || observed.thread_group_id() != credentials.pid().get()
        {
            return Err(ZfsWorkerError::PeerMismatch);
        }
        self.worker_parent.validate_current()?;
        Ok(cgroup)
    }
}

/// Runs one Storage-only reader on its inherited systemd socket.
///
/// # Errors
///
/// Rejects a missing private mount namespace, incorrect Storage peer, malformed
/// request, unsupported snapshot tree, or incomplete bounded exchange.
pub fn run_inherited_held_snapshot_reader() -> Result<(), ZfsWorkerError> {
    aos_sandbox_linux::process::disable_core_dumps()?;
    require_private_mount_namespace()?;

    let storaged = open_cgroup_root()?.resolve(Path::new(STORAGED_CGROUP))?;
    let inherited: OwnedFd = rustix::io::dup(std::io::stdin().as_fd())?;
    let mut socket = SeqpacketSocket::from_owned(inherited)?;
    socket
        .peer()
        .require_local_filesystem_path(socket.as_fd()?, Path::new(SOCKET_PATH))?;
    verify_storaged_peer(socket.peer(), &storaged)?;
    socket.enable_record_subjects()?;

    let deadline = Deadline::after(EXCHANGE_TIMEOUT);
    let ready = encode_ready(&current_cgroup_path()?)?;
    send_before(&mut socket, &ready, deadline)?;
    let record = receive_before(&mut socket, MAXIMUM_REQUEST_BYTES, deadline)?;
    verify_same_subject(socket.peer(), record.subject())?;
    storaged.verify_exact_membership(record.subject().pidfd())?;
    let (snapshot_name, expected_pool_guid, expected_snapshot_guid, request_digest) =
        decode_request(record.payload())?;

    let measured =
        measure_bound_detached_snapshot(snapshot_name, expected_pool_guid, expected_snapshot_guid)
            .map_err(|error| ZfsWorkerError::Executable(error.to_string()))?;
    let observation = HeldSnapshotReaderObservationV1 {
        content_digest: measured.content_digest,
        tree_digest: measured.tree.digest(),
        tree_size: measured.tree.encoded_size(),
        mount_id: measured.mount_id.get(),
        root_device: measured.root_device,
        root_inode: measured.root_inode,
        nodes: u32::try_from(measured.nodes)
            .map_err(|_| ZfsWorkerError::Protocol("measured node count exceeds wire bound"))?,
        file_bytes: u64::try_from(measured.file_bytes)
            .map_err(|_| ZfsWorkerError::Protocol("measured file bytes exceed wire bound"))?,
        // This is asserted only after the mounted root FD's UUID matched both
        // immutable GUIDs before and after the complete byte walk.
        mounted_snapshot_guid: expected_snapshot_guid,
    };
    send_before(
        &mut socket,
        &encode_result(request_digest, observation),
        deadline,
    )?;
    let acknowledgement = receive_before(&mut socket, 10, deadline)?;
    verify_same_subject(socket.peer(), acknowledgement.subject())?;
    storaged.verify_exact_membership(acknowledgement.subject().pidfd())?;
    decode_ack(acknowledgement.payload())
}

fn require_private_mount_namespace() -> Result<(), ZfsWorkerError> {
    // systemd mounts this exact marker only while constructing the service's
    // PrivateMounts namespace. PID 1's nsfs link is inaccessible under
    // ProtectProc=invisible without adding CAP_SYS_PTRACE.
    let marker = rustix::fs::open(
        NAMESPACE_MARKER,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let parent = rustix::fs::open(
        "/run",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let flags = rustix::fs::fstatvfs(&marker)?.f_flag;
    let filesystem = rustix::fs::fstatfs(&marker)?;
    if MountId::from_fd(marker.as_fd())? == MountId::from_fd(parent.as_fd())?
        || filesystem.f_type as u64 != TMPFS_MAGIC
        || !flags.contains(
            StatVfsMountFlags::RDONLY
                | StatVfsMountFlags::NOSUID
                | StatVfsMountFlags::NODEV
                | StatVfsMountFlags::NOEXEC,
        )
    {
        return Err(ZfsWorkerError::Protocol(
            "reader private mount namespace marker is invalid",
        ));
    }
    Ok(())
}

fn encode_request(
    snapshot: &ResolvedSnapshot,
    expected_pool_guid: u64,
    cut_digest: ObjectDigest,
    nonce: [u8; 16],
) -> Result<Vec<u8>, ZfsWorkerError> {
    let name = snapshot.name().as_bytes();
    validate_name(name)?;
    if snapshot.guid() == 0
        || expected_pool_guid == 0
        || cut_digest.as_bytes() == &[0; 32]
        || nonce == [0; 16]
    {
        return Err(ZfsWorkerError::Protocol(
            "reader request identity is invalid",
        ));
    }
    let mut bytes = Vec::with_capacity(76 + name.len());
    bytes.extend_from_slice(REQUEST_MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&snapshot.guid().to_be_bytes());
    bytes.extend_from_slice(&expected_pool_guid.to_be_bytes());
    bytes.extend_from_slice(cut_digest.as_bytes());
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(
        &u16::try_from(name.len())
            .map_err(|_| ZfsWorkerError::Protocol("snapshot name is oversized"))?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(name);
    Ok(bytes)
}

fn decode_request(bytes: &[u8]) -> Result<(&str, u64, u64, ObjectDigest), ZfsWorkerError> {
    if bytes.len() < 76 || bytes.len() > MAXIMUM_REQUEST_BYTES || &bytes[..8] != REQUEST_MAGIC {
        return Err(ZfsWorkerError::Protocol(
            "reader request length or magic is invalid",
        ));
    }
    if bytes[8..10] != VERSION.to_be_bytes()
        || bytes[10..18] == [0; 8]
        || bytes[18..26] == [0; 8]
        || bytes[26..58] == [0; 32]
        || bytes[58..74] == [0; 16]
    {
        return Err(ZfsWorkerError::Protocol(
            "reader request identity is invalid",
        ));
    }
    let length = usize::from(u16::from_be_bytes([bytes[74], bytes[75]]));
    if bytes.len() != 76 + length {
        return Err(ZfsWorkerError::Protocol("reader snapshot length differs"));
    }
    let name = &bytes[76..];
    validate_name(name)?;
    let name = std::str::from_utf8(name)
        .map_err(|_| ZfsWorkerError::Protocol("reader snapshot name is not UTF-8"))?;
    let mut guid = [0; 8];
    guid.copy_from_slice(&bytes[10..18]);
    let mut pool = [0; 8];
    pool.copy_from_slice(&bytes[18..26]);
    Ok((
        name,
        u64::from_be_bytes(pool),
        u64::from_be_bytes(guid),
        digest_request(bytes),
    ))
}

fn validate_name(name: &[u8]) -> Result<(), ZfsWorkerError> {
    let separator = name.iter().position(|byte| *byte == b'@');
    let snapshot_component = separator.and_then(|index| name.get(index + 1..));
    if name.is_empty()
        || name.len() > MAXIMUM_REQUEST_BYTES - 76
        || name.iter().filter(|byte| **byte == b'@').count() != 1
        || snapshot_component.is_none_or(|part| part.is_empty() || part == b"." || part == b"..")
        || !name.iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-' | b'.' | b'@' | b':')
        })
        || name
            .split(|byte| *byte == b'/')
            .any(|part| part.is_empty() || part == b"." || part == b".." || part.starts_with(b"@"))
    {
        return Err(ZfsWorkerError::Protocol("reader snapshot name is invalid"));
    }
    Ok(())
}

fn digest_request(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(REQUEST_DOMAIN)
            .chain_update(bytes)
            .finalize()
            .into(),
    )
}

fn encode_ready(cgroup: &str) -> Result<Vec<u8>, ZfsWorkerError> {
    if !cgroup.starts_with(READER_CGROUP_PREFIX) || !cgroup.ends_with(READER_CGROUP_SUFFIX) {
        return Err(ZfsWorkerError::PeerMismatch);
    }
    encode_ready_frame(cgroup, READY_MAGIC, VERSION)
}

fn decode_ready(bytes: &[u8]) -> Result<&str, ZfsWorkerError> {
    decode_ready_frame(bytes, READY_MAGIC, VERSION)
}

fn encode_result(
    digest: ObjectDigest,
    measured: HeldSnapshotReaderObservationV1,
) -> [u8; RESULT_BYTES] {
    let mut bytes = [0; RESULT_BYTES];
    bytes[..8].copy_from_slice(RESULT_MAGIC);
    bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
    bytes[10..42].copy_from_slice(digest.as_bytes());
    bytes[42..74].copy_from_slice(measured.content_digest.as_bytes());
    bytes[74..106].copy_from_slice(measured.tree_digest.as_bytes());
    bytes[106..114].copy_from_slice(&measured.tree_size.to_be_bytes());
    bytes[114..122].copy_from_slice(&measured.mount_id.to_be_bytes());
    bytes[122..130].copy_from_slice(&measured.root_device.to_be_bytes());
    bytes[130..138].copy_from_slice(&measured.root_inode.to_be_bytes());
    bytes[138..142].copy_from_slice(&measured.nodes.to_be_bytes());
    bytes[142..150].copy_from_slice(&measured.file_bytes.to_be_bytes());
    bytes[150..158].copy_from_slice(&measured.mounted_snapshot_guid.to_be_bytes());
    bytes
}

fn decode_result(
    bytes: &[u8],
    expected: ObjectDigest,
    expected_snapshot_guid: u64,
) -> Result<HeldSnapshotReaderObservationV1, ZfsWorkerError> {
    if bytes.len() != RESULT_BYTES
        || &bytes[..8] != RESULT_MAGIC
        || bytes[8..10] != VERSION.to_be_bytes()
        || bytes[10..42] != *expected.as_bytes()
    {
        return Err(ZfsWorkerError::Protocol("reader result header is invalid"));
    }
    let array = |start: usize| -> [u8; 8] {
        let mut value = [0; 8];
        value.copy_from_slice(&bytes[start..start + 8]);
        value
    };
    let mut content = [0; 32];
    content.copy_from_slice(&bytes[42..74]);
    let mut tree = [0; 32];
    tree.copy_from_slice(&bytes[74..106]);
    let measured = HeldSnapshotReaderObservationV1 {
        content_digest: ObjectDigest::from_bytes(content),
        tree_digest: ObjectDigest::from_bytes(tree),
        tree_size: u64::from_be_bytes(array(106)),
        mount_id: u64::from_be_bytes(array(114)),
        root_device: u64::from_be_bytes(array(122)),
        root_inode: u64::from_be_bytes(array(130)),
        nodes: u32::from_be_bytes([bytes[138], bytes[139], bytes[140], bytes[141]]),
        file_bytes: u64::from_be_bytes(array(142)),
        mounted_snapshot_guid: u64::from_be_bytes(array(150)),
    };
    if measured.content_digest.as_bytes() == &[0; 32]
        || measured.tree_digest.as_bytes() == &[0; 32]
        || measured.tree_size == 0
        || measured.mount_id == 0
        || measured.root_inode == 0
        || measured.nodes == 0
        || measured.mounted_snapshot_guid != expected_snapshot_guid
    {
        return Err(ZfsWorkerError::Protocol(
            "reader result has no exact mounted snapshot GUID proof",
        ));
    }
    Ok(measured)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{ManagedDatasetRoot, ResolvedDataset, StorageDomainsV1};

    #[test]
    fn rejects_ambiguous_snapshot_names() {
        for name in [
            b"pool/../data@snap".as_slice(),
            b"pool/data@x@y",
            b"pool/data@",
            b"pool//data@snap",
            b"pool/data@x\n",
        ] {
            assert!(validate_name(name).is_err());
        }
        assert!(validate_name(b"pool/data@snap-1").is_ok());
    }

    #[test]
    fn ready_frame_preserves_reader_role_and_exact_length() {
        let cgroup = "aos.slice/aos-control.slice/aos-sandbox-held-snapshot-reader@1.service";
        let frame = encode_ready(cgroup).unwrap();

        assert_eq!(decode_ready(&frame).unwrap(), cgroup);
        assert!(super::super::decode_ready(&frame).is_err());
        assert!(decode_ready(&frame[..frame.len() - 1]).is_err());
        assert!(decode_ready(&[frame.as_slice(), &[0]].concat()).is_err());
    }

    #[test]
    fn request_decoder_retains_both_expected_guids() {
        let name = b"pool/data@snap";
        let mut request = Vec::new();
        request.extend_from_slice(REQUEST_MAGIC);
        request.extend_from_slice(&VERSION.to_be_bytes());
        request.extend_from_slice(&11_u64.to_be_bytes());
        request.extend_from_slice(&13_u64.to_be_bytes());
        request.extend_from_slice(&[3; 32]);
        request.extend_from_slice(&[5; 16]);
        request.extend_from_slice(&(name.len() as u16).to_be_bytes());
        request.extend_from_slice(name);

        let (decoded_name, pool_guid, snapshot_guid, digest) = decode_request(&request).unwrap();
        assert_eq!(decoded_name, "pool/data@snap");
        assert_eq!(pool_guid, 13);
        assert_eq!(snapshot_guid, 11);
        assert_eq!(digest, digest_request(&request));

        request[18..26].fill(0);
        assert!(decode_request(&request).is_err());
    }

    #[test]
    fn rejects_changed_or_truncated_reader_result() {
        let digest = ObjectDigest::from_bytes([1; 32]);
        let measured = HeldSnapshotReaderObservationV1 {
            content_digest: ObjectDigest::from_bytes([2; 32]),
            tree_digest: ObjectDigest::from_bytes([3; 32]),
            tree_size: 1,
            mount_id: 2,
            root_device: 3,
            root_inode: 4,
            nodes: 1,
            file_bytes: 5,
            mounted_snapshot_guid: 7,
        };
        let bytes = encode_result(digest, measured);
        assert_eq!(decode_result(&bytes, digest, 7).unwrap(), measured);
        assert!(decode_result(&bytes, ObjectDigest::from_bytes([9; 32]), 7).is_err());
        assert!(decode_result(&bytes[..157], digest, 7).is_err());
        assert!(decode_result(&bytes, digest, 8).is_err());

        // A missing mounted GUID remains invalid even when the request names
        // the expected snapshot.
        let unbound = encode_result(
            digest,
            HeldSnapshotReaderObservationV1 {
                mounted_snapshot_guid: 0,
                ..measured
            },
        );
        assert!(decode_result(&unbound, digest, 7).is_err());
    }

    #[test]
    #[ignore = "requires the installed systemd reader, native ZFS hold, and cgroup-v2 VM"]
    fn systemd_reader_vm_client() {
        let case = std::fs::read_to_string("/run/aos/held-reader-case").unwrap();
        let fields = case.trim().split(':').collect::<Vec<_>>();
        assert_eq!(fields.len(), 5);
        let variant = fields[0];
        let pool_guid = fields[1].parse::<u64>().unwrap();
        let root_guid = fields[2].parse::<u64>().unwrap();
        let dataset_guid = fields[3].parse::<u64>().unwrap();
        let snapshot_guid = fields[4].parse::<u64>().unwrap();
        let different_guid = |guid: u64| if guid == 1 { 2 } else { guid - 1 };

        let domains = StorageDomainsV1::new(
            ObjectDigest::from_bytes([1; 32]),
            ObjectDigest::from_bytes([2; 32]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
        )
        .unwrap();
        let root = ManagedDatasetRoot::from_catalog("aosproof", "aosproof/aos", root_guid).unwrap();
        let dataset = ResolvedDataset::from_catalog(
            root,
            "aosproof/aos/project/workspace",
            dataset_guid,
            [5; 32],
            domains,
        )
        .unwrap();
        let expected_snapshot_guid = if variant == "wrong-snapshot" {
            different_guid(snapshot_guid)
        } else {
            snapshot_guid
        };
        let snapshot =
            ResolvedSnapshot::from_catalog(dataset, "held", expected_snapshot_guid, [6; 32])
                .unwrap();
        let expected_pool_guid = if variant == "wrong-pool" {
            different_guid(pool_guid)
        } else {
            pool_guid
        };

        // This fixture supplies a nonzero request binding, not a protected
        // Storage journal cut or any SourceRoot authority.
        let mut reader = SystemdHeldSnapshotReaderV1::new(open_cgroup_root().unwrap()).unwrap();
        let observation = reader.measure(
            &snapshot,
            expected_pool_guid,
            ObjectDigest::from_bytes([7; 32]),
            [8; 16],
        );
        match variant {
            "matched" => {
                let measured = observation.unwrap();
                assert_eq!(measured.mounted_snapshot_guid, snapshot_guid);
                assert_ne!(measured.content_digest.as_bytes(), &[0; 32]);
                assert!(measured.mount_id > 0 && measured.nodes > 0);
            }
            "wrong-pool" | "wrong-snapshot" => {
                assert!(observation.is_err());
                assert!(!reader.fail_stopped);
            }
            _ => panic!("unknown held-reader VM case"),
        }
    }

    #[test]
    #[ignore = "requires a wrong-cgroup systemd service and the installed reader socket"]
    fn systemd_reader_vm_decoy() {
        let mut socket = SeqpacketSocket::connect(Path::new(SOCKET_PATH)).unwrap();
        let deadline = Deadline::after(Duration::from_secs(10));

        loop {
            assert!(
                deadline.remaining().is_some(),
                "decoy peer was not rejected"
            );
            match socket.receive(MAXIMUM_READY_BYTES) {
                Err(aos_sandbox_linux::seqpacket::SeqpacketError::WouldBlock) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
                Ok(_) => panic!("reader sent READY to a wrong-cgroup peer"),
            }
        }
    }
}
