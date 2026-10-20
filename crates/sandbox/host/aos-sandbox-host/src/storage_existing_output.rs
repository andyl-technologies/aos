//! Host client for one authenticated Storage AOSEOR03 logical readback.
//!
//! A successful response is a current Storage-local observation only. It
//! cannot authorize Create, Observe, or a Host effect without the ordered
//! all-owner barrier.

mod retaining;
pub(crate) mod capture;
pub(crate) use retaining::StorageExistingOutputOriginalV2;
use retaining::*;

use std::fs;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::path::Path;

use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::pidfd::PidFdInfo;
use aos_sandbox_linux::seqpacket::KernelAuthorizedRecordSubject;
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_protocol::storage_existing_output::{
    ExistingOutputRequestV1, ExistingOutputResponseV1, RESPONSE_BYTES,
};
use aos_sandbox_protocol::storage_held_output_session::{
    ACK_BYTES, HeldOutputAckV1, HeldOutputBeginV1, HeldOutputProofV1, HeldOutputTerminalModeV1,
    HeldOutputTerminalV1, PROOF_BYTES,
};
use rand::{TryRngCore as _, rngs::OsRng};

use crate::storage_root_export::{boottime, receive_reply, send_request};
use crate::{HostError, Result};

const QUERY_SOCKET: &str = "/run/aos/sandbox-storage/existing-output.sock";
const STORAGE_CGROUP: &str = "aos.slice/aos-control.slice/aos-storaged.service";
const SYSTEMD_MANAGER_CGROUP: &str = "init.scope";
const QUERY_DEADLINE_NANOSECONDS: u64 = 10_000_000_000;

/// Retains the exact Storage service cgroup for output query replies.
#[derive(Debug)]
pub struct StorageExistingOutputClientV1 {
    storage_cgroup: RetainedCgroupAnchor,
    manager_cgroup: RetainedCgroupAnchor,
}

/// Names the Storage v2 claim and exact logical split expected by a future
/// authenticated Controller cut.
///
/// Construction validates shape only. The caller must establish Controller
/// provenance and keep that owner held before this value can enter a barrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedExistingOutputV1 {
    record_digest: [u8; 32],
    claim_digest: [u8; 32],
    admitted_bytes: u64,
    maximum_stdout_bytes: u64,
    maximum_stderr_bytes: u64,
}

/// Retains the byte-exact request and authenticated Storage reply for a Host
/// durability precursor. The pair carries no effect authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExistingOutputObservationV1 {
    request: ExistingOutputRequestV1,
    response: ExistingOutputResponseV1,
}

impl ExistingOutputObservationV1 {
    /// Reopens only a canonical request and matching canonical reply.
    ///
    /// Host state authenticates the stored bytes before calling this helper.
    ///
    /// # Errors
    ///
    /// Rejects malformed, swapped, or mismatched exchange bytes.
    pub(crate) fn from_recovered_bytes(request: &[u8], response: &[u8]) -> Result<Self> {
        let request = ExistingOutputRequestV1::decode(request).map_err(query_error)?;
        let response = ExistingOutputResponseV1::decode(response).map_err(query_error)?;
        response.verify_request(request).map_err(query_error)?;
        Ok(Self { request, response })
    }

    /// Returns the exact request selected by Host.
    #[must_use]
    pub const fn request(self) -> ExistingOutputRequestV1 {
        self.request
    }

    /// Returns the exact Storage row verified against that request.
    #[must_use]
    pub const fn response(self) -> ExistingOutputResponseV1 {
        self.response
    }
}

impl ExpectedExistingOutputV1 {
    /// Constructs an exact v2 claim and output split for read-only comparison.
    ///
    /// # Errors
    ///
    /// Rejects sentinel digests or a split that does not equal admitted bytes.
    pub fn new(
        record_digest: [u8; 32],
        claim_digest: [u8; 32],
        admitted_bytes: u64,
        maximum_stdout_bytes: u64,
        maximum_stderr_bytes: u64,
    ) -> Result<Self> {
        if record_digest == [0; 32]
            || claim_digest == [0; 32]
            || maximum_stdout_bytes.checked_add(maximum_stderr_bytes) != Some(admitted_bytes)
        {
            return Err(query_error("expected output is invalid"));
        }
        Ok(Self {
            record_digest,
            claim_digest,
            admitted_bytes,
            maximum_stdout_bytes,
            maximum_stderr_bytes,
        })
    }

    /// Returns the exact AOSEOR03 record digest selected by Host.
    #[must_use]
    pub const fn record_digest(self) -> [u8; 32] {
        self.record_digest
    }

    /// Compares every output field in Storage's authenticated reply.
    ///
    /// # Errors
    ///
    /// Rejects a wrong assignment, v2 claim, record, or byte split.
    pub fn verify(
        self,
        assignment_digest: [u8; 32],
        response: &ExistingOutputResponseV1,
    ) -> Result<()> {
        if assignment_digest == [0; 32]
            || response.assignment_digest != assignment_digest
            || response.claim_digest != self.claim_digest
            || response.record_digest != self.record_digest
            || response.admitted_bytes != self.admitted_bytes
            || response.maximum_stdout_bytes != self.maximum_stdout_bytes
            || response.maximum_stderr_bytes != self.maximum_stderr_bytes
        {
            return Err(query_error("Storage output differs from expected source"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketRouteIdentity {
    device: u64,
    inode: u64,
}

impl StorageExistingOutputClientV1 {
    /// Opens the fixed Storage service cgroup beneath a retained cgroup-v2 root.
    ///
    /// # Errors
    ///
    /// Rejects an absent, inactive, or unsafe Storage service cgroup.
    pub fn new(cgroup_root: CgroupV2Root) -> Result<Self> {
        let storage_cgroup = cgroup_root
            .resolve(Path::new(STORAGE_CGROUP))
            .map_err(query_error)?;
        let manager_cgroup = cgroup_root
            .resolve(Path::new(SYSTEMD_MANAGER_CGROUP))
            .map_err(query_error)?;
        storage_cgroup.validate_current().map_err(query_error)?;
        manager_cgroup.validate_current().map_err(query_error)?;
        Ok(Self {
            storage_cgroup,
            manager_cgroup,
        })
    }

    /// Queries the exact retained AOSEOR03 row known to Host.
    ///
    /// The returned sequence identifies only Storage's local journal head.
    /// The caller must retain and compare the independently authenticated
    /// accepted-Create, environment, Host, and physical Storage observations
    /// before using this readback at a future effect barrier.
    ///
    /// # Errors
    ///
    /// Rejects an absent row, missing endpoint, wrong responder, malformed or
    /// swapped reply, changed cgroup, or expired deadline.
    pub fn query(
        &self,
        execution: [u8; 16],
        create: [u8; 16],
        record_digest: [u8; 32],
    ) -> Result<ExistingOutputResponseV1> {
        self.query_exchange(execution, create, record_digest)
            .map(|observation| observation.response)
    }

    fn query_exchange(
        &self,
        execution: [u8; 16],
        create: [u8; 16],
        record_digest: [u8; 32],
    ) -> Result<ExistingOutputObservationV1> {
        self.query_exchange_with_disposition(execution, create, record_digest, None, None)
    }

    fn query_exchange_with_disposition(
        &self, execution: [u8; 16], create: [u8; 16], record_digest: [u8; 32],
        cutoff: Option<u64>, original: Option<&mut QueryOriginalV2>,
    ) -> Result<ExistingOutputObservationV1> {
        let (open, mut native, reply) = query_destinations(original);
        let (mut socket, route, manager) = self.open_checked_socket_with_disposition(open)?;
        let (nonce, deadline) = fresh_challenge_observed(cutoff, &mut native)?;
        let request = ExistingOutputRequestV1 {
            nonce,
            deadline_boottime_nanoseconds: deadline,
            execution,
            create,
            record_digest,
        };
        if self.verify_activation_peer_observed(socket.get()?, &mut native)? != manager
            || validate_socket_route_observed(&mut native)? != route
        {
            return Err(query_error("socket activation peer changed"));
        }
        if let Some(original) = native.as_deref_mut() { original.request = Some(request); }
        {
            let encoded = capture(request.encode(), &mut native)?;
            send_observed(socket.get_mut()?, &encoded, deadline, &mut native)?;
        }

        let mut reply = self.receive_storage_record_observed(
            socket.get_mut()?,
            manager,
            route,
            deadline,
            RESPONSE_BYTES,
            None,
            reply,
        )?;
        reply.retire_ordinary_subject();
        let response = capture(ExistingOutputResponseV1::decode(reply.bytes()?), &mut native)?;
        capture(response.verify_request(request), &mut native)?;
        Ok(ExistingOutputObservationV1 { request, response })
    }

    /// Queries Storage and compares its exact row to a current Host assignment
    /// and separately supplied v2 Controller claim.
    ///
    /// The result remains a read-only observation. No accepted Create, physical
    /// backing, or ordered owner lifetime is established by this method.
    ///
    /// # Errors
    ///
    /// Rejects any query failure or mismatched Storage row.
    pub fn query_expected(
        &self,
        execution: [u8; 16],
        create: [u8; 16],
        assignment_digest: [u8; 32],
        expected: ExpectedExistingOutputV1,
    ) -> Result<ExistingOutputObservationV1> {
        let observation = self.query_exchange(execution, create, expected.record_digest())?;
        expected.verify(assignment_digest, &observation.response)?;
        Ok(observation)
    }

    /// Holds an exact Storage AOSEOR03 row while the caller inspects its cut.
    ///
    /// The input is a historical authenticated Storage row, not an accepted
    /// Create or current Host permit. A successful callback supplies its own
    /// nonzero settlement digest; Storage treats that value as opaque and only
    /// releases the read-only hold after a matching terminal exchange. A
    /// callback error attempts Abort and is returned unchanged. No public
    /// execution path calls this precursor.
    ///
    /// # Errors
    ///
    /// Rejects a missing or changed endpoint, wrong live Storage responder,
    /// stale row/head, malformed or replayed frames, timeout, or a lost ack.
    pub fn with_held_session<T>(
        &self,
        expected: ExistingOutputResponseV1,
        inspect: impl FnOnce(&HeldOutputProofV1) -> Result<(T, [u8; 32])>,
    ) -> Result<T> {
        let mut held = self.begin_held_observed(expected, None, None)?;
        match inspect(&held.proof) {
            Ok((value, settlement_digest)) => {
                let deadline = held.begin.deadline_boottime_nanoseconds;
                self.terminal_observed(&mut held, HeldOutputTerminalModeV1::Settle,
                    settlement_digest, deadline, None, None)?;
                Ok(value)
            }
            Err(error) => {
                // Preserve the ordinary precursor's send-only best-effort Abort.
                // Selected ownership uses the same terminal grammar plus its Ack.
                if let Ok(abort) = HeldOutputTerminalV1::new(
                    held.begin, held.proof, HeldOutputTerminalModeV1::Abort, [0;32],
                ) {
                    if let Ok(bytes) = abort.encode() {
                        let _ = send_request(&mut held.socket, &bytes,
                            held.begin.deadline_boottime_nanoseconds);
                    }
                }
                Err(error)
            }
        }
    }

    fn begin_held_observed(
        &self, expected: ExistingOutputResponseV1, cutoff: Option<u64>,
        original: Option<&mut QueryOriginalV2>,
    ) -> Result<HeldClientStateV2> {
        let (open, mut native, reply) = query_destinations(original);
        let (mut socket, route, manager) = self.open_checked_socket_with_disposition(open)?;
        let (nonce, deadline) = fresh_challenge_observed(cutoff, &mut native)?;
        let begin = HeldOutputBeginV1 {
            nonce,
            deadline_boottime_nanoseconds: deadline,
            execution: expected.execution,
            create: expected.create,
            record_digest: expected.record_digest,
            expected_journal_sequence: expected.journal_sequence,
            assignment_digest: expected.assignment_digest,
            claim_digest: expected.claim_digest,
            admitted_bytes: expected.admitted_bytes,
            maximum_stdout_bytes: expected.maximum_stdout_bytes,
            maximum_stderr_bytes: expected.maximum_stderr_bytes,
        };
        if self.verify_activation_peer_observed(socket.get()?, &mut native)? != manager
            || validate_socket_route_observed(&mut native)? != route
        {
            return Err(query_error("socket activation peer changed"));
        }
        if let Some(original) = native.as_deref_mut() { original.begin = Some(begin); }
        {
            let encoded = capture(begin.encode(), &mut native)?;
            send_observed(socket.get_mut()?, &encoded, deadline, &mut native)?;
        }

        let reply = self.receive_storage_record_observed(
            socket.get_mut()?, manager, route, deadline, PROOF_BYTES, None, reply,
        )?;
        let proof = capture(HeldOutputProofV1::decode(reply.bytes()?), &mut native)?;
        capture(proof.verify_begin(begin), &mut native)?;
        let (proof_bytes, storage, proof_subject) = reply.into_parts()?;

        Ok(HeldClientStateV2 {
            proof_subject, proof_bytes, socket: socket.take()?, route, manager,
            begin, proof, storage,
        })
    }

    fn terminal_observed(
        &self, held: &mut HeldClientStateV2, mode: HeldOutputTerminalModeV1,
        settlement_digest: [u8;32], cutoff: u64,
        mut native: NativeDestinationV2<'_>, reply: Option<&mut ReplyOriginalV2>,
    ) -> Result<()> {
        let terminal = capture(HeldOutputTerminalV1::new(
            held.begin, held.proof, mode, settlement_digest,
        ), &mut native)?;
        if let Some(original) = native.as_deref_mut() { original.terminal = Some(terminal); }
        let deadline = held.begin.deadline_boottime_nanoseconds.min(cutoff);
        let sent = {
            let encoded = capture(terminal.encode(), &mut native)?;
            send_observed(&mut held.socket, &encoded, deadline, &mut native)
        };
        // The selected original always attempts its already owed Ack on the
        // SAME held channel, including after send refusal or native poison.
        // Ordinary None keeps the old short-circuit send/receive chronology.
        let selected = native.is_some();
        let sent = if selected { sent } else { sent?; Ok(()) };
        let acknowledged = (|| {
            let mut received = self.receive_storage_record_observed(
                &mut held.socket, held.manager, held.route, deadline, ACK_BYTES,
                Some((held.storage, &held.proof_subject)), reply,
            )?;
            received.retire_ordinary_subject();
            let ack = capture(HeldOutputAckV1::decode(received.bytes()?), &mut native)?;
            capture(ack.verify_terminal(held.begin, held.proof, terminal), &mut native)
        })();
        if native.is_some() { sent.and(acknowledged) } else { acknowledged }
    }

    fn open_checked_socket_with_disposition<'original>(
        &self, original: Option<&'original mut OpenOriginalV2>,
    ) -> Result<(SocketGuardV2<'original>, SocketRouteIdentity, PidFdInfo)> {
        let retain_raw_peer = original.is_some();
        self.open_checked_socket_recipe_v3(original, retain_raw_peer, retain_raw_peer)
    }

    // Actual Capture selects the same raw-native peer admission destination.
    // This remains mechanical custody; all Storage/manager/route checks below
    // run in the same engine, and this port grants no physical authority.
    fn open_capture_socket_retaining_v3<'original>(
        &self, original: &'original mut OpenOriginalV2,
    ) -> Result<(SocketGuardV2<'original>, SocketRouteIdentity, PidFdInfo)> {
        self.open_checked_socket_recipe_v3(Some(original), true, false)
    }

    fn open_checked_socket_recipe_v3<'original>(
        &self, original: Option<&'original mut OpenOriginalV2>, retain_raw_peer: bool,
        descriptor_free: bool,
    ) -> Result<(SocketGuardV2<'original>, SocketRouteIdentity, PidFdInfo)> {
        let (destination, admission, mut native) = open_destinations(original);
        active_observed(&self.storage_cgroup, &mut native)?;
        let route = validate_socket_route_observed(&mut native)?;
        let socket = connect_observed_with_mode_v6(destination, admission, &mut native,
            retain_raw_peer, descriptor_free)?;
        let manager = self.verify_activation_peer_observed(socket.get()?, &mut native)?;
        if validate_socket_route_observed(&mut native)? != route {
            return Err(query_error("socket route changed"));
        }
        Ok((socket, route, manager))
    }

    fn receive_storage_record_observed<'original>(
        &self,
        socket: &mut DescriptorSubjectSocket,
        manager: PidFdInfo,
        route: SocketRouteIdentity,
        deadline: u64,
        maximum_bytes: usize,
        expected_storage: Option<(PidFdInfo, &KernelAuthorizedRecordSubject)>,
        original: Option<&'original mut ReplyOriginalV2>,
    ) -> Result<StorageReplyGuardV2<'original>> {
        self.receive_storage_record_kind_observed(
            socket, manager, route, deadline, maximum_bytes, expected_storage, original, false,
        )
    }

    fn receive_storage_record_kind_observed<'original>(
        &self,
        socket: &mut DescriptorSubjectSocket,
        manager: PidFdInfo,
        route: SocketRouteIdentity,
        deadline: u64,
        maximum_bytes: usize,
        expected_storage: Option<(PidFdInfo, &KernelAuthorizedRecordSubject)>,
        original: Option<&'original mut ReplyOriginalV2>,
        capture_pipes: bool,
    ) -> Result<StorageReplyGuardV2<'original>> {
        let (packet_destination, subject_destination, bytes_destination, descriptors_destination, mut native) = reply_destinations(original);
        let record = if capture_pipes {
            receive_capture_pipes_observed(socket, deadline, maximum_bytes, packet_destination, &mut native)?
        } else {
            receive_observed(socket, deadline, maximum_bytes, packet_destination, &mut native)?
        };
        validate_origin_observed(socket, record.get()?, &mut native)?;
        let credentials = record.get()?.subject().credentials();
        if credentials.uid() != 0 || credentials.gid() != 0
            || record.get()?.descriptors().len() != if capture_pipes { 2 } else { 0 } {
            return Err(query_error("responder identity is invalid"));
        }
        let storage = membership_observed(&self.storage_cgroup, record.get()?.subject().pidfd(), &mut native)?;
        if storage.pid() != credentials.pid().get()
            || storage.thread_group_id() != storage.pid()
            || expected_storage.is_some_and(|(expected, subject)| {
                expected != storage || !alive_observed(subject, &mut native, true).unwrap_or(false)
            })
            || !alive_observed(record.get()?.subject(), &mut native, false)?
        {
            return Err(query_error("responder execution changed"));
        }
        let bytes = ValueGuardV2::new(record.get()?.payload().to_vec(), bytes_destination);
        let (_, subject, descriptors) = record.take()?.into_parts();
        let subject = ValueGuardV2::new(subject, subject_destination);
        let descriptors = ValueGuardV2::new(descriptors, descriptors_destination);
        if clock_observed(&mut native)? >= deadline
            || self.verify_activation_peer_observed(socket, &mut native)? != manager
            || validate_socket_route_observed(&mut native)? != route
            || membership_observed(&self.storage_cgroup, subject.get()?.pidfd(), &mut native)?
                != storage
            || !alive_observed(subject.get()?, &mut native, false)?
        {
            return Err(query_error("responder changed or deadline elapsed"));
        }
        Ok(StorageReplyGuardV2 { bytes, subject, descriptors, storage })
    }

    fn verify_activation_peer_observed(&self, socket: &DescriptorSubjectSocket, native: &mut NativeDestinationV2<'_>) -> Result<PidFdInfo> {
        // A systemd-owned listening socket reports PID 1 as the connection
        // peer. The response record independently names the Storage worker.
        let peer = socket.peer();
        let credentials = peer.credentials();
        if credentials.uid() != 0 || credentials.gid() != 0 || credentials.pid().get() != 1 {
            return Err(query_error("socket activation peer is invalid"));
        }
        let info = membership_observed(&self.manager_cgroup, peer.pidfd(), native)?;
        if !manager_identity_is_valid(
            credentials.uid(),
            credentials.gid(),
            credentials.pid().get(),
            info.pid(),
            info.thread_group_id(),
        ) || !peer_alive_observed(peer, native)?
        {
            return Err(query_error("socket activation manager is invalid"));
        }
        Ok(info)
    }
}

fn validate_socket_route_observed(native: &mut NativeDestinationV2<'_>) -> Result<SocketRouteIdentity> {
    for directory in ["/run", "/run/aos", "/run/aos/sandbox-storage"] {
        let metadata = route_metadata_observed(directory, native)?;
        if !route_directory_is_safe(
            metadata.file_type().is_dir(),
            metadata.uid(),
            metadata.mode(),
        ) {
            return Err(query_error("socket route directory is unsafe"));
        }
    }
    let metadata = route_metadata_observed(QUERY_SOCKET, native)?;
    if !route_endpoint_is_safe(
        metadata.file_type().is_socket(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
        metadata.nlink(),
    ) {
        return Err(query_error("socket route endpoint is unsafe"));
    }
    Ok(SocketRouteIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn fresh_challenge() -> Result<([u8; 32], u64)> {
    fresh_challenge_observed(None, &mut None)
}

fn manager_identity_is_valid(
    uid: u32,
    gid: u32,
    peer_pid: u32,
    cgroup_pid: u32,
    thread_group_id: u32,
) -> bool {
    uid == 0 && gid == 0 && peer_pid == 1 && cgroup_pid == 1 && thread_group_id == 1
}

fn route_directory_is_safe(is_directory: bool, uid: u32, mode: u32) -> bool {
    is_directory && uid == 0 && mode & 0o022 == 0
}

fn route_endpoint_is_safe(is_socket: bool, uid: u32, gid: u32, mode: u32, links: u64) -> bool {
    is_socket && uid == 0 && gid == 0 && mode & 0o7777 == 0o600 && links == 1
}

fn query_error(error: impl std::fmt::Display) -> HostError {
    HostError::State(format!("existing-output query failed: {error}"))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn expected_output_requires_exact_v2_claim_assignment_and_split() {
        let expected = ExpectedExistingOutputV1::new([1; 32], [2; 32], 7, 3, 4).unwrap();
        let request = ExistingOutputRequestV1 {
            nonce: [3; 32],
            deadline_boottime_nanoseconds: 10,
            execution: [4; 16],
            create: [5; 16],
            record_digest: [1; 32],
        };
        let mut response = ExistingOutputResponseV1 {
            nonce: request.nonce,
            request_digest: request.digest().unwrap(),
            execution: request.execution,
            create: request.create,
            assignment_digest: [6; 32],
            claim_digest: [2; 32],
            record_digest: request.record_digest,
            admitted_bytes: 7,
            maximum_stdout_bytes: 3,
            maximum_stderr_bytes: 4,
            journal_sequence: 1,
        };
        expected.verify([6; 32], &response).unwrap();
        assert_eq!(
            ExistingOutputObservationV1::from_recovered_bytes(
                &request.encode().unwrap(),
                &response.encode().unwrap(),
            )
            .unwrap()
            .response(),
            response,
        );
        assert!(expected.verify([7; 32], &response).is_err());

        response.claim_digest = [8; 32];
        assert!(expected.verify([6; 32], &response).is_err());
        response.claim_digest = [2; 32];
        response.maximum_stdout_bytes = 4;
        response.maximum_stderr_bytes = 3;
        assert!(expected.verify([6; 32], &response).is_err());
        response.maximum_stdout_bytes = 3;
        response.maximum_stderr_bytes = 4;
        response.record_digest = [9; 32];
        assert!(expected.verify([6; 32], &response).is_err());
        assert!(
            ExistingOutputObservationV1::from_recovered_bytes(
                &request.encode().unwrap(),
                &response.encode().unwrap(),
            )
            .is_err()
        );

        assert!(ExpectedExistingOutputV1::new([1; 32], [2; 32], 7, 3, 3).is_err());
        assert!(ExpectedExistingOutputV1::new([0; 32], [2; 32], 0, 0, 0).is_err());
        assert!(ExpectedExistingOutputV1::new([1; 32], [2; 32], 0, 0, 0).is_ok());
    }

    #[test]
    fn activation_peer_requires_exact_root_pid_one() {
        assert!(manager_identity_is_valid(0, 0, 1, 1, 1));
        for identity in [
            (1, 0, 1, 1, 1),
            (0, 1, 1, 1, 1),
            (0, 0, 2, 1, 1),
            (0, 0, 1, 2, 1),
            (0, 0, 1, 1, 2),
        ] {
            assert!(!manager_identity_is_valid(
                identity.0, identity.1, identity.2, identity.3, identity.4,
            ));
        }
    }

    #[test]
    fn route_rejects_writable_names_symlinks_and_replaced_endpoint() {
        assert!(route_directory_is_safe(true, 0, 0o40710));
        assert!(!route_directory_is_safe(true, 0, 0o40730));
        assert!(!route_directory_is_safe(false, 0, 0o40710));
        assert!(route_endpoint_is_safe(true, 0, 0, 0o140600, 1));
        assert!(!route_endpoint_is_safe(true, 0, 0, 0o140660, 1));
        assert!(!route_endpoint_is_safe(true, 0, 0, 0o140600, 2));

        let directory = TempDir::new().unwrap();
        let first_path = directory.path().join("first.sock");
        let second_path = directory.path().join("second.sock");
        let _first = UnixListener::bind(&first_path).unwrap();
        let _second = UnixListener::bind(&second_path).unwrap();
        let first = fs::symlink_metadata(&first_path).unwrap();
        let second = fs::symlink_metadata(&second_path).unwrap();
        let first_identity = SocketRouteIdentity {
            device: first.dev(),
            inode: first.ino(),
        };
        let second_identity = SocketRouteIdentity {
            device: second.dev(),
            inode: second.ino(),
        };
        assert_ne!(first_identity, second_identity);

        let alias = directory.path().join("alias.sock");
        symlink(&first_path, &alias).unwrap();
        let alias = fs::symlink_metadata(alias).unwrap();
        assert!(!route_endpoint_is_safe(
            alias.file_type().is_socket(),
            0,
            0,
            0o140600,
            1,
        ));
    }
}
