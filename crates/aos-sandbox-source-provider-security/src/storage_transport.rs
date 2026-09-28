//! Fixed authenticated SourceProvider clients for Storage intake.
//!
//! This client accepts an already signed plan; it cannot mint one. The fixed
//! Storage socket, root account, retained service cgroup, connection peer, and
//! record subject must agree before a reply is retained. LocalLive inspection
//! remains descriptor-free and unavailable-only. Native reply custody still
//! requires independent signature, protected-state, and physical validation.

use std::os::fd::OwnedFd;
use std::path::Path;

use aos_sandbox_linux::cgroup::CgroupV2Root;
use aos_sandbox_linux::pidfd::PidFdInfo;
use aos_sandbox_linux::seqpacket::bounded::{BoundedRecordError, boottime, receive, send};
use aos_sandbox_linux::seqpacket::{
    ConnectionPeerIdentity, KernelAuthorizedRecordSubject, SeqpacketSocket,
};
use aos_sandbox_source_provider_protocol::{
    STORAGE_NATIVE_ACQUIRE_REPLY_BYTES_V3, SignedStorageLiveExportRequestV1,
    SignedStorageNativeAcquireRequestV2, StorageLiveExportTransportRequestV1,
    StorageLiveExportUnavailableV1, StorageNativeAcquireReplyV3, StorageZfsHoldUnavailableV1,
};
use rustix::fs::{Mode, OFlags, open};
use rustix::rand::{GetRandomFlags, getrandom};

const LIVE_EXPORT_SOCKET: &str = "/run/aos/sandbox-storage/live-export-request.sock";
const NATIVE_HOLD_SOCKET: &str = "/run/aos/sandbox-storage/zfs-hold-request.sock";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const STORAGE_CGROUP: &str = "aos.slice/aos-control.slice/aos-storaged.service";
const EXCHANGE_NANOSECONDS: u64 = 60_000_000_000;
const UNAVAILABLE_RESPONSE_BYTES: usize = 96;

/// Reports transport, descriptor framing, or Storage-peer authentication failure.
#[derive(Debug, thiserror::Error)]
pub enum ProductionSourceProviderStorageErrorV1 {
    /// The fixed Storage endpoint or retained cgroup could not be established.
    #[error("SourceProvider Storage endpoint is unavailable")]
    Endpoint,
    /// The connection peer or record subject is not the live Storage service.
    #[error("SourceProvider Storage peer is unauthenticated")]
    Peer,
    /// Kernel entropy could not produce a fresh challenge.
    #[error("SourceProvider Storage challenge generation failed")]
    Entropy,
    /// The bounded record exchange failed.
    #[error("SourceProvider Storage exchange failed: {0}")]
    Transport(#[from] BoundedRecordError),
    /// Storage's response did not match the exact signed request.
    #[error("SourceProvider Storage response is invalid")]
    Response,
    /// The descriptor-bearing carrier failed.
    #[error("SourceProvider Storage descriptor exchange failed: {0}")]
    DescriptorTransport(#[from] aos_sandbox_linux::seqpacket::SeqpacketError),
}

/// Reports the only currently permitted Storage exchange outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionSourceProviderStorageOutcomeV1 {
    /// Storage inspected a request but granted no export or descriptor.
    Unavailable,
}

/// Retains an exact native reply and its live, kernel-authenticated Storage peer.
///
/// Private fields prevent callers from manufacturing live origin with scalar
/// peer claims. This retains peer and FD custody, not perpetual currentness of
/// Storage's global journal or Provider completion authority.
pub struct ReceivedStorageNativeAcquireV3 {
    reply: StorageNativeAcquireReplyV3,
    descriptor: Option<OwnedFd>,
    connection: SeqpacketSocket,
    cgroup: aos_sandbox_linux::cgroup::RetainedCgroupAnchor,
    execution: StorageEndpointExecutionV1,
    subject: KernelAuthorizedRecordSubject,
}

impl ReceivedStorageNativeAcquireV3 {
    /// Borrows the exact canonical acceptance and receipt bundle.
    #[must_use]
    pub const fn reply(&self) -> &StorageNativeAcquireReplyV3 {
        &self.reply
    }

    /// Rechecks the same live Storage process, subject, connection, and cgroup.
    ///
    /// # Errors
    ///
    /// Rejects Storage process death, peer substitution, or cgroup drift.
    pub fn revalidate(&self) -> Result<(), ProductionSourceProviderStorageErrorV1> {
        verify_storage_record(
            &self.cgroup,
            self.execution,
            self.connection.peer(),
            &self.subject,
        )
    }

    /// Takes the originally received FD once after peer revalidation.
    ///
    /// This releases received custody, never durable Provider handoff authority.
    ///
    /// # Errors
    ///
    /// Rejects stale peer custody or a descriptor already taken.
    pub fn take_original_descriptor(
        &mut self,
    ) -> Result<OwnedFd, ProductionSourceProviderStorageErrorV1> {
        self.revalidate()?;
        self.descriptor
            .take()
            .ok_or(ProductionSourceProviderStorageErrorV1::Response)
    }
}

/// Exchanges exact retained native bytes with the fixed authenticated endpoint.
///
/// Retries send identical signed bytes and nonce. A positive result owns one
/// SourceRoot FD plus live peer custody; explicit unavailability owns none.
/// A transport error never proves that Storage did not accept the request.
///
/// # Errors
///
/// Rejects endpoint, peer, deadline, packet, response binding, descriptor-table,
/// or nominated record-subject failures.
pub fn exchange_signed_storage_native_acquire_v2(
    request: &SignedStorageNativeAcquireRequestV2,
) -> Result<Option<ReceivedStorageNativeAcquireV3>, ProductionSourceProviderStorageErrorV1> {
    let cgroup = retained_storage_cgroup()?;
    let mut connection = SeqpacketSocket::connect(Path::new(NATIVE_HOLD_SOCKET))
        .map_err(|_| ProductionSourceProviderStorageErrorV1::Endpoint)?;
    let execution = verify_storage_peer(&cgroup, connection.peer())?;
    let deadline = boottime()?
        .checked_add(EXCHANGE_NANOSECONDS)
        .ok_or(ProductionSourceProviderStorageErrorV1::Response)?;
    send(&mut connection, &request.to_canonical_bytes(), deadline)?;
    let record = receive_native_reply(
        &mut connection,
        STORAGE_NATIVE_ACQUIRE_REPLY_BYTES_V3,
        deadline,
    )?;
    verify_storage_record(&cgroup, execution, connection.peer(), record.subject())?;
    let bound = connection
        .bind_received_descriptors(record)
        .map_err(|_| ProductionSourceProviderStorageErrorV1::Peer)?;
    let (payload, subject, mut descriptors, _) = bound.into_parts();

    if payload.starts_with(b"AOSZHU01") {
        if !descriptors.is_empty() {
            return Err(ProductionSourceProviderStorageErrorV1::Response);
        }
        StorageZfsHoldUnavailableV1::from_canonical_bytes(&payload)
            .and_then(|response| response.verify_for(request.request().claims()))
            .map_err(|_| ProductionSourceProviderStorageErrorV1::Response)?;
        verify_storage_record(&cgroup, execution, connection.peer(), &subject)?;
        return Ok(None);
    }

    let reply = StorageNativeAcquireReplyV3::from_canonical_bytes(&payload)
        .map_err(|_| ProductionSourceProviderStorageErrorV1::Response)?;
    if descriptors.len() != 1
        || reply.acceptance().acceptance().request_digest() != request.digest()
    {
        return Err(ProductionSourceProviderStorageErrorV1::Response);
    }
    let descriptor = descriptors
        .pop()
        .ok_or(ProductionSourceProviderStorageErrorV1::Response)?;
    let received = ReceivedStorageNativeAcquireV3 {
        reply,
        descriptor: Some(descriptor),
        connection,
        cgroup,
        execution,
        subject,
    };
    received.revalidate()?;
    Ok(Some(received))
}

fn receive_native_reply(
    socket: &mut SeqpacketSocket,
    maximum: usize,
    deadline: u64,
) -> Result<
    aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord,
    ProductionSourceProviderStorageErrorV1,
> {
    use aos_sandbox_linux::seqpacket::SeqpacketError;
    use rustix::event::{PollFd, PollFlags, Timespec, poll};

    loop {
        let remaining = deadline
            .checked_sub(boottime()?)
            .filter(|remaining| *remaining > 0)
            .ok_or(BoundedRecordError::Clock)?;
        match socket.receive_with_optional_descriptor(maximum) {
            Ok(record) => {
                if boottime()? >= deadline {
                    return Err(BoundedRecordError::Clock.into());
                }
                return Ok(record);
            }
            Err(SeqpacketError::Interrupted) => continue,
            Err(SeqpacketError::WouldBlock) => {}
            Err(error) => return Err(error.into()),
        }
        let timeout = Timespec {
            tv_sec: i64::try_from(remaining / 1_000_000_000)
                .map_err(|_| BoundedRecordError::Clock)?,
            tv_nsec: i64::try_from(remaining % 1_000_000_000)
                .map_err(|_| BoundedRecordError::Clock)?,
        };
        let mut ready = [PollFd::from_borrowed_fd(socket.as_fd()?, PollFlags::IN)];
        match poll(&mut ready, Some(&timeout)) {
            Ok(0) => return Err(BoundedRecordError::Clock.into()),
            Ok(_) | Err(rustix::io::Errno::INTR) => {}
            Err(error) => return Err(BoundedRecordError::Io(error).into()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StorageEndpointExecutionV1 {
    Storage(PidFdInfo),
    SocketManager(PidFdInfo),
}

/// Submits one already signed plan to the fixed Storage service.
///
/// This is a closed readback seam: it cannot construct a Provider plan, sign
/// one, or convert `Unavailable` into a lease or Mount Acquire success.
///
/// # Errors
///
/// Rejects missing/changed endpoint, cgroup, peer, record subject, challenge,
/// deadline, packet, or exact response binding.
pub fn inspect_signed_storage_export_plan(
    signed_plan: SignedStorageLiveExportRequestV1,
) -> Result<ProductionSourceProviderStorageOutcomeV1, ProductionSourceProviderStorageErrorV1> {
    let storage_cgroup = retained_storage_cgroup()?;
    let mut connection = SeqpacketSocket::connect(Path::new(LIVE_EXPORT_SOCKET))
        .map_err(|_| ProductionSourceProviderStorageErrorV1::Endpoint)?;
    let execution = verify_storage_peer(&storage_cgroup, connection.peer())?;

    let mut nonce = [0; 32];
    let mut filled = 0;
    while filled < nonce.len() {
        let count = getrandom(&mut nonce[filled..], GetRandomFlags::empty())
            .map_err(|_| ProductionSourceProviderStorageErrorV1::Entropy)?;
        if count == 0 {
            return Err(ProductionSourceProviderStorageErrorV1::Entropy);
        }
        filled += count;
    }
    let request = StorageLiveExportTransportRequestV1::new(1, nonce, signed_plan)
        .map_err(|_| ProductionSourceProviderStorageErrorV1::Response)?;
    let deadline = boottime()?
        .checked_add(EXCHANGE_NANOSECONDS)
        .ok_or(ProductionSourceProviderStorageErrorV1::Response)?;
    send(&mut connection, &request.to_canonical_bytes(), deadline)?;
    let record = receive(&mut connection, UNAVAILABLE_RESPONSE_BYTES, deadline)?;
    if verify_storage_record(
        &storage_cgroup,
        execution,
        connection.peer(),
        record.subject(),
    )
    .is_err()
    {
        return Err(ProductionSourceProviderStorageErrorV1::Peer);
    }
    let response = StorageLiveExportUnavailableV1::from_canonical_bytes(record.payload())
        .map_err(|_| ProductionSourceProviderStorageErrorV1::Response)?;
    response
        .matches_request(&request)
        .map_err(|_| ProductionSourceProviderStorageErrorV1::Response)?;
    verify_storage_peer(&storage_cgroup, connection.peer())?;
    Ok(ProductionSourceProviderStorageOutcomeV1::Unavailable)
}

fn retained_storage_cgroup()
-> Result<aos_sandbox_linux::cgroup::RetainedCgroupAnchor, ProductionSourceProviderStorageErrorV1> {
    let descriptor = open(
        CGROUP_ROOT,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ProductionSourceProviderStorageErrorV1::Endpoint)?;
    CgroupV2Root::from_owned(descriptor)
        .and_then(|root| root.resolve(Path::new(STORAGE_CGROUP)))
        .map_err(|_| ProductionSourceProviderStorageErrorV1::Endpoint)
}

fn verify_storage_peer(
    cgroup: &aos_sandbox_linux::cgroup::RetainedCgroupAnchor,
    peer: &ConnectionPeerIdentity,
) -> Result<StorageEndpointExecutionV1, ProductionSourceProviderStorageErrorV1> {
    cgroup
        .validate_current()
        .map_err(|_| ProductionSourceProviderStorageErrorV1::Peer)?;
    let credentials = peer.credentials();
    if credentials.uid() != 0 || credentials.gid() != 0 {
        return Err(ProductionSourceProviderStorageErrorV1::Peer);
    }
    // With socket activation the connection establisher may be PID 1, while
    // each response record must independently name the live Storage service.
    let info = peer.initial_info();
    let pid = credentials.pid().get();
    if info.pid() != pid
        || info.thread_group_id() != pid
        || !peer
            .is_alive()
            .map_err(|_| ProductionSourceProviderStorageErrorV1::Peer)?
    {
        return Err(ProductionSourceProviderStorageErrorV1::Peer);
    }
    if let Ok(storage) = cgroup.verify_exact_membership(peer.pidfd()) {
        if same_process(storage, info) {
            return Ok(StorageEndpointExecutionV1::Storage(storage));
        }
    }
    if pid == 1 {
        return Ok(StorageEndpointExecutionV1::SocketManager(info));
    }
    Err(ProductionSourceProviderStorageErrorV1::Peer)
}

fn verify_storage_record(
    cgroup: &aos_sandbox_linux::cgroup::RetainedCgroupAnchor,
    expected: StorageEndpointExecutionV1,
    peer: &ConnectionPeerIdentity,
    subject: &KernelAuthorizedRecordSubject,
) -> Result<(), ProductionSourceProviderStorageErrorV1> {
    let current = verify_storage_peer(cgroup, peer)?;
    let credentials = subject.credentials();
    if current != expected
        || credentials.uid() != 0
        || credentials.gid() != 0
        || !subject
            .is_alive()
            .map_err(|_| ProductionSourceProviderStorageErrorV1::Peer)?
    {
        return Err(ProductionSourceProviderStorageErrorV1::Peer);
    }
    let record = cgroup
        .verify_exact_membership(subject.pidfd())
        .map_err(|_| ProductionSourceProviderStorageErrorV1::Peer)?;
    if credentials.pid().get() != record.pid()
        || record.thread_group_id() != record.pid()
        || (matches!(expected, StorageEndpointExecutionV1::Storage(info) if !same_process(info, record)))
        || verify_storage_peer(cgroup, peer)? != expected
    {
        return Err(ProductionSourceProviderStorageErrorV1::Peer);
    }
    Ok(())
}

fn same_process(left: PidFdInfo, right: PidFdInfo) -> bool {
    left.pid() == right.pid()
        && left.thread_group_id() == right.thread_group_id()
        && left.cgroup_id() == right.cgroup_id()
}
