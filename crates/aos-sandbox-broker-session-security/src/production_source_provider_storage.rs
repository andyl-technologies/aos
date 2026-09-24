//! Fixed authenticated SourceProvider client for unavailable-only Storage intake.
//!
//! This client accepts an already signed plan; it cannot mint one. The fixed
//! Storage socket, root account, retained service cgroup, connection peer, and
//! record subject must agree before an `Unavailable` response is accepted.
//! No response can convey a lease, descriptor, or effect authorization.

use std::path::Path;

use aos_sandbox_linux::cgroup::CgroupV2Root;
use aos_sandbox_linux::pidfd::PidFdInfo;
use aos_sandbox_linux::seqpacket::bounded::{BoundedRecordError, boottime, receive, send};
use aos_sandbox_linux::seqpacket::{
    ConnectionPeerIdentity, KernelAuthorizedRecordSubject, SeqpacketSocket,
};
use aos_sandbox_source_provider_protocol::{
    SignedStorageLiveExportRequestV1, StorageLiveExportTransportRequestV1,
    StorageLiveExportUnavailableV1,
};
use rustix::fs::{Mode, OFlags, open};
use rustix::rand::{GetRandomFlags, getrandom};

const STORAGE_SOCKET: &str = "/run/aos/sandbox-storage/live-export-request.sock";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const STORAGE_CGROUP: &str = "aos.slice/aos-control.slice/aos-storaged.service";
const EXCHANGE_NANOSECONDS: u64 = 60_000_000_000;
const UNAVAILABLE_RESPONSE_BYTES: usize = 96;

/// Reports unavailable-only transport or Storage-peer authentication failure.
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
}

/// Reports the only currently permitted Storage exchange outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionSourceProviderStorageOutcomeV1 {
    /// Storage inspected a request but granted no export or descriptor.
    Unavailable,
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
    let cgroup_descriptor = open(
        CGROUP_ROOT,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ProductionSourceProviderStorageErrorV1::Endpoint)?;
    let cgroup_root = CgroupV2Root::from_owned(cgroup_descriptor)
        .map_err(|_| ProductionSourceProviderStorageErrorV1::Endpoint)?;
    let storage_cgroup = cgroup_root
        .resolve(Path::new(STORAGE_CGROUP))
        .map_err(|_| ProductionSourceProviderStorageErrorV1::Endpoint)?;
    let mut connection = SeqpacketSocket::connect(Path::new(STORAGE_SOCKET))
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
