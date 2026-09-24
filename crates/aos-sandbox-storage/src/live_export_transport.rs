//! Root-only, nonauthorizing Provider-to-Storage export-plan ingress.
//!
//! The accepted process and record subject must both be the live SourceProvider
//! service in its retained cgroup. Storage independently pins both plan keys,
//! its current export catalog, and the physical workspace origin. The only
//! response is a descriptor-free `Unavailable`; the exact inspected plan and
//! physical readback are durably replay-fenced before that response. No lease
//! or export effect is reachable without independent selected-row/current-
//! attempt proof and an enforcing read-only KernelExportGrant owner.

use std::path::Path;

use aos_sandbox_linux::seqpacket::RecordSubjectListener;
use aos_sandbox_source_provider_protocol::{
    MAXIMUM_STORAGE_EXPORT_REQUEST_PACKET_BYTES_V1, StorageLiveExportTransportRequestV1,
    StorageLiveExportUnavailableV1,
};

use crate::live_export_request_readback::{
    StorageLiveExportReadbackErrorV1, StorageLiveExportRequestReadbackOwnerV1,
};
use crate::live_export_request_replay::{
    StorageLiveExportReplayErrorV1, StorageLiveExportReplayLedgerV1,
};
use crate::peer::ProviderLiveExportPeerVerifier;
use crate::runtime::{StorageBrokerRuntime, StorageRuntimeError};
use crate::service::StorageServiceError;
use crate::transport::{accept_connection, boottime, receive, send};

const REQUEST_RECEIVE_NANOSECONDS: u64 = 10_000_000_000;
const READBACK_NANOSECONDS: u64 = 45_000_000_000;

/// Reports a closed inspection or ordinary request rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageLiveExportTransportOutcomeV1 {
    /// Storage authenticated and inspected the plan but granted no export.
    Unavailable,
    /// A peer, packet, protected input, or physical observation failed closed.
    Rejected,
}

/// Inspects one Provider connection and returns only explicit unavailability.
///
/// # Errors
///
/// Returns a fatal error for a retired listener/cgroup, invalid clock, or
/// Storage runtime requiring process reopen. Other failures close the child
/// without an authority-bearing response.
pub fn serve_live_export_request_once(
    listener: &mut RecordSubjectListener,
    runtime: &mut StorageBrokerRuntime,
    verifier: &ProviderLiveExportPeerVerifier,
    authority_directory: &Path,
) -> Result<StorageLiveExportTransportOutcomeV1, StorageServiceError> {
    if runtime.requires_reopen() {
        return Err(StorageRuntimeError::ReopenRequired.into());
    }
    verifier.validate_current()?;
    let Some(mut connection) = accept_connection(listener)? else {
        return Ok(StorageLiveExportTransportOutcomeV1::Rejected);
    };
    let execution = match verifier.verify_connection(connection.peer()) {
        Ok(execution) => execution,
        Err(()) => return Ok(StorageLiveExportTransportOutcomeV1::Rejected),
    };
    let receive_deadline = boottime()?
        .checked_add(REQUEST_RECEIVE_NANOSECONDS)
        .ok_or(StorageServiceError::Clock)?;
    let record = match receive(
        &mut connection,
        MAXIMUM_STORAGE_EXPORT_REQUEST_PACKET_BYTES_V1,
        receive_deadline,
    ) {
        Ok(record) => record,
        Err(_) => return Ok(StorageLiveExportTransportOutcomeV1::Rejected),
    };
    if verifier
        .verify_record(execution, connection.peer(), record.subject())
        .is_err()
    {
        return Ok(StorageLiveExportTransportOutcomeV1::Rejected);
    }
    let request = match StorageLiveExportTransportRequestV1::from_canonical_bytes(record.payload())
    {
        Ok(request) if request.sequence() == 1 => request,
        _ => return Ok(StorageLiveExportTransportOutcomeV1::Rejected),
    };
    drop(record);

    // One request per accepted channel keeps transport sequence state exact.
    // The protected replay journal below fences retries across connections.
    let readback_owner =
        match StorageLiveExportRequestReadbackOwnerV1::open_root_owned(authority_directory) {
            Ok(owner) => owner,
            Err(_) => return Ok(StorageLiveExportTransportOutcomeV1::Rejected),
        };
    let readback_deadline = boottime()?
        .checked_add(READBACK_NANOSECONDS)
        .ok_or(StorageServiceError::Clock)?;
    let signed_plan = request.signed_plan().to_canonical_bytes();
    let readback = match readback_owner.inspect(runtime, &signed_plan, readback_deadline) {
        Ok(readback) => readback,
        Err(StorageLiveExportReadbackErrorV1::Origin(StorageRuntimeError::ReopenRequired)) => {
            return Err(StorageRuntimeError::ReopenRequired.into());
        }
        Err(_) => return Ok(StorageLiveExportTransportOutcomeV1::Rejected),
    };
    if readback.signed_request_digest() != request.signed_plan().digest() {
        return Ok(StorageLiveExportTransportOutcomeV1::Rejected);
    }

    // This is only a replay fence for a physically inspected, signed plan.
    // KernelExportGrant, read-only clone, and terminal revocation authority
    // do not exist yet; the response below remains descriptor-free Unavailable.
    let mut replay = match StorageLiveExportReplayLedgerV1::open_root_owned(authority_directory) {
        Ok(replay) => replay,
        Err(_) => return Err(StorageRuntimeError::ReopenRequired.into()),
    };
    match replay.record(&readback) {
        Ok(_) => {}
        Err(
            StorageLiveExportReplayErrorV1::Conflict | StorageLiveExportReplayErrorV1::Noncanonical,
        ) => {
            return Ok(StorageLiveExportTransportOutcomeV1::Rejected);
        }
        Err(StorageLiveExportReplayErrorV1::Journal(_)) => {
            return Err(StorageRuntimeError::ReopenRequired.into());
        }
    }
    drop(readback);

    if boottime()? >= readback_deadline
        || verifier.verify_connection(connection.peer()) != Ok(execution)
    {
        return Ok(StorageLiveExportTransportOutcomeV1::Rejected);
    }
    let response = StorageLiveExportUnavailableV1::for_request(&request).to_canonical_bytes();
    if send(&mut connection, &response, readback_deadline).is_err() {
        return Ok(StorageLiveExportTransportOutcomeV1::Rejected);
    }
    Ok(StorageLiveExportTransportOutcomeV1::Unavailable)
}
