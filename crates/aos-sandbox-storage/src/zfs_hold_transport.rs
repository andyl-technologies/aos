//! Authenticated, Unavailable-only native Provider-to-Storage hold inspection.
//!
//! The live Provider process can submit one AOSZHQ01 assertion per connection.
//! Storage independently joins its selected native row to a confined reader's
//! exact detached mount and drops that mount before sending AOSZHU01. This
//! endpoint cannot sign a hold receipt, spend a Provider challenge, or deliver
//! a SourceRoot descriptor.

use aos_sandbox_linux::seqpacket::RecordSubjectListener;
use aos_sandbox_source_provider_protocol::{
    MAXIMUM_STORAGE_ZFS_HOLD_REQUEST_PACKET_BYTES_V1, StorageZfsHoldTransportRequestV1,
    StorageZfsHoldUnavailableV1,
};

use crate::peer::ProviderLiveExportPeerVerifier;
use crate::runtime::{StorageBrokerRuntime, StorageRuntimeError};
use crate::service::StorageServiceError;
use crate::transport::{accept_connection, boottime, receive, send};

const REQUEST_RECEIVE_NANOSECONDS: u64 = 10_000_000_000;
const READBACK_NANOSECONDS: u64 = 180_000_000_000;

/// Reports whether one closed native request was authenticated and inspected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageZfsHoldTransportOutcomeV1 {
    /// Storage inspected the exact claim but granted no SourceRoot authority.
    Unavailable,
    /// The connection, packet, protected cut, or physical mount failed closed.
    Rejected,
}

/// Inspects one live Provider request and returns only descriptor-free Unavailable.
///
/// # Errors
///
/// Returns a fatal error for a retired listener/cgroup, invalid clock, or a
/// Storage runtime requiring process reopen. Ordinary rejection closes only
/// the accepted child.
pub fn serve_zfs_hold_request_once(
    listener: &mut RecordSubjectListener,
    runtime: &mut StorageBrokerRuntime,
    verifier: &ProviderLiveExportPeerVerifier,
) -> Result<StorageZfsHoldTransportOutcomeV1, StorageServiceError> {
    if runtime.requires_reopen() {
        return Err(StorageRuntimeError::ReopenRequired.into());
    }
    verifier.validate_current()?;
    let Some(mut connection) = accept_connection(listener)? else {
        return Ok(StorageZfsHoldTransportOutcomeV1::Rejected);
    };
    let execution = match verifier.verify_connection(connection.peer()) {
        Ok(execution) => execution,
        Err(()) => return Ok(StorageZfsHoldTransportOutcomeV1::Rejected),
    };
    let receive_deadline = boottime()?
        .checked_add(REQUEST_RECEIVE_NANOSECONDS)
        .ok_or(StorageServiceError::Clock)?;
    let record = match receive(
        &mut connection,
        MAXIMUM_STORAGE_ZFS_HOLD_REQUEST_PACKET_BYTES_V1,
        receive_deadline,
    ) {
        Ok(record) => record,
        Err(_) => return Ok(StorageZfsHoldTransportOutcomeV1::Rejected),
    };
    if verifier
        .verify_record(execution, connection.peer(), record.subject())
        .is_err()
    {
        return Ok(StorageZfsHoldTransportOutcomeV1::Rejected);
    }
    let request = match StorageZfsHoldTransportRequestV1::from_canonical_bytes(record.payload()) {
        Ok(request) if request.sequence() == 1 => request,
        _ => return Ok(StorageZfsHoldTransportOutcomeV1::Rejected),
    };
    drop(record);

    // Provider's catalog is a selection claim, not Storage authority. Only
    // the independently recovered Snapshot/hold cut can authorize the read.
    let (binding, _) = request.selection();
    let catalog = request.catalog();
    let (_, snapshot) = match catalog.select_under_head(
        catalog.generation(),
        catalog.digest(),
        catalog.namespace_digest(),
        binding,
    ) {
        Ok(selected) => selected,
        Err(_) => return Ok(StorageZfsHoldTransportOutcomeV1::Rejected),
    };
    let readback_deadline = boottime()?
        .checked_add(READBACK_NANOSECONDS)
        .ok_or(StorageServiceError::Clock)?;
    let held = match runtime.observe_native_held_snapshot_claim_with_mount(&snapshot) {
        Ok(held) => held,
        Err(StorageRuntimeError::ReopenRequired) => {
            return Err(StorageRuntimeError::ReopenRequired.into());
        }
        Err(_) => return Ok(StorageZfsHoldTransportOutcomeV1::Rejected),
    };
    if held.verify_mount().is_err() {
        return Ok(StorageZfsHoldTransportOutcomeV1::Rejected);
    }
    // No descriptor, receipt, or retained authority escapes this inspection.
    drop(held);

    if boottime()? >= readback_deadline
        || verifier.verify_connection(connection.peer()) != Ok(execution)
    {
        return Ok(StorageZfsHoldTransportOutcomeV1::Rejected);
    }
    let response = StorageZfsHoldUnavailableV1::for_request(&request).to_canonical_bytes();
    if send(&mut connection, &response, readback_deadline).is_err() {
        return Ok(StorageZfsHoldTransportOutcomeV1::Rejected);
    }
    Ok(StorageZfsHoldTransportOutcomeV1::Unavailable)
}
