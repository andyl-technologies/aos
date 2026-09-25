//! Authenticated, read-only Host query of one retained AOSEOR03 row.
//!
//! The response is a Storage-local observation. No Create, Observe, ZFS, or
//! Host effect is admitted by this endpoint.

use std::path::Path;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::seqpacket::{RecordSubjectListener, SeqpacketError};
use aos_sandbox_protocol::storage_existing_output::{
    ExistingOutputRequestV1, ExistingOutputResponseV1, REQUEST_BYTES,
};

use crate::execution_output_credential::StorageExecutionOutputCustodyV1;
use crate::peer::HostRootExportPeerVerifier;
use crate::root_export::receive_request;
use crate::service::StorageServiceError;
use crate::transport::boottime;

const RECEIVE_NANOSECONDS: u64 = 5_000_000_000;
const MAXIMUM_QUERY_NANOSECONDS: u64 = 10_000_000_000;

/// Serves one Host query against the already-open protected Storage writer.
///
/// # Errors
///
/// Returns an error when the listener, credential, or protected writer custody
/// changes. Ordinary hostile connections and absent rows close without reply.
pub fn serve_existing_output_query_once(
    listener: &mut RecordSubjectListener,
    verifier: &HostRootExportPeerVerifier,
    custody: &StorageExecutionOutputCustodyV1,
    state_root: &Path,
) -> Result<(), StorageServiceError> {
    verifier.validate_current()?;
    listener.validate_current()?;
    custody.recheck(state_root)?;

    let mut connection = match listener.accept_descriptor_subject() {
        Ok(connection) => connection,
        Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
            return Ok(());
        }
        Err(_) => return Ok(()),
    };
    let execution = match verifier.verify_connection(connection.peer()) {
        Ok(execution) => execution,
        Err(()) => return Ok(()),
    };

    let receive_deadline = boottime()?
        .checked_add(RECEIVE_NANOSECONDS)
        .ok_or(StorageServiceError::Clock)?;
    let packet = match receive_request(&mut connection, receive_deadline, REQUEST_BYTES) {
        Ok(packet) => packet,
        Err(()) => return Ok(()),
    };
    let record = match connection.bind_received(packet) {
        Ok(record) => record,
        Err(_) => return Ok(()),
    };
    if verifier
        .verify_record(execution, record.peer(), record.subject())
        .is_err()
        || !record.descriptors().is_empty()
    {
        return Ok(());
    }
    let request = match ExistingOutputRequestV1::decode(record.payload()) {
        Ok(request) => request,
        Err(_) => return Ok(()),
    };
    drop(record);

    let now = boottime()?;
    let latest = now
        .checked_add(MAXIMUM_QUERY_NANOSECONDS)
        .ok_or(StorageServiceError::Clock)?;
    if request.deadline_boottime_nanoseconds <= now
        || request.deadline_boottime_nanoseconds > latest
        || verifier.verify_connection(connection.peer()) != Ok(execution)
    {
        return Ok(());
    }

    let retained = match custody.ledger().read_protected_retained_output(
        request.execution,
        request.create,
        ObjectDigest::from_bytes(request.record_digest),
    ) {
        Ok(retained) => retained,
        Err(_) => return Ok(()),
    };
    let response = ExistingOutputResponseV1 {
        nonce: request.nonce,
        request_digest: request.digest().map_err(|_| {
            StorageServiceError::Activation(
                "canonical existing-output request was invalid".to_owned(),
            )
        })?,
        execution: retained.execution(),
        create: retained.create_operation(),
        assignment_digest: *retained.assignment_digest().as_bytes(),
        claim_digest: *retained.claim_digest().as_bytes(),
        record_digest: *retained.record_digest().as_bytes(),
        admitted_bytes: retained.admitted_bytes(),
        maximum_stdout_bytes: retained.maximum_stdout_bytes(),
        maximum_stderr_bytes: retained.maximum_stderr_bytes(),
        journal_sequence: retained.journal_sequence(),
    };
    let bytes = response.encode().map_err(|_| {
        StorageServiceError::Activation("protected existing-output row was invalid".to_owned())
    })?;

    custody.recheck(state_root)?;
    if custody
        .ledger()
        .revalidate_retained_output(&retained)
        .is_err()
        || boottime()? >= request.deadline_boottime_nanoseconds
        || verifier.verify_connection(connection.peer()) != Ok(execution)
        || connection.send(&bytes).is_err()
    {
        return Ok(());
    }
    custody.recheck(state_root)?;
    Ok(())
}
