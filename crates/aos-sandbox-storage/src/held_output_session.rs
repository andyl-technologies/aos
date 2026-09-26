//! Authenticated, read-only AOSEOR03 hold on the existing Host query socket.
//!
//! Storage retains its exclusive output writer from the exact proof through a
//! matching terminal and acknowledgement. A caller settlement digest is only
//! an opaque coordinate: this service neither verifies earlier owners nor
//! commits ReserveOutput, Create, Apply, or any other effect.

use std::path::Path;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::pidfd::PidFdInfo;
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_protocol::storage_existing_output::ExistingOutputResponseV1;
use aos_sandbox_protocol::storage_held_output_session::{
    HeldOutputAckV1, HeldOutputBeginV1, HeldOutputProofV1, HeldOutputTerminalV1, TERMINAL_BYTES,
};

use crate::execution_output::ExecutionOutputLedgerErrorV1;
use crate::execution_output_credential::StorageExecutionOutputCustodyV1;
use crate::peer::HostRootExportPeerVerifier;
use crate::root_export::receive_request;
use crate::service::StorageServiceError;
use crate::transport::boottime;

const MAXIMUM_SESSION_NANOSECONDS: u64 = 10_000_000_000;

/// Runs one closed held-output flight on an already authenticated Host child.
///
/// The caller must verify the first record and connection establisher before
/// invoking this function. Every subsequent record is independently bound to
/// that same live service execution. Invalid selectors, terminal frames,
/// timeout, and disconnect close without acknowledgement.
///
/// # Errors
///
/// Returns an error for changed protected credentials, writer names, corrupt
/// journal custody, or an invalid kernel clock requiring process reopen.
pub(crate) fn serve_held_output_session(
    connection: &mut DescriptorSubjectSocket,
    verifier: &HostRootExportPeerVerifier,
    execution: PidFdInfo,
    custody: &StorageExecutionOutputCustodyV1,
    state_root: &Path,
    begin: HeldOutputBeginV1,
) -> Result<(), StorageServiceError> {
    let now = boottime()?;
    let latest = now
        .checked_add(MAXIMUM_SESSION_NANOSECONDS)
        .ok_or(StorageServiceError::Clock)?;
    if begin.deadline_boottime_nanoseconds <= now
        || begin.deadline_boottime_nanoseconds > latest
        || verifier.verify_connection(connection.peer()) != Ok(execution)
    {
        return Ok(());
    }

    let result = custody.with_held_existing_output_for_session(
        state_root,
        begin.execution,
        begin.create,
        ObjectDigest::from_bytes(begin.record_digest),
        begin.expected_journal_sequence,
        |held| {
            let retained = held.readback();
            let proof = HeldOutputProofV1 {
                row: ExistingOutputResponseV1 {
                    nonce: begin.nonce,
                    request_digest: begin.digest().map_err(|_| protected_changed())?,
                    execution: retained.execution(),
                    create: retained.create_operation(),
                    assignment_digest: *retained.assignment_digest().as_bytes(),
                    claim_digest: *retained.claim_digest().as_bytes(),
                    record_digest: *retained.record_digest().as_bytes(),
                    admitted_bytes: retained.admitted_bytes(),
                    maximum_stdout_bytes: retained.maximum_stdout_bytes(),
                    maximum_stderr_bytes: retained.maximum_stderr_bytes(),
                    journal_sequence: retained.journal_sequence(),
                },
            };
            if proof.verify_begin(begin).is_err() {
                return Ok(());
            }
            let proof_bytes = proof.encode().map_err(|_| protected_changed())?;

            custody.recheck(state_root)?;
            held.revalidate().map_err(|_| protected_changed())?;
            if boottime()? >= begin.deadline_boottime_nanoseconds
                || verifier.verify_connection(connection.peer()) != Ok(execution)
                || connection.send(&proof_bytes).is_err()
            {
                return Ok(());
            }

            let packet = match receive_request(
                connection,
                begin.deadline_boottime_nanoseconds,
                TERMINAL_BYTES,
            ) {
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
            let terminal = match HeldOutputTerminalV1::decode(record.payload()) {
                Ok(terminal) => terminal,
                Err(_) => return Ok(()),
            };
            drop(record);
            if terminal.verify_proof(begin, proof).is_err() {
                return Ok(());
            }

            custody.recheck(state_root)?;
            held.revalidate().map_err(|_| protected_changed())?;
            let ack = HeldOutputAckV1::new(begin, proof, terminal)
                .and_then(HeldOutputAckV1::encode)
                .map_err(|_| protected_changed())?;
            if boottime()? >= begin.deadline_boottime_nanoseconds
                || verifier.verify_connection(connection.peer()) != Ok(execution)
                || connection.send(&ack).is_err()
            {
                return Ok(());
            }
            custody.recheck(state_root)?;
            held.revalidate().map_err(|_| protected_changed())?;
            Ok(())
        },
    )?;

    match result {
        Ok(outcome) => outcome,
        Err(ExecutionOutputLedgerErrorV1::NotCurrent) => Ok(()),
        Err(_) => Err(protected_changed()),
    }
}

fn protected_changed() -> StorageServiceError {
    StorageServiceError::Activation("held output writer or row changed".to_owned())
}
