//! Admission interlock for retained Controller execution Observe identities.
//!
//! The Controller execution owner writes `AOSCOB01` under the execution ID:
//!
//! ```text
//! AOSCOB01 || execution:16 || Create-operation:16 || Observe-operation:16
//!          || spec-digest:32 || source-operation-commitment:32
//!          || authorization-receipt:40 || record-digest:32
//! ```
//!
//! The reconciler does not own that reservation or gain dispatch authority
//! from it. It checks the complete protected binding before assigning a new
//! generic Operation ID, so a later admission cannot consume the reserved ID.

use aos_sandbox_core::OperationId;
use sha2::{Digest as _, Sha256};

use crate::journal::{Journal, RecordNamespace};

use super::ReconcilerError;

const MAGIC: &[u8; 8] = b"AOSCOB01";
const RECEIPT_MAGIC: &[u8; 8] = b"AOSEXE01";
const RECORD_BYTES: usize = 192;
const OPERATION_DOMAIN: &[u8] = b"aos.sandbox.controller.execution-observe-operation.v1\0";
const RECORD_DOMAIN: &[u8] = b"aos.sandbox.controller.execution-observe-reservation.v1\0";
const CORRUPT: &str = "invalid Controller execution Observe reservation";

pub(super) fn claims_operation(
    journal: &Journal,
    operation: OperationId,
) -> Result<bool, ReconcilerError> {
    for (key, value) in journal.records(RecordNamespace::ControllerExecutionObserveReservation) {
        let reserved = decode_operation(key, value)?;
        if reserved == operation {
            return Ok(true);
        }
    }
    Ok(false)
}

fn decode_operation(key: &[u8], value: &[u8]) -> Result<OperationId, ReconcilerError> {
    if key.len() != 16
        || value.len() != RECORD_BYTES
        || &value[..8] != MAGIC
        || key != &value[8..24]
        || value[8..24] == [0; 16]
        || value[24..40] == [0; 16]
        || value[40..56] == [0; 16]
        || value[40..56] == value[24..40]
        || value[56..88] == [0; 32]
        || value[88..120] == [0; 32]
        || &value[120..128] != RECEIPT_MAGIC
        || value[128..160] == [0; 32]
    {
        return Err(ReconcilerError::CorruptLedger(CORRUPT));
    }

    let expected_record: [u8; 32] = Sha256::new()
        .chain_update(RECORD_DOMAIN)
        .chain_update(&value[..160])
        .finalize()
        .into();
    let expected_operation: [u8; 32] = Sha256::new()
        .chain_update(OPERATION_DOMAIN)
        .chain_update(&value[24..40])
        .chain_update(&value[8..24])
        .chain_update(&value[56..88])
        .chain_update(&value[88..120])
        .chain_update(&value[120..160])
        .finalize()
        .into();
    if value[160..] != expected_record || value[40..56] != expected_operation[..16] {
        return Err(ReconcilerError::CorruptLedger(CORRUPT));
    }

    let operation = value[40..56]
        .try_into()
        .map_err(|_| ReconcilerError::CorruptLedger(CORRUPT))?;
    Ok(OperationId::from_bytes(operation))
}

#[cfg(test)]
pub(super) fn fixture(execution: [u8; 16], create: [u8; 16]) -> (OperationId, Vec<u8>) {
    let specification_digest = [3; 32];
    let source_commitment = [4; 32];
    let mut receipt = [5; 40];
    receipt[..8].copy_from_slice(RECEIPT_MAGIC);
    let digest: [u8; 32] = Sha256::new()
        .chain_update(OPERATION_DOMAIN)
        .chain_update(create)
        .chain_update(execution)
        .chain_update(specification_digest)
        .chain_update(source_commitment)
        .chain_update(receipt)
        .finalize()
        .into();
    let operation = OperationId::from_bytes(digest[..16].try_into().unwrap());

    let mut bytes = Vec::with_capacity(RECORD_BYTES);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&execution);
    bytes.extend_from_slice(&create);
    bytes.extend_from_slice(operation.as_bytes());
    bytes.extend_from_slice(&specification_digest);
    bytes.extend_from_slice(&source_commitment);
    bytes.extend_from_slice(&receipt);
    bytes.extend_from_slice(
        &Sha256::new()
            .chain_update(RECORD_DOMAIN)
            .chain_update(&bytes)
            .finalize(),
    );
    (operation, bytes)
}
