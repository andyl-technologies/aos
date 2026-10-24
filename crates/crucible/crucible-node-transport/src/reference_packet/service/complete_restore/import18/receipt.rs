//! Binds distinct Import18 receipts to literal assigned pairs and phase contexts.
//!
//! Receipt DATA is not an input lease or installation witness. The native issuer
//! must own its original admitted banks and once state before publishing Prepare,
//! and its installed model and held gate before publishing Commit.

use super::*;

/// Borrows the complete Import18 phase context and expected backend schema.
///
/// The expected schema remains an independent input to the full Import18
/// binding check. This view creates no authenticated context, native owner,
/// Prepare lease, Source budget or installation witness.
pub struct PacketNativeImport18ReceiptContextData<'a> {
    /// Borrows the independently selected backend continuation schema.
    pub expected_backend_schema: &'a SchemaRef,
    /// Borrows the full phase context that must match the assigned proof.
    pub context: &'a PacketNativeImport17Context,
}

/// Computes input receipt DATA for the same actual signed Prepare assignment.
///
/// The private native issuer separately authenticates its current birth, exact
/// admitted allocation, retained seven banks and original once-only lease owner.
/// All serialization and returned DATA backing needs independent admission.
///
/// # Errors
/// Refuses changed request, binding, proof, phase, response correlation or extent.
pub fn native_import18_prepare_receipt_data(
    key: &[u8; 32],
    binding: &PacketNativeImport18Binding,
    request: &PacketCompleteRestorePrepareRequest,
    context: &PacketNativeImport18ReceiptContextData<'_>,
    assignment: &PacketNativeImportReceiptAssignmentData<'_>,
) -> Result<PacketNativeImport17PrepareReceipt, ProviderError> {
    let PacketNativeImport18ReceiptContextData {
        expected_backend_schema,
        context,
    } = *context;
    let PacketNativeImportReceiptAssignmentData {
        original,
        response,
        maximum_frame_bytes,
    } = *assignment;

    context.authenticate_import18_prepare_data(
        binding,
        request,
        expected_backend_schema,
        original,
        maximum_frame_bytes,
    )?;
    authenticate_original_proof(key, context, original)?;
    let assigned = native_import18_assigned_response_digest(
        original,
        response,
        PacketNativeImport18Phase::Prepare,
        maximum_frame_bytes,
    )?;
    let bytes = bounded(context, MAXIMUM_NATIVE_IMPORT17_CONTEXT_BYTES)?;
    let mut receipt = PacketNativeImport17PrepareReceipt {
        schema: PacketNativeImport18Phase::Prepare
            .payload_phase_data()
            .receipt_extension()
            .to_owned(),
        algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.to_owned(),
        import_binding_digest: bytes32(binding.digest_data()?),
        context_digest: bytes32(*blake3::hash(&bytes).as_bytes()),
        prepare_digest: bytes32(*digest32(&binding.prepare_digest)?),
        input_roster: native_import18_input_roster_digest_data(request, binding)?,
        transfer_token: keyed(
            "source-owned.packet-native-import-transfer-token-key/17",
            key,
            &bytes,
        ),
        generation: request.generation,
        native_sequence: response.sequence,
        assigned_response: bytes32(assigned),
        mac: Bytes::default(),
    };
    receipt.mac = keyed(
        "source-owned.packet-native-import-prepare-receipt-key/17",
        key,
        &receipt_input(&receipt)?,
    );
    receipt.validate_data()?;
    Ok(receipt)
}

/// Verifies input receipt DATA against the same retained request and response.
///
/// # Errors
/// Refuses changed receipt, key, binding, assignment, request or response fields.
pub fn verify_native_import18_prepare_receipt_data(
    key: &[u8; 32],
    binding: &PacketNativeImport18Binding,
    request: &PacketCompleteRestorePrepareRequest,
    context: &PacketNativeImport18ReceiptContextData<'_>,
    assignment: &PacketNativeImportReceiptAssignmentData<'_>,
    receipt: &PacketNativeImport17PrepareReceipt,
) -> Result<(), ProviderError> {
    receipt.validate_data()?;
    let expected =
        native_import18_prepare_receipt_data(key, binding, request, context, assignment)?;
    compare_receipt(receipt, &expected)
}

/// Computes Commit receipt DATA for the same actual signed Commit assignment.
///
/// The private issuer additionally requires its actual completed successor-family
/// Prepare lease, full validated bodies, model installation and physical Hold.
/// This helper cannot establish or replace any of those live predicates.
///
/// # Errors
/// Refuses changed binding, request, proof, normalization, phase or response.
pub fn native_import18_commit_receipt_data(
    key: &[u8; 32],
    binding: &PacketNativeImport18Binding,
    request: &PacketCompleteRestoreCommitRequest,
    context: &PacketNativeImport18ReceiptContextData<'_>,
    assignment: &PacketNativeImportReceiptAssignmentData<'_>,
    normalization: &[u8],
) -> Result<PacketNativeImport17CommitReceipt, ProviderError> {
    let PacketNativeImport18ReceiptContextData {
        expected_backend_schema,
        context,
    } = *context;
    let PacketNativeImportReceiptAssignmentData {
        original,
        response,
        maximum_frame_bytes,
    } = *assignment;

    context.authenticate_import18_commit_data(
        binding,
        request,
        expected_backend_schema,
        original,
        normalization,
        maximum_frame_bytes,
    )?;
    authenticate_original_proof(key, context, original)?;
    let assigned = native_import18_assigned_response_digest(
        original,
        response,
        PacketNativeImport18Phase::Commit,
        maximum_frame_bytes,
    )?;
    let mut receipt = PacketNativeImport17CommitReceipt {
        schema: PacketNativeImport18Phase::Commit
            .payload_phase_data()
            .receipt_extension()
            .to_owned(),
        algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.to_owned(),
        import_binding_digest: bytes32(binding.digest_data()?),
        context_digest: bytes32(
            *blake3::hash(&bounded(context, MAXIMUM_NATIVE_IMPORT17_CONTEXT_BYTES)?).as_bytes(),
        ),
        commit_digest: bytes32(
            *blake3::hash(&bounded(
                request,
                super::super::transfer::MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES,
            )?)
            .as_bytes(),
        ),
        installed_mapping: binding.normalization.clone(),
        transfer_token: bytes32(*digest32(&request.transfer_token)?),
        native_sequence: response.sequence,
        assigned_response: bytes32(assigned),
        mac: Bytes::default(),
    };
    receipt.mac = keyed(
        "source-owned.packet-native-import-commit-receipt-key/17",
        key,
        &receipt_input(&receipt)?,
    );
    receipt.validate_data()?;
    Ok(receipt)
}

/// Verifies Commit receipt DATA against the same completed phase correspondence.
///
/// # Errors
/// Refuses changed key, binding, phase, mapping, assignment or receipt fields.
pub fn verify_native_import18_commit_receipt_data(
    key: &[u8; 32],
    binding: &PacketNativeImport18Binding,
    request: &PacketCompleteRestoreCommitRequest,
    context: &PacketNativeImport18ReceiptContextData<'_>,
    assignment: &PacketNativeImportReceiptAssignmentData<'_>,
    normalization: &[u8],
    receipt: &PacketNativeImport17CommitReceipt,
) -> Result<(), ProviderError> {
    receipt.validate_data()?;
    let expected = native_import18_commit_receipt_data(
        key,
        binding,
        request,
        context,
        assignment,
        normalization,
    )?;
    compare_receipt(receipt, &expected)
}

fn authenticate_original_proof(
    key: &[u8; 32],
    context: &PacketNativeImport17Context,
    original: &Envelope,
) -> Result<(), ProviderError> {
    let value = original
        .extensions
        .get(match context.peer.phase_data() {
            super::super::import17::PacketNativeImport17Phase::Prepare => {
                PacketNativeImport18Phase::Prepare.proof_extension()
            }
            super::super::import17::PacketNativeImport17Phase::Commit => {
                PacketNativeImport18Phase::Commit.proof_extension()
            }
        })
        .ok_or_else(invalid)?;
    let proof = PacketNativeImport17Proof::deserialize(value).map_err(ContractError::from)?;
    verify_native_import17_proof_data(key, context, &proof)
}

fn receipt_input(receipt: &impl Serialize) -> Result<Vec<u8>, ProviderError> {
    let mut value = serde_json::to_value(receipt).map_err(ContractError::from)?;
    value.as_object_mut().ok_or_else(invalid)?.remove("mac");
    bounded(&value, MAXIMUM_NATIVE_IMPORT17_RECEIPT_BYTES)
}

fn compare_receipt(
    actual: &impl Serialize,
    expected: &impl Serialize,
) -> Result<(), ProviderError> {
    let actual = bounded(actual, MAXIMUM_NATIVE_IMPORT17_RECEIPT_BYTES)?;
    let expected = bounded(expected, MAXIMUM_NATIVE_IMPORT17_RECEIPT_BYTES)?;
    same_digest(
        blake3::hash(&actual).as_bytes(),
        blake3::hash(&expected).as_bytes(),
    )
}

fn keyed(domain: &str, key: &[u8; 32], bytes: &[u8]) -> Bytes {
    let derived = blake3::derive_key(domain, key);
    bytes32(*blake3::keyed_hash(&derived, bytes).as_bytes())
}

fn bytes32(value: [u8; 32]) -> Bytes {
    Bytes::new(value.to_vec())
}

#[cfg(test)]
mod tests;
