//! Binds distinct Native17 receipts to literal assigned pairs and phase contexts.
//!
//! Receipt DATA is not an input lease or installation witness. The native issuer
//! must own its original admitted banks and once state before publishing Prepare,
//! and its installed model and held gate before publishing Commit.

use super::*;

/// Borrows an assigned request/response pair and its negotiated wire extent.
///
/// These are input data for receipt correspondence, not a native lease,
/// completed phase, Source permission or authenticated response. Receipt helpers
/// independently validate the complete pair against their phase and context.
pub struct PacketNativeImportReceiptAssignmentData<'a> {
    /// Borrows the exact original request, including its assigned proof.
    pub original: &'a Envelope,
    /// Borrows the correlated original response, including its receipt extension.
    pub response: &'a Envelope,
    /// Bounds the complete assigned frames under the same negotiated connection.
    pub maximum_frame_bytes: usize,
}

/// Retains the complete new-family input receipt without certifying installation.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeImport17PrepareReceipt {
    /// Selects the distinct Prepare receipt extension.
    pub schema: String,
    /// Names the canonical keyed construction.
    pub algorithm: String,
    /// Hashes every additional import binding field.
    pub import_binding_digest: Bytes,
    /// Hashes the complete new-family independently derived context.
    pub context_digest: Bytes,
    /// Hashes the complete inert Prepare payload, including allocation.
    pub prepare_digest: Bytes,
    /// Binds the original six input banks and their exact allocation roster.
    pub input_roster: Bytes,
    /// Retains the new-family lease digest, never an older transfer token.
    pub transfer_token: Bytes,
    /// Retains the original positive source-born lease generation.
    pub generation: U64,
    /// Retains the actual correlated native response sequence.
    pub native_sequence: U64,
    /// Hashes that full response after removing only this receipt.
    pub assigned_response: Bytes,
    /// Authenticates all preceding fields under the new Prepare receipt domain.
    pub mac: Bytes,
}

/// Retains the same-lease Commit receipt without certifying World publication.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeImport17CommitReceipt {
    /// Selects the distinct Commit receipt extension.
    pub schema: String,
    /// Names the canonical keyed construction.
    pub algorithm: String,
    /// Hashes every additional import binding field.
    pub import_binding_digest: Bytes,
    /// Hashes the complete new-family independently derived context.
    pub context_digest: Bytes,
    /// Hashes the complete same-lease inert Commit payload.
    pub commit_digest: Bytes,
    /// Names the exact normalization bank consumed by this installation.
    pub installed_mapping: ContentRef,
    /// Retains the same actual new-family Prepare token.
    pub transfer_token: Bytes,
    /// Retains the actual correlated native response sequence.
    pub native_sequence: U64,
    /// Hashes that full response after removing only this receipt.
    pub assigned_response: Bytes,
    /// Authenticates all preceding fields under the new Commit receipt domain.
    pub mac: Bytes,
}

impl PacketNativeImport17PrepareReceipt {
    /// Checks the exact phase, finite sequence and all fixed-width fields.
    ///
    /// # Errors
    /// Refuses another family, zero generation/sequence or malformed digest/extent.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        validate_common(
            &self.schema,
            &self.algorithm,
            PacketNativeImport17Phase::Prepare,
            self.native_sequence,
            &[
                &self.import_binding_digest,
                &self.context_digest,
                &self.prepare_digest,
                &self.input_roster,
                &self.transfer_token,
                &self.assigned_response,
                &self.mac,
            ],
        )?;
        if self.generation.get() == 0 {
            return Err(invalid());
        }
        crate::connection::serialized_credit(self, MAXIMUM_NATIVE_IMPORT17_RECEIPT_BYTES)?;
        Ok(())
    }
}

impl PacketNativeImport17CommitReceipt {
    /// Checks the exact phase, full mapping reference and all fixed-width fields.
    ///
    /// # Errors
    /// Refuses another family, zero sequence or malformed mapping/digest/extent.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        validate_common(
            &self.schema,
            &self.algorithm,
            PacketNativeImport17Phase::Commit,
            self.native_sequence,
            &[
                &self.import_binding_digest,
                &self.context_digest,
                &self.commit_digest,
                &self.transfer_token,
                &self.assigned_response,
                &self.mac,
            ],
        )?;
        self.installed_mapping.validate()?;
        crate::connection::serialized_credit(self, MAXIMUM_NATIVE_IMPORT17_RECEIPT_BYTES)?;
        Ok(())
    }
}

/// Computes input receipt DATA for the same actual signed Prepare assignment.
///
/// The private native issuer separately authenticates its current birth, exact
/// admitted allocation, retained six banks and original once-only lease owner.
/// All serialization and returned DATA backing needs independent admission.
///
/// # Errors
/// Refuses changed request, binding, proof, phase, response correlation or extent.
pub fn native_import17_prepare_receipt_data(
    key: &[u8; 32],
    binding: &PacketNativeImport17Binding,
    request: &PacketCompleteRestorePrepareRequest,
    context: &PacketNativeImport17Context,
    assignment: &PacketNativeImportReceiptAssignmentData<'_>,
) -> Result<PacketNativeImport17PrepareReceipt, ProviderError> {
    let PacketNativeImportReceiptAssignmentData {
        original,
        response,
        maximum_frame_bytes,
    } = *assignment;

    context.authenticate_prepare_data(binding, request, original, maximum_frame_bytes)?;
    authenticate_original_proof(key, context, original)?;
    let assigned = native_import17_assigned_response_digest(
        original,
        response,
        PacketNativeImport17Phase::Prepare,
        maximum_frame_bytes,
    )?;
    let bytes = bounded(context, MAXIMUM_NATIVE_IMPORT17_CONTEXT_BYTES)?;
    let mut receipt = PacketNativeImport17PrepareReceipt {
        schema: PacketNativeImport17Phase::Prepare
            .receipt_extension()
            .to_owned(),
        algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.to_owned(),
        import_binding_digest: bytes32(binding.digest_data()?),
        context_digest: bytes32(*blake3::hash(&bytes).as_bytes()),
        prepare_digest: bytes32(*digest32(&binding.prepare_digest)?),
        input_roster: request.input_roster_digest_data()?,
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
pub fn verify_native_import17_prepare_receipt_data(
    key: &[u8; 32],
    binding: &PacketNativeImport17Binding,
    request: &PacketCompleteRestorePrepareRequest,
    context: &PacketNativeImport17Context,
    assignment: &PacketNativeImportReceiptAssignmentData<'_>,
    receipt: &PacketNativeImport17PrepareReceipt,
) -> Result<(), ProviderError> {
    receipt.validate_data()?;
    let expected =
        native_import17_prepare_receipt_data(key, binding, request, context, assignment)?;
    compare_receipt(receipt, &expected)
}

/// Computes Commit receipt DATA for the same actual signed Commit assignment.
///
/// The private issuer additionally requires its actual completed new-family
/// Prepare lease, full validated bodies, model installation and physical Hold.
/// This helper cannot establish or replace any of those live predicates.
///
/// # Errors
/// Refuses changed binding, request, proof, normalization, phase or response.
pub fn native_import17_commit_receipt_data(
    key: &[u8; 32],
    binding: &PacketNativeImport17Binding,
    request: &PacketCompleteRestoreCommitRequest,
    context: &PacketNativeImport17Context,
    assignment: &PacketNativeImportReceiptAssignmentData<'_>,
    normalization: &[u8],
) -> Result<PacketNativeImport17CommitReceipt, ProviderError> {
    let PacketNativeImportReceiptAssignmentData {
        original,
        response,
        maximum_frame_bytes,
    } = *assignment;

    context.authenticate_commit_data(
        binding,
        request,
        original,
        normalization,
        maximum_frame_bytes,
    )?;
    authenticate_original_proof(key, context, original)?;
    let assigned = native_import17_assigned_response_digest(
        original,
        response,
        PacketNativeImport17Phase::Commit,
        maximum_frame_bytes,
    )?;
    let mut receipt = PacketNativeImport17CommitReceipt {
        schema: PacketNativeImport17Phase::Commit
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
pub fn verify_native_import17_commit_receipt_data(
    key: &[u8; 32],
    binding: &PacketNativeImport17Binding,
    request: &PacketCompleteRestoreCommitRequest,
    context: &PacketNativeImport17Context,
    assignment: &PacketNativeImportReceiptAssignmentData<'_>,
    normalization: &[u8],
    receipt: &PacketNativeImport17CommitReceipt,
) -> Result<(), ProviderError> {
    receipt.validate_data()?;
    let expected = native_import17_commit_receipt_data(
        key,
        binding,
        request,
        context,
        assignment,
        normalization,
    )?;
    compare_receipt(receipt, &expected)
}

fn validate_common(
    schema: &str,
    algorithm: &str,
    phase: PacketNativeImport17Phase,
    native_sequence: U64,
    digests: &[&Bytes],
) -> Result<(), ProviderError> {
    if schema != phase.receipt_extension()
        || algorithm != PACKET_COMPLETE_RESTORE_ALGORITHM
        || native_sequence.get() == 0
    {
        return Err(invalid());
    }
    for value in digests {
        digest32(value)?;
    }
    Ok(())
}

fn authenticate_original_proof(
    key: &[u8; 32],
    context: &PacketNativeImport17Context,
    original: &Envelope,
) -> Result<(), ProviderError> {
    let value = original
        .extensions
        .get(context.peer.phase_data().proof_extension())
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
