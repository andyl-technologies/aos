//! Authenticates stage17 context/proof/receipt DATA under separate phase domains.
//!
//! These helpers require independently admitted construction. Matching MACs
//! never create a native stage, current assignment or physical release witness.

use super::*;
use crucible_node_format::Bytes;
use serde::{Deserialize, Serialize};

/// Retains the three independently derived digests for one assigned stage.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeImport17StageContext {
    /// Selects exactly the unchanged stage-context17 grammar.
    pub schema: String,
    /// Names the keyed canonical construction.
    pub algorithm: String,
    /// Selects the independently spent stage and its distinct key domain.
    pub phase: PacketNativeImport17Stage,
    /// Hashes the complete actual admitted bootstrap ACK context.
    pub birth_context_digest: Bytes,
    /// Hashes every field of the complete stage binding.
    pub stage_binding_digest: Bytes,
    /// Hashes the actual assigned Envelope with only its own proof removed.
    pub assigned_original_digest: Bytes,
}

/// Carries one phase-specific stage proof without granting native authority.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeImport17StageProof {
    /// Names the exact phase-specific proof extension.
    pub schema: String,
    /// Names the keyed canonical construction.
    pub algorithm: String,
    /// Hashes the complete independent stage context.
    pub context_digest: Bytes,
    /// Contains the distinct-domain keyed output.
    pub mac: Bytes,
}

/// Carries an assigned terminal and physical report without certifying its truth.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeImport17StageReceipt {
    /// Names the exact phase-specific receipt extension.
    pub schema: String,
    /// Names the keyed canonical construction.
    pub algorithm: String,
    /// Selects the independent stage receipt domain.
    pub phase: PacketNativeImport17Stage,
    /// Hashes the complete independently authenticated stage context.
    pub context_digest: Bytes,
    /// Hashes the assigned response with only its own receipt removed.
    pub assigned_response: Bytes,
    /// Reports true for Arm and false for World/FirstObserve.
    pub physical_gate_held: bool,
    /// Authenticates every preceding field under the phase receipt domain.
    pub mac: Bytes,
}

impl PacketNativeImport17StageContext {
    /// Checks the closed context and exact digest widths without issuing a grant.
    ///
    /// # Errors
    /// Refuses another grammar/algorithm, malformed digests or encoded overflow.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != "source-owned.packet-native-import-stage-context/17"
            || self.algorithm != PACKET_COMPLETE_RESTORE_ALGORITHM
        {
            return Err(invalid());
        }
        for digest in [
            &self.birth_context_digest,
            &self.stage_binding_digest,
            &self.assigned_original_digest,
        ] {
            digest32(digest)?;
        }
        crate::connection::serialized_credit(self, MAXIMUM_NATIVE_IMPORT17_STAGE_CONTEXT_BYTES)?;
        Ok(())
    }

    /// Joins complete stage DATA to the same actual stage18 wire assignment.
    ///
    /// The caller independently supplies its actual admitted birth context and
    /// validates current Source/native/SDK owners and full18 selection. This
    /// comparison alone cannot authenticate the provenance of supplied DATA.
    ///
    /// # Errors
    /// Refuses changed stage, binding, birth, baseline body, target or assignment.
    pub fn authenticate_stage18_data(
        &self,
        binding: &PacketNativeImport17StageBinding,
        birth_context_digest: &[u8; 32],
        original: &crate::envelope::Envelope,
        maximum_frame_bytes: usize,
    ) -> Result<(), ProviderError> {
        self.validate_data()?;
        binding.validate_data()?;
        if self.phase != binding.phase {
            return Err(invalid());
        }
        same_digest(self.birth_context_digest.as_slice(), birth_context_digest)?;
        same_digest(
            self.stage_binding_digest.as_slice(),
            &binding.digest_data()?,
        )?;
        let expected = bounded(binding, MAXIMUM_NATIVE_IMPORT17_STAGE_BINDING_BYTES)?;
        let carried = original
            .extensions
            .get(NATIVE_IMPORT17_STAGE_EXTENSION)
            .ok_or_else(invalid)?;
        if expected != bounded(carried, MAXIMUM_NATIVE_IMPORT17_STAGE_BINDING_BYTES)? {
            return Err(invalid());
        }
        assigned::authenticate_target_data(original, &binding.target, self.phase)?;
        same_digest(
            self.assigned_original_digest.as_slice(),
            &native_import18_stage_assigned_request_digest(
                original,
                self.phase,
                maximum_frame_bytes,
            )?,
        )
    }
}

impl PacketNativeImport17StageProof {
    /// Checks this proof's exact phase schema and digest widths.
    ///
    /// # Errors
    /// Refuses another phase/algorithm, malformed digests or encoded overflow.
    pub fn validate_data(&self, phase: PacketNativeImport17Stage) -> Result<(), ProviderError> {
        if self.schema != phase.proof_extension()
            || self.algorithm != PACKET_COMPLETE_RESTORE_ALGORITHM
        {
            return Err(invalid());
        }
        digest32(&self.context_digest)?;
        digest32(&self.mac)?;
        crate::connection::serialized_credit(self, MAXIMUM_NATIVE_IMPORT17_STAGE_PROOF_BYTES)?;
        Ok(())
    }
}

impl PacketNativeImport17StageReceipt {
    /// Checks this receipt's exact phase, digest widths and physical report.
    ///
    /// # Errors
    /// Refuses another phase/algorithm, a phase-inconsistent report, malformed
    /// digests or encoded overflow. A valid report still needs physical custody.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != self.phase.receipt_extension()
            || self.algorithm != PACKET_COMPLETE_RESTORE_ALGORITHM
            || self.physical_gate_held != (self.phase == PacketNativeImport17Stage::Arm)
        {
            return Err(invalid());
        }
        digest32(&self.context_digest)?;
        digest32(&self.assigned_response)?;
        digest32(&self.mac)?;
        crate::connection::serialized_credit(self, MAXIMUM_NATIVE_IMPORT17_STAGE_RECEIPT_BYTES)?;
        Ok(())
    }
}

/// Computes distinct proof DATA from a separately authenticated stage context.
///
/// The caller independently funds canonicalization and returned owned bytes,
/// retains its actual SDK assignment and consumes the genuine Source once owner.
///
/// # Errors
/// Refuses invalid context DATA or bounded canonical construction failure.
pub fn native_import17_stage_proof_data(
    key: &[u8; 32],
    context: &PacketNativeImport17StageContext,
) -> Result<PacketNativeImport17StageProof, ProviderError> {
    let bytes = context_bytes(context)?;
    let derived = blake3::derive_key(context.phase.proof_domain(), key);
    Ok(PacketNativeImport17StageProof {
        schema: context.phase.proof_extension().into(),
        algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.into(),
        context_digest: Bytes::new(blake3::hash(&bytes).as_bytes().to_vec()),
        mac: Bytes::new(blake3::keyed_hash(&derived, &bytes).as_bytes().to_vec()),
    })
}

/// Verifies phase-specific proof DATA without issuing a native phase token.
///
/// # Errors
/// Refuses another context, phase, key, schema, digest or MAC.
pub fn verify_native_import17_stage_proof_data(
    key: &[u8; 32],
    context: &PacketNativeImport17StageContext,
    proof: &PacketNativeImport17StageProof,
) -> Result<(), ProviderError> {
    proof.validate_data(context.phase)?;
    let bytes = context_bytes(context)?;
    let derived = blake3::derive_key(context.phase.proof_domain(), key);
    if blake3::hash(&bytes) != *proof.context_digest.as_slice()
        || blake3::keyed_hash(&derived, &bytes) != *proof.mac.as_slice()
    {
        return Err(invalid());
    }
    Ok(())
}

/// Computes an assigned-response receipt after independently proven phase effects.
///
/// The actual native issuer separately proves physical Hold/release, current
/// once ownership, completed predecessors and original SDK publication custody.
/// This helper derives the required report from the phase and creates DATA only.
///
/// # Errors
/// Refuses invalid context DATA or bounded canonical construction failure.
pub fn native_import17_stage_receipt_data(
    key: &[u8; 32],
    context: &PacketNativeImport17StageContext,
    assigned_response: &[u8; 32],
) -> Result<PacketNativeImport17StageReceipt, ProviderError> {
    let bytes = context_bytes(context)?;
    let mut receipt = PacketNativeImport17StageReceipt {
        schema: context.phase.receipt_extension().into(),
        algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.into(),
        phase: context.phase,
        context_digest: Bytes::new(blake3::hash(&bytes).as_bytes().to_vec()),
        assigned_response: Bytes::new(assigned_response.to_vec()),
        physical_gate_held: context.phase == PacketNativeImport17Stage::Arm,
        mac: Bytes::default(),
    };
    let input = receipt_input(&receipt)?;
    let derived = blake3::derive_key(context.phase.receipt_domain(), key);
    receipt.mac = Bytes::new(blake3::keyed_hash(&derived, &input).as_bytes().to_vec());
    receipt.validate_data()?;
    Ok(receipt)
}

/// Verifies the complete distinct receipt and its actual assigned-response digest.
///
/// # Errors
/// Refuses another stage, key, context, assigned response, report or MAC.
pub fn verify_native_import17_stage_receipt_data(
    key: &[u8; 32],
    context: &PacketNativeImport17StageContext,
    assigned_response: &[u8; 32],
    receipt: &PacketNativeImport17StageReceipt,
) -> Result<(), ProviderError> {
    receipt.validate_data()?;
    if context.phase != receipt.phase {
        return Err(invalid());
    }
    let bytes = context_bytes(context)?;
    if blake3::hash(&bytes) != *receipt.context_digest.as_slice() {
        return Err(invalid());
    }
    same_digest(assigned_response, receipt.assigned_response.as_slice())?;
    let input = receipt_input(receipt)?;
    let derived = blake3::derive_key(context.phase.receipt_domain(), key);
    if blake3::keyed_hash(&derived, &input) != *receipt.mac.as_slice() {
        return Err(invalid());
    }
    Ok(())
}

fn context_bytes(context: &PacketNativeImport17StageContext) -> Result<Vec<u8>, ProviderError> {
    context.validate_data()?;
    bounded(context, MAXIMUM_NATIVE_IMPORT17_STAGE_CONTEXT_BYTES)
}

fn receipt_input(receipt: &PacketNativeImport17StageReceipt) -> Result<Vec<u8>, ProviderError> {
    #[derive(Serialize)]
    struct Input<'a> {
        schema: &'a str,
        algorithm: &'a str,
        phase: PacketNativeImport17Stage,
        context_digest: &'a Bytes,
        assigned_response: &'a Bytes,
        physical_gate_held: bool,
    }
    bounded(
        &Input {
            schema: &receipt.schema,
            algorithm: &receipt.algorithm,
            phase: receipt.phase,
            context_digest: &receipt.context_digest,
            assigned_response: &receipt.assigned_response,
            physical_gate_held: receipt.physical_gate_held,
        },
        MAXIMUM_NATIVE_IMPORT17_STAGE_RECEIPT_BYTES,
    )
}
