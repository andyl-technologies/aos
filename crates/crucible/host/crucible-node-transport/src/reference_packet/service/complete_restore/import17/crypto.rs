//! Computes separately keyed Native17 proof DATA, never a native restoration token.

use super::*;

impl PacketNativeImport17Proof {
    /// Checks the exact phase grammar and both thirty-two-byte proof fields.
    ///
    /// # Errors
    /// Refuses old or foreign proof domains, construction, width or extent.
    pub fn validate_data(&self, phase: PacketNativeImport17Phase) -> Result<(), ProviderError> {
        if self.schema != phase.proof_extension()
            || self.algorithm != PACKET_COMPLETE_RESTORE_ALGORITHM
        {
            return Err(invalid());
        }
        digest32(&self.context_digest)?;
        digest32(&self.mac)?;
        crate::connection::serialized_credit(self, MAXIMUM_NATIVE_IMPORT17_PROOF_BYTES)?;
        Ok(())
    }
}

/// Computes inert proof DATA under the exact new phase key domain.
///
/// The actual Source issuer must independently consume its complete original
/// cold/factory/Window conjunction and SDK assignment before exposing a request.
/// This helper creates no actor, Source grant, lease, once state or native token.
/// Serializer, canonical and digest-output work remains independently admitted.
///
/// # Errors
/// Refuses invalid or oversized context DATA or a bounded canonical encoding failure.
pub fn native_import17_proof_data(
    key: &[u8; 32],
    context: &PacketNativeImport17Context,
) -> Result<PacketNativeImport17Proof, ProviderError> {
    context.validate_data()?;
    let phase = context.peer.phase_data();
    let bytes = bounded(context, MAXIMUM_NATIVE_IMPORT17_CONTEXT_BYTES)?;
    let derived = blake3::derive_key(phase.proof_domain(), key);
    let result = PacketNativeImport17Proof {
        schema: phase.proof_extension().to_owned(),
        algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.to_owned(),
        context_digest: Bytes::new(blake3::hash(&bytes).as_bytes().to_vec()),
        mac: Bytes::new(blake3::keyed_hash(&derived, &bytes).as_bytes().to_vec()),
    };
    result.validate_data(phase)?;
    Ok(result)
}

/// Verifies complete Native17 phase proof DATA without granting installation.
///
/// Native must independently derive and authenticate every context field before
/// this call, retain all original/failure custody, reserve its exact banks and
/// issue its private same-actor phase token only after the complete conjunction.
///
/// # Errors
/// Refuses another key, context, phase, proof grammar or keyed output.
pub fn verify_native_import17_proof_data(
    key: &[u8; 32],
    context: &PacketNativeImport17Context,
    proof: &PacketNativeImport17Proof,
) -> Result<(), ProviderError> {
    proof.validate_data(context.peer.phase_data())?;
    let expected = native_import17_proof_data(key, context)?;
    same_digest(
        proof.context_digest.as_slice(),
        expected.context_digest.as_slice(),
    )?;
    same_digest(proof.mac.as_slice(), expected.mac.as_slice())
}
