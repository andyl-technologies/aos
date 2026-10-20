//! Encodes a versioned canonical ACK admission proof without issuing authority.
//!
//! The source and native verifier independently obtain the complete inputs from
//! their original kernel, Hello, policy, registration and assigned-request
//! owners. This module checks data and cryptographic correspondence only. An
//! opaque native admission marker still requires those original owners.
//!
//! ```text
//! {"schema":"source-owned.packet-canonical-ack-admission/5",
//!  "algorithm":"blake3-keyed-canonical/1","context_digest":"<32 bytes>",
//!  "mac":"<32 bytes>"}
//! ```

use crate::ProviderError;
use crucible_node_format::{Bytes, canonical};
use serde::{Deserialize, Serialize};

/// Names the registered envelope extension and immutable proof specification.
pub const PACKET_CANONICAL_ACK_ADMISSION_FEATURE: &str =
    "source-owned.packet-canonical-ack-admission/5";

/// Names the exact standard key derivation and keyed-hash construction.
pub const PACKET_CANONICAL_ACK_ADMISSION_ALGORITHM: &str = "blake3-keyed-canonical/1";

/// Bounds the validated canonical proof before assigning its original frame.
pub const MAXIMUM_CANONICAL_ACK_ADMISSION_PROOF_BYTES: usize = 256;

/// Bounds the fixed canonical context and its independently charged scratch.
pub const MAXIMUM_CANONICAL_ACK_ADMISSION_CONTEXT_BYTES: usize = 1024;

const KEY_DERIVATION_CONTEXT: &str = "source-owned.packet-canonical-ack-admission-key/5";
const CONTEXT_SCHEMA: &str = "source-owned.packet-canonical-ack-admission-context/5";

/// Contains fixed role-normalized digests of independently owned actual inputs.
///
/// Structured input digests are standard BLAKE3 over the complete canonical
/// closed normalized value. Hello digests use standard BLAKE3 key derivation
/// with context `source-owned.cnp-original-hello-frame/5` and the actual four-byte
/// header followed by its full literal body as key material. Assigned
/// request input uses the exact canonical Admit envelope, including sequence,
/// with only this proof extension removed. Full underlying values and custody
/// remain retained independently; matching this data creates no authority.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketCanonicalAckAdmissionContext {
    /// Names the exact context grammar.
    pub schema: String,
    /// Names the exact key derivation and MAC construction.
    pub algorithm: String,
    /// Binds the original source-issued private birth association.
    pub source_birth: Bytes,
    /// Binds both roles' actual PID, UID and measured executable identities.
    pub kernel_binding: Bytes,
    /// Binds the complete role-normalized immutable selected policy tuple.
    pub policy_binding: Bytes,
    /// Binds the actual host registration and connection identity.
    pub host_registration: Bytes,
    /// Binds the actual native registration and connection identity.
    pub native_registration: Bytes,
    /// Binds the complete literal controller-to-native Hello frame.
    pub hello_request: Bytes,
    /// Binds the complete literal native-to-controller Hello response frame.
    pub hello_response: Bytes,
    /// Binds the exact SDK-assigned original Admit envelope and sequence.
    pub assigned_admit: Bytes,
}

/// Contains a bounded inert proof transported on one assigned original Admit.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketCanonicalAckAdmissionProof {
    /// Names the exact registered proof grammar.
    pub schema: String,
    /// Names the exact key derivation and MAC construction.
    pub algorithm: String,
    /// Identifies the complete canonical context without supplying its authority.
    pub context_digest: Bytes,
    /// Contains the keyed BLAKE3 output, exactly 32 decoded bytes.
    pub mac: Bytes,
}

impl PacketCanonicalAckAdmissionContext {
    /// Checks the fixed context syntax without authenticating its input owners.
    ///
    /// # Errors
    /// Refuses a foreign grammar, algorithm or a digest of any other length.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != CONTEXT_SCHEMA
            || self.algorithm != PACKET_CANONICAL_ACK_ADMISSION_ALGORITHM
            || [
                &self.source_birth,
                &self.kernel_binding,
                &self.policy_binding,
                &self.host_registration,
                &self.native_registration,
                &self.hello_request,
                &self.hello_response,
                &self.assigned_admit,
            ]
            .iter()
            .any(|digest| digest.as_slice().len() != 32)
        {
            return Err(ProviderError::Correlation("canonical ACK context syntax"));
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, ProviderError> {
        self.validate_data()?;
        let value =
            serde_json::to_value(self).map_err(crucible_node_format::ContractError::from)?;
        let bytes = canonical::canonical_json(&value)?;
        if bytes.len() > MAXIMUM_CANONICAL_ACK_ADMISSION_CONTEXT_BYTES {
            return Err(ProviderError::ResourceExhausted(
                "canonical ACK context extent",
            ));
        }
        Ok(bytes)
    }
}

impl PacketCanonicalAckAdmissionProof {
    /// Checks the exact bounded proof grammar without authenticating a peer.
    ///
    /// # Errors
    /// Refuses a foreign grammar or algorithm, or a non-32-byte digest or MAC.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != PACKET_CANONICAL_ACK_ADMISSION_FEATURE
            || self.algorithm != PACKET_CANONICAL_ACK_ADMISSION_ALGORITHM
            || self.context_digest.as_slice().len() != 32
            || self.mac.as_slice().len() != 32
        {
            return Err(ProviderError::Correlation("canonical ACK proof syntax"));
        }
        Ok(())
    }
}

/// Computes inert proof data from an already authenticated source's private key.
///
/// This helper has no key issuer, source association or native marker constructor.
/// The source retains its assigned original before calling it. Its canonical
/// context buffers, JSON value and fixed byte encodings are bounded scratch that
/// must be included in the selected source demand.
///
/// # Errors
/// Refuses invalid context syntax or canonical serialization failure.
pub fn canonical_ack_admission_proof_data(
    private_birth_key: &[u8; 32],
    context: &PacketCanonicalAckAdmissionContext,
) -> Result<PacketCanonicalAckAdmissionProof, ProviderError> {
    let bytes = context.canonical_bytes()?;
    let key = blake3::derive_key(KEY_DERIVATION_CONTEXT, private_birth_key);
    let mac = blake3::keyed_hash(&key, &bytes);

    Ok(PacketCanonicalAckAdmissionProof {
        schema: PACKET_CANONICAL_ACK_ADMISSION_FEATURE.to_owned(),
        algorithm: PACKET_CANONICAL_ACK_ADMISSION_ALGORITHM.to_owned(),
        context_digest: Bytes::new(blake3::hash(&bytes).as_bytes().to_vec()),
        mac: Bytes::new(mac.as_bytes().to_vec()),
    })
}

/// Verifies exact context correspondence using constant-time BLAKE3 hash equality.
///
/// Success proves only cryptographic data correspondence. The caller must still
/// authenticate the same actual native key, assigned request, registration,
/// Hello and policy and consume its private admission issuer exactly once.
///
/// # Errors
/// Refuses invalid data, a changed context, another birth key or a wrong MAC.
pub fn verify_canonical_ack_admission_proof_data(
    private_birth_key: &[u8; 32],
    context: &PacketCanonicalAckAdmissionContext,
    proof: &PacketCanonicalAckAdmissionProof,
) -> Result<(), ProviderError> {
    proof.validate_data()?;
    let bytes = context.canonical_bytes()?;
    let key = blake3::derive_key(KEY_DERIVATION_CONTEXT, private_birth_key);
    let expected_context = blake3::hash(&bytes);
    let expected_mac = blake3::keyed_hash(&key, &bytes);
    if expected_context != *proof.context_digest.as_slice() || expected_mac != *proof.mac.as_slice()
    {
        return Err(ProviderError::Correlation(
            "canonical ACK proof correspondence",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> PacketCanonicalAckAdmissionContext {
        PacketCanonicalAckAdmissionContext {
            schema: CONTEXT_SCHEMA.to_owned(),
            algorithm: PACKET_CANONICAL_ACK_ADMISSION_ALGORITHM.to_owned(),
            source_birth: Bytes::new(vec![1; 32]),
            kernel_binding: Bytes::new(vec![2; 32]),
            policy_binding: Bytes::new(vec![3; 32]),
            host_registration: Bytes::new(vec![4; 32]),
            native_registration: Bytes::new(vec![5; 32]),
            hello_request: Bytes::new(vec![6; 32]),
            hello_response: Bytes::new(vec![7; 32]),
            assigned_admit: Bytes::new(vec![8; 32]),
        }
    }

    #[test]
    fn canonical_ack_proof_refuses_another_birth_and_assigned_original() -> Result<(), ProviderError>
    {
        let mut original = context();
        let proof = canonical_ack_admission_proof_data(&[11; 32], &original)?;
        verify_canonical_ack_admission_proof_data(&[11; 32], &original, &proof)?;

        assert!(verify_canonical_ack_admission_proof_data(&[12; 32], &original, &proof).is_err());
        original.assigned_admit = Bytes::new(vec![9; 32]);
        assert!(verify_canonical_ack_admission_proof_data(&[11; 32], &original, &proof).is_err());
        Ok(())
    }

    #[test]
    fn canonical_ack_proof_has_closed_bounded_wire_syntax() -> Result<(), ProviderError> {
        let original = context();
        let mut proof = canonical_ack_admission_proof_data(&[11; 32], &original)?;
        let value =
            serde_json::to_value(&proof).map_err(crucible_node_format::ContractError::from)?;
        let bytes = canonical::canonical_json(&value)?;
        assert_eq!(bytes.len(), 212);
        assert!(bytes.len() <= MAXIMUM_CANONICAL_ACK_ADMISSION_PROOF_BYTES);

        let mut foreign = value;
        foreign["authority"] = serde_json::json!(true);
        assert!(serde_json::from_value::<PacketCanonicalAckAdmissionProof>(foreign).is_err());
        proof.mac = Bytes::new(vec![0; 31]);
        assert!(proof.validate_data().is_err());
        assert!(verify_canonical_ack_admission_proof_data(&[11; 32], &original, &proof).is_err());
        Ok(())
    }
}
