//! Authenticates bounded fresh report data without constructing native authority.

use super::*;
use crucible_node_format::canonical;

/// Separates complete original envelope commitments by their protocol role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketNativeFreshRestoreOriginalRole {
    /// Commits the actual selected startup request.
    Query,
    /// Commits the completed original assigned Admit request.
    AdmitRequest,
    /// Commits the successful response to that original Admit.
    AdmitResponse,
    /// Commits the completed startup response, including its report reference.
    QueryResponse,
}

impl PacketNativeFreshRestoreOriginalRole {
    fn domain(self) -> &'static str {
        match self {
            Self::Query => "source-owned.packet-fresh-restore-query-original/13",
            Self::AdmitRequest => "source-owned.packet-fresh-restore-admit-original/13",
            Self::AdmitResponse => "source-owned.packet-fresh-restore-admit-response/13",
            Self::QueryResponse => "source-owned.packet-fresh-restore-query-response/13",
        }
    }

    pub(crate) fn verified_canonical_body_digest(self, bytes: &[u8]) -> [u8; 32] {
        blake3::derive_key(self.domain(), bytes)
    }
}

/// Commits one complete canonical original envelope in its separate role domain.
///
/// All proof and selected extension fields remain in the input. Callers must
/// authenticate typed/raw correspondence and charge the capped DOM/canonical
/// work before calling. Source retains the result before readonly preflight.
/// The numeric bound grants no right to receive or allocate a frame.
///
/// # Errors
/// Refuses malformed envelope data, an incompatible method/message role, zero
/// extent or serialization beyond the separately admitted original frame bound.
pub fn fresh_restore_allocation_envelope_digest_data(
    original: &crate::envelope::Envelope,
    role: PacketNativeFreshRestoreOriginalRole,
    maximum_encoded_bytes: usize,
) -> Result<[u8; 32], ProviderError> {
    use crate::envelope::{MessageKind, Method};

    let expected = match role {
        PacketNativeFreshRestoreOriginalRole::Query => (MessageKind::Request, Method::Observe),
        PacketNativeFreshRestoreOriginalRole::AdmitRequest => (MessageKind::Request, Method::Admit),
        PacketNativeFreshRestoreOriginalRole::AdmitResponse => {
            (MessageKind::Response, Method::Admit)
        }
        PacketNativeFreshRestoreOriginalRole::QueryResponse => {
            (MessageKind::Response, Method::Observe)
        }
    };
    original.validate()?;
    if maximum_encoded_bytes == 0 || (original.message, original.method) != expected {
        return Err(invalid());
    }
    crate::connection::serialized_credit(original, maximum_encoded_bytes)?;
    let value =
        serde_json::to_value(original).map_err(crucible_node_format::ContractError::from)?;
    let bytes = bounded_canonical(&value, maximum_encoded_bytes)?;
    Ok(role.verified_canonical_body_digest(&bytes))
}

/// Derives inert nonce data from the same original fresh-birth key.
///
/// The caller must authenticate the actual key owner and retain the one-shot
/// query association. Repeating this calculation does not renew that occurrence.
pub fn fresh_restore_allocation_nonce_data(key: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("source-owned.packet-fresh-restore-allocation-nonce/13", key)
}

/// Computes separate keyed proof data over the complete canonical report data.
///
/// The native producer independently proves fresh origin and requested storage.
/// The caller must charge the bounded DOM/canonical/proof banks before calling.
/// This function cannot issue an allocation or a restoration token.
///
/// # Errors
/// Refuses malformed scope/storage, overflow or an oversized canonical input.
pub fn fresh_restore_allocation_proof_data(
    key: &[u8; 32],
    data: &PacketNativeFreshRestoreAllocationData,
) -> Result<PacketNativeFreshRestoreAllocationProof, ProviderError> {
    data.validate_data()?;
    if data.scope.nonce.as_slice() != fresh_restore_allocation_nonce_data(key) {
        return Err(invalid());
    }
    crate::connection::serialized_credit(data, MAXIMUM_FRESH_RESTORE_ALLOCATION_REPORT_BYTES)?;
    let value = serde_json::to_value(data).map_err(crucible_node_format::ContractError::from)?;
    // The raw count above precedes the DOM. Canonicalization has an independent
    // bounded writer, so a different escaping extent cannot grow the output.
    let bytes = bounded_canonical(&value, MAXIMUM_FRESH_RESTORE_ALLOCATION_REPORT_BYTES)?;
    let derived = blake3::derive_key("source-owned.packet-fresh-restore-allocation-key/13", key);
    Ok(PacketNativeFreshRestoreAllocationProof {
        schema: PACKET_FRESH_RESTORE_ALLOCATION_PROOF.to_owned(),
        algorithm: FRESH_RESTORE_ALLOCATION_ALGORITHM.to_owned(),
        context_digest: Bytes::new(blake3::hash(&bytes).as_bytes().to_vec()),
        mac: Bytes::new(blake3::keyed_hash(&derived, &bytes).as_bytes().to_vec()),
    })
}

/// Verifies complete report data against the same original fresh-birth key.
///
/// Source invokes this while retaining the completed query, before readonly
/// whole preflight. A valid MAC does not authenticate currentness or grant space.
///
/// # Errors
/// Refuses another key, changed data, malformed proof or bounded encoding failure.
pub fn verify_fresh_restore_allocation_proof_data(
    key: &[u8; 32],
    data: &PacketNativeFreshRestoreAllocationData,
    proof: &PacketNativeFreshRestoreAllocationProof,
) -> Result<(), ProviderError> {
    proof.validate_data()?;
    let expected = fresh_restore_allocation_proof_data(key, data)?;
    for (actual, expected) in [
        (&proof.context_digest, &expected.context_digest),
        (&proof.mac, &expected.mac),
    ] {
        let actual: [u8; 32] = actual.as_slice().try_into().map_err(|_| invalid())?;
        let expected: [u8; 32] = expected.as_slice().try_into().map_err(|_| invalid())?;
        if blake3::Hash::from(actual) != blake3::Hash::from(expected) {
            return Err(invalid());
        }
    }
    Ok(())
}

fn bounded_canonical(value: &serde_json::Value, maximum: usize) -> Result<Vec<u8>, ProviderError> {
    struct Writer {
        bytes: Vec<u8>,
        maximum: usize,
    }

    impl std::io::Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let next = self
                .bytes
                .len()
                .checked_add(bytes.len())
                .filter(|next| *next <= self.maximum)
                .ok_or_else(|| std::io::Error::other("fresh report canonical extent"))?;
            self.bytes.extend_from_slice(bytes);
            if self.bytes.len() != next {
                return Err(std::io::Error::other("fresh report canonical write"));
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut writer = Writer {
        bytes: Vec::new(),
        maximum,
    };
    writer
        .bytes
        .try_reserve_exact(writer.maximum)
        .map_err(|_| ProviderError::ResourceExhausted("fresh report canonical bank reservation"))?;
    canonical::canonical_json_to_writer(value, &mut writer)?;
    Ok(writer.bytes)
}
