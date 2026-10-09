//! Descriptor-free Provider-to-Storage LocalLive request exchange.
//!
//! The request transports an already signed plan, a connection-local sequence,
//! and a fresh nonce. The only response defined here is `Unavailable`; it
//! cannot carry a lease, descriptor, or authorization. Storage must still pin
//! both plan signers and independently verify current protected state.
//!
//! ```text
//! AOSSLQ01 | version:u16be=1 | reserved[6]=0 | sequence:u64be |
//! nonce[32] | signed-plan-length:u32be | signed-plan[.length]
//! AOSSLU01 | version:u16be=1 | reserved[6]=0 | sequence:u64be |
//! nonce[32] | signed-plan-digest[32] | status:u8=1 | reserved[7]=0
//! ```

use aos_sandbox_core::ObjectDigest;

use crate::{MAXIMUM_FRAME_BYTES, SignedStorageLiveExportRequestV1};

const REQUEST_MAGIC: &[u8; 8] = b"AOSSLQ01";
const RESPONSE_MAGIC: &[u8; 8] = b"AOSSLU01";
const VERSION: u16 = 1;
const REQUEST_HEADER_BYTES: usize = 60;
const RESPONSE_BYTES: usize = 96;
const MAXIMUM_SIGNED_PLAN_BYTES: usize = MAXIMUM_FRAME_BYTES + 612;

/// Maximum accepted descriptor-free transport packet size.
pub const MAXIMUM_STORAGE_EXPORT_REQUEST_PACKET_BYTES_V1: usize =
    REQUEST_HEADER_BYTES + MAXIMUM_SIGNED_PLAN_BYTES;

/// Rejects malformed, replayed, or mismatched transport control bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StorageLiveExportTransportErrorV1 {
    /// The packet is not the exact canonical format.
    #[error("Storage live-export transport packet is noncanonical")]
    Noncanonical,
    /// The connection-local sequence is repeated or moves backward.
    #[error("Storage live-export transport sequence was replayed")]
    Replay,
    /// The response does not name the exact request and signed plan.
    #[error("Storage live-export transport response does not match request")]
    ResponseMismatch,
}

/// Carries one exact signed plan over a descriptor-free connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageLiveExportTransportRequestV1 {
    sequence: u64,
    nonce: [u8; 32],
    signed_plan: SignedStorageLiveExportRequestV1,
}

impl StorageLiveExportTransportRequestV1 {
    /// Constructs one nonzero connection-local request identity.
    ///
    /// # Errors
    ///
    /// Rejects zero sequence or nonce.
    pub fn new(
        sequence: u64,
        nonce: [u8; 32],
        signed_plan: SignedStorageLiveExportRequestV1,
    ) -> Result<Self, StorageLiveExportTransportErrorV1> {
        if sequence == 0 || nonce == [0; 32] {
            return Err(StorageLiveExportTransportErrorV1::Noncanonical);
        }
        Ok(Self {
            sequence,
            nonce,
            signed_plan,
        })
    }

    /// Decodes one complete signed-plan packet without trusting its signatures.
    ///
    /// # Errors
    ///
    /// Rejects invalid framing, length, nested signed-plan format, or tail.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, StorageLiveExportTransportErrorV1> {
        if bytes.len() < REQUEST_HEADER_BYTES
            || bytes.len() > MAXIMUM_STORAGE_EXPORT_REQUEST_PACKET_BYTES_V1
            || &bytes[..8] != REQUEST_MAGIC
            || bytes[8..10] != VERSION.to_be_bytes()
            || bytes[10..16] != [0; 6]
        {
            return Err(StorageLiveExportTransportErrorV1::Noncanonical);
        }
        let sequence = u64::from_be_bytes(
            bytes[16..24]
                .try_into()
                .map_err(|_| StorageLiveExportTransportErrorV1::Noncanonical)?,
        );
        let nonce = bytes[24..56]
            .try_into()
            .map_err(|_| StorageLiveExportTransportErrorV1::Noncanonical)?;
        let plan_length = u32::from_be_bytes(
            bytes[56..60]
                .try_into()
                .map_err(|_| StorageLiveExportTransportErrorV1::Noncanonical)?,
        ) as usize;
        if plan_length == 0
            || plan_length > MAXIMUM_SIGNED_PLAN_BYTES
            || bytes.len() != REQUEST_HEADER_BYTES + plan_length
        {
            return Err(StorageLiveExportTransportErrorV1::Noncanonical);
        }
        let signed_plan =
            SignedStorageLiveExportRequestV1::from_canonical_bytes(&bytes[REQUEST_HEADER_BYTES..])
                .map_err(|_| StorageLiveExportTransportErrorV1::Noncanonical)?;
        Self::new(sequence, nonce, signed_plan)
    }

    /// Encodes the only accepted request packet representation.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let plan = self.signed_plan.to_canonical_bytes();
        let mut bytes = Vec::with_capacity(REQUEST_HEADER_BYTES + plan.len());
        bytes.extend_from_slice(REQUEST_MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&[0; 6]);
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&(plan.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&plan);
        bytes
    }

    /// Returns the connection-local sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the challenge nonce to match in the response.
    #[must_use]
    pub const fn nonce(&self) -> [u8; 32] {
        self.nonce
    }

    /// Returns the exact signed plan that Storage must verify independently.
    #[must_use]
    pub const fn signed_plan(&self) -> &SignedStorageLiveExportRequestV1 {
        &self.signed_plan
    }

    /// Advances a retained connection-local sequence without accepting replay.
    ///
    /// # Errors
    ///
    /// Rejects an equal or lower sequence than the preceding accepted packet.
    pub fn validate_next_sequence(
        &self,
        previous_sequence: u64,
    ) -> Result<(), StorageLiveExportTransportErrorV1> {
        if self.sequence <= previous_sequence {
            return Err(StorageLiveExportTransportErrorV1::Replay);
        }
        Ok(())
    }
}

/// Acknowledges inspection while explicitly denying every export authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageLiveExportUnavailableV1 {
    sequence: u64,
    nonce: [u8; 32],
    signed_plan_digest: ObjectDigest,
}

impl StorageLiveExportUnavailableV1 {
    /// Constructs the sole response from an accepted request identity.
    #[must_use]
    pub fn for_request(request: &StorageLiveExportTransportRequestV1) -> Self {
        Self {
            sequence: request.sequence,
            nonce: request.nonce,
            signed_plan_digest: request.signed_plan.digest(),
        }
    }

    /// Decodes only the fixed unavailable response.
    ///
    /// # Errors
    ///
    /// Rejects changed version, status, reserved bytes, or length.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, StorageLiveExportTransportErrorV1> {
        if bytes.len() != RESPONSE_BYTES
            || &bytes[..8] != RESPONSE_MAGIC
            || bytes[8..10] != VERSION.to_be_bytes()
            || bytes[10..16] != [0; 6]
            || bytes[88] != 1
            || bytes[89..96] != [0; 7]
        {
            return Err(StorageLiveExportTransportErrorV1::Noncanonical);
        }
        let sequence = u64::from_be_bytes(
            bytes[16..24]
                .try_into()
                .map_err(|_| StorageLiveExportTransportErrorV1::Noncanonical)?,
        );
        let nonce = bytes[24..56]
            .try_into()
            .map_err(|_| StorageLiveExportTransportErrorV1::Noncanonical)?;
        let signed_plan_digest = ObjectDigest::from_bytes(
            bytes[56..88]
                .try_into()
                .map_err(|_| StorageLiveExportTransportErrorV1::Noncanonical)?,
        );
        if sequence == 0 || nonce == [0; 32] || signed_plan_digest.as_bytes() == &[0; 32] {
            return Err(StorageLiveExportTransportErrorV1::Noncanonical);
        }
        Ok(Self {
            sequence,
            nonce,
            signed_plan_digest,
        })
    }

    /// Encodes the fixed unavailable response.
    #[must_use]
    pub fn to_canonical_bytes(self) -> [u8; RESPONSE_BYTES] {
        let mut bytes = [0; RESPONSE_BYTES];
        bytes[..8].copy_from_slice(RESPONSE_MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
        bytes[16..24].copy_from_slice(&self.sequence.to_be_bytes());
        bytes[24..56].copy_from_slice(&self.nonce);
        bytes[56..88].copy_from_slice(self.signed_plan_digest.as_bytes());
        bytes[88] = 1;
        bytes
    }

    /// Confirms the response is for this exact request and signed plan.
    ///
    /// # Errors
    ///
    /// Rejects a replayed or substituted response identity.
    pub fn matches_request(
        self,
        request: &StorageLiveExportTransportRequestV1,
    ) -> Result<(), StorageLiveExportTransportErrorV1> {
        if self != Self::for_request(request) {
            return Err(StorageLiveExportTransportErrorV1::ResponseMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::{
        AcquireSourceRequestV1, SourceProviderKeyUsageV1, SourceProviderMethod,
        SourceProviderSigningKeyV1, SourceResourceV1, SourceUseV1, StorageLiveExportRequestV1,
        StorageLiveExportSelectorV1, digest_logical_binding_bytes, encode_acquire_request,
        prospective_mount_apply_template_digest_v1, sign_request,
    };

    fn digest(byte: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([byte; 32])
    }

    fn request() -> StorageLiveExportTransportRequestV1 {
        let root_key = SigningKey::from_bytes(&[41; 32]);
        let provider_key = SigningKey::from_bytes(&[42; 32]);
        let mut template = Vec::new();
        for tag in 1u8..=27 {
            let value = match tag {
                1 => b"AOSMSEM1".to_vec(),
                2 => 1u16.to_be_bytes().to_vec(),
                _ => vec![tag, tag.wrapping_add(1)],
            };
            template.push(tag);
            template.extend_from_slice(&(value.len() as u32).to_be_bytes());
            template.extend_from_slice(&value);
        }
        let template_digest = prospective_mount_apply_template_digest_v1(&template).unwrap();
        let binding = b"exact-root-mount-attachment".to_vec();
        let binding_digest = digest_logical_binding_bytes(&binding);
        let root_request = AcquireSourceRequestV1::new_v2(
            digest(1),
            2,
            [3; 16],
            4,
            template,
            template_digest,
            SourceUseV1::MountCreate,
            [5; 16],
            [6; 16],
            [7; 16],
            8,
            digest(9),
            binding,
            binding_digest,
            1000,
            60,
            digest(10),
            false,
            0,
            true,
        )
        .unwrap();
        let root_signer = SourceProviderSigningKeyV1::for_signing_key(
            [7; 16],
            8,
            digest(9),
            [11; 16],
            12,
            SourceProviderKeyUsageV1::RootMountRecord,
            &root_key,
        )
        .unwrap();
        let signed_root_request = sign_request(
            SourceProviderMethod::Acquire,
            encode_acquire_request(&root_request),
            root_signer,
            &root_key,
        )
        .unwrap();
        let resource = SourceResourceV1::new(
            digest(13),
            [14; 32],
            15,
            digest(16),
            17,
            digest(18),
            19,
            digest(20),
        )
        .unwrap();
        let selector =
            StorageLiveExportSelectorV1::new([21; 16], 22, [23; 32], digest(24)).unwrap();
        let plan = StorageLiveExportRequestV1::new(
            [25; 16],
            digest(26),
            digest(27),
            [28; 16],
            digest(29),
            resource,
            selector,
            900,
            930,
            signed_root_request,
        )
        .unwrap();
        let provider_signer = SourceProviderSigningKeyV1::for_signing_key(
            [30; 16],
            31,
            digest(32),
            [33; 16],
            34,
            SourceProviderKeyUsageV1::ProviderOutcome,
            &provider_key,
        )
        .unwrap();
        let signed_plan =
            SignedStorageLiveExportRequestV1::sign(plan, provider_signer, &provider_key).unwrap();
        StorageLiveExportTransportRequestV1::new(7, [35; 32], signed_plan).unwrap()
    }

    #[test]
    fn request_and_unavailable_response_bind_exact_plan_nonce_and_sequence() {
        let request = request();
        let wire = request.to_canonical_bytes();
        let decoded = StorageLiveExportTransportRequestV1::from_canonical_bytes(&wire).unwrap();
        assert_eq!(decoded, request);
        assert!(decoded.validate_next_sequence(6).is_ok());
        assert_eq!(
            decoded.validate_next_sequence(7),
            Err(StorageLiveExportTransportErrorV1::Replay)
        );
        assert_eq!(
            decoded.validate_next_sequence(8),
            Err(StorageLiveExportTransportErrorV1::Replay)
        );

        let response = StorageLiveExportUnavailableV1::for_request(&request);
        let encoded = response.to_canonical_bytes();
        assert_eq!(
            StorageLiveExportUnavailableV1::from_canonical_bytes(&encoded).unwrap(),
            response
        );
        assert!(response.matches_request(&request).is_ok());
        let different_sequence = StorageLiveExportTransportRequestV1::new(
            8,
            request.nonce(),
            request.signed_plan().clone(),
        )
        .unwrap();
        assert_eq!(
            response.matches_request(&different_sequence),
            Err(StorageLiveExportTransportErrorV1::ResponseMismatch)
        );
        let different_nonce = StorageLiveExportTransportRequestV1::new(
            request.sequence(),
            [36; 32],
            request.signed_plan().clone(),
        )
        .unwrap();
        assert_eq!(
            response.matches_request(&different_nonce),
            Err(StorageLiveExportTransportErrorV1::ResponseMismatch)
        );

        let mut changed_digest = encoded;
        changed_digest[56] ^= 1;
        let changed_response =
            StorageLiveExportUnavailableV1::from_canonical_bytes(&changed_digest).unwrap();
        assert_eq!(
            changed_response.matches_request(&request),
            Err(StorageLiveExportTransportErrorV1::ResponseMismatch)
        );
    }

    #[test]
    fn transport_rejects_tamper_tail_and_status_upgrade() {
        let mut wire = request().to_canonical_bytes();
        wire.push(0);
        assert_eq!(
            StorageLiveExportTransportRequestV1::from_canonical_bytes(&wire),
            Err(StorageLiveExportTransportErrorV1::Noncanonical)
        );
        wire.pop();
        wire[16..24].copy_from_slice(&0_u64.to_be_bytes());
        assert_eq!(
            StorageLiveExportTransportRequestV1::from_canonical_bytes(&wire),
            Err(StorageLiveExportTransportErrorV1::Noncanonical)
        );

        let mut response =
            StorageLiveExportUnavailableV1::for_request(&request()).to_canonical_bytes();
        response[88] = 2;
        assert_eq!(
            StorageLiveExportUnavailableV1::from_canonical_bytes(&response),
            Err(StorageLiveExportTransportErrorV1::Noncanonical)
        );
    }
}
