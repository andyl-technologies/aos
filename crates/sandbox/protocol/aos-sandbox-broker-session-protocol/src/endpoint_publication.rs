//! Untrusted broker endpoint publication for authenticated session bootstrap.
//!
//! The fixed 64-byte record contains only enough information for a client to
//! select the dynamic broker process value used by the subsequently signed
//! hello. Decoding does not authenticate the record or grant any authority:
//!
//! ```text
//! AOSBSE01 || version:u16be=1 || role:u8=2 || reserved[5]=0 ||
//! broker-process-execution-id[16] || manifest-binding[32]
//! ```

/// Exact byte length of an `AOSBSE01` broker publication.
pub const BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES: usize = 64;

const ENDPOINT_MAGIC: &[u8; 8] = b"AOSBSE01";
const ENDPOINT_VERSION: u16 = 1;
const BROKER_ROLE: u8 = 2;

/// Reports a malformed or noncanonical untrusted endpoint publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BrokerSessionEndpointPublicationError {
    /// The record has a wrong length, magic, version, role, or reserved byte.
    #[error("invalid Broker Session Authentication endpoint publication")]
    InvalidEncoding,
    /// A required untrusted claim uses its all-zero sentinel.
    #[error("Broker Session Authentication endpoint publication contains a zero sentinel")]
    ZeroSentinel,
}

/// Carries decoded broker bootstrap claims without authenticating them.
///
/// A caller must compare the manifest binding with protected local state and
/// authenticate the process-execution ID through the later BrokerHello. Neither
/// accessor is suitable for selecting trust, routing, keys, or policy.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct UntrustedBrokerSessionEndpointPublicationV1 {
    broker_process_execution_id: [u8; 16],
    manifest_binding: [u8; 32],
}

impl core::fmt::Debug for UntrustedBrokerSessionEndpointPublicationV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("UntrustedBrokerSessionEndpointPublicationV1([redacted])")
    }
}

impl UntrustedBrokerSessionEndpointPublicationV1 {
    /// Constructs one explicitly untrusted broker publication value.
    ///
    /// Construction checks only the two required nonzero sentinels. It does
    /// not establish protected provenance, freshness, or broker authority.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionEndpointPublicationError::ZeroSentinel`] when
    /// either claim is all zero.
    pub fn from_untrusted_broker_claims(
        broker_process_execution_id: [u8; 16],
        manifest_binding: [u8; 32],
    ) -> Result<Self, BrokerSessionEndpointPublicationError> {
        if broker_process_execution_id.iter().all(|byte| *byte == 0)
            || manifest_binding.iter().all(|byte| *byte == 0)
        {
            return Err(BrokerSessionEndpointPublicationError::ZeroSentinel);
        }

        Ok(Self {
            broker_process_execution_id,
            manifest_binding,
        })
    }

    /// Decodes one exact canonical record as untrusted claims.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionEndpointPublicationError`] for every wrong
    /// length, trailing byte, magic, version, role, reserved byte, or sentinel.
    pub fn decode_untrusted(bytes: &[u8]) -> Result<Self, BrokerSessionEndpointPublicationError> {
        if bytes.len() != BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES
            || &bytes[..8] != ENDPOINT_MAGIC
            || u16::from_be_bytes([bytes[8], bytes[9]]) != ENDPOINT_VERSION
            || bytes[10] != BROKER_ROLE
            || bytes[11..16].iter().any(|byte| *byte != 0)
        {
            return Err(BrokerSessionEndpointPublicationError::InvalidEncoding);
        }

        let mut broker_process_execution_id = [0_u8; 16];
        broker_process_execution_id.copy_from_slice(&bytes[16..32]);
        let mut manifest_binding = [0_u8; 32];
        manifest_binding.copy_from_slice(&bytes[32..64]);
        Self::from_untrusted_broker_claims(broker_process_execution_id, manifest_binding)
    }

    /// Encodes the exact canonical untrusted broker publication.
    #[must_use]
    pub fn to_canonical_bytes(self) -> [u8; BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES] {
        let mut output = [0_u8; BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES];
        output[..8].copy_from_slice(ENDPOINT_MAGIC);
        output[8..10].copy_from_slice(&ENDPOINT_VERSION.to_be_bytes());
        output[10] = BROKER_ROLE;
        output[16..32].copy_from_slice(&self.broker_process_execution_id);
        output[32..64].copy_from_slice(&self.manifest_binding);
        output
    }

    /// Returns the untrusted broker process-execution claim.
    #[must_use]
    pub const fn untrusted_broker_process_execution_id(self) -> [u8; 16] {
        self.broker_process_execution_id
    }

    /// Returns the untrusted protected-manifest binding claim.
    #[must_use]
    pub const fn untrusted_manifest_binding(self) -> [u8; 32] {
        self.manifest_binding
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical() -> [u8; BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES] {
        UntrustedBrokerSessionEndpointPublicationV1::from_untrusted_broker_claims(
            [0x11; 16], [0x22; 32],
        )
        .unwrap_or_else(|error| panic!("publication fixture failed: {error}"))
        .to_canonical_bytes()
    }

    #[test]
    fn exact_golden_round_trip_and_boundaries() {
        let expected = concat!(
            "414f5342534530310001020000000000",
            "11111111111111111111111111111111",
            "2222222222222222222222222222222222222222222222222222222222222222"
        );
        let bytes = canonical();
        assert_eq!(hex::encode(bytes), expected);
        assert_eq!(
            UntrustedBrokerSessionEndpointPublicationV1::decode_untrusted(&bytes)
                .unwrap_or_else(|error| panic!("publication decode failed: {error}"))
                .to_canonical_bytes(),
            bytes
        );
        assert!(
            UntrustedBrokerSessionEndpointPublicationV1::decode_untrusted(&bytes[..63]).is_err()
        );
        let mut extended = bytes.to_vec();
        extended.push(0);
        assert!(UntrustedBrokerSessionEndpointPublicationV1::decode_untrusted(&extended).is_err());
    }

    #[test]
    fn every_fixed_and_sentinel_field_is_closed() {
        for index in 0..16 {
            let mut changed = canonical();
            changed[index] ^= 1;
            assert!(
                UntrustedBrokerSessionEndpointPublicationV1::decode_untrusted(&changed).is_err(),
                "fixed byte {index}"
            );
        }

        let mut zero_process = canonical();
        zero_process[16..32].fill(0);
        assert!(
            UntrustedBrokerSessionEndpointPublicationV1::decode_untrusted(&zero_process).is_err()
        );
        let mut zero_binding = canonical();
        zero_binding[32..64].fill(0);
        assert!(
            UntrustedBrokerSessionEndpointPublicationV1::decode_untrusted(&zero_binding).is_err()
        );
    }
}
