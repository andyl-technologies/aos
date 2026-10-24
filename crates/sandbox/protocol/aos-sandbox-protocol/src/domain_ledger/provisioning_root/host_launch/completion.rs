//! Frames the final comparison of one Start resource on its original Root socket.
//!
//! ```text
//! AOSHRP02 | eight u32be field lengths | binding97 | C-native64 |
//! Source-native64 | Session-native64 | signed-resource-request |
//! resource-outcome | signed-inventory-request | inventory-outcome
//!
//! Host uses its actual signed Host1 Ready and distinct fresh Inventory3.
//! The Host request embeds the signed Guardian plan. Root must independently
//! authenticate and compare that exact pair and the protected publication;
//! this framing alone supplies neither readiness nor a Guardian phase proof.
//! ```
//!
//! Every field is comparison DATA. Root must independently read the current
//! protected journals, verify both exact authenticated exchanges and revalidate
//! its original current-policy decision. A decoded proof cannot complete a
//! resource, dispose a native flight or authorize the next resource.

use aos_sandbox_broker_session_protocol::projection::{
    AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES, AUTHENTICATED_RESPONSE_MAXIMUM_BYTES,
};
use aos_sandbox_model::bounded_codec::BoundedReader;

use super::{HistoryErrorV1, HostResourcePurposeDataV1, framing};

const PROOF_MAGIC: &[u8; 8] = b"AOSHRP02";
const PROOF_DOMAIN: &[u8] = b"aos.sandbox.root.start-resource.proof.v2\0";
const CLOSED_MAGIC: &[u8; 8] = b"AOSHRD02";
const BINDING_BYTES: usize = 97;
const NATIVE_BYTES: usize = 64;

/// Holds the exact announcement width before any proof-body allocation.
pub const RESOURCE_PROOF_HEADER_BYTES_V2: usize = 8 + 8 * 4;

/// Holds the exact final Root acknowledgement width, without trailing bytes.
pub const RESOURCE_CLOSED_BYTES_V2: usize = 8 + BINDING_BYTES + 32 + 3 * 8;

/// Selects only a closed original purpose for the shared final-proof DATA.
///
/// Existing Start ordinals keep their exact wire encoding. Maintenance is a
/// separate ordinal; decoding it cannot construct an accepted Start or a grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceCompletionPurposeDataV3 {
    /// Names one actual accepted Start resource child.
    Start(HostResourcePurposeDataV1),
    /// Names only the actual current Maintenance Storage31 child.
    MaintenanceStorage,
}

impl ResourceCompletionPurposeDataV3 {
    fn decode_v3(code: u8) -> Result<Self, HistoryErrorV1> {
        match code {
            5 => Ok(Self::MaintenanceStorage),
            code => HostResourcePurposeDataV1::decode_v1(code).map(Self::Start),
        }
    }

    fn code_v3(self) -> u8 {
        match self {
            Self::Start(purpose) => purpose as u8,
            Self::MaintenanceStorage => 5,
        }
    }
}

impl From<HostResourcePurposeDataV1> for ResourceCompletionPurposeDataV3 {
    fn from(purpose: HostResourcePurposeDataV1) -> Self { Self::Start(purpose) }
}

/// Binds one resource's final comparison to its original Root opening and reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceCompletionBindingDataV2 {
    /// The resource purpose selected by the original unsigned Root reply.
    pub purpose: ResourceCompletionPurposeDataV3,
    /// The same actual Root flight's nonce.
    pub root_nonce: [u8; 16],
    /// The same actual Controller flight's nonce.
    pub controller_nonce: [u8; 16],
    /// The exact original opening-query commitment.
    pub query_digest: [u8; 32],
    /// The exact original unsigned-reply commitment.
    pub reply_digest: [u8; 32],
}

impl ResourceCompletionBindingDataV2 {
    fn validate(self) -> Result<(), HistoryErrorV1> {
        if self.root_nonce == [0; 16]
            || self.controller_nonce == [0; 16]
            || self.query_digest == [0; 32]
            || self.reply_digest == [0; 32]
        {
            return Err(HistoryErrorV1::Malformed);
        }
        Ok(())
    }

    fn decode(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let mut input = BoundedReader::new(bytes, |_| HistoryErrorV1::Extent);
        let binding = Self {
            purpose: ResourceCompletionPurposeDataV3::decode_v3(input.array::<1>()?[0])?,
            root_nonce: input.array()?,
            controller_nonce: input.array()?,
            query_digest: input.array()?,
            reply_digest: input.array()?,
        };
        input.finish()?;
        binding.validate()?;
        Ok(binding)
    }

    fn encode(self) -> Result<[u8; BINDING_BYTES], HistoryErrorV1> {
        self.validate()?;
        let mut bytes = [0; BINDING_BYTES];
        bytes[0] = self.purpose.code_v3();
        bytes[1..17].copy_from_slice(&self.root_nonce);
        bytes[17..33].copy_from_slice(&self.controller_nonce);
        bytes[33..65].copy_from_slice(&self.query_digest);
        bytes[65..97].copy_from_slice(&self.reply_digest);
        Ok(bytes)
    }
}

/// Borrows complete final resource exchanges and their current native positions.
#[derive(Clone, Copy)]
pub struct ResourceCompletionProofDataV2<'proof> {
    /// The original Root opening and reply identities.
    pub binding: ResourceCompletionBindingDataV2,
    /// The actual current Controller names, NEXT and durable end.
    pub controller_native: &'proof [u8],
    /// The actual current Source names, NEXT and durable end.
    pub source_native: &'proof [u8],
    /// The actual resource Session names, NEXT and durable end.
    pub session_native: &'proof [u8],
    /// The exact signed resource request retained by the same Session.
    pub resource_request: &'proof [u8],
    /// The complete authenticated terminal outcome of that resource request.
    pub resource_outcome: &'proof [u8],
    /// The distinct fresh signed Inventory request on the same Session.
    pub inventory_request: &'proof [u8],
    /// The complete authenticated terminal outcome of that Inventory request.
    pub inventory_outcome: &'proof [u8],
}

impl<'proof> ResourceCompletionProofDataV2<'proof> {
    fn maxima() -> [usize; 8] {
        [
            BINDING_BYTES,
            NATIVE_BYTES,
            NATIVE_BYTES,
            NATIVE_BYTES,
            AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES,
            AUTHENTICATED_RESPONSE_MAXIMUM_BYTES,
            AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES,
            AUTHENTICATED_RESPONSE_MAXIMUM_BYTES,
        ]
    }

    fn fields<'fields>(&'fields self, binding: &'fields [u8]) -> [&'fields [u8]; 8]
    where
        'proof: 'fields,
    {
        [
            binding,
            self.controller_native,
            self.source_native,
            self.session_native,
            self.resource_request,
            self.resource_outcome,
            self.inventory_request,
            self.inventory_outcome,
        ]
    }

    /// Measures the exact announced body before a receiver admits its growth.
    ///
    /// # Errors
    /// Refuses another protocol, empty fields, exceeded bounds or wrong fixed widths.
    pub fn declared_bytes_v2(header: &[u8]) -> Result<usize, HistoryErrorV1> {
        let bytes = framing::declared_fields_bytes(header, PROOF_MAGIC, Self::maxima())?;
        for (index, width) in [BINDING_BYTES, NATIVE_BYTES, NATIVE_BYTES, NATIVE_BYTES]
            .into_iter()
            .enumerate()
        {
            let start = 8 + index * 4;
            if header.get(start..start + 4) != Some((width as u32).to_be_bytes().as_slice()) {
                return Err(HistoryErrorV1::Extent);
            }
        }
        Ok(bytes)
    }

    /// Decodes only exact borrowed framing, without adopting any native owner.
    ///
    /// # Errors
    /// Refuses invalid bindings, native positions, nested bounds or trailing bytes.
    pub fn decode_v2(bytes: &'proof [u8]) -> Result<Self, HistoryErrorV1> {
        let [
            binding,
            controller_native,
            source_native,
            session_native,
            resource_request,
            resource_outcome,
            inventory_request,
            inventory_outcome,
        ] = framing::decode_fields(bytes, PROOF_MAGIC, Self::maxima())?;
        let proof = Self {
            binding: ResourceCompletionBindingDataV2::decode(binding)?,
            controller_native,
            source_native,
            session_native,
            resource_request,
            resource_outcome,
            inventory_request,
            inventory_outcome,
        };
        proof.encoded_bytes_v2()?;
        Ok(proof)
    }

    /// Measures the complete checked framing without allocating an aggregate body.
    ///
    /// # Errors
    /// Refuses invalid bindings, native positions, empty fields or checked overflow.
    pub fn encoded_bytes_v2(self) -> Result<usize, HistoryErrorV1> {
        let binding = self.binding.encode()?;
        for native in [
            self.controller_native,
            self.source_native,
            self.session_native,
        ] {
            require_native_position(native)?;
        }
        for (field, maximum) in self.fields(&binding).into_iter().zip(Self::maxima()) {
            if field.is_empty() || field.len() > maximum {
                return Err(HistoryErrorV1::Extent);
            }
        }
        framing::fields_bytes(self.fields(&binding))
    }

    /// Copies a checked range from the same borrowed proof fields.
    ///
    /// # Errors
    /// Refuses malformed fields, overflow or a range outside the complete proof.
    pub fn encode_range_v2(self, offset: usize, output: &mut [u8]) -> Result<(), HistoryErrorV1> {
        self.encoded_bytes_v2()?;
        let binding = self.binding.encode()?;
        framing::encode_fields_range(PROOF_MAGIC, self.fields(&binding), offset, output)
    }

    /// Commits every byte of the original proof under its closed protocol domain.
    ///
    /// # Errors
    /// Refuses malformed fields or checked extent overflow before hashing.
    pub fn digest_v2(self) -> Result<[u8; 32], HistoryErrorV1> {
        self.encoded_bytes_v2()?;
        let binding = self.binding.encode()?;
        super::super::opening::hash_fields(PROOF_DOMAIN, PROOF_MAGIC, self.fields(&binding))
    }
}

/// Carries the final Root comparison result on the same original connection.
///
/// This DATA does not construct a completed resource token. The actual client
/// must match its retained query, reply and proof, verify the original clock
/// contract, observe strict EOF and finish every independently owed native post.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceCompletionClosedDataV2 {
    /// The exact original resource opening and unsigned reply identities.
    pub binding: ResourceCompletionBindingDataV2,
    /// The exact complete final comparison-proof commitment.
    pub proof_digest: [u8; 32],
    /// Root's actual independently sampled final wall time.
    pub observed_wall_seconds: i64,
    /// Root's actual independently sampled final BOOTTIME.
    pub observed_boottime_ns: u64,
    /// The original child cutoff, without any renewed interval.
    pub cutoff_ns: u64,
}

impl ResourceCompletionClosedDataV2 {
    fn validate(self) -> Result<(), HistoryErrorV1> {
        self.binding.validate()?;
        if self.proof_digest == [0; 32]
            || self.observed_wall_seconds <= 0
            || self.observed_boottime_ns == 0
            || self.observed_boottime_ns >= self.cutoff_ns
        {
            return Err(HistoryErrorV1::Malformed);
        }
        Ok(())
    }

    /// Decodes exact final acknowledgement DATA without completing custody.
    ///
    /// # Errors
    /// Refuses another protocol, invalid binding, expired cutoff or trailing bytes.
    pub fn decode_v2(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let mut input = BoundedReader::new(bytes, |_| HistoryErrorV1::Extent);
        if input.array::<8>()? != *CLOSED_MAGIC {
            return Err(HistoryErrorV1::Malformed);
        }
        let closed = Self {
            binding: ResourceCompletionBindingDataV2::decode(input.bytes(BINDING_BYTES)?)?,
            proof_digest: input.array()?,
            observed_wall_seconds: input.i64()?,
            observed_boottime_ns: input.u64()?,
            cutoff_ns: input.u64()?,
        };
        input.finish()?;
        closed.validate()?;
        Ok(closed)
    }

    /// Encodes the checked final comparison fields without allocating a body.
    ///
    /// # Errors
    /// Refuses invalid binding identities, a missing proof or elapsed cutoff.
    pub fn encode_v2(self) -> Result<[u8; RESOURCE_CLOSED_BYTES_V2], HistoryErrorV1> {
        self.validate()?;
        let mut bytes = [0; RESOURCE_CLOSED_BYTES_V2];
        bytes[..8].copy_from_slice(CLOSED_MAGIC);
        bytes[8..105].copy_from_slice(&self.binding.encode()?);
        bytes[105..137].copy_from_slice(&self.proof_digest);
        bytes[137..145].copy_from_slice(&self.observed_wall_seconds.to_be_bytes());
        bytes[145..153].copy_from_slice(&self.observed_boottime_ns.to_be_bytes());
        bytes[153..161].copy_from_slice(&self.cutoff_ns.to_be_bytes());
        Ok(bytes)
    }
}

fn require_native_position(bytes: &[u8]) -> Result<(), HistoryErrorV1> {
    let mut input = BoundedReader::new(bytes, |_| HistoryErrorV1::Extent);
    crate::domain_ledger::protected_names::ProtectedJournalNamesV1::from_bytes(input.bytes(48)?)
        .map_err(|_| HistoryErrorV1::Malformed)?;
    if input.u64()? == 0 || input.u64()? == 0 {
        return Err(HistoryErrorV1::Malformed);
    }
    input.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_ledger::protected_names::ProtectedJournalNamesV1;

    fn binding() -> ResourceCompletionBindingDataV2 {
        ResourceCompletionBindingDataV2 {
            purpose: HostResourcePurposeDataV1::NetworkPrepare.into(),
            root_nonce: [1; 16],
            controller_nonce: [2; 16],
            query_digest: [3; 32],
            reply_digest: [4; 32],
        }
    }

    #[test]
    fn proof_binds_every_exchange_and_distinguishes_final_host_launch() {
        let mut native = [0; NATIVE_BYTES];
        native[..48].copy_from_slice(
            &ProtectedJournalNamesV1::from_historical_fields((1, 2), (3, 4), (5, 6)).to_bytes(),
        );
        native[48..56].copy_from_slice(&7_u64.to_be_bytes());
        native[56..].copy_from_slice(&8_u64.to_be_bytes());
        let proof = ResourceCompletionProofDataV2 {
            binding: binding(),
            controller_native: &native,
            source_native: &native,
            session_native: &native,
            resource_request: b"signed resource request",
            resource_outcome: b"complete authenticated resource outcome",
            inventory_request: b"distinct signed inventory request",
            inventory_outcome: b"complete authenticated inventory outcome",
        };
        let mut bytes = vec![0; proof.encoded_bytes_v2().unwrap()];
        for (index, chunk) in bytes.chunks_mut(17).enumerate() {
            proof.encode_range_v2(index * 17, chunk).unwrap();
        }
        assert_eq!(
            ResourceCompletionProofDataV2::declared_bytes_v2(
                &bytes[..RESOURCE_PROOF_HEADER_BYTES_V2],
            )
            .unwrap(),
            bytes.len()
        );
        assert_eq!(
            ResourceCompletionProofDataV2::decode_v2(&bytes)
                .unwrap()
                .digest_v2()
                .unwrap(),
            proof.digest_v2().unwrap()
        );

        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert_ne!(
            ResourceCompletionProofDataV2::decode_v2(&bytes)
                .unwrap()
                .digest_v2()
                .unwrap(),
            proof.digest_v2().unwrap()
        );
        bytes.push(0);
        assert!(ResourceCompletionProofDataV2::decode_v2(&bytes).is_err());
        let host = ResourceCompletionProofDataV2 {
            binding: ResourceCompletionBindingDataV2 {
                purpose: HostResourcePurposeDataV1::HostLaunch.into(),
                ..binding()
            },
            ..proof
        };
        assert_eq!(host.encoded_bytes_v2().unwrap(), proof.encoded_bytes_v2().unwrap());
        assert_ne!(host.digest_v2().unwrap(), proof.digest_v2().unwrap());
        let mut host_bytes = vec![0; host.encoded_bytes_v2().unwrap()];
        host.encode_range_v2(0, &mut host_bytes).unwrap();
        assert_eq!(ResourceCompletionProofDataV2::decode_v2(&host_bytes).unwrap().binding,
            host.binding);

        let maintenance = ResourceCompletionProofDataV2 {
            binding: ResourceCompletionBindingDataV2 {
                purpose: ResourceCompletionPurposeDataV3::MaintenanceStorage,
                ..binding()
            },
            ..proof
        };
        let mut maintenance_bytes = vec![0; maintenance.encoded_bytes_v2().unwrap()];
        maintenance.encode_range_v2(0, &mut maintenance_bytes).unwrap();
        assert_eq!(maintenance_bytes[RESOURCE_PROOF_HEADER_BYTES_V2], 5);
        assert_eq!(host_bytes[RESOURCE_PROOF_HEADER_BYTES_V2], 4);
        assert_ne!(maintenance.digest_v2().unwrap(), proof.digest_v2().unwrap());
        assert_eq!(ResourceCompletionProofDataV2::decode_v2(&maintenance_bytes).unwrap().binding,
            maintenance.binding);
    }

    #[test]
    fn final_acknowledgement_is_exact_and_does_not_extend_its_cutoff() {
        let closed = ResourceCompletionClosedDataV2 {
            binding: binding(),
            proof_digest: [5; 32],
            observed_wall_seconds: 10,
            observed_boottime_ns: 20,
            cutoff_ns: 30,
        };
        let mut bytes = closed.encode_v2().unwrap().to_vec();
        assert_eq!(
            ResourceCompletionClosedDataV2::decode_v2(&bytes).unwrap(),
            closed
        );
        bytes.push(0);
        assert!(ResourceCompletionClosedDataV2::decode_v2(&bytes).is_err());
        assert!(
            ResourceCompletionClosedDataV2 {
                observed_boottime_ns: 30,
                ..closed
            }
            .encode_v2()
            .is_err()
        );
        assert!(
            super::super::super::storage_apply::StorageApplyClosedDataV1::decode_v1(
                &closed.encode_v2().unwrap(),
            )
            .is_err()
        );
    }
}
