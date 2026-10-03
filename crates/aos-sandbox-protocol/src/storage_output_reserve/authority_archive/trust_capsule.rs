//! Exact historical Controller plan/lease public pin preimages.
//!
//! Carried keys are comparison data, never receiver-selected trust anchors.
//!
//! ```text
//! AOSCPN01 | version:u16 | roles:u8 | reserved:5 |
//! plan-policy:length+bytes | plan-public:32 | revocation-scope:16 |
//! lease-policy:length+bytes | lease-public:32 | node:16 | domain-sha256:32
//! ```

use aos_proto::aos::sandbox::local::v1::BrokerAuthorizationArtifactsV1;
use aos_sandbox_core::format::{
    decode_broker_authorization_plan, decode_ownership_lease, decode_signature,
    decode_trust_policy, encode_trust_policy,
};
use aos_sandbox_core::{
    DecodeLimits, MediaType, NodeId, PortableMediaType, SignaturePurpose,
    descriptor_for_bytes, verify_signature,
};
use sha2::Digest as _;

use super::{ArchiveResult, HistoricalStorageOutputArchiveErrorV1, Reader, digest, nonzero};

const DOMAIN: &[u8] = b"aos.sandbox.controller-storage-output-public-pins.v1\0";
const MAXIMUM_POLICY_BYTES: usize = 65_536;
pub(super) const MAXIMUM_BYTES: usize = 131_224;

/// Retains complete public policy/key comparison bytes without installing trust.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoricalControllerOutputPublicPinsV1 {
    bytes: Vec<u8>,
    node: NodeId,
    plan_policy: Vec<u8>,
    plan_public: [u8; 32],
    lease_policy: Vec<u8>,
    lease_public: [u8; 32],
    revocation_scope: [u8; 16],
}

impl HistoricalControllerOutputPublicPinsV1 {
    /// Decodes exact bounded historical Controller public pin bytes.
    ///
    /// # Errors
    ///
    /// Rejects malformed framing, noncanonical/wrong-purpose policies, missing
    /// public keys, zero scopes/node, reserved bytes or a changed checksum.
    pub fn decode(bytes: &[u8]) -> Result<Self, HistoricalStorageOutputArchiveErrorV1> {
        if bytes.len() > MAXIMUM_BYTES {
            return Err(HistoricalStorageOutputArchiveErrorV1::TooLarge);
        }
        let mut reader = Reader::new(bytes);
        if reader.take(8)? != b"AOSCPN01" || reader.u16()? != 1 || reader.u8()? != 2 {
            return Err(HistoricalStorageOutputArchiveErrorV1::Invalid);
        }
        reader.zero(5)?;
        let (plan_policy, plan_public) =
            validate_policy(&mut reader, SignaturePurpose::BrokerAuthorization)?;
        let revocation_scope = reader.array()?;
        nonzero(&revocation_scope)?;
        let (lease_policy, lease_public) =
            validate_policy(&mut reader, SignaturePurpose::OwnershipLease)?;
        let node = reader.array()?;
        nonzero(&node)?;
        let checksum = reader.array()?;
        reader.finish()?;
        let prefix = bytes
            .get(..bytes.len().saturating_sub(32))
            .ok_or(HistoricalStorageOutputArchiveErrorV1::Invalid)?;
        if checksum != digest(DOMAIN, prefix) {
            return Err(HistoricalStorageOutputArchiveErrorV1::Invalid);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            node: NodeId::from_bytes(node),
            plan_policy,
            plan_public,
            lease_policy,
            lease_public,
            revocation_scope,
        })
    }

    /// Borrows the unchanged full historical public pin capsule.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the historical node comparison identity.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Checks historical signature self-consistency using the existing verifier.
    ///
    /// Recorded capsule keys are not a receiver's independent trust anchors.
    /// The recorded issue time is a comparison value, not a fresh clock sample.
    pub(super) fn validate_quartet(
        &self,
        quartet: &BrokerAuthorizationArtifactsV1,
        wall_interval: (i64, i64),
        generations: [u64; 3],
    ) -> ArchiveResult<()> {
        if quartet.broker_plan.is_empty()
            || quartet.broker_plan.len() > 786_432
            || quartet.broker_plan_signature.is_empty()
            || quartet.broker_plan_signature.len() > 65_536
            || quartet.ownership_lease.is_empty()
            || quartet.ownership_lease.len() > 65_536
            || quartet.ownership_lease_signature.is_empty()
            || quartet.ownership_lease_signature.len() > 65_536
        {
            return Err(HistoricalStorageOutputArchiveErrorV1::Invalid);
        }
        let limits = bounded_limits(786_432);
        let plan = decode_broker_authorization_plan(&quartet.broker_plan, limits)
            .map_err(|_| HistoricalStorageOutputArchiveErrorV1::Invalid)?;
        let lease = decode_ownership_lease(&quartet.ownership_lease, bounded_limits(65_536))
            .map_err(|_| HistoricalStorageOutputArchiveErrorV1::Invalid)?;
        let plan_signature = decode_signature(&quartet.broker_plan_signature, bounded_limits(65_536))
            .map_err(|_| HistoricalStorageOutputArchiveErrorV1::Invalid)?;
        let lease_signature = decode_signature(&quartet.ownership_lease_signature, bounded_limits(65_536))
            .map_err(|_| HistoricalStorageOutputArchiveErrorV1::Invalid)?;
        let plan_descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::BrokerAuthorizationPlan.as_str().to_owned())
                .map_err(|_| HistoricalStorageOutputArchiveErrorV1::Invalid)?,
            &quartet.broker_plan,
        );
        let lease_descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::OwnershipLease.as_str().to_owned())
                .map_err(|_| HistoricalStorageOutputArchiveErrorV1::Invalid)?,
            &quartet.ownership_lease,
        );
        if plan.node() != self.node
            || lease.node() != self.node
            || lease.assignment().sandbox() != plan.assignment().sandbox()
            || lease.assignment().incarnation() != plan.assignment().incarnation()
            || lease.assignment().epoch() != plan.assignment().epoch()
            || lease.assignment().digest() != plan.assignment().digest()
            || plan.revocation_scope().as_bytes() != &self.revocation_scope
            || (plan.issued_seconds(), plan.expires_seconds()) != wall_interval
            || plan_signature.statement().subject() != &plan_descriptor
            || lease_signature.statement().subject() != &lease_descriptor
            || plan_signature.statement().purpose() != SignaturePurpose::BrokerAuthorization
            || lease_signature.statement().purpose() != SignaturePurpose::OwnershipLease
            || plan_signature.statement().issued_seconds() != plan.issued_seconds()
            || plan_signature.statement().expires_seconds() != Some(plan.expires_seconds())
            || lease_signature.statement().issued_seconds() != lease.authority_issued_seconds()
            || lease_signature.statement().expires_seconds() != Some(lease.authority_expires_seconds())
            || plan.issued_seconds() < lease.authority_issued_seconds()
            || plan.expires_seconds() > lease.authority_expires_seconds()
            || plan.ownership_authority() != lease_signature.statement().signer()
            || generations != [
                lease.lease_generation(),
                plan_signature.statement().signer().generation(),
                lease_signature.statement().signer().generation(),
            ]
        {
            return Err(HistoricalStorageOutputArchiveErrorV1::Invalid);
        }
        verify_signature(
            &plan_signature,
            &self.plan_policy,
            &self.plan_public,
            wall_interval.0,
            bounded_limits(MAXIMUM_POLICY_BYTES),
        ).map_err(|_| HistoricalStorageOutputArchiveErrorV1::Invalid)?;
        verify_signature(
            &lease_signature,
            &self.lease_policy,
            &self.lease_public,
            wall_interval.0,
            bounded_limits(MAXIMUM_POLICY_BYTES),
        ).map_err(|_| HistoricalStorageOutputArchiveErrorV1::Invalid)?;
        Ok(())
    }
}

fn bounded_limits(maximum_bytes: usize) -> DecodeLimits {
    DecodeLimits {
        maximum_bytes,
        maximum_collection_items: MAXIMUM_POLICY_BYTES,
        maximum_total_items: maximum_bytes,
        maximum_byte_string_bytes: maximum_bytes,
        maximum_text_bytes: MAXIMUM_POLICY_BYTES,
        maximum_depth: 32,
    }
}

fn validate_policy(
    reader: &mut Reader<'_>,
    purpose: SignaturePurpose,
) -> ArchiveResult<(Vec<u8>, [u8; 32])> {
    let bytes = reader.field(MAXIMUM_POLICY_BYTES)?;
    let policy = decode_trust_policy(bytes, bounded_limits(MAXIMUM_POLICY_BYTES))
        .map_err(|_| HistoricalStorageOutputArchiveErrorV1::Invalid)?;
    let public_key = reader.array::<32>()?;
    nonzero(&public_key)?;
    let fingerprint = sha2::Sha256::digest(public_key);
    if policy.purpose() != purpose
        || encode_trust_policy(&policy) != bytes
        || !policy.allowed_keys().iter().any(|key| {
            key.public_key_sha256().as_bytes() == fingerprint.as_slice()
        })
    {
        return Err(HistoricalStorageOutputArchiveErrorV1::Invalid);
    }
    Ok((bytes.to_vec(), public_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_pins_bound_length_before_nested_allocation() {
        assert!(matches!(HistoricalControllerOutputPublicPinsV1::decode(&vec![0; MAXIMUM_BYTES + 1]),
            Err(HistoricalStorageOutputArchiveErrorV1::TooLarge)));

        let mut bytes = b"AOSCPN01".to_vec();
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&[2, 0, 0, 0, 0, 0]);
        bytes.extend_from_slice(&65_537_u32.to_be_bytes());
        assert!(matches!(HistoricalControllerOutputPublicPinsV1::decode(&bytes),
            Err(HistoricalStorageOutputArchiveErrorV1::TooLarge)));
    }

    #[test]
    fn incomplete_quartet_is_refused_without_minting_historical_signature_proof() {
        let pins = HistoricalControllerOutputPublicPinsV1 {
            bytes: Vec::new(),
            node: NodeId::from_bytes([1; 16]),
            plan_policy: Vec::new(),
            plan_public: [2; 32],
            lease_policy: Vec::new(),
            lease_public: [3; 32],
            revocation_scope: [4; 16],
        };

        assert!(pins.validate_quartet(
            &BrokerAuthorizationArtifactsV1::default(), (100, 130), [1; 3],
        ).is_err());
    }
}
