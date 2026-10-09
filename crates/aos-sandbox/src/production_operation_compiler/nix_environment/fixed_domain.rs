//! Canonical fixed Nix domain-pin DATA shared by authentic purpose owners.
//!
//! Decoding compares the existing compact JSON layout and intrinsic limits.
//! It neither authenticates a credential nor constructs startup, selector,
//! session, journal, floor or operation authority.
//!
//! ```text
//! {"version":2,"identities":[controllerUID,controllerGID,builderUID,builderGID],
//!  "node":...,"deployment":...,"endpoint":...,"domain":...,
//!  "domain_commitment":...,"disclosure":...}
//! ```

use aos_sandbox_core::{NodeId, ObjectDigest, ResourceId};
use serde::{Deserialize, Serialize};

const MAXIMUM_PIN_BYTES: usize = 1_048_576;

/// Reports malformed or unsupported fixed-domain DATA, not a custody failure.
#[derive(Debug, thiserror::Error)]
pub enum NixFixedDomainPinsDecodeErrorV2 {
    /// The original JSON cannot be decoded or canonically encoded.
    #[error(transparent)]
    Encoding(#[from] serde_json::Error),
    /// The representation or intrinsic fixed-domain fields disagree.
    #[error("fixed Nix domain-pin DATA is noncanonical or unsupported")]
    Invalid,
}

/// Contains the existing canonical fixed-domain fields as nonauthorizing DATA.
///
/// The structural Serde implementations do not authenticate these fields.
/// Only `decode` checks canonical representation and intrinsic constraints.
/// A caller-selected value cannot construct an original startup or floor loan.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NixFixedDomainPinsDataV2 {
    pub(super) version: u16,
    pub(super) identities: [u32; 4],
    pub(super) node: NodeId,
    pub(super) deployment: ObjectDigest,
    pub(super) endpoint: ResourceId,
    pub(super) domain: ResourceId,
    pub(super) domain_commitment: ObjectDigest,
    pub(super) disclosure: ObjectDigest,
}

impl NixFixedDomainPinsDataV2 {
    /// Decodes the existing canonical JSON and supported intrinsic fields.
    ///
    /// The caller must independently authenticate the original credential and
    /// compare contextual node and Controller execution identities.
    ///
    /// # Errors
    ///
    /// Returns `Encoding` for the original Serde failures and `Invalid` for
    /// bytes beyond the existing credential cap, noncanonical bytes, a foreign
    /// version, zero fields or reused identities.
    pub fn decode(bytes: &[u8]) -> Result<Self, NixFixedDomainPinsDecodeErrorV2> {
        if bytes.len() > MAXIMUM_PIN_BYTES {
            return Err(NixFixedDomainPinsDecodeErrorV2::Invalid);
        }

        let pins: Self = serde_json::from_slice(bytes)?;
        if serde_json::to_vec(&pins)? != bytes
            || pins.version != 2
            || pins.identities.contains(&0)
            || pins.identities[0] == pins.identities[2]
            || pins.identities[1] == pins.identities[3]
            || pins.node.as_bytes() == &[0; 16]
            || pins.endpoint.as_bytes() == &[0; 16]
            || pins.domain.as_bytes() == &[0; 16]
            || [pins.deployment, pins.domain_commitment, pins.disclosure]
                .iter()
                .any(|digest| digest.as_bytes() == &[0; 32])
        {
            return Err(NixFixedDomainPinsDecodeErrorV2::Invalid);
        }
        Ok(pins)
    }

    /// Returns the original Controller and later-builder identities as DATA.
    #[must_use]
    pub const fn identities(&self) -> [u32; 4] {
        self.identities
    }

    /// Returns the claimed node identity as DATA.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Returns the claimed deployment commitment as DATA.
    #[must_use]
    pub const fn deployment(&self) -> ObjectDigest {
        self.deployment
    }

    /// Returns the claimed fixed endpoint identity as DATA.
    #[must_use]
    pub const fn endpoint(&self) -> ResourceId {
        self.endpoint
    }

    /// Returns the claimed store-domain identity as DATA.
    #[must_use]
    pub const fn domain(&self) -> ResourceId {
        self.domain
    }

    /// Returns the claimed complete domain commitment as DATA.
    #[must_use]
    pub const fn domain_commitment(&self) -> ObjectDigest {
        self.domain_commitment
    }

    /// Returns the claimed disclosure commitment as DATA.
    #[must_use]
    pub const fn disclosure(&self) -> ObjectDigest {
        self.disclosure
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These fields exercise DATA only, never an original owner or credential.
    fn pins() -> NixFixedDomainPinsDataV2 {
        NixFixedDomainPinsDataV2 {
            version: 2,
            identities: [811, 812, 813, 814],
            node: NodeId::from_bytes([1; 16]),
            deployment: ObjectDigest::from_bytes([2; 32]),
            endpoint: ResourceId::from_bytes([3; 16]),
            domain: ResourceId::from_bytes([4; 16]),
            domain_commitment: ObjectDigest::from_bytes([5; 32]),
            disclosure: ObjectDigest::from_bytes([6; 32]),
        }
    }

    #[test]
    fn canonical_fields_keep_the_existing_order_and_exact_roundtrip() {
        let original = pins();
        let bytes = serde_json::to_vec(&original).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();

        let decoded = NixFixedDomainPinsDataV2::decode(&bytes).unwrap();

        assert_eq!(decoded, original);
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), bytes);
        let names = [
            "version",
            "identities",
            "node",
            "deployment",
            "endpoint",
            "domain",
            "domain_commitment",
            "disclosure",
        ];
        let offsets = names.map(|name| text.find(&format!("\"{name}\":")).unwrap());
        assert!(offsets.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn structural_json_errors_keep_the_encoding_category() {
        for bytes in [b"{".as_slice(), b"{}".as_slice()] {
            assert!(matches!(
                NixFixedDomainPinsDataV2::decode(bytes),
                Err(NixFixedDomainPinsDecodeErrorV2::Encoding(_)),
            ));
        }

        let mut unknown = serde_json::to_vec(&pins()).unwrap();
        unknown.pop();
        unknown.extend_from_slice(b",\"extra\":1}");
        assert!(matches!(
            NixFixedDomainPinsDataV2::decode(&unknown),
            Err(NixFixedDomainPinsDecodeErrorV2::Encoding(_)),
        ));
    }

    #[test]
    fn valid_json_with_noncanonical_bytes_remains_invalid() {
        let bytes = serde_json::to_vec(&pins()).unwrap();
        let mut spaced = vec![b' '];
        spaced.extend_from_slice(&bytes);

        assert!(matches!(
            NixFixedDomainPinsDataV2::decode(&spaced),
            Err(NixFixedDomainPinsDecodeErrorV2::Invalid),
        ));
    }

    #[test]
    fn each_intrinsic_zero_and_role_reuse_is_refused() {
        let mut candidates = Vec::new();
        let mut version = pins();
        version.version = 1;
        candidates.push(version);
        for index in 0..4 {
            let mut zero = pins();
            zero.identities[index] = 0;
            candidates.push(zero);
        }
        let mut reused_uid = pins();
        reused_uid.identities[2] = reused_uid.identities[0];
        candidates.push(reused_uid);
        let mut reused_gid = pins();
        reused_gid.identities[3] = reused_gid.identities[1];
        candidates.push(reused_gid);

        for index in 0..6 {
            let mut zero = pins();
            match index {
                0 => zero.node = NodeId::from_bytes([0; 16]),
                1 => zero.endpoint = ResourceId::from_bytes([0; 16]),
                2 => zero.domain = ResourceId::from_bytes([0; 16]),
                3 => zero.deployment = ObjectDigest::from_bytes([0; 32]),
                4 => zero.domain_commitment = ObjectDigest::from_bytes([0; 32]),
                5 => zero.disclosure = ObjectDigest::from_bytes([0; 32]),
                _ => unreachable!(),
            }
            candidates.push(zero);
        }

        for candidate in candidates {
            assert!(matches!(
                NixFixedDomainPinsDataV2::decode(&serde_json::to_vec(&candidate).unwrap()),
                Err(NixFixedDomainPinsDecodeErrorV2::Invalid),
            ));
        }
    }

    #[test]
    fn getters_project_the_complete_existing_data_contract() {
        let value = pins();

        assert_eq!(value.identities(), [811, 812, 813, 814]);
        assert_eq!(value.node(), NodeId::from_bytes([1; 16]));
        assert_eq!(value.deployment(), ObjectDigest::from_bytes([2; 32]));
        assert_eq!(value.endpoint(), ResourceId::from_bytes([3; 16]));
        assert_eq!(value.domain(), ResourceId::from_bytes([4; 16]));
        assert_eq!(value.domain_commitment(), ObjectDigest::from_bytes([5; 32]));
        assert_eq!(value.disclosure(), ObjectDigest::from_bytes([6; 32]));
    }

    #[test]
    fn the_existing_public_credential_cap_precedes_json_decoding() {
        let oversized = vec![b' '; MAXIMUM_PIN_BYTES + 1];

        assert!(matches!(
            NixFixedDomainPinsDataV2::decode(&oversized),
            Err(NixFixedDomainPinsDecodeErrorV2::Invalid),
        ));
    }
}
