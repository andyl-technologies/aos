//! Canonical approval DATA for the first administrative Source successor.
//!
//! These bytes are not a current ancestry loan, a Root receipt or funding.
//! The resident issuer derives the context from its original owners; the later
//! mutation consumer must independently authenticate its own current cut.
//!
//! ```text
//! AOSCSI02[80] = header16 | project16 | request16 | sandbox16 |
//!                validity-seconds:u32be | reserved12
//! AOSCSA02[896] = header16 | issuer-generation8 | administrative-epoch8 |
//! instance32 | project16 | request16 | sandbox16 | roles32 | floor32 |
//! completed-controller32 | publisher-generation8 | publisher-head32 |
//! publisher-revision32 | authorization-head32 | AOSPSC02[224] |
//! predecessor-tree-head32 | predecessor-lineage-head32 | predecessor-tree32 |
//! predecessor-generation8 | successor-generation8 | seven-ceilings28 |
//! reserved4 | successor-tree32 | boot16 | boottime-nanoseconds8 |
//! issued-wall-seconds8 | expires-wall-seconds8 | AOSCSI02[80] | signature64
//! AOSCSA03[1072] retains the complete AOSPSC03[400] at the same prefix;
//! subsequent fields follow that packet, with a distinct v3 signature domain.
//! ```

use aos_sandbox_protocol::source_project_authorization::parse_unverified_project_authorization_claims_v2;
use aos_sandbox_core::{ObjectDigest, ProjectId, SandboxId};
use ed25519_dalek::{Signature, VerifyingKey};

use super::genesis_profile::{SourceGenesisErrorV1, hash, take};
use aos_sandbox_core::source_tree_model::TreeLimitsV1;

/// Bounds the fixed privileged administrative intent.
pub const SOURCE_SUCCESSOR_INTENT_BYTES_V2: usize = 80;
/// Bounds the signed first-successor approval, including its exact intent.
pub const SOURCE_SUCCESSOR_APPROVAL_BYTES_V2: usize = 896;
/// Bounds the approval retaining every signed Project resource dimension.
pub const SOURCE_SUCCESSOR_APPROVAL_BYTES_V3: usize = 1072;
pub(crate) const BODY_BYTES: usize = SOURCE_SUCCESSOR_APPROVAL_BYTES_V2 - 64;
pub(crate) const RESOURCE_BODY_BYTES: usize = SOURCE_SUCCESSOR_APPROVAL_BYTES_V3 - 64;
const SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.source-administration.successor.signature.v2\0/var/lib/aos/sandbox/source-domains/source-domains-v1.journal\0";
const PACKET_DOMAIN: &[u8] = b"aos.sandbox.source-administration.successor.packet.v2\0";
const RESOURCE_SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.source-administration.successor.signature.v3\0/var/lib/aos/sandbox/source-domains/source-domains-v1.journal\0";
const RESOURCE_PACKET_DOMAIN: &[u8] = b"aos.sandbox.source-administration.successor.packet.v3\0";

/// Selects one fixed operation without supplying current heads or authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceSuccessorIntentDataV2 {
    bytes: [u8; SOURCE_SUCCESSOR_INTENT_BYTES_V2],
}

impl SourceSuccessorIntentDataV2 {
    /// Decodes the exact parentless, non-live insertion intent.
    ///
    /// # Errors
    /// Rejects other purposes/operations, reserved bytes, sentinel identities,
    /// trailing bytes or validity outside the explicit 1..=300-second policy.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SourceGenesisErrorV1> {
        if bytes.len() != SOURCE_SUCCESSOR_INTENT_BYTES_V2
            || bytes.get(..16) != Some(b"AOSCSI02\0\x02\0\0\0\x01\0\0")
            || bytes[68..] != [0; 12]
            || [16, 32, 48].into_iter().any(|offset| bytes[offset..offset + 16] == [0; 16])
            || !(1..=300).contains(&u32::from_be_bytes(take(bytes, 64)?))
        {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        Ok(Self { bytes: take(bytes, 0)? })
    }

    /// Returns the signed-input project selector, not project authority.
    pub fn project(self) -> ProjectId {
        let mut project = [0; 16];
        project.copy_from_slice(&self.bytes[16..32]);
        ProjectId::from_bytes(project)
    }

    /// Returns the original administrative request identity.
    pub fn request(self) -> [u8; 16] {
        let mut request = [0; 16];
        request.copy_from_slice(&self.bytes[32..48]);
        request
    }

    /// Returns the target logical sandbox selector.
    pub fn sandbox(self) -> SandboxId {
        let mut sandbox = [0; 16];
        sandbox.copy_from_slice(&self.bytes[48..64]);
        SandboxId::from_bytes(sandbox)
    }

    /// Returns the independently selected approval validity in seconds.
    pub fn validity_seconds(self) -> u32 {
        u32::from_be_bytes([self.bytes[64], self.bytes[65], self.bytes[66], self.bytes[67]])
    }

    /// Borrows the exact original fixed intent bytes.
    pub const fn as_bytes(&self) -> &[u8; SOURCE_SUCCESSOR_INTENT_BYTES_V2] {
        &self.bytes
    }
}

/// Retains canonical approval bytes without a live owner or mutation permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceSuccessorApprovalDataV2 {
    bytes: Vec<u8>,
}

impl SourceSuccessorApprovalDataV2 {
    /// Validates canonical DATA framing, without authenticating a signature.
    ///
    /// # Errors
    /// Rejects unsupported versions/generations, sentinel joins, changed intent,
    /// invalid ceilings, expiry arithmetic or malformed authorization DATA.
    pub fn from_record_bytes(bytes: &[u8]) -> Result<Self, SourceGenesisErrorV1> {
        if !matches!(bytes.len(), SOURCE_SUCCESSOR_APPROVAL_BYTES_V2 | SOURCE_SUCCESSOR_APPROVAL_BYTES_V3) {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        let body_bytes = bytes.len() - 64;
        validate_body(&bytes[..body_bytes])?;
        if bytes[body_bytes..] == [0; 64] {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        Ok(Self { bytes: bytes.to_vec() })
    }

    /// Verifies only the distinct successor signature against a selected key.
    ///
    /// # Errors
    /// Rejects noncanonical DATA or a bad signature. Success supplies neither
    /// key provisioning nor current Controller/Source/Root ownership.
    pub fn verify_signature(&self, key: &VerifyingKey) -> Result<(), SourceGenesisErrorV1> {
        key.verify_strict(
            &signature_message(self.body())?,
            &Signature::from_bytes(&take(&self.bytes, self.bytes.len() - 64)?),
        )
        .map_err(|_| SourceGenesisErrorV1::NonCanonical)
    }

    /// Borrows the exact saved public packet.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns a domain-separated packet commitment, not currentness.
    pub fn digest(&self) -> ObjectDigest {
        hash(if self.has_resource_authorization() { RESOURCE_PACKET_DOMAIN } else { PACKET_DOMAIN }, &self.bytes)
    }

    pub(crate) fn intent(&self) -> Result<SourceSuccessorIntentDataV2, SourceGenesisErrorV1> {
        SourceSuccessorIntentDataV2::from_bytes(&self.bytes[self.joins_offset() + 216..self.bytes.len() - 64])
    }

    pub(crate) fn epoch(&self) -> Result<u64, SourceGenesisErrorV1> {
        Ok(u64::from_be_bytes(take(&self.bytes, 24)?))
    }

    pub(crate) fn body(&self) -> &[u8] {
        &self.bytes[..self.bytes.len() - 64]
    }

    pub(crate) fn has_resource_authorization(&self) -> bool {
        self.bytes.len() == SOURCE_SUCCESSOR_APPROVAL_BYTES_V3
    }

    pub(crate) fn authorization_packet(&self) -> &[u8] {
        &self.bytes[312..self.joins_offset()]
    }

    pub(crate) fn joins_offset(&self) -> usize {
        self.bytes.len() - 360
    }

    pub(crate) fn old_tree_head(&self) -> ObjectDigest {
        super::genesis_profile::digest_at(&self.bytes, self.joins_offset())
    }

    pub(crate) fn old_lineage_head(&self) -> ObjectDigest {
        super::genesis_profile::digest_at(&self.bytes, self.joins_offset() + 32)
    }

    pub(crate) fn old_tree_commit(&self) -> ObjectDigest {
        super::genesis_profile::digest_at(&self.bytes, self.joins_offset() + 64)
    }

    pub(crate) fn next_tree_commit(&self) -> ObjectDigest {
        super::genesis_profile::digest_at(&self.bytes, self.joins_offset() + 144)
    }

    pub(crate) fn boot(&self) -> Result<[u8; 16], SourceGenesisErrorV1> {
        take(&self.bytes, self.joins_offset() + 176)
    }

    pub(crate) fn issued_boottime(&self) -> Result<u64, SourceGenesisErrorV1> {
        Ok(u64::from_be_bytes(take(&self.bytes, self.joins_offset() + 192)?))
    }

    pub(crate) fn issued_wall(&self) -> Result<u64, SourceGenesisErrorV1> {
        Ok(u64::from_be_bytes(take(&self.bytes, self.joins_offset() + 200)?))
    }

    pub(crate) fn expires_wall(&self) -> Result<u64, SourceGenesisErrorV1> {
        Ok(u64::from_be_bytes(take(&self.bytes, self.joins_offset() + 208)?))
    }
}

pub(crate) fn signature_message(body: &[u8]) -> Result<Vec<u8>, SourceGenesisErrorV1> {
    validate_body(body)?;
    let domain = if body.len() == RESOURCE_BODY_BYTES { RESOURCE_SIGNATURE_DOMAIN } else { SIGNATURE_DOMAIN };
    let mut message = Vec::with_capacity(domain.len() + body.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(body);
    Ok(message)
}

pub(crate) fn validate_body(body: &[u8]) -> Result<(), SourceGenesisErrorV1> {
    let resource = body.len() == RESOURCE_BODY_BYTES;
    let header: &[u8; 16] = if resource { b"AOSCSA03\0\x03\0\0\0\0\0\0" } else { b"AOSCSA02\0\x02\0\0\0\0\0\0" };
    if (!resource && body.len() != BODY_BYTES) || body.get(..16) != Some(header.as_slice()) {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    let joins = body.len() - 296;
    if body[joins + 96..joins + 104] != 1_u64.to_be_bytes()
        || body[joins + 104..joins + 112] != 2_u64.to_be_bytes()
        || body[joins + 140..joins + 144] != [0; 4]
        || [16, 24, 208, joins + 192, joins + 200, joins + 208].into_iter().any(|offset| body[offset..offset + 8] == [0; 8])
        || [32, 112, 144, 176, 216, 248, 280, joins, joins + 32, joins + 64, joins + 144]
            .into_iter().any(|offset| body[offset..offset + 32] == [0; 32])
        || body[joins + 176..joins + 192] == [0; 16]
    {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    let intent = SourceSuccessorIntentDataV2::from_bytes(&body[joins + 216..])?;
    if body[64..80] != intent.project().as_bytes()[..]
        || body[80..96] != intent.request()
        || body[96..112] != intent.sandbox().as_bytes()[..]
        || u64::from_be_bytes(take(body, joins + 200)?)
            .checked_add(u64::from(intent.validity_seconds()))
            != Some(u64::from_be_bytes(take(body, joins + 208)?))
    {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    let authorization = parse_unverified_project_authorization_claims_v2(
        &body[312..joins],
    )?;
    if authorization.project() != intent.project()
        || authorization.publisher_generation() != u64::from_be_bytes(take(body, 208)?)
        || authorization.publisher_head_digest().as_bytes() != &body[216..248]
        || authorization.publisher_revision_digest().as_bytes() != &body[248..280]
        || authorization.limits() != limits(body, joins)?
        || authorization.resource_envelope().is_some() != resource
    {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    Ok(())
}

fn limits(body: &[u8], joins: usize) -> Result<TreeLimitsV1, SourceGenesisErrorV1> {
    let mut values = [0_usize; 7];
    for (index, value) in values.iter_mut().enumerate() {
        *value = usize::try_from(u32::from_be_bytes(take(body, joins + 112 + index * 4)?))
            .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
    }
    TreeLimitsV1::new(values[0], values[1], values[2], values[3], values[4], values[5], values[6])
        .map_err(|_| SourceGenesisErrorV1::NonCanonical)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    // Structural test DATA only. The embedded AOSPSC02 is not provisioned,
    // current or signature-authenticated; no test manufactures a live owner.
    pub(crate) fn approval_fixture() -> (SourceSuccessorApprovalDataV2, SigningKey) {
        let key = SigningKey::from_bytes(&[23; 32]);
        let mut body = [0; BODY_BYTES];
        body[..16].copy_from_slice(b"AOSCSA02\0\x02\0\0\0\0\0\0");
        body[16..24].copy_from_slice(&4_u64.to_be_bytes());
        body[24..32].copy_from_slice(&6_u64.to_be_bytes());
        body[32..64].fill(1);
        body[64..112].fill(1);
        for (index, offset) in [112, 144, 176, 216, 248, 280, 536, 568, 600, 680].into_iter().enumerate() {
            body[offset..offset + 32].fill(index as u8 + 2);
        }
        body[208..216].copy_from_slice(&2_u64.to_be_bytes());
        let mut authorization = [1; 224];
        authorization[..12].fill(0);
        authorization[..8].copy_from_slice(b"AOSPSC02");
        authorization[8..10].copy_from_slice(&2_u16.to_be_bytes());
        authorization[12..20].copy_from_slice(&4_u64.to_be_bytes());
        authorization[20..36].fill(1);
        authorization[36..44].copy_from_slice(&2_u64.to_be_bytes());
        authorization[44..76].copy_from_slice(&body[216..248]);
        authorization[76..108].copy_from_slice(&body[248..280]);
        authorization[124..132].copy_from_slice(&5_u64.to_be_bytes());
        for (index, ceiling) in [1_u32, 8, 7, 6, 5, 4, 3].into_iter().enumerate() {
            authorization[132 + index * 4..136 + index * 4].copy_from_slice(&ceiling.to_be_bytes());
            body[648 + index * 4..652 + index * 4].copy_from_slice(&ceiling.to_be_bytes());
        }
        body[312..536].copy_from_slice(&authorization);
        body[632..640].copy_from_slice(&1_u64.to_be_bytes());
        body[640..648].copy_from_slice(&2_u64.to_be_bytes());
        body[712..728].fill(12);
        body[728..736].copy_from_slice(&1_000_000_000_u64.to_be_bytes());
        body[736..744].copy_from_slice(&1_000_u64.to_be_bytes());
        body[744..752].copy_from_slice(&1_300_u64.to_be_bytes());
        body[752..832].copy_from_slice(&intent());
        let mut bytes = [0; SOURCE_SUCCESSOR_APPROVAL_BYTES_V2];
        bytes[..BODY_BYTES].copy_from_slice(&body);
        bytes[BODY_BYTES..].copy_from_slice(&key.sign(&signature_message(&body).unwrap()).to_bytes());
        (SourceSuccessorApprovalDataV2::from_record_bytes(&bytes).unwrap(), key)
    }

    fn intent() -> [u8; 80] {
        let mut bytes = [0; 80];
        bytes[..16].copy_from_slice(b"AOSCSI02\0\x02\0\0\0\x01\0\0");
        bytes[16..64].fill(1);
        bytes[64..68].copy_from_slice(&300_u32.to_be_bytes());
        bytes
    }

    #[test]
    fn intent_roundtrip_is_only_fixed_operation_data() {
        let bytes = intent();
        let parsed = SourceSuccessorIntentDataV2::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.as_bytes(), &bytes);
        assert_eq!(parsed.validity_seconds(), 300);
    }

    #[test]
    fn intent_rejects_every_reserved_or_identity_region_and_wrong_purpose() {
        for offset in [0, 8, 10, 12, 14, 68, 79] {
            let mut bytes = intent();
            bytes[offset] ^= 1;
            assert!(SourceSuccessorIntentDataV2::from_bytes(&bytes).is_err(), "{offset}");
        }
        for offset in [16, 32, 48] {
            let mut bytes = intent();
            bytes[offset..offset + 16].fill(0);
            assert!(SourceSuccessorIntentDataV2::from_bytes(&bytes).is_err());
        }
        for validity in [0_u32, 301, u32::MAX] {
            let mut bytes = intent();
            bytes[64..68].copy_from_slice(&validity.to_be_bytes());
            assert!(SourceSuccessorIntentDataV2::from_bytes(&bytes).is_err());
        }
        assert!(SourceSuccessorIntentDataV2::from_bytes(&intent()[..79]).is_err());
    }

    #[test]
    fn successor_signature_is_distinct_and_never_accepts_raw_body_signing() {
        let (packet, key) = approval_fixture();

        assert!(packet.verify_signature(&key.verifying_key()).is_ok());
        assert!(packet.verify_signature(&SigningKey::from_bytes(&[24; 32]).verifying_key()).is_err());
        let mut wrong = packet.as_bytes().to_vec();
        wrong[BODY_BYTES..].copy_from_slice(&key.sign(packet.body()).to_bytes());
        let wrong = SourceSuccessorApprovalDataV2::from_record_bytes(&wrong).unwrap();
        assert!(wrong.verify_signature(&key.verifying_key()).is_err());
    }

    #[test]
    fn approval_rejects_version_generation_shape_expiry_and_embedded_crosslinks() {
        let (packet, _) = approval_fixture();
        for offset in [0, 8, 10, 632, 640, 676, 752, 764] {
            let mut bytes = packet.as_bytes().to_vec();
            bytes[offset] ^= 1;
            assert!(SourceSuccessorApprovalDataV2::from_record_bytes(&bytes).is_err(), "offset {offset}");
        }
        for offset in [16, 24, 32, 112, 144, 176, 208, 216, 248, 280, 536, 568, 600, 680, 712, 728, 736] {
            let mut bytes = packet.as_bytes().to_vec();
            let width = if [16, 24, 208, 728, 736].contains(&offset) { 8 } else if offset == 712 { 16 } else { 32 };
            bytes[offset..offset + width].fill(0);
            assert!(SourceSuccessorApprovalDataV2::from_record_bytes(&bytes).is_err(), "offset {offset}");
        }
        let mut mismatch = packet.as_bytes().to_vec();
        mismatch[216] ^= 1;
        assert!(SourceSuccessorApprovalDataV2::from_record_bytes(&mismatch).is_err());
        let mut expiry = packet.as_bytes().to_vec();
        expiry[744..752].copy_from_slice(&1_301_u64.to_be_bytes());
        assert!(SourceSuccessorApprovalDataV2::from_record_bytes(&expiry).is_err());
        let mut limits = packet.as_bytes().to_vec();
        limits[648..652].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(SourceSuccessorApprovalDataV2::from_record_bytes(&limits).is_err());
        assert!(SourceSuccessorApprovalDataV2::from_record_bytes(&packet.as_bytes()[..895]).is_err());
        let trailing = [packet.as_bytes(), &[0]].concat();
        assert!(SourceSuccessorApprovalDataV2::from_record_bytes(&trailing).is_err());
    }
}
