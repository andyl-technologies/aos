//! Canonical fixed Root Environment boot-clock evidence records.
//!
//! The record is historical DATA. Only the held policy/deployment owner may
//! append and lend it through its actual protected native interval.
//!
//! ```text
//! AOSENVA1 | version:u16be | reserved:6 | boot:32 | monotonic:u64be |
//! authenticated-at:u64be | valid-until:u64be | count:u32be |
//! predecessor-boots[count]:32 | sha256(domain || preceding-bytes):32
//! ```

use aos_sandbox_core::{ObjectDigest, bounded_codec::BoundedReader};
use sha2::{Digest as _, Sha256};
use super::EnvironmentProtectedEvidenceErrorV1;
use crate::environment::EnvironmentLeaseTimeV1;

pub(super) const EVIDENCE_MAGIC: &[u8; 8] = b"AOSENVA1";
pub(super) const EVIDENCE_VERSION: u16 = 1;
pub(super) const EVIDENCE_DOMAIN: &[u8] = b"aos.sandbox.environment.fixed-protected-evidence.v1\0";
pub(super) const MAXIMUM_PREDECESSOR_BOOTS: usize = 262_144;
pub(super) const FIXED_PREFIX_BYTES: usize = 8 + 2 + 6 + 32 + 8 + 8 + 8 + 4;
pub(super) const DIGEST_BYTES: usize = 32;

pub(super) struct DecodedEnvironmentEvidenceV1 {
    pub(super) current_boot: ObjectDigest,
    pub(super) current_time: EnvironmentLeaseTimeV1,
    pub(super) authenticated_at_unix_seconds: u64,
    pub(super) valid_until_unix_seconds: u64,
    pub(super) predecessor_boots: Vec<ObjectDigest>,
    pub(super) attestation: ObjectDigest,
}

pub(super) fn decode_evidence(
    encoded: &[u8],
) -> Result<DecodedEnvironmentEvidenceV1, EnvironmentProtectedEvidenceErrorV1> {
    if encoded.len() < FIXED_PREFIX_BYTES + DIGEST_BYTES {
        return Err(EnvironmentProtectedEvidenceErrorV1::InvalidEvidence);
    }
    let (body, stored_digest) = encoded.split_at(encoded.len() - DIGEST_BYTES);
    let expected_digest = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(EVIDENCE_DOMAIN)
            .chain_update(body)
            .finalize()
            .into(),
    );
    if stored_digest != expected_digest.as_bytes() {
        return Err(EnvironmentProtectedEvidenceErrorV1::InvalidEvidence);
    }

    let mut cursor = BoundedReader::new(body, |_| {
        EnvironmentProtectedEvidenceErrorV1::InvalidEvidence
    });
    if cursor.array::<8>()? != *EVIDENCE_MAGIC
        || u16::from_be_bytes(cursor.array::<2>()?) != EVIDENCE_VERSION
        || cursor.array::<6>()? != [0; 6]
    {
        return Err(EnvironmentProtectedEvidenceErrorV1::InvalidEvidence);
    }
    let current_boot = ObjectDigest::from_bytes(cursor.array::<32>()?);
    let current_time = EnvironmentLeaseTimeV1::new(u64::from_be_bytes(cursor.array::<8>()?))
        .map_err(|_| EnvironmentProtectedEvidenceErrorV1::InvalidEvidence)?;
    let authenticated_at_unix_seconds = u64::from_be_bytes(cursor.array::<8>()?);
    let valid_until_unix_seconds = u64::from_be_bytes(cursor.array::<8>()?);
    let predecessor_count = usize::try_from(u32::from_be_bytes(cursor.array::<4>()?))
        .map_err(|_| EnvironmentProtectedEvidenceErrorV1::InvalidEvidence)?;
    if current_boot.as_bytes() == &[0; 32] || predecessor_count > MAXIMUM_PREDECESSOR_BOOTS {
        return Err(EnvironmentProtectedEvidenceErrorV1::InvalidEvidence);
    }
    let mut predecessor_boots = Vec::new();
    predecessor_boots
        .try_reserve_exact(predecessor_count)
        .map_err(|_| EnvironmentProtectedEvidenceErrorV1::InvalidEvidence)?;
    for _ in 0..predecessor_count {
        predecessor_boots.push(ObjectDigest::from_bytes(cursor.array::<32>()?));
    }
    if !cursor.is_empty()
        || predecessor_boots
            .iter()
            .any(|boot| boot.as_bytes() == &[0; 32] || boot == &current_boot)
        || !predecessor_boots.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(EnvironmentProtectedEvidenceErrorV1::InvalidEvidence);
    }
    Ok(DecodedEnvironmentEvidenceV1 {
        current_boot,
        current_time,
        authenticated_at_unix_seconds,
        valid_until_unix_seconds,
        predecessor_boots,
        attestation: expected_digest,
    })
}

/// Encodes the same canonical Root record validated by the existing decoder.
pub(super) fn encode_evidence_v1(
    current_boot: ObjectDigest,
    current_time: EnvironmentLeaseTimeV1,
    authenticated_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
    predecessor_boots: &[ObjectDigest],
) -> Result<Vec<u8>, EnvironmentProtectedEvidenceErrorV1> {
    let invalid = || EnvironmentProtectedEvidenceErrorV1::InvalidEvidence;
    if current_boot.as_bytes() == &[0; 32]
        || authenticated_at_unix_seconds == 0
        || valid_until_unix_seconds <= authenticated_at_unix_seconds
        || predecessor_boots.len() > MAXIMUM_PREDECESSOR_BOOTS
        || predecessor_boots.iter().any(|boot| boot.as_bytes() == &[0; 32] || *boot == current_boot)
        || !predecessor_boots.windows(2).all(|pair| pair[0] < pair[1])
    { return Err(invalid()); }
    let capacity = predecessor_boots.len().checked_mul(32)
        .and_then(|bytes| bytes.checked_add(FIXED_PREFIX_BYTES + DIGEST_BYTES))
        .ok_or_else(invalid)?;
    let mut encoded = Vec::new();
    encoded.try_reserve_exact(capacity).map_err(|_| invalid())?;
    encoded.extend_from_slice(EVIDENCE_MAGIC);
    encoded.extend_from_slice(&EVIDENCE_VERSION.to_be_bytes());
    encoded.extend_from_slice(&[0; 6]);
    encoded.extend_from_slice(current_boot.as_bytes());
    encoded.extend_from_slice(&current_time.get().to_be_bytes());
    encoded.extend_from_slice(&authenticated_at_unix_seconds.to_be_bytes());
    encoded.extend_from_slice(&valid_until_unix_seconds.to_be_bytes());
    encoded.extend_from_slice(&u32::try_from(predecessor_boots.len()).map_err(|_| invalid())?.to_be_bytes());
    for boot in predecessor_boots { encoded.extend_from_slice(boot.as_bytes()); }
    let digest = Sha256::new().chain_update(EVIDENCE_DOMAIN).chain_update(&encoded).finalize();
    encoded.extend_from_slice(&digest);
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issued_record_round_trips_the_existing_decoder_and_rejects_boot_rebinding() {
        let boot = ObjectDigest::from_bytes([3; 32]);
        let previous = [ObjectDigest::from_bytes([1; 32]), ObjectDigest::from_bytes([2; 32])];
        let encoded = encode_evidence_v1(boot, EnvironmentLeaseTimeV1::new(100).unwrap(),
            200, 300, &previous).unwrap();

        let decoded = decode_evidence(&encoded).unwrap();
        assert_eq!(decoded.current_boot, boot);
        assert_eq!(decoded.predecessor_boots, previous);
        assert_eq!(decoded.current_time.get(), 100);
        assert_eq!(decoded.valid_until_unix_seconds, 300);

        let mut changed = encoded;
        changed[16] ^= 1;
        assert!(decode_evidence(&changed).is_err());
        assert!(encode_evidence_v1(boot, EnvironmentLeaseTimeV1::new(100).unwrap(),
            200, 300, &[boot]).is_err());
    }

    #[test]
    fn issuer_never_converts_missing_or_expired_policy_time_into_a_validity_window() {
        let boot = ObjectDigest::from_bytes([3; 32]);
        let time = EnvironmentLeaseTimeV1::new(100).unwrap();
        assert!(encode_evidence_v1(boot, time, 0, 300, &[]).is_err());
        assert!(encode_evidence_v1(boot, time, 300, 300, &[]).is_err());
        assert!(encode_evidence_v1(boot, time, 301, 300, &[]).is_err());
        assert!(encode_evidence_v1(boot, time, 200, 300,
            &[ObjectDigest::from_bytes([2; 32]), ObjectDigest::from_bytes([1; 32])]).is_err());
    }
}
