//! Structural local ownership format tests without trusted-file or live authority claims.

use aos_sandbox_core::{
    AssignmentEpoch, DesiredGeneration, IncarnationId, LeaseAssignment, NodeId,
    ObjectDigest, SandboxId,
};

use super::*;

const BOOTSTRAP_DOMAIN: &[u8] = b"aos.sandbox.multi-node.ownership-bootstrap.v1\0";
const RESPONSE_DOMAIN: &[u8] = b"aos.sandbox.multi-node.ownership-response.v1\0";
const ARTIFACT_LIMITS: [usize; 4] = [64 * 1024, 64 * 1024, 1024, 64 * 1024];

fn claim() -> OwnershipClaimV1 {
    OwnershipClaimV1::acquire(
        [1; 16],
        LeaseAssignment::new(
            SandboxId::from_bytes([2; 16]),
            IncarnationId::from_bytes([3; 16]),
            AssignmentEpoch::new(4),
            ObjectDigest::from_bytes([5; 32]),
        ).unwrap(),
        DesiredGeneration::new(6),
        NodeId::from_bytes([7; 16]),
        100,
    ).unwrap()
}

fn seal(domain: &[u8], mut payload: Vec<u8>) -> Vec<u8> {
    let checksum = Sha256::new().chain_update(domain).chain_update(&payload).finalize();
    payload.extend_from_slice(&checksum);
    payload
}

fn bootstrap_payload(policy: &[u8], key: [u8; 32]) -> Vec<u8> {
    let mut payload = b"AOSMOL01".to_vec();
    payload.extend_from_slice(&u32::try_from(policy.len()).unwrap().to_be_bytes());
    payload.extend_from_slice(policy);
    payload.extend_from_slice(&key);
    payload
}

fn artifacts() -> [Vec<u8>; 4] {
    [vec![1], vec![2; 2], vec![3; 3], vec![4; 4]]
}

fn response_payload(claim: &OwnershipClaimV1, fields: &[Vec<u8>; 4]) -> (Vec<u8>, [usize; 4]) {
    let mut payload = b"AOSMOI01".to_vec();
    payload.extend_from_slice(claim.request_id());
    payload.extend_from_slice(claim.digest().as_bytes());
    let mut offsets = [0; 4];
    for (index, field) in fields.iter().enumerate() {
        offsets[index] = payload.len();
        payload.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
        payload.extend_from_slice(field);
    }
    (payload, offsets)
}

#[test]
fn bootstrap_returns_exact_raw_fields_at_the_policy_limit() {
    for length in [1, 64 * 1024] {
        let policy = vec![11; length];
        let key = [12; 32];
        let bytes = seal(BOOTSTRAP_DOMAIN, bootstrap_payload(&policy, key));

        let (decoded_policy, decoded_key) = decode_bootstrap(&bytes).unwrap();

        assert_eq!(decoded_policy, policy);
        assert_eq!(decoded_key, key);
    }
}

#[test]
fn bootstrap_rejects_resealed_short_prefixes_lengths_and_trailing_bytes() {
    let payload = bootstrap_payload(&[11; 3], [12; 32]);
    let mut malformed = (0..payload.len()).map(|length| payload[..length].to_vec()).collect::<Vec<_>>();
    for length in [0, 64 * 1024 + 1, u32::MAX] {
        let mut changed = payload.clone();
        changed[8..12].copy_from_slice(&length.to_be_bytes());
        malformed.push(changed);
    }
    let mut trailing = payload.clone();
    trailing.push(0);
    malformed.push(trailing);
    let mut bad_magic = payload;
    bad_magic[0] ^= 1;
    malformed.push(bad_magic);

    let mut bad_checksum = seal(BOOTSTRAP_DOMAIN, bootstrap_payload(&[11; 3], [12; 32]));
    *bad_checksum.last_mut().unwrap() ^= 1;
    assert!(matches!(decode_bootstrap(&bad_checksum), Err(ProtectedLeaseAuthorityErrorV1::Authority(super::super::DurableOwnershipAuthorityError::CorruptState))));

    for payload in malformed {
        assert!(matches!(
            decode_bootstrap(&seal(BOOTSTRAP_DOMAIN, payload)),
            Err(ProtectedLeaseAuthorityErrorV1::Authority(super::super::DurableOwnershipAuthorityError::CorruptState))
        ));
    }
}

#[test]
fn response_preserves_all_four_exact_artifacts_at_each_field_limit() {
    let claim = claim();
    for (index, limit) in ARTIFACT_LIMITS.into_iter().enumerate() {
        let mut fields = artifacts();
        fields[index] = vec![13; limit];
        let (payload, _) = response_payload(&claim, &fields);

        let response = decode_fixed_issuer_response(&seal(RESPONSE_DOMAIN, payload), &claim).unwrap();

        assert_eq!([response.lease(), response.signature(), response.receipt(), response.receipt_signature()], fields.each_ref().map(Vec::as_slice));
    }
}

#[test]
fn response_rejects_resealed_short_prefixes_lengths_and_trailing_bytes() {
    let claim = claim();
    let (payload, offsets) = response_payload(&claim, &artifacts());
    let mut malformed = (0..payload.len()).map(|length| payload[..length].to_vec()).collect::<Vec<_>>();
    for (index, limit) in ARTIFACT_LIMITS.into_iter().enumerate() {
        for length in [0, u32::try_from(limit + 1).unwrap(), u32::MAX] {
            let mut changed = payload.clone();
            changed[offsets[index]..offsets[index] + 4].copy_from_slice(&length.to_be_bytes());
            malformed.push(changed);
        }
    }
    let mut trailing = payload;
    trailing.push(0);
    malformed.push(trailing);

    for payload in malformed {
        assert_eq!(decode_fixed_issuer_response(&seal(RESPONSE_DOMAIN, payload), &claim).unwrap_err(), OwnershipAuthorityError::Unavailable);
    }
}

#[test]
fn response_checks_checksum_then_context_before_artifact_lengths() {
    let claim = claim();
    let (payload, offsets) = response_payload(&claim, &artifacts());
    for mismatch in [8, 24] {
        let mut changed = payload.clone();
        changed[mismatch] ^= 1;
        changed[offsets[0]..offsets[0] + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        let valid_checksum = seal(RESPONSE_DOMAIN, changed);
        let mut bad_checksum = valid_checksum.clone();
        *bad_checksum.last_mut().unwrap() ^= 1;

        assert_eq!(decode_fixed_issuer_response(&bad_checksum, &claim).unwrap_err(), OwnershipAuthorityError::Unavailable);
        assert_eq!(decode_fixed_issuer_response(&valid_checksum, &claim).unwrap_err(), OwnershipAuthorityError::IdempotencyConflict);
    }
}
