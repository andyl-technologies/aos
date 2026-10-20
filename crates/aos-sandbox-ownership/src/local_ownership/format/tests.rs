//! Structural local ownership format tests without trusted-file or live authority claims.

use super::*;
use sha2::{Digest as _, Sha256};

const BOOTSTRAP_DOMAIN: &[u8] = b"aos.sandbox.multi-node.ownership-bootstrap.v1\0";

fn seal(domain: &[u8], mut payload: Vec<u8>) -> Vec<u8> {
    let checksum = Sha256::new()
        .chain_update(domain)
        .chain_update(&payload)
        .finalize();
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
    let mut malformed = (0..payload.len())
        .map(|length| payload[..length].to_vec())
        .collect::<Vec<_>>();
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
    assert!(matches!(
        decode_bootstrap(&bad_checksum),
        Err(ProtectedLeaseAuthorityErrorV1::Authority(
            super::super::DurableOwnershipAuthorityError::CorruptState
        ))
    ));

    for payload in malformed {
        assert!(matches!(
            decode_bootstrap(&seal(BOOTSTRAP_DOMAIN, payload)),
            Err(ProtectedLeaseAuthorityErrorV1::Authority(
                super::super::DurableOwnershipAuthorityError::CorruptState
            ))
        ));
    }
}
