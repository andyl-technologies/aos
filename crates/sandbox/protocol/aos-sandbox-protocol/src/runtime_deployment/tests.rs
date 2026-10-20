//! UNRUN strict deployment-wire and purpose-separation vectors.

use ed25519_dalek::{Signer as _, SigningKey};

use super::*;

fn genesis() -> DeploymentGenesisV1 {
    let mut name = [3; 34];
    name[..2].copy_from_slice(&0x000b_u16.to_be_bytes());
    DeploymentGenesisV1 {
        node: [1; 16],
        deployment: [2; 16],
        signer: SigningKey::from_bytes(&[4; 32]).verifying_key().to_bytes(),
        nv_name: name,
        salt_name: name,
        empty_ledger_anchor: [5; 32],
        publisher_profile: [6; 32],
        nspawn_digest: [7; 32],
        root_digest: [8; 32],
        supervisor_filter: [9; 32],
        payload_filter: [10; 32],
        mac_policy: [11; 32],
        credential_contract: [12; 32],
        uid_start: 100_000,
        uid_count: 65_536,
    }
}

fn receipt(key: &SigningKey) -> DeploymentReceiptV1 {
    let mut receipt = DeploymentReceiptV1 {
        query: DeploymentQueryV1 {
            nonce: [13; 32],
            kernel_boot: [14; 16],
            genesis_digest: genesis().digest().unwrap(),
        },
        generation: 1,
        monotonic_epoch: 2,
        current_nv: [15; 32],
        prepared_head: [16; 32],
        specimen_profile: [17; 32],
        signature: [0; 64],
    };
    receipt.signature = key.sign(&receipt.signing_bytes().unwrap()).to_bytes();
    receipt
}

#[test]
fn closed_records_round_trip_without_runtime_or_guest_identity() {
    let genesis = genesis();
    let bytes = genesis.encode().unwrap();
    assert_eq!(bytes.len(), DEPLOYMENT_GENESIS_BYTES_V1);
    assert_eq!(DeploymentGenesisV1::decode(&bytes).unwrap(), genesis);

    let key = SigningKey::from_bytes(&[4; 32]);
    let receipt = receipt(&key);
    let bytes = receipt.encode().unwrap();
    assert_eq!(bytes.len(), DEPLOYMENT_RECEIPT_BYTES_V1);
    assert_eq!(DeploymentReceiptV1::decode(&bytes).unwrap(), receipt);
    receipt.verify(receipt.query, &key.verifying_key()).unwrap();
    assert_eq!(DEPLOYMENT_NV_INDEX_V1, 0x0180_a055);
    assert_eq!(DEPLOYMENT_SALT_HANDLE_V1, 0x8100_a055);
    assert_ne!(DEPLOYMENT_NV_INDEX_V1, 0x0180_a046);
    assert_ne!(DEPLOYMENT_NV_INDEX_V1, 0x0180_a053);
}

#[test]
fn rejects_incomplete_noncanonical_genesis() {
    let original = genesis().encode().unwrap();
    for (offset, length) in [
        (8, 16), (24, 16), (40, 32), (72, 34), (106, 34),
        (140, 32), (172, 32), (204, 32), (236, 32), (268, 32),
        (300, 32), (332, 32), (364, 32), (396, 4), (400, 4),
    ] {
        let mut bytes = original;
        bytes[offset..offset + length].fill(0);
        assert!(DeploymentGenesisV1::decode(&bytes).is_err(), "offset {offset}");
    }
    assert!(DeploymentGenesisV1::decode(&original[..original.len() - 1]).is_err());
    assert!(DeploymentGenesisV1::decode(&[original.as_slice(), &[0]].concat()).is_err());
    let mut overflowing = genesis();
    overflowing.uid_start = u32::MAX;
    assert!(overflowing.encode().is_err());
}

#[test]
fn receipt_binds_every_actual_currentness_field_and_original_query() {
    let key = SigningKey::from_bytes(&[4; 32]);
    let original = receipt(&key);
    let bytes = original.encode().unwrap();
    for offset in [16, 48, 64, 96, 104, 112, 144, 176, 208] {
        let mut changed = bytes;
        changed[offset] ^= 1;
        let decoded = DeploymentReceiptV1::decode(&changed);
        assert!(decoded.is_err() || decoded.unwrap().verify(original.query, &key.verifying_key()).is_err());
    }
    let mut fresh_query = original.query;
    fresh_query.nonce = [18; 32];
    assert!(original.verify(fresh_query, &key.verifying_key()).is_err());
    assert!(original.verify(original.query, &SigningKey::from_bytes(&[19; 32]).verifying_key()).is_err());
}
