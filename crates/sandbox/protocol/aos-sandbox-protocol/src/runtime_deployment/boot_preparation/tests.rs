//! Hostile full-preimage tests for the new comparison-only boot codecs.

use super::*;
use ed25519_dalek::{Signer as _, SigningKey};

fn signed_fixture() -> (
    DeploymentGenesisV1,
    [u8; 468],
    SignedBootPreparationPurposeDataV1,
    SigningKey,
) {
    let provisioner = SigningKey::from_bytes(&[1; 32]);
    let publisher = SigningKey::from_bytes(&[2; 32]);
    let mut name = [3; 34];
    name[..2].copy_from_slice(&0x000b_u16.to_be_bytes());
    let genesis = DeploymentGenesisV1 {
        node: [4; 16],
        deployment: [5; 16],
        signer: publisher.verifying_key().to_bytes(),
        nv_name: name,
        salt_name: name,
        empty_ledger_anchor: [6; 32],
        publisher_profile: [7; 32],
        nspawn_digest: [8; 32],
        root_digest: [9; 32],
        supervisor_filter: [10; 32],
        payload_filter: [11; 32],
        mac_policy: [12; 32],
        credential_contract: [13; 32],
        uid_start: 65_536,
        uid_count: 65_536,
    };
    let mut signed = [0; 468];
    signed[..404].copy_from_slice(&genesis.encode().unwrap());
    let mut message = b"aos.runtime-deployment.genesis.v1\0".to_vec();
    message.extend_from_slice(&signed[..404]);
    signed[404..].copy_from_slice(&provisioner.sign(&message).to_bytes());
    let fields = BootPreparationPurposeDataV1 {
        node: genesis.node,
        deployment: genesis.deployment,
        signed_genesis_digest: Sha256::digest(signed).into(),
        publisher: genesis.signer,
        publisher_profile: genesis.publisher_profile,
        source_contract: boot_preparation_source_contract_data_v1(),
        program_contract: boot_preparation_program_contract_data_v1([14; 32]),
        credential_contract: boot_preparation_credential_contract_data_v1(),
        directory_contract: boot_preparation_directory_contract_data_v1(),
    };
    let mut bytes = [0; BOOT_PREPARATION_PURPOSE_BYTES_V1];
    bytes[..BOOT_PREPARATION_PURPOSE_BODY_BYTES_V1]
        .copy_from_slice(&fields.encode_body_v1().unwrap());
    bytes[BOOT_PREPARATION_PURPOSE_BODY_BYTES_V1..].copy_from_slice(
        &provisioner
            .sign(&fields.signing_bytes_v1().unwrap())
            .to_bytes(),
    );
    let purpose = SignedBootPreparationPurposeDataV1::verify_v1(
        &bytes,
        &signed,
        &genesis,
        &provisioner.verifying_key(),
    )
    .unwrap();
    (genesis, signed, purpose, publisher)
}

fn record_fields(purpose: &SignedBootPreparationPurposeDataV1) -> BootPreparationRecordDataV1 {
    let p = purpose.fields_v1();
    BootPreparationRecordDataV1 {
        purpose: purpose.digest_v1(),
        signed_genesis_digest: p.signed_genesis_digest,
        node: p.node,
        deployment: p.deployment,
        publisher_generation: 2,
        boot: [15; 16],
        publisher_invocation: [16; 16],
        previous_record: [0; 32],
        source_contract: p.source_contract,
        publisher_profile: p.publisher_profile,
        nspawn_path_digest: [17; 32],
        nspawn_device: 18,
        nspawn_inode: 19,
        nspawn_digest: [8; 32],
        pid1_digest: [20; 32],
        hostd_digest: [21; 32],
        inspector_digest: [22; 32],
        probe_digest: [23; 32],
        mac_policy_digest: [12; 32],
        supervisor_profile_digest: [24; 32],
        payload_filter_digest: [25; 32],
        artifact_digest: [26; 32],
        predecessor_ordinal: 1,
        predecessor_sequence: 4,
        predecessor_head: [27; 32],
        predecessor_nv: [28; 32],
    }
}

fn signed_record(
    purpose: &SignedBootPreparationPurposeDataV1,
    signer: &SigningKey,
) -> SignedBootPreparationRecordDataV1 {
    let fields = record_fields(purpose);
    let mut bytes = [0; BOOT_PREPARATION_RECORD_BYTES_V1];
    bytes[..BOOT_PREPARATION_RECORD_BODY_BYTES_V1]
        .copy_from_slice(&fields.encode_body_v1().unwrap());
    bytes[BOOT_PREPARATION_RECORD_BODY_BYTES_V1..]
        .copy_from_slice(&signer.sign(&fields.signing_bytes_v1().unwrap()).to_bytes());
    SignedBootPreparationRecordDataV1::verify_v1(&bytes, purpose).unwrap()
}

fn completion_bytes(
    record: &SignedBootPreparationRecordDataV1,
    signer: &SigningKey,
) -> [u8; BOOT_PREPARATION_COMPLETION_BYTES_V1] {
    let fields = BootPreparationCompletionFieldsDataV1 {
        target_head: [29; 32],
        target_nv: [30; 32],
        native_transaction: boot_preparation_transaction_data_v1(record.fields_v1()).unwrap(),
    };
    let mut bytes = [0; BOOT_PREPARATION_COMPLETION_BYTES_V1];
    bytes[..BOOT_PREPARATION_COMPLETION_BODY_BYTES_V1]
        .copy_from_slice(&fields.encode_body_v1(record).unwrap());
    bytes[BOOT_PREPARATION_COMPLETION_BODY_BYTES_V1..].copy_from_slice(
        &signer
            .sign(&fields.signing_bytes_v1(record).unwrap())
            .to_bytes(),
    );
    bytes
}

#[test]
fn full_completion_preserves_record_invocation_and_actual_first_successor_relation() {
    let (_, _, purpose, signer) = signed_fixture();
    let record = signed_record(&purpose, &signer);
    let bytes = completion_bytes(&record, &signer);

    let receipt = SignedBootPreparationCompletionDataV1::verify_v1(&bytes, &purpose).unwrap();

    assert_eq!(receipt.record_v1().bytes_v1(), record.bytes_v1());
    assert_eq!(
        receipt.record_v1().fields_v1().publisher_invocation,
        [16; 16]
    );
    assert_eq!(receipt.record_v1().fields_v1().publisher_generation, 2);
    assert_eq!(receipt.target_next_sequence_v1(), 7);
    assert_eq!(receipt.record_v1().digest_v1(), record.digest_v1());
}

#[test]
fn a_fresh_outer_signature_cannot_hide_a_different_native_uuid() {
    let (_, _, purpose, signer) = signed_fixture();
    let record = signed_record(&purpose, &signer);
    let mut bytes = completion_bytes(&record, &signer);
    bytes[80] ^= 1;
    let mut message = b"aos.runtime-deployment.boot-completion.v1\0".to_vec();
    message.extend_from_slice(&bytes[..BOOT_PREPARATION_COMPLETION_BODY_BYTES_V1]);
    bytes[BOOT_PREPARATION_COMPLETION_BODY_BYTES_V1..]
        .copy_from_slice(&signer.sign(&message).to_bytes());

    assert!(SignedBootPreparationCompletionDataV1::verify_v1(&bytes, &purpose).is_err());
}

#[test]
fn purpose_rejects_substituted_decoded_genesis_even_when_signed_bytes_stay_identical() {
    let (mut genesis, signed, purpose, _) = signed_fixture();
    genesis.uid_start += 65_536;
    let provisioner = SigningKey::from_bytes(&[1; 32]);

    assert!(
        SignedBootPreparationPurposeDataV1::verify_v1(
            purpose.bytes_v1(),
            &signed,
            &genesis,
            &provisioner.verifying_key(),
        )
        .is_err()
    );
}

#[test]
fn neither_generation_one_nor_a_missing_actual_invocation_is_a_normal_preparation() {
    let (_, _, purpose, _) = signed_fixture();
    let mut fields = record_fields(&purpose);
    fields.publisher_generation = 1;
    fields.predecessor_ordinal = 0;
    assert!(fields.encode_body_v1().is_err());

    let mut fields = record_fields(&purpose);
    fields.publisher_invocation = [0; 16];
    assert!(fields.encode_body_v1().is_err());
    assert!(boot_preparation_key_data_v1(1).is_err());
}
