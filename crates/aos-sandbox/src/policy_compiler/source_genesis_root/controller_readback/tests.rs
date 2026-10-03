//! Closed signature kinds; these packet fixtures create no held owner authority.

use aos_sandbox_core::ProjectId;

use super::*;
use crate::JournalLimits;
use crate::hierarchy::source_genesis::tests as source_fixture;
use crate::policy_compiler::encode_controller_hold_signer_credential_v1;

fn signed_packet(kind: u8, key: &SigningKey) -> [u8; CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1] {
    let directory = source_fixture::directory();
    let journal = source_fixture::open(directory.path(), JournalLimits::default());
    let names = journal.protected_writer_physical_names_v1().unwrap();
    let acceptance = source_fixture::acceptance(ProjectId::from_bytes([1; 16]));
    let mut packet = [0; CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1];
    packet[..8].copy_from_slice(MAGIC);
    packet[8..10].copy_from_slice(&1_u16.to_be_bytes());
    packet[10] = kind;
    packet[16..24].copy_from_slice(&7_u64.to_be_bytes());
    packet[24..28].copy_from_slice(&811_u32.to_be_bytes());
    packet[28..32].copy_from_slice(&812_u32.to_be_bytes());
    packet[32..40].copy_from_slice(&1_u64.to_be_bytes());
    packet[40..48].copy_from_slice(&7_u64.to_be_bytes());
    packet[48..64].copy_from_slice(&[9; 16]);
    packet[64..672].copy_from_slice(acceptance.record_bytes());
    packet[672..720].copy_from_slice(&names.to_bytes());
    packet[720..768].copy_from_slice(&names.to_bytes());
    packet[768..800].copy_from_slice(&[10; 32]);
    resign(&mut packet, key);
    packet
}

fn resign(packet: &mut [u8; CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1], key: &SigningKey) {
    let signature = key.sign(&[DOMAIN, &packet[..BODY_BYTES]].concat());
    packet[BODY_BYTES..].copy_from_slice(&signature.to_bytes());
}

#[test]
fn historical_recovery_and_final_completion_are_distinct_signed_kinds() {
    let key = SigningKey::from_bytes(&[80; 32]);
    let credential = encode_controller_hold_signer_credential_v1(7, &key.verifying_key()).unwrap();
    let pin = PinnedControllerHoldSignerV1::decode(&credential).unwrap();

    let historical = verify(&signed_packet(1, &key), &pin, [9; 16], 811, 812).unwrap();
    assert!(historical.historical);
    assert!(!historical.completed);
    assert!(!historical.vacant);

    let completed = verify(&signed_packet(3, &key), &pin, [9; 16], 811, 812).unwrap();
    assert!(completed.historical);
    assert!(completed.completed);
    assert!(!completed.vacant);
    assert_eq!(historical.acceptance, completed.acceptance);
    assert_eq!(historical.source_instance, completed.source_instance);
}

#[test]
fn final_kind_rejects_unsigned_promotion_unknown_kind_and_empty_instance() {
    let key = SigningKey::from_bytes(&[80; 32]);
    let credential = encode_controller_hold_signer_credential_v1(7, &key.verifying_key()).unwrap();
    let pin = PinnedControllerHoldSignerV1::decode(&credential).unwrap();
    let mut promoted = signed_packet(1, &key);
    promoted[10] = 3;
    assert!(verify(&promoted, &pin, [9; 16], 811, 812).is_err());
    assert!(verify(&signed_packet(4, &key), &pin, [9; 16], 811, 812).is_err());

    let mut empty = signed_packet(3, &key);
    empty[768..800].fill(0);
    resign(&mut empty, &key);
    assert!(verify(&empty, &pin, [9; 16], 811, 812).is_err());
    assert!(verify(&signed_packet(3, &key), &pin, [11; 16], 811, 812).is_err());
}
