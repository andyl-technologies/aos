//! Checks real phase-bank reservations and failed private signer DATA.
//!
//! Mapping flags here model a failed private preparation; no Core claim, SDK
//! mapping, signing right or native restoration association is constructed.

use super::*;

fn reserved() -> OriginalAckPeerAssociation {
    let mut slot = None;
    OriginalAckPeerAssociation::reserve_into(8192, &mut slot).unwrap();
    let mut owner = slot.unwrap();
    owner.reserve_complete_restore_banks(8192).unwrap();
    owner.reserve_restore_transfer_phase_banks(8192).unwrap();
    owner
}

#[test]
fn restoration_capacity_transfer_keeps_both_phases_and_failed_signer_spares() {
    let mut owner = reserved();
    let legacy = owner.restore.as_ref().unwrap().allocated_bytes().unwrap();
    let transfer = owner.restore_transfer_banks.as_mut().unwrap();
    let raw_bytes = transfer.allocated_bytes().unwrap();
    transfer.mapping_attempted = true;
    transfer.mapping_complete = true;
    let prepare = Id::new("failed/prepare").unwrap();
    let commit = Id::new("failed/commit").unwrap();
    transfer
        .begin_original_prepare([7; 32], &prepare, &commit)
        .unwrap();
    let signer = transfer.signer.as_mut().unwrap();
    signer.failed = true;
    let mut text = String::with_capacity(197);
    text.push_str("failed prepare body");
    let mut values = Vec::with_capacity(3);
    values.push(serde_json::Value::String(text));
    let array_bytes = values.capacity() * size_of::<serde_json::Value>();
    signer.prepare.normalized[0] = Some(serde_json::Value::Array(values));
    let mut text = String::with_capacity(211);
    text.push_str("failed commit partial");
    signer.commit.normalized[4] = Some(serde_json::Value::String(text));
    let strings = signer.prepare_id.as_ref().unwrap().allocated_capacity()
        + signer.commit_id.as_ref().unwrap().allocated_capacity()
        + 197
        + 211;

    let mut census = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);
    transfer.record_capacity_data(&mut census).unwrap();
    let facts = census.finish();

    assert_eq!(facts.capacity_records, 15);
    assert_eq!(facts.vector_banks, 11);
    assert_eq!(facts.vector_capacity_bytes, raw_bytes + array_bytes);
    assert_eq!(facts.string_banks, 4);
    assert_eq!(facts.string_capacity_bytes, strings);
    assert!(
        transfer
            .signer()
            .unwrap()
            .authenticate_prepare_verified()
            .is_err()
    );
    assert!(
        transfer
            .begin_original_prepare([7; 32], &prepare, &commit)
            .is_err()
    );
    assert_eq!(
        owner.restore.as_ref().unwrap().allocated_bytes().unwrap(),
        legacy
    );
}

#[test]
fn restoration_capacity_transfer_short_rows_keep_prior_component_and_real_bank_prefix() {
    let owner = reserved();
    let transfer = owner.restore_transfer_banks.as_ref().unwrap();
    let prefix = String::with_capacity(173);
    let mut census = OriginalOwnerCapacityMetadataData::new(4, None);
    census.observe(&prefix).unwrap();

    assert_eq!(
        transfer.record_capacity_data(&mut census),
        Err(RuntimeError::ResourceLimit)
    );

    let facts = census.finish();
    assert_eq!(facts.capacity_records, 4);
    assert_eq!(facts.string_capacity_bytes, prefix.capacity());
    assert_eq!(
        facts.vector_capacity_bytes,
        transfer.prepare[..3]
            .iter()
            .map(Vec::capacity)
            .sum::<usize>()
    );
    assert!(transfer.signer.is_none());
    assert!(!transfer.mapping_attempted && !transfer.mapping_complete);
}
