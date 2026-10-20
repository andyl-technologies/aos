//! Complete normal055 boot-record comparison on the existing native row input.
//!
//! This module parses only the explicit normal signed schema. The enclosing
//! original Journal supplies all rows and actual native BEGIN/COMMIT UUIDs;
//! the existing full-history reader and HEAD engine remain the sole mechanics.
//! A successful fold is historical DATA, not a SourceM or publication permit.

use std::collections::BTreeMap;

use aos_sandbox_protocol::runtime_deployment::DeploymentGenesisV1;
use aos_sandbox_protocol::runtime_deployment::boot_preparation::{
    BOOT_PREPARATION_COMPOSITE_GENESIS_BYTES_V1, BOOT_PREPARATION_GENESIS_KEY_V1,
    SignedBootPreparationPurposeDataV1, SignedBootPreparationRecordDataV1,
    boot_preparation_genesis_transaction_data_v1, boot_preparation_key_data_v1,
    boot_preparation_transaction_data_v1,
};

use crate::journal::JournalTransaction;
use crate::tpm_nv_custody::{
    NvCustodyEndpointV1, NvCustodyErrorV1, canonical_purpose_main_head_v1,
};

/// Actual first-local normal schema limit; each record has one immutable PUT.
pub(super) const MAXIMUM_NORMAL_BOOT_RECORDS_V1: usize = 64;
pub(in crate::runtime_deployment) const MAIN_LIMITS_V1: crate::journal::JournalLimits =
    crate::journal::JournalLimits {
        maximum_journal_bytes: 128 * 1024,
        maximum_record_bytes: 1024,
        maximum_key_bytes: 32,
        maximum_records_per_transaction: 1,
        maximum_transaction_bytes: 1024,
        maximum_transactions: 1 + MAXIMUM_NORMAL_BOOT_RECORDS_V1,
        maximum_materialized_bytes: 64 * 1024,
        maximum_materialized_records: 1 + MAXIMUM_NORMAL_BOOT_RECORDS_V1,
    };
const INITIAL_SEQUENCE: u64 = 4;

pub(super) fn require_rows_v1(
    sequence: u64,
    records: &BTreeMap<&[u8], &[u8]>,
    composite_genesis: &[u8],
    genesis: &DeploymentGenesisV1,
    scope: [u8; 32],
    purpose: &SignedBootPreparationPurposeDataV1,
) -> Result<Option<SignedBootPreparationRecordDataV1>, NvCustodyErrorV1> {
    if records.is_empty()
        || records.len() > 1 + MAXIMUM_NORMAL_BOOT_RECORDS_V1
        || composite_genesis.len() != BOOT_PREPARATION_COMPOSITE_GENESIS_BYTES_V1
        || records.get(BOOT_PREPARATION_GENESIS_KEY_V1).copied() != Some(composite_genesis)
        || &composite_genesis[468..] != purpose.bytes_v1()
    {
        return Err(NvCustodyErrorV1::Provisioning);
    }

    let mut prefix = BTreeMap::from([(BOOT_PREPARATION_GENESIS_KEY_V1, composite_genesis)]);
    let mut predecessor_sequence = INITIAL_SEQUENCE;
    let mut predecessor_ordinal = 1u64;
    let mut previous: Option<SignedBootPreparationRecordDataV1> = None;
    for (&key, &value) in records {
        if key == BOOT_PREPARATION_GENESIS_KEY_V1 {
            continue;
        }
        let record = SignedBootPreparationRecordDataV1::verify_v1(value, purpose)
            .map_err(|_| NvCustodyErrorV1::Encoding)?;
        let fields = record.fields_v1();
        let expected_key = boot_preparation_key_data_v1(fields.publisher_generation)
            .map_err(|_| NvCustodyErrorV1::Encoding)?;
        let predecessor_head = canonical_purpose_main_head_v1(
            NvCustodyEndpointV1::RuntimeDeployment,
            scope,
            predecessor_sequence,
            &prefix,
        )?;
        if key != expected_key
            || fields.predecessor_sequence != predecessor_sequence
            || fields.predecessor_head != predecessor_head
            || fields.predecessor_ordinal != predecessor_ordinal
            || fields.previous_record != previous.as_ref().map_or([0; 32], |row| row.digest_v1())
            || fields.nspawn_digest != genesis.nspawn_digest
            || fields.mac_policy_digest != genesis.mac_policy
        {
            return Err(NvCustodyErrorV1::Provisioning);
        }
        prefix.insert(key, value);
        predecessor_sequence = predecessor_sequence
            .checked_add(3)
            .ok_or(NvCustodyErrorV1::Encoding)?;
        predecessor_ordinal = fields.publisher_generation;
        previous = Some(record);
    }
    if sequence != predecessor_sequence {
        return Err(NvCustodyErrorV1::Provisioning);
    }
    Ok(previous)
}

/// Compares exact native association after the sole COMMIT parser validated it.
pub(crate) fn require_native_binding_v1(
    key: &[u8],
    value: &[u8],
    transaction: [u8; 16],
    begin_sequence: u64,
    purpose: &SignedBootPreparationPurposeDataV1,
) -> Result<(), NvCustodyErrorV1> {
    let record = SignedBootPreparationRecordDataV1::verify_v1(value, purpose)
        .map_err(|_| NvCustodyErrorV1::Encoding)?;
    let fields = record.fields_v1();
    if key
        != boot_preparation_key_data_v1(fields.publisher_generation)
            .map_err(|_| NvCustodyErrorV1::Encoding)?
        || fields.predecessor_sequence != begin_sequence
        || transaction
            != boot_preparation_transaction_data_v1(fields)
                .map_err(|_| NvCustodyErrorV1::Encoding)?
    {
        return Err(NvCustodyErrorV1::Provisioning);
    }
    Ok(())
}

pub(super) fn validated_append_rows_v1<'data>(
    sequence: u64,
    records: &BTreeMap<&'data [u8], &'data [u8]>,
    transaction: &'data JournalTransaction,
    composite_genesis: &[u8],
    genesis: &DeploymentGenesisV1,
    scope: [u8; 32],
    purpose: &SignedBootPreparationPurposeDataV1,
) -> Result<(u64, BTreeMap<&'data [u8], &'data [u8]>), NvCustodyErrorV1> {
    require_rows_v1(
        sequence,
        records,
        composite_genesis,
        genesis,
        scope,
        purpose,
    )?;
    if records.len() >= 1 + MAXIMUM_NORMAL_BOOT_RECORDS_V1 || transaction.records().len() != 1 {
        return Err(NvCustodyErrorV1::Encoding);
    }
    let row = &transaction.records()[0];
    let value = row.value().ok_or(NvCustodyErrorV1::Encoding)?;
    if row.namespace() != super::NAMESPACE
        || row.key() == BOOT_PREPARATION_GENESIS_KEY_V1
        || records.contains_key(row.key())
    {
        return Err(NvCustodyErrorV1::Provisioning);
    }
    require_native_binding_v1(row.key(), value, *transaction.id(), sequence, purpose)?;

    let mut after = records.clone();
    after.insert(row.key(), value);
    let next_sequence = sequence.checked_add(3).ok_or(NvCustodyErrorV1::Encoding)?;
    require_rows_v1(
        next_sequence,
        &after,
        composite_genesis,
        genesis,
        scope,
        purpose,
    )?;
    Ok((next_sequence, after))
}

pub(super) fn genesis_native_identity_v1(composite: &[u8]) -> Result<[u8; 16], NvCustodyErrorV1> {
    let composite = composite
        .try_into()
        .map_err(|_| NvCustodyErrorV1::Encoding)?;
    Ok(boot_preparation_genesis_transaction_data_v1(composite))
}
