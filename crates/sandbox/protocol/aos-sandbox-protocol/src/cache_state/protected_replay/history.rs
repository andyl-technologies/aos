//! Historical partition grouping and complete intermediate-transaction correlations.

use super::*;

/// Retains the same partition/history/checkpoint maps at the authority frontier.
///
/// Fields contain historical DATA and do not establish a Native inventory.
pub struct CachePartitionHistoryDataV1 {
    /// Checkpoint bodies grouped by historical partition.
    pub checkpoints_by_partition: BTreeMap<ObjectDigest, Vec<Vec<u8>>>,
    /// Canonical event bytes grouped by partition and sequence.
    pub records_by_partition: BTreeMap<ObjectDigest, BTreeMap<u64, Vec<u8>>>,
    /// Exact supplied and observed physical partition identities.
    pub partitions: BTreeMap<ObjectDigest, PhysicalPartitionId>,
}

/// Groups the exact historical envelopes before the caller's authority checks.
///
/// # Errors
/// Returns [`DomainLedgerDataError`] for malformed bodies, foreign partitions,
/// conflicting sequence aliases or invalid keys.
pub fn group_cache_history_data_v1<'envelope, S: ProtectedDomainSchemaV1<Kind = CacheResidencyProtectedRecordKindV1>>(
    envelopes: impl IntoIterator<Item = &'envelope ProtectedDomainEnvelopeV1<S>>,
    validator: &S::ReplayValidator,
    limits: CacheRecoveryLimitsV1,
    mut partitions: BTreeMap<ObjectDigest, PhysicalPartitionId>,
) -> Result<CachePartitionHistoryDataV1, DomainLedgerDataError> {
    let mut records_by_partition = BTreeMap::<ObjectDigest, BTreeMap<u64, Vec<u8>>>::new();
    let mut checkpoints_by_partition = BTreeMap::<ObjectDigest, Vec<Vec<u8>>>::new();
    for envelope in envelopes {
        validate_cache_key(envelope.key())?;
        if envelope.key().kind() == CacheResidencyProtectedRecordKindV1::EffectObservation {
            let reducer = decode_reducer_payload_with_validator::<
                S,
            >(envelope.key(), envelope.payload(), validator)?;
            decode_cache_effect_observation(envelope.key().identity(), reducer.body())
                .ok_or(DomainLedgerDataError::NonCanonicalRecord)?;
            continue;
        }
        let reducer = decode_reducer_payload_with_validator::<
            S,
        >(envelope.key(), envelope.payload(), validator)?;
        let descriptor_end = 8 + PARTITION_DESCRIPTOR_BYTES;
        let partition = decode_partition_descriptor(
            reducer
                .body()
                .get(8..descriptor_end)
                .ok_or(DomainLedgerDataError::NonCanonicalRecord)?,
        )
        .ok_or(DomainLedgerDataError::NonCanonicalRecord)?;
        let partition_digest = partition.digest();
        if partitions
            .insert(partition_digest, partition)
            .is_some_and(|value| value != partition)
        {
            return Err(DomainLedgerDataError::NonCanonicalRecord);
        }
        if envelope.key().kind() == CacheResidencyProtectedRecordKindV1::Checkpoint {
            checkpoints_by_partition
                .entry(partition_digest)
                .or_default()
                .push(reducer.body()[descriptor_end..].to_vec());
            continue;
        }
        let record = decode_cache_body(
            envelope.key().kind(),
            envelope.key().identity(),
            reducer.body(),
            limits,
        )
        .ok_or(DomainLedgerDataError::NonCanonicalRecord)?
        .ok_or(DomainLedgerDataError::NonCanonicalRecord)?;
        let encoded_record = &reducer.body()[descriptor_end..];
        let pin_alias = record.kind == CacheRecordKindV1::Pin
            && matches!(
                envelope.key().kind(),
                CacheResidencyProtectedRecordKindV1::GlobalAccounting
                    | CacheResidencyProtectedRecordKindV1::ProjectAccounting
                    | CacheResidencyProtectedRecordKindV1::DomainAccounting
                    | CacheResidencyProtectedRecordKindV1::Pin
                    | CacheResidencyProtectedRecordKindV1::Current
            );
        match records_by_partition
            .entry(partition_digest)
            .or_default()
            .entry(record.sequence)
        {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(encoded_record.to_vec());
            }
            std::collections::btree_map::Entry::Occupied(entry)
                if pin_alias && entry.get().as_slice() == encoded_record => {}
            std::collections::btree_map::Entry::Occupied(_) => {
                return Err(DomainLedgerDataError::NonCanonicalRecord);
            }
        }
    }
    Ok(CachePartitionHistoryDataV1 { checkpoints_by_partition, records_by_partition, partitions })
}

/// Returns the compiled inline historical grouping carrier bytes.
#[must_use]
pub const fn partition_history_inline_bytes_v1() -> usize {
    std::mem::size_of::<CachePartitionHistoryDataV1>()
}

/// Validates every retained complete transaction and observation correlation.
///
/// # Errors
/// Returns [`DomainLedgerDataError`] for invalid family membership, duplicate
/// observation identity or missing/extraneous transaction correlations.
pub fn validate_projection_transaction_groups_data_v1<S: ProtectedDomainSchemaV1<Kind = CacheResidencyProtectedRecordKindV1>>(
    projection: &ProtectedDomainProjectionV1<S>,
    validator: &S::ReplayValidator,
    limits: CacheRecoveryLimitsV1,
) -> Result<(), DomainLedgerDataError> {

    let mut original_transactions = BTreeMap::<[u8; 16], Vec<(ObjectDigest, ObjectDigest)>>::new();
    let mut observations = BTreeMap::<[u8; 16], CacheEffectObservationDataV1>::new();
    for envelope in projection.records().iter().filter(|envelope| {
        envelope.key().kind() == CacheResidencyProtectedRecordKindV1::EffectObservation
    }) {
        let reducer = decode_reducer_payload_with_validator::<
            S,
        >(envelope.key(), envelope.payload(), validator)?;
        let observation =
            decode_cache_effect_observation(envelope.key().identity(), reducer.body())
                .ok_or(DomainLedgerDataError::NonCanonicalRecord)?;
        if observations
            .insert(observation.transaction_id, observation)
            .is_some()
        {
            return Err(DomainLedgerDataError::NonCanonicalRecord);
        }
    }
    let mut grouped_observations = BTreeMap::<[u8; 16], CacheEffectObservationDataV1>::new();
    for transaction in projection.transactions() {
        if transaction.phase() != ProtectedDomainReplayPhaseV1::Incomplete {
            validate_cache_transition(
                classify_replayed_cache_transaction(transaction.records())?,
                transaction.records(),
                validator, limits,
            )?;
        }
        if transaction.records().iter().any(|record| {
            record.key().kind() == CacheResidencyProtectedRecordKindV1::EffectObservation
        }) {
            if transaction.records().len() != 1
                || transaction.phase() != ProtectedDomainReplayPhaseV1::Observed
            {
                return Err(DomainLedgerDataError::NonCanonicalRecord);
            }
            let envelope = &transaction.records()[0];
            let reducer = decode_reducer_payload_with_validator::<
                S,
            >(envelope.key(), envelope.payload(), validator)?;
            let observation =
                decode_cache_effect_observation(envelope.key().identity(), reducer.body())
                    .ok_or(DomainLedgerDataError::NonCanonicalRecord)?;
            if grouped_observations
                .insert(observation.transaction_id, observation)
                .is_some()
            {
                return Err(DomainLedgerDataError::NonCanonicalRecord);
            }
            continue;
        }
        if transaction.phase() != ProtectedDomainReplayPhaseV1::Prepared
            || transaction
                .records()
                .iter()
                .filter(|record| record.key().kind() == CacheResidencyProtectedRecordKindV1::Effect)
                .count()
                != 1
        {
            continue;
        }
        if let Some(partition) = cache_transaction_partition(transaction.records())? {
            original_transactions
                .entry(transaction.transaction_id())
                .or_default()
                .push((transaction.transaction_digest(), partition));
        }
    }
    if grouped_observations != observations {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    for (transaction_id, observation) in observations {
        let matches = original_transactions
            .get(&transaction_id)
            .into_iter()
            .flatten()
            .filter(|(digest, partition)| {
                *digest == observation.transaction_digest && *partition == observation.partition
            })
            .count();
        if matches != 1 {
            return Err(DomainLedgerDataError::NonCanonicalRecord);
        }
    }
    Ok(())
}

/// Compares the complete recovered inventory with its actual final event bytes.
///
/// # Errors
/// Returns [`DomainLedgerDataError`] for an invalid final event or head mismatch.
pub fn validate_partition_history_tail_data_v1(
    inventory: &super::super::recovery::CacheRecoveryInventoryDataV1,
    records: &[Vec<u8>],
    partition: PhysicalPartitionId,
    limits: CacheRecoveryLimitsV1,
) -> Result<(), DomainLedgerDataError> {
    if let Some(last) = records.last() {
        let decoded = decode_atomic_object_record(partition, last, limits)
            .map_err(|_| DomainLedgerDataError::NonCanonicalRecord)?;
        if inventory.head_sequence != decoded.record.sequence
            || inventory.head_digest != decoded.record.digest
        {
            return Err(DomainLedgerDataError::NonCanonicalRecord);
        }
    }
    Ok(())
}
