//! Exact Cache transaction-family membership and record correlation DATA.

use super::*;

/// Validates every member of the exact supplied historical transaction.
///
/// # Errors
/// Returns [`DomainLedgerDataError`] for invalid family membership or correlations.
pub fn validate_cache_transition<S: ProtectedDomainSchemaV1<Kind = CacheResidencyProtectedRecordKindV1>>(
    transition: CacheResidencyTransactionKindV1,
    successors: &[ProtectedDomainEnvelopeV1<S>],
    validator: &S::ReplayValidator,
    limits: CacheRecoveryLimitsV1,
) -> Result<(), DomainLedgerDataError> {
    if transition == CacheResidencyTransactionKindV1::Recovery {
        return if successors.len() == 1
            && successors[0].key().kind() == CacheResidencyProtectedRecordKindV1::EffectObservation
            && successors[0].revision() == 1
            && successors[0].predecessor().is_none()
        {
            Ok(())
        } else {
            Err(DomainLedgerDataError::NonCanonicalRecord)
        };
    }
    let Some(first) = successors.first() else {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    };
    let partition = first.key().identity().get(..32);
    if partition.is_none()
        || successors.iter().any(|successor| {
            successor.key().identity().get(..32) != partition
                || validate_cache_key(successor.key()).is_err()
                || (!matches!(
                    successor.key().kind(),
                    CacheResidencyProtectedRecordKindV1::Checkpoint
                ) && (successor.revision() != 1 || successor.predecessor().is_some()))
        })
    {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    if !matches!(
        transition,
        CacheResidencyTransactionKindV1::Checkpoint | CacheResidencyTransactionKindV1::Recovery
    ) {
        let mut operation = None;
        let mut sequences = std::collections::BTreeSet::new();
        let mut decoded = Vec::with_capacity(successors.len());
        for successor in successors {
            let reducer = decode_reducer_payload_with_validator::<
                S,
            >(successor.key(), successor.payload(), validator)?;
            let record = decode_cache_body(
                successor.key().kind(),
                successor.key().identity(),
                reducer.body(),
                limits,
            )
            .ok_or(DomainLedgerDataError::NonCanonicalRecord)?
            .ok_or(DomainLedgerDataError::NonCanonicalRecord)?;
            if successor.key().identity()[..32] != *record.partition.as_bytes()
                || successor.key().identity()[49..81] != *record.subject.as_bytes()
                || operation.is_some_and(|current| current != record.operation)
                || (transition != CacheResidencyTransactionKindV1::PinChange
                    && !sequences.insert(record.sequence))
            {
                return Err(DomainLedgerDataError::NonCanonicalRecord);
            }
            operation = Some(record.operation);
            decoded.push((successor.key().kind(), record));
        }
        decoded.sort_by_key(|(kind, _)| S::order(*kind));
        let shared = decoded
            .first()
            .map(|(_, record)| record)
            .ok_or(DomainLedgerDataError::NonCanonicalRecord)?;
        if transition == CacheResidencyTransactionKindV1::PinChange {
            // Accounting and Current are aliases of the one atomic Pin event.
            // They cannot invent quota changes or advance durable history.
            if shared.kind != CacheRecordKindV1::Pin
                || decoded.iter().any(|(_, record)| record != shared)
            {
                return Err(DomainLedgerDataError::NonCanonicalRecord);
            }
        } else if decoded.iter().any(|(kind, record)| {
            matches!(
                kind,
                CacheResidencyProtectedRecordKindV1::GlobalAccounting
                    | CacheResidencyProtectedRecordKindV1::ProjectAccounting
                    | CacheResidencyProtectedRecordKindV1::DomainAccounting
            ) && record.kind != CacheRecordKindV1::Quota
        }) {
            return Err(DomainLedgerDataError::NonCanonicalRecord);
        } else if decoded.windows(2).any(|pair| {
            pair[0].1.sequence.checked_add(1) != Some(pair[1].1.sequence)
                || pair[0].1.operation != pair[1].1.operation
        }) {
            return Err(DomainLedgerDataError::NonCanonicalRecord);
        }
        if decoded.iter().skip(1).any(|(_, record)| {
            record.plan != shared.plan
                || record.model != shared.model
                || record.payload != shared.payload
                || record.catalog_projection != shared.catalog_projection
                || record.reservation_projection != shared.reservation_projection
                || record.pin_projection != shared.pin_projection
                || record.progress_projection != shared.progress_projection
        }) {
            return Err(DomainLedgerDataError::NonCanonicalRecord);
        }
        let accounting = |kind| {
            decoded
                .iter()
                .find(|(candidate, _)| *candidate == kind)
                .map(|(_, record)| record)
        };
        if let (Some(global), Some(project), Some(domain)) = (
            accounting(CacheResidencyProtectedRecordKindV1::GlobalAccounting),
            accounting(CacheResidencyProtectedRecordKindV1::ProjectAccounting),
            accounting(CacheResidencyProtectedRecordKindV1::DomainAccounting),
        ) && transition != CacheResidencyTransactionKindV1::PinChange
        {
            if global.amount < project.amount
                || project.amount < domain.amount
                || global.model != project.model
                || project.model != domain.model
            {
                return Err(DomainLedgerDataError::NonCanonicalRecord);
            }
        }
    }
    let has = |kind| successors.iter().any(|value| value.key().kind() == kind);
    let count = |kind| {
        successors
            .iter()
            .filter(|value| value.key().kind() == kind)
            .count()
    };
    let only = |allowed: &[CacheResidencyProtectedRecordKindV1]| {
        successors
            .iter()
            .all(|value| allowed.contains(&value.key().kind()))
    };
    use CacheResidencyProtectedRecordKindV1 as Record;
    let valid = match transition {
        CacheResidencyTransactionKindV1::Admission => {
            successors.len() == 9
                && count(Record::Authority) == 1
                && count(Record::GlobalAccounting) == 1
                && count(Record::ProjectAccounting) == 1
                && count(Record::DomainAccounting) == 1
                && count(Record::Reservation) == 1
                && count(Record::Pin) == 1
                && count(Record::Catalog) == 1
                && count(Record::Effect) == 1
                && count(Record::Current) == 1
                && only(&[
                    Record::Authority,
                    Record::GlobalAccounting,
                    Record::ProjectAccounting,
                    Record::DomainAccounting,
                    Record::Reservation,
                    Record::Pin,
                    Record::Catalog,
                    Record::Effect,
                    Record::Current,
                ])
        }
        CacheResidencyTransactionKindV1::PinChange => {
            successors.len() == 5
                && count(Record::GlobalAccounting) == 1
                && count(Record::ProjectAccounting) == 1
                && count(Record::DomainAccounting) == 1
                && count(Record::Pin) == 1
                && count(Record::Current) == 1
                && only(&[
                    Record::GlobalAccounting,
                    Record::ProjectAccounting,
                    Record::DomainAccounting,
                    Record::Pin,
                    Record::Current,
                ])
        }
        CacheResidencyTransactionKindV1::Scrub => {
            successors.len() == 5
                && count(Record::Authority) == 1
                && count(Record::Pin) == 1
                && count(Record::Scrub) == 1
                && count(Record::Catalog) == 1
                && count(Record::Current) == 1
                && only(&[
                    Record::Authority,
                    Record::Pin,
                    Record::Scrub,
                    Record::Catalog,
                    Record::Current,
                ])
        }
        CacheResidencyTransactionKindV1::EvictionPrepare => {
            successors.len() == 6
                && count(Record::Authority) == 1
                && count(Record::Pin) == 1
                && count(Record::Eviction) == 1
                && count(Record::Catalog) == 1
                && count(Record::Effect) == 1
                && count(Record::Current) == 1
                && only(&[
                    Record::Authority,
                    Record::Pin,
                    Record::Eviction,
                    Record::Catalog,
                    Record::Effect,
                    Record::Current,
                ])
        }
        CacheResidencyTransactionKindV1::EvictionFinalize => {
            successors.len() == 8
                && count(Record::GlobalAccounting) == 1
                && count(Record::ProjectAccounting) == 1
                && count(Record::DomainAccounting) == 1
                && count(Record::Pin) == 1
                && count(Record::Scrub) == 1
                && count(Record::Eviction) == 1
                && count(Record::Catalog) == 1
                && count(Record::Current) == 1
                && !has(Record::Effect)
                && only(&[
                    Record::GlobalAccounting,
                    Record::ProjectAccounting,
                    Record::DomainAccounting,
                    Record::Pin,
                    Record::Scrub,
                    Record::Eviction,
                    Record::Catalog,
                    Record::Current,
                ])
        }
        CacheResidencyTransactionKindV1::Recovery => {
            successors.len() == 1 && has(Record::EffectObservation)
        }
        CacheResidencyTransactionKindV1::Checkpoint => {
            successors.len() == 1 && has(Record::Checkpoint)
        }
    };
    if !valid {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    Ok(())
}

/// Classifies the exact historical group without granting effect authority.
///
/// # Errors
/// Returns [`DomainLedgerDataError`] for an unsupported family combination.
pub fn classify_replayed_cache_transaction<S: ProtectedDomainSchemaV1<Kind = CacheResidencyProtectedRecordKindV1>>(
    records: &[ProtectedDomainEnvelopeV1<S>],
) -> Result<CacheResidencyTransactionKindV1, DomainLedgerDataError> {
    use CacheResidencyProtectedRecordKindV1 as Record;
    if records.len() == 1 && records[0].key().kind() == Record::Checkpoint {
        return Ok(CacheResidencyTransactionKindV1::Checkpoint);
    }
    if records.len() == 1 && records[0].key().kind() == Record::EffectObservation {
        return Ok(CacheResidencyTransactionKindV1::Recovery);
    }
    let has = |kind| records.iter().any(|record| record.key().kind() == kind);
    if has(Record::Reservation) && has(Record::Effect) {
        Ok(CacheResidencyTransactionKindV1::Admission)
    } else if has(Record::Eviction) && has(Record::Effect) {
        Ok(CacheResidencyTransactionKindV1::EvictionPrepare)
    } else if has(Record::Eviction) && has(Record::Current) {
        Ok(CacheResidencyTransactionKindV1::EvictionFinalize)
    } else if has(Record::Scrub) {
        Ok(CacheResidencyTransactionKindV1::Scrub)
    } else if has(Record::Pin) && has(Record::Current) {
        Ok(CacheResidencyTransactionKindV1::PinChange)
    } else if has(Record::Authority) && has(Record::Current) {
        Ok(CacheResidencyTransactionKindV1::Recovery)
    } else {
        Err(DomainLedgerDataError::NonCanonicalRecord)
    }
}
