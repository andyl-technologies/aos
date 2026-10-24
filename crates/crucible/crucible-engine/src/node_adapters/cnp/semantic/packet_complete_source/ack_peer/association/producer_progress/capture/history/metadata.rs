//! Prices and retains independent capacity banks before history serialization.
//!
//! Passive quotation walks actual owners without decoding archived state,
//! allocating a row bank, acquiring SourceRead or creating Capture authority.

use super::super::super::construction::sum;
use super::*;
use crucible_node_transport::retained_metadata::{
    RetainedProtocolMetadataFacts,
    aliases::MetadataAliasBank,
    records::{MetadataCapacityRecord, MetadataRecordBank},
};

pub(super) struct HistoryPrequoteData {
    pub(super) owners: usize,
    pub(super) common_aliases: usize,
    pub(super) retained: usize,
    pub(super) transient: usize,
}

pub(super) fn prequote_data(
    history: &ProducerProgressHistory,
    maximum: usize,
) -> Result<HistoryPrequoteData, RuntimeError> {
    let mut quote = HistoryPrequoteData {
        owners: 0,
        common_aliases: 0,
        retained: 0,
        transient: 0,
    };
    provider::visit(history, |_, _, _, value| {
        let facts = value.facts()?;
        quote.owners = quote
            .owners
            .checked_add(1)
            .ok_or(RuntimeError::ResourceLimit)?;
        quote.retained = sum(
            [
                quote.retained,
                owner_bank_bytes(&facts)?,
                size_of::<RecordedProviderOwner>(),
            ],
            maximum,
        )?;
        quote.transient = sum([quote.transient, value.serialization_transient()?], maximum)?;
        Ok(())
    })?;
    for attempt in &history.attempts {
        if let Some(admission) = &attempt.admission {
            let (_, shared) = CapacityRows(admission).metadata_demand_data()?;
            quote.common_aliases = quote
                .common_aliases
                .checked_add(shared)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        for body in &attempt.upload_bodies {
            if let UploadBody::Chunk(body) = body {
                // Bytes::serialize builds exactly one temporary base64 string.
                // Charge its padded upper extent independently of output banks.
                let encoding = body
                    .bytes
                    .as_slice()
                    .len()
                    .checked_add(2)
                    .map(|bytes| bytes / 3)
                    .and_then(|groups| groups.checked_mul(4))
                    .ok_or(RuntimeError::ResourceLimit)?;
                quote.transient = sum([quote.transient, encoding], maximum)?;
            }
        }
    }
    // The caller adds Node/other Source shared occurrences before reserving
    // ONE lookup for the complete graph. This passive part creates no lookup.
    sum([quote.retained, quote.transient], maximum)?;
    Ok(quote)
}

fn owner_bank_bytes(facts: &RetainedProtocolMetadataFacts) -> Result<usize, RuntimeError> {
    let rows = facts.capacity_records.max(1);
    let aliases = facts.shared_backing_views.max(1);
    if rows > 131_072 || aliases > 131_072 {
        return Err(RuntimeError::ResourceLimit);
    }
    let records = rows
        .checked_mul(size_of::<MetadataCapacityRecord>())
        .ok_or(RuntimeError::ResourceLimit)?;
    let alias = MetadataAliasBank::reservation_requested_bytes(aliases)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    records
        .checked_add(alias)
        .ok_or(RuntimeError::ResourceLimit)
}

/// Fills the caller-retained slots without allowing the outer bank to grow.
pub(super) fn record_into(
    history: &ProducerProgressHistory,
    quoted: &HistoryPrequoteData,
    maximum: usize,
    completed: &mut Vec<RecordedProviderOwner>,
) -> Result<(), RuntimeError> {
    if !completed.is_empty() || completed.capacity() < quoted.owners {
        return Err(RuntimeError::ResourceLimit);
    }
    provider::visit(history, |attempt, owner, element, value| {
        if completed.len() >= quoted.owners || completed.len() >= completed.capacity() {
            return Err(RuntimeError::ResourceLimit);
        }
        let before = value.facts()?;
        // Install the actual owner before either fallible bank allocation.
        completed.push(RecordedProviderOwner {
            owner,
            attempt,
            element,
            records: None,
            aliases: None,
        });
        let retained = completed.last_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        retained.records = Some(
            MetadataRecordBank::reserve(before.capacity_records.max(1))
                .map_err(|_| RuntimeError::ResourceLimit)?,
        );
        retained.aliases = Some(
            MetadataAliasBank::reserve(before.shared_backing_views.max(1))
                .map_err(|_| RuntimeError::ResourceLimit)?,
        );
        let records = retained
            .records
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let aliases = retained
            .aliases
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let after = value.record(records, aliases)?;
        if after != before {
            return Err(RuntimeError::InvalidReceipt);
        }
        // The allocation may reserve more than requested; retain that actual
        // bank and refuse before writing rather than silently borrowing slack.
        if records
            .allocated_bytes()
            .checked_add(aliases.allocated_bytes())
            .ok_or(RuntimeError::ResourceLimit)?
            > owner_bank_bytes(&before)?
        {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(())
    })?;
    if completed.len() != quoted.owners || allocated_bytes(completed)? > quoted.retained {
        return Err(RuntimeError::ResourceLimit);
    }
    sum([quoted.retained, quoted.transient], maximum)?;
    Ok(())
}

pub(super) fn allocated_bytes(owners: &Vec<RecordedProviderOwner>) -> Result<usize, RuntimeError> {
    let mut bytes = owners
        .capacity()
        .checked_mul(size_of::<RecordedProviderOwner>())
        .ok_or(RuntimeError::ResourceLimit)?;
    for owner in owners {
        if let Some(records) = &owner.records {
            bytes = bytes
                .checked_add(records.allocated_bytes())
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        if let Some(aliases) = &owner.aliases {
            bytes = bytes
                .checked_add(aliases.allocated_bytes())
                .ok_or(RuntimeError::ResourceLimit)?;
        }
    }
    Ok(bytes)
}
