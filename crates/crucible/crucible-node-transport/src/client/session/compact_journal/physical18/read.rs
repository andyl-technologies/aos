//! Checks whole custody before constructing its final independent history owners.
//!
//! The only owning preflight work is one temporary envelope bank at a time.
//! Capacity records bound the complete String/Vec population; content8 owns and
//! validates every local shared edge. Tree and Box geometry remain separate.

use super::super::{
    CompactClientCustody, CompactClientJournal, CompactClientOriginal, PendingEnvelope,
};
use super::{CompactCustody18Limits, Edition, invalid, refused};
use crate::ProviderError;
use crate::client::{
    ClientContent,
    compact_json::{CompactJson, physical18::HistoricalCompactEnvelope18},
    compact_metadata8::ValidatedCompactMetadata8,
};
use crate::envelope::RequestOrigin;
use crate::protocol_snapshot::owned11::typed::{Fields, Ledger, plain_string, unsigned};
use crate::retained_metadata::records::{
    METADATA_CAPACITY_RECORD_FORMAT, MetadataRecordKind, ValidatedMetadataRecords,
};
use crucible_node_format::{HashRef, Id};
use std::{
    collections::BTreeMap,
    mem::{align_of, size_of},
};

pub(super) fn decode(
    input: &[u8],
    limits: CompactCustody18Limits,
    edition: Edition,
) -> Result<CompactClientCustody, ProviderError> {
    if input.len() > limits.maximum_input_bytes {
        return Err(refused());
    }
    let mut fields = Fields::array(input)?;
    if plain_string(next(&mut fields)?)? != edition.tag()
        || plain_string(next(&mut fields)?)? != METADATA_CAPACITY_RECORD_FORMAT
    {
        return Err(invalid());
    }
    let data = next(&mut fields)?;
    let records = ValidatedMetadataRecords::validate(
        next(&mut fields)?,
        limits.maximum_capacity_rows,
        limits.maximum_backing_capacity_bytes,
    )?;
    fields.finish()?;

    // Include both journals, content trees and all ordinary JSON populations.
    let mut tree_entries = 0usize;
    for record in records.rows() {
        let record = record?;
        if record.kind == MetadataRecordKind::Tree {
            tree_entries = tree_entries
                .checked_add(record.extent)
                .ok_or_else(refused)?;
            if tree_entries > limits.json.maximum_tree_entries {
                return Err(refused());
            }
        }
    }
    read(
        data,
        &mut Ledger::new(records.rows(), limits.json),
        limits,
        edition,
        false,
    )?;
    read(
        data,
        &mut Ledger::new(records.rows(), limits.json),
        limits,
        edition,
        true,
    )?
    .ok_or_else(invalid)
}

fn read(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    limits: CompactCustody18Limits,
    edition: Edition,
    build: bool,
) -> Result<Option<CompactClientCustody>, ProviderError> {
    let mut fields = Fields::array(input)?;
    let maximum_requests = number(next(&mut fields)?)?;
    let maximum_bytes = number(next(&mut fields)?)?;
    let retained_bytes = number(next(&mut fields)?)?;
    let maximum_envelope_bank_bytes = number(next(&mut fields)?)?;
    if maximum_requests == 0
        || maximum_requests > 4096
        || maximum_bytes == 0
        || retained_bytes > maximum_bytes
        || maximum_envelope_bank_bytes == 0
        || maximum_envelope_bank_bytes > limits.maximum_envelope_bank_bytes
        || maximum_envelope_bank_bytes
            > CompactJson::maximum_storage_bytes(maximum_bytes, usize::MAX)?
    {
        return Err(refused());
    }

    let controller = originals(
        next(&mut fields)?,
        ledger,
        maximum_requests,
        maximum_envelope_bank_bytes,
        build,
    )?;
    let provider = originals(
        next(&mut fields)?,
        ledger,
        maximum_requests,
        maximum_envelope_bank_bytes,
        build,
    )?;
    let content_bytes = next(&mut fields)?;
    let content = ValidatedCompactMetadata8::validate(content_bytes, limits.content)?;
    if edition == Edition::Coupled18
        && content.data().stored_limits().maximum_bytes != maximum_bytes
    {
        return Err(invalid());
    }
    ledger.rows = content.validate_compact_custody18_capacity_rows(ledger.rows.clone())?;

    let pending_bytes = next(&mut fields)?;
    let pending = if pending_bytes == b"null" {
        None
    } else {
        let mut pending_fields = Fields::array(pending_bytes)?;
        let origin = match plain_string(next(&mut pending_fields)?)? {
            "controller" => RequestOrigin::Controller,
            "provider" => RequestOrigin::Provider,
            _ => return Err(invalid()),
        };
        let envelope = super::typed::envelope(next(&mut pending_fields)?, ledger, build)?;
        pending_fields.finish()?;
        envelope.map(|envelope| PendingEnvelope { origin, envelope })
    };
    let unexpected_bytes = next(&mut fields)?;
    let unexpected = if unexpected_bytes == b"null" {
        None
    } else {
        super::typed::frame(unexpected_bytes, ledger, build)?
    };
    fields.finish()?;
    if ledger.rows.next().is_some() {
        return Err(invalid());
    }
    if !build {
        return Ok(None);
    }

    Ok(Some(CompactClientCustody {
        journal: CompactClientJournal {
            maximum_requests,
            maximum_bytes,
            retained_bytes,
            maximum_envelope_bank_bytes,
            controller,
            provider,
            pending,
            unexpected,
        },
        content: ClientContent::decode_compact_metadata8_data(content_bytes, limits.content)?,
    }))
}

fn originals(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    maximum_requests: usize,
    maximum_bank: usize,
    build: bool,
) -> Result<BTreeMap<Id, CompactClientOriginal>, ProviderError> {
    let entries = ledger.row_aligned(
        MetadataRecordKind::Tree,
        size_of::<Id>() + size_of::<CompactClientOriginal>(),
        align_of::<Id>().max(align_of::<CompactClientOriginal>()),
    )?;
    if entries > maximum_requests {
        return Err(refused());
    }
    let mut fields = Fields::object(input)?;
    let mut result = BTreeMap::new();
    let mut count = 0usize;
    let mut previous = None;
    while let Some((key, value)) = fields.pair()? {
        let text = plain_string(key)?;
        if previous.is_some_and(|prior| prior >= text) || count >= entries {
            return Err(invalid());
        }
        previous = Some(text);
        let key = ledger.read::<Id>(key, build)?;
        let mut original = Fields::array(value)?;
        // Each validation-only bank is dropped before the next is decoded.
        let request = bank(next(&mut original)?, ledger, maximum_bank, build)?;
        let identity = ledger.read::<HashRef>(next(&mut original)?, build)?;
        let response_bytes = next(&mut original)?;
        let response = if response_bytes == b"null" {
            None
        } else {
            bank(response_bytes, ledger, maximum_bank, build)?
        };
        original.finish()?;
        count += 1;
        if build {
            result.insert(
                key.ok_or_else(invalid)?,
                CompactClientOriginal {
                    request: request.ok_or_else(invalid)?,
                    identity: identity.ok_or_else(invalid)?,
                    response,
                },
            );
        }
    }
    if count != entries {
        return Err(invalid());
    }
    Ok(result)
}

fn bank(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    maximum: usize,
    build: bool,
) -> Result<Option<CompactJson>, ProviderError> {
    let capacity = ledger.row_aligned(MetadataRecordKind::Vector, 1, 1)?;
    if capacity > maximum {
        return Err(refused());
    }
    let bank =
        HistoricalCompactEnvelope18::decode(input, ledger.limits.maximum_input_bytes, capacity)?;
    if bank.retained_bank_bytes() != capacity {
        return Err(invalid());
    }
    Ok(if build {
        Some(bank.into_historical_bank())
    } else {
        None
    })
}

pub(super) fn next<'a>(fields: &mut Fields<'a>) -> Result<&'a [u8], ProviderError> {
    fields.next_value()?.ok_or_else(invalid)
}

fn number(input: &[u8]) -> Result<usize, ProviderError> {
    usize::try_from(unsigned(input)?).map_err(|_| refused())
}
