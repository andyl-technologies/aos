//! Reconstructs native transfer, chunk, pin and retirement history as inert data.

use super::super::{
    state::{next, tag},
    typed::{Fields, Ledger, invalid, plain_string},
};
use super::{bytes::bank, shared::NativeLedger};
use crate::{
    ProviderError,
    blob::{BlobLimits, BlobRetirement, TransferKey},
    envelope::RequestOrigin,
    retained_metadata::{aliases::MetadataSharedKind, records::MetadataRecordKind},
};
use crucible_node_format::{ContentRef, Id, U64};
use std::{collections::BTreeMap, rc::Rc};

/// Retains a historical consuming-pin phase without issuing a consuming pin.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoricalNativePinPhase {
    /// Retains an original held obligation.
    Held,
    /// Retains an original quarantined obligation.
    Quarantined,
    /// Retains an original settled obligation.
    Settled,
}

/// Retains every original consuming-pin field without settlement authority.
pub struct HistoricalNativeBlobPin {
    /// Retains the complete original owner identity and String capacity.
    pub owner: Id,
    /// Retains the complete consuming schema reference.
    pub schema: ContentRef,
    /// Retains the original held/quarantined/settled phase.
    pub phase: HistoricalNativePinPhase,
    /// Retains any complete authenticated receipt as historical data only.
    pub receipt: Option<ContentRef>,
}

/// Retains every original transfer and its nonrefunded storage obligation.
pub struct HistoricalNativeBlobRecord {
    /// Retains the full original content commitment.
    pub content: ContentRef,
    /// Retains the originally declared decoded length.
    pub length: usize,
    /// Retains all received bytes and the original spare Vec capacity.
    pub bytes: Vec<u8>,
    /// Retains all original offset/length chunk boundaries including retries.
    pub chunks: BTreeMap<usize, usize>,
    /// Retains the original digest verification phase.
    pub verified: bool,
    /// Retains the original quarantine phase.
    pub quarantined: bool,
    /// Retains whether content was exposed to an original consuming operation.
    pub exposed: bool,
    /// Retains the full original retirement and custody receipt.
    pub retirement: Option<BlobRetirement>,
    /// Retains every original consuming-pin identity and obligation.
    pub pins: BTreeMap<u64, HistoricalNativeBlobPin>,
    /// Retains whether this record still consumes reserved byte credit.
    pub charged: bool,
}

/// Retains the entire original native blob ledger without a live receiver.
pub struct HistoricalNativeBlobLedger {
    /// Retains original nonrefunded content storage usage.
    pub reserved: usize,
    /// Retains the next original consuming-pin identity without renewing it.
    pub next_pin: U64,
    /// Retains the lifetime consuming-pin population.
    pub pins_created: usize,
    /// Retains all original records, tombstones and their typed field owners.
    pub records: BTreeMap<TransferKey, HistoricalNativeBlobRecord>,
}

/// Retains the native receiver declaration and its original shared ledger group.
pub struct HistoricalNativeBlobReceiver {
    /// Retains the original session identity and its String capacity.
    pub session: Id,
    /// Retains the original surviving incarnation identity and its capacity.
    pub incarnation: Id,
    /// Retains all seven finite original receiver limits.
    pub limits: BlobLimits,
    /// Shares the full historical ledger with the original Connection data.
    pub state: Rc<HistoricalNativeBlobLedger>,
    /// Identifies the checked shared original supervisor family as historical data.
    pub supervisor_group: usize,
}

// Preserves the original origin/session/incarnation/transfer ordering.
type TransferKeyOrder<'a> = (u8, &'a str, &'a str, &'a str);

fn key<'a>(
    input: &'a [u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<(Option<TransferKey>, TransferKeyOrder<'a>), ProviderError> {
    let mut fields = Fields::array(input)?;
    let (rank, origin) = match plain_string(next(&mut fields)?)? {
        "controller" => (0, RequestOrigin::Controller),
        "provider" => (1, RequestOrigin::Provider),
        _ => return Err(invalid()),
    };
    let session_raw = next(&mut fields)?;
    let incarnation_raw = next(&mut fields)?;
    let transfer_raw = next(&mut fields)?;
    let borrowed = (
        rank,
        plain_string(session_raw)?,
        plain_string(incarnation_raw)?,
        plain_string(transfer_raw)?,
    );
    let session = ledger.read::<Id>(session_raw, build)?;
    let incarnation = ledger.read::<Id>(incarnation_raw, build)?;
    let transfer = ledger.read::<Id>(transfer_raw, build)?;
    fields.finish()?;
    Ok((
        if build {
            Some(TransferKey {
                origin,
                session: session.ok_or_else(invalid)?,
                incarnation: incarnation.ok_or_else(invalid)?,
                transfer: transfer.ok_or_else(invalid)?,
            })
        } else {
            None
        },
        borrowed,
    ))
}

fn retirement(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<Option<BlobRetirement>>, ProviderError> {
    let mut fields = Fields::array(input)?;
    let kind = plain_string(next(&mut fields)?)?;
    let owner = next(&mut fields)?;
    let receipt = next(&mut fields)?;
    fields.finish()?;
    let value = match kind {
        "none" | "abandon-inert" => {
            if owner != b"null" || receipt != b"null" {
                return Err(invalid());
            }
            if kind == "none" {
                None
            } else {
                Some(BlobRetirement::AbandonInert)
            }
        }
        "operation" => {
            if owner == b"null" || receipt == b"null" {
                return Err(invalid());
            }
            let owner = ledger.read::<Id>(owner, build)?;
            let receipt = ledger.read::<ContentRef>(receipt, build)?;
            if build {
                Some(BlobRetirement::Operation {
                    owner: owner.ok_or_else(invalid)?,
                    receipt: receipt.ok_or_else(invalid)?,
                })
            } else {
                None
            }
        }
        "durable-store" => {
            if owner != b"null" || receipt == b"null" {
                return Err(invalid());
            }
            let receipt = ledger.read::<ContentRef>(receipt, build)?;
            if build {
                Some(BlobRetirement::DurableStore {
                    receipt: receipt.ok_or_else(invalid)?,
                })
            } else {
                None
            }
        }
        _ => return Err(invalid()),
    };
    Ok(build.then_some(value))
}

fn chunks(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<BTreeMap<usize, usize>>, ProviderError> {
    let count = ledger.row(MetadataRecordKind::Tree, std::mem::size_of::<usize>() * 2)?;
    ledger.native17_target_tree_data::<usize, usize>(count)?;
    let mut fields = Fields::array(input)?;
    let mut actual = 0usize;
    let mut previous = None;
    let mut result = BTreeMap::new();
    while let Some(item) = fields.next()? {
        actual = actual
            .checked_add(1)
            .filter(|n| *n <= count)
            .ok_or_else(invalid)?;
        let mut pair = Fields::array(item)?;
        let offset = ledger
            .read::<usize>(next(&mut pair)?, true)?
            .ok_or_else(invalid)?;
        let length = ledger
            .read::<usize>(next(&mut pair)?, true)?
            .ok_or_else(invalid)?;
        pair.finish()?;
        if length == 0
            || previous.is_some_and(|value| value >= offset)
            || offset.checked_add(length).is_none()
        {
            return Err(invalid());
        }
        previous = Some(offset);
        if build {
            result.insert(offset, length);
        }
    }
    fields.finish()?;
    if actual != count {
        return Err(invalid());
    }
    Ok(build.then_some(result))
}

fn pins(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<BTreeMap<u64, HistoricalNativeBlobPin>>, ProviderError> {
    let count = ledger.row(
        MetadataRecordKind::Tree,
        crate::blob::original_blob_layouts().pin_tree,
    )?;
    ledger.native17_target_tree_data::<u64, HistoricalNativeBlobPin>(count)?;
    let mut fields = Fields::array(input)?;
    let mut actual = 0usize;
    let mut previous = None;
    let mut result = BTreeMap::new();
    while let Some(item) = fields.next()? {
        actual = actual
            .checked_add(1)
            .filter(|n| *n <= count)
            .ok_or_else(invalid)?;
        let mut pin = Fields::array(item)?;
        let id = ledger
            .read::<U64>(next(&mut pin)?, true)?
            .ok_or_else(invalid)?
            .get();
        if id == 0 || previous.is_some_and(|value| value >= id) {
            return Err(invalid());
        }
        previous = Some(id);
        let owner = ledger.read::<Id>(next(&mut pin)?, build)?;
        let schema = ledger.read::<ContentRef>(next(&mut pin)?, build)?;
        let phase = match plain_string(next(&mut pin)?)? {
            "held" => HistoricalNativePinPhase::Held,
            "quarantined" => HistoricalNativePinPhase::Quarantined,
            "settled" => HistoricalNativePinPhase::Settled,
            _ => return Err(invalid()),
        };
        let receipt = ledger.read::<Option<ContentRef>>(next(&mut pin)?, build)?;
        pin.finish()?;
        if build {
            result.insert(
                id,
                HistoricalNativeBlobPin {
                    owner: owner.ok_or_else(invalid)?,
                    schema: schema.ok_or_else(invalid)?,
                    phase,
                    receipt: receipt.ok_or_else(invalid)?,
                },
            );
        }
    }
    fields.finish()?;
    if actual != count {
        return Err(invalid());
    }
    Ok(build.then_some(result))
}

pub(super) fn read_ledger(
    input: &[u8],
    ledger: &mut NativeLedger<'_, '_, '_, '_, '_>,
    build: bool,
) -> Result<Option<HistoricalNativeBlobLedger>, ProviderError> {
    let mut fields = Fields::array(input)?;
    tag(&mut fields, "source-private.native-blob-ledger/11")?;
    let reserved = ledger.ledger.read::<usize>(next(&mut fields)?, build)?;
    let next_pin = ledger.ledger.read::<U64>(next(&mut fields)?, build)?;
    let pins_created = ledger.ledger.read::<usize>(next(&mut fields)?, build)?;
    let count = ledger.ledger.row(
        MetadataRecordKind::Tree,
        crate::blob::original_blob_layouts().record_tree,
    )?;
    ledger
        .ledger
        .native17_target_tree_data::<TransferKey, HistoricalNativeBlobRecord>(count)?;
    ledger.historical_payload_layout_bytes = ledger
        .historical_payload_layout_bytes
        .checked_add(
            count
                .checked_mul(
                    std::mem::size_of::<TransferKey>()
                        + std::mem::size_of::<HistoricalNativeBlobRecord>(),
                )
                .ok_or_else(invalid)?,
        )
        .ok_or_else(invalid)?;
    let mut records = Fields::array(next(&mut fields)?)?;
    let mut actual = 0usize;
    let mut previous = None;
    let mut result = BTreeMap::new();
    while let Some(item) = records.next()? {
        actual = actual
            .checked_add(1)
            .filter(|n| *n <= count)
            .ok_or_else(invalid)?;
        let mut record = Fields::array(item)?;
        let (key, borrowed_key) = key(next(&mut record)?, ledger.ledger, build)?;
        if previous.is_some_and(|previous| previous >= borrowed_key) {
            return Err(invalid());
        }
        previous = Some(borrowed_key);
        let content = ledger
            .ledger
            .read::<ContentRef>(next(&mut record)?, build)?;
        let length = ledger.ledger.read::<usize>(next(&mut record)?, build)?;
        let bytes = bank(next(&mut record)?, ledger.ledger, build, None)?;
        let chunks = chunks(next(&mut record)?, ledger.ledger, build)?;
        let verified = ledger.ledger.read::<bool>(next(&mut record)?, build)?;
        let quarantined = ledger.ledger.read::<bool>(next(&mut record)?, build)?;
        let exposed = ledger.ledger.read::<bool>(next(&mut record)?, build)?;
        let retirement = retirement(next(&mut record)?, ledger.ledger, build)?;
        let pin_row = ledger.ledger.rows.clone().next().ok_or_else(invalid)??;
        ledger.historical_payload_layout_bytes = ledger
            .historical_payload_layout_bytes
            .checked_add(
                pin_row
                    .extent
                    .checked_mul(
                        std::mem::size_of::<u64>() + std::mem::size_of::<HistoricalNativeBlobPin>(),
                    )
                    .ok_or_else(invalid)?,
            )
            .ok_or_else(invalid)?;
        let pins = pins(next(&mut record)?, ledger.ledger, build)?;
        let charged = ledger.ledger.read::<bool>(next(&mut record)?, build)?;
        record.finish()?;
        if build {
            result.insert(
                key.ok_or_else(invalid)?,
                HistoricalNativeBlobRecord {
                    content: content.ok_or_else(invalid)?,
                    length: length.ok_or_else(invalid)?,
                    bytes: bytes.ok_or_else(invalid)?,
                    chunks: chunks.ok_or_else(invalid)?,
                    verified: verified.ok_or_else(invalid)?,
                    quarantined: quarantined.ok_or_else(invalid)?,
                    exposed: exposed.ok_or_else(invalid)?,
                    retirement: retirement.ok_or_else(invalid)?,
                    pins: pins.ok_or_else(invalid)?,
                    charged: charged.ok_or_else(invalid)?,
                },
            );
        }
    }
    records.finish()?;
    fields.finish()?;
    if actual != count {
        return Err(invalid());
    }
    if !build {
        return Ok(None);
    }
    Ok(Some(HistoricalNativeBlobLedger {
        reserved: reserved.ok_or_else(invalid)?,
        next_pin: next_pin.ok_or_else(invalid)?,
        pins_created: pins_created.ok_or_else(invalid)?,
        records: result,
    }))
}

pub(super) fn read_receiver(
    input: &[u8],
    ledger: &mut NativeLedger<'_, '_, '_, '_, '_>,
    build: bool,
    supervisor_layout: usize,
) -> Result<Option<HistoricalNativeBlobReceiver>, ProviderError> {
    let mut fields = Fields::array(input)?;
    tag(&mut fields, "source-private.native-blob-receiver/11")?;
    let session = ledger.ledger.read::<Id>(next(&mut fields)?, build)?;
    let incarnation = ledger.ledger.read::<Id>(next(&mut fields)?, build)?;
    let mut limits = Fields::array(next(&mut fields)?)?;
    let mut values = [0usize; 7];
    for value in &mut values {
        *value = ledger
            .ledger
            .read::<usize>(next(&mut limits)?, true)?
            .ok_or_else(invalid)?;
    }
    limits.finish()?;
    let [
        reserved_bytes,
        content_bytes,
        chunk_bytes,
        transfers_per_origin,
        tombstones_per_origin,
        chunks_per_transfer,
        operation_pins,
    ] = values;
    if chunk_bytes == 0
        || chunk_bytes > 1_048_576
        || !(1..=4096).contains(&transfers_per_origin)
        || !(1..=4096).contains(&tombstones_per_origin)
        || chunks_per_transfer == 0
        || operation_pins == 0
    {
        return Err(invalid());
    }
    let limits = BlobLimits {
        reserved_bytes,
        content_bytes,
        chunk_bytes,
        transfers_per_origin,
        tombstones_per_origin,
        chunks_per_transfer,
        operation_pins,
    };
    let state = ledger.blobs(next(&mut fields)?, build)?;
    let marker = next(&mut fields)?;
    if plain_string(marker)? != "source-private.native-supervisor-owner/11"
        || ledger.ledger.row(MetadataRecordKind::Shared, 1)? != supervisor_layout
    {
        return Err(invalid());
    }
    let supervisor_group = ledger.ledger.shared(
        MetadataSharedKind::NativeSupervisor,
        supervisor_layout,
        marker,
        b"",
    )?;
    fields.finish()?;
    if !build {
        return Ok(None);
    }
    Ok(Some(HistoricalNativeBlobReceiver {
        session: session.ok_or_else(invalid)?,
        incarnation: incarnation.ok_or_else(invalid)?,
        limits,
        state: state.ok_or_else(invalid)?,
        supervisor_group,
    }))
}

impl HistoricalNativeBlobReceiver {
    /// Checks all retained transfer, chunk, reservation and pin relationships.
    ///
    /// # Errors
    /// Refuses inconsistent scopes, lengths, chunks, digests, pin history or
    /// nonrefunded credit. This data predicate grants no consuming authority.
    pub fn authenticate_state(&self) -> Result<(), ProviderError> {
        // Actual metadata rows already bound the population below131072. The
        // fixed bitset checks global identities without another heap owner.
        let mut pin_ids = [0u64; 2048];
        let mut charged = 0usize;
        let mut pins_created = 0usize;
        let mut active = [0usize; 2];
        let mut retired = [0usize; 2];
        for (key, record) in &self.state.records {
            let origin = match key.origin {
                RequestOrigin::Controller => 0,
                RequestOrigin::Provider => 1,
            };
            if key.session != self.session
                || key.incarnation != self.incarnation
                || record.content.length.get() != record.length as u64
                || record.length > self.limits.content_bytes
                || record.bytes.len() > record.length
                || record.chunks.len() > self.limits.chunks_per_transfer
            {
                return Err(invalid());
            }
            if record.retirement.is_none() {
                active[origin] = active[origin].checked_add(1).ok_or_else(invalid)?;
            } else {
                retired[origin] = retired[origin].checked_add(1).ok_or_else(invalid)?;
            }
            let mut end = 0usize;
            for (offset, length) in &record.chunks {
                if *offset != end || *length == 0 || *length > self.limits.chunk_bytes {
                    return Err(invalid());
                }
                end = end
                    .checked_add(*length)
                    .filter(|end| *end <= record.bytes.len())
                    .ok_or_else(invalid)?;
            }
            if end != record.bytes.len() {
                return Err(invalid());
            }
            let unresolved = record
                .pins
                .values()
                .any(|pin| pin.phase != HistoricalNativePinPhase::Settled);
            if record.charged {
                charged = charged.checked_add(record.length).ok_or_else(invalid)?;
                if record.verified {
                    record
                        .content
                        .verify(&record.bytes)
                        .map_err(|_| invalid())?;
                }
            } else if record.retirement.is_none()
                || unresolved
                || !record.bytes.is_empty()
                || !record.chunks.is_empty()
            {
                return Err(invalid());
            }
            if !record.pins.is_empty() && (!record.exposed || !record.verified) {
                return Err(invalid());
            }
            for (id, pin) in &record.pins {
                if *id == 0
                    || *id >= self.state.next_pin.get()
                    || *id > 131072
                    || (pin.phase == HistoricalNativePinPhase::Settled) != pin.receipt.is_some()
                {
                    return Err(invalid());
                }
                let index = usize::try_from(*id - 1).map_err(|_| invalid())?;
                let bit = 1u64 << (index % 64);
                let word = pin_ids.get_mut(index / 64).ok_or_else(invalid)?;
                if *word & bit != 0 {
                    return Err(invalid());
                }
                *word |= bit;
            }
            pins_created = pins_created
                .checked_add(record.pins.len())
                .ok_or_else(invalid)?;
        }
        if charged != self.state.reserved
            || charged > self.limits.reserved_bytes
            || pins_created != self.state.pins_created
            || pins_created > self.limits.operation_pins
            || self.state.next_pin.get()
                != (pins_created as u64).checked_add(1).ok_or_else(invalid)?
            || active
                .into_iter()
                .any(|count| count > self.limits.transfers_per_origin)
            || retired
                .into_iter()
                .any(|count| count > self.limits.tombstones_per_origin)
        {
            return Err(invalid());
        }
        Ok(())
    }
}

pub(super) const PIN_IDENTITY_SCRATCH_BYTES: usize = std::mem::size_of::<[u64; 2048]>();

// The closed owning walk fails to compile if a historical field is added.
super::super::retained_storage::fields!(HistoricalNativeBlobPin, owner, schema, phase, receipt);
super::super::retained_storage::fields!(
    HistoricalNativeBlobRecord,
    content,
    length,
    bytes,
    chunks,
    verified,
    quarantined,
    exposed,
    retirement,
    pins,
    charged
);
super::super::retained_storage::fields!(
    HistoricalNativeBlobLedger,
    reserved,
    next_pin,
    pins_created,
    records
);
super::super::retained_storage::fields!(
    HistoricalNativeBlobReceiver,
    session,
    incarnation,
    limits,
    state,
    supervisor_group
);

/// Reads the stable complete Blob-ledger leaf using the enclosing17 ledger.
///
/// The adapter borrows the same cursor and alias backend. Its separate numeric
/// count reports historical map payload layouts to the caller's admission.
///
/// # Errors
/// Refuses the exact leaf grammar, missing rows or unavailable final backing.
pub(crate) fn read_native17_blob_leaf_data(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<(Option<HistoricalNativeBlobLedger>, usize), ProviderError> {
    let mut exact_rows = ledger.rows.clone();
    let mut adapter = NativeLedger {
        class: None,
        ledger,
        groups: None,
        historical_payload_layout_bytes: 0,
        correlation_capacity_span: None,
    };
    let value = read_ledger(input, &mut adapter, build)?;
    let end = adapter.ledger.rows.encoded_position();
    let layouts = crate::blob::original_blob_layouts();
    let (_, record_alignment, pin_alignment) = crate::blob::original_blob_alignment17_data();
    let mut entries = 0usize;
    while exact_rows.encoded_position() < end {
        let row = exact_rows.next().ok_or_else(invalid)??;
        let expected_alignment = match row.kind {
            MetadataRecordKind::String | MetadataRecordKind::Vector if row.element_bytes == 1 => 1,
            MetadataRecordKind::Tree => {
                entries = entries
                    .checked_add(row.extent)
                    .filter(|entries| *entries <= adapter.ledger.limits.maximum_tree_entries)
                    .ok_or_else(invalid)?;
                if row.element_bytes == layouts.record_tree {
                    record_alignment
                } else if row.element_bytes == layouts.pin_tree {
                    pin_alignment
                } else if row.element_bytes == 2 * std::mem::size_of::<usize>() {
                    std::mem::align_of::<usize>()
                } else {
                    return Err(invalid());
                }
            }
            _ => return Err(invalid()),
        };
        if row.alignment != expected_alignment {
            return Err(invalid());
        }
    }
    Ok((value, adapter.historical_payload_layout_bytes))
}

// The whole17 owning path retains exact transfer/pin partials in typed slots.
pub(crate) mod native17_retained;

pub(crate) mod current17;

/// Names actual fixed local and returned headers of this handwritten reader.
///
/// Empty maps and `Option` payloads remain real controls when `build` is false;
/// no tree entries, backing allocations or owning reconstruction are included.
pub(super) fn borrowed_validation_headers_data() -> usize {
    use std::mem::size_of;

    fn header<T>() -> usize {
        size_of::<Option<T>>() + size_of::<Result<Option<T>, ProviderError>>()
    }

    fn field<T: super::super::typed::HistoricalType>() -> usize {
        header::<T>() + T::borrowed_header_counter_scratch_data()
    }

    field::<Id>()
        + field::<Id>()
        + field::<Id>()
        + field::<Id>()
        + field::<ContentRef>()
        + field::<ContentRef>()
        + field::<usize>()
        + field::<usize>()
        + field::<U64>()
        + field::<Id>()
        + field::<ContentRef>()
        + field::<Option<ContentRef>>()
        + field::<usize>()
        + field::<U64>()
        + field::<usize>()
        + field::<ContentRef>()
        + field::<usize>()
        + field::<bool>()
        + field::<bool>()
        + field::<bool>()
        + field::<bool>()
        + field::<Id>()
        + field::<Id>()
        + field::<usize>()
        + header::<TransferKey>()
        + header::<Option<BlobRetirement>>()
        + header::<BTreeMap<usize, usize>>()
        + header::<BTreeMap<u64, HistoricalNativeBlobPin>>()
        + header::<HistoricalNativeBlobLedger>()
        + header::<HistoricalNativeBlobReceiver>()
        + header::<Vec<u8>>()
        + header::<std::rc::Rc<HistoricalNativeBlobLedger>>()
        + size_of::<BTreeMap<usize, usize>>()
        + size_of::<BTreeMap<u64, HistoricalNativeBlobPin>>()
        + size_of::<BTreeMap<TransferKey, HistoricalNativeBlobRecord>>()
        + size_of::<Option<TransferKeyOrder<'static>>>()
        + size_of::<TransferKeyOrder<'static>>()
        + size_of::<(Option<TransferKey>, TransferKeyOrder<'static>)>()
        + size_of::<Result<(Option<TransferKey>, TransferKeyOrder<'static>), ProviderError>>()
        + size_of::<Option<usize>>()
        + size_of::<[usize; 7]>()
}
