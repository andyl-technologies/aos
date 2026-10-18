//! Restores the complete endpoint-owned original Observe allocation association.
//!
//! ```text
//! ["source-private.native-capture-allocation-owner/12", creator,
//!  "same-original-thread", "complete-original-observe", observe, sdk_owner,
//!  currency, report, report_ref, [raw_capacity, compact_bytes], capture_option]
//! ```
//!
//! Creator and currency markers remain historical data. They never reconstruct
//! a current thread, Control identity, source admission or report capability.

use super::super::{
    state::{next, tag},
    typed::{Fields, invalid},
};
use super::{capture_sdk::HistoricalNativeCaptureSdkOwner, shared::NativeLedger};
use crate::retained_metadata::{aliases::MetadataSharedKind, records::MetadataRecordKind};
use crate::{
    ProviderError,
    envelope::{Envelope, MessageKind, Method},
    reference_packet::service::capture_allocation::{
        PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA, PacketNativeCaptureAllocationReport,
    },
};
use crucible_node_contract::{ContentRef, HashRef, Position, Validate};

/// Retains the original Control currency as inert historical correspondence.
pub struct HistoricalNativeCaptureCurrency {
    /// Retains the original process identifier without live-process permission.
    pub creator: u32,
    /// Counts actual Control originals before the quoted Observe.
    pub originals_before: usize,
    /// Retains the actual original native model cursor.
    pub cursor: Position,
    /// Identifies the same Control and currency backing in the local alias graph.
    pub control_group: usize,
}

/// Retains all completed allocation-owner fields without live source authority.
pub struct HistoricalNativeCaptureAllocationOwner {
    creator: u32,
    observe: Envelope,
    sdk: HistoricalNativeCaptureSdkOwner,
    currency: HistoricalNativeCaptureCurrency,
    report: PacketNativeCaptureAllocationReport,
    report_reference: ContentRef,
    encoded_report: Vec<u8>,
    capture: Option<Envelope>,
}

impl HistoricalNativeCaptureAllocationOwner {
    /// Borrows the complete original Observe envelope.
    pub fn original_observe_data(&self) -> &Envelope {
        &self.observe
    }

    /// Borrows the exact independently retained typed report.
    pub fn report_data(&self) -> &PacketNativeCaptureAllocationReport {
        &self.report
    }

    /// Borrows the complete raw report bank while preserving its capacity.
    pub fn report_bytes_data(&self) -> &Vec<u8> {
        &self.encoded_report
    }

    /// Borrows the full original raw-report reference.
    pub fn report_reference_data(&self) -> &ContentRef {
        &self.report_reference
    }

    /// Borrows the complete historical SDK association and numeric facts.
    pub fn sdk_data(&self) -> &HistoricalNativeCaptureSdkOwner {
        &self.sdk
    }

    /// Borrows the original Control currency without creating one.
    pub fn currency_data(&self) -> &HistoricalNativeCaptureCurrency {
        &self.currency
    }

    /// Borrows the exact Capture original when the owner has entered that boundary.
    pub fn capture_request_data(&self) -> Option<&Envelope> {
        self.capture.as_ref()
    }

    fn authenticate_quote_facts(&self) -> Result<(), ProviderError> {
        if self.report.shared_edges.get()
            != u64::try_from(self.sdk.strong_edges).map_err(|_| invalid())?
            || self.report.unique_roots.get()
                != u64::try_from(self.sdk.unique_roots).map_err(|_| invalid())?
        {
            return Err(invalid());
        }
        for (report, rows, quote) in [
            (
                &self.report.before,
                &self.report.metadata_banks.before,
                &self.sdk.data.before,
            ),
            (
                &self.report.after,
                &self.report.metadata_banks.after,
                &self.sdk.data.after,
            ),
        ] {
            let literal = quote
                .allocation
                .literal
                .map_or(0, |bank| bank.allocated_bytes);
            for (reported, actual) in [
                (report.encoded_capacity, quote.allocation.encoded_capacity),
                (report.literal_and_descriptor_bytes, literal),
                (report.current_encoded_bytes, quote.current_encoded_extent),
                (rows.selected_rows, quote.records.maximum_rows),
                (rows.selected_rows, quote.aliases.maximum_rows),
                (rows.record_capacity, quote.records.capacity_rows),
                (rows.record_bytes, quote.records.allocated_bytes),
                (rows.alias_row_capacity, quote.aliases.row_capacity),
                (rows.alias_lookup_capacity, quote.aliases.lookup_capacity),
                (rows.alias_row_bytes, quote.aliases.row_bytes),
                (rows.alias_lookup_bytes, quote.aliases.lookup_bytes),
            ] {
                if reported.get() != u64::try_from(actual).map_err(|_| invalid())? {
                    return Err(invalid());
                }
            }
        }
        Ok(())
    }

    pub(super) fn authenticate_connection(
        &self,
        connection: &super::connection::HistoricalNativeConnection,
    ) -> Result<(), ProviderError> {
        self.sdk.authenticate_connection(connection)?;
        self.observe.validate()?;
        self.report.validate_data()?;
        self.report_reference.validate()?;
        self.authenticate_quote_facts()?;
        let scope = &self.report.scope;
        if self.creator == 0
            || self.currency.creator != self.creator
            || self.observe.message != MessageKind::Request
            || self.observe.method != Method::Observe
            || self.observe.request_id.0.as_ref() != Some(&scope.observe_request)
            || self.observe.sequence != scope.observe_sequence
            || scope.native_pid.get() != u64::from(self.creator)
            || scope.control_originals_before.get()
                != u64::try_from(self.currency.originals_before).map_err(|_| invalid())?
            || scope.model_cursor != self.currency.cursor
            || scope.session != connection.authority.session
            || scope.incarnation != connection.authority.incarnation
            || self.report_reference.media_type != PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA
        {
            return Err(invalid());
        }
        authenticate_hash(
            "cnp.blob.v1",
            &self.report_reference.hash,
            self.report_reference.length.get(),
            &self.encoded_report,
        )?;
        super::capture_report::authenticate_canonical_report(&self.encoded_report, &self.report)?;
        let (observe_body, observe_slot) =
            original_body_and_slot(&self.observe, &connection.frames)?;
        // Observe facts name the completed prefix before its proof publication.
        // The same immutable bank capacities survive appended proof/Capture slots.
        let maximum_frame_bytes = usize::try_from(connection.authority.limits.frame_bytes.get())
            .map_err(|_| invalid())?;
        if connection
            .frames
            .original_storage_prefix_data(observe_slot, maximum_frame_bytes)?
            != self.sdk.data.original_storage
        {
            return Err(invalid());
        }
        authenticate_hash(
            crate::reference_packet::service::capture_allocation::NATIVE_CAPTURE_ALLOCATION_OBSERVE_DOMAIN,
            &scope.observe_hash,
            u64::try_from(observe_body.len()).map_err(|_| invalid())?,
            observe_body,
        )?;
        if let Some(capture) = &self.capture {
            if capture.message != MessageKind::Request
                || capture.method != Method::Begin
                || capture.body.get("kind").and_then(serde_json::Value::as_str) != Some("capture")
            {
                return Err(invalid());
            }
            capture.validate()?;
            original_body(capture, &connection.frames)?;
        }
        Ok(())
    }
}

fn original_body<'a>(
    original: &Envelope,
    frames: &'a crate::transport::DecodedCompactOriginalFrames,
) -> Result<&'a [u8], ProviderError> {
    original_body_and_slot(original, frames).map(|(body, _)| body)
}

fn original_body_and_slot<'a>(
    original: &Envelope,
    frames: &'a crate::transport::DecodedCompactOriginalFrames,
) -> Result<(&'a [u8], usize), ProviderError> {
    let mut found = None;
    for (index, frame) in frames.frames().enumerate() {
        if frame.direction != crate::transport::original_frames::FrameDirection::Incoming
            || !frame.complete
            || frame.transferred != frame.bytes.len()
        {
            continue;
        }
        let body = frame.bytes.get(4..).ok_or_else(invalid)?;
        if !same_original_header(original, body)? {
            continue;
        }
        // Only the exact original ID and sequence reach the full body walk.
        // A malformed or duplicated matching slot refuses rather than being
        // skipped in favor of a later same-valued replacement.
        super::super::correspondence::envelope(original, body)?;
        if found.replace((body, index)).is_some() {
            return Err(invalid());
        }
    }
    found.ok_or_else(invalid)
}

fn same_original_header(original: &Envelope, body: &[u8]) -> Result<bool, ProviderError> {
    let request = original.request_id.0.as_ref().ok_or_else(invalid)?;
    let mut fields = Fields::object(body)?;
    let mut request_field = None;
    let mut sequence_field = None;
    let mut count = 0usize;
    while let Some((key, value)) = fields.pair()? {
        count = count
            .checked_add(1)
            .filter(|count| *count <= 14)
            .ok_or_else(invalid)?;
        match super::super::typed::plain_string(key)? {
            "request_id" if request_field.replace(value).is_some() => return Err(invalid()),
            "sequence" if sequence_field.replace(value).is_some() => return Err(invalid()),
            _ => {}
        }
    }
    fields.finish()?;
    let actual_request = request_field.ok_or_else(invalid)?;
    if actual_request == b"null" {
        return Ok(false);
    }
    if super::super::typed::plain_string(actual_request)? != request.as_str() {
        return Ok(false);
    }
    let sequence = super::super::typed::plain_string(sequence_field.ok_or_else(invalid)?)?;
    Ok(super::super::typed::unsigned(sequence.as_bytes())? == original.sequence.get())
}

fn authenticate_hash(
    domain: &str,
    reference: &HashRef,
    length: u64,
    bytes: &[u8],
) -> Result<(), ProviderError> {
    reference.validate()?;
    if reference.domain != domain || length != u64::try_from(bytes.len()).map_err(|_| invalid())? {
        return Err(invalid());
    }
    let mut hash = blake3::Hasher::new();
    hash.update(b"CNP/1\0");
    hash.update(
        &u32::try_from(domain.len())
            .map_err(|_| invalid())?
            .to_be_bytes(),
    );
    hash.update(domain.as_bytes());
    hash.update(&length.to_be_bytes());
    hash.update(bytes);
    if hash.finalize().to_hex().as_bytes() != reference.digest.as_bytes() {
        return Err(invalid());
    }
    Ok(())
}

fn currency(
    input: &[u8],
    ledger: &mut NativeLedger<'_, '_, '_, '_, '_>,
    build: bool,
) -> Result<Option<HistoricalNativeCaptureCurrency>, ProviderError> {
    let mut fields = Fields::array(input)?;
    tag(
        &mut fields,
        "source-private.native-control-capture-currency/12",
    )?;
    let creator = next(&mut fields)?;
    let originals_before = next(&mut fields)?;
    let cursor = next(&mut fields)?;
    let mut group = None;
    // The ordinary observer records both real Rc edges before scalar fields.
    for _ in 0..2 {
        let marker = next(&mut fields)?;
        if super::super::typed::plain_string(marker)?
            != "source-private.native-control-identity-owner/12"
            || ledger.ledger.row(MetadataRecordKind::Shared, 1)? != std::mem::size_of::<()>()
        {
            return Err(invalid());
        }
        let actual = ledger.ledger.shared(
            MetadataSharedKind::NativeControlIdentity,
            std::mem::size_of::<()>(),
            marker,
            b"",
        )?;
        if group.is_some_and(|original| original != actual) {
            return Err(invalid());
        }
        group = Some(actual);
    }
    fields.finish()?;
    let creator = ledger.ledger.read::<u32>(creator, build)?;
    let originals_before = ledger.ledger.read::<usize>(originals_before, build)?;
    let cursor = ledger.ledger.read::<Position>(cursor, build)?;
    if !build {
        return Ok(None);
    }
    Ok(Some(HistoricalNativeCaptureCurrency {
        creator: creator.ok_or_else(invalid)?,
        originals_before: originals_before.ok_or_else(invalid)?,
        cursor: cursor.ok_or_else(invalid)?,
        control_group: group.ok_or_else(invalid)?,
    }))
}

pub(super) fn read(
    input: &[u8],
    ledger: &mut NativeLedger<'_, '_, '_, '_, '_>,
    build: bool,
) -> Result<Option<HistoricalNativeCaptureAllocationOwner>, ProviderError> {
    let mut fields = Fields::array(input)?;
    tag(
        &mut fields,
        "source-private.native-capture-allocation-owner/12",
    )?;
    let creator = ledger.ledger.read::<u32>(next(&mut fields)?, build)?;
    tag(&mut fields, "same-original-thread")?;
    tag(&mut fields, "complete-original-observe")?;
    let observe = ledger.ledger.read::<Envelope>(next(&mut fields)?, build)?;
    let sdk = super::capture_sdk::read(next(&mut fields)?, ledger, build)?;
    let currency = currency(next(&mut fields)?, ledger, build)?;
    let report = ledger
        .ledger
        .read::<PacketNativeCaptureAllocationReport>(next(&mut fields)?, build)?;
    let report_reference = ledger
        .ledger
        .read::<ContentRef>(next(&mut fields)?, build)?;
    let encoded_report = super::bytes::bank(next(&mut fields)?, ledger.ledger, build, None)?;
    let capture = ledger
        .ledger
        .read::<Option<Envelope>>(next(&mut fields)?, build)?;
    fields.finish()?;
    if !build {
        return Ok(None);
    }
    Ok(Some(HistoricalNativeCaptureAllocationOwner {
        creator: creator.ok_or_else(invalid)?,
        observe: observe.ok_or_else(invalid)?,
        sdk: sdk.ok_or_else(invalid)?,
        currency: currency.ok_or_else(invalid)?,
        report: report.ok_or_else(invalid)?,
        report_reference: report_reference.ok_or_else(invalid)?,
        encoded_report: encoded_report.ok_or_else(invalid)?,
        capture: capture.ok_or_else(invalid)?,
    }))
}

// crucible-lint: allow panic-shortcut -- borrowed original-header identity and duplicate refusal controls.
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "exact original-header and malformed data assertions"
)]
mod tests {
    use super::*;
    use crate::envelope::Nullable;
    use crucible_node_contract::{Id, U64, canonical};

    fn original() -> Envelope {
        Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(Some(Id::new("session").unwrap())),
            incarnation_id: Nullable(Some(Id::new("incarnation").unwrap())),
            node_id: Nullable(None),
            execution_owner_id: Nullable(None),
            capture_owner_id: Nullable(None),
            request_id: Nullable(Some(Id::new("observe").unwrap())),
            operation_id: Nullable(None),
            sequence: U64::new(7),
            method: Method::Observe,
            body: serde_json::Map::new(),
            extensions: Default::default(),
        }
    }

    #[test]
    fn original_header_scan_handles_late_fields_and_refuses_duplicate_or_changed_sequence() {
        let original = original();
        let bytes = canonical::canonical_json(&serde_json::to_value(&original).unwrap()).unwrap();
        assert!(same_original_header(&original, &bytes).unwrap());
        let text = std::str::from_utf8(&bytes).unwrap();
        let changed = text.replace("\"sequence\":\"7\"", "\"sequence\":\"8\"");
        assert_ne!(changed, text);
        assert!(!same_original_header(&original, changed.as_bytes()).unwrap());
        let duplicate = text.replace(
            "\"request_id\":\"observe\"",
            "\"request_id\":\"observe\",\"request_id\":\"observe\"",
        );
        assert!(same_original_header(&original, duplicate.as_bytes()).is_err());
        let unknown = text.replace("\"request_id\":\"observe\"", "\"request_id\":\"different\"");
        assert!(!same_original_header(&original, unknown.as_bytes()).unwrap());
    }
}

// The closed owning walk fails to compile if a historical field is added.
super::super::retained_storage::fields!(
    HistoricalNativeCaptureCurrency,
    creator,
    originals_before,
    cursor,
    control_group
);
super::super::retained_storage::fields!(
    HistoricalNativeCaptureAllocationOwner,
    creator,
    observe,
    sdk,
    currency,
    report,
    report_reference,
    encoded_report,
    capture
);

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

    field::<u32>()
        + field::<usize>()
        + field::<Position>()
        + field::<u32>()
        + field::<Envelope>()
        + field::<PacketNativeCaptureAllocationReport>()
        + field::<ContentRef>()
        + field::<Option<Envelope>>()
        + header::<HistoricalNativeCaptureAllocationOwner>()
        + header::<super::capture_sdk::HistoricalNativeCaptureSdkOwner>()
        + header::<HistoricalNativeCaptureCurrency>()
}
