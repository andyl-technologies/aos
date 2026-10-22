//! Prepares a distinct original bootstrap response slot before publication.
//!
//! Preparation retains a distinct bank beside the original Hello pair. Neither
//! encoded bytes nor a completed preparation prove any physical transfer.
//!
//! ```text
//! [length: four big-endian bytes][canonical sealed BootstrapResult18 response]
//! transferred = 0; complete = false
//! ```

use crate::ProviderError;
use crate::envelope::Envelope;
use crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData as Extent;
use crate::transport::original_frames::{FrameDirection, OriginalFrameReservation};
use crucible_node_format::Id;
use serde_json::Value;
use std::io::{self, Write};
use std::mem::{size_of, size_of_val};

/// Retains constructor prefixes and original response transfer progress.
pub(super) struct Literal {
    reserve_started: bool,
    reserved: bool,
    serialize_started: bool,
    measure_started: bool,
    measure_complete: bool,
    encode_started: bool,
    encoded_complete: bool,
    value: Option<Value>,
    journal: Option<OriginalFrameReservation>,
    measured: Option<usize>,
    slot: Option<usize>,
    encoded: usize,
}

impl Literal {
    /// Initializes empty proposal custody without allocation.
    pub(super) fn empty_data() -> Self {
        Self {
            reserve_started: false,
            reserved: false,
            serialize_started: false,
            measure_started: false,
            measure_complete: false,
            encode_started: false,
            encoded_complete: false,
            value: None,
            journal: None,
            measured: None,
            slot: None,
            encoded: 0,
        }
    }

    /// Retains the defining closed-shape bank before encoding begins.
    ///
    /// # Errors
    /// Refuses retry, invalid framing, overflow or allocation failure.
    pub(super) fn reserve_data(&mut self, maximum_encoded: usize) -> Result<(), ProviderError> {
        if self.reserve_started {
            return Err(refused());
        }
        self.reserve_started = true;
        let framed = maximum_encoded.checked_add(4).ok_or_else(exhausted)?;
        OriginalFrameReservation::reserve_retained_into_data(framed, 1, &mut self.journal)?;
        self.reserved = true;
        Ok(())
    }

    /// Retains the actual sealed response serializer tree once.
    ///
    /// # Errors
    /// Refuses retry, missing reservation or serialization failure.
    pub(super) fn serialize_data(
        &mut self,
        reply: &crate::envelope::Envelope,
    ) -> Result<(), ProviderError> {
        if self.serialize_started {
            return Err(refused());
        }
        self.serialize_started = true;
        if !self.reserved {
            return Err(refused());
        }
        self.value =
            Some(serde_json::to_value(reply).map_err(crucible_node_format::ContractError::from)?);
        Ok(())
    }

    /// Retains bounded canonical measurement, including any failed prefix.
    ///
    /// # Errors
    /// Refuses retry, missing tree, invalid JSON, nesting or excessive length.
    pub(super) fn measure_data(
        &mut self,
        maximum: usize,
        maximum_nesting: usize,
    ) -> Result<(), ProviderError> {
        if self.measure_started {
            return Err(refused());
        }
        self.measure_started = true;
        if maximum_nesting == 0 || maximum_nesting > crate::transport::MAX_NESTING {
            return Err(refused());
        }
        let value = self.value.as_ref().ok_or_else(refused)?;
        ensure_nesting_data(value, maximum_nesting)?;
        let mut writer = CountWriter {
            written: 0,
            maximum,
        };
        let outcome = crucible_node_format::canonical::canonical_json_to_writer(value, &mut writer);
        // The actual prefix count survives even a serializer/writer refusal.
        self.measured = Some(writer.written);
        outcome?;
        if writer.written == 0 {
            return Err(refused());
        }
        self.measure_complete = true;
        Ok(())
    }

    /// Retains the framed proposal and original request ID without transfer.
    ///
    /// # Errors
    /// Refuses retry, incomplete measurement, changed ID or bounded writer failure.
    pub(super) fn encode_data(&mut self, request_id: &Id) -> Result<(), ProviderError> {
        if self.encode_started {
            return Err(refused());
        }
        self.encode_started = true;
        if !self.measure_complete {
            return Err(refused());
        }
        let value = self.value.as_ref().ok_or_else(refused)?;
        if value.get("request_id").and_then(Value::as_str) != Some(request_id.as_str()) {
            return Err(refused());
        }
        let measured = self.measured.ok_or_else(refused)?;
        let header = u32::try_from(measured)
            .map_err(|_| exhausted())?
            .to_be_bytes();
        let framed = measured.checked_add(4).ok_or_else(exhausted)?;
        let journal = self.journal.as_mut().ok_or_else(refused)?;
        let slot = journal.begin(FrameDirection::Outgoing, framed)?;
        self.slot = Some(slot);
        journal.retain_request(slot, request_id)?;
        journal.append(slot, &header)?;
        let mut writer = JournalWriter {
            journal,
            slot,
            written: 0,
            maximum: measured,
        };
        let outcome = crucible_node_format::canonical::canonical_json_to_writer(value, &mut writer);
        self.encoded = writer.written;
        outcome?;
        if self.encoded != measured {
            return Err(refused());
        }
        // Encoding retains a proposal. Only the physical publisher may call
        // advance/finish after each actual successful write on the same stream.
        let frame = writer.journal.frame(slot).ok_or_else(refused)?;
        if frame.transferred != 0 || frame.complete || frame.bytes.len() != framed {
            return Err(refused());
        }
        self.encoded_complete = true;
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn assert_prepared_data(&self, reply: &Envelope) {
        let value = serde_json::to_value(reply).unwrap();
        assert_eq!(self.value.as_ref(), Some(&value));
        let canonical = crucible_node_format::canonical::canonical_json(&value).unwrap();
        assert!(self.reserved && self.measure_complete && self.encoded_complete);
        assert_eq!(self.measured, Some(canonical.len()));
        assert_eq!(self.encoded, canonical.len());
        let journal = self.journal.as_ref().unwrap();
        let frame = journal.frame(self.slot.unwrap()).unwrap();
        assert_eq!(frame.direction, FrameDirection::Outgoing);
        assert_eq!(&frame.bytes[..4], &(canonical.len() as u32).to_be_bytes());
        assert_eq!(&frame.bytes[4..], canonical);
        assert_eq!(frame.transferred, 0);
        assert!(!frame.complete);
        assert_eq!(journal.frames().count(), 1);
        assert_eq!(journal.outgoing_original_id_slots(), 1);
        assert!(journal.contains_original_id(reply.request_id.0.as_ref().unwrap().as_str()));
    }

    /// Counts actual retained tree and reservation backing after either outcome.
    ///
    /// # Errors
    /// Refuses unsupported metadata, traversal limits or checked overflow.
    pub(super) fn retained_backing_data(&self) -> Result<usize, ProviderError> {
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        if let Some(value) = &self.value {
            observer.observe(value)?;
        }
        let dom =
            crate::retained_metadata::requested_metadata_backing_storage_data(&observer.finish())?;
        dom.checked_add(
            self.journal
                .as_ref()
                .map_or(0, OriginalFrameReservation::allocated_bytes),
        )
        .ok_or_else(exhausted)
    }
}

// The Literal header is already part of its enclosing Attempt. The retained
// term includes the complete generic DOM bound independently of the fixed bank.
/// Quotes separate DOM, bank, canonical work and constructor storage.
///
/// # Errors
/// Refuses invalid reservation geometry or checked layout overflow.
pub(super) fn backing_construction_data(extent: Extent) -> Result<[usize; 3], ProviderError> {
    let framed = extent
        .maximum_canonical_encoded_bytes
        .checked_add(4)
        .ok_or_else(exhausted)?;
    let bank = OriginalFrameReservation::retained_reservation_requested_bytes_data(framed, 1)?;
    let retained = extent
        .value_dom_requested_bytes
        .checked_add(bank)
        .ok_or_else(exhausted)?;
    // These sequential passes share no output Vec. Keep the full generic DOM
    // constructor and JCS work terms; a fixed bank does not discount either.
    let transient = [
        extent.value_dom_requested_bytes,
        extent.canonical_work_requested_bytes,
        OriginalFrameReservation::retained_reservation_constructor_transient_data(),
        size_of::<Value>(),
        size_of::<Result<Value, serde_json::Error>>(),
        size_of::<[u8; 4]>(),
        size_of::<[u8; 128]>(),
    ]
    .into_iter()
    .try_fold(0usize, |sum, term| {
        sum.checked_add(term).ok_or_else(exhausted)
    })?;
    Ok([retained, transient, counter_scratch_data()?])
}

/// Names the measurement, writer, journal and census controls.
///
/// # Errors
/// Refuses checked control-layout accumulation overflow.
pub(super) fn counter_scratch_data() -> Result<usize, ProviderError> {
    let terms = [
        OriginalFrameReservation::retained_reservation_counter_scratch_data(),
        size_of::<CountWriter>(),
        size_of::<JournalWriter<'static>>(),
        size_of::<&mut CountWriter>(),
        size_of::<&mut JournalWriter<'static>>(),
        size_of::<&mut Literal>() * 4,
        size_of::<&Literal>(),
        size_of::<&Envelope>(),
        size_of::<&Value>() * 3,
        size_of::<Option<&Value>>(),
        size_of::<Result<&Value, ProviderError>>(),
        size_of::<&Id>(),
        size_of::<&str>() * 2,
        size_of::<Option<&str>>() * 2,
        size_of::<&mut OriginalFrameReservation>(),
        size_of::<Option<&mut OriginalFrameReservation>>(),
        size_of::<Result<&mut OriginalFrameReservation, ProviderError>>(),
        size_of::<crate::transport::original_frames::OriginalFrame<'static>>(),
        size_of::<Option<crate::transport::original_frames::OriginalFrame<'static>>>(),
        size_of::<Result<crate::transport::original_frames::OriginalFrame<'static>, ProviderError>>(
        ),
        size_of::<&[u8]>() * 2,
        size_of::<usize>() * 19,
        size_of::<Option<usize>>() * 4,
        size_of::<Result<usize, ProviderError>>() * 4,
        size_of::<Result<usize, io::Error>>() * 2,
        size_of::<io::Error>() * 2,
        size_of::<Result<(), io::Error>>() * 2,
        size_of::<Result<(), ProviderError>>() * 8,
        size_of::<Result<(), crucible_node_format::ContractError>>() * 2,
        size_of::<Result<u32, std::num::TryFromIntError>>(),
        size_of::<Extent>(),
        size_of::<[usize; 7]>(),
        size_of::<std::array::IntoIter<usize, 7>>(),
        size_of::<[usize; 3]>(),
        size_of::<crate::retained_metadata::MetadataObserver<'static>>(),
        size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>(),
        size_of::<Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError>>(),
        size_of::<&mut crate::retained_metadata::MetadataObserver<'static>>(),
        // The closed Envelope/body/result/funding grammar has at most five
        // simultaneously active Value observations. No generic DOM term is
        // removed to pay for these concrete recursive census controls.
        5 * (size_of::<&Value>()
            + size_of::<&String>()
            + size_of::<(&String, &Value)>()
            + size_of::<serde_json::map::Iter<'static>>()
            + size_of::<&mut crate::retained_metadata::MetadataObserver<'static>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<serde_json::map::Values<'static>>()
            + size_of::<std::slice::Iter<'static, Value>>()
            + size_of::<usize>()
            + size_of::<Option<usize>>()),
        // retain_request scans the actual two-direction slot bank and copies a
        // single validated Id into its fixed descriptor; no String is allocated.
        crate::transport::original_frames::original_frames_iterator_counter_scratch_data(),
    ];
    let array_bytes = size_of_val(&terms);
    let mut iterator = terms.into_iter();
    let controls = array_bytes
        .checked_add(size_of_val(&iterator))
        .ok_or_else(exhausted)?;
    iterator.try_fold(controls, |sum, term| {
        sum.checked_add(term).ok_or_else(exhausted)
    })
}

// Checks the retained actual tree without a second parser DOM. Empty maps are
// containers too, following the same negotiated nesting rule as CNP framing.
fn ensure_nesting_data(value: &Value, remaining: usize) -> Result<(), ProviderError> {
    match value {
        Value::Object(fields) => {
            let next = remaining.checked_sub(1).ok_or_else(refused)?;
            for value in fields.values() {
                ensure_nesting_data(value, next)?;
            }
        }
        Value::Array(values) => {
            let next = remaining.checked_sub(1).ok_or_else(refused)?;
            for value in values {
                ensure_nesting_data(value, next)?;
            }
        }
        _ => {}
    }
    Ok(())
}

struct CountWriter {
    written: usize,
    maximum: usize,
}

impl Write for CountWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .written
            .checked_add(bytes.len())
            .filter(|next| *next <= self.maximum)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        self.written = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct JournalWriter<'a> {
    journal: &'a mut OriginalFrameReservation,
    slot: usize,
    written: usize,
    maximum: usize,
}

impl Write for JournalWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .written
            .checked_add(bytes.len())
            .filter(|next| *next <= self.maximum)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        self.journal
            .append(self.slot, bytes)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        self.written = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("bootstrap literal preparation DATA")
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("bootstrap literal preparation DATA")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_measurement_keeps_its_actual_count_and_cannot_be_encoded_or_retried() {
        let mut literal = Literal::empty_data();
        literal.reserve_data(128).unwrap();
        literal.value = Some(serde_json::json!({"original": "retained"}));
        let before = literal.retained_backing_data().unwrap();

        assert!(literal.measure_data(3, 64).is_err());
        assert_eq!(literal.measured, Some(1));
        assert!(!literal.measure_complete);
        assert!(literal.measure_data(128, 64).is_err());
        assert!(literal.encode_data(&Id::new("original").unwrap()).is_err());

        assert!(literal.slot.is_none());
        assert!(!literal.encoded_complete);
        assert_eq!(literal.retained_backing_data().unwrap(), before);
    }

    #[test]
    fn selected_nesting_checks_actual_containers_before_any_encoded_slot() {
        let value = serde_json::json!({"body": {"result": {"funding": {}}}});
        let mut literal = Literal::empty_data();
        literal.reserve_data(128).unwrap();
        literal.value = Some(value.clone());
        let before = literal.retained_backing_data().unwrap();

        assert!(literal.measure_data(128, 3).is_err());
        assert!(literal.measured.is_none() && literal.slot.is_none());
        assert!(!literal.measure_complete);
        assert!(literal.measure_data(128, 4).is_err());
        assert_eq!(literal.retained_backing_data().unwrap(), before);

        let bytes = crucible_node_format::canonical::canonical_json(&value).unwrap();
        assert!(crucible_node_format::canonical::parse_json_with_depth(&bytes, 128, 3).is_err());
        crucible_node_format::canonical::parse_json_with_depth(&bytes, 128, 4).unwrap();
        let mut enough = Literal::empty_data();
        enough.reserve_data(128).unwrap();
        enough.value = Some(value);
        enough.measure_data(128, 4).unwrap();
        assert_eq!(enough.measured, Some(bytes.len()));
    }

    #[test]
    fn failed_encoding_retains_the_original_slot_prefix_and_spends_the_attempt() {
        let id = Id::new("original").unwrap();
        let mut literal = Literal::empty_data();
        literal.reserve_data(128).unwrap();
        literal.value = Some(serde_json::json!({"request_id": id.as_str()}));
        literal.measure_data(128, 64).unwrap();
        // Inject an undersized measured count at the sink boundary. Production
        // custody has no mutation loan between measurement and encoding.
        literal.measured = Some(2);
        let before = literal.retained_backing_data().unwrap();

        assert!(literal.encode_data(&id).is_err());
        let journal = literal.journal.as_ref().unwrap();
        let slot = literal.slot.unwrap();
        let frame = journal.frame(slot).unwrap();
        assert_eq!(frame.bytes, b"\0\0\0\x02{");
        assert_eq!(frame.transferred, 0);
        assert!(!frame.complete && !literal.encoded_complete);
        assert_eq!(literal.encoded, 1);
        assert!(journal.contains_original_id(id.as_str()));
        let pointer = frame.bytes.as_ptr();

        assert!(literal.encode_data(&id).is_err());
        assert_eq!(
            literal
                .journal
                .as_ref()
                .unwrap()
                .frame(slot)
                .unwrap()
                .bytes
                .as_ptr(),
            pointer
        );
        assert_eq!(literal.retained_backing_data().unwrap(), before);
    }
}

#[path = "literal/publication.rs"]
mod publication;

/// Names physical write progress and terminal checks beside the retained bank.
pub(super) fn publication_counter_scratch_data() -> usize {
    size_of::<&mut Literal>() * 3
        + size_of::<&Literal>() * 2
        + size_of::<&mut crate::client::OriginalNativePublicBirthChannel>()
        + size_of::<&mut Option<ProviderError>>()
        + size_of::<&mut OriginalFrameReservation>()
        + size_of::<crate::transport::original_frames::OriginalFrame<'static>>() * 4
        + size_of::<Option<crate::transport::original_frames::OriginalFrame<'static>>>() * 4
        + size_of::<&[u8]>() * 3
        + size_of::<usize>() * 5
        + size_of::<io::Error>()
        + size_of::<io::ErrorKind>() * 2
        + size_of::<io::Result<usize>>() * 2
        + size_of::<Result<(), ProviderError>>() * 6
}
