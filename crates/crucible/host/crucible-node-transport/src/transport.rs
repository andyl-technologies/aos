//! Length-prefixed CNP/1 stream framing with fatal-error fencing.
//!
//! ```text
//! frame = uint32_be(json_byte_length) || utf8_json
//! ```
//!
//! A framing or parsing failure permanently poisons the reader. Its owner must
//! close the connection and retain any unresolved operation obligations.

use std::cell::RefCell;
use std::io::{Read, Write};
use std::rc::Rc;

pub mod original_frames;
use original_frames::{FrameDirection, OriginalFrameReservation};

use crucible_node_format::canonical;
use serde_json::Value;

use crate::ProviderError;

pub use crucible_source_birth_data::profile::reference_packet::service::native_startup::report_ack::MAX_FRAME_BYTES;

/// Limits nested JSON containers independently of frame byte length.
pub const MAX_NESTING: usize = 64;

/// Decodes bounded frames from a stream whose reads may split any byte range.
pub struct FrameReader<R> {
    stream: R,
    maximum_bytes: usize,
    maximum_nesting: usize,
    failed: bool,
    originals: Option<Rc<RefCell<OriginalFrameReservation>>>,
    last_original_slot: Option<usize>,
}

/// Reports only existing reader fields after a same-bank correspondence check.
#[derive(Clone, Copy, serde::Serialize)]
pub(crate) struct OriginalFrameReaderFacts {
    pub(crate) maximum_bytes: usize,
    pub(crate) maximum_nesting: usize,
    pub(crate) failed: bool,
    pub(crate) last_original_slot: Option<usize>,
}

impl<R> FrameReader<R> {
    /// Borrows the original stream without reading, replacing or duplicating it.
    pub(crate) fn stream_ref(&self) -> &R {
        &self.stream
    }

    /// Observes scalar reader state only when the actual bank Rc is unchanged.
    pub(crate) fn original_owned11_facts(
        &self,
        bank: &Rc<RefCell<OriginalFrameReservation>>,
    ) -> Result<OriginalFrameReaderFacts, ProviderError> {
        if self
            .originals
            .as_ref()
            .is_none_or(|original| !Rc::ptr_eq(original, bank))
        {
            return Err(ProviderError::Correlation("original reader bank changed"));
        }
        Ok(OriginalFrameReaderFacts {
            maximum_bytes: self.maximum_bytes,
            maximum_nesting: self.maximum_nesting,
            failed: self.failed,
            last_original_slot: self.last_original_slot,
        })
    }
}

impl<R: Read> FrameReader<R> {
    /// Creates a reader with a positive limit within the CNP/1 hard ceiling.
    ///
    /// # Errors
    /// Rejects a zero allowance or one larger than [`MAX_FRAME_BYTES`].
    pub fn new(stream: R, maximum_bytes: usize) -> Result<Self, ProviderError> {
        Self::with_limits(stream, maximum_bytes, MAX_NESTING)
    }

    /// Creates a reader enforcing both negotiated byte and nesting limits.
    ///
    /// # Errors
    /// Rejects zero or larger-than-baseline limits before reading any bytes.
    pub fn with_limits(
        stream: R,
        maximum_bytes: usize,
        maximum_nesting: usize,
    ) -> Result<Self, ProviderError> {
        check_limit(maximum_bytes)?;
        if maximum_nesting == 0 || maximum_nesting > MAX_NESTING {
            return Err(ProviderError::Frame("invalid negotiated nesting limit"));
        }

        Ok(Self {
            stream,
            maximum_bytes,
            maximum_nesting,
            failed: false,
            originals: None,
            last_original_slot: None,
        })
    }

    // Complete-source births keep the stream outside all fallible framing checks.
    pub(crate) fn with_limits_owned(
        stream: R,
        maximum_bytes: usize,
        maximum_nesting: usize,
    ) -> Result<Self, (R, ProviderError)> {
        let admission = check_limit(maximum_bytes).and({
            if maximum_nesting == 0 || maximum_nesting > MAX_NESTING {
                Err(ProviderError::Frame("invalid negotiated nesting limit"))
            } else {
                Ok(())
            }
        });
        if let Err(error) = admission {
            return Err((stream, error));
        }
        Ok(Self {
            stream,
            maximum_bytes,
            maximum_nesting,
            failed: false,
            originals: None,
            last_original_slot: None,
        })
    }

    /// Reads exactly one JSON frame, distinguishing clean EOF from truncation.
    ///
    /// # Errors
    /// Rejects invalid lengths before allocation, partial frames, malformed
    /// JSON, duplicate keys, invalid Unicode, and reuse after any failure.
    /// An error leaves the stream fenced; bytes are never scanned to resync.
    pub fn read(&mut self) -> Result<Option<Value>, ProviderError> {
        self.read_retained()
            .map(|frame| frame.map(|frame| frame.value))
    }

    /// Keeps original validated wire bytes for source-owned native preparation.
    pub(crate) fn read_retained(&mut self) -> Result<Option<RetainedFrame>, ProviderError> {
        self.read_retained_with_maximum_bytes(self.maximum_bytes)
    }

    // This data-only restriction never increases negotiated credit. The native
    // source-owned ACK scope must authenticate its original peer marker before
    // using it. Oversized headers retain their partial literal slot and poison
    // this same reader; no fallback or replay is attempted.
    pub(crate) fn read_retained_with_maximum_bytes(
        &mut self,
        maximum_bytes: usize,
    ) -> Result<Option<RetainedFrame>, ProviderError> {
        if self.failed {
            return Err(ProviderError::Frame("connection already failed"));
        }
        if maximum_bytes == 0 || maximum_bytes > self.maximum_bytes {
            return Err(ProviderError::Frame(
                "selected read exceeds negotiated frame limit",
            ));
        }
        let result = self.read_frame_with_maximum_bytes(maximum_bytes);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// Reads an original frame under its caller-authenticated layout window.
    ///
    /// The view restricts allocation and grants no read or native authority.
    ///
    /// # Errors
    /// Preserves framing/read errors and fences the same reader on refused
    /// preflight or strict parsing. Existing literal originals stay retained.
    pub(crate) fn read_original_native_preflight(
        &mut self,
        maximum_bytes: usize,
        preflight: &crate::reference_packet::service::native_startup::OriginalNativeFramePreflight<
            '_,
        >,
    ) -> Result<Option<RetainedFrame>, ProviderError> {
        if self.failed {
            return Err(ProviderError::Frame("connection already failed"));
        }
        if maximum_bytes == 0 || maximum_bytes > self.maximum_bytes {
            return Err(ProviderError::Frame(
                "selected read exceeds negotiated frame limit",
            ));
        }
        if self.originals.is_none() {
            return Err(ProviderError::Frame("original bank absent"));
        }
        let result = self.read_original_frame_with_preflight(maximum_bytes, Some(preflight));
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    pub(crate) fn stream_mut(&mut self) -> &mut R {
        &mut self.stream
    }

    /// Returns the same original stream; its separate journal retains all cuts.
    pub(crate) fn into_inner(self) -> R {
        self.stream
    }

    pub(crate) fn original_slot(&self) -> Option<usize> {
        self.last_original_slot
    }

    pub(crate) fn install_originals(&mut self, originals: Rc<RefCell<OriginalFrameReservation>>) {
        self.originals = Some(originals);
    }

    fn read_frame_with_maximum_bytes(
        &mut self,
        maximum_bytes: usize,
    ) -> Result<Option<RetainedFrame>, ProviderError> {
        if self.originals.is_some() {
            return self.read_original_frame_with_maximum_bytes(maximum_bytes);
        }
        let mut header = [0_u8; 4];
        let first = loop {
            match self.stream.read(&mut header[..1]) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                result => break result?,
            }
        };
        if first == 0 {
            return Ok(None);
        }
        self.stream.read_exact(&mut header[1..])?;

        let length = u32::from_be_bytes(header) as usize;
        if length == 0 || length > maximum_bytes {
            return Err(ProviderError::Frame("length outside admitted allowance"));
        }

        let mut body = vec![0_u8; length];
        self.stream.read_exact(&mut body)?;
        let value = canonical::parse_json_with_depth(&body, maximum_bytes, self.maximum_nesting)?;
        Ok(Some(RetainedFrame { value, bytes: body }))
    }
    fn read_original_frame_with_maximum_bytes(
        &mut self,
        maximum_bytes: usize,
    ) -> Result<Option<RetainedFrame>, ProviderError> {
        self.read_original_frame_with_preflight(maximum_bytes, None)
    }

    fn read_original_frame_with_preflight(
        &mut self,
        maximum_bytes: usize,
        preflight: Option<
            &crate::reference_packet::service::native_startup::OriginalNativeFramePreflight<'_>,
        >,
    ) -> Result<Option<RetainedFrame>, ProviderError> {
        let bank = self
            .originals
            .as_ref()
            .ok_or(ProviderError::Frame("original bank absent"))?
            .clone();
        // The maximum possible frame is admitted before reading its first byte.
        let slot = bank
            .borrow_mut()
            .begin(FrameDirection::Incoming, maximum_bytes + 4)?;
        self.last_original_slot = Some(slot);
        let mut header = [0_u8; 4];
        let mut used = 0;
        while used < header.len() {
            let count = match self.stream.read(&mut header[used..]) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            if count == 0 {
                if used == 0 {
                    return Ok(None);
                }
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
            }
            bank.borrow_mut()
                .append(slot, &header[used..used + count])?;
            used += count;
        }
        let length = u32::from_be_bytes(header) as usize;
        if length == 0 || length > maximum_bytes {
            return Err(ProviderError::Frame("length outside admitted allowance"));
        }
        if let Some(preflight) = preflight {
            preflight.admit_raw_bank(length)?;
        }
        let mut body = vec![0_u8; length];
        used = 0;
        while used < length {
            let count = match self.stream.read(&mut body[used..]) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            if count == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
            }
            bank.borrow_mut().append(slot, &body[used..used + count])?;
            used += count;
        }
        bank.borrow_mut().finish(slot)?;
        if let Some(preflight) = preflight {
            preflight.admit(&body)?;
        }
        let value = canonical::parse_json_with_depth(&body, maximum_bytes, self.maximum_nesting)?;
        Ok(Some(RetainedFrame { value, bytes: body }))
    }
}

/// Carries a validated frame without canonicalizing its original wire body.
///
/// Parsing establishes transport validity only. Native custody and installed
/// source qualification must separately authenticate preparation provenance.
pub(crate) struct RetainedFrame {
    pub(crate) value: Value,
    pub(crate) bytes: Vec<u8>,
}

/// Writes one bounded canonical JSON frame to a connected stream.
///
/// # Errors
/// Rejects invalid limits, oversized JSON and I/O failures. Partial writes
/// leave the connection unusable; callers must retain uncertain effects and
/// must not retransmit on the same stream as a new operation.
pub fn write_frame(
    stream: &mut impl Write,
    value: &Value,
    maximum_bytes: usize,
) -> Result<(), ProviderError> {
    write_frame_with_limits(stream, value, maximum_bytes, MAX_NESTING)
}

/// Writes a frame under the negotiated byte and container-depth allowances.
///
/// # Errors
/// Rejects invalid limits, JSON outside either allowance, or incomplete I/O.
/// Validation finishes before any frame bytes are sent. An I/O failure leaves
/// the connection unusable and does not settle any associated operation.
pub fn write_frame_with_limits(
    stream: &mut impl Write,
    value: &Value,
    maximum_bytes: usize,
    maximum_nesting: usize,
) -> Result<(), ProviderError> {
    check_limit(maximum_bytes)?;
    if maximum_nesting == 0 || maximum_nesting > MAX_NESTING {
        return Err(ProviderError::Frame("invalid negotiated nesting limit"));
    }

    let bytes = canonical::canonical_json(value)?;
    if bytes.len() > maximum_bytes {
        return Err(ProviderError::Frame("outgoing length exceeds allowance"));
    }
    canonical::parse_json_with_depth(&bytes, maximum_bytes, maximum_nesting)?;
    let length = u32::try_from(bytes.len())
        .map_err(|_| ProviderError::Frame("outgoing length is unrepresentable"))?;

    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(&bytes)?;
    Ok(())
}

fn check_limit(maximum_bytes: usize) -> Result<(), ProviderError> {
    if maximum_bytes == 0 || maximum_bytes > MAX_FRAME_BYTES {
        return Err(ProviderError::Frame("invalid negotiated frame limit"));
    }
    Ok(())
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- These transport tests deliberately panic on invalid fixtures or failed invariants.
#[allow(clippy::unwrap_used)]
mod tests {
    use std::io::Cursor;

    use serde_json::json;

    use super::*;

    struct Fragmented {
        bytes: Cursor<Vec<u8>>,
    }

    impl Read for Fragmented {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let length = output.len().min(1);
            self.bytes.read(&mut output[..length])
        }
    }

    #[test]
    fn stream_fragmentation_and_adjacent_frames_preserve_boundaries() {
        let mut stream = Vec::new();
        write_frame(&mut stream, &json!({"one": "1"}), 128).unwrap();
        write_frame(&mut stream, &json!({"two": "2"}), 128).unwrap();
        let mut reader = FrameReader::new(
            Fragmented {
                bytes: Cursor::new(stream),
            },
            128,
        )
        .unwrap();

        assert_eq!(reader.read().unwrap(), Some(json!({"one": "1"})));
        assert_eq!(reader.read().unwrap(), Some(json!({"two": "2"})));
        assert_eq!(reader.read().unwrap(), None);
    }

    #[test]
    fn truncation_is_not_clean_eof_and_fences_reuse() {
        for bytes in [vec![0], vec![0, 0, 0], vec![0, 0, 0, 2, b'{']] {
            let mut reader = FrameReader::new(Cursor::new(bytes), 128).unwrap();

            assert!(reader.read().is_err());
            assert!(matches!(
                reader.read(),
                Err(ProviderError::Frame("connection already failed"))
            ));
        }
    }

    #[test]
    fn invalid_prefix_never_allocates_or_reads_the_body() {
        for length in [0_u32, 129, u32::MAX] {
            let bytes = length.to_be_bytes().to_vec();
            let mut reader = FrameReader::new(Cursor::new(bytes), 128).unwrap();

            assert!(matches!(reader.read(), Err(ProviderError::Frame(_))));
            assert_eq!(reader.stream.position(), 4);
        }
    }

    #[test]
    fn duplicate_keys_and_invalid_unicode_are_fatal() {
        for body in [
            b"{\"a\":1,\"a\":2}".as_slice(),
            b"{\"a\":\"\\ud800\"}",
            b"{\"a\":\"\xff\"}",
        ] {
            let mut bytes = (body.len() as u32).to_be_bytes().to_vec();
            bytes.extend_from_slice(body);
            let mut reader = FrameReader::new(Cursor::new(bytes), 128).unwrap();

            assert!(reader.read().is_err());
            assert!(reader.read().is_err());
        }
    }

    #[test]
    fn a_smaller_negotiated_nesting_limit_is_enforced() {
        let mut stream = Vec::new();
        write_frame(&mut stream, &json!({"nested": {"value": "1"}}), 128).unwrap();
        let mut reader = FrameReader::with_limits(Cursor::new(stream), 128, 1).unwrap();

        assert!(reader.read().is_err());
        assert!(reader.read().is_err());
    }

    #[test]
    fn outbound_validation_finishes_before_frame_publication() {
        let mut stream = Vec::new();
        let nested = json!({"nested": {"value": "1"}});

        assert!(write_frame_with_limits(&mut stream, &nested, 128, 1).is_err());
        assert!(stream.is_empty());

        write_frame_with_limits(&mut stream, &nested, 128, 2).unwrap();
        let mut reader = FrameReader::with_limits(Cursor::new(stream), 128, 2).unwrap();
        assert_eq!(reader.read().unwrap(), Some(nested));
    }
}

#[cfg(test)]
mod retained_frame_tests {
    //! Checks byte custody only; these frames cannot issue native authority.

    use std::io::Cursor;

    use super::*;

    #[test]
    fn retained_frame_preserves_original_valid_wire_body() {
        let original = br#"{ "kind" : "ready", "source" : "native packet" }"#;
        let mut wire = Vec::new();
        wire.extend_from_slice(&(original.len() as u32).to_be_bytes());
        wire.extend_from_slice(original);
        let mut reader = FrameReader::new(Cursor::new(wire.clone()), 1024)
            .unwrap_or_else(|error| panic!("bounded reader failed: {error}"));

        let retained = reader
            .read_retained()
            .unwrap_or_else(|error| panic!("original body failed: {error}"))
            .unwrap_or_else(|| panic!("complete original frame is absent"));
        assert_eq!(retained.bytes, original);
        assert_eq!(retained.value["kind"], "ready");
        assert_ne!(
            canonical::canonical_json(&retained.value)
                .unwrap_or_else(|error| panic!("parsed value failed: {error}")),
            retained.bytes
        );

        let mut legacy = FrameReader::new(Cursor::new(wire), 1024)
            .unwrap_or_else(|error| panic!("legacy reader failed: {error}"));
        assert_eq!(
            legacy
                .read()
                .unwrap_or_else(|error| panic!("legacy frame failed: {error}")),
            Some(retained.value)
        );
    }

    #[test]
    fn retained_frame_keeps_the_original_fatal_parse_fence() {
        let original = br#"{"kind":"ready","kind":"foreign"}"#;
        let mut wire = Vec::new();
        wire.extend_from_slice(&(original.len() as u32).to_be_bytes());
        wire.extend_from_slice(original);
        let mut reader = FrameReader::new(Cursor::new(wire), 1024)
            .unwrap_or_else(|error| panic!("bounded reader failed: {error}"));

        assert!(reader.read_retained().is_err());
        assert!(reader.read().is_err());
        assert!(reader.read_retained().is_err());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Test assertion panics are the control verdict.
mod selected_header_tests {
    use super::*;
    use std::io::Cursor;

    fn reader(
        wire: Vec<u8>,
        bytes: usize,
    ) -> (
        FrameReader<Cursor<Vec<u8>>>,
        Rc<RefCell<OriginalFrameReservation>>,
    ) {
        let bank = Rc::new(RefCell::new(
            OriginalFrameReservation::reserve(bytes, 2).unwrap(),
        ));
        let mut reader = FrameReader::new(Cursor::new(wire), 65_536).unwrap();
        reader.install_originals(bank.clone());
        (reader, bank)
    }

    #[test]
    fn selected_header_limit_admits_bank_before_header_with_exact_smaller_allowance() {
        let mut wire = 2_u32.to_be_bytes().to_vec();
        wire.extend_from_slice(b"{}");
        let (mut restricted, bank) = reader(wire.clone(), 6);

        assert_eq!(
            restricted
                .read_retained_with_maximum_bytes(2)
                .unwrap()
                .unwrap()
                .bytes,
            b"{}"
        );
        assert_eq!(restricted.stream.position(), 6);
        let bank = bank.borrow();
        let frame = bank.frames().next().unwrap();
        assert_eq!(frame.bytes, wire);
        assert!(frame.complete);
        assert_eq!(frame.transferred, 6);
        drop(bank);

        let (mut generic, original) = reader(wire, 6);
        assert!(generic.read_retained().is_err());
        assert_eq!(generic.stream.position(), 0);
        assert_eq!(original.borrow().frames().count(), 0);
    }

    #[test]
    fn selected_oversized_header_never_reads_body_and_retains_same_partial_original() {
        let mut wire = 9_u32.to_be_bytes().to_vec();
        wire.extend_from_slice(b"body-never-read");
        let (mut reader, bank) = reader(wire, 12);
        let allocation = bank.borrow().allocated_bytes();

        assert!(reader.read_retained_with_maximum_bytes(8).is_err());
        assert_eq!(reader.stream.position(), 4);
        assert_eq!(reader.original_slot(), Some(0));
        let before = serde_json::to_vec(&bank.borrow().protocol_view()).unwrap();
        {
            let bank = bank.borrow();
            let frame = bank.frames().next().unwrap();
            assert_eq!(frame.bytes, 9_u32.to_be_bytes());
            assert_eq!(frame.transferred, 4);
            assert!(!frame.complete);
            assert_eq!(bank.allocated_bytes(), allocation);
        }
        assert!(reader.read_retained().is_err());
        assert!(reader.read_retained_with_maximum_bytes(8).is_err());
        assert_eq!(reader.stream.position(), 4);
        assert_eq!(
            serde_json::to_vec(&bank.borrow().protocol_view()).unwrap(),
            before
        );
    }

    #[test]
    fn selected_partial_header_and_invalid_restriction_preserve_original_state() {
        let wire = vec![0, 0];
        let (mut reader, bank) = reader(wire.clone(), 12);
        for limit in [0, 65_537] {
            assert!(reader.read_retained_with_maximum_bytes(limit).is_err());
            assert_eq!(reader.stream.position(), 0);
            assert_eq!(bank.borrow().frames().count(), 0);
        }
        assert!(reader.read_retained_with_maximum_bytes(8).is_err());
        assert_eq!(reader.stream.position(), 2);
        let bank = bank.borrow();
        let frame = bank.frames().next().unwrap();
        assert_eq!(frame.bytes, wire);
        assert_eq!(frame.transferred, 2);
        assert!(!frame.complete);
        drop(bank);
        assert!(reader.read_retained_with_maximum_bytes(8).is_err());
        assert_eq!(reader.stream.position(), 2);
    }

    #[test]
    fn selected_oversized_header_on_actual_unix_keeps_body_unread_and_original_header() {
        use std::{
            io::{Read, Write},
            os::unix::net::UnixStream,
            time::Duration,
        };

        let (stream, mut peer) = UnixStream::pair().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        peer.set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let body = b"123456789";
        peer.write_all(&9_u32.to_be_bytes()).unwrap();
        peer.write_all(body).unwrap();
        let bank = Rc::new(RefCell::new(
            OriginalFrameReservation::reserve(12, 2).unwrap(),
        ));
        let mut reader = FrameReader::new(stream, 65_536).unwrap();
        reader.install_originals(bank.clone());

        assert!(reader.read_retained_with_maximum_bytes(8).is_err());
        assert_eq!(reader.original_slot(), Some(0));
        let retained = serde_json::to_vec(&bank.borrow().protocol_view()).unwrap();
        {
            let bank = bank.borrow();
            let frame = bank.frames().next().unwrap();
            assert_eq!(frame.bytes, 9_u32.to_be_bytes());
            assert_eq!(frame.transferred, 4);
            assert!(!frame.complete);
        }
        assert!(reader.read_retained_with_maximum_bytes(8).is_err());
        assert_eq!(
            serde_json::to_vec(&bank.borrow().protocol_view()).unwrap(),
            retained
        );

        // This test-only forensic read occurs after the fatal reader fence.
        // All nine original body bytes remain in the real Unix socket queue.
        let mut queued = [0; 9];
        reader.stream_mut().read_exact(&mut queued).unwrap();
        assert_eq!(&queued, body);
        assert_eq!(
            serde_json::to_vec(&bank.borrow().protocol_view()).unwrap(),
            retained
        );
    }
}

pub(crate) use original_frames::original_frame_bank_layout;
pub use original_frames::{DecodedCompactOriginalFrames, ValidatedCompactOriginalFrames};

impl FrameReader<crate::client::DeadlineStream> {
    pub(crate) fn observe_original_host_live_metadata(
        &self,
        bank: &Rc<RefCell<OriginalFrameReservation>>,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.original_owned11_facts(bank)?;
        let Self {
            stream,
            maximum_bytes,
            maximum_nesting,
            failed,
            originals,
            last_original_slot,
        } = self;
        stream.observe_original_host_live_metadata(observer)?;
        observer.observe(maximum_bytes)?;
        observer.observe(maximum_nesting)?;
        observer.observe(failed)?;
        observer.observe(last_original_slot)?;
        let bank = originals
            .as_ref()
            .ok_or(ProviderError::Correlation("live host reader bank absent"))?;
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::FrameBank,
            bank.as_ref(),
        )?;
        bank.try_borrow()
            .map_err(|_| ProviderError::Conflict("live host reader bank borrowed"))?
            .observe_owned11_metadata(observer)
    }
}

#[cfg(test)]
mod original_live_host_metadata_tests {
    use super::*;
    use crate::{client::DeadlineStream, retained_metadata::MetadataObserver};
    use std::{os::unix::net::UnixStream, time::Duration};
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn actual_deadline_reader_counts_full_spare_bank_and_shared_roots_without_reading() -> TestResult
    {
        let (stream, _peer) = UnixStream::pair()?;
        let (stream, _deadline) = DeadlineStream::new(stream, Duration::from_secs(60))?;
        let mut reader = FrameReader::with_limits(stream, 64, 8)?;
        let bank = Rc::new(RefCell::new(OriginalFrameReservation::reserve(4096, 9)?));
        let actual_backing = bank.borrow().allocated_bytes();
        reader.originals = Some(Rc::clone(&bank));
        let strong = Rc::strong_count(&bank);
        let mut observer = MetadataObserver::new();
        reader.observe_original_host_live_metadata(&bank, &mut observer)?;
        let facts = observer.finish();
        assert_eq!(facts.vector_capacity_bytes, actual_backing);
        assert_eq!(facts.shared_backing_views, 2);
        assert_eq!(Rc::strong_count(&bank), strong);
        assert_eq!(reader.last_original_slot, None);
        Ok(())
    }

    #[test]
    fn foreign_reader_bank_refuses_before_observing_any_requested_backing() -> TestResult {
        let (stream, _peer) = UnixStream::pair()?;
        let (stream, _deadline) = DeadlineStream::new(stream, Duration::from_secs(60))?;
        let mut reader = FrameReader::with_limits(stream, 64, 8)?;
        let actual = Rc::new(RefCell::new(OriginalFrameReservation::reserve(4096, 9)?));
        let foreign = Rc::new(RefCell::new(OriginalFrameReservation::reserve(4096, 9)?));
        reader.originals = Some(actual);
        let mut observer = MetadataObserver::new();
        assert!(
            reader
                .observe_original_host_live_metadata(&foreign, &mut observer)
                .is_err()
        );
        let facts = observer.finish();
        assert_eq!(facts.observed_nodes, 0);
        assert_eq!(facts.vector_capacity_bytes, 0);
        Ok(())
    }
}

impl FrameReader<crate::client::DeadlineStream> {
    pub(crate) fn observe_original_host_startup_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        let Self {
            stream,
            maximum_bytes,
            maximum_nesting,
            failed,
            originals,
            last_original_slot,
        } = self;
        if *failed || originals.is_some() || last_original_slot.is_some() {
            return Err(ProviderError::Frame("original host startup reader changed"));
        }
        stream.observe_original_host_live_metadata(observer)?;
        observer.observe(maximum_bytes)?;
        observer.observe(maximum_nesting)
    }
}
