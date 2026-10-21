//! Retains the native endpoint's original literal Hello and response cursor.
//!
//! The selected source reserves this byte/descriptor bank before accepting a
//! stream and charges its actual allocation in the host's pre-Child profile.
//! Incoming bytes remain literal; only the originally planned outgoing response
//! is encoded. This journal grants no negotiation, capture or native authority.

pub use crate::hello_frames::OriginalHelloFrameDigests;

use crate::{
    ProviderError,
    protocol_snapshot::ProtocolCaptureOwner,
    transport::{
        FrameReader,
        original_frames::{FrameDirection, OriginalFrameReservation},
    },
};
use serde_json::Value;
use std::{
    cell::RefCell,
    io::{self, Read, Write},
    rc::Rc,
};

#[path = "native_hello/retained_reservation.rs"]
mod retained_reservation;
pub(crate) use retained_reservation::OriginalNativeHelloReservation;

#[path = "native_hello/retained_exchange.rs"]
mod retained_exchange;
pub(crate) use retained_exchange::RetainedOriginalNativeHelloExchange;

const MAXIMUM_HELLO_BYTES: usize = 1024 * 1024;

/// Owns one precharged native Hello attempt, including partial failed traffic.
pub struct OriginalNativeHelloJournal {
    bank: Rc<RefCell<OriginalFrameReservation>>,
    maximum_bytes: usize,
    maximum_nesting: usize,
    owner: ProtocolCaptureOwner,
    attempted: bool,
    received: bool,
    write_started: bool,
    failed: bool,
}

/// Retains the original native Hello journal and socket when binding refuses.
///
/// Recovery does not reset an attempted Hello, replace literal frames, or renew
/// any exchange deadline embedded in the supplied stream.
pub struct OriginalNativeHelloBindRefusal<S: Read + Write> {
    journal: OriginalNativeHelloJournal,
    stream: S,
    error: ProviderError,
}

impl<S: Read + Write> OriginalNativeHelloBindRefusal<S> {
    /// Borrows the original binding refusal without extracting retained owners.
    pub fn error(&self) -> &ProviderError {
        &self.error
    }

    /// Transfers the same socket and literal journal back to their phase owner.
    pub fn into_original(self) -> (S, OriginalNativeHelloJournal) {
        (self.stream, self.journal)
    }
}

impl OriginalNativeHelloJournal {
    /// Quotes requested literal byte and descriptor backing for one Hello.
    ///
    /// This includes both framed directions and their two lifetime descriptors.
    /// It excludes the journal and shared-owner headers, parsing work, and any
    /// allocator rounding. Actual construction must still check its capacities.
    /// The allocation-free DATA grants no reservation or native authority.
    ///
    /// # Errors
    /// Refuses zero or over-one-MiB frame credit or checked layout overflow.
    pub fn reservation_requested_storage_data(
        maximum_bytes: usize,
    ) -> Result<usize, ProviderError> {
        if maximum_bytes == 0 || maximum_bytes > MAXIMUM_HELLO_BYTES {
            return Err(ProviderError::ResourceExhausted(
                "native original Hello limits",
            ));
        }
        maximum_bytes
            .checked_add(4)
            .and_then(|bytes| bytes.checked_mul(2))
            .and_then(|bytes| {
                crate::transport::original_frames::original_frame_slot_layout()
                    .checked_mul(2)
                    .and_then(|descriptors| bytes.checked_add(descriptors))
            })
            .ok_or(ProviderError::ResourceExhausted(
                "native original Hello requested storage",
            ))
    }

    /// Observes the actual Hello bank in the native Capture shared-root roster.
    ///
    /// The original creator guard precedes every bank borrow. This journal's
    /// inline owner, phase and framing fields remain part of the caller's root;
    /// only its actual shared bank payload and child capacities are deduplicated.
    pub(crate) fn observe_unique_capture_metadata(
        &self,
        roots: &mut crate::retained_metadata::NativeCaptureMetadataRoots,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        let Self {
            bank,
            maximum_bytes,
            maximum_nesting,
            owner: _,
            attempted,
            received,
            write_started,
            failed,
        } = self;
        let original = bank
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("native Hello Capture metadata bank borrowed"))?;
        if roots.observe_shared(
            observer,
            crate::retained_metadata::aliases::MetadataSharedKind::FrameBank,
            bank.as_ref(),
        )? {
            original.observe_owned11_metadata(observer)?;
        }
        observer.observe(&[*maximum_bytes, *maximum_nesting])?;
        observer.observe(&[*attempted, *received, *write_started, *failed])
    }

    /// Binds framing while returning both original owners on every refusal.
    ///
    /// This owning complete-source transition performs no reads, writes, or
    /// callbacks. In particular, an attempted journal cannot be replaced with a
    /// fresh reservation after a failed native Hello.
    ///
    /// # Errors
    /// Retains the same stream and journal on foreign ownership, an attempted
    /// Hello, an unavailable original-bank borrow, or invalid framing limits.
    pub fn bind_owned<S: Read + Write>(
        self,
        stream: S,
    ) -> Result<OriginalNativeHelloExchange<S>, Box<OriginalNativeHelloBindRefusal<S>>> {
        let admission = self.owner.ensure_current().and_then(|()| {
            let bank = self.bank.try_borrow().map_err(|_| {
                ProviderError::Correlation("native original Hello bank borrowed during bind")
            })?;
            if self.attempted || bank.frames().next().is_some() {
                Err(ProviderError::Conflict(
                    "native original Hello already attempted",
                ))
            } else {
                Ok(())
            }
        });
        if let Err(error) = admission {
            return Err(Box::new(OriginalNativeHelloBindRefusal {
                journal: self,
                stream,
                error,
            }));
        }
        let mut reader = match FrameReader::with_limits_owned(
            stream,
            self.maximum_bytes,
            self.maximum_nesting,
        ) {
            Ok(reader) => reader,
            Err((stream, error)) => {
                return Err(Box::new(OriginalNativeHelloBindRefusal {
                    journal: self,
                    stream,
                    error,
                }));
            }
        };
        reader.install_originals(self.bank.clone());
        Ok(OriginalNativeHelloExchange {
            reader,
            journal: self,
        })
    }

    /// Reserves both literal directions before accepting the original stream.
    ///
    /// # Errors
    /// Refuses zero or over-one-MiB frame credit, invalid nesting, or allocation
    /// failure. Both endpoints' banks and temporary parsing are separate charges.
    pub fn reserve(maximum_bytes: usize, maximum_nesting: usize) -> Result<Self, ProviderError> {
        if maximum_bytes == 0
            || maximum_bytes > MAXIMUM_HELLO_BYTES
            || !(1..=64).contains(&maximum_nesting)
        {
            return Err(ProviderError::ResourceExhausted(
                "native original Hello limits",
            ));
        }
        Ok(Self {
            bank: Rc::new(RefCell::new(OriginalFrameReservation::reserve(
                (maximum_bytes + 4) * 2,
                1,
            )?)),
            maximum_bytes,
            maximum_nesting,
            owner: ProtocolCaptureOwner::new(),
            attempted: false,
            received: false,
            write_started: false,
            failed: false,
        })
    }

    #[cfg(test)]
    pub(crate) fn original_test_identity(&self) -> impl Fn(&Self) -> bool + use<> {
        // Weak identity cannot keep a dropped original bank alive and mask a
        // constructor custody failure; it compares only same-allocation origin.
        let original = Rc::downgrade(&self.bank);
        move |journal| {
            original.strong_count() != 0
                && std::rc::Weak::ptr_eq(&original, &Rc::downgrade(&journal.bank))
        }
    }

    /// Returns role-normalized digests of complete original raw Hello frames.
    ///
    /// The original process/thread guard precedes every bank observation. These
    /// digests are data; source/kernel/registrar association is independently
    /// required before they can enter an authenticated admission context.
    ///
    /// # Errors
    /// Refuses a foreign actor, failed/incomplete Hello, changed framing extent,
    /// repeated direction or a concurrently borrowed original bank.
    pub fn original_literal_frame_digests(
        &self,
    ) -> Result<OriginalHelloFrameDigests, ProviderError> {
        self.owner.ensure_current()?;
        if !self.attempted || !self.received || !self.write_started || self.failed {
            return Err(ProviderError::Correlation(
                "native original Hello exchange incomplete",
            ));
        }
        let bank = self
            .bank
            .try_borrow()
            .map_err(|_| ProviderError::Correlation("native original Hello bank borrowed"))?;
        crate::hello_frames::original_hello_frame_digests(
            &bank,
            crate::connection::EndpointRole::Provider,
        )
    }

    /// Reports the actual byte and descriptor allocation for source admission.
    pub fn allocated_bytes(&self) -> usize {
        self.bank.borrow().allocated_bytes()
    }

    /// Borrows every literal original, including failed framing and write cuts.
    pub fn original_frames(&self) -> std::cell::Ref<'_, OriginalFrameReservation> {
        self.bank.borrow()
    }

    /// Borrows complete private journal data without issuing capture authority.
    ///
    /// Literal bytes include the original secret Hello material. The source
    /// seals these fields with its actual same-owner endpoint and process state;
    /// serializing this data alone cannot authenticate an installed capture.
    pub fn protocol_view(&self) -> impl serde::Serialize + '_ {
        struct View<'a>(&'a OriginalNativeHelloJournal);
        impl serde::Serialize for View<'_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let journal = self.0;
                let bank = journal.bank.borrow();
                serde::Serialize::serialize(
                    &(
                        "source-private.native-Hello/5",
                        journal.maximum_bytes,
                        journal.maximum_nesting,
                        journal.attempted,
                        journal.received,
                        journal.write_started,
                        journal.failed,
                        bank.protocol_view(),
                    ),
                    serializer,
                )
            }
        }
        View(self)
    }

    /// Binds this unused original attempt to one owning native stream.
    ///
    /// # Errors
    /// Refuses process/thread drift or an already attempted journal. No stream
    /// I/O occurs; the source factory independently authenticates the peer.
    pub fn bind<S: Read + Write>(
        self,
        stream: S,
    ) -> Result<OriginalNativeHelloExchange<S>, ProviderError> {
        self.owner.ensure_current()?;
        if self.attempted || self.bank.borrow().frames().next().is_some() {
            return Err(ProviderError::Conflict(
                "native original Hello already attempted",
            ));
        }
        let mut reader =
            FrameReader::with_limits(stream, self.maximum_bytes, self.maximum_nesting)?;
        reader.install_originals(self.bank.clone());
        Ok(OriginalNativeHelloExchange {
            reader,
            journal: self,
        })
    }
}

/// Keeps the same original stream and journal through native Hello framing.
///
/// The caller authenticates the returned parsed request against these literal
/// originals before admitting Hello and prepares the response from that same
/// authenticated exchange. A failure retains this object and its original
/// progress; no reset, resynchronization or renewed response attempt exists.
pub struct OriginalNativeHelloExchange<S: Read + Write> {
    reader: FrameReader<S>,
    journal: OriginalNativeHelloJournal,
}

impl<S: Read + Write> OriginalNativeHelloExchange<S> {
    /// Borrows the same owning stream without I/O or descriptor duplication.
    pub(crate) fn original_stream_data(&self) -> &S {
        let Self { reader, journal: _ } = self;
        reader.stream_ref()
    }

    /// Reads the original request once and retains its exact header/body bytes.
    ///
    /// # Errors
    /// Refuses owner drift, repeated reads, invalid/partial framing, duplicate
    /// keys or malformed JSON. Partial originals stay in the same bank.
    pub fn receive(&mut self) -> Result<Option<Value>, ProviderError> {
        self.receive_with_preflight(None)
    }

    /// Receives the same once-only Hello through its original layout window.
    ///
    /// # Errors
    /// Refuses a foreign/spent original, framing/layout overflow or strict parse
    /// failure while retaining the same journal and permanently spent attempt.
    pub(crate) fn receive_original_preflight(
        &mut self,
        preflight: &crate::reference_packet::service::native_startup::OriginalNativeFramePreflight<
            '_,
        >,
    ) -> Result<Option<Value>, ProviderError> {
        self.receive_with_preflight(Some(preflight))
    }

    fn receive_with_preflight(
        &mut self,
        preflight: Option<
            &crate::reference_packet::service::native_startup::OriginalNativeFramePreflight<'_>,
        >,
    ) -> Result<Option<Value>, ProviderError> {
        self.journal.owner.ensure_current()?;
        if self.journal.attempted || self.journal.failed {
            return Err(ProviderError::Conflict(
                "native original Hello read already attempted",
            ));
        }
        self.journal.attempted = true;
        let received = match preflight {
            Some(preflight) => self
                .reader
                .read_original_native_preflight(self.journal.maximum_bytes, preflight)
                .map(|frame| frame.map(|frame| frame.value)),
            None => self.reader.read(),
        };
        match received {
            Ok(value) => {
                self.journal.received = value.is_some();
                Ok(value)
            }
            Err(error) => {
                self.journal.failed = true;
                Err(error)
            }
        }
    }

    /// Publishes the once-prepared original response and retains actual progress.
    ///
    /// Response encoding and complete frame credit precede its first write. The
    /// source authenticates the actual Hello before invoking this method. No
    /// received request is reconstructed or substituted by canonical encoding.
    ///
    /// # Errors
    /// Refuses drift, absent complete request, repeated publication, exhausted
    /// response credit or partial I/O. Every successful write advances only this
    /// original cursor; any attempted response permanently consumes the slot.
    pub fn publish(&mut self, response: &Value) -> Result<(), ProviderError> {
        self.journal.owner.ensure_current()?;
        if self.journal.failed {
            return Err(ProviderError::Conflict(
                "native original Hello failed attempt",
            ));
        }
        let result = self.publish_original(response);
        if result.is_err() {
            self.journal.failed = true;
        }
        result
    }

    fn publish_original(&mut self, response: &Value) -> Result<(), ProviderError> {
        if !self.journal.received || self.journal.write_started {
            return Err(ProviderError::Conflict(
                "native original Hello response unavailable or attempted",
            ));
        }
        self.journal.write_started = true;
        validate_selected_depth(response, 0, self.journal.maximum_nesting)?;
        let mut count = Count {
            used: 0,
            maximum: self.journal.maximum_bytes,
        };
        crucible_node_format::canonical::canonical_json_to_writer(response, &mut count)?;
        let mut bank = self.journal.bank.borrow_mut();
        let slot = bank.begin(FrameDirection::Outgoing, count.used + 4)?;
        let length = u32::try_from(count.used)
            .map_err(|_| ProviderError::Frame("native original Hello response length"))?;
        bank.append(slot, &length.to_be_bytes())?;
        crucible_node_format::canonical::canonical_json_to_writer(
            response,
            &mut OriginalWriter {
                bank: &mut bank,
                slot,
            },
        )?;

        let mut transferred = 0;
        let total = count.used + 4;
        while transferred < total {
            let written = {
                let frame = bank
                    .frames()
                    .find(|frame| frame.direction == FrameDirection::Outgoing)
                    .ok_or(ProviderError::Frame(
                        "native original Hello response slot absent",
                    ))?;
                match self.reader.stream_mut().write(&frame.bytes[transferred..]) {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    result => result?,
                }
            };
            if written == 0 {
                return Err(io::Error::from(io::ErrorKind::WriteZero).into());
            }
            bank.advance(slot, written)?;
            transferred += written;
        }
        bank.finish(slot)
    }

    /// Borrows the original journal without changing its attempt or stream.
    pub fn originals(&self) -> &OriginalNativeHelloJournal {
        &self.journal
    }

    /// Moves the same stream and all original journals back to their source owner.
    ///
    /// This is data/resource transfer even after failure; it proves no complete
    /// negotiation or graceful release. The source retains unresolved originals.
    pub fn into_parts(self) -> (S, OriginalNativeHelloJournal) {
        (self.reader.into_inner(), self.journal)
    }
}

// Mirrors the authoritative writer's container-depth convention without
// constructing encoded bytes or changing numeric/string canonicalization.
fn validate_selected_depth(
    value: &Value,
    depth: usize,
    maximum: usize,
) -> Result<(), ProviderError> {
    match value {
        Value::Array(values) => {
            if depth >= maximum {
                return Err(ProviderError::Frame(
                    "native Hello response exceeds selected nesting",
                ));
            }
            for value in values {
                validate_selected_depth(value, depth + 1, maximum)?;
            }
        }
        Value::Object(values) => {
            if depth >= maximum {
                return Err(ProviderError::Frame(
                    "native Hello response exceeds selected nesting",
                ));
            }
            for value in values.values() {
                validate_selected_depth(value, depth + 1, maximum)?;
            }
        }
        _ => {}
    }
    Ok(())
}

struct Count {
    used: usize,
    maximum: usize,
}
impl Write for Count {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.used = self
            .used
            .checked_add(bytes.len())
            .filter(|n| *n <= self.maximum)
            .ok_or_else(|| io::Error::other("native original Hello complete response credit"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct OriginalWriter<'a> {
    bank: &'a mut OriginalFrameReservation,
    slot: usize,
}
impl Write for OriginalWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bank
            .append(self.slot, bytes)
            .map_err(io::Error::other)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(all(test, unix))]
// crucible-lint: allow panic-shortcut -- Literal journal fixtures deliberately panic on broken invariants.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn wire(bytes: &[u8]) -> Vec<u8> {
        let mut frame = (bytes.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(bytes);
        frame
    }

    #[test]
    fn original_hello_requested_layout_includes_both_actual_descriptor_owners() {
        for maximum_bytes in [1, 128, 65_536, MAXIMUM_HELLO_BYTES] {
            let requested =
                OriginalNativeHelloJournal::reservation_requested_storage_data(maximum_bytes)
                    .unwrap();
            let original = OriginalNativeHelloJournal::reserve(maximum_bytes, 64).unwrap();
            let raw_only = (maximum_bytes + 4) * 2;

            assert_eq!(
                requested,
                raw_only + 2 * crate::transport::original_frames::original_frame_slot_layout()
            );
            assert_eq!(original.allocated_bytes(), requested);
            // CompleteBirth and endpoint preflight compare these actual
            // capacities with the selected limit; exact fits, one short fails.
            assert!(original.allocated_bytes() <= requested);
            assert!(original.allocated_bytes() > requested - 1);
            assert!(original.allocated_bytes() > raw_only);
            assert_eq!(original.original_frames().frames().count(), 0);
        }

        for invalid in [0, MAXIMUM_HELLO_BYTES + 1, usize::MAX] {
            assert!(
                OriginalNativeHelloJournal::reservation_requested_storage_data(invalid).is_err()
            );
            assert!(OriginalNativeHelloJournal::reserve(invalid, 64).is_err());
        }
    }

    #[test]
    fn native5_original_native_hello_actual_unix_keeps_literal_whitespace() {
        let request = crate::handshake::tests::original_hello_envelope();
        let mut bytes = serde_json::to_vec(&request).unwrap();
        bytes.extend_from_slice(b" \n\t");
        let incoming = wire(&bytes);
        let (stream, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        peer.write_all(&incoming).unwrap();
        let mut exchange = OriginalNativeHelloJournal::reserve(4096, 64)
            .unwrap()
            .bind(stream)
            .unwrap();
        assert_eq!(
            exchange.receive().unwrap().unwrap(),
            serde_json::to_value(request).unwrap()
        );
        let response = serde_json::json!({"response":"original", "sequence":"1"});
        exchange.publish(&response).unwrap();
        assert!(exchange.publish(&response).is_err());
        assert!(exchange.receive().is_err());

        let expected = wire(&crucible_node_format::canonical::canonical_json(&response).unwrap());
        let mut received = vec![0; expected.len()];
        peer.read_exact(&mut received).unwrap();
        assert_eq!(received, expected);
        let (_same_stream, original) = exchange.into_parts();
        let bank = original.original_frames();
        let frames: Vec<_> = bank.frames().collect();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].bytes, incoming);
        assert_eq!(frames[1].bytes, received);
        assert!(
            frames
                .iter()
                .all(|f| f.complete && f.transferred == f.bytes.len())
        );
    }

    #[test]
    fn native5_original_native_hello_actual_unix_partial_response_keeps_kernel_prefix() {
        let (stream, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
        stream.set_nonblocking(true).unwrap();
        peer.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        peer.write_all(&wire(b"{} \n")).unwrap();
        let mut exchange = OriginalNativeHelloJournal::reserve(1_048_576, 64)
            .unwrap()
            .bind(stream)
            .unwrap();
        exchange.receive().unwrap().unwrap();
        let response = serde_json::json!({"original":"x".repeat(700_000)});
        assert!(exchange.publish(&response).is_err());
        assert!(exchange.journal.failed);
        let view: serde_json::Value =
            serde_json::to_value(exchange.originals().protocol_view()).unwrap();
        assert_eq!(view[6], true);
        let bank = exchange.originals().original_frames();
        let frame = bank
            .frames()
            .find(|f| f.direction == FrameDirection::Outgoing)
            .unwrap();
        assert!(frame.transferred > 4 && frame.transferred < frame.bytes.len());
        assert!(!frame.complete);
        let mut actual_prefix = vec![0; frame.transferred];
        peer.read_exact(&mut actual_prefix).unwrap();
        assert_eq!(actual_prefix, frame.bytes[..frame.transferred]);
        drop(bank);
        assert!(
            exchange
                .publish(&serde_json::json!({"changed":true}))
                .is_err()
        );
        let (_same_stream, journal) = exchange.into_parts();
        assert!(journal.failed);
        assert_eq!(journal.original_frames().frames().count(), 2);
    }

    struct CutStream {
        incoming: Cursor<Vec<u8>>,
        written: Vec<u8>,
        remaining: usize,
    }
    impl Read for CutStream {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.incoming.read(bytes)
        }
    }
    impl Write for CutStream {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Err(io::Error::from(io::ErrorKind::BrokenPipe));
            }
            let count = bytes.len().min(self.remaining).min(2);
            self.written.extend_from_slice(&bytes[..count]);
            self.remaining -= count;
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn native5_original_native_hello_partial_response_retains_same_cursor() {
        let stream = CutStream {
            incoming: Cursor::new(wire(b"{}")),
            written: Vec::new(),
            remaining: 6,
        };
        let mut exchange = OriginalNativeHelloJournal::reserve(128, 64)
            .unwrap()
            .bind(stream)
            .unwrap();
        exchange.receive().unwrap().unwrap();
        assert!(
            exchange
                .publish(&serde_json::json!({"original":1}))
                .is_err()
        );
        assert!(exchange.publish(&serde_json::json!({"changed":2})).is_err());
        let (stream, original) = exchange.into_parts();
        let bank = original.original_frames();
        let outgoing = bank
            .frames()
            .find(|f| f.direction == FrameDirection::Outgoing)
            .unwrap();
        assert_eq!(outgoing.transferred, 6);
        assert!(!outgoing.complete);
        assert_eq!(stream.written, outgoing.bytes[..6]);
        assert!(outgoing.bytes.ends_with(b"{\"original\":1}"));
    }

    #[test]
    fn native5_original_native_hello_malformed_and_partial_request_stay_literal() {
        for incoming in [vec![0, 0, 0], vec![0, 0, 0, 5, b'{'], wire(b"!!")] {
            let stream = CutStream {
                incoming: Cursor::new(incoming.clone()),
                written: Vec::new(),
                remaining: 128,
            };
            let mut exchange = OriginalNativeHelloJournal::reserve(128, 64)
                .unwrap()
                .bind(stream)
                .unwrap();
            assert!(exchange.receive().is_err());
            assert!(exchange.publish(&serde_json::json!({})).is_err());
            let (stream, original) = exchange.into_parts();
            assert!(stream.written.is_empty());
            let bank = original.original_frames();
            assert_eq!(bank.frames().count(), 1);
            assert_eq!(bank.frames().next().unwrap().bytes, incoming);
        }
    }

    #[test]
    fn native5_original_native_hello_selected_depth_refuses_before_slot_or_write() {
        let nested = serde_json::json!({"nested":{"value":"1"}});
        for maximum_nesting in [1, 2] {
            let stream = CutStream {
                incoming: Cursor::new(wire(b"{}")),
                written: Vec::new(),
                remaining: 128,
            };
            let mut exchange = OriginalNativeHelloJournal::reserve(128, maximum_nesting)
                .unwrap()
                .bind(stream)
                .unwrap();
            exchange.receive().unwrap().unwrap();
            let result = exchange.publish(&nested);
            if maximum_nesting == 1 {
                assert!(result.is_err());
                assert!(exchange.journal.failed && exchange.journal.write_started);
                assert!(exchange.publish(&serde_json::json!({})).is_err());
                let (stream, original) = exchange.into_parts();
                assert!(stream.written.is_empty());
                assert_eq!(original.original_frames().frames().count(), 1);
            } else {
                result.unwrap();
                let (stream, original) = exchange.into_parts();
                assert!(!stream.written.is_empty());
                assert!(!original.failed);
                assert_eq!(original.original_frames().frames().count(), 2);
            }
        }
    }

    #[test]
    fn native5_original_native_hello_response_credit_refuses_before_write() {
        let stream = CutStream {
            incoming: Cursor::new(wire(b"{}")),
            written: Vec::new(),
            remaining: 128,
        };
        let mut exchange = OriginalNativeHelloJournal::reserve(16, 64)
            .unwrap()
            .bind(stream)
            .unwrap();
        exchange.receive().unwrap().unwrap();
        assert!(
            exchange
                .publish(&serde_json::json!({"oversized":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}))
                .is_err()
        );
        assert!(exchange.publish(&serde_json::json!({})).is_err());
        let (stream, original) = exchange.into_parts();
        assert!(stream.written.is_empty());
        assert_eq!(original.original_frames().frames().count(), 1);
    }
    #[test]
    fn native5_original_native_hello_owned_bind_keeps_attempted_journal_and_socket() {
        use std::os::fd::AsRawFd;
        let (stream, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let descriptor = stream.as_raw_fd();
        peer.write_all(&wire(b"{} \n")).unwrap();
        let original = OriginalNativeHelloJournal::reserve(128, 64).unwrap();
        let same = original.original_test_identity();
        let mut exchange = match original.bind_owned(stream) {
            Ok(exchange) => exchange,
            Err(_) => panic!("original unused Hello binding refused"),
        };
        exchange.receive().unwrap().unwrap();
        let (stream, original) = exchange.into_parts();
        let bytes = serde_json::to_vec(&original.protocol_view()).unwrap();
        let failure = match original.bind_owned(stream) {
            Ok(_) => panic!("attempted Hello was reset"),
            Err(failure) => failure,
        };
        assert!(matches!(failure.error(), ProviderError::Conflict(_)));
        let (mut stream, original) = failure.into_original();
        assert_eq!(stream.as_raw_fd(), descriptor);
        assert!(same(&original));
        assert_eq!(
            serde_json::to_vec(&original.protocol_view()).unwrap(),
            bytes
        );
        peer.write_all(b"held").unwrap();
        let mut held = [0; 4];
        stream.read_exact(&mut held).unwrap();
        assert_eq!(&held, b"held");
        let failure = match original.bind_owned(stream) {
            Ok(_) => panic!("retry reset literal Hello"),
            Err(failure) => failure,
        };
        let (_, original) = failure.into_original();
        assert!(same(&original));
        assert_eq!(
            serde_json::to_vec(&original.protocol_view()).unwrap(),
            bytes
        );
    }

    #[test]
    fn native5_original_native_hello_owned_bind_invalid_limits_retains_both_owners() {
        use std::os::fd::AsRawFd;
        let (stream, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let descriptor = stream.as_raw_fd();
        let mut original = OriginalNativeHelloJournal::reserve(128, 64).unwrap();
        let same = original.original_test_identity();
        // A private hostile fixture tests the framing refusal; public reserve
        // cannot construct this invalid selected depth.
        original.maximum_nesting = 0;
        let failure = match original.bind_owned(stream) {
            Ok(_) => panic!("invalid framing depth was accepted"),
            Err(failure) => failure,
        };
        let (stream, original) = failure.into_original();
        assert_eq!(stream.as_raw_fd(), descriptor);
        assert!(same(&original));
        assert_eq!(original.maximum_nesting, 0);
        assert!(!original.attempted);
        assert_eq!(original.original_frames().frames().count(), 0);
    }
}

// crucible-lint: allow panic-shortcut -- real original Hello bank identity and origin/borrow refusal observations.
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "actual journal bank and origin controls"
)]
mod capture_metadata_tests {
    use super::*;
    use crate::retained_metadata::{MetadataObserver, NativeCaptureMetadataRoots};

    #[test]
    fn hello_unique_walk_counts_repeated_bank_once_and_distinct_equal_banks_separately() {
        let first = OriginalNativeHelloJournal::reserve(128, 64).unwrap();
        let second = OriginalNativeHelloJournal::reserve(128, 64).unwrap();
        let mut roots = NativeCaptureMetadataRoots::new();
        let mut observer = MetadataObserver::new();
        first
            .observe_unique_capture_metadata(&mut roots, &mut observer)
            .unwrap();
        let first_edges = roots.finish().unwrap();
        assert_eq!(first_edges, (1, 1));
        let once = observer.finish();

        let mut roots = NativeCaptureMetadataRoots::new();
        let mut observer = MetadataObserver::new();
        first
            .observe_unique_capture_metadata(&mut roots, &mut observer)
            .unwrap();
        first
            .observe_unique_capture_metadata(&mut roots, &mut observer)
            .unwrap();
        assert_eq!(roots.finish().unwrap(), (2, 1));
        let repeated = observer.finish();
        assert_eq!(repeated.vector_capacity_bytes, once.vector_capacity_bytes);
        assert_eq!(repeated.shared_value_bytes, once.shared_value_bytes);

        let mut roots = NativeCaptureMetadataRoots::new();
        let mut observer = MetadataObserver::new();
        first
            .observe_unique_capture_metadata(&mut roots, &mut observer)
            .unwrap();
        second
            .observe_unique_capture_metadata(&mut roots, &mut observer)
            .unwrap();
        assert_eq!(roots.finish().unwrap(), (2, 2));
        let distinct = observer.finish();
        assert_eq!(
            distinct.vector_capacity_bytes,
            2 * once.vector_capacity_bytes
        );
        assert_eq!(distinct.shared_value_bytes, 2 * once.shared_value_bytes);
    }

    #[test]
    fn hello_unique_walk_checks_actual_origin_and_borrow_before_root_credit() {
        let mut original = OriginalNativeHelloJournal::reserve(128, 64).unwrap();
        let mut roots = NativeCaptureMetadataRoots::new();
        let mut observer = MetadataObserver::new();
        let borrowed = original.bank.borrow_mut();
        assert!(
            original
                .observe_unique_capture_metadata(&mut roots, &mut observer)
                .is_err()
        );
        assert_eq!(roots.finish().unwrap(), (0, 0));
        drop(borrowed);

        // This is a real creator-thread mismatch, without changing an ID label.
        original.owner = std::thread::spawn(ProtocolCaptureOwner::new)
            .join()
            .unwrap();
        assert!(
            original
                .observe_unique_capture_metadata(&mut roots, &mut observer)
                .is_err()
        );
        assert_eq!(roots.finish().unwrap(), (0, 0));
    }
}

pub(crate) mod settled17;
pub(crate) use settled17::HistoricalNativeHello17;

#[path = "native_hello/retained_literal.rs"]
mod retained_literal;
pub(crate) use retained_literal::OriginalNativeHelloLiteral;
