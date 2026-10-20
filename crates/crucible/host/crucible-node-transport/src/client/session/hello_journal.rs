//! Retains one original pre-connection Hello exchange under pre-reserved credit.
//!
//! The complete request is prepared before Child. Complete incoming wire JSON is
//! retained before envelope or handshake authentication, including a refused
//! response. This private journal is data, not lease or native authority; it
//! preserves complete validated response body bytes and secret Hello material.

use std::io::{self, Write};

use serde_json::Value;

use crate::{ProviderError, envelope::Envelope};

pub use crate::hello_frames::OriginalHelloFrameDigests;

const MAXIMUM_BYTES: usize = 1024 * 1024;

/// Owns bounded original Hello bodies without registration or command authority.
///
/// The host reserves this journal before launching the original peer. Accessors
/// borrow private data only; callers must not publish its admission token. A
/// failed or incomplete frame leaves the original attempt fenced and does not
/// imply that a complete response was received or authenticated.
pub struct OriginalHelloJournal {
    request: Envelope,
    request_value: Value,
    response: Vec<u8>,
    maximum_bytes: usize,
    maximum_nesting: usize,
    attempted: bool,
    received: bool,
    literal: Option<LiteralHello>,
}

struct LiteralHello {
    bank: std::rc::Rc<
        std::cell::RefCell<crate::transport::original_frames::OriginalFrameReservation>,
    >,
    outgoing: usize,
    write_started: bool,
    original_cut: crate::protocol_snapshot::ProtocolCaptureOwner,
}

impl OriginalHelloJournal {
    /// Reports actual retained native Hello owners and complete bank capacities.
    ///
    /// # Errors
    /// Refuses absent original native custody, foreign origin, a borrowed bank
    /// or checked traversal overflow. A digest supplies no storage credit.
    pub fn original_retained_metadata_facts(
        &self,
    ) -> Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError> {
        let Self {
            request,
            request_value,
            response,
            maximum_bytes: _,
            maximum_nesting: _,
            attempted: _,
            received: _,
            literal,
        } = self;
        let LiteralHello {
            bank,
            outgoing: _,
            write_started: _,
            original_cut,
        } = literal.as_ref().ok_or(ProviderError::Correlation(
            "original Hello metadata custody absent",
        ))?;
        original_cut.ensure_current()?;
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        observer.observe(request)?;
        observer.observe(request_value)?;
        observer.observe(response)?;
        observer.shared_value(bank.as_ref())?;
        let bank = bank
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("original Hello metadata bank borrowed"))?;
        bank.observe_owned11_metadata(&mut observer)?;
        Ok(observer.finish())
    }

    /// Reserves the complete original request and one full incoming frame.
    ///
    /// # Errors
    /// Refuses zero or over-one-MiB frame credit, invalid nesting, an oversized
    /// original request or unavailable incoming storage. No I/O occurs here.
    pub fn reserve(
        request: &Envelope,
        maximum_bytes: usize,
        maximum_nesting: usize,
    ) -> Result<Self, ProviderError> {
        if maximum_bytes == 0
            || maximum_bytes > MAXIMUM_BYTES
            || maximum_nesting == 0
            || maximum_nesting > 64
        {
            return Err(ProviderError::ResourceExhausted(
                "original Hello journal limits",
            ));
        }
        serde_json::to_writer(
            Counter {
                bytes: 0,
                limit: maximum_bytes,
            },
            request,
        )
        .map_err(crucible_node_format::ContractError::from)?;
        let request_value =
            serde_json::to_value(request).map_err(crucible_node_format::ContractError::from)?;
        let mut response = Vec::new();
        response
            .try_reserve_exact(maximum_bytes)
            .map_err(|_| ProviderError::ResourceExhausted("original Hello response reservation"))?;
        Ok(Self {
            request: request.clone(),
            request_value,
            response,
            maximum_bytes,
            maximum_nesting,
            attempted: false,
            received: false,
            literal: None,
        })
    }

    /// Reserves literal Hello framing before a Native5 child exists.
    ///
    /// The ordinary journal-absent and baseline reservation paths keep their
    /// existing behavior. This opt-in retains the actual planned request frame,
    /// its write cursor and complete or partial incoming framing bytes.
    ///
    /// # Errors
    /// Refuses baseline credit errors, unavailable literal storage or a request
    /// outside the original frame allowance. No native I/O occurs here.
    pub fn reserve_native5(
        request: &Envelope,
        maximum_bytes: usize,
        maximum_nesting: usize,
    ) -> Result<Self, ProviderError> {
        use crate::transport::original_frames::{FrameDirection, OriginalFrameReservation};
        let mut original = Self::reserve(request, maximum_bytes, maximum_nesting)?;
        let mut count = Counter {
            bytes: 0,
            limit: maximum_bytes,
        };
        crucible_node_format::canonical::canonical_json_to_writer(
            &original.request_value,
            &mut count,
        )?;
        let mut bank = OriginalFrameReservation::reserve((maximum_bytes + 4) * 2, 1)?;
        let outgoing = bank.begin(FrameDirection::Outgoing, count.bytes + 4)?;
        let length = u32::try_from(count.bytes)
            .map_err(|_| ProviderError::Frame("literal Hello frame length"))?;
        bank.append(outgoing, &length.to_be_bytes())?;
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
        crucible_node_format::canonical::canonical_json_to_writer(
            &original.request_value,
            &mut OriginalWriter {
                bank: &mut bank,
                slot: outgoing,
            },
        )?;
        original.literal = Some(LiteralHello {
            bank: std::rc::Rc::new(std::cell::RefCell::new(bank)),
            outgoing,
            write_started: false,
            original_cut: crate::protocol_snapshot::ProtocolCaptureOwner::new(),
        });
        Ok(original)
    }

    pub(crate) fn authenticate_original_literal_bank(
        &self,
        actual: &std::rc::Rc<
            std::cell::RefCell<crate::transport::original_frames::OriginalFrameReservation>,
        >,
    ) -> Result<(), ProviderError> {
        let literal = self
            .literal
            .as_ref()
            .ok_or(ProviderError::Correlation("original literal Hello absent"))?;
        literal.original_cut.ensure_current()?;
        if !std::rc::Rc::ptr_eq(&literal.bank, actual) {
            return Err(ProviderError::Correlation(
                "original recorded Hello connection differs",
            ));
        }
        Ok(())
    }

    /// Returns role-normalized digests of complete original raw Hello frames.
    ///
    /// No frame is reconstructed. The source separately authenticates this
    /// journal's association with its actual controller, native and registrar.
    ///
    /// # Errors
    /// Refuses a nonliteral, foreign-origin, unattempted, incomplete or repeated
    /// Hello direction, changed raw framing extent or concurrently borrowed bank.
    pub fn original_literal_frame_digests(
        &self,
    ) -> Result<OriginalHelloFrameDigests, ProviderError> {
        let literal = self
            .literal
            .as_ref()
            .ok_or(ProviderError::Correlation("original literal Hello absent"))?;
        literal.original_cut.ensure_current()?;
        if !self.attempted || !self.received || !literal.write_started {
            return Err(ProviderError::Correlation(
                "original literal Hello exchange incomplete",
            ));
        }
        let bank = literal
            .bank
            .try_borrow()
            .map_err(|_| ProviderError::Correlation("original literal Hello bank borrowed"))?;
        crate::hello_frames::original_hello_frame_digests(
            &bank,
            crate::connection::EndpointRole::Controller,
        )
    }

    /// Reports the additional actual literal byte/descriptor reservation.
    ///
    /// Baseline Envelope/Value/response capacity and temporary encoding remain
    /// separate charges in the source's pre-Child complete resource profile.
    pub fn literal_allocated_bytes(&self) -> usize {
        self.literal
            .as_ref()
            .map_or(0, |literal| literal.bank.borrow().allocated_bytes())
    }

    /// Borrows literal Hello frames and partial progress without reencoding them.
    pub fn original_frames(
        &self,
    ) -> Option<std::cell::Ref<'_, crate::transport::original_frames::OriginalFrameReservation>>
    {
        self.literal.as_ref().map(|literal| literal.bank.borrow())
    }

    pub(super) fn literal_bank(
        &self,
    ) -> Option<
        std::rc::Rc<
            std::cell::RefCell<crate::transport::original_frames::OriginalFrameReservation>,
        >,
    > {
        self.literal.as_ref().map(|literal| literal.bank.clone())
    }

    pub(super) fn publish_literal(
        &mut self,
        stream: &mut impl Write,
    ) -> Result<bool, ProviderError> {
        let Some(literal) = &mut self.literal else {
            return Ok(false);
        };
        literal.original_cut.ensure_current()?;
        if !self.attempted {
            return Err(ProviderError::Correlation(
                "literal Hello not reserved for its original attempt",
            ));
        }
        if literal.write_started {
            return Err(ProviderError::Conflict(
                "literal Hello write already attempted",
            ));
        }
        literal.write_started = true;
        let mut bank = literal.bank.borrow_mut();
        let frame = bank
            .frames()
            .next()
            .ok_or(ProviderError::Frame("literal Hello request absent"))?;
        if frame.transferred != 0 || frame.complete {
            return Err(ProviderError::Conflict("literal Hello already attempted"));
        }
        let length = frame.bytes.len();
        let mut transferred = 0;
        while transferred < length {
            let count = {
                let frame = bank
                    .frames()
                    .next()
                    .ok_or(ProviderError::Frame("literal Hello request absent"))?;
                match stream.write(&frame.bytes[transferred..]) {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    result => result?,
                }
            };
            if count == 0 {
                return Err(io::Error::from(io::ErrorKind::WriteZero).into());
            }
            bank.advance(literal.outgoing, count)?;
            transferred += count;
        }
        bank.finish(literal.outgoing)?;
        Ok(true)
    }

    /// Borrows the complete private original request, including secret material.
    pub fn request(&self) -> &Envelope {
        &self.request
    }

    /// Borrows a complete received JSON body before interpreting its authority.
    ///
    /// The body preserves the actual validated JSON bytes, including whitespace
    /// and a rejected envelope. The framing length is not included. No body is
    /// exposed for malformed JSON, an incomplete frame or an unattempted exchange.
    pub fn response(&self) -> Option<&[u8]> {
        self.received.then_some(self.response.as_slice())
    }

    /// Reports that the original exchange was reserved for its one attempt.
    pub fn attempted(&self) -> bool {
        self.attempted
    }

    pub(super) fn begin(
        &mut self,
        request: &Envelope,
        maximum_bytes: usize,
        maximum_nesting: usize,
    ) -> Result<(), ProviderError> {
        if let Some(literal) = &self.literal {
            literal.original_cut.ensure_current()?;
        }
        if self.attempted
            || &self.request != request
            || self.maximum_bytes != maximum_bytes
            || self.maximum_nesting != maximum_nesting
        {
            return Err(ProviderError::Correlation(
                "original Hello journal changed or used",
            ));
        }
        self.attempted = true;
        Ok(())
    }

    pub(super) fn request_value(&self) -> &Value {
        &self.request_value
    }

    pub(super) fn retain_response(&mut self, bytes: &[u8]) -> Result<(), ProviderError> {
        if !self.attempted || self.received || !self.response.is_empty() {
            return Err(ProviderError::Correlation(
                "original Hello response already retained",
            ));
        }
        if bytes.is_empty()
            || bytes.len() > self.maximum_bytes
            || bytes.len() > self.response.capacity()
        {
            return Err(ProviderError::ResourceExhausted(
                "original Hello response credit",
            ));
        }
        // The frame decoder has already bounded and validated these original
        // bytes. All complete retention capacity was reserved before Child;
        // copying here neither canonicalizes the body nor allocates another Vec.
        self.response.extend_from_slice(bytes);
        self.received = true;
        Ok(())
    }
}

struct Counter {
    bytes: usize,
    limit: usize,
}

impl Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .filter(|total| *total <= self.limit)
            .ok_or_else(|| io::Error::other("original Hello request credit"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "hello_journal/tests.rs"]
mod tests;

#[cfg(all(test, unix))]
// crucible-lint: allow panic-shortcut -- These original Hello framing controls deliberately panic on invalid fixtures.
#[allow(clippy::unwrap_used)]
mod literal_tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn native5_original_hello_keeps_literal_request_and_partial_incoming_header() {
        let request = crate::handshake::tests::original_hello_envelope();
        let mut original = OriginalHelloJournal::reserve_native5(&request, 16384, 64).unwrap();
        assert!(original.literal_allocated_bytes() >= 32776);
        let planned = original
            .original_frames()
            .unwrap()
            .frames()
            .next()
            .unwrap()
            .bytes
            .to_vec();
        original.begin(&request, 16384, 64).unwrap();
        let (mut stream, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
        original.publish_literal(&mut stream).unwrap();
        let mut received = vec![0; planned.len()];
        peer.read_exact(&mut received).unwrap();
        assert_eq!(received, planned);
        assert!(original.publish_literal(&mut stream).is_err());
        peer.write_all(&[0, 0, 0]).unwrap();
        peer.shutdown(std::net::Shutdown::Write).unwrap();
        let mut reader = crate::transport::FrameReader::new(stream, 16384).unwrap();
        reader.install_originals(original.literal_bank().unwrap());
        assert!(reader.read_retained().is_err());
        let bank = original.original_frames().unwrap();
        let frames: Vec<_> = bank.frames().collect();
        assert!(frames[0].complete);
        assert_eq!(frames[0].transferred, planned.len());
        assert_eq!(frames[1].bytes, [0, 0, 0]);
        assert_eq!(frames[1].transferred, 3);
        assert!(!frames[1].complete);
        assert!(original.response().is_none());
        assert!(original.attempted());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod role_digest_tests {
    use super::*;
    use crate::{
        envelope::{MessageKind, Method, Nullable},
        native_hello::OriginalNativeHelloJournal,
        transport::FrameReader,
    };
    use crucible_node_format::U64;
    use std::{os::unix::net::UnixStream, time::Duration};

    #[test]
    fn original_hello_raw_digest_matches_actual_duplex_unix_and_refuses_equal_foreign_bank() {
        // These are literal transport models, with no negotiated registrar or
        // private Child. The journal/connection source conjunction is separate.
        let request = Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(None),
            incarnation_id: Nullable(None),
            node_id: Nullable(None),
            execution_owner_id: Nullable(None),
            capture_owner_id: Nullable(None),
            request_id: Nullable(Some(crucible_node_format::Id::new("hello").unwrap())),
            operation_id: Nullable(None),
            sequence: U64::new(1),
            method: Method::Hello,
            body: serde_json::Map::new(),
            extensions: crucible_node_format::Extensions::new(),
        };
        let (mut host_stream, native_stream) = UnixStream::pair().unwrap();
        host_stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        native_stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut journal = OriginalHelloJournal::reserve_native5(&request, 65_536, 64).unwrap();
        assert!(journal.original_literal_frame_digests().is_err());
        journal.begin(&request, 65_536, 64).unwrap();
        journal.publish_literal(&mut host_stream).unwrap();
        let actual_bank = journal.literal_bank().unwrap();
        let mut native = OriginalNativeHelloJournal::reserve(65_536, 64)
            .unwrap()
            .bind(native_stream)
            .unwrap();
        let received = native.receive().unwrap().unwrap();
        assert_eq!(received, serde_json::to_value(&request).unwrap());
        native
            .publish(&serde_json::json!({"transport-model":"response"}))
            .unwrap();
        let mut reader = FrameReader::with_limits(host_stream, 65_536, 64).unwrap();
        reader.install_originals(actual_bank.clone());
        let reply = reader.read_retained().unwrap().unwrap();
        journal.retain_response(&reply.bytes).unwrap();

        journal
            .authenticate_original_literal_bank(&actual_bank)
            .unwrap();
        assert_eq!(
            journal.original_literal_frame_digests().unwrap(),
            native.originals().original_literal_frame_digests().unwrap()
        );
        let foreign = OriginalHelloJournal::reserve_native5(&request, 65_536, 64).unwrap();
        assert!(
            foreign
                .authenticate_original_literal_bank(&actual_bank)
                .is_err()
        );
        assert!(journal.literal_bank().is_some());
    }
}
