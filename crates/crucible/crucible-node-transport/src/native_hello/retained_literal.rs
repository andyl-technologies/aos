//! Retains one original public Hello read before any JSON or protocol decision.
//!
//! The separate literal journal owns every observed header/body byte. This
//! capsule also retains the actual bounded body allocation and read cursors,
//! including after partial I/O, allocation refusal or a terminal admission failure.

use super::*;
use std::mem::size_of;

/// Owns a once-only, unparsed original Hello body and its physical progress.
pub(crate) struct OriginalNativeHelloLiteral {
    owner: ProtocolCaptureOwner,
    bank: Option<Rc<RefCell<OriginalFrameReservation>>>,
    header: [u8; 4],
    header_received: usize,
    body: Vec<u8>,
    body_received: usize,
    slot: Option<usize>,
    complete: bool,
}

impl OriginalNativeHelloLiteral {
    /// Quotes the separately retained body bank and actual read controls.
    ///
    /// The existing journal, socket and original cut remain charged separately.
    /// This quote covers no JSON parser, negotiation, response or native model.
    ///
    /// # Errors
    /// Refuses invalid Hello framing or checked layout overflow.
    pub(crate) fn construction_data(maximum: usize) -> Result<[usize; 3], ProviderError> {
        OriginalNativeHelloJournal::reservation_requested_storage_data(maximum)?;
        Ok([
            maximum,
            size_of::<Self>() + size_of::<Option<Self>>() + size_of::<Vec<u8>>(),
            Self::counter_scratch_data(),
        ])
    }

    /// Counts the actual body allocation after either outcome.
    ///
    /// The enclosing exchange census separately counts the actual shared bank
    /// edge below and discounts it only through checked pointer equality.
    ///
    /// # Errors
    /// Refuses foreign process/thread custody.
    pub(crate) fn retained_body_backing_data(&self) -> Result<usize, ProviderError> {
        let Self {
            owner,
            bank: _,
            header: _,
            header_received: _,
            body,
            body_received: _,
            slot: _,
            complete: _,
        } = self;
        owner.ensure_current()?;
        Ok(body.capacity())
    }

    /// Borrows the actual shared bank edge for the enclosing whole-owner census.
    ///
    /// # Errors
    /// Refuses foreign process/thread custody.
    pub(crate) fn original_bank_data(
        &self,
    ) -> Result<Option<&Rc<RefCell<OriginalFrameReservation>>>, ProviderError> {
        self.owner.ensure_current()?;
        Ok(self.bank.as_ref())
    }

    /// Borrows the complete literal body without parsing or issuing authority.
    ///
    /// # Errors
    /// Refuses incomplete reads, changed framing, original journal or custody.
    pub(crate) fn body_data<S: Read + Write>(
        &self,
        exchange: &OriginalNativeHelloExchange<S>,
    ) -> Result<&[u8], ProviderError> {
        self.owner.ensure_current()?;
        exchange.journal.owner.ensure_current()?;
        let reader = exchange
            .reader
            .original_owned11_facts(&exchange.journal.bank)?;
        if self
            .bank
            .as_ref()
            .is_none_or(|bank| !Rc::ptr_eq(bank, &exchange.journal.bank))
            || !self.complete
            || self.header_received != 4
            || self.body_received != self.body.len()
            || u32::from_be_bytes(self.header) as usize != self.body.len()
            || !exchange.journal.attempted
            || exchange.journal.failed
            || reader.failed
            || reader.last_original_slot != self.slot
        {
            return Err(refused());
        }
        let bank = exchange.journal.bank.try_borrow().map_err(|_| refused())?;
        let frame = bank
            .frame(self.slot.ok_or_else(refused)?)
            .ok_or_else(refused)?;
        if frame.direction != FrameDirection::Incoming
            || !frame.complete
            || frame.transferred != self.body.len() + 4
            || frame.bytes.get(..4) != Some(self.header.as_slice())
            || frame.bytes.get(4..) != Some(self.body.as_slice())
        {
            return Err(refused());
        }
        Ok(&self.body)
    }

    /// Names actual fixed read, bank-borrow, allocation and terminal controls.
    pub(crate) fn counter_scratch_data() -> usize {
        size_of::<crate::transport::OriginalFrameReaderFacts>()
            + size_of::<Result<crate::transport::OriginalFrameReaderFacts, ProviderError>>()
            + size_of::<[u8; 4]>()
            + size_of::<&Rc<RefCell<OriginalFrameReservation>>>()
            + size_of::<Option<&Rc<RefCell<OriginalFrameReservation>>>>()
            + size_of::<Result<Option<&Rc<RefCell<OriginalFrameReservation>>>, ProviderError>>()
            + size_of::<&Self>()
            + size_of::<&mut Self>()
            + size_of::<&mut Option<Self>>()
            + size_of::<Option<Self>>()
            + size_of::<&mut [u8]>()
            + size_of::<&[u8]>()
            + size_of::<Option<usize>>() * 2
            + size_of::<usize>() * 6
            + size_of::<Rc<RefCell<OriginalFrameReservation>>>()
            + size_of::<std::cell::Ref<'static, OriginalFrameReservation>>()
            + size_of::<std::cell::RefMut<'static, OriginalFrameReservation>>()
            + size_of::<
                Result<std::cell::Ref<'static, OriginalFrameReservation>, std::cell::BorrowError>,
            >()
            + size_of::<
                Result<
                    std::cell::RefMut<'static, OriginalFrameReservation>,
                    std::cell::BorrowMutError,
                >,
            >()
            + size_of::<crate::transport::original_frames::OriginalFrame<'static>>()
            + size_of::<Option<crate::transport::original_frames::OriginalFrame<'static>>>()
            + size_of::<Result<(), std::collections::TryReserveError>>()
            + size_of::<Result<usize, io::Error>>()
            + size_of::<io::ErrorKind>()
            + size_of::<Result<(), ProviderError>>() * 4
            + size_of::<Result<&[u8], ProviderError>>()
    }
}

impl<S: Read + Write> OriginalNativeHelloExchange<S> {
    // The enclosing owner must independently admit the complete maximum body
    // before calling. Install the partial before spending the journal or I/O.
    pub(super) fn receive_literal_into_data(
        &mut self,
        output: &mut Option<OriginalNativeHelloLiteral>,
    ) -> Result<(), ProviderError> {
        self.journal.owner.ensure_current()?;
        if output.is_some()
            || self.journal.attempted
            || self.journal.failed
            || self
                .reader
                .original_owned11_facts(&self.journal.bank)?
                .failed
        {
            return Err(refused());
        }
        *output = Some(OriginalNativeHelloLiteral {
            owner: ProtocolCaptureOwner::new(),
            bank: None,
            header: [0; 4],
            header_received: 0,
            body: Vec::new(),
            body_received: 0,
            slot: None,
            complete: false,
        });
        self.journal.attempted = true;
        let literal = output.as_mut().ok_or_else(refused)?;
        let outcome = self.read_literal(literal);
        if outcome.is_err() {
            self.journal.failed = true;
            self.reader.fence_original_literal_data();
        }
        outcome
    }

    fn read_literal(
        &mut self,
        literal: &mut OriginalNativeHelloLiteral,
    ) -> Result<(), ProviderError> {
        let bank = &self.journal.bank;
        let slot = self
            .reader
            .begin_original_literal_data(self.journal.maximum_bytes, bank)?;
        literal.slot = Some(slot);
        literal.bank = Some(Rc::clone(bank));
        read_into(
            self.reader.stream_mut(),
            bank,
            slot,
            &mut literal.header,
            &mut literal.header_received,
        )?;
        let length = u32::from_be_bytes(literal.header) as usize;
        if length == 0 || length > self.journal.maximum_bytes {
            return Err(ProviderError::Frame("length outside admitted allowance"));
        }
        literal
            .body
            .try_reserve_exact(length)
            .map_err(|_| refused())?;
        if literal.body.capacity() != length {
            return Err(refused());
        }
        literal.body.resize(length, 0);
        read_into(
            self.reader.stream_mut(),
            bank,
            slot,
            &mut literal.body,
            &mut literal.body_received,
        )?;
        bank.try_borrow_mut().map_err(|_| refused())?.finish(slot)?;
        self.journal.owner.ensure_current()?;
        literal.complete = true;
        // A complete literal read alone cannot authorize publish(). The original
        // journal's received flag awaits the separately funded strict parser.
        literal.body_data(self).map(|_| ())
    }
}

fn read_into(
    stream: &mut impl Read,
    bank: &Rc<RefCell<OriginalFrameReservation>>,
    slot: usize,
    bytes: &mut [u8],
    received: &mut usize,
) -> Result<(), ProviderError> {
    while *received < bytes.len() {
        let count = match stream.read(&mut bytes[*received..]) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if count == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }
        // Advance the actual I/O cursor even if retaining the literal fails.
        let start = *received;
        *received += count;
        bank.try_borrow_mut()
            .map_err(|_| refused())?
            .append(slot, &bytes[start..*received])?;
    }
    Ok(())
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original Hello literal custody")
}

#[cfg(test)]
// Deliberate fixture panics expose changed physical ownership and framing.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn exchange(bytes: Vec<u8>) -> OriginalNativeHelloExchange<Cursor<Vec<u8>>> {
        OriginalNativeHelloJournal::reserve(64, 64)
            .unwrap()
            .bind(Cursor::new(bytes))
            .unwrap()
    }

    #[test]
    fn literal_read_preserves_unparsed_bytes_and_never_enables_publication() {
        let body = b"{invalid JSON is still literal DATA";
        let mut wire = (body.len() as u32).to_be_bytes().to_vec();
        wire.extend_from_slice(body);
        wire.extend_from_slice(b"next-frame-unread");
        let original_pointer = wire.as_ptr();
        let mut exchange = exchange(wire);
        let mut literal = None;
        exchange.receive_literal_into_data(&mut literal).unwrap();
        let literal_ref = literal.as_ref().unwrap();
        assert_eq!(literal_ref.body_data(&exchange).unwrap(), body);
        assert_eq!(
            literal_ref.retained_body_backing_data().unwrap(),
            body.len()
        );
        assert_eq!(
            exchange.original_stream_data().get_ref().as_ptr(),
            original_pointer
        );
        assert_eq!(
            exchange.original_stream_data().position(),
            (body.len() + 4) as u64
        );
        let pointer = literal_ref.body.as_ptr();
        assert!(exchange.publish(&serde_json::Value::Null).is_err());
        assert_eq!(
            exchange.original_stream_data().position(),
            (body.len() + 4) as u64
        );
        assert!(exchange.receive_literal_into_data(&mut literal).is_err());
        assert!(exchange.receive().is_err());
        assert_eq!(literal_ref_pointer(&literal), pointer);
    }

    fn literal_ref_pointer(literal: &Option<OriginalNativeHelloLiteral>) -> *const u8 {
        literal.as_ref().unwrap().body.as_ptr()
    }

    #[test]
    fn partial_reads_retain_the_actual_allocation_and_journal_prefix() {
        for wire in [vec![0, 0], vec![0, 0, 0, 8, b'a', b'b']] {
            let expected = wire.clone();
            let mut exchange = exchange(wire);
            let mut literal = None;
            assert!(exchange.receive_literal_into_data(&mut literal).is_err());
            let partial = literal.as_ref().unwrap();
            assert_eq!(partial.header_received, expected.len().min(4));
            assert_eq!(partial.body_received, expected.len().saturating_sub(4));
            assert_eq!(
                partial.retained_body_backing_data().unwrap(),
                if expected.len() > 4 { 8 } else { 0 }
            );
            assert!(partial.body_data(&exchange).is_err());
            let bank = exchange.journal.bank.borrow();
            let frame = bank.frame(partial.slot.unwrap()).unwrap();
            assert_eq!(frame.bytes, expected);
            assert!(!frame.complete);
            drop(bank);
            let pointer = partial.body.as_ptr();
            assert!(exchange.receive_literal_into_data(&mut literal).is_err());
            assert_eq!(literal.as_ref().unwrap().body.as_ptr(), pointer);
            assert!(exchange.receive().is_err());
        }
    }

    #[test]
    fn invalid_lengths_spend_the_original_header_without_allocating_a_body() {
        for length in [0u32, 65] {
            let mut exchange = exchange(length.to_be_bytes().to_vec());
            let mut literal = None;
            assert!(exchange.receive_literal_into_data(&mut literal).is_err());
            let partial = literal.as_ref().unwrap();
            assert_eq!(partial.header, length.to_be_bytes());
            assert_eq!(partial.header_received, 4);
            assert_eq!(partial.retained_body_backing_data().unwrap(), 0);
            assert_eq!(partial.body_received, 0);
            assert!(exchange.journal.failed);
            assert!(
                exchange
                    .reader
                    .original_owned11_facts(&exchange.journal.bank)
                    .unwrap()
                    .failed
            );
            assert!(exchange.receive().is_err());
        }
    }

    #[test]
    fn identical_literals_on_distinct_original_banks_cannot_substitute_custody() {
        let mut first = exchange(vec![0, 0, 0, 1, b'0']);
        let mut first_literal = None;
        first.receive_literal_into_data(&mut first_literal).unwrap();
        let mut second = exchange(vec![0, 0, 0, 1, b'0']);
        let mut second_literal = None;
        second
            .receive_literal_into_data(&mut second_literal)
            .unwrap();
        assert!(first_literal.as_ref().unwrap().body_data(&second).is_err());
        assert!(second_literal.as_ref().unwrap().body_data(&first).is_err());
        assert_eq!(
            first_literal.as_ref().unwrap().body_data(&first).unwrap(),
            b"0"
        );
        assert_eq!(
            second_literal.as_ref().unwrap().body_data(&second).unwrap(),
            b"0"
        );
    }

    #[test]
    fn occupied_destination_preserves_both_originals_without_spending_incoming_io() {
        let mut first = exchange(vec![0, 0, 0, 1, b'0']);
        let mut output = None;
        first.receive_literal_into_data(&mut output).unwrap();
        let pointer = literal_ref_pointer(&output);
        let mut incoming = exchange(vec![0, 0, 0, 1, b'1']);
        assert!(incoming.receive_literal_into_data(&mut output).is_err());
        assert!(!incoming.journal.attempted);
        assert_eq!(incoming.original_stream_data().position(), 0);
        assert_eq!(literal_ref_pointer(&output), pointer);
        assert_eq!(output.as_ref().unwrap().body_data(&first).unwrap(), b"0");
    }
}
