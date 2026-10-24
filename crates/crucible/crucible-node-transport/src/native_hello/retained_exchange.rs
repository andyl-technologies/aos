//! Retains original journal/stream moves and every owning framing refusal.
//!
//! The journal's reservation remains a separate actual owner. Its bank receives
//! an alias discount only through checked shared-pointer identity. Framing moves
//! the one original stream without performing protocol I/O or negotiation.

use super::*;
use std::mem::size_of;

/// Retains one original framing constructor and its successful or refused owners.
pub(crate) struct RetainedOriginalNativeHelloExchange<S: Read + Write> {
    owner: ProtocolCaptureOwner,
    journal: Option<OriginalNativeHelloJournal>,
    stream: Option<S>,
    exchange: Option<OriginalNativeHelloExchange<S>>,
    refusal: Option<Box<OriginalNativeHelloBindRefusal<S>>>,
    complete: bool,
}

impl<S: Read + Write> RetainedOriginalNativeHelloExchange<S> {
    /// Installs the empty constructor before transferring either original owner.
    ///
    /// The caller separately admits this constructor and retains all three
    /// destinations on either outcome. No read, write or negotiation occurs.
    ///
    /// # Errors
    /// Refuses an occupied destination, missing original stream/journal,
    /// foreign creator or original framing/bank admission failure.
    pub(crate) fn bind_into_data(
        reservation: &mut OriginalNativeHelloReservation,
        stream: &mut Option<S>,
        output: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(refused());
        }
        *output = Some(Self {
            owner: ProtocolCaptureOwner::new(),
            journal: None,
            stream: None,
            exchange: None,
            refusal: None,
            complete: false,
        });
        let original = output.as_mut().ok_or_else(refused)?;
        original.owner.ensure_current()?;
        reservation.transfer_journal_into_data(&mut original.journal)?;
        original.stream = stream.take();
        if original.stream.is_none() {
            return Err(refused());
        }
        let journal = original.journal.take().ok_or_else(refused)?;
        let stream = original.stream.take().ok_or_else(refused)?;
        match journal.bind_owned(stream) {
            Ok(exchange) => original.exchange = Some(exchange),
            Err(refusal) => {
                original.refusal = Some(refusal);
                return Err(refused());
            }
        }
        original.owner.ensure_current()?;
        original.complete = true;
        Ok(())
    }

    /// Lends the completed original exchange while preserving its owning capsule.
    ///
    /// # Errors
    /// Refuses incomplete construction, stale creator, callback or terminal guard.
    pub(crate) fn with_exchange_data<R: Copy>(
        &self,
        inspect: impl FnOnce(&OriginalNativeHelloExchange<S>) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.owner.ensure_current()?;
        if !self.complete {
            return Err(refused());
        }
        let exchange = self.exchange.as_ref().ok_or_else(refused)?;
        exchange.journal.owner.ensure_current()?;
        let outcome = inspect(exchange);
        let terminal = self
            .owner
            .ensure_current()
            .and_then(|()| exchange.journal.owner.ensure_current());
        let result = outcome?;
        terminal?;
        Ok(result)
    }

    /// Receives one independently admitted literal into its surviving owner.
    ///
    /// # Errors
    /// Refuses incomplete or stale framing, repeated read, partial I/O or a
    /// terminal creator check. Neither outcome parses or publishes a Hello.
    pub(crate) fn receive_literal_into_data(
        &mut self,
        output: &mut Option<OriginalNativeHelloLiteral>,
    ) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if !self.complete {
            return Err(refused());
        }
        let exchange = self.exchange.as_mut().ok_or_else(refused)?;
        exchange.journal.owner.ensure_current()?;
        let outcome = exchange.receive_literal_into_data(output);
        let terminal = self
            .owner
            .ensure_current()
            .and_then(|()| exchange.journal.owner.ensure_current());
        outcome?;
        terminal
    }

    /// Publishes the same prepared proposal without moving the owning exchange.
    ///
    /// The enclosing source independently admits the complete response effect.
    /// Original byte progress and failure remain in the publication and journal.
    ///
    /// # Errors
    /// Refuses incomplete binding, stale creator, publication or terminal custody.
    pub(crate) fn publish_literal_response_data(
        &mut self,
        literal: &OriginalNativeHelloLiteral,
        body: &[u8],
        publication: &mut OriginalNativeHelloPublication,
        cut: crate::operational_time::OperationalDeadline,
    ) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if !self.complete {
            return Err(refused());
        }
        let exchange = self.exchange.as_mut().ok_or_else(refused)?;
        exchange.journal.owner.ensure_current()?;
        let outcome = exchange.publish_literal_response_data(literal, body, publication, cut);
        let terminal = self
            .owner
            .ensure_current()
            .and_then(|()| exchange.journal.owner.ensure_current());
        outcome?;
        terminal
    }

    /// Borrows the original stream after independently completed Hello publication.
    ///
    /// The caller admits every effect and retains its partial I/O owner before
    /// entry. No descriptor moves or duplicates and the original literal pair
    /// stays unchanged. This loan creates no SDK request or native permission.
    ///
    /// # Errors
    /// Refuses incomplete/stale publication, callback refusal, changed literal
    /// pair, original creator or terminal cut correspondence.
    pub(crate) fn with_completed_publication_stream_data<R: Copy>(
        &mut self,
        publication: &OriginalNativeHelloPublication,
        cut: crate::operational_time::OperationalDeadline,
        inspect: impl FnOnce(&mut S) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.owner.ensure_current()?;
        if !self.complete {
            return Err(refused());
        }
        let exchange = self.exchange.as_mut().ok_or_else(refused)?;
        let before = publication.completed_frame_digests_data(exchange, cut)?;
        let outcome = inspect(exchange.reader.stream_mut());
        let terminal = self
            .owner
            .ensure_current()
            .and_then(|()| publication.completed_frame_digests_data(exchange, cut));
        let result = outcome?;
        if terminal? != before {
            return Err(refused());
        }
        Ok(result)
    }

    /// Quotes actual completed-publication, stream and concrete result controls.
    ///
    /// # Errors
    /// Refuses checked accumulation overflow.
    pub(crate) fn publication_stream_counter_scratch_data<R: Copy>() -> Result<usize, ProviderError>
    {
        [
            OriginalNativeHelloPublication::completed_frame_digests_counter_scratch_data::<S>(),
            size_of::<&mut Self>(),
            size_of::<&OriginalNativeHelloPublication>(),
            size_of::<&mut S>(),
            size_of::<crate::operational_time::OperationalDeadline>(),
            size_of::<crate::hello_frames::OriginalHelloFrameDigests>() * 2,
            size_of::<Result<crate::hello_frames::OriginalHelloFrameDigests, ProviderError>>(),
            size_of::<R>(),
            size_of::<Result<R, ProviderError>>(),
            size_of::<Result<R, ProviderError>>(),
        ]
        .into_iter()
        .try_fold(Self::counter_scratch_data(), |sum, field| {
            sum.checked_add(field).ok_or_else(refused)
        })
    }

    /// Names the concrete wrapper controls beside the actual byte publisher.
    pub(crate) fn publication_counter_scratch_data() -> usize {
        Self::counter_scratch_data()
            + size_of::<&mut Self>()
            + size_of::<&OriginalNativeHelloLiteral>()
            + size_of::<&[u8]>()
            + size_of::<&mut OriginalNativeHelloPublication>()
            + size_of::<crate::operational_time::OperationalDeadline>()
            + size_of::<Result<(), ProviderError>>() * 3
    }

    /// Counts actual binding backing beside the original reservation's own census.
    ///
    /// `stream_backing` counts the surviving actual stream's child allocations.
    /// `literal_bank` borrows the actual retained incoming body's bank edge.
    /// Existing reservation bank backing must be included separately. Distinct
    /// banks receive separate charges; only proven Rc aliases are discounted.
    /// Expiration and incomplete construction do not hide surviving owners.
    ///
    /// # Errors
    /// Refuses foreign custody, unavailable bank borrowing, stream census
    /// failure or checked requested-layout overflow.
    pub(crate) fn retained_backing_beside_reservation_data(
        &self,
        reservation: &OriginalNativeHelloReservation,
        literal_bank: Option<&Rc<RefCell<OriginalFrameReservation>>>,
        stream_backing: impl Fn(&S) -> Result<usize, ProviderError>,
    ) -> Result<usize, ProviderError> {
        let Self {
            owner,
            journal,
            stream,
            exchange,
            refusal,
            complete: _,
        } = self;
        owner.ensure_current()?;
        reservation.retained_backing_data()?;

        let mut bytes = 0usize;
        if let Some(stream) = stream {
            bytes = stream_backing(stream)?;
        }
        if let Some(exchange) = exchange {
            bytes = bytes
                .checked_add(stream_backing(exchange.reader.stream_ref())?)
                .ok_or_else(refused)?;
        }
        if let Some(refusal) = refusal {
            // The defining no-I/O bind emits only static custody/framing errors.
            // A future allocating error needs its own explicit retained layout.
            let OriginalNativeHelloBindRefusal {
                journal: _,
                stream: original_stream,
                error,
            } = refusal.as_ref();
            match error {
                ProviderError::Frame(_)
                | ProviderError::Correlation(_)
                | ProviderError::ResourceExhausted(_)
                | ProviderError::Conflict(_) => {}
                ProviderError::Io(_) | ProviderError::Contract(_) => return Err(refused()),
            }
            bytes = bytes
                .checked_add(size_of::<OriginalNativeHelloBindRefusal<S>>())
                .ok_or_else(refused)?;
            bytes = bytes
                .checked_add(stream_backing(original_stream)?)
                .ok_or_else(refused)?;
        }

        let banks = [
            journal.as_ref().map(journal_bank_data).transpose()?,
            exchange
                .as_ref()
                .map(|exchange| journal_bank_data(&exchange.journal))
                .transpose()?,
            exchange
                .as_ref()
                .and_then(|exchange| exchange.reader.original_bank_data()),
            refusal
                .as_ref()
                .map(|refusal| journal_bank_data(&refusal.journal))
                .transpose()?,
            literal_bank,
        ];

        for (index, bank) in banks.iter().enumerate() {
            let Some(bank) = bank else {
                continue;
            };
            if reservation.counts_bank_data(bank)?
                || banks[..index]
                    .iter()
                    .flatten()
                    .any(|previous| Rc::ptr_eq(previous, bank))
            {
                continue;
            }

            let actual = bank.try_borrow().map_err(|_| refused())?;
            let shared = crate::retained_metadata::requested_storage::shared_header_storage_data(
                1,
                std::mem::align_of::<RefCell<OriginalFrameReservation>>(),
            )?;
            bytes = bytes
                .checked_add(shared)
                .and_then(|n| n.checked_add(size_of::<RefCell<OriginalFrameReservation>>()))
                .and_then(|n| n.checked_add(actual.allocated_bytes()))
                .ok_or_else(refused)?;
        }
        Ok(bytes)
    }

    /// Prices fresh binding storage without charging the moved stream/bank twice.
    ///
    /// The original reservation and actual stream backing remain independently
    /// charged. Successful binding allocates nothing; its sole allocating
    /// refusal retains one actual Box payload. Inline owners belong to the root.
    pub(crate) fn construction_data() -> [usize; 3] {
        [
            size_of::<OriginalNativeHelloBindRefusal<S>>(),
            size_of::<Self>()
                + size_of::<Option<Self>>()
                + size_of::<OriginalNativeHelloJournal>()
                + size_of::<Option<OriginalNativeHelloJournal>>()
                + size_of::<S>()
                + size_of::<FrameReader<S>>()
                + size_of::<Result<FrameReader<S>, (S, ProviderError)>>()
                + size_of::<OriginalNativeHelloExchange<S>>()
                + size_of::<OriginalNativeHelloBindRefusal<S>>()
                + size_of::<
                    Result<OriginalNativeHelloExchange<S>, Box<OriginalNativeHelloBindRefusal<S>>>,
                >(),
            Self::counter_scratch_data(),
        ]
    }

    /// Names actual transfer, framing, fixed alias-roster and census controls.
    pub(crate) fn counter_scratch_data() -> usize {
        OriginalNativeHelloReservation::counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&mut Self>()
            + size_of::<&mut Option<Self>>()
            + size_of::<&mut OriginalNativeHelloReservation>()
            + size_of::<&mut Option<OriginalNativeHelloJournal>>()
            + size_of::<Option<&OriginalNativeHelloJournal>>()
            + size_of::<&OriginalNativeHelloReservation>()
            + size_of::<&mut Option<S>>()
            + size_of::<&S>() * 3
            + size_of::<&OriginalNativeHelloJournal>() * 3
            + size_of::<Result<Option<&Rc<RefCell<OriginalFrameReservation>>>, ProviderError>>()
            + size_of::<Result<&Rc<RefCell<OriginalFrameReservation>>, ProviderError>>()
            + size_of::<[Option<&Rc<RefCell<OriginalFrameReservation>>>; 5]>()
            + size_of::<
                std::slice::Iter<'static, Option<&'static Rc<RefCell<OriginalFrameReservation>>>>,
            >() * 2
            + size_of::<
                std::iter::Enumerate<
                    std::slice::Iter<
                        'static,
                        Option<&'static Rc<RefCell<OriginalFrameReservation>>>,
                    >,
                >,
            >()
            + size_of::<
                std::iter::Flatten<
                    std::slice::Iter<
                        'static,
                        Option<&'static Rc<RefCell<OriginalFrameReservation>>>,
                    >,
                >,
            >()
            + size_of::<std::cell::Ref<'static, OriginalFrameReservation>>()
            + size_of::<
                Result<std::cell::Ref<'static, OriginalFrameReservation>, std::cell::BorrowError>,
            >()
            + size_of::<&Rc<RefCell<OriginalFrameReservation>>>() * 3
            + size_of::<Result<(), ProviderError>>() * 3
            + size_of::<Result<usize, ProviderError>>() * 3
            + size_of::<usize>() * 4
            + size_of::<Option<usize>>()
            + size_of::<[usize; 3]>()
    }

    /// Names a separate future immutable exchange inspection and Copy result.
    pub(crate) fn exchange_loan_counter_scratch_data<R: Copy>() -> usize {
        Self::counter_scratch_data() + size_of::<R>() + size_of::<Result<R, ProviderError>>()
    }
}

fn journal_bank_data(
    journal: &OriginalNativeHelloJournal,
) -> Result<&Rc<RefCell<OriginalFrameReservation>>, ProviderError> {
    let OriginalNativeHelloJournal {
        bank,
        maximum_bytes: _,
        maximum_nesting: _,
        owner,
        attempted: _,
        received: _,
        write_started: _,
        failed: _,
    } = journal;
    owner.ensure_current()?;
    Ok(bank)
}

fn refused() -> ProviderError {
    ProviderError::Correlation("retained original native Hello exchange")
}

#[cfg(test)]
// Deliberate fixture invariant panics expose lost original constructor owners.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Cursor;

    type Original = RetainedOriginalNativeHelloExchange<Cursor<Vec<u8>>>;

    fn reservation() -> OriginalNativeHelloReservation {
        let mut slot = None;
        OriginalNativeHelloReservation::reserve_into_data(256, 64, &mut slot).unwrap();
        slot.unwrap()
    }

    #[test]
    fn successful_binding_moves_the_same_stream_and_bank_without_io_or_allocation() {
        let mut bank = reservation();
        let before = bank.retained_backing_data().unwrap();
        let mut stream = Some(Cursor::new(vec![3, 5, 7]));
        let pointer = stream.as_ref().unwrap().get_ref().as_ptr();
        let capacity = stream.as_ref().unwrap().get_ref().capacity();
        let mut output = None;
        Original::bind_into_data(&mut bank, &mut stream, &mut output).unwrap();
        assert!(stream.is_none());
        assert!(bank.with_journal_data(|_| Ok(())).is_err());
        let original = output.as_ref().unwrap();
        original
            .with_exchange_data(|exchange| {
                assert_eq!(exchange.original_stream_data().get_ref().as_ptr(), pointer);
                assert_eq!(exchange.original_stream_data().position(), 0);
                assert!(exchange.journal.original_frames().frames().next().is_none());
                Ok(())
            })
            .unwrap();
        assert_eq!(bank.retained_backing_data().unwrap(), before);
        assert_eq!(
            original
                .retained_backing_beside_reservation_data(&bank, None, |stream| Ok(stream
                    .get_ref()
                    .capacity()))
                .unwrap(),
            capacity
        );
        let mut other = Some(Cursor::new(vec![11]));
        let other_pointer = other.as_ref().unwrap().get_ref().as_ptr();
        assert!(Original::bind_into_data(&mut bank, &mut other, &mut output).is_err());
        assert_eq!(other.as_ref().unwrap().get_ref().as_ptr(), other_pointer);
    }

    #[test]
    fn refused_binding_retains_its_actual_box_journal_and_same_stream() {
        let mut bank = reservation();
        bank.journal_mut_fixture_data().unwrap().attempted = true;
        let before = bank.retained_backing_data().unwrap();
        let mut stream = Some(Cursor::new(vec![1, 2, 3]));
        let pointer = stream.as_ref().unwrap().get_ref().as_ptr();
        let capacity = stream.as_ref().unwrap().get_ref().capacity();
        let mut output = None;
        assert!(Original::bind_into_data(&mut bank, &mut stream, &mut output).is_err());
        let original = output.as_ref().unwrap();
        assert!(original.with_exchange_data(|_| Ok(())).is_err());
        assert!(stream.is_none());
        let refusal = original.refusal.as_ref().unwrap();
        assert_eq!(refusal.stream.get_ref().as_ptr(), pointer);
        assert_eq!(refusal.stream.position(), 0);
        assert_eq!(bank.retained_backing_data().unwrap(), before);
        assert_eq!(
            original
                .retained_backing_beside_reservation_data(&bank, None, |stream| Ok(stream
                    .get_ref()
                    .capacity()))
                .unwrap(),
            Original::construction_data()[0] + capacity
        );
    }

    #[test]
    fn absent_stream_keeps_the_transferred_journal_and_occupied_partial_spent() {
        let mut bank = reservation();
        let before = bank.retained_backing_data().unwrap();
        let mut stream = None;
        let mut output: Option<Original> = None;
        assert!(Original::bind_into_data(&mut bank, &mut stream, &mut output).is_err());
        let original = output.as_ref().unwrap();
        assert!(original.journal.is_some());
        assert!(original.exchange.is_none());
        assert!(original.refusal.is_none());
        assert!(bank.with_journal_data(|_| Ok(())).is_err());
        assert_eq!(bank.retained_backing_data().unwrap(), before);
        assert_eq!(
            original
                .retained_backing_beside_reservation_data(&bank, None, |_| Ok(0))
                .unwrap(),
            0
        );
        assert!(Original::bind_into_data(&mut bank, &mut stream, &mut output).is_err());
    }

    #[test]
    fn distinct_reader_bank_is_counted_and_borrowed_original_refuses_the_census() {
        let mut bank = reservation();
        let mut stream = Some(Cursor::new(Vec::new()));
        let mut output = None;
        Original::bind_into_data(&mut bank, &mut stream, &mut output).unwrap();
        let original = output.as_mut().unwrap();
        let other = OriginalNativeHelloJournal::reserve(256, 64).unwrap();
        original
            .exchange
            .as_mut()
            .unwrap()
            .reader
            .install_originals(Rc::clone(&other.bank));
        let expected = other.allocated_bytes()
            + size_of::<RefCell<OriginalFrameReservation>>()
            + crate::retained_metadata::requested_storage::shared_header_storage_data(
                1,
                std::mem::align_of::<RefCell<OriginalFrameReservation>>(),
            )
            .unwrap();
        assert_eq!(
            original
                .retained_backing_beside_reservation_data(&bank, None, |_| Ok(0))
                .unwrap(),
            expected
        );
        assert_eq!(
            original
                .retained_backing_beside_reservation_data(&bank, Some(&other.bank), |_| Ok(0))
                .unwrap(),
            expected
        );
        let distinct_literal = OriginalNativeHelloJournal::reserve(128, 64).unwrap();
        let distinct_backing = distinct_literal.allocated_bytes()
            + size_of::<RefCell<OriginalFrameReservation>>()
            + crate::retained_metadata::requested_storage::shared_header_storage_data(
                1,
                std::mem::align_of::<RefCell<OriginalFrameReservation>>(),
            )
            .unwrap();
        assert_eq!(
            original
                .retained_backing_beside_reservation_data(
                    &bank,
                    Some(&distinct_literal.bank),
                    |_| Ok(0)
                )
                .unwrap(),
            expected + distinct_backing
        );
        let held_literal = distinct_literal.bank.borrow_mut();
        assert!(
            original
                .retained_backing_beside_reservation_data(
                    &bank,
                    Some(&distinct_literal.bank),
                    |_| Ok(0)
                )
                .is_err()
        );
        drop(held_literal);
        let same_bank = Rc::clone(&original.exchange.as_ref().unwrap().journal.bank);
        let held = same_bank.borrow_mut();
        assert!(
            original
                .retained_backing_beside_reservation_data(&bank, None, |_| Ok(0))
                .is_err()
        );
        drop(held);
        assert_eq!(
            original
                .retained_backing_beside_reservation_data(&bank, None, |_| Ok(0))
                .unwrap(),
            expected
        );
    }
}
