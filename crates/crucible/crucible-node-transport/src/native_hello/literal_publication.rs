//! Retains the once-only publication of an independently prepared Hello body.
//!
//! The enclosing owner authenticates and funds the response before this byte
//! transition. The complete proposal enters the existing literal bank before
//! the first write. No parsing, SDK authority, ACK or native readiness is granted.

use super::*;
use crate::operational_time::OperationalDeadline;
use std::mem::size_of;

/// Retains the original publication slot, cut and failure through partial I/O.
pub(crate) struct OriginalNativeHelloPublication {
    owner: ProtocolCaptureOwner,
    started: bool,
    complete: bool,
    cut: Option<OperationalDeadline>,
    bank: Option<Rc<RefCell<OriginalFrameReservation>>>,
    slot: Option<usize>,
    failure: Option<ProviderError>,
}

const _: fn(&OriginalNativeHelloPublication) = |value| {
    let OriginalNativeHelloPublication {
        owner: _,
        started: _,
        complete: _,
        cut: _,
        bank: _,
        slot: _,
        failure: _,
    } = value;
};

impl OriginalNativeHelloPublication {
    /// Installs fixed destinations before the enclosing bootstrap reads inputs.
    pub(crate) fn empty_data() -> Self {
        Self {
            owner: ProtocolCaptureOwner::new(),
            started: false,
            complete: false,
            cut: None,
            bank: None,
            slot: None,
            failure: None,
        }
    }

    /// Counts the empty pre-exchange destination without assuming a journal alias.
    ///
    /// # Errors
    /// Refuses foreign custody or a publication that already started/bound a bank.
    pub(crate) fn retained_backing_before_exchange_data(&self) -> Result<usize, ProviderError> {
        self.owner.ensure_current()?;
        if self.started || self.bank.is_some() || self.failure.is_some() {
            return Err(refused());
        }
        Ok(0)
    }

    /// Counts retained failure backing beside the separately charged journal.
    ///
    /// # Errors
    /// Refuses foreign custody, a substituted bank or an owning custom I/O
    /// failure whose dynamic layout has no closed source declaration. Such a
    /// failure remains retained even when its census refuses.
    pub(crate) fn retained_backing_beside_exchange_data<S: Read + Write>(
        &self,
        exchange: &OriginalNativeHelloExchange<S>,
    ) -> Result<usize, ProviderError> {
        self.owner.ensure_current()?;
        exchange.journal.owner.ensure_current()?;
        if self
            .bank
            .as_ref()
            .is_some_and(|bank| !Rc::ptr_eq(bank, &exchange.journal.bank))
        {
            return Err(refused());
        }
        match self.failure.as_ref() {
            None
            | Some(ProviderError::Frame(_))
            | Some(ProviderError::Correlation(_))
            | Some(ProviderError::ResourceExhausted(_))
            | Some(ProviderError::Conflict(_)) => Ok(0),
            Some(ProviderError::Io(error)) if error.get_ref().is_none() => Ok(0),
            Some(_) => Err(refused()),
        }
    }

    /// Observes complete literal role digests without granting protocol validity.
    ///
    /// # Errors
    /// Refuses incomplete/refused publication, expired or substituted original
    /// custody/cut, changed bank identity or incomplete actual frame progress.
    pub(crate) fn completed_frame_digests_data<S: Read + Write>(
        &self,
        exchange: &OriginalNativeHelloExchange<S>,
        cut: OperationalDeadline,
    ) -> Result<OriginalHelloFrameDigests, ProviderError> {
        self.guard(cut)?;
        exchange.journal.owner.ensure_current()?;
        if !self.complete
            || self.failure.is_some()
            || exchange.journal.failed
            || !exchange.journal.write_started
            || self
                .bank
                .as_ref()
                .is_none_or(|bank| !Rc::ptr_eq(bank, &exchange.journal.bank))
        {
            return Err(refused());
        }
        let bank = exchange.journal.bank.try_borrow().map_err(|_| refused())?;
        let frame = bank
            .frame(self.slot.ok_or_else(refused)?)
            .ok_or_else(refused)?;
        if frame.direction != FrameDirection::Outgoing
            || !frame.complete
            || frame.transferred != frame.bytes.len()
        {
            return Err(refused());
        }
        crate::hello_frames::original_hello_frame_digests(
            &bank,
            crate::connection::EndpointRole::Provider,
        )
    }

    /// Names completed raw-pair inspection beside this actual publication owner.
    pub(crate) fn completed_frame_digests_counter_scratch_data<S: Read + Write>() -> usize {
        Self::counter_scratch_data::<S>()
            + crate::hello_frames::original_hello_frame_digests_counter_scratch_data()
            + size_of::<crate::hello_frames::OriginalHelloFrameDigests>()
            + size_of::<Result<crate::hello_frames::OriginalHelloFrameDigests, ProviderError>>()
    }

    /// Prices byte publication into an already reserved journal and actual stream.
    ///
    /// The caller separately prices its prepared body, stream implementation
    /// work/backing, fixed containing root and whole-owner guards. No encoding
    /// or new byte bank is constructed.
    /// This zero-heap row applies to source streams with non-owning I/O errors;
    /// arbitrary custom error backing requires a separate source declaration.
    pub(crate) fn construction_data<S: Read + Write>() -> [usize; 3] {
        [
            0,
            size_of::<Self>() + size_of::<ProviderError>(),
            Self::counter_scratch_data::<S>(),
        ]
    }

    /// Names actual literal checks, slot operations and sequential write controls.
    pub(crate) fn counter_scratch_data<S: Read + Write>() -> usize {
        OriginalNativeHelloLiteral::counter_scratch_data()
            + size_of::<&Self>() * 2
            + size_of::<&mut Self>() * 2
            + size_of::<&mut OriginalNativeHelloExchange<S>>() * 2
            + size_of::<&OriginalNativeHelloExchange<S>>() * 2
            + size_of::<&OriginalNativeHelloLiteral>()
            + size_of::<OperationalDeadline>() * 3
            + size_of::<Option<OperationalDeadline>>()
            + size_of::<Option<usize>>() * 2
            + size_of::<usize>() * 5
            + size_of::<u32>()
            + size_of::<[u8; 4]>()
            + size_of::<&[u8]>() * 4
            + size_of::<std::cell::RefMut<'static, OriginalFrameReservation>>()
            + size_of::<
                Result<
                    std::cell::RefMut<'static, OriginalFrameReservation>,
                    std::cell::BorrowMutError,
                >,
            >()
            + size_of::<std::cell::Ref<'static, OriginalFrameReservation>>()
            + size_of::<
                Result<std::cell::Ref<'static, OriginalFrameReservation>, std::cell::BorrowError>,
            >()
            + size_of::<crate::transport::original_frames::OriginalFrame<'static>>()
            + size_of::<Option<crate::transport::original_frames::OriginalFrame<'static>>>()
            + size_of::<Result<usize, ProviderError>>() * 2
            + size_of::<Result<usize, io::Error>>()
            + size_of::<Result<(), ProviderError>>() * 5
            + size_of::<ProviderError>()
            + size_of::<Option<ProviderError>>()
            + size_of::<io::Error>()
            + size_of::<io::ErrorKind>()
            + size_of::<Rc<RefCell<OriginalFrameReservation>>>()
    }

    fn guard(&self, cut: OperationalDeadline) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if !self.started || self.cut != Some(cut) || cut.is_expired() {
            return Err(refused());
        }
        Ok(())
    }
}

impl<S: Read + Write> OriginalNativeHelloExchange<S> {
    /// Publishes prepared bytes once while retaining every original I/O outcome.
    ///
    /// The enclosing owner must independently admit and authenticate the complete
    /// body and all work before invoking this primitive. It copies the proposal
    /// into the existing bank before any write and never parses incoming bytes
    /// or marks the request as parsed. The original stream/cut are never renewed.
    ///
    /// # Errors
    /// Refuses re-entry, stale custody/cut, incomplete or substituted literal,
    /// invalid extent, exhausted reservation or partial/zero/error I/O. The first
    /// failure and all original proposal/progress remain retained, with no retry.
    pub(crate) fn publish_literal_response_data(
        &mut self,
        literal: &OriginalNativeHelloLiteral,
        body: &[u8],
        publication: &mut OriginalNativeHelloPublication,
        cut: OperationalDeadline,
    ) -> Result<(), ProviderError> {
        publication.owner.ensure_current()?;
        if publication.started {
            return Err(refused());
        }
        publication.started = true;
        publication.cut = Some(cut);
        let outcome = self.publish_current_literal_response(literal, body, publication, cut);
        if let Err(error) = outcome {
            publication.failure = Some(error);
            self.journal.failed = true;
            return Err(refused());
        }
        publication.complete = true;
        Ok(())
    }

    fn publish_current_literal_response(
        &mut self,
        literal: &OriginalNativeHelloLiteral,
        body: &[u8],
        publication: &mut OriginalNativeHelloPublication,
        cut: OperationalDeadline,
    ) -> Result<(), ProviderError> {
        publication.guard(cut)?;
        self.journal.owner.ensure_current()?;
        if self.journal.failed || self.journal.write_started {
            return Err(refused());
        }
        self.journal.write_started = true;
        literal.body_data(self)?;
        if body.is_empty() || body.len() > self.journal.maximum_bytes {
            return Err(refused());
        }
        let length = u32::try_from(body.len()).map_err(|_| refused())?;
        let total = body.len().checked_add(4).ok_or_else(refused)?;
        publication.bank = Some(Rc::clone(&self.journal.bank));
        let mut bank = self.journal.bank.try_borrow_mut().map_err(|_| refused())?;
        let slot = bank.begin(FrameDirection::Outgoing, total)?;
        publication.slot = Some(slot);
        bank.append(slot, &length.to_be_bytes())?;
        bank.append(slot, body)?;

        let mut transferred = 0;
        while transferred < total {
            publication.guard(cut)?;
            self.journal.owner.ensure_current()?;
            let frame = bank.frame(slot).ok_or_else(refused)?;
            let written = match self.reader.stream_mut().write(&frame.bytes[transferred..]) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            if written == 0 || written > total - transferred {
                return Err(io::Error::from(io::ErrorKind::WriteZero).into());
            }
            bank.advance(slot, written)?;
            transferred += written;
        }
        bank.finish(slot)?;
        publication.guard(cut)?;
        self.journal.owner.ensure_current()
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original Hello literal publication refused")
}

#[cfg(all(test, unix))]
#[path = "literal_publication_tests.rs"]
mod tests;
