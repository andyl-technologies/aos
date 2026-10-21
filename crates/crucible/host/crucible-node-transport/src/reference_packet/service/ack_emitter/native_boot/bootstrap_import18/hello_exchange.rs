//! Moves original journal and public channel into one retained framing exchange.

use super::*;
use crate::client::OriginalNativePublicBirthChannel;
use crate::native_hello::{OriginalNativeHelloExchange, RetainedOriginalNativeHelloExchange};

type Exchange = RetainedOriginalNativeHelloExchange<OriginalNativePublicBirthChannel>;

/// Admits the original framing constructor without protocol effects.
pub(in super::super) trait OriginalImport18HelloExchangeAdmission {
    /// Admits fresh binding work while original stream/bank backing stays charged.
    ///
    /// # Errors
    /// Refuses unavailable original credit or incomplete enclosing custody.
    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        row: [usize; 3],
    ) -> Result<(), ProviderError>;

    /// Observes actual framing and moved stream backing in the same whole owner.
    ///
    /// # Errors
    /// Refuses unavailable credit or incomplete whole-owner observation.
    fn finish_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        actual_backing: usize,
    ) -> Result<(), ProviderError>;
}

impl OriginalImport18RawBootstrap {
    /// Binds the same actual public channel and journal under original custody once.
    ///
    /// Original stream/cut backing moves into the exchange and remains charged.
    /// The literal reservation keeps its same bank; aliases are independently
    /// checked by the census. No Hello is received, published or negotiated.
    ///
    /// # Errors
    /// Refuses re-entry, incomplete prior work, expired/changed custody,
    /// unavailable admission, framing failure or terminal correspondence.
    pub(in super::super) fn construct_hello_exchange_data(
        &mut self,
        admission: &dyn OriginalImport18HelloExchangeAdmission,
    ) -> Result<(), ProviderError> {
        if self.hello_exchange_started {
            return Err(refused());
        }
        self.hello_exchange_started = true;
        let outcome = self.construct_current_hello_exchange(admission);
        let terminal = self.typed_bodies_data().map(|_| ());
        outcome?;
        terminal?;
        self.hello_exchange_complete = true;
        Ok(())
    }

    fn construct_current_hello_exchange(
        &mut self,
        admission: &dyn OriginalImport18HelloExchangeAdmission,
    ) -> Result<(), ProviderError> {
        if !self.initial_reconstructed
            || !self.selection_authenticated
            || !self.hello_complete
            || !self.hello_frames_complete
            || !self.public_channel_complete
        {
            return Err(refused());
        }
        self.authenticate_public_channel_data()?;
        self.admit_source_row(self.initial_construction.as_ref().ok_or_else(refused)?.row)?;
        let row = construction_data();
        self.hello_exchange_row = Some(row);
        admission.construct_data(self, row)?;
        let outcome = self.bind_current_hello_exchange();
        let terminal = self
            .hello_exchange_backing_data()
            .and_then(|actual| admission.finish_data(self, actual));
        outcome?;
        terminal
    }

    fn bind_current_hello_exchange(&mut self) -> Result<(), ProviderError> {
        self.authenticate_public_channel_data()?;
        Exchange::bind_into_data(
            self.hello_frames.as_mut().ok_or_else(refused)?,
            &mut self.public_channel,
            &mut self.hello_exchange,
        )?;
        self.hello_exchange
            .as_ref()
            .ok_or_else(refused)?
            .with_exchange_data(|exchange| exchange.original_stream_data().completed_data(self.cut))
    }

    /// Lends the same completed exchange with physical and typed terminal guards.
    ///
    /// Callers separately admit their inspection. Only Copy DATA may return.
    ///
    /// # Errors
    /// Refuses incomplete construction, stale original custody, callback failure
    /// or any changed terminal physical/typed guard, including callback refusal.
    pub(in super::super) fn with_hello_exchange_data<R: Copy>(
        &self,
        inspect: impl FnOnce(
            &OriginalNativeHelloExchange<OriginalNativePublicBirthChannel>,
        ) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        if !self.hello_exchange_complete {
            return Err(refused());
        }
        self.typed_bodies_data()?;
        let outcome = self
            .hello_exchange
            .as_ref()
            .ok_or_else(refused)?
            .with_exchange_data(|exchange| {
                exchange.original_stream_data().completed_data(self.cut)?;
                let result = inspect(exchange);
                let terminal = exchange.original_stream_data().completed_data(self.cut);
                let result = result?;
                terminal?;
                Ok(result)
            });
        let terminal = self.typed_bodies_data().map(|_| ());
        let result = outcome?;
        terminal?;
        Ok(result)
    }

    /// Counts actual exchange and moved cut backing beside the original bank census.
    ///
    /// # Errors
    /// Refuses missing reservation, stale creator, borrowed banks or overflow.
    pub(super) fn hello_exchange_backing_data(&self) -> Result<usize, ProviderError> {
        self.hello_exchange.as_ref().map_or(Ok(0), |exchange| {
            exchange.retained_backing_beside_reservation_data(
                self.hello_frames.as_ref().ok_or_else(refused)?,
                self.hello_literal
                    .as_ref()
                    .map(|literal| literal.original_bank_data())
                    .transpose()?
                    .flatten(),
                OriginalNativePublicBirthChannel::retained_backing_data,
            )
        })
    }

    /// Names a separate future exchange loan and its actual Copy output controls.
    pub(in super::super) fn hello_exchange_loan_counter_scratch_data<R: Copy>() -> usize {
        Exchange::exchange_loan_counter_scratch_data::<R>()
            + counter_scratch_data()
            + private_body_owner_counter_scratch_data()
            + native_import18_private_prefix_counter_scratch_data()
    }
}

/// Quotes fresh framing work while existing original stream/bank backing remains charged.
pub(in crate::reference_packet::service) fn construction_data() -> [usize; 3] {
    let mut row = Exchange::construction_data();
    row[2] += counter_scratch_data();
    row
}

/// Names actual constructor, original-cut correspondence and census controls.
pub(in crate::reference_packet::service) fn counter_scratch_data() -> usize {
    Exchange::counter_scratch_data()
        + size_of::<&OriginalImport18RawBootstrap>()
        + size_of::<&mut OriginalImport18RawBootstrap>()
        + size_of::<&dyn OriginalImport18HelloExchangeAdmission>()
        + size_of::<&OriginalNativeHelloExchange<OriginalNativePublicBirthChannel>>()
        + size_of::<&Exchange>()
        + size_of::<Option<&Exchange>>()
        + size_of::<[usize; 3]>()
        + size_of::<usize>()
        + size_of::<Result<(), ProviderError>>() * 4
}
