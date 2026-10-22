//! Encodes and publishes the actual admitted original Hello under bootstrap custody.
//!
//! Separate quote, effect construction and surviving-census admissions precede
//! their work. A failed terminal guard contains the actual retained SDK lease;
//! response bytes and original journal progress remain in their physical owners.

use super::*;
use crate::client::OriginalNativePublicBirthChannel;
use crate::native_hello::OriginalNativeHelloExchange;
use crate::reference_packet::service::PacketNative5SourceLaunch;

#[path = "hello_publication/attempt.rs"]
mod attempt;
#[path = "hello_publication/storage.rs"]
mod storage;
pub(super) use attempt::Attempt;
use storage::Quote;

/// Admits encoding, publication and surviving custody under genuine funding.
pub(in super::super) trait OriginalImport18HelloPublicationAdmission {
    /// Admits the complete pure quote and its original custody guards.
    ///
    /// # Errors
    /// Refuses unavailable credit or incomplete original enclosing correspondence.
    fn quote_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        scratch: usize,
    ) -> Result<(), ProviderError>;

    /// Admits full construction and the public response effect before either.
    ///
    /// # Errors
    /// Refuses short original credit or missing enclosing publication permission.
    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        row: [usize; 3],
    ) -> Result<(), ProviderError>;

    /// Observes the retained encoded body, diagnostic and original publication.
    ///
    /// # Errors
    /// Refuses incomplete whole-owner census or unavailable original credit.
    fn finish_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        actual_backing: usize,
    ) -> Result<(), ProviderError>;
}

impl OriginalImport18RawBootstrap {
    /// Encodes and publishes the actual SDK-admitted original response once.
    ///
    /// The enclosing producer must supply genuine Source/Birth funding and
    /// publication permission. This transition creates no native policy, model,
    /// opaque Initial/Recipe, bootstrap ACK or readiness grant.
    ///
    /// # Errors
    /// Refuses retry, missing original lease/inputs, credit, encoding, publication,
    /// changed custody/cut or terminal census. Refusal contains the actual lease
    /// while retaining every original owner and all physical output progress.
    pub(in super::super) fn publish_hello_response_data(
        &mut self,
        admission: &dyn OriginalImport18HelloPublicationAdmission,
    ) -> Result<(), ProviderError> {
        self.hello_publication.start_data(self.cut)?;

        let outcome = self.publish_current_hello(admission);
        let terminal = self.guard_hello_publication_inputs();
        let completed = outcome
            .and(terminal)
            .and_then(|()| self.hello_publication.complete_data(self.cut));

        if let Err(error) = completed {
            self.hello_publication.refuse_data();
            let _ = self.hello_registrar.contain_admission_data();
            return Err(error);
        }

        Ok(())
    }

    fn guard_hello_publication_inputs(&self) -> Result<(), ProviderError> {
        self.with_hello_authority_data(|_| Ok(()))
    }

    fn publish_current_hello(
        &mut self,
        admission: &dyn OriginalImport18HelloPublicationAdmission,
    ) -> Result<(), ProviderError> {
        self.admit_source_row(self.initial_construction.as_ref().ok_or_else(refused)?.row)?;
        self.guard_hello_publication_inputs()?;
        admission.quote_data(self, counter_scratch_data())?;
        self.guard_hello_publication_inputs()?;

        let quote = storage::quote_data(
            self.typed_bodies_data()?.launch.launch_data(),
            self.bounds.requested_peak,
        )?;
        self.hello_publication.quote_data(quote, self.cut)?;
        admission.construct_data(self, quote.row)?;

        let outcome = self.encode_and_publish_current_hello();
        let terminal = self.guard_hello_publication_inputs();
        let census = self
            .hello_publication_backing_data()
            .and_then(|actual| admission.finish_data(self, actual));

        outcome?;
        terminal?;
        census
    }

    fn encode_and_publish_current_hello(&mut self) -> Result<(), ProviderError> {
        self.guard_hello_publication_inputs()?;
        let cut = self.cut;
        let Self {
            hello_response,
            hello_publication,
            ..
        } = self;
        hello_publication.encode_data(hello_response.data(cut)?, cut)?;

        // Complete encoding and another original lease/input guard precede the
        // first public byte. A failed encoding never consumes a journal slot.
        self.guard_hello_publication_inputs()?;
        let Self {
            hello_publication,
            hello_exchange,
            hello_literal,
            ..
        } = self;
        hello_publication.publish_data(
            hello_exchange.as_mut().ok_or_else(refused)?,
            hello_literal.as_ref().ok_or_else(refused)?,
            cut,
        )
    }

    /// Counts all surviving publication/encoding backing even after refusal.
    ///
    /// # Errors
    /// Refuses foreign custody, missing original journal association, unavailable
    /// exchange inspection, unknown custom I/O layout or checked overflow.
    pub(super) fn hello_publication_backing_data(&self) -> Result<usize, ProviderError> {
        match &self.hello_exchange {
            Some(exchange) => exchange.with_exchange_data(|exchange| {
                self.hello_publication.retained_backing_data(Some(exchange))
            }),
            None => self
                .hello_publication
                .retained_backing_data::<OriginalNativePublicBirthChannel>(None),
        }
    }

    /// Names completed body-loan controls beside independently admitted callbacks.
    ///
    /// # Errors
    /// Refuses checked overflow for the caller's concrete Copy result layout.
    pub(in super::super) fn published_hello_body_loan_counter_scratch_data<R: Copy>()
    -> Result<usize, ProviderError> {
        let fixed = Self::hello_authority_loan_counter_scratch_data::<()>()
            + Attempt::counter_scratch_data::<OriginalNativePublicBirthChannel>()
            + size_of::<&Self>() * 2
            + size_of::<&[u8]>() * 2
            + size_of::<Result<(), ProviderError>>() * 3;
        fixed
            .checked_add(size_of::<R>())
            .and_then(|n| n.checked_add(size_of::<R>()))
            .and_then(|n| n.checked_add(size_of::<Result<R, ProviderError>>()))
            .and_then(|n| n.checked_add(size_of::<Result<R, ProviderError>>()))
            .ok_or_else(refused)
    }

    /// Lends completed proposal DATA under the same original SDK lease and cut.
    ///
    /// The caller separately admits inspection work. Only Copy DATA returns;
    /// this loan cannot move response backing, a registration lease or a socket.
    ///
    /// # Errors
    /// Refuses incomplete/refused publication, stale original custody, callback
    /// failure or any terminal input, live-lease and completed-body guard.
    pub(in super::super) fn with_published_hello_body_data<R: Copy>(
        &self,
        inspect: impl FnOnce(&[u8]) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.guard_hello_publication_inputs()?;
        let outcome = inspect(self.hello_publication.body_data(self.cut)?);
        let terminal = self
            .guard_hello_publication_inputs()
            .and_then(|()| self.hello_publication.body_data(self.cut).map(|_| ()));
        let result = outcome?;
        terminal?;
        Ok(result)
    }
}

/// Quotes complete original encoding/publication without constructing output.
///
/// # Errors
/// Refuses unsupported geometry, declarations, overflow or short complete peak.
pub(in crate::reference_packet::service) fn construction_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    storage::quote_data(launch, maximum).map(|quote| quote.row)
}

/// Names pure quote, original guarded loans and sequential complete constructor.
pub(in crate::reference_packet::service) fn counter_scratch_data() -> usize {
    // Original guards, quote/encoding and publication execute sequentially.
    // Fixed outer operands below coexist with whichever window is active.
    storage::counter_scratch_data()
        .max(OriginalImport18RawBootstrap::hello_authority_loan_counter_scratch_data::<()>())
        + size_of::<&OriginalImport18RawBootstrap>() * 2
        + size_of::<&mut OriginalImport18RawBootstrap>() * 2
        + size_of::<&dyn OriginalImport18HelloPublicationAdmission>()
        + size_of::<Quote>() * 2
        + size_of::<Result<Quote, ProviderError>>()
        + size_of::<OperationalDeadline>() * 2
        + size_of::<Result<(), ProviderError>>() * 6
        + size_of::<Result<usize, ProviderError>>() * 2
        + size_of::<&OriginalNativeHelloExchange<OriginalNativePublicBirthChannel>>()
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original import18 Hello publication refused")
}
