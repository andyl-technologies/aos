//! Constructs actual response DATA from the original SDK Hello owners.
//!
//! Physical output slots precede private receipt. Quote and constructor work
//! require separate original admission; complete typed output survives terminal
//! refusal. This transition supplies response DATA without connection admission
//! or publication.

use super::*;
use crate::envelope::Envelope;
use crate::reference_packet::service::PacketNative5SourceLaunch;

#[path = "hello_response/attempt.rs"]
mod attempt;
#[path = "hello_response/projection.rs"]
mod projection;
#[path = "hello_response/serialize_controls.rs"]
mod serialize_controls;
pub(super) use serialize_controls::{
    initial_request_comparison_depth_data, initial_result_comparison_depth_data,
};
#[path = "hello_response/storage.rs"]
mod storage;
pub(super) use attempt::Attempt;

/// Separately admits quote, actual typed construction and surviving ownership.
pub(in super::super) trait OriginalImport18HelloResponseAdmission {
    /// Admits quote controls under the same original bootstrap custody.
    ///
    /// # Errors
    /// Refuses missing original credit or incomplete enclosing correspondence.
    fn quote_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        scratch: usize,
    ) -> Result<(), ProviderError>;

    /// Admits the stored row before the actual SDK response serializer allocates.
    ///
    /// # Errors
    /// Refuses short original credit or incomplete whole-owner demand.
    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        row: [usize; 3],
    ) -> Result<(), ProviderError>;

    /// Observes every surviving constructor output after either outcome.
    ///
    /// # Errors
    /// Refuses incomplete original census or demand beyond original credit.
    fn finish_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        actual_backing: usize,
    ) -> Result<(), ProviderError>;
}

impl OriginalImport18RawBootstrap {
    /// Constructs the actual response after the complete original request/result.
    ///
    /// # Errors
    /// Refuses re-entry, original custody/cut, admission, serialization,
    /// original correspondence or any terminal guard/census.
    pub(in super::super) fn construct_hello_response_data(
        &mut self,
        admission: &dyn OriginalImport18HelloResponseAdmission,
    ) -> Result<(), ProviderError> {
        self.hello_response.start_data(self.cut)?;
        let outcome = self.construct_current_hello_response(admission);
        let terminal = self.guard_hello_response_inputs();
        match outcome.and(terminal) {
            Ok(()) => self.hello_response.complete_data(),
            Err(error) => {
                self.hello_response.refuse_data();
                Err(error)
            }
        }
    }

    fn guard_hello_response_inputs(&self) -> Result<(), ProviderError> {
        self.with_hello_envelope_data(|_| Ok(()))?;
        Ok(())
    }

    fn construct_current_hello_response(
        &mut self,
        admission: &dyn OriginalImport18HelloResponseAdmission,
    ) -> Result<(), ProviderError> {
        self.admit_source_row(self.initial_construction.as_ref().ok_or_else(refused)?.row)?;
        self.guard_hello_response_inputs()?;
        admission.quote_data(self, counter_scratch_data())?;
        self.guard_hello_response_inputs()?;
        let row = construction_data(
            self.typed_bodies_data()?.launch.launch_data(),
            self.bounds.requested_peak,
        )?;
        self.hello_response.quote_data(row)?;
        admission.construct_data(self, row)?;
        let outcome = self.construct_guarded_hello_response();
        let terminal = self
            .hello_response
            .retained_backing_data()
            .and_then(|actual| admission.finish_data(self, actual));
        outcome?;
        terminal
    }

    fn construct_guarded_hello_response(&mut self) -> Result<(), ProviderError> {
        self.guard_hello_response_inputs()?;
        let cut = self.cut;
        let Self {
            hello_envelope,
            hello_result,
            hello_response,
            ..
        } = self;
        let outcome =
            hello_response.construct_data(hello_envelope.data(cut)?, hello_result.data(cut)?, cut);
        let terminal = self.guard_hello_response_inputs();
        outcome?;
        terminal
    }

    /// Lends the actual response envelope while original body and custody match.
    ///
    /// The caller independently admits callback work. Copy output cannot move
    /// an envelope allocation out of this original retained owner.
    ///
    /// # Errors
    /// Refuses incomplete/refused construction, stale/substituted cuts, changed
    /// original inputs, callback errors or either terminal custody guard.
    pub(in super::super) fn with_hello_response_data<R: Copy>(
        &self,
        inspect: impl FnOnce(&Envelope) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.guard_hello_response_inputs()?;
        let outcome = inspect(self.hello_response.data(self.cut)?);
        let terminal = self
            .guard_hello_response_inputs()
            .and_then(|()| self.hello_response.data(self.cut).map(|_| ()));
        let output = outcome?;
        terminal?;
        Ok(output)
    }

    /// Names completed response custody and its original request/result loans.
    pub(in super::super) fn hello_response_loan_counter_scratch_data<R: Copy>() -> usize {
        Self::hello_envelope_loan_counter_scratch_data::<()>()
            + Attempt::counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&Envelope>()
            + size_of::<&serde_json::Value>()
            + size_of::<R>() * 2
            + size_of::<Result<R, ProviderError>>() * 2
            + size_of::<Result<(), ProviderError>>() * 3
    }
}

/// Quotes actual response construction before the future original request ID.
///
/// # Errors
/// Refuses invalid declarations, unsupported geometry, overflow or short credit.
pub(in crate::reference_packet::service) fn construction_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    let mut row = storage::construction_data(launch, maximum)?;
    row[2] = row[2]
        .checked_add(counter_scratch_data())
        .ok_or_else(refused)?;
    ensure_peak_data(row, maximum)?;
    Ok(row)
}

/// Names actual serializer, original guard/loan, admission and census controls.
pub(in crate::reference_packet::service) fn counter_scratch_data() -> usize {
    storage::counter_scratch_data()
        + Attempt::counter_scratch_data()
        + OriginalImport18RawBootstrap::hello_envelope_loan_counter_scratch_data::<()>()
        + size_of::<&dyn OriginalImport18HelloResponseAdmission>()
        + size_of::<&OriginalImport18RawBootstrap>()
        + size_of::<&mut OriginalImport18RawBootstrap>()
        + size_of::<&Envelope>() * 2
        + size_of::<&crate::handshake::HelloResult>()
        + size_of::<OperationalDeadline>()
        + size_of::<&serde_json::Value>()
        + size_of::<[usize; 3]>() * 2
        + size_of::<std::array::IntoIter<usize, 3>>()
        + size_of::<Result<(), ProviderError>>() * 6
        + size_of::<Result<usize, ProviderError>>() * 2
        + size_of::<usize>() * 4
}

fn ensure_peak_data(row: [usize; 3], maximum: usize) -> Result<(), ProviderError> {
    let peak = row.into_iter().try_fold(0usize, |sum, axis| {
        sum.checked_add(axis).ok_or_else(refused)
    })?;
    if peak > maximum {
        return Err(refused());
    }
    Ok(())
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original import18 Hello response admission refused")
}
