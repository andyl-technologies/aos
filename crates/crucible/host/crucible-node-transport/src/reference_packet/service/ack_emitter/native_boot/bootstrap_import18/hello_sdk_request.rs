//! Constructs the actual SDK request from the same checked initial Hello tree.
//!
//! Physical output slots precede private receipt. Quote and constructor work
//! require separate original admission; complete typed output survives terminal
//! refusal. No temporary canonical input, second JSON parse or connection grant
//! is introduced by this transition.

use super::*;
use crate::handshake::HelloRequest;
use crate::reference_packet::service::PacketNative5SourceLaunch;

#[path = "hello_sdk_request/attempt.rs"]
mod attempt;
#[path = "hello_sdk_request/storage.rs"]
mod storage;
pub(super) use attempt::Attempt;

/// Separately admits quote, actual typed construction and surviving ownership.
pub(in super::super) trait OriginalImport18SdkHelloRequestAdmission {
    /// Admits quote controls under the same original bootstrap custody.
    ///
    /// # Errors
    /// Refuses missing original credit or incomplete enclosing correspondence.
    fn quote_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        scratch: usize,
    ) -> Result<(), ProviderError>;

    /// Admits the stored row before the actual SDK request decoder allocates.
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
    /// Constructs the real SDK request once after claims and registrar checks.
    ///
    /// # Errors
    /// Refuses re-entry, original custody/cut, admission, typed decoding,
    /// exact original correspondence or any terminal guard/census.
    pub(in super::super) fn construct_sdk_hello_request_data(
        &mut self,
        admission: &dyn OriginalImport18SdkHelloRequestAdmission,
    ) -> Result<(), ProviderError> {
        self.hello_sdk_request.start_data(self.cut)?;
        let outcome = self.construct_current_sdk_hello_request(admission);
        let terminal = self.guard_sdk_hello_request_inputs();
        match outcome.and(terminal) {
            Ok(()) => self.hello_sdk_request.complete_data(),
            Err(error) => {
                self.hello_sdk_request.refuse_data();
                Err(error)
            }
        }
    }

    fn guard_sdk_hello_request_inputs(&self) -> Result<(), ProviderError> {
        self.with_hello_registrar_data(|_| Ok(()))?;
        Ok(())
    }

    fn construct_current_sdk_hello_request(
        &mut self,
        admission: &dyn OriginalImport18SdkHelloRequestAdmission,
    ) -> Result<(), ProviderError> {
        self.admit_source_row(self.initial_construction.as_ref().ok_or_else(refused)?.row)?;
        self.guard_sdk_hello_request_inputs()?;
        admission.quote_data(self, counter_scratch_data())?;
        self.guard_sdk_hello_request_inputs()?;
        let mut row = self.with_hello_literal_data(|raw| {
            storage::construction_data(raw.len(), self.bounds.requested_peak)
        })?;
        row[2] = row[2]
            .checked_add(counter_scratch_data())
            .ok_or_else(refused)?;
        ensure_peak_data(row, self.bounds.requested_peak)?;
        self.hello_sdk_request.quote_data(row)?;
        admission.construct_data(self, row)?;
        let outcome = self.decode_current_sdk_hello_request();
        let terminal = self
            .hello_sdk_request
            .retained_backing_data()
            .and_then(|actual| admission.finish_data(self, actual));
        outcome?;
        terminal
    }

    fn decode_current_sdk_hello_request(&mut self) -> Result<(), ProviderError> {
        self.guard_sdk_hello_request_inputs()?;
        let claims = self.with_hello_request_data(|claims, _| Ok(claims))?;
        let outcome = self.hello_sdk_request.construct_data(
            self.hello_value.value_data()?,
            claims,
            self.parsed
                .bodies_data()?
                .launch
                .launch_data()
                .admission_token
                .as_slice(),
            self.cut,
        );
        let terminal = self.guard_sdk_hello_request_inputs();
        outcome?;
        terminal
    }

    /// Lends the actual typed request while original body and custody match.
    ///
    /// The caller independently admits callback work. Copy output cannot move
    /// a request allocation out of this original retained owner.
    ///
    /// # Errors
    /// Refuses incomplete/refused construction, stale/substituted cuts, changed
    /// body/claims, callback errors or either terminal correspondence guard.
    pub(in super::super) fn with_sdk_hello_request_data<R: Copy>(
        &self,
        inspect: impl FnOnce(&HelloRequest) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.guard_sdk_hello_request_inputs()?;
        let claims = self.with_hello_request_data(|claims, _| Ok(claims))?;
        let value = self.hello_value.value_data()?;
        let token = self
            .typed_bodies_data()?
            .launch
            .launch_data()
            .admission_token
            .as_slice();
        self.hello_sdk_request
            .authenticate_data(value, claims, token, self.cut)?;
        let outcome = inspect(self.hello_sdk_request.data(self.cut)?);
        let terminal = self.guard_sdk_hello_request_inputs().and_then(|()| {
            self.hello_sdk_request
                .authenticate_data(value, claims, token, self.cut)
        });
        let output = outcome?;
        terminal?;
        Ok(output)
    }
}

/// Quotes the same typed construction for every bounded future original body.
///
/// # Errors
/// Refuses invalid framing, checked overflow or the independent full restriction.
pub(in crate::reference_packet::service) fn construction_bound_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    let bytes = usize::try_from(launch.limits.frame_bytes.get()).map_err(|_| refused())?;
    let mut row = storage::construction_data(bytes, maximum)?;
    row[2] = row[2]
        .checked_add(counter_scratch_data())
        .ok_or_else(refused)?;
    ensure_peak_data(row, maximum)?;
    Ok(row)
}

/// Names actual decoder, original guard/loan, admission and census controls.
pub(in crate::reference_packet::service) fn counter_scratch_data() -> usize {
    storage::counter_scratch_data()
        + Attempt::counter_scratch_data()
        + OriginalImport18RawBootstrap::hello_registrar_loan_counter_scratch_data::<()>()
        + size_of::<&dyn OriginalImport18SdkHelloRequestAdmission>()
        + size_of::<&OriginalImport18RawBootstrap>()
        + size_of::<&mut OriginalImport18RawBootstrap>()
        + size_of::<super::hello_request::Claims>() * 2
        + size_of::<&HelloRequest>() * 2
        + size_of::<&serde_json::Value>()
        + size_of::<&[u8]>() * 2
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
    ProviderError::Correlation("original import18 SDK Hello request admission refused")
}
