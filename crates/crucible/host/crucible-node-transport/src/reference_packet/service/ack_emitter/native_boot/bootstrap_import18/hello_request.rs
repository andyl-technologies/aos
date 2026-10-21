//! Admits initial Hello claims and a typed offer under the original bootstrap.

use super::*;
use crate::handshake::ExtensionOfferV1;
use crate::reference_packet::service::PacketNative5SourceLaunch;

#[path = "hello_request/attempt.rs"]
mod attempt;
#[path = "hello_request/storage.rs"]
mod storage;
#[path = "hello_request/wire.rs"]
mod wire;
pub(super) use attempt::Attempt;
pub(in super::super) use wire::Claims;

/// Admits request inspection separately from strict parsing and live negotiation.
pub(in super::super) trait OriginalImport18HelloRequestAdmission {
    /// Admits fixed quote controls before inspecting the original literal.
    ///
    /// # Errors
    /// Refuses unavailable original credit or incomplete enclosing custody.
    fn quote_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        scratch: usize,
    ) -> Result<(), ProviderError>;

    /// Admits the actual stored row before any typed offer allocation.
    ///
    /// # Errors
    /// Refuses unavailable credit or incomplete whole-owner correspondence.
    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        row: [usize; 3],
    ) -> Result<(), ProviderError>;

    /// Observes surviving claims, typed output and diagnostics after either result.
    ///
    /// # Errors
    /// Refuses unavailable credit or incomplete whole-owner census.
    fn finish_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        actual_backing: usize,
    ) -> Result<(), ProviderError>;
}

impl OriginalImport18RawBootstrap {
    /// Checks initial Hello claims and retains its validated typed offer once.
    ///
    /// The request borrows the original strict tree, launch, token and feature
    /// roster. It creates no live connection, response, bootstrap ACK or model.
    ///
    /// # Errors
    /// Refuses re-entry, incomplete or stale custody, admission, malformed or
    /// foreign claims, invalid/unsupported required definitions or terminal guards.
    pub(in super::super) fn inspect_hello_request_data(
        &mut self,
        admission: &dyn OriginalImport18HelloRequestAdmission,
    ) -> Result<(), ProviderError> {
        self.hello_request.start_data()?;
        let outcome = self.inspect_current_hello_request(admission);
        let terminal = self.guard_hello_request_inputs();
        match outcome.and(terminal) {
            Ok(()) => self.hello_request.complete_data(),
            Err(error) => {
                self.hello_request.refuse_data();
                Err(error)
            }
        }
    }

    fn guard_hello_request_inputs(&self) -> Result<(), ProviderError> {
        self.with_hello_value_data(|_| Ok(()))?;
        self.with_hello_selection_data(|_| Ok(()))?;
        self.typed_bodies_data()?;
        Ok(())
    }

    fn inspect_current_hello_request(
        &mut self,
        admission: &dyn OriginalImport18HelloRequestAdmission,
    ) -> Result<(), ProviderError> {
        self.admit_source_row(self.initial_construction.as_ref().ok_or_else(refused)?.row)?;
        self.guard_hello_request_inputs()?;
        admission.quote_data(self, counter_scratch_data())?;
        self.guard_hello_request_inputs()?;
        let maximum = self.bounds.requested_peak;
        let mut row =
            self.with_hello_literal_data(|raw| storage::construction_data(raw.len(), maximum))?;
        row[2] = row[2]
            .checked_add(counter_scratch_data())
            .ok_or_else(exhausted)?;
        ensure_peak_data(row, maximum)?;
        self.hello_request.quote_data(row)?;
        admission.construct_data(self, row)?;
        let outcome = self.decode_current_hello_request();
        let terminal = self
            .hello_request
            .retained_backing_data()
            .and_then(|actual| admission.finish_data(self, actual));
        outcome?;
        terminal
    }

    fn decode_current_hello_request(&mut self) -> Result<(), ProviderError> {
        self.guard_hello_request_inputs()?;
        let cut = self.cut;
        let Self {
            parsed,
            hello_selection,
            hello_value,
            hello_request,
            ..
        } = self;
        let launch = parsed.bodies_data()?.launch.launch_data();
        let outcome = hello_request.inspect_data(
            hello_value.value_data()?,
            launch,
            hello_selection.as_ref().ok_or_else(refused)?,
            cut,
        );
        let terminal = self.guard_hello_request_inputs();
        outcome?;
        terminal
    }

    /// Lends retained request DATA while all original input guards hold.
    ///
    /// The caller admits its inspection independently; only Copy DATA returns.
    ///
    /// # Errors
    /// Refuses incomplete/refused inspection, stale custody, callback or terminal guards.
    pub(in super::super) fn with_hello_request_data<R: Copy>(
        &self,
        inspect: impl FnOnce(Claims, &ExtensionOfferV1) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.guard_hello_request_inputs()?;
        let (claims, offer) = self.hello_request.data()?;
        let outcome = inspect(claims, offer);
        let terminal = self
            .guard_hello_request_inputs()
            .and_then(|()| self.hello_request.data().map(|_| ()));
        let output = outcome?;
        terminal?;
        Ok(output)
    }
}

/// Prices the same request constructor for every bounded future original body.
///
/// # Errors
/// Refuses invalid framing, overflow or a row above the independent restriction.
pub(in crate::reference_packet::service) fn construction_bound_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    let bytes = usize::try_from(launch.limits.frame_bytes.get()).map_err(|_| exhausted())?;
    let mut row = storage::construction_data(bytes, maximum)?;
    row[2] = row[2]
        .checked_add(counter_scratch_data())
        .ok_or_else(exhausted)?;
    ensure_peak_data(row, maximum)?;
    Ok(row)
}

fn ensure_peak_data(row: [usize; 3], maximum: usize) -> Result<(), ProviderError> {
    let peak = row.into_iter().try_fold(0usize, |sum, axis| {
        sum.checked_add(axis).ok_or_else(exhausted)
    })?;
    if peak > maximum {
        return Err(exhausted());
    }
    Ok(())
}

/// Names real request, quote, original-input loan and admission controls.
pub(in crate::reference_packet::service) fn counter_scratch_data() -> usize {
    Attempt::counter_scratch_data()
        + OriginalImport18RawBootstrap::hello_value_loan_counter_scratch_data::<()>()
        + OriginalImport18RawBootstrap::hello_selection_loan_counter_scratch_data::<()>()
        + size_of::<&dyn OriginalImport18HelloRequestAdmission>()
        + size_of::<&OriginalImport18RawBootstrap>()
        + size_of::<&mut OriginalImport18RawBootstrap>()
        + size_of::<Result<(), ProviderError>>() * 5
        + size_of::<[usize; 3]>()
        + size_of::<std::array::IntoIter<usize, 3>>()
        + size_of::<usize>() * 5
}
