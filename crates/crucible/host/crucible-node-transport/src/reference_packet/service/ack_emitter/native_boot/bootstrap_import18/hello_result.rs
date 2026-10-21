//! Constructs the actual initial SDK Hello result under original bootstrap custody.
//!
//! A fresh kernel challenge and complete original provider manifest remain in
//! physical slots after either terminal outcome. Separate original admissions
//! fund quote, constructor and census work. This DATA transition does not admit
//! an SDK connection, publish a reply, acknowledge bootstrap or adopt a model.

use super::*;
use crate::handshake::HelloResult;
use crate::reference_packet::service::PacketNative5SourceLaunch;

#[path = "hello_result/attempt.rs"]
mod attempt;
#[path = "hello_result/storage.rs"]
mod storage;
pub(super) use attempt::Attempt;

/// Separately admits result quoting, construction and surviving ownership.
pub(in super::super) trait OriginalImport18HelloResultAdmission {
    /// Admits quote controls under the same original bootstrap custody.
    ///
    /// # Errors
    /// Refuses unavailable original credit or incomplete input correspondence.
    fn quote_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        scratch: usize,
    ) -> Result<(), ProviderError>;

    /// Admits the stored row before kernel entropy or field allocation.
    ///
    /// # Errors
    /// Refuses insufficient original credit or incomplete whole-owner demand.
    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        row: [usize; 3],
    ) -> Result<(), ProviderError>;

    /// Observes surviving fixed entropy and complete result ownership.
    ///
    /// Fixed bytes already belong to the physical bootstrap header. This
    /// backing argument counts only additional actual heap allocations.
    ///
    /// # Errors
    /// Refuses incomplete census or whole-owner demand above original credit.
    fn finish_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        actual_backing: usize,
    ) -> Result<(), ProviderError>;
}

impl OriginalImport18RawBootstrap {
    /// Constructs the actual result once after original SDK request checks.
    ///
    /// # Errors
    /// Refuses re-entry, original custody/cut, admission, unavailable entropy,
    /// constructor failure or any terminal original guard/census.
    pub(in super::super) fn construct_hello_result_data(
        &mut self,
        admission: &dyn OriginalImport18HelloResultAdmission,
    ) -> Result<(), ProviderError> {
        self.hello_result.start_data(self.cut)?;
        let outcome = self.construct_current_hello_result(admission);
        let terminal = self.guard_hello_result_inputs();
        match outcome.and(terminal) {
            Ok(()) => self.hello_result.complete_data(),
            Err(error) => {
                self.hello_result.refuse_data();
                Err(error)
            }
        }
    }

    fn guard_hello_result_inputs(&self) -> Result<(), ProviderError> {
        self.with_sdk_hello_request_data(|_| Ok(()))?;
        Ok(())
    }

    fn construct_current_hello_result(
        &mut self,
        admission: &dyn OriginalImport18HelloResultAdmission,
    ) -> Result<(), ProviderError> {
        self.admit_source_row(self.initial_construction.as_ref().ok_or_else(refused)?.row)?;
        self.guard_hello_result_inputs()?;
        admission.quote_data(self, counter_scratch_data())?;
        self.guard_hello_result_inputs()?;
        let row = construction_data(
            self.typed_bodies_data()?.launch.launch_data(),
            self.bounds.requested_peak,
        )?;
        self.hello_result.quote_data(row)?;
        admission.construct_data(self, row)?;
        let outcome = self.construct_guarded_hello_result();
        let terminal = self
            .hello_result
            .retained_backing_data()
            .and_then(|actual| admission.finish_data(self, actual));
        outcome?;
        terminal
    }

    fn construct_guarded_hello_result(&mut self) -> Result<(), ProviderError> {
        self.guard_hello_result_inputs()?;
        let claims = self.with_hello_request_data(|claims, _| Ok(claims))?;
        let cut = self.cut;
        let Self {
            parsed,
            hello_selection,
            hello_sdk_request,
            hello_result,
            ..
        } = self;
        let outcome = hello_result.construct_data(
            parsed.bodies_data()?.launch.launch_data(),
            hello_selection.as_ref().ok_or_else(refused)?,
            hello_sdk_request.data(cut)?,
            claims.limits,
            cut,
        );
        let terminal = self.guard_hello_result_inputs();
        outcome?;
        terminal
    }

    /// Names completed result custody without repeating construction or entropy.
    pub(in super::super) fn hello_result_loan_counter_scratch_data<R: Copy>() -> usize {
        Self::sdk_hello_request_loan_counter_scratch_data::<()>()
            + Attempt::counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&HelloResult>()
            + size_of::<R>() * 2
            + size_of::<Result<R, ProviderError>>() * 2
            + size_of::<Result<(), ProviderError>>() * 3
    }

    /// Lends the same completed result while every original input guard holds.
    ///
    /// The caller independently admits callback work. Copy output cannot move
    /// result ownership or grant connection admission or publication.
    ///
    /// # Errors
    /// Refuses incomplete/refused construction, stale/substituted cuts, callback
    /// failure or either terminal guard, including after an error callback.
    pub(in super::super) fn with_hello_result_data<R: Copy>(
        &self,
        inspect: impl FnOnce(&HelloResult) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.guard_hello_result_inputs()?;
        let result = self.hello_result.data(self.cut)?;
        let outcome = inspect(result);
        let terminal = self
            .guard_hello_result_inputs()
            .and_then(|()| self.hello_result.data(self.cut).map(|_| ()));
        let output = outcome?;
        terminal?;
        Ok(output)
    }
}

/// Quotes the actual initial result before the future public Hello arrives.
///
/// # Errors
/// Refuses invalid declarations, unsupported clone layouts, overflow or the
/// independently selected original complete-peak restriction.
pub(in crate::reference_packet::service) fn construction_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    let mut row = storage::construction_data(launch, maximum)?;
    row[2] = row[2]
        .checked_add(counter_scratch_data())
        .ok_or_else(refused)?;
    let peak = row.into_iter().try_fold(0usize, |sum, axis| {
        sum.checked_add(axis).ok_or_else(refused)
    })?;
    if peak > maximum {
        return Err(refused());
    }
    Ok(row)
}

/// Names actual result, entropy, quote, original loan and admission controls.
pub(in crate::reference_packet::service) fn counter_scratch_data() -> usize {
    storage::counter_scratch_data()
        + OriginalImport18RawBootstrap::sdk_hello_request_loan_counter_scratch_data::<()>()
        + size_of::<&dyn OriginalImport18HelloResultAdmission>()
        + size_of::<&OriginalImport18RawBootstrap>()
        + size_of::<&mut OriginalImport18RawBootstrap>()
        + size_of::<&HelloResult>()
        + size_of::<super::hello_request::Claims>()
        + size_of::<[usize; 3]>() * 2
        + size_of::<std::array::IntoIter<usize, 3>>()
        + size_of::<Result<(), ProviderError>>() * 5
        + size_of::<Result<usize, ProviderError>>() * 2
        + size_of::<usize>() * 4
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original import18 Hello result admission refused")
}
