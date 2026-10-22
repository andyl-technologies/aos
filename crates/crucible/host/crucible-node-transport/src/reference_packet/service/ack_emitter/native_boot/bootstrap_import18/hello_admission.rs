//! Admits the original initial SDK lease under complete original bootstrap custody.
//!
//! Separate admissions cover the pure quote, complete SDK construction and the
//! surviving registrar census. The original request, response and callback field
//! owners stay in place. This transition publishes no response or ACK and does
//! not create a native model, policy, opaque Initial or Recipe.

use super::*;
use crate::handshake::ConnectionAuthority;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crate::reference_packet::service::complete_restore::import18::hello::NATIVE_IMPORT18_CONNECTION_ID;
use crucible_node_format::Id;

#[path = "hello_admission/attempt.rs"]
mod attempt;
pub(super) use attempt::Attempt;

/// Admits quote, complete construction and actual census under genuine funding.
pub(in super::super) trait OriginalImport18HelloAdmission {
    /// Admits quote and original guard controls before the pure constructor quote.
    ///
    /// # Errors
    /// Refuses unavailable original credit or incomplete enclosing correspondence.
    fn quote_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        scratch: usize,
    ) -> Result<(), ProviderError>;

    /// Admits the stored complete row before connection allocation or SDK calls.
    ///
    /// # Errors
    /// Refuses short original credit or incomplete whole-owner demand.
    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        row: [usize; 3],
    ) -> Result<(), ProviderError>;

    /// Observes the actual registrar and surviving lease after either SDK outcome.
    ///
    /// This census includes the prior issuer as well as the new owners. The
    /// constructor's retained axis prices only additional SDK ownership.
    ///
    /// # Errors
    /// Refuses incomplete whole-owner census or unavailable original credit.
    fn finish_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        registrar_backing: usize,
    ) -> Result<(), ProviderError>;
}

impl OriginalImport18RawBootstrap {
    /// Admits the actual SDK lease once with the original native verifier.
    ///
    /// The enclosing producer must supply genuine Source/Birth funding. This
    /// internal transition grants SDK negotiation alone; it cannot produce an
    /// opaque Initial, Recipe, ACK, policy, publication or native model.
    ///
    /// # Errors
    /// Refuses retry, missing original response/custody, unavailable admission,
    /// SDK/verifier failure, stale live registration or any terminal guard/census.
    pub(in super::super) fn admit_hello_data(
        &mut self,
        admission: &dyn OriginalImport18HelloAdmission,
    ) -> Result<(), ProviderError> {
        self.hello_admission.start_data(self.cut)?;
        let outcome = self.admit_current_hello(admission);
        let terminal = self.guard_hello_admission_inputs();
        let completed = outcome
            .and(terminal)
            .and_then(|()| self.hello_admission.complete_data(self.cut));
        if let Err(error) = completed {
            self.hello_admission.refuse_data();
            // Containment must not erase the original failure or retained lease.
            // The phase is already spent even when no wrapper was initialized.
            let _ = self.hello_registrar.contain_admission_data();
            return Err(error);
        }
        Ok(())
    }

    fn guard_hello_admission_inputs(&self) -> Result<(), ProviderError> {
        self.with_hello_response_data(|_| Ok(()))
    }

    fn admit_current_hello(
        &mut self,
        admission: &dyn OriginalImport18HelloAdmission,
    ) -> Result<(), ProviderError> {
        self.admit_source_row(self.initial_construction.as_ref().ok_or_else(refused)?.row)?;
        self.guard_hello_admission_inputs()?;
        admission.quote_data(self, counter_scratch_data())?;
        self.guard_hello_admission_inputs()?;

        let row = construction_data(
            self.typed_bodies_data()?.launch.launch_data(),
            self.bounds.requested_peak,
        )?;
        self.hello_admission.quote_data(row, self.cut)?;
        admission.construct_data(self, row)?;
        let outcome = self.admit_guarded_hello();
        // Evaluate both terminal paths even when the SDK or input guard refuses.
        // The SDK primitive retained its real lease/error before these checks.
        let terminal = self.guard_hello_admission_inputs();
        let census = self
            .hello_registrar
            .retained_backing_data()
            .and_then(|actual| admission.finish_data(self, actual));
        outcome?;
        terminal?;
        census
    }

    fn admit_guarded_hello(&mut self) -> Result<(), ProviderError> {
        self.guard_hello_admission_inputs()?;
        self.hello_admission.quoted_data(self.cut)?;
        let cut = self.cut;
        let Self {
            process,
            thread,
            stream,
            cut: original_cut,
            parsed,
            hello_selection,
            hello_sdk_request,
            hello_result,
            hello_envelope,
            hello_response,
            hello_exchange,
            hello_registrar,
            ..
        } = self;
        let launch = parsed.bodies_data()?.launch.launch_data();
        let request = hello_sdk_request.data(cut)?;
        let result = hello_result.data(cut)?;
        let mut verifier = hello_verifier::Verifier::new_data(
            channel_custody::BorrowedCustody::new_data(process, thread, original_cut, stream),
            launch,
            hello_selection.as_ref().ok_or_else(refused)?,
            request,
            result,
            hello_exchange
                .destination_data()
                .as_ref()
                .ok_or_else(refused)?,
            cut,
        );
        hello_registrar.admit_initial_data(
            hello_envelope.data(cut)?,
            hello_response.data(cut)?,
            request,
            result,
            Id::new(NATIVE_IMPORT18_CONNECTION_ID)?,
            &mut verifier,
            cut,
        )
    }

    /// Names completed original lease inspection and its surrounding guards.
    pub(in super::super) fn hello_authority_loan_counter_scratch_data<R: Copy>() -> usize {
        Self::hello_response_loan_counter_scratch_data::<()>()
            + Attempt::counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&ConnectionAuthority>()
            + size_of::<Result<&ConnectionAuthority, ProviderError>>()
            + size_of::<R>() * 2
            + size_of::<Result<R, ProviderError>>() * 2
            + size_of::<Result<(), ProviderError>>() * 3
    }

    /// Lends the same completed SDK lease under complete original input guards.
    ///
    /// The caller separately funds its inspection; only Copy DATA can return.
    /// This loan cannot move or clone the lease or establish native readiness.
    ///
    /// # Errors
    /// Refuses incomplete/refused admission, stale original custody/cut, callback
    /// failure or any terminal original input and live registration check.
    pub(in super::super) fn with_hello_authority_data<R: Copy>(
        &self,
        inspect: impl FnOnce(&ConnectionAuthority) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.guard_hello_admission_inputs()?;
        self.hello_admission.completed_data(self.cut)?;
        let outcome = inspect(self.hello_registrar.authority_data(self.cut)?);
        let terminal = self
            .guard_hello_admission_inputs()
            .and_then(|()| self.hello_admission.completed_data(self.cut))
            .and_then(|()| self.hello_registrar.authority_data(self.cut).map(|_| ()));
        let output = outcome?;
        terminal?;
        Ok(output)
    }
}

/// Composes SDK construction with sequential original guards and terminal census.
///
/// # Errors
/// Refuses the closed SDK quote, overflow or an independent complete-peak limit.
pub(in crate::reference_packet::service) fn construction_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    let mut row = hello_registrar::initial_admission_construction_data(launch, maximum)?;
    // Whole-root guards/census and the inner SDK call run in separate windows.
    // Fixed outer call operands coexist with either and remain separately priced.
    row[2] = row[2]
        .max(counter_scratch_data())
        .checked_add(enclosing_counter_scratch_data())
        .ok_or_else(refused)?;
    let peak = row.into_iter().try_fold(0usize, |sum, axis| {
        sum.checked_add(axis).ok_or_else(refused)
    })?;
    if peak > maximum {
        return Err(refused());
    }
    Ok(row)
}

/// Names sequential quote/guard/census controls without invoking any of them.
pub(in crate::reference_packet::service) fn counter_scratch_data() -> usize {
    hello_registrar::initial_admission_counter_scratch_data()
        .max(OriginalImport18RawBootstrap::hello_response_loan_counter_scratch_data::<()>())
        .max(hello_registrar::counter_scratch_data())
        + enclosing_counter_scratch_data()
}

fn enclosing_counter_scratch_data() -> usize {
    Attempt::counter_scratch_data()
        + size_of::<&OriginalImport18RawBootstrap>() * 2
        + size_of::<&mut OriginalImport18RawBootstrap>() * 2
        + size_of::<&dyn OriginalImport18HelloAdmission>()
        + size_of::<[usize; 3]>() * 3
        + size_of::<crate::handshake::ConnectionAuthority>()
        + size_of::<Id>()
        + size_of::<Result<Id, crucible_node_format::ContractError>>()
        + size_of::<OperationalDeadline>() * 2
        + size_of::<Result<(), ProviderError>>() * 6
        + size_of::<Result<usize, ProviderError>>() * 2
        + size_of::<Result<[usize; 3], ProviderError>>()
        + size_of::<std::array::IntoIter<usize, 3>>()
        + size_of::<usize>() * 3
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original import18 SDK admission refused")
}
