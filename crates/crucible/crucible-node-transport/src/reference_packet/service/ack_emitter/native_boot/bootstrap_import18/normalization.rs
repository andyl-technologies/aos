//! Decodes the actual normalization bank under original completed-input custody.
//!
//! This separately retained attempt checks inert recipe and Host correspondence.
//! Signed Prepare authentication, semantic validation and complete independent
//! recipe reconstruction remain mandatory before any fresh native effect.

use super::*;
use crate::reference_packet::service::complete_restore::import18::OriginalImport18NormalizationAttempt;

/// Borrows independent whole-owner admission around this actual DATA decoder.
pub(in super::super) trait OriginalImport18NormalizationAdmission {
    /// Admits the stored row before parsing, with the actual attempt retained.
    ///
    /// # Errors
    /// Refuses unavailable original custody, short credit or incomplete census.
    fn construct_data(
        &self,
        attempt: &OriginalImport18NormalizationAttempt,
        row: [usize; 3],
    ) -> Result<(), ProviderError>;

    /// Observes surviving typed backing after success or decoder refusal.
    ///
    /// The actual attempt retains its formatted failure diagnostic and all
    /// seven original banks remain live.
    ///
    /// # Errors
    /// Refuses stale custody, a changed owner or actual backing above its row.
    fn finish_data(
        &self,
        attempt: &OriginalImport18NormalizationAttempt,
        actual_typed_backing: usize,
    ) -> Result<(), ProviderError>;
}

impl OriginalImport18RawBootstrap {
    /// Spends one normalization decode under the same original seven-bank loan.
    ///
    /// The caller admits fixed quote controls and retains the attempt's inline
    /// root before entry. Its independent admission observes the complete actual
    /// enclosing owner before decoding and after either decoder outcome. This
    /// transition authenticates DATA only; it issues no signed Prepare or model.
    ///
    /// # Errors
    /// Refuses re-entry, unavailable original inputs, oversized/malformed DATA,
    /// short admission, changed recipe/Host operands or terminal original guards.
    pub(in super::super) fn decode_normalization_data(
        &self,
        attempt: &mut OriginalImport18NormalizationAttempt,
        admission: &dyn OriginalImport18NormalizationAdmission,
    ) -> Result<(), ProviderError> {
        if attempt.started_data() {
            return Err(refused());
        }
        let result = self.with_completed_inputs_data(|loans| {
            let (reference, raw) = loans.inputs[5];
            let row = attempt.quote_data(raw, self.bounds.requested_peak)?;
            admission.construct_data(attempt, row)?;

            let outcome = attempt.decode_data(raw).and_then(|()| {
                let decoded = attempt.decoded.as_ref().ok_or_else(refused)?;
                loans
                    .recipe
                    .authenticate_normalization_data(decoded, reference)?;
                let boot = self.typed_bodies_data()?.boot;
                if &decoded.host_registration != boot.expected_host_registration_data() {
                    return Err(ProviderError::Correlation(
                        "original import18 normalization Host DATA",
                    ));
                }
                Ok(())
            });

            let outcome = match outcome {
                Ok(()) => Ok(()),
                Err(error) => {
                    attempt.retain_failure_data(error);
                    Err(ProviderError::Correlation(
                        "original import18 normalization DATA",
                    ))
                }
            };
            let backing = attempt.retained_backing_data();
            let terminal = backing.and_then(|actual| admission.finish_data(attempt, actual));
            outcome?;
            terminal
        });
        // Even a guard/quote refusal consumes this particular occurrence.
        // Decoded partials survive a later admission or original-cut refusal.
        match result {
            Ok(()) => attempt.complete_data(),
            Err(error) => {
                attempt.refuse_data();
                Err(error)
            }
        }
    }

    /// Names separate quote, decoder and original-loan controls before entry.
    pub(in super::super) fn normalization_counter_scratch_data() -> usize {
        Self::completed_input_loan_counter_scratch_data::<()>()
            + OriginalImport18NormalizationAttempt::counter_scratch_data()
            + size_of::<&dyn OriginalImport18NormalizationAdmission>()
            + size_of::<&mut OriginalImport18NormalizationAttempt>()
            + size_of::<[usize; 3]>()
            + size_of::<usize>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Result<(), ProviderError>>() * 3
    }
}
