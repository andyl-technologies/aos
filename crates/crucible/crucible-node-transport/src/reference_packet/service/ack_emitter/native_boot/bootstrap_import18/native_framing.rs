//! Preflights actual Snapshot17 role framing under original input custody.
//!
//! This nonowning reader checks complete fullrefs, native Snapshot framing,
//! embedded before/Control correspondence and the final Journal role roster.
//! Full native graph, signed Controller/Source lineage, semantic spend and
//! normalization validation remain required before independent recipe/model
//! adoption. Snapshot18 is not interpreted using the older reader.

use super::*;
use crate::protocol_snapshot::restored_settled17::{
    NativeCold17Admission, RestoredSettledNative17Input, RestoredSettledNative17Limits,
    RestoredSettledNative17Plan, restored_settled_native17_counter_scratch_data,
};
use crate::reference_packet::service::complete_restore::import18::{
    OriginalImport18NormalizationAttempt, PacketNativeImport18Normalization,
};

/// Observes the actual native prefix after either decoder outcome.
///
/// Constructor admission remains inherited from the independently funded cold
/// reader. This final observation includes the surviving attempt in the actual
/// enclosing owner and does not declare any native work stage completed.
pub(in super::super) trait OriginalImport18NativeGraphAdmission:
    NativeCold17Admission
{
    /// Observes retained graph backing before terminal original custody guards.
    ///
    /// # Errors
    /// Refuses stale custody, an incomplete enclosing census or short credit.
    fn finish_attempt_data(
        &self,
        attempt: &crate::protocol_snapshot::restored_settled17::RestoredSettledNative18GraphAttempt,
        actual_graph_backing: usize,
    ) -> Result<(), ProviderError>;
}

impl OriginalImport18RawBootstrap {
    /// Preflights complete native role framing inside the original guarded loan.
    ///
    /// The enclosing caller admits the fixed loan controls and supplies its
    /// genuine whole-owner cold-reader admission before entering. Inspection
    /// returns Copy DATA only; no live native installation is constructed here.
    ///
    /// # Errors
    /// Refuses unavailable original inputs/custody, another native grammar,
    /// malformed or mismatched role framing, admission or inspection refusal,
    /// or terminal bootstrap guards after the actual reader and callback.
    pub(in super::super) fn with_native17_framing_data<R: Copy>(
        &self,
        admission: &dyn NativeCold17Admission,
        inspect: impl FnOnce(&RestoredSettledNative17Plan<'_>) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.with_completed_inputs_data(|loans| {
            let limits = loans.recipe.native17_decoder_limits_data()?;
            let [after, control, anchor, snapshot, journal, _, _] = loans.inputs;
            let input = RestoredSettledNative17Input {
                snapshot,
                current_protocol: after,
                control,
                anchor,
                journal,
            };
            let plan = RestoredSettledNative17Plan::validate_with_admission_data(
                &input, &limits, admission,
            )?;
            inspect(&plan)
        })
    }

    /// Joins actual decoded normalization and framed native history in one loan.
    ///
    /// The caller retains a completed normalization attempt and independently
    /// admits this wrapper's fixed controls, framing work and callback demand.
    /// Its exact raw bank, recipe and original Host are checked again before
    /// comparing the embedded before and Journal's semantic/Runtime references.
    /// Full signed provenance and native graph validation remain required.
    ///
    /// # Errors
    /// Refuses incomplete/foreign normalization DATA, changed original operands,
    /// native framing/context or admission failure, or terminal original guards.
    pub(in super::super) fn with_normalized_native17_framing_data<R: Copy>(
        &self,
        normalization: &OriginalImport18NormalizationAttempt,
        admission: &dyn NativeCold17Admission,
        inspect: impl FnOnce(
            &RestoredSettledNative17Plan<'_>,
            &PacketNativeImport18Normalization,
        ) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.with_completed_inputs_data(|loans| {
            let decoded = normalization.completed_decoded_data(loans.inputs[5].1)?;
            loans
                .recipe
                .authenticate_normalization_data(decoded, loans.inputs[5].0)?;
            if &decoded.host_registration
                != self
                    .typed_bodies_data()?
                    .boot
                    .expected_host_registration_data()
            {
                return Err(ProviderError::Correlation(
                    "original import18 normalization Host DATA",
                ));
            }

            let limits = loans.recipe.native17_decoder_limits_data()?;
            let [after, control, anchor, snapshot, journal, _, _] = loans.inputs;
            let input = RestoredSettledNative17Input {
                snapshot,
                current_protocol: after,
                control,
                anchor,
                journal,
            };
            let plan = RestoredSettledNative17Plan::validate_with_admission_data(
                &input, &limits, admission,
            )?;
            plan.authenticate_semantic_context_data(
                &decoded.native_before,
                &decoded.source17,
                &decoded.source_runtime,
                usize::try_from(decoded.limits.maximum_before_bytes.get())
                    .map_err(|_| refused())?,
            )?;
            inspect(&plan, decoded)
        })
    }

    /// Retains both native decoder banks beneath the original normalized loan.
    ///
    /// The caller owns and funds the attempt's inline root before entry, plus
    /// all original bootstrap banks, normalized-loan controls and independently
    /// admitted cold constructors. A failed guard or reader consumes this slot
    /// and preserves every initialized raw or typed child. Graph completion is
    /// inert DATA; SDK/Source/semantic validation and phase funding stay required.
    ///
    /// # Errors
    /// Refuses a reused slot, invalid original normalization/framing, admission
    /// or decoder failure, short target limits, or terminal original guards.
    pub(in super::super) fn decode_native17_graphs_into_data(
        &self,
        normalization: &OriginalImport18NormalizationAttempt,
        destination: &mut Option<
            crate::protocol_snapshot::restored_settled17::RestoredSettledNative18GraphAttempt,
        >,
        admission: &dyn OriginalImport18NativeGraphAdmission,
    ) -> Result<(), ProviderError> {
        use crate::protocol_snapshot::restored_settled17::RestoredSettledNative18GraphAttempt;

        // Install the once-attempt even when the first original guard refuses.
        let attempt = RestoredSettledNative18GraphAttempt::begin_into_data(destination)?;
        let outcome = self.with_normalized_native17_framing_data(
            normalization,
            admission,
            |plan, decoded| {
                let maximum = usize::try_from(decoded.limits.maximum_target_requested_bytes.get())
                    .map_err(|_| refused())?;
                attempt.read_framed_with_admission_data(plan, maximum, admission)
            },
        );

        // Observe real surviving backing even when framing or decoding refused.
        // The callback cannot bypass a fresh original/cut guard after it runs.
        let observed = attempt
            .retained_requested_storage_data(usize::MAX)
            .and_then(|actual| admission.finish_attempt_data(attempt, actual));
        let terminal = self.with_completed_inputs_data(|_| Ok(()));
        attempt.finish_original_guards_data(outcome.and(observed).and(terminal))
    }

    /// Names the separate original loan and owning native graph reader controls.
    pub(in super::super) fn native17_graph_decode_counter_scratch_data() -> usize {
        use crate::protocol_snapshot::restored_settled17::RestoredSettledNative18GraphAttempt;

        Self::normalized_native17_framing_counter_scratch_data::<()>()
            + RestoredSettledNative18GraphAttempt::counter_scratch_data()
            + size_of::<&dyn OriginalImport18NativeGraphAdmission>()
            + size_of::<&mut Option<RestoredSettledNative18GraphAttempt>>()
            + size_of::<Result<&mut RestoredSettledNative18GraphAttempt, ProviderError>>()
            + size_of::<Result<(), ProviderError>>() * 4
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Result<usize, std::num::TryFromIntError>>()
    }

    /// Names actual normalized-framing controls without changing initial demand.
    pub(in super::super) fn normalized_native17_framing_counter_scratch_data<R: Copy>() -> usize {
        Self::native17_framing_counter_scratch_data::<R>()
            + OriginalImport18NormalizationAttempt::completed_loan_counter_scratch_data()
            + crate::reference_packet::service::complete_restore::import18::native_import18_normalization_counter_scratch_data()
            + RestoredSettledNative17Plan::semantic_context_counter_scratch_data()
            + size_of::<&OriginalImport18NormalizationAttempt>()
            + size_of::<&PacketNativeImport18Normalization>()
            + size_of::<&serde_json::Value>() * 2
            + size_of::<Result<usize, std::num::TryFromIntError>>()
            + size_of::<Result<(), ProviderError>>() * 3
    }

    /// Names this nonowning reader's separate fixed controls before inspection.
    ///
    /// The concrete cold-reader admission supplies its independently declared
    /// framing work. Initial-only work, full owning decode and callback demand
    /// remain separate; no retained input or target is allocated here.
    pub(in super::super) fn native17_framing_counter_scratch_data<R: Copy>() -> usize {
        Self::completed_input_loan_counter_scratch_data::<R>()
            + restored_settled_native17_counter_scratch_data()
            + size_of::<&dyn NativeCold17Admission>()
            + size_of::<RestoredSettledNative17Input<'static>>()
            + size_of::<&RestoredSettledNative17Input<'static>>()
            + size_of::<RestoredSettledNative17Limits>()
            + size_of::<Result<RestoredSettledNative17Limits, ProviderError>>()
            + size_of::<RestoredSettledNative17Plan<'static>>()
            + size_of::<&RestoredSettledNative17Plan<'static>>()
            + size_of::<Result<RestoredSettledNative17Plan<'static>, ProviderError>>()
            + size_of::<Result<R, ProviderError>>()
    }
}
