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
