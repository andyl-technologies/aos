//! Constructs a current17 source beneath its same real installed code graph.

use super::*;
use crate::node_state::{
    CompleteOriginalRestorationSource, CompleteRestoredSettledSourceLoadAttempt,
};

impl ConformanceRuntime {
    /// Retains one strict current17 load and its Source before any final recheck.
    ///
    /// The caller owns actual prepared setup and must include its independently
    /// observed backing in `additional_retained_bytes`. This is only storage DATA;
    /// the actual selected archive, signed provenance, opaque code graph and
    /// installed factory are authenticated before decoding or Source construction.
    /// Every failed raw/typed load and any completed output remain in caller slots.
    ///
    /// # Errors
    /// Refuses occupied destinations, a foreign signed/code plan, unsupported
    /// current17 family, a spent attempt or exhausted independently summed credit.
    pub fn prepare_complete_restored_settled_archive_code_source_into(
        graph: &crate::node_admission::CompleteArchiveCodeGraph,
        archive: &mut Option<NativeArchiveRecord>,
        factory: &dyn NativeWorldFactory,
        limits: super::super::super::HostSchedulingContinuationLimits,
        additional_retained_bytes: usize,
        pending: &mut Option<CompleteRestoredSettledSourceLoadAttempt>,
        output: &mut Option<CollectingCompleteRestorationSource>,
    ) -> Result<(), StateError> {
        if output.is_some() {
            return Err(crate::node_state::schema(
                RuntimeError::OutstandingObligations,
            ));
        }
        let mut source = None;
        let result = CompleteOriginalRestorationSource::prepare_restored_settled_source_into(
            archive,
            graph,
            factory,
            limits,
            additional_retained_bytes,
            pending,
            &mut source,
        );
        // The native constructor performs no fallible work after filling source.
        // Install its actual owner before this caller's final currency fence.
        if let Some(original) = source {
            *output = Some(CollectingCompleteRestorationSource { original });
        }
        result?;
        graph
            .plan()
            .reauthenticate()
            .map_err(crate::node_state::schema)
    }
}
