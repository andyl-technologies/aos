//! Bounded operational notices for attempt publication phases.
//!
//! These helpers format stored identities and counts at the caller's existing
//! phase boundary. Admission and the process budget remain owned by the shared
//! execution diagnostic sink; reporting never changes worker reconciliation.

use std::sync::atomic::Ordering;

use crucible_campaign::ExecutionId;

use super::SharedExecutor;
use crate::{ExecutionCancellation, QueuedAttempt};

pub(super) fn record_phase(
    stage: &str,
    execution: ExecutionId,
    cancellation: &ExecutionCancellation,
) {
    crate::crucible_execution::record_execution_phase_diagnostic(
        stage,
        format_args!(
            "execution={execution:?} canceled={}",
            cancellation.is_canceled()
        ),
    );
}

pub(super) fn record_queued_phase(stage: &str, queued: &QueuedAttempt) {
    record_phase(stage, queued.execution(), queued.cancellation());
}

pub(super) fn record_retained_publication<L, V>(
    shared: &SharedExecutor<L, V>,
    phase: &str,
    cancellation: &crate::ExecutionCancellation,
) {
    let count = shared.counters.publication_retries.load(Ordering::Relaxed);
    if count.is_power_of_two() {
        crate::crucible_execution::record_execution_phase_diagnostic(
            "retained-publication-retry",
            format_args!(
                "phase={phase} retries={count} canceled={}",
                cancellation.is_canceled()
            ),
        );
    }
}
