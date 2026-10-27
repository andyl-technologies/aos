//! Per-attempt adjustments to one newly constructed QEMU lifecycle's configuration.
//!
//! The factory's trusted configuration is shared by every attempt. Each new
//! lifecycle additionally receives the attempt's remaining host watchdog and
//! the attempt-storage sink for its resolved-effect trace segments.

use super::{
    AttemptExecutionContext, ProductionVmLifecycleConfig, QemuAttemptProductionVmLifecycleError,
};

/// Directs one newly constructed QEMU lifecycle's trace segments to attempt storage.
///
/// Without an executor namespace the lifecycle keeps its private in-memory
/// segment store.
pub(super) fn config_for_attempt_trace_storage(
    config: ProductionVmLifecycleConfig,
    context: &AttemptExecutionContext,
) -> Result<ProductionVmLifecycleConfig, QemuAttemptProductionVmLifecycleError> {
    let sink = context
        .create_fault_trace_sink()
        .map_err(QemuAttemptProductionVmLifecycleError::TraceStorage)?;
    Ok(match sink {
        Some(sink) => config.with_fault_trace_segments(sink),
        None => config,
    })
}

/// Applies the remaining assignment deadline to one newly constructed QEMU lifecycle.
pub(crate) fn config_for_assignment_host_watchdog(
    config: ProductionVmLifecycleConfig,
    context: &AttemptExecutionContext,
) -> Result<ProductionVmLifecycleConfig, QemuAttemptProductionVmLifecycleError> {
    let Some(remaining) = context.remaining_host_watchdog() else {
        // Campaign advances use virtual bounds. The finite per-operation
        // ceiling remains a polling slice and transport/lifecycle safety bound.
        return Ok(config.with_unbounded_advance_completion());
    };
    if remaining.is_zero() {
        return Err(QemuAttemptProductionVmLifecycleError::HostWatchdogExpired);
    }
    // The campaign's explicit assignment watchdog supersedes the fixed
    // transport fallback. Its separate timer interrupts a child even when
    // many short QEMU awaits would each finish within this initial remainder.
    Ok(config.with_completion_timeout(remaining))
}
