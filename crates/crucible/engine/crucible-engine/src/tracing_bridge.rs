//! Opt-in bridge from Crucible diagnostics to `tracing`.
//!
//! The bridge is deliberately a sink at the edge of event-log production. It
//! never reads subscriber state, never reports whether a subscriber captured an
//! event, and produces only observational diagnostic entries.

use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::model::VirtualTime;
use crate::scheduler::{EventDiagnosticPayload, EventLevel, SchedulerEventLogEntry};

/// Configuration for the host-side `tracing` bridge.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TracingBridgeConfig {
    /// Whether diagnostic mirroring into the event log and `tracing` is enabled.
    pub enabled: bool,
}

impl TracingBridgeConfig {
    /// Builds an explicit disabled bridge configuration.
    #[must_use]
    pub const fn disabled() -> Self {
        Self { enabled: false }
    }

    /// Builds an explicit enabled bridge configuration.
    #[must_use]
    pub const fn enabled() -> Self {
        Self { enabled: true }
    }
}

/// Observational bridge that mirrors diagnostics to `tracing`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TracingBridge {
    config: TracingBridgeConfig,
}

impl TracingBridge {
    /// Builds a bridge from explicit configuration.
    #[must_use]
    pub const fn new(config: TracingBridgeConfig) -> Self {
        Self { config }
    }

    /// Builds an enabled bridge.
    #[must_use]
    pub const fn enabled() -> Self {
        Self::new(TracingBridgeConfig::enabled())
    }

    /// Builds a disabled bridge.
    #[must_use]
    pub const fn disabled() -> Self {
        Self::new(TracingBridgeConfig::disabled())
    }

    /// Returns whether this bridge is enabled.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Mirrors a host diagnostic as an observational event-log entry.
    ///
    /// Disabled bridges return `None`. Enabled bridges return a diagnostic
    /// event-log entry and best-effort emit the same diagnostic to `tracing`.
    /// Subscriber capture, filtering, and panics are ignored so the bridge does
    /// not let host diagnostics feed back into event-log construction.
    #[must_use]
    pub fn mirror_diagnostic(
        &self,
        sequence: u64,
        at: VirtualTime,
        diagnostic: EventDiagnosticPayload,
    ) -> Option<SchedulerEventLogEntry> {
        if !self.config.enabled {
            return None;
        }

        let entry = SchedulerEventLogEntry::diagnostic(sequence, at, diagnostic.clone());
        let _ = catch_unwind(AssertUnwindSafe(|| emit_tracing_diagnostic(&diagnostic)));
        Some(entry)
    }
}

fn emit_tracing_diagnostic(diagnostic: &EventDiagnosticPayload) {
    let detail_count = diagnostic.details.len();
    match diagnostic.level {
        EventLevel::Trace => tracing::trace!(
            target: "crucible::tracing_bridge",
            diagnostic_name = %diagnostic.name,
            detail_count,
            "crucible tracing bridge diagnostic"
        ),
        EventLevel::Debug => tracing::debug!(
            target: "crucible::tracing_bridge",
            diagnostic_name = %diagnostic.name,
            detail_count,
            "crucible tracing bridge diagnostic"
        ),
        EventLevel::Info => tracing::info!(
            target: "crucible::tracing_bridge",
            diagnostic_name = %diagnostic.name,
            detail_count,
            "crucible tracing bridge diagnostic"
        ),
        EventLevel::Warn => tracing::warn!(
            target: "crucible::tracing_bridge",
            diagnostic_name = %diagnostic.name,
            detail_count,
            "crucible tracing bridge diagnostic"
        ),
        EventLevel::Error => tracing::error!(
            target: "crucible::tracing_bridge",
            diagnostic_name = %diagnostic.name,
            detail_count,
            "crucible tracing bridge diagnostic"
        ),
    }
}
