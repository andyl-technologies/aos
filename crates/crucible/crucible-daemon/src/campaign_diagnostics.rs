//! Structured operational diagnostics for the local campaign service.
//!
//! Diagnostics remain outside campaign semantic state and transport responses.
//! A listener routes bounded, path-free records to an optional deployment sink
//! after semantic failure validation. Request records carry only the public
//! service operation, exact request digest, stable failure vocabulary, and an
//! optional closed category from the original invocation error.

use std::panic::{AssertUnwindSafe, catch_unwind};

use crucible_campaign::{
    CampaignHash, CampaignServiceFailure, CampaignServiceFailureCategory,
    CampaignServiceFailureSource, CampaignServiceOperation,
};

/// One path-free operational diagnostic emitted by a campaign listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CampaignServiceDiagnostic {
    /// A decoded request produced a validated stable service failure.
    RequestFailure {
        /// Public operation selected by the versioned frame kind.
        operation: CampaignServiceOperation,
        /// Digest of the exact canonical request, including its principal.
        request_digest: CampaignHash,
        /// Stable failure returned to the caller.
        failure: CampaignServiceFailure,
    },
    /// Original branch-admission cause, bound to the same validated failure.
    RequestFailureSource {
        /// Public operation selected by the decoded request.
        operation: CampaignServiceOperation,
        /// Digest of the original canonical request.
        request_digest: CampaignHash,
        /// Closed category obtained directly from that invocation's error.
        category: CampaignServiceFailureCategory,
    },
    /// A connection was rejected or closed at an operational boundary.
    ConnectionFailure(CampaignConnectionDiagnostic),
}

/// Closed operational connection-failure categories.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CampaignConnectionDiagnostic {
    /// Every fixed worker and pending-connection slot was occupied.
    CapacityRejected,
    /// A newly accepted stream could not enter blocking service mode.
    StreamConfigurationFailed,
    /// Kernel peer credentials resolved to a principal that was denied.
    PeerUnauthorized,
    /// Peer identity policy could not make a definitive authentication decision.
    PeerAuthenticationUnavailable,
    /// Framing, canonical decoding, response binding, deadline, or I/O failed.
    ProtocolFailed,
    /// A fixed connection worker violated an internal invariant or panicked.
    WorkerFailed,
    /// The listener accept loop encountered a terminal I/O failure.
    ListenerFailed,
}

/// Deployment-owned receiver for campaign-service operational diagnostics.
///
/// Implementations must return promptly. The listener invokes the sink outside
/// repository locks and never includes backend paths, private error text, peer
/// process identifiers, or campaign object bodies in a diagnostic.
pub trait CampaignServiceDiagnosticSink: Send + Sync {
    /// Records one structured operational diagnostic.
    fn record(&self, diagnostic: CampaignServiceDiagnostic);
}

// Optional observer implementations cannot replace the original service refusal.
pub(crate) fn original_failure_category(
    error: &impl CampaignServiceFailureSource,
) -> Option<CampaignServiceFailureCategory> {
    catch_unwind(AssertUnwindSafe(|| {
        error.campaign_service_failure_category()
    }))
    .ok()
    .flatten()
}

pub(crate) fn route_campaign_service_diagnostic(
    sink: Option<&dyn CampaignServiceDiagnosticSink>,
    diagnostic: CampaignServiceDiagnostic,
) {
    if let Some(sink) = sink {
        let _ = catch_unwind(AssertUnwindSafe(|| sink.record(diagnostic)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct PanickingCategory;

    impl CampaignServiceFailureSource for PanickingCategory {
        fn campaign_service_failure(&self) -> CampaignServiceFailure {
            CampaignServiceFailure::Unavailable
        }

        fn campaign_service_failure_category(&self) -> Option<CampaignServiceFailureCategory> {
            panic!("diagnostic category panic");
        }
    }

    #[test]
    fn panicking_category_preserves_original_refusal() {
        let error = PanickingCategory;

        assert_eq!(original_failure_category(&error), None);
        assert_eq!(
            error.campaign_service_failure(),
            CampaignServiceFailure::Unavailable
        );
    }

    struct PanickingSink;

    impl CampaignServiceDiagnosticSink for PanickingSink {
        fn record(&self, _diagnostic: CampaignServiceDiagnostic) {
            panic!("diagnostic sink panic");
        }
    }

    #[test]
    fn panicking_sink_is_isolated_from_serving() {
        route_campaign_service_diagnostic(
            Some(&PanickingSink),
            CampaignServiceDiagnostic::ConnectionFailure(
                CampaignConnectionDiagnostic::ProtocolFailed,
            ),
        );
    }
}
