//! Structured operational diagnostics for the local campaign service.
//!
//! Diagnostics remain outside campaign semantic state and transport responses.
//! A listener routes bounded, path-free records to an optional deployment sink
//! after semantic failure validation. Request records carry only the public
//! service operation, exact request digest, and stable failure vocabulary.

use std::panic::{AssertUnwindSafe, catch_unwind};

use crucible_campaign::{CampaignHash, CampaignServiceFailure, CampaignServiceOperation};

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
