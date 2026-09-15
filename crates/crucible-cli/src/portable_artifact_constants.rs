//! Schema and media-type constants for portable CLI artifacts.

pub(super) const REPLAY_CLOSURE_SAVEPOINT_HANDLE_SCHEMA: &str = "crucible.savepoint-handle.v5";
pub(super) const CAMPAIGN_OBSERVATION_REPLAY_CLOSURE_SAVEPOINT_HANDLE_SCHEMA: &str =
    "crucible.savepoint-handle.v6";
pub(super) const FAILURE_TRIAGE_FINDINGS_LEDGER_SCHEMA: &str =
    "crucible.failure-triage.findings-ledger.v4";
pub(super) const RECORDED_DECISION_PAYLOAD_MEDIA_TYPE: &str =
    "application/vnd.crucible.recorded-decision-payload+text";
pub(super) const CONTENT_ADDRESS_PREFIX: &str = "crucible-hash:";
