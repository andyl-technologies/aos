//! Schema and media-type constants for portable CLI artifacts.

pub(super) const SAVEPOINT_HANDLE_SCHEMA: &str = "crucible.savepoint-handle.v3";
pub(super) const SAVEPOINT_HANDLE_SCHEMA_V2: &str = "crucible.savepoint-handle.v2";
pub(super) const FAILURE_TRIAGE_FINDINGS_LEDGER_SCHEMA_V1: &str =
    "crucible.failure-triage.findings-ledger.v1";
pub(super) const FAILURE_TRIAGE_FINDINGS_LEDGER_SCHEMA_V2: &str =
    "crucible.failure-triage.findings-ledger.v2";
pub(super) const FAILURE_TRIAGE_FINDINGS_LEDGER_SCHEMA_V3: &str =
    "crucible.failure-triage.findings-ledger.v3";
pub(super) const RECORDED_DECISION_PAYLOAD_MEDIA_TYPE: &str =
    "application/vnd.crucible.recorded-decision-payload+text";
pub(super) const CONTENT_ADDRESS_PREFIX: &str = "crucible-hash:";
