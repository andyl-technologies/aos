//! Diagnostic row for a savepoint capture refused at its reached stop.
//!
//! A savepoint capture drives an attempt to its declared stop and then needs
//! an exact checkpoint there. When the stop is not exact-checkpoint ready, the
//! capture fails closed (RFC-0010 ADV-12) and the public capture status
//! reports only `failed`. This row names the attempt and the lifecycle's
//! readiness reason for operators:
//!
//! ```text
//! CRUCIBLE-SAVEPOINT-CAPTURE-REFUSAL-V1 attempt=<id> reason=<token> node=<name|none> detail=<text>
//! ```
//!
//! `detail` is last because its human-readable text contains spaces.

use std::io::Write;

use crate::CrucibleAttemptExecution;
use crate::qemu_campaign_lifecycle::QemuExactCheckpointRefusal;

/// Formats the refusal row for one attempt.
pub(super) fn savepoint_capture_refusal_row(
    attempt: &str,
    refusal: &QemuExactCheckpointRefusal,
) -> String {
    let node = match refusal {
        QemuExactCheckpointRefusal::Named(reason) => reason.node(),
        QemuExactCheckpointRefusal::Unnamed => None,
    };
    let node = node.map_or("none", |node| node.name.as_str());
    format!(
        "CRUCIBLE-SAVEPOINT-CAPTURE-REFUSAL-V1 attempt={attempt} reason={} node={node} detail={refusal}",
        refusal.token()
    )
}

/// Writes the refusal row for the attempt being captured.
pub(super) fn record_savepoint_capture_refusal(
    input: &CrucibleAttemptExecution,
    refusal: &QemuExactCheckpointRefusal,
) {
    let attempt = input
        .attempt()
        .id()
        .map_or_else(|_| String::from("unavailable"), |id| id.to_string());
    let _ = writeln!(
        std::io::stderr().lock(),
        "{}",
        savepoint_capture_refusal_row(&attempt, refusal)
    );
}
