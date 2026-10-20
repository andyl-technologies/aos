//! Failure triage and time-travel debugging planning.

#[path = "triage_debug/campaign_evidence.rs"]
pub(crate) mod campaign_evidence;

use super::*;
use campaign_evidence::{build_campaign_triage_minimization, parse_campaign_findings_ledger_bytes};
#[path = "triage_debug/debug_relay.rs"]
mod debug_relay;
#[path = "triage_debug/debug_terminal.rs"]
mod debug_terminal;
#[path = "triage_debug/ledger_format.rs"]
mod ledger_format;
#[path = "triage_debug/triage.rs"]
mod triage;

pub(crate) use debug_relay::{plan_debug_invocation, run_remote_debug_relay};
pub(crate) use debug_terminal::parse_debug_reverse_condition;
pub(crate) use debug_terminal::run_private_unix_debug_relay_with_client_async;
#[cfg(test)]
pub(crate) use debug_terminal::{
    GUEST_TRANSCRIPT_HEADER, GuestTranscriptDirection, GuestTranscriptWriter,
};
#[cfg(test)]
pub(crate) use ledger_format::ledger_hex;
pub(crate) use ledger_format::{format_content_hash_ref, write_reproduction_findings_ledger};
#[cfg(test)]
pub(crate) use triage::{
    build_triage_minimization, build_triage_report_set, triage_evidence_for_finding,
    triage_property_evidence_for_violation,
};
pub(crate) use triage::{
    emit_triage_report, run_campaign_triage_invocation,
    triage_property_evidence_for_violation_with_recording, triage_timeout_evidence,
};

#[path = "triage_debug/coordinates.rs"]
mod coordinates;

pub(super) use coordinates::*;
#[path = "triage_debug/guest_channel_response.rs"]
mod guest_channel_response;

use guest_channel_response::{
    GuestChannelRecordOutcome, handle_guest_channel_response,
    handle_guest_channel_shutdown_response, receive_guest_channel_shutdown_signal,
};

pub(crate) fn selected_triage_members<T>(
    mode: TriageMinimizeArg,
    members: &[T],
) -> Result<&[T], CliError> {
    match mode {
        TriageMinimizeArg::None => Err(CliError::Triage(String::from(
            "triage member selection requires an enabled minimization mode",
        ))),
        TriageMinimizeArg::Representative => members
            .get(..1)
            .ok_or_else(|| CliError::Triage(String::from("triage cluster has no representative"))),
        TriageMinimizeArg::All => Ok(members),
    }
}

// crucible-lint: allow host-nondeterminism-state -- this pure conversion is exported only for CLI contract tests.
pub(crate) use guest_channel_response::guest_input_message;
#[path = "triage_debug/slug.rs"]
mod slug;

// crucible-lint: allow host-nondeterminism-state -- these parsing helpers are pure CLI input normalization and do not construct scheduler state.
pub(crate) use slug::*;
