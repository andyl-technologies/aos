//! Bounded advisory control rows from the exact child's private stderr stream.
//!
//! [`ControlDiagnosticsFold`] consumes the stream incrementally as it is
//! drained, so the summary never needs the complete stream. It keeps one
//! partial row of at most 513 bytes, the accepted and rejected row counts, and
//! the final 32 accepted rows of at most 512 bytes each. Native log-file traces
//! remain a separate artifact. A matching callback PID filters unrelated
//! records but is not an execution or provenance receipt.
//!
//! The rendered summary has this shape:
//!
//! ```text
//! stream_bytes=<n> accepted_rows=<n> rejected_rows=<n> tail_rows=<n> omitted_rows=<n> incomplete_last_row=<bool>
//! <accepted row>
//! ...
//! ```

use std::collections::VecDeque;

#[path = "checkpoint_stop.rs"]
mod checkpoint_stop;

#[path = "control_stage.rs"]
mod control_stage;

#[path = "network_output_context.rs"]
mod network_output_context;

#[path = "native_stop_context.rs"]
mod native_stop_context;

const MAXIMUM_ROWS: usize = 32;
const MAXIMUM_ROW_BYTES: usize = 512;

/// Row prefixes that make a line a candidate control diagnostic.
const CANDIDATE_PREFIXES: [&[u8]; 15] = [
    b"CRUCIBLE-CHECKPOINT-STOP-V1 ",
    b"CRUCIBLE-CONTROL-STAGE-V1 ",
    b"CRUCIBLE-NATIVE-STOP-CONTEXT-V1 ",
    b"CRUCIBLE-NETWORK-OUTPUT-CONTEXT-V1 ",
    b"CRUCIBLE-CONTROL-CALLBACK-V1 ",
    b"CRUCIBLE-CONTROL-LAST-V1 ",
    b"CRUCIBLE-CONTROL-SETTLEMENT-LAST-V1 ",
    b"CRUCIBLE-CONTROL-PENDING-V1 ",
    b"crucible_sim_rr_control_",
    b"CRUCIBLE-ZERO-LENGTH-QUERY-V1 ",
    b"CRUCIBLE-DEVICE-WAIT-V1 ",
    b"CRUCIBLE-IDLE-PLAN-V1 ",
    b"CRUCIBLE-CLOCK-DOMAIN-V1 ",
    b"qemu-system-",
    b"crucible-qemu-plugin: ",
];

/// Opt-in plugin trace schemas whose rows name the child in a `pid=` field.
///
/// They are off unless a diagnostic flight forwards their opt-in, and a hot
/// fork's private stream is the only place its rows can be seen.
const PLUGIN_TRACE_SCHEMAS: [&str; 4] = [
    "CRUCIBLE-ZERO-LENGTH-QUERY-V1",
    "CRUCIBLE-DEVICE-WAIT-V1",
    "CRUCIBLE-IDLE-PLAN-V1",
    "CRUCIBLE-CLOCK-DOMAIN-V1",
];

/// Prefixes of the fatal lines QEMU's `error_report` and the plugin's
/// fail-loud paths write just before a child exits.
///
/// A child that exits on such an error leaves nothing else in its private
/// stream, so the line is kept as an advisory row. It names no PID and is not
/// an execution receipt.
const FATAL_LINE_PREFIXES: [&str; 2] = ["qemu-system-", "crucible-qemu-plugin: "];

/// Incremental row fold over one child's private diagnostics stream.
///
/// Rows are classified as they complete, so the child process identifier must
/// be bound before the first drain. Rows completed while no identifier is
/// bound can only match PID-free schemas; production binds the identifier
/// when the successful fork transfers the consumer, before any child-owned
/// drain.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct ControlDiagnosticsFold {
    child_process_id: Option<u32>,
    /// Leading bytes of the current incomplete row, capped one byte past the
    /// row limit so an overlong candidate is still recognized and rejected.
    pending: Vec<u8>,
    accepted: usize,
    rejected: usize,
    rows: VecDeque<String>,
}

impl ControlDiagnosticsFold {
    pub(super) fn bind_child_process_id(&mut self, child_process_id: u32) {
        self.child_process_id = Some(child_process_id);
    }

    /// Folds one drained chunk; rows may span chunk boundaries.
    pub(super) fn ingest(&mut self, bytes: &[u8]) {
        let mut remaining = bytes;
        while let Some(newline) = remaining.iter().position(|byte| *byte == b'\n') {
            self.extend_pending(&remaining[..newline]);
            self.finish_row();
            remaining = &remaining[newline + 1..];
        }
        self.extend_pending(remaining);
    }

    fn extend_pending(&mut self, bytes: &[u8]) {
        let room = (MAXIMUM_ROW_BYTES + 1).saturating_sub(self.pending.len());
        self.pending
            .extend_from_slice(&bytes[..bytes.len().min(room)]);
    }

    fn finish_row(&mut self) {
        let line = std::mem::take(&mut self.pending);
        if !CANDIDATE_PREFIXES
            .iter()
            .any(|prefix| line.starts_with(prefix))
        {
            return;
        }

        // A capped line longer than the row limit fails the length check here.
        let row = std::str::from_utf8(&line)
            .ok()
            .filter(|row| valid_row(row, self.child_process_id));
        let Some(row) = row else {
            self.rejected += 1;
            return;
        };
        self.accepted += 1;
        if self.rows.len() == MAXIMUM_ROWS {
            self.rows.pop_front();
        }
        self.rows.push_back(row.to_owned());
    }

    /// Renders the summary for a stream of `stream_bytes` drained bytes.
    pub(super) fn render(&self, stream_bytes: u64) -> String {
        format!(
            "stream_bytes={stream_bytes} accepted_rows={} rejected_rows={} tail_rows={} omitted_rows={} incomplete_last_row={}\n{}",
            self.accepted,
            self.rejected,
            self.rows.len(),
            self.accepted - self.rows.len(),
            !self.pending.is_empty(),
            self.rows
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join("\n")
        )
    }
}

/// Applies the fixed row grammar; PID-bearing schemas need a bound child.
fn valid_row(row: &str, child_process_id: Option<u32>) -> bool {
    if row.len() > MAXIMUM_ROW_BYTES
        || !row
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic())
    {
        return false;
    }
    if crate::spawn::valid_rr_control_boundary_row(row)
        || FATAL_LINE_PREFIXES
            .iter()
            .any(|prefix| row.starts_with(prefix))
    {
        return true;
    }
    let Some(child_process_id) = child_process_id else {
        return false;
    };
    checkpoint_stop::valid_row(row, child_process_id)
        || control_stage::valid_row(row, child_process_id)
        || native_stop_context::valid_row(row, child_process_id)
        || network_output_context::valid_row(row, child_process_id)
        || valid_callback_row(row, child_process_id)
        || valid_last_callback_row(row, child_process_id)
        || valid_settlement_row(row, child_process_id)
        || valid_pending_row(row, child_process_id)
        || valid_plugin_trace_row(row, child_process_id)
        || (crate::spawn::valid_control_delivery_row(row)
            && row
                .split_ascii_whitespace()
                .next_back()
                .and_then(|field| field.strip_prefix("pid="))
                .and_then(|pid| pid.parse::<i64>().ok())
                == Some(i64::from(child_process_id)))
}

/// Summarizes one complete in-memory stream; the fold's test oracle.
#[cfg(test)]
pub(super) fn control_diagnostics_summary(bytes: &[u8], child_process_id: u32) -> String {
    let mut fold = ControlDiagnosticsFold::default();
    fold.bind_child_process_id(child_process_id);
    fold.ingest(bytes);
    fold.render(bytes.len() as u64)
}

/// Accepts an opt-in plugin trace row whose `pid=` field names this child.
fn valid_plugin_trace_row(row: &str, child_process_id: u32) -> bool {
    let mut fields = row.split_ascii_whitespace();
    let Some(schema) = fields.next() else {
        return false;
    };
    let expected_pid = child_process_id.to_string();
    PLUGIN_TRACE_SCHEMAS.contains(&schema)
        && fields
            .filter_map(|field| field.strip_prefix("pid="))
            .any(|pid| pid == expected_pid)
}

fn value<'a>(fields: &mut std::str::SplitAsciiWhitespace<'a>, key: &str) -> Option<&'a str> {
    fields.next()?.strip_prefix(key)
}

fn valid_pending_row(row: &str, child_process_id: u32) -> bool {
    let mut fields = row.split_ascii_whitespace();
    if row.len() >= MAXIMUM_ROW_BYTES
        || fields.next() != Some("CRUCIBLE-CONTROL-PENDING-V1")
        || value(&mut fields, "phase=") != Some("return")
        || value(&mut fields, "pid=").and_then(|pid| pid.parse::<u32>().ok())
            != Some(child_process_id)
        || !value(&mut fields, "callback=").is_some_and(unsigned::<u64>)
        || !value(&mut fields, "raw=").is_some_and(unsigned::<u64>)
        || !value(&mut fields, "token=").is_some_and(|token| {
            unsigned::<u32>(token) && token.parse::<u32>().is_ok_and(|token| token & 1 == 0)
        })
    {
        return false;
    }
    let identity =
        ["device=", "inode=", "length=", "slot=", "generation="].map(|key| value(&mut fields, key));
    if identity != [Some("unavailable"); 5]
        && !(identity[0].is_some_and(unsigned::<u64>)
            && identity[1].is_some_and(unsigned::<u64>)
            && identity[2].is_some_and(unsigned::<u64>)
            && identity[3].is_some_and(unsigned::<u32>)
            && identity[4].is_some_and(unsigned::<u64>))
    {
        return false;
    }
    let frontier = value(&mut fields, "frontier=");
    let capture = value(&mut fields, "capture=");
    let reason = value(&mut fields, "reason=");
    let observed = frontier.is_some_and(unsigned::<u64>)
        && capture.is_some_and(unsigned::<u32>)
        && matches!(
            reason,
            Some(
                "entered"
                    | "pump-active"
                    | "frontier-pending"
                    | "publication-backpressure"
                    | "frontier-unsettled"
                    | "settled"
                    | "error"
            )
        );
    let unavailable = frontier == Some("unavailable")
        && capture == Some("unavailable")
        && reason == Some("unavailable");
    (observed || unavailable) && fields.next().is_none()
}

fn valid_settlement_row(row: &str, child_process_id: u32) -> bool {
    let mut fields = row.split_ascii_whitespace();
    if fields.next() != Some("CRUCIBLE-CONTROL-SETTLEMENT-LAST-V1")
        || value(&mut fields, "phase=") != Some("after-drain")
        || !matches!(
            value(&mut fields, "teardown="),
            Some("host-quit" | "shared-shutdown" | "run-control-fault")
        )
        || value(&mut fields, "pid=").and_then(|pid| pid.parse::<u32>().ok())
            != Some(child_process_id)
    {
        return false;
    }
    for key in ["device=", "inode=", "length="] {
        if !value(&mut fields, key).is_some_and(unsigned::<u64>) {
            return false;
        }
    }
    if !value(&mut fields, "slot=").is_some_and(unsigned::<u32>)
        || !value(&mut fields, "generation=").is_some_and(unsigned::<u64>)
        || !value(&mut fields, "final_token=").is_some_and(unsigned::<u32>)
    {
        return false;
    }
    if fields.clone().next() == Some("observation=unavailable") {
        fields.next();
        return fields.next().is_none();
    }
    if !value(&mut fields, "callback=").is_some_and(unsigned::<u64>)
        || !value(&mut fields, "raw=").is_some_and(unsigned::<u64>)
        || !value(&mut fields, "token=").is_some_and(unsigned::<u32>)
        || !value(&mut fields, "frontier=").is_some_and(unsigned::<u64>)
        || !matches!(
            value(&mut fields, "reason="),
            Some(
                "entered"
                    | "pump-active"
                    | "frontier-pending"
                    | "publication-backpressure"
                    | "frontier-unsettled"
                    | "settled"
                    | "error"
            )
        )
    {
        return false;
    }
    fields.next().is_none()
}

fn unsigned<T: std::str::FromStr>(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<T>().is_ok()
}

fn valid_callback_row(row: &str, child_process_id: u32) -> bool {
    let mut fields = row.split_ascii_whitespace();
    if fields.next() != Some("CRUCIBLE-CONTROL-CALLBACK-V1") {
        return false;
    }
    let phase = value(&mut fields, "phase=");
    let reason = value(&mut fields, "reason=");
    if !matches!(
        (phase, reason),
        (Some("entry"), Some("native-delivery"))
            | (Some("admitted"), Some("guard-open"))
            | (
                Some("rejected"),
                Some(
                    "hot-fork-held"
                        | "teardown-closed"
                        | "teardown-and-hot-fork"
                        | "shared-shutdown"
                )
            )
            | (
                Some("exit"),
                Some("pending" | "acknowledged" | "no-request" | "error")
            )
    ) || value(&mut fields, "pid=").and_then(|value| value.parse::<u32>().ok())
        != Some(child_process_id)
        || !value(&mut fields, "raw_icount=").is_some_and(unsigned::<u64>)
    {
        return false;
    }
    let expected_kind = if matches!(phase, Some("entry" | "rejected")) {
        "cached"
    } else {
        "observed"
    };
    if value(&mut fields, "token_kind=") != Some(expected_kind) {
        return false;
    }
    for key in ["token_before=", "token_after="] {
        if !value(&mut fields, key)
            .is_some_and(|value| value == "unavailable" || unsigned::<u32>(value))
        {
            return false;
        }
    }
    fields.next().is_none()
}

fn valid_last_callback_row(row: &str, child_process_id: u32) -> bool {
    let mut fields = row.split_ascii_whitespace();
    if fields.next() != Some("CRUCIBLE-CONTROL-LAST-V1") {
        return false;
    }
    let kind = value(&mut fields, "kind=");
    if !matches!(kind, Some("last-callback" | "last-admitted"))
        || value(&mut fields, "phase=") != Some("after-drain")
        || !matches!(
            value(&mut fields, "teardown="),
            Some("host-quit" | "shared-shutdown" | "run-control-fault")
        )
        || value(&mut fields, "pid=").and_then(|pid| pid.parse::<u32>().ok())
            != Some(child_process_id)
    {
        return false;
    }
    for key in ["device=", "inode=", "length="] {
        if !value(&mut fields, key).is_some_and(unsigned::<u64>) {
            return false;
        }
    }
    if !value(&mut fields, "slot=").is_some_and(unsigned::<u32>)
        || !value(&mut fields, "generation=").is_some_and(unsigned::<u64>)
        || !value(&mut fields, "final_token=").is_some_and(unsigned::<u32>)
    {
        return false;
    }
    if fields.clone().next() == Some("observation=unavailable") {
        fields.next();
        return fields.next().is_none();
    }
    if !value(&mut fields, "callback=").is_some_and(unsigned::<u64>) {
        return false;
    }
    let Some(raw) = value(&mut fields, "raw_icount=") else {
        return false;
    };
    let Some(phase) = value(&mut fields, "callback_phase=") else {
        return false;
    };
    let Some(reason) = value(&mut fields, "reason=") else {
        return false;
    };
    if kind == Some("last-admitted") && !matches!(phase, "admitted" | "exit") {
        return false;
    }
    let expected_mask = match (phase, reason) {
        ("rejected", "hot-fork-held") => "1",
        ("rejected", "teardown-closed") => "2",
        ("rejected", "teardown-and-hot-fork") => "3",
        ("rejected", "shared-shutdown") => "4",
        _ => "0",
    };
    if value(&mut fields, "rejection_mask=") != Some(expected_mask) {
        return false;
    }
    let remaining = fields.collect::<Vec<_>>().join(" ");
    // Reuse the existing exact callback grammar; region fields add no authority.
    valid_callback_row(
        &format!(
            "CRUCIBLE-CONTROL-CALLBACK-V1 phase={phase} reason={reason} pid={child_process_id} raw_icount={raw} {remaining}"
        ),
        child_process_id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn final_callback_public_vector_is_retained_only_for_owned_pid_and_exact_schema() {
        // Matches the GPL-side real callback emitter's public diagnostic vector.
        let row = "CRUCIBLE-CONTROL-LAST-V1 kind=last-callback phase=after-drain teardown=host-quit pid=191 device=1 inode=2 length=4096 slot=0 generation=2 final_token=3 callback=1 raw_icount=7 callback_phase=exit reason=acknowledged rejection_mask=0 token_kind=observed token_before=2 token_after=3";
        let summary = control_diagnostics_summary(format!("{row}\n").as_bytes(), 191);
        assert!(summary.contains("accepted_rows=1 rejected_rows=0"));
        assert!(summary.contains(row));
        for invalid in [
            row.replace("pid=191", "pid=192"),
            row.replace("rejection_mask=0", "rejection_mask=2"),
            row.replace("token_kind=observed", "token_kind=cached"),
            row.replace("length=4096", "length=-1"),
            row.replace("phase=after-drain", "phase=before-drain"),
            format!("{row} unexpected=1"),
        ] {
            let summary = control_diagnostics_summary(format!("{invalid}\n").as_bytes(), 191);
            assert!(summary.contains("accepted_rows=0 rejected_rows=1"));
        }
    }

    #[test]
    fn final_rejection_and_unavailable_rows_preserve_existing_tail_limits() {
        let row = "CRUCIBLE-CONTROL-LAST-V1 kind=last-callback phase=after-drain teardown=host-quit pid=191 device=1 inode=2 length=4096 slot=0 generation=2 final_token=4510 callback=100 raw_icount=5859612126 callback_phase=rejected reason=hot-fork-held rejection_mask=1 token_kind=cached token_before=4509 token_after=unavailable";
        assert!(valid_last_callback_row(row, 191));
        assert!(!valid_last_callback_row(
            &row.replace("kind=last-callback", "kind=last-admitted"),
            191
        ));
        let unavailable = "CRUCIBLE-CONTROL-LAST-V1 kind=last-admitted phase=after-drain teardown=run-control-fault pid=191 device=1 inode=2 length=4096 slot=0 generation=2 final_token=4510 observation=unavailable\n";
        let summary = control_diagnostics_summary(unavailable.repeat(40).as_bytes(), 191);
        assert!(summary.contains("accepted_rows=40 rejected_rows=0 tail_rows=32 omitted_rows=8"));
    }

    fn callback(token: u32) -> String {
        format!(
            "CRUCIBLE-CONTROL-CALLBACK-V1 phase=exit reason=pending pid=153 raw_icount=5859612126 token_kind=observed token_before={token} token_after={token}\n"
        )
    }

    #[test]
    fn latest_rows_survive_unrelated_and_malformed_stderr() {
        let mut bytes = b"unrelated private payload\n".to_vec();
        for token in 1..=45 {
            bytes.extend_from_slice(callback(token).as_bytes());
        }
        for malformed in [
            callback(46).replace("pid=153", "pid=132"),
            callback(46).replace("reason=pending", "reason=unknown"),
            callback(46).replace("raw_icount=5859612126", "raw_icount=-1"),
            callback(46).replace("token_kind=observed", "token_kind=cached"),
            callback(46).replace("token_after=46", "token_after=4294967296"),
            callback(46).replace("\n", " extra=untrusted\n"),
            callback(46).replace("\n", "\x1b\n"),
            format!("CRUCIBLE-CONTROL-CALLBACK-V1 {}\n", "x".repeat(512)),
        ] {
            bytes.extend_from_slice(malformed.as_bytes());
        }
        bytes.extend_from_slice(b"CRUCIBLE-CONTROL-CALLBACK-V1 incomplete");

        let summary = control_diagnostics_summary(&bytes, 153);
        assert!(summary.contains(
            "accepted_rows=45 rejected_rows=8 tail_rows=32 omitted_rows=13 incomplete_last_row=true"
        ));
        assert_eq!(summary.lines().count(), 33);
        assert_eq!(summary.lines().nth(1), Some(callback(14).trim_end()));
        assert!(summary.ends_with(callback(45).trim_end()));
        assert!(!summary.contains("unrelated private payload"));
        assert!(!summary.contains("untrusted"));
        assert!(summary.len() <= 32 * MAXIMUM_ROW_BYTES + 256);
    }

    #[test]
    fn plugin_trace_rows_are_kept_only_for_this_child() {
        let zero_length = "CRUCIBLE-ZERO-LENGTH-QUERY-V1 pid=153 reason=already-answered count=64 sequence=30500 ceiling_ps=1853541416016 current_ps=1853541416016 raw=4416718920";
        let publication = "CRUCIBLE-DEVICE-WAIT-V1 phase=publication pid=153 boundary=sim-publication kind=superseded raw=2 current=100 value=unavailable";
        let foreign = zero_length.replace("pid=153", "pid=132");
        let bytes = format!("{zero_length}\n{publication}\n{foreign}\n");

        let summary = control_diagnostics_summary(bytes.as_bytes(), 153);

        assert!(summary.contains("accepted_rows=2 rejected_rows=1"));
        assert!(summary.contains(zero_length));
        assert!(summary.contains(publication));
        assert!(!summary.contains("pid=132"));
    }

    #[test]
    fn a_child_fatal_line_and_its_clock_rows_survive_the_summary() {
        let clock = "CRUCIBLE-CLOCK-DOMAIN-V1 pid=153 reason=repeated cause=timer count=1 plugin_ps=587001000000 deadline_ps=587001000000 raw=1213 virtual_ps=587001000000 qemu_deadline_ps=587001000000 qemu_raw=1213 sim_tick_bias=586940350000 icount_bias_ps=0 warp_start=-1";
        let foreign_clock = clock.replace("pid=153", "pid=132");
        let qemu_fatal = "qemu-system-x86_64: Crucible sim idle warp exceeds the clock";
        let plugin_fatal =
            "crucible-qemu-plugin: RUN control reader panicked; aborting QEMU process";
        let bytes = format!(
            "unrelated private payload\n{clock}\n{foreign_clock}\n{qemu_fatal}\n{plugin_fatal}\nqemu-system-x86_64: \x1b[31m\n"
        );

        let summary = control_diagnostics_summary(bytes.as_bytes(), 153);

        assert!(summary.contains("accepted_rows=3 rejected_rows=2"));
        assert!(summary.contains(clock));
        assert!(summary.contains(qemu_fatal));
        assert!(summary.contains(plugin_fatal));
        assert!(!summary.contains("pid=132"));
        assert!(!summary.contains("unrelated private payload"));
    }

    #[test]
    fn shares_native_advisory_schemas_and_ignores_obsolete_defer_prefix() {
        let boundary = "crucible_sim_rr_control_boundary phase=ack request=2 ack=2 complete=1 token=0x2 state=5";
        let native = "crucible_sim_rr_control_delivery phase=registered-return request=2 ack=2 complete=2 rr_token=0x0 token=0x0 deferred=0 state=5 runstate=4 owner=0 pid=153";
        let summary =
            control_diagnostics_summary(format!("{boundary}\n{native}\n").as_bytes(), 153);
        assert!(summary.contains("accepted_rows=2 rejected_rows=0"));
        assert!(summary.ends_with(native));
        let obsolete = "CRUCIBLE-RR-CONTROL-DEFER-V1 reason=publication-backpressure raw_icount=7 token_before=2 token_after=2 fault_command_frontier=6\n";
        let summary = control_diagnostics_summary(obsolete.as_bytes(), 153);
        assert!(summary.contains("accepted_rows=0"));
        assert_eq!(summary.lines().count(), 1);
        let invalid = control_diagnostics_summary(format!("{native} extra=1\n").as_bytes(), 153);
        assert!(invalid.contains("accepted_rows=0 rejected_rows=1"));
        for pid in ["132", "-1"] {
            let foreign = native.replace("pid=153", &format!("pid={pid}"));
            let summary = control_diagnostics_summary(format!("{foreign}\n").as_bytes(), 153);
            assert!(summary.contains("accepted_rows=0 rejected_rows=1"));
            assert_eq!(summary.lines().count(), 1);
        }
    }

    #[test]
    fn pending_summary_retains_original_child_and_rejects_mixed_binding_or_odd_token() {
        let row = "CRUCIBLE-CONTROL-PENDING-V1 phase=return pid=153 callback=7 raw=8 token=54008 device=1 inode=2 length=4096 slot=0 generation=2 frontier=6 capture=0 reason=pump-active\n";
        let mut bytes = row.to_owned();
        for invalid in [
            row.replace("pid=153", "pid=132"),
            row.replace("token=54008", "token=54009"),
            row.replace("device=1", "device=unavailable"),
            row.replace("capture=0", "capture=unavailable"),
            row.replace("pump-active", "invented"),
            row.trim_end().to_owned() + " extra=1\n",
        ] {
            bytes.push_str(&invalid);
        }
        let summary = control_diagnostics_summary(bytes.as_bytes(), 153);
        assert!(summary.contains("accepted_rows=1 rejected_rows=6 tail_rows=1"));
        assert!(summary.ends_with(row.trim_end()));
        let unavailable = "CRUCIBLE-CONTROL-PENDING-V1 phase=return pid=153 callback=7 raw=8 token=54008 device=unavailable inode=unavailable length=unavailable slot=unavailable generation=unavailable frontier=unavailable capture=unavailable reason=unavailable\n";
        let summary = control_diagnostics_summary(unavailable.as_bytes(), 153);
        assert!(summary.contains("accepted_rows=1 rejected_rows=0 tail_rows=1"));
        assert!(summary.ends_with(unavailable.trim_end()));
    }

    #[test]
    fn settlement_summary_keeps_exact_child_and_closed_reason_vocabulary() {
        let row = "CRUCIBLE-CONTROL-SETTLEMENT-LAST-V1 phase=after-drain teardown=host-quit pid=153 device=1 inode=2 length=4096 slot=0 generation=2 final_token=2 callback=7 raw=8 token=2 frontier=6 reason=pump-active\n";
        let unavailable = row
            .split(" callback=")
            .next()
            .unwrap_or_default()
            .to_owned()
            + " observation=unavailable\n";
        let mut bytes = format!("{row}{unavailable}");
        for bad in [
            row.replace("pid=153", "pid=132"),
            row.replace("pump-active", "invented"),
            row.replace("frontier=6", "frontier=-1"),
            row.replace(" token=2 ", " token=4294967296 "),
            row.trim_end().to_owned() + " extra=1\n",
        ] {
            bytes.push_str(&bad);
        }
        let summary = control_diagnostics_summary(bytes.as_bytes(), 153);
        assert!(summary.contains("accepted_rows=2 rejected_rows=5 tail_rows=2"));
        assert!(summary.contains("reason=pump-active"));
        assert!(summary.ends_with("observation=unavailable"));
    }

    #[test]
    fn late_native_stop_context_uses_existing_child_tail_bound() {
        let mut bytes = Vec::new();
        for generation in 0..40 {
            let row = format!(
                "CRUCIBLE-NATIVE-STOP-CONTEXT-V1 phase=stopped pid=153 gen={generation} request=7 ack=6 complete=6 state=2 runstate=4 flush=0 shutdown=0 advance=0 fd=7 scope=unavailable pc=unavailable coord=unavailable\n"
            );
            bytes.extend_from_slice(row.as_bytes());
        }
        for malformed in [
            "CRUCIBLE-NATIVE-STOP-CONTEXT-V1 phase=stopped pid=132 gen=40 request=7 ack=6 complete=6 state=2 runstate=4 flush=0 shutdown=0 advance=0 fd=7 scope=unavailable pc=unavailable coord=unavailable\n".to_owned(),
            format!("CRUCIBLE-NATIVE-STOP-CONTEXT-V1 {}\n", "x".repeat(512)),
        ] {
            bytes.extend_from_slice(malformed.as_bytes());
        }
        bytes.extend_from_slice(b"CRUCIBLE-NATIVE-STOP-CONTEXT-V1 incomplete");

        let summary = control_diagnostics_summary(&bytes, 153);
        assert!(summary.contains(
            "accepted_rows=40 rejected_rows=2 tail_rows=32 omitted_rows=8 incomplete_last_row=true"
        ));
        assert_eq!(summary.lines().count(), 33);
        assert!(
            summary
                .lines()
                .nth(1)
                .is_some_and(|row| row.contains("gen=8 "))
        );
        assert!(
            summary
                .lines()
                .last()
                .is_some_and(|row| row.contains("gen=39 "))
        );
        assert!(!summary.contains("pid=132"));
        assert!(summary.len() <= 32 * MAXIMUM_ROW_BYTES + 256);
    }
}

#[cfg(test)]
#[path = "stop_notice_tests.rs"]
mod stop_notice_tests;
