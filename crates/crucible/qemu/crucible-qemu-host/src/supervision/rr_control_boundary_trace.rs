//! Strict decoding for the native RR control-boundary trace.
//!
//! QEMU's log trace backend emits one fixed seven-field line for each native
//! request, acknowledgement, completion, lifecycle-cancellation, and bounded
//! control-path diagnostic transition.
//! This module accepts
//! that schema only, preserving generation, scheduler-token, and RR-state
//! evidence without interpreting arbitrary QEMU log text.

use thiserror::Error;

const EVENT_NAME: &str = "crucible_sim_rr_control_boundary";

/// One phase of the native RR control-boundary protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuRrControlBoundaryTracePhase {
    /// The main loop drained at least one byte from the plugin wake eventfd.
    WakeDrain,
    /// A durable native request was published.
    Request,
    /// A wake coalesced with an unclaimed native request.
    Coalesce,
    /// The RR owner acknowledged and scheduled the request.
    Ack,
    /// An idle futex was armed while a native request was pending.
    IdleArm,
    /// A pending native request signaled the active idle futex.
    IdleWake,
    /// The active idle futex returned while a native request was pending.
    IdleReturn,
    /// The scheduled control boundary completed.
    Complete,
    /// The plugin control callback was entered.
    CallbackEnter,
    /// Lifecycle cancellation settled an incomplete request without a callback.
    Cancel,
}

/// One strictly decoded native RR control-boundary trace row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuRrControlBoundaryTraceRecord {
    /// Protocol phase represented by this row.
    pub phase: QemuRrControlBoundaryTracePhase,
    /// Latest durably published request generation.
    pub request: u64,
    /// Latest RR-acknowledged generation.
    pub ack: u64,
    /// Latest completed generation.
    pub complete: u64,
    /// Native RR schedule token, zero before scheduling.
    pub schedule_token: u64,
    /// Native RR lifecycle-state discriminant.
    pub state: u8,
}

/// A strict native RR control-boundary trace decoding error.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum QemuRrControlBoundaryTraceError {
    /// The trace did not end at an authenticated row boundary.
    #[error("RR control-boundary trace does not end with LF")]
    Unterminated,
    /// The retained trace contained an empty line.
    #[error("RR control-boundary trace line {line} is empty")]
    EmptyLine {
        /// One-based line number.
        line: usize,
    },
    /// A line differed from the fixed seven-field schema.
    #[error("RR control-boundary trace line {line} has an invalid schema")]
    InvalidSchema {
        /// One-based line number.
        line: usize,
    },
    /// A phase value was outside the fixed lifecycle and diagnostic set.
    #[error("RR control-boundary trace line {line} has invalid phase `{value}`")]
    InvalidPhase {
        /// One-based line number.
        line: usize,
        /// Rejected phase value.
        value: String,
    },
    /// A numeric field was malformed or outside its fixed representation.
    #[error("RR control-boundary trace line {line} has invalid `{field}` value `{value}`")]
    InvalidNumber {
        /// One-based line number.
        line: usize,
        /// Rejected field name.
        field: &'static str,
        /// Rejected field value.
        value: String,
    },
}

/// Decodes a complete bounded RR control-boundary trace.
///
/// # Errors
///
/// Returns [`QemuRrControlBoundaryTraceError`] when any row differs from the
/// fixed event name, field order, phase set, decimal generation/state encoding,
/// or hexadecimal schedule-token encoding.
pub fn parse_qemu_rr_control_boundary_trace(
    trace: &str,
) -> Result<Vec<QemuRrControlBoundaryTraceRecord>, QemuRrControlBoundaryTraceError> {
    if !trace.ends_with('\n') {
        return Err(QemuRrControlBoundaryTraceError::Unterminated);
    }
    trace
        .split_terminator('\n')
        .enumerate()
        .map(|(index, row)| parse_row(index + 1, row))
        .collect()
}

fn parse_row(
    line: usize,
    row: &str,
) -> Result<QemuRrControlBoundaryTraceRecord, QemuRrControlBoundaryTraceError> {
    if row.is_empty() {
        return Err(QemuRrControlBoundaryTraceError::EmptyLine { line });
    }
    let fields = row.split(' ').collect::<Vec<_>>();
    let [event, phase, request, ack, complete, token, state] = fields.as_slice() else {
        return Err(QemuRrControlBoundaryTraceError::InvalidSchema { line });
    };
    if *event != EVENT_NAME {
        return Err(QemuRrControlBoundaryTraceError::InvalidSchema { line });
    }

    let phase = match field_value(phase, "phase", line)? {
        "wake-drain" => QemuRrControlBoundaryTracePhase::WakeDrain,
        "request" => QemuRrControlBoundaryTracePhase::Request,
        "coalesce" => QemuRrControlBoundaryTracePhase::Coalesce,
        "ack" => QemuRrControlBoundaryTracePhase::Ack,
        "idle-arm" => QemuRrControlBoundaryTracePhase::IdleArm,
        "idle-wake" => QemuRrControlBoundaryTracePhase::IdleWake,
        "idle-return" => QemuRrControlBoundaryTracePhase::IdleReturn,
        "complete" => QemuRrControlBoundaryTracePhase::Complete,
        "callback-enter" => QemuRrControlBoundaryTracePhase::CallbackEnter,
        "cancel" => QemuRrControlBoundaryTracePhase::Cancel,
        value => {
            return Err(QemuRrControlBoundaryTraceError::InvalidPhase {
                line,
                value: value.to_owned(),
            });
        }
    };
    let request = decimal_field(request, "request", line)?;
    let ack = decimal_field(ack, "ack", line)?;
    let complete = decimal_field(complete, "complete", line)?;
    let token = field_value(token, "token", line)?;
    let Some(token) = token.strip_prefix("0x") else {
        return Err(invalid_number(line, "token", token));
    };
    let schedule_token =
        u64::from_str_radix(token, 16).map_err(|_source| invalid_number(line, "token", token))?;
    let state_value = field_value(state, "state", line)?;
    let state = state_value
        .parse::<u8>()
        .map_err(|_source| invalid_number(line, "state", state_value))?;

    let record = QemuRrControlBoundaryTraceRecord {
        phase,
        request,
        ack,
        complete,
        schedule_token,
        state,
    };
    if canonical_row(record) != row {
        return Err(QemuRrControlBoundaryTraceError::InvalidSchema { line });
    }
    Ok(record)
}

fn canonical_row(record: QemuRrControlBoundaryTraceRecord) -> String {
    let phase = match record.phase {
        QemuRrControlBoundaryTracePhase::WakeDrain => "wake-drain",
        QemuRrControlBoundaryTracePhase::Request => "request",
        QemuRrControlBoundaryTracePhase::Coalesce => "coalesce",
        QemuRrControlBoundaryTracePhase::Ack => "ack",
        QemuRrControlBoundaryTracePhase::IdleArm => "idle-arm",
        QemuRrControlBoundaryTracePhase::IdleWake => "idle-wake",
        QemuRrControlBoundaryTracePhase::IdleReturn => "idle-return",
        QemuRrControlBoundaryTracePhase::Complete => "complete",
        QemuRrControlBoundaryTracePhase::CallbackEnter => "callback-enter",
        QemuRrControlBoundaryTracePhase::Cancel => "cancel",
    };
    format!(
        "{EVENT_NAME} phase={phase} request={} ack={} complete={} token=0x{:x} state={}",
        record.request, record.ack, record.complete, record.schedule_token, record.state
    )
}

fn field_value<'a>(
    field: &'a str,
    name: &'static str,
    line: usize,
) -> Result<&'a str, QemuRrControlBoundaryTraceError> {
    field
        .strip_prefix(name)
        .and_then(|suffix| suffix.strip_prefix('='))
        .filter(|value| !value.is_empty())
        .ok_or(QemuRrControlBoundaryTraceError::InvalidSchema { line })
}

fn decimal_field(
    field: &str,
    name: &'static str,
    line: usize,
) -> Result<u64, QemuRrControlBoundaryTraceError> {
    let value = field_value(field, name, line)?;
    value
        .parse::<u64>()
        .map_err(|_source| invalid_number(line, name, value))
}

fn invalid_number(
    line: usize,
    field: &'static str,
    value: &str,
) -> QemuRrControlBoundaryTraceError {
    QemuRrControlBoundaryTraceError::InvalidNumber {
        line,
        field,
        value: value.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXACT: &str = "crucible_sim_rr_control_boundary phase=request request=1 ack=0 complete=0 token=0x0 state=2\ncrucible_sim_rr_control_boundary phase=ack request=1 ack=1 complete=0 token=0x1 state=2\ncrucible_sim_rr_control_boundary phase=complete request=1 ack=1 complete=1 token=0x1 state=2\n";

    #[test]
    fn parser_accepts_exact_native_schema() {
        let rows = parse_qemu_rr_control_boundary_trace(EXACT)
            .unwrap_or_else(|error| panic!("exact trace should decode: {error}"));
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].phase, QemuRrControlBoundaryTracePhase::Request);
        assert_eq!(rows[0].state, 2);
        assert_eq!(rows[1].schedule_token, 1);
        assert_eq!(rows[2].complete, 1);
    }

    #[test]
    fn parser_accepts_lifecycle_cancellation() {
        let trace = format!(
            "{EXACT}{EVENT_NAME} phase=request request=2 ack=1 complete=1 token=0x0 state=2\n{EVENT_NAME} phase=cancel request=2 ack=2 complete=2 token=0x0 state=2\n"
        );
        let rows = parse_qemu_rr_control_boundary_trace(&trace)
            .unwrap_or_else(|error| panic!("cancellation trace should decode: {error}"));

        assert_eq!(rows.len(), 5);
        assert_eq!(rows[4].phase, QemuRrControlBoundaryTracePhase::Cancel);
        assert_eq!(rows[4].complete, 2);
    }

    #[test]
    fn parser_accepts_bounded_control_path_diagnostics() {
        let phases = [
            ("wake-drain", QemuRrControlBoundaryTracePhase::WakeDrain),
            ("coalesce", QemuRrControlBoundaryTracePhase::Coalesce),
            ("idle-arm", QemuRrControlBoundaryTracePhase::IdleArm),
            ("idle-wake", QemuRrControlBoundaryTracePhase::IdleWake),
            ("idle-return", QemuRrControlBoundaryTracePhase::IdleReturn),
            (
                "callback-enter",
                QemuRrControlBoundaryTracePhase::CallbackEnter,
            ),
        ];

        for (name, expected) in phases {
            let trace =
                format!("{EVENT_NAME} phase={name} request=1 ack=0 complete=0 token=0x0 state=5\n");
            let rows = parse_qemu_rr_control_boundary_trace(&trace)
                .unwrap_or_else(|error| panic!("diagnostic trace should decode: {error}"));

            assert_eq!(rows[0].phase, expected);
        }
    }

    #[test]
    fn parser_rejects_reordered_unknown_and_malformed_fields() {
        for trace in [
            EXACT.replace("request=1 ack=0", "ack=0 request=1"),
            EXACT.replace("phase=request", "phase=foreign"),
            EXACT.replace("token=0x0", "token=0"),
            EXACT.replacen("state=2", "state=256", 1),
            EXACT.replace(EVENT_NAME, "foreign_event"),
            EXACT.replace("phase=request ", "phase=request  "),
            EXACT.replace("phase=request ", "phase=request\t"),
            EXACT.replace("token=0x1", "token=0x01"),
            EXACT.trim_end().to_owned(),
        ] {
            assert!(parse_qemu_rr_control_boundary_trace(&trace).is_err());
        }
    }
}
