//! Strict decoding for QEMU's fixed runtime-determinism diagnostic trace.

use thiserror::Error;

const IDLE_EVENT: &str = "crucible_sim_determinism_idle";
const TIMER_EVENT: &str = "crucible_sim_determinism_timer";

/// One decoded runtime-determinism trace row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuRuntimeDeterminismTraceRecord {
    /// A plugin-owned idle-time advance transition.
    Idle(QemuRuntimeDeterminismIdleRecord),
    /// A due `QEMU_CLOCK_VIRTUAL` callback.
    Timer(QemuRuntimeDeterminismTimerRecord),
}

impl QemuRuntimeDeterminismTraceRecord {
    /// Returns the process-global trace sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        match self {
            Self::Idle(record) => record.sequence,
            Self::Timer(record) => record.sequence,
        }
    }

    /// Returns the raw retired-instruction count sampled by QEMU.
    #[must_use]
    pub const fn raw_icount(self) -> u64 {
        match self {
            Self::Idle(record) => record.raw_icount,
            Self::Timer(record) => record.raw_icount,
        }
    }
}

/// Phase of one plugin-owned idle-time advance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuRuntimeDeterminismIdlePhase {
    /// The plugin published an advance request.
    Request,
    /// The completion bottom half committed the plugin-visible logical time.
    Complete,
}

/// One native idle-time advance trace row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuRuntimeDeterminismIdleRecord {
    /// Advance phase.
    pub phase: QemuRuntimeDeterminismIdlePhase,
    /// Process-global trace sequence.
    pub sequence: u64,
    /// Raw retired-instruction count.
    pub raw_icount: u64,
    /// Current QEMU virtual time in picoseconds.
    pub virtual_ps: i64,
    /// Requested logical simulation tick in picoseconds.
    pub target_tick: i64,
    /// Earliest virtual deadline, or `-1` when none is armed.
    pub deadline_ps: i64,
    /// RR owner index, or `u64::MAX` when no RR CPU owns the boundary.
    pub rr_owner: u64,
    /// Position within the RR quantum.
    pub rr_cursor: u64,
    /// Realized CPU count.
    pub cpu_count: u32,
    /// Halted-CPU bitmap.
    pub halted: u64,
    /// Pending vCPU-work bitmap.
    pub work: u64,
    /// Exit-request bitmap.
    pub exit: u64,
    /// Interrupt-request bitmap.
    pub interrupt: u64,
    /// Stop-request bitmap.
    pub stop: u64,
    /// Native RR execution-state value.
    pub state: u8,
}

/// QEMU timer-list scope for a due virtual timer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuRuntimeDeterminismTimerScope {
    /// The global main-loop timer list.
    Global,
    /// An AioContext-owned timer list.
    Aio,
}

/// Thread-class owner of a due virtual timer callback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuRuntimeDeterminismTimerOwner {
    /// The serialized RR vCPU thread.
    Rr,
    /// A non-vCPU host thread.
    Host,
}

/// One due virtual-timer callback trace row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuRuntimeDeterminismTimerRecord {
    /// Process-global trace sequence.
    pub sequence: u64,
    /// Pointer-free timer allocation identity.
    pub timer: u64,
    /// Pointer-free timer-list allocation identity.
    pub list: u64,
    /// Timer-list ownership class.
    pub scope: QemuRuntimeDeterminismTimerScope,
    /// Callback thread class.
    pub owner: QemuRuntimeDeterminismTimerOwner,
    /// Timer expiry in virtual picoseconds.
    pub expire_ps: i64,
    /// Current virtual time in picoseconds.
    pub current_ps: i64,
    /// Raw retired-instruction count.
    pub raw_icount: u64,
}

/// A strict runtime-determinism trace decoding error.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum QemuRuntimeDeterminismTraceError {
    /// The trace did not end at an authenticated row boundary.
    #[error("runtime-determinism trace does not end with LF")]
    Unterminated,
    /// A row differed from one of the two fixed schemas.
    #[error("runtime-determinism trace line {line} has an invalid schema")]
    InvalidSchema {
        /// One-based line number.
        line: usize,
    },
    /// A field used a noncanonical value.
    #[error("runtime-determinism trace line {line} has invalid `{field}` value `{value}`")]
    InvalidValue {
        /// One-based line number.
        line: usize,
        /// Rejected field name.
        field: &'static str,
        /// Rejected field value.
        value: String,
    },
    /// Process-global sequence values were not contiguous from one.
    #[error("runtime-determinism trace line {line} sequence {current} did not follow {previous}")]
    NonContiguousSequence {
        /// One-based line number.
        line: usize,
        /// Prior row sequence.
        previous: u64,
        /// Current row sequence.
        current: u64,
    },
    /// Idle-advance rows did not form exact request/complete pairs.
    #[error("runtime-determinism trace line {line} violates idle phase order")]
    InvalidIdleSequence {
        /// One-based line number, or the line after EOF for an incomplete pair.
        line: usize,
    },
}

/// Decodes a complete fixed runtime-determinism trace.
///
/// # Errors
///
/// Returns [`QemuRuntimeDeterminismTraceError`] for a torn row, noncanonical
/// whitespace or number, unknown field/enum value, a host-owned global timer,
/// noncontiguous sequence, or an incomplete idle request/completion pair.
pub fn parse_qemu_runtime_determinism_trace(
    trace: &str,
) -> Result<Vec<QemuRuntimeDeterminismTraceRecord>, QemuRuntimeDeterminismTraceError> {
    if !trace.ends_with('\n') {
        return Err(QemuRuntimeDeterminismTraceError::Unterminated);
    }

    let mut previous: Option<u64> = None;
    let records = trace
        .split_terminator('\n')
        .enumerate()
        .map(|(index, row)| {
            let line = index + 1;
            let record = parse_row(line, row)?;
            let current = record.sequence();
            let follows =
                previous.map_or(current == 1, |prior| prior.checked_add(1) == Some(current));
            if !follows {
                return Err(QemuRuntimeDeterminismTraceError::NonContiguousSequence {
                    line,
                    previous: previous.unwrap_or(0),
                    current,
                });
            }
            previous = Some(current);
            Ok(record)
        })
        .collect::<Result<Vec<_>, _>>()?;
    validate_idle_sequences(&records)?;
    Ok(records)
}

fn validate_idle_sequences(
    records: &[QemuRuntimeDeterminismTraceRecord],
) -> Result<(), QemuRuntimeDeterminismTraceError> {
    let mut pending = None;
    for (index, record) in records.iter().enumerate() {
        let QemuRuntimeDeterminismTraceRecord::Idle(record) = record else {
            continue;
        };
        pending = match (pending, record.phase) {
            (None, QemuRuntimeDeterminismIdlePhase::Request) => Some(record.target_tick),
            (Some(target), QemuRuntimeDeterminismIdlePhase::Complete)
                if record.target_tick == target =>
            {
                None
            }
            _ => {
                return Err(QemuRuntimeDeterminismTraceError::InvalidIdleSequence {
                    line: index + 1,
                });
            }
        };
    }
    if pending.is_some() {
        return Err(QemuRuntimeDeterminismTraceError::InvalidIdleSequence {
            line: records.len() + 1,
        });
    }
    Ok(())
}

fn parse_row(
    line: usize,
    row: &str,
) -> Result<QemuRuntimeDeterminismTraceRecord, QemuRuntimeDeterminismTraceError> {
    let event = row.split(' ').next().unwrap_or_default();
    if event == IDLE_EVENT {
        parse_idle(line, row)
    } else if event == TIMER_EVENT {
        parse_timer(line, row)
    } else {
        Err(QemuRuntimeDeterminismTraceError::InvalidSchema { line })
    }
}

fn parse_idle(
    line: usize,
    row: &str,
) -> Result<QemuRuntimeDeterminismTraceRecord, QemuRuntimeDeterminismTraceError> {
    let fields = row.split(' ').collect::<Vec<_>>();
    let [
        event,
        phase,
        seq,
        raw,
        virtual_ps,
        target_tick,
        deadline_ps,
        rr_owner,
        rr_cursor,
        cpu_count,
        halted,
        work,
        exit,
        interrupt,
        stop,
        state,
    ] = fields.as_slice()
    else {
        return Err(QemuRuntimeDeterminismTraceError::InvalidSchema { line });
    };
    if *event != IDLE_EVENT {
        return Err(QemuRuntimeDeterminismTraceError::InvalidSchema { line });
    }
    let phase = match field(phase, "phase", line)? {
        "request" => QemuRuntimeDeterminismIdlePhase::Request,
        "complete" => QemuRuntimeDeterminismIdlePhase::Complete,
        value => return Err(invalid(line, "phase", value)),
    };
    let record = QemuRuntimeDeterminismIdleRecord {
        phase,
        sequence: decimal(seq, "seq", line)?,
        raw_icount: decimal(raw, "raw", line)?,
        virtual_ps: signed(virtual_ps, "virtual_ps", line)?,
        target_tick: signed(target_tick, "target_tick", line)?,
        deadline_ps: signed(deadline_ps, "deadline_ps", line)?,
        rr_owner: decimal(rr_owner, "rr_owner", line)?,
        rr_cursor: decimal(rr_cursor, "rr_cursor", line)?,
        cpu_count: decimal(cpu_count, "cpu_count", line)?,
        halted: hexadecimal(halted, "halted", line)?,
        work: hexadecimal(work, "work", line)?,
        exit: hexadecimal(exit, "exit", line)?,
        interrupt: hexadecimal(interrupt, "interrupt", line)?,
        stop: hexadecimal(stop, "stop", line)?,
        state: decimal(state, "state", line)?,
    };
    if record.cpu_count == 0 || record.cpu_count > 64 {
        return Err(QemuRuntimeDeterminismTraceError::InvalidSchema { line });
    }
    let valid_cpu_mask = if record.cpu_count == 64 {
        u64::MAX
    } else {
        (1_u64 << record.cpu_count) - 1
    };
    if record.sequence == 0
        || record.target_tick < 0
        || record.virtual_ps < 0
        || record.deadline_ps < -1
        || record.halted & !valid_cpu_mask != 0
        || record.work & !valid_cpu_mask != 0
        || record.exit & !valid_cpu_mask != 0
        || record.interrupt & !valid_cpu_mask != 0
        || record.stop & !valid_cpu_mask != 0
        || record.state > 6
        || canonical_idle(record) != row
    {
        return Err(QemuRuntimeDeterminismTraceError::InvalidSchema { line });
    }
    Ok(QemuRuntimeDeterminismTraceRecord::Idle(record))
}

fn parse_timer(
    line: usize,
    row: &str,
) -> Result<QemuRuntimeDeterminismTraceRecord, QemuRuntimeDeterminismTraceError> {
    let fields = row.split(' ').collect::<Vec<_>>();
    let [
        event,
        seq,
        timer,
        list,
        scope,
        owner,
        expire_ps,
        current_ps,
        raw,
    ] = fields.as_slice()
    else {
        return Err(QemuRuntimeDeterminismTraceError::InvalidSchema { line });
    };
    if *event != TIMER_EVENT {
        return Err(QemuRuntimeDeterminismTraceError::InvalidSchema { line });
    }
    let scope = match field(scope, "scope", line)? {
        "global" => QemuRuntimeDeterminismTimerScope::Global,
        "aio" => QemuRuntimeDeterminismTimerScope::Aio,
        value => return Err(invalid(line, "scope", value)),
    };
    let owner = match field(owner, "owner", line)? {
        "rr" => QemuRuntimeDeterminismTimerOwner::Rr,
        "host" => QemuRuntimeDeterminismTimerOwner::Host,
        value => return Err(invalid(line, "owner", value)),
    };
    let record = QemuRuntimeDeterminismTimerRecord {
        sequence: decimal(seq, "seq", line)?,
        timer: decimal(timer, "timer", line)?,
        list: decimal(list, "list", line)?,
        scope,
        owner,
        expire_ps: signed(expire_ps, "expire_ps", line)?,
        current_ps: signed(current_ps, "current_ps", line)?,
        raw_icount: decimal(raw, "raw", line)?,
    };
    if record.sequence == 0
        || record.timer == 0
        || record.list == 0
        || (record.scope == QemuRuntimeDeterminismTimerScope::Global
            && record.owner != QemuRuntimeDeterminismTimerOwner::Rr)
        || canonical_timer(record) != row
    {
        return Err(QemuRuntimeDeterminismTraceError::InvalidSchema { line });
    }
    Ok(QemuRuntimeDeterminismTraceRecord::Timer(record))
}

fn canonical_idle(record: QemuRuntimeDeterminismIdleRecord) -> String {
    let phase = match record.phase {
        QemuRuntimeDeterminismIdlePhase::Request => "request",
        QemuRuntimeDeterminismIdlePhase::Complete => "complete",
    };
    format!(
        "{IDLE_EVENT} phase={phase} seq={} raw={} virtual_ps={} target_tick={} deadline_ps={} rr_owner={} rr_cursor={} cpu_count={} halted={:#x} work={:#x} exit={:#x} interrupt={:#x} stop={:#x} state={}",
        record.sequence,
        record.raw_icount,
        record.virtual_ps,
        record.target_tick,
        record.deadline_ps,
        record.rr_owner,
        record.rr_cursor,
        record.cpu_count,
        record.halted,
        record.work,
        record.exit,
        record.interrupt,
        record.stop,
        record.state,
    )
}

fn canonical_timer(record: QemuRuntimeDeterminismTimerRecord) -> String {
    let scope = match record.scope {
        QemuRuntimeDeterminismTimerScope::Global => "global",
        QemuRuntimeDeterminismTimerScope::Aio => "aio",
    };
    let owner = match record.owner {
        QemuRuntimeDeterminismTimerOwner::Rr => "rr",
        QemuRuntimeDeterminismTimerOwner::Host => "host",
    };
    format!(
        "{TIMER_EVENT} seq={} timer={} list={} scope={scope} owner={owner} expire_ps={} current_ps={} raw={}",
        record.sequence,
        record.timer,
        record.list,
        record.expire_ps,
        record.current_ps,
        record.raw_icount,
    )
}

fn field<'a>(
    value: &'a str,
    name: &'static str,
    line: usize,
) -> Result<&'a str, QemuRuntimeDeterminismTraceError> {
    value
        .strip_prefix(name)
        .and_then(|value| value.strip_prefix('='))
        .ok_or(QemuRuntimeDeterminismTraceError::InvalidSchema { line })
}

fn decimal<T>(
    value: &str,
    name: &'static str,
    line: usize,
) -> Result<T, QemuRuntimeDeterminismTraceError>
where
    T: std::str::FromStr + ToString,
{
    let value = field(value, name, line)?;
    let parsed = value
        .parse::<T>()
        .map_err(|_source| invalid(line, name, value))?;
    if parsed.to_string() != value {
        return Err(invalid(line, name, value));
    }
    Ok(parsed)
}

fn signed(
    value: &str,
    name: &'static str,
    line: usize,
) -> Result<i64, QemuRuntimeDeterminismTraceError> {
    decimal(value, name, line)
}

fn hexadecimal(
    value: &str,
    name: &'static str,
    line: usize,
) -> Result<u64, QemuRuntimeDeterminismTraceError> {
    let value = field(value, name, line)?;
    let digits = value
        .strip_prefix("0x")
        .ok_or_else(|| invalid(line, name, value))?;
    let parsed = u64::from_str_radix(digits, 16).map_err(|_source| invalid(line, name, value))?;
    if format!("{parsed:#x}") != value {
        return Err(invalid(line, name, value));
    }
    Ok(parsed)
}

fn invalid(line: usize, field: &'static str, value: &str) -> QemuRuntimeDeterminismTraceError {
    QemuRuntimeDeterminismTraceError::InvalidValue {
        line,
        field,
        value: value.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXACT: &str = concat!(
        "crucible_sim_determinism_idle phase=request seq=1 raw=8000000 virtual_ps=400000000 target_tick=400001000 deadline_ps=400000500 rr_owner=2 rr_cursor=17 cpu_count=4 halted=0xf work=0x0 exit=0x0 interrupt=0x0 stop=0x0 state=2\n",
        "crucible_sim_determinism_timer seq=2 timer=31 list=2 scope=global owner=rr expire_ps=400000500 current_ps=400000500 raw=8000000\n",
        "crucible_sim_determinism_idle phase=complete seq=3 raw=8000000 virtual_ps=400001000 target_tick=400001000 deadline_ps=-1 rr_owner=18446744073709551615 rr_cursor=17 cpu_count=4 halted=0xe work=0x0 exit=0x0 interrupt=0x4 stop=0x0 state=2\n",
    );

    #[test]
    fn exact_trace_decodes_all_fixed_rows() {
        let records = parse_qemu_runtime_determinism_trace(EXACT)
            .unwrap_or_else(|error| panic!("fixed trace should decode: {error}"));

        assert_eq!(records.len(), 3);
        assert_eq!(records[0].sequence(), 1);
        assert_eq!(records[1].raw_icount(), 8_000_000);
    }

    #[test]
    fn exact_trace_accepts_the_genesis_rr_cursor() {
        let trace = EXACT.replace("rr_cursor=17", "rr_cursor=0");
        let records = parse_qemu_runtime_determinism_trace(&trace)
            .unwrap_or_else(|error| panic!("zero is a valid RR cursor: {error}"));

        assert!(records.iter().all(|record| match record {
            QemuRuntimeDeterminismTraceRecord::Idle(record) => record.rr_cursor == 0,
            QemuRuntimeDeterminismTraceRecord::Timer(_) => true,
        }));
    }

    #[test]
    fn exact_trace_preserves_subnanosecond_timer_time() {
        let trace = EXACT.replace(
            "expire_ps=400000500 current_ps=400000500",
            "expire_ps=400000501 current_ps=400000501",
        );
        let records = parse_qemu_runtime_determinism_trace(&trace)
            .unwrap_or_else(|error| panic!("picosecond timer should decode: {error}"));

        let QemuRuntimeDeterminismTraceRecord::Timer(timer) = records[1] else {
            panic!("second row should be a timer");
        };
        assert_eq!(timer.expire_ps, 400_000_501);
    }

    #[test]
    fn trace_rejects_torn_noncanonical_and_nonmonotonic_rows() {
        for trace in [
            EXACT.trim_end().to_owned(),
            EXACT.replace("seq=2", "seq=1"),
            EXACT.replace("raw=8000000", "raw=08000000"),
            EXACT.replace("halted=0xf", "halted=0x0f"),
            EXACT.replace(" phase=", "  phase="),
            EXACT.replace("scope=global", "scope=other"),
            EXACT.replace("scope=global owner=rr", "scope=global owner=host"),
            EXACT.replace("halted=0xf", "halted=0x10"),
            EXACT.replace("phase=request", "phase=complete"),
            EXACT.replacen("target_tick=400001000", "target_tick=400001001", 1),
            EXACT.replace("virtual_ps=400000000", "virtual_ns=400000000"),
        ] {
            assert!(parse_qemu_runtime_determinism_trace(&trace).is_err());
        }
    }
}
