//! Console matchers report a match at the evaluation point of its batch.
//!
//! Native console bytes keep their emission time, while the scheduler
//! evaluates each quantum at the evaluation boundary that closes it. These
//! tests pin that a match ending anywhere in a quantum is reported at that
//! boundary, and that every way of rebuilding matcher state agrees with the
//! incrementally appended prefix.

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const PATTERN: &str = "ok";

fn guest() -> NodeId {
    NodeId {
        name: String::from("guest"),
    }
}

/// Builds the `sequence`th log entry: one native console byte emitted at `at`.
fn native_byte(sequence: u64, at: u64, byte: u8) -> TestResult<SchedulerEventLogEntry> {
    let event = ObservableEvent::native_console_byte(
        VirtualTime { ticks: at },
        guest(),
        crate::NativeConsoleByteOrigin {
            device: ContentHash { bytes: [9; 32] },
            stream: 7,
            logical_generation: 0,
            node_sequence: sequence + 1,
            stream_sequence: sequence + 1,
            emitted_ps: at,
            raw_prefix: 0,
            vcpu: 0,
            byte,
        },
    )?;
    Ok(SchedulerEventLogEntry::with_payload_for_test(
        sequence,
        event.at(),
        SchedulerEventLogPayload::Observable(event.payload().clone()),
    ))
}

fn boundary(sequence: u64, at: u64) -> SchedulerEventLogEntry {
    SchedulerEventLogEntry::evaluation_boundary(
        sequence,
        VirtualTime { ticks: at },
        SchedulerEvaluationBoundaryKind::Quantum,
    )
}

fn console_match() -> Predicate {
    Predicate::console_match(guest(), RegexProgram::from_pattern(PATTERN))
}

/// Evaluates `console_match` at the prefix's own evaluation point.
fn matches_at_point(prefix: &ConditionEventLogPrefix) -> TestResult<bool> {
    let mut pass =
        ConditionEvaluationPass::from_log_prefix_ref(prefix, |_: ConditionLeaf<'_>| false);
    Ok(pass.evaluate_assertion_condition(&console_match())?)
}

fn declared_genesis() -> TestResult<ConditionEventLogPrefix> {
    let mut prefix = ConditionEventLogPrefix::genesis();
    prefix.declare_console_pattern(&guest(), PATTERN)?;
    Ok(prefix)
}

#[test]
fn native_console_match_is_true_at_the_boundary_that_closes_its_batch() -> TestResult {
    let mut prefix = declared_genesis()?;

    // One quantum: the pattern completes at t=100 and the frontier is t=200.
    prefix.append_entries(vec![
        native_byte(0, 100, b'o')?,
        native_byte(1, 100, b'k')?,
        boundary(2, 200),
    ])?;
    assert_eq!(prefix.point().at(), VirtualTime { ticks: 200 });
    assert!(matches_at_point(&prefix)?);

    // The next quantum prints nothing new, so the leaf is false again.
    prefix.append_entries(vec![boundary(3, 300)])?;
    assert!(!matches_at_point(&prefix)?);
    Ok(())
}

/// Three quanta; the pattern completes in the second, at t=160.
fn quantum_log() -> TestResult<Vec<SchedulerEventLogEntry>> {
    Ok(vec![
        native_byte(0, 50, b'x')?,
        boundary(1, 100),
        native_byte(2, 150, b'o')?,
        native_byte(3, 160, b'k')?,
        boundary(4, 200),
        native_byte(5, 250, b'z')?,
        boundary(6, 300),
    ])
}

/// Entry counts at which each live quantum append ends.
const QUANTUM_ENDS: [usize; 3] = [2, 5, 7];

/// Appends `log` one quantum at a time, keeping the prefix after each append.
fn appended_quanta(log: &[SchedulerEventLogEntry]) -> TestResult<Vec<ConditionEventLogPrefix>> {
    let mut prefix = declared_genesis()?;
    let mut appended = Vec::new();
    let mut start = 0;
    for end in QUANTUM_ENDS {
        prefix.append_entries(log[start..end].to_vec())?;
        appended.push(prefix.clone());
        start = end;
    }
    Ok(appended)
}

/// Round-trips matcher states through their canonical checkpoint encoding.
fn checkpointed(
    folds: &ConsoleMatchFolds,
    declarations: &ConsoleMatchFolds,
) -> TestResult<ConsoleMatchFolds> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&folds.to_wire(), &mut bytes)?;
    let wire: Vec<ConsoleMatchStateWire> = ciborium::de::from_reader(bytes.as_slice())?;
    declarations
        .restored_from(&wire)
        .ok_or_else(|| "checkpointed matchers did not restore".into())
}

/// Rebuilds the prefix at quantum `index` every way the crate rebuilds one.
fn rebuilt_prefixes(
    log: &[SchedulerEventLogEntry],
    appended: &[ConditionEventLogPrefix],
    index: usize,
) -> TestResult<Vec<(&'static str, ConditionEventLogPrefix)>> {
    let end = QUANTUM_ENDS[index];
    let live = &appended[index];
    let latest = appended.last().ok_or("no quanta appended")?;
    let mut rebuilt = Vec::new();

    let mut declared_late =
        ConditionEventLogPrefix::from_scheduler_event_log_entries(log[..end].to_vec())?;
    declared_late.declare_console_pattern(&guest(), PATTERN)?;
    rebuilt.push(("declared over history", declared_late));

    let rewound = latest
        .with_facts_through_point(live.point())
        .ok_or("rewind refused")?;
    rebuilt.push(("refolded on rewind", rewound));

    let earlier = index.checked_sub(1).map(|earlier| &appended[earlier]);
    let continued = latest
        .with_facts_through_point_after(earlier, live.point())
        .ok_or("continued rewind refused")?;
    rebuilt.push(("continued from an earlier prefix", continued));

    let matchers = live.console_folds.refold(std::iter::empty());
    let refolded = ConditionEventLogPrefix::from_scheduler_event_log_entries(log[..end].to_vec())?
        .with_console_matchers(&matchers);
    rebuilt.push(("refolded from scratch", refolded));

    // Checkpoint restore cuts history at every running time maximum, so a
    // quantum may arrive as several smaller appends.
    let mut entry_by_entry = declared_genesis()?;
    for entry in &log[..end] {
        entry_by_entry.append_entries(vec![entry.clone()])?;
    }
    rebuilt.push(("appended entry by entry", entry_by_entry));

    let mut restored =
        ConditionEventLogPrefix::from_scheduler_event_log_entries(log[..end].to_vec())?;
    restored.console_folds = checkpointed(&live.console_folds, &matchers)?;
    rebuilt.push(("restored from a checkpoint", restored));

    Ok(rebuilt)
}

fn assert_rebuilds_agree(index: usize, expected: bool) -> TestResult {
    let log = quantum_log()?;
    let appended = appended_quanta(&log)?;
    let live = &appended[index];
    assert_eq!(matches_at_point(live)?, expected);

    for (how, prefix) in rebuilt_prefixes(&log, &appended, index)? {
        assert_eq!(prefix.point().at(), live.point().at(), "{how}");
        assert_eq!(prefix.console_folds, live.console_folds, "{how}");
        assert_eq!(matches_at_point(&prefix)?, expected, "{how}");
    }
    Ok(())
}

#[test]
fn rebuilt_matchers_agree_with_appends_before_any_match() -> TestResult {
    assert_rebuilds_agree(0, false)
}

#[test]
fn rebuilt_matchers_agree_with_appends_for_a_match_in_the_current_batch() -> TestResult {
    assert_rebuilds_agree(1, true)
}

#[test]
fn rebuilt_matchers_agree_with_appends_for_a_match_in_an_earlier_batch() -> TestResult {
    assert_rebuilds_agree(2, false)
}

#[test]
fn a_match_checkpointed_before_its_boundary_is_reported_at_that_boundary() -> TestResult {
    let log = quantum_log()?;

    // Stop after the byte completing the match, before its boundary.
    let mut live = declared_genesis()?;
    live.append_entries(log[..4].to_vec())?;
    assert!(
        matches_at_point(&live)?,
        "pending match at its own byte time"
    );

    let mut restored =
        ConditionEventLogPrefix::from_scheduler_event_log_entries(log[..4].to_vec())?;
    let declarations = live.console_folds.refold(std::iter::empty());
    restored.console_folds = checkpointed(&live.console_folds, &declarations)?;
    assert_eq!(restored.console_folds, live.console_folds);

    for prefix in [&mut live, &mut restored] {
        prefix.append_entries(vec![log[4].clone()])?;
        assert!(matches_at_point(prefix)?);
        prefix.append_entries(log[5..].to_vec())?;
        assert!(!matches_at_point(prefix)?);
    }
    assert_eq!(restored.console_folds, live.console_folds);
    Ok(())
}

#[test]
fn closed_matcher_states_keep_their_earlier_checkpoint_encoding() -> TestResult {
    let log = quantum_log()?;
    let mut prefix = declared_genesis()?;

    prefix.append_entries(log[..4].to_vec())?;
    let mut pending = Vec::new();
    ciborium::ser::into_writer(&prefix.console_folds.to_wire(), &mut pending)?;
    prefix.append_entries(vec![log[4].clone()])?;
    let mut closed = Vec::new();
    ciborium::ser::into_writer(&prefix.console_folds.to_wire(), &mut closed)?;

    let names_pending = |bytes: &[u8]| {
        bytes
            .windows(b"match_pending".len())
            .any(|window| window == b"match_pending")
    };
    assert!(names_pending(&pending));
    assert!(!names_pending(&closed));
    Ok(())
}

#[test]
fn a_pending_match_without_its_time_is_refused_on_restore() -> TestResult {
    let mut prefix = declared_genesis()?;
    let mut wire = prefix.console_folds.to_wire();
    let Some(state) = wire.first_mut() else {
        return Err("no declared matcher".into());
    };
    state.match_pending = true;
    assert_eq!(prefix.console_folds.restored_from(&wire), None);

    if let Some(state) = wire.first_mut() {
        state.last_match_at = Some(VirtualTime { ticks: 1 });
    }
    prefix.console_folds = prefix
        .console_folds
        .restored_from(&wire)
        .ok_or("pending match with its time refused")?;
    prefix.append_entries(vec![boundary(0, 5)])?;
    assert!(matches_at_point(&prefix)?);
    Ok(())
}
