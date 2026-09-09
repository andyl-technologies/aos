//! Bounded operational diagnostics for guest-selectable resolution boundaries.

use std::fmt::{self, Write as _};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crucible_campaign::{
    AttemptId, CampaignHash, ChoiceCoordinate, ChoiceOpportunityId, ExecutionId,
};

/// Maximum configured event count emitted by one packaged executor pool.
pub const MAX_GUEST_SELECTABLE_BOUNDARY_DIAGNOSTIC_EVENTS: usize = 4_096;

const MAX_GUEST_SELECTABLE_BOUNDARY_DIAGNOSTIC_BYTES: usize = 4 * 1024;
const TRUNCATION_SUFFIX: &str = " ... event truncated";

/// Explicit shared limit for one packaged executor pool's boundary diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestSelectableBoundaryDiagnosticConfig {
    maximum_events: usize,
}

impl GuestSelectableBoundaryDiagnosticConfig {
    /// Builds an enabled diagnostic policy with a hard executor-pool event limit.
    ///
    /// # Errors
    ///
    /// Returns [`GuestSelectableBoundaryDiagnosticConfigError`] when the limit
    /// is zero or exceeds [`MAX_GUEST_SELECTABLE_BOUNDARY_DIAGNOSTIC_EVENTS`].
    pub fn new(
        maximum_events: usize,
    ) -> Result<Self, GuestSelectableBoundaryDiagnosticConfigError> {
        if maximum_events == 0 || maximum_events > MAX_GUEST_SELECTABLE_BOUNDARY_DIAGNOSTIC_EVENTS {
            return Err(GuestSelectableBoundaryDiagnosticConfigError { maximum_events });
        }

        Ok(Self { maximum_events })
    }

    /// Returns the maximum emitted event count before one truncation marker.
    #[must_use]
    pub const fn maximum_events(self) -> usize {
        self.maximum_events
    }
}

/// Invalid guest-selectable boundary diagnostic configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "guest-selectable boundary diagnostic event limit {maximum_events} is outside 1..={MAX_GUEST_SELECTABLE_BOUNDARY_DIAGNOSTIC_EVENTS}"
)]
pub struct GuestSelectableBoundaryDiagnosticConfigError {
    maximum_events: usize,
}

/// Identifies where one guest-selectable request was resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestSelectableBoundaryDiagnosticStage {
    /// Normal modeled execution discovered a new guest choice source.
    SourceDiscovery,
    /// Fresh process reconstruction replayed an authenticated selection.
    Replay,
}

impl fmt::Display for GuestSelectableBoundaryDiagnosticStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceDiscovery => formatter.write_str("source-discovery"),
            Self::Replay => formatter.write_str("replay"),
        }
    }
}

/// One typed, bounded guest-selectable resolution coordinate.
///
/// `expected_opportunity` and `expected_coordinate` are present only for replay
/// and originate from the authenticated retained selection. The other choice
/// fields originate from the single live request resolution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestSelectableBoundaryDiagnosticEvent {
    stage: GuestSelectableBoundaryDiagnosticStage,
    attempt: Option<AttemptId>,
    execution: Option<ExecutionId>,
    decision_index: usize,
    node: String,
    request_sequence: u64,
    trap_icount: u64,
    stopped_icount: u64,
    vcpu_index: u32,
    opportunity: ChoiceOpportunityId,
    coordinate: ChoiceCoordinate,
    expected_opportunity: Option<ChoiceOpportunityId>,
    expected_coordinate: Option<ChoiceCoordinate>,
}

impl GuestSelectableBoundaryDiagnosticEvent {
    /// Builds one already-validated boundary event.
    // crucible-lint: allow rust-allow -- the event keeps its complete correlation and physical coordinate explicit.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        stage: GuestSelectableBoundaryDiagnosticStage,
        attempt: Option<AttemptId>,
        execution: Option<ExecutionId>,
        decision_index: usize,
        node: impl Into<String>,
        request_sequence: u64,
        trap_icount: u64,
        stopped_icount: u64,
        vcpu_index: u32,
        opportunity: ChoiceOpportunityId,
        coordinate: ChoiceCoordinate,
        expected_opportunity: Option<ChoiceOpportunityId>,
        expected_coordinate: Option<ChoiceCoordinate>,
    ) -> Self {
        Self {
            stage,
            attempt,
            execution,
            decision_index,
            node: node.into(),
            request_sequence,
            trap_icount,
            stopped_icount,
            vcpu_index,
            opportunity,
            coordinate,
            expected_opportunity,
            expected_coordinate,
        }
    }

    /// Returns the resolution stage.
    #[must_use]
    pub const fn stage(&self) -> GuestSelectableBoundaryDiagnosticStage {
        self.stage
    }

    /// Returns the semantic attempt identity when an assignment supplied one.
    #[must_use]
    pub const fn attempt(&self) -> Option<AttemptId> {
        self.attempt
    }

    /// Returns the process-local execution incarnation when assigned.
    #[must_use]
    pub const fn execution(&self) -> Option<ExecutionId> {
        self.execution
    }

    /// Returns the configuration decision index at this boundary.
    #[must_use]
    pub const fn decision_index(&self) -> usize {
        self.decision_index
    }

    /// Returns the node that issued the request.
    #[must_use]
    pub fn node(&self) -> &str {
        &self.node
    }

    /// Returns the guest request sequence.
    #[must_use]
    pub const fn request_sequence(&self) -> u64 {
        self.request_sequence
    }

    /// Returns the semantic doorbell trap instruction count.
    #[must_use]
    pub const fn trap_icount(&self) -> u64 {
        self.trap_icount
    }

    /// Returns the exact native VM-stop instruction count.
    #[must_use]
    pub const fn stopped_icount(&self) -> u64 {
        self.stopped_icount
    }

    /// Returns the marker vCPU after topology validation.
    #[must_use]
    pub const fn vcpu_index(&self) -> u32 {
        self.vcpu_index
    }

    /// Returns the opportunity produced by live request resolution.
    #[must_use]
    pub const fn opportunity(&self) -> ChoiceOpportunityId {
        self.opportunity
    }

    /// Returns the scheduler and producer coordinate produced by resolution.
    #[must_use]
    pub const fn coordinate(&self) -> ChoiceCoordinate {
        self.coordinate
    }

    /// Returns the authenticated retained opportunity expected during replay.
    #[must_use]
    pub const fn expected_opportunity(&self) -> Option<ChoiceOpportunityId> {
        self.expected_opportunity
    }

    /// Returns the authenticated retained coordinate expected during replay.
    #[must_use]
    pub const fn expected_coordinate(&self) -> Option<ChoiceCoordinate> {
        self.expected_coordinate
    }
}

impl fmt::Display for GuestSelectableBoundaryDiagnosticEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "CRUCIBLE-GUEST-SELECTABLE-BOUNDARY-V1 stage={} attempt={} execution={} decision_index={} node={:?} request_sequence={} trap_icount={} stopped_icount={} vcpu={} opportunity={} scheduler={} producer={} expected_opportunity={} expected_scheduler={} expected_producer={}",
            self.stage,
            OptionalIdentity(self.attempt.map(|value| value.to_text())),
            OptionalExecution(self.execution),
            self.decision_index,
            self.node,
            self.request_sequence,
            self.trap_icount,
            self.stopped_icount,
            self.vcpu_index,
            self.opportunity,
            self.coordinate.scheduler,
            self.coordinate.producer,
            OptionalIdentity(self.expected_opportunity.map(|value| value.to_text())),
            OptionalHash(self.expected_coordinate.map(|value| value.scheduler)),
            OptionalHash(self.expected_coordinate.map(|value| value.producer)),
        )
    }
}

struct OptionalIdentity(Option<String>);

impl fmt::Display for OptionalIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Some(value) => formatter.write_str(value),
            None => formatter.write_str("none"),
        }
    }
}

struct OptionalHash(Option<CampaignHash>);

impl fmt::Display for OptionalHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(value) => value.fmt(formatter),
            None => formatter.write_str("none"),
        }
    }
}

struct OptionalExecution(Option<ExecutionId>);

impl fmt::Display for OptionalExecution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Some(execution) = self.0 else {
            return formatter.write_str("none");
        };
        for byte in execution.as_bytes() {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
pub(crate) struct GuestSelectableBoundaryDiagnosticRecorder {
    state: Option<Arc<GuestSelectableBoundaryDiagnosticState>>,
}

impl fmt::Debug for GuestSelectableBoundaryDiagnosticRecorder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GuestSelectableBoundaryDiagnosticRecorder")
            .field(
                "maximum_events",
                &self.state.as_ref().map(|state| state.maximum_events),
            )
            .finish_non_exhaustive()
    }
}

struct GuestSelectableBoundaryDiagnosticState {
    maximum_events: usize,
    claimed: AtomicUsize,
    destination: GuestSelectableBoundaryDiagnosticDestination,
}

enum GuestSelectableBoundaryDiagnosticDestination {
    Stderr,
    #[cfg(test)]
    Capture(Arc<std::sync::Mutex<Vec<String>>>),
    #[cfg(test)]
    Fail,
}

impl GuestSelectableBoundaryDiagnosticRecorder {
    pub(crate) const fn is_enabled(&self) -> bool {
        self.state.is_some()
    }

    pub(crate) fn stderr(config: GuestSelectableBoundaryDiagnosticConfig) -> Self {
        Self {
            state: Some(Arc::new(GuestSelectableBoundaryDiagnosticState {
                maximum_events: config.maximum_events(),
                claimed: AtomicUsize::new(0),
                destination: GuestSelectableBoundaryDiagnosticDestination::Stderr,
            })),
        }
    }

    pub(crate) fn record(&self, event: &GuestSelectableBoundaryDiagnosticEvent) {
        let Some(state) = &self.state else {
            return;
        };
        let Some(claimed) = state
            .claimed
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |claimed| {
                (claimed <= state.maximum_events).then_some(claimed + 1)
            })
            .ok()
        else {
            return;
        };

        if claimed < state.maximum_events {
            state.write_line(&bounded_event_line(event));
        } else {
            state.write_line(&format!(
                "CRUCIBLE-GUEST-SELECTABLE-BOUNDARY-V1 truncated maximum_events={}",
                state.maximum_events
            ));
        }
    }

    #[cfg(test)]
    pub(crate) fn capture(
        config: GuestSelectableBoundaryDiagnosticConfig,
    ) -> (Self, Arc<std::sync::Mutex<Vec<String>>>) {
        let lines = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = Self {
            state: Some(Arc::new(GuestSelectableBoundaryDiagnosticState {
                maximum_events: config.maximum_events(),
                claimed: AtomicUsize::new(0),
                destination: GuestSelectableBoundaryDiagnosticDestination::Capture(Arc::clone(
                    &lines,
                )),
            })),
        };
        (recorder, lines)
    }

    #[cfg(test)]
    fn failing(config: GuestSelectableBoundaryDiagnosticConfig) -> Self {
        Self {
            state: Some(Arc::new(GuestSelectableBoundaryDiagnosticState {
                maximum_events: config.maximum_events(),
                claimed: AtomicUsize::new(0),
                destination: GuestSelectableBoundaryDiagnosticDestination::Fail,
            })),
        }
    }
}

impl GuestSelectableBoundaryDiagnosticState {
    fn write_line(&self, line: &str) {
        match &self.destination {
            GuestSelectableBoundaryDiagnosticDestination::Stderr => {
                // Diagnostic write failures never change the attempt result.
                write_line_best_effort(std::io::stderr().lock(), line);
            }
            #[cfg(test)]
            GuestSelectableBoundaryDiagnosticDestination::Capture(lines) => {
                if let Ok(mut lines) = lines.lock() {
                    lines.push(line.to_owned());
                }
            }
            #[cfg(test)]
            GuestSelectableBoundaryDiagnosticDestination::Fail => {
                write_line_best_effort(FailingWriter, line);
            }
        }
    }
}

fn bounded_event_line(event: &GuestSelectableBoundaryDiagnosticEvent) -> String {
    let mut line = BoundedEventLine::new();
    let _ = write!(line, "{event}");
    line.finish()
}

fn write_line_best_effort(mut destination: impl io::Write, line: &str) {
    let _ = writeln!(destination, "{line}");
}

struct BoundedEventLine {
    line: String,
    truncated: bool,
}

impl BoundedEventLine {
    fn new() -> Self {
        Self {
            line: String::with_capacity(MAX_GUEST_SELECTABLE_BOUNDARY_DIAGNOSTIC_BYTES),
            truncated: false,
        }
    }

    fn finish(mut self) -> String {
        if !self.truncated {
            return self.line;
        }

        let retained_limit =
            MAX_GUEST_SELECTABLE_BOUNDARY_DIAGNOSTIC_BYTES - TRUNCATION_SUFFIX.len();
        let mut retained = retained_limit.min(self.line.len());
        while !self.line.is_char_boundary(retained) {
            retained -= 1;
        }
        self.line.truncate(retained);
        self.line.push_str(TRUNCATION_SUFFIX);
        self.line
    }
}

impl fmt::Write for BoundedEventLine {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        if self.truncated || value.is_empty() {
            return Ok(());
        }

        let remaining = MAX_GUEST_SELECTABLE_BOUNDARY_DIAGNOSTIC_BYTES - self.line.len();
        if value.len() <= remaining {
            self.line.push_str(value);
            return Ok(());
        }

        let mut retained = remaining;
        while !value.is_char_boundary(retained) {
            retained -= 1;
        }
        self.line.push_str(&value[..retained]);
        self.truncated = true;
        Ok(())
    }
}

#[cfg(test)]
struct FailingWriter;

#[cfg(test)]
impl io::Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("injected diagnostic write failure"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- fixture failures localize bounded diagnostic regressions.
    #![allow(clippy::expect_used)]

    use crucible_cas::content_store::{ContentId, ObjectKind};

    use super::*;

    fn opportunity(label: &[u8]) -> ChoiceOpportunityId {
        let content = ContentId::for_bytes(ObjectKind::CampaignFact, 1, label);
        ChoiceOpportunityId::parse(&format!(
            "crucible.campaign.choice-opportunity@{}",
            content.encode()
        ))
        .expect("choice opportunity")
    }

    fn event(node: impl Into<String>) -> GuestSelectableBoundaryDiagnosticEvent {
        GuestSelectableBoundaryDiagnosticEvent::new(
            GuestSelectableBoundaryDiagnosticStage::Replay,
            None,
            Some(ExecutionId::from_bytes([0x71; 16]).expect("execution")),
            12,
            node,
            34,
            56,
            57,
            2,
            opportunity(b"replayed"),
            ChoiceCoordinate {
                scheduler: CampaignHash::from_bytes([0x81; 32]),
                producer: CampaignHash::from_bytes([0x82; 32]),
            },
            Some(opportunity(b"expected")),
            Some(ChoiceCoordinate {
                scheduler: CampaignHash::from_bytes([0x91; 32]),
                producer: CampaignHash::from_bytes([0x92; 32]),
            }),
        )
    }

    #[test]
    fn configuration_rejects_zero_and_values_above_the_pool_ceiling() {
        assert!(GuestSelectableBoundaryDiagnosticConfig::new(0).is_err());
        assert!(
            GuestSelectableBoundaryDiagnosticConfig::new(
                MAX_GUEST_SELECTABLE_BOUNDARY_DIAGNOSTIC_EVENTS + 1
            )
            .is_err()
        );
        assert_eq!(
            GuestSelectableBoundaryDiagnosticConfig::new(
                MAX_GUEST_SELECTABLE_BOUNDARY_DIAGNOSTIC_EVENTS
            )
            .expect("maximum policy")
            .maximum_events(),
            MAX_GUEST_SELECTABLE_BOUNDARY_DIAGNOSTIC_EVENTS
        );
    }

    #[test]
    fn event_line_contains_both_live_and_authenticated_replay_coordinates() {
        let line = event("guest-a").to_string();

        for field in [
            "stage=replay",
            "attempt=none",
            "execution=71717171717171717171717171717171",
            "decision_index=12",
            "node=\"guest-a\"",
            "request_sequence=34",
            "trap_icount=56",
            "stopped_icount=57",
            "vcpu=2",
            "opportunity=crucible.campaign.choice-opportunity@",
            "scheduler=81818181",
            "producer=82828282",
            "expected_opportunity=crucible.campaign.choice-opportunity@",
            "expected_scheduler=91919191",
            "expected_producer=92929292",
        ] {
            assert!(line.contains(field), "missing `{field}` from `{line}`");
        }
    }

    #[test]
    fn cloned_recorders_share_one_limit_and_emit_one_truncation_marker() {
        let config = GuestSelectableBoundaryDiagnosticConfig::new(2).expect("policy");
        let (recorder, lines) = GuestSelectableBoundaryDiagnosticRecorder::capture(config);
        let clone = recorder.clone();
        let event = event("guest-a");

        recorder.record(&event);
        clone.record(&event);
        recorder.record(&event);
        clone.record(&event);

        let lines = lines.lock().expect("captured diagnostics");
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("stage=replay"));
        assert!(lines[1].contains("stage=replay"));
        assert_eq!(
            lines[2],
            "CRUCIBLE-GUEST-SELECTABLE-BOUNDARY-V1 truncated maximum_events=2"
        );
    }

    #[test]
    fn rendered_events_obey_the_byte_limit_at_a_utf8_boundary() {
        let line = bounded_event_line(&event("xé".repeat(4_096)));

        assert!(line.len() <= MAX_GUEST_SELECTABLE_BOUNDARY_DIAGNOSTIC_BYTES);
        assert!(line.ends_with(TRUNCATION_SUFFIX));
        assert!(std::str::from_utf8(line.as_bytes()).is_ok());
    }

    #[test]
    fn disabled_and_failed_diagnostic_io_leave_semantic_values_unchanged() {
        let config = GuestSelectableBoundaryDiagnosticConfig::new(1).expect("policy");
        let event = event("guest-a");
        let expected = event.clone();

        GuestSelectableBoundaryDiagnosticRecorder::default().record(&event);
        GuestSelectableBoundaryDiagnosticRecorder::failing(config).record(&event);

        assert_eq!(event, expected);
    }
}
