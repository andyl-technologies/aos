//! Executes the installed portless Clock's original qualification programme.
//!
//! Every case uses the real HostModelNode and common runtime scheduler. This
//! owner retains the same activation, original tokens, expected native bodies
//! and observed bodies through failures. Normal class acceptance is supplied by
//! the separate complete installed witness population; constructing this owner
//! alone issues no Accepted report or provider registration.

mod admission_cases;
mod adverse;
mod failures;
pub use admission_cases::ClockAdmissionObservationData;
pub use adverse::OriginalClockAdverseWitness;
pub use failures::OriginalClockFailureWitness;
mod oracle;
mod pause;
pub(super) mod profile;
pub use profile::InstalledNormalClockProfile;
mod source;
mod state;
mod state_programme;
mod state_witness;
pub use state_witness::{ClockStateObservationData, OriginalClockStateWitness};
mod state_staging;
pub use state::InstalledNormalClockStateFactory;
pub use state_programme::OriginalClockStateProgramme;

mod programme;
pub use programme::NormalClockProgramme;

#[cfg(test)]
mod tests;

use std::{
    path::PathBuf,
    task::{Context, Poll, Waker},
    thread::ThreadId,
};

use crucible_campaign::ExecutionId;
use crucible_engine::{
    node_admission::AdmittedGraph,
    node_contract::{
        ActivationPublisher, BeginResult, ExactBoundaryPolicy,
        MAXIMUM_ACTIVATION_COORDINATOR_BYTES, NodeRuntime, OperationOutcome, OperationRequest,
        OperationToken, OwnerIdentity, ProgressEvidence, StopReason, WorldActivation,
    },
    node_scheduling::InputPayload,
};
use crucible_node_format::{ContentRef, Id, Phase, Position, U64, canonical};

use super::{
    InstalledNodeCatalog, InstalledNodeKind, InstalledNodeSelection, InstalledPreparedWorld,
    NodeObservedError, measure_executable, refused,
};
use crate::node_qualification::{
    ExactCompletionCase, ExactCompletionObservation, ProductionConformanceRunner,
    QualificationError,
};

use oracle::ExpectedClockCase;

const CASES: [(&str, u64, bool); 4] = [
    ("clock/one-ps", 1, false),
    ("clock/fractional-ns", 1001, false),
    ("clock/same-instant-settle", 1001, true),
    ("clock/after-settlement", 1_000_001, false),
];
const MAXIMUM_CASE_BYTES: usize = 16 * 1024;

struct ClockCase {
    name: &'static str,
    operation: Id,
    expected: ExpectedClockCase,
    oracle: InputPayload,
    attempted: bool,
    token: Option<OperationToken>,
    objects: Option<Vec<InputPayload>>,
    acknowledged: bool,
    collected: bool,
}

/// Owns one real installed Clock and its nonreplaceable source programme.
///
/// No constructor accepts observed outcomes, successful claim bytes, a caller
/// model, a replacement runtime or a supplied acceptance policy. Every semantic
/// case is attempted once; a failed case blocks subsequent dispatch.
#[must_use = "retain the original Clock runtime and its evidence through refusal"]
pub struct OriginalClockQualificationRun {
    graph: AdmittedGraph,
    scenario: crate::node_scenario::NodeScenario,
    runtime: Option<NodeRuntime>,
    retired: Option<crucible_engine::node_contract::QuarantinedRuntime>,
    captured: Option<crucible_engine::node_state::NativeArchiveRecord>,
    capture_attempted: bool,
    retirement_attempted: bool,
    activation: Option<WorldActivation>,
    proposal: crucible_engine::node_contract::ActivationRecord,
    origin: ClockOrigin,
    source_lifetime: std::rc::Rc<()>,
    node: Id,
    cases: Vec<ClockCase>,
    pause: pause::OriginalClockPause,
    admission_cases: admission_cases::OriginalClockAdmissionCases,
    next: usize,
    failed: bool,
    arm_attempted: bool,
}

#[derive(Clone)]
struct ClockOrigin {
    source: ContentRef,
    source_path: PathBuf,
    process: u32,
    thread: ThreadId,
}

impl ClockOrigin {
    fn current(&self) -> Result<(), NodeObservedError> {
        // Reject origin before opening or hashing an executable on another thread.
        if std::process::id() != self.process || std::thread::current().id() != self.thread {
            return Err(refused(
                "Clock qualification original process/thread changed",
            ));
        }
        if measure_executable(&self.source_path)? != self.source {
            return Err(refused("Clock qualification original executable changed"));
        }
        Ok(())
    }
}

impl InstalledNodeCatalog {
    /// Prepares the actual source-installed Clock before normal witness collection.
    ///
    /// This distinct entry uses the existing closed Clock source admission and
    /// unchanged model implementation. It cannot install a normal class policy
    /// or bypass a previously installed behavioral gate.
    ///
    /// # Errors
    /// Refuses another node family, unavailable source/native ownership, changed
    /// installation or original scenario, and exhausted preparation capacity.
    pub fn prepare_original_clock_qualification(
        &mut self,
        profile: &InstalledNormalClockProfile,
        execution: ExecutionId,
    ) -> Result<OriginalClockQualificationRun, NodeObservedError> {
        let node = profile.selection.node.clone();
        let source = self.host_identity.clone();
        if measure_executable(&self.host_executable)? != source {
            return Err(refused(
                "Clock qualification host source changed before preparation",
            ));
        }
        let InstalledPreparedWorld {
            graph,
            realization,
            scenario,
        } = self.prepare_normal_clock_world(profile, execution)?;
        let proposal = realization.activation_record().clone();
        let owners = proposal.owners.clone();
        let mut cases = Vec::new();
        cases
            .try_reserve_exact(CASES.len())
            .map_err(|_| refused("Clock qualification case reservation failed"))?;
        let mut start = proposal.boundary;
        for (name, time, settle) in CASES {
            let limit = Position::new(
                U64::new(time),
                U64::new(if settle { 1 } else { 0 }),
                Phase::BoundaryControl,
            );
            let operation = Id::new(name)?;
            let expected =
                ExpectedClockCase::new(&node, &owners, &operation, start, limit, settle)?;
            let oracle_bytes = canonical::canonical_json(&serde_json::json!({
                "schema":"crucible.normal-clock-case/1", "host":source,
                "case":name,"request":expected.request,"outcome":expected.outcome,
                "objects":expected.objects,
            }))?;
            let oracle = InputPayload {
                reference: canonical::content_ref(&oracle_bytes, "application/json")?,
                bytes: oracle_bytes,
            };
            cases.push(ClockCase {
                name,
                operation,
                expected,
                oracle,
                attempted: false,
                token: None,
                objects: None,
                acknowledged: false,
                collected: false,
            });
            start = limit;
        }
        let runtime = realization
            .admit(&graph)
            .map_err(|failure| super::native(&failure.error))?;
        let pause = pause::OriginalClockPause::new(&node, &proposal.owners)?;
        Ok(OriginalClockQualificationRun {
            graph,
            scenario,
            runtime: Some(runtime),
            retired: None,
            captured: None,
            capture_attempted: false,
            retirement_attempted: false,
            proposal,
            activation: None,
            origin: ClockOrigin {
                source,
                source_path: self.host_executable.clone(),
                process: std::process::id(),
                thread: std::thread::current().id(),
            },
            source_lifetime: std::rc::Rc::new(()),
            node,
            pause,
            admission_cases: admission_cases::OriginalClockAdmissionCases::new()?,
            cases,
            next: 0,
            failed: false,
            arm_attempted: false,
        })
    }
}

impl OriginalClockQualificationRun {
    fn current(&self) -> Result<(), NodeObservedError> {
        self.origin.current()
    }

    /// Arms the same real owner and commits its complete original world once.
    ///
    /// The publisher must retain genuine complete coordinator/owner bytes under
    /// its ordinary durable publication contract. Scalar acknowledgements fail
    /// the runtime's existing complete-world barrier.
    ///
    /// # Errors
    /// Refuses changed source, a second attempt, invalid actual readiness or an
    /// uncommitted publication. Original runtime custody remains in this owner.
    pub fn activate(
        &mut self,
        publisher: &mut dyn ActivationPublisher,
    ) -> Result<(), NodeObservedError> {
        self.current()?;
        if self.arm_attempted || self.failed {
            return Err(refused("Clock qualification activation already attempted"));
        }
        self.arm_attempted = true;
        let result = (|| {
            let runtime = self
                .runtime
                .as_mut()
                .ok_or_else(|| refused("original Clock retired"))?;
            runtime.arm_all()?;
            self.admission_cases.inspect_prepublication(
                runtime,
                &self.graph,
                &self.node,
                &self.proposal,
            )?;
            let preparations = runtime.prepared_node_records()?.to_vec();
            let coordinator = runtime
                .initial_coordinator_snapshot(&self.graph, MAXIMUM_ACTIVATION_COORDINATOR_BYTES)?;
            publisher.retain_initial_coordinator(&self.proposal, preparations, coordinator)?;
            self.activation = Some(runtime.activate(publisher)?);
            self.current()
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// Executes the next fixed source case through its original common grant.
    ///
    /// The full expected permission, progress, frontier, native integer body,
    /// empty causes and output roster were retained before the first Arm. This
    /// reads and retains actual proof bodies before committing the scheduler
    /// and acknowledging the same token. No retry or observer can replace it.
    ///
    /// # Errors
    /// Refuses stale source, incomplete activation, prior failure, exhausted
    /// programme, an uncertain/pending result or any complete oracle mismatch.
    pub fn execute_next(&mut self) -> Result<&str, NodeObservedError> {
        self.current()?;
        if self.failed || self.next >= self.cases.len() {
            return Err(refused("Clock qualification programme unavailable"));
        }
        let result = self.execute_current();
        if let Err(error) = result {
            self.failed = true;
            return Err(error);
        }
        if let Err(error) = self.current() {
            self.failed = true;
            return Err(error);
        }
        Ok(self.cases[self.next - 1].name)
    }

    fn execute_current(&mut self) -> Result<(), NodeObservedError> {
        let activation = self
            .activation
            .as_ref()
            .ok_or_else(|| refused("Clock qualification not activated"))?;
        let runtime = self
            .runtime
            .as_mut()
            .ok_or_else(|| refused("original Clock retired"))?;
        execute_clock_case(
            runtime,
            &self.graph,
            activation,
            &self.node,
            &mut self.cases[self.next],
        )?;
        self.next += 1;
        Ok(())
    }

    /// Collects one completed original through the normal production runner.
    ///
    /// The runner still requires its same installed source/oracle and complete
    /// normal scope. This owner supplies the real runtime/token, never decoded
    /// passed bytes or a caller-selected expected outcome.
    ///
    /// # Errors
    /// Refuses stale/failed originals, missing completion/ACK, repeated collection
    /// or the runner's independently authenticated case/oracle/scope/budgets.
    pub fn collect_completed<'a>(
        &mut self,
        case_name: &str,
        runner: &'a mut ProductionConformanceRunner<'_>,
    ) -> Result<&'a ExactCompletionObservation, QualificationError> {
        self.current()
            .map_err(|_| QualificationError::Refused("Clock source no longer current"))?;
        let index = self
            .cases
            .iter()
            .position(|case| case.name == case_name)
            .filter(|index| *index < self.next)
            .ok_or(QualificationError::Refused(
                "Clock has no such original completion",
            ))?;
        let case = &mut self.cases[index];
        if self.failed || !case.acknowledged || case.collected {
            return Err(QualificationError::Refused(
                "Clock original collection unavailable",
            ));
        }
        case.collected = true;
        let token = case
            .token
            .as_ref()
            .ok_or(QualificationError::Refused("Clock original token absent"))?;
        let activation = self.activation.as_ref().ok_or(QualificationError::Refused(
            "Clock original activation absent",
        ))?;
        // Leave the original blocked if an installed callback unwinds.
        self.failed = true;
        let result = runner.collect_exact(
            ExactCompletionCase {
                case: case.name.into(),
                oracle: case.oracle.reference.clone(),
                request: case.expected.request.clone(),
                outcome: case.expected.outcome.clone(),
                input: None,
                acknowledged: true,
                maximum_bytes: MAXIMUM_CASE_BYTES as u64,
            },
            self.runtime
                .as_mut()
                .ok_or(QualificationError::Refused("original Clock retired"))?,
            activation,
            token,
        );
        if result.is_ok() {
            self.current().map_err(|_| {
                QualificationError::Refused("Clock source changed during collection")
            })?;
            self.failed = false;
        }
        result
    }

    /// Borrows the source-regenerated original Clock world, without authority.
    pub fn scenario_data(&self) -> &crate::node_scenario::NodeScenario {
        &self.scenario
    }

    /// Borrows all immutable case oracles prepared before any native operation.
    ///
    /// These data cannot install a source, class policy or successful report.
    pub fn case_oracles_data(&self) -> impl ExactSizeIterator<Item = (&str, &InputPayload)> {
        self.cases.iter().map(|case| (case.name, &case.oracle))
    }
}

fn execute_clock_case(
    runtime: &mut NodeRuntime,
    graph: &AdmittedGraph,
    activation: &WorldActivation,
    node: &Id,
    case: &mut ClockCase,
) -> Result<(), NodeObservedError> {
    execute_clock_case_selected(runtime, graph, activation, node, case, true)
}

fn execute_clock_case_selected(
    runtime: &mut NodeRuntime,
    graph: &AdmittedGraph,
    activation: &WorldActivation,
    node: &Id,
    case: &mut ClockCase,
    acknowledge: bool,
) -> Result<(), NodeObservedError> {
    if case.attempted {
        return Err(refused("original Clock case already attempted"));
    }
    case.attempted = true;
    let observation = runtime.observe_scheduling(activation, node)?;
    runtime
        .scheduler(graph, activation)?
        .accept_boundary_observation(observation)?;
    let grant = match &case.expected.request {
        OperationRequest::ExactRun { limit, .. } => runtime
            .scheduler(graph, activation)?
            .admit_exact(node, case.operation.clone(), limit.time_ps)?,
        OperationRequest::BoundarySettle { limit, .. } => runtime
            .scheduler(graph, activation)?
            .admit_boundary_settlement(node, case.operation.clone(), *limit)?,
        _ => {
            return Err(refused(
                "Clock source programme contains unsupported operation",
            ));
        }
    };
    let (start, limit) = match case.expected.request {
        OperationRequest::ExactRun { start, limit, .. }
        | OperationRequest::BoundarySettle { start, limit } => (start, limit),
        _ => return Err(refused("Clock source programme request changed")),
    };
    if grant.node() != node
        || grant.operation() != &case.operation
        || grant.start() != start
        || grant.limit() != limit
    {
        return Err(refused(
            "Clock scheduler permission differs from source programme",
        ));
    }
    match runtime.begin_admitted(grant)? {
        BeginResult::Accepted(token) => case.token = Some(token),
        BeginResult::Uncertain { token, .. } => {
            case.token = Some(token);
            return Err(refused("Clock submission uncertain"));
        }
        BeginResult::Refused(_) => return Err(refused("Clock original grant refused")),
    }
    let token = case
        .token
        .as_ref()
        .ok_or_else(|| refused("Clock original token absent"))?;
    let actual = match runtime.poll(token, &mut Context::from_waker(Waker::noop())) {
        Poll::Ready(Ok(outcome)) => outcome,
        Poll::Ready(Err(error)) => return Err(super::native(error)),
        Poll::Pending => return Err(refused("synchronous Clock original remains pending")),
    };
    if runtime
        .original_completed_operation(token)?
        .admission()
        .request()
        != &case.expected.request
    {
        return Err(refused(
            "Clock original request differs from source programme",
        ));
    }
    if actual != case.expected.outcome {
        return Err(refused(
            "Clock complete native outcome differs from source oracle",
        ));
    }
    let references = case
        .expected
        .objects
        .iter()
        .map(|object| object.reference.clone())
        .collect::<Vec<_>>();
    case.objects = Some(runtime.original_witness().operation_evidence(
        token,
        &references,
        U64::new(MAXIMUM_CASE_BYTES as u64),
    )?);
    case.expected.authenticate_objects(
        case.objects
            .as_deref()
            .ok_or_else(|| refused("Clock original body custody absent"))?,
    )?;
    if !acknowledge {
        return Ok(());
    }
    let receipt = runtime.scheduling_receipt(token)?;
    let commit = runtime.commit_scheduling_receipt(receipt)?;
    runtime.acknowledge_scheduled(token, &commit)?;
    if !runtime.original_completed_operation(token)?.acknowledged() {
        return Err(refused("Clock original publication ACK absent"));
    }
    case.acknowledged = true;
    Ok(())
}

mod resources;
pub use resources::{OriginalClockAggregateResources, OriginalClockProcessBootstrap};

mod publications;

impl crate::node_qualification::RetainedMetadataOwned for ClockOrigin {
    fn charge(
        &self,
        counter: &mut crate::node_qualification::RetainedMetadataCounter,
    ) -> Result<(), QualificationError> {
        let Self {
            source,
            source_path,
            process,
            thread,
        } = self;
        if *process != std::process::id() || *thread != std::thread::current().id() {
            return Err(QualificationError::Refused(
                "foreign Clock requested storage origin",
            ));
        }
        counter.charge(source)?;
        counter.charge(source_path)
    }
}

impl crate::node_qualification::RetainedMetadataOwned for ClockCase {
    fn charge(
        &self,
        counter: &mut crate::node_qualification::RetainedMetadataCounter,
    ) -> Result<(), QualificationError> {
        let Self {
            name: _,
            operation,
            expected,
            oracle,
            attempted: _,
            token,
            objects,
            acknowledged: _,
            collected: _,
        } = self;
        counter.charge(operation)?;
        counter.charge(expected)?;
        counter.charge(oracle)?;
        counter.charge(token)?;
        counter.charge(objects)
    }
}

impl crate::node_qualification::RetainedMetadataOwned for OriginalClockQualificationRun {
    fn charge(
        &self,
        counter: &mut crate::node_qualification::RetainedMetadataCounter,
    ) -> Result<(), QualificationError> {
        let Self {
            graph,
            scenario,
            runtime,
            retired,
            captured,
            capture_attempted: _,
            retirement_attempted: _,
            activation,
            proposal,
            origin,
            source_lifetime,
            node,
            cases,
            pause,
            admission_cases,
            next: _,
            failed: _,
            arm_attempted: _,
        } = self;
        counter.charge(origin)?;
        counter.charge(graph)?;
        counter.charge(scenario)?;
        counter.charge(runtime)?;
        counter.charge(retired)?;
        counter.charge(captured)?;
        counter.charge(activation)?;
        counter.charge(proposal)?;
        counter.rc(source_lifetime)?;
        counter.charge(node)?;
        counter.charge(cases)?;
        counter.charge(pause)?;
        counter.charge(admission_cases)
    }
}
