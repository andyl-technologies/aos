//! Drives the authored four-owner ordinary API while retaining original custody.
//!
//! Collection is distinct from accepted behavioral enrollment. This owner never
//! manufactures an accepted class, replays Begin after ambiguity, or lets a
//! returned error drop the sole runtime, publisher or original native supervisor.

use std::{
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
};

use crucible_campaign::ExecutionId;
use crucible_engine::{
    node_admission::AdmittedGraph,
    node_contract::{
        ActivationPublisher, NodeRuntime, OperationToken, PreparedRealization, WorldActivation,
    },
    node_dispatch::DispatchRound,
};
use crucible_node_format::{Id, U64};
use crucible_store::content_store::{ImmutableBlobBackend, MutableRefBackend, RefName};

use super::super::super::{InstalledNodeCatalog, InstalledNodeSelection, execution_text};
use super::super::{installed::InstalledMixedEngine, publication::NativeCustodyPublisher};
use super::{
    Gem5CaseScope,
    case::OriginalCase,
    native_oracle::{Gem5CaseExpectation, OriginalGem5Case},
    storage_oracle::{BlockCaseExpectation, OriginalBlockCase},
    unit::UnitMeasurement,
};
use crate::{
    node_observed_executor::StoredWorldActivationPublisher,
    node_qualification::QualificationError,
    node_scenario::{NodeRunConfiguration, NodeScenario},
};

const MAXIMUM_ROUNDS: u64 = 128;
const MAXIMUM_CASES: usize = 64;
const MAXIMUM_CASE_BYTES: u64 = 64 * 1024 * 1024;
const MAXIMUM_COLLECTED_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Selects a fixed independent source oracle before actual original execution.
#[derive(Clone, Copy)]
pub enum Gem5BehavioralCase {
    /// Requires the independently calculated original x86 workload publication.
    LcgOutput,
    /// Requires an empty exact completion at the original exclusive ceiling.
    ExclusiveHorizon,
}

/// Supplies an authored finite source run and independently owned durable stores.
///
/// This request grants no native permission or behavioral acceptance. Reservation
/// independently regenerates the installed source and measures the whole unit.
pub struct Gem5BehavioralRequest {
    /// Names the exact original four source-installed selections in source order.
    pub selections: Vec<InstalledNodeSelection>,
    /// Retains the complete authored ordinary scenario without projection.
    pub scenario: NodeScenario,
    /// Bounds original modeled horizon and actual scheduler round count.
    pub configuration: NodeRunConfiguration,
    /// Names this original qualification run without granting activation.
    pub execution: ExecutionId,
    /// Retains the actual independently managed immutable publication store.
    pub blobs: Arc<dyn ImmutableBlobBackend>,
    /// Retains the actual durable reference backend for the same publication.
    pub refs: Arc<dyn MutableRefBackend>,
    /// Selects the closed independent oracle before native preparation.
    pub case: Gem5BehavioralCase,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Reserved,
    Prepared,
    Starting,
    Active,
    Interrupted,
    Complete,
}

/// Owns returned preparation, runtime and publisher originals during collection.
///
/// The caller must keep this owning value outside any callback unwind boundary.
/// Pre-return preparation containment belongs to the installed preparation guards;
/// this wrapper does not replace those guards or recover arbitrary callback state.
pub struct Gem5BehavioralRun {
    engine: InstalledMixedEngine,
    selections: Vec<InstalledNodeSelection>,
    scenario: NodeScenario,
    configuration: NodeRunConfiguration,
    execution: ExecutionId,
    unit: Arc<UnitMeasurement>,
    realization: Option<PreparedRealization>,
    preparation_failure: Option<Box<crucible_engine::node_contract::RuntimePreparationFailure>>,
    original_preparation: Option<super::super::installed::host_group::IndependentLiveWorld>,
    graph: Option<Rc<AdmittedGraph>>,
    scope: Option<Gem5CaseScope>,
    runtime: Option<NodeRuntime>,
    activation: Option<WorldActivation>,
    publisher: NativeCustodyPublisher,
    round: Option<DispatchRound>,
    original_node: Option<Id>,
    planned_case: Option<String>,
    cases: Vec<Rc<OriginalCase>>,
    collected_bytes: u64,
    storage_node: Id,
    storage_tokens: Vec<OperationToken>,
    storage_expectation: Option<BlockCaseExpectation>,
    write_observed: bool,
    read_observed: bool,
    predecessor_tokens: Vec<OperationToken>,
    final_runtime: Option<crucible_engine::node_contract::OriginalLineageRuntimeRecord>,
    final_scheduler: Option<crucible_engine::node_scheduling::SchedulingSnapshot>,
    rounds: u64,
    node_index: usize,
    nodes: Vec<Id>,
    expectation: Gem5CaseExpectation,
    requires_lcg: bool,
    phase: Phase,
}

impl Gem5BehavioralRun {
    /// Reserves the exact authored source and finite collection before any Child.
    ///
    /// # Errors
    /// Refuses non-four-owner selections, changed source worlds, unsupported
    /// configuration, source identity drift, missing installed files or credits.
    pub fn reserve(
        catalog: &InstalledNodeCatalog,
        request: Gem5BehavioralRequest,
    ) -> Result<Self, QualificationError> {
        let Gem5BehavioralRequest {
            selections,
            scenario,
            configuration,
            execution,
            blobs,
            refs,
            case,
        } = request;
        let selections = selections.as_slice();
        configuration.artifact(&scenario).map_err(evidence)?;
        if selections.len() != 4
            || configuration.maximum_rounds.get() == 0
            || configuration.maximum_rounds.get() > MAXIMUM_ROUNDS
        {
            return Err(QualificationError::Refused(
                "behavioral original round/owner credit",
            ));
        }
        let engine = InstalledMixedEngine::with_runtime(
            catalog.socket_parent.clone(),
            catalog.custody.clone(),
        )
        .map_err(evidence)?;
        let profile = super::super::host_group::profile::IndependentGroupProfile::build(
            engine.installed.clone(),
            catalog,
            selections,
        )
        .map_err(evidence)?;
        if scenario.canonical_bytes().map_err(evidence)?
            != profile.scenario.canonical_bytes().map_err(evidence)?
        {
            return Err(QualificationError::Refused(
                "authored ordinary source differs",
            ));
        }
        let unit = Arc::new(UnitMeasurement::measure(
            catalog,
            engine.installed.as_ref(),
            &profile,
            &configuration,
            case,
        )?);
        let expectation = match case {
            Gem5BehavioralCase::LcgOutput => Gem5CaseExpectation::lcg_progress(),
            Gem5BehavioralCase::ExclusiveHorizon => Gem5CaseExpectation::horizon(),
        };
        let mut original_selections = Vec::new();
        original_selections.try_reserve_exact(4).map_err(evidence)?;
        original_selections.extend_from_slice(selections);
        let storage_node =
            super::super::host_group::selection::IndependentGroupSelection::new(selections)
                .map_err(evidence)?
                .block
                .node
                .clone();
        let mut nodes = Vec::new();
        nodes.try_reserve_exact(4).map_err(evidence)?;
        nodes.extend(
            profile
                .scenario
                .descriptors
                .iter()
                .map(|descriptor| descriptor.id.clone()),
        );
        let mut cases = Vec::new();
        cases.try_reserve_exact(MAXIMUM_CASES).map_err(evidence)?;
        let mut predecessor_tokens = Vec::new();
        predecessor_tokens
            .try_reserve_exact(MAXIMUM_ROUNDS as usize * 4)
            .map_err(evidence)?;
        let mut storage_tokens = Vec::new();
        storage_tokens
            .try_reserve_exact(MAXIMUM_ROUNDS as usize)
            .map_err(evidence)?;
        let stored = StoredWorldActivationPublisher::new(
            blobs,
            refs,
            RefName::new(format!(
                "node-world-activations/gem5-qualification-{}",
                execution_text(execution)
            ))
            .map_err(evidence)?,
        )
        .map_err(evidence)?;
        let publisher = NativeCustodyPublisher {
            stored,
            queue: engine.native.clone(),
            restored: None,
        };
        Ok(Self {
            engine,
            selections: original_selections,
            scenario,
            configuration,
            execution,
            unit,
            realization: None,
            preparation_failure: None,
            original_preparation: None,
            graph: None,
            scope: None,
            runtime: None,
            activation: None,
            publisher,
            round: None,
            original_node: None,
            planned_case: None,
            cases,
            collected_bytes: 0,
            storage_node,
            storage_tokens,
            storage_expectation: None,
            write_observed: false,
            read_observed: false,
            predecessor_tokens,
            final_runtime: None,
            final_scheduler: None,
            rounds: 0,
            node_index: 0,
            nodes,
            expectation,
            requires_lcg: matches!(case, Gem5BehavioralCase::LcgOutput),
            phase: Phase::Reserved,
        })
    }

    /// Prepares actual inactive native and Host owners through the ordinary engine.
    ///
    /// Returned preparations stay in this run before later source callbacks.
    /// Pre-return effects use the installed engine's original custody guards.
    /// A second attempt cannot replace preparation or start another Child.
    ///
    /// # Errors
    /// Refuses stale source, another phase or any genuine native qualification.
    ///
    /// # Panics
    /// Installed callbacks may unwind. The caller must retain this run; effects
    /// before an original preparation returns rely on the installed engine guards.
    pub fn prepare(&mut self, catalog: &InstalledNodeCatalog) -> Result<(), QualificationError> {
        if self.phase != Phase::Reserved {
            return Err(QualificationError::Refused(
                "original preparation already attempted",
            ));
        }
        self.unit.current()?;
        self.phase = Phase::Interrupted;
        let original = self
            .engine
            .prepare_independent_group(
                catalog,
                &self.selections,
                &self.scenario,
                Id::new(format!("activation/{}", execution_text(self.execution)))?,
                None,
            )
            .map_err(evidence)?;
        self.original_preparation = Some(original);
        let scope = Gem5CaseScope::from_prepared(
            self.original_preparation
                .as_ref()
                .ok_or(QualificationError::Refused("original preparation absent"))?,
            &self.selections,
        )?;
        let original = self
            .original_preparation
            .take()
            .ok_or(QualificationError::Refused("original preparation absent"))?;
        self.graph = Some(original.graph);
        self.realization = Some(original.realization);
        self.scope = Some(scope);
        self.phase = Phase::Prepared;
        Ok(())
    }

    /// Arms and publishes one complete original prepared barrier without redispatch.
    ///
    /// # Errors
    /// Refuses incomplete preparation, changed source, failed Arm or uncertain
    /// durable publication. Returned runtime and publisher fields remain held.
    ///
    /// # Panics
    /// Native or durable-backend callbacks may unwind. Already stored originals
    /// remain in this borrowed run, which the caller must retain without retrying.
    pub fn start(&mut self) -> Result<(), QualificationError> {
        if self.phase != Phase::Prepared {
            return Err(QualificationError::Refused(
                "original activation cannot be replaced",
            ));
        }
        self.unit.current()?;
        self.phase = Phase::Starting;
        let graph = self
            .graph
            .as_ref()
            .ok_or(QualificationError::Refused("original graph absent"))?;
        let realization = self
            .realization
            .take()
            .ok_or(QualificationError::Refused("original realization absent"))?;
        let target = realization.activation_record().clone();
        let runtime = match realization.admit(graph) {
            Ok(runtime) => runtime,
            Err(original_failure) => {
                let error = evidence(&original_failure.error);
                self.preparation_failure = Some(original_failure);
                return Err(error);
            }
        };
        self.runtime = Some(runtime);
        let runtime = self
            .runtime
            .as_mut()
            .ok_or(QualificationError::Refused("original runtime absent"))?;
        runtime.arm_all().map_err(evidence)?;
        let original_nodes = runtime.prepared_node_records().map_err(evidence)?;
        if original_nodes.len() != 4 {
            return Err(QualificationError::Refused(
                "original prepared roster changed",
            ));
        }
        super::unit::encode(original_nodes)?;
        let nodes = original_nodes.to_vec();
        let coordinator = runtime
            .initial_coordinator_snapshot(graph, 16 * 1024 * 1024)
            .map_err(evidence)?;
        self.publisher
            .retain_initial_coordinator(&target, nodes, coordinator)
            .map_err(evidence)?;
        let activation = runtime.activate(&mut self.publisher).map_err(evidence)?;
        self.activation = Some(activation);
        self.scope
            .as_mut()
            .ok_or(QualificationError::Refused("original source scope absent"))?
            .mark_activated(
                self.activation
                    .as_ref()
                    .ok_or(QualificationError::Refused("original activation absent"))?,
            )?;
        self.phase = Phase::Active;
        Ok(())
    }

    /// Polls actual planned operations while keeping the same original grants.
    ///
    /// This method returns Pending on native latency and never submits a second
    /// Begin for an existing round. Errors are sticky; original fields already
    /// installed in this run remain held.
    ///
    /// # Errors
    /// Refuses drift, exhausted authored credit, scheduling/native ambiguity,
    /// missing original proof or failed independent semantic collection.
    ///
    /// # Panics
    /// Installed/native or durable-backend callbacks may unwind. The caller must
    /// retain the same run and its original round rather than redispatching Begin.
    pub fn poll(&mut self, context: &mut Context<'_>) -> Poll<Result<bool, QualificationError>> {
        if self.phase == Phase::Complete {
            return Poll::Ready(Ok(true));
        }
        if self.phase != Phase::Active {
            return Poll::Ready(Err(QualificationError::Refused(
                "original run is interrupted",
            )));
        }
        self.phase = Phase::Interrupted;
        let result = self.poll_original(context);
        if matches!(result, Poll::Pending | Poll::Ready(Ok(false))) {
            self.phase = Phase::Active;
        }
        if matches!(result, Poll::Ready(Ok(true))) {
            self.phase = Phase::Complete;
        }
        result
    }

    fn poll_original(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Result<bool, QualificationError>> {
        let result = self.advance(context);
        match result {
            Ok(value) => value,
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn advance(
        &mut self,
        context: &mut Context<'_>,
    ) -> Result<Poll<Result<bool, QualificationError>>, QualificationError> {
        let graph = self
            .graph
            .as_ref()
            .ok_or(QualificationError::Refused("original graph absent"))?;
        let activation = self
            .activation
            .as_ref()
            .ok_or(QualificationError::Refused("original activation absent"))?;
        let runtime = self
            .runtime
            .as_mut()
            .ok_or(QualificationError::Refused("original runtime absent"))?;
        let scope = self
            .scope
            .as_ref()
            .ok_or(QualificationError::Refused("original source scope absent"))?;
        scope.authenticate_world_hash(&activation.record().world_binding_hash)?;
        if let Some(round) = &mut self.round {
            match round.poll(runtime, context) {
                Poll::Pending => return Ok(Poll::Pending),
                Poll::Ready(result) => result.map_err(evidence)?,
            }
            // Native polling may have retained a result. Reauthenticate complete
            // current source before any coordinator publication or native ACK.
            publish_current_original(
                || scope.authenticate_world_hash(&activation.record().world_binding_hash),
                || round.publish(runtime).map(|_| ()).map_err(evidence),
            )?;
            if self
                .original_node
                .as_ref()
                .is_some_and(|node| node.as_str() == "cpu")
            {
                if self.cases.len() == MAXIMUM_CASES {
                    return Err(QualificationError::Refused("original case slots exhausted"));
                }
                let token = round
                    .tokens()
                    .next()
                    .ok_or(QualificationError::Refused("original round token absent"))?;
                let expectation = &self.expectation;
                let case = OriginalGem5Case::collect(
                    &mut runtime.original_witness(),
                    token,
                    expectation,
                    scope,
                )?;
                if self.planned_case.as_deref() != Some(case.id()) {
                    return Err(QualificationError::Refused(
                        "collected original case differs from predeclared episode",
                    ));
                }
                let verdict = case.verdict();
                self.collected_bytes = charge_case(self.collected_bytes, case.objects())?;
                let predecessor_retained = case.checksum_predecessor().is_none_or(|prior| {
                    self.cases.iter().any(|retained| match retained.as_ref() {
                        OriginalCase::Cpu(original) => std::ptr::eq(original.as_ref(), prior),
                        OriginalCase::Storage(_) => false,
                    })
                });
                let case = Rc::new(case);
                self.cases.push(Rc::new(OriginalCase::Cpu(case.clone())));
                // Retain the returned observation before interpreting a custody
                // mismatch, just as for an independent semantic refusal below.
                if !predecessor_retained {
                    return Err(QualificationError::Refused(
                        "checksum predecessor is not held by this original run",
                    ));
                }
                if verdict != crate::node_qualification::CaseVerdict::Passed {
                    return Err(QualificationError::Refused(
                        "independent original CPU semantic case failed",
                    ));
                }
                if self.requires_lcg && case.observed_lcg_output() {
                    // The next declared grant may observe this source guest's exit.
                    // Its predicate keeps the genuine acknowledged checksum case.
                    self.expectation = Gem5CaseExpectation::post_output_progress(case)?;
                }
            }
            if self
                .original_node
                .as_ref()
                .is_some_and(|node| is_selected_storage(node, &self.storage_node))
            {
                let token = round
                    .tokens()
                    .next()
                    .ok_or(QualificationError::Refused("original Block token absent"))?;
                let expectation =
                    self.storage_expectation
                        .as_ref()
                        .ok_or(QualificationError::Refused(
                            "predeclared storage expectation absent",
                        ))?;
                let case = OriginalBlockCase::collect(
                    &mut runtime.original_witness(),
                    token,
                    &self.storage_tokens,
                    expectation,
                    scope,
                )?;
                if self.planned_case.as_deref() != Some(case.id()) {
                    return Err(QualificationError::Refused(
                        "collected storage episode differs from predeclared case",
                    ));
                }
                let verdict = case.verdict();
                if case.observed_expected_response() {
                    if self.write_observed {
                        self.read_observed = true;
                    } else {
                        self.write_observed = true;
                    }
                }
                self.collected_bytes = charge_case(self.collected_bytes, case.objects())?;
                self.cases
                    .push(Rc::new(OriginalCase::Storage(Rc::new(case))));
                if verdict != crate::node_qualification::CaseVerdict::Passed {
                    return Err(QualificationError::Refused(
                        "independent original storage semantic case failed",
                    ));
                }
                if self.storage_tokens.len() + round.tokens().count() > MAXIMUM_ROUNDS as usize {
                    return Err(QualificationError::Refused(
                        "original storage predecessor token credit",
                    ));
                }
                self.storage_tokens.extend(round.tokens().cloned());
                self.storage_expectation = None;
            }
            if self.predecessor_tokens.len() + round.tokens().count() > MAXIMUM_ROUNDS as usize * 4
            {
                return Err(QualificationError::Refused(
                    "original predecessor token credit",
                ));
            }
            self.predecessor_tokens.extend(round.tokens().cloned());
            scope.authenticate_world_hash(&activation.record().world_binding_hash)?;
            self.round = None;
            self.original_node = None;
            self.planned_case = None;
            self.node_index += 1;
            return Ok(Poll::Ready(Ok(false)));
        }
        if self.node_index == self.nodes.len() {
            let finished = self.nodes.iter().try_fold(true, |finished, node| {
                Ok::<_, QualificationError>(
                    finished
                        && runtime
                            .scheduler(graph, activation)
                            .map_err(evidence)?
                            .position(node)
                            .map_err(evidence)?
                            .time_ps
                            >= self.configuration.horizon_ps,
                )
            })?;
            if finished {
                if self.requires_lcg && !self.cases.iter().any(|case| case.observed_lcg_output()) {
                    return Err(QualificationError::Refused(
                        "original independent LCG publication absent",
                    ));
                }
                if !self.write_observed || !self.read_observed {
                    return Err(QualificationError::Refused(
                        "original independent write/read response absent",
                    ));
                }
                return Ok(Poll::Ready(Ok(true)));
            }
            self.rounds += 1;
            self.node_index = 0;
        }
        if self.rounds >= self.configuration.maximum_rounds.get() {
            return Err(QualificationError::Refused(
                "authored original round credit exhausted",
            ));
        }
        let node = &self.nodes[self.node_index];
        if runtime
            .scheduler(graph, activation)
            .map_err(evidence)?
            .position(node)
            .map_err(evidence)?
            .time_ps
            >= self.configuration.horizon_ps
        {
            self.node_index += 1;
            return Ok(Poll::Ready(Ok(false)));
        }
        for original in &self.nodes {
            let observation = runtime
                .observe_scheduling(activation, original)
                .map_err(evidence)?;
            runtime
                .scheduler(graph, activation)
                .map_err(evidence)?
                .accept_boundary_observation(observation)
                .map_err(evidence)?;
        }
        let name = format!(
            "gem5-qualification/{}/{}/{node}",
            execution_text(self.execution),
            self.rounds
        );
        // Planning may Stage a real input batch. Reserve the complete collector
        // account before that first effect, even when no Begin grant is produced.
        if (node.as_str() == "cpu" || is_selected_storage(node, &self.storage_node))
            && (self.cases.len() >= MAXIMUM_CASES
                || self
                    .collected_bytes
                    .checked_add(MAXIMUM_CASE_BYTES)
                    .is_none_or(|total| total > MAXIMUM_COLLECTED_BYTES))
        {
            return Err(QualificationError::Refused(
                "complete original collector credit before Stage or Begin",
            ));
        }
        let grant = crate::node_execution::plan_exact_operation::<
            crate::node_observed_executor::NodeObservedError,
            _,
        >(
            runtime,
            crate::node_execution::ExactOperationRequest {
                graph,
                activation,
                node,
                horizon: self.configuration.horizon_ps,
                names: crate::node_execution::ExactOperationNames {
                    operation: Id::new(&name)?,
                    stage: Id::new(format!("{name}/stage"))?,
                    batch: Id::new(format!("{name}/batch"))?,
                },
            },
            |_| Ok(()),
        )
        .map_err(evidence)?;
        if let Some(grant) = grant {
            if node.as_str() == "cpu" {
                let expectation = &self.expectation;
                self.planned_case =
                    Some(expectation.case_id(activation.record(), &Id::new(&name)?)?);
            }
            if is_selected_storage(node, &self.storage_node) {
                let expectation = if self.write_observed {
                    BlockCaseExpectation::read_progress(scope)?
                } else {
                    BlockCaseExpectation::write_progress(scope)?
                };
                self.planned_case =
                    Some(expectation.case_id(activation.record(), &Id::new(&name)?)?);
                self.storage_expectation = Some(expectation);
            }
            let mut grants = Vec::new();
            grants.try_reserve_exact(1).map_err(evidence)?;
            grants.push(grant);
            let round = DispatchRound::start(runtime, grants, 1)
                .map_err(|failure| QualificationError::Evidence(failure.reason))?;
            self.round = Some(round);
            self.original_node = Some(node.clone());
            scope.authenticate_world_hash(&activation.record().world_binding_hash)?;
            Ok(Poll::Pending)
        } else {
            self.node_index += 1;
            Ok(Poll::Ready(Ok(false)))
        }
    }

    /// Reads bounded diagnostic data while preserving the complete refused run.
    ///
    /// The original activation authenticates this read. These fields explain a
    /// retained failure and grant no execution, publication or release authority.
    ///
    /// # Errors
    /// Refuses an absent runtime/activation or a foreign opaque activation.
    pub fn retained_error_diagnostic(&mut self) -> Result<serde_json::Value, QualificationError> {
        let activation = self.activation.as_ref().ok_or(QualificationError::Refused(
            "original diagnostic activation absent",
        ))?;
        let runtime = self.runtime.as_mut().ok_or(QualificationError::Refused(
            "original diagnostic runtime absent",
        ))?;
        let site = runtime
            .original_witness()
            .original_error_site(activation)
            .map_err(evidence)?;
        Ok(serde_json::json!({
            "schema": "crucible.gem5.original-refusal-site.v1",
            "activation": activation.record().activation_id,
            "node_index": self.node_index,
            "planned_node": self.nodes.get(self.node_index),
            "dispatched_node": self.original_node,
            "planned_case": self.planned_case,
            "original_error_site": site,
            "semantic_or_native_authority": false,
        }))
    }

    /// Retains both original common ledgers after every actual final ACK.
    ///
    /// These represented records do not authenticate opaque native suspension or
    /// grant capture, restoration, accepted enrollment or retirement authority.
    ///
    /// # Errors
    /// Refuses an incomplete run, changed source, absent original runtime or a
    /// represented record exceeding the unchanged sixteen-MiB record ceiling.
    pub fn retain_common_witness(&mut self) -> Result<(), QualificationError> {
        if self.phase != Phase::Complete || self.round.is_some() {
            return Err(QualificationError::Refused(
                "original common suffix incomplete",
            ));
        }
        self.unit.current()?;
        let runtime = self
            .runtime
            .as_ref()
            .ok_or(QualificationError::Refused("original runtime absent"))?;
        let cut = crucible_node_format::Position {
            time_ps: self.configuration.horizon_ps,
            microstep: 0.into(),
            phase: crucible_node_format::Phase::BoundaryControl,
        };
        let ordinal = U64::from(self.predecessor_tokens.len() as u64);
        if self.final_runtime.is_none() {
            self.final_runtime = Some(
                runtime
                    .original_lineage_runtime_snapshot(
                        cut,
                        ordinal,
                        crucible_engine::node_contract::OriginalInputLineageLimits {
                            maximum_objects: 4096,
                            maximum_bytes: 64 * 1024 * 1024,
                            maximum_edges: 16_384,
                        },
                        16 * 1024 * 1024,
                    )
                    .map_err(evidence)?,
            );
        }
        if self.final_scheduler.is_none() {
            self.final_scheduler = Some(
                runtime
                    .original_lineage_scheduler_snapshot(
                        self.activation
                            .as_ref()
                            .ok_or(QualificationError::Refused("original activation absent"))?,
                        cut,
                        ordinal,
                    )
                    .map_err(evidence)?,
            );
        }
        super::unit::encode(
            self.final_scheduler
                .as_ref()
                .ok_or(QualificationError::Refused("original scheduler absent"))?,
        )?;
        self.unit.current()?;
        Ok(())
    }

    /// Borrows retained original represented suffix records without live authority.
    pub fn common_witness(
        &self,
    ) -> Option<(
        &crucible_engine::node_contract::OriginalLineageRuntimeRecord,
        &crucible_engine::node_scheduling::SchedulingSnapshot,
    )> {
        Some((self.final_runtime.as_ref()?, self.final_scheduler.as_ref()?))
    }

    /// Borrows complete source-authenticated case bodies without live authority.
    pub fn original_case_objects(
        &self,
    ) -> impl Iterator<Item = (&crucible_node_format::ContentRef, &[u8])> {
        self.cases.iter().flat_map(|case| {
            case.objects()
                .iter()
                .map(|(reference, body)| (reference, body.as_slice()))
        })
    }

    pub(super) fn source_scenario(&self) -> &NodeScenario {
        &self.scenario
    }

    /// Borrows all original observations, including a failed semantic result.
    pub(super) fn cases(&self) -> &[Rc<OriginalCase>] {
        &self.cases
    }

    /// Borrows exact source axes without returning mutable runtime authority.
    pub(super) fn unit(&self) -> &Arc<UnitMeasurement> {
        &self.unit
    }
}

fn evidence(error: impl std::fmt::Display) -> QualificationError {
    QualificationError::Evidence(error.to_string())
}

// Each collector has a finite whole-body account. Reserve that complete account
// before Begin, then retain its actual extent alongside every original case.
fn charge_case(
    retained: u64,
    objects: &[(crucible_node_format::ContentRef, Vec<u8>)],
) -> Result<u64, QualificationError> {
    let bytes = objects.iter().try_fold(0u64, |sum, (reference, body)| {
        reference.verify(body)?;
        sum.checked_add(body.len() as u64)
            .filter(|total| *total <= MAXIMUM_CASE_BYTES)
            .ok_or(QualificationError::Refused(
                "original collector whole-body credit",
            ))
    })?;
    retained
        .checked_add(bytes)
        .filter(|total| *total <= MAXIMUM_COLLECTED_BYTES)
        .ok_or(QualificationError::Refused(
            "complete retained original case credit",
        ))
}

// Collection follows the original selected Block identity. A presentation name
// cannot select a different node or silently omit the actual Block episode.
fn is_selected_storage(node: &Id, selected: &Id) -> bool {
    node == selected
}

fn publish_current_original(
    authenticate: impl FnOnce() -> Result<(), QualificationError>,
    publish: impl FnOnce() -> Result<(), QualificationError>,
) -> Result<(), QualificationError> {
    authenticate()?;
    publish()
}

#[cfg(test)]
#[path = "publication_scope_tests.rs"]
mod publication_scope_tests;

#[cfg(test)]
#[path = "storage_selection_tests.rs"]
mod storage_selection_tests;
