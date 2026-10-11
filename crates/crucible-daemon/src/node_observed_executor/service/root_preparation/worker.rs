//! Owns the fixed Root recipe through original grants, capture and retirement.
//!
//! Native owners remain fields of the worker across every fallible step. Status
//! completion follows authentic reclamation and pinned namespace release; a
//! channel ending or a native operation returning supplies neither proof.

use std::{
    collections::BTreeSet,
    path::PathBuf,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use crucible::{
    node_admission::AdmittedGraph,
    node_contract::{BeginResult, NodeRuntime, OperationOutcome, OperationToken, WorldActivation},
    node_state::{
        NativeArchive, NativeArchiveLimits, RestorePublication, RestoredWorld, StateLimits,
        StateRequirements, StateRestoreMode, stage_restore,
    },
};
use crucible_cas::content_store::{
    BlobHandle, ContentId, ImmutableBlobBackend, MutableRefBackend, ObjectKind, RefName,
};
use crucible_node_contract::{Bytes, ContentRef, Id, Phase, Position, U64};

use super::super::{NodeObservationServiceError, refused};
use super::{
    RootPreparationAction, RootPreparationRequest, RootPreparationState, encode, execution_id,
};
use crate::{
    node_execution::{ExactOperationNames, ExactOperationRequest, plan_exact_operation},
    node_observed_executor::{
        InstalledNodeCatalog, InstalledNodeKind, InstalledNodeSelection,
        InstalledRootCleanupFailure, InstalledRootPreservation, InstalledRootRestore,
        InstalledRootRetirement, NodeObservedError, StoredWorldActivationPublisher,
    },
    node_scenario::NodeScenario,
};

#[path = "worker_retirement.rs"]
mod retirement_transition;

const COMMON_TIME_PS: u64 = 1_000_000_000;
const UART_LIMIT_PS: u64 = 2_000_000_000;
const HELD_OPERATION: &str = "root-operator/original-held-uart";

#[derive(Clone)]
pub(in super::super) struct Installation {
    pub(in super::super) companion: PathBuf,
    pub(in super::super) expected_companion: ContentRef,
    pub(in super::super) parent: PathBuf,
    pub(in super::super) timeout: Duration,
    pub(in super::super) maximum_admitted_worlds: usize,
}

impl Installation {
    pub(in super::super) fn from_configuration(
        configuration: &super::super::NodeObservationServiceConfig,
    ) -> Result<Self, NodeObservationServiceError> {
        super::custody_geometry::slots(
            &RootPreparationAction::CaptureHeldUart {},
            configuration.maximum_worlds,
        )?;
        Ok(Self {
            companion: configuration.device_executable.clone(),
            expected_companion: configuration.expected_device.clone(),
            parent: configuration.socket_parent.clone(),
            timeout: configuration.control_timeout,
            maximum_admitted_worlds: configuration.maximum_worlds,
        })
    }
}

enum Owner {
    Empty,
    Initial {
        preservation: Option<Box<InstalledRootPreservation>>,
        runtime: Option<Box<NodeRuntime>>,
        activation: Option<WorldActivation>,
        graph: Rc<AdmittedGraph>,
    },
    Restored {
        plan: Option<Box<InstalledRootRestore>>,
        world: Option<Box<RestoredWorld>>,
    },
    Retiring(Option<Box<InstalledRootRetirement>>),
    Released,
}

#[derive(Clone, Copy)]
enum Step {
    Prepare,
    BootstrapRoot,
    BootstrapClock,
    HeldUart,
    Capture,
    CommitHeld,
    BeginRetirement,
    Reclaim,
    Complete,
}

/// Keeps all effect-capable wrappers outside the actor's callback unwind scope.
pub(in super::super) struct Worker {
    request: RootPreparationRequest,
    journal: super::diagnostics::Journal,
    catalog: InstalledNodeCatalog,
    archive: NativeArchive,
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
    owner: Owner,
    step: Step,
    token: Option<OperationToken>,
    progress: Option<OperationOutcome>,
    artifact: Option<ContentRef>,
    roots: BTreeSet<ContentId>,
    diagnostic: Option<String>,
    native_preparation_started: bool,
    description: Option<Bytes>,
}

impl Worker {
    pub(in super::super) fn new(
        request: RootPreparationRequest,
        installation: &Installation,
        blobs: Arc<dyn ImmutableBlobBackend>,
        refs: Arc<dyn MutableRefBackend>,
        mut journal: super::diagnostics::Journal,
    ) -> Result<Self, NodeObservationServiceError> {
        let setup = (|| {
            request.validate()?;
            journal.enter("installed_catalog")?;
            let custody_slots = super::custody_geometry::slots(
                &request.action,
                installation.maximum_admitted_worlds,
            )?;
            let catalog = InstalledNodeCatalog::new(
                installation.companion.clone(),
                installation.expected_companion.clone(),
                installation.parent.clone(),
                installation.timeout,
                custody_slots,
            )
            .map_err(refused)?;
            journal.enter("regenerate_scenario")?;
            let regenerated = catalog.scenario(&request.selections).map_err(refused)?;
            let regenerated = regenerated.canonical_bytes().map_err(refused)?;
            let describing = matches!(request.action, RootPreparationAction::DescribeHeldUart {});
            if !describing && regenerated != request.scenario.as_slice() {
                return Err(refused(
                    "Root original scenario differs from installed source",
                ));
            }
            journal.enter("open_archive")?;
            let archive =
                NativeArchive::open(installation.parent.join("root-operator-archive"), limits())
                    .map_err(refused)?;
            Ok((catalog, regenerated, describing, archive))
        })();
        let (catalog, regenerated, describing, archive) = match setup {
            Ok(value) => value,
            Err(error) => {
                journal.first_refusal(&super::diagnostic(&error));
                journal.publish()?;
                return Err(error);
            }
        };
        Ok(Self {
            request,
            journal,
            catalog,
            archive,
            blobs,
            refs,
            owner: Owner::Empty,
            step: if describing {
                Step::Complete
            } else {
                Step::Prepare
            },
            token: None,
            progress: None,
            artifact: None,
            roots: BTreeSet::new(),
            diagnostic: None,
            native_preparation_started: false,
            description: describing.then(|| Bytes::new(regenerated)),
        })
    }

    pub(in super::super) fn retention_roots(&self) -> impl Iterator<Item = ContentId> + '_ {
        self.roots.iter().copied()
    }

    /// Polls the same original work, including cleanup after a reported failure.
    pub(in super::super) fn poll(
        &mut self,
        context: &mut Context<'_>,
        stopping: bool,
    ) -> Poll<Result<RootPreparationState, NodeObservationServiceError>> {
        if stopping && self.diagnostic.is_none() {
            self.diagnostic =
                Some("Root actor admission stopped; original custody retained".into());
            self.journal
                .first_refusal("Root actor admission stopped; original custody retained");
            self.step = Step::BeginRetirement;
        }
        let phase = match self.step {
            Step::Prepare => "prepare",
            Step::BootstrapRoot => "bootstrap_root",
            Step::BootstrapClock => "bootstrap_clock",
            Step::HeldUart => "held_uart",
            Step::Capture => "capture",
            Step::CommitHeld => "commit_held",
            Step::BeginRetirement => "begin_retirement",
            Step::Reclaim => "reclaim",
            Step::Complete => "complete",
        };
        let cleanup = matches!(
            self.step,
            Step::BeginRetirement | Step::Reclaim | Step::Complete
        );
        let checkpoint = self.checkpoint(phase);
        if !cleanup && self.diagnostic.is_some() {
            self.step = Step::BeginRetirement;
            return Poll::Pending;
        }
        // Diagnostic storage is a pre-effect admission fence, never a gate on
        // containment of the original owner. Its last durable body stays readable.
        let result = advance_after_checkpoint(checkpoint, cleanup, || self.advance(context));
        match result {
            Ok(result) => result,
            Err(error) => {
                if self.diagnostic.is_none() {
                    self.diagnostic = Some(super::diagnostic(error));
                }
                // A failed transition never drops the original owner. If no
                // authentic activation exists, cleanup cannot be invented and
                // this worker remains retained rather than advertising retirement.
                self.journal
                    .first_refusal(self.diagnostic.as_deref().unwrap_or("Root refusal"));
                self.step = Step::BeginRetirement;
                // A failed diagnostic write also leaves the original owner in
                // custody. Its previous durable phase remains independently readable.
                let _ = self.checkpoint("begin_retirement");
                Poll::Pending
            }
        }
    }

    pub(in super::super) fn retain_unwind_diagnostic(&mut self) {
        self.journal
            .first_refusal("Root worker transition unwound; original custody retained");
        // Diagnostic persistence can fail independently; neither failure drops
        // the native wrapper or proves that an original process was reclaimed.
        let _ = self.checkpoint("worker_unwind");
    }

    fn checkpoint(&mut self, phase: &str) -> Result<(), NodeObservationServiceError> {
        let (owner, activation) = match &self.owner {
            Owner::Empty => ("empty", false),
            Owner::Initial { activation, .. } => ("initial", activation.is_some()),
            Owner::Restored { world, .. } => ("restored", world.is_some()),
            Owner::Retiring(_) => ("retiring", false),
            Owner::Released => ("released", false),
        };
        let status = match &self.owner {
            Owner::Initial {
                preservation: Some(owner),
                ..
            } => Some(owner.cleanup_status()),
            Owner::Restored {
                plan: Some(owner), ..
            } => Some(owner.cleanup_status()),
            Owner::Retiring(Some(owner)) => Some(owner.cleanup_status()),
            _ => None,
        };
        if let Some(status) = status {
            let status = status.map_err(refused)?;
            if let Some(failure) = &status.first_failure {
                let reason = match failure {
                    InstalledRootCleanupFailure::Refused { reason } => reason.as_str(),
                    InstalledRootCleanupFailure::Unwound {} => "original Root cleanup unwound",
                };
                self.journal.first_refusal(reason);
                if self.diagnostic.is_none() {
                    self.diagnostic = Some(super::diagnostic(reason));
                }
            }
            // Lease movement is volatile. Record it only at semantic milestones;
            // new failure/reclamation facts always update the retained queue view.
            let retain = self.journal.current.phase != phase
                || self
                    .journal
                    .current
                    .native_cleanup
                    .as_ref()
                    .is_none_or(|prior| {
                        prior.failed != status.failed
                            || prior.reclaimed != status.reclaimed
                            || prior.first_failure != status.first_failure
                    });
            if retain {
                self.journal.current.native_cleanup = Some(status);
            }
        }
        self.journal.current.owner = owner.into();
        self.journal.current.activation_present = activation;
        self.journal.current.native_preparation_started = self.native_preparation_started;
        self.journal.current.token_operation =
            self.token.as_ref().map(|token| token.operation().clone());
        self.journal.enter(phase)
    }

    fn advance(
        &mut self,
        context: &mut Context<'_>,
    ) -> Result<
        Poll<Result<RootPreparationState, NodeObservationServiceError>>,
        NodeObservationServiceError,
    > {
        match self.step {
            Step::Prepare => {
                self.prepare()?;
                self.step = match self.request.action {
                    RootPreparationAction::DescribeHeldUart {} => Step::Complete,
                    RootPreparationAction::CaptureHeldUart {} => Step::BootstrapRoot,
                    RootPreparationAction::ContinueHeldUart { .. } => Step::CommitHeld,
                };
            }
            Step::BootstrapRoot | Step::BootstrapClock | Step::HeldUart => {
                if self.token.is_none() {
                    let (node, name, horizon) = match self.step {
                        Step::BootstrapRoot => {
                            ("root", "root-operator/original-bootstrap", COMMON_TIME_PS)
                        }
                        Step::BootstrapClock => (
                            "clock",
                            "root-operator/original-common-clock",
                            COMMON_TIME_PS,
                        ),
                        _ => ("root", HELD_OPERATION, UART_LIMIT_PS),
                    };
                    self.observe()?;
                    let (runtime, graph, activation) = self.active()?;
                    let node = id(node)?;
                    let grant = plan_exact_operation::<NodeObservedError, _>(
                        runtime,
                        ExactOperationRequest {
                            graph,
                            activation: &activation,
                            node: &node,
                            horizon: horizon.into(),
                            names: ExactOperationNames {
                                operation: id(name)?,
                                stage: id("root-operator/unused-closed-stage")?,
                                batch: id("root-operator/unused-closed-batch")?,
                            },
                        },
                        |_| {
                            Err(NodeObservedError::Native(
                                "closed Root recipe unexpectedly staged input".into(),
                            ))
                        },
                    )
                    .map_err(refused)?
                    .ok_or_else(|| refused("Root original planner has no safe grant"))?;
                    self.journal.current.granted_operation = Some(super::RootGrantedOperation {
                        node: grant.node().clone(),
                        operation: grant.operation().clone(),
                        start: grant.start(),
                        limit: grant.limit(),
                    });
                    self.checkpoint("begin_original_operation")?;
                    let (runtime, _, _) = self.active()?;
                    let BeginResult::Accepted(token) =
                        runtime.begin_admitted(grant).map_err(refused)?
                    else {
                        return Err(refused("Root original planner grant was refused"));
                    };
                    self.token = Some(token);
                }
                let token = self
                    .token
                    .as_ref()
                    .ok_or_else(|| refused("Root original token absent"))?
                    .clone();
                let (runtime, _, _) = self.active()?;
                let Poll::Ready(outcome) = runtime.poll(&token, context) else {
                    return Ok(Poll::Pending);
                };
                let outcome = outcome.map_err(refused)?;
                if matches!(self.step, Step::HeldUart) {
                    validate_uart(&outcome)?;
                    self.progress = Some(outcome);
                    self.step = Step::Capture;
                } else {
                    if outcome.scheduling.as_ref().is_none_or(|progress| {
                        progress.reached != common_cut() || !progress.publications.is_empty()
                    }) {
                        return Err(refused(
                            "Root bootstrap differs from fixed original horizon",
                        ));
                    }
                    self.commit(&token)?;
                    self.token = None;
                    self.step = if matches!(self.step, Step::BootstrapRoot) {
                        Step::BootstrapClock
                    } else {
                        Step::HeldUart
                    };
                }
            }
            Step::Capture => {
                self.checkpoint("capture_original_world")?;
                let Owner::Initial {
                    preservation,
                    runtime,
                    activation,
                    graph,
                } = &mut self.owner
                else {
                    return Err(refused("Root capture lacks its original owning runtime"));
                };
                let preservation = preservation
                    .as_ref()
                    .ok_or_else(|| refused("Root capture policy absent"))?;
                let runtime = runtime
                    .as_mut()
                    .ok_or_else(|| refused("Root capture runtime absent"))?;
                let activation = activation
                    .as_ref()
                    .ok_or_else(|| refused("Root original activation absent"))?;
                let factory = preservation.factory();
                let immutable = preservation.immutable();
                let record = self
                    .archive
                    .capture_world_typed(
                        graph,
                        runtime,
                        activation,
                        common_cut(),
                        U64::new(17),
                        id(&format!("root-operator/{}/capture", self.request.execution))?,
                        requirements()?,
                        immutable.as_ref(),
                        factory.as_ref(),
                    )
                    .map_err(refused)?;
                self.artifact = Some(record.artifact().clone());
                self.step = Step::BeginRetirement;
            }
            Step::CommitHeld => {
                if self.token.is_none() {
                    let (runtime, _, _) = self.active()?;
                    self.token = Some(runtime.recover(&id(HELD_OPERATION)?).map_err(refused)?);
                }
                let token = self
                    .token
                    .as_ref()
                    .ok_or_else(|| refused("Root original held token absent"))?
                    .clone();
                let (runtime, _, _) = self.active()?;
                let Poll::Ready(outcome) = runtime.poll(&token, context) else {
                    return Ok(Poll::Pending);
                };
                let outcome = outcome.map_err(refused)?;
                validate_uart(&outcome)?;
                self.commit(&token)?;
                self.progress = Some(outcome);
                self.step = Step::BeginRetirement;
            }
            Step::BeginRetirement => {
                if !retirement_transition::begin(&mut self.owner, self.native_preparation_started)?
                {
                    return Ok(Poll::Pending);
                }
                self.step = Step::Reclaim;
            }
            Step::Reclaim => {
                if let Owner::Retiring(retirement) = &mut self.owner {
                    let owned = retirement
                        .as_mut()
                        .ok_or_else(|| refused("Root reclamation owner absent"))?;
                    match owned.poll_reclamation(context) {
                        Poll::Pending => return Ok(Poll::Pending),
                        Poll::Ready(Err(error)) => return Err(refused(error)),
                        Poll::Ready(Ok(())) => {}
                    }
                    let owned = retirement
                        .take()
                        .ok_or_else(|| refused("Root reclaimed owner absent"))?;
                    if let Err(failure) = (*owned).release_namespace() {
                        let failure = *failure;
                        *retirement = Some(Box::new(failure.retirement));
                        return Err(refused(failure.error));
                    }
                    self.owner = Owner::Released;
                }
                self.step = Step::Complete;
            }
            Step::Complete => {
                if let Some(reason) = &self.diagnostic {
                    return Ok(Poll::Ready(Ok(RootPreparationState::Unavailable {
                        reason: reason.clone(),
                    })));
                }
                if let Some(scenario) = &self.description {
                    return Ok(Poll::Ready(Ok(RootPreparationState::Described {
                        scenario: scenario.clone(),
                    })));
                }
                let progress = self
                    .progress
                    .as_ref()
                    .ok_or_else(|| refused("Root actual outcome absent"))?;
                return Ok(Poll::Ready(Ok(RootPreparationState::Completed {
                    scenario: self.request.scenario.clone(),
                    artifact: self
                        .artifact
                        .clone()
                        .ok_or_else(|| refused("Root signed artifact absent"))?,
                    progress: Bytes::new(encode(progress)?),
                    continued: matches!(
                        self.request.action,
                        RootPreparationAction::ContinueHeldUart { .. }
                    ),
                })));
            }
        }
        Ok(Poll::Pending)
    }

    fn prepare(&mut self) -> Result<(), NodeObservationServiceError> {
        match self.request.action.clone() {
            RootPreparationAction::DescribeHeldUart {} => {
                return Err(refused("Root description cannot prepare native owners"));
            }
            RootPreparationAction::CaptureHeldUart {} => {
                let scenario =
                    NodeScenario::from_json(self.request.scenario.as_slice()).map_err(refused)?;
                self.native_preparation_started = true;
                self.checkpoint("prepare_native_world")?;
                let prepared = self
                    .catalog
                    .prepare_root_native_world(
                        &self.request.selections,
                        scenario,
                        execution_id(&self.request.execution)?,
                    )
                    .map_err(refused)?;
                let target = prepared.world.realization.activation_record().clone();
                let graph = Rc::new(prepared.world.graph);
                self.checkpoint("admit_native_world")?;
                let runtime = prepared
                    .world
                    .realization
                    .admit(&graph)
                    .map_err(|failure| refused(&failure.error))?;
                self.owner = Owner::Initial {
                    preservation: Some(Box::new(prepared.preservation)),
                    runtime: Some(Box::new(runtime)),
                    activation: None,
                    graph,
                };
                self.checkpoint("arm_native_world")?;
                let Owner::Initial {
                    preservation,
                    runtime,
                    activation,
                    graph,
                } = &mut self.owner
                else {
                    return Err(refused("Root initial custody disappeared"));
                };
                let runtime = runtime
                    .as_mut()
                    .ok_or_else(|| refused("Root initial runtime absent"))?;
                runtime.arm_all().map_err(refused)?;
                self.journal.enter("read_original_preparations")?;
                let preparations = runtime.prepared_node_records().map_err(refused)?.to_vec();
                self.journal.enter("initial_coordinator_snapshot")?;
                let coordinator = runtime
                    .initial_coordinator_snapshot(graph, 16 * 1024 * 1024)
                    .map_err(refused)?;
                self.journal.enter("prepare_original_publisher")?;
                let stored = publisher(&self.blobs, &self.refs, &self.request.execution)?
                    .with_prepared_coordinator(target, preparations, coordinator)
                    .map_err(refused)?;
                let mut publisher = preservation
                    .as_ref()
                    .ok_or_else(|| refused("Root original policy absent"))?
                    .publisher(stored)
                    .map_err(refused)?;
                self.journal.enter("activate_original_world")?;
                *activation = Some(runtime.activate(publisher.as_mut()).map_err(refused)?);
            }
            RootPreparationAction::ContinueHeldUart { source } => {
                self.checkpoint("load_original_archive")?;
                let record = self.archive.load(&source).map_err(refused)?;
                if record.manifest().cut != common_cut()
                    || record.manifest().event_ordinal != U64::new(17)
                {
                    return Err(refused(
                        "Root source is outside the fixed original held recipe",
                    ));
                }
                validate_source_recipe(&record.runtime_snapshot().map_err(refused)?)?;
                self.native_preparation_started = true;
                self.checkpoint("prepare_native_restore")?;
                let plan = self
                    .catalog
                    .prepare_root_native_restore(&self.request.selections, record.clone())
                    .map_err(refused)?;
                self.owner = Owner::Restored {
                    plan: Some(Box::new(plan)),
                    world: None,
                };
                self.checkpoint("admit_original_restore")?;
                let Owner::Restored { plan, world } = &mut self.owner else {
                    return Err(refused("Root restore custody disappeared"));
                };
                let plan = plan
                    .as_ref()
                    .ok_or_else(|| refused("Root original restore plan absent"))?;
                let factory = plan.factory();
                let verified = record
                    .admit(&plan.graph, requirements()?, factory.as_ref())
                    .map_err(refused)?;
                self.journal.enter("stage_original_restore")?;
                let mut driver = plan.driver().map_err(refused)?;
                let staged = stage_restore(
                    &plan.graph,
                    verified,
                    plan.target.clone(),
                    &mut driver,
                    limits().state,
                )
                .map_err(|failure| refused(&failure.error))?;
                let mut publisher = plan
                    .publisher(publisher(&self.blobs, &self.refs, &self.request.execution)?)
                    .map_err(refused)?;
                self.journal.enter("publish_original_restore")?;
                let RestorePublication::Committed(restored) = staged.publish(publisher.as_mut())
                else {
                    return Err(refused(
                        "Root original whole-world restoration did not publish",
                    ));
                };
                *world = Some(restored);
                self.artifact = Some(source.clone());
            }
        }
        Ok(())
    }

    fn active(
        &mut self,
    ) -> Result<(&mut NodeRuntime, &AdmittedGraph, WorldActivation), NodeObservationServiceError>
    {
        match &mut self.owner {
            Owner::Initial {
                runtime,
                activation,
                graph,
                ..
            } => Ok((
                runtime
                    .as_mut()
                    .ok_or_else(|| refused("Root runtime absent"))?,
                graph,
                activation
                    .as_ref()
                    .ok_or_else(|| refused("Root activation absent"))?
                    .clone(),
            )),
            Owner::Restored { plan, world } => {
                let plan = plan
                    .as_ref()
                    .ok_or_else(|| refused("Root restore plan absent"))?;
                let world = world
                    .as_mut()
                    .ok_or_else(|| refused("Root restored world absent"))?;
                let activation = world.activation().clone();
                Ok((world.runtime_mut(), &plan.graph, activation))
            }
            _ => Err(refused("Root has no effect-capable active owner")),
        }
    }

    fn observe(&mut self) -> Result<(), NodeObservationServiceError> {
        for name in ["clock", "root"] {
            self.checkpoint(if name == "clock" {
                "observe_closed_clock_and_original_evidence"
            } else {
                "observe_closed_root_and_original_evidence"
            })?;
            let node = id(name)?;
            let (runtime, _, activation) = self.active()?;
            let observation = runtime
                .observe_scheduling(&activation, &node)
                .map_err(refused)?;
            let objects = runtime
                .scheduling_evidence(
                    &observation,
                    crucible::node_contract::InputProvenanceLimits {
                        maximum_objects: 64,
                        maximum_bytes: 8 * 1024 * 1024,
                    },
                )
                .map_err(refused)?;
            let bytes = encode(&serde_json::json!({
                "format": "crucible.root-original-boundary", "version": 1,
                "observation": observation.native(),
                "objects": objects.into_iter().map(|object| serde_json::json!({
                    "reference": object.reference, "bytes": Bytes::new(object.bytes),
                })).collect::<Vec<_>>(),
            }))?;
            if bytes.len() > 12 * 1024 * 1024 || self.roots.len() >= 8 {
                return Err(refused(
                    "Root original boundary exceeds reserved evidence credit",
                ));
            }
            let identity = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
            self.roots.insert(identity);
            if !self
                .blobs
                .put_if_absent(identity, &BlobHandle::from_bytes(bytes))
                .map_err(refused)?
                .is_durable()
            {
                return Err(refused("Root original boundary durability is uncertain"));
            }
            self.checkpoint(if name == "clock" {
                "accept_original_clock_boundary"
            } else {
                "accept_original_root_boundary"
            })?;
            let (runtime, graph, activation) = self.active()?;
            runtime
                .scheduler(graph, &activation)
                .map_err(refused)?
                .accept_boundary_observation(observation)
                .map_err(refused)?;
        }
        Ok(())
    }

    fn commit(&mut self, token: &OperationToken) -> Result<(), NodeObservationServiceError> {
        self.checkpoint("commit_original_coordinator_receipt")?;
        let (runtime, _, _) = self.active()?;
        let receipt = runtime.scheduling_receipt(token).map_err(refused)?;
        let commit = runtime
            .commit_scheduling_receipt(receipt)
            .map_err(refused)?;
        self.checkpoint("acknowledge_original_native_prefix")?;
        let (runtime, _, _) = self.active()?;
        runtime
            .acknowledge_scheduled(token, &commit)
            .map_err(refused)
    }
}

pub(in super::super) fn selections()
-> Result<Vec<InstalledNodeSelection>, NodeObservationServiceError> {
    Ok(vec![
        InstalledNodeSelection {
            node: id("clock")?,
            owner: id("owner/clock")?,
            kind: InstalledNodeKind::HostClock,
        },
        InstalledNodeSelection {
            node: id("root")?,
            owner: id("owner/root")?,
            kind: InstalledNodeKind::Gem5ArmRoot,
        },
    ])
}

fn validate_uart(outcome: &OperationOutcome) -> Result<(), NodeObservationServiceError> {
    let progress = outcome
        .scheduling
        .as_ref()
        .ok_or_else(|| refused("Root original native scheduling receipt absent"))?;
    if progress.reached != Position::new(1_166_530_000.into(), 1.into(), Phase::BoundaryControl)
        || progress.publications.len() != 1
        || progress.publications[0].payload_bytes != [91]
        || !progress.publications[0].causal_parents.is_empty()
    {
        return Err(refused(
            "Root original UART differs from the fixed source recipe",
        ));
    }
    Ok(())
}

fn validate_source_recipe(
    snapshot: &crucible::node_contract::RuntimeSnapshot,
) -> Result<(), NodeObservationServiceError> {
    use crucible::node_contract::{OperationRequest, SavedRuntimeResult};

    if snapshot.schema_version != 1
        || snapshot.capture_cut != common_cut()
        || snapshot.capture_ordinal != U64::new(17)
        || snapshot.operations.len() != 3
        || !snapshot.inputs.is_empty()
        || snapshot.terminal.is_some()
    {
        return Err(refused(
            "Root source contains another original runtime recipe",
        ));
    }
    for (name, node, start, limit, held) in [
        (
            "root-operator/original-bootstrap",
            "root",
            0,
            COMMON_TIME_PS,
            false,
        ),
        (
            "root-operator/original-common-clock",
            "clock",
            0,
            COMMON_TIME_PS,
            false,
        ),
        (HELD_OPERATION, "root", COMMON_TIME_PS, UART_LIMIT_PS, true),
    ] {
        let operation = snapshot
            .operations
            .iter()
            .find(|operation| operation.operation.as_str() == name)
            .ok_or_else(|| refused("Root source omitted its original operation"))?;
        let OperationRequest::ExactRun {
            start: original_start,
            limit: original_limit,
            ..
        } = operation.request
        else {
            return Err(refused(
                "Root source operation is outside fixed exact execution",
            ));
        };
        if operation.route.node.as_str() != node
            || original_start != Position::new(start.into(), 0.into(), Phase::BoundaryControl)
            || original_limit != Position::new(limit.into(), 0.into(), Phase::BoundaryControl)
            || operation.input_batch.is_some()
        {
            return Err(refused("Root source changed its original grant or route"));
        }
        if held {
            let SavedRuntimeResult::Complete(outcome) = &operation.result else {
                return Err(refused(
                    "Root source no longer holds the original unacknowledged UART",
                ));
            };
            if operation.scheduling_commit.is_some() {
                return Err(refused(
                    "Root held source publication was already committed",
                ));
            }
            validate_uart(outcome)?;
        } else {
            let SavedRuntimeResult::Acknowledged(outcome) = &operation.result else {
                return Err(refused(
                    "Root source omitted original bootstrap ACK custody",
                ));
            };
            if operation.scheduling_commit.is_none()
                || outcome.scheduling.as_ref().is_none_or(|progress| {
                    progress.reached != common_cut() || !progress.publications.is_empty()
                })
            {
                return Err(refused(
                    "Root source bootstrap differs from its original common cut",
                ));
            }
        }
    }
    Ok(())
}

fn common_cut() -> Position {
    Position::new(COMMON_TIME_PS.into(), 0.into(), Phase::BoundaryControl)
}

fn id(value: &str) -> Result<Id, NodeObservationServiceError> {
    Id::new(value).map_err(refused)
}

fn publisher(
    blobs: &Arc<dyn ImmutableBlobBackend>,
    refs: &Arc<dyn MutableRefBackend>,
    execution: &str,
) -> Result<StoredWorldActivationPublisher, NodeObservationServiceError> {
    StoredWorldActivationPublisher::new(
        blobs.clone(),
        refs.clone(),
        RefName::new(format!("node-world-activations/root-operator-{execution}"))
            .map_err(refused)?,
    )
    .map_err(refused)
}

fn requirements() -> Result<StateRequirements, NodeObservationServiceError> {
    Ok(StateRequirements {
        preservation_contract: id("arm-root/native-preservation-v2")?,
        exact_model_continuation: true,
        deterministic: true,
        restore_mode: StateRestoreMode::DurableRestart,
    })
}

fn limits() -> NativeArchiveLimits {
    NativeArchiveLimits {
        state: StateLimits {
            maximum_content_bytes: 512 * 1024 * 1024,
            maximum_total_content_bytes: 2 * 1024 * 1024 * 1024,
            maximum_record_bytes: 16 * 1024 * 1024,
            maximum_native_processes: 8192,
            ..StateLimits::default()
        },
        native: crucible::node_contract::NativeCaptureLimits {
            maximum_objects: 20_000,
            maximum_record_bytes: 16 * 1024 * 1024,
            maximum_total_record_bytes: 64 * 1024 * 1024,
            maximum_artifact_bytes: 2 * 1024 * 1024 * 1024,
            maximum_total_artifact_bytes: 8 * 1024 * 1024 * 1024,
        },
    }
}

// Runs cleanup even when its data-only journal cannot be advanced. Fresh native
// transitions still require their original diagnostic reservation/publication.
pub(super) fn advance_after_checkpoint<T>(
    checkpoint: Result<(), NodeObservationServiceError>,
    cleanup: bool,
    advance: impl FnOnce() -> Result<T, NodeObservationServiceError>,
) -> Result<T, NodeObservationServiceError> {
    if !cleanup {
        checkpoint?;
    }
    advance()
}
