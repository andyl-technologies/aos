//! Holds the actual complete world and original result across storage refusal.

use super::super::ledger::{CapabilityPreparationLedger, CapabilityReservation, SealedCompletion};
use super::super::{
    CapabilityPreparationAction, CapabilityPreparationRequest, CapabilityPreparationState,
    NodeObservationServiceError, encode, execution_id, refused,
};
use crate::{
    node_observed_executor::{
        InstalledCapabilityCandidate, InstalledIndependentNativePreservation, InstalledNodeCatalog,
        StoredWorldActivationPublisher,
    },
    node_scenario::NodeRunConfiguration,
};
use crucible::{
    node_admission::AdmittedGraph,
    node_contract::{ActivationRecord, NodeRuntime, WorldActivation},
    node_scheduling::NativePublication,
    node_state::{
        NativeArchive, NativeArchiveLimits, NativeArchiveRecord, NativeWorldRestoreDriver,
        RestorePublication, RestoredWorld, StateRequirements, StateRestoreMode, stage_restore,
    },
};
use crucible_cas::content_store::{ImmutableBlobBackend, MutableRefBackend, RefName};
use crucible_node_contract::{Bytes, ContentRef, Id, Phase, Position};
use std::{
    rc::Rc,
    sync::Arc,
    task::{Context, Waker},
};

pub(super) struct Worker {
    failure_cleanup: failure::FailureCleanup,
    request: CapabilityPreparationRequest,
    reservation: CapabilityReservation,
    ledger: CapabilityPreparationLedger,
    catalog: InstalledNodeCatalog,
    archive: NativeArchive,
    archive_path: std::path::PathBuf,
    archive_limits: NativeArchiveLimits,
    authenticator: super::retirement_auth::Authenticator,
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
    graph: Option<Rc<AdmittedGraph>>,
    preservation: Option<InstalledIndependentNativePreservation>,
    failure_retirement: Option<crate::node_observed_executor::factory::PreparedFailureRetirement>,
    runtime: Option<NodeRuntime>,
    restored: Option<Box<RestoredWorld>>,
    driver: Option<NativeWorldRestoreDriver>,
    source: Option<NativeArchiveRecord>,
    activation: Option<WorldActivation>,
    target: Option<ActivationRecord>,
    publications: Option<Vec<(Id, NativePublication)>>,
    artifact: Option<ContentRef>,
    outcome: Option<CapabilityPreparationState>,
    sealed: Option<SealedCompletion>,
    sealed_retirement: Option<super::super::ledger::retirement::SealedRetirement>,
    supervision: Option<crate::node_observed_executor::factory::OriginalNativeSupervision>,
    supervised: bool,
    started: bool,
    effect_capable: bool,
    completed: bool,
    persisted: bool,
    retiring: bool,
}

impl Worker {
    pub(super) fn new(
        submission: &mut Option<super::Submission>,
        catalog: InstalledNodeCatalog,
    ) -> Result<Self, NodeObservationServiceError> {
        let archive_path = submission
            .as_ref()
            .ok_or_else(|| refused("original submission absent"))?
            .archive
            .clone();
        let archive_limits = limits();
        let archive = NativeArchive::open(&archive_path, archive_limits).map_err(refused)?;
        let authenticator = super::retirement_auth::Authenticator::open(
            &submission
                .as_ref()
                .ok_or_else(|| refused("original submission absent"))?
                .archive,
        )?;
        let mut publications = Vec::new();
        publications.try_reserve_exact(33).map_err(refused)?;

        let submission = submission
            .take()
            .ok_or_else(|| refused("original submission already adopted"))?;
        Ok(Self {
            failure_cleanup: failure::FailureCleanup::new(),
            request: submission.request,
            reservation: submission.reservation,
            ledger: submission.ledger,
            catalog,
            archive,
            archive_path,
            archive_limits,
            authenticator,
            blobs: submission.blobs,
            refs: submission.refs,
            graph: None,
            preservation: None,
            failure_retirement: None,
            runtime: None,
            restored: None,
            driver: None,
            source: None,
            activation: None,
            target: None,
            publications: Some(publications),
            artifact: None,
            outcome: None,
            sealed: None,
            sealed_retirement: None,
            supervision: None,
            supervised: false,
            started: false,
            effect_capable: false,
            completed: false,
            persisted: false,
            retiring: false,
        })
    }

    pub(super) fn execute_once(&mut self) -> Result<(), NodeObservationServiceError> {
        if self.started {
            return Err(refused(
                "original complete native action cannot be dispatched twice",
            ));
        }
        self.started = true;
        self.request.validate()?;
        let configuration = NodeRunConfiguration::from_json(self.request.configuration.as_slice())
            .map_err(refused)?;
        // Both credits are fixed before native preparation. Each later round
        // consumes its original slot before observation or effect submission.
        let mut rounds = super::round_credit::RoundCredit::new(configuration.maximum_rounds.get())?;
        let candidates = self
            .request
            .candidates
            .iter()
            .map(|candidate| InstalledCapabilityCandidate {
                id: candidate.id.clone(),
                selections: candidate.selections.clone(),
            })
            .collect::<Vec<_>>();
        if let CapabilityPreparationAction::Continue { source } = &self.request.action {
            let record = self.archive.load(source).map_err(refused)?;
            self.ledger
                .authenticate_capture(&self.request, &record, &self.authenticator)?;
            if configuration.horizon_ps <= record.manifest().cut.time_ps {
                return Err(refused(
                    "future original horizon must follow the captured cut",
                ));
            }
            self.source = Some(record);
        }
        let resolved = match &self.source {
            Some(source) => self.catalog.resolve_capabilities_raw_from_source(
                &candidates,
                self.request.requirements.as_slice(),
                source,
            ),
            None => self
                .catalog
                .resolve_capabilities_raw(&candidates, self.request.requirements.as_slice()),
        }
        .map_err(refused)?;
        self.catalog
            .preflight_capability_independent_outputs(&resolved, self.source.as_ref())
            .map_err(refused)?;
        let (archive_limits, credit_reference) = self
            .catalog
            .preflight_capability_independent_capture_credit(&resolved, self.source.as_ref())
            .map_err(refused)?;
        self.archive = NativeArchive::open(&self.archive_path, archive_limits).map_err(refused)?;
        self.archive_limits = archive_limits;
        let scenario = Bytes::new(resolved.scenario().canonical_bytes().map_err(refused)?);
        super::super::validate_scenario_credit(&scenario)?;
        let stored = self.publisher()?;
        if self.source.is_none() {
            // The complete immutable handles and future history credit are
            // retained before the first adapter constructor or native effect.
            // Inherited Continue cleanup requires its own original-source codec.
            self.failure_retirement = Some(
                self.catalog
                    .preflight_capability_failure_retirement(&resolved)
                    .map_err(refused)?,
            );
        }
        if let Some(original) = self.failure_retirement.as_mut() {
            original
                .persist_sources(
                    &self.request.execution,
                    self.blobs.as_ref(),
                    self.refs.as_ref(),
                )
                .map_err(refused)?;
        }
        // Every later failure retains this worker. Its original runtime or
        // reserved driver is never replaced by a terminal data receipt.
        self.effect_capable = true;
        match &self.source {
            None => {
                let prepared = self
                    .catalog
                    .prepare_capability_independent_native_world(
                        &resolved,
                        execution_id(&self.request.execution)?,
                    )
                    .map_err(refused)?;
                self.target = Some(prepared.world.realization.activation_record().clone());
                self.graph = Some(Rc::new(prepared.world.graph));
                self.preservation = Some(prepared.preservation);
                self.preservation
                    .as_ref()
                    .ok_or_else(|| refused("original preservation scope absent"))?
                    .authenticate_capture_credit(&credit_reference)
                    .map_err(refused)?;
                self.preservation
                    .as_ref()
                    .ok_or_else(|| refused("original failure-retirement factory absent"))?
                    .authenticate_failure_retirement(
                        self.failure_retirement
                            .as_ref()
                            .ok_or_else(|| refused("prebirth failure-retirement holder absent"))?,
                    )
                    .map_err(refused)?;
                self.runtime = Some(
                    prepared
                        .world
                        .realization
                        .admit(
                            self.graph
                                .as_ref()
                                .ok_or_else(|| refused("original graph absent"))?,
                        )
                        .map_err(|failure| refused(&failure.error))?,
                );
                let runtime = self
                    .runtime
                    .as_mut()
                    .ok_or_else(|| refused("original runtime absent"))?;
                runtime.arm_all().map_err(refused)?;
                let graph = self
                    .graph
                    .as_ref()
                    .ok_or_else(|| refused("original graph absent"))?;
                let target = self
                    .target
                    .as_ref()
                    .ok_or_else(|| refused("original target absent"))?;
                let nodes = runtime.prepared_node_records().map_err(refused)?.to_vec();
                let coordinator = runtime
                    .initial_coordinator_snapshot(
                        graph,
                        self.archive_limits.state.maximum_record_bytes,
                    )
                    .map_err(refused)?;
                let stored = stored
                    .with_prepared_coordinator(target.clone(), nodes, coordinator)
                    .map_err(refused)?;
                let mut publisher = self
                    .preservation
                    .as_ref()
                    .ok_or_else(|| refused("original policy absent"))?
                    .initial_publisher(stored);
                self.activation = Some(runtime.activate(&mut publisher).map_err(refused)?);
            }
            Some(source) => {
                let plan = self
                    .catalog
                    .prepare_capability_independent_native_restore(&resolved, source.clone())
                    .map_err(refused)?;
                self.target = Some(plan.target.clone());
                self.graph = Some(plan.graph);
                self.preservation = Some(plan.preservation);
                self.preservation
                    .as_ref()
                    .ok_or_else(|| refused("fresh preservation scope absent"))?
                    .authenticate_capture_credit(&credit_reference)
                    .map_err(refused)?;
                let graph = self
                    .graph
                    .as_ref()
                    .ok_or_else(|| refused("fresh graph absent"))?;
                let factory = self
                    .preservation
                    .as_ref()
                    .ok_or_else(|| refused("fresh policy absent"))?
                    .factory();
                let verified = source
                    .admit(graph, requirements()?, factory.as_ref())
                    .map_err(refused)?;
                self.driver = Some(
                    NativeWorldRestoreDriver::new(
                        graph.clone(),
                        source.clone(),
                        factory,
                        self.catalog.custody().clone(),
                    )
                    .map_err(refused)?,
                );
                let target = self
                    .target
                    .as_ref()
                    .ok_or_else(|| refused("fresh target absent"))?;
                let staged = stage_restore(
                    graph,
                    verified,
                    target.clone(),
                    self.driver
                        .as_mut()
                        .ok_or_else(|| refused("fresh driver absent"))?,
                    self.archive_limits.state,
                )
                .map_err(|failure| refused(&failure.error))?;
                let mut publisher = self
                    .preservation
                    .as_ref()
                    .ok_or_else(|| refused("fresh policy absent"))?
                    .restored_publisher(stored, source, target)
                    .map_err(refused)?;
                match staged.publish(&mut publisher) {
                    RestorePublication::Committed(world) => {
                        self.activation = Some(world.activation().clone());
                        self.restored = Some(world);
                    }
                    _ => {
                        return Err(refused(
                            "fresh original complete publication was not committed",
                        ));
                    }
                }
            }
        }
        let graph = self
            .graph
            .as_ref()
            .ok_or_else(|| refused("complete graph absent"))?;
        let activation = self
            .activation
            .as_ref()
            .ok_or_else(|| refused("complete activation absent"))?;
        let runtime = match &mut self.restored {
            Some(world) => world.runtime_mut(),
            None => self
                .runtime
                .as_mut()
                .ok_or_else(|| refused("complete runtime absent"))?,
        };
        let publications = self
            .publications
            .as_mut()
            .ok_or_else(|| refused("original publication slot absent"))?;
        super::execution::advance(
            runtime,
            graph,
            activation,
            &self.request.execution,
            configuration.horizon_ps,
            &mut rounds,
            publications,
        )?;
        let captured = self
            .archive
            .capture_world_typed(
                graph,
                runtime,
                activation,
                Position::new(configuration.horizon_ps, 0.into(), Phase::BoundaryControl),
                1.into(),
                Id::new(format!("capability/{}/capture", self.request.execution))
                    .map_err(refused)?,
                requirements()?,
                self.preservation
                    .as_ref()
                    .ok_or_else(|| refused("complete preservation absent"))?
                    .immutable()
                    .as_ref(),
                self.preservation
                    .as_ref()
                    .ok_or_else(|| refused("complete preservation absent"))?
                    .factory()
                    .as_ref(),
            )
            .map_err(refused)?;
        self.artifact = Some(captured.artifact().clone());
        let progress = encode(
            self.publications
                .as_ref()
                .ok_or_else(|| refused("original publications absent"))?,
        )?;
        if progress.len() > 1024 * 1024 {
            return Err(refused("predeclared original progress credit differs"));
        }
        self.outcome = Some(CapabilityPreparationState::Native {
            scenario,
            artifact: captured.artifact().clone(),
            progress: Bytes::new(progress),
        });
        self.completed = true;
        Ok(())
    }

    pub(super) fn fail(&mut self, reason: String) {
        if self.outcome.is_none() {
            self.outcome = Some(CapabilityPreparationState::Unavailable {
                reason: reason.chars().take(512).collect(),
            });
        }
    }

    pub(super) fn reconcile(&mut self) -> Result<bool, NodeObservationServiceError> {
        if self.sealed.is_none() {
            let outcome = self
                .outcome
                .as_ref()
                .ok_or_else(|| refused("original outcome absent"))?;
            self.sealed = Some(
                self.ledger
                    .seal_completion(&self.reservation, outcome.clone())?,
            );
        }
        if !self.persisted {
            self.ledger.persist_completion(
                &self.reservation,
                self.sealed
                    .as_ref()
                    .ok_or_else(|| refused("sealed original absent"))?,
            )?;
            self.persisted = true;
        }
        // Failed effect-capable work remains a held original capsule. A data
        // refusal cannot demonstrate that partial preparation or effects ended.
        if self.effect_capable && !self.completed {
            self.publish_completion()?;
            if let (Some(original), Some(runtime), Some(activation)) = (
                self.failure_retirement.as_mut(),
                self.runtime.as_ref(),
                self.activation.as_ref(),
            ) {
                let configuration =
                    NodeRunConfiguration::from_json(self.request.configuration.as_slice())
                        .map_err(refused)?;
                original
                    .retain_failure_history(
                        runtime,
                        activation,
                        Position::new(configuration.horizon_ps, 0.into(), Phase::BoundaryControl),
                        1.into(),
                        self.blobs.as_ref(),
                        self.refs.as_ref(),
                    )
                    .map_err(refused)?;
            }
            return self.reconcile_failed_original();
        }
        if !self.effect_capable {
            self.publish_completion()?;
            return Ok(true);
        }
        if !self.retiring {
            self.runtime.take();
            self.restored.take();
            self.driver.take();
            self.retiring = true;
        }
        let mut context = Context::from_waker(Waker::noop());
        let _ = self.catalog.custody().poll_reclamation(&mut context);
        if self.catalog.custody().reserved_worlds() != 0 {
            return Ok(false);
        }
        match (&self.preservation, &self.target) {
            (Some(policy), Some(target)) => {
                if !policy.reclaimed(target).map_err(refused)? {
                    return Ok(false);
                }
                if !self.supervised {
                    if self.supervision.is_none() {
                        let source = self
                            .archive
                            .load(
                                self.artifact
                                    .as_ref()
                                    .ok_or_else(|| refused("captured supervisor source absent"))?,
                            )
                            .map_err(refused)?;
                        self.supervision = Some(
                            policy
                                .authenticate_supervision(
                                    self.graph.as_ref().ok_or_else(|| {
                                        refused("original supervisor graph absent")
                                    })?,
                                    source,
                                    requirements()?,
                                )
                                .map_err(refused)?,
                        );
                    }
                    policy
                        .supervise_original(
                            target,
                            self.supervision
                                .as_mut()
                                .ok_or_else(|| refused("original supervisor history absent"))?,
                        )
                        .map_err(refused)?;
                    self.supervised = true;
                }
                if self.sealed_retirement.is_none() {
                    let Some((reference, body)) = policy.retirement(target).map_err(refused)?
                    else {
                        return Ok(false);
                    };
                    self.sealed_retirement = Some(
                        self.ledger.seal_retirement(
                            &self.reservation,
                            self.artifact
                                .as_ref()
                                .ok_or_else(|| refused("original captured artifact absent"))?,
                            target,
                            reference,
                            body,
                            &self.authenticator,
                        )?,
                    );
                }
                self.ledger.place_retirement(
                    &self.reservation,
                    self.sealed_retirement
                        .as_ref()
                        .ok_or_else(|| refused("original retirement seal absent"))?,
                )?;
                // Native becomes publicly visible only after its original
                // signed cleanup relation can authorize a later Continue.
                self.publish_completion()?;
                // Placement and signature authentication remain conjunct with
                // actual supervisor ownership. Reopening the complete original
                // archive never resubmits a native operation or a Capture.
                let source = self
                    .archive
                    .load(
                        self.artifact
                            .as_ref()
                            .ok_or_else(|| refused("durable supervisor source absent"))?,
                    )
                    .map_err(refused)?;
                self.ledger.authenticate_supervisor_release(
                    &self.reservation,
                    self.sealed
                        .as_ref()
                        .ok_or_else(|| refused("original supervisor seal absent"))?,
                    &source,
                    &self.authenticator,
                )?;
                let reopened = policy
                    .authenticate_supervision(
                        self.graph
                            .as_ref()
                            .ok_or_else(|| refused("durable supervisor graph absent"))?,
                        source,
                        requirements()?,
                    )
                    .map_err(refused)?;
                policy
                    .release_supervised(target, &reopened)
                    .map_err(refused)?;
                Ok(true)
            }
            (None, None) if !self.effect_capable => Ok(true),
            _ => Ok(false),
        }
    }

    fn publish_completion(&self) -> Result<(), NodeObservationServiceError> {
        self.ledger.place_completion(
            &self.reservation,
            self.sealed
                .as_ref()
                .ok_or_else(|| refused("sealed original absent"))?,
        )?;
        Ok(())
    }

    fn publisher(&self) -> Result<StoredWorldActivationPublisher, NodeObservationServiceError> {
        StoredWorldActivationPublisher::new(
            self.blobs.clone(),
            self.refs.clone(),
            RefName::new(format!(
                "node-world-activations/capability-{}",
                self.request.execution
            ))
            .map_err(refused)?,
        )
        .map_err(refused)
    }
}

fn requirements() -> Result<StateRequirements, NodeObservationServiceError> {
    Ok(StateRequirements {
        preservation_contract: Id::new("independent-group/native-preservation-v1")
            .map_err(refused)?,
        exact_model_continuation: true,
        deterministic: true,
        restore_mode: StateRestoreMode::DurableRestart,
    })
}

fn limits() -> NativeArchiveLimits {
    InstalledNodeCatalog::independent_native_archive_reader_limits()
}

#[path = "failure.rs"]
mod failure;
