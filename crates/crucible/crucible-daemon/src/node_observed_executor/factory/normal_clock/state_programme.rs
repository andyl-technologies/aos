//! Retains actual capture, original retirement and two independent continuations.
//!
//! Signed archives remain historical data. Each branch requires a new measured
//! catalog, source-regenerated graph, opaque native source, fresh preparation and
//! whole-world publication. No original mutable runtime is lent to a branch.

use std::{path::PathBuf, rc::Rc};

use crucible_engine::{
    node_contract::{QuarantinedRuntime, RuntimeSnapshot},
    node_state::{
        NativeArchive, NativeArchiveLimits, NativeArchiveRecord, NativeWorldRestoreDriver,
        RestorePublication, RestoredWorld, StateRequirements, StateRestoreMode, stage_restore,
    },
};

use super::*;

pub(super) const CAPTURE_ORDINAL: u64 = 7;
pub(super) const SUFFIX_PS: u64 = 2_000_003;

pub(super) struct Branch {
    pub(super) execution: ExecutionId,
    pub(super) catalog: InstalledNodeCatalog,
    pub(super) graph: Option<std::rc::Rc<AdmittedGraph>>,
    pub(super) factory: Option<Rc<state::InstalledNormalClockStateFactory>>,
    pub(super) world: Option<Box<RestoredWorld>>,
    pub(super) expected: Option<ClockCase>,
    pub(super) future: Option<NativeArchiveRecord>,
    pub(super) attempted: bool,
    pub(super) failure: Option<crucible_engine::node_state::RestoreFailure>,
}

/// Holds the original artifact and two independently owned fresh Clock branches.
///
/// The service actor must retain this owner before invoking its methods. Every
/// attempt is one-shot; errors preserve the same original and branch capsules.
/// Physical allocator completeness is not inferred from serialized archive credit.
#[must_use = "retain the original archive and both actual continuation owners"]
pub struct OriginalClockStateProgramme {
    pub(super) origin: ClockOrigin,
    pub(super) profile: InstalledNormalClockProfile,
    pub(super) archive: NativeArchive,
    pub(super) artifact: Option<ContentRef>,
    pub(super) record: Option<NativeArchiveRecord>,
    pub(super) original: Option<RuntimeSnapshot>,
    pub(super) branches: [Branch; 2],
    pub(super) capture_attempted: bool,
    pub(super) reopened: bool,
    pub(super) compared: bool,
    pub(super) failed: bool,
}

pub(super) fn limits() -> NativeArchiveLimits {
    let mut limits = NativeArchiveLimits::default();
    // The actual measured daemon executable is a complete immutable input,
    // independently bounded from the small native continuation records.
    limits.state.maximum_content_bytes = 512 * 1024 * 1024;
    limits
}

pub(super) fn requirements() -> Result<StateRequirements, NodeObservedError> {
    Ok(StateRequirements {
        preservation_contract: Id::new(
            crucible_engine::node_adapters::HOST_PUBLIC_CLOCK_CONTINUATION_PROFILE,
        )?,
        exact_model_continuation: true,
        deterministic: true,
        restore_mode: StateRestoreMode::DurableRestart,
    })
}

impl OriginalClockQualificationRun {
    fn capture_and_retire(
        &mut self,
        archive: &NativeArchive,
        factory: &state::InstalledNormalClockStateFactory,
    ) -> Result<(), NodeObservedError> {
        self.current()?;
        if self.failed
            || self.next != self.cases.len()
            || self.capture_attempted
            || self.cases.iter().any(|case| !case.acknowledged)
            || !self.pause.complete()
        {
            return Err(refused(
                "original Clock is not an unused complete capture frontier",
            ));
        }
        self.capture_attempted = true;
        // A panic or error cannot leave the old programme executable.
        self.failed = true;
        let activation = self
            .activation
            .as_ref()
            .ok_or_else(|| refused("original Clock activation absent"))?;
        let cut = self
            .cases
            .last()
            .ok_or_else(|| refused("Clock case population absent"))?
            .expected
            .outcome
            .scheduling
            .as_ref()
            .ok_or_else(|| refused("Clock closed prefix absent"))?
            .reached;
        let runtime = self
            .runtime
            .as_mut()
            .ok_or_else(|| refused("original Clock already retired"))?;
        self.captured = Some(
            archive
                .capture_world_typed(
                    &self.graph,
                    runtime,
                    activation,
                    cut,
                    U64::new(CAPTURE_ORDINAL),
                    Id::new("normal-clock/original-state")?,
                    requirements()?,
                    factory,
                    factory,
                )
                .map_err(super::super::native)?,
        );
        self.retirement_attempted = true;
        // The original slot remains owned if availability refuses. On success
        // the real quarantine capsule retains native handles and history.
        self.retired = Some(NodeRuntime::take_graceful_retirement(&mut self.runtime)?);
        self.current()
    }

    fn finish_retirement(&mut self) -> Result<(), NodeObservedError> {
        self.current()?;
        let original = self
            .captured
            .as_ref()
            .ok_or_else(|| refused("original capture absent"))?
            .runtime_snapshot()
            .map_err(super::super::native)?;
        let retired: &mut QuarantinedRuntime = self
            .retired
            .as_mut()
            .ok_or_else(|| refused("original Clock retirement absent"))?;
        match retired.poll_reclamation(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Err(super::super::native(error)),
            Poll::Pending => {
                return Err(refused(
                    "synchronous original Clock reclamation remains pending",
                ));
            }
        }
        retired.authenticate_retired_ledger(&original, limits().state.maximum_record_bytes)?;
        self.current()
    }
}

impl OriginalClockStateProgramme {
    /// Reserves actual branch holders under the current measured installation.
    ///
    /// Namespaces and the archive are local qualification data, never source
    /// authority. The caller retains this returned owner before any capture.
    ///
    /// # Errors
    /// Refuses changed source, invalid archive paths or unavailable branch custody.
    pub fn new(
        catalog: &InstalledNodeCatalog,
        archive_path: PathBuf,
        branch_namespaces: [PathBuf; 2],
        executions: [ExecutionId; 2],
    ) -> Result<Self, NodeObservedError> {
        let profile = catalog.installed_normal_clock()?;
        if branch_namespaces[0] == branch_namespaces[1]
            || executions[0] == executions[1]
            || branch_namespaces
                .iter()
                .any(|path| !path.is_absolute() || path == &catalog.socket_parent)
            || !archive_path.is_absolute()
        {
            return Err(refused("normal Clock independent branch scope differs"));
        }
        let [left, right] = branch_namespaces;
        let branch = |namespace, execution| -> Result<Branch, NodeObservedError> {
            Ok(Branch {
                execution,
                catalog: (if catalog.runtime_wake.is_some() {
                    InstalledNodeCatalog::new_with_bounded_runtime_wake
                } else {
                    InstalledNodeCatalog::new
                })(
                    catalog.device_executable.clone(),
                    catalog.device_identity.clone(),
                    namespace,
                    catalog.control_timeout,
                    2,
                )?,
                graph: None,
                factory: None,
                world: None,
                expected: None,
                future: None,
                attempted: false,
                failure: None,
            })
        };
        Ok(Self {
            origin: ClockOrigin {
                source: catalog.host_identity.clone(),
                source_path: catalog.host_executable.clone(),
                process: std::process::id(),
                thread: std::thread::current().id(),
            },
            profile,
            archive: NativeArchive::open(archive_path, limits()).map_err(super::super::native)?,
            artifact: None,
            record: None,
            original: None,
            branches: [branch(left, executions[0])?, branch(right, executions[1])?],
            capture_attempted: false,
            reopened: false,
            compared: false,
            failed: false,
        })
    }

    /// Captures the actual nonzero frontier and reclaims its original owner.
    ///
    /// The same fenced original remains retained in its programme. Both fresh
    /// branches are forbidden until its real retirement receipt authenticates
    /// the unchanged original operation, ACK, input and activation ledger.
    ///
    /// # Errors
    /// Refuses prior attempts, incomplete original work or failed native retirement.
    pub fn capture_and_retire_original(
        &mut self,
        original: &mut OriginalClockQualificationRun,
        catalog: &InstalledNodeCatalog,
    ) -> Result<(), NodeObservedError> {
        self.origin.current()?;
        if self.capture_attempted || self.failed {
            return Err(refused("Clock state capture already attempted"));
        }
        self.capture_attempted = true;
        self.failed = true;
        let factory = catalog.installed_normal_clock_state_factory(&self.profile)?;
        original.capture_and_retire(&self.archive, factory.as_ref())?;
        original.finish_retirement()?;
        let record = original
            .captured
            .as_ref()
            .ok_or_else(|| refused("original signed Clock capture absent"))?;
        self.artifact = Some(record.artifact().clone());
        self.original = Some(record.runtime_snapshot().map_err(super::super::native)?);
        // Reload the signed artifact from durable storage after authenticating
        // real source retirement. A retained in-memory native pointer is not a
        // restoration input; the original capsule is never loaned below.
        self.record = Some(
            self.archive
                .load(record.artifact())
                .map_err(super::super::native)?,
        );
        self.reopened = true;
        self.origin.current()?;
        self.failed = false;
        Ok(())
    }

    pub(super) fn original_state_witness<'a>(
        &'a mut self,
        original: &'a OriginalClockQualificationRun,
    ) -> Result<super::state_witness::OriginalClockStateWitness<'a>, NodeObservedError> {
        self.origin.current()?;
        if !self.compared || self.failed {
            return Err(refused("Clock complete original state unavailable"));
        }
        let snapshot = |branch: &mut Branch| -> Result<RuntimeSnapshot, NodeObservedError> {
            let world = branch
                .world
                .as_mut()
                .ok_or_else(|| refused("actual Clock branch absent"))?;
            Ok(world.runtime_mut().runtime_snapshot(
                Position::new(SUFFIX_PS.into(), 0.into(), Phase::BoundaryControl),
                (CAPTURE_ORDINAL + 1).into(),
                super::state_witness::MAXIMUM_STATE_BYTES,
            )?)
        };
        let [left, right] = &mut self.branches;
        let fresh = [snapshot(left)?, snapshot(right)?];
        let witness = super::state_witness::OriginalClockStateWitness {
            programme: self,
            original,
            fresh,
        };
        witness.authenticate_current()?;
        Ok(witness)
    }

    /// Borrows the actual captured artifact after original owner retirement.
    pub fn artifact_data(&self) -> Option<&ContentRef> {
        self.artifact.as_ref()
    }

    /// Reports whether the two actual fresh continuations were fully compared.
    ///
    /// This is diagnostic data, never a normal class or activation permission.
    pub fn compared_data(&self) -> bool {
        self.compared && !self.failed
    }

    /// Restores and executes one independent branch through full native barriers.
    ///
    /// Expected suffix state and complete receipt bodies are fixed before model
    /// construction. Each branch retains its actual restored world before any
    /// operation. Branch one requires successful branch zero; no retry occurs.
    ///
    /// # Errors
    /// Refuses changed source, missing retirement, duplicate/out-of-order branches,
    /// native source/restore/publication failures or any full suffix mismatch.
    pub fn execute_branch(
        &mut self,
        index: usize,
        publisher: &mut dyn ActivationPublisher,
    ) -> Result<(), NodeObservedError> {
        self.origin.current()?;
        if self.failed
            || !self.reopened
            || index >= 2
            || (index == 1 && self.branches[0].future.is_none())
        {
            return Err(refused("normal Clock continuation branch is unavailable"));
        }
        self.failed = true;
        let record = self
            .record
            .as_ref()
            .ok_or_else(|| refused("durably reloaded Clock source absent"))?;
        let branch = &mut self.branches[index];
        if branch.attempted {
            return Err(refused("normal Clock continuation already attempted"));
        }
        branch.attempted = true;
        let factory = branch
            .catalog
            .installed_normal_clock_state_factory(&self.profile)?;
        // Preserve the concrete origin before staging or any factory callback.
        // Later storage reads authenticate this same allocation, never a label.
        branch.factory = Some(Rc::clone(&factory));
        let (graph, target) = branch.catalog.prepare_normal_clock_restore_graph(
            &self.profile,
            record,
            branch.execution,
        )?;
        let graph = Rc::new(graph);
        // The initial graph-generation capsule cannot escape as restored state.
        match branch
            .catalog
            .poll_original_runtime_custody(&mut Context::from_waker(Waker::noop()))?
        {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Err(super::super::native(error)),
            Poll::Pending => {
                return Err(refused(
                    "discarded initial Clock reclamation remains pending",
                ));
            }
        }
        if branch.catalog.custody().reserved_worlds() != 0 {
            return Err(refused("discarded initial Clock preparation remains owned"));
        }
        branch.graph = Some(Rc::clone(&graph));
        let node = self.profile.selection.node.clone();
        let operation = Id::new("normal-clock/future")?;
        let limit = Position::new(U64::new(SUFFIX_PS), U64::new(0), Phase::BoundaryControl);
        let expected = ExpectedClockCase::new(
            &node,
            &target.owners,
            &operation,
            target.boundary,
            limit,
            false,
        )?;
        let oracle_bytes = canonical::canonical_json(
            &serde_json::json!({"schema":"crucible.normal-clock-state-suffix/1","request":expected.request,"outcome":expected.outcome,"objects":expected.objects}),
        )?;
        branch.expected = Some(ClockCase {
            name: "normal-clock/future",
            operation,
            expected,
            oracle: InputPayload {
                reference: canonical::content_ref(&oracle_bytes, "application/json")?,
                bytes: oracle_bytes,
            },
            attempted: false,
            token: None,
            objects: None,
            acknowledged: false,
            collected: false,
        });
        let verified = record
            .admit(&graph, requirements()?, factory.as_ref())
            .map_err(super::super::native)?;
        let mut driver = NativeWorldRestoreDriver::new(
            Rc::clone(&graph),
            record.clone(),
            factory.clone(),
            branch.catalog.custody().clone(),
        )
        .map_err(super::super::native)?;
        let prepared = match stage_restore(&graph, verified, target, &mut driver, limits().state) {
            Ok(prepared) => prepared,
            Err(failure) => {
                branch.failure = Some(failure);
                return Err(refused("Clock original restoration failure retained"));
            }
        };
        let prepared = match prepared
            .retain_original_coordinator(publisher, MAXIMUM_ACTIVATION_COORDINATOR_BYTES)
        {
            Ok(prepared) => prepared,
            Err(failure) => {
                branch.failure = Some(failure);
                return Err(refused(
                    "Clock original coordinator handoff failure retained",
                ));
            }
        };
        let world = match prepared.publish_original_retained(publisher) {
            RestorePublication::Committed(world) => world,
            RestorePublication::Failed(failure) => {
                branch.failure = Some(failure);
                return Err(refused("Clock original publication failure retained"));
            }
            RestorePublication::Uncertain(pending) => {
                branch.failure = Some((*pending).retain_uncertain_failure());
                return Err(refused(
                    "Clock original publication remains uncertain and retained",
                ));
            }
        };
        branch.world = Some(world);
        let world = branch
            .world
            .as_mut()
            .ok_or_else(|| refused("actual fresh Clock world absent"))?;
        let activation = world.activation().clone();
        let original = self
            .original
            .as_ref()
            .ok_or_else(|| refused("retired original ledger absent"))?;
        let restored = world.runtime_mut().runtime_snapshot(
            original.capture_cut,
            original.capture_ordinal,
            limits().state.maximum_record_bytes,
        )?;
        authenticate_restored_history(original, &restored, activation.record())?;
        let case = branch
            .expected
            .as_mut()
            .ok_or_else(|| refused("Clock suffix oracle absent"))?;
        execute_clock_case(world.runtime_mut(), &graph, &activation, &node, case)?;
        branch.future = Some(
            self.archive
                .capture_world_typed(
                    &graph,
                    world.runtime_mut(),
                    &activation,
                    limit,
                    U64::new(CAPTURE_ORDINAL + 1),
                    Id::new(format!("normal-clock/branch-{index}"))?,
                    requirements()?,
                    factory.as_ref(),
                    factory.as_ref(),
                )
                .map_err(super::super::native)?,
        );
        self.origin.current()?;
        self.failed = false;
        Ok(())
    }

    /// Authenticates both actual suffixes, signed native bytes and fresh owners.
    ///
    /// Normal class collection must still bind this original owner through its
    /// installed source. This data result cannot issue an Accepted class policy.
    ///
    /// # Errors
    /// Refuses incomplete or repeated comparison, shared fresh identity, differing
    /// original history or nonidentical independently checked native suffixes.
    pub fn authenticate_repeatable_continuations(&mut self) -> Result<(), NodeObservedError> {
        self.origin.current()?;
        if self.failed || self.compared {
            return Err(refused("normal Clock state comparison unavailable"));
        }
        self.failed = true;
        let left = &self.branches[0];
        let right = &self.branches[1];
        let left_world = left
            .world
            .as_ref()
            .ok_or_else(|| refused("left Clock branch absent"))?;
        let right_world = right
            .world
            .as_ref()
            .ok_or_else(|| refused("right Clock branch absent"))?;
        if left_world.activation().record().owners == right_world.activation().record().owners
            || left_world.activation().record().activation_id
                == right_world.activation().record().activation_id
        {
            return Err(refused("independent Clock branches reused live authority"));
        }
        let mut native = Vec::new();
        for branch in &self.branches {
            let future = branch
                .future
                .as_ref()
                .ok_or_else(|| refused("actual future native capture absent"))?;
            let graph = branch
                .graph
                .as_ref()
                .ok_or_else(|| refused("actual future graph absent"))?;
            let factory = branch
                .catalog
                .installed_normal_clock_state_factory(&self.profile)?;
            let admitted = future
                .admit(graph, requirements()?, factory.as_ref())
                .map_err(super::super::native)?;
            let saved = future.runtime_snapshot().map_err(super::super::native)?;
            let owner = future
                .owners()
                .first()
                .ok_or_else(|| refused("actual future Clock owner absent"))?;
            let source = future
                .authenticated_source(&owner.owner, &saved, admitted.content())
                .map_err(super::super::native)?;
            let inventory = crucible_engine::node_adapters::validate_public_clock_continuation(
                &source,
                graph,
                &self.profile.selection.node,
                state::resources(),
            )
            .map_err(super::super::native)?;
            let expected_native =
                crucible_engine::node_adapters::host_clock_initial_bytes(SUFFIX_PS);
            if inventory.native_model.bytes != expected_native {
                return Err(refused("actual Clock suffix native integer differs"));
            }
            let case = branch
                .expected
                .as_ref()
                .ok_or_else(|| refused("actual Clock suffix original absent"))?;
            if !case.acknowledged {
                return Err(refused("actual Clock suffix ACK absent"));
            }
            case.expected.authenticate_objects(
                case.objects
                    .as_deref()
                    .ok_or_else(|| refused("actual suffix bodies absent"))?,
            )?;
            native.push(inventory.native_model.bytes);
        }
        if native[0] != native[1] {
            return Err(refused("independent future Clock state differs"));
        }
        self.compared = true;
        self.origin.current()?;
        self.failed = false;
        Ok(())
    }
}

fn authenticate_restored_history(
    original: &RuntimeSnapshot,
    restored: &RuntimeSnapshot,
    target: &crucible_engine::node_contract::ActivationRecord,
) -> Result<(), NodeObservedError> {
    use crucible_engine::node_contract::SavedRuntimeResult;

    if !original.inputs.is_empty()
        || original.terminal.is_some()
        || original.condition_stop.is_some()
        || target.world_binding_hash != original.source_activation.world_binding_hash
        || target.generation <= original.source_activation.generation
        || target.activation_id == original.source_activation.activation_id
        || target.boundary != original.capture_cut
    {
        return Err(refused("fresh Clock authority/history selection differs"));
    }
    // Predict exactly Core's installed source-to-target rebind. Every other
    // field, including original proof references, ACKs and committed outputs,
    // must remain identical; observed history never supplies expected values.
    let mut expected = original.clone();
    expected.source_activation = target.into();
    for owner in &mut expected.owners {
        owner.identity = target
            .owners
            .iter()
            .find(|fresh| fresh.owner == owner.identity.owner)
            .filter(|fresh| {
                fresh.incarnation != owner.identity.incarnation
                    && fresh.generation > owner.identity.generation
            })
            .ok_or_else(|| refused("fresh Clock owner did not advance original lineage"))?
            .clone();
    }
    for operation in &mut expected.operations {
        for owner in &mut operation.route.owners {
            *owner = target
                .owners
                .iter()
                .find(|fresh| fresh.owner == owner.owner)
                .ok_or_else(|| refused("fresh Clock operation owner absent"))?
                .clone();
        }
        match &mut operation.result {
            SavedRuntimeResult::Complete(outcome) | SavedRuntimeResult::Acknowledged(outcome) => {
                outcome.owners = operation.route.owners.clone();
                if let Some(observation) = &mut outcome.scheduling {
                    observation.owners = operation.route.owners.clone();
                }
            }
            SavedRuntimeResult::Pending | SavedRuntimeResult::Failed(_) => {
                return Err(refused("Clock source programme has unfinished native work"));
            }
        }
    }
    if restored != &expected {
        return Err(refused(
            "fresh Clock lost or changed original complete history",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "state_tests.rs"]
mod tests;

impl OriginalClockStateProgramme {
    pub(super) fn authenticate_live_requested_storage_data(
        &mut self,
        aggregate: &OriginalClockAggregateResources,
    ) -> Result<(), NodeObservedError> {
        self.origin.current()?;
        if self.failed || self.branches.iter().any(|branch| branch.failure.is_some()) {
            // RestoreFailure can own opaque panic/callback backing. Retention
            // is genuine; its unknown requested geometry must not become zero.
            return Err(super::super::native(
                crucible_engine::node_contract::RuntimeError::UnsupportedFacet,
            ));
        }
        for branch in &mut self.branches {
            let world = branch
                .world
                .as_mut()
                .ok_or_else(|| refused("Clock actual fresh world absent"))?;
            aggregate
                .authenticate_runtime_data(world.runtime_mut())
                .map_err(super::super::native)?;
        }
        self.origin.current()
    }
}

impl crate::node_qualification::RetainedMetadataOwned for Branch {
    fn charge(
        &self,
        counter: &mut crate::node_qualification::RetainedMetadataCounter,
    ) -> Result<(), QualificationError> {
        use std::mem::size_of;
        let Self {
            execution: _,
            catalog,
            graph,
            factory,
            world,
            expected,
            future,
            attempted: _,
            failure,
        } = self;
        if failure.is_some() {
            // Opaque panic payloads/failed native ownership stay retained. No
            // later construction receives zero credit for these unknown banks.
            return Err(QualificationError::Refused(
                "unsupported retained Clock restore failure storage",
            ));
        }
        counter.charge(catalog)?;
        if let Some(graph) = graph {
            if counter.rc(graph)? {
                counter.charge(graph.as_ref())?;
            }
        }
        if let Some(factory) = factory {
            if counter.rc(factory)? {
                counter.charge(factory.as_ref())?;
            }
        }
        if let Some(world) = world {
            let typed = factory.as_ref().ok_or(QualificationError::Refused(
                "Clock restored factory owner absent",
            ))?;
            // This retained concrete allocation came from the same branch's
            // original catalog before the real driver callback. No arbitrary
            // factory/enum label is accepted as a readonly staging promise.
            let original: Rc<dyn crucible_engine::node_state::NativeWorldFactory> = typed.clone();
            counter.add(size_of::<RestoredWorld>())?;
            let bytes = world
                .original_closed_requested_storage_precredit_data(&original, counter.remaining())
                .map_err(|_| {
                    QualificationError::Refused("Clock restored world storage unavailable")
                })?;
            counter.add(bytes)?;
        }
        counter.charge(expected)?;
        counter.charge(future)
    }
}

impl crate::node_qualification::RetainedMetadataOwned for OriginalClockStateProgramme {
    fn charge(
        &self,
        counter: &mut crate::node_qualification::RetainedMetadataCounter,
    ) -> Result<(), QualificationError> {
        let Self {
            origin,
            profile,
            archive,
            artifact,
            record,
            original,
            branches,
            capture_attempted: _,
            reopened: _,
            compared: _,
            failed: _,
        } = self;
        counter.charge(origin)?;
        counter.charge(profile)?;
        counter.add(archive.retained_requested_storage_precredit_data())?;
        counter.charge(artifact)?;
        counter.charge(record)?;
        counter.charge(original)?;
        counter.charge(branches)
    }
}

impl OriginalClockStateProgramme {
    pub(super) fn original_storage_scratch_data(&self) -> Result<usize, QualificationError> {
        let mut scratch =
            AdmittedGraph::original_retained_requested_storage_precredit_scratch_data();
        for branch in &self.branches {
            if branch.failure.is_some() {
                return Err(QualificationError::Refused(
                    "opaque Clock restoration scratch",
                ));
            }
            if let Some(world) = &branch.world {
                let factory = branch
                    .factory
                    .as_ref()
                    .ok_or(QualificationError::Refused("Clock restored factory absent"))?;
                let original: Rc<dyn crucible_engine::node_state::NativeWorldFactory> =
                    factory.clone();
                scratch = scratch.max(
                    world
                        .original_closed_requested_storage_precredit_scratch_data(&original)
                        .map_err(|_| {
                            QualificationError::Refused("Clock restored owning scratch unavailable")
                        })?,
                );
            }
        }
        scratch
            .checked_add(std::mem::size_of::<
                Rc<dyn crucible_engine::node_state::NativeWorldFactory>,
            >())
            .ok_or(QualificationError::Refused(
                "Clock restoration scratch overflow",
            ))
    }
}
