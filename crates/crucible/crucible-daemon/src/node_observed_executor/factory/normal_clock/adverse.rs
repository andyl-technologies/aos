//! Exercises actual two-owner readiness loss and post-commit effect containment.
//!
//! Both worlds are regenerated from the installed public Clock implementation.
//! The only faults deliberately withhold already validated original messages;
//! no model, native result, ready record or publisher success is supplied by a
//! caller. Each world and its real failure capsule remain actor-owned. These
//! originals do not grant behavioral acceptance or clear other missing suites.

use crucible_engine::node_contract::{
    Lifecycle, NodeStatus, OriginalCompletionLoss, OriginalReadinessLoss, PhysicalState,
    PublicationStatus, RuntimeError, RuntimePollFailure, SavedRuntimeActivation,
};

use super::*;

mod witness;
pub use witness::OriginalClockAdverseWitness;

type Status = (Lifecycle, PhysicalState, Option<Position>);

struct Fixture {
    execution: ExecutionId,
    catalog: InstalledNodeCatalog,
    scenario: Option<crate::node_scenario::NodeScenario>,
    graph: Option<AdmittedGraph>,
    runtime: Option<NodeRuntime>,
    proposal: Option<crucible_engine::node_contract::ActivationRecord>,
    activation: Option<WorldActivation>,
    before: Option<[Status; 2]>,
    after: Option<[Status; 2]>,
    first: Option<ClockCase>,
    second: Option<ClockCase>,
    attempted: bool,
}

pub(super) struct OriginalClockAdverseProgramme {
    origin: ClockOrigin,
    worlds: [Fixture; 2],
    readiness_loss: Option<OriginalReadinessLoss>,
    completion_loss: Option<OriginalCompletionLoss>,
    before_gate_errors: Vec<RuntimePollFailure>,
    arm_error: Option<RuntimeError>,
    activation_error: Option<RuntimeError>,
    unexpected_activation: Option<WorldActivation>,
    after_gate_error: Option<RuntimePollFailure>,
    actual_lost_completion: Option<RuntimePollFailure>,
    first_after_effect: Option<Vec<InputPayload>>,
    publication_before: Option<PublicationStatus>,
    publication_after: Option<PublicationStatus>,
    attempted: bool,
    complete: bool,
}

impl Fixture {
    fn from_catalog(catalog: InstalledNodeCatalog, execution: ExecutionId) -> Self {
        Self {
            execution,
            catalog,
            scenario: None,
            graph: None,
            runtime: None,
            proposal: None,
            activation: None,
            before: None,
            after: None,
            first: None,
            second: None,
            attempted: false,
        }
    }

    fn prepare(&mut self) -> Result<(), NodeObservedError> {
        if self.attempted {
            return Err(refused("Clock adverse world already attempted"));
        }
        self.attempted = true;
        let prepared = self
            .catalog
            .prepare_original_clock_activation_world(self.execution)?;
        self.proposal = Some(prepared.realization.activation_record().clone());
        self.scenario = Some(prepared.scenario);
        self.graph = Some(prepared.graph);
        let graph = self
            .graph
            .as_ref()
            .ok_or_else(|| refused("Clock adverse graph absent"))?;
        // The catalog retains failed preparations through its ordinary native
        // custody. The successful runtime enters this actor-owned slot at once.
        self.runtime = Some(
            prepared
                .realization
                .admit(graph)
                .map_err(|failure| super::super::native(&failure.error))?,
        );
        let proposal = self
            .proposal
            .as_ref()
            .ok_or_else(|| refused("Clock adverse proposal absent"))?;
        if proposal.owners.len() != 2 || proposal.boundary.time_ps.get() != 0 {
            return Err(refused("Clock adverse initial owner population differs"));
        }
        for (index, (node, owner)) in profile::ACTIVATION_CLOCKS.iter().enumerate() {
            let owners = proposal
                .owners
                .iter()
                .filter(|actual| actual.owner.as_str() == *owner)
                .cloned()
                .collect::<Vec<_>>();
            if owners.len() != 1 {
                return Err(refused("Clock adverse independent owner absent"));
            }
            let operation = Id::new(if index == 0 {
                "clock/adverse-published-effect"
            } else {
                "clock/adverse-lost-completion"
            })?;
            let expected = ExpectedClockCase::new(
                &Id::new(*node)?,
                &owners,
                &operation,
                proposal.boundary,
                Position::new(
                    U64::new(index as u64 + 1),
                    U64::new(0),
                    Phase::BoundaryControl,
                ),
                false,
            )?;
            // This full oracle is fixed before either native owner is armed.
            let bytes = canonical::canonical_json(&serde_json::json!({
                "schema":"crucible.normal-clock-adverse-effect/1",
                "request":expected.request,"outcome":expected.outcome,"objects":expected.objects,
            }))?;
            let case = ClockCase {
                name: if index == 0 {
                    "clock/adverse-published-effect"
                } else {
                    "clock/adverse-lost-completion"
                },
                operation,
                expected,
                oracle: InputPayload {
                    reference: canonical::content_ref(&bytes, "application/json")?,
                    bytes,
                },
                attempted: false,
                token: None,
                objects: None,
                acknowledged: false,
                collected: false,
            };
            if index == 0 {
                self.first = Some(case);
            } else {
                self.second = Some(case);
            }
        }
        self.before = Some(statuses(
            self.runtime
                .as_mut()
                .ok_or_else(|| refused("Clock adverse runtime absent"))?,
        )?);
        if self.before
            != Some([
                (
                    Lifecycle::Prepared,
                    PhysicalState::Suspended,
                    Some(proposal.boundary),
                ),
                (
                    Lifecycle::Prepared,
                    PhysicalState::Suspended,
                    Some(proposal.boundary),
                ),
            ])
        {
            return Err(refused(
                "Clock adverse owners are not independently inactive at birth",
            ));
        }
        Ok(())
    }
}

impl OriginalClockAdverseProgramme {
    pub(super) fn new(
        catalog: &InstalledNodeCatalog,
        aggregate: &OriginalClockAggregateResources,
        original: ExecutionId,
        executions: [ExecutionId; 2],
    ) -> Result<Self, NodeObservedError> {
        if executions[0] == executions[1] || executions.contains(&original) {
            return Err(refused(
                "Clock adverse executions must be independently fresh",
            ));
        }
        let root = aggregate
            .publication_path_data()
            .map_err(super::super::native)?;
        let fixture = |execution, suffix| -> Result<Fixture, NodeObservedError> {
            let actual = InstalledNodeCatalog::new_with_bounded_runtime_wake(
                catalog.device_executable.clone(),
                catalog.device_identity.clone(),
                root.join(suffix),
                catalog.control_timeout,
                1,
            )?;
            if actual.host_identity != catalog.host_identity {
                return Err(refused("Clock adverse catalog has another host image"));
            }
            Ok(Fixture::from_catalog(actual, execution))
        };
        let mut before_gate_errors = Vec::new();
        before_gate_errors
            .try_reserve_exact(2)
            .map_err(|_| refused("Clock gate refusal bank reservation"))?;
        Ok(Self {
            origin: ClockOrigin {
                source: catalog.host_identity.clone(),
                source_path: catalog.host_executable.clone(),
                process: std::process::id(),
                thread: std::thread::current().id(),
            },
            worlds: [
                fixture(executions[0], "adverse-readiness")?,
                fixture(executions[1], "adverse-effect")?,
            ],
            readiness_loss: None,
            completion_loss: None,
            before_gate_errors,
            arm_error: None,
            activation_error: None,
            unexpected_activation: None,
            after_gate_error: None,
            actual_lost_completion: None,
            first_after_effect: None,
            publication_before: None,
            publication_after: None,
            attempted: false,
            complete: false,
        })
    }

    pub(super) fn original_executions_data(&self) -> [ExecutionId; 2] {
        [self.worlds[0].execution, self.worlds[1].execution]
    }

    pub(super) fn execute(
        &mut self,
        original: &WorldActivation,
        aggregate: &OriginalClockAggregateResources,
        publisher: &mut crate::node_observed_executor::StoredWorldActivationPublisher,
    ) -> Result<(), NodeObservedError> {
        self.origin.current()?;
        if self.attempted {
            return Err(refused("Clock adverse programme already attempted"));
        }
        self.attempted = true;
        aggregate
            .authenticate_current()
            .map_err(super::super::native)?;
        self.execute_readiness_loss(original, publisher)?;
        self.check_original_loss_data_storage(aggregate.limits_data().memory_bytes.get())?;
        aggregate
            .authenticate_current()
            .map_err(super::super::native)?;
        self.execute_postcommit_loss(publisher)?;
        self.check_original_loss_data_storage(aggregate.limits_data().memory_bytes.get())?;
        aggregate
            .authenticate_current()
            .map_err(super::super::native)?;
        self.origin.current()?;
        self.complete = true;
        Ok(())
    }

    // These are the two actual newly retained loss-data components, not an
    // exhaustive programme/Source/native resource row. The full bounded normal
    // caller must still account for every other owner and its simultaneous
    // scratch. This check cannot substitute for that separate admission.
    fn check_original_loss_data_storage(&self, maximum: u64) -> Result<(), NodeObservedError> {
        let maximum = usize::try_from(maximum)
            .map_err(|_| refused("Clock loss data address-space ceiling"))?;
        let scratch = OriginalReadinessLoss::retained_requested_storage_scratch_data()
            .max(OriginalCompletionLoss::retained_requested_storage_scratch_data());
        let mut bytes = scratch;
        if let Some(original) = &self.readiness_loss {
            bytes = bytes
                .checked_add(original.retained_requested_storage_data(maximum)?)
                .ok_or_else(|| refused("Clock readiness data layout overflow"))?;
        }
        if let Some(original) = &self.completion_loss {
            bytes = bytes
                .checked_add(original.retained_requested_storage_data(maximum)?)
                .ok_or_else(|| refused("Clock completion data layout overflow"))?;
        }
        if bytes > maximum {
            return Err(refused(
                "Clock original loss data plus fixed scratch exceeds policy",
            ));
        }
        Ok(())
    }

    fn execute_readiness_loss(
        &mut self,
        original: &WorldActivation,
        publisher: &mut dyn ActivationPublisher,
    ) -> Result<(), NodeObservedError> {
        let fixture = &mut self.worlds[0];
        fixture.prepare()?;
        let runtime = fixture
            .runtime
            .as_mut()
            .ok_or_else(|| refused("Clock lost-ready runtime absent"))?;
        self.arm_error = match runtime
            .arm_all_with_original_readiness_loss(&Id::new("clock-b")?, &mut self.readiness_loss)
        {
            Err(error) => Some(error),
            Ok(()) => return Err(refused("Clock readiness-loss cut returned success")),
        };
        let loss = self
            .readiness_loss
            .as_ref()
            .ok_or_else(|| refused("Clock actual lost readiness absent"))?;
        if !matches!(self.arm_error, Some(RuntimeError::InvalidReceipt))
            || loss.activation_record_data()
                != fixture
                    .proposal
                    .as_ref()
                    .ok_or_else(|| refused("Clock lost-ready proposal absent"))?
            || loss.preceding_preparations_data().len() != 1
            || loss.preceding_preparations_data()[0].node().as_str() != "clock-a"
            || loss.withheld_preparation_data().node().as_str() != "clock-b"
        {
            return Err(refused(
                "Clock loss was not after real first-owner readiness",
            ));
        }
        // Attempt the ordinary publication entry on the actual abandoned world.
        // A refusal observation alone cannot establish that activate() keeps the
        // gate closed. The real stored publisher is the same one used below;
        // no caller-provided success or replacement readiness is introduced.
        self.activation_error = match runtime.activate(publisher) {
            Err(error) => Some(error),
            Ok(activation) => {
                self.unexpected_activation = Some(activation);
                return Err(refused("Clock lost-readiness world unexpectedly activated"));
            }
        };
        if !matches!(self.activation_error, Some(RuntimeError::OwnerUnavailable)) {
            return Err(refused(
                "Clock lost-readiness publication refused differently",
            ));
        }
        for (node, _) in profile::ACTIVATION_CLOCKS {
            let refusal = match runtime.observe_scheduling(original, &Id::new(node)?) {
                Err(error) => error,
                Ok(_) => {
                    return Err(refused(
                        "Clock inactive adverse world issued native observation",
                    ));
                }
            };
            self.before_gate_errors.push(refusal);
        }
        fixture.after = Some(statuses(runtime)?);
        let boundary = loss.activation_record_data().boundary;
        if self.before_gate_errors.len() != 2
            || !self.before_gate_errors.iter().all(|error| {
                matches!(
                    error,
                    RuntimePollFailure::Admission(RuntimeError::NotActivated)
                )
            })
            || fixture.after
                != Some([
                    (
                        Lifecycle::Prepared,
                        PhysicalState::Suspended,
                        Some(boundary),
                    ),
                    (
                        Lifecycle::Quarantined,
                        PhysicalState::Suspended,
                        Some(boundary),
                    ),
                ])
        {
            return Err(refused(
                "Clock lost readiness opened a gate or changed native boundary",
            ));
        }
        Ok(())
    }

    fn execute_postcommit_loss(
        &mut self,
        publisher: &mut dyn ActivationPublisher,
    ) -> Result<(), NodeObservedError> {
        let fixture = &mut self.worlds[1];
        fixture.prepare()?;
        let runtime = fixture
            .runtime
            .as_mut()
            .ok_or_else(|| refused("Clock postcommit runtime absent"))?;
        let graph = fixture
            .graph
            .as_ref()
            .ok_or_else(|| refused("Clock postcommit graph absent"))?;
        let proposal = fixture
            .proposal
            .as_ref()
            .ok_or_else(|| refused("Clock postcommit proposal absent"))?;
        runtime.arm_all()?;
        let coordinator =
            runtime.initial_coordinator_snapshot(graph, MAXIMUM_ACTIVATION_COORDINATOR_BYTES)?;
        publisher.retain_initial_coordinator(
            proposal,
            runtime.prepared_node_records()?.to_vec(),
            coordinator,
        )?;
        fixture.activation = Some(runtime.activate(publisher)?);
        let activation = fixture
            .activation
            .as_ref()
            .ok_or_else(|| refused("Clock actual postcommit activation absent"))?;
        let prepared = activation
            .prepared_publication_data()
            .ok_or_else(|| refused("Clock complete original publication absent"))?;
        self.publication_before = Some(publisher.reconcile_complete(activation.record(), prepared));
        if self.publication_before != Some(PublicationStatus::Committed) {
            return Err(refused(
                "Clock adverse complete publication not genuinely durable",
            ));
        }
        let first = fixture
            .first
            .as_mut()
            .ok_or_else(|| refused("Clock first effect oracle absent"))?;
        execute_clock_case(runtime, graph, activation, &Id::new("clock-a")?, first)?;
        let second = fixture
            .second
            .as_mut()
            .ok_or_else(|| refused("Clock second effect oracle absent"))?;
        execute_clock_case_selected(
            runtime,
            graph,
            activation,
            &Id::new("clock-b")?,
            second,
            false,
        )?;
        let token = second
            .token
            .as_ref()
            .ok_or_else(|| refused("Clock second effect token absent"))?;
        runtime.retain_original_completion_loss(token, &mut self.completion_loss)?;
        self.actual_lost_completion =
            match runtime.poll(token, &mut Context::from_waker(Waker::noop())) {
                Poll::Ready(Err(error)) => Some(error),
                _ => {
                    return Err(refused(
                        "Clock lost completion did not retain explicit failure",
                    ));
                }
            };
        self.after_gate_error = match runtime.observe_scheduling(activation, &Id::new("clock-b")?) {
            Err(error) => Some(error),
            Ok(_) => {
                return Err(refused(
                    "Clock contained owner remains ordinarily schedulable",
                ));
            }
        };
        let first_token = first
            .token
            .as_ref()
            .ok_or_else(|| refused("Clock published effect token absent"))?;
        let refs = first
            .expected
            .objects
            .iter()
            .map(|body| body.reference.clone())
            .collect::<Vec<_>>();
        self.first_after_effect = Some(runtime.original_witness().operation_evidence(
            first_token,
            &refs,
            U64::new(MAXIMUM_CASE_BYTES as u64),
        )?);
        first.expected.authenticate_objects(
            self.first_after_effect
                .as_deref()
                .ok_or_else(|| refused("Clock original published bodies absent after failure"))?,
        )?;
        fixture.after = Some(statuses(runtime)?);
        self.publication_after = Some(publisher.reconcile_complete(activation.record(), prepared));
        if !matches!(
            self.after_gate_error,
            Some(RuntimePollFailure::Admission(
                RuntimeError::OwnerUnavailable
            ))
        ) || !matches!(self.actual_lost_completion, Some(RuntimePollFailure::Native(ref failure)) if failure.effects == crucible_engine::node_contract::EffectKnowledge::Unknown)
            || self
                .completion_loss
                .as_ref()
                .is_none_or(|loss| loss.original_outcome_data() != &second.expected.outcome)
            || !first.acknowledged
            || second.acknowledged
            || self.first_after_effect != first.objects
            || self.publication_after != Some(PublicationStatus::Committed)
            || fixture.after
                != Some([
                    (
                        Lifecycle::Stopped,
                        PhysicalState::Suspended,
                        Some(Position::new(1.into(), 0.into(), Phase::BoundaryControl)),
                    ),
                    (
                        Lifecycle::Quarantined,
                        PhysicalState::Suspended,
                        Some(Position::new(2.into(), 0.into(), Phase::BoundaryControl)),
                    ),
                ])
        {
            return Err(refused(
                "Clock postcommit effect, uncertainty or containment oracle differs",
            ));
        }
        Ok(())
    }

    fn authenticate_observed_data(
        &mut self,
        original: &OriginalClockQualificationRun,
        publisher: &mut crate::node_observed_executor::StoredWorldActivationPublisher,
    ) -> Result<(), NodeObservedError> {
        self.origin.current()?;
        original.current()?;
        if !self.complete
            || self.unexpected_activation.is_some()
            || !matches!(self.arm_error, Some(RuntimeError::InvalidReceipt))
            || !matches!(self.activation_error, Some(RuntimeError::OwnerUnavailable))
            || self.before_gate_errors.len() != 2
            || !self.before_gate_errors.iter().all(|error| {
                matches!(
                    error,
                    RuntimePollFailure::Admission(RuntimeError::NotActivated)
                )
            })
            || !matches!(
                self.after_gate_error,
                Some(RuntimePollFailure::Admission(
                    RuntimeError::OwnerUnavailable
                ))
            )
            || !matches!(self.actual_lost_completion, Some(RuntimePollFailure::Native(ref error))
                if error.effects == crucible_engine::node_contract::EffectKnowledge::Unknown)
        {
            return Err(refused("Clock original adverse ownership frontier changed"));
        }
        let source_activation = original
            .activation
            .as_ref()
            .ok_or_else(|| refused("Clock original activation absent during adverse loan"))?;
        for (index, world) in self.worlds.iter_mut().enumerate() {
            let runtime = world
                .runtime
                .as_mut()
                .ok_or_else(|| refused("Clock original adverse runtime absent"))?;
            if Some(statuses(runtime)?) != world.after {
                return Err(refused("Clock current adverse native boundaries changed"));
            }
            if index == 0 {
                for (node, _) in profile::ACTIVATION_CLOCKS {
                    if !matches!(
                        runtime.observe_scheduling(source_activation, &Id::new(node)?),
                        Err(RuntimePollFailure::Admission(RuntimeError::NotActivated))
                    ) {
                        return Err(refused("Clock abandoned world opened a native gate"));
                    }
                }
                continue;
            }
            let activation = world
                .activation
                .as_ref()
                .ok_or_else(|| refused("Clock original postcommit activation absent"))?;
            let prepared = activation
                .prepared_publication_data()
                .ok_or_else(|| refused("Clock original complete publication absent"))?;
            if publisher.reconcile_complete(activation.record(), prepared)
                != PublicationStatus::Committed
            {
                return Err(refused(
                    "Clock original adverse publication no longer committed",
                ));
            }
            let first = world
                .first
                .as_ref()
                .ok_or_else(|| refused("Clock first original effect absent"))?;
            let second = world
                .second
                .as_ref()
                .ok_or_else(|| refused("Clock lost original effect absent"))?;
            let token = first
                .token
                .as_ref()
                .ok_or_else(|| refused("Clock first original token absent"))?;
            let references = first
                .expected
                .objects
                .iter()
                .map(|object| object.reference.clone())
                .collect::<Vec<_>>();
            let actual = runtime.original_witness().operation_evidence(
                token,
                &references,
                U64::new(MAXIMUM_CASE_BYTES as u64),
            )?;
            first.expected.authenticate_objects(&actual)?;
            if Some(&actual) != self.first_after_effect.as_ref()
                || first.objects.as_ref() != Some(&actual)
                || !first.acknowledged
                || second.acknowledged
                || self
                    .completion_loss
                    .as_ref()
                    .is_none_or(|loss| loss.original_outcome_data() != &second.expected.outcome)
                || !matches!(runtime.poll(second.token.as_ref().ok_or_else(|| refused("Clock lost original token absent"))?,
                    &mut Context::from_waker(Waker::noop())), Poll::Ready(Err(RuntimePollFailure::Native(ref error)))
                    if error.effects == crucible_engine::node_contract::EffectKnowledge::Unknown)
            {
                return Err(refused(
                    "Clock original postcommit effect or uncertainty changed",
                ));
            }
        }
        self.origin.current()
    }

    pub(super) fn original_data(&self) -> Result<InputPayload, NodeObservedError> {
        self.origin.current()?;
        if !self.complete {
            return Err(refused("Clock actual adverse originals incomplete"));
        }
        let loss = self
            .readiness_loss
            .as_ref()
            .ok_or_else(|| refused("Clock readiness original absent"))?;
        let worlds = self
            .worlds
            .iter()
            .map(|world| {
                let proposal = world
                    .proposal
                    .as_ref()
                    .ok_or_else(|| refused("Clock adverse proposal absent"))?;
                Ok((
                    world.scenario.as_ref(),
                    SavedRuntimeActivation::from(proposal),
                    world.before,
                    world.after,
                ))
            })
            .collect::<Result<Vec<_>, NodeObservedError>>()?;
        let value = (
            "crucible.normal-clock-original-adverse/1",
            &worlds,
            loss.preceding_preparations_data(),
            loss.withheld_preparation_data(),
            "actual activate refused OwnerUnavailable before publication; both scheduling observations NotActivated; selected native owner contained",
            self.completion_loss
                .as_ref()
                .map(|loss| loss.original_outcome_data()),
            &self.first_after_effect,
            ("committed", "committed", "unknown"),
            "explicit loss after original native validation; no rollback",
        );
        // Check the complete borrowed representation before constructing a DOM.
        // This is a requested serialization extent, not a physical peak claim.
        serde_json::to_writer(&mut ReportCredit(512 * 1024), &value)?;
        let bytes = canonical::canonical_json(&serde_json::to_value(value)?)?;
        if bytes.len() > 512 * 1024 {
            return Err(refused(
                "Clock actual adverse report exceeds original ceiling",
            ));
        }
        Ok(InputPayload {
            reference: canonical::content_ref(&bytes, "application/json")?,
            bytes,
        })
    }
}

fn statuses(runtime: &mut NodeRuntime) -> Result<[Status; 2], NodeObservedError> {
    let status = |value: NodeStatus| (value.lifecycle, value.physical, value.boundary);
    Ok([
        status(runtime.status(&Id::new("clock-a")?)?),
        status(runtime.status(&Id::new("clock-b")?)?),
    ])
}

struct ReportCredit(usize);

impl std::io::Write for ReportCredit {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or_else(|| std::io::Error::other("Clock adverse metadata extent"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_observed_executor::StoredWorldActivationPublisher;
    use crucible_store::content_store::{
        DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend, RefName,
    };
    use std::{sync::Arc, time::Duration};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    #[ignore = "requires a genuine installed reference executable and an admitted finite native plan"]
    fn actual_two_public_clock_owners_retain_lost_readiness_and_postcommit_effects() -> TestResult {
        let root = tempfile::tempdir()?;
        let executable = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE")?);
        let identity = measure_executable(&executable)?;
        let catalog = |name: &str| {
            InstalledNodeCatalog::new_with_bounded_runtime_wake(
                executable.clone(),
                identity.clone(),
                root.path().join(name),
                Duration::from_secs(5),
                1,
            )
        };
        let mut original_catalog = catalog("original")?;
        let profile = original_catalog.installed_normal_clock()?;
        let mut original = original_catalog
            .prepare_original_clock_qualification(&profile, ExecutionId::from_bytes([89; 16])?)?;
        let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
            "normal-clock-adverse",
            root.path().join("blobs"),
        ));
        let refs: Arc<dyn MutableRefBackend> =
            Arc::new(DirectoryRefBackend::new(root.path().join("refs")));
        let publisher = |name| {
            StoredWorldActivationPublisher::new(
                Arc::clone(&blobs),
                Arc::clone(&refs),
                RefName::new(name)?,
            )
        };
        let mut original_publisher = publisher("node-world-activations/adverse-original")?;
        let mut adverse_publisher = publisher("node-world-activations/adverse-effect")?;
        original.activate(&mut original_publisher)?;

        let mut adverse = OriginalClockAdverseProgramme {
            origin: original.origin.clone(),
            worlds: [
                Fixture::from_catalog(catalog("ready")?, ExecutionId::from_bytes([90; 16])?),
                Fixture::from_catalog(catalog("effect")?, ExecutionId::from_bytes([91; 16])?),
            ],
            readiness_loss: None,
            completion_loss: None,
            before_gate_errors: Vec::with_capacity(2),
            arm_error: None,
            activation_error: None,
            unexpected_activation: None,
            after_gate_error: None,
            actual_lost_completion: None,
            first_after_effect: None,
            publication_before: None,
            publication_after: None,
            attempted: true,
            complete: false,
        };
        let activation = original
            .activation
            .as_ref()
            .ok_or("original activation missing")?;
        adverse.execute_readiness_loss(activation, &mut adverse_publisher)?;
        adverse.execute_postcommit_loss(&mut adverse_publisher)?;
        adverse.complete = true;
        let report = adverse.original_data()?;
        report.reference.verify(&report.bytes)?;
        assert!(adverse.readiness_loss.is_some());
        assert!(adverse.completion_loss.is_some());
        assert_eq!(adverse.before_gate_errors.len(), 2);
        assert!(matches!(
            adverse.activation_error,
            Some(RuntimeError::OwnerUnavailable)
        ));
        assert!(adverse.unexpected_activation.is_none());
        assert_eq!(
            adverse.publication_before,
            Some(PublicationStatus::Committed)
        );
        assert_eq!(
            adverse.publication_after,
            Some(PublicationStatus::Committed)
        );
        // Both real worlds remain owned through the final oracle. The test
        // makes no normal class-policy or bounded-environment installation.
        assert!(adverse.worlds.iter().all(|world| world.runtime.is_some()));
        let witness = OriginalClockAdverseWitness::new(
            &mut adverse,
            &original,
            &mut adverse_publisher,
            &report,
        )?;
        witness.authenticate_current()?;
        assert_eq!(witness.reference(), &report.reference);
        assert_eq!(witness.bytes(), report.bytes.as_slice());
        Ok(())
    }
}

impl crate::node_qualification::RetainedMetadataOwned for Fixture {
    fn charge(
        &self,
        counter: &mut crate::node_qualification::RetainedMetadataCounter,
    ) -> Result<(), QualificationError> {
        let Self {
            execution: _,
            catalog,
            scenario,
            graph,
            runtime,
            proposal,
            activation,
            before: _,
            after: _,
            first,
            second,
            attempted: _,
        } = self;
        counter.charge(catalog)?;
        counter.charge(scenario)?;
        counter.charge(graph)?;
        counter.charge(runtime)?;
        counter.charge(proposal)?;
        counter.charge(activation)?;
        counter.charge(first)?;
        counter.charge(second)
    }
}

impl crate::node_qualification::RetainedMetadataOwned for OriginalClockAdverseProgramme {
    fn charge(
        &self,
        counter: &mut crate::node_qualification::RetainedMetadataCounter,
    ) -> Result<(), QualificationError> {
        use std::mem::size_of;
        let Self {
            origin,
            worlds,
            readiness_loss,
            completion_loss,
            before_gate_errors,
            arm_error,
            activation_error,
            unexpected_activation,
            after_gate_error,
            actual_lost_completion,
            first_after_effect,
            publication_before: _,
            publication_after: _,
            attempted: _,
            complete: _,
        } = self;
        counter.charge(origin)?;
        counter.charge(worlds)?;
        if let Some(loss) = readiness_loss {
            let bytes = loss
                .retained_requested_storage_data(counter.remaining())
                .map_err(|_| {
                    QualificationError::Refused("Clock readiness-loss storage unavailable")
                })?
                .checked_sub(size_of::<OriginalReadinessLoss>())
                .ok_or(QualificationError::Refused(
                    "Clock loss inline layout differs",
                ))?;
            counter.add(bytes)?;
        }
        if let Some(loss) = completion_loss {
            let bytes = loss
                .retained_requested_storage_data(counter.remaining())
                .map_err(|_| {
                    QualificationError::Refused("Clock completion-loss storage unavailable")
                })?
                .checked_sub(size_of::<OriginalCompletionLoss>())
                .ok_or(QualificationError::Refused(
                    "Clock loss inline layout differs",
                ))?;
            counter.add(bytes)?;
        }
        counter.charge(before_gate_errors)?;
        counter.charge(arm_error)?;
        counter.charge(activation_error)?;
        counter.charge(unexpected_activation)?;
        counter.charge(after_gate_error)?;
        counter.charge(actual_lost_completion)?;
        counter.charge(first_after_effect)
    }
}

impl OriginalClockAdverseProgramme {
    pub(super) fn original_storage_scratch_data(&self) -> Result<usize, QualificationError> {
        let mut scratch = OriginalReadinessLoss::retained_requested_storage_scratch_data()
            .max(OriginalCompletionLoss::retained_requested_storage_scratch_data());
        for world in &self.worlds {
            if let Some(runtime) = &world.runtime {
                scratch = scratch.max(
                    runtime
                        .original_retained_requested_storage_precredit_scratch_data()
                        .map_err(|_| {
                            QualificationError::Refused("Clock adverse owning scratch unavailable")
                        })?,
                );
            }
        }
        Ok(scratch)
    }
}
