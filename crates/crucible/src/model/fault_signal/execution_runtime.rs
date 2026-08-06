//! Complete signal-to-adapter fault execution ownership.
//!
//! [`FaultExecutionRuntime`] is the production bridge between a scenario's
//! admitted signal program, binding evaluation, and the three transactional
//! adapter families. It owns one atomic checkpoint surface so callers never
//! persist evaluator state without the corresponding adapter state.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use super::*;

/// The complete live signal-driven fault engine for one non-empty plan.
pub struct FaultExecutionRuntime<'a> {
    program: &'a SignalProgram,
    bindings: Vec<FaultBinding>,
    scenario_seed: ContentHash,
    binding_runtime: FaultBindingRuntime<'a>,
    adapters: TransactionalFaultAdapters,
    replay: Option<ResolvedEffectTrace>,
    retained_effects: BTreeSet<ContentHash>,
    branch_parent: Option<ContentHash>,
}

impl<'a> FaultExecutionRuntime<'a> {
    /// Admits live capabilities and creates an empty execution continuation.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] if the plan is empty or has more than
    /// one program, a live capability is absent, or evaluator state cannot be
    /// initialized.
    pub fn new(
        plan: &'a FaultSignalPlan,
        artifacts: &'a dyn SignalArtifactProvider,
        boundary: SignalBoundarySnapshot,
        scenario_seed: ContentHash,
        manifests: FaultAdapterManifests,
    ) -> Result<Self, FaultExecutionError> {
        let program = sole_program(plan)?;
        admit_manifests(plan.bindings(), &manifests)?;
        let bindings = plan.bindings().to_vec();
        let binding_runtime = FaultBindingRuntime::new(
            program,
            bindings.clone(),
            artifacts,
            boundary,
            scenario_seed,
        )?;
        let adapters = TransactionalFaultAdapters::new(manifests)?;
        Ok(Self {
            program,
            bindings,
            scenario_seed,
            binding_runtime,
            adapters,
            replay: None,
            retained_effects: BTreeSet::new(),
            branch_parent: None,
        })
    }

    /// Restores one authenticated evaluator-and-adapter continuation.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] if identities, capabilities, canonical
    /// bytes, or the duplicated binding/adapter contribution views disagree.
    pub fn restore(
        plan: &'a FaultSignalPlan,
        artifacts: &'a dyn SignalArtifactProvider,
        scenario_seed: ContentHash,
        manifests: FaultAdapterManifests,
        checkpoint: &FaultRuntimeCheckpoint,
    ) -> Result<Self, FaultExecutionError> {
        let program = sole_program(plan)?;
        checkpoint.validate(program, plan.bindings(), scenario_seed)?;
        admit_manifests(plan.bindings(), &manifests)?;
        let bindings = plan.bindings().to_vec();
        let binding_runtime = FaultBindingRuntime::restore(
            program,
            bindings.clone(),
            artifacts,
            scenario_seed,
            &checkpoint.binding_runtime,
        )?;
        let adapters = TransactionalFaultAdapters::restore(manifests, checkpoint.adapters.clone())?;
        validate_contribution_mirror(binding_runtime.active(), &adapters)?;
        Ok(Self {
            program,
            bindings,
            scenario_seed,
            binding_runtime,
            adapters,
            replay: checkpoint.replay.clone(),
            retained_effects: checkpoint.retained_effects.clone(),
            branch_parent: checkpoint.branch_parent,
        })
    }

    /// Evaluates every due non-opportunity binding at one scheduler boundary.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] if evaluation or an atomic production
    /// adapter transaction fails.
    pub fn evaluate_boundary(
        &mut self,
        coordinate: FaultCoordinate,
        same_coordinate_sequence: u64,
    ) -> Result<BindingEvaluation, FaultExecutionError> {
        Ok(self.binding_runtime.evaluate_boundary(
            coordinate,
            same_coordinate_sequence,
            &mut self.adapters,
        )?)
    }

    /// Evaluates due bindings and atomically mirrors them into a live backend.
    ///
    /// The canonical adapter ledger and `backend` prepare the same ordered
    /// action batch. Successful observations come from `backend`; a rejection
    /// restores the canonical ledger to its exact before-state.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] if evaluation fails, either participant
    /// rejects the batch, their action identities differ, or rollback fails.
    pub fn evaluate_boundary_with_backend<B>(
        &mut self,
        coordinate: FaultCoordinate,
        same_coordinate_sequence: u64,
        backend: &mut B,
    ) -> Result<BindingEvaluation, FaultExecutionError>
    where
        B: FaultActionSink,
    {
        let mut sink = MirroredFaultActionSink::new(&mut self.adapters, backend);
        Ok(self.binding_runtime.evaluate_boundary(
            coordinate,
            same_coordinate_sequence,
            &mut sink,
        )?)
    }

    /// Evaluates every binding matching one exact production opportunity.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] if opportunity identity, evaluation, or
    /// atomic adapter application fails.
    pub fn evaluate_opportunity(
        &mut self,
        opportunity: &FaultOpportunity,
        same_coordinate_sequence: u64,
    ) -> Result<BindingEvaluation, FaultExecutionError> {
        Ok(self.binding_runtime.evaluate_opportunity(
            opportunity,
            same_coordinate_sequence,
            &mut self.adapters,
        )?)
    }

    /// Evaluates one opportunity and mirrors it into a live backend atomically.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] under the same conditions as
    /// [`Self::evaluate_boundary_with_backend`], plus invalid opportunity
    /// identity, target, or phase.
    pub fn evaluate_opportunity_with_backend<B>(
        &mut self,
        opportunity: &FaultOpportunity,
        same_coordinate_sequence: u64,
        backend: &mut B,
    ) -> Result<BindingEvaluation, FaultExecutionError>
    where
        B: FaultActionSink,
    {
        let mut sink = MirroredFaultActionSink::new(&mut self.adapters, backend);
        Ok(self.binding_runtime.evaluate_opportunity(
            opportunity,
            same_coordinate_sequence,
            &mut sink,
        )?)
    }

    /// Replaces one-boundary-delayed production telemetry.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] if the telemetry snapshot exceeds the
    /// admitted resource contract.
    pub fn set_boundary_snapshot(
        &mut self,
        boundary: SignalBoundarySnapshot,
    ) -> Result<(), FaultExecutionError> {
        self.binding_runtime.set_boundary_snapshot(boundary)?;
        Ok(())
    }

    /// Returns the committed state for one production adapter family.
    #[must_use]
    pub const fn adapter(&self, adapter: FaultAdapter) -> &TransactionalAdapterRuntime {
        self.adapters.adapter(adapter)
    }

    /// Captures the evaluator, bindings, adapters, replay, and branch state.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] if canonical state cannot be encoded or
    /// if a transaction is still in flight.
    pub fn checkpoint(&self) -> Result<FaultRuntimeCheckpoint, FaultExecutionError> {
        Ok(FaultRuntimeCheckpoint {
            semantic_version: FAULT_RUNTIME_STATE_VERSION,
            binding_runtime: self.binding_runtime.checkpoint()?,
            adapters: self.adapters.checkpoints()?,
            replay: self.replay.clone(),
            retained_effects: self.retained_effects.clone(),
            branch_parent: self.branch_parent,
        })
    }

    /// Returns the exact program identity owned by this continuation.
    #[must_use]
    pub const fn program_id(&self) -> ContentHash {
        self.program.id()
    }

    /// Returns the scenario seed identity owned by this continuation.
    #[must_use]
    pub const fn scenario_seed(&self) -> ContentHash {
        self.scenario_seed
    }

    /// Returns the canonical admitted binding contracts.
    #[must_use]
    pub fn bindings(&self) -> &[FaultBinding] {
        &self.bindings
    }
}

fn sole_program(plan: &FaultSignalPlan) -> Result<&SignalProgram, FaultExecutionError> {
    match plan.programs() {
        [program] => Ok(program),
        [] => Err(FaultExecutionError::EmptyPlan),
        _ => Err(FaultExecutionError::ProgramCardinality),
    }
}

fn admit_manifests(
    bindings: &[FaultBinding],
    manifests: &FaultAdapterManifests,
) -> Result<(), FaultExecutionError> {
    for (adapter, manifest) in [
        (FaultAdapter::Network, &manifests.network),
        (FaultAdapter::Storage, &manifests.storage),
        (FaultAdapter::Node, &manifests.node),
    ] {
        let family = bindings
            .iter()
            .filter(|binding| binding.effect().kind().descriptor().adapter == adapter)
            .cloned()
            .collect::<Vec<_>>();
        manifest.admit(&family)?;
    }
    Ok(())
}

fn validate_contribution_mirror(
    binding: &ActiveContributionTable,
    adapters: &TransactionalFaultAdapters,
) -> Result<(), FaultExecutionError> {
    for adapter in [
        FaultAdapter::Network,
        FaultAdapter::Storage,
        FaultAdapter::Node,
    ] {
        let expected = binding
            .composition_groups()
            .into_iter()
            .filter(|group| group.effect.descriptor().adapter == adapter)
            .collect::<Vec<_>>();
        if expected != adapters.adapter(adapter).composition_groups() {
            return Err(FaultExecutionError::ContributionMirror);
        }
    }
    Ok(())
}

/// Failure to admit, evaluate, apply, checkpoint, or restore fault execution.
#[derive(Debug)]
pub enum FaultExecutionError {
    /// The scenario contains no signal program and needs no execution runtime.
    EmptyPlan,
    /// The scenario violates the closed one-program public schema.
    ProgramCardinality,
    /// Binding evaluation or evaluator state failed.
    Binding(BindingRuntimeError),
    /// Production adapter, checkpoint, replay, or capability state failed.
    Runtime(FaultRuntimeError),
    /// Binding and adapter checkpoints disagree about committed contributions.
    ContributionMirror,
}

impl From<BindingRuntimeError> for FaultExecutionError {
    fn from(value: BindingRuntimeError) -> Self {
        Self::Binding(value)
    }
}

impl From<FaultRuntimeError> for FaultExecutionError {
    fn from(value: FaultRuntimeError) -> Self {
        Self::Runtime(value)
    }
}

impl fmt::Display for FaultExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "fault execution failed: {self:?}")
    }
}

impl Error for FaultExecutionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Binding(error) => Some(error),
            Self::Runtime(error) => Some(error),
            Self::EmptyPlan | Self::ProgramCardinality | Self::ContributionMirror => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

    struct NoArtifacts;

    impl SignalArtifactProvider for NoArtifacts {
        fn inverse_cdf_table(
            &self,
            content: &ContentHash,
        ) -> Result<InverseCdfTable, SignalEvaluationError> {
            Err(SignalEvaluationError::ArtifactContentMismatch(*content))
        }

        fn evaluate_artifact_source(
            &self,
            node: &SignalNode,
            _source: &SignalSourceSpecification,
            _coordinate: &SignalCoordinate,
            _same_coordinate_sequence: u64,
            _choice: &SignalChoiceContext,
            _inputs: &[EvaluatedSignal],
        ) -> Result<EvaluatedSignal, SignalEvaluationError> {
            Err(SignalEvaluationError::ArtifactSourceRequired(
                node.id.clone(),
            ))
        }
    }

    fn object_id(value: &str) -> FaultObjectId {
        FaultObjectId::parse(value)
            .unwrap_or_else(|error| panic!("test object ID must be valid: {error}"))
    }

    fn signal_id(value: &str) -> SignalId {
        SignalId::parse(value)
            .unwrap_or_else(|error| panic!("test signal ID must be valid: {error}"))
    }

    fn manifest(adapter: FaultAdapter) -> FaultCapabilityManifest {
        FaultCapabilityManifest {
            backend: object_id(match adapter {
                FaultAdapter::Network => "network-production",
                FaultAdapter::Storage => "storage-production",
                FaultAdapter::Node => "node-production",
            }),
            capabilities: EffectKind::all()
                .iter()
                .filter(|kind| kind.descriptor().adapter == adapter)
                .map(|kind| {
                    FaultCapabilityId::parse(kind.descriptor().capability)
                        .unwrap_or_else(|error| panic!("registry capability: {error}"))
                })
                .collect::<BTreeSet<_>>(),
            bounds: BTreeMap::new(),
        }
    }

    fn manifests() -> FaultAdapterManifests {
        FaultAdapterManifests {
            network: manifest(FaultAdapter::Network),
            storage: manifest(FaultAdapter::Storage),
            node: manifest(FaultAdapter::Node),
        }
    }

    fn test_plan() -> FaultSignalPlan {
        let output = signal_id("output");
        let program = SignalProgram::new(
            vec![SignalNode {
                id: output.clone(),
                domain: SignalDomain::VirtualTime,
                output: SignalShape::new(SignalValueType::Bool, SignalUnit::Dimensionless, 0)
                    .unwrap_or_else(|error| panic!("test shape: {error}")),
                inputs: Vec::new(),
                kind: SignalNodeKind::Constant {
                    value: SignalValue::Bool(true),
                },
            }],
            vec![output.clone()],
            SignalResourceLimits::default(),
        )
        .unwrap_or_else(|error| panic!("test program: {error}"));
        let targets = ResolvedTargetSet::new(
            vec![ResolvedFaultTarget::NetworkSegment {
                segment: object_id("segment-a"),
                direction: FaultDirection::AToB,
            }],
            false,
        )
        .unwrap_or_else(|error| panic!("test targets: {error}"));
        let effect = EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Persistent,
            EffectSpecification::Network(NetworkEffectSpecification::Availability {
                state: NetworkAvailabilityState::Down,
                queued_policy: NetworkInFlightPolicy::Drop,
                in_flight_policy: NetworkInFlightPolicy::Drop,
            }),
        )
        .unwrap_or_else(|error| panic!("test effect: {error}"));
        let binding = FaultBinding::new(
            object_id("network-outage"),
            vec![output],
            BindingSampling::AtBoundary,
            BindingMapping::ActiveWhenTrue { invert: false },
            TargetSelector::Exact(targets),
            BTreeSet::from([FaultPhase::Admit]),
            effect,
            None,
            BindingSearchPolicy::Fixed,
            BindingObservabilityPolicy {
                samples: SampleObservation::ChangesAndEffects,
                record_inactive_opportunities: false,
                retain_mapped_values: true,
            },
            &program,
        )
        .unwrap_or_else(|error| panic!("test binding: {error}"));
        FaultSignalPlan::new(vec![program], vec![binding])
            .unwrap_or_else(|error| panic!("test plan: {error}"))
    }

    #[test]
    fn execution_checkpoint_restores_the_same_adapter_contributions() {
        let plan = test_plan();
        let seed = ContentHash::from_bytes(b"scenario-seed");
        let mut runtime = FaultExecutionRuntime::new(
            &plan,
            &NoArtifacts,
            SignalBoundarySnapshot::default(),
            seed,
            manifests(),
        )
        .unwrap_or_else(|error| panic!("execution runtime: {error}"));
        let evaluation = runtime
            .evaluate_boundary(
                FaultCoordinate {
                    virtual_nanos: 0,
                    retired_instructions: None,
                },
                0,
            )
            .unwrap_or_else(|error| panic!("boundary: {error}"));
        assert_eq!(evaluation.actions.len(), 1);
        let checkpoint = runtime
            .checkpoint()
            .unwrap_or_else(|error| panic!("checkpoint: {error}"));
        let restored =
            FaultExecutionRuntime::restore(&plan, &NoArtifacts, seed, manifests(), &checkpoint)
                .unwrap_or_else(|error| panic!("restore: {error}"));
        assert_eq!(
            restored.adapter(FaultAdapter::Network).composition_groups(),
            runtime.adapter(FaultAdapter::Network).composition_groups()
        );
    }
}
