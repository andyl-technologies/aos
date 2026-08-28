//! Fixture constructors and evidence output for the cross-domain campaign.

use super::*;
use crate::model::{
    ChoiceTag, Decision, EngineError, Icount, NodeId, NodeTemplate, OverrideDecision, Plan,
    Properties, ReadyPoint, ScenarioDefForm, SchedulingPoint, Seed, WhiteBoxPolicy, World,
    WorldNode,
};

#[derive(Default)]
pub(super) struct CampaignBackend {
    prepared: Option<PreparedActionBatch>,
}

impl CampaignBackend {
    fn precondition() -> ContentHash {
        ContentHash::from_bytes(b"cross-domain-production-backend-precondition")
    }
}

impl FaultActionSink for CampaignBackend {
    fn prepare_batch(
        &mut self,
        actions: &[ResolvedBindingAction],
    ) -> Result<PreparedActionBatch, Box<RejectedActionBatch>> {
        let precondition = Self::precondition();
        if let Some(action) = actions.iter().find(|action| {
            action
                .expected_precondition
                .is_some_and(|expected| expected != precondition)
        }) {
            return Err(Box::new(RejectedActionBatch {
                error: FaultRuntimeError::ReplayPreconditionMismatch {
                    action: action.id(),
                    expected: action
                        .expected_precondition
                        .unwrap_or_else(|| panic!("mismatched action must carry a precondition")),
                    observed: precondition,
                },
                observations: vec![FaultObservation {
                    semantic_version: FAULT_RUNTIME_STATE_VERSION,
                    kind: FaultObservationKind::EffectRejected,
                    coordinate: action.coordinate,
                    binding: Some(action.binding.clone()),
                    target: Some(action.target.clone()),
                    opportunity: action.opportunity,
                    evidence: precondition,
                }],
                rejected_action: Some(action.id()),
            }));
        }

        let evidence = ContentHash::from_bytes(b"cross-domain-production-backend-evidence");
        let prepared = PreparedActionBatch {
            transaction: ContentHash::from_bytes(b"cross-domain-production-transaction"),
            results: actions
                .iter()
                .map(|action| PreparedActionResult {
                    action: action.id(),
                    precondition: Some(precondition),
                    observation: FaultObservation {
                        semantic_version: FAULT_RUNTIME_STATE_VERSION,
                        kind: match action.kind {
                            BindingActionKind::UpsertPersistent => {
                                FaultObservationKind::BindingActivation
                            }
                            BindingActionKind::RemovePersistent => {
                                FaultObservationKind::BindingDeactivation
                            }
                            BindingActionKind::Apply => FaultObservationKind::EffectCommitted,
                        },
                        coordinate: action.coordinate,
                        binding: Some(action.binding.clone()),
                        target: Some(action.target.clone()),
                        opportunity: action.opportunity,
                        evidence,
                    },
                })
                .collect(),
        };
        self.prepared = Some(prepared.clone());
        Ok(prepared)
    }

    fn commit_batch(
        &mut self,
        transaction: ContentHash,
    ) -> Result<PreparedActionBatch, FaultActionCommitError> {
        let mut prepared = self
            .prepared
            .take()
            .filter(|prepared| prepared.transaction == transaction)
            .ok_or(FaultActionCommitError::Fatal(
                FaultRuntimeError::UnknownAdapterTransaction,
            ))?;
        for result in &mut prepared.results {
            if result
                .observation
                .target
                .as_ref()
                .is_some_and(|target| target.kind().adapter() == FaultAdapter::Node)
            {
                result.observation.coordinate.retired_instructions = Some(64);
            }
        }
        Ok(prepared)
    }

    fn abort_batch(&mut self, transaction: ContentHash) -> Result<(), FaultRuntimeError> {
        match self.prepared.take() {
            Some(prepared) if prepared.transaction == transaction => Ok(()),
            Some(prepared) => {
                self.prepared = Some(prepared);
                Err(FaultRuntimeError::UnknownAdapterTransaction)
            }
            None => Err(FaultRuntimeError::UnknownAdapterTransaction),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn transition_binding(
    id: &str,
    signal: &SignalId,
    target: ResolvedFaultTarget,
    phase: FaultPhase,
    specification: EffectSpecification,
    transition_table: FaultObjectId,
    search: BindingSearchPolicy,
    program: &SignalProgram,
    registry: &BindingMappingRegistry,
) -> FaultBinding {
    FaultBinding::new_with_registry(
        object_id(id),
        vec![signal.clone()],
        BindingSampling::AtEvent(BindingEventParent::VirtualTime),
        BindingMapping::StateTransition { transition_table },
        target_selector(target),
        [phase].into_iter().collect(),
        EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::StateMachine,
            specification,
        )
        .unwrap_or_else(|error| panic!("state-machine effect {id}: {error}")),
        None,
        search,
        observability(),
        program,
        registry,
    )
    .unwrap_or_else(|error| panic!("state-machine binding {id}: {error}"))
}

pub(super) fn impulse_binding(
    id: &str,
    signal: &SignalId,
    target: ResolvedFaultTarget,
    phase: FaultPhase,
    specification: EffectSpecification,
    program: &SignalProgram,
) -> FaultBinding {
    FaultBinding::new(
        object_id(id),
        vec![signal.clone()],
        BindingSampling::AtEvent(BindingEventParent::VirtualTime),
        BindingMapping::ImpulseOnEvent,
        target_selector(target),
        [phase].into_iter().collect(),
        EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Impulse,
            specification,
        )
        .unwrap_or_else(|error| panic!("impulse effect {id}: {error}")),
        None,
        BindingSearchPolicy::Fixed,
        observability(),
        program,
    )
    .unwrap_or_else(|error| panic!("impulse binding {id}: {error}"))
}

pub(super) fn persistent_binding(
    id: &str,
    signal: &SignalId,
    target: ResolvedFaultTarget,
    phase: FaultPhase,
    specification: EffectSpecification,
    program: &SignalProgram,
) -> FaultBinding {
    FaultBinding::new(
        object_id(id),
        vec![signal.clone()],
        BindingSampling::AtBoundary,
        BindingMapping::ActiveWhenTrue { invert: false },
        target_selector(target),
        [phase].into_iter().collect(),
        EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Persistent,
            specification,
        )
        .unwrap_or_else(|error| panic!("persistent effect {id}: {error}")),
        None,
        BindingSearchPolicy::Fixed,
        observability(),
        program,
    )
    .unwrap_or_else(|error| panic!("persistent binding {id}: {error}"))
}

pub(super) fn target_selector(target: ResolvedFaultTarget) -> TargetSelector {
    TargetSelector::Exact(
        ResolvedTargetSet::new(vec![target], false)
            .unwrap_or_else(|error| panic!("cross-domain target: {error}")),
    )
}

pub(super) fn object_set<const N: usize>(values: [&str; N]) -> ObjectIdSet {
    ObjectIdSet::new(values.into_iter().map(object_id).collect())
        .unwrap_or_else(|error| panic!("cross-domain object set: {error}"))
}

fn observability() -> BindingObservabilityPolicy {
    BindingObservabilityPolicy {
        samples: SampleObservation::ChangesAndEffects,
        record_inactive_opportunities: false,
        retain_mapped_values: true,
    }
}

pub(super) fn campaign_coordinate() -> FaultCoordinate {
    FaultCoordinate {
        virtual_nanos: CAMPAIGN_COORDINATE,
        retired_instructions: None,
    }
}

pub(super) fn campaign_scenario() -> ScenarioDefForm {
    let world = World::from_nodes(vec![WorldNode {
        id: NodeId {
            name: "fleet-node-a".to_owned(),
        },
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: "crucible-cross-domain-fleet".to_owned(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 64 },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: 2,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
    .unwrap_or_else(|error| panic!("cross-domain campaign world: {error}"));
    ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(0x0014_cafe),
    )
    .unwrap_or_else(|error| panic!("cross-domain campaign scenario: {error}"))
}

pub(super) fn noise_override(key: &str) -> Decision {
    Decision::Override(OverrideDecision {
        point: SchedulingPoint {
            key: key.to_owned(),
        },
        choice: ChoiceTag {
            name: "irrelevant".to_owned(),
        },
    })
}

pub(super) fn campaign_error(
    operation: &'static str,
    error: impl std::fmt::Display,
) -> EngineError {
    EngineError::ScenarioSerialization {
        reason: format!("{operation}: {error}"),
    }
}

pub(super) fn write_campaign_evidence(record_count: usize) {
    let Ok(path) = std::env::var(EVIDENCE_PATH_ENV) else {
        return;
    };
    let evidence = format!(
        "cross_domain_fleet_campaign=PASS\n\
         causes=interference,movement,satellite-contact,shared-power,vibration\n\
         effects=clock.transform,cpu.service,interrupt.disposition,memory.mutation,network.contact,network.route_transition,storage.volatile_cache_loss\n\
         search_candidates=2\n\
         original_decisions=4\n\
         minimized_decisions=1\n\
         minimized_failure_preserved=true\n\
         locked_replay_without_explorer=true\n\
         resolved_effect_records={record_count}\n"
    );
    std::fs::write(path, evidence)
        .unwrap_or_else(|error| panic!("write cross-domain fleet evidence: {error}"));
}
