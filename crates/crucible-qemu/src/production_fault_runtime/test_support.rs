//! Shared production fault-runtime test fixtures.

use super::*;
pub(super) use crucible::model::{
    BindingActionCause, BindingEventParent, BindingMapping, BindingMappingRegistry,
    BindingObservabilityPolicy, BindingSampling, BindingSearchPolicy, CountLimit,
    EFFECT_SEMANTIC_VERSION, EffectLifetime, EffectRequest, EffectSpecification, EvaluatedSignal,
    FaultBinding, FaultDirection, FaultPhase, InverseCdfTable, NetworkAvailabilityState,
    NetworkEffectSpecification, NetworkInFlightPolicy, PositiveU64, ResolvedFaultTarget,
    ResolvedMappingOutput, ResolvedTargetSet, SampleObservation, SignalChoiceContext,
    SignalCoordinate, SignalDomain, SignalEvaluationError, SignalId, SignalNode, SignalNodeKind,
    SignalPoint, SignalResourceLimits, SignalShape, SignalSourceSpecification, SignalUnit,
    SignalValue, SignalValueType, StateTransitionTableDeclaration, StorageEffectSpecification,
    TargetSelector,
};

pub(super) struct NoArtifacts;

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
        _resource_limits: FaultResourceLimits,
    ) -> Result<EvaluatedSignal, SignalEvaluationError> {
        Err(SignalEvaluationError::ArtifactSourceRequired(
            node.id.clone(),
        ))
    }
}

pub(super) fn object_id(value: &str) -> FaultObjectId {
    FaultObjectId::parse(value)
        .unwrap_or_else(|error| panic!("test object ID should be valid: {error}"))
}

pub(super) fn signal_id(value: &str) -> SignalId {
    SignalId::parse(value).unwrap_or_else(|error| panic!("test signal ID should be valid: {error}"))
}

pub(super) fn lifecycle_action(
    transition: NodeLifecycleTransition,
    boot_policy: NodeBootPolicy,
) -> ResolvedBindingAction {
    let effect = EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Impulse,
        EffectSpecification::Node(NodeEffectSpecification::Lifecycle {
            transition,
            downtime_nanos: 32,
            boot_policy,
            volatile_state_policy: NodeStatePolicy::Preserve,
            device_state_policy: NodeStatePolicy::Clear,
        }),
    )
    .unwrap_or_else(|error| panic!("test lifecycle effect should be valid: {error}"));
    ResolvedBindingAction {
        kind: BindingActionKind::Apply,
        binding: object_id("node-reset"),
        target: ResolvedFaultTarget::Node {
            node: object_id("node-a"),
        },
        phase: FaultPhase::Boundary,
        effect: Arc::new(effect),
        mapping_output: Arc::new(ResolvedMappingOutput::Activation { active: true }),
        mapped_digest: ContentHash::from_bytes(b"node-reset-mapping"),
        transition_sequence: 1,
        opportunity: None,
        coordinate: FaultCoordinate {
            virtual_nanos: 100,
            retired_instructions: Some(44),
        },
        cause: BindingActionCause::Signal,
        expected_precondition: None,
    }
}

pub(super) fn lifecycle_event(action: &ResolvedBindingAction) -> DequeuedFaultEvent {
    let mut payload = vec![0_u8; LIFECYCLE_EVIDENCE_BYTES];
    let before_hash = [5_u8; 32];
    let transition = match action.effect.specification() {
        EffectSpecification::Node(NodeEffectSpecification::Lifecycle { transition, .. }) => {
            lifecycle_tag(*transition)
        }
        other => panic!("test lifecycle action contains {other:?}"),
    };
    let mut after_hash = [6_u8; 32];
    payload[0..8].copy_from_slice(b"CRUCLIF1");
    payload[8..10].copy_from_slice(&4_u16.to_le_bytes());
    payload[10..12].copy_from_slice(&transition.to_le_bytes());
    payload[12..16].copy_from_slice(&1_u32.to_le_bytes());
    payload[16..20].copy_from_slice(&2_u32.to_le_bytes());
    let preserved_domains = u32::from(matches!(transition, 1 | 3 | 5));
    payload[20..24].copy_from_slice(&preserved_domains.to_le_bytes());
    payload[24..32].copy_from_slice(&44_u64.to_le_bytes());
    payload[32..40].copy_from_slice(&100_u64.to_le_bytes());
    payload[40..48].copy_from_slice(&32_u64.to_le_bytes());
    payload[48..56].copy_from_slice(&4096_u64.to_le_bytes());
    payload[56..64].copy_from_slice(&128_u64.to_le_bytes());
    let binding_hash =
        ContentHash::from_canonical_material("crucible.fault-binding.v1", action.binding.as_str());
    payload[64..96].copy_from_slice(&binding_hash.bytes);
    payload[96..104].copy_from_slice(&132_u64.to_le_bytes());
    payload[112..120].copy_from_slice(&4096_u64.to_le_bytes());
    payload[120..128].copy_from_slice(&128_u64.to_le_bytes());
    payload[128..160].copy_from_slice(&before_hash);
    payload[160..192].copy_from_slice(&after_hash);
    let boot_policy = match action.effect.specification() {
        EffectSpecification::Node(NodeEffectSpecification::Lifecycle { boot_policy, .. }) => {
            boot_policy
        }
        other => panic!("test lifecycle action contains {other:?}"),
    };
    match boot_policy {
        NodeBootPolicy::Immediate => {
            payload[192..196].copy_from_slice(&1_u32.to_le_bytes());
            payload[196..200].copy_from_slice(&1_u32.to_le_bytes());
            payload[200..204].copy_from_slice(&1_u32.to_le_bytes());
            payload[216..224].copy_from_slice(&u64::MAX.to_le_bytes());
        }
        NodeBootPolicy::RequireReady {
            ready_marker,
            maximum_attempts,
            retry_delay_nanos,
            exhausted,
        } => {
            payload[192..196].copy_from_slice(&2_u32.to_le_bytes());
            payload[196..200].copy_from_slice(&1_u32.to_le_bytes());
            payload[200..204].copy_from_slice(&maximum_attempts.get().to_le_bytes());
            payload[204..208].copy_from_slice(&u32::from(lifecycle_tag(*exhausted)).to_le_bytes());
            payload[208..216].copy_from_slice(&retry_delay_nanos.to_le_bytes());
            payload[216..224].copy_from_slice(&4200_u64.to_le_bytes());
            let marker_hash: [u8; 32] = Sha256::digest(ready_marker.as_str().as_bytes()).into();
            payload[224..256].copy_from_slice(&marker_hash);
        }
    }
    payload[288..292].copy_from_slice(&u32::from(transition).to_le_bytes());
    if matches!(transition, 2 | 4 | 6) {
        let pre_exit_hash = [9_u8; 32];
        let mut material = [0_u8; 48];
        material[0..8].copy_from_slice(b"CRUCTRM1");
        material[8..12].copy_from_slice(&u32::from(transition).to_le_bytes());
        material[16..48].copy_from_slice(&pre_exit_hash);
        after_hash = Sha256::digest(material).into();
        payload[160..192].copy_from_slice(&after_hash);
        payload[256..288].copy_from_slice(&pre_exit_hash);
        payload[292..296].copy_from_slice(&LIFECYCLE_TERMINAL_CAUSE_DIRECT.to_le_bytes());
        payload[296..300].copy_from_slice(
            &(LIFECYCLE_TERMINAL_PRE_EXIT_VALID | LIFECYCLE_TERMINAL_EXIT_REQUIRED).to_le_bytes(),
        );
    }
    DequeuedFaultEvent {
        header: crucible_shmem::FaultEventHeaderV1 {
            command_kind: crucible_shmem::FaultCommandKind::NodeLifecycle,
            outcome: FaultEventOutcomeV1::Applied,
            event_sequence: 1,
            rule_command_sequence: 2,
            observed_icount: 44,
            model_phase: 1,
            target_kind: 1,
            generation: 1,
            binding_hash: binding_hash.bytes,
            opportunity_hash: [2; 32],
            action_hash: action.id().bytes,
            target_hash: ContentHash::from_canonical_material(
                "crucible.resolved-fault-target.v1",
                &action.target.canonical_material(),
            )
            .bytes,
            before_hash,
            after_hash,
            evidence_hash: Sha256::digest(&payload).into(),
            payload_hash: *blake3::hash(&payload).as_bytes(),
            payload_offset: 0,
            payload_length: LIFECYCLE_EVIDENCE_BYTES as u32,
        },
        payload,
    }
}
