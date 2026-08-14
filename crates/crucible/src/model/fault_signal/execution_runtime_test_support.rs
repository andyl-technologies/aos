//! Shared fixtures for signal-to-adapter execution tests.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

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
        .unwrap_or_else(|error| panic!("test object ID must be valid: {error}"))
}

pub(super) fn signal_id(value: &str) -> SignalId {
    SignalId::parse(value).unwrap_or_else(|error| panic!("test signal ID must be valid: {error}"))
}

pub(super) fn manifest(adapter: FaultAdapter) -> FaultCapabilityManifest {
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

pub(super) fn manifests() -> FaultAdapterManifests {
    FaultAdapterManifests {
        network: manifest(FaultAdapter::Network),
        storage: manifest(FaultAdapter::Storage),
        node: manifest(FaultAdapter::Node),
    }
}

pub(super) fn test_plan() -> FaultSignalPlan {
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
    FaultSignalPlan::new(vec![program], vec![binding], FaultResourceLimits::default())
        .unwrap_or_else(|error| panic!("test plan: {error}"))
}

pub(super) fn network_outcome_plan() -> FaultSignalPlan {
    let output = signal_id("frame-effect");
    let program = SignalProgram::new(
        vec![SignalNode {
            id: output.clone(),
            domain: SignalDomain::VirtualTime,
            output: SignalShape::new(
                SignalValueType::ProbabilityMillionths,
                SignalUnit::ProbabilityMillionths,
                0,
            )
            .unwrap_or_else(|error| panic!("test shape: {error}")),
            inputs: Vec::new(),
            kind: SignalNodeKind::Constant {
                value: SignalValue::ProbabilityMillionths(1_000_000),
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
        EffectLifetime::Opportunity,
        EffectSpecification::Network(NetworkEffectSpecification::Jitter {
            maximum_nanos: PositiveU64::new("maximum_nanos", 5)
                .unwrap_or_else(|error| panic!("test jitter: {error}")),
            distribution: NetworkDistribution::Uniform,
            distribution_lookup: None,
        }),
    )
    .unwrap_or_else(|error| panic!("test effect: {error}"));
    let binding = FaultBinding::new(
        object_id("frame-delay"),
        vec![output],
        BindingSampling::AtOpportunity,
        BindingMapping::Hazard,
        TargetSelector::Exact(targets),
        BTreeSet::from([FaultPhase::Resolve]),
        effect,
        Some(OpportunityFilter {
            adapter: FaultAdapter::Network,
            operations: OperationSet::new(vec![FaultOperation::NetworkTraverse])
                .unwrap_or_else(|error| panic!("test operation filter: {error}")),
            phases: BTreeSet::from([FaultPhase::Resolve]),
            target_kinds: BTreeSet::from([FaultTargetKind::NetworkSegment]),
        }),
        BindingSearchPolicy::Fixed,
        BindingObservabilityPolicy {
            samples: SampleObservation::ChangesAndEffects,
            record_inactive_opportunities: false,
            retain_mapped_values: true,
        },
        &program,
    )
    .unwrap_or_else(|error| panic!("test binding: {error}"));
    FaultSignalPlan::new(vec![program], vec![binding], FaultResourceLimits::default())
        .unwrap_or_else(|error| panic!("test plan: {error}"))
}

pub(super) fn frame_opportunity(
    coordinate: FaultCoordinate,
    producer_sequence: u64,
) -> FaultOpportunity {
    frame_opportunity_with_operation(
        coordinate,
        producer_sequence,
        FaultOperation::NetworkTraverse,
    )
}

pub(super) fn frame_opportunity_with_operation(
    coordinate: FaultCoordinate,
    producer_sequence: u64,
    operation: FaultOperation,
) -> FaultOpportunity {
    FaultOpportunity::new(
        ResolvedFaultTarget::NetworkSegment {
            segment: object_id("segment-a"),
            direction: FaultDirection::AToB,
        },
        operation,
        FaultPhase::Resolve,
        coordinate,
        producer_sequence,
        Some(FaultDirection::AToB),
        OpportunityPayload::NetworkFrame {
            producer: object_id("sender"),
            destination: object_id("receiver"),
            producer_sequence,
            protocol_expansion_path: Vec::new(),
            generated_response_depth: 0,
            generated_response_cause: None,
            forwarding_mutation_path: Vec::new(),
            length_bytes: 128,
            payload_digest: ContentHash::from_bytes(b"captured-frame"),
        },
    )
    .unwrap_or_else(|error| panic!("test opportunity: {error}"))
}
