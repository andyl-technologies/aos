//! Unit tests for active contributions and adapter checkpoint state.

use super::*;

fn object_id(value: &str) -> FaultObjectId {
    match FaultObjectId::parse(value) {
        Ok(id) => id,
        Err(error) => panic!("test object ID must be valid: {error}"),
    }
}

#[test]
fn resolved_effect_trace_rejects_unversioned_and_future_envelopes() {
    let trace = ResolvedEffectTrace {
        mode: FaultReplayMode::LockedEffect,
        work_items: Vec::new(),
        cursor: 0,
    };
    let bytes = trace
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("trace should encode: {error}"));
    assert!(bytes.starts_with(RESOLVED_EFFECT_TRACE_MAGIC));
    assert_eq!(
        ResolvedEffectTrace::from_canonical_bytes(&bytes, FaultResourceLimits::default()),
        Ok(trace.clone())
    );

    let mut unversioned = Vec::new();
    ciborium::ser::into_writer(&trace, &mut unversioned)
        .unwrap_or_else(|error| panic!("legacy trace fixture should encode: {error}"));
    assert_eq!(
        ResolvedEffectTrace::from_canonical_bytes(&unversioned, FaultResourceLimits::default()),
        Err(FaultRuntimeError::VersionOrIdentityMismatch)
    );

    let mut future = bytes;
    future[..RESOLVED_EFFECT_TRACE_MAGIC.len()]
        .copy_from_slice(b"crucible.resolved-effect-trace.v2\0");
    assert_eq!(
        ResolvedEffectTrace::from_canonical_bytes(&future, FaultResourceLimits::default()),
        Err(FaultRuntimeError::VersionOrIdentityMismatch)
    );
}

#[test]
fn healing_removes_only_one_contributor() {
    let target = ResolvedFaultTarget::NetworkSegment {
        segment: object_id("segment-a"),
        direction: FaultDirection::AToB,
    };
    let request = match EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Persistent,
        EffectSpecification::Network(NetworkEffectSpecification::Availability {
            state: NetworkAvailabilityState::Down,
            queued_policy: NetworkInFlightPolicy::Drop,
            in_flight_policy: NetworkInFlightPolicy::Drop,
        }),
    ) {
        Ok(value) => value,
        Err(error) => panic!("test request must be valid: {error}"),
    };
    let mut table = ActiveContributionTable::default();
    for name in ["binding-a", "binding-b"] {
        let result = table.activate(
            ActiveContributionKey {
                target: target.clone(),
                phase: FaultPhase::Admit,
                effect: EffectKind::NetworkAvailability,
                binding: object_id(name),
            },
            ActiveEffectContribution {
                request: Arc::new(request.clone()),
                mapped_parameters: ContentHash::from_bytes(name.as_bytes()),
                mapping_output: Arc::new(ResolvedMappingOutput::Activation { active: true }),
                transition_sequence: 1,
            },
            FaultResourceLimits::default(),
        );
        assert!(result.is_ok());
    }
    let removed = table.deactivate(&ActiveContributionKey {
        target,
        phase: FaultPhase::Admit,
        effect: EffectKind::NetworkAvailability,
        binding: object_id("binding-a"),
    });
    assert!(removed.is_some());
    assert_eq!(table.entries().len(), 1);
    assert_eq!(table.composition_groups()[0].contributors.len(), 1);
}

#[test]
fn active_contributions_obey_the_plan_owned_per_target_limit() {
    let target = ResolvedFaultTarget::NetworkSegment {
        segment: object_id("segment-limited"),
        direction: FaultDirection::AToB,
    };
    let request = EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Persistent,
        EffectSpecification::Network(NetworkEffectSpecification::Availability {
            state: NetworkAvailabilityState::Down,
            queued_policy: NetworkInFlightPolicy::Drop,
            in_flight_policy: NetworkInFlightPolicy::Drop,
        }),
    )
    .unwrap_or_else(|error| panic!("test request must be valid: {error}"));
    let limits = FaultResourceLimits {
        active_contributions_per_target: 1,
        ..FaultResourceLimits::default()
    };
    let mut table = ActiveContributionTable::default();
    for name in ["binding-first", "binding-rejected"] {
        let result = table.activate(
            ActiveContributionKey {
                target: target.clone(),
                phase: FaultPhase::Admit,
                effect: EffectKind::NetworkAvailability,
                binding: object_id(name),
            },
            ActiveEffectContribution {
                request: Arc::new(request.clone()),
                mapped_parameters: ContentHash::from_bytes(name.as_bytes()),
                mapping_output: Arc::new(ResolvedMappingOutput::Activation { active: true }),
                transition_sequence: 1,
            },
            limits,
        );
        if name == "binding-first" {
            assert!(result.is_ok());
        } else {
            assert!(matches!(
                result,
                Err(FaultRuntimeError::ResourceLimit(
                    FaultResourceLimitError::Exceeded {
                        field: "active_contributions_per_target",
                        current: 1,
                        requested: 1,
                        configured: 1,
                        ..
                    }
                ))
            ));
        }
    }
    assert_eq!(table.entries().len(), 1);
}

#[test]
fn adapter_checkpoint_digest_is_revalidated() {
    let mut state =
        match AdapterCheckpointState::new(1, vec![1, 2, 3], FaultResourceLimits::default()) {
            Ok(value) => value,
            Err(error) => panic!("test adapter state must be valid: {error}"),
        };
    state.bytes.push(4);
    assert_eq!(
        state.validate(FaultResourceLimits::default()),
        Err(FaultRuntimeError::AdapterCheckpointDigest)
    );
}

#[test]
fn composition_identity_includes_the_concrete_target() {
    let contributor = CompositionContributor {
        binding: object_id("binding-a"),
        parameters: ContentHash::from_bytes(b"same"),
        mapping_output: ResolvedMappingOutput::Activation { active: true },
    };
    let first = EffectComposition::new(
        ResolvedFaultTarget::NetworkSegment {
            segment: object_id("segment-a"),
            direction: FaultDirection::AToB,
        },
        FaultPhase::Admit,
        EffectKind::NetworkAvailability,
        contributor.clone(),
    );
    let second = EffectComposition::new(
        ResolvedFaultTarget::NetworkSegment {
            segment: object_id("segment-b"),
            direction: FaultDirection::AToB,
        },
        FaultPhase::Admit,
        EffectKind::NetworkAvailability,
        contributor,
    );
    assert_ne!(first.digest, second.digest);
}
