//! Request identity, keyed choice, and volatile cache boundary regressions.

use super::*;

#[test]
fn opportunity_binds_wire_digest_range_phase_and_monotone_sequence() {
    let request = BlockRequest::read(7, 512, 1024);
    let coordinate = FaultCoordinate {
        virtual_ticks: 40,
        retired_instructions: Some(20),
    };
    let first = block_request_fault_opportunity(
        target(),
        &request,
        [3; 32],
        FaultPhase::Resolve,
        coordinate,
        11,
    )
    .unwrap_or_else(|error| panic!("opportunity should be valid: {error}"));
    let next = block_request_fault_opportunity(
        target(),
        &request,
        [3; 32],
        FaultPhase::Resolve,
        coordinate,
        12,
    )
    .unwrap_or_else(|error| panic!("opportunity should be valid: {error}"));
    let changed_wire = block_request_fault_opportunity(
        target(),
        &request,
        [4; 32],
        FaultPhase::Resolve,
        coordinate,
        11,
    )
    .unwrap_or_else(|error| panic!("opportunity should be valid: {error}"));

    assert_eq!(first.operation(), FaultOperation::StorageRead);
    assert_eq!(first.phase(), FaultPhase::Resolve);
    assert_ne!(first.id(), next.id());
    assert_ne!(first.id(), changed_wire.id());
}

#[test]
fn delivery_opportunity_binds_the_computed_response() {
    let request = BlockRequest::read(7, 512, 4);
    let directive = ResolvedBlockFaultDirective::fault_free(&request, 4096);
    let delivery = BlockDeliveryOpportunity {
        request_sequence: 11,
        request: request.clone(),
        request_icount: 20,
        ready_ticks: 40,
        wire_digest: [3; 32],
        response: BlockResponse::ok(request.request_id, b"good".to_vec()),
        resolved: directive,
        required_durable_frontier: None,
    };
    let coordinate = FaultCoordinate {
        virtual_ticks: 40,
        retired_instructions: Some(20),
    };
    let first = block_delivery_fault_opportunity(target(), &delivery, coordinate)
        .unwrap_or_else(|error| panic!("delivery opportunity should be valid: {error}"));
    let mut changed = delivery;
    changed.response = BlockResponse::ok(request.request_id, b"evil".to_vec());
    let changed = block_delivery_fault_opportunity(target(), &changed, coordinate)
        .unwrap_or_else(|error| panic!("changed delivery should be valid: {error}"));

    assert_eq!(first.phase(), FaultPhase::Deliver);
    assert_ne!(first.id(), changed.id());
    assert!(matches!(
        first.payload(),
        OpportunityPayload::StorageCompletion {
            response_status: 0,
            ..
        }
    ));
}

#[test]
fn delivery_completion_payload_authenticates_the_original_request() {
    let request = BlockRequest::read(7, 512, 4);
    let wire = request
        .encode()
        .unwrap_or_else(|error| panic!("test request should encode: {error}"));
    let delivery = BlockDeliveryOpportunity {
        request_sequence: 11,
        request: request.clone(),
        request_icount: 20,
        ready_ticks: 40,
        wire_digest: *blake3::hash(&wire).as_bytes(),
        response: BlockResponse::ok(request.request_id, b"good".to_vec()),
        resolved: ResolvedBlockFaultDirective::fault_free(&request, 4096),
        required_durable_frontier: None,
    };
    let opportunity = block_delivery_fault_opportunity(
        target(),
        &delivery,
        FaultCoordinate {
            virtual_ticks: 40,
            retired_instructions: Some(20),
        },
    )
    .unwrap_or_else(|error| panic!("delivery opportunity should be valid: {error}"));

    let resolved = resolve_block_fault_directive_with_capacity(
        &opaque_world(),
        &target(),
        &request,
        delivery.request_sequence,
        &opportunity,
        4096,
        context(),
        &mut unexpected_read_source,
        [],
    )
    .unwrap_or_else(|error| panic!("delivery request identity should validate: {error}"));
    assert_eq!(resolved.request_sequence, delivery.request_sequence);
}

#[test]
fn keyed_choices_are_reproducible_and_scenario_owned() {
    let latency = action(
        "keyed-choice",
        EffectLifetime::Opportunity,
        FaultPhase::Resolve,
        StorageEffectSpecification::Latency {
            operations: OperationSet::new(vec![FaultOperation::StorageRead])
                .unwrap_or_else(|error| panic!("operation set should be valid: {error}")),
            extra_nanos: 0,
            jitter_nanos: 99,
        },
        ResolvedMappingOutput::Hazard {
            probability_millionths: 1_000_000,
        },
    );
    let request = BlockRequest::read(5, 512, 512);
    let first = keyed_inclusive(context(), &latency, &request, b"test-choice", u64::MAX);
    let repeated = keyed_inclusive(context(), &latency, &request, b"test-choice", u64::MAX);
    let different_seed = keyed_inclusive(
        StorageFaultResolutionContext::new(ContentHash::from_bytes(b"different-seed")),
        &latency,
        &request,
        b"test-choice",
        u64::MAX,
    );

    assert_eq!(first, repeated);
    assert_ne!(first, different_seed);
}

#[test]
fn hazard_probability_uses_the_request_keyed_draw() {
    let latency = action(
        "small-hazard",
        EffectLifetime::Opportunity,
        FaultPhase::Resolve,
        StorageEffectSpecification::Latency {
            operations: OperationSet::new(vec![FaultOperation::StorageRead])
                .unwrap_or_else(|error| panic!("operation set should be valid: {error}")),
            extra_nanos: 1,
            jitter_nanos: 0,
        },
        ResolvedMappingOutput::Hazard {
            probability_millionths: 1,
        },
    );
    let request = BlockRequest::read(5, 512, 512);
    let expected = keyed_inclusive(
        context(),
        &latency,
        &request,
        b"storage.effect-probability.v1",
        999_999,
    ) < 1;

    assert_eq!(
        probability_applies(context(), &latency, &request, 1_000_000)
            .unwrap_or_else(|error| panic!("hazard should resolve: {error}")),
        expected
    );
}

#[test]
fn opportunity_action_requires_exact_opportunity_identity() {
    let request = BlockRequest::read(9, 0, 512);
    let opportunity = opportunity(&request, FaultPhase::Resolve);
    let latency = action(
        "unbound-latency",
        EffectLifetime::Opportunity,
        FaultPhase::Resolve,
        StorageEffectSpecification::Latency {
            operations: OperationSet::new(vec![FaultOperation::StorageRead])
                .unwrap_or_else(|error| panic!("operation set should be valid: {error}")),
            extra_nanos: 1,
            jitter_nanos: 0,
        },
        ResolvedMappingOutput::Hazard {
            probability_millionths: 1_000_000,
        },
    );

    assert!(matches!(
        resolve_block_fault_directive_with_capacity(
            &opaque_world(),
            &target(),
            &request,
            1,
            &opportunity,
            4096,
            context(),
            &mut unexpected_read_source,
            [&latency],
        ),
        Err(StorageFaultResolutionError::ActionIdentity { .. })
    ));
}

#[test]
fn opportunity_payload_cannot_alias_another_same_operation_request() {
    let first_request = BlockRequest::read(9, 0, 512);
    let second_request = BlockRequest::read(10, 512, 512);
    let first_opportunity = opportunity(&first_request, FaultPhase::Resolve);

    assert_eq!(
        resolve_block_fault_directive_with_capacity(
            &opaque_world(),
            &target(),
            &second_request,
            1,
            &first_opportunity,
            4096,
            context(),
            &mut unexpected_read_source,
            [],
        ),
        Err(StorageFaultResolutionError::OpportunityMismatch)
    );
}

#[test]
fn write_fragments_follow_physical_atomic_boundaries() {
    let request = BlockRequest::write(1, 6, vec![0; 12]);
    assert_eq!(
        atomic_fragments(&request, 8, &id("atomic-test"))
            .unwrap_or_else(|error| panic!("fragments should resolve: {error}")),
        vec![
            BlockFaultByteSpan {
                start: 0,
                length: 2,
            },
            BlockFaultByteSpan {
                start: 2,
                length: 8,
            },
            BlockFaultByteSpan {
                start: 10,
                length: 2,
            },
        ]
    );
}

#[test]
fn volatile_cache_loss_selection_is_exact_and_reproducible() {
    let all = action(
        "cache-loss-all",
        EffectLifetime::Impulse,
        FaultPhase::Boundary,
        StorageEffectSpecification::VolatileCacheLoss {
            selector: StorageVolatileCacheLossSelector::All,
            loss: StorageVolatileCacheLossKind::ProtectionFailure,
        },
        ResolvedMappingOutput::Impulse {
            event: SignalValue::Bytes(vec![1]),
        },
    );
    let state = BlockFaultState::write_through(4096);
    let eligible = [2, 5, 9];
    assert_eq!(
        select_volatile_cache_loss(
            context(),
            &all,
            &StorageVolatileCacheLossSelector::All,
            &state,
            &eligible,
        )
        .unwrap_or_else(|error| panic!("all selection should resolve: {error}")),
        vec![2, 5, 9]
    );
    assert_eq!(
        select_volatile_cache_loss(
            context(),
            &all,
            &StorageVolatileCacheLossSelector::AfterSequence { sequence: 2 },
            &state,
            &eligible,
        )
        .unwrap_or_else(|error| panic!("sequence selection should resolve: {error}")),
        vec![5, 9]
    );
    let subset = StorageVolatileCacheLossSelector::KeyedSubset {
        count: BoundedCount::new(CountLimit::LargeStateEntries, 2)
            .unwrap_or_else(|error| panic!("subset count should be valid: {error}")),
    };
    let first = select_volatile_cache_loss(context(), &all, &subset, &state, &eligible)
        .unwrap_or_else(|error| panic!("keyed selection should resolve: {error}"));
    let repeated = select_volatile_cache_loss(context(), &all, &subset, &state, &eligible)
        .unwrap_or_else(|error| panic!("keyed selection should repeat: {error}"));
    assert_eq!(first, repeated);
    assert_eq!(first.len(), 2);
    assert!(first.iter().all(|sequence| eligible.contains(sequence)));
}

#[test]
fn volatile_cache_loss_requires_a_boundary_event_payload() {
    let bytes = action(
        "cache-loss-bytes",
        EffectLifetime::Impulse,
        FaultPhase::Boundary,
        StorageEffectSpecification::VolatileCacheLoss {
            selector: StorageVolatileCacheLossSelector::All,
            loss: StorageVolatileCacheLossKind::PowerLoss,
        },
        ResolvedMappingOutput::Impulse {
            event: SignalValue::Bytes(vec![1]),
        },
    );
    assert!(matches!(
        resolve_volatile_cache_loss(
            &target(),
            &BlockFaultState::write_through(4096),
            context(),
            &bytes,
            VolatileCacheLossReplay::Record,
        ),
        Err(StorageFaultResolutionError::ActionIdentity { .. })
    ));

    let event = action(
        "cache-loss-event",
        EffectLifetime::Impulse,
        FaultPhase::Boundary,
        StorageEffectSpecification::VolatileCacheLoss {
            selector: StorageVolatileCacheLossSelector::All,
            loss: StorageVolatileCacheLossKind::PowerLoss,
        },
        ResolvedMappingOutput::Impulse {
            event: SignalValue::Event {
                schema: SignalId::parse("loss-event")
                    .unwrap_or_else(|error| panic!("test signal ID should be valid: {error}")),
                payload: vec![7],
            },
        },
    );
    let state = BlockFaultState::write_through(4096);
    let resolved = resolve_volatile_cache_loss(
        &target(),
        &state,
        context(),
        &event,
        VolatileCacheLossReplay::Record,
    )
    .unwrap_or_else(|error| panic!("event loss should resolve: {error}"));
    assert_eq!(resolved.entry_set_digest, state.volatile_entries_digest());
    assert!(resolved.eligible_sequences.is_empty());
    assert!(resolved.protected_sequences.is_empty());
    assert!(resolved.selected_sequences.is_empty());
    assert_eq!(resolved.durable_frontier_before, 0);
    assert_eq!(resolved.durable_frontier_after, 0);
    assert!(matches!(
        resolve_volatile_cache_loss(
            &target(),
            &state,
            context(),
            &event,
            VolatileCacheLossReplay::Locked {
                expected_entry_set_digest: [9; 32],
            },
        ),
        Err(StorageFaultResolutionError::ReplayEntrySetMismatch { .. })
    ));
    record_production_effect_rows(
        &[crucible::model::EffectKind::StorageVolatileCacheLoss],
        "volatile-cache-loss-authenticates-entry-set",
        "entry-set-digest+selected-sequences+durable-frontier",
    );
}

#[test]
fn independently_sampled_storage_phases_merge_without_erasing_prior_fields() {
    let request = BlockRequest::write(77, 8, vec![1; 4]);
    let mut accumulated = ResolvedBlockFaultDirective::fault_free(&request, 4096);
    accumulated.request_sequence = 1_001;

    let mut admit = accumulated.clone();
    admit.availability = BlockFaultAvailability::Degraded;
    admit.reported_capacity_bytes = 2048;
    merge_block_fault_phase_directive(&mut accumulated, FaultPhase::Admit, admit)
        .unwrap_or_else(|error| panic!("admit phase should merge: {error}"));

    let mut resolve = ResolvedBlockFaultDirective::fault_free(&request, 4096);
    resolve.request_sequence = 1_001;
    resolve.execution_ticks = 31;
    resolve.additional_latency_nanos = 7;
    resolve.error_result = Some(BlockFaultResult::IoError);
    merge_block_fault_phase_directive(&mut accumulated, FaultPhase::Resolve, resolve)
        .unwrap_or_else(|error| panic!("resolve phase should merge: {error}"));

    let mut deliver = ResolvedBlockFaultDirective::fault_free(&request, 4096);
    deliver.request_sequence = 1_001;
    deliver.additional_latency_nanos = 11;
    merge_block_fault_phase_directive(&mut accumulated, FaultPhase::Deliver, deliver)
        .unwrap_or_else(|error| panic!("deliver phase should merge: {error}"));

    assert_eq!(accumulated.availability, BlockFaultAvailability::Degraded);
    assert_eq!(accumulated.reported_capacity_bytes, 2048);
    assert_eq!(accumulated.execution_ticks, 31);
    assert_eq!(accumulated.additional_latency_nanos, 18);
    assert_eq!(accumulated.error_result, Some(BlockFaultResult::IoError));
}
