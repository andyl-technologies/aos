//! Referenced-event window retention, accounting, and coverage tests.

use std::sync::Arc;

use super::*;
use crucible_engine::model::{
    BindingActionCause, BindingActionKind, EFFECT_SEMANTIC_VERSION, EffectLifetime, EffectRequest,
    FaultActionSink, FaultCoordinate, FaultPhase, HostFaultActionSink, PositiveU64,
    ResolvedBindingAction, ResolvedMappingOutput, SignalId, SignalValue,
};

fn limits() -> FaultResourceLimits {
    FaultResourceLimits::default()
}

fn event(signal: &str, ticks: u64, sequence: u64) -> ReferencedSignalEvent {
    let mut event = ReferencedSignalEvent {
        signal: SignalId::parse(signal)
            .unwrap_or_else(|error| panic!("test signal should parse: {error}")),
        coordinate: FaultCoordinate {
            virtual_ticks: ticks,
            retired_instructions: None,
        },
        same_coordinate_sequence: sequence,
        value: SignalValue::Event {
            schema: SignalId::parse("recovery-schema")
                .unwrap_or_else(|error| panic!("test schema should parse: {error}")),
            payload: vec![u8::try_from(ticks % 251).unwrap_or(0)],
        },
        evidence: ContentHash::default(),
    };
    let (evidence, _bytes) = event
        .canonical_value_identity()
        .unwrap_or_else(|error| panic!("test event should encode: {error}"));
    event.evidence = evidence;
    event
}

fn key(signal: &str) -> [u8; 32] {
    storage_recovery_event_key(
        &FaultObjectId::parse(signal)
            .unwrap_or_else(|error| panic!("test signal should parse: {error}")),
    )
}

fn coordinate(ticks: u64, sequence: u64) -> ReferencedEventCoordinate {
    ReferencedEventCoordinate { ticks, sequence }
}

fn consumer(name: &str) -> ReferencedEventConsumer {
    ReferencedEventConsumer::block_recovery(&ResolvedFaultTarget::BlockDevice {
        device: ContentHash::from_bytes(name.as_bytes()),
    })
    .unwrap_or_else(|error| panic!("test consumer should derive: {error}"))
}

fn emit(window: &mut ReferencedEventWindow, events: &[ReferencedSignalEvent]) {
    let charged = window
        .charge(events, limits())
        .unwrap_or_else(|error| panic!("test events should charge: {error}"));
    window
        .try_reserve(charged.len(), limits())
        .unwrap_or_else(|error| panic!("test window should reserve: {error}"));
    window.publish(charged);
}

fn retained_coordinates(window: &ReferencedEventWindow) -> Vec<(u64, u64)> {
    window
        .retained()
        .iter()
        .map(|retained| (retained.coordinate().ticks, retained.coordinate().sequence))
        .collect()
}

fn empty_host() -> HostFaultActionState {
    HostFaultActionState::default()
}

#[test]
fn charge_counts_each_event_once_and_chains_the_complete_history() {
    let mut window = ReferencedEventWindow::default();
    let first = event("recovered", 10, 0);
    let second = event("recovered", 20, 1);

    emit(&mut window, std::slice::from_ref(&first));
    let after_first = window.history();
    emit(&mut window, std::slice::from_ref(&second));

    let expected_bytes = [&first, &second]
        .iter()
        .map(|event| {
            referenced_event_log_bytes(event, limits())
                .unwrap_or_else(|error| panic!("test event should measure: {error}"))
        })
        .sum::<u64>();
    assert_eq!(window.emitted(), 2);
    assert_eq!(window.usage().records, 2);
    assert_eq!(window.usage().log_bytes, expected_bytes);
    assert_eq!(after_first, chain_history(ContentHash::default(), &first));
    assert_eq!(window.history(), chain_history(after_first, &second));
}

#[test]
fn charge_rejects_an_event_that_precedes_the_newest_emission() {
    let mut window = ReferencedEventWindow::default();
    emit(&mut window, &[event("recovered", 20, 0)]);

    assert!(matches!(
        window.charge(&[event("recovered", 19, 5)], limits()),
        Err(ProductionFaultRuntimeError::Execution(
            FaultExecutionError::CheckpointPresence
        ))
    ));
}

#[test]
fn charge_reserves_event_records_from_the_cumulative_count() {
    let mut window = ReferencedEventWindow::default();
    emit(
        &mut window,
        &[event("recovered", 1, 0), event("recovered", 2, 0)],
    );
    let mut tight = limits();
    tight.event_records = 2;

    assert!(matches!(
        window.charge(&[event("recovered", 3, 0)], tight),
        Err(ProductionFaultRuntimeError::ResourceLimit(
            FaultResourceLimitError::Exceeded {
                field: "event_records",
                current: 2,
                requested: 1,
                configured: 2,
                ..
            }
        ))
    ));
}

#[test]
fn unbound_window_retires_every_event_but_keeps_counts_and_history() {
    let mut window = ReferencedEventWindow::default();
    emit(
        &mut window,
        &[event("recovered", 5, 0), event("recovered", 9, 0)],
    );
    let history = window.history();

    window
        .retire_unneeded(&empty_host(), limits())
        .unwrap_or_else(|error| panic!("retirement should succeed: {error}"));

    assert!(window.retained().is_empty());
    assert_eq!(window.emitted(), 2);
    assert_eq!(window.history(), history);
    assert_eq!(
        window.retired_frontier(key("recovered")),
        Some(coordinate(9, 0))
    );
}

#[test]
fn subscription_keeps_its_earliest_releasing_event_and_the_newest_tick() {
    let mut window = ReferencedEventWindow::default();
    let block = consumer("block-a");
    window
        .bind_consumers(&[block], &empty_host(), limits())
        .unwrap_or_else(|error| panic!("binding should succeed: {error}"));
    window
        .report_subscriptions(
            block,
            vec![ReferencedEventSubscription {
                event: key("recovered"),
                after: coordinate(15, 0),
            }],
            &empty_host(),
            limits(),
        )
        .unwrap_or_else(|error| panic!("report should succeed: {error}"));
    emit(
        &mut window,
        &[
            event("recovered", 10, 0),
            event("recovered", 20, 0),
            event("other", 25, 0),
            event("recovered", 26, 0),
            event("recovered", 30, 0),
            event("other", 30, 1),
        ],
    );

    window
        .retire_unneeded(&empty_host(), limits())
        .unwrap_or_else(|error| panic!("retirement should succeed: {error}"));

    assert_eq!(
        retained_coordinates(&window),
        vec![(20, 0), (30, 0), (30, 1)]
    );
    assert_eq!(
        window.retired_frontier(key("recovered")),
        Some(coordinate(26, 0))
    );
    assert_eq!(
        window.retired_frontier(key("other")),
        Some(coordinate(25, 0))
    );
    assert_eq!(window.emitted(), 6);
}

#[test]
fn verification_rejects_an_unreported_subscription_behind_a_retired_event() {
    let mut window = ReferencedEventWindow::default();
    let block = consumer("block-a");
    window
        .bind_consumers(&[block], &empty_host(), limits())
        .unwrap_or_else(|error| panic!("binding should succeed: {error}"));
    emit(
        &mut window,
        &[event("recovered", 10, 0), event("other", 20, 0)],
    );
    window
        .retire_unneeded(&empty_host(), limits())
        .unwrap_or_else(|error| panic!("retirement should succeed: {error}"));
    let behind = ReferencedEventSubscription {
        event: key("recovered"),
        after: coordinate(5, 0),
    };
    let ahead = ReferencedEventSubscription {
        event: key("recovered"),
        after: coordinate(10, 0),
    };

    assert!(
        window
            .verify_subscriptions(block, &[ahead], &empty_host())
            .is_ok()
    );
    assert!(matches!(
        window.verify_subscriptions(block, &[behind], &empty_host()),
        Err(ProductionFaultRuntimeError::ReferencedEventWindow { .. })
    ));
    assert!(matches!(
        window.report_subscriptions(block, vec![behind], &empty_host(), limits()),
        Err(ProductionFaultRuntimeError::ReferencedEventWindow { .. })
    ));
    assert!(matches!(
        window.verify_subscriptions(consumer("unbound"), &[], &empty_host()),
        Err(ProductionFaultRuntimeError::ReferencedEventWindow { .. })
    ));
}

#[test]
fn rebinding_keeps_reported_subscriptions_and_drops_unbound_consumers() {
    let mut window = ReferencedEventWindow::default();
    let kept = consumer("kept");
    let dropped = consumer("dropped");
    let subscription = ReferencedEventSubscription {
        event: key("recovered"),
        after: coordinate(1, 0),
    };
    window
        .bind_consumers(&[kept, dropped], &empty_host(), limits())
        .unwrap_or_else(|error| panic!("binding should succeed: {error}"));
    window
        .report_subscriptions(kept, vec![subscription], &empty_host(), limits())
        .unwrap_or_else(|error| panic!("report should succeed: {error}"));

    window
        .bind_consumers(&[kept], &empty_host(), limits())
        .unwrap_or_else(|error| panic!("rebinding should succeed: {error}"));

    assert_eq!(
        window.consumer_subscriptions().get(&kept),
        Some(&vec![subscription])
    );
    assert!(!window.consumer_subscriptions().contains_key(&dropped));
}

#[test]
fn persistent_recovery_action_keeps_its_tick_and_first_later_event() {
    let host = host_with_persistent_stall("recovered", 20);
    let mut window = ReferencedEventWindow::default();
    window
        .bind_consumers(&[consumer("block-a")], &host, limits())
        .unwrap_or_else(|error| panic!("binding should succeed: {error}"));
    emit(
        &mut window,
        &[
            event("recovered", 10, 0),
            event("recovered", 20, 1),
            event("recovered", 20, 4),
            event("recovered", 30, 0),
            event("recovered", 40, 0),
            event("other", 50, 0),
        ],
    );

    window
        .retire_unneeded(&host, limits())
        .unwrap_or_else(|error| panic!("retirement should succeed: {error}"));

    assert_eq!(
        retained_coordinates(&window),
        vec![(20, 1), (20, 4), (30, 0), (50, 0)]
    );
    // A completion this action retains later subscribes at its installation
    // tick, so verification accepts it although later events retired.
    let late_retention = ReferencedEventSubscription {
        event: key("recovered"),
        after: coordinate(20, 2),
    };
    assert!(
        window
            .verify_subscriptions(consumer("block-a"), &[late_retention], &host)
            .is_ok()
    );
}

/// A full-history scan and the window select the same releasing event.
///
/// Subscriptions are created at the evaluation cursor, as opportunity
/// evaluations create them, and are reported before the next emission.
#[test]
fn window_selection_matches_a_full_history_scan() {
    let keys = ["recovered-a", "recovered-b", "recovered-c"];
    let mut state = 0x5eed_u64;
    let mut next = move |bound: u64| {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (state >> 33) % bound
    };

    for _case in 0..64 {
        let block = consumer("block-a");
        let mut window = ReferencedEventWindow::default();
        window
            .bind_consumers(&[block], &empty_host(), limits())
            .unwrap_or_else(|error| panic!("binding should succeed: {error}"));
        let mut history = Vec::new();
        let mut live = Vec::<ReferencedEventSubscription>::new();
        let mut cursor = coordinate(0, 0);

        for _step in 0..48 {
            // Advance the monotone evaluation cursor.
            cursor = if next(3) == 0 {
                coordinate(cursor.ticks, cursor.sequence + 1)
            } else {
                coordinate(cursor.ticks + 1 + next(4), 0)
            };
            match next(4) {
                0 | 1 => {
                    let emitted = (0..=next(2))
                        .map(|_| {
                            event(
                                keys[usize::try_from(next(3)).unwrap_or(0)],
                                cursor.ticks,
                                cursor.sequence,
                            )
                        })
                        .collect::<Vec<_>>();
                    window
                        .retire_unneeded(&empty_host(), limits())
                        .unwrap_or_else(|error| panic!("retirement should succeed: {error}"));
                    emit(&mut window, &emitted);
                    history.extend(emitted);
                }
                2 => live.push(ReferencedEventSubscription {
                    event: key(keys[usize::try_from(next(3)).unwrap_or(0)]),
                    after: cursor,
                }),
                _ => {
                    if !live.is_empty() {
                        let position =
                            usize::try_from(next(u64::try_from(live.len()).unwrap_or(1)))
                                .unwrap_or(0);
                        live.swap_remove(position);
                    }
                }
            }
            window
                .verify_subscriptions(block, &live, &empty_host())
                .unwrap_or_else(|error| panic!("live subscriptions should be covered: {error}"));
            window
                .report_subscriptions(block, live.clone(), &empty_host(), limits())
                .unwrap_or_else(|error| panic!("report should succeed: {error}"));

            for subscription in &live {
                let full = history
                    .iter()
                    .filter(|event| key(event.signal.as_str()) == subscription.event)
                    .map(ReferencedEventCoordinate::of)
                    .filter(|candidate| *candidate > subscription.after)
                    .min();
                let windowed = window
                    .retained()
                    .iter()
                    .filter(|retained| retained.key() == subscription.event)
                    .map(RetainedReferencedEvent::coordinate)
                    .filter(|candidate| *candidate > subscription.after)
                    .min();
                assert_eq!(windowed, full, "subscription {subscription:?}");
            }
        }
    }
}

fn host_with_persistent_stall(recovery: &str, installed_ticks: u64) -> HostFaultActionState {
    let effect = EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::StateMachine,
        EffectSpecification::Storage(StorageEffectSpecification::StallTimeout {
            stall_nanos: PositiveU64::new("stall_nanos", 20)
                .unwrap_or_else(|error| panic!("test stall should be positive: {error}")),
            recovery_event: Some(
                FaultObjectId::parse(recovery)
                    .unwrap_or_else(|error| panic!("test recovery should parse: {error}")),
            ),
            timeout_result: FaultObjectId::parse("timeout-result")
                .unwrap_or_else(|error| panic!("test result should parse: {error}")),
        }),
    )
    .unwrap_or_else(|error| panic!("test stall effect should be valid: {error}"));
    let action = ResolvedBindingAction {
        kind: BindingActionKind::UpsertPersistent,
        binding: FaultObjectId::parse("storage-stall")
            .unwrap_or_else(|error| panic!("test binding should parse: {error}")),
        target: ResolvedFaultTarget::BlockDevice {
            device: ContentHash::from_bytes(b"block-a"),
        },
        phase: FaultPhase::Resolve,
        effect: Arc::new(effect),
        mapping_output: Arc::new(ResolvedMappingOutput::Activation { active: true }),
        mapped_digest: ContentHash::from_bytes(b"storage-stall-mapping"),
        transition_sequence: 1,
        opportunity: None,
        coordinate: FaultCoordinate {
            virtual_ticks: installed_ticks,
            retired_instructions: None,
        },
        cause: BindingActionCause::Signal,
        expected_precondition: None,
    };
    let mut sink = HostFaultActionSink::new(limits());
    let prepared = sink
        .prepare_batch(std::slice::from_ref(&action))
        .unwrap_or_else(|error| panic!("test stall should prepare: {}", error.error));
    sink.commit_batch(prepared.transaction)
        .unwrap_or_else(|error| panic!("test stall should commit: {error:?}"));
    sink.state().clone()
}
