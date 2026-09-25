//! Authenticated boundary and continuation evidence for native equivalence.

fn accepted_step(
    configuration: &crucible::Configuration,
    decision: crucible::Decision,
) -> crucible::Configuration {
    match crucible::try_step(configuration, decision) {
        Ok(configuration) => configuration,
        Err(error) => panic!("test configuration step should be accepted: {error}"),
    }
}

use std::collections::BTreeMap;

use crucible::model::{
    BindingActionCause, BindingActionKind, EffectKind, EffectLifetime, FaultPhase,
};
use crucible::{
    Configuration, Decision, FingerprintSample, GuestMeasurementEvent, NodeId,
    ObservableEventPayload, QuantumOutcome, QuantumRequest, SchedulerEventLogEntry,
    SchedulerEventLogPayload, SelectionDecision,
};
use crucible_api::ProductionFaultEvidenceSnapshot;
use crucible_campaign::{ChoiceValue, ConfigurationId, IntegerValue, Selection};

use super::*;
use crate::guest_selectable::{resolve_guest_selectable, selected_guest_reply};

#[derive(Debug, PartialEq, Eq)]
pub(super) struct ContinuationEvidence {
    pub(super) reply_events: Vec<SchedulerEventLogEntry>,
    pub(super) outcomes: Vec<QuantumOutcome>,
    pub(super) fingerprints: BTreeMap<NodeId, FingerprintSample>,
    pub(super) fault_evidence: ProductionFaultEvidenceSnapshot,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct BoundaryEvidence {
    pub(super) configuration: Configuration,
    pub(super) pending: QemuNodeSelectablePendingRequest,
    pub(super) fingerprints: BTreeMap<NodeId, FingerprintSample>,
    pub(super) fault_evidence: ProductionFaultEvidenceSnapshot,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct PreparedWorldEvidence {
    scheduler: crucible::SingleSchedulerCheckpoint,
    fault_checkpoint: ContentHash,
    event_log_objects: usize,
    signal_artifact_objects: usize,
    selectable_catalogs: usize,
    node_states: Vec<(NodeId, ProductionVmHotForkNodeServiceState)>,
    io_states: Vec<(
        NodeId,
        ProductionVmHotForkIoNodeKind,
        ProductionVmHotForkNodeServiceState,
    )>,
}

#[derive(Clone, Copy)]
pub(super) enum EquivalenceTopology {
    MultiNode,
    SingleNode,
}

pub(super) fn drive_to_pending_boundary(
    lifecycle: &mut impl QemuFreshAttemptLifecycleOwner,
    source: &crucible::ScenarioDefForm,
    topology: EquivalenceTopology,
) -> BoundaryEvidence {
    drive_configuration_to_pending_boundary(
        lifecycle,
        source,
        Configuration::genesis(source.scenario_def()),
        topology,
    )
}

pub(super) fn drive_configuration_to_pending_boundary(
    lifecycle: &mut impl QemuFreshAttemptLifecycleOwner,
    source: &crucible::ScenarioDefForm,
    mut configuration: Configuration,
    topology: EquivalenceTopology,
) -> BoundaryEvidence {
    let mut observed_http = false;
    let mut observed_block = false;
    let mut observed_ninep = false;
    // A non-genesis start has already authenticated and replayed the prefix
    // containing the scaling workload's measurement-begin marker.
    let mut observed_measurement_begin = !configuration.is_genesis();
    let mut observed_pre_event_queue_and_cache = false;
    let mut pending = None;

    for _ in 0..MAX_SOURCE_QUANTA {
        let outcome = lifecycle
            .drive_quantum(QuantumRequest {
                configuration,
                control: Vec::new(),
            })
            .expect("drive fresh equivalence boundary");
        observed_http |= satisfied(&outcome.event_log_entries, "curl-receives-http-200");
        observed_block |= satisfied(&outcome.event_log_entries, "curl-block-read-complete");
        observed_ninep |= satisfied(&outcome.event_log_entries, "io-probe-complete");
        observed_measurement_begin |= outcome.event_log_entries.iter().any(|entry| {
            matches!(
                entry.payload(),
                SchedulerEventLogPayload::Observable(ObservableEventPayload::GuestMeasurement {
                    event: GuestMeasurementEvent::Begin { measurement, instance },
                    ..
                }) if measurement == "hot-fork-window" && instance == "instance-1"
            )
        });
        configuration = outcome.configuration;
        let requests = lifecycle
            .drain_pending_selectable_requests()
            .expect("inspect pending equivalence choice");
        assert!(requests.len() <= 1, "one guest choice may be pending");
        if let Some(request) = requests.into_iter().next() {
            pending = Some(request);
        }

        let fault_evidence = lifecycle
            .fault_evidence_snapshot()
            .expect("inspect equivalence fault state");
        observed_pre_event_queue_and_cache |= pre_event_queue_and_cache_present(&fault_evidence);
        let topology_ready = match topology {
            EquivalenceTopology::MultiNode => {
                observed_http
                    && observed_block
                    && observed_ninep
                    && observed_pre_event_queue_and_cache
            }
            EquivalenceTopology::SingleNode => true,
        };
        if topology_ready
            && observed_measurement_begin
            && let Some(pending) = pending.take()
        {
            assert!(
                lifecycle
                    .exact_checkpoint_ready()
                    .expect("inspect exact boundary"),
                "pending choice boundary must be checkpoint ready"
            );
            return capture_boundary_evidence(lifecycle, source, configuration, pending, topology);
        }
    }
    panic!("equivalence fixture did not reach the complete pending boundary");
}

pub(super) fn select_pending_configuration(
    lifecycle: &mut impl QemuFreshAttemptLifecycleOwner,
    source: &crucible::ScenarioDefForm,
    parent: Configuration,
    pending: &QemuNodeSelectablePendingRequest,
) -> Configuration {
    let discovery = resolve_guest_selectable(
        crucible_campaign::ScenarioDefId::from_hash(crucible_campaign::CampaignHash::from_bytes(
            source.scenario_def().id().bytes,
        )),
        source,
        pending.node(),
        pending.pending(),
    )
    .expect("resolve pending scaling choice");
    let parent_id = ConfigurationId::from_hash(crucible_campaign::CampaignHash::from_bytes(
        parent.id().bytes,
    ));
    let selection = Selection::new_campaign_branch(
        discovery.opportunity(),
        discovery.domain(),
        ChoiceValue::Integer(IntegerValue::Unsigned(7)),
        discovery.opportunity().branch_point_id(parent_id),
    )
    .expect("select scaling continuation");
    let decision = SelectionDecision::new(&selection);
    let selected = accepted_step(&parent, Decision::Selection(decision.clone()));
    let reply = selected_guest_reply(pending.pending(), &discovery, &selection)
        .expect("build exact scaling reply");
    lifecycle
        .apply_selectable_reply(&parent, decision, &selected, pending, &reply)
        .expect("apply exact scaling reply");
    selected
}

fn pre_event_queue_and_cache_present(evidence: &ProductionFaultEvidenceSnapshot) -> bool {
    if evidence.frontier.ticks >= scenario::PERMANENT_FAILURE_NANOS {
        return false;
    }

    let shared_queue_occupied = evidence.network_queues.iter().any(|queue| {
        matches!(
            &queue.target,
            crucible::model::ResolvedFaultTarget::NetworkQueue { queue, .. }
                if queue.as_str() == "shared-egress"
        ) && queue.reservations > 0
            && queue
                .last_finish_nanos
                .is_some_and(|finish| finish > scenario::PERMANENT_FAILURE_NANOS)
    });
    let volatile_cache_occupied = evidence
        .block_devices
        .iter()
        .any(|device| device.volatile_entries > 0);

    shared_queue_occupied && volatile_cache_occupied
}

pub(super) fn drain_exact_pending(
    lifecycle: &mut impl QemuFreshAttemptLifecycleOwner,
) -> QemuNodeSelectablePendingRequest {
    let requests = lifecycle
        .drain_pending_selectable_requests()
        .expect("inspect restored pending choice");
    let [pending] = requests.as_slice() else {
        panic!("restored boundary must expose exactly one pending choice")
    };
    pending.clone()
}

pub(super) fn capture_boundary_evidence(
    lifecycle: &mut impl QemuFreshAttemptLifecycleOwner,
    source: &crucible::ScenarioDefForm,
    configuration: Configuration,
    pending: QemuNodeSelectablePendingRequest,
    topology: EquivalenceTopology,
) -> BoundaryEvidence {
    assert_eq!(pending.node().name, "curl");
    assert_eq!(
        pending.pending().request().selectable_id(),
        "hot-fork.retry-quanta"
    );
    let sequence = pending.pending().request().sequence();
    let observed_sequence = usize::try_from(sequence).expect("selectable sequence fits usize");
    assert_eq!(observed_sequence, configuration.schedule.len() + 1);
    let instance_key = pending.pending().request().instance_key();
    let scaling_instance_key = format!("scaling/{sequence}");
    assert!(
        instance_key == "continuation/one" || instance_key == scaling_instance_key.as_str(),
        "unexpected selectable instance key {instance_key}"
    );
    assert!(pending.pending().request().narrowed_domain().is_some());
    assert!(pending.pending().request().reply_capacity() > 0);
    assert!(pending.pending().icount() > 0);
    assert_eq!(pending.pending().vcpu_index(), 0);
    assert!(pending.pending().guest_virtual_address() > 0);
    let fingerprints: BTreeMap<NodeId, FingerprintSample> = source
        .world()
        .vm_nodes()
        .iter()
        .map(|node| {
            let sample = lifecycle
                .sample_fingerprint(node.id.clone())
                .expect("sample pending-boundary fingerprint");
            (node.id.clone(), sample)
        })
        .collect();
    let fault_evidence = normalized_fault_evidence(lifecycle);
    match topology {
        EquivalenceTopology::MultiNode => {
            assert!(
                fault_evidence.frontier.ticks < scenario::PERMANENT_FAILURE_NANOS,
                "exact source boundary must precede the shared fault"
            );
            assert!(pre_event_queue_and_cache_present(&fault_evidence));
            assert!(
                fault_evidence
                    .nodes
                    .iter()
                    .all(|node| node.service_state == "running" && node.backend_owned)
            );
        }
        EquivalenceTopology::SingleNode => {
            assert_eq!(fingerprints.len(), 1);
            assert_eq!(fault_evidence.nodes.len(), 1);
            assert_eq!(fault_evidence.nodes[0].node.name, "curl");
            assert_eq!(fault_evidence.nodes[0].service_state, "running");
            assert!(fault_evidence.nodes[0].backend_owned);
            assert_eq!(fault_evidence.block_devices.len(), 1);
        }
    }

    BoundaryEvidence {
        configuration,
        pending,
        fingerprints,
        fault_evidence,
    }
}

pub(super) fn prepared_world_evidence(
    world: &ProductionVmHotForkSourceWorld,
    topology: EquivalenceTopology,
) -> PreparedWorldEvidence {
    let continuation = world.continuation();
    assert_eq!(continuation.selectable_catalog_count(), 1);
    assert!(continuation.event_log_object_count() > 0);
    match topology {
        EquivalenceTopology::MultiNode => {
            assert!(continuation.signal_artifact_object_count() > 0);
            assert!(continuation.io_nodes().iter().any(|node| {
                node.kind() == ProductionVmHotForkIoNodeKind::Block
                    && node.owner_service_state() == ProductionVmHotForkNodeServiceState::Running
            }));
            assert!(continuation.io_nodes().iter().any(|node| {
                node.kind() == ProductionVmHotForkIoNodeKind::NineP
                    && node.owner_service_state() == ProductionVmHotForkNodeServiceState::Running
            }));
        }
        EquivalenceTopology::SingleNode => {
            assert_eq!(continuation.nodes().len(), 1);
            assert_eq!(continuation.nodes()[0].node().name, "curl");
            assert_eq!(
                continuation.nodes()[0].service_state(),
                ProductionVmHotForkNodeServiceState::Running
            );
            assert_eq!(continuation.io_nodes().len(), 2);
            for kind in [
                ProductionVmHotForkIoNodeKind::Block,
                ProductionVmHotForkIoNodeKind::NineP,
            ] {
                assert!(continuation.io_nodes().iter().any(|node| {
                    node.kind() == kind
                        && node.owner_service_state()
                            == ProductionVmHotForkNodeServiceState::Running
                }));
            }
        }
    }

    // Process generations identify operational incarnations. They intentionally
    // differ after restore and fork and are excluded from semantic comparison.
    PreparedWorldEvidence {
        scheduler: continuation.scheduler().clone(),
        fault_checkpoint: continuation.fault_checkpoint_identity(),
        event_log_objects: continuation.event_log_object_count(),
        signal_artifact_objects: continuation.signal_artifact_object_count(),
        selectable_catalogs: continuation.selectable_catalog_count(),
        node_states: continuation
            .nodes()
            .iter()
            .map(|node| (node.node().clone(), node.service_state()))
            .collect(),
        io_states: continuation
            .io_nodes()
            .iter()
            .map(|node| (node.node().clone(), node.kind(), node.owner_service_state()))
            .collect(),
    }
}

pub(super) fn normalized_fault_evidence(
    lifecycle: &impl QemuFreshAttemptLifecycleOwner,
) -> ProductionFaultEvidenceSnapshot {
    let mut evidence = lifecycle
        .fault_evidence_snapshot()
        .expect("capture semantic fault evidence");
    for node in &mut evidence.nodes {
        // A restore or fork creates a new process generation. The remaining
        // fields retain scheduler activity, service state, ownership, queues,
        // device state, and complete signal/effect evidence.
        node.generation = 0;
    }
    evidence
}

fn assert_shared_fault_evidence(evidence: &ProductionFaultEvidenceSnapshot) {
    const EVENT_NANOS: u64 = 30_000_000_000;
    const SHARED: [(&str, EffectKind); 3] = [
        (
            "shared-power-network",
            EffectKind::NetworkForwarderLifecycle,
        ),
        ("shared-power-block", EffectKind::StorageVolatileCacheLoss),
        ("shared-power-node", EffectKind::NodeLifecycle),
    ];
    let trace = evidence
        .resolved_effect_trace
        .as_ref()
        .expect("shared fault trace must be present");
    let work_item = trace
        .work_items
        .iter()
        .find(|item| {
            item.records.iter().any(|record| {
                SHARED
                    .iter()
                    .any(|(binding, _)| record.binding.as_str() == *binding)
            })
        })
        .expect("shared fault event must be recorded");
    assert_eq!(
        work_item.coordinate.virtual_ticks,
        EVENT_NANOS * crucible::SIM_TICKS_PER_NS
    );
    assert_eq!(work_item.records.len(), SHARED.len());
    for (binding, effect) in SHARED {
        assert!(work_item.records.iter().any(|record| {
            record.binding.as_str() == binding
                && record.effect == effect
                && record.action_kind == BindingActionKind::Apply
                && record.phase == FaultPhase::Boundary
                && record.lifetime == EffectLifetime::Impulse
                && record.coordinate.virtual_ticks == EVENT_NANOS * crucible::SIM_TICKS_PER_NS
                && record.same_coordinate_sequence == work_item.same_coordinate_sequence
                && record.derivation_fingerprint == work_item.derivation_fingerprint
                && record.cause == BindingActionCause::Signal
        }));
    }
    assert!(
        trace
            .work_items
            .iter()
            .flat_map(|item| &item.records)
            .any(|record| {
                record.binding.as_str() == "ninep-read-errno"
                    && record.effect == EffectKind::NinePResult
                    && record.action_kind == BindingActionKind::Apply
                    && record.phase == FaultPhase::Resolve
                    && record.lifetime == EffectLifetime::Opportunity
                    && record.coordinate.virtual_ticks >= EVENT_NANOS * crucible::SIM_TICKS_PER_NS
                    && record.cause == BindingActionCause::Signal
            })
    );
}

fn assert_reactivation_evidence(evidence: &ProductionFaultEvidenceSnapshot) {
    let trace = evidence
        .resolved_effect_trace
        .as_ref()
        .expect("reactivation trace must be present");
    for (binding, nanos) in [
        ("inactive-power-off-curl", scenario::INACTIVE_WORLD_NANOS),
        (
            "inactive-power-off-io-probe",
            scenario::INACTIVE_WORLD_NANOS,
        ),
        ("reactivate-curl", scenario::REACTIVATION_NANOS),
    ] {
        assert!(
            trace
                .work_items
                .iter()
                .flat_map(|item| &item.records)
                .any(|record| {
                    record.binding.as_str() == binding
                        && record.effect == EffectKind::NodeLifecycle
                        && record.action_kind == BindingActionKind::Apply
                        && record.phase == FaultPhase::Boundary
                        && record.lifetime == EffectLifetime::Impulse
                        && record.coordinate.virtual_ticks == nanos * crucible::SIM_TICKS_PER_NS
                        && record.cause == BindingActionCause::Signal
                })
        );
    }
}

pub(super) fn assert_continuation_equivalent(
    label: &str,
    actual: &ContinuationEvidence,
    reference: &ContinuationEvidence,
) {
    assert_eq!(
        actual.reply_events, reference.reply_events,
        "{label} changed the selected reply boundary"
    );
    assert_eq!(
        actual.outcomes.first(),
        reference.outcomes.first(),
        "{label} changed the first completed quantum"
    );
    assert_eq!(
        actual.outcomes, reference.outcomes,
        "{label} changed the bounded continuation"
    );
    assert_eq!(
        actual.outcomes.last(),
        reference.outcomes.last(),
        "{label} changed the bounded final state"
    );
    assert_eq!(actual.fingerprints, reference.fingerprints);
    assert_eq!(actual.fault_evidence, reference.fault_evidence);
}

pub(super) fn continue_from_pending(
    lifecycle: &mut impl QemuFreshAttemptLifecycleOwner,
    source: &crucible::ScenarioDefForm,
    mut configuration: Configuration,
    pending: QemuNodeSelectablePendingRequest,
) -> ContinuationEvidence {
    let discovery = resolve_guest_selectable(
        crucible_campaign::ScenarioDefId::from_hash(crucible_campaign::CampaignHash::from_bytes(
            source.scenario_def().id().bytes,
        )),
        source,
        pending.node(),
        pending.pending(),
    )
    .expect("resolve pending equivalence choice");
    let parent = configuration.clone();
    let parent_id = ConfigurationId::from_hash(crucible_campaign::CampaignHash::from_bytes(
        parent.id().bytes,
    ));
    let selection = Selection::new_campaign_branch(
        discovery.opportunity(),
        discovery.domain(),
        ChoiceValue::Integer(IntegerValue::Unsigned(7)),
        discovery.opportunity().branch_point_id(parent_id),
    )
    .expect("select equivalence continuation");
    let decision = SelectionDecision::new(&selection);
    let selected = accepted_step(&parent, Decision::Selection(decision.clone()));
    let reply = selected_guest_reply(pending.pending(), &discovery, &selection)
        .expect("build exact equivalence reply");
    let reply_events = lifecycle
        .apply_selectable_reply(&parent, decision, &selected, &pending, &reply)
        .expect("apply exact equivalence reply");
    configuration = selected;

    let mut outcomes = Vec::new();
    let mut completed = false;
    let mut measurement_sample = false;
    let mut measurement_end = false;
    let mut observed_ninep_fault = false;
    let mut observed_permanent_failure = false;
    let mut observed_network_outage = false;
    let mut observed_volatile_cache_loss = false;
    let mut observed_inactive_world = false;
    let mut observed_reactivation = false;
    let mut observed_reactivated_progress = false;
    let requires_reactivation = source.world().vm_nodes().len() > 1;
    for _ in 0..POST_CHOICE_QUANTA {
        let outcome = lifecycle
            .drive_quantum(QuantumRequest {
                configuration,
                control: Vec::new(),
            })
            .expect("drive selected continuation");
        completed |= satisfied(&outcome.event_log_entries, "hot-fork-continuation-complete");
        observed_ninep_fault |= satisfied(&outcome.event_log_entries, "io-probe-fault-observed");
        for entry in &outcome.event_log_entries {
            if let SchedulerEventLogPayload::Observable(
                ObservableEventPayload::GuestMeasurement { event, .. },
            ) = entry.payload()
            {
                measurement_sample |= matches!(
                    event,
                    GuestMeasurementEvent::Sample { measurement, metric, .. }
                        if measurement == "hot-fork-window" && metric == "selected-retry"
                );
                measurement_end |= matches!(
                    event,
                    GuestMeasurementEvent::End { measurement, instance }
                        if measurement == "hot-fork-window" && instance == "instance-1"
                );
            }
        }
        if requires_reactivation {
            let fault_evidence = lifecycle
                .fault_evidence_snapshot()
                .expect("inspect inactive-world reactivation");
            let running = fault_evidence
                .nodes
                .iter()
                .filter(|node| node.service_state == "running")
                .count();
            observed_permanent_failure |= fault_evidence.nodes.iter().any(|node| {
                node.node.name == "nginx" && node.service_state == "permanently_failed"
            });
            if (scenario::PERMANENT_FAILURE_NANOS * crucible::SIM_TICKS_PER_NS
                ..(scenario::PERMANENT_FAILURE_NANOS + scenario::NINEP_FAULT_WINDOW_NANOS)
                    * crucible::SIM_TICKS_PER_NS)
                .contains(&fault_evidence.frontier.ticks)
            {
                observed_network_outage |= fault_evidence.network_outages.iter().any(|outage| {
                    matches!(
                        &outage.target,
                        crucible::model::ResolvedFaultTarget::NetworkForwarder { forwarder }
                            if forwarder.as_str() == "shared-forwarder"
                    ) && outage.unavailable_until_nanos
                        == scenario::PERMANENT_FAILURE_NANOS + scenario::NINEP_FAULT_WINDOW_NANOS
                });
                observed_volatile_cache_loss |= fault_evidence
                    .block_devices
                    .iter()
                    .any(|device| device.volatile_entries == 0);
            }
            if outcome.frontier.ticks >= scenario::INACTIVE_WORLD_NANOS && running == 0 {
                observed_inactive_world = true;
                assert!(
                    outcome.advanced_node.is_none(),
                    "inactive world advanced a backend node"
                );
            }
            let curl_running = fault_evidence
                .nodes
                .iter()
                .any(|node| node.node.name == "curl" && node.service_state == "running");
            if outcome.frontier.ticks >= scenario::REACTIVATION_NANOS && curl_running {
                observed_reactivation = true;
                observed_reactivated_progress |= outcome
                    .advanced_node
                    .as_ref()
                    .is_some_and(|node| node.node.name == "curl");
            }
        }
        configuration = outcome.configuration.clone();
        outcomes.push(outcome);
        if completed
            && measurement_sample
            && measurement_end
            && (!requires_reactivation
                || (observed_ninep_fault
                    && observed_permanent_failure
                    && observed_network_outage
                    && observed_volatile_cache_loss
                    && observed_inactive_world
                    && observed_reactivation
                    && observed_reactivated_progress))
        {
            break;
        }
    }
    assert!(completed, "selected guest continuation completed");
    assert!(
        measurement_sample,
        "selected measurement sample was retained"
    );
    assert!(measurement_end, "open measurement window closed");
    if requires_reactivation {
        assert!(
            observed_ninep_fault,
            "the guest observed the injected 9p result"
        );
        assert!(
            observed_permanent_failure,
            "the shared event permanently failed Nginx"
        );
        assert!(
            observed_network_outage,
            "the shared event interrupted the routed forwarder"
        );
        assert!(
            observed_volatile_cache_loss,
            "the shared event cleared the occupied volatile block cache"
        );
        assert!(
            observed_inactive_world,
            "all production QEMU nodes became inactive"
        );
        assert!(observed_reactivation, "the Boot event reactivated Curl");
        assert!(
            observed_reactivated_progress,
            "Curl resumed real guest execution after Boot"
        );
    }

    let fingerprints = source
        .world()
        .vm_nodes()
        .iter()
        .map(|node| {
            let sample = lifecycle
                .sample_fingerprint(node.id.clone())
                .expect("sample continuation fingerprint");
            (node.id.clone(), sample)
        })
        .collect();
    let fault_evidence = normalized_fault_evidence(lifecycle);
    if fault_evidence.nodes.len() > 1 {
        assert_shared_fault_evidence(&fault_evidence);
        assert_reactivation_evidence(&fault_evidence);
    }

    ContinuationEvidence {
        reply_events,
        outcomes,
        fingerprints,
        fault_evidence,
    }
}
