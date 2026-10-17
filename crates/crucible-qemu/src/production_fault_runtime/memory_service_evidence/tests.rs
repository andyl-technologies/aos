//! Native service payload validation and diagnostic publication regressions.

// crucible-lint: allow panic-shortcut -- codec and publication fixtures panic to localize invalid test setup.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::production_fault_runtime::test_support::test_host_manifests;
use crucible_shmem::{FaultCommandKind, FaultEventHeaderV1};

fn native_event() -> DequeuedFaultEvent {
    let mut payload = vec![0; 576];
    payload[..8].copy_from_slice(b"CRUCMEM2");
    payload[304..336].fill(5);
    payload[336..368].fill(6);
    payload[368..376].copy_from_slice(b"CRUCSVC3");
    payload[376..380].copy_from_slice(&3_u32.to_le_bytes());
    for (offset, value) in [
        (392, 10_u64),
        (400, 15),
        (408, 20),
        (416, 5),
        (424, 8),
        (432, 28),
        (440, 20),
        (448, 100),
        (456, 200),
    ] {
        payload[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    payload[464..468].copy_from_slice(&3_u32.to_le_bytes());
    payload[468..472].copy_from_slice(&(FaultEventOutcomeV1::Applied as u32).to_le_bytes());
    DequeuedFaultEvent {
        header: FaultEventHeaderV1 {
            command_kind: FaultCommandKind::MemoryService,
            outcome: FaultEventOutcomeV1::Applied,
            event_sequence: 1,
            rule_command_sequence: 2,
            observed_icount: 7,
            model_phase: 18,
            target_kind: 4,
            generation: 1,
            binding_hash: [1; 32],
            opportunity_hash: [2; 32],
            action_hash: [3; 32],
            target_hash: [4; 32],
            before_hash: [5; 32],
            after_hash: [6; 32],
            evidence_hash: [7; 32],
            payload_hash: [8; 32],
            payload_offset: 0,
            payload_length: 576,
        },
        payload,
    }
}

fn boundary() -> FaultCoordinate {
    FaultCoordinate {
        virtual_ticks: 30,
        retired_instructions: None,
    }
}

fn occurrence() -> QemuMemoryServiceOccurrence {
    parse_occurrence(&native_event(), boundary())
        .unwrap()
        .unwrap()
}

#[test]
fn diagnostic_preserves_native_ledger_coordinates_and_identity() {
    let record = occurrence();

    assert_eq!(record.boundary_ticks, 30);
    assert_eq!(record.observed_absolute_icount, 7);
    assert_eq!(
        (record.ready_before_ticks, record.ready_after_ticks),
        (10, 15)
    );
    assert_eq!(
        (
            record.fixed_latency_ticks,
            record.queue_delay_ticks,
            record.completion_delay_ticks
        ),
        (20, 8, 28)
    );
    assert_eq!(record.configured_latency_ticks, 20);
    assert_eq!(record.demand_ticks, 5);
    assert_eq!(
        (
            record.bytes_per_second,
            record.operations_per_second,
            record.rate_flags
        ),
        (100, 200, 3)
    );
    assert_eq!(record.action_hash, [3; 32]);
    assert_eq!(record.target_hash, [4; 32]);
    assert_eq!(record.evidence_hash, [7; 32]);
}

#[test]
fn malformed_payload_versions_flags_and_signed_clocks_are_rejected() {
    for (offset, bytes) in [
        (376, 2_u32.to_le_bytes().to_vec()),
        (464, 4_u32.to_le_bytes().to_vec()),
        (400, 9_u64.to_le_bytes().to_vec()),
        (432, 27_u64.to_le_bytes().to_vec()),
        (408, u64::MAX.to_le_bytes().to_vec()),
        (392, u64::MAX.to_le_bytes().to_vec()),
        (304, vec![0; 32]),
    ] {
        let mut event = native_event();
        event.payload[offset..offset + bytes.len()].copy_from_slice(&bytes);
        assert!(
            parse_occurrence(&event, boundary()).is_err(),
            "offset {offset}"
        );
    }
    let mut event = native_event();
    event.payload.pop();
    assert!(parse_occurrence(&event, boundary()).is_err());

    let mut event = native_event();
    event.header.outcome = FaultEventOutcomeV1::Passed;
    assert_eq!(parse_occurrence(&event, boundary()).unwrap(), None);
}

#[test]
fn failed_boundary_never_publishes_staged_occurrence_and_empty_boundary_clears() {
    let mut nodes = QemuNodeSet::new();
    let plan =
        FaultSignalPlan::new(Vec::new(), Vec::new(), FaultResourceLimits::default()).unwrap();
    let mut runtime = ProductionFaultRuntime::new(
        plan.clone(),
        None,
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"service-diagnostic"),
        test_host_manifests(),
        &nodes,
    )
    .unwrap();
    runtime.memory_service_evidence.stage(Some(occurrence()));
    runtime.memory_service_evidence.commit_boundary();
    assert!(runtime.memory_service_occurrence().unwrap().is_some());

    assert!(
        runtime
            .evaluate_boundary_with_event_reservation(boundary(), 0, &mut nodes, u64::MAX, 0)
            .is_err()
    );
    assert_eq!(runtime.memory_service_occurrence().unwrap(), None);
    runtime.memory_service_evidence.stage(Some(occurrence()));
    runtime.memory_service_evidence.commit_boundary();

    // An inert plan rejects unexpected pending effects before publication.
    runtime.pending_qemu_observations.push(FaultObservation {
        semantic_version: crucible::model::FAULT_RUNTIME_STATE_VERSION,
        kind: FaultObservationKind::EffectApplied,
        coordinate: boundary(),
        binding: None,
        target: None,
        opportunity: None,
        evidence: ContentHash::from_bytes(b"unexpected-effect"),
    });
    assert!(
        runtime
            .evaluate_boundary_with_effective_limits(boundary(), 0, &mut nodes)
            .is_err()
    );
    assert_eq!(runtime.memory_service_occurrence().unwrap(), None);
    runtime.pending_qemu_observations.clear();
    runtime.memory_service_evidence.stage(Some(occurrence()));
    runtime.memory_service_evidence.commit_boundary();
    runtime
        .evaluate_boundary_with_effective_limits(boundary(), 0, &mut nodes)
        .unwrap();
    assert_eq!(runtime.memory_service_occurrence().unwrap(), None);

    runtime.memory_service_evidence.stage(Some(occurrence()));
    runtime.memory_service_evidence.commit_boundary();
    let checkpoint = runtime.checkpoint(&mut nodes).unwrap();
    let restored = ProductionFaultRuntime::restore(
        plan,
        None,
        ContentHash::from_bytes(b"service-diagnostic"),
        checkpoint,
        test_host_manifests(),
        &mut nodes,
    )
    .unwrap();
    assert_eq!(restored.memory_service_occurrence().unwrap(), None);
    runtime.poison();
    assert!(runtime.memory_service_occurrence().is_err());
}
