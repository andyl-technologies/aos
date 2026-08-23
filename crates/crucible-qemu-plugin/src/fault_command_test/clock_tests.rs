//! Typed clock-command evidence tests.

use super::*;

#[test]
fn clock_timer_evidence_is_manifest_bound_and_typed() {
    let row = FaultClockCapabilityRowV1 {
        id: "arm-generic-counter-vcpu-0".to_owned(),
        implementation: "target/arm/generic-timer".to_owned(),
        source_kind: 7,
        base_domain: 1,
        timer_relationship: 1,
        width_bits: 64,
        flags: 0,
        frequency_numerator: 62_500_000,
        frequency_denominator: 1,
        model_phase_mask: (1_u64 << 27) | (1_u64 << 28) | (1_u64 << 29),
        vmstate: true,
        monotonicity: 2,
    };
    let manifest = FaultClockCapabilityManifestV1 {
        architecture: FaultCapabilityScope::Aarch64,
        rows: vec![row.clone()],
    }
    .encode()
    .unwrap_or_else(|error| panic!("clock manifest should encode: {error}"));
    let mut raw = vec![0_u8; 384];
    raw[..8].copy_from_slice(b"CRUCCTE1");
    raw[8..10].copy_from_slice(&1_u16.to_le_bytes());
    raw[10..12].copy_from_slice(&7_u16.to_le_bytes());
    raw[12..14].copy_from_slice(&1_u16.to_le_bytes());
    raw[16..20].copy_from_slice(&3_u32.to_le_bytes());
    raw[20..24].copy_from_slice(&1_u32.to_le_bytes());
    raw[24..32].copy_from_slice(&8_u64.to_le_bytes());
    raw[32..40].copy_from_slice(&100_u64.to_le_bytes());
    raw[40..48].copy_from_slice(&200_u64.to_le_bytes());
    raw[48..56].copy_from_slice(&4_u64.to_le_bytes());
    raw[56..64].copy_from_slice(&110_u64.to_le_bytes());
    raw[64..72].copy_from_slice(&210_u64.to_le_bytes());
    raw[72..80].copy_from_slice(&5_u64.to_le_bytes());
    raw[80..88].copy_from_slice(&5_u64.to_le_bytes());
    let source_id = crucible_shmem::fault_object_id_hash_v1(&row.id);
    raw[88..120].copy_from_slice(&source_id);
    raw[120..152].copy_from_slice(&[6; 32]);
    raw[152..184].copy_from_slice(&[7; 32]);
    raw[184..216].copy_from_slice(&[8; 32]);
    raw[216..224].copy_from_slice(&9_u64.to_le_bytes());
    raw[224..226].copy_from_slice(&30_u16.to_le_bytes());
    let arm_sequence = 2_u64;
    raw[240..248].copy_from_slice(
        &clock_timer_opportunity(source_id, arm_sequence, 30, 1, 3, 5).to_le_bytes(),
    );
    raw[248..256].copy_from_slice(&arm_sequence.to_le_bytes());
    let event = QemuFaultEvent {
        command_kind: FaultCommandKind::ClockTransform as u16,
        outcome: FaultEventOutcomeV1::Applied as u16,
        model_phase: 30,
        target_kind: NodeFaultTargetKindV1::Clock as u16,
        event_sequence: 1,
        rule_command_sequence: 2,
        observed_icount: 17,
        generation: 4,
        binding_hash: [6; 32],
        before_hash: [7; 32],
        after_hash: [8; 32],
        ..QemuFaultEvent::default()
    };
    let expectation = ClockCommandExpectation {
        operation: NodeFaultOperationV1::Upsert,
        command_kind: FaultCommandKind::ClockTransform as u16,
        binding_hash: [6; 32],
        model_phase: 30,
        source_ids: vec![source_id],
        parameters: ClockCommandParameters::Transform {
            kind: 1,
            signed_value: 1,
            ratio: [1, 1],
            unsigned_value: 0,
            process: None,
            monotonicity: 2,
            overdue_policy: 1,
        },
    };
    let encoded = translate_clock_evidence(&raw, &manifest, &event, 22, &expectation)
        .unwrap_or_else(|error| panic!("clock evidence should translate: {error}"));
    let decoded = FaultClockEvidenceV1::decode(&encoded)
        .unwrap_or_else(|error| panic!("clock evidence should decode: {error}"));
    assert_eq!(decoded.observed_icount, 22);
    assert!(matches!(
        decoded.observation,
        FaultClockObservationV1::TimerTransition { sequence: 8, .. }
    ));
    for offset in [224, 232, 240, 248] {
        let mut corrupt = raw.clone();
        corrupt[offset] ^= 1;
        assert!(matches!(
            translate_clock_evidence(&corrupt, &manifest, &event, 22, &expectation),
            Err(FaultCommandBridgeError::ClockEvidence)
        ));
    }
}

#[test]
fn clock_impulse_result_and_event_use_the_same_typed_evidence() {
    let row = FaultClockCapabilityRowV1 {
        id: "x86-tsc-vcpu-0".to_owned(),
        implementation: "target/i386/tcg".to_owned(),
        source_kind: 1,
        base_domain: 1,
        timer_relationship: 0,
        width_bits: 64,
        flags: 1,
        frequency_numerator: 1_000_000_000,
        frequency_denominator: 1,
        model_phase_mask: (1_u64 << 27) | (1_u64 << 30) | (1_u64 << 31),
        vmstate: true,
        monotonicity: 2,
    };
    let manifest = FaultClockCapabilityManifestV1 {
        architecture: FaultCapabilityScope::X86_64,
        rows: vec![row.clone()],
    }
    .encode()
    .unwrap_or_else(|error| panic!("clock manifest should encode: {error}"));
    let source_id = crucible_shmem::fault_object_id_hash_v1(&row.id);
    let mut raw = vec![0_u8; 384];
    raw[..8].copy_from_slice(b"CRUCCIM1");
    raw[8..10].copy_from_slice(&1_u16.to_le_bytes());
    raw[10..12].copy_from_slice(&1_u16.to_le_bytes());
    raw[16..24].copy_from_slice(&17_u64.to_le_bytes());
    raw[24..32].copy_from_slice(&100_u64.to_le_bytes());
    raw[32..40].copy_from_slice(&101_u64.to_le_bytes());
    raw[40..48].copy_from_slice(&5_u64.to_le_bytes());
    raw[48..56].copy_from_slice(&1_u64.to_le_bytes());
    raw[56..64].copy_from_slice(&1_u64.to_le_bytes());
    raw[72..80].copy_from_slice(&5_u64.to_le_bytes());
    raw[80..112].copy_from_slice(&source_id);
    raw[112..144].copy_from_slice(&[6; 32]);
    raw[144..176].copy_from_slice(&[7; 32]);
    raw[176..208].copy_from_slice(&[8; 32]);
    raw[208..210].copy_from_slice(&29_u16.to_le_bytes());
    raw[210..212].copy_from_slice(&1_u16.to_le_bytes());
    raw[212..220].copy_from_slice(&100_u64.to_le_bytes());
    raw[220..228].copy_from_slice(&101_u64.to_le_bytes());
    raw[228..236].copy_from_slice(&1_u64.to_le_bytes());
    raw[236..244].copy_from_slice(&1_u64.to_le_bytes());
    raw[244..252].copy_from_slice(&5_u64.to_le_bytes());
    raw[264..268].copy_from_slice(&2_u32.to_le_bytes());
    raw[268..272].copy_from_slice(&1_u32.to_le_bytes());
    raw[272..276].copy_from_slice(&1_u32.to_le_bytes());
    let event = QemuFaultEvent {
        command_kind: FaultCommandKind::ClockTransform as u16,
        outcome: FaultEventOutcomeV1::Applied as u16,
        model_phase: 29,
        target_kind: NodeFaultTargetKindV1::Clock as u16,
        event_sequence: 1,
        rule_command_sequence: 2,
        observed_icount: 17,
        generation: 4,
        binding_hash: [6; 32],
        before_hash: [7; 32],
        after_hash: [8; 32],
        ..QemuFaultEvent::default()
    };
    let result = QemuFaultResult {
        command_kind: FaultCommandKind::ClockTransform as u16,
        status: FaultResultStatus::Applied as u16,
        phase: FaultBoundaryPhase::NodeBoundary as u16,
        command_sequence: 2,
        observed_icount: 17,
        applied_icount: 17,
        before_hash: [7; 32],
        after_hash: [8; 32],
        ..QemuFaultResult::default()
    };
    let expectation = ClockCommandExpectation {
        operation: NodeFaultOperationV1::Apply,
        command_kind: FaultCommandKind::ClockTransform as u16,
        binding_hash: [6; 32],
        model_phase: 29,
        source_ids: vec![source_id],
        parameters: ClockCommandParameters::Transform {
            kind: 1,
            signed_value: 5,
            ratio: [1, 1],
            unsigned_value: 0,
            process: None,
            monotonicity: 2,
            overdue_policy: 1,
        },
    };
    let from_event = translate_clock_evidence(&raw, &manifest, &event, 22, &expectation)
        .unwrap_or_else(|error| panic!("clock impulse event should translate: {error}"));
    let from_result = translate_clock_impulse_evidence(&raw, &manifest, &result, 5, &expectation)
        .unwrap_or_else(|error| panic!("clock impulse result should translate: {error}"));
    assert_eq!(from_event, from_result);
    let decoded = FaultClockEvidenceV1::decode(&from_event)
        .unwrap_or_else(|error| panic!("clock impulse should decode: {error}"));
    assert!(matches!(
        decoded.observation,
        FaultClockObservationV1::Impulse {
            transform_kind: 1,
            new_additive_nanos: 5,
            ..
        }
    ));
    let mut mismatched = expectation.clone();
    mismatched.parameters = ClockCommandParameters::Transform {
        kind: 1,
        signed_value: 6,
        ratio: [1, 1],
        unsigned_value: 0,
        process: None,
        monotonicity: 2,
        overdue_policy: 1,
    };
    assert!(matches!(
        translate_clock_evidence(&raw, &manifest, &event, 22, &mismatched),
        Err(FaultCommandBridgeError::ClockEvidence)
    ));
}
