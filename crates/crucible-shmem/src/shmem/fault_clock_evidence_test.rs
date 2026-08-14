//! Clock-fault evidence codec tests.

use super::*;

fn evidence(observation: FaultClockObservationV1) -> FaultClockEvidenceV1 {
    FaultClockEvidenceV1 {
        source_kind: 7,
        model_phase: 30,
        observed_icount: 42,
        source_id: [1; 32],
        binding_hash: [2; 32],
        before_hash: [3; 32],
        after_hash: [4; 32],
        manifest_sha256: [5; 32],
        transform_generation: 9,
        opportunity: 10,
        observation,
    }
}

#[test]
fn every_clock_evidence_kind_round_trips_canonically() {
    let observations = [
        FaultClockObservationV1::Read {
            raw_value: 11,
            transformed_value: 12,
            raw_architectural_value: 21,
            transformed_architectural_value: 22,
            source_width_bits: 32,
            wrap_action: 0,
            anchor_raw: 9,
            anchor_value: 10,
            drift_ratio: [1001, 1000],
            additive_nanos: -2,
            frozen_value: 0,
            read_error: false,
            read_opportunity: 13,
            transform_kind: 5,
            contribution: -7,
            monotonicity: 2,
            overdue_policy: 1,
            source_state: 1,
            freeze_release: 0,
            synchronization_remaining_nanos: -3,
        },
        FaultClockObservationV1::Wander {
            scheduler_nanos: 20,
            raw_nanos: 21,
            offsets: [-2, 3],
            rates_ppb: [-4, 5],
            next_nanos: [22, 23],
            sequences: [6, 7],
        },
        FaultClockObservationV1::SourceTransition {
            scheduler_nanos: 30,
            raw_nanos: 31,
            states: [1, 5],
            old_value: 32,
            new_anchor_value: 33,
            transition_generation: 2,
            old_fallback: [0; 32],
            new_fallback: [6; 32],
            synchronization_remaining_nanos: [0, -4],
            synchronization_ratio: [1001, 1000],
            synchronization_threshold_nanos: 1,
        },
        FaultClockObservationV1::TimerTransition {
            role: 1,
            index: 3,
            action: 1,
            sequence: 7,
            old_deadlines: [11, 12],
            new_deadlines: [13, 14],
            generations: [8, 9],
            opportunity_phase: 30,
            jitter_contribution: -2,
            timer_opportunity: 15,
            arm_sequence: 14,
        },
        FaultClockObservationV1::Impulse {
            transform_kind: 2,
            raw_nanos: 40,
            old_value: 41,
            signed_value: 0,
            ratio: [1001, 1000],
            unsigned_value: 0,
            new_anchor: [43, 44],
            new_drift_ratio: [1001, 1000],
            new_additive_nanos: -9,
            new_frozen_value: 0,
            new_freeze_release: 0,
            new_monotonicity: 2,
            new_overdue_policy: 1,
            new_source_state: 1,
        },
    ];
    for observation in observations {
        let mut value = evidence(observation);
        if matches!(&value.observation, FaultClockObservationV1::Impulse { .. }) {
            value.opportunity = 0;
        }
        let encoded = value
            .encode()
            .unwrap_or_else(|error| panic!("clock evidence should encode: {error}"));
        assert_eq!(
            FaultClockEvidenceV1::decode(&encoded)
                .unwrap_or_else(|error| panic!("clock evidence should decode: {error}")),
            value
        );
    }
}

#[test]
fn clock_evidence_rejects_noncanonical_and_unbound_records() {
    let value = evidence(FaultClockObservationV1::TimerTransition {
        role: 1,
        index: 3,
        action: 1,
        sequence: 7,
        old_deadlines: [11, 12],
        new_deadlines: [13, 14],
        generations: [8, 9],
        opportunity_phase: 30,
        jitter_contribution: -2,
        timer_opportunity: 15,
        arm_sequence: 14,
    });
    let mut encoded = value
        .encode()
        .unwrap_or_else(|error| panic!("clock evidence should encode: {error}"));
    encoded[223] = 1;
    assert!(FaultClockEvidenceV1::decode(&encoded).is_err());

    let mut missing_identity = value;
    missing_identity.source_id = [0; 32];
    assert!(missing_identity.encode().is_err());
}
