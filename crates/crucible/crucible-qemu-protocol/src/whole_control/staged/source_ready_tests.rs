//! Malformed and cross-implementation controls for correlation-only Ready bytes.

// crucible-lint: allow panic-shortcut -- Conformance controls panic on failed invariants.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::whole_control::staged::{self, StagedFrameKind};

fn modeled_receipt() -> SourceReadyReceipt {
    SourceReadyReceipt {
        binding: SourceReadyBinding {
            scope: [1; 32],
            native_epoch: 2,
            process_generation: 3,
            barrier_generation: 4,
            setup_digest: [6; 32],
            profile_digest: [7; 32],
            launch_digest: [8; 32],
            queue_plan_digest: [9; 32],
            backend: SourceBackend::Qemu,
            closure_codec_version: 1,
        },
        source_cut: 5,
        clock: SourceClockObservation {
            raw: 11,
            semantic_ps: 550,
            sim_bias_ps: 12,
            anchor_raw: 9,
            anchor_ps: 450,
            park_ps: 500,
            bias_high: -1,
            bias_low: 13,
            logical_offset_ps: 14,
            mode: SourceClockMode::ParkedAffine,
            instruction_ps: 50,
            time_shift: 0,
            ns_divisor: 1000,
        },
        closure_digest: [10; 32],
        closure_object_count: 15,
        closure_edge_count: 16,
    }
}

#[test]
fn fixed_receipt_matches_independent_big_endian_vector_and_domain_digest() {
    let receipt = modeled_receipt();
    let encoded = receipt.encode().unwrap();
    let independent = include_bytes!("../../../testdata/source-ready-modeled-v1.bin");

    assert_eq!(&encoded, independent);
    assert_eq!(SourceReadyReceipt::decode(independent).unwrap(), receipt);
    assert_eq!(
        receipt.digest().unwrap(),
        [
            0xa4, 0xe7, 0x99, 0xa4, 0xf9, 0xbf, 0x90, 0x8f, 0x25, 0xe0, 0xdf, 0xf2, 0x32, 0x1f,
            0x98, 0xbf, 0x29, 0x8d, 0xc8, 0xde, 0xd6, 0x02, 0x50, 0x98, 0xb0, 0x19, 0x9a, 0x9a,
            0x36, 0x50, 0x73, 0x3a
        ]
    );
    assert_eq!(SOURCE_CLOCK_BYTES, 88);
}

#[test]
fn all_backend_families_preserve_their_own_qualified_profile_and_clock() {
    for backend in [
        SourceBackend::Qemu,
        SourceBackend::Gem5,
        SourceBackend::Kvm,
        SourceBackend::External,
    ] {
        let mut receipt = modeled_receipt();
        receipt.binding.backend = backend;
        receipt.binding.closure_codec_version = 17;
        receipt.binding.profile_digest = [21; 32];
        receipt.binding.launch_digest = [22; 32];
        receipt.clock.mode = SourceClockMode::IndependentObserved;
        receipt.clock.instruction_ps = 0;
        receipt.clock.semantic_ps = 557;
        receipt.closure_edge_count = 0;

        let decoded = SourceReadyReceipt::decode(&receipt.encode().unwrap()).unwrap();
        decoded.validate_against(&receipt.binding).unwrap();
        assert_eq!(decoded, receipt);
    }
}

#[test]
fn receipt_rejects_unknown_versions_tags_and_missing_original_correlations() {
    let original = modeled_receipt().encode().unwrap();
    for extent in [0, 1, 343, 345] {
        assert!(SourceReadyReceipt::decode(&vec![0; extent]).is_err());
    }
    for (offset, value) in [
        (0, 2),
        (4, 343),
        (272, 1),
        (276, 0),
        (280, 64),
        (284, 999),
        (336, 0),
        (336, 5),
        (340, 0),
    ] {
        let mut changed = original;
        put_u32(&mut changed, offset, value);
        assert!(
            SourceReadyReceipt::decode(&changed).is_err(),
            "offset {offset}"
        );
    }
    for (offset, extent) in [
        (8, 32),
        (40, 8),
        (48, 8),
        (56, 8),
        (64, 8),
        (72, 32),
        (104, 32),
        (136, 32),
        (168, 32),
        (288, 32),
        (320, 8),
    ] {
        let mut changed = original;
        changed[offset..offset + extent].fill(0);
        assert!(
            SourceReadyReceipt::decode(&changed).is_err(),
            "offset {offset}"
        );
    }
}

#[test]
fn exact_binding_rejects_changed_backend_codec_and_constructor_identity() {
    let original = modeled_receipt();
    for offset in [8, 40, 48, 56, 72, 104, 136, 168, 339, 343] {
        let mut changed = original.encode().unwrap();
        changed[offset] ^= 1;
        if let Ok(receipt) = SourceReadyReceipt::decode(&changed) {
            assert!(receipt.validate_against(&original.binding).is_err());
        }
    }
    let mut receipt = original.clone();
    receipt.binding.backend = SourceBackend::Gem5;
    assert!(receipt.validate_against(&original.binding).is_err());
    receipt.binding.backend = SourceBackend::External;
    assert!(receipt.validate_against(&original.binding).is_err());
}

#[test]
fn offered_and_consumed_acknowledgements_name_every_original_receipt_byte() {
    let receipt = modeled_receipt();
    let acknowledgement = SourceReadyAcknowledgement::for_receipt(&receipt).unwrap();
    let offered = acknowledgement.encode().unwrap();
    let consumed = SourceReadyAcknowledgement::decode(&offered).unwrap();

    assert_eq!(consumed.encode().unwrap(), offered);
    consumed.validate_against(&receipt).unwrap();
    for offset in [8, 40, 48, 56, 88] {
        let mut changed = offered;
        changed[offset] ^= 1;
        assert!(
            SourceReadyAcknowledgement::decode(&changed)
                .unwrap()
                .validate_against(&receipt)
                .is_err()
        );
    }
    for offset in [64, 200, 208, 248, 264, 288, 320, 328, 342] {
        let mut changed = receipt.encode().unwrap();
        changed[offset] ^= 1;
        let changed_receipt = SourceReadyReceipt::decode(&changed).unwrap();
        assert!(acknowledgement.validate_against(&changed_receipt).is_err());
    }
}

#[test]
fn acknowledgement_rejects_partial_bodies_reserved_fields_and_missing_identity() {
    let original = SourceReadyAcknowledgement::for_receipt(&modeled_receipt())
        .unwrap()
        .encode()
        .unwrap();
    for extent in [0, 127, 129] {
        assert!(SourceReadyAcknowledgement::decode(&vec![0; extent]).is_err());
    }
    for (offset, extent) in [(8, 32), (40, 8), (48, 8), (56, 32), (88, 32)] {
        let mut changed = original;
        changed[offset..offset + extent].fill(0);
        assert!(SourceReadyAcknowledgement::decode(&changed).is_err());
    }
    for offset in [0, 4, 120, 127] {
        let mut changed = original;
        changed[offset] ^= 1;
        assert!(SourceReadyAcknowledgement::decode(&changed).is_err());
    }
}

#[test]
fn readiness_grammar_requires_exact_bodies_and_one_original_reserved_exchange() {
    let profile = staged::tests::profile();
    for (kind, extent) in [
        (StagedFrameKind::SourceReady, 344),
        (StagedFrameKind::SourceReadyAcknowledgement, 128),
        (StagedFrameKind::SourceReadyAcknowledgementConsumed, 128),
    ] {
        let header = staged::encode_frame_header(kind, extent, &profile).unwrap();
        assert_eq!(
            staged::decode_frame_header(&header, &profile).unwrap(),
            (kind, extent)
        );
        assert!(staged::encode_frame_header(kind, extent - 1, &profile).is_err());
        assert!(staged::encode_frame_header(kind, extent + 1, &profile).is_err());
    }
    let mut changed =
        staged::encode_frame_header(StagedFrameKind::SourceReady, 344, &profile).unwrap();
    put_u32(&mut changed, 12, 13);
    assert!(staged::decode_frame_header(&changed, &profile).is_err());
    let history = profile.minimum_wire_history_bytes().unwrap();
    let mut insufficient = profile.clone();
    insufficient.compute.native_history_byte_limit = history;
    insufficient.compute.provider_history_byte_limit = history;
    insufficient.validate().unwrap();
    assert!(staged::encode_frame_header(StagedFrameKind::SourceReady, 344, &insufficient).is_err());
    // Existing selected grammars retain their original admission rules.
    assert!(
        staged::encode_frame_header(
            StagedFrameKind::ExecutionAcknowledgement,
            128,
            &insufficient
        )
        .is_ok()
    );
}
