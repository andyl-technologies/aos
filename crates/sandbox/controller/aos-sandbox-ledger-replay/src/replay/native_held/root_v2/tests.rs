//! Actual signed phase0, PreparedStored and discard-Root1 Closed source vectors.
//!
//! The shared Protocol fixture supplies genuine canonical original rows. Budgets
//! in transfer tests are explicit DATA inputs, not attained maxima or admission
//! proof. Authenticated Inventory/settlement and terminal ACK fixture coverage
//! remains with Protocol; this compact seam does not duplicate its owner engine.

use super::JournalError;

use aos_sandbox_protocol::domain_ledger::capacity_family::native_held::{
    NativeHeldCapacityPurposeV3, NativeHeldCapacityRecordV3, NativeHeldCapacityRequestV3,
};

use std::collections::BTreeMap;

use aos_sandbox_model::ObjectDigest;
use aos_sandbox_protocol as protocol;
use aos_sandbox_source_provider_protocol::{
    NativeAcquireCatalogBindingV3, SourceProviderKeyUsageV1,
    native_held_completion::{
        NativeHeldControlKindV1 as ControlKind, NativeHeldOwnerV1, NativeHeldScopeV1,
        NativeHeldSectionTagV1,
        assertion::{
            NativeHeldDispositionV1, RootNativeDispositionAssertionV1, RootNativeObservationV1,
        },
        frame::{
            NativeHeldSectionV1, NativeHeldSignerV1, PreparedNativeHeldControlV1,
            SignedNativeHeldControlV1,
        },
        native_held_flight_digest_v1,
        suffix::NativeHeldCompletionSuffixV1,
        witness::{
            NativeHeldByteWitnessV1, NativeHeldGenerationClaimV1, NativeHeldOwnerWitnessV1,
            ROOT_NATIVE_WITNESS_FAMILIES_V1, RootNativeHeldWitnessV1,
            native_held_record_byte_digest_v1,
        },
    },
};
use ed25519_dalek::{Signer as _, SigningKey};
use protocol::mount_source_acquisition_state::{
    StoredRecordV2, acquisition_key, encode_mount_source_state_record_v2,
    native_held_completion::{
        RootNativeCutKindV1, RootNativeCutV1, RootNativeHeldSidecarV2,
        RootNativeNoInterestTerminalV1, native_root_sidecar_key_v2, validate_native_root_graph_v2,
    },
    provider_attempt_key, provider_head_key, provider_session_key,
    validate_mount_source_state_graph_v2,
};

#[path = "../../../../../../protocol/aos-sandbox-protocol/src/mount_source_acquisition_state/native_held_completion/tests/fixture.rs"]
mod fixture;

use super::*;

use super::fixture::Original;

fn digest(byte: u8) -> ObjectDigest {
    ObjectDigest::from_bytes([byte; 32])
}

#[test]
fn actual_prepared_store_rederives_all_fields_and_preserves_old_wire_floor() {
    let fixture = Original::new();
    let original = fixture.graph(false, false);
    let after = fixture.graph(true, false);
    let proposal =
        validate_native_root_transition_v2(&original, &after, fixture.attempt, [102; 16]).unwrap();
    let old = fixture.floor(&original, 7);
    let mut next_request = old.request();
    next_request.future_transactions = 6;
    next_request.terminal_records = 90;
    next_request.poison_records = 90;
    next_request.terminal_bytes = 9_000_000;
    next_request.poison_bytes = 9_000_000;
    let next = NativeHeldCapacityRecordV3::new(next_request, old.admission_transaction_id())
        .map_err(JournalError::from)
        .unwrap();

    let append = root_native_capacity_append_v2(
        &proposal,
        &original,
        &after,
        &original,
        fixture.attempt,
        [102; 16],
    )
    .unwrap();
    assert_eq!(
        append.step(),
        super::super::NativeHeldCapacityStepV2::Root(Kind::PreparedStored)
    );
    let transaction = root_native_capacity_transition_v2(
        &proposal,
        &original,
        &after,
        &original,
        fixture.attempt,
        [102; 16],
        &old,
        Some(&next),
        JournalLimits::default(),
    )
    .unwrap();
    assert_eq!(transaction.records().len(), 3);
    assert_eq!(transaction.records()[2], next.to_journal_record());
    assert_eq!(&next.to_journal_record().value().unwrap()[8..10], &[0, 3]);
    assert_eq!(
        NativeHeldCapacityRecordV3::from_journal_record(&next.to_journal_record())
            .map_err(JournalError::from)
            .unwrap(),
        next
    );

    let mut forged = proposal.clone();
    forged.maximum_remaining_transactions = 5;
    assert!(
        root_native_capacity_append_v2(
            &forged,
            &original,
            &after,
            &original,
            fixture.attempt,
            [102; 16]
        )
        .is_err()
    );
    forged = proposal.clone();
    forged.before_images.clear();
    assert!(
        root_native_capacity_append_v2(
            &forged,
            &original,
            &after,
            &original,
            fixture.attempt,
            [102; 16]
        )
        .is_err()
    );
    assert!(
        root_native_capacity_append_v2(
            &proposal,
            &original,
            &after,
            &original,
            fixture.attempt,
            [103; 16]
        )
        .is_err()
    );

    let mut enlarged_request = old.request();
    enlarged_request.future_transactions = 6;
    let enlarged =
        NativeHeldCapacityRecordV3::new(enlarged_request, old.admission_transaction_id())
            .map_err(JournalError::from)
            .unwrap();
    assert!(
        root_native_capacity_transition_v2(
            &proposal,
            &original,
            &after,
            &original,
            fixture.attempt,
            [102; 16],
            &old,
            Some(&enlarged),
            JournalLimits::default()
        )
        .is_err()
    );
    let limits = JournalLimits {
        maximum_records_per_transaction: 2,
        ..JournalLimits::default()
    };
    assert!(
        root_native_capacity_transition_v2(
            &proposal,
            &original,
            &after,
            &original,
            fixture.attempt,
            [102; 16],
            &old,
            Some(&next),
            limits
        )
        .is_err()
    );
}

#[test]
fn actual_phase0_closed_can_discard_root1_but_needs_the_original_context() {
    let fixture = Original::new();
    let original = fixture.graph(false, false);
    let closed = fixture.graph(false, true);
    let proposal =
        validate_native_root_transition_v2(&original, &closed, fixture.attempt, [101; 16]).unwrap();
    assert_eq!(proposal.kind, Kind::ClosedAssertionRecorded);
    assert!(
        closed.sidecars()[&fixture.attempt]
            .suffix()
            .prepared()
            .is_none()
    );
    assert!(
        closed.sidecars()[&fixture.attempt]
            .suffix()
            .controls()
            .is_empty()
    );

    root_native_capacity_append_v2(
        &proposal,
        &original,
        &closed,
        &original,
        fixture.attempt,
        [101; 16],
    )
    .unwrap();
    assert!(
        root_native_capacity_append_v2(
            &proposal,
            &original,
            &closed,
            &closed,
            fixture.attempt,
            [101; 16]
        )
        .is_err()
    );
    let old = fixture.floor(&original, 7);
    assert!(
        root_native_capacity_transition_v2(
            &proposal,
            &original,
            &closed,
            &original,
            fixture.attempt,
            [101; 16],
            &old,
            None,
            JournalLimits::default()
        )
        .is_err()
    );

    let mut wrong = old.request();
    wrong.checkpoint_digest = [199; 32];
    let wrong = NativeHeldCapacityRecordV3::new(wrong, old.admission_transaction_id())
        .map_err(JournalError::from)
        .unwrap();
    assert!(
        root_native_capacity_transition_v2(
            &proposal,
            &original,
            &closed,
            &original,
            fixture.attempt,
            [101; 16],
            &wrong,
            None,
            JournalLimits::default()
        )
        .is_err()
    );
    let wrong_admission = NativeHeldCapacityRecordV3::new(old.request(), [199; 16])
        .map_err(JournalError::from)
        .unwrap();
    assert!(
        root_native_capacity_transition_v2(
            &proposal,
            &original,
            &closed,
            &original,
            fixture.attempt,
            [101; 16],
            &wrong_admission,
            None,
            JournalLimits::default()
        )
        .is_err()
    );
}

#[test]
fn original_context_rejects_same_attempt_with_a_different_cut_or_root1() {
    let mut fixture = Original::new();
    let original = fixture.graph(false, false);
    let stored = fixture.graph(true, false);
    let proposal =
        validate_native_root_transition_v2(&original, &stored, fixture.attempt, [102; 16]).unwrap();
    let legacy = validate_mount_source_state_graph_v2(
        fixture
            .rows
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_slice())),
    )
    .unwrap();
    fixture.cut = RootNativeCutV1::capture(
        RootNativeCutKindV1::Admission,
        [200; 16],
        &legacy,
        fixture.attempt,
    )
    .unwrap();
    let foreign_cut = fixture.graph(false, false);
    assert!(
        root_native_capacity_append_v2(
            &proposal,
            &original,
            &stored,
            &foreign_cut,
            fixture.attempt,
            [102; 16]
        )
        .is_err()
    );
    fixture.cut = original.sidecars()[&fixture.attempt]
        .admission_cut()
        .clone();
    fixture.witness.local_socket_cookie = 8;
    let foreign_preparation = fixture.graph(false, false);
    assert!(
        root_native_capacity_append_v2(
            &proposal,
            &original,
            &stored,
            &foreign_preparation,
            fixture.attempt,
            [102; 16]
        )
        .is_err()
    );
}

#[test]
fn public_marker_constructor_remains_structural_data_not_a_floor_join() {
    let settled = protocol::mount_source_acquisition_state::RecordRefV2 {
        id: [1; 32],
        revision: 3,
        record_digest: [2; 32],
    };
    let faulted = protocol::mount_source_acquisition_state::RecordRefV2 {
        id: [3; 32],
        revision: 1,
        record_digest: [4; 32],
    };
    let marker =
        RootNativeNoInterestTerminalV1::new([5; 16], digest(6), settled, faulted, [7; 32], [8; 32])
            .unwrap();
    assert_eq!(marker.to_canonical_bytes().unwrap().len(), 272);
    assert_eq!(
        RootNativeNoInterestTerminalV1::from_canonical_bytes(&marker.to_canonical_bytes().unwrap())
            .unwrap(),
        marker
    );
    assert!(
        RootNativeNoInterestTerminalV1::new([0; 16], digest(6), settled, faulted, [7; 32], [8; 32])
            .is_err()
    );

    let fixture = Original::new();
    let original = fixture.graph(false, false);
    let old = fixture.floor(&original, 7);
    let record = old.to_journal_record();
    let exact_digest = digest_bytes(record.value().unwrap());
    let exact = RootNativeNoInterestTerminalV1::new(
        [5; 16],
        digest(6),
        settled,
        faulted,
        old.reservation_id(),
        exact_digest,
    )
    .unwrap();
    // This is an isolated exact DATA binding check, not an authenticated owner
    // cleanup proposal, committed floor retirement or no-dispatch authority.
    require_retired_floor(&exact, &old).unwrap();
    let wrong_id = RootNativeNoInterestTerminalV1::new(
        [5; 16],
        digest(6),
        settled,
        faulted,
        [7; 32],
        exact_digest,
    )
    .unwrap();
    assert!(require_retired_floor(&wrong_id, &old).is_err());
    let wrong_digest = RootNativeNoInterestTerminalV1::new(
        [5; 16],
        digest(6),
        settled,
        faulted,
        old.reservation_id(),
        old.reservation_id(),
    )
    .unwrap();
    assert!(require_retired_floor(&wrong_digest, &old).is_err());
}
