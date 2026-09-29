//! Synthetic cold-prefix claims, never protected Complete or current recovery.

use super::*;
use aos_sandbox_source_provider_protocol::native_held_completion::{
    assertion::{ProviderNativeSettlementAssertionV1, StorageNativeSettlementAssertionV1},
    recovery::{
        NativeHeldColdCustodyV1, NativeHeldRecoveryChildStatusV1, NativeHeldRecoveryFieldsV1,
        NativeHeldRecoveryModeV1, NativeHeldRecoveryQueryV1, NativeHeldRecoveryRowClassV1,
        NativeHeldRecoveryTargetV1, NativeHeldRuntimeStatusV1, ProviderNativeRecoveryStateV1,
        RootNativeRecoveryAssertionV1, StorageNativeRecoveryStateV1,
    },
};

pub(super) fn changed(
    before: &SourceNativeHeldCompletionRecordV1,
    phase: u8,
    prepared: Option<PreparedNativeHeldControlV1>,
    controls: Vec<SignedNativeHeldControlV1>,
) -> SourceNativeHeldCompletionRecordV1 {
    let mut original = before.original.clone();
    original.revision += 1;
    let suffix = NativeHeldCompletionSuffixV1::new(
        Owner::Provider,
        phase,
        before.suffix.flight(),
        prepared,
        controls,
    )
    .unwrap();
    SourceNativeHeldCompletionRecordV1::new(original, suffix).unwrap()
}

pub(super) fn recovery_query(
    before: &SourceNativeHeldCompletionRecordV1,
    disposition: RootNativeDispositionAssertionV1,
) -> SignedNativeHeldControlV1 {
    let root = before.suffix.control(Kind::RootPrepared).unwrap();
    let query = NativeHeldRecoveryQueryV1 {
        recovery_session: d(121),
        nonce: [122; 32],
        sequence: 1,
        mode: NativeHeldRecoveryModeV1::SettleRecordedDisposition,
        target: NativeHeldRecoveryTargetV1::RootScope,
        original_prepared: root.digest(),
        parent_root_query: d(0),
    };
    let accepted = disposition.disposition == NativeHeldDispositionV1::Accepted;
    let assertion = RootNativeRecoveryAssertionV1 {
        phase: if accepted { 5 } else { 11 },
        runtime_status: NativeHeldRuntimeStatusV1::RecoveryOnly,
        cold_custody: NativeHeldColdCustodyV1::Unavailable,
        diagnostic_sequence: 1,
        records: disposition.records.clone(),
        disposition: Some(disposition),
        hot_archive: before
            .suffix
            .control(if accepted {
                Kind::RootAccepted
            } else {
                Kind::RootClosed
            })
            .map(SignedNativeHeldControlV1::to_canonical_bytes),
        settlement: None,
    };
    PreparedNativeHeldControlV1::new(
        Kind::RootRecoveryQuery,
        *root.scope(),
        d(0),
        vec![
            section(
                Tag::RecoveryQuery,
                query.to_canonical_bytes().unwrap().to_vec(),
            ),
            section(
                Tag::RootRecoveryAssertion,
                assertion.to_canonical_bytes().unwrap(),
            ),
        ],
        root.prepared().signer().clone(),
    )
    .unwrap()
    .with_signature([0xB9; 64])
}

pub(super) fn child_query(
    record: &SourceNativeHeldCompletionRecordV1,
    parent: &SignedNativeHeldControlV1,
) -> PreparedNativeHeldControlV1 {
    let query = NativeHeldRecoveryQueryV1 {
        nonce: [123; 32],
        sequence: 1,
        target: NativeHeldRecoveryTargetV1::NativeScope,
        parent_root_query: parent.digest(),
        ..evidence::query(parent.prepared()).unwrap()
    };
    PreparedNativeHeldControlV1::new(
        Kind::ProviderStorageRecoveryQuery,
        evidence::full_scope(record).unwrap(),
        parent.digest(),
        vec![
            section(
                Tag::RecoveryQuery,
                query.to_canonical_bytes().unwrap().to_vec(),
            ),
            section(Tag::RootRecoveryControl, parent.to_canonical_bytes()),
        ],
        NativeHeldSignerV1::SourceProvider(
            record
                .original
                .canonical_request
                .as_ref()
                .unwrap()
                .signer()
                .clone(),
        ),
    )
    .unwrap()
}

// Constructs only canonical metadata. In particular, no Source Complete graph,
// protected snapshot, eligible current signature or writer is supplied here.
fn cold_storage_recorded() -> SourceNativeHeldCompletionRecordV1 {
    let held = held_prepared(d(120));
    cold_storage_recorded_from(&held)
}

pub(super) fn cold_storage_recorded_from(
    original: &SourceNativeHeldCompletionRecordV1,
) -> SourceNativeHeldCompletionRecordV1 {
    let closed = cold_closed(original);
    let disposition = evidence::root_disposition(&closed).unwrap().unwrap();
    let parent = recovery_query(&closed, disposition.clone());
    let mut controls = closed.suffix.controls().to_vec();
    controls.push(parent.clone());
    let root_recorded = changed(&closed, 7, closed.suffix.prepared().cloned(), controls);
    let child = child_query(&root_recorded, &parent).with_signature([0xBB; 64]);
    let mut controls = root_recorded.suffix.controls().to_vec();
    controls.push(child.clone());
    let query_recorded = changed(&root_recorded, 7, None, controls);
    let reply = query_recorded
        .original
        .accepted_reply
        .clone()
        .unwrap_or_else(|| request_tests::prepared().accepted_reply.unwrap());
    let storage = storage_recovery_control(&query_recorded, &reply);
    let mut controls = query_recorded.suffix.controls().to_vec();
    controls.push(storage);
    changed(&query_recorded, 8, None, controls)
}

pub(super) fn storage_recovery_control(
    record: &SourceNativeHeldCompletionRecordV1,
    reply: &aos_sandbox_source_provider_protocol::StorageNativeAcquireReplyV3,
) -> SignedNativeHeldControlV1 {
    let disposition = evidence::root_disposition(record).unwrap().unwrap();
    let child = record
        .suffix
        .control(Kind::ProviderStorageRecoveryQuery)
        .unwrap();
    let acceptance = reply.acceptance();
    let assertion = StorageNativeSettlementAssertionV1 {
        disposition: disposition.disposition,
        scope: evidence::full_scope(record).unwrap(),
        root_disposition: disposition.digest().unwrap(),
        acceptance: acceptance.acceptance().clone(),
    };
    let state = StorageNativeRecoveryStateV1 {
        fields: NativeHeldRecoveryFieldsV1 {
            phase: 4,
            runtime_status: NativeHeldRuntimeStatusV1::RecoveryOnly,
            row_class: NativeHeldRecoveryRowClassV1::Native,
            child_status: NativeHeldRecoveryChildStatusV1::NotQueried,
            diagnostic_sequence: 1,
            native_request: record.original.native_request_digest,
            acceptance: acceptance.acceptance().digest(),
            root_disposition: assertion.root_disposition,
            storage_settlement: assertion.digest().unwrap(),
            provider_settlement: d(0),
            witness: Some(
                NativeHeldByteWitnessV1::new(Family::StorageIssuance, vec![124; 48], d(125))
                    .unwrap(),
            ),
            disposition: Some(disposition),
            own_assertion: assertion.to_canonical_bytes().unwrap().to_vec(),
            hot_terminal: None,
            child: None,
        },
    };
    let storage = PreparedNativeHeldControlV1::new(
        Kind::StorageRecoveryState,
        evidence::full_scope(record).unwrap(),
        child.digest(),
        vec![
            section(
                Tag::RecoveryQuery,
                evidence::query(child.prepared())
                    .unwrap()
                    .to_canonical_bytes()
                    .unwrap()
                    .to_vec(),
            ),
            section(
                Tag::StorageRecoveryState,
                state.to_canonical_bytes().unwrap(),
            ),
        ],
        NativeHeldSignerV1::Storage(acceptance.signer()),
    )
    .unwrap()
    .with_signature([0xBC; 64]);
    storage
}

pub(super) fn provider_terminal(
    record: &SourceNativeHeldCompletionRecordV1,
    artifact: ObjectDigest,
) -> PreparedNativeHeldControlV1 {
    let disposition = evidence::root_disposition(record).unwrap().unwrap();
    let storage = evidence::storage_assertion(record).unwrap().unwrap();
    let parent = record.suffix.control(Kind::RootRecoveryQuery).unwrap();
    let assertion = ProviderNativeSettlementAssertionV1 {
        disposition: disposition.disposition,
        scope: evidence::full_scope(record).unwrap(),
        root_disposition: disposition.digest().unwrap(),
        storage_settlement: storage.digest().unwrap(),
        source_artifact: artifact,
    };
    let key = native_completion::native_completion_key_v2(record.original.acquisition_id);
    let bytes = record.to_canonical_bytes().unwrap();
    let state = ProviderNativeRecoveryStateV1 {
        fields: NativeHeldRecoveryFieldsV1 {
            phase: record.suffix.phase(),
            runtime_status: NativeHeldRuntimeStatusV1::RecoveryOnly,
            row_class: NativeHeldRecoveryRowClassV1::Native,
            child_status: NativeHeldRecoveryChildStatusV1::VerifiedState,
            diagnostic_sequence: 1,
            native_request: record.original.native_request_digest,
            acceptance: evidence::acceptance(record).unwrap(),
            root_disposition: assertion.root_disposition,
            storage_settlement: assertion.storage_settlement,
            provider_settlement: assertion.digest().unwrap(),
            witness: Some(
                NativeHeldByteWitnessV1::new(
                    Family::ProviderNative,
                    key.clone(),
                    native_held_record_byte_digest_v1(Family::ProviderNative, &key, &bytes)
                        .unwrap(),
                )
                .unwrap(),
            ),
            disposition: Some(disposition),
            own_assertion: assertion.to_canonical_bytes().unwrap().to_vec(),
            hot_terminal: None,
            child: Some(
                record
                    .suffix
                    .control(Kind::StorageRecoveryState)
                    .unwrap()
                    .to_canonical_bytes(),
            ),
        },
    };
    PreparedNativeHeldControlV1::new(
        Kind::ProviderRecoveryState,
        evidence::full_scope(record).unwrap(),
        parent.digest(),
        vec![
            section(
                Tag::RecoveryQuery,
                evidence::query(parent.prepared())
                    .unwrap()
                    .to_canonical_bytes()
                    .unwrap()
                    .to_vec(),
            ),
            section(
                Tag::ProviderRecoveryState,
                state.to_canonical_bytes().unwrap(),
            ),
        ],
        NativeHeldSignerV1::SourceProvider(
            record
                .original
                .canonical_request
                .as_ref()
                .unwrap()
                .signer()
                .clone(),
        ),
    )
    .unwrap()
}

#[test]
fn cold_terminal_artifact_is_not_zero_from_missing_hot3_after_complete() {
    let held = held_prepared(d(120));
    assert_eq!(evidence::artifact(&held).unwrap(), d(120));
    let storage = cold_storage_recorded();
    assert_eq!(storage.original.state, Outer::Active);
    assert!(storage.suffix.control(Kind::ProviderHeld).is_none());
    assert_eq!(
        evidence::root_disposition(&storage)
            .unwrap()
            .unwrap()
            .source_artifact,
        d(0)
    );

    let terminal = provider_terminal(&storage, d(120));
    let next = changed(
        &storage,
        8,
        Some(terminal),
        storage.suffix.controls().to_vec(),
    );
    assert_eq!(evidence::artifact(&next).unwrap(), d(120));
    // Complete/A authenticity is still a full original graph obligation. This
    // canonical claim cannot pass that graph by itself or create a terminal permit.
    let key = native_completion::native_completion_key_v2(next.original.acquisition_id);
    let bytes = next.to_canonical_bytes().unwrap();
    assert!(validate_native_held_records_v1([(key.as_slice(), bytes.as_slice())]).is_err());

    let zero = provider_terminal(&storage, d(0));
    let suffix = NativeHeldCompletionSuffixV1::new(
        Owner::Provider,
        8,
        storage.suffix.flight(),
        Some(zero),
        storage.suffix.controls().to_vec(),
    )
    .unwrap();
    assert!(SourceNativeHeldCompletionRecordV1::new(storage.original.clone(), suffix).is_err());
}
