//! Focused floor DATA adapters over the existing Source requested fixture.
//!
//! No owner graph, protected configuration, journal, receipt or live custody is
//! fabricated. Witness digests are synthetic; these fixtures test lower-level
//! canonical inventories and immutable bindings, not whole-graph association.

use super::*;
use aos_sandbox::journal::native_held::{
    NativeHeldCapacityPurposeV3, NativeHeldCapacityRequestV3, OriginalSourceCapacityBudgetsV5,
};
use aos_sandbox_source_provider_ledger::ledger::{
    format,
    model::{AcquisitionKeyV1, AttemptKeyV1},
    native_completion::{OriginalSourceProvenanceClaimsV5, OriginalSourceProvenanceV5},
};
use aos_sandbox_source_provider_protocol::{
    SourceProviderMethod,
    native_held_completion::{
        NativeHeldControlKindV1, NativeHeldScopeV1, NativeHeldSectionTagV1,
        frame::{NativeHeldSectionV1, NativeHeldSignerV1, PreparedNativeHeldControlV1},
        native_held_flight_digest_v1,
        witness::{
            NativeHeldByteWitnessV1, NativeHeldGenerationClaimV1, NativeHeldOwnerWitnessV1,
            NativeHeldRecordFamilyV1, ROOT_NATIVE_WITNESS_FAMILIES_V1, RootNativeHeldWitnessV1,
        },
    },
};

pub(super) fn floor() -> OriginalSourceCapacityRecordV5 {
    let native = crate::native_completion::fixture_requested([1; 32], 500, digest(2));
    let signed = native.canonical_request.as_ref().unwrap();
    let claims = signed.request().claims();
    let root_signer = signed.request().signed_root_request().signer();
    let generation = NativeHeldGenerationClaimV1 { generation: 1, digest: digest(3) };
    let root_records = ROOT_NATIVE_WITNESS_FAMILIES_V1.map(|family| {
        let prefix: &[u8] = match family {
            NativeHeldRecordFamilyV1::RootSession => b"aos.mount.source-provider-session.v2\0",
            NativeHeldRecordFamilyV1::RootAttempt => b"aos.mount.source-provider-query-attempt.v2\0",
            NativeHeldRecordFamilyV1::RootAcquisition => b"aos.mount.source-acquisition.v2\0",
            NativeHeldRecordFamilyV1::RootHead => b"aos.mount.source-provider-head.v2\0",
            _ => unreachable!("fixed Root witness families"),
        };
        let mut key = prefix.to_vec();
        key.resize(family.key_bytes(), 4);
        NativeHeldByteWitnessV1::new(family, key, digest(5)).unwrap()
    });
    let witness = NativeHeldOwnerWitnessV1::Root(RootNativeHeldWitnessV1 {
        local_socket_cookie: 1,
        journal_sequence: 1,
        planning_sequence: 1,
        trust: generation,
        revocation: generation,
        provider_head: generation,
        provider_floor: generation,
        publication: digest(6),
        records: root_records,
    });
    let root_prepared = PreparedNativeHeldControlV1::new(
        NativeHeldControlKindV1::RootPrepared,
        NativeHeldScopeV1 {
            flight: native_held_flight_digest_v1(native.root_request_digest, digest(7), native.session_binding),
            original_source_session: native.session_binding,
            mount_attempt: digest(7),
            provider_attempt: digest(0),
            provider_acquisition: native.acquisition_id,
            original_root_request: native.root_request_digest,
            original_native_request: digest(0),
        },
        digest(0),
        vec![NativeHeldSectionV1::new(
            NativeHeldSectionTagV1::Witness,
            witness.to_canonical_bytes().unwrap(),
        ).unwrap()],
        NativeHeldSignerV1::SourceProvider(root_signer.clone()),
    ).unwrap().with_signature([8; 64]);
    let keys = [
        format::attempt_key(&AttemptKeyV1 {
            provider_id: native.provider_id,
            holder_id: native.holder_id,
            root_record_key_id: root_signer.key_id(),
            method: SourceProviderMethod::Acquire as u8,
            request_id: [3; 16],
        }),
        format::acquisition_key(&AcquisitionKeyV1 {
            provider_id: native.provider_id,
            holder_id: native.holder_id,
            acquisition_id: native.acquisition_id,
        }),
        format::session_key(native.provider_id, native.holder_id),
        format::session_history_key(native.provider_id, native.holder_id, native.session_binding),
    ];
    let families = [
        NativeHeldRecordFamilyV1::ProviderAttempt,
        NativeHeldRecordFamilyV1::ProviderAcquisition,
        NativeHeldRecordFamilyV1::ProviderHolder,
        NativeHeldRecordFamilyV1::ProviderHistory,
    ];
    let anchor = native.original_clock.unwrap();
    let provenance = OriginalSourceProvenanceV5::new_untrusted(OriginalSourceProvenanceClaimsV5 {
        root_prepared,
        claims: claims.clone(),
        initial: anchor.initial(),
        original_deadline: anchor.initial().boottime_nanoseconds() + 600_000_000_000,
        narrowed_deadline: anchor.deadline(),
        journal_sequence: 1,
        configuration: digest(9),
        records: std::array::from_fn(|index| {
            NativeHeldByteWitnessV1::new(families[index], keys[index].clone(), digest(10)).unwrap()
        }),
    }).unwrap();
    let request = NativeHeldCapacityRequestV3 {
        purpose: NativeHeldCapacityPurposeV3::Provider,
        owner_id: Sha256::new()
            .chain_update(b"aos.sandbox.source-provider.native-dispatch-capacity-owner.v2\0")
            .chain_update(native.provider_id)
            .chain_update(native.holder_id)
            .chain_update(native.acquisition_id.as_bytes())
            .finalize().into(),
        owner_digest: [11; 32],
        operation_id: [12; 16],
        artifact_digest: *native.attempt_digest.as_bytes(),
        checkpoint_digest: *native.root_request_digest.as_bytes(),
        chain_head_digest: *native.session_binding.as_bytes(),
        future_transactions: 20,
        terminal_records: 100,
        terminal_bytes: 100_000,
        poison_records: 100,
        poison_bytes: 100_000,
    };
    OriginalSourceCapacityRecordV5::new(
        request,
        [13; 16],
        OriginalSourceCapacityBudgetsV5 {
            terminal_records: request.terminal_records,
            terminal_bytes: request.terminal_bytes,
            poison_records: request.poison_records,
            poison_bytes: request.poison_bytes,
        },
        provenance,
    ).unwrap()
}

pub(super) fn successor(original: &OriginalSourceCapacityRecordV5, count: u32) -> OriginalSourceCapacityRecordV5 {
    let mut request = original.request();
    request.future_transactions = count;
    OriginalSourceCapacityRecordV5::new(
        request, original.admission_transaction_id(), original.origin_budgets(),
        original.original_provenance().clone(),
    ).unwrap()
}

/// Returns floor-only canonical DATA, explicitly not a complete owner fixture.
pub(super) fn floor_only_union_state() -> State {
    let row = floor().to_journal_record().unwrap();
    State::from([((row.namespace(), row.key().to_vec()), row.value().unwrap().to_vec())])
}

/// Encodes independent canonical legacy DATA, without a protected producer.
pub(super) fn legacy_row(admission: u8) -> (aos_sandbox::GlobalCapacityReservationRequestV1, JournalRecord) {
    use aos_sandbox::{GlobalCapacityReservationPurposeV1, GlobalCapacityReservationRequestV1};

    let request = GlobalCapacityReservationRequestV1 {
        purpose: GlobalCapacityReservationPurposeV1::SourceProviderNativeTerminal,
        owner_namespace: RecordNamespace::SourceProviderAuthority,
        owner_id: [20; 32],
        owner_digest: [21; 32],
        operation_id: [22; 16],
        artifact_digest: [23; 32],
        checkpoint_digest: [24; 32],
        chain_head_digest: [25; 32],
        future_transactions: 1,
        terminal_records: 4,
        terminal_bytes: 4096,
        poison_records: 4,
        poison_bytes: 4096,
    };
    let mut body = Vec::new();
    body.extend_from_slice(&request.owner_id);
    body.extend_from_slice(&request.owner_digest);
    body.extend_from_slice(&request.operation_id);
    body.extend_from_slice(&request.artifact_digest);
    body.extend_from_slice(&request.checkpoint_digest);
    body.extend_from_slice(&request.chain_head_digest);
    body.extend_from_slice(&request.terminal_records.to_be_bytes());
    body.extend_from_slice(&request.terminal_bytes.to_be_bytes());
    body.extend_from_slice(&request.poison_records.to_be_bytes());
    body.extend_from_slice(&request.poison_bytes.to_be_bytes());
    body.extend_from_slice(&[admission; 16]);
    let identity: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.journal.global-capacity-reservation.v1\0")
        .chain_update([3, 41])
        .chain_update(&body)
        .finalize().into();
    let mut value = b"AOSJCR01\0\x01\x29\x03\0\0".to_vec();
    value.extend_from_slice(&body);
    value.extend_from_slice(&identity);
    let mut key = b"aos.journal.global-capacity-reservation.v1\0".to_vec();
    key.extend_from_slice(&identity);
    (request, JournalRecord::put(RecordNamespace::GlobalCapacityReservation, key, value))
}

/// Supplies synthetic origin DATA solely to exercise immutable comparison helpers.
pub(super) fn origin(floor: OriginalSourceCapacityRecordV5) -> ValidatedAdmission {
    use aos_sandbox_source_provider_protocol::SourceProviderAuthorityV1;

    let native = crate::native_completion::fixture_requested([1; 32], 500, digest(2));
    let signed = native.canonical_request.as_ref().unwrap();
    let provider = signed.signer();
    let holder = signed.request().signed_root_request().signer();
    let owner = OriginalSourceOwnerDataV5 {
        prefix: OriginalSourceOwnerPrefixV5::Applying,
        provider: SourceProviderAuthorityV1::new(
            provider.authority_id(), provider.authority_generation(), provider.authority_digest(),
        ).unwrap(),
        holder: SourceProviderAuthorityV1::new(
            holder.authority_id(), holder.authority_generation(), holder.authority_digest(),
        ).unwrap(),
        acquisition_id: native.acquisition_id,
        operation_id: floor.request().operation_id,
        reservation_acquisition_digest: ObjectDigest::from_bytes(floor.request().owner_digest),
        attempt_digest: native.attempt_digest,
        root_request_digest: native.root_request_digest,
        session_binding: native.session_binding,
        root_prepared_digest: floor.original_provenance().claims().root_prepared.digest(),
        configuration_digest: floor.original_provenance().claims().configuration,
        catalog_head: (signed.request().claims().catalog().generation(), signed.request().claims().catalog().digest()),
        resource_namespace_digest: signed.request().claims().catalog().namespace_digest(),
        backend_id: [26; 32],
        backend_lineage_digest: digest(27),
        normalized_intent_digest: digest(28),
        native_request_digest: None,
    };
    ValidatedAdmission { after: State::new(), initial_floor: floor, owner }
}

pub(super) fn cold(admission: &ValidatedAdmission) -> SourcePreRequestedColdArchiveV1 {
    use aos_sandbox_source_provider_protocol::{
        PreparedSourceNoEscapeClosureV1, SourceNoEscapeClosureClaimsV1,
    };

    let floor = &admission.initial_floor;
    let owner = &admission.owner;
    let native = crate::native_completion::fixture_requested([1; 32], 500, digest(2));
    let staged = floor.original_provenance().claims().claims.to_canonical_bytes();
    let staged_digest = ObjectDigest::from_bytes(Sha256::new()
        .chain_update(b"aos-source-provider-pre-requested-staged-claims.v1\0")
        .chain_update((staged.len() as u32).to_be_bytes())
        .chain_update(staged).finalize().into());
    let mut challenge_key = b"AOSZHK01".to_vec();
    challenge_key.extend_from_slice(&floor.original_provenance().claims().claims.attempt().0);
    let claims = SourceNoEscapeClosureClaimsV1 {
        provider_id: owner.provider.authority_id(),
        holder_id: owner.holder.authority_id(),
        original_session: owner.session_binding,
        acquisition_id: owner.acquisition_id,
        original_signed_request: owner.root_request_digest,
        original_attempt: owner.attempt_digest,
        original_source_floor: ObjectDigest::from_bytes(floor.reservation_id()),
        original_root_prepared: owner.root_prepared_digest,
        original_applying: owner.reservation_acquisition_digest,
        admission_transaction: floor.admission_transaction_id(),
        admission_sequence: 7,
        first_cold_transaction: [29; 16],
        first_cold_sequence: 16,
        challenge_cut: digest(30),
        challenge_sequence: 0,
        staged_claims: staged_digest,
        challenge_absence: NativeHeldByteWitnessV1::new(
            NativeHeldRecordFamilyV1::Challenge, challenge_key, digest(0),
        ).unwrap(),
        faulted_acquisition: digest(31),
        retired_attempt: digest(32),
        cleared_session: digest(33),
        session_history_successor: digest(34),
        terminal_records: floor.original_provenance().claims().records.clone(),
    };
    let prepared = PreparedSourceNoEscapeClosureV1::new_untrusted(
        claims, native.canonical_request.as_ref().unwrap().signer().clone(),
    ).unwrap();
    SourcePreRequestedColdArchiveV1::new_untrusted(
        floor.to_journal_record().unwrap().value().unwrap().to_vec(), prepared, None, None,
    ).unwrap()
}
