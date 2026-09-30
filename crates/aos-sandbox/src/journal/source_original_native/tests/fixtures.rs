//! Pure original owner fixtures adapted from the accepted Ledger DATA vectors.
//!
//! Canonical sessions/catalogs/requests are built with public existing codecs.
//! Synthetic signatures and clock claims establish no protected writer or origin.

use super::*;
use aos_sandbox_core::{RawClockProvenance, RawPairedClockSample};
use aos_sandbox_source_provider_ledger::{
    NormalizedAcquisitionIntentV1, identity,
    ledger::{
        format::*,
        model::*,
        native_completion::{
            NativeAcquireClockAnchorV1, NativeAcquireCompletionRecordV2,
            OriginalSourceProvenanceClaimsV5, OriginalSourceProvenanceV5,
        },
        native_held_completion::SourceNativeHeldCompletionRecordV1,
        reducer::inventory_state_digest,
    },
};
use aos_sandbox_source_provider_protocol::*;
use aos_sandbox_source_provider_protocol::native_held_completion::{
    NativeHeldControlKindV1, NativeHeldOwnerV1, NativeHeldScopeV1, NativeHeldSectionTagV1,
    frame::{NativeHeldSectionV1, NativeHeldSignerV1, PreparedNativeHeldControlV1},
    native_held_flight_digest_v1,
    suffix::NativeHeldCompletionSuffixV1,
    witness::{
        NativeHeldByteWitnessV1, NativeHeldGenerationClaimV1, NativeHeldOwnerWitnessV1,
        NativeHeldRecordFamilyV1, RootNativeHeldWitnessV1,
        ROOT_NATIVE_WITNESS_FAMILIES_V1, native_held_record_byte_digest_v1,
    },
};
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};

fn digest(byte: u8) -> ObjectDigest {
    ObjectDigest::from_bytes([byte; 32])
}

fn signer(byte: u8, usage: SourceProviderKeyUsageV1) -> SourceProviderSigningKeyV1 {
    let (id, generation, state) = match usage {
        SourceProviderKeyUsageV1::RootMountHello | SourceProviderKeyUsageV1::RootMountRecord => {
            ([7; 16], 8, digest(9))
        }
        SourceProviderKeyUsageV1::ProviderHello | SourceProviderKeyUsageV1::ProviderOutcome => {
            ([33; 16], 35, digest(36))
        }
        _ => ([90; 16], 1, digest(91)),
    };
    let (key_id, key_generation) = match usage {
        SourceProviderKeyUsageV1::RootMountRecord => ([11; 16], 12),
        SourceProviderKeyUsageV1::ProviderOutcome => ([37; 16], 38),
        _ => ([byte; 16], 1),
    };
    SourceProviderSigningKeyV1::for_signing_key(
        id,
        generation,
        state,
        key_id,
        key_generation,
        usage,
        &SigningKey::from_bytes(&[byte; 32]),
    )
    .unwrap()
}

fn session(nonce: u8) -> HolderSessionHeadRecordV1 {
    let signers = [
        signer(52, SourceProviderKeyUsageV1::RootMountHello),
        signer(51, SourceProviderKeyUsageV1::RootMountRecord),
        signer(53, SourceProviderKeyUsageV1::ProviderHello),
        signer(54, SourceProviderKeyUsageV1::ProviderOutcome),
    ];
    let root = sign_hello(
        SourceProviderHelloV1::new(
            SourceProviderPeerRole::RootMount,
            [nonce; 32],
            [5; 16],
            [6; 16],
            signers[1].clone(),
            signers[3].clone(),
            [85; 16],
            86,
            digest(87),
            None,
            1,
            false,
            false,
        )
        .unwrap(),
        signers[0].clone(),
        &SigningKey::from_bytes(&[52; 32]),
    )
    .unwrap();
    let provider = sign_hello(
        SourceProviderHelloV1::new(
            SourceProviderPeerRole::Provider,
            [nonce + 1; 32],
            [4; 16],
            [6; 16],
            signers[3].clone(),
            signers[1].clone(),
            [85; 16],
            86,
            digest(87),
            Some(digest_signed_hello(&root)),
            1,
            false,
            false,
        )
        .unwrap(),
        signers[2].clone(),
        &SigningKey::from_bytes(&[53; 32]),
    )
    .unwrap();
    HolderSessionHeadRecordV1 {
        revision: 1,
        session_generation: 1,
        provider: SourceProviderAuthorityV1::new([33; 16], 35, digest(36)).unwrap(),
        holder: SourceProviderAuthorityV1::new([7; 16], 8, digest(9)).unwrap(),
        session_binding: source_provider_session_binding_v1(&root, &provider),
        predecessor_session_binding: None,
        supersession_evidence_digest: None,
        boot_id: [6; 16],
        root_process_instance: [5; 16],
        provider_process_instance: [4; 16],
        provider_process_id: 80,
        provider_start_time_ticks: 81,
        provider_execution_commitment: provider_execution_commitment_v1([6; 16], 80, 81, [4; 16]),
        root_writer: WriterIdentityV1 {
            uid: 0,
            gid: 0,
            tgid: 82,
            start_time_ticks: 83,
            cgroup_digest: digest(84),
        },
        route_id: [85; 16],
        route_generation: 86,
        route_digest: digest(87),
        resource_namespace_digest: digest(24),
        trust_generation: 1,
        trust_digest: digest(88),
        revocation_generation: 1,
        revocation_digest: digest(10),
        signer_set_commitment: source_provider_signer_set_commitment_v1(
            &signers[0],
            &signers[1],
            &signers[2],
            &signers[3],
        ),
        signers,
        request_sequence_floor: 1,
        response_sequence_floor: 1,
        acquisition_sequence_floor: 1,
        next_acquisition_sequence: 5,
        next_request_sequence: 3,
        next_response_sequence: 1,
        pending_attempt_digest: None,
        last_completed_attempt_digest: None,
        root_hello_digest: digest_signed_hello(&root),
        provider_hello_digest: digest_signed_hello(&provider),
        root_hello: root.to_canonical_bytes(),
        provider_hello: provider.to_canonical_bytes(),
    }
}

fn catalog(native: &NativeAcquireCompletionRecordV2) -> CatalogHeadRecordV1 {
    let held = native
        .canonical_request
        .as_ref()
        .unwrap()
        .request()
        .claims()
        .catalog();
    let publisher = signer(55, SourceProviderKeyUsageV1::CatalogPublisher);
    let mut publication = b"AOSPCP01".to_vec();
    publication.extend_from_slice(&2_u16.to_be_bytes());
    publication.extend_from_slice(&[0; 6]);
    publication.extend_from_slice(&[33; 16]);
    publication.extend_from_slice(&35_u64.to_be_bytes());
    publication.extend_from_slice(digest(36).as_bytes());
    publication.extend_from_slice(held.namespace_digest().as_bytes());
    publication.extend_from_slice(&held.generation().to_be_bytes());
    publication.extend_from_slice(held.digest().as_bytes());
    publication.extend_from_slice(&publisher.authority_id());
    publication.extend_from_slice(&1_u64.to_be_bytes());
    publication.extend_from_slice(&0_u64.to_be_bytes());
    publication.extend_from_slice(&[0; 32]);
    publication.extend_from_slice(&held.generation().to_be_bytes());
    publication.extend_from_slice(held.digest().as_bytes());
    publication.extend_from_slice(&500_i64.to_be_bytes());
    publication.extend_from_slice(&1_u64.to_be_bytes());
    publication.extend_from_slice(digest(88).as_bytes());
    publication.extend_from_slice(&1_u64.to_be_bytes());
    publication.extend_from_slice(digest(10).as_bytes());
    publication.extend_from_slice(&publisher.authority_id());
    publication.extend_from_slice(&publisher.authority_generation().to_be_bytes());
    publication.extend_from_slice(publisher.authority_digest().as_bytes());
    publication.extend_from_slice(&publisher.key_id());
    publication.extend_from_slice(&publisher.key_generation().to_be_bytes());
    publication.extend_from_slice(publisher.public_key_digest().as_bytes());
    publication.push(publisher.usage() as u8);
    publication.extend_from_slice(&[0; 7]);
    assert_eq!(publication.len(), 456);
    let mut message = b"aos.sandbox.source-provider.catalog-publication.v1\0".to_vec();
    message.extend_from_slice(&publication);
    publication.extend_from_slice(&SigningKey::from_bytes(&[55; 32]).sign(&message).to_bytes());
    let mut receipt = Sha256::new();
    receipt.update(b"aos.sandbox.source-provider.catalog-publication-receipt.v1\0");
    receipt.update(&publication);
    CatalogHeadRecordV1 {
        revision: 1,
        provider: SourceProviderAuthorityV1::new([33; 16], 35, digest(36)).unwrap(),
        resource_namespace_digest: held.namespace_digest(),
        catalog_generation: held.generation(),
        catalog_digest: held.digest(),
        publisher_authority_id: publisher.authority_id(),
        publication_generation: 1,
        publication_receipt_digest: ObjectDigest::from_bytes(receipt.finalize().into()),
        predecessor_catalog_generation: 0,
        predecessor_catalog_digest: digest(0),
        catalog_floor_generation: held.generation(),
        catalog_floor_digest: held.digest(),
        publication_seconds: 500,
        publication_trust_generation: 1,
        publication_trust_digest: digest(88),
        publication_revocation_generation: 1,
        publication_revocation_digest: digest(10),
        publisher_signer: publisher,
        canonical_publication: publication,
    }
}

fn prototype(
    session_binding: ObjectDigest,
    boot_id: [u8; 16],
) -> NativeAcquireCompletionRecordV2 {
    let nonce = [1; 32];
    let issued = 500;
    let request_sequence = 2;
    let request_id = [3; 16];
    let acquisition_sequence = 4;

    let mut template = Vec::new();
    for tag in 1_u8..=27 {
        let value = match tag {
            1 => b"AOSMSEM1".to_vec(),
            2 => 1_u16.to_be_bytes().to_vec(),
            _ => vec![tag, tag + 1],
        };
        template.push(tag);
        template.extend_from_slice(&(value.len() as u32).to_be_bytes());
        template.extend_from_slice(&value);
    }
    let template_digest = prospective_mount_apply_template_digest_v1(&template).unwrap();
    let binding = b"native-requested-first-fixture".to_vec();
    let binding_digest = digest_logical_binding_bytes(&binding);
    let root = AcquireSourceRequestV1::new_v2(
        session_binding,
        request_sequence,
        request_id,
        acquisition_sequence,
        template,
        template_digest,
        SourceUseV1::MountCreate,
        [99; 16],
        boot_id,
        [7; 16],
        8,
        digest(9),
        binding,
        binding_digest,
        issued + 600,
        60,
        digest(10),
        false,
        0,
        false,
    )
    .unwrap();
    let key = SigningKey::from_bytes(&[51; 32]);
    let root_signer = SourceProviderSigningKeyV1::for_signing_key(
        [7; 16],
        8,
        digest(9),
        [11; 16],
        12,
        SourceProviderKeyUsageV1::RootMountRecord,
        &key,
    )
    .unwrap();
    let signed_root = sign_request(
        SourceProviderMethod::Acquire,
        encode_acquire_request(&root),
        root_signer,
        &key,
    )
    .unwrap();
    let snapshot = ZfsHeldSnapshotProofV1::new(
        [13; 32],
        14,
        15,
        16,
        17,
        [18; 16],
        19,
        digest(20),
        digest(21),
        digest(22),
    )
    .unwrap();
    let catalog = ProviderHeldSnapshotCatalogV1::new(
        23,
        digest(24),
        vec![
            ProviderHeldSnapshotRowV1::new(
                binding_digest,
                [25; 32],
                26,
                digest(27),
                28,
                digest(29),
                snapshot,
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let claims = StorageZfsHoldTransportRequestV1::new(
        1,
        nonce,
        source_provider_request_attempt_digest_v1(
            signed_root.signer(),
            SourceProviderMethod::Acquire,
            root.request_id(),
        ),
        [33; 16],
        root.holder_authority_id(),
        root.session_binding(),
        root.acquisition_id(),
        binding_digest,
        digest(34),
        issued,
        issued + 60,
        catalog,
    )
    .unwrap();
    let provider_key = SigningKey::from_bytes(&[54; 32]);
    let signer = SourceProviderSigningKeyV1::for_signing_key(
        [33; 16],
        35,
        digest(36),
        [37; 16],
        38,
        SourceProviderKeyUsageV1::ProviderOutcome,
        &provider_key,
    )
    .unwrap();
    let signed = SignedStorageNativeAcquireRequestV2::sign(
        StorageNativeAcquireRequestV2::new(claims, signed_root).unwrap(),
        signer,
        &provider_key,
    )
    .unwrap();
    let initial = RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
        root.boot_id(),
        issued,
        1_000_000_000,
    )
    .unwrap();
    let anchor = NativeAcquireClockAnchorV1::new_untrusted(initial, &signed).unwrap();
    NativeAcquireCompletionRecordV2::requested(signed, digest(39), anchor).unwrap()
}

pub(super) struct Fixture {
    pub(super) before: State,
    pub(super) applying: JournalTransaction,
    pub(super) requested: JournalTransaction,
    pub(super) initial_floor: OriginalSourceCapacityRecordV5,
}

fn root_prepared(
    native: &NativeAcquireCompletionRecordV2,
) -> aos_sandbox_source_provider_protocol::native_held_completion::frame::SignedNativeHeldControlV1 {
    let records = ROOT_NATIVE_WITNESS_FAMILIES_V1.map(|family| {
        let prefix: &[u8] = match family {
            NativeHeldRecordFamilyV1::RootSession => b"aos.mount.source-provider-session.v2\0",
            NativeHeldRecordFamilyV1::RootAttempt => b"aos.mount.source-provider-query-attempt.v2\0",
            NativeHeldRecordFamilyV1::RootAcquisition => b"aos.mount.source-acquisition.v2\0",
            NativeHeldRecordFamilyV1::RootHead => b"aos.mount.source-provider-head.v2\0",
            _ => unreachable!("fixed Root families"),
        };
        let mut key = prefix.to_vec();
        key.resize(family.key_bytes(), 91);
        NativeHeldByteWitnessV1::new(family, key, digest(92)).unwrap()
    });
    let generation = NativeHeldGenerationClaimV1 {
        generation: 1,
        digest: digest(93),
    };
    let witness = NativeHeldOwnerWitnessV1::Root(RootNativeHeldWitnessV1 {
        local_socket_cookie: 1,
        journal_sequence: 1,
        planning_sequence: 1,
        trust: generation,
        revocation: generation,
        provider_head: generation,
        provider_floor: generation,
        publication: digest(94),
        records,
    });
    let scope = NativeHeldScopeV1 {
        flight: native_held_flight_digest_v1(
            native.root_request_digest,
            digest(95),
            native.session_binding,
        ),
        original_source_session: native.session_binding,
        mount_attempt: digest(95),
        provider_attempt: digest(0),
        provider_acquisition: native.acquisition_id,
        original_root_request: native.root_request_digest,
        original_native_request: digest(0),
    };

    PreparedNativeHeldControlV1::new(
        NativeHeldControlKindV1::RootPrepared,
        scope,
        digest(0),
        vec![NativeHeldSectionV1::new(
            NativeHeldSectionTagV1::Witness,
            witness.to_canonical_bytes().unwrap(),
        )
        .unwrap()],
        NativeHeldSignerV1::SourceProvider(
            native
                .canonical_request
                .as_ref()
                .unwrap()
                .request()
                .signed_root_request()
                .signer()
                .clone(),
        ),
    )
    .unwrap()
    .with_signature([0xA1; 64])
}

pub(super) fn fixture() -> Fixture {
    let mut holder = session(40);
    holder.revision = 2;
    let prototype = prototype(holder.session_binding, holder.boot_id);
    let publication = catalog(&prototype);
    let head = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.source-provider.current-catalog-publication-head.v1\0")
            .chain_update(encode_catalog(&publication))
            .finalize()
            .into(),
    );
    let binding = NativeAcquireCatalogBindingV3::new(
        publication.resource_namespace_digest,
        publication.catalog_generation,
        publication.catalog_digest,
        publication.catalog_floor_generation,
        publication.catalog_floor_digest,
        head,
        ObjectDigest::from_bytes(Sha256::digest(&publication.canonical_publication).into()),
    )
    .unwrap();
    let old_native = prototype.canonical_request.as_ref().unwrap();
    let root = AcquireSourceRequestV1::new_native_v3(
        decode_acquire_request(old_native.request().signed_root_request().subject()).unwrap(),
        binding,
    )
    .unwrap();
    assert_eq!(root.node_id(), [99; 16]);
    assert_ne!(root.node_id(), holder.root_process_instance);

    let signed_root = sign_request(
        SourceProviderMethod::Acquire,
        encode_acquire_request(&root),
        holder.signers[1].clone(),
        &SigningKey::from_bytes(&[51; 32]),
    )
    .unwrap();
    let old_claims = old_native.request().claims();
    let claims = StorageZfsHoldTransportRequestV1::new(
        1,
        old_claims.attempt().0,
        old_claims.attempt().1,
        holder.provider.authority_id(),
        holder.holder.authority_id(),
        holder.session_binding,
        root.acquisition_id(),
        root.binding_digest(),
        head,
        500,
        560,
        old_claims.catalog().clone(),
    )
    .unwrap();
    let signed_native = SignedStorageNativeAcquireRequestV2::sign(
        StorageNativeAcquireRequestV2::new_native_v3(claims, signed_root.clone()).unwrap(),
        holder.signers[3].clone(),
        &SigningKey::from_bytes(&[54; 32]),
    )
    .unwrap();
    let intent = NormalizedAcquisitionIntentV1::from_original_acquire_request(
        &root,
        holder.provider.clone(),
        holder.holder.clone(),
        root.node_id(),
        holder.boot_id,
        holder.route_id,
        holder.route_generation,
        holder.route_digest,
        holder.resource_namespace_digest,
        holder.revocation_generation,
        holder.revocation_digest,
    )
    .unwrap();
    let attempt_digest = signed_native.request().claims().attempt().1;
    let attempt = AttemptRecordV1 {
        revision: 1,
        state: ProviderAttemptStateV1::Reserved,
        provider: holder.provider.clone(),
        holder: holder.holder.clone(),
        root_record_signer: holder.signers[1].clone(),
        method: SourceProviderMethod::Acquire,
        status: None,
        request_id: root.request_id(),
        signed_request_digest: digest_signed_request(&signed_root),
        typed_request_digest: digest_acquire_request(&root),
        operation_intent_digest: intent.digest(),
        acquisition_sequence: root.acquisition_sequence(),
        attempt_digest,
        session_binding: holder.session_binding,
        request_sequence: root.sequence(),
        response_sequence: None,
        deadline_seconds: root.deadline_seconds(),
        verified_at_seconds: 500,
        completed_at_seconds: None,
        current_valid_until_seconds: root.deadline_seconds(),
        proof_class_capabilities: 1,
        supports_recursive: false,
        supports_kernel_coupled: false,
        root_process_instance: holder.root_process_instance,
        provider_process_instance: holder.provider_process_instance,
        signer_set_commitment: holder.signer_set_commitment,
        recovery_predecessor_attempt_digest: None,
        recovery_predecessor_session_binding: None,
        recovery_fence_digest: None,
        recovery_fence_class: 0,
        recovery_revocation_generation: 0,
        recovery_revocation_digest: digest(0),
        signed_request_digest_again: digest_signed_request(&signed_root),
        response_digest: None,
        descriptor_commitment: empty_descriptor_set_commitment_v1(),
        result_digest: None,
        response_catalog_generation: 0,
        response_catalog_digest: digest(0),
        signed_request: signed_root.to_canonical_bytes(),
        completed_response: Vec::new(),
    };
    holder.pending_attempt_digest = Some(attempt_digest);
    let held_catalog = signed_native.request().claims().catalog();
    let (resource, _) = held_catalog
        .select_under_head(
            held_catalog.generation(),
            held_catalog.digest(),
            held_catalog.namespace_digest(),
            root.binding_digest(),
        )
        .unwrap();
    let backend = identity::acquire_native_dispatch_id_v2(
        intent.digest(),
        resource.catalog_generation(),
        resource.catalog_digest(),
        attempt_digest,
    );
    let effect = identity::acquire_effect_id_v1(root.acquisition_id(), attempt_digest).unwrap();
    let lineage = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.source-provider.acquire-lineage.v1\0")
            .chain_update(holder.provider.authority_id())
            .chain_update(holder.holder.authority_id())
            .chain_update(holder.session_binding.as_bytes())
            .chain_update(attempt_digest.as_bytes())
            .chain_update(root.acquisition_id().as_bytes())
            .chain_update(effect)
            .chain_update([0; 16])
            .chain_update([0; 32])
            .chain_update(backend)
            .finalize()
            .into(),
    );
    let acquisition = AcquisitionRecordV1 {
        revision: 1,
        state: ProviderAcquisitionStateV1::Applying,
        provider: holder.provider.clone(),
        holder: holder.holder.clone(),
        acquisition_id: root.acquisition_id(),
        acquisition_sequence: root.acquisition_sequence(),
        effect_id: effect,
        normalized_intent: intent,
        effect_attempt_digest: attempt_digest,
        current_attempt_digest: attempt_digest,
        lease_attempt_digest: None,
        lease_issue_generation: 0,
        lease_id: None,
        lease_digest: None,
        lease_history: Vec::new(),
        resource_namespace_digest: resource.resource_namespace_digest(),
        resource_id: resource.resource_id(),
        resource_generation: resource.resource_generation(),
        resource_digest: resource.resource_digest(),
        catalog_generation: resource.catalog_generation(),
        catalog_digest: resource.catalog_digest(),
        selection_generation: resource.selection_generation(),
        selection_digest: resource.selection_digest(),
        proof_class: 0,
        proof_digest: digest(0),
        resource_commitment: digest(0),
        backend_id: backend,
        backend_lineage_digest: lineage,
        native_no_dispatch_reservation_digest: None,
        backend_evidence: None,
        reopen_identity: None,
        source_root: None,
        release_effect_id: None,
        signed_lease: Vec::new(),
    };
    let mut authority = AuthorityHeadRecordV1 {
        revision: 1,
        state: ProviderAuthorityStateV1::Active,
        provider: holder.provider.clone(),
        trust_generation: 1,
        trust_digest: digest(88),
        revocation_generation: 1,
        revocation_digest: digest(10),
        valid_from_seconds: 499,
        valid_until_seconds: 1100,
        route_id: holder.route_id,
        route_generation: holder.route_generation,
        route_digest: holder.route_digest,
        resource_namespace_digest: holder.resource_namespace_digest,
        proof_class_capabilities: 1,
        supports_recursive: false,
        supports_kernel_coupled: false,
        provider_hello_signer: holder.signers[2].clone(),
        provider_outcome_signer: holder.signers[3].clone(),
        catalog_generation: publication.catalog_generation,
        catalog_digest: publication.catalog_digest,
        inventory_generation: 1,
        inventory_state_digest: digest(1),
        last_lease_issue_generation: 0,
        last_release_generation: 0,
        active_lease_count: 0,
    };
    let keys = [
        attempt_key(&AttemptKeyV1 {
            provider_id: holder.provider.authority_id(),
            holder_id: holder.holder.authority_id(),
            root_record_key_id: holder.signers[1].key_id(),
            method: SourceProviderMethod::Acquire as u8,
            request_id: root.request_id(),
        }),
        acquisition_key(&AcquisitionKeyV1 {
            provider_id: holder.provider.authority_id(),
            holder_id: holder.holder.authority_id(),
            acquisition_id: acquisition.acquisition_id,
        }),
        session_key(
            holder.provider.authority_id(),
            holder.holder.authority_id(),
        ),
        session_history_key(
            holder.provider.authority_id(),
            holder.holder.authority_id(),
            holder.session_binding,
        ),
    ];
    let values = [
        encode_attempt(&attempt),
        encode_acquisition(&acquisition),
        encode_session(&holder),
        encode_session_history(&holder),
    ];
    let mut rows = BTreeMap::from([
        (
            authority_key(holder.provider.authority_id()),
            encode_authority(&authority),
        ),
        (
            catalog_key(holder.provider.authority_id(), publication.catalog_generation),
            encode_catalog(&publication),
        ),
    ]);
    rows.extend(keys.iter().cloned().zip(values.iter().cloned()));
    let (inventory, count) = inventory_state_digest(
        holder.provider.authority_id(),
        publication.catalog_generation,
        publication.catalog_digest,
        rows.iter().map(|(key, value)| (key.as_slice(), value.as_slice())),
        1024,
    )
    .unwrap();
    authority.inventory_state_digest = inventory;
    authority.active_lease_count = count;
    rows.insert(
        authority_key(holder.provider.authority_id()),
        encode_authority(&authority),
    );

    let anchor = NativeAcquireClockAnchorV1::new_untrusted(
        prototype.original_clock.unwrap().initial(),
        &signed_native,
    )
    .unwrap();
    let native = NativeAcquireCompletionRecordV2::requested(
        signed_native.clone(),
        record_digest(&values[1]).unwrap(),
        anchor,
    )
    .unwrap();
    let root_prepared = root_prepared(&native);
    let families = [
        NativeHeldRecordFamilyV1::ProviderAttempt,
        NativeHeldRecordFamilyV1::ProviderAcquisition,
        NativeHeldRecordFamilyV1::ProviderHolder,
        NativeHeldRecordFamilyV1::ProviderHistory,
    ];
    let witnesses = std::array::from_fn(|index| {
        NativeHeldByteWitnessV1::new(
            families[index],
            keys[index].clone(),
            native_held_record_byte_digest_v1(families[index], &keys[index], &values[index])
                .unwrap(),
        )
        .unwrap()
    });
    let provenance = OriginalSourceProvenanceV5::new_untrusted(
        OriginalSourceProvenanceClaimsV5 {
            root_prepared: root_prepared.clone(),
            claims: signed_native.request().claims().clone(),
            initial: anchor.initial(),
            original_deadline: 600_000_000_000,
            narrowed_deadline: 60_000_000_000,
            journal_sequence: 1,
            configuration: digest(102),
            records: witnesses,
        },
    )
    .unwrap();
    let request = super::super::super::capacity_reservation::native_held::NativeHeldCapacityRequestV3 {
        purpose: NativeHeldCapacityPurposeV3::Provider,
        owner_id: Sha256::new()
            .chain_update(b"aos.sandbox.source-provider.native-dispatch-capacity-owner.v2\0")
            .chain_update(holder.provider.authority_id())
            .chain_update(holder.holder.authority_id())
            .chain_update(acquisition.acquisition_id.as_bytes())
            .finalize()
            .into(),
        owner_digest: *record_digest(&values[1]).unwrap().as_bytes(),
        operation_id: effect,
        artifact_digest: *attempt_digest.as_bytes(),
        checkpoint_digest: *digest_signed_request(&signed_root).as_bytes(),
        chain_head_digest: *holder.session_binding.as_bytes(),
        future_transactions: 20,
        terminal_records: 1000,
        terminal_bytes: 1_000_000_000,
        poison_records: 1000,
        poison_bytes: 1_000_000_000,
    };
    let initial_floor = OriginalSourceCapacityRecordV5::new(
        request,
        [30; 16],
        super::super::super::capacity_reservation::native_held::OriginalSourceCapacityBudgetsV5 {
            terminal_records: request.terminal_records,
            terminal_bytes: request.terminal_bytes,
            poison_records: request.poison_records,
            poison_bytes: request.poison_bytes,
        },
        provenance,
    )
    .unwrap();
    let mut applying_records: Vec<_> = keys
        .iter()
        .cloned()
        .zip(values)
        .map(|(key, value)| {
            JournalRecord::put(RecordNamespace::SourceProviderAuthority, key, value)
        })
        .collect();
    applying_records.push(initial_floor.to_journal_record().unwrap());
    let applying = JournalTransaction::new([30; 16], applying_records).unwrap();

    let suffix = NativeHeldCompletionSuffixV1::new(
        NativeHeldOwnerV1::Provider,
        0,
        root_prepared.scope().flight,
        None,
        vec![root_prepared],
    )
    .unwrap();
    let held = SourceNativeHeldCompletionRecordV1::new(native, suffix).unwrap();
    let held_record = JournalRecord::put(
        RecordNamespace::SourceProviderAuthority,
        aos_sandbox_source_provider_ledger::ledger::native_completion::native_completion_key_v2(
            acquisition.acquisition_id,
        ),
        held.to_canonical_bytes().unwrap(),
    );
    let floor_record = initial_floor.to_journal_record().unwrap();
    let width = floor_record.value().unwrap().len() as u64;
    let consumed = 611 + held_record.value().unwrap().len() as u64 + width;
    let mut remaining = request;
    remaining.future_transactions = 19;
    remaining.terminal_records -= 3;
    remaining.poison_records -= 3;
    remaining.terminal_bytes -= consumed;
    remaining.poison_bytes -= consumed;
    let next = OriginalSourceCapacityRecordV5::new(
        remaining,
        [30; 16],
        initial_floor.origin_budgets(),
        initial_floor.original_provenance().clone(),
    )
    .unwrap();
    let requested = JournalTransaction::new(
        [31; 16],
        vec![
            held_record,
            JournalRecord::delete(
                RecordNamespace::GlobalCapacityReservation,
                floor_record.key().to_vec(),
            ),
            next.to_journal_record().unwrap(),
        ],
    )
    .unwrap();

    let mut idle = holder;
    idle.revision = 1;
    idle.pending_attempt_digest = None;
    idle.next_request_sequence = root.sequence();
    idle.next_acquisition_sequence = root.acquisition_sequence();
    rows.remove(&keys[0]);
    rows.remove(&keys[1]);
    rows.insert(keys[2].clone(), encode_session(&idle));
    rows.insert(keys[3].clone(), encode_session_history(&idle));
    let before = rows
        .into_iter()
        .map(|(key, value)| {
            ((RecordNamespace::SourceProviderAuthority, key), value)
        })
        .collect();

    Fixture {
        before,
        applying,
        requested,
        initial_floor,
    }
}
