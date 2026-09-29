//! Canonical whole-graph DATA fixtures adapted from the existing native graph tests.
//!
//! Only pure codecs, cryptographic DATA and reducers are used. No Journal,
//! protected owner, live clock/FD, dispatch bridge, IO or runtime factory exists.
//! The existing runtime fixture cannot be imported across the acyclic Ledger
//! boundary; its canonical session/catalog/request construction is reused here.

use super::*;
use crate::ledger::native_completion::{
    NativeAcquireClockAnchorV1, NativeAcquireCompletionRecordV2,
};
use crate::ledger::{format::*, model::*};
use aos_sandbox_core::{RawClockProvenance, RawPairedClockSample};
use aos_sandbox_source_provider_protocol::*;
use ed25519_dalek::Signer as _;

fn digest(byte: u8) -> ObjectDigest {
    d(byte)
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

pub(super) fn session(nonce: u8) -> HolderSessionHeadRecordV1 {
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

fn requested_with_session(
    nonce: [u8; 32],
    issued: i64,
    session_binding: ObjectDigest,
) -> NativeAcquireCompletionRecordV2 {
    requested_with_boot(nonce, issued, session_binding, [6; 16])
}

fn requested_with_boot(
    nonce: [u8; 32],
    issued: i64,
    session_binding: ObjectDigest,
    boot_id: [u8; 16],
) -> NativeAcquireCompletionRecordV2 {
    requested_with_identity(nonce, issued, session_binding, boot_id, 2, [3; 16], 4)
}

fn requested_with_identity(
    nonce: [u8; 32],
    issued: i64,
    session_binding: ObjectDigest,
    boot_id: [u8; 16],
    request_sequence: u64,
    request_id: [u8; 16],
    acquisition_sequence: u64,
) -> NativeAcquireCompletionRecordV2 {
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
        [5; 16],
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

pub(super) fn prepared(
    requested: &NativeAcquireCompletionRecordV2,
) -> NativeAcquireCompletionRecordV2 {
    let descriptor = SourceRootObservationV1::new([6; 16], 72, 73, 74, true, true, true).unwrap();
    prepared_with_descriptor(requested, descriptor).0
}

fn prepared_with_descriptor(
    requested: &NativeAcquireCompletionRecordV2,
    descriptor: SourceRootObservationV1,
) -> (
    NativeAcquireCompletionRecordV2,
    VerifiedStorageNativeAcquireV3,
) {
    let signed = requested.canonical_request.as_ref().unwrap();
    let catalog = signed.request().claims().catalog();
    let (resource, snapshot) = catalog
        .select_under_head(
            catalog.generation(),
            catalog.digest(),
            catalog.namespace_digest(),
            requested.binding_digest,
        )
        .unwrap();
    let signer = StorageZfsHoldSignerV1::new([61; 16], 62, digest(63), [64; 16], 65).unwrap();
    let key = SigningKey::from_bytes(&[66; 32]);
    let head =
        StorageZfsHoldHeadV1::new(67, digest(68), 62, digest(63), 69, digest(70), digest(71))
            .unwrap();
    let receipt = StorageZfsHoldReceiptV1::new(
        requested.challenge,
        requested.attempt_digest,
        requested.binding_digest,
        resource,
        snapshot,
        head,
        requested.challenge_issued_seconds,
        requested.challenge_valid_until_seconds,
    )
    .unwrap();
    let unsigned = SignedStorageZfsHoldReceiptV1::new(receipt.clone(), signer, [0; 64]);
    let receipt = SignedStorageZfsHoldReceiptV1::new(
        receipt,
        signer,
        key.sign(&unsigned.signing_message()).to_bytes(),
    );
    let topology =
        storage_native_nonrecursive_topology_v1(signed, &receipt, &descriptor, 2, 75).unwrap();
    let acceptance = StorageNativeAcceptanceV3::new(
        [76; 16],
        signed.digest(),
        receipt.digest(),
        descriptor.clone(),
        topology,
    )
    .unwrap();
    let reply = StorageNativeAcquireReplyV3::new(
        SignedStorageNativeAcceptanceV3::sign(acceptance, signer, &key),
        receipt,
    )
    .unwrap();
    let original_key = SigningKey::from_bytes(&[51; 32]).verifying_key().to_bytes();
    let provider_key = SigningKey::from_bytes(&[54; 32]).verifying_key().to_bytes();
    let verified = reply
        .verify_for(StorageNativeAcquireVerificationV3 {
            request: signed,
            provider_signer: signed.signer(),
            provider_key: &provider_key,
            root_signer: signed.request().signed_root_request().signer(),
            root_key: &original_key,
            storage_verifier: StorageZfsHoldVerifierV1::new(signer, key.verifying_key().to_bytes())
                .unwrap(),
            expected_receipt: reply.receipt().receipt(),
            observed_descriptor: &descriptor,
            descriptor_roles: &[SourceProviderDescriptorRole::SourceRoot],
            now_seconds: requested.challenge_issued_seconds + 1,
        })
        .unwrap();
    (
        requested.prepare_accepted(reply, &verified).unwrap(),
        verified,
    )
}

#[derive(Clone)]
pub(super) struct Graph {
    pub(super) authority: AuthorityHeadRecordV1,
    pub(super) catalog: CatalogHeadRecordV1,
    pub(super) sessions: Vec<HolderSessionHeadRecordV1>,
    pub(super) attempts: Vec<AttemptRecordV1>,
    pub(super) acquisition: AcquisitionRecordV1,
    pub(super) native: NativeAcquireCompletionRecordV2,
}

impl Graph {
    pub(super) fn applying() -> Self {
        Self::applying_for_session(session(40), 2, [3; 16], 4, [1; 32])
    }

    pub(super) fn applying_for_session(
        mut session: HolderSessionHeadRecordV1,
        request_sequence: u64,
        request_id: [u8; 16],
        acquisition_sequence: u64,
        nonce: [u8; 32],
    ) -> Self {
        session.next_request_sequence = request_sequence + 1;
        session.next_acquisition_sequence = acquisition_sequence + 1;
        let prototype = requested_with_identity(
            nonce,
            500,
            session.session_binding,
            session.boot_id,
            request_sequence,
            request_id,
            acquisition_sequence,
        );
        let signed = prototype
            .canonical_request
            .as_ref()
            .unwrap()
            .request()
            .signed_root_request();
        let root = decode_acquire_request(signed.subject()).unwrap();
        let intent = crate::NormalizedAcquisitionIntentV1::from_acquire_request(
            &root,
            session.provider.clone(),
            session.holder.clone(),
            session.root_process_instance,
            session.boot_id,
            session.route_id,
            session.route_generation,
            session.route_digest,
            session.resource_namespace_digest,
            session.revocation_generation,
            session.revocation_digest,
        )
        .unwrap();
        let attempt = AttemptRecordV1 {
            revision: 1,
            state: ProviderAttemptStateV1::Reserved,
            provider: session.provider.clone(),
            holder: session.holder.clone(),
            root_record_signer: signed.signer().clone(),
            method: SourceProviderMethod::Acquire,
            status: None,
            request_id: root.request_id(),
            signed_request_digest: digest_signed_request(signed),
            typed_request_digest: digest_acquire_request(&root),
            operation_intent_digest: intent.digest(),
            acquisition_sequence: root.acquisition_sequence(),
            attempt_digest: prototype.attempt_digest,
            session_binding: session.session_binding,
            request_sequence: root.sequence(),
            response_sequence: None,
            deadline_seconds: root.deadline_seconds(),
            verified_at_seconds: 500,
            completed_at_seconds: None,
            current_valid_until_seconds: root.deadline_seconds(),
            proof_class_capabilities: 1,
            supports_recursive: false,
            supports_kernel_coupled: false,
            root_process_instance: session.root_process_instance,
            provider_process_instance: session.provider_process_instance,
            signer_set_commitment: session.signer_set_commitment,
            recovery_predecessor_attempt_digest: None,
            recovery_predecessor_session_binding: None,
            recovery_fence_digest: None,
            recovery_fence_class: 0,
            recovery_revocation_generation: 0,
            recovery_revocation_digest: digest(0),
            signed_request_digest_again: digest_signed_request(signed),
            response_digest: None,
            descriptor_commitment: empty_descriptor_set_commitment_v1(),
            result_digest: None,
            response_catalog_generation: 0,
            response_catalog_digest: digest(0),
            signed_request: signed.to_canonical_bytes(),
            completed_response: Vec::new(),
        };
        session.pending_attempt_digest = Some(attempt.attempt_digest);
        let catalog = catalog(&prototype);
        let held = prototype
            .canonical_request
            .as_ref()
            .unwrap()
            .request()
            .claims()
            .catalog();
        let (resource, _) = held
            .select_under_head(
                held.generation(),
                held.digest(),
                held.namespace_digest(),
                root.binding_digest(),
            )
            .unwrap();
        let backend = crate::identity::acquire_native_dispatch_id_v2(
            intent.digest(),
            held.generation(),
            held.digest(),
            attempt.attempt_digest,
        );
        let effect =
            crate::identity::acquire_effect_id_v1(root.acquisition_id(), attempt.attempt_digest)
                .unwrap();
        let mut acquisition = AcquisitionRecordV1 {
            revision: 1,
            state: ProviderAcquisitionStateV1::Applying,
            provider: session.provider.clone(),
            holder: session.holder.clone(),
            acquisition_id: root.acquisition_id(),
            acquisition_sequence: root.acquisition_sequence(),
            effect_id: effect,
            normalized_intent: intent,
            effect_attempt_digest: attempt.attempt_digest,
            current_attempt_digest: attempt.attempt_digest,
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
            backend_lineage_digest: digest(0),
            native_no_dispatch_reservation_digest: None,
            backend_evidence: None,
            reopen_identity: None,
            source_root: None,
            release_effect_id: None,
            signed_lease: Vec::new(),
        };
        acquisition.backend_lineage_digest =
            graph::original_lineage(&acquisition, session.session_binding);
        let native = NativeAcquireCompletionRecordV2::requested(
            request_for_publication(&prototype, &catalog),
            record_digest(&encode_acquisition(&acquisition)).unwrap(),
            prototype.original_clock.unwrap(),
        )
        .unwrap();
        let authority = AuthorityHeadRecordV1 {
            revision: 1,
            state: ProviderAuthorityStateV1::Active,
            provider: session.provider.clone(),
            trust_generation: 1,
            trust_digest: digest(88),
            revocation_generation: 1,
            revocation_digest: digest(10),
            valid_from_seconds: 499,
            valid_until_seconds: 1100,
            route_id: session.route_id,
            route_generation: session.route_generation,
            route_digest: session.route_digest,
            resource_namespace_digest: session.resource_namespace_digest,
            proof_class_capabilities: 1,
            supports_recursive: false,
            supports_kernel_coupled: false,
            provider_hello_signer: session.signers[2].clone(),
            provider_outcome_signer: session.signers[3].clone(),
            catalog_generation: catalog.catalog_generation,
            catalog_digest: catalog.catalog_digest,
            inventory_generation: 1,
            inventory_state_digest: digest(1),
            last_lease_issue_generation: 0,
            last_release_generation: 0,
            active_lease_count: 0,
        };
        let mut graph = Self {
            authority,
            catalog,
            sessions: vec![session],
            attempts: vec![attempt],
            acquisition,
            native,
        };
        graph.refresh_inventory();
        graph
    }

    pub(super) fn rows(&self) -> BTreeMap<Vec<u8>, Vec<u8>> {
        let mut rows = BTreeMap::from([
            (
                authority_key(self.authority.provider.authority_id()),
                encode_authority(&self.authority),
            ),
            (
                catalog_key(
                    self.catalog.provider.authority_id(),
                    self.catalog.catalog_generation,
                ),
                encode_catalog(&self.catalog),
            ),
            (
                acquisition_key(&AcquisitionKeyV1 {
                    provider_id: self.acquisition.provider.authority_id(),
                    holder_id: self.acquisition.holder.authority_id(),
                    acquisition_id: self.acquisition.acquisition_id,
                }),
                encode_acquisition(&self.acquisition),
            ),
            (
                crate::ledger::native_completion::native_completion_key_v2(
                    self.native.acquisition_id,
                ),
                encode_native_completion_v2(&self.native),
            ),
        ]);
        for session in &self.sessions {
            rows.insert(
                session_history_key(
                    session.provider.authority_id(),
                    session.holder.authority_id(),
                    session.session_binding,
                ),
                encode_session_history(session),
            );
        }
        let current = self.sessions.last().unwrap();
        rows.insert(
            session_key(
                current.provider.authority_id(),
                current.holder.authority_id(),
            ),
            encode_session(current),
        );
        for attempt in &self.attempts {
            rows.insert(
                attempt_key(&AttemptKeyV1 {
                    provider_id: attempt.provider.authority_id(),
                    holder_id: attempt.holder.authority_id(),
                    root_record_key_id: attempt.root_record_signer.key_id(),
                    method: attempt.method as u8,
                    request_id: attempt.request_id,
                }),
                encode_attempt(attempt),
            );
        }
        rows
    }

    pub(super) fn refresh_inventory(&mut self) {
        self.try_refresh_inventory().unwrap();
    }

    fn try_refresh_inventory(&mut self) -> Result<(), crate::ledger::LedgerFormatErrorV1> {
        let rows = self.rows();
        let (digest, count) = crate::ledger::reducer::inventory_state_digest(
            self.authority.provider.authority_id(),
            self.catalog.catalog_generation,
            self.catalog.catalog_digest,
            rows.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
            1024,
        )?;
        self.authority.inventory_state_digest = digest;
        self.authority.active_lease_count = count;
        Ok(())
    }
}

fn request_for_publication(
    original: &NativeAcquireCompletionRecordV2,
    publication: &CatalogHeadRecordV1,
) -> SignedStorageNativeAcquireRequestV2 {
    let signed = original.canonical_request.as_ref().unwrap();
    let claims = signed.request().claims();
    let commitment = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.source-provider.current-catalog-publication-head.v1\0")
            .chain_update(encode_catalog(publication))
            .finalize()
            .into(),
    );
    let next = StorageZfsHoldTransportRequestV1::new(
        claims.sequence(),
        claims.attempt().0,
        claims.attempt().1,
        claims.provider_acquisition().0,
        claims.holder_session().0,
        claims.holder_session().1,
        claims.provider_acquisition().1,
        claims.selection().0,
        commitment,
        claims.validity().0,
        claims.validity().1,
        claims.catalog().clone(),
    )
    .unwrap();
    SignedStorageNativeAcquireRequestV2::sign(
        StorageNativeAcquireRequestV2::new(next, signed.request().signed_root_request().clone())
            .unwrap(),
        signed.signer().clone(),
        &SigningKey::from_bytes(&[54; 32]),
    )
    .unwrap()
}

pub(super) fn completion_rows(
    rows: &BTreeMap<Vec<u8>, Vec<u8>>,
    before: &SourceNativeHeldCompletionRecordV1,
) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let keys = graph::companion_keys(before).unwrap();
    let DecodedRecordV1::Attempt(attempt) = decode_record(&keys[1], &rows[&keys[1]]).unwrap()
    else {
        panic!("actual Attempt");
    };
    let DecodedRecordV1::Acquisition(acquisition) =
        decode_record(&keys[2], &rows[&keys[2]]).unwrap()
    else {
        panic!("actual Acquisition");
    };
    let native = before.original.advance(Outer::Active).unwrap();
    let reply = native.accepted_reply.as_ref().unwrap();
    let receipt = reply.receipt().receipt();
    let resource = receipt.resource().clone();
    let snapshot = receipt.snapshot().clone();
    let proof = SourceProviderProofV1::ZfsHeldSnapshot {
        proof: snapshot.clone(),
        topology: reply.acceptance().acceptance().topology().clone(),
    };
    let provider_key = SigningKey::from_bytes(&[54; 32]);
    let provider_signer = native.canonical_request.as_ref().unwrap().signer().clone();
    let lease_id =
        crate::identity::lease_id_v1(acquisition.acquisition_id, 1, acquisition.backend_id)
            .unwrap();
    let lease = sign_export_lease(
        SourceExportLeaseV1::new(
            lease_id,
            attempt.request_id,
            attempt.typed_request_digest,
            acquisition.holder.authority_id(),
            acquisition.holder.authority_generation(),
            acquisition.holder.authority_digest(),
            acquisition.provider.clone(),
            resource.clone(),
            proof.clone(),
            native.binding_digest,
            501,
            550,
            digest(10),
        )
        .unwrap(),
        provider_signer.clone(),
        &provider_key,
    )
    .unwrap();
    let root = native.original_root;
    let provider_receipt = sign_provider_receipt(
        SourceProviderReceiptV1::new(
            attempt.request_id,
            attempt.typed_request_digest,
            acquisition.acquisition_id,
            attempt.provider_process_instance,
            digest_signed_export_lease(&lease),
            lease.to_canonical_bytes(),
            SourceProviderDescriptorRole::SourceRoot,
            root.kernel_boot_id,
            root.device,
            root.inode,
            root.unique_mount_id,
            digest_provider_proof(&proof),
        )
        .unwrap(),
        provider_signer.clone(),
        &provider_key,
    )
    .unwrap();
    let result = Some(provider_receipt.to_canonical_bytes());
    let status = SourceProviderResponseStatusV1::new(
        SourceProviderMethod::Acquire,
        attempt.request_id,
        attempt.signed_request_digest,
        SourceProviderStatus::Complete,
        attempt.provider_process_instance,
        attempt.session_binding,
        1,
        response_result_digest_v1(
            SourceProviderMethod::Acquire,
            SourceProviderStatus::Complete,
            result.as_deref(),
        ),
        native.descriptor_commitment,
    )
    .unwrap();
    let response = encode_acquire_response(
        &AcquireSourceResponseV1::new(
            sign_response_status(status, provider_signer, &provider_key).unwrap(),
            result,
        )
        .unwrap(),
    );
    let evidence = crate::BackendEvidenceV1::new_acquired(
        crate::BackendEvidenceClassV1::ZfsHeldSnapshot,
        [61; 16],
        62,
        digest(63),
        67,
        reply.receipt().digest(),
        Vec::new(),
    )
    .unwrap();
    let reopen = crate::ReopenIdentityV1::new(
        crate::BackendEvidenceClassV1::ZfsHeldSnapshot,
        acquisition.backend_id,
        62,
        digest(63),
        resource.resource_id(),
        resource.resource_generation(),
        resource.resource_digest(),
        snapshot.storage_handle(),
        snapshot.storage_version(),
        snapshot.active_hold_digest(),
    )
    .unwrap();
    let patch = crate::AcquireCompletionPatchV1::new(
        keys[2].clone(),
        attempt.attempt_digest,
        1,
        digest_provider_proof(&proof),
        provider_resource_commitment_v1(&resource, digest_provider_proof(&proof)),
        Some(evidence.encode()),
        Some(reopen.encode().to_vec()),
        root,
    )
    .unwrap();
    let plan = crate::AcquireCompletionPlanV1::new(keys[1].clone(), patch, 1024)
        .unwrap()
        .with_native_completion(native.clone())
        .unwrap();
    let suffix = NativeHeldCompletionSuffixV1::new(
        Owner::Provider,
        4,
        before.suffix.flight(),
        None,
        before.suffix.controls().to_vec(),
    )
    .unwrap();
    let record = SourceNativeHeldCompletionRecordV1::new(native, suffix).unwrap();
    let finalized = crate::ledger::completion::finalize_native_held_complete(
        rows, plan, &record, response, lease, 501,
    )
    .unwrap();
    let mut after = rows.clone();
    for (key, value) in finalized.mutations() {
        after.insert(key.clone(), value.clone().unwrap());
    }
    after
}
