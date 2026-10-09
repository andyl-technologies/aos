//! Canonical whole-graph replay and protected native floor retention.
//!
//! Unlike the width-only capacity projections, these fixtures retain signed
//! HELLO/request/lease/response artifacts and pass the strict Ledger graph
//! validator before the actual capacity owner is checked. They do not mint a
//! protected runtime configuration, an FD, or a native terminal capability.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt as _;

use aos_sandbox::{Journal, JournalLimits, JournalRecord};
use aos_sandbox_source_provider_ledger::ledger::format::*;
use aos_sandbox_source_provider_ledger::ledger::model::*;
use aos_sandbox_source_provider_ledger::{
    BackendEvidenceClassV1, BackendEvidenceV1, ReopenIdentityV1,
};
use aos_sandbox_source_provider_protocol::*;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::Digest as _;

use super::*;
use crate::ledger::native_completion::{
    NativeAcquireCompletionRecordV2, NativeAcquireCompletionStateV2,
};
use crate::native_completion::{fixture_prepared, fixture_requested};

#[path = "native_v3_admission_tests.rs"]
mod native_v3_admission_tests;

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

#[derive(Clone)]
struct Graph {
    authority: AuthorityHeadRecordV1,
    catalog: CatalogHeadRecordV1,
    sessions: Vec<HolderSessionHeadRecordV1>,
    attempts: Vec<AttemptRecordV1>,
    acquisition: AcquisitionRecordV1,
    native: NativeAcquireCompletionRecordV2,
    release: Option<ReleaseRecordV1>,
}

impl Graph {
    fn applying() -> Self {
        let mut session = session(40);
        let prototype = fixture_requested([1; 32], 500, session.session_binding);
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
        let backend = aos_sandbox_source_provider_ledger::identity::acquire_native_dispatch_id_v2(
            intent.digest(),
            held.generation(),
            held.digest(),
            attempt.attempt_digest,
        );
        let effect = aos_sandbox_source_provider_ledger::identity::acquire_effect_id_v1(
            root.acquisition_id(),
            attempt.attempt_digest,
        )
        .unwrap();
        let plan = crate::AcquirePlanV1 {
            provider_id: session.provider.authority_id(),
            holder_id: session.holder.authority_id(),
            session_binding: session.session_binding,
            attempt_digest: attempt.attempt_digest,
            acquisition_id: root.acquisition_id(),
            effect_id: effect,
            normalized_intent_digest: intent.digest(),
            kernel_coupled: false,
            backend_id: backend,
        };
        let acquisition = AcquisitionRecordV1 {
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
            backend_lineage_digest: plan.lineage_digest(),
            native_no_dispatch_reservation_digest: None,
            backend_evidence: None,
            reopen_identity: None,
            source_root: None,
            release_effect_id: None,
            signed_lease: Vec::new(),
        };
        let native = NativeAcquireCompletionRecordV2::requested(
            prototype.canonical_request.clone().unwrap(),
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
            release: None,
        };
        graph.refresh_inventory();
        graph
    }

    fn rows(&self) -> BTreeMap<Vec<u8>, Vec<u8>> {
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
        if let Some(release) = &self.release {
            rows.insert(
                release_key(&ReleaseKeyV1 {
                    provider_id: release.provider.authority_id(),
                    holder_id: release.holder.authority_id(),
                    acquisition_id: release.acquisition_id,
                }),
                encode_release(release),
            );
        }
        rows
    }

    fn refresh_inventory(&mut self) {
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

    fn active(&mut self) {
        let prepared = if self.native.state == NativeAcquireCompletionStateV2::Requested {
            fixture_prepared(&self.native)
        } else {
            self.native.clone()
        };
        let reply = prepared.accepted_reply.as_ref().unwrap();
        let receipt = reply.receipt().receipt();
        let resource = receipt.resource().clone();
        let snapshot = receipt.snapshot().clone();
        let proof = SourceProviderProofV1::ZfsHeldSnapshot {
            proof: snapshot.clone(),
            topology: reply.acceptance().acceptance().topology().clone(),
        };
        let attempt = &mut self.attempts[0];
        let lease_id = aos_sandbox_source_provider_ledger::identity::lease_id_v1(
            self.acquisition.acquisition_id,
            1,
            self.acquisition.backend_id,
        )
        .unwrap();
        let key = SigningKey::from_bytes(&[54; 32]);
        let lease = sign_export_lease(
            SourceExportLeaseV1::new(
                lease_id,
                attempt.request_id,
                attempt.typed_request_digest,
                self.acquisition.holder.authority_id(),
                self.acquisition.holder.authority_generation(),
                self.acquisition.holder.authority_digest(),
                self.acquisition.provider.clone(),
                resource.clone(),
                proof.clone(),
                prepared.binding_digest,
                501,
                550,
                digest(10),
            )
            .unwrap(),
            self.sessions[0].signers[3].clone(),
            &key,
        )
        .unwrap();
        let root = prepared.original_root;
        let provider_receipt = sign_provider_receipt(
            SourceProviderReceiptV1::new(
                attempt.request_id,
                attempt.typed_request_digest,
                self.acquisition.acquisition_id,
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
            self.sessions[0].signers[3].clone(),
            &key,
        )
        .unwrap();
        complete_attempt(
            attempt,
            SourceProviderStatus::Complete,
            Some(provider_receipt.to_canonical_bytes()),
            self.sessions[0].signers[3].clone(),
            1,
            501,
            prepared.descriptor_commitment,
        );
        let acquisition = &mut self.acquisition;
        acquisition.revision += 1;
        acquisition.state = ProviderAcquisitionStateV1::Active;
        acquisition.lease_attempt_digest = Some(attempt.attempt_digest);
        acquisition.lease_issue_generation = 1;
        acquisition.lease_id = Some(lease_id);
        acquisition.lease_digest = Some(digest_signed_export_lease(&lease));
        acquisition.lease_history.push(LeaseLineageV1 {
            issue_generation: 1,
            lease_id,
            lease_digest: digest_signed_export_lease(&lease),
            attempt_digest: attempt.attempt_digest,
        });
        acquisition.proof_class = 1;
        acquisition.proof_digest = digest_provider_proof(&proof);
        acquisition.resource_commitment =
            provider_resource_commitment_v1(&resource, acquisition.proof_digest);
        acquisition.backend_evidence = Some(
            BackendEvidenceV1::new_acquired(
                BackendEvidenceClassV1::ZfsHeldSnapshot,
                [61; 16],
                62,
                digest(63),
                67,
                reply.receipt().digest(),
                Vec::new(),
            )
            .unwrap(),
        );
        acquisition.reopen_identity = Some(
            ReopenIdentityV1::new(
                BackendEvidenceClassV1::ZfsHeldSnapshot,
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
            .unwrap(),
        );
        acquisition.source_root = Some(root);
        acquisition.signed_lease = lease.to_canonical_bytes();
        self.native = prepared
            .advance(NativeAcquireCompletionStateV2::Active)
            .unwrap();
        self.sessions[0].revision += 1;
        self.sessions[0].pending_attempt_digest = None;
        self.sessions[0].last_completed_attempt_digest = Some(attempt.attempt_digest);
        self.sessions[0].next_response_sequence = 2;
        self.authority.revision += 1;
        self.authority.inventory_generation += 1;
        self.authority.last_lease_issue_generation = 1;
        self.refresh_inventory();
    }

    fn supersede_session(&mut self) {
        let original = self.sessions.last().unwrap();
        let mut next = session(45);
        next.session_generation = original.session_generation + 1;
        next.predecessor_session_binding = Some(original.session_binding);
        next.supersession_evidence_digest = Some(digest(92));
        self.sessions.push(next);
    }

    fn releasing(&mut self) {
        self.native = self
            .native
            .advance(NativeAcquireCompletionStateV2::CleanupRequired)
            .unwrap();
        let session = self.sessions.last_mut().unwrap();
        let lease_id = self.acquisition.lease_id.unwrap();
        let lease_digest = self.acquisition.lease_digest.unwrap();
        let root = ReleaseSourceRequestV1::new(
            session.session_binding,
            3,
            [93; 16],
            self.acquisition.acquisition_id,
            self.acquisition.holder.authority_id(),
            self.acquisition.holder.authority_generation(),
            self.acquisition.holder.authority_digest(),
            lease_id,
            lease_digest,
            1100,
        )
        .unwrap();
        let signed = sign_request(
            SourceProviderMethod::Release,
            encode_release_request(&root),
            session.signers[1].clone(),
            &SigningKey::from_bytes(&[51; 32]),
        )
        .unwrap();
        let mut attempt = self.attempts[0].clone();
        attempt.revision = 1;
        attempt.state = ProviderAttemptStateV1::Reserved;
        attempt.method = SourceProviderMethod::Release;
        attempt.status = None;
        attempt.request_id = root.request_id();
        attempt.signed_request_digest = digest_signed_request(&signed);
        attempt.signed_request_digest_again = attempt.signed_request_digest;
        attempt.typed_request_digest = digest_release_request(&root);
        attempt.operation_intent_digest = source_provider_release_intent_digest_v1(&root);
        attempt.attempt_digest = source_provider_request_attempt_digest_v1(
            signed.signer(),
            SourceProviderMethod::Release,
            root.request_id(),
        );
        attempt.session_binding = session.session_binding;
        attempt.request_sequence = 3;
        attempt.response_sequence = None;
        attempt.verified_at_seconds = 502;
        attempt.completed_at_seconds = None;
        attempt.response_digest = None;
        attempt.result_digest = None;
        attempt.descriptor_commitment = empty_descriptor_set_commitment_v1();
        attempt.signed_request = signed.to_canonical_bytes();
        attempt.completed_response.clear();
        session.revision += 1;
        session.next_request_sequence = 4;
        session.pending_attempt_digest = Some(attempt.attempt_digest);
        let effect = aos_sandbox_source_provider_ledger::identity::release_effect_id_v1(
            self.acquisition.acquisition_id,
            attempt.attempt_digest,
            1,
        )
        .unwrap();
        let plan = crate::ReleasePlanV1 {
            provider_id: attempt.provider.authority_id(),
            holder_id: attempt.holder.authority_id(),
            session_binding: attempt.session_binding,
            attempt_digest: attempt.attempt_digest,
            acquisition_id: self.acquisition.acquisition_id,
            effect_id: effect,
            lease_id,
            lease_digest,
            backend_id: self.acquisition.backend_id,
            acquired_evidence: self.acquisition.backend_evidence.clone().unwrap(),
        };
        self.acquisition.revision += 1;
        self.acquisition.state = ProviderAcquisitionStateV1::Releasing;
        self.acquisition.current_attempt_digest = attempt.attempt_digest;
        self.acquisition.release_effect_id = Some(effect);
        self.release = Some(ReleaseRecordV1 {
            revision: 1,
            state: ProviderReleaseStateV1::Intent,
            provider: attempt.provider.clone(),
            holder: attempt.holder.clone(),
            acquisition_id: self.acquisition.acquisition_id,
            acquisition_sequence: self.acquisition.acquisition_sequence,
            lease_id,
            lease_digest,
            effect_id: effect,
            release_generation: 1,
            effect_attempt_digest: attempt.attempt_digest,
            attempt_digest: attempt.attempt_digest,
            backend_id: self.acquisition.backend_id,
            backend_lineage_digest: plan.lineage_digest(),
            backend_evidence: None,
            release_observation_digest: None,
            released_seconds: None,
            receipt_digest: None,
            signed_receipt: Vec::new(),
            acquisition_record_digest: record_digest(&encode_acquisition(&self.acquisition))
                .unwrap(),
        });
        self.attempts.push(attempt);
        self.authority.revision += 1;
        self.authority.inventory_generation += 1;
        self.authority.last_release_generation = 1;
        self.refresh_inventory();
    }

    fn faulted(&mut self) {
        // Preserve the exact three-row record_backend_conflict projection.
        self.acquisition.revision += 1;
        self.acquisition.state = ProviderAcquisitionStateV1::Faulted;
        if let Some(release) = &mut self.release {
            release.revision += 1;
            release.acquisition_record_digest =
                record_digest(&encode_acquisition(&self.acquisition)).unwrap();
        }
        self.authority.revision += 1;
        self.authority.state = ProviderAuthorityStateV1::AcquireClosed;
        self.authority.inventory_generation += 1;
        self.refresh_inventory();
    }

    fn released(&mut self) {
        let release = self.release.as_mut().unwrap();
        let attempt = self.attempts.last_mut().unwrap();
        let session = self.sessions.last_mut().unwrap();
        let receipt = sign_release_receipt(
            SourceReleaseReceiptV1::new(
                attempt.request_id,
                attempt.typed_request_digest,
                release.lease_id,
                release.lease_digest,
                release.provider.clone(),
                attempt.provider_process_instance,
                release.release_generation,
                503,
            )
            .unwrap(),
            session.signers[3].clone(),
            &SigningKey::from_bytes(&[54; 32]),
        )
        .unwrap();
        // Structural tombstone fixtures also cover an already immutable
        // Pending/Unavailable response; later effect progression cannot rewrite it.
        if attempt.state == ProviderAttemptStateV1::Reserved {
            complete_attempt(
                attempt,
                SourceProviderStatus::Complete,
                Some(receipt.to_canonical_bytes()),
                session.signers[3].clone(),
                session.next_response_sequence,
                503,
                empty_descriptor_set_commitment_v1(),
            );
            session.revision += 1;
            session.pending_attempt_digest = None;
            session.last_completed_attempt_digest = Some(attempt.attempt_digest);
            session.next_response_sequence += 1;
        }
        let acquired = self.acquisition.backend_evidence.as_ref().unwrap();
        let evidence = BackendEvidenceV1::new_released(
            acquired.class(),
            acquired.backend_authority_id(),
            acquired.backend_generation(),
            acquired.backend_digest(),
            acquired.observation_generation() + 1,
            digest(94),
            acquired.observation_generation(),
            acquired.observation_digest(),
            Vec::new(),
        )
        .unwrap();
        self.acquisition.revision += 1;
        self.acquisition.state = ProviderAcquisitionStateV1::Released;
        release.revision += 1;
        release.state = ProviderReleaseStateV1::Tombstone;
        release.release_observation_digest = Some(evidence.observation_digest());
        release.backend_evidence = Some(evidence);
        release.released_seconds = Some(503);
        release.receipt_digest = Some(digest_signed_release_receipt(&receipt));
        release.signed_receipt = receipt.to_canonical_bytes();
        release.acquisition_record_digest =
            record_digest(&encode_acquisition(&self.acquisition)).unwrap();
        self.authority.revision += 1;
        self.authority.inventory_generation += 1;
        self.refresh_inventory();
    }

    fn pending(&mut self) {
        let attempt = &mut self.attempts[0];
        complete_attempt(
            attempt,
            SourceProviderStatus::Pending,
            None,
            self.sessions[0].signers[3].clone(),
            1,
            501,
            empty_descriptor_set_commitment_v1(),
        );
        self.acquisition.revision += 1;
        self.acquisition.state = ProviderAcquisitionStateV1::Pending;
        self.sessions[0].revision += 1;
        self.sessions[0].pending_attempt_digest = None;
        self.sessions[0].last_completed_attempt_digest = Some(attempt.attempt_digest);
        self.sessions[0].next_response_sequence = 2;
    }
}

fn complete_attempt(
    attempt: &mut AttemptRecordV1,
    status: SourceProviderStatus,
    result: Option<Vec<u8>>,
    signer: SourceProviderSigningKeyV1,
    sequence: u64,
    completed: i64,
    descriptor: ObjectDigest,
) {
    let result_digest = response_result_digest_v1(attempt.method, status, result.as_deref());
    let subject = SourceProviderResponseStatusV1::new(
        attempt.method,
        attempt.request_id,
        attempt.signed_request_digest,
        status,
        attempt.provider_process_instance,
        attempt.session_binding,
        sequence,
        result_digest,
        descriptor,
    )
    .unwrap();
    let signed = sign_response_status(subject, signer, &SigningKey::from_bytes(&[54; 32])).unwrap();
    let bytes = match attempt.method {
        SourceProviderMethod::Acquire => {
            encode_acquire_response(&AcquireSourceResponseV1::new(signed, result).unwrap())
        }
        SourceProviderMethod::Release => ReleaseSourceResponseProfileV2::from_parts(signed, result)
            .unwrap()
            .to_canonical_bytes(),
        _ => panic!("unexpected fixture method"),
    };
    attempt.revision += 1;
    attempt.state = ProviderAttemptStateV1::Completed;
    attempt.status = Some(status);
    attempt.response_sequence = Some(sequence);
    attempt.completed_at_seconds = Some(completed);
    attempt.response_digest = Some(provider_response_artifact_digest_v1(attempt.method, &bytes));
    attempt.result_digest = Some(result_digest);
    attempt.descriptor_commitment = descriptor;
    attempt.completed_response = bytes;
}

fn open(directory: &std::path::Path) -> Journal {
    Journal::open_protected_at_uid(
        directory,
        "native-whole-graph.journal",
        JournalLimits::default(),
        rustix::process::geteuid().as_raw(),
    )
    .unwrap()
    .0
}

fn recover_graph(
    owner: &ProtectedJournalAuthority<'_>,
) -> Result<RecoveredProviderLedgerV1, ProviderLedgerError> {
    let rows: Vec<_> = owner
        .records()?
        .map(|(k, v)| (k.to_vec(), v.to_vec()))
        .collect();
    recover_rows(rows)
}

fn recover_rows(
    rows: Vec<(Vec<u8>, Vec<u8>)>,
) -> Result<RecoveredProviderLedgerV1, ProviderLedgerError> {
    aos_sandbox_source_provider_ledger::validate_prospective_records(
        rows.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
    )
    .map_err(crate::transaction::map_pure_ledger_error)?;
    let mut authority = None;
    let mut catalog_history = BTreeMap::new();
    let mut sessions = BTreeMap::new();
    let mut session_history = BTreeMap::new();
    let mut attempts = BTreeMap::new();
    let mut acquisitions = BTreeMap::new();
    let mut releases = BTreeMap::new();
    let mut native_completions = BTreeMap::new();
    for (key, value) in rows {
        match decode_record(&key, &value).map_err(crate::transaction::map_pure_ledger_error)? {
            DecodedRecordV1::Authority(row) => authority = Some(row),
            DecodedRecordV1::Catalog(row) => {
                catalog_history.insert(row.catalog_generation, row);
            }
            DecodedRecordV1::Session(row) => {
                sessions.insert(
                    (row.provider.authority_id(), row.holder.authority_id()),
                    row,
                );
            }
            DecodedRecordV1::SessionHistory(row) => {
                session_history.insert(
                    (
                        row.provider.authority_id(),
                        row.holder.authority_id(),
                        row.session_binding,
                    ),
                    row,
                );
            }
            DecodedRecordV1::Attempt(row) => {
                attempts.insert(
                    AttemptKeyV1 {
                        provider_id: row.provider.authority_id(),
                        holder_id: row.holder.authority_id(),
                        root_record_key_id: row.root_record_signer.key_id(),
                        method: row.method as u8,
                        request_id: row.request_id,
                    },
                    row,
                );
            }
            DecodedRecordV1::Acquisition(row) => {
                acquisitions.insert(
                    AcquisitionKeyV1 {
                        provider_id: row.provider.authority_id(),
                        holder_id: row.holder.authority_id(),
                        acquisition_id: row.acquisition_id,
                    },
                    row,
                );
            }
            DecodedRecordV1::Release(row) => {
                releases.insert(
                    ReleaseKeyV1 {
                        provider_id: row.provider.authority_id(),
                        holder_id: row.holder.authority_id(),
                        acquisition_id: row.acquisition_id,
                    },
                    row,
                );
            }
            DecodedRecordV1::NativeCompletion(row) => {
                native_completions.insert(row.acquisition_id, row);
            }
        }
    }
    let authority = authority.unwrap();
    Ok(RecoveredProviderLedgerV1 {
        catalog: catalog_history[&authority.catalog_generation].clone(),
        authority,
        catalog_history,
        sessions,
        session_history,
        attempts,
        acquisitions,
        releases,
        native_completions,
        recovery_work: Vec::new(),
    })
}

fn transaction(id: u8, rows: BTreeMap<Vec<u8>, Vec<u8>>) -> JournalTransaction {
    JournalTransaction::new(
        [id; 16],
        rows.into_iter()
            .map(|(key, value)| {
                JournalRecord::put(RecordNamespace::SourceProviderAuthority, key, value)
            })
            .collect(),
    )
    .unwrap()
}

fn admit(
    owner: &mut ProtectedJournalAuthority<'_>,
    graph: &Graph,
) -> aos_sandbox::GlobalCapacityReservationV1 {
    admit_rows(owner, graph, graph.rows())
}

fn admit_rows(
    owner: &mut ProtectedJournalAuthority<'_>,
    graph: &Graph,
    rows: BTreeMap<Vec<u8>, Vec<u8>>,
) -> aos_sandbox::GlobalCapacityReservationV1 {
    aos_sandbox_source_provider_ledger::validate_prospective_records(
        rows.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
    )
    .unwrap();
    let prepared = owner
        .prepare_global_capacity_reservation_v1(
            request(
                &graph.acquisition,
                &graph.attempts[0],
                &graph.sessions[0],
                None,
            )
            .unwrap(),
            [100; 16],
        )
        .unwrap();
    let mut records = transaction(100, rows).records().to_vec();
    records.push(prepared.record().clone());
    let admission = JournalTransaction::new([100; 16], records).unwrap();
    let preflight = owner
        .preflight_global_capacity_reservation_v1(&prepared, &admission)
        .unwrap();
    let (_, reservation) = owner
        .commit_global_capacity_reservation_v1(&preflight, prepared, &admission)
        .unwrap();
    validate_set(owner, &recover_graph(owner).unwrap()).unwrap();
    reservation
}

fn commit_graph(owner: &mut ProtectedJournalAuthority<'_>, id: u8, graph: &Graph) {
    let current: Vec<_> = owner
        .records()
        .unwrap()
        .map(|(k, v)| (k.to_vec(), v.to_vec()))
        .collect();
    let next = graph.rows();
    aos_sandbox_source_provider_ledger::validate_prospective_transition(
        current.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
        next.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
    )
    .unwrap();
    // Apply only changed rows, as the real owner does; cleanup is marker-only.
    let previous: BTreeMap<_, _> = current.into_iter().collect();
    let mutations = next
        .into_iter()
        .filter(|(key, value)| previous.get(key) != Some(value))
        .collect();
    owner.commit(&transaction(id, mutations)).unwrap();
}

fn admit_release_suffix(
    owner: &mut ProtectedJournalAuthority<'_>,
    id: u8,
    graph: &Graph,
    require_active_cas: bool,
) -> aos_sandbox::GlobalCapacityReservationV1 {
    let current: BTreeMap<_, _> = owner
        .records()
        .unwrap()
        .map(|(key, value)| (key.to_vec(), value.to_vec()))
        .collect();
    let next = graph.rows();
    if require_active_cas {
        crate::ledger::native_completion::release_fence::validate_native_release_admission_v1(
            &current, &next,
        )
        .unwrap();
    } else {
        aos_sandbox_source_provider_ledger::validate_prospective_transition(
            current
                .iter()
                .map(|(key, value)| (key.as_slice(), value.as_slice())),
            next.iter()
                .map(|(key, value)| (key.as_slice(), value.as_slice())),
        )
        .unwrap();
    }
    let mutations = next
        .into_iter()
        .filter(|(key, value)| current.get(key) != Some(value))
        .collect::<BTreeMap<_, _>>();
    let mut rows = transaction(id, mutations).records().to_vec();
    // Decode the canonical prospective graph through the same helper before
    // binding the capacity request; no projected dummy acquisition is used.
    let decoded = graph_recovered(graph);
    let request =
        crate::native_release_capacity::fixture_request(&decoded, graph.acquisition.acquisition_id)
            .unwrap();
    let capacity = owner
        .prepare_global_capacity_reservation_v1(request, [id; 16])
        .unwrap();
    rows.push(capacity.record().clone());
    if require_active_cas {
        assert_eq!(rows.len(), 8);
    }
    let admission = JournalTransaction::new([id; 16], rows).unwrap();
    let preflight = owner
        .preflight_global_capacity_reservation_v1(&capacity, &admission)
        .unwrap();
    let (_, retained) = owner
        .commit_global_capacity_reservation_v1(&preflight, capacity, &admission)
        .unwrap();
    validate_set(owner, &recover_graph(owner).unwrap()).unwrap();
    retained
}

// Reuse the hostile decoder rather than hand-assembling a model projection.
// An isolated protected journal authenticates storage/readback, not signatures
// or installed runtime configuration; those qualifications remain separate.
fn graph_recovered(graph: &Graph) -> RecoveredProviderLedgerV1 {
    recover_rows(graph.rows().into_iter().collect()).unwrap()
}

fn complete_release_status_suffix(
    owner: &mut ProtectedJournalAuthority<'_>,
    id: u8,
    graph: &mut Graph,
    status: SourceProviderStatus,
) {
    complete_release_result_suffix(owner, id, graph, status, None);
}

fn complete_release_result_suffix(
    owner: &mut ProtectedJournalAuthority<'_>,
    id: u8,
    graph: &mut Graph,
    status: SourceProviderStatus,
    result: Option<Vec<u8>>,
) {
    let before = recover_graph(owner).unwrap();
    let capacity = crate::native_release_capacity::exact_reservation(
        owner,
        &before,
        graph.acquisition.acquisition_id,
    )
    .unwrap();
    let mut completed = graph.attempts.last().unwrap().clone();
    let session = graph.sessions.last().unwrap();
    complete_attempt(
        &mut completed,
        status,
        result,
        session.signers[3].clone(),
        session.next_response_sequence,
        503,
        empty_descriptor_set_commitment_v1(),
    );
    let plan = aos_sandbox_source_provider_ledger::ReleaseStatusCompletionPlanV1::new(attempt_key(
        &AttemptKeyV1 {
            provider_id: completed.provider.authority_id(),
            holder_id: completed.holder.authority_id(),
            root_record_key_id: completed.root_record_signer.key_id(),
            method: SourceProviderMethod::Release as u8,
            request_id: completed.request_id,
        },
    ))
    .unwrap();
    let current = graph.rows();
    let finalized = plan
        .finalize(
            current
                .iter()
                .map(|(key, value)| (key.as_slice(), value.as_slice())),
            completed.completed_response.clone(),
            None,
            503,
        )
        .unwrap();
    let (mutations, _) = finalized.into_parts();
    assert_eq!(mutations.len(), 3);
    let mut rows = Vec::new();
    let mut next = current;
    for (key, value) in mutations {
        let value = value.unwrap();
        next.insert(key.clone(), value.clone());
        rows.push(JournalRecord::put(
            RecordNamespace::SourceProviderAuthority,
            key,
            value,
        ));
    }
    rows.push(capacity.settlement_record());
    let terminal = JournalTransaction::new([id; 16], rows).unwrap();
    assert_eq!(terminal.records().len(), 4);
    let preflight = owner
        .preflight_reserved_terminal_v1(&capacity, &terminal)
        .unwrap();
    owner
        .commit_reserved_terminal_v1(&preflight, capacity, &terminal)
        .unwrap();
    let recovered = recover_graph(owner).unwrap();
    validate_set(owner, &recovered).unwrap();
    graph.attempts = graph
        .attempts
        .iter()
        .map(|old| {
            recovered
                .attempts
                .values()
                .find(|row| row.attempt_digest == old.attempt_digest)
                .unwrap()
                .clone()
        })
        .collect();
    graph.sessions = graph
        .sessions
        .iter()
        .map(|old| {
            recovered.session_history[&(
                old.provider.authority_id(),
                old.holder.authority_id(),
                old.session_binding,
            )]
                .clone()
        })
        .collect();
    assert_eq!(graph.rows(), next);
}

#[test]
fn native_graph_missing_marker_rejects_active_but_preserves_applying_reservation() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut graph = Graph::applying();
    let key =
        crate::ledger::native_completion::native_completion_key_v2(graph.native.acquisition_id);
    let mut applying = graph.rows();
    applying.remove(&key);
    aos_sandbox_source_provider_ledger::validate_prospective_records(
        applying.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
    )
    .unwrap();

    // Protected admission reserves the distinct dispatch floor before the
    // Requested row exists. Absence here is legitimate, not Active evidence.
    let mut journal = open(directory.path());
    let mut owner = journal
        .claim_source_provider_native_terminal_authority_v1()
        .unwrap();
    let reservation = admit_rows(&mut owner, &graph, applying);
    let original = reservation.request();
    assert_eq!(original.terminal_records, 7);
    assert!(recover_graph(&owner).unwrap().native_completions.is_empty());
    drop(owner);
    drop(journal);

    let mut journal = open(directory.path());
    let mut owner = journal
        .claim_source_provider_native_terminal_authority_v1()
        .unwrap();
    let recovered = recover_graph(&owner).unwrap();
    assert!(recovered.native_completions.is_empty());
    assert_eq!(
        recovered.acquisitions.values().next().unwrap().state,
        ProviderAcquisitionStateV1::Applying
    );
    validate_set(&owner, &recovered).unwrap();
    assert_eq!(
        owner
            .recover_unique_global_capacity_reservation_v1(&binding(original))
            .unwrap()
            .request(),
        original
    );

    commit_graph(&mut owner, 120, &graph);
    graph.native = fixture_prepared(&graph.native);
    commit_graph(&mut owner, 121, &graph);
    graph.active();
    commit_graph(&mut owner, 122, &graph);
    validate_set(&owner, &recover_graph(&owner).unwrap()).unwrap();
    let mut missing = graph.rows();
    missing.remove(&key);
    assert!(
        aos_sandbox_source_provider_ledger::validate_prospective_records(
            missing.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
        )
        .is_err()
    );

    // A raw protected delete creates a hostile cut solely to exercise replay;
    // the production prospective validator would reject this deletion.
    owner
        .commit(
            &JournalTransaction::new(
                [123; 16],
                vec![JournalRecord::delete(
                    RecordNamespace::SourceProviderAuthority,
                    key,
                )],
            )
            .unwrap(),
        )
        .unwrap();
    drop(owner);
    drop(journal);
    let mut journal = open(directory.path());
    let owner = journal
        .claim_source_provider_native_terminal_authority_v1()
        .unwrap();
    assert!(recover_graph(&owner).is_err());
    assert_eq!(
        owner
            .recover_unique_global_capacity_reservation_v1(&binding(original))
            .unwrap()
            .request(),
        original
    );
    // This fixture validates the pure whole graph and actual protected floor,
    // not recover_records with production protected trust/configuration.
}

#[test]
fn native_graph_cleanup_retains_applying_and_active_floor_across_protected_reopen() {
    for active in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut graph = Graph::applying();
        let mut journal = open(directory.path());
        let mut owner = journal
            .claim_source_provider_native_terminal_authority_v1()
            .unwrap();
        let reservation = admit(&mut owner, &graph);
        let original_request = reservation.request();
        graph.native = fixture_prepared(&graph.native);
        commit_graph(&mut owner, 101, &graph);
        if active {
            graph.active();
            commit_graph(&mut owner, 102, &graph);
        }
        graph.native = graph
            .native
            .advance(NativeAcquireCompletionStateV2::CleanupRequired)
            .unwrap();
        commit_graph(&mut owner, 103, &graph);
        let recovered = recover_graph(&owner).unwrap();
        validate_set(&owner, &recovered).unwrap();
        assert_eq!(
            owner
                .recover_global_capacity_reservation_v1(reservation.reservation_id())
                .unwrap()
                .request(),
            original_request
        );
        assert_eq!(original_request.terminal_records, 7);
        assert_eq!(
            recovered.acquisitions.values().next().unwrap().state,
            if active {
                ProviderAcquisitionStateV1::Active
            } else {
                ProviderAcquisitionStateV1::Applying
            }
        );
        drop(owner);
        drop(journal);

        let mut journal = open(directory.path());
        let owner = journal
            .claim_source_provider_native_terminal_authority_v1()
            .unwrap();
        validate_set(&owner, &recover_graph(&owner).unwrap()).unwrap();
        assert_eq!(
            owner
                .recover_unique_global_capacity_reservation_v1(&binding(original_request))
                .unwrap()
                .request(),
            original_request
        );
    }
}

#[test]
fn native_graph_rejects_wrong_backend_attempt_session_and_early_floor_deletion() {
    let graph = Graph::applying();
    let acquisition_key = acquisition_key(&AcquisitionKeyV1 {
        provider_id: graph.acquisition.provider.authority_id(),
        holder_id: graph.acquisition.holder.authority_id(),
        acquisition_id: graph.acquisition.acquisition_id,
    });
    for wrong in [1_u8, 2, 3] {
        let mut rows = graph.rows();
        let mut acquisition = graph.acquisition.clone();
        let mut native = graph.native.clone();
        match wrong {
            1 => {
                acquisition.backend_id = [99; 32];
                rows.insert(acquisition_key.clone(), encode_acquisition(&acquisition));
            }
            2 => {
                native.attempt_digest = digest(99);
                rows.insert(
                    crate::ledger::native_completion::native_completion_key_v2(
                        native.acquisition_id,
                    ),
                    encode_native_completion_v2(&native),
                );
            }
            _ => {
                native.session_binding = digest(99);
                rows.insert(
                    crate::ledger::native_completion::native_completion_key_v2(
                        native.acquisition_id,
                    ),
                    encode_native_completion_v2(&native),
                );
            }
        }
        assert!(
            aos_sandbox_source_provider_ledger::validate_prospective_records(
                rows.iter().map(|(k, v)| (k.as_slice(), v.as_slice()))
            )
            .is_err()
        );
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut journal = open(directory.path());
        let mut owner = journal
            .claim_source_provider_native_terminal_authority_v1()
            .unwrap();
        let _retained_floor = admit(&mut owner, &graph);
        // Raw protected append deliberately creates a hostile graph, without
        // pretending the production prospective validator would authorize it.
        owner.commit(&transaction(106 + wrong, rows)).unwrap();
        drop(owner);
        drop(journal);
        let mut journal = open(directory.path());
        let owner = journal
            .claim_source_provider_native_terminal_authority_v1()
            .unwrap();
        assert!(recover_graph(&owner).is_err());
    }
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut journal = open(directory.path());
    let mut owner = journal
        .claim_source_provider_native_terminal_authority_v1()
        .unwrap();
    let reservation = admit(&mut owner, &graph);
    let mut graph = graph;
    graph.native = fixture_prepared(&graph.native);
    commit_graph(&mut owner, 103, &graph);
    graph.native = graph
        .native
        .advance(NativeAcquireCompletionStateV2::CleanupRequired)
        .unwrap();
    commit_graph(&mut owner, 104, &graph);
    let terminal = JournalTransaction::new(
        [105; 16],
        vec![
            JournalRecord::put(
                RecordNamespace::SourceProviderAuthority,
                crate::ledger::native_completion::native_completion_key_v2(
                    graph.native.acquisition_id,
                ),
                encode_native_completion_v2(&graph.native),
            ),
            reservation.settlement_record(),
        ],
    )
    .unwrap();
    let preflight = owner
        .preflight_reserved_terminal_v1(&reservation, &terminal)
        .unwrap();
    owner
        .commit_reserved_terminal_v1(&preflight, reservation, &terminal)
        .unwrap();
    // This deliberately corrupted protected cut remains a valid ordinary graph:
    // only the capacity union proves that local cleanup cannot spend its floor.
    assert!(validate_set(&owner, &recover_graph(&owner).unwrap()).is_err());
}

#[test]
fn native_graph_cleanup_pending_or_faulted_still_requires_original_floor() {
    for pending in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut graph = Graph::applying();
        let mut journal = open(directory.path());
        let mut owner = journal
            .claim_source_provider_native_terminal_authority_v1()
            .unwrap();
        let reservation = admit(&mut owner, &graph);
        graph.native = fixture_prepared(&graph.native);
        commit_graph(&mut owner, 110, &graph);
        graph.native = graph
            .native
            .advance(NativeAcquireCompletionStateV2::CleanupRequired)
            .unwrap();
        commit_graph(&mut owner, 111, &graph);
        if pending {
            graph.pending();
        } else {
            graph.acquisition.revision += 1;
            graph.acquisition.state = ProviderAcquisitionStateV1::Faulted;
        }
        commit_graph(&mut owner, 112, &graph);
        let recovered = recover_graph(&owner).unwrap();
        validate_set(&owner, &recovered).unwrap();
        assert_eq!(
            owner
                .recover_unique_global_capacity_reservation_v1(&binding(reservation.request()))
                .unwrap()
                .request(),
            reservation.request()
        );
    }
}

#[test]
fn native_graph_release_retains_original_acquire_session_until_exact_tombstone() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut graph = Graph::applying();
    let mut journal = open(directory.path());
    let mut owner = journal
        .claim_source_provider_native_terminal_authority_v1()
        .unwrap();
    let reservation = admit(&mut owner, &graph);
    let original = reservation.request();
    graph.native = fixture_prepared(&graph.native);
    commit_graph(&mut owner, 113, &graph);
    graph.active();
    commit_graph(&mut owner, 114, &graph);
    graph.native = graph
        .native
        .advance(NativeAcquireCompletionStateV2::CleanupRequired)
        .unwrap();
    commit_graph(&mut owner, 115, &graph);
    graph.supersede_session();
    commit_graph(&mut owner, 116, &graph);
    graph.releasing();
    admit_release_suffix(&mut owner, 117, &graph, false);
    let recovered = recover_graph(&owner).unwrap();
    validate_set(&owner, &recovered).unwrap();
    assert_ne!(
        graph.acquisition.current_attempt_digest,
        graph.native.attempt_digest
    );
    assert_ne!(
        graph.sessions.last().unwrap().session_binding,
        graph.native.session_binding
    );
    assert_eq!(
        owner
            .recover_unique_global_capacity_reservation_v1(&binding(original))
            .unwrap()
            .request(),
        original
    );
    // Even if scalar capacity happens to match, corrupting either original
    // authority graph link must fail full typed replay before floor validation.
    let mut missing_original = graph.rows();
    missing_original.remove(&session_history_key(
        graph.authority.provider.authority_id(),
        graph.acquisition.holder.authority_id(),
        graph.native.session_binding,
    ));
    assert!(
        aos_sandbox_source_provider_ledger::validate_prospective_records(
            missing_original
                .iter()
                .map(|(k, v)| (k.as_slice(), v.as_slice()))
        )
        .is_err()
    );
    let mut wrong_effect = graph.rows();
    let mut acquisition = graph.acquisition.clone();
    acquisition.effect_attempt_digest = acquisition.current_attempt_digest;
    wrong_effect.insert(
        acquisition_key(&AcquisitionKeyV1 {
            provider_id: acquisition.provider.authority_id(),
            holder_id: acquisition.holder.authority_id(),
            acquisition_id: acquisition.acquisition_id,
        }),
        encode_acquisition(&acquisition),
    );
    assert!(
        aos_sandbox_source_provider_ledger::validate_prospective_records(
            wrong_effect
                .iter()
                .map(|(k, v)| (k.as_slice(), v.as_slice()))
        )
        .is_err()
    );
    drop(owner);
    drop(journal);

    let mut journal = open(directory.path());
    let mut owner = journal
        .claim_source_provider_native_terminal_authority_v1()
        .unwrap();
    validate_set(&owner, &recover_graph(&owner).unwrap()).unwrap();
    complete_release_status_suffix(
        &mut owner,
        124,
        &mut graph,
        SourceProviderStatus::Unavailable,
    );
    graph.released();
    // This is a signed canonical structural terminal fixture, NOT a new live
    // native terminal producer or proof that Root/Storage custody is absent.
    commit_graph(&mut owner, 118, &graph);
    let terminal = recover_graph(&owner).unwrap();
    assert!(dispatch_terminal_in_validated_graph(&graph.acquisition, &terminal).unwrap());
    assert!(validate_set(&owner, &terminal).is_err()); // retained floor is orphan

    let mut missing_tombstone = graph.rows();
    missing_tombstone.remove(&release_key(&ReleaseKeyV1 {
        provider_id: graph.authority.provider.authority_id(),
        holder_id: graph.acquisition.holder.authority_id(),
        acquisition_id: graph.acquisition.acquisition_id,
    }));
    assert!(
        aos_sandbox_source_provider_ledger::validate_prospective_records(
            missing_tombstone
                .iter()
                .map(|(k, v)| (k.as_slice(), v.as_slice()))
        )
        .is_err()
    );
    let mut contradictory = terminal.clone();
    contradictory
        .native_completions
        .get_mut(&graph.native.acquisition_id)
        .unwrap()
        .state = NativeAcquireCompletionStateV2::Active;
    assert!(dispatch_terminal_in_validated_graph(&graph.acquisition, &contradictory).is_err());
    let mut wrong_tombstone = terminal.clone();
    wrong_tombstone
        .releases
        .values_mut()
        .next()
        .unwrap()
        .attempt_digest = graph.native.attempt_digest;
    assert!(dispatch_terminal_in_validated_graph(&graph.acquisition, &wrong_tombstone).is_err());
    let exact = owner
        .recover_unique_global_capacity_reservation_v1(&binding(original))
        .unwrap();
    let settlement = JournalTransaction::new(
        [119; 16],
        vec![
            JournalRecord::put(
                RecordNamespace::SourceProviderAuthority,
                crate::ledger::native_completion::native_completion_key_v2(
                    graph.native.acquisition_id,
                ),
                encode_native_completion_v2(&graph.native),
            ),
            exact.settlement_record(),
        ],
    )
    .unwrap();
    let preflight = owner
        .preflight_reserved_terminal_v1(&exact, &settlement)
        .unwrap();
    owner
        .commit_reserved_terminal_v1(&preflight, exact, &settlement)
        .unwrap();
    validate_set(&owner, &recover_graph(&owner).unwrap()).unwrap();
    drop(owner);
    drop(journal);
    let mut journal = open(directory.path());
    let owner = journal
        .claim_source_provider_native_terminal_authority_v1()
        .unwrap();
    validate_set(&owner, &recover_graph(&owner).unwrap()).unwrap();
}

#[test]
fn native_release_fence_atomic_admission_preserves_history_and_closes_old_reply_export() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut graph = Graph::applying();
    let mut journal = open(directory.path());
    let mut owner = journal
        .claim_source_provider_native_terminal_authority_v1()
        .unwrap();
    let original_floor = admit(&mut owner, &graph).request();
    graph.native = fixture_prepared(&graph.native);
    commit_graph(&mut owner, 130, &graph);
    graph.active();
    commit_graph(&mut owner, 131, &graph);
    let original_native = graph.native.clone();
    let original_acquisition = graph.acquisition.clone();
    let old_prepared_reply = graph.attempts[0].completed_response.clone();
    let original_request = graph.attempts[0].signed_request.clone();
    crate::ledger::native_completion::validate_native_complete_export_v1(
        &graph.acquisition,
        Some(&graph.native),
        &graph.attempts[0],
    )
    .unwrap();
    let active = graph.rows();

    // A crash before admission leaves the original Active graph and native7.
    drop(owner);
    drop(journal);
    let mut journal = open(directory.path());
    let mut owner = journal
        .claim_source_provider_native_terminal_authority_v1()
        .unwrap();
    validate_set(&owner, &recover_graph(&owner).unwrap()).unwrap();
    graph.releasing();
    let release_floor = admit_release_suffix(&mut owner, 132, &graph, true);
    let release_request = release_floor.request();
    assert_eq!(release_request.terminal_records, 4);
    assert_ne!(release_request.owner_id, original_floor.owner_id);
    assert_ne!(release_request.operation_id, original_floor.operation_id);
    assert_ne!(
        release_request.artifact_digest,
        original_floor.artifact_digest
    );
    assert_eq!(
        release_request.chain_head_digest,
        *graph.attempts.last().unwrap().session_binding.as_bytes()
    );
    assert_eq!(
        graph.native,
        original_native
            .advance(NativeAcquireCompletionStateV2::CleanupRequired)
            .unwrap()
    );
    assert_eq!(graph.acquisition.lease_id, original_acquisition.lease_id);
    assert_eq!(
        graph.acquisition.lease_digest,
        original_acquisition.lease_digest
    );
    assert_eq!(
        graph.acquisition.source_root,
        original_acquisition.source_root
    );
    assert_eq!(
        graph.acquisition.lease_history,
        original_acquisition.lease_history
    );
    assert_eq!(graph.attempts[0].completed_response, old_prepared_reply);
    assert_eq!(graph.attempts[0].signed_request, original_request);
    assert!(
        crate::ledger::native_completion::validate_native_complete_export_v1(
            &graph.acquisition,
            Some(&graph.native),
            &graph.attempts[0],
        )
        .is_err()
    );
    assert!(
        crate::ledger::native_completion::validate_native_export_open_v1(
            &graph.acquisition,
            Some(&graph.native)
        )
        .is_err()
    );
    // Undecodable history would also block authenticated Release recovery.
    // The fence instead preserves the exact original Acquire and Release joins.
    graph
        .native
        .validate_provider_graph(&graph.attempts[0], &graph.acquisition)
        .unwrap();
    crate::ledger::reducer::validate_release_join(
        &graph.acquisition,
        graph.release.as_ref().unwrap(),
        graph.attempts.last().unwrap(),
    )
    .unwrap();
    assert!(
        crate::ledger::native_completion::release_fence::validate_native_release_admission_v1(
            &active,
            &graph.rows()
        )
        .is_ok()
    );
    drop(owner);
    drop(journal);

    // Crash after the atomic eight-record append retains BOTH exact floors.
    let mut journal = open(directory.path());
    let mut owner = journal
        .claim_source_provider_native_terminal_authority_v1()
        .unwrap();
    let recovered = recover_graph(&owner).unwrap();
    validate_set(&owner, &recovered).unwrap();
    assert_eq!(
        owner
            .recover_unique_global_capacity_reservation_v1(&binding(original_floor))
            .unwrap()
            .request(),
        original_floor
    );
    assert_eq!(
        crate::native_release_capacity::exact_reservation(
            &owner,
            &recovered,
            graph.acquisition.acquisition_id
        )
        .unwrap()
        .request(),
        release_request
    );
    complete_release_status_suffix(
        &mut owner,
        133,
        &mut graph,
        SourceProviderStatus::Unavailable,
    );
    assert_eq!(
        graph.acquisition.state,
        ProviderAcquisitionStateV1::Releasing
    );
    assert_eq!(
        graph.native.state,
        NativeAcquireCompletionStateV2::CleanupRequired
    );
    assert_eq!(
        graph.release.as_ref().unwrap().state,
        ProviderReleaseStateV1::Intent
    );
    assert!(graph.release.as_ref().unwrap().backend_evidence.is_none());
    assert!(
        owner
            .recover_global_capacity_reservation_v1(release_floor.reservation_id())
            .is_err()
    );
    assert_eq!(
        owner
            .recover_unique_global_capacity_reservation_v1(&binding(original_floor))
            .unwrap()
            .request(),
        original_floor
    );
    drop(owner);
    drop(journal);

    let mut journal = open(directory.path());
    let owner = journal
        .claim_source_provider_native_terminal_authority_v1()
        .unwrap();
    let recovered = recover_graph(&owner).unwrap();
    validate_set(&owner, &recovered).unwrap();
    let original = recovered
        .attempts
        .values()
        .find(|row| row.attempt_digest == graph.native.attempt_digest)
        .unwrap();
    assert_eq!(original.completed_response, old_prepared_reply);
    assert!(
        crate::ledger::native_completion::validate_native_complete_export_v1(
            &graph.acquisition,
            Some(&graph.native),
            original,
        )
        .is_err()
    );
    // This tests the shared protected-graph eligibility used by the security
    // send callers, not an installed socket/Root peer or SCM_RIGHTS handoff.
}

#[test]
fn native_release_fence_rejects_incomplete_cas_and_changed_original_artifacts() {
    let mut graph = Graph::applying();
    graph.native = fixture_prepared(&graph.native);
    graph.active();
    let active = graph.rows();
    let native = graph.native.clone();
    graph.releasing();
    let next = graph.rows();
    crate::ledger::native_completion::release_fence::validate_native_release_admission_v1(
        &active, &next,
    )
    .unwrap();
    let changed: Vec<_> = next
        .keys()
        .filter(|key| active.get(*key) != next.get(*key))
        .cloned()
        .collect();
    assert_eq!(changed.len(), 7);
    for omitted in &changed {
        let mut wrong = next.clone();
        if let Some(old) = active.get(omitted) {
            wrong.insert(omitted.clone(), old.clone());
        } else {
            wrong.remove(omitted);
        }
        assert!(
            crate::ledger::native_completion::release_fence::validate_native_release_admission_v1(
                &active, &wrong
            )
            .is_err()
        );
    }
    for mutation in 0..5 {
        let mut wrong = next.clone();
        let mut marker = graph.native.clone();
        match mutation {
            0 => marker.challenge = [99; 32],
            1 => marker.session_binding = digest(99),
            2 => marker.attempt_digest = graph.attempts.last().unwrap().attempt_digest,
            3 => marker.original_clock = None,
            _ => marker.state = NativeAcquireCompletionStateV2::Active,
        }
        wrong.insert(
            crate::ledger::native_completion::native_completion_key_v2(marker.acquisition_id),
            encode_native_completion_v2(&marker),
        );
        assert!(
            crate::ledger::native_completion::release_fence::validate_native_release_admission_v1(
                &active, &wrong
            )
            .is_err()
        );
    }
    let mut unbound = graph.clone();
    unbound.acquisition.backend_id =
        aos_sandbox_source_provider_ledger::identity::acquire_native_no_dispatch_id_v1(
            unbound.acquisition.normalized_intent.digest(),
            unbound.acquisition.catalog_generation,
            unbound.acquisition.catalog_digest,
        );
    assert!(
        crate::ledger::native_completion::release_fence::validate_native_release_admission_v1(
            &active,
            &unbound.rows()
        )
        .is_err()
    );
    let mut extra = next.clone();
    extra.insert(b"foreign-extra".to_vec(), vec![1]);
    assert!(
        crate::ledger::native_completion::release_fence::validate_native_release_admission_v1(
            &active, &extra
        )
        .is_err()
    );
    assert_eq!(native.state, NativeAcquireCompletionStateV2::Active);
}

#[test]
fn native_release_fence_preserves_both_capacity_floors_under_pressure() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let limits = JournalLimits {
        maximum_journal_bytes: DISPATCH_TERMINAL_BYTES
            + crate::ledger::native_completion::release_fence::NATIVE_RELEASE_STATUS_TERMINAL_BYTES_V1 + 1024 * 1024,
        ..JournalLimits::default()
    };
    let mut journal = Journal::open_protected_at_uid(
        directory.path(),
        "native-whole-graph.journal",
        limits,
        rustix::process::geteuid().as_raw(),
    )
    .unwrap()
    .0;
    let mut owner = journal
        .claim_source_provider_native_terminal_authority_v1()
        .unwrap();
    let mut graph = Graph::applying();
    let original_floor = admit(&mut owner, &graph).request();
    graph.native = fixture_prepared(&graph.native);
    commit_graph(&mut owner, 140, &graph);
    graph.active();
    commit_graph(&mut owner, 141, &graph);
    graph.releasing();
    let status_floor = admit_release_suffix(&mut owner, 142, &graph, true);
    assert_eq!(status_floor.request().terminal_records, 4);
    // Repeated exact canonical puts create pressure without a malformed/dummy
    // model. Every append must preserve both reserved terminal alternatives.
    let mut refused = false;
    for index in 1..1000_u16 {
        let mut id = [143; 16];
        id[..2].copy_from_slice(&index.to_be_bytes());
        let rows = graph
            .rows()
            .into_iter()
            .map(|(key, value)| {
                JournalRecord::put(RecordNamespace::SourceProviderAuthority, key, value)
            })
            .collect();
        let repeat = JournalTransaction::new(id, rows).unwrap();
        if owner
            .preflight_transactions(std::slice::from_ref(&repeat))
            .is_err()
        {
            refused = true;
            break;
        }
        owner.commit(&repeat).unwrap();
    }
    assert!(refused);
    validate_set(&owner, &recover_graph(&owner).unwrap()).unwrap();
    assert_eq!(
        owner
            .recover_unique_global_capacity_reservation_v1(&binding(original_floor))
            .unwrap()
            .request(),
        original_floor
    );
    complete_release_status_suffix(&mut owner, 144, &mut graph, SourceProviderStatus::Pending);
    validate_set(&owner, &recover_graph(&owner).unwrap()).unwrap();
    assert_eq!(
        owner
            .recover_unique_global_capacity_reservation_v1(&binding(original_floor))
            .unwrap()
            .request(),
        original_floor
    );
}

#[test]
fn native_release_fence_cold_replay_rejects_foreign_request_session_and_geometry() {
    for changed in 0..6 {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut journal = open(directory.path());
        let mut owner = journal
            .claim_source_provider_native_terminal_authority_v1()
            .unwrap();
        let mut graph = Graph::applying();
        let original = admit(&mut owner, &graph).request();
        graph.native = fixture_prepared(&graph.native);
        commit_graph(&mut owner, 145, &graph);
        graph.active();
        commit_graph(&mut owner, 146, &graph);
        // The current Release may use a genuine different session while the
        // native7 floor remains bound to immutable original Acquire history.
        graph.supersede_session();
        commit_graph(&mut owner, 147, &graph);
        let before: BTreeMap<_, _> = owner
            .records()
            .unwrap()
            .map(|(key, value)| (key.to_vec(), value.to_vec()))
            .collect();
        graph.releasing();
        let next = graph.rows();
        crate::ledger::native_completion::release_fence::validate_native_release_admission_v1(
            &before, &next,
        )
        .unwrap();
        let mut request = crate::native_release_capacity::fixture_request(
            &graph_recovered(&graph),
            graph.acquisition.acquisition_id,
        )
        .unwrap();
        assert_ne!(request.chain_head_digest, original.chain_head_digest);
        match changed {
            0 => request.artifact_digest = original.artifact_digest,
            1 => request.checkpoint_digest = original.checkpoint_digest,
            2 => request.chain_head_digest = original.chain_head_digest,
            3 => request.owner_id = original.owner_id,
            4 => {
                request.terminal_bytes -= 1;
                request.poison_bytes -= 1;
            }
            _ => request.owner_digest = original.owner_digest,
        }
        // Raw protected admission deliberately creates a hostile capacity
        // cut. Production derives the exact binding before this append.
        let capacity = owner
            .prepare_global_capacity_reservation_v1(request, [148; 16])
            .unwrap();
        let mut rows = transaction(
            148,
            next.into_iter()
                .filter(|(key, value)| before.get(key) != Some(value))
                .collect(),
        )
        .records()
        .to_vec();
        rows.push(capacity.record().clone());
        let admission = JournalTransaction::new([148; 16], rows).unwrap();
        let preflight = owner
            .preflight_global_capacity_reservation_v1(&capacity, &admission)
            .unwrap();
        owner
            .commit_global_capacity_reservation_v1(&preflight, capacity, &admission)
            .unwrap();
        assert!(validate_set(&owner, &recover_graph(&owner).unwrap()).is_err());
        drop(owner);
        drop(journal);
        let mut journal = open(directory.path());
        let owner = journal
            .claim_source_provider_native_terminal_authority_v1()
            .unwrap();
        // The canonical owner graph is valid, but the foreign suffix cannot
        // masquerade as current Release authority or the original native7.
        assert!(validate_set(&owner, &recover_graph(&owner).unwrap()).is_err());
        assert_eq!(
            owner
                .recover_unique_global_capacity_reservation_v1(&binding(original))
                .unwrap()
                .request(),
            original
        );
    }
}

#[test]
fn native_release_fence_faulted_observation_retains_exact_original_and_status_floors() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut journal = open(directory.path());
    let mut owner = journal
        .claim_source_provider_native_terminal_authority_v1()
        .unwrap();
    let mut graph = Graph::applying();
    let original = admit(&mut owner, &graph).request();
    graph.native = fixture_prepared(&graph.native);
    commit_graph(&mut owner, 150, &graph);
    graph.active();
    commit_graph(&mut owner, 151, &graph);
    graph.releasing();
    let release_status = admit_release_suffix(&mut owner, 152, &graph, true).request();
    let native = graph.native.clone();

    // Mirror record_backend_conflict's actual three-row canonical update.
    // Neither a local contradiction nor AcquireClosed settles the Reserved
    // Release request, proves absence, or consumes either capacity floor.
    graph.faulted();
    commit_graph(&mut owner, 153, &graph);
    let recovered = recover_graph(&owner).unwrap();
    validate_set(&owner, &recovered).unwrap();
    assert_eq!(
        crate::native_release_capacity::exact_reservation(
            &owner,
            &recovered,
            graph.acquisition.acquisition_id
        )
        .unwrap()
        .request(),
        release_status
    );
    assert_eq!(
        owner
            .recover_unique_global_capacity_reservation_v1(&binding(original))
            .unwrap()
            .request(),
        original
    );
    assert_eq!(graph.native, native);
    assert!(
        crate::ledger::native_completion::validate_native_export_open_v1(
            &graph.acquisition,
            Some(&graph.native)
        )
        .is_err()
    );
    // Capacity retention is deliberately broader than runtime completion:
    // the native status facade and actual caller still require Releasing.
    assert_ne!(
        graph.acquisition.state,
        ProviderAcquisitionStateV1::Releasing
    );
    for changed in 0..3 {
        let mut foreign = graph.release.clone().unwrap();
        match changed {
            0 => foreign.lease_id = [99; 16],
            1 => foreign.lease_digest = digest(99),
            _ => foreign.backend_id = [99; 32],
        }
        assert!(crate::ledger::native_completion::release_fence::native_release_status_capacity_binding_v1(
            &graph.acquisition, &graph.native, &graph.attempts[0], &foreign,
            graph.attempts.last().unwrap(), graph.sessions.last().unwrap(),
        ).is_err());
    }
    drop(owner);
    drop(journal);

    let mut journal = open(directory.path());
    let mut owner = journal
        .claim_source_provider_native_terminal_authority_v1()
        .unwrap();
    let recovered = recover_graph(&owner).unwrap();
    validate_set(&owner, &recovered).unwrap();
    assert_eq!(
        crate::native_release_capacity::exact_reservation(
            &owner,
            &recovered,
            graph.acquisition.acquisition_id
        )
        .unwrap()
        .request(),
        release_status
    );
    assert_eq!(
        owner
            .recover_unique_global_capacity_reservation_v1(&binding(original))
            .unwrap()
            .request(),
        original
    );
    let mut hostile = graph.release.clone().unwrap();
    hostile.backend_id = [99; 32];
    let key = release_key(&ReleaseKeyV1 {
        provider_id: hostile.provider.authority_id(),
        holder_id: hostile.holder.authority_id(),
        acquisition_id: hostile.acquisition_id,
    });
    // A raw protected append exercises hostile replay, not production
    // authorization. Immutable native capacity bytes still cannot bless it.
    owner
        .commit(&transaction(
            154,
            BTreeMap::from([(key, encode_release(&hostile))]),
        ))
        .unwrap();
    drop(owner);
    drop(journal);
    let mut journal = open(directory.path());
    let owner = journal
        .claim_source_provider_native_terminal_authority_v1()
        .unwrap();
    assert!(
        recover_graph(&owner)
            .and_then(|recovered| validate_set(&owner, &recovered))
            .is_err()
    );
}

#[test]
fn native_faulted_replay_requires_original_artifacts_and_exact_current_release_intent() {
    let mut graph = Graph::applying();
    graph.native = fixture_prepared(&graph.native);
    graph.active();

    let mut before_release = graph.clone();
    before_release.native = before_release
        .native
        .advance(NativeAcquireCompletionStateV2::CleanupRequired)
        .unwrap();
    before_release.faulted();
    let rows = before_release.rows();
    aos_sandbox_source_provider_ledger::validate_prospective_records(
        rows.iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
    )
    .unwrap();
    crate::ledger::reducer::validate_retained_lease(
        &before_release.acquisition,
        &before_release.attempts[0],
    )
    .unwrap();

    graph.releasing();
    graph.faulted();
    let rows = graph.rows();
    aos_sandbox_source_provider_ledger::validate_prospective_records(
        rows.iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
    )
    .unwrap();
    // The old active-only entry point stays closed once an effect is retained.
    assert!(
        crate::ledger::reducer::validate_retained_lease(&graph.acquisition, &graph.attempts[0])
            .is_err()
    );

    for mutation in 0..15 {
        let mut foreign = graph.clone();
        match mutation {
            0 => foreign.release = None,
            1 => foreign.release.as_mut().unwrap().effect_id = [99; 16],
            2 => foreign.acquisition.release_effect_id = Some([99; 16]),
            3 => foreign.release.as_mut().unwrap().lease_id = [99; 16],
            4 => foreign.release.as_mut().unwrap().lease_digest = digest(99),
            5 => foreign.release.as_mut().unwrap().backend_id = [99; 32],
            6 => foreign.release.as_mut().unwrap().attempt_digest = digest(99),
            7 => foreign.acquisition.lease_attempt_digest = Some(digest(99)),
            8 => foreign.acquisition.signed_lease[0] ^= 1,
            9 => foreign.acquisition.proof_digest = digest(99),
            10 => foreign.acquisition.backend_evidence = None,
            11 => foreign.acquisition.reopen_identity = None,
            12 => foreign.acquisition.state = ProviderAcquisitionStateV1::Active,
            13 => foreign.release.as_mut().unwrap().state = ProviderReleaseStateV1::Tombstone,
            _ => foreign.release.as_mut().unwrap().acquisition_record_digest = digest(99),
        }
        // Keep unrelated inventory and the current row digest truthful so the
        // negative cases cannot rely only on a stale aggregate projection.
        if mutation != 14
            && let Some(release) = &mut foreign.release
        {
            release.acquisition_record_digest =
                record_digest(&encode_acquisition(&foreign.acquisition)).unwrap();
        }
        let inventory = foreign.try_refresh_inventory();
        assert_eq!(
            inventory.is_err(),
            (7..=13).contains(&mutation),
            "malformed canonical artifact {mutation}",
        );
        let rows = foreign.rows();
        assert!(
            aos_sandbox_source_provider_ledger::validate_prospective_records(
                rows.iter()
                    .map(|(key, value)| (key.as_slice(), value.as_slice())),
            )
            .is_err(),
            "substituted Faulted lineage {mutation}",
        );
    }
}

#[test]
fn native_export_fence_result_crash_reopen_consumes_only_status4_and_never_terminalizes() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut graph = Graph::applying();
    let mut journal = open(directory.path());
    let mut owner = journal
        .claim_source_provider_native_terminal_authority_v1()
        .unwrap();
    let original_floor = admit(&mut owner, &graph).request();
    graph.native = fixture_prepared(&graph.native);
    commit_graph(&mut owner, 155, &graph);
    graph.active();
    commit_graph(&mut owner, 156, &graph);
    graph.releasing();
    let status_floor = admit_release_suffix(&mut owner, 157, &graph, true);
    let exact_status_floor = status_floor.request();
    let native_bytes = encode_native_completion_v2(&graph.native);

    // Admission is already the export fence. Crash before result production
    // leaves both protected floors and all original artifacts intact.
    drop(owner);
    drop(journal);
    let mut journal = open(directory.path());
    let mut owner = journal
        .claim_source_provider_native_terminal_authority_v1()
        .unwrap();
    let current = recover_graph(&owner).unwrap();
    validate_set(&owner, &current).unwrap();
    let status_floor = crate::native_release_capacity::exact_reservation(
        &owner,
        &current,
        graph.acquisition.acquisition_id,
    )
    .unwrap();
    assert_eq!(status_floor.request(), exact_status_floor);
    let records = graph.rows().into_iter().collect::<Vec<_>>();
    let subject = crate::ledger::native_completion::export_result::native_export_fence_subject_v1(
        &records,
        graph.attempts.last().unwrap().attempt_digest,
        owner.snapshot().unwrap().sequence(),
        status_floor.admission_transaction_id(),
        status_floor.reservation_id(),
    )
    .unwrap();
    assert_eq!(subject.release().request_sequence, 3);
    assert_eq!(subject.release().response_sequence, 2);
    let signed = SignedSourceProviderNativeExportFenceV1::sign(
        subject,
        graph.sessions.last().unwrap().signers[3].clone(),
        &SigningKey::from_bytes(&[54; 32]),
    )
    .unwrap();
    let result = signed.to_canonical_bytes();
    complete_release_result_suffix(
        &mut owner,
        158,
        &mut graph,
        SourceProviderStatus::Pending,
        Some(result.clone()),
    );
    let exact_response = graph.attempts.last().unwrap().completed_response.clone();
    assert_eq!(
        exact_response.len(),
        MAXIMUM_NATIVE_RELEASE_RESPONSE_BYTES_V2
    );
    assert_eq!(encode_native_completion_v2(&graph.native), native_bytes);
    assert_eq!(
        graph.acquisition.state,
        ProviderAcquisitionStateV1::Releasing
    );
    assert_eq!(
        graph.release.as_ref().unwrap().state,
        ProviderReleaseStateV1::Intent
    );
    assert!(graph.release.as_ref().unwrap().backend_evidence.is_none());
    assert!(graph.release.as_ref().unwrap().signed_receipt.is_empty());
    assert_eq!(
        graph.native.state,
        NativeAcquireCompletionStateV2::CleanupRequired
    );
    assert!(
        crate::ledger::native_completion::validate_native_complete_export_v1(
            &graph.acquisition,
            Some(&graph.native),
            &graph.attempts[0]
        )
        .is_err()
    );
    assert_eq!(
        owner
            .recover_unique_global_capacity_reservation_v1(&binding(original_floor))
            .unwrap()
            .request(),
        original_floor
    );
    assert!(
        owner
            .recover_unique_global_capacity_reservation_v1(&binding(exact_status_floor))
            .is_err()
    );
    drop(owner);
    drop(journal);

    // Lost send/readback cannot cause a new fence/request or free native7.
    let mut journal = open(directory.path());
    let owner = journal
        .claim_source_provider_native_terminal_authority_v1()
        .unwrap();
    let current = recover_graph(&owner).unwrap();
    validate_set(&owner, &current).unwrap();
    let attempt = current
        .attempts
        .values()
        .find(|row| row.method == SourceProviderMethod::Release)
        .unwrap();
    assert_eq!(attempt.completed_response, exact_response);
    let profile =
        ReleaseSourceResponseProfileV2::from_canonical_bytes(&attempt.completed_response).unwrap();
    assert_eq!(profile.status(), SourceProviderStatus::Pending);
    assert_eq!(profile.signed_result(), Some(result.as_slice()));
    assert_eq!(profile.native_fence(), Some(&signed));
    // Exercise the actual durable-reply parser without granting a carrier,
    // production ingress configuration or permission to send descriptors.
    let reply = crate::backend::DurableProviderReplyV1 {
        response: attempt.completed_response.clone(),
        source_root: None,
        durability: crate::backend::DurableReplyAuthorityV1::RevalidatedReplay {
            snapshot: owner.snapshot().unwrap(),
            attempt_key: Vec::new(),
        },
    };
    assert_eq!(reply.session_binding().unwrap(), attempt.session_binding);
    signed
        .verify(SigningKey::from_bytes(&[54; 32]).verifying_key().as_bytes())
        .unwrap();
    assert_eq!(
        owner
            .recover_unique_global_capacity_reservation_v1(&binding(original_floor))
            .unwrap()
            .request(),
        original_floor
    );
}

#[test]
fn native_export_fence_result_rejects_resigned_original_artifact_or_release_substitution() {
    let mut graph = Graph::applying();
    graph.native = fixture_prepared(&graph.native);
    graph.active();
    graph.releasing();
    let records = graph.rows().into_iter().collect::<Vec<_>>();
    let attempt = graph.attempts.last().unwrap();
    let original = crate::ledger::native_completion::export_result::native_export_fence_subject_v1(
        &records,
        attempt.attempt_digest,
        99,
        [98; 16],
        [97; 32],
    )
    .unwrap();
    for mutation in 0..10 {
        let mut release = original.release().clone();
        let mut acquire = original.acquire().clone();
        let mut signed_acceptance_digest = original.signed_acceptance_digest();
        let mut cut = original.cut();
        let mut acceptance = original.acceptance().clone();
        match mutation {
            0 => release.attempt_digest = digest(96),
            1 => release.typed_request_digest = digest(96),
            2 => acquire.attempt_digest = digest(96),
            3 => acquire.session_binding = digest(96),
            4 => signed_acceptance_digest = digest(96),
            5 => cut.reservation_id = [96; 32],
            6 => {
                acceptance = StorageNativeAcceptanceV3::new(
                    [96; 16],
                    acceptance.request_digest(),
                    acceptance.receipt_digest(),
                    acceptance.descriptor().clone(),
                    acceptance.topology().clone(),
                )
                .unwrap()
            }
            7 => {
                acceptance = StorageNativeAcceptanceV3::new(
                    acceptance.issuance_id(),
                    acceptance.request_digest(),
                    digest(96),
                    acceptance.descriptor().clone(),
                    acceptance.topology().clone(),
                )
                .unwrap()
            }
            8 => release.request_sequence += 1,
            _ => release.response_sequence += 1,
        }
        let subject = SourceProviderNativeExportFenceV1::new(
            release,
            acquire,
            original.native_request_digest(),
            signed_acceptance_digest,
            acceptance,
            cut,
        )
        .unwrap();
        let signed = SignedSourceProviderNativeExportFenceV1::sign(
            subject,
            graph.sessions.last().unwrap().signers[3].clone(),
            &SigningKey::from_bytes(&[54; 32]),
        )
        .unwrap();
        signed
            .verify(SigningKey::from_bytes(&[54; 32]).verifying_key().as_bytes())
            .unwrap();
        let mut completed = attempt.clone();
        complete_attempt(
            &mut completed,
            SourceProviderStatus::Pending,
            Some(signed.to_canonical_bytes()),
            graph.sessions.last().unwrap().signers[3].clone(),
            signed.subject().release().response_sequence,
            503,
            empty_descriptor_set_commitment_v1(),
        );
        assert!(crate::ledger::native_completion::export_result::validate_native_export_fence_result_v1(&records, attempt.attempt_digest, &completed.completed_response).is_err());
    }
}
