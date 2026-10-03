//! Genuine canonical native response fixtures reused from existing Mount disposition tests.
//!
//! All signing occurs in test-only DATA construction. There is no protected
//! trust/currentness, live FD, runtime admission or installed initializer here.

use super::*;
use crate::mount_source_acquisition_state::*;
use crate::mount_source_acquisition_state::{checkpoint, format::state_error};
use crate::{
    MountSourcePhysicalProofV1, SourceRealizationBindingV1, mount_source_physical_proof_digest_v1,
    mount_source_proof_class_from_provider_v1, mount_source_realization_handle_v1,
};
use aos_sandbox_source_provider_protocol::*;
use ed25519_dalek::Signer as _;
use sha2::{Digest as _, Sha256};

const HOLDER: [u8; 16] = [1; 16];
const PROVIDER: [u8; 16] = [2; 16];
const BOOT: [u8; 16] = [3; 16];

fn d(byte: u8) -> ObjectDigest {
    digest(byte)
}

fn signer(
    authority: [u8; 16],
    key_id: [u8; 16],
    usage: SourceProviderKeyUsageV1,
    key: &SigningKey,
) -> SourceProviderSigningKeyV1 {
    fixture::signer(authority, key_id, usage, key)
}

pub(super) struct OriginalNative {
    pub(super) completed: SourceProviderQueryAttemptV2,
    pub(super) descriptor: SourceRootObservationV1,
    pub(super) request_digest: ObjectDigest,
    pub(super) signed_acceptance_digest: ObjectDigest,
    pub(super) acceptance: StorageNativeAcceptanceV3,
    pub(super) request: SignedStorageNativeAcquireRequestV2,
    pub(super) reply: StorageNativeAcquireReplyV3,
}

pub(super) fn native_catalog(
    session: &SourceProviderSessionV2,
    binding: ObjectDigest,
) -> ProviderHeldSnapshotCatalogV1 {
    let snapshot =
        ZfsHeldSnapshotProofV1::new([61; 32], 1, 62, 63, 64, [65; 16], 1, d(66), d(67), d(68))
            .unwrap();
    ProviderHeldSnapshotCatalogV1::new(
        1,
        ObjectDigest::from_bytes(session.scope.resource_namespace_digest),
        vec![
            ProviderHeldSnapshotRowV1::new(binding, [79; 32], 1, d(80), 1, d(81), snapshot)
                .unwrap(),
        ],
    )
    .unwrap()
}

fn consumed(
    original: &SourceProviderQueryAttemptV2,
    session: &SourceProviderSessionV2,
    status: SourceProviderStatus,
    result: Option<Vec<u8>>,
    descriptor: ObjectDigest,
) -> SourceProviderQueryAttemptV2 {
    let method = match original.method {
        ProviderMethodV2::Acquire => SourceProviderMethod::Acquire,
        ProviderMethodV2::Release => SourceProviderMethod::Release,
        _ => panic!("acquisition fixture method"),
    };
    let key = SigningKey::from_bytes(&[14; 32]);
    let result_digest = response_result_digest_v1(method, status, result.as_deref());
    let status_subject = SourceProviderResponseStatusV1::new(
        method,
        original.request_id,
        ObjectDigest::from_bytes(original.signed_request_digest),
        status,
        session.provider_process_instance,
        ObjectDigest::from_bytes(session.session_binding),
        original.request_sequence,
        result_digest,
        descriptor,
    )
    .unwrap();
    let signed_status = sign_response_status(
        status_subject,
        signer(
            PROVIDER,
            [24; 16],
            SourceProviderKeyUsageV1::ProviderOutcome,
            &key,
        ),
        &key,
    )
    .unwrap();
    let response = match method {
        SourceProviderMethod::Acquire => encode_acquire_response(
            &AcquireSourceResponseV1::new(signed_status.clone(), result.clone()).unwrap(),
        ),
        SourceProviderMethod::Release => {
            ReleaseSourceResponseProfileV2::from_parts(signed_status.clone(), result.clone())
                .unwrap()
                .to_canonical_bytes()
        }
        _ => unreachable!(),
    };
    let mut anchor = OutcomeVerificationAnchorV2 {
        verification_started_seconds: 110,
        verification_completed_seconds: 111,
        kernel_boot_id: session.kernel_boot_id,
        trusted_clock_evidence_digest: session.trusted_clock_evidence_digest,
        anchor_digest: [0; 32],
    };
    anchor.anchor_digest = checkpoint::outcome_verification_anchor_digest_v2(
        &anchor,
        session.session_id,
        original.attempt_id,
        original.request_sequence,
        original.request_sequence,
        Sha256::digest(&response).into(),
    );
    let mut next = original.clone();
    next.revision = 2;
    next.state = ProviderAttemptStateV2::DispositionConsumed {
        response_sequence: original.request_sequence,
        verification_anchor: anchor,
        status: match status {
            SourceProviderStatus::Complete => ProviderStatusV2::Complete,
            SourceProviderStatus::Pending => ProviderStatusV2::Pending,
            _ => panic!("fixture disposition"),
        },
        signed_status_digest: Sha256::digest(signed_status.to_canonical_bytes()).into(),
        signed_status: signed_status.to_canonical_bytes(),
        signed_result: result.unwrap_or_default(),
        signed_result_digest: *result_digest.as_bytes(),
    };
    next.record_digest = [0; 32];
    match seal_record(StoredRecordV2::ProviderQueryAttempt { value: next }).unwrap() {
        StoredRecordV2::ProviderQueryAttempt { value } => value,
        _ => panic!("sealed fixture attempt"),
    }
}

pub(super) fn original_native(fixture: &Fixture) -> OriginalNative {
    let attempt = &fixture.attempt;
    let session = &fixture.session;
    let signed_root =
        SignedSourceProviderRequestV1::from_canonical_bytes(&attempt.signed_request).unwrap();
    let root = decode_acquire_request(signed_root.subject()).unwrap();
    let provider_key = SigningKey::from_bytes(&[14; 32]);
    let provider_signer = signer(
        PROVIDER,
        [24; 16],
        SourceProviderKeyUsageV1::ProviderOutcome,
        &provider_key,
    );
    let catalog = native_catalog(session, root.binding_digest());
    let (resource, snapshot) = catalog
        .select_under_head(
            catalog.generation(),
            catalog.digest(),
            catalog.namespace_digest(),
            root.binding_digest(),
        )
        .unwrap();
    let provider_attempt = source_provider_request_attempt_digest_v1(
        signed_root.signer(),
        SourceProviderMethod::Acquire,
        attempt.request_id,
    );
    let claims = StorageZfsHoldTransportRequestV1::new(
        1,
        [69; 32],
        provider_attempt,
        PROVIDER,
        HOLDER,
        root.session_binding(),
        root.acquisition_id(),
        root.binding_digest(),
        root.native_catalog().unwrap().current_head_commitment(),
        110,
        160,
        catalog,
    )
    .unwrap();
    let request = SignedStorageNativeAcquireRequestV2::sign(
        StorageNativeAcquireRequestV2::new_native_v3(claims, signed_root).unwrap(),
        provider_signer.clone(),
        &provider_key,
    )
    .unwrap();
    let storage_head = StorageZfsHoldHeadV1::new(1, d(71), 1, d(72), 1, d(73), d(74)).unwrap();
    let receipt = StorageZfsHoldReceiptV1::new(
        [69; 32],
        provider_attempt,
        root.binding_digest(),
        resource.clone(),
        snapshot.clone(),
        storage_head,
        110,
        160,
    )
    .unwrap();
    let storage_signer = StorageZfsHoldSignerV1::new([75; 16], 1, d(72), [76; 16], 1).unwrap();
    let storage_key = SigningKey::from_bytes(&[77; 32]);
    let unsigned = SignedStorageZfsHoldReceiptV1::new(receipt.clone(), storage_signer, [0; 64]);
    let receipt = SignedStorageZfsHoldReceiptV1::new(
        receipt,
        storage_signer,
        storage_key.sign(&unsigned.signing_message()).to_bytes(),
    );
    let descriptor = SourceRootObservationV1::new(BOOT, 83, 84, 85, true, true, true).unwrap();
    let topology =
        storage_native_nonrecursive_topology_v1(&request, &receipt, &descriptor, 2, 55).unwrap();
    let acceptance = StorageNativeAcceptanceV3::new(
        [78; 16],
        request.digest(),
        receipt.digest(),
        descriptor.clone(),
        topology.clone(),
    )
    .unwrap();
    let signed_acceptance =
        SignedStorageNativeAcceptanceV3::sign(acceptance.clone(), storage_signer, &storage_key);
    let reply =
        StorageNativeAcquireReplyV3::new(signed_acceptance.clone(), receipt.clone()).unwrap();
    let proof = SourceProviderProofV1::ZfsHeldSnapshot {
        proof: snapshot,
        topology,
    };
    let lease = sign_export_lease(
        SourceExportLeaseV1::new(
            [82; 16],
            attempt.request_id,
            digest_acquire_request(&root),
            HOLDER,
            1,
            d(7),
            SourceProviderAuthorityV1::new(PROVIDER, 1, d(8)).unwrap(),
            resource,
            proof.clone(),
            root.binding_digest(),
            110,
            160,
            root.revocation_digest(),
        )
        .unwrap(),
        provider_signer.clone(),
        &provider_key,
    )
    .unwrap();
    let receipt = sign_provider_receipt(
        SourceProviderReceiptV1::new(
            attempt.request_id,
            digest_acquire_request(&root),
            root.acquisition_id(),
            session.provider_process_instance,
            digest_signed_export_lease(&lease),
            lease.to_canonical_bytes(),
            SourceProviderDescriptorRole::SourceRoot,
            BOOT,
            83,
            84,
            85,
            digest_provider_proof(&proof),
        )
        .unwrap(),
        provider_signer,
        &provider_key,
    )
    .unwrap();
    OriginalNative {
        completed: consumed(
            attempt,
            session,
            SourceProviderStatus::Complete,
            Some(receipt.to_canonical_bytes()),
            source_root_descriptor_commitment_v1(&descriptor),
        ),
        descriptor,
        request_digest: request.digest(),
        signed_acceptance_digest: signed_acceptance.digest(),
        acceptance,
        request,
        reply,
    }
}

pub(super) fn acquire_evidence(
    row: &SourceAcquisitionRowV2,
    attempt: &SourceProviderQueryAttemptV2,
    session: &SourceProviderSessionV2,
) -> Result<SourceAcquisitionEvidenceV2> {
    let ProviderAttemptStateV2::DispositionConsumed {
        verification_anchor,
        signed_result,
        ..
    } = &attempt.state
    else {
        return Err(state_error("Complete Acquire attempt is not consumed"));
    };
    let signed_receipt = SignedSourceProviderReceiptV1::from_canonical_bytes(signed_result)
        .map_err(|_| state_error("Complete Acquire receipt is invalid"))?;
    let receipt = signed_receipt.subject();
    let signed_lease =
        SignedSourceExportLeaseV1::from_canonical_bytes(receipt.signed_export_lease())
            .map_err(|_| state_error("Complete Acquire export lease is invalid"))?;
    let lease = signed_lease.subject();
    let resource = lease.resource();
    let proof_digest = digest_provider_proof(lease.proof());
    let resource_commitment = provider_resource_commitment_v1(resource, proof_digest);
    let mount_proof = mount_source_proof_class_from_provider_v1(lease.proof());
    let proof_class = match mount_proof {
        crate::MountSourceProofClassV1::ImmutableTree => {
            SourceAcquisitionProofClassV2::ImmutableTree
        }
        crate::MountSourceProofClassV1::LocalLive => SourceAcquisitionProofClassV2::LocalLive,
        crate::MountSourceProofClassV1::BestEffortReplica => {
            SourceAcquisitionProofClassV2::BestEffortReplica
        }
    };
    if proof_class == SourceAcquisitionProofClassV2::LocalLive {
        let binding = SourceRealizationBindingV1::from_canonical_bytes(&row.source_binding)
            .map_err(|_| state_error("Complete Acquire source binding is invalid"))?;
        if !binding.matches_local_live_provider_proof(lease.proof()) {
            return Err(state_error(
                "Complete Acquire live grant differs from its View source",
            ));
        }
    }
    let physical = mount_source_physical_proof_digest_v1(MountSourcePhysicalProofV1 {
        binding_digest: row.source_binding_digest,
        proof_class: mount_proof,
        provider_authority_id: lease.provider().authority_id(),
        provider_authority_generation: lease.provider().authority_generation(),
        provider_authority_digest: *lease.provider().authority_digest().as_bytes(),
        provider_resource_id: resource.resource_id(),
        provider_resource_generation: resource.resource_generation(),
        provider_resource_digest: *resource_commitment.as_bytes(),
        provider_catalog_generation: resource.catalog_generation(),
        provider_catalog_digest: *resource.catalog_digest().as_bytes(),
        kernel_boot_id: receipt.kernel_boot_id(),
        device: receipt.device(),
        inode: receipt.inode(),
        unique_mount_id: receipt.unique_mount_id(),
    });
    let observation = SourceRootObservationV1::new(
        receipt.kernel_boot_id(),
        receipt.device(),
        receipt.inode(),
        receipt.unique_mount_id(),
        true,
        true,
        true,
    )
    .map_err(|_| state_error("Complete Acquire descriptor observation is invalid"))?;
    let descriptor = source_root_descriptor_commitment_v1(&observation);
    let selection_floor = SourceSelectionFloorV1::new(
        ObjectDigest::from_bytes(row.provider_acquisition.acquisition_id),
        session.scope.provider_authority_id,
        session.scope.route_id,
        resource.clone(),
        signed_lease.signer().clone(),
        lease.lease_id(),
        digest_signed_export_lease(&signed_lease),
        lease.proof().class_code(),
        proof_digest,
        resource_commitment,
        session.trust_generation,
        ObjectDigest::from_bytes(session.trust_digest),
        session.revocation_generation,
        ObjectDigest::from_bytes(session.revocation_digest),
    )
    .map_err(|_| state_error("Complete Acquire selection floor is invalid"))?;
    let (catalog_floor, requested_selection_floor) = protocol_acquire_verification_floor_v2(
        attempt
            .acquire_verification_floor
            .as_ref()
            .ok_or_else(|| state_error("Complete Acquire lacks its pre-I/O verification floor"))?,
    )
    .map_err(|_| state_error("Complete Acquire verification floor is invalid"))?;
    if requested_selection_floor
        .as_ref()
        .is_some_and(|floor| floor != &selection_floor)
    {
        return Err(state_error(
            "Complete Acquire changes its pre-I/O selection floor",
        ));
    }
    let selection = selection_floor_snapshot_v2(&selection_floor);
    Ok(SourceAcquisitionEvidenceV2 {
        acquire_attempt: RecordRefV2 {
            id: attempt.attempt_id,
            revision: attempt.revision,
            record_digest: attempt.record_digest,
        },
        outcome_verification_anchor: *verification_anchor,
        provider_acquisition: row.provider_acquisition,
        session_id: session.session_id,
        provider_outcome_signer_digest: session.signers[3].public_key_fingerprint,
        historical_lease_signer: HistoricalLeaseSignerV2 {
            signer: session.signers[3].clone(),
            catalog_floor_provider_authority_id: catalog_floor.provider_authority_id(),
            catalog_floor_resource_namespace_digest: *catalog_floor
                .resource_namespace_digest()
                .as_bytes(),
            minimum_catalog_generation: catalog_floor.minimum_catalog_generation(),
            minimum_catalog_digest: *catalog_floor.minimum_catalog_digest().as_bytes(),
            selection_floor: selection,
            selection_floor_digest: *selection_floor.digest().as_bytes(),
        },
        provider_resource_id: resource.resource_id(),
        provider_resource_generation: resource.resource_generation(),
        provider_resource_digest: *resource_commitment.as_bytes(),
        provider_catalog_generation: resource.catalog_generation(),
        provider_catalog_digest: *resource.catalog_digest().as_bytes(),
        provider_selection_generation: resource.selection_generation(),
        provider_selection_digest: *resource.selection_digest().as_bytes(),
        provider_proof_class: lease.proof().class_code(),
        proof_class,
        provider_proof_digest: *proof_digest.as_bytes(),
        lease_id: lease.lease_id(),
        signed_lease_digest: *digest_signed_export_lease(&signed_lease).as_bytes(),
        lease_issued_seconds: lease.issued_seconds(),
        lease_expires_seconds: lease.expires_seconds(),
        source_realization_handle: mount_source_realization_handle_v1(
            row.source_binding_digest,
            physical,
        ),
        source_physical_proof_digest: physical,
        source_kernel_boot_id: receipt.kernel_boot_id(),
        source_device: receipt.device(),
        source_inode: receipt.inode(),
        source_unique_mount_id: receipt.unique_mount_id(),
        descriptor_commitment: *descriptor.as_bytes(),
    })
}
