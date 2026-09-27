//! Synthetic cryptographic graph tests; no protected owner or native effect is activated.

use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::{Signer as _, SigningKey};

use super::*;
use crate::*;

fn d(byte: u8) -> ObjectDigest {
    ObjectDigest::from_bytes([byte; 32])
}

struct Fixture {
    request: SignedStorageNativeAcquireRequestV2,
    root_key: SigningKey,
    provider_key: SigningKey,
    storage_key: SigningKey,
    receipt: SignedStorageZfsHoldReceiptV1,
    acceptance: SignedStorageNativeAcceptanceV2,
    descriptor: SourceRootObservationV1,
    verifier: StorageZfsHoldVerifierV1,
}

impl Fixture {
    fn new() -> Self {
        let root_key = SigningKey::from_bytes(&[51; 32]);
        let provider_key = SigningKey::from_bytes(&[52; 32]);
        let storage_key = SigningKey::from_bytes(&[53; 32]);
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
        let binding = b"native-original-root-binding".to_vec();
        let binding_digest = digest_logical_binding_bytes(&binding);
        let root = AcquireSourceRequestV1::new_v2(
            d(1),
            2,
            [3; 16],
            4,
            template,
            template_digest,
            SourceUseV1::MountCreate,
            [5; 16],
            [6; 16],
            [7; 16],
            8,
            d(9),
            binding,
            binding_digest,
            1000,
            60,
            d(10),
            false,
            0,
            true,
        )
        .unwrap();
        let root_signer = SourceProviderSigningKeyV1::for_signing_key(
            [7; 16],
            8,
            d(9),
            [11; 16],
            12,
            SourceProviderKeyUsageV1::RootMountRecord,
            &root_key,
        )
        .unwrap();
        let signed_root = sign_request(
            SourceProviderMethod::Acquire,
            encode_acquire_request(&root),
            root_signer,
            &root_key,
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
            d(20),
            d(21),
            d(22),
        )
        .unwrap();
        let catalog = ProviderHeldSnapshotCatalogV1::new(
            23,
            d(24),
            vec![
                ProviderHeldSnapshotRowV1::new(
                    binding_digest,
                    [25; 32],
                    26,
                    d(27),
                    28,
                    d(29),
                    snapshot,
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let claims = StorageZfsHoldTransportRequestV1::new(
            30,
            [31; 32],
            d(32),
            [33; 16],
            root.holder_authority_id(),
            root.session_binding(),
            root.acquisition_id(),
            binding_digest,
            d(34),
            900,
            930,
            catalog,
        )
        .unwrap();
        let request = StorageNativeAcquireRequestV2::new(claims, signed_root).unwrap();
        let provider_signer = SourceProviderSigningKeyV1::for_signing_key(
            [33; 16],
            35,
            d(36),
            [37; 16],
            38,
            SourceProviderKeyUsageV1::ProviderOutcome,
            &provider_key,
        )
        .unwrap();
        let request =
            SignedStorageNativeAcquireRequestV2::sign(request, provider_signer, &provider_key)
                .unwrap();
        let claims = request.request().claims();
        let catalog = claims.catalog();
        let (resource, snapshot) = catalog
            .select_under_head(
                catalog.generation(),
                catalog.digest(),
                catalog.namespace_digest(),
                binding_digest,
            )
            .unwrap();
        let head = StorageZfsHoldHeadV1::new(39, d(40), 41, d(42), 43, d(44), d(45)).unwrap();
        let subject = StorageZfsHoldReceiptV1::new(
            claims.attempt().0,
            claims.attempt().1,
            binding_digest,
            resource,
            snapshot,
            head,
            900,
            930,
        )
        .unwrap();
        let signer = StorageZfsHoldSignerV1::new([46; 16], 41, d(42), [47; 16], 48).unwrap();
        let receipt = sign_receipt(subject, signer, &storage_key);
        let descriptor =
            SourceRootObservationV1::new([6; 16], 49, 50, 51, true, true, true).unwrap();
        let acceptance = StorageNativeAcceptanceV2::new(
            [54; 16],
            request.digest(),
            receipt.digest(),
            descriptor.clone(),
        )
        .unwrap();
        let acceptance = SignedStorageNativeAcceptanceV2::sign(acceptance, signer, &storage_key);
        let verifier =
            StorageZfsHoldVerifierV1::new(signer, storage_key.verifying_key().to_bytes()).unwrap();
        Self {
            request,
            root_key,
            provider_key,
            storage_key,
            receipt,
            acceptance,
            descriptor,
            verifier,
        }
    }

    fn reply(&self) -> StorageNativeAcquireReplyV2 {
        StorageNativeAcquireReplyV2::new(self.acceptance.clone(), self.receipt.clone()).unwrap()
    }

    fn verify(
        &self,
        reply: &StorageNativeAcquireReplyV2,
        observed: &SourceRootObservationV1,
        roles: &[SourceProviderDescriptorRole],
    ) -> Result<VerifiedStorageNativeAcquireV2, StorageNativeAcquireErrorV2> {
        reply.verify_for(StorageNativeAcquireVerificationV2 {
            request: &self.request,
            provider_signer: self.request.signer(),
            provider_key: &self.provider_key.verifying_key().to_bytes(),
            root_signer: self.request.request().signed_root_request().signer(),
            root_key: &self.root_key.verifying_key().to_bytes(),
            storage_verifier: self.verifier,
            expected_receipt: self.receipt.receipt(),
            observed_descriptor: observed,
            descriptor_roles: roles,
            now_seconds: 910,
        })
    }
}

fn sign_receipt(
    subject: StorageZfsHoldReceiptV1,
    signer: StorageZfsHoldSignerV1,
    key: &SigningKey,
) -> SignedStorageZfsHoldReceiptV1 {
    let unsigned = SignedStorageZfsHoldReceiptV1::new(subject.clone(), signer, [0; 64]);
    SignedStorageZfsHoldReceiptV1::new(
        subject,
        signer,
        key.sign(&unsigned.signing_message()).to_bytes(),
    )
}

#[test]
fn canonical_native_graph_is_distinct_from_negative_only_carrier() {
    let fixture = Fixture::new();
    let request = fixture.request.to_canonical_bytes();
    assert_eq!(
        SignedStorageNativeAcquireRequestV2::from_canonical_bytes(&request).unwrap(),
        fixture.request
    );
    assert!(
        SignedStorageNativeAcquireRequestV2::from_canonical_bytes(
            &fixture.request.request().claims().to_canonical_bytes()
        )
        .is_err()
    );
    assert!(StorageZfsHoldTransportRequestV1::from_canonical_bytes(&request).is_err());
    assert_eq!(
        fixture.acceptance.acceptance().to_canonical_bytes().len(),
        136
    );
    assert_eq!(fixture.acceptance.to_canonical_bytes().len(), 288);
    let reply = fixture.reply();
    assert_eq!(reply.to_canonical_bytes().len(), 1112);
    assert_eq!(
        StorageNativeAcquireReplyV2::from_canonical_bytes(&reply.to_canonical_bytes()).unwrap(),
        reply
    );
    let verified = fixture
        .verify(
            &reply,
            &fixture.descriptor,
            &[SourceProviderDescriptorRole::SourceRoot],
        )
        .unwrap();
    assert_eq!(verified.request_digest(), fixture.request.digest());
    assert_eq!(verified.receipt_digest(), fixture.receipt.digest());
    assert_eq!(
        verified.signed_acceptance_digest(),
        fixture.acceptance.digest()
    );
    assert_eq!(
        verified.acceptance().descriptor_commitment(),
        source_root_descriptor_commitment_v1(&fixture.descriptor)
    );

    for offset in [0, 8, 10, 16, 17, 18, 19] {
        let mut changed = request.clone();
        changed[offset] ^= 0x80;
        assert!(
            SignedStorageNativeAcquireRequestV2::from_canonical_bytes(&changed).is_err(),
            "request offset {offset}"
        );
    }
    assert!(
        SignedStorageNativeAcquireRequestV2::from_canonical_bytes(&request[..request.len() - 1])
            .is_err()
    );
    let mut trailing = request.clone();
    trailing.push(1);
    assert!(SignedStorageNativeAcquireRequestV2::from_canonical_bytes(&trailing).is_err());
    for offset in [8, 10, 16, 18, 19] {
        let mut changed = reply.to_canonical_bytes();
        changed[offset] ^= 1;
        assert!(
            StorageNativeAcquireReplyV2::from_canonical_bytes(&changed).is_err(),
            "reply offset {offset}"
        );
    }
}

#[test]
fn signatures_and_exact_original_request_cannot_be_replaced() {
    let fixture = Fixture::new();
    let mut wire = fixture.request.to_canonical_bytes();
    let signature_offset = wire.len() - 1;
    wire[signature_offset] ^= 1;
    let changed = SignedStorageNativeAcquireRequestV2::from_canonical_bytes(&wire).unwrap();
    assert_eq!(
        changed.verify(
            fixture.request.signer(),
            &fixture.provider_key.verifying_key().to_bytes(),
            fixture.request.request().signed_root_request().signer(),
            &fixture.root_key.verifying_key().to_bytes()
        ),
        Err(StorageNativeAcquireErrorV2::Authority)
    );
    assert_eq!(
        changed.require_exact_replay(&fixture.request),
        Err(StorageNativeAcquireErrorV2::ReplayConflict)
    );
    assert!(
        fixture
            .request
            .verify(
                fixture.request.signer(),
                &fixture.root_key.verifying_key().to_bytes(),
                fixture.request.request().signed_root_request().signer(),
                &fixture.root_key.verifying_key().to_bytes()
            )
            .is_err()
    );

    let foreign_key = SigningKey::from_bytes(&[60; 32]);
    let wrong_acceptance = SignedStorageNativeAcceptanceV2::sign(
        fixture.acceptance.acceptance().clone(),
        fixture.receipt.signer(),
        &foreign_key,
    );
    let wrong_reply =
        StorageNativeAcquireReplyV2::new(wrong_acceptance, fixture.receipt.clone()).unwrap();
    assert_eq!(
        fixture.verify(
            &wrong_reply,
            &fixture.descriptor,
            &[SourceProviderDescriptorRole::SourceRoot]
        ),
        Err(StorageNativeAcquireErrorV2::Authority)
    );
    let wrong_subject = StorageNativeAcceptanceV2::new(
        [54; 16],
        d(61),
        fixture.receipt.digest(),
        fixture.descriptor.clone(),
    )
    .unwrap();
    let wrong_reply = StorageNativeAcquireReplyV2::new(
        SignedStorageNativeAcceptanceV2::sign(
            wrong_subject,
            fixture.receipt.signer(),
            &fixture.storage_key,
        ),
        fixture.receipt.clone(),
    )
    .unwrap();
    assert_eq!(
        fixture.verify(
            &wrong_reply,
            &fixture.descriptor,
            &[SourceProviderDescriptorRole::SourceRoot]
        ),
        Err(StorageNativeAcquireErrorV2::Mismatch)
    );
}

#[test]
fn missing_fd_cold_remount_reboot_and_total_custody_loss_never_complete() {
    let fixture = Fixture::new();
    let reply = fixture.reply();
    assert!(fixture.verify(&reply, &fixture.descriptor, &[]).is_err());
    assert!(
        fixture
            .verify(
                &reply,
                &fixture.descriptor,
                &[
                    SourceProviderDescriptorRole::SourceRoot,
                    SourceProviderDescriptorRole::SourceRoot
                ]
            )
            .is_err()
    );
    let verified = fixture
        .verify(
            &reply,
            &fixture.descriptor,
            &[SourceProviderDescriptorRole::SourceRoot],
        )
        .unwrap();
    for descriptor in [
        SourceRootObservationV1::new([6; 16], 49, 50, 52, true, true, true).unwrap(),
        SourceRootObservationV1::new([62; 16], 49, 50, 51, true, true, true).unwrap(),
        SourceRootObservationV1::new([6; 16], 49, 63, 51, true, true, true).unwrap(),
    ] {
        assert!(
            fixture
                .verify(
                    &reply,
                    &descriptor,
                    &[SourceProviderDescriptorRole::SourceRoot]
                )
                .is_err()
        );
        assert_eq!(
            verified.require_exact_live_retry(
                &descriptor,
                StorageNativeDescriptorCustodyV2::RetainedOriginal
            ),
            Err(StorageNativeAcquireErrorV2::Mismatch)
        );
    }
    assert_eq!(
        verified
            .require_exact_live_retry(&fixture.descriptor, StorageNativeDescriptorCustodyV2::Lost),
        Err(StorageNativeAcquireErrorV2::CustodyLost)
    );
    assert!(
        verified
            .require_exact_live_retry(
                &fixture.descriptor,
                StorageNativeDescriptorCustodyV2::RetainedOriginal
            )
            .is_ok()
    );
}

#[test]
fn authenticated_cleanup_is_exact_and_never_a_positive_reply() {
    let fixture = Fixture::new();
    let query = StorageNativeCleanupRequestV2::new(
        1,
        d(64),
        [65; 32],
        StorageNativeCleanupReasonV2::CustodyLost,
        &fixture.request,
        fixture.acceptance.acceptance(),
    )
    .unwrap();
    let query = SignedStorageNativeCleanupRequestV2::sign(
        query,
        fixture.request.signer().clone(),
        &fixture.provider_key,
    )
    .unwrap();
    assert_eq!(
        SignedStorageNativeCleanupRequestV2::from_canonical_bytes(&query.to_canonical_bytes())
            .unwrap(),
        query
    );
    query
        .verify(
            fixture.request.signer(),
            &fixture.provider_key.verifying_key().to_bytes(),
        )
        .unwrap();
    let subject = StorageNativeCleanupReceiptV2::new(
        &query,
        d(66),
        StorageNativeCleanupDispositionV2::Absent,
    )
    .unwrap();
    let response = SignedStorageNativeCleanupReceiptV2::sign(
        subject.clone(),
        fixture.receipt.signer(),
        &fixture.storage_key,
    );
    assert_eq!(
        SignedStorageNativeCleanupReceiptV2::from_canonical_bytes(&response.to_canonical_bytes())
            .unwrap(),
        response
    );
    response
        .verify_for(&query, &subject, fixture.verifier)
        .unwrap();
    assert!(
        StorageNativeAcquireReplyV2::from_canonical_bytes(&response.to_canonical_bytes()).is_err()
    );

    let other_query = StorageNativeCleanupRequestV2::new(
        2,
        d(64),
        [67; 32],
        StorageNativeCleanupReasonV2::CustodyLost,
        &fixture.request,
        fixture.acceptance.acceptance(),
    )
    .unwrap();
    let other_query = SignedStorageNativeCleanupRequestV2::sign(
        other_query,
        fixture.request.signer().clone(),
        &fixture.provider_key,
    )
    .unwrap();
    assert_eq!(
        response.verify_for(&other_query, &subject, fixture.verifier),
        Err(StorageNativeAcquireErrorV2::Mismatch)
    );
    let other_subject = StorageNativeCleanupReceiptV2::new(
        &query,
        d(68),
        StorageNativeCleanupDispositionV2::Retired,
    )
    .unwrap();
    assert_eq!(
        response.verify_for(&query, &other_subject, fixture.verifier),
        Err(StorageNativeAcquireErrorV2::Mismatch)
    );
    let mut changed = response.to_canonical_bytes();
    changed[119] = 1;
    assert!(SignedStorageNativeCleanupReceiptV2::from_canonical_bytes(&changed).is_err());
}
