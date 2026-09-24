//! Signed source-provider process protocol foundation.
//!
//! This crate owns the transport-neutral SourceProvider 1.0 wire contract used
//! between the root Mount broker and independently authoritative source
//! providers. It defines canonical messages and signatures, but deliberately
//! contains no socket paths, file descriptors, provider routing, journal state,
//! or backend evidence verification.
//! Mutually signed nonce-bearing hellos define a transcript-bound session;
//! requests and provider-signed statuses then carry exact direction-local
//! sequence values for caller-owned replay-state advancement.
//!
//! Every record uses the following outer frame:
//!
//! ```text
//! AOSSPV01 || major:u16be || minor:u16be || method:u8 || kind:u8 ||
//! flags:u16be=0 || reserved:u32be=0 || body-length:u32be || canonical-body
//! ```
//!
//! [`model`] owns operation values, [`proof`] owns backend proof claims,
//! [`codec`] owns the canonical wire representation, and [`crypto`] owns
//! domain-separated Ed25519 signatures and digests. [`trust`] models trust,
//! route, and supplied session inputs; [`verification`] authenticates signed
//! records and validates their complete graph. A future branded Linux adapter
//! must establish kernel-observation provenance before production use.
//! Linux `SOCK_SEQPACKET` and `SCM_RIGHTS` transport lives in
//! `aos-sandbox-linux`; descriptor integers and endpoint names never enter this
//! format.

mod accessors;
pub mod catalog_currentness;
pub mod catalog_manifest;
pub mod codec;
pub mod crypto;
pub mod model;
pub mod normalized_intent;
pub mod proof;
pub mod storage_live_export_lease;
pub mod storage_live_export_request;
pub mod trust;
pub mod verification;

pub use catalog_currentness::{
    CatalogCurrentnessErrorV1, CatalogCurrentnessQueryV1, SignedCatalogCurrentnessV1,
};
pub use catalog_manifest::{
    MAXIMUM_PROVIDER_CATALOG_ROWS_V1, ProviderCatalogManifestErrorV1, ProviderCatalogManifestV1,
    ProviderCatalogRowV1,
};
pub use codec::{
    MAXIMUM_FRAME_BYTES, SIGNED_SOURCE_PROVIDER_HELLO_BYTES, SOURCE_PROVIDER_HELLO_FRAME_BYTES,
    SOURCE_PROVIDER_HELLO_SUBJECT_BYTES, SourceProviderFrameError, SourceProviderFrameKind,
    SourceProviderMessageV1, decode_acquire_request, decode_acquire_response, decode_export_lease,
    decode_hello, decode_inventory, decode_inventory_request, decode_inventory_response,
    decode_message, decode_provider_proof, decode_provider_receipt, decode_release_receipt,
    decode_release_request, decode_release_response, decode_response_status,
    encode_acquire_request, encode_acquire_response, encode_export_lease, encode_hello,
    encode_inventory, encode_inventory_request, encode_inventory_response, encode_message,
    encode_provider_proof, encode_provider_receipt, encode_release_receipt, encode_release_request,
    encode_release_response, encode_response_status, validate_message_descriptor_contract,
};
pub use crypto::{
    SignedSourceExportLeaseV1, SignedSourceProviderHelloV1, SignedSourceProviderInventoryV1,
    SignedSourceProviderReceiptV1, SignedSourceProviderRequestV1, SignedSourceProviderStatusV1,
    SignedSourceReleaseReceiptV1, SourceProviderKeyUsageV1, SourceProviderSignature,
    SourceProviderSignatureError, SourceProviderSigningKeyV1, digest_acquire_request,
    digest_inventory, digest_inventory_request, digest_provider_proof, digest_provider_receipt,
    digest_release_receipt, digest_release_request, digest_signed_export_lease,
    digest_signed_hello, digest_signed_release_receipt, digest_signed_request,
    empty_descriptor_set_commitment_v1, provider_execution_commitment_v1,
    provider_resource_commitment_v1, provider_response_artifact_digest_v1,
    response_result_digest_v1, sign_export_lease, sign_hello, sign_inventory,
    sign_provider_receipt, sign_release_receipt, sign_request, sign_response_status,
    source_provider_session_binding_v1, verify_export_lease, verify_hello, verify_inventory,
    verify_provider_receipt, verify_provider_receipt_and_lease, verify_release_receipt,
    verify_request, verify_response_status,
};
pub use model::{
    ACQUIRE_SOURCE_REQUEST_VERSION_V1, ACQUIRE_SOURCE_REQUEST_VERSION_V2,
    ALL_PROOF_CLASS_CAPABILITIES, AcquireSourceRequestV1, AcquireSourceResponseV1,
    InventoryLeaseStateV1, InventorySourceRequestV1, InventorySourceResponseV1,
    MAXIMUM_BINDING_BYTES, MAXIMUM_INVENTORY_ENTRIES, MAXIMUM_RECURSIVE_BYTE_COUNT,
    MAXIMUM_RECURSIVE_DEPTH, MAXIMUM_RECURSIVE_ENTRY_COUNT, MAXIMUM_SOURCE_LEASE_SECONDS,
    MAXIMUM_SOURCE_SUBMOUNTS, ReleaseSourceRequestV1, ReleaseSourceResponseV1, SourceExportLeaseV1,
    SourceProviderAuthorityV1, SourceProviderDescriptorRole, SourceProviderFeature,
    SourceProviderHelloV1, SourceProviderInventoryEntryV1, SourceProviderInventoryV1,
    SourceProviderMethod, SourceProviderPeerRole, SourceProviderReceiptV1,
    SourceProviderResponseStatusV1, SourceProviderStatus, SourceProviderValidationError,
    SourceReleaseReceiptV1, SourceResourceV1, SourceUseV1, digest_logical_binding_bytes,
    prospective_mount_apply_template_digest_v1, source_acquisition_id_v2,
};
pub use normalized_intent::{
    MAXIMUM_NORMALIZED_ACQUISITION_INTENT_BYTES, NormalizedAcquisitionIntentError,
    NormalizedAcquisitionIntentV1, NormalizedAcquisitionIntentV2,
};
pub use proof::{
    BestEffortReplicaProofV1, ImmutablePublisherTreeProofV1, LocalLiveExportProofV1,
    RecursiveTopologyProofV1, SourceProviderProofV1, ZfsHeldSnapshotProofV1,
};
pub use storage_live_export_lease::{
    SignedStorageLiveExportLeaseV1, StorageLiveExportConsumerV1, StorageLiveExportLeaseErrorV1,
    StorageLiveExportLeaseV1, StorageLiveExportSignerV1, StorageLiveExportSourceV1,
    StorageLiveExportVerifierV1,
};
pub use storage_live_export_request::{
    SignedStorageLiveExportRequestV1, StorageLiveExportRequestErrorV1,
    StorageLiveExportRequestReplayV1, StorageLiveExportRequestV1, StorageLiveExportSelectorV1,
};
pub use trust::{
    MAXIMUM_SOURCE_PROVIDER_AUTHORITY_TRUSTS, MAXIMUM_SOURCE_PROVIDER_KEY_TRUSTS,
    MAXIMUM_SOURCE_SELECTION_FLOORS, ProtectedRootMountPeerV1, ProtectedSourceProviderRouteV1,
    ProviderCatalogFloorV1, SourceProviderAuthorityTrustStateV1, SourceProviderAuthorityTrustV1,
    SourceProviderCurrentAuthorityV1, SourceProviderIngressSessionV1,
    SourceProviderKeyTrustStateV1, SourceProviderKeyTrustV1, SourceProviderProcessIdentityV1,
    SourceProviderSessionV1, SourceProviderTrustError, SourceProviderTrustSetV1,
    SourceSelectionFloorV1, source_provider_signer_set_commitment_v1,
    source_provider_trust_set_digest_v1,
};
pub use verification::{
    ProviderRequestSequenceExpectationV1, ProviderRequestVerificationContextV1,
    SourceProviderVerificationContextV1, SourceProviderVerificationError, SourceRootObservationV1,
    VerifiedProviderAcquireRequestV1, VerifiedProviderIngressProjectionV1,
    VerifiedProviderInventoryRequestV1, VerifiedProviderReleaseRequestV1,
    VerifiedProviderRequestAttemptV1, VerifiedProviderRequestReplayV1,
    VerifiedProviderRequestSequenceAdvanceV1, VerifiedProviderRequestSequenceV1,
    VerifiedProviderRequestV1, VerifiedRootMountProcessProjectionV1, VerifiedSourceAcquisitionV1,
    VerifiedSourceInventoryV1, VerifiedSourceProviderDispositionV1,
    VerifiedSourceProviderSequenceV1, VerifiedSourceReleaseV1,
    source_provider_acquire_intent_digest_v1, source_provider_inventory_intent_digest_v1,
    source_provider_release_intent_digest_v1, source_provider_request_attempt_digest_v1,
    source_root_descriptor_commitment_v1, verify_acquire, verify_provider_request, verify_release,
    verify_source_inventory,
};
