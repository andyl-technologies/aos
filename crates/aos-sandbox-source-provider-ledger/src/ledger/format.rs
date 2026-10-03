//! Canonical AOSSPL01 record envelopes, keys, and bodies.
//!
//! ```text
//! AOSSPL01 | version:u16be=5 | kind:u8 | state:u8 | flags:u16be |
//! reserved:u16be | body_len:u32be | reserved:u32be | revision:u64be |
//! record_digest[32] | body[body_len]
//! ```
//!
//! Version 5 is the accepted baseline family member. Older versions are not decoded or
//! upgraded in place: opening a namespace containing them fails before graph
//! allocation with an explicit offline-migration error. This prevents an
//! ambiguous dual interpretation of records without protected completion time.
//! Digest-only native completion uses a version-5 envelope and version-2 body.
//! Exact native request retention uses a version-6 envelope and version-3 body.
//! Original paired-clock retention uses a version-7 envelope and version-4 body;
//! version-6 rows cannot infer an anchor or supply positive recovery authority.
//! Mixed graphs retain version-5 baseline records; older readers reject the
//! new native body and cannot silently activate it.
//! Separate envelope9/body1 retains pre-Requested Source closure DATA; only its
//! explicit cold decoder accepts it, without constructing a live native request.
//!
//! The seven baseline closed bodies use these exact semantic orders; `authority` is a
//! 56-byte authority tuple, `signer` is the protocol's canonical 120-byte
//! signer reference. Optional fixed-width values use their all-zero sentinel;
//! variable artifacts have explicit presence and length fields.
//!
//! ```text
//! AuthorityHead(632): authority, trust-head, revocation-head, validity,
//! route-head, namespace, capabilities/recursive/kernel/pad[5], hello-signer,
//! outcome-signer, catalog-head, inventory-head, lease-gen, release-gen,
//! active-count, reserved[40]
//! CatalogHead(476+publication): authority, namespace, catalog-head,
//! publisher-id, publication-gen/receipt/time/trust/revocation, predecessor-head,
//! floor-head, publisher-signer, publication-length, canonical-publication
//! HolderHead(1232+hellos): provider, holder, session-binding, boot-id,
//! root/provider-process, provider-pid/start/execution-commitment, writer,
//! route/namespace, trust/revocation, signers[4], signer-commitment,
//! request/response/acquisition floors and next heads, pending/last-attempt, hello
//! lengths/digests, root-hello, provider-hello
//! SessionHistory(1232+hellos): exact immutable HolderHead body keyed by its
//! session binding; state is historical rather than current-head
//! Attempt(960+frames): provider, holder, root-record-signer, method/status,
//! request-id, request/typed/intent/attempt digests, session/request-response sequences/deadline,
//! verification/completion/current-validity, negotiated policy, processes, signer-set,
//! optional old-attempt/session/fence recovery bridge including fence class
//! and authenticated current revocation head, frame lengths/digests,
//! descriptor/result, response catalog, signed-request/completed-response
//! Acquisition(824+artifacts): provider, holder, acquisition sequence/effect/intent,
//! effect/current/lease attempts, lease generation/id/digest, resource/catalog/
//! selection/proof commitments, backend-id, native terminal reservation digest,
//! release-effect, artifact lengths,
//! lease-history, normalized-intent, evidence, reopen-identity, signed-lease
//! Release(464+artifacts): provider, holder, acquisition sequence/lease/effect,
//! release-generation, effect/current attempts, backend-id, evidence/observation/time,
//! receipt/artifact digest, acquisition-record digest, evidence, receipt
//! ```

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    SignedSourceExportLeaseV1, SignedSourceProviderHelloV1, SignedSourceProviderRequestV1,
    SourceProviderKeyUsageV1, SourceProviderMethod, digest_provider_proof,
    digest_signed_export_lease, digest_signed_hello, digest_signed_request,
    provider_resource_commitment_v1, source_provider_request_attempt_digest_v1,
    source_provider_session_binding_v1, source_provider_signer_set_commitment_v1,
};
use sha2::{Digest as _, Sha256};

use super::LedgerFormatErrorV1;
use super::codec::{Decoder, Encoder, read_array, read_u32, read_u64};
use super::evidence::BackendEvidenceV1;
use super::model::{
    AcquisitionKeyV1, AcquisitionRecordV1, AttemptKeyV1, AttemptRecordV1, AuthorityHeadRecordV1,
    CatalogHeadRecordV1, DecodedRecordV1, HolderSessionHeadRecordV1, LeaseLineageV1,
    ProviderAcquisitionStateV1, ProviderAttemptStateV1, ProviderAuthorityStateV1,
    ProviderReleaseStateV1, RecordKind, ReleaseKeyV1, ReleaseRecordV1, SourceRootIdentityV1,
    WriterIdentityV1,
};
pub use super::primitives::{
    acquisition_key, attempt_key, authority_key, catalog_key, release_key, session_history_key,
    session_key,
};
use super::primitives::{
    decode_acquisition_state, decode_attempt_state, decode_authority_state, decode_method,
    decode_optional_status, decode_release_state, optional_bytes_digest,
};
use super::reopen::ReopenIdentityV1;
use crate::NormalizedAcquisitionIntentV1;
use crate::limits::{
    MAXIMUM_SIGNED_HELLO_BYTES, MAXIMUM_SIGNED_LEASE_BYTES, MAXIMUM_SIGNED_RELEASE_RECEIPT_BYTES,
    MAXIMUM_SIGNED_REQUEST_OR_RESPONSE_BYTES,
};

const MAGIC: &[u8; 8] = b"AOSSPL01";
// Version 5 also retains the original native no-dispatch reservation digest.
// The earlier completion-time field still prevents historical time substitution.
const VERSION: u16 = 5;
const ENVELOPE_BYTES: usize = 64;
const HEADER_BYTES: usize = 32;

const AUTHORITY_DOMAIN: &[u8] = b"aos.sandbox.source-provider.ledger.authority-head.v1\0";
const CATALOG_DOMAIN: &[u8] = b"aos.sandbox.source-provider.ledger.catalog-head.v1\0";
const SESSION_DOMAIN: &[u8] = b"aos.sandbox.source-provider.ledger.session-head.v1\0";
const SESSION_HISTORY_DOMAIN: &[u8] = b"aos.sandbox.source-provider.ledger.session-history.v1\0";
const ATTEMPT_DOMAIN: &[u8] = b"aos.sandbox.source-provider.ledger.attempt.v1\0";
const ACQUISITION_DOMAIN: &[u8] = b"aos.sandbox.source-provider.ledger.acquisition.v1\0";
const RELEASE_DOMAIN: &[u8] = b"aos.sandbox.source-provider.ledger.release.v1\0";
const NATIVE_COMPLETION_DOMAIN: &[u8] =
    b"aos.sandbox.source-provider.ledger.native-completion.v2\0";

const AUTHORITY_BODY_BYTES: usize = 632;
const CATALOG_FIXED_BYTES: usize = 476;
const MAXIMUM_CATALOG_PUBLICATION_BYTES: usize = 520;
const SESSION_FIXED_BYTES: usize = 1_232;
const ATTEMPT_FIXED_BYTES: usize = 960;
const ACQUISITION_FIXED_BYTES: usize = 824;
const LEASE_LINEAGE_BYTES: usize = 88;
const RELEASE_FIXED_BYTES: usize = 464;
const AUTHORITY_SEMANTIC_BYTES: usize = 592;
const SESSION_SEMANTIC_BYTES: usize = 1_232;
const ATTEMPT_SEMANTIC_BYTES: usize = 864;
const ACQUISITION_SEMANTIC_BYTES: usize = 820;
const RELEASE_SEMANTIC_BYTES: usize = 464;
const ATTEMPT_RESERVED_BYTES: usize = ATTEMPT_FIXED_BYTES - ATTEMPT_SEMANTIC_BYTES;
const ACQUISITION_RESERVED_BYTES: usize = ACQUISITION_FIXED_BYTES - ACQUISITION_SEMANTIC_BYTES;
const SESSION_RECORD_MAXIMUM_BYTES: usize =
    ENVELOPE_BYTES + SESSION_FIXED_BYTES + 2 * MAXIMUM_SIGNED_HELLO_BYTES;
const ATTEMPT_RECORD_MAXIMUM_BYTES: usize =
    ENVELOPE_BYTES + ATTEMPT_FIXED_BYTES + 2 * MAXIMUM_SIGNED_REQUEST_OR_RESPONSE_BYTES;
const ACQUISITION_RECORD_COMMON_MAXIMUM_BYTES: usize = ENVELOPE_BYTES
    + ACQUISITION_FIXED_BYTES
    + crate::limits::MAXIMUM_BACKEND_EVIDENCE_PAYLOAD_BYTES
    + 120
    + 256
    + MAXIMUM_SIGNED_LEASE_BYTES
    + LEASE_LINEAGE_BYTES * crate::limits::MAXIMUM_LEASE_HISTORY_PER_ACQUISITION;

// Only the nested normalized profile grows; the ledger's fixed layout is shared.
const ACQUISITION_RECORD_LEGACY_INTENT_MAXIMUM_BYTES: usize =
    ACQUISITION_RECORD_COMMON_MAXIMUM_BYTES
        + aos_sandbox_source_provider_protocol::MAXIMUM_NORMALIZED_ACQUISITION_INTENT_V2_BYTES;
const ACQUISITION_RECORD_MAXIMUM_BYTES: usize =
    ACQUISITION_RECORD_COMMON_MAXIMUM_BYTES + crate::MAXIMUM_NORMALIZED_ACQUISITION_INTENT_BYTES;

const RELEASE_RECORD_MAXIMUM_BYTES: usize = ENVELOPE_BYTES
    + RELEASE_FIXED_BYTES
    + crate::limits::MAXIMUM_BACKEND_EVIDENCE_PAYLOAD_BYTES
    + 120
    + MAXIMUM_SIGNED_RELEASE_RECEIPT_BYTES;

// Capacity projections borrow the codec's bound; they do not maintain a second
// Release length policy or confuse its95-byte key with legacy capacity syntax.
pub(crate) const fn maximum_release_value_bytes() -> usize {
    RELEASE_RECORD_MAXIMUM_BYTES
}

/// Bounds all six owner records in an atomic native Acquire completion.
///
/// This adds the format maxima for attempt, acquisition, current and historical
/// session, authority, and native carrier, including their exact key widths and
/// nine-byte mutation framing. It does not include the journal frame headers or
/// a global capacity-reservation deletion; the owner accounts for those too.
pub const MAXIMUM_NATIVE_ACQUIRE_COMPLETION_OWNER_BYTES_V2: usize =
    NATIVE_ACQUIRE_COMPLETION_OWNER_RECORD_BOUNDS_V2[0]
        + NATIVE_ACQUIRE_COMPLETION_OWNER_RECORD_BOUNDS_V2[1]
        + NATIVE_ACQUIRE_COMPLETION_OWNER_RECORD_BOUNDS_V2[2]
        + NATIVE_ACQUIRE_COMPLETION_OWNER_RECORD_BOUNDS_V2[3]
        + NATIVE_ACQUIRE_COMPLETION_OWNER_RECORD_BOUNDS_V2[4]
        + NATIVE_ACQUIRE_COMPLETION_OWNER_RECORD_BOUNDS_V2[5];

/// Bounds the six atomic native owner mutations in semantic record order.
///
/// The order is attempt, acquisition, current session, historical session,
/// authority, native carrier. Each bound includes its key and mutation framing.
pub const NATIVE_ACQUIRE_COMPLETION_OWNER_RECORD_BOUNDS_V2: [usize; 6] = [
    ATTEMPT_RECORD_MAXIMUM_BYTES + 96 + 9,
    ACQUISITION_RECORD_MAXIMUM_BYTES + 99 + 9,
    SESSION_RECORD_MAXIMUM_BYTES + 63 + 9,
    SESSION_RECORD_MAXIMUM_BYTES + 103 + 9,
    ENVELOPE_BYTES + AUTHORITY_BODY_BYTES + 49 + 9,
    ENVELOPE_BYTES + super::native_completion::MAXIMUM_BODY_BYTES + 40 + 9,
];

/// Bounds seven owner mutations in the native lease-bearing Release admission.
///
/// This is a distinct admission geometry, not the six-row Acquire completion
/// or its persistent seven-record cleanup floor. The Release intent is added
/// alongside the original native marker, not substituted for it.
pub const MAXIMUM_NATIVE_RELEASE_ADMISSION_OWNER_BYTES_V1: usize =
    MAXIMUM_NATIVE_ACQUIRE_COMPLETION_OWNER_BYTES_V2 + RELEASE_RECORD_MAXIMUM_BYTES + 99 + 9;

/// Bounds the three status-only Release completion owner mutations.
///
/// Includes Attempt, current Session and SessionHistory keys and mutation
/// framing. No acquisition, native marker or Release intent changes here.
pub const MAXIMUM_NATIVE_RELEASE_STATUS_OWNER_BYTES_V1: usize =
    NATIVE_ACQUIRE_COMPLETION_OWNER_RECORD_BOUNDS_V2[0]
        + NATIVE_ACQUIRE_COMPLETION_OWNER_RECORD_BOUNDS_V2[2]
        + NATIVE_ACQUIRE_COMPLETION_OWNER_RECORD_BOUNDS_V2[3];

const _: () = assert!(
    MAXIMUM_NATIVE_RELEASE_ADMISSION_OWNER_BYTES_V1 < crate::limits::MAXIMUM_TRANSACTION_BYTES
);

/// Bounds one exact native request or accepted-carrier mutation.
///
/// Includes its canonical envelope, fixed key and mutation framing, but not
/// the journal frame headers.
pub const MAXIMUM_NATIVE_ACQUIRE_CARRIER_MUTATION_BYTES_V2: usize =
    ENVELOPE_BYTES + super::native_completion::MAXIMUM_BODY_BYTES + 40 + 9;

const _: () = assert!(
    MAXIMUM_NATIVE_ACQUIRE_COMPLETION_OWNER_BYTES_V2 < crate::limits::MAXIMUM_TRANSACTION_BYTES
);

const _: () = assert!(ENVELOPE_BYTES == 64);
const _: () = assert!(AUTHORITY_BODY_BYTES + ENVELOPE_BYTES == 696);
const _: () = assert!(AUTHORITY_SEMANTIC_BYTES + 40 == AUTHORITY_BODY_BYTES);
const _: () = assert!(CATALOG_FIXED_BYTES == 264 + 88 + 120 + 4);
const _: () = assert!(SESSION_SEMANTIC_BYTES == SESSION_FIXED_BYTES);
const _: () = assert!(ATTEMPT_SEMANTIC_BYTES + ATTEMPT_RESERVED_BYTES == ATTEMPT_FIXED_BYTES);
const _: () =
    assert!(ACQUISITION_SEMANTIC_BYTES + ACQUISITION_RESERVED_BYTES == ACQUISITION_FIXED_BYTES);
const _: () = assert!(RELEASE_SEMANTIC_BYTES == RELEASE_FIXED_BYTES);
const _: () = assert!(SESSION_RECORD_MAXIMUM_BYTES == 9_488);
const _: () = assert!(ATTEMPT_RECORD_MAXIMUM_BYTES == 2_098_176);
const _: () = assert!(ACQUISITION_RECORD_LEGACY_INTENT_MAXIMUM_BYTES == 487_052);
const _: () = assert!(ACQUISITION_RECORD_MAXIMUM_BYTES == 487_228);
const _: () = assert!(
    ACQUISITION_RECORD_MAXIMUM_BYTES - ACQUISITION_RECORD_LEGACY_INTENT_MAXIMUM_BYTES == 176
);
const _: () = assert!(8 + 16 + 32 + 32 == LEASE_LINEAGE_BYTES);
const _: () = assert!(RELEASE_RECORD_MAXIMUM_BYTES == 131_720);

/// Encodes one provider authority head in canonical AOSSPL01 form.
#[must_use]
pub fn encode_authority(value: &AuthorityHeadRecordV1) -> Vec<u8> {
    let key = authority_key(value.provider.authority_id());
    let mut body = Encoder::with_capacity(AUTHORITY_BODY_BYTES);
    body.authority(&value.provider);
    body.u64(value.trust_generation);
    body.digest(value.trust_digest);
    body.u64(value.revocation_generation);
    body.digest(value.revocation_digest);
    body.i64(value.valid_from_seconds);
    body.i64(value.valid_until_seconds);
    body.array(&value.route_id);
    body.u64(value.route_generation);
    body.digest(value.route_digest);
    body.digest(value.resource_namespace_digest);
    body.u8(value.proof_class_capabilities);
    body.u8(u8::from(value.supports_recursive));
    body.u8(u8::from(value.supports_kernel_coupled));
    body.zeros(5);
    body.signer(&value.provider_hello_signer);
    body.signer(&value.provider_outcome_signer);
    body.u64(value.catalog_generation);
    body.digest(value.catalog_digest);
    body.u64(value.inventory_generation);
    body.digest(value.inventory_state_digest);
    body.u64(value.last_lease_issue_generation);
    body.u64(value.last_release_generation);
    body.u64(value.active_lease_count);
    body.zeros(40);
    debug_assert_eq!(body.len(), AUTHORITY_BODY_BYTES);
    encode_envelope(
        RecordKind::AuthorityHead,
        value.state as u8,
        value.revision,
        &key,
        body.as_slice(),
    )
}

/// Encodes one immutable catalog generation in canonical AOSSPL01 form.
#[must_use]
pub fn encode_catalog(value: &CatalogHeadRecordV1) -> Vec<u8> {
    let key = catalog_key(value.provider.authority_id(), value.catalog_generation);
    let mut body = Encoder::with_capacity(CATALOG_FIXED_BYTES + value.canonical_publication.len());
    body.authority(&value.provider);
    body.digest(value.resource_namespace_digest);
    body.u64(value.catalog_generation);
    body.digest(value.catalog_digest);
    body.array(&value.publisher_authority_id);
    body.u64(value.publication_generation);
    body.digest(value.publication_receipt_digest);
    body.u64(value.predecessor_catalog_generation);
    body.digest(value.predecessor_catalog_digest);
    body.u64(value.catalog_floor_generation);
    body.digest(value.catalog_floor_digest);
    body.i64(value.publication_seconds);
    body.u64(value.publication_trust_generation);
    body.digest(value.publication_trust_digest);
    body.u64(value.publication_revocation_generation);
    body.digest(value.publication_revocation_digest);
    body.signer(&value.publisher_signer);
    body.u32(value.canonical_publication.len() as u32);
    debug_assert_eq!(body.len(), CATALOG_FIXED_BYTES);
    body.bytes(&value.canonical_publication);
    encode_envelope(
        RecordKind::CatalogHead,
        0,
        value.revision,
        &key,
        body.as_slice(),
    )
}

/// Encodes one current holder-session head in canonical AOSSPL01 form.
#[must_use]
pub fn encode_session(value: &HolderSessionHeadRecordV1) -> Vec<u8> {
    let key = session_key(value.provider.authority_id(), value.holder.authority_id());
    encode_session_record(value, RecordKind::SessionHead, key)
}

/// Encodes one immutable session transcript in canonical AOSSPL01 form.
#[must_use]
pub fn encode_session_history(value: &HolderSessionHeadRecordV1) -> Vec<u8> {
    let key = session_history_key(
        value.provider.authority_id(),
        value.holder.authority_id(),
        value.session_binding,
    );
    encode_session_record(value, RecordKind::SessionHistory, key)
}

fn encode_session_record(
    value: &HolderSessionHeadRecordV1,
    kind: RecordKind,
    key: Vec<u8>,
) -> Vec<u8> {
    let mut body = Encoder::with_capacity(
        SESSION_FIXED_BYTES + value.root_hello.len() + value.provider_hello.len(),
    );
    body.authority(&value.provider);
    body.authority(&value.holder);
    body.u64(value.session_generation);
    body.digest(value.session_binding);
    body.optional_digest(value.predecessor_session_binding);
    body.optional_digest(value.supersession_evidence_digest);
    body.array(&value.boot_id);
    body.array(&value.root_process_instance);
    body.array(&value.provider_process_instance);
    body.u32(value.provider_process_id);
    body.zeros(4);
    body.u64(value.provider_start_time_ticks);
    body.digest(value.provider_execution_commitment);
    body.u32(value.root_writer.uid);
    body.u32(value.root_writer.gid);
    body.u32(value.root_writer.tgid);
    body.zeros(4);
    body.u64(value.root_writer.start_time_ticks);
    body.digest(value.root_writer.cgroup_digest);
    body.array(&value.route_id);
    body.u64(value.route_generation);
    body.digest(value.route_digest);
    body.digest(value.resource_namespace_digest);
    body.u64(value.trust_generation);
    body.digest(value.trust_digest);
    body.u64(value.revocation_generation);
    body.digest(value.revocation_digest);
    for signer in &value.signers {
        body.signer(signer);
    }
    body.digest(value.signer_set_commitment);
    body.u64(value.request_sequence_floor);
    body.u64(value.response_sequence_floor);
    body.u64(value.acquisition_sequence_floor);
    body.u64(value.next_acquisition_sequence);
    body.u64(value.next_request_sequence);
    body.u64(value.next_response_sequence);
    body.optional_digest(value.pending_attempt_digest);
    body.optional_digest(value.last_completed_attempt_digest);
    body.digest(value.root_hello_digest);
    body.digest(value.provider_hello_digest);
    body.u32(value.root_hello.len() as u32);
    body.u32(value.provider_hello.len() as u32);
    debug_assert_eq!(body.len(), SESSION_FIXED_BYTES);
    body.bytes(&value.root_hello);
    body.bytes(&value.provider_hello);
    encode_envelope(kind, 0, value.revision, &key, body.as_slice())
}

/// Encodes one provider attempt in canonical AOSSPL01 form.
#[must_use]
pub fn encode_attempt(value: &AttemptRecordV1) -> Vec<u8> {
    let key = attempt_key(&AttemptKeyV1 {
        provider_id: value.provider.authority_id(),
        holder_id: value.holder.authority_id(),
        root_record_key_id: value.root_record_signer.key_id(),
        method: value.method as u8,
        request_id: value.request_id,
    });
    let mut body = Encoder::with_capacity(
        ATTEMPT_FIXED_BYTES + value.signed_request.len() + value.completed_response.len(),
    );
    body.authority(&value.provider);
    body.authority(&value.holder);
    body.signer(&value.root_record_signer);
    body.u8(value.method as u8);
    body.u8(value.status.map_or(0, |status| status as u8));
    body.zeros(6);
    body.array(&value.request_id);
    body.digest(value.signed_request_digest);
    body.digest(value.typed_request_digest);
    body.digest(value.operation_intent_digest);
    body.u64(value.acquisition_sequence);
    body.digest(value.attempt_digest);
    body.digest(value.session_binding);
    body.u64(value.request_sequence);
    body.u64(value.response_sequence.unwrap_or(0));
    body.i64(value.deadline_seconds);
    body.i64(value.verified_at_seconds);
    body.i64(value.completed_at_seconds.unwrap_or(0));
    body.i64(value.current_valid_until_seconds);
    body.u8(value.proof_class_capabilities);
    body.u8(u8::from(value.supports_recursive));
    body.u8(u8::from(value.supports_kernel_coupled));
    body.zeros(5);
    body.array(&value.root_process_instance);
    body.array(&value.provider_process_instance);
    body.digest(value.signer_set_commitment);
    body.optional_digest(value.recovery_predecessor_attempt_digest);
    body.optional_digest(value.recovery_predecessor_session_binding);
    body.optional_digest(value.recovery_fence_digest);
    body.u8(value.recovery_fence_class);
    body.zeros(7);
    body.u64(value.recovery_revocation_generation);
    body.digest(value.recovery_revocation_digest);
    body.digest(value.signed_request_digest_again);
    body.optional_digest(value.response_digest);
    body.digest(value.descriptor_commitment);
    body.optional_digest(value.result_digest);
    body.u64(value.response_catalog_generation);
    body.digest(value.response_catalog_digest);
    body.u32(value.signed_request.len() as u32);
    body.u32(value.completed_response.len() as u32);
    body.zeros(ATTEMPT_RESERVED_BYTES);
    debug_assert_eq!(body.len(), ATTEMPT_FIXED_BYTES);
    body.bytes(&value.signed_request);
    body.bytes(&value.completed_response);
    encode_envelope(
        RecordKind::Attempt,
        value.state as u8,
        value.revision,
        &key,
        body.as_slice(),
    )
}

/// Encodes one provider acquisition in canonical AOSSPL01 form.
#[must_use]
pub fn encode_acquisition(value: &AcquisitionRecordV1) -> Vec<u8> {
    let key = acquisition_key(&AcquisitionKeyV1 {
        provider_id: value.provider.authority_id(),
        holder_id: value.holder.authority_id(),
        acquisition_id: value.acquisition_id,
    });
    let intent = value.normalized_intent.to_canonical_bytes();
    let evidence = value
        .backend_evidence
        .as_ref()
        .map_or_else(Vec::new, BackendEvidenceV1::encode);
    let reopen = value
        .reopen_identity
        .as_ref()
        .map_or_else(Vec::new, |identity| identity.encode().to_vec());
    let lease_history_bytes = value.lease_history.len() * LEASE_LINEAGE_BYTES;
    let mut body = Encoder::with_capacity(
        ACQUISITION_FIXED_BYTES
            + lease_history_bytes
            + intent.len()
            + evidence.len()
            + reopen.len()
            + value.signed_lease.len(),
    );
    body.authority(&value.provider);
    body.authority(&value.holder);
    body.digest(value.acquisition_id);
    body.u64(value.acquisition_sequence);
    body.array(&value.effect_id);
    body.digest(value.normalized_intent.digest());
    body.digest(value.effect_attempt_digest);
    body.digest(value.current_attempt_digest);
    body.optional_digest(value.lease_attempt_digest);
    body.u64(value.lease_issue_generation);
    body.optional_array(value.lease_id);
    body.optional_digest(value.lease_digest);
    body.digest(value.resource_namespace_digest);
    body.array(&value.resource_id);
    body.u64(value.resource_generation);
    body.digest(value.resource_digest);
    body.u64(value.catalog_generation);
    body.digest(value.catalog_digest);
    body.u64(value.selection_generation);
    body.digest(value.selection_digest);
    body.u8(value.proof_class);
    body.zeros(7);
    body.digest(value.proof_digest);
    body.digest(value.resource_commitment);
    body.array(&value.backend_id);
    body.digest(value.backend_lineage_digest);
    body.optional_digest(value.native_no_dispatch_reservation_digest);
    body.digest(optional_bytes_digest(&evidence));
    body.u8(u8::from(value.backend_evidence.is_some()));
    body.u8(u8::from(value.reopen_identity.is_some()));
    body.u8(u8::from(value.source_root.is_some()));
    body.u8(u8::from(value.release_effect_id.is_some()));
    body.zeros(4);
    body.source_root(value.source_root);
    body.optional_array(value.release_effect_id);
    body.u32(intent.len() as u32);
    body.u32(evidence.len() as u32);
    body.u32(reopen.len() as u32);
    body.u32(value.signed_lease.len() as u32);
    body.u32(value.lease_history.len() as u32);
    body.zeros(ACQUISITION_RESERVED_BYTES);
    debug_assert_eq!(body.len(), ACQUISITION_FIXED_BYTES);
    for lineage in &value.lease_history {
        body.u64(lineage.issue_generation);
        body.array(&lineage.lease_id);
        body.digest(lineage.lease_digest);
        body.digest(lineage.attempt_digest);
    }
    body.bytes(&intent);
    body.bytes(&evidence);
    body.bytes(&reopen);
    body.bytes(&value.signed_lease);
    encode_envelope(
        RecordKind::Acquisition,
        value.state as u8,
        value.revision,
        &key,
        body.as_slice(),
    )
}

/// Encodes one release lineage in canonical AOSSPL01 form.
#[must_use]
pub fn encode_release(value: &ReleaseRecordV1) -> Vec<u8> {
    let key = release_key(&ReleaseKeyV1 {
        provider_id: value.provider.authority_id(),
        holder_id: value.holder.authority_id(),
        acquisition_id: value.acquisition_id,
    });
    let evidence = value
        .backend_evidence
        .as_ref()
        .map_or_else(Vec::new, BackendEvidenceV1::encode);
    let mut body =
        Encoder::with_capacity(RELEASE_FIXED_BYTES + evidence.len() + value.signed_receipt.len());
    body.authority(&value.provider);
    body.authority(&value.holder);
    body.digest(value.acquisition_id);
    body.u64(value.acquisition_sequence);
    body.array(&value.lease_id);
    body.digest(value.lease_digest);
    body.array(&value.effect_id);
    body.u64(value.release_generation);
    body.digest(value.effect_attempt_digest);
    body.digest(value.attempt_digest);
    body.array(&value.backend_id);
    body.digest(value.backend_lineage_digest);
    body.optional_digest(value.release_observation_digest);
    body.optional_i64(value.released_seconds);
    body.optional_digest(value.receipt_digest);
    body.digest(value.acquisition_record_digest);
    body.u32(evidence.len() as u32);
    body.u32(value.signed_receipt.len() as u32);
    debug_assert_eq!(body.len(), RELEASE_FIXED_BYTES);
    body.bytes(&evidence);
    body.bytes(&value.signed_receipt);
    encode_envelope(
        RecordKind::Release,
        value.state as u8,
        value.revision,
        &key,
        body.as_slice(),
    )
}

/// Decodes one hostile record after exact key, digest, and canonicality checks.
///
/// # Errors
///
/// Returns [`LedgerFormatErrorV1`] for an unknown or malformed envelope,
/// oversized body, key/body mismatch, digest mismatch, or noncanonical body.
pub fn decode_record(key: &[u8], bytes: &[u8]) -> Result<DecodedRecordV1, LedgerFormatErrorV1> {
    let envelope = decode_envelope(key, bytes)?;
    let decoded = match envelope.kind {
        RecordKind::AuthorityHead => DecodedRecordV1::Authority(decode_authority_body(envelope)?),
        RecordKind::CatalogHead => DecodedRecordV1::Catalog(decode_catalog_body(envelope)?),
        RecordKind::SessionHead => DecodedRecordV1::Session(decode_session_body(envelope, false)?),
        RecordKind::SessionHistory => {
            DecodedRecordV1::SessionHistory(decode_session_body(envelope, true)?)
        }
        RecordKind::Attempt => DecodedRecordV1::Attempt(decode_attempt_body(envelope)?),
        RecordKind::Acquisition => DecodedRecordV1::Acquisition(decode_acquisition_body(envelope)?),
        RecordKind::Release => DecodedRecordV1::Release(decode_release_body(envelope)?),
        RecordKind::NativeCompletion => {
            DecodedRecordV1::NativeCompletion(super::native_completion::decode_body(
                envelope.key,
                envelope.body,
                envelope.revision,
                envelope.state,
            )?)
        }
    };
    Ok(decoded)
}

/// Re-encodes one decoded record using its canonical AOSSPL01 representation.
pub fn encode_decoded_record(value: &DecodedRecordV1) -> Vec<u8> {
    match value {
        DecodedRecordV1::Authority(value) => encode_authority(value),
        DecodedRecordV1::Catalog(value) => encode_catalog(value),
        DecodedRecordV1::Session(value) => encode_session(value),
        DecodedRecordV1::SessionHistory(value) => encode_session_history(value),
        DecodedRecordV1::Attempt(value) => encode_attempt(value),
        DecodedRecordV1::Acquisition(value) => encode_acquisition(value),
        DecodedRecordV1::Release(value) => encode_release(value),
        DecodedRecordV1::NativeCompletion(value) => encode_native_completion_v2(value),
    }
}

/// Encodes one typed, nonauthorizing native completion recovery record.
#[must_use]
pub fn encode_native_completion_v2(
    value: &super::native_completion::NativeAcquireCompletionRecordV2,
) -> Vec<u8> {
    let key = super::native_completion::native_completion_key_v2(value.acquisition_id);
    encode_envelope(
        RecordKind::NativeCompletion,
        value.state as u8,
        value.revision,
        &key,
        &super::native_completion::encode_body(value),
    )
}

/// Returns the authenticated digest embedded in a validated AOSSPL01 record.
///
/// # Errors
///
/// Returns [`LedgerFormatErrorV1`] when the bytes are too short to contain the
/// fixed envelope.
pub fn record_digest(bytes: &[u8]) -> Result<ObjectDigest, LedgerFormatErrorV1> {
    if bytes.len() < ENVELOPE_BYTES {
        return Err(LedgerFormatErrorV1::Corrupt("short record envelope"));
    }
    Ok(ObjectDigest::from_bytes(read_array(bytes, 32)?))
}

pub(super) struct Envelope<'a> {
    pub(super) kind: RecordKind,
    pub(super) state: u8,
    pub(super) revision: u64,
    pub(super) key: &'a [u8],
    pub(super) body: &'a [u8],
}

fn encode_envelope(kind: RecordKind, state: u8, revision: u64, key: &[u8], body: &[u8]) -> Vec<u8> {
    let version = if kind == RecordKind::NativeCompletion {
        super::native_completion::envelope_version(body)
    } else {
        VERSION
    };
    encode_envelope_version(kind, state, revision, key, body, version)
}

pub(super) fn encode_envelope_version(
    kind: RecordKind,
    state: u8,
    revision: u64,
    key: &[u8],
    body: &[u8],
    version: u16,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(ENVELOPE_BYTES + body.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&version.to_be_bytes());
    bytes.push(kind as u8);
    bytes.push(state);
    bytes.extend_from_slice(&[0; 2]);
    bytes.extend_from_slice(&[0; 2]);
    bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&[0; 4]);
    bytes.extend_from_slice(&revision.to_be_bytes());
    let digest = calculate_record_digest(kind, key, &bytes, body);
    bytes.extend_from_slice(digest.as_bytes());
    bytes.extend_from_slice(body);
    bytes
}

fn decode_envelope<'a>(
    key: &'a [u8],
    bytes: &'a [u8],
) -> Result<Envelope<'a>, LedgerFormatErrorV1> {
    decode_envelope_version(key, bytes, None)
}

// Separate pure held/cold decoders supply version8/9. The legacy decoder
// continues deriving its exact5/6/7 member from the legacy body magic.
pub(super) fn decode_envelope_version<'a>(
    key: &'a [u8],
    bytes: &'a [u8],
    held_version: Option<u16>,
) -> Result<Envelope<'a>, LedgerFormatErrorV1> {
    if bytes.len() < ENVELOPE_BYTES || bytes.get(..8) != Some(MAGIC.as_slice()) {
        return Err(LedgerFormatErrorV1::Corrupt("record envelope header"));
    }
    let encoded_version = u16::from_be_bytes(read_array(bytes, 8)?);
    if encoded_version == 2 {
        return Err(LedgerFormatErrorV1::Corrupt(
            "AOSSPL v2 requires explicit offline migration",
        ));
    }
    let kind = RecordKind::decode(bytes[10])?;
    if held_version.is_some() && kind != RecordKind::NativeCompletion {
        return Err(LedgerFormatErrorV1::Corrupt("held native record kind"));
    }
    let expected_version = if let Some(version) = held_version {
        version
    } else if kind == RecordKind::NativeCompletion {
        super::native_completion::envelope_version(&bytes[ENVELOPE_BYTES..])
    } else {
        VERSION
    };
    if encoded_version != expected_version {
        return Err(LedgerFormatErrorV1::Corrupt(
            "unsupported AOSSPL format version",
        ));
    }
    if bytes.get(12..16) != Some([0_u8; 4].as_slice())
        || bytes.get(20..24) != Some([0_u8; 4].as_slice())
    {
        return Err(LedgerFormatErrorV1::Corrupt("record envelope header"));
    }
    let body_len = read_u32(bytes, 16)? as usize;
    if ENVELOPE_BYTES.checked_add(body_len) != Some(bytes.len()) {
        return Err(LedgerFormatErrorV1::Corrupt("record envelope length"));
    }
    let revision = read_u64(bytes, 24)?;
    if revision == 0 {
        return Err(LedgerFormatErrorV1::Corrupt("zero record revision"));
    }
    let expected =
        calculate_record_digest(kind, key, &bytes[..HEADER_BYTES], &bytes[ENVELOPE_BYTES..]);
    if expected.as_bytes() != &read_array::<32>(bytes, 32)? {
        return Err(LedgerFormatErrorV1::Corrupt("record digest mismatch"));
    }
    Ok(Envelope {
        kind,
        state: bytes[11],
        revision,
        key,
        body: &bytes[ENVELOPE_BYTES..],
    })
}

fn calculate_record_digest(
    kind: RecordKind,
    key: &[u8],
    header: &[u8],
    body: &[u8],
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(kind_domain(kind));
    hasher.update((key.len() as u32).to_be_bytes());
    hasher.update(key);
    hasher.update(((HEADER_BYTES + body.len()) as u32).to_be_bytes());
    hasher.update(header);
    hasher.update(body);
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn kind_domain(kind: RecordKind) -> &'static [u8] {
    match kind {
        RecordKind::AuthorityHead => AUTHORITY_DOMAIN,
        RecordKind::CatalogHead => CATALOG_DOMAIN,
        RecordKind::SessionHead => SESSION_DOMAIN,
        RecordKind::SessionHistory => SESSION_HISTORY_DOMAIN,
        RecordKind::Attempt => ATTEMPT_DOMAIN,
        RecordKind::Acquisition => ACQUISITION_DOMAIN,
        RecordKind::Release => RELEASE_DOMAIN,
        RecordKind::NativeCompletion => NATIVE_COMPLETION_DOMAIN,
    }
}

fn decode_authority_body(
    envelope: Envelope<'_>,
) -> Result<AuthorityHeadRecordV1, LedgerFormatErrorV1> {
    if envelope.body.len() != AUTHORITY_BODY_BYTES {
        return Err(LedgerFormatErrorV1::Corrupt("authority body length"));
    }
    let mut body = Decoder::new(envelope.body);
    let provider = body.authority()?;
    let value = AuthorityHeadRecordV1 {
        revision: envelope.revision,
        state: decode_authority_state(envelope.state)?,
        provider: provider.clone(),
        trust_generation: body.nonzero_u64()?,
        trust_digest: body.nonzero_digest()?,
        revocation_generation: body.nonzero_u64()?,
        revocation_digest: body.nonzero_digest()?,
        valid_from_seconds: body.nonnegative_i64()?,
        valid_until_seconds: body.nonnegative_i64()?,
        route_id: body.nonzero_array()?,
        route_generation: body.nonzero_u64()?,
        route_digest: body.nonzero_digest()?,
        resource_namespace_digest: body.nonzero_digest()?,
        proof_class_capabilities: body.nonzero_u8()?,
        supports_recursive: body.boolean()?,
        supports_kernel_coupled: body.boolean()?,
        provider_hello_signer: {
            body.zeros(5)?;
            body.signer()?
        },
        provider_outcome_signer: body.signer()?,
        catalog_generation: body.nonzero_u64()?,
        catalog_digest: body.nonzero_digest()?,
        inventory_generation: body.nonzero_u64()?,
        inventory_state_digest: body.nonzero_digest()?,
        last_lease_issue_generation: body.u64()?,
        last_release_generation: body.u64()?,
        active_lease_count: body.u64()?,
    };
    body.zeros(40)?;
    body.finish()?;
    if authority_key(provider.authority_id()) != envelope.key {
        return Err(LedgerFormatErrorV1::Corrupt("authority key/body mismatch"));
    }
    if value.valid_until_seconds <= value.valid_from_seconds
        || value.proof_class_capabilities & !0x0f != 0
        || value.provider_hello_signer.usage() != SourceProviderKeyUsageV1::ProviderHello
        || value.provider_outcome_signer.usage() != SourceProviderKeyUsageV1::ProviderOutcome
        || value.provider_hello_signer.authority_id() != provider.authority_id()
        || value.provider_outcome_signer.authority_id() != provider.authority_id()
    {
        return Err(LedgerFormatErrorV1::Corrupt("authority body fields"));
    }
    Ok(value)
}

fn decode_catalog_body(envelope: Envelope<'_>) -> Result<CatalogHeadRecordV1, LedgerFormatErrorV1> {
    if envelope.state != 0 || envelope.body.len() < CATALOG_FIXED_BYTES {
        return Err(LedgerFormatErrorV1::Corrupt("catalog body shape"));
    }
    let mut body = Decoder::new(envelope.body);
    let provider = body.authority()?;
    let mut value = CatalogHeadRecordV1 {
        revision: envelope.revision,
        provider: provider.clone(),
        resource_namespace_digest: body.nonzero_digest()?,
        catalog_generation: body.nonzero_u64()?,
        catalog_digest: body.nonzero_digest()?,
        publisher_authority_id: body.nonzero_array()?,
        publication_generation: body.nonzero_u64()?,
        publication_receipt_digest: body.nonzero_digest()?,
        predecessor_catalog_generation: body.u64()?,
        predecessor_catalog_digest: body.digest()?,
        catalog_floor_generation: body.nonzero_u64()?,
        catalog_floor_digest: body.nonzero_digest()?,
        publication_seconds: body.nonnegative_i64()?,
        publication_trust_generation: body.nonzero_u64()?,
        publication_trust_digest: body.nonzero_digest()?,
        publication_revocation_generation: body.nonzero_u64()?,
        publication_revocation_digest: body.nonzero_digest()?,
        publisher_signer: body.signer()?,
        canonical_publication: Vec::new(),
    };
    let publication_len = body.bounded_len(MAXIMUM_CATALOG_PUBLICATION_BYTES)?;
    if body.offset() != CATALOG_FIXED_BYTES {
        return Err(LedgerFormatErrorV1::Corrupt("catalog fixed offsets"));
    }
    value.canonical_publication = body.take(publication_len)?.to_vec();
    body.finish()?;
    if catalog_key(provider.authority_id(), value.catalog_generation) != envelope.key {
        return Err(LedgerFormatErrorV1::Corrupt("catalog key/body mismatch"));
    }
    let predecessor_is_valid = if value.predecessor_catalog_generation == 0 {
        value.predecessor_catalog_digest.as_bytes() == &[0; 32]
    } else {
        value.predecessor_catalog_generation < value.catalog_generation
            && value.predecessor_catalog_digest.as_bytes() != &[0; 32]
    };
    if !predecessor_is_valid
        || value.catalog_floor_generation > value.catalog_generation
        || (value.catalog_floor_generation == value.catalog_generation
            && value.catalog_floor_digest != value.catalog_digest)
        || value.publisher_signer.usage() != SourceProviderKeyUsageV1::CatalogPublisher
        || value.publisher_signer.authority_id() != value.publisher_authority_id
        || value.canonical_publication.is_empty()
    {
        return Err(LedgerFormatErrorV1::Corrupt("catalog predecessor"));
    }
    Ok(value)
}

fn decode_session_body(
    envelope: Envelope<'_>,
    history: bool,
) -> Result<HolderSessionHeadRecordV1, LedgerFormatErrorV1> {
    if envelope.state != 0 || envelope.body.len() < SESSION_FIXED_BYTES {
        return Err(LedgerFormatErrorV1::Corrupt("session body shape"));
    }
    let mut body = Decoder::new(envelope.body);
    let provider = body.authority()?;
    let holder = body.authority()?;
    let mut value = HolderSessionHeadRecordV1 {
        revision: envelope.revision,
        provider: provider.clone(),
        holder: holder.clone(),
        session_generation: body.nonzero_u64()?,
        session_binding: body.nonzero_digest()?,
        predecessor_session_binding: body.optional_digest()?,
        supersession_evidence_digest: body.optional_digest()?,
        boot_id: body.nonzero_array()?,
        root_process_instance: body.nonzero_array()?,
        provider_process_instance: body.nonzero_array()?,
        provider_process_id: body.nonzero_u32()?,
        provider_start_time_ticks: {
            body.zeros(4)?;
            body.nonzero_u64()?
        },
        provider_execution_commitment: body.nonzero_digest()?,
        root_writer: WriterIdentityV1 {
            uid: body.u32()?,
            gid: body.u32()?,
            tgid: body.nonzero_u32()?,
            start_time_ticks: {
                body.zeros(4)?;
                body.nonzero_u64()?
            },
            cgroup_digest: body.nonzero_digest()?,
        },
        route_id: body.nonzero_array()?,
        route_generation: body.nonzero_u64()?,
        route_digest: body.nonzero_digest()?,
        resource_namespace_digest: body.nonzero_digest()?,
        trust_generation: body.nonzero_u64()?,
        trust_digest: body.nonzero_digest()?,
        revocation_generation: body.nonzero_u64()?,
        revocation_digest: body.nonzero_digest()?,
        signers: [
            body.signer()?,
            body.signer()?,
            body.signer()?,
            body.signer()?,
        ],
        signer_set_commitment: body.nonzero_digest()?,
        request_sequence_floor: body.nonzero_u64()?,
        response_sequence_floor: body.nonzero_u64()?,
        acquisition_sequence_floor: body.nonzero_u64()?,
        next_acquisition_sequence: body.nonzero_u64()?,
        next_request_sequence: body.nonzero_u64()?,
        next_response_sequence: body.nonzero_u64()?,
        pending_attempt_digest: body.optional_digest()?,
        last_completed_attempt_digest: body.optional_digest()?,
        root_hello_digest: body.nonzero_digest()?,
        provider_hello_digest: body.nonzero_digest()?,
        root_hello: Vec::new(),
        provider_hello: Vec::new(),
    };
    let root_len = body.bounded_len(MAXIMUM_SIGNED_HELLO_BYTES)?;
    let provider_len = body.bounded_len(MAXIMUM_SIGNED_HELLO_BYTES)?;
    if body.offset() != SESSION_FIXED_BYTES {
        return Err(LedgerFormatErrorV1::Corrupt("session fixed section"));
    }
    value.root_hello = body.take(root_len)?.to_vec();
    value.provider_hello = body.take(provider_len)?.to_vec();
    body.finish()?;
    if history {
        if session_history_key(
            provider.authority_id(),
            holder.authority_id(),
            value.session_binding,
        ) != envelope.key
        {
            return Err(LedgerFormatErrorV1::Corrupt(
                "session history key/body identity",
            ));
        }
    } else if session_key(provider.authority_id(), holder.authority_id()) != envelope.key {
        return Err(LedgerFormatErrorV1::Corrupt("session key/body mismatch"));
    }
    let expected_uses = [
        SourceProviderKeyUsageV1::RootMountHello,
        SourceProviderKeyUsageV1::RootMountRecord,
        SourceProviderKeyUsageV1::ProviderHello,
        SourceProviderKeyUsageV1::ProviderOutcome,
    ];
    if value
        .signers
        .iter()
        .zip(expected_uses)
        .any(|(signer, usage)| signer.usage() != usage)
        || value.signers[..2].iter().any(|signer| {
            signer.authority_id() != holder.authority_id()
                || signer.authority_generation() != holder.authority_generation()
                || signer.authority_digest() != holder.authority_digest()
        })
        || value.signers[2..].iter().any(|signer| {
            signer.authority_id() != provider.authority_id()
                || signer.authority_generation() != provider.authority_generation()
                || signer.authority_digest() != provider.authority_digest()
        })
        || value.root_hello.is_empty()
        || value.provider_hello.is_empty()
        || value.request_sequence_floor > value.next_request_sequence
        || value.response_sequence_floor > value.next_response_sequence
        || (value.session_generation == 1
            && (value.predecessor_session_binding.is_some()
                || value.supersession_evidence_digest.is_some()))
        || (value.session_generation > 1
            && (value.predecessor_session_binding.is_none()
                || value.supersession_evidence_digest.is_none()))
    {
        return Err(LedgerFormatErrorV1::Corrupt(
            "session signer or hello shape",
        ));
    }
    if aos_sandbox_source_provider_protocol::provider_execution_commitment_v1(
        value.boot_id,
        value.provider_process_id,
        value.provider_start_time_ticks,
        value.provider_process_instance,
    ) != value.provider_execution_commitment
    {
        return Err(LedgerFormatErrorV1::Corrupt(
            "provider execution commitment",
        ));
    }
    let root_hello = SignedSourceProviderHelloV1::from_canonical_bytes(&value.root_hello)
        .map_err(|_| LedgerFormatErrorV1::Corrupt("retained Root Mount hello"))?;
    let provider_hello = SignedSourceProviderHelloV1::from_canonical_bytes(&value.provider_hello)
        .map_err(|_| LedgerFormatErrorV1::Corrupt("retained provider hello"))?;
    if root_hello.signer() != &value.signers[0]
        || provider_hello.signer() != &value.signers[2]
        || root_hello.subject().role()
            != aos_sandbox_source_provider_protocol::SourceProviderPeerRole::RootMount
        || provider_hello.subject().role()
            != aos_sandbox_source_provider_protocol::SourceProviderPeerRole::Provider
        || root_hello.subject().process_instance() != value.root_process_instance
        || provider_hello.subject().process_instance() != value.provider_process_instance
        || root_hello.subject().kernel_boot_id() != value.boot_id
        || provider_hello.subject().kernel_boot_id() != value.boot_id
        || root_hello.subject().traffic_signer() != &value.signers[1]
        || root_hello.subject().expected_peer_traffic_signer() != &value.signers[3]
        || provider_hello.subject().traffic_signer() != &value.signers[3]
        || provider_hello.subject().expected_peer_traffic_signer() != &value.signers[1]
        || root_hello.subject().route_id() != value.route_id
        || provider_hello.subject().route_id() != value.route_id
        || root_hello.subject().route_generation() != value.route_generation
        || provider_hello.subject().route_generation() != value.route_generation
        || root_hello.subject().route_digest() != value.route_digest
        || provider_hello.subject().route_digest() != value.route_digest
        || provider_hello.subject().client_hello_digest() != Some(value.root_hello_digest)
        || digest_signed_hello(&root_hello) != value.root_hello_digest
        || digest_signed_hello(&provider_hello) != value.provider_hello_digest
        || source_provider_session_binding_v1(&root_hello, &provider_hello) != value.session_binding
        || source_provider_signer_set_commitment_v1(
            &value.signers[0],
            &value.signers[1],
            &value.signers[2],
            &value.signers[3],
        ) != value.signer_set_commitment
    {
        return Err(LedgerFormatErrorV1::Corrupt(
            "retained session transcript mismatch",
        ));
    }
    Ok(value)
}

fn decode_attempt_body(envelope: Envelope<'_>) -> Result<AttemptRecordV1, LedgerFormatErrorV1> {
    if envelope.body.len() < ATTEMPT_FIXED_BYTES {
        return Err(LedgerFormatErrorV1::Corrupt("attempt body shape"));
    }
    let state = decode_attempt_state(envelope.state)?;
    let mut body = Decoder::new(envelope.body);
    let provider = body.authority()?;
    let holder = body.authority()?;
    let root_record_signer = body.signer()?;
    let method = decode_method(body.u8()?)?;
    let status = decode_optional_status(body.u8()?)?;
    body.zeros(6)?;
    let mut value = AttemptRecordV1 {
        revision: envelope.revision,
        state,
        provider: provider.clone(),
        holder: holder.clone(),
        root_record_signer: root_record_signer.clone(),
        method,
        status,
        request_id: body.nonzero_array()?,
        signed_request_digest: body.nonzero_digest()?,
        typed_request_digest: body.nonzero_digest()?,
        operation_intent_digest: body.nonzero_digest()?,
        acquisition_sequence: body.u64()?,
        attempt_digest: body.nonzero_digest()?,
        session_binding: body.nonzero_digest()?,
        request_sequence: body.nonzero_u64()?,
        response_sequence: match body.u64()? {
            0 => None,
            value => Some(value),
        },
        deadline_seconds: body.nonnegative_i64()?,
        verified_at_seconds: body.nonnegative_i64()?,
        completed_at_seconds: match body.nonnegative_i64()? {
            0 => None,
            value => Some(value),
        },
        current_valid_until_seconds: body.nonnegative_i64()?,
        proof_class_capabilities: body.nonzero_u8()?,
        supports_recursive: body.boolean()?,
        supports_kernel_coupled: body.boolean()?,
        root_process_instance: {
            body.zeros(5)?;
            body.nonzero_array()?
        },
        provider_process_instance: body.nonzero_array()?,
        signer_set_commitment: body.nonzero_digest()?,
        recovery_predecessor_attempt_digest: body.optional_digest()?,
        recovery_predecessor_session_binding: body.optional_digest()?,
        recovery_fence_digest: body.optional_digest()?,
        recovery_fence_class: body.u8()?,
        recovery_revocation_generation: {
            body.zeros(7)?;
            body.u64()?
        },
        recovery_revocation_digest: body.digest()?,
        signed_request_digest_again: body.nonzero_digest()?,
        response_digest: body.optional_digest()?,
        descriptor_commitment: body.digest()?,
        result_digest: body.optional_digest()?,
        response_catalog_generation: body.u64()?,
        response_catalog_digest: body.digest()?,
        signed_request: Vec::new(),
        completed_response: Vec::new(),
    };
    let request_len = body.bounded_len(MAXIMUM_SIGNED_REQUEST_OR_RESPONSE_BYTES)?;
    let response_len = body.bounded_len(MAXIMUM_SIGNED_REQUEST_OR_RESPONSE_BYTES)?;
    if body.offset() != ATTEMPT_SEMANTIC_BYTES {
        return Err(LedgerFormatErrorV1::Corrupt("attempt fixed offsets"));
    }
    body.zeros(ATTEMPT_RESERVED_BYTES)?;
    value.signed_request = body.take(request_len)?.to_vec();
    value.completed_response = body.take(response_len)?.to_vec();
    body.finish()?;
    let key = AttemptKeyV1 {
        provider_id: provider.authority_id(),
        holder_id: holder.authority_id(),
        root_record_key_id: root_record_signer.key_id(),
        method: method as u8,
        request_id: value.request_id,
    };
    let recovery_bridge_shape = value.recovery_predecessor_attempt_digest.is_some()
        == value.recovery_predecessor_session_binding.is_some()
        && value.recovery_predecessor_attempt_digest.is_some()
            == value.recovery_fence_digest.is_some()
        && if value.recovery_fence_digest.is_some() {
            (1..=3).contains(&value.recovery_fence_class)
                && value.recovery_revocation_generation > 0
                && value.recovery_revocation_digest.as_bytes() != &[0; 32]
        } else {
            value.recovery_fence_class == 0
                && value.recovery_revocation_generation == 0
                && value.recovery_revocation_digest.as_bytes() == &[0; 32]
        };
    if attempt_key(&key) != envelope.key
        || root_record_signer.usage() != SourceProviderKeyUsageV1::RootMountRecord
        || !recovery_bridge_shape
        || value.signed_request_digest != value.signed_request_digest_again
        || value.attempt_digest
            != source_provider_request_attempt_digest_v1(
                &value.root_record_signer,
                value.method,
                value.request_id,
            )
        || value.verified_at_seconds > value.deadline_seconds
        || value.completed_at_seconds.is_some_and(|completed| {
            completed < value.verified_at_seconds || completed >= value.deadline_seconds
        })
        || value.deadline_seconds > value.current_valid_until_seconds
        || value.proof_class_capabilities == 0
        || value.proof_class_capabilities & !0x0f != 0
    {
        return Err(LedgerFormatErrorV1::Corrupt("attempt identity"));
    }
    if !value.signed_request.is_empty() {
        let signed_request =
            SignedSourceProviderRequestV1::from_canonical_bytes(&value.signed_request)
                .map_err(|_| LedgerFormatErrorV1::Corrupt("retained signed request"))?;
        if signed_request.method() != value.method
            || signed_request.signer() != &value.root_record_signer
            || digest_signed_request(&signed_request) != value.signed_request_digest
            || super::artifact::typed_request_digest(&signed_request)? != value.typed_request_digest
            || signed_request.to_canonical_bytes() != value.signed_request
        {
            return Err(LedgerFormatErrorV1::Corrupt(
                "retained signed request mismatch",
            ));
        }
        super::artifact::validate_request_cross_links(&value, &signed_request)?;
    }
    if !value.completed_response.is_empty()
        && value.response_digest
            != Some(super::artifact::response_artifact_digest(
                value.method,
                &value.completed_response,
            ))
    {
        return Err(LedgerFormatErrorV1::Corrupt(
            "retained response digest mismatch",
        ));
    }
    if !value.completed_response.is_empty() {
        super::artifact::validate_completed_response(&value)?;
    }
    let completed_shape = status.is_some()
        && value.response_digest.is_some()
        && value.result_digest.is_some()
        && !value.completed_response.is_empty();
    let catalog_shape = match (method, state, status) {
        (SourceProviderMethod::Inventory, ProviderAttemptStateV1::Completed, Some(_))
        | (SourceProviderMethod::Inventory, ProviderAttemptStateV1::Retired, Some(_)) => {
            value.response_catalog_generation > 0
                && value.response_catalog_digest.as_bytes() != &[0; 32]
        }
        _ => {
            value.response_catalog_generation == 0
                && value.response_catalog_digest.as_bytes() == &[0; 32]
        }
    };
    if !catalog_shape {
        return Err(LedgerFormatErrorV1::Corrupt(
            "attempt response catalog shape",
        ));
    }
    match state {
        ProviderAttemptStateV1::Reserved
            if status.is_none()
                && value.response_sequence.is_none()
                && value.response_digest.is_none()
                && value.result_digest.is_none()
                && value.completed_at_seconds.is_none()
                && value.completed_response.is_empty()
                && !value.signed_request.is_empty() => {}
        ProviderAttemptStateV1::Completed
            if completed_shape
                && value.response_sequence.is_some()
                && value.completed_at_seconds.is_some()
                && !value.signed_request.is_empty() => {}
        ProviderAttemptStateV1::Retired
            if (status.is_some()
                && value.response_sequence.is_some()
                && value.response_digest.is_some()
                && value.completed_at_seconds.is_some()
                && value.result_digest.is_some())
                || (status.is_none()
                    && value.response_sequence.is_none()
                    && value.response_digest.is_none()
                    && value.completed_at_seconds.is_none()
                    && value.result_digest.is_none()
                    && value.completed_response.is_empty()
                    && !value.signed_request.is_empty()) => {}
        _ => return Err(LedgerFormatErrorV1::Corrupt("attempt state shape")),
    }
    Ok(value)
}

fn decode_acquisition_body(
    envelope: Envelope<'_>,
) -> Result<AcquisitionRecordV1, LedgerFormatErrorV1> {
    if envelope.body.len() < ACQUISITION_FIXED_BYTES {
        return Err(LedgerFormatErrorV1::Corrupt("acquisition body shape"));
    }
    let state = decode_acquisition_state(envelope.state)?;
    let mut body = Decoder::new(envelope.body);
    let provider = body.authority()?;
    let holder = body.authority()?;
    let acquisition_id = body.nonzero_digest()?;
    let acquisition_sequence = body.nonzero_u64()?;
    let effect_id = body.nonzero_array()?;
    let intent_digest = body.nonzero_digest()?;
    let effect_attempt_digest = body.nonzero_digest()?;
    let current_attempt_digest = body.nonzero_digest()?;
    let lease_attempt_digest = body.optional_digest()?;
    let lease_issue_generation = body.u64()?;
    let lease_id = body.optional_array()?;
    let lease_digest = body.optional_digest()?;
    let resource_namespace_digest = body.digest()?;
    let resource_id = body.array()?;
    let resource_generation = body.u64()?;
    let resource_digest = body.digest()?;
    let catalog_generation = body.u64()?;
    let catalog_digest = body.digest()?;
    let selection_generation = body.u64()?;
    let selection_digest = body.digest()?;
    let proof_class = body.u8()?;
    body.zeros(7)?;
    let proof_digest = body.digest()?;
    let resource_commitment = body.digest()?;
    let backend_id = body.array()?;
    let backend_lineage_digest = body.nonzero_digest()?;
    let native_no_dispatch_reservation_digest = body.optional_digest()?;
    let evidence_digest = body.digest()?;
    let evidence_present = body.boolean()?;
    let reopen_present = body.boolean()?;
    let source_root_present = body.boolean()?;
    let release_present = body.boolean()?;
    body.zeros(4)?;
    let source_root = body.optional_source_root(source_root_present)?;
    let release_effect_id = body.optional_array()?;
    if release_effect_id.is_some() != release_present {
        return Err(LedgerFormatErrorV1::Corrupt("acquisition release link"));
    }
    let intent_len = body.bounded_len(crate::MAXIMUM_NORMALIZED_ACQUISITION_INTENT_BYTES)?;
    let evidence_len =
        body.bounded_len(crate::limits::MAXIMUM_BACKEND_EVIDENCE_PAYLOAD_BYTES + 120)?;
    let reopen_len = body.bounded_len(256)?;
    let lease_len = body.bounded_len(MAXIMUM_SIGNED_LEASE_BYTES)?;
    let lease_history_count =
        body.bounded_len(crate::limits::MAXIMUM_LEASE_HISTORY_PER_ACQUISITION)?;
    if body.offset() != ACQUISITION_SEMANTIC_BYTES {
        return Err(LedgerFormatErrorV1::Corrupt("acquisition fixed offsets"));
    }
    body.zeros(ACQUISITION_RESERVED_BYTES)?;
    let mut lease_history = Vec::with_capacity(lease_history_count);
    for _ in 0..lease_history_count {
        lease_history.push(LeaseLineageV1 {
            issue_generation: body.nonzero_u64()?,
            lease_id: body.nonzero_array()?,
            lease_digest: body.nonzero_digest()?,
            attempt_digest: body.nonzero_digest()?,
        });
    }
    let intent = NormalizedAcquisitionIntentV1::from_canonical_bytes(body.take(intent_len)?)
        .map_err(|_| LedgerFormatErrorV1::Corrupt("normalized acquisition intent"))?;
    let evidence_bytes = body.take(evidence_len)?;
    let backend_evidence = if evidence_present {
        Some(BackendEvidenceV1::decode(evidence_bytes)?)
    } else if evidence_bytes.is_empty() {
        None
    } else {
        return Err(LedgerFormatErrorV1::Corrupt("unexpected backend evidence"));
    };
    let reopen_bytes = body.take(reopen_len)?;
    let reopen_identity = if reopen_present {
        Some(ReopenIdentityV1::decode(reopen_bytes)?)
    } else if reopen_bytes.is_empty() {
        None
    } else {
        return Err(LedgerFormatErrorV1::Corrupt("unexpected reopen identity"));
    };
    let signed_lease = body.take(lease_len)?.to_vec();
    body.finish()?;
    let key = AcquisitionKeyV1 {
        provider_id: provider.authority_id(),
        holder_id: holder.authority_id(),
        acquisition_id,
    };
    if acquisition_key(&key) != envelope.key
        || intent.acquisition_id() != acquisition_id
        || intent.acquisition_sequence() != acquisition_sequence
        || intent.provider() != &provider
        || intent.holder() != &holder
        || intent.digest() != intent_digest
        || intent.native_catalog().is_some_and(|catalog| {
            catalog.resource_namespace_digest() != resource_namespace_digest
                || catalog.head() != (catalog_generation, catalog_digest)
        })
        || optional_bytes_digest(evidence_bytes) != evidence_digest
    {
        return Err(LedgerFormatErrorV1::Corrupt("acquisition cross-link"));
    }
    let active_shape = lease_id.is_some()
        && lease_digest.is_some()
        && lease_attempt_digest.is_some()
        && lease_issue_generation > 0
        && resource_namespace_digest.as_bytes() != &[0; 32]
        && resource_id != [0; 32]
        && resource_generation > 0
        && resource_digest.as_bytes() != &[0; 32]
        && catalog_generation > 0
        && catalog_digest.as_bytes() != &[0; 32]
        && selection_generation > 0
        && selection_digest.as_bytes() != &[0; 32]
        && (1..=4).contains(&proof_class)
        && proof_digest.as_bytes() != &[0; 32]
        && resource_commitment.as_bytes() != &[0; 32]
        && backend_id != [0; 32]
        && backend_evidence.is_some()
        && reopen_identity.is_some()
        && source_root.is_some()
        && !lease_history.is_empty()
        && !signed_lease.is_empty();
    let reserved_shape = lease_id.is_none()
        && lease_digest.is_none()
        && lease_attempt_digest.is_none()
        && lease_issue_generation == 0
        && resource_namespace_digest.as_bytes() != &[0; 32]
        && resource_id == [0; 32]
        && resource_generation == 0
        && resource_digest.as_bytes() == &[0; 32]
        && catalog_generation > 0
        && catalog_digest.as_bytes() != &[0; 32]
        && selection_generation == 0
        && selection_digest.as_bytes() == &[0; 32]
        && proof_class == 0
        && proof_digest.as_bytes() == &[0; 32]
        && resource_commitment.as_bytes() == &[0; 32]
        && backend_id != [0; 32]
        && backend_evidence.is_none()
        && reopen_identity.is_none()
        && source_root.is_none()
        && lease_history.is_empty()
        && release_effect_id.is_none()
        && signed_lease.is_empty();
    // Either protected catalog family may durably select a Provider row before
    // any backend effect. Selection is not proof, lease, or descriptor custody.
    let selected_reserved_shape = lease_id.is_none()
        && lease_digest.is_none()
        && lease_attempt_digest.is_none()
        && lease_issue_generation == 0
        && resource_namespace_digest.as_bytes() != &[0; 32]
        && resource_id != [0; 32]
        && resource_generation > 0
        && resource_digest.as_bytes() != &[0; 32]
        && catalog_generation > 0
        && catalog_digest.as_bytes() != &[0; 32]
        && selection_generation > 0
        && selection_digest.as_bytes() != &[0; 32]
        && proof_class == 0
        && proof_digest.as_bytes() == &[0; 32]
        && resource_commitment.as_bytes() == &[0; 32]
        && backend_id != [0; 32]
        && backend_evidence.is_none()
        && reopen_identity.is_none()
        && source_root.is_none()
        && lease_history.is_empty()
        && release_effect_id.is_none()
        && signed_lease.is_empty();
    let released_compact_shape = lease_id.is_some()
        && lease_digest.is_some()
        && lease_attempt_digest.is_some()
        && lease_issue_generation > 0
        && resource_namespace_digest.as_bytes() != &[0; 32]
        && resource_id != [0; 32]
        && resource_generation > 0
        && resource_digest.as_bytes() != &[0; 32]
        && catalog_generation > 0
        && catalog_digest.as_bytes() != &[0; 32]
        && selection_generation > 0
        && selection_digest.as_bytes() != &[0; 32]
        && (1..=4).contains(&proof_class)
        && proof_digest.as_bytes() != &[0; 32]
        && resource_commitment.as_bytes() != &[0; 32]
        && backend_id != [0; 32]
        && backend_evidence.is_some()
        && reopen_identity.is_none()
        && source_root.is_some()
        && lease_history.is_empty()
        && release_effect_id.is_some()
        && signed_lease.is_empty();
    match state {
        ProviderAcquisitionStateV1::Applying | ProviderAcquisitionStateV1::Pending
            if reserved_shape || selected_reserved_shape => {}
        ProviderAcquisitionStateV1::Active if active_shape && release_effect_id.is_none() => {}
        ProviderAcquisitionStateV1::Releasing if active_shape && release_effect_id.is_some() => {}
        ProviderAcquisitionStateV1::Released
            if (active_shape && release_effect_id.is_some()) || released_compact_shape => {}
        ProviderAcquisitionStateV1::Faulted
            if reserved_shape || selected_reserved_shape || active_shape => {}
        _ => return Err(LedgerFormatErrorV1::Corrupt("acquisition state shape")),
    }
    if active_shape {
        let evidence = backend_evidence
            .as_ref()
            .ok_or(LedgerFormatErrorV1::Corrupt("active backend evidence"))?;
        let reopen = reopen_identity
            .as_ref()
            .ok_or(LedgerFormatErrorV1::Corrupt("active reopen identity"))?;
        let signed = SignedSourceExportLeaseV1::from_canonical_bytes(&signed_lease)
            .map_err(|_| LedgerFormatErrorV1::Corrupt("retained signed lease"))?;
        let lease_resource = signed.subject().resource();
        let current_lineage = lease_history.last().ok_or(LedgerFormatErrorV1::Corrupt(
            "missing current lease lineage",
        ))?;
        if evidence.state() != crate::BackendEvidenceStateV1::Acquired
            || evidence.class() as u8 != proof_class
            || reopen.class() != evidence.class()
            || reopen.backend_id() != backend_id
            || reopen.backend_generation() != evidence.backend_generation()
            || reopen.backend_digest() != evidence.backend_digest()
            || reopen.resource_id() != resource_id
            || reopen.resource_generation() != resource_generation
            || reopen.resource_digest() != resource_digest
            || digest_signed_export_lease(&signed)
                != lease_digest.ok_or(LedgerFormatErrorV1::Corrupt("active signed lease digest"))?
            || signed.subject().lease_id()
                != lease_id.ok_or(LedgerFormatErrorV1::Corrupt("active lease ID"))?
            || current_lineage.issue_generation != lease_issue_generation
            || Some(current_lineage.lease_id) != lease_id
            || Some(current_lineage.lease_digest) != lease_digest
            || Some(current_lineage.attempt_digest) != lease_attempt_digest
            || !lease_history.windows(2).all(|pair| {
                pair[0].issue_generation < pair[1].issue_generation
                    && pair[0].lease_id != pair[1].lease_id
                    && pair[0].lease_digest != pair[1].lease_digest
                    && pair[0].attempt_digest != pair[1].attempt_digest
            })
            || signed.subject().provider() != &provider
            || signed.subject().holder_authority_id() != holder.authority_id()
            || signed.subject().holder_generation() != holder.authority_generation()
            || signed.subject().holder_authority_digest() != holder.authority_digest()
            || signed.subject().binding_digest() != intent.binding_digest()
            || signed.subject().revocation_digest() != intent.holder_revocation_digest()
            || signed.subject().expires_seconds() <= signed.subject().issued_seconds()
            || lease_resource.resource_namespace_digest() != resource_namespace_digest
            || lease_resource.resource_id() != resource_id
            || lease_resource.resource_generation() != resource_generation
            || lease_resource.resource_digest() != resource_digest
            || lease_resource.catalog_generation() != catalog_generation
            || lease_resource.catalog_digest() != catalog_digest
            || lease_resource.selection_generation() != selection_generation
            || lease_resource.selection_digest() != selection_digest
            || digest_provider_proof(signed.subject().proof()) != proof_digest
            || signed.subject().proof().class_code() != proof_class
            || !reopen.matches_proof(signed.subject().proof())
            || provider_resource_commitment_v1(lease_resource, proof_digest) != resource_commitment
        {
            return Err(LedgerFormatErrorV1::Corrupt(
                "active acquisition artifact mismatch",
            ));
        }
    }
    let value = AcquisitionRecordV1 {
        revision: envelope.revision,
        state,
        provider,
        holder,
        acquisition_id,
        acquisition_sequence,
        effect_id,
        normalized_intent: intent,
        effect_attempt_digest,
        current_attempt_digest,
        lease_attempt_digest,
        lease_issue_generation,
        lease_id,
        lease_digest,
        lease_history,
        resource_namespace_digest,
        resource_id,
        resource_generation,
        resource_digest,
        catalog_generation,
        catalog_digest,
        selection_generation,
        selection_digest,
        proof_class,
        proof_digest,
        resource_commitment,
        backend_id,
        backend_lineage_digest,
        native_no_dispatch_reservation_digest,
        backend_evidence,
        reopen_identity,
        source_root,
        release_effect_id,
        signed_lease,
    };
    if let Some(reservation_digest) = value.native_no_dispatch_reservation_digest {
        let mut original = value.clone();
        original.revision = original
            .revision
            .checked_sub(1)
            .ok_or(LedgerFormatErrorV1::Corrupt("native settlement revision"))?;
        original.state = ProviderAcquisitionStateV1::Applying;
        original.native_no_dispatch_reservation_digest = None;
        if value.state != ProviderAcquisitionStateV1::Faulted
            || value.backend_id
                != crate::identity::acquire_native_no_dispatch_id_v1(
                    value.normalized_intent.digest(),
                    value.catalog_generation,
                    value.catalog_digest,
                )
            || value.proof_class != 0
            || !selected_reserved_shape
            || record_digest(&encode_acquisition(&original))? != reservation_digest
        {
            return Err(LedgerFormatErrorV1::Corrupt(
                "native settlement reservation provenance",
            ));
        }
    }
    Ok(value)
}

#[cfg(test)]
mod native_selected_reservation_tests {
    use aos_sandbox_source_provider_protocol::{
        AcquireSourceRequestV1, ProviderHeldSnapshotCatalogV1, ProviderHeldSnapshotRowV1,
        SourceProviderAuthorityV1, SourceUseV1, ZfsHeldSnapshotProofV1,
        digest_logical_binding_bytes, prospective_mount_apply_template_digest_v1,
    };

    use super::*;

    fn digest(byte: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([byte; 32])
    }

    #[test]
    fn acquisition_profile_geometry_preserves_legacy_bound_and_full_owner_budget() {
        // These literal format widths independently pin the shared artifacts.
        let common_bytes = 64 + 824 + 65_536 + 120 + 256 + 262_144 + 88 * 1_024;
        assert_eq!(
            ACQUISITION_RECORD_LEGACY_INTENT_MAXIMUM_BYTES,
            common_bytes + 67_996
        );
        assert_eq!(ACQUISITION_RECORD_MAXIMUM_BYTES, common_bytes + 68_172);
        assert_eq!(
            NATIVE_ACQUIRE_COMPLETION_OWNER_RECORD_BOUNDS_V2[1],
            487_228 + 99 + 9
        );

        assert_eq!(
            NATIVE_ACQUIRE_COMPLETION_OWNER_RECORD_BOUNDS_V2
                .iter()
                .sum::<usize>(),
            MAXIMUM_NATIVE_ACQUIRE_COMPLETION_OWNER_BYTES_V2
        );
        assert_eq!(
            MAXIMUM_NATIVE_RELEASE_ADMISSION_OWNER_BYTES_V1,
            MAXIMUM_NATIVE_ACQUIRE_COMPLETION_OWNER_BYTES_V2 + 131_720 + 99 + 9
        );
        assert!(
            MAXIMUM_NATIVE_RELEASE_ADMISSION_OWNER_BYTES_V1
                < crate::limits::MAXIMUM_TRANSACTION_BYTES
        );
    }

    #[test]
    fn native_selected_applying_record_remains_proofless_until_completion() {
        let provider = SourceProviderAuthorityV1::new([21; 16], 22, digest(23)).unwrap();
        let holder = SourceProviderAuthorityV1::new([7; 16], 8, digest(9)).unwrap();
        let mut template = Vec::new();
        for tag in 1u8..=27 {
            let value = match tag {
                1 => b"AOSMSEM1".to_vec(),
                2 => 1u16.to_be_bytes().to_vec(),
                _ => vec![tag, tag.wrapping_add(1)],
            };
            template.push(tag);
            template.extend_from_slice(&(value.len() as u32).to_be_bytes());
            template.extend_from_slice(&value);
        }
        let template_digest = prospective_mount_apply_template_digest_v1(&template).unwrap();
        let binding = b"native-held-snapshot-attachment".to_vec();
        let binding_digest = digest_logical_binding_bytes(&binding);
        let request = AcquireSourceRequestV1::new_v2(
            digest(1),
            2,
            [3; 16],
            4,
            template,
            template_digest,
            SourceUseV1::MountCreate,
            [5; 16],
            [6; 16],
            holder.authority_id(),
            holder.authority_generation(),
            holder.authority_digest(),
            binding,
            binding_digest,
            1_000,
            60,
            digest(10),
            false,
            0,
            false,
        )
        .unwrap();
        let namespace = digest(27);
        let intent = NormalizedAcquisitionIntentV1::from_acquire_request(
            &request,
            provider.clone(),
            holder.clone(),
            [5; 16],
            [6; 16],
            [24; 16],
            25,
            digest(26),
            namespace,
            28,
            digest(10),
        )
        .unwrap();
        let snapshot = ZfsHeldSnapshotProofV1::new(
            [11; 32],
            12,
            13,
            14,
            15,
            [16; 16],
            17,
            digest(18),
            digest(19),
            digest(20),
        )
        .unwrap();
        let row = ProviderHeldSnapshotRowV1::new(
            binding_digest,
            [30; 32],
            31,
            digest(32),
            33,
            digest(34),
            snapshot,
        )
        .unwrap();
        let catalog = ProviderHeldSnapshotCatalogV1::new(29, namespace, vec![row]).unwrap();
        let (resource, _) = catalog
            .select_under_head(29, catalog.digest(), namespace, binding_digest)
            .unwrap();
        let native_backend_id = crate::identity::acquire_native_no_dispatch_id_v1(
            intent.digest(),
            resource.catalog_generation(),
            resource.catalog_digest(),
        );
        assert_ne!(
            native_backend_id,
            crate::identity::acquire_backend_plan_id_v1(
                intent.digest(),
                resource.catalog_generation(),
                resource.catalog_digest(),
            )
        );

        let acquisition = AcquisitionRecordV1 {
            revision: 1,
            state: ProviderAcquisitionStateV1::Applying,
            provider: provider.clone(),
            holder: holder.clone(),
            acquisition_id: request.acquisition_id(),
            acquisition_sequence: request.acquisition_sequence(),
            effect_id: [35; 16],
            normalized_intent: intent,
            effect_attempt_digest: digest(36),
            current_attempt_digest: digest(36),
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
            backend_id: native_backend_id,
            backend_lineage_digest: digest(38),
            native_no_dispatch_reservation_digest: None,
            backend_evidence: None,
            reopen_identity: None,
            source_root: None,
            release_effect_id: None,
            signed_lease: Vec::new(),
        };
        let key = acquisition_key(&AcquisitionKeyV1 {
            provider_id: provider.authority_id(),
            holder_id: holder.authority_id(),
            acquisition_id: request.acquisition_id(),
        });
        let bytes = encode_acquisition(&acquisition);
        let DecodedRecordV1::Acquisition(decoded) = decode_record(&key, &bytes).unwrap() else {
            panic!("fixture decoded as another record kind");
        };
        assert_eq!(decoded, acquisition);

        let native_request = AcquireSourceRequestV1::new_native_v3(
            request.clone(),
            aos_sandbox_source_provider_protocol::NativeAcquireCatalogBindingV3::new(
                namespace,
                resource.catalog_generation(),
                resource.catalog_digest(),
                resource.catalog_generation(),
                resource.catalog_digest(),
                digest(39),
                digest(40),
            )
            .unwrap(),
        )
        .unwrap();
        let mut native_acquisition = acquisition.clone();
        native_acquisition.normalized_intent =
            NormalizedAcquisitionIntentV1::from_original_acquire_request(
                &native_request,
                provider.clone(),
                holder.clone(),
                [5; 16],
                [6; 16],
                [24; 16],
                25,
                digest(26),
                namespace,
                28,
                digest(10),
            )
            .unwrap();
        native_acquisition.backend_id = crate::identity::acquire_native_no_dispatch_id_v1(
            native_acquisition.normalized_intent.digest(),
            resource.catalog_generation(),
            resource.catalog_digest(),
        );
        let native_bytes = encode_acquisition(&native_acquisition);
        assert_eq!(native_bytes.len(), bytes.len() + 176);
        assert_eq!(&bytes[8..10], &5_u16.to_be_bytes());
        assert_eq!(&native_bytes[8..10], &5_u16.to_be_bytes());
        let DecodedRecordV1::Acquisition(decoded_native) =
            decode_record(&key, &native_bytes).unwrap()
        else {
            panic!("native normalized fixture changed record kind");
        };
        assert_eq!(decoded_native, native_acquisition);
        assert_eq!(
            decoded_native.normalized_intent.native_catalog(),
            native_request.native_catalog()
        );
        assert!(
            decoded_native
                .normalized_intent
                .matches_original_acquire_request(&native_request)
        );

        let mut changed_head = native_acquisition.clone();
        changed_head.catalog_digest = digest(99);
        assert!(decode_record(&key, &encode_acquisition(&changed_head)).is_err());

        let mut native_terminal = native_acquisition.clone();
        native_terminal.revision = 2;
        native_terminal.state = ProviderAcquisitionStateV1::Faulted;
        native_terminal.native_no_dispatch_reservation_digest =
            Some(record_digest(&native_bytes).unwrap());
        let native_terminal_bytes = encode_acquisition(&native_terminal);
        assert!(decode_record(&key, &native_terminal_bytes).is_ok());
        #[cfg(target_os = "linux")]
        protected_native_terminal_replay(&key, &native_bytes, &native_terminal_bytes);

        let mut terminal = acquisition.clone();
        terminal.revision = 2;
        terminal.state = ProviderAcquisitionStateV1::Faulted;
        terminal.native_no_dispatch_reservation_digest = Some(record_digest(&bytes).unwrap());
        let terminal_bytes = encode_acquisition(&terminal);
        let DecodedRecordV1::Acquisition(decoded_terminal) =
            decode_record(&key, &terminal_bytes).unwrap()
        else {
            panic!("terminal fixture decoded as another record kind");
        };
        assert_eq!(decoded_terminal, terminal);

        terminal.native_no_dispatch_reservation_digest = Some(digest(99));
        assert!(decode_record(&key, &encode_acquisition(&terminal)).is_err());

        let mut premature_proof = acquisition.clone();
        premature_proof.proof_class = 1;
        assert!(decode_record(&key, &encode_acquisition(&premature_proof)).is_err());

        let mut missing_selection = acquisition;
        missing_selection.resource_id = [0; 32];
        assert!(decode_record(&key, &encode_acquisition(&missing_selection)).is_err());

        #[cfg(target_os = "linux")]
        protected_native_terminal_replay(&key, &bytes, &terminal_bytes);
    }

    #[cfg(target_os = "linux")]
    fn protected_native_terminal_replay(key: &[u8], applying: &[u8], terminal: &[u8]) {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        use aos_sandbox::{
            Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace,
        };

        const FILE: &str = "native-no-dispatch-record.journal";
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = directory.path().metadata().unwrap().uid();

        for (transaction_id, expected) in [([1; 16], applying), ([2; 16], terminal)] {
            let (mut journal, _) = Journal::open_protected_at_uid(
                directory.path(),
                FILE,
                JournalLimits::default(),
                uid,
            )
            .unwrap();
            let mut authority = journal
                .claim_protected_authority(RecordNamespace::SourceProviderAuthority)
                .unwrap();
            let transaction = JournalTransaction::new(
                transaction_id,
                vec![JournalRecord::put(
                    RecordNamespace::SourceProviderAuthority,
                    key.to_vec(),
                    expected.to_vec(),
                )],
            )
            .unwrap();
            authority.commit(&transaction).unwrap();
            drop(authority);
            drop(journal);

            let (mut reopened, _) = Journal::open_protected_at_uid(
                directory.path(),
                FILE,
                JournalLimits::default(),
                uid,
            )
            .unwrap();
            let authority = reopened
                .claim_protected_authority(RecordNamespace::SourceProviderAuthority)
                .unwrap();
            let retained = authority.get(key).unwrap().unwrap();
            assert_eq!(retained, expected);
            assert!(matches!(
                decode_record(key, retained).unwrap(),
                DecodedRecordV1::Acquisition(_)
            ));
        }
    }
}

fn decode_release_body(envelope: Envelope<'_>) -> Result<ReleaseRecordV1, LedgerFormatErrorV1> {
    if envelope.body.len() < RELEASE_FIXED_BYTES {
        return Err(LedgerFormatErrorV1::Corrupt("release body shape"));
    }
    let state = decode_release_state(envelope.state)?;
    let mut body = Decoder::new(envelope.body);
    let provider = body.authority()?;
    let holder = body.authority()?;
    let acquisition_id = body.nonzero_digest()?;
    let acquisition_sequence = body.nonzero_u64()?;
    let lease_id = body.nonzero_array()?;
    let lease_digest = body.nonzero_digest()?;
    let effect_id = body.nonzero_array()?;
    let release_generation = body.nonzero_u64()?;
    let effect_attempt_digest = body.nonzero_digest()?;
    let attempt_digest = body.nonzero_digest()?;
    let backend_id = body.nonzero_array()?;
    let backend_lineage_digest = body.nonzero_digest()?;
    let release_observation_digest = body.optional_digest()?;
    let released_seconds = body.optional_i64()?;
    let receipt_digest = body.optional_digest()?;
    let acquisition_record_digest = body.nonzero_digest()?;
    let evidence_len =
        body.bounded_len(crate::limits::MAXIMUM_BACKEND_EVIDENCE_PAYLOAD_BYTES + 120)?;
    let receipt_len = body.bounded_len(MAXIMUM_SIGNED_RELEASE_RECEIPT_BYTES)?;
    if body.offset() != RELEASE_FIXED_BYTES {
        return Err(LedgerFormatErrorV1::Corrupt("release fixed offsets"));
    }
    let evidence_bytes = body.take(evidence_len)?;
    let backend_evidence = if !evidence_bytes.is_empty() {
        Some(BackendEvidenceV1::decode(evidence_bytes)?)
    } else {
        None
    };
    let signed_receipt = body.take(receipt_len)?.to_vec();
    body.finish()?;
    let key = ReleaseKeyV1 {
        provider_id: provider.authority_id(),
        holder_id: holder.authority_id(),
        acquisition_id,
    };
    if release_key(&key) != envelope.key {
        return Err(LedgerFormatErrorV1::Corrupt("release key/body mismatch"));
    }
    match state {
        ProviderReleaseStateV1::Intent
            if backend_evidence.is_none()
                && release_observation_digest.is_none()
                && released_seconds.is_none()
                && receipt_digest.is_none()
                && signed_receipt.is_empty() => {}
        ProviderReleaseStateV1::Tombstone
            if backend_evidence.is_some()
                && release_observation_digest.is_some()
                && released_seconds.is_some()
                && receipt_digest.is_some()
                && !signed_receipt.is_empty() => {}
        _ => return Err(LedgerFormatErrorV1::Corrupt("release state shape")),
    }
    if let Some(evidence) = &backend_evidence
        && (evidence.state() != crate::BackendEvidenceStateV1::Released
            || Some(evidence.observation_digest()) != release_observation_digest)
    {
        return Err(LedgerFormatErrorV1::Corrupt("release evidence cross-link"));
    }
    Ok(ReleaseRecordV1 {
        revision: envelope.revision,
        state,
        provider,
        holder,
        acquisition_id,
        acquisition_sequence,
        lease_id,
        lease_digest,
        effect_id,
        release_generation,
        effect_attempt_digest,
        attempt_digest,
        backend_id,
        backend_lineage_digest,
        backend_evidence,
        release_observation_digest,
        released_seconds,
        receipt_digest,
        signed_receipt,
        acquisition_record_digest,
    })
}
