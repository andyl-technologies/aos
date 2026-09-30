//! Typed native acceptance retained across challenge-spend and Active commits.
//!
//! This pure model grants no signing, descriptor, effect, or release authority.
//! Digest-only inert records retain their version-5 envelope/body. Live request
//! retention originally used version 6 with `AOSNCR03`. Version 7 `AOSNCR04`
//! adds mandatory original paired-clock metadata after the reservation digest,
//! before the bounded signed request and optional typed reply. Versions 5 and 6
//! remain historical; neither may infer an anchor or enable positive recovery.
//!
//! ```text
//! AOSNCR02 | provider:16 | holder:16 | session:32 | attempt:32 |
//! acquisition:32 | challenge:32 | challenge-validity:2*i64 |
//! root-request-digest:32 | root-request-id:16 |
//! typed-request-digest:32 | native-request-digest:32 | receipt-digest:32 |
//! signed-acceptance-digest:32 | acceptance-payload-digest:32 |
//! issuance-id:16 | binding-digest:32 |
//! publication-head:32 | original-root:(boot:16,device:u64,inode:u64,mount:u64) |
//! descriptor-commitment:32
//! ```

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    MAXIMUM_SIGNED_STORAGE_NATIVE_ACQUIRE_REQUEST_BYTES_V2, STORAGE_NATIVE_ACQUIRE_REPLY_BYTES_V3,
    SignedStorageNativeAcquireRequestV2, SourceProviderMethod, StorageNativeAcquireReplyV3,
    VerifiedStorageNativeAcquireV3, decode_acquire_request, digest_acquire_request,
    digest_signed_request,
};

use super::LedgerFormatErrorV1;
use super::codec::{Decoder, Encoder};
use super::model::{
    AcquisitionRecordV1, AttemptRecordV1, ProviderAcquisitionStateV1, SourceRootIdentityV1,
};

#[path = "native_completion/clock.rs"]
mod clock;

pub use clock::NativeAcquireClockAnchorV1;

#[path = "native_completion/original_provenance.rs"]
mod original_provenance;

pub use original_provenance::{
    MAXIMUM_ORIGINAL_SOURCE_PROVENANCE_BYTES_V5, OriginalSourceProvenanceClaimsV5,
    OriginalSourceProvenanceV5,
};

#[path = "native_completion/original_source_owner.rs"]
mod original_source_owner;

pub use original_source_owner::{
    OriginalSourceAdmissionComparisonV5, OriginalSourceOwnerDataV5, OriginalSourceOwnerPrefixV5, OriginalSourceOwnerTransactionV5,
    classify_original_source_owner_v5, derive_original_source_pre_requested_retirement_v1,
    propose_original_source_applying_v5, propose_original_source_requested_v5,
};

#[path = "native_completion/pre_requested_cold.rs"]
pub(crate) mod pre_requested_cold;

pub use pre_requested_cold::{
    MAXIMUM_SOURCE_PRE_REQUESTED_COLD_ARCHIVE_BYTES_V1,
    MAXIMUM_SOURCE_PRE_REQUESTED_COLD_FLOOR_DATA_BYTES_V1,
    SOURCE_PRE_REQUESTED_COLD_ARCHIVE_FIXED_BYTES_V1,
    OriginalSourcePreRequestedRetirementV1, SourcePreRequestedColdArchiveV1,
    SourcePreRequestedColdPhaseV1, SourcePreRequestedColdTransactionV1,
    classify_original_source_pre_requested_cold_v1,
    propose_original_source_pre_requested_closed_v1,
    propose_original_source_pre_requested_closure_stored_v1,
    propose_original_source_pre_requested_root_acknowledged_v1,
    validate_original_source_pre_requested_cold_records_v1,
};

#[path = "native_completion/export_fence.rs"]
mod export_fence;

pub use export_fence::{validate_native_complete_export_v1, validate_native_export_open_v1};

#[path = "native_completion/release_fence.rs"]
pub mod release_fence;

#[path = "native_completion/export_result.rs"]
pub mod export_result;

pub(super) const BODY_BYTES: usize = 544;
pub(super) const MAXIMUM_BODY_BYTES: usize = BODY_BYTES
    + 32
    + clock::CLOCK_BYTES
    + 8
    + MAXIMUM_SIGNED_STORAGE_NATIVE_ACQUIRE_REQUEST_BYTES_V2
    + STORAGE_NATIVE_ACQUIRE_REPLY_BYTES_V3;
const BODY_MAGIC: &[u8; 8] = b"AOSNCR02";
const REQUESTED_BODY_MAGIC: &[u8; 8] = b"AOSNCR03";
const CLOCKED_BODY_MAGIC: &[u8; 8] = b"AOSNCR04";
const KEY_MAGIC: &[u8; 8] = b"AOSNCK02";

/// Names one irreversible native completion recovery phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NativeAcquireCompletionStateV2 {
    /// Exact signed native bytes are durable before any possible Storage send.
    Requested = 0,
    /// Exact Storage acceptance is retained before challenge spend.
    Prepared = 1,
    /// The exact challenge is spent but Provider completion may be pending.
    Spent = 2,
    /// The exact original Acquire is durably Active.
    Active = 3,
    /// Original descriptor custody or completion authority was lost.
    CleanupRequired = 4,
}

/// Binds one native acceptance to its original request and descriptor identity.
///
/// Public scalar fields are nonauthorizing format claims. Only protected
/// owners may turn their canonical bytes into custody or recovery decisions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeAcquireCompletionRecordV2 {
    /// Names the protected record revision.
    pub revision: u64,
    /// Names the one-way recovery phase.
    pub state: NativeAcquireCompletionStateV2,
    /// Names the original Provider authority.
    pub provider_id: [u8; 16],
    /// Names the original Root Mount holder authority.
    pub holder_id: [u8; 16],
    /// Commits the original live holder session.
    pub session_binding: ObjectDigest,
    /// Commits the original reserved Acquire attempt.
    pub attempt_digest: ObjectDigest,
    /// Names the original acquisition lineage.
    pub acquisition_id: ObjectDigest,
    /// Retains the single original challenge nonce.
    pub challenge: [u8; 32],
    /// Names the original challenge's inclusive issue second.
    pub challenge_issued_seconds: i64,
    /// Names the original challenge's exclusive expiry second.
    pub challenge_valid_until_seconds: i64,
    /// Commits the exact Root Mount signed Acquire request.
    pub root_request_digest: ObjectDigest,
    /// Names the original Root Mount request ID.
    pub root_request_id: [u8; 16],
    /// Commits the typed original Acquire request.
    pub typed_request_digest: ObjectDigest,
    /// Commits the exact signed Provider-to-Storage native request.
    pub native_request_digest: ObjectDigest,
    /// Commits the exact signed AOSZHR01 receipt.
    pub receipt_digest: ObjectDigest,
    /// Commits the exact signed Storage acceptance.
    pub acceptance_digest: ObjectDigest,
    /// Commits the original unsigned acceptance payload across signer rotation.
    pub acceptance_payload_digest: ObjectDigest,
    /// Names the protected Storage acceptance issuance.
    pub issuance_id: [u8; 16],
    /// Commits the original normalized resource binding.
    pub binding_digest: ObjectDigest,
    /// Commits the original protected catalog publication.
    pub publication_head: ObjectDigest,
    /// Retains the original boot and descriptor identity, never a remount hint.
    pub original_root: SourceRootIdentityV1,
    /// Commits the full original SourceRoot descriptor observation.
    pub descriptor_commitment: ObjectDigest,
    /// Retains exact canonical signed native bytes; absent only for old inert rows.
    pub canonical_request: Option<SignedStorageNativeAcquireRequestV2>,
    /// Retains the exact typed signed receipt and acceptance after verification.
    pub accepted_reply: Option<StorageNativeAcquireReplyV3>,
    /// Commits the original Applying acquisition for durable capacity recovery.
    pub reservation_acquisition_digest: Option<ObjectDigest>,
    /// Retains the original local clock pair; absent only for historical rows.
    pub original_clock: Option<NativeAcquireClockAnchorV1>,
}

impl NativeAcquireCompletionRecordV2 {
    /// Retains the original signed native request before dispatch is possible.
    ///
    /// This pure constructor grants no authority to send or complete. A fixed
    /// owner must commit and read back the row with sufficient durable capacity.
    ///
    /// # Errors
    ///
    /// Rejects malformed RootMount bytes, a sentinel reservation, or a clock
    /// block inconsistent with the exact original signed request.
    pub fn requested(
        request: SignedStorageNativeAcquireRequestV2,
        reservation_acquisition_digest: ObjectDigest,
        original_clock: NativeAcquireClockAnchorV1,
    ) -> Result<Self, LedgerFormatErrorV1> {
        original_clock.validate_request(&request)?;
        Self::requested_artifacts(
            request,
            reservation_acquisition_digest,
            Some(original_clock),
        )
    }

    fn requested_artifacts(
        request: SignedStorageNativeAcquireRequestV2,
        reservation_acquisition_digest: ObjectDigest,
        original_clock: Option<NativeAcquireClockAnchorV1>,
    ) -> Result<Self, LedgerFormatErrorV1> {
        if reservation_acquisition_digest.as_bytes() == &[0; 32] {
            return Err(LedgerFormatErrorV1::Corrupt("native reservation digest"));
        }
        let claims = request.request().claims();
        let root = decode_acquire_request(request.request().signed_root_request().subject())
            .map_err(|_| LedgerFormatErrorV1::Corrupt("native original request"))?;
        let zero = ObjectDigest::from_bytes([0; 32]);
        Ok(Self {
            revision: 1,
            state: NativeAcquireCompletionStateV2::Requested,
            provider_id: claims.provider_acquisition().0,
            holder_id: claims.holder_session().0,
            session_binding: claims.holder_session().1,
            attempt_digest: claims.attempt().1,
            acquisition_id: claims.provider_acquisition().1,
            challenge: claims.attempt().0,
            challenge_issued_seconds: claims.validity().0,
            challenge_valid_until_seconds: claims.validity().1,
            root_request_digest: digest_signed_request(request.request().signed_root_request()),
            root_request_id: root.request_id(),
            typed_request_digest: digest_acquire_request(&root),
            native_request_digest: request.digest(),
            receipt_digest: zero,
            acceptance_digest: zero,
            acceptance_payload_digest: zero,
            issuance_id: [0; 16],
            binding_digest: claims.selection().0,
            publication_head: claims.selection().1,
            original_root: SourceRootIdentityV1 {
                kernel_boot_id: [0; 16],
                device: 0,
                inode: 0,
                unique_mount_id: 0,
            },
            descriptor_commitment: zero,
            canonical_request: Some(request),
            accepted_reply: None,
            reservation_acquisition_digest: Some(reservation_acquisition_digest),
            original_clock,
        })
    }

    /// Adds exact accepted artifacts once without replacing the signed request.
    ///
    /// # Errors
    ///
    /// Rejects a non-Requested row, changed signed artifacts, or issuance scope.
    pub fn prepare_accepted(
        &self,
        reply: StorageNativeAcquireReplyV3,
        verified: &VerifiedStorageNativeAcquireV3,
    ) -> Result<Self, LedgerFormatErrorV1> {
        if self.state != NativeAcquireCompletionStateV2::Requested || self.original_clock.is_none()
        {
            return Err(LedgerFormatErrorV1::Corrupt(
                "native acceptance already retained",
            ));
        }
        let next = self.with_accepted_reply(reply)?;
        let request = next
            .canonical_request
            .as_ref()
            .ok_or(LedgerFormatErrorV1::Corrupt("missing native signed bytes"))?;
        next.validate_verified_acceptance(request, verified)?;
        next.validate_canonical_artifacts()?;
        Ok(next)
    }

    fn with_accepted_reply(
        &self,
        reply: StorageNativeAcquireReplyV3,
    ) -> Result<Self, LedgerFormatErrorV1> {
        let request = self
            .canonical_request
            .as_ref()
            .ok_or(LedgerFormatErrorV1::Corrupt(
                "native request retention missing",
            ))?;
        let claims = request.request().claims();
        let catalog = claims.catalog();
        let (resource, snapshot) = catalog
            .select_under_head(
                catalog.generation(),
                catalog.digest(),
                catalog.namespace_digest(),
                claims.selection().0,
            )
            .map_err(|_| LedgerFormatErrorV1::Corrupt("native retained selection"))?;
        let receipt = reply.receipt().receipt();
        if receipt.attempt() != claims.attempt()
            || receipt.binding_digest() != claims.selection().0
            || receipt.resource() != &resource
            || receipt.snapshot() != &snapshot
            || receipt.validity().0 < claims.validity().0
            || receipt.validity().1 > claims.validity().1
        {
            return Err(LedgerFormatErrorV1::Corrupt(
                "native retained receipt scope",
            ));
        }
        let acceptance = reply.acceptance().acceptance();
        if acceptance.request_digest() != self.native_request_digest {
            return Err(LedgerFormatErrorV1::Corrupt(
                "native acceptance request changed",
            ));
        }
        let descriptor = acceptance.descriptor();
        let mut next = self.advance(NativeAcquireCompletionStateV2::Prepared)?;
        next.receipt_digest = reply.receipt().digest();
        next.acceptance_digest = reply.acceptance().digest();
        next.acceptance_payload_digest = acceptance.digest();
        next.issuance_id = acceptance.issuance_id();
        next.original_root = SourceRootIdentityV1::new(
            descriptor.kernel_boot_id(),
            descriptor.device(),
            descriptor.inode(),
            descriptor.unique_mount_id(),
        )?;
        next.descriptor_commitment = acceptance.descriptor_commitment();
        next.accepted_reply = Some(reply);
        Ok(next)
    }

    /// Checks exact canonical retained artifacts without authenticating signatures.
    ///
    /// Old digest-only rows remain decodable but cannot satisfy live completion.
    ///
    /// # Errors
    ///
    /// Rejects rewritten signed bytes, a mismatched typed bundle, or wrong phase.
    pub fn validate_canonical_artifacts(&self) -> Result<(), LedgerFormatErrorV1> {
        let Some(request) = self.canonical_request.as_ref() else {
            if self.state == NativeAcquireCompletionStateV2::Requested
                || self.accepted_reply.is_some()
                || self.reservation_acquisition_digest.is_some()
                || self.original_clock.is_some()
            {
                return Err(LedgerFormatErrorV1::Corrupt(
                    "missing native request retention",
                ));
            }
            return Ok(());
        };
        if let Some(clock) = self.original_clock {
            clock.validate_request(request)?;
        }
        let mut requested = Self::requested_artifacts(
            request.clone(),
            self.reservation_acquisition_digest
                .ok_or(LedgerFormatErrorV1::Corrupt(
                    "missing native reservation digest",
                ))?,
            self.original_clock,
        )?;
        if let Some(reply) = self.accepted_reply.clone() {
            requested = requested.with_accepted_reply(reply)?;
        } else if !matches!(
            self.state,
            NativeAcquireCompletionStateV2::Requested
                | NativeAcquireCompletionStateV2::CleanupRequired
        ) {
            return Err(LedgerFormatErrorV1::Corrupt("native acceptance missing"));
        }
        requested.state = self.state;
        requested.revision = self.revision;
        if requested != *self {
            return Err(LedgerFormatErrorV1::Corrupt(
                "native canonical artifacts changed",
            ));
        }
        Ok(())
    }

    /// Checks an independently verified V3 acceptance against every retained claim.
    ///
    /// This check grants no currentness or FD custody authority. A protected
    /// owner still needs the original live descriptor and an independent
    /// current Storage acceptance cut before completing Acquire.
    ///
    /// # Errors
    ///
    /// Rejects changed signed inputs, issuance, original descriptor, or scope.
    pub fn validate_verified_acceptance(
        &self,
        request: &SignedStorageNativeAcquireRequestV2,
        verified: &VerifiedStorageNativeAcquireV3,
    ) -> Result<(), LedgerFormatErrorV1> {
        let claims = request.request().claims();
        let signed_root = request.request().signed_root_request();
        let root = decode_acquire_request(signed_root.subject())
            .map_err(|_| LedgerFormatErrorV1::Corrupt("native original request"))?;
        let descriptor = verified.acceptance().descriptor();
        let original_root = SourceRootIdentityV1::new(
            descriptor.kernel_boot_id(),
            descriptor.device(),
            descriptor.inode(),
            descriptor.unique_mount_id(),
        )?;

        if self.native_request_digest != request.digest()
            || self.native_request_digest != verified.request_digest()
            || self.receipt_digest != verified.receipt_digest()
            || self.acceptance_digest != verified.signed_acceptance_digest()
            || self.acceptance_payload_digest != verified.acceptance_payload_digest()
            || self.issuance_id != verified.acceptance().issuance_id()
            || self.original_root != original_root
            || self.descriptor_commitment != verified.acceptance().descriptor_commitment()
            || (self.provider_id, self.acquisition_id) != claims.provider_acquisition()
            || (self.holder_id, self.session_binding) != claims.holder_session()
            || (self.challenge, self.attempt_digest) != claims.attempt()
            || (self.binding_digest, self.publication_head) != claims.selection()
            || (
                self.challenge_issued_seconds,
                self.challenge_valid_until_seconds,
            ) != claims.validity()
            || self.root_request_digest != digest_signed_request(signed_root)
            || self.root_request_id != root.request_id()
            || self.typed_request_digest != digest_acquire_request(&root)
        {
            return Err(LedgerFormatErrorV1::Corrupt(
                "native verified acceptance changed",
            ));
        }

        Ok(())
    }

    /// Checks exact original Provider graph links without restoring authority.
    ///
    /// # Errors
    ///
    /// Rejects kernel coupling, renewal, rebind, changed request/session,
    /// foreign acquisition, or Active without the exact original root.
    pub fn validate_provider_graph(
        &self,
        attempt: &AttemptRecordV1,
        acquisition: &AcquisitionRecordV1,
    ) -> Result<(), LedgerFormatErrorV1> {
        self.validate_canonical_artifacts()?;
        validate_native_provider_phase(
            self.state,
            acquisition.state,
            acquisition.lease_id.is_some(),
            acquisition.proof_class,
            acquisition.normalized_intent.kernel_coupled(),
        )?;

        if self.provider_id != acquisition.provider.authority_id()
            || self
                .original_clock
                .is_some_and(|clock| clock.initial().wall_seconds() < attempt.verified_at_seconds)
            || self.holder_id != acquisition.holder.authority_id()
            || attempt.provider != acquisition.provider
            || attempt.holder != acquisition.holder
            || attempt.method != SourceProviderMethod::Acquire
            || self.acquisition_id != acquisition.acquisition_id
            || self.attempt_digest != attempt.attempt_digest
            || self.attempt_digest != acquisition.effect_attempt_digest
            || (self.attempt_digest != acquisition.current_attempt_digest
                && !(self.state == NativeAcquireCompletionStateV2::CleanupRequired
                    && matches!(
                        acquisition.state,
                        ProviderAcquisitionStateV1::Releasing
                            | ProviderAcquisitionStateV1::Released
                            | ProviderAcquisitionStateV1::Faulted
                    )))
            || self.session_binding != attempt.session_binding
            || self.root_request_digest != attempt.signed_request_digest
            || self.root_request_id != attempt.request_id
            || self.typed_request_digest != attempt.typed_request_digest
            || self.binding_digest != acquisition.normalized_intent.binding_digest()
            || (self.canonical_request.is_some()
                && acquisition.backend_id
                    != crate::identity::acquire_native_dispatch_id_v2(
                        acquisition.normalized_intent.digest(),
                        acquisition.catalog_generation,
                        acquisition.catalog_digest,
                        self.attempt_digest,
                    ))
            || acquisition
                .lease_attempt_digest
                .is_some_and(|attempt| attempt != self.attempt_digest)
            || acquisition
                .lease_history
                .iter()
                .any(|lease| lease.attempt_digest != self.attempt_digest)
            || (acquisition.state == ProviderAcquisitionStateV1::Active
                && (acquisition.source_root != Some(self.original_root)
                    || acquisition.lease_attempt_digest != Some(self.attempt_digest)))
        {
            return Err(LedgerFormatErrorV1::Corrupt(
                "native completion Provider graph",
            ));
        }

        Ok(())
    }

    /// Proposes a one-way revision without changing the immutable acceptance.
    ///
    /// # Errors
    ///
    /// Rejects phase rollback, reactivation after cleanup, and revision overflow.
    pub fn advance(
        &self,
        state: NativeAcquireCompletionStateV2,
    ) -> Result<Self, LedgerFormatErrorV1> {
        if (state as u8) < (self.state as u8) {
            return Err(LedgerFormatErrorV1::Corrupt(
                "native completion phase rollback",
            ));
        }

        let mut next = self.clone();
        if state != self.state {
            next.revision = next
                .revision
                .checked_add(1)
                .ok_or(LedgerFormatErrorV1::Corrupt(
                    "native completion revision exhausted",
                ))?;
            next.state = state;
        }

        Ok(next)
    }

    /// Checks a monotonic successor with byte-exact immutable acceptance claims.
    ///
    /// # Errors
    ///
    /// Rejects rewritten identity, signed evidence, original descriptor, phase
    /// rollback, or a revision that does not match exactly one phase advance.
    pub fn validate_successor(&self, next: &Self) -> Result<(), LedgerFormatErrorV1> {
        self.validate_canonical_artifacts()?;
        next.validate_canonical_artifacts()?;
        if self.state == NativeAcquireCompletionStateV2::Requested
            && next.state == NativeAcquireCompletionStateV2::Prepared
        {
            let expected = self.with_accepted_reply(
                next.accepted_reply
                    .clone()
                    .ok_or(LedgerFormatErrorV1::Corrupt("native acceptance missing"))?,
            )?;
            return if expected == *next {
                Ok(())
            } else {
                Err(LedgerFormatErrorV1::Corrupt(
                    "native accepted request was rewritten",
                ))
            };
        }
        if self.advance(next.state)? != *next {
            return Err(LedgerFormatErrorV1::Corrupt(
                "native acceptance was rewritten",
            ));
        }

        Ok(())
    }
}

// A selected reservation deliberately has no proof until the exact lease and
// native Active marker share one Provider commit. Acceptance alone is not proof.
// Immutable ZFS is never the LocalLive kernel-coupled proof class.
fn validate_native_provider_phase(
    native: NativeAcquireCompletionStateV2,
    acquisition: ProviderAcquisitionStateV1,
    lease_present: bool,
    proof_class: u8,
    kernel_coupled: bool,
) -> Result<(), LedgerFormatErrorV1> {
    let active = acquisition == ProviderAcquisitionStateV1::Active;
    let expected_proof_class = if lease_present { 1 } else { 0 };
    if kernel_coupled
        || proof_class != expected_proof_class
        || (native == NativeAcquireCompletionStateV2::Active && !active)
        || (active
            && !matches!(
                native,
                NativeAcquireCompletionStateV2::Active
                    | NativeAcquireCompletionStateV2::CleanupRequired
            ))
    {
        return Err(LedgerFormatErrorV1::Corrupt(
            "native Provider phase/proof class",
        ));
    }

    Ok(())
}

/// Classifies exact cross-journal recovery without granting completion authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeAcquireRecoveryDecisionV2 {
    /// Only the original signed request may read back the Storage acceptance.
    AwaitOriginalAcceptance,
    /// The original challenge is still issued; a new nonce is forbidden.
    AwaitOriginalSpend,
    /// The spent receipt may complete only with the retained original live FD.
    OriginalCompletionPending,
    /// The exact Active record may replay only with that same live FD custody.
    OriginalActive,
    /// Completion and replay are closed; exact authenticated cleanup is required.
    CleanupRequired,
    /// Another owner may retain the original FD; recovery is not proven absent.
    OriginalCustodyUnavailable,
}

/// Reduces the two durable journals and original descriptor custody.
///
/// `live_original_root` is a nonauthorizing identity projection of runtime-owned
/// custody, not permission to reopen a path. A fixed owner must derive it from
/// the original retained FD. `None` never allows remount, renewal, or a nonce.
/// Provider Active and the native Active marker must share one Provider commit;
/// only challenge spend may lead that commit in the separate journal.
///
/// # Errors
///
/// Rejects a changed receipt, session, descriptor, or impossible Active cut.
pub fn reduce_native_acquire_recovery_v2(
    record: &NativeAcquireCompletionRecordV2,
    challenge_receipt: Option<ObjectDigest>,
    provider_active: bool,
    live_session: Option<ObjectDigest>,
    live_original_root: Option<(SourceRootIdentityV1, ObjectDigest)>,
) -> Result<NativeAcquireRecoveryDecisionV2, LedgerFormatErrorV1> {
    record.validate_canonical_artifacts()?;
    if challenge_receipt.is_some_and(|digest| digest != record.receipt_digest)
        || live_session.is_some_and(|session| session != record.session_binding)
        || live_original_root.is_some_and(|identity| {
            identity != (record.original_root, record.descriptor_commitment)
        })
        || (provider_active && challenge_receipt.is_none())
        || (record.state == NativeAcquireCompletionStateV2::Active && !provider_active)
        || (provider_active
            && !matches!(
                record.state,
                NativeAcquireCompletionStateV2::Active
                    | NativeAcquireCompletionStateV2::CleanupRequired
            ))
        || (record.state == NativeAcquireCompletionStateV2::Spent && challenge_receipt.is_none())
    {
        return Err(LedgerFormatErrorV1::Corrupt(
            "native completion cross-journal equivocation",
        ));
    }
    if record.state == NativeAcquireCompletionStateV2::Requested {
        return Ok(NativeAcquireRecoveryDecisionV2::AwaitOriginalAcceptance);
    }
    if record.canonical_request.is_some()
        && record.state != NativeAcquireCompletionStateV2::CleanupRequired
        && (live_session.is_none() || live_original_root.is_none())
    {
        return Ok(NativeAcquireRecoveryDecisionV2::OriginalCustodyUnavailable);
    }
    if record.state == NativeAcquireCompletionStateV2::CleanupRequired
        || live_session.is_none()
        || live_original_root.is_none()
    {
        return Ok(NativeAcquireRecoveryDecisionV2::CleanupRequired);
    }
    Ok(match (challenge_receipt, provider_active) {
        (None, false) => NativeAcquireRecoveryDecisionV2::AwaitOriginalSpend,
        (Some(_), false) => NativeAcquireRecoveryDecisionV2::OriginalCompletionPending,
        (Some(_), true) => NativeAcquireRecoveryDecisionV2::OriginalActive,
        (None, true) => return Err(LedgerFormatErrorV1::Corrupt("unspent native Active")),
    })
}

/// Constructs the canonical unique native-completion key for an acquisition.
#[must_use]
pub fn native_completion_key_v2(acquisition_id: ObjectDigest) -> Vec<u8> {
    let mut key = KEY_MAGIC.to_vec();
    key.extend_from_slice(acquisition_id.as_bytes());
    key
}

pub(super) fn encode_body(value: &NativeAcquireCompletionRecordV2) -> Vec<u8> {
    let mut body = Encoder::with_capacity(BODY_BYTES);
    body.array(if value.original_clock.is_some() {
        CLOCKED_BODY_MAGIC
    } else if value.canonical_request.is_some() {
        REQUESTED_BODY_MAGIC
    } else {
        BODY_MAGIC
    });
    body.array(&value.provider_id);
    body.array(&value.holder_id);
    for digest in [
        value.session_binding,
        value.attempt_digest,
        value.acquisition_id,
    ] {
        body.digest(digest);
    }
    body.array(&value.challenge);
    body.i64(value.challenge_issued_seconds);
    body.i64(value.challenge_valid_until_seconds);
    body.digest(value.root_request_digest);
    body.array(&value.root_request_id);
    for digest in [
        value.typed_request_digest,
        value.native_request_digest,
        value.receipt_digest,
        value.acceptance_digest,
        value.acceptance_payload_digest,
    ] {
        body.digest(digest);
    }
    body.array(&value.issuance_id);
    body.digest(value.binding_digest);
    body.digest(value.publication_head);
    body.source_root(Some(value.original_root));
    body.digest(value.descriptor_commitment);
    debug_assert_eq!(body.len(), BODY_BYTES);
    if let Some(request) = value.canonical_request.as_ref() {
        body.optional_digest(value.reservation_acquisition_digest);
        if let Some(clock) = value.original_clock {
            clock.encode(&mut body);
        }
        let request = request.to_canonical_bytes();
        body.u32(request.len() as u32);
        body.bytes(&request);
        let reply = value
            .accepted_reply
            .as_ref()
            .map(StorageNativeAcquireReplyV3::to_canonical_bytes);
        let expected_bytes = BODY_BYTES
            + 40
            + value.original_clock.map_or(0, |_| clock::CLOCK_BYTES)
            + request.len()
            + reply.as_ref().map_or(0, Vec::len);
        body.u32(reply.as_ref().map_or(0, Vec::len) as u32);
        if let Some(reply) = reply {
            body.bytes(&reply);
        }
        debug_assert_eq!(body.len(), expected_bytes);
    }
    debug_assert!(body.len() <= MAXIMUM_BODY_BYTES);
    body.as_slice().to_vec()
}

#[cfg(test)]
#[path = "native_completion/request_tests.rs"]
pub(crate) mod request_tests;

pub(super) fn envelope_version(body: &[u8]) -> u16 {
    if body.get(..8) == Some(CLOCKED_BODY_MAGIC.as_slice()) {
        7
    } else if body.get(..8) == Some(REQUESTED_BODY_MAGIC.as_slice()) {
        6
    } else {
        5
    }
}

pub(super) fn decode_body(
    key: &[u8],
    bytes: &[u8],
    revision: u64,
    state: u8,
) -> Result<NativeAcquireCompletionRecordV2, LedgerFormatErrorV1> {
    let clocked = bytes.get(..8) == Some(CLOCKED_BODY_MAGIC.as_slice());
    let retained = clocked || bytes.get(..8) == Some(REQUESTED_BODY_MAGIC.as_slice());
    let clock_bytes = if clocked { clock::CLOCK_BYTES } else { 0 };
    if (!retained && (bytes.len() != BODY_BYTES || bytes.get(..8) != Some(BODY_MAGIC.as_slice())))
        || (retained
            && (bytes.len() < BODY_BYTES + 40 + clock_bytes
                || bytes.len() > MAXIMUM_BODY_BYTES - clock::CLOCK_BYTES + clock_bytes))
    {
        return Err(LedgerFormatErrorV1::Corrupt(
            "native completion version or width",
        ));
    }
    let state = match state {
        0 => NativeAcquireCompletionStateV2::Requested,
        1 => NativeAcquireCompletionStateV2::Prepared,
        2 => NativeAcquireCompletionStateV2::Spent,
        3 => NativeAcquireCompletionStateV2::Active,
        4 => NativeAcquireCompletionStateV2::CleanupRequired,
        _ => return Err(LedgerFormatErrorV1::Corrupt("native completion phase")),
    };
    let mut body = Decoder::new(&bytes[8..]);
    let mut value = NativeAcquireCompletionRecordV2 {
        revision,
        state,
        provider_id: body.nonzero_array()?,
        holder_id: body.nonzero_array()?,
        session_binding: body.nonzero_digest()?,
        attempt_digest: body.nonzero_digest()?,
        acquisition_id: body.nonzero_digest()?,
        challenge: body.nonzero_array()?,
        challenge_issued_seconds: body.nonnegative_i64()?,
        challenge_valid_until_seconds: body.nonnegative_i64()?,
        root_request_digest: body.nonzero_digest()?,
        root_request_id: body.nonzero_array()?,
        typed_request_digest: body.nonzero_digest()?,
        native_request_digest: body.nonzero_digest()?,
        receipt_digest: body.digest()?,
        acceptance_digest: body.digest()?,
        acceptance_payload_digest: body.digest()?,
        issuance_id: body.array()?,
        binding_digest: body.nonzero_digest()?,
        publication_head: body.nonzero_digest()?,
        original_root: SourceRootIdentityV1 {
            kernel_boot_id: body.array()?,
            device: body.u64()?,
            inode: body.u64()?,
            unique_mount_id: body.u64()?,
        },
        descriptor_commitment: body.digest()?,
        canonical_request: None,
        accepted_reply: None,
        reservation_acquisition_digest: None,
        original_clock: None,
    };
    if retained {
        value.reservation_acquisition_digest = Some(body.nonzero_digest()?);
        if clocked {
            value.original_clock = Some(NativeAcquireClockAnchorV1::decode(&mut body)?);
        }
        let request_length = body.u32()? as usize;
        if request_length == 0
            || request_length > MAXIMUM_SIGNED_STORAGE_NATIVE_ACQUIRE_REQUEST_BYTES_V2
        {
            return Err(LedgerFormatErrorV1::Corrupt(
                "native retained request length",
            ));
        }
        value.canonical_request = Some(
            SignedStorageNativeAcquireRequestV2::from_canonical_bytes(body.take(request_length)?)
                .map_err(|_| LedgerFormatErrorV1::Corrupt("native retained signed request"))?,
        );
        let reply_length = body.u32()? as usize;
        if reply_length != 0 {
            if reply_length != STORAGE_NATIVE_ACQUIRE_REPLY_BYTES_V3 {
                return Err(LedgerFormatErrorV1::Corrupt("native retained reply length"));
            }
            value.accepted_reply = Some(
                StorageNativeAcquireReplyV3::from_canonical_bytes(body.take(reply_length)?)
                    .map_err(|_| LedgerFormatErrorV1::Corrupt("native retained accepted reply"))?,
            );
        }
    } else {
        SourceRootIdentityV1::new(
            value.original_root.kernel_boot_id,
            value.original_root.device,
            value.original_root.inode,
            value.original_root.unique_mount_id,
        )?;
        if [
            value.receipt_digest,
            value.acceptance_digest,
            value.acceptance_payload_digest,
            value.descriptor_commitment,
        ]
        .iter()
        .any(|digest| digest.as_bytes() == &[0; 32])
            || value.issuance_id == [0; 16]
        {
            return Err(LedgerFormatErrorV1::Corrupt(
                "native legacy acceptance sentinel",
            ));
        }
    }
    body.finish()?;
    value.validate_canonical_artifacts()?;
    if native_completion_key_v2(value.acquisition_id) != key
        || revision == 0
        || value.challenge_valid_until_seconds <= value.challenge_issued_seconds
    {
        return Err(LedgerFormatErrorV1::Corrupt(
            "native completion key or revision",
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::format::{decode_record, encode_native_completion_v2};
    use crate::ledger::model::DecodedRecordV1;

    fn digest(byte: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([byte; 32])
    }

    fn record() -> NativeAcquireCompletionRecordV2 {
        NativeAcquireCompletionRecordV2 {
            revision: 1,
            state: NativeAcquireCompletionStateV2::Prepared,
            provider_id: [1; 16],
            holder_id: [2; 16],
            session_binding: digest(3),
            attempt_digest: digest(4),
            acquisition_id: digest(5),
            challenge: [6; 32],
            challenge_issued_seconds: 100,
            challenge_valid_until_seconds: 160,
            root_request_digest: digest(7),
            root_request_id: [8; 16],
            typed_request_digest: digest(9),
            native_request_digest: digest(10),
            receipt_digest: digest(11),
            acceptance_digest: digest(12),
            acceptance_payload_digest: digest(24),
            issuance_id: [13; 16],
            binding_digest: digest(14),
            publication_head: digest(15),
            original_root: SourceRootIdentityV1::new([16; 16], 17, 18, 19).unwrap(),
            descriptor_commitment: digest(20),
            canonical_request: None,
            accepted_reply: None,
            reservation_acquisition_digest: None,
            original_clock: None,
        }
    }

    #[test]
    fn native_completion_uses_explicit_canonical_version_and_width() {
        let record = record();
        let key = native_completion_key_v2(record.acquisition_id);
        let bytes = encode_native_completion_v2(&record);
        assert_eq!(bytes.len(), 64 + BODY_BYTES);
        assert_eq!(&bytes[8..10], &5_u16.to_be_bytes());
        let DecodedRecordV1::NativeCompletion(decoded) = decode_record(&key, &bytes).unwrap()
        else {
            panic!("wrong typed family");
        };
        assert_eq!(decoded, record);

        let mut legacy_envelope = bytes.clone();
        legacy_envelope[8..10].copy_from_slice(&4_u16.to_be_bytes());
        assert!(decode_record(&key, &legacy_envelope).is_err());
        assert!(decode_record(&key, &bytes[..bytes.len() - 1]).is_err());
        assert!(crate::validate_prospective_records([(key.as_slice(), bytes.as_slice())]).is_err());
    }

    #[test]
    fn crash_cuts_require_exact_original_custody_without_new_nonce() {
        let record = record();
        let live = Some((record.original_root, record.descriptor_commitment));
        let session = Some(record.session_binding);
        assert_eq!(
            reduce_native_acquire_recovery_v2(&record, None, false, session, live),
            Ok(NativeAcquireRecoveryDecisionV2::AwaitOriginalSpend)
        );
        assert_eq!(
            reduce_native_acquire_recovery_v2(
                &record,
                Some(record.receipt_digest),
                false,
                session,
                live
            ),
            Ok(NativeAcquireRecoveryDecisionV2::OriginalCompletionPending)
        );
        let spent = record
            .advance(NativeAcquireCompletionStateV2::Spent)
            .unwrap();
        assert!(
            reduce_native_acquire_recovery_v2(
                &spent,
                Some(record.receipt_digest),
                true,
                session,
                live
            )
            .is_err()
        );
        let active = spent
            .advance(NativeAcquireCompletionStateV2::Active)
            .unwrap();
        assert_eq!(
            reduce_native_acquire_recovery_v2(
                &active,
                Some(record.receipt_digest),
                true,
                session,
                live
            ),
            Ok(NativeAcquireRecoveryDecisionV2::OriginalActive)
        );
        assert_eq!(active.challenge, record.challenge);
        assert_eq!(
            active
                .advance(NativeAcquireCompletionStateV2::Active)
                .unwrap(),
            active
        );

        assert!(
            reduce_native_acquire_recovery_v2(&spent, Some(digest(21)), false, session, live)
                .is_err()
        );
        assert!(
            reduce_native_acquire_recovery_v2(
                &spent,
                Some(record.receipt_digest),
                false,
                Some(digest(22)),
                live
            )
            .is_err()
        );
        let remounted = SourceRootIdentityV1::new([16; 16], 17, 18, 23).unwrap();
        assert!(
            reduce_native_acquire_recovery_v2(
                &spent,
                Some(record.receipt_digest),
                false,
                session,
                Some((remounted, record.descriptor_commitment))
            )
            .is_err()
        );
        assert!(reduce_native_acquire_recovery_v2(&active, None, true, session, live).is_err());
    }

    #[test]
    fn total_descriptor_or_session_loss_closes_completion_and_cleanup_is_one_way() {
        let record = record();
        for state in [
            NativeAcquireCompletionStateV2::Prepared,
            NativeAcquireCompletionStateV2::Spent,
            NativeAcquireCompletionStateV2::Active,
        ] {
            let record = record.advance(state).unwrap();
            let receipt = (state != NativeAcquireCompletionStateV2::Prepared)
                .then_some(record.receipt_digest);
            let active = state == NativeAcquireCompletionStateV2::Active;
            assert_eq!(
                reduce_native_acquire_recovery_v2(
                    &record,
                    receipt,
                    active,
                    Some(record.session_binding),
                    None
                ),
                Ok(NativeAcquireRecoveryDecisionV2::CleanupRequired)
            );
        }
        assert_eq!(
            reduce_native_acquire_recovery_v2(
                &record,
                None,
                false,
                None,
                Some((record.original_root, record.descriptor_commitment))
            ),
            Ok(NativeAcquireRecoveryDecisionV2::CleanupRequired)
        );
        let cleanup = record
            .advance(NativeAcquireCompletionStateV2::CleanupRequired)
            .unwrap();
        assert!(
            cleanup
                .advance(NativeAcquireCompletionStateV2::Active)
                .is_err()
        );
        assert_eq!(cleanup.challenge, record.challenge);
    }

    #[test]
    fn native_successor_rejects_equivocation_renewal_and_rollback() {
        let original = record();
        let spent = original
            .advance(NativeAcquireCompletionStateV2::Spent)
            .unwrap();
        original.validate_successor(&spent).unwrap();
        spent.validate_successor(&spent).unwrap();

        type Mutation = fn(&mut NativeAcquireCompletionRecordV2);
        let mutations: &[(&str, Mutation)] = &[
            ("revision", |record| record.revision += 1),
            ("receipt", |record| record.receipt_digest = digest(25)),
            ("signed acceptance", |record| {
                record.acceptance_digest = digest(25)
            }),
            ("acceptance payload", |record| {
                record.acceptance_payload_digest = digest(25)
            }),
            ("session", |record| record.session_binding = digest(25)),
            ("challenge", |record| record.challenge = [25; 32]),
            ("renewal", |record| {
                record.challenge_valid_until_seconds += 60
            }),
            ("Root request", |record| {
                record.root_request_digest = digest(25)
            }),
            ("native request", |record| {
                record.native_request_digest = digest(25)
            }),
            ("acquisition", |record| record.acquisition_id = digest(25)),
            ("attempt", |record| record.attempt_digest = digest(25)),
            ("issuance", |record| record.issuance_id = [25; 16]),
            ("remount", |record| {
                record.original_root = SourceRootIdentityV1::new([16; 16], 17, 18, 25).unwrap();
            }),
        ];
        for (label, mutate) in mutations {
            let mut changed = spent.clone();
            mutate(&mut changed);
            assert!(original.validate_successor(&changed).is_err(), "{label}");
        }

        assert!(spent.validate_successor(&original).is_err());
    }

    #[test]
    fn native_provider_phase_join_requires_unproved_reservation_and_atomic_active() {
        use NativeAcquireCompletionStateV2 as Native;
        use ProviderAcquisitionStateV1 as Acquisition;
        use aos_sandbox_source_provider_protocol::{
            RecursiveTopologyProofV1, SourceProviderProofV1, ZfsHeldSnapshotProofV1,
        };

        let proof = SourceProviderProofV1::ZfsHeldSnapshot {
            proof: ZfsHeldSnapshotProofV1::new(
                [26; 32],
                27,
                28,
                29,
                30,
                [31; 16],
                32,
                digest(33),
                digest(34),
                digest(35),
            )
            .unwrap(),
            topology: RecursiveTopologyProofV1::new([36; 16], 37, digest(38), 1, 0, 1, 0).unwrap(),
        };
        let kernel_coupled = proof.requires_kernel_coupled();
        assert!(!kernel_coupled);
        let zfs_class = proof.class_code();
        assert_eq!(zfs_class, 1);

        // These are strict graph-join projections, not signed lease artifacts
        // or a fixed-owner positive completion qualification.
        let applying = Acquisition::Applying;
        let active = Acquisition::Active;
        let cases = [
            (Native::Prepared, applying, false, 0, true),
            (Native::Prepared, applying, false, zfs_class, false),
            (Native::Spent, applying, false, 0, true),
            (Native::Spent, applying, false, zfs_class, false),
            (Native::CleanupRequired, applying, false, 0, true),
            (Native::CleanupRequired, applying, false, zfs_class, false),
            (Native::Active, applying, false, 0, false),
            (Native::Prepared, active, true, zfs_class, false),
            (Native::Spent, active, true, zfs_class, false),
            (Native::Active, active, true, zfs_class, true),
            (Native::Active, active, true, 0, false),
            (Native::Active, active, true, 2, false),
            (Native::CleanupRequired, active, true, zfs_class, true),
            (Native::CleanupRequired, active, true, 0, false),
            (Native::CleanupRequired, active, true, 2, false),
        ];
        for (native, acquisition, lease_present, proof_class, valid) in cases {
            assert_eq!(
                validate_native_provider_phase(
                    native,
                    acquisition,
                    lease_present,
                    proof_class,
                    kernel_coupled,
                )
                .is_ok(),
                valid,
                "{native:?}/{acquisition:?}/lease={lease_present}/proof={proof_class}"
            );
            assert!(
                validate_native_provider_phase(
                    native,
                    acquisition,
                    lease_present,
                    proof_class,
                    true
                )
                .is_err(),
                "kernel-coupled {native:?}/{acquisition:?}"
            );
        }
    }
}
