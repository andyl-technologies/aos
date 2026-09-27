//! Typed native acceptance retained across challenge-spend and Active commits.
//!
//! This pure model grants no signing, descriptor, effect, or release authority.
//! The native-only version-5 AOSSPL envelope contains this versioned body:
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
    SignedStorageNativeAcquireRequestV2, SourceProviderMethod, VerifiedStorageNativeAcquireV2,
    decode_acquire_request, digest_acquire_request, digest_signed_request,
};

use super::LedgerFormatErrorV1;
use super::codec::{Decoder, Encoder};
use super::model::{
    AcquisitionRecordV1, AttemptRecordV1, ProviderAcquisitionStateV1, SourceRootIdentityV1,
};

pub(super) const BODY_BYTES: usize = 544;
const BODY_MAGIC: &[u8; 8] = b"AOSNCR02";
const KEY_MAGIC: &[u8; 8] = b"AOSNCK02";

/// Names one irreversible native completion recovery phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NativeAcquireCompletionStateV2 {
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
}

impl NativeAcquireCompletionRecordV2 {
    /// Checks an independently verified acceptance against every retained claim.
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
        verified: &VerifiedStorageNativeAcquireV2,
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
    /// Rejects renewal, rebind, changed request/session, foreign acquisition,
    /// or a claimed Active state without the exact original root.
    pub fn validate_provider_graph(
        &self,
        attempt: &AttemptRecordV1,
        acquisition: &AcquisitionRecordV1,
    ) -> Result<(), LedgerFormatErrorV1> {
        validate_native_provider_phase(
            self.state,
            acquisition.state,
            acquisition.lease_id.is_some(),
            acquisition.proof_class,
        )?;

        if self.provider_id != acquisition.provider.authority_id()
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
            || !acquisition.normalized_intent.kernel_coupled()
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
fn validate_native_provider_phase(
    native: NativeAcquireCompletionStateV2,
    acquisition: ProviderAcquisitionStateV1,
    lease_present: bool,
    proof_class: u8,
) -> Result<(), LedgerFormatErrorV1> {
    let active = acquisition == ProviderAcquisitionStateV1::Active;
    let expected_proof_class = if lease_present { 1 } else { 0 };
    if proof_class != expected_proof_class
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
    /// The original challenge is still issued; a new nonce is forbidden.
    AwaitOriginalSpend,
    /// The spent receipt may complete only with the retained original live FD.
    OriginalCompletionPending,
    /// The exact Active record may replay only with that same live FD custody.
    OriginalActive,
    /// Completion and replay are closed; exact authenticated cleanup is required.
    CleanupRequired,
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
    body.array(BODY_MAGIC);
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
    body.as_slice().to_vec()
}

pub(super) fn decode_body(
    key: &[u8],
    bytes: &[u8],
    revision: u64,
    state: u8,
) -> Result<NativeAcquireCompletionRecordV2, LedgerFormatErrorV1> {
    if bytes.len() != BODY_BYTES || bytes.get(..8) != Some(BODY_MAGIC.as_slice()) {
        return Err(LedgerFormatErrorV1::Corrupt(
            "native completion version or width",
        ));
    }
    let state = match state {
        1 => NativeAcquireCompletionStateV2::Prepared,
        2 => NativeAcquireCompletionStateV2::Spent,
        3 => NativeAcquireCompletionStateV2::Active,
        4 => NativeAcquireCompletionStateV2::CleanupRequired,
        _ => return Err(LedgerFormatErrorV1::Corrupt("native completion phase")),
    };
    let mut body = Decoder::new(&bytes[8..]);
    let value = NativeAcquireCompletionRecordV2 {
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
        receipt_digest: body.nonzero_digest()?,
        acceptance_digest: body.nonzero_digest()?,
        acceptance_payload_digest: body.nonzero_digest()?,
        issuance_id: body.nonzero_array()?,
        binding_digest: body.nonzero_digest()?,
        publication_head: body.nonzero_digest()?,
        original_root: SourceRootIdentityV1::new(
            body.nonzero_array()?,
            body.nonzero_u64()?,
            body.nonzero_u64()?,
            body.nonzero_u64()?,
        )?,
        descriptor_commitment: body.nonzero_digest()?,
    };
    body.finish()?;
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

        // These are strict graph-join projections, not signed lease artifacts
        // or a fixed-owner positive completion qualification.
        for native in [Native::Prepared, Native::Spent, Native::CleanupRequired] {
            assert!(
                validate_native_provider_phase(native, Acquisition::Applying, false, 0).is_ok()
            );
            assert!(
                validate_native_provider_phase(native, Acquisition::Applying, false, 1).is_err()
            );
        }
        assert!(
            validate_native_provider_phase(Native::Active, Acquisition::Applying, false, 0)
                .is_err()
        );
        for native in [Native::Prepared, Native::Spent] {
            assert!(validate_native_provider_phase(native, Acquisition::Active, true, 1).is_err());
        }
        for native in [Native::Active, Native::CleanupRequired] {
            assert!(validate_native_provider_phase(native, Acquisition::Active, true, 1).is_ok());
            assert!(validate_native_provider_phase(native, Acquisition::Active, true, 0).is_err());
            assert!(validate_native_provider_phase(native, Acquisition::Active, true, 2).is_err());
        }
    }
}
