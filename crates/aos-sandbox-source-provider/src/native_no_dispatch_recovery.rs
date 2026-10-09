//! Exact protected terminal settlement for a native reservation with no backend dispatch.
//!
//! Only the dedicated native no-dispatch backend identity may yield this
//! descriptor-free recovery observation. It cannot be reused for a future
//! positive Storage or SourceRoot path.

use aos_sandbox::ProtectedJournalSnapshot;
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    ACQUIRE_SOURCE_REQUEST_VERSION_V2, ACQUIRE_SOURCE_REQUEST_VERSION_V3,
    NativeRecoveryTerminalDigestsV1, SignedSourceProviderRequestV1, SourceProviderMethod,
    decode_acquire_request, digest_acquire_request, digest_signed_request,
};

use crate::acquire::derive_native_no_dispatch_id;
use crate::format::{
    acquisition_key, attempt_key, encode_acquisition, encode_attempt, encode_session,
    record_digest, session_key,
};
use crate::model::{ProviderAcquisitionStateV1, ProviderAttemptStateV1};
use crate::{FixedProviderOwnerV1, ProviderLedgerError};

/// Carries exact durable native terminal records and their protected snapshot.
///
/// Construction is restricted to the fixed Provider owner after full typed
/// replay. The snapshot must still be current when a response is signed.
#[must_use = "a native settlement is not a Mount terminal outcome until sent and consumed"]
pub struct NativeNoDispatchSettlementV1 {
    pub(crate) digests: NativeRecoveryTerminalDigestsV1,
    pub(crate) query_digest: ObjectDigest,
    pub(crate) snapshot: ProtectedJournalSnapshot,
}

impl FixedProviderOwnerV1 {
    /// Durably retires one proofless native reservation that forbids dispatch.
    ///
    /// The four digests name the original Applying acquisition and its exact
    /// Faulted acquisition, Retired attempt, and cleared old session. This is
    /// not a Storage plan, completed source, or permission for a successor.
    /// Recovery does not require the original catalog row to remain current:
    /// admission already retained that selection, and this path attests only
    /// that the dedicated native reservation could never dispatch an effect.
    ///
    /// # Errors
    ///
    /// Rejects absent or changed protected attempt, native row, holder session,
    /// no-dispatch identity, signed RootMount request, or journal custody.
    pub(crate) fn settle_native_no_dispatch_recovery(
        &mut self,
        acquisition_id: ObjectDigest,
        expected_provider_id: [u8; 16],
        expected_holder_id: [u8; 16],
        expected_signed_request_digest: ObjectDigest,
        query_digest: ObjectDigest,
    ) -> Result<NativeNoDispatchSettlementV1, ProviderLedgerError> {
        self.with_ledger(|ledger| {
            let journal_snapshot = ledger.journal.snapshot()?;
            let mut acquisitions = ledger
                .recovered
                .acquisitions
                .iter()
                .filter(|(_, record)| record.acquisition_id == acquisition_id);
            let (acquisition_key_value, acquisition) = acquisitions
                .next()
                .ok_or(ProviderLedgerError::Unavailable)?;
            if acquisitions.next().is_some() {
                return Err(ProviderLedgerError::Equivocation);
            }
            let acquisition = acquisition.clone();
            let acquisition_key_value = acquisition_key_value.clone();
            // A native dispatch marker can never become proof of no dispatch,
            // even before Storage acceptance or descriptor custody exists.
            if ledger
                .recovered
                .native_completions
                .contains_key(&acquisition_id)
            {
                return Err(ProviderLedgerError::Unavailable);
            }
            let key = acquisition_key(&acquisition_key_value);
            let mut attempts = ledger.recovered.attempts.iter().filter(|(_, attempt)| {
                attempt.attempt_digest == acquisition.current_attempt_digest
            });
            let (attempt_key_value, attempt) =
                attempts.next().ok_or(ProviderLedgerError::Unavailable)?;
            if attempts.next().is_some() {
                return Err(ProviderLedgerError::Equivocation);
            }
            let attempt = attempt.clone();
            let attempt_key_value = attempt_key_value.clone();
            let holder_head = ledger
                .recovered
                .sessions
                .get(&(expected_provider_id, expected_holder_id))
                .ok_or(ProviderLedgerError::Unavailable)?
                .clone();
            let signed_request =
                SignedSourceProviderRequestV1::from_canonical_bytes(&attempt.signed_request)
                    .map_err(|_| ProviderLedgerError::Corrupt("retained signed Acquire request"))?;
            let request = decode_acquire_request(signed_request.subject())
                .map_err(|_| ProviderLedgerError::Corrupt("retained Acquire subject"))?;
            let closed_id = derive_native_no_dispatch_id(
                acquisition.normalized_intent.digest(),
                acquisition.catalog_generation,
                acquisition.catalog_digest,
            );
            let applying = acquisition.state == ProviderAcquisitionStateV1::Applying
                && attempt.state == ProviderAttemptStateV1::Reserved
                && holder_head.pending_attempt_digest == Some(attempt.attempt_digest);
            let settled = acquisition.state == ProviderAcquisitionStateV1::Faulted
                && attempt.state == ProviderAttemptStateV1::Retired
                && holder_head.pending_attempt_digest.is_none();
            if !(applying || settled)
                || acquisition.provider.authority_id() != expected_provider_id
                || acquisition.holder.authority_id() != expected_holder_id
                || acquisition.normalized_intent.kernel_coupled()
                || acquisition.proof_class != 0
                || acquisition.backend_id != closed_id
                || (applying && acquisition.native_no_dispatch_reservation_digest.is_some())
                || (settled && acquisition.native_no_dispatch_reservation_digest.is_none())
                || acquisition.resource_id == [0; 32]
                || acquisition.lease_id.is_some()
                || acquisition.backend_evidence.is_some()
                || acquisition.source_root.is_some()
                || acquisition.effect_attempt_digest != attempt.attempt_digest
                || attempt.method != SourceProviderMethod::Acquire
                || attempt.status.is_some()
                || attempt.response_sequence.is_some()
                || attempt.provider != acquisition.provider
                || attempt.holder != acquisition.holder
                || attempt.proof_class_capabilities & 1 == 0
                || attempt.operation_intent_digest != acquisition.normalized_intent.digest()
                || attempt.signed_request_digest != expected_signed_request_digest
                || attempt.signed_request_digest != digest_signed_request(&signed_request)
                || attempt.signed_request_digest_again != attempt.signed_request_digest
                || attempt.typed_request_digest != digest_acquire_request(&request)
                || attempt.root_record_signer != *signed_request.signer()
                || attempt.session_binding != holder_head.session_binding
                || holder_head.signers[1] != attempt.root_record_signer
                || holder_head.next_request_sequence
                    != attempt
                        .request_sequence
                        .checked_add(1)
                        .ok_or(ProviderLedgerError::Unavailable)?
                || request.session_binding() != attempt.session_binding
                || request.sequence() != attempt.request_sequence
                || request.request_id() != attempt.request_id
                || request.acquisition_id() != acquisition_id
                || !matches_original_no_dispatch_profile(&request, &acquisition)
                || request.acquisition_sequence() != acquisition.acquisition_sequence
                || request.binding_digest() != acquisition.normalized_intent.binding_digest()
                || request.kernel_coupled()
            {
                return Err(ProviderLedgerError::Unavailable);
            }

            let retained = ledger
                .journal
                .get(&key)?
                .ok_or(ProviderLedgerError::Unavailable)?;
            let attempt_key = attempt_key(&attempt_key_value);
            let retained_attempt = ledger
                .journal
                .get(&attempt_key)?
                .ok_or(ProviderLedgerError::Unavailable)?;
            let holder_key = session_key(expected_provider_id, expected_holder_id);
            let retained_session = ledger
                .journal
                .get(&holder_key)?
                .ok_or(ProviderLedgerError::Unavailable)?;
            if retained != encode_acquisition(&acquisition).as_slice()
                || retained_attempt != encode_attempt(&attempt).as_slice()
                || retained_session != encode_session(&holder_head).as_slice()
            {
                return Err(ProviderLedgerError::ConfigurationMismatch);
            }
            let reservation_digest = if settled {
                acquisition
                    .native_no_dispatch_reservation_digest
                    .ok_or(ProviderLedgerError::Unavailable)?
            } else {
                record_digest(&encode_acquisition(&acquisition))?
            };
            let post_records = if applying {
                let reserved_acquisition = acquisition.clone();
                let reserved_attempt = attempt.clone();
                let reserved_session = holder_head.clone();
                let mut faulted = acquisition;
                faulted.revision = faulted
                    .revision
                    .checked_add(1)
                    .ok_or(ProviderLedgerError::Unavailable)?;
                faulted.state = ProviderAcquisitionStateV1::Faulted;
                faulted.native_no_dispatch_reservation_digest = Some(reservation_digest);

                let mut retired = attempt;
                retired.revision = retired
                    .revision
                    .checked_add(1)
                    .ok_or(ProviderLedgerError::Unavailable)?;
                retired.state = ProviderAttemptStateV1::Retired;

                let mut cleared = holder_head;
                cleared.revision = cleared
                    .revision
                    .checked_add(1)
                    .ok_or(ProviderLedgerError::Unavailable)?;
                cleared.pending_attempt_digest = None;
                let expected_faulted = encode_acquisition(&faulted);
                let expected_retired = encode_attempt(&retired);
                let expected_cleared = encode_session(&cleared);

                crate::native_no_dispatch_capacity::commit_terminal(
                    ledger,
                    b"settle-native-no-dispatch-acquire",
                    vec![
                        (key.clone(), expected_faulted.clone()),
                        (attempt_key.clone(), expected_retired.clone()),
                        (holder_key.clone(), expected_cleared.clone()),
                    ],
                    &reserved_acquisition,
                    &reserved_attempt,
                    &reserved_session,
                )?;
                Some((
                    faulted,
                    retired,
                    cleared,
                    expected_faulted,
                    expected_retired,
                    expected_cleared,
                ))
            } else {
                None
            };

            let committed = post_records.is_some();
            let outcome = (|| {
                let faulted = ledger
                    .journal
                    .get(&key)?
                    .ok_or(ProviderLedgerError::Unavailable)?;
                let retired = ledger
                    .journal
                    .get(&attempt_key)?
                    .ok_or(ProviderLedgerError::Unavailable)?;
                let cleared = ledger
                    .journal
                    .get(&holder_key)?
                    .ok_or(ProviderLedgerError::Unavailable)?;
                if let Some((_, _, _, expected_faulted, expected_retired, expected_cleared)) =
                    &post_records
                {
                    if faulted != expected_faulted.as_slice()
                        || retired != expected_retired.as_slice()
                        || cleared != expected_cleared.as_slice()
                    {
                        return Err(ProviderLedgerError::ConfigurationMismatch);
                    }
                }
                let digests = NativeRecoveryTerminalDigestsV1 {
                    reservation: reservation_digest,
                    faulted_acquisition: record_digest(faulted)?,
                    retired_attempt: record_digest(retired)?,
                    cleared_session: record_digest(cleared)?,
                };
                ledger.journal.validate_source_provider_authority()?;
                if settled {
                    ledger
                        .journal
                        .validate_source_provider_authority_snapshot(&journal_snapshot)?;
                }
                if let Some((faulted, retired, cleared, _, _, _)) = post_records {
                    ledger
                        .recovered
                        .acquisitions
                        .insert(acquisition_key_value, faulted);
                    ledger.recovered.attempts.insert(attempt_key_value, retired);
                    ledger
                        .recovered
                        .sessions
                        .insert((expected_provider_id, expected_holder_id), cleared.clone());
                    ledger.recovered.session_history.insert(
                        (
                            expected_provider_id,
                            expected_holder_id,
                            cleared.session_binding,
                        ),
                        cleared,
                    );
                }
                Ok(NativeNoDispatchSettlementV1 {
                    digests,
                    query_digest,
                    snapshot: ledger.journal.snapshot()?,
                })
            })();
            if committed && outcome.is_err() {
                ledger.poison_runtime();
            }
            outcome
        })
    }
}

/// Compares retained DATA without admitting an effect or recreating a clock.
pub(crate) fn matches_original_no_dispatch_profile(
    request: &aos_sandbox_source_provider_protocol::AcquireSourceRequestV1,
    acquisition: &crate::model::AcquisitionRecordV1,
) -> bool {
    match request.acquisition_version() {
        ACQUIRE_SOURCE_REQUEST_VERSION_V2 => {
            acquisition.normalized_intent.native_catalog().is_none()
        }
        ACQUIRE_SOURCE_REQUEST_VERSION_V3 => request.native_catalog().is_some_and(|catalog| {
            acquisition
                .normalized_intent
                .matches_original_acquire_request(request)
                && catalog.resource_namespace_digest() == acquisition.resource_namespace_digest
                && catalog.resource_namespace_digest()
                    == acquisition.normalized_intent.resource_namespace_digest()
                && catalog.head() == (acquisition.catalog_generation, acquisition.catalog_digest)
        }),
        _ => false,
    }
}
