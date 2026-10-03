//! Common owner-side verification, replay, and journal transaction machinery.

use std::collections::BTreeMap;

use aos_sandbox::{
    JournalRecord, JournalTransaction, ProtectedJournalAuthority, ProtectedJournalPreflight,
    RecordNamespace,
};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    AcquireSourceRequestV1, ProviderRequestSequenceExpectationV1, SignedSourceProviderRequestV1,
    SourceProviderDescriptorRole, SourceProviderMethod, SourceResourceV1,
    VerifiedProviderIngressProjectionV1, VerifiedProviderRequestV1,
    decode_acquire_request, decode_acquire_response,
    decode_inventory_request, decode_release_request, digest_signed_request,
};
use aos_sandbox_source_provider_security::ProviderSessionSupersessionEvidenceV1;
use sha2::{Digest as _, Sha256};

use crate::format::{
    attempt_key, decode_record, encode_decoded_record, encode_session_history, record_digest,
    session_history_key,
};
use crate::ledger::model::DecodedRecordV1;
use crate::ledger::native_completion::{
    release_fence::validate_native_release_admission_v1, validate_native_complete_export_v1,
};
use crate::limits::{MAXIMUM_TRANSACTION_BYTES, MAXIMUM_TRANSACTION_RECORDS};
use crate::model::{
    AcquisitionRecordV1, AttemptKeyV1, AttemptRecordV1, CatalogHeadRecordV1, HolderSessionHeadRecordV1,
    ProviderAcquisitionStateV1, ProviderAttemptStateV1,
    ProviderRecoveryWorkV1, RecoveredProviderLedgerV1, WriterIdentityV1,
};
use crate::state::ProviderLedgerV1;
use crate::{
    DurableAcquireReplayV1, DurableCachedResponseV1, NormalizedAcquisitionIntentV1,
    ProviderAdmissionDispositionV1, ProviderLedgerError,
};

const TRANSACTION_ID_DOMAIN: &[u8] = b"aos.sandbox.source-provider.ledger.transaction-id.v1\0";

enum MutationShapeV1 {
    Ordinary,
    NativeReleaseFence,
}

pub(crate) enum CompletionCapacityV1 {
    Preflight {
        preflight: ProtectedJournalPreflight,
        transaction: JournalTransaction,
    },
    NativeNoDispatch,
    // The native owner separately preflights Requested/Prepared/Active while
    // preserving durable cleanup headroom. Generic effects cannot consume it.
    NativeDispatch,
    // This permits only the narrow descriptor-free Release status builder.
    // Physical release/Complete paths still reject native custody.
    NativeReleaseStatus,
}

pub(crate) struct PreparedLedgerMutationV1 {
    pub(crate) transaction: JournalTransaction,
    pub(crate) digest: ObjectDigest,
    pub(crate) prospective_recovered: RecoveredProviderLedgerV1,
}

pub(crate) fn commit_sealed_completion(
    ledger: &mut ProviderLedgerV1<'_>,
    custody: &mut aos_sandbox_source_provider_security::CurrentProviderIngressSessionV1,
    builder: aos_sandbox_source_provider_security::ProviderCompletionBuilderV1,
) -> Result<aos_sandbox_source_provider_security::CommittedProviderOutcomeV1, ProviderLedgerError> {
    let committed = commit_sealed_builder(ledger, custody, builder)?;
    recover_after_sealed_commit(ledger)?;
    Ok(committed)
}

pub(crate) fn commit_retained_native_completion(
    ledger: &mut ProviderLedgerV1<'_>,
    custody: &mut aos_sandbox_source_provider_security::CurrentProviderIngressSessionV1,
    builder: aos_sandbox_source_provider_security::ProviderCompletionBuilderV1,
) -> Result<ObjectDigest, ProviderLedgerError> {
    let committed = commit_sealed_builder(ledger, custody, builder)?;
    let binding = committed.session_binding();
    ledger.native_reply_custody.retain_committed(committed);
    recover_after_sealed_commit(ledger)?;
    Ok(binding)
}

fn commit_sealed_builder(
    ledger: &mut ProviderLedgerV1<'_>,
    custody: &mut aos_sandbox_source_provider_security::CurrentProviderIngressSessionV1,
    builder: aos_sandbox_source_provider_security::ProviderCompletionBuilderV1,
) -> Result<aos_sandbox_source_provider_security::CommittedProviderOutcomeV1, ProviderLedgerError> {
    let committed = match builder.commit(&mut ledger.journal, custody) {
        Ok(committed) => committed,
        Err(error) => {
            ledger.poison_runtime();
            return Err(error.into());
        }
    };
    Ok(committed)
}

fn recover_after_sealed_commit(
    ledger: &mut ProviderLedgerV1<'_>,
) -> Result<(), ProviderLedgerError> {
    let recovered =
        match crate::recovery::recover_capacity_checked(&ledger.journal, &ledger.configuration) {
            Ok(recovered) => recovered,
            Err(error) => {
                ledger.poison_runtime();
                return Err(error);
            }
        };
    ledger.recovered = recovered;
    ledger.refresh_recovery_work();
    Ok(())
}

pub(crate) fn map_pure_ledger_error(
    error: aos_sandbox_source_provider_ledger::LedgerFormatErrorV1,
) -> ProviderLedgerError {
    match error {
        aos_sandbox_source_provider_ledger::LedgerFormatErrorV1::Corrupt(message) => {
            ProviderLedgerError::Corrupt(message)
        }
        aos_sandbox_source_provider_ledger::LedgerFormatErrorV1::LimitExceeded(message) => {
            ProviderLedgerError::LimitExceeded(message)
        }
        aos_sandbox_source_provider_ledger::LedgerFormatErrorV1::NeedsProvenance(message) => {
            ProviderLedgerError::MigrationNeedsProvenance(message)
        }
    }
}

impl core::fmt::Debug for CompletionCapacityV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CompletionCapacityV1([redacted])")
    }
}

impl CompletionCapacityV1 {
    pub(crate) const fn native_no_dispatch() -> Self {
        Self::NativeNoDispatch
    }

    pub(crate) fn validate(
        &self,
        journal: &ProtectedJournalAuthority<'_>,
    ) -> Result<(), ProviderLedgerError> {
        match self {
            Self::Preflight {
                preflight,
                transaction,
            } => {
                journal
                    .validate_preflight_for_effect(preflight, std::slice::from_ref(transaction))?;
                Ok(())
            }
            Self::NativeNoDispatch | Self::NativeDispatch | Self::NativeReleaseStatus => {
                Err(ProviderLedgerError::Unavailable)
            }
        }
    }
}

pub(crate) fn preflight_completion_capacity(
    journal: &ProtectedJournalAuthority<'_>,
    purpose: &[u8],
    reservation_digest: ObjectDigest,
    maximum_completion_bytes: usize,
) -> Result<CompletionCapacityV1, ProviderLedgerError> {
    let transaction =
        completion_capacity_transaction(purpose, reservation_digest, maximum_completion_bytes)?;
    let preflight = journal.preflight_transactions(std::slice::from_ref(&transaction))?;
    Ok(CompletionCapacityV1::Preflight {
        preflight,
        transaction,
    })
}

fn completion_capacity_transaction(
    purpose: &[u8],
    reservation_digest: ObjectDigest,
    maximum_completion_bytes: usize,
) -> Result<JournalTransaction, ProviderLedgerError> {
    if maximum_completion_bytes == 0 || maximum_completion_bytes > MAXIMUM_TRANSACTION_BYTES {
        return Err(ProviderLedgerError::LimitExceeded(
            "completion capacity bytes",
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.source-provider.completion-capacity.v1\0");
    hasher.update((purpose.len() as u32).to_be_bytes());
    hasher.update(purpose);
    hasher.update(reservation_digest.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest[..16]);
    if id == [0; 16] {
        return Err(ProviderLedgerError::Corrupt(
            "zero completion-capacity identity",
        ));
    }
    let mut key = b"aos.source-provider.capacity.v1\0".to_vec();
    key.extend_from_slice(&digest);
    let transaction = JournalTransaction::new(
        id,
        vec![JournalRecord::put(
            RecordNamespace::SourceProviderAuthority,
            key,
            vec![0; maximum_completion_bytes],
        )],
    )?;
    Ok(transaction)
}

/// Confirms that no writer displaced the just-synced protected state.
pub(crate) fn confirm_current_after_commit(
    ledger: &ProviderLedgerV1<'_>,
) -> Result<(), ProviderLedgerError> {
    let committed = ledger.journal.snapshot()?;
    ledger
        .journal
        .validate_source_provider_authority_snapshot(&committed)?;
    Ok(())
}

pub(crate) fn confirm_current_session_after_commit(
    custody: &mut aos_sandbox_source_provider_security::CurrentProviderIngressSessionV1,
    expected_session_binding: ObjectDigest,
) -> Result<(), ProviderLedgerError> {
    let current = custody.current_projection()?;
    if current.session_binding() != expected_session_binding {
        return Err(ProviderLedgerError::Equivocation);
    }
    Ok(())
}

pub(crate) fn authorize_current_reservation(
    security_session: &mut aos_sandbox_source_provider_security::CurrentProviderIngressSessionV1,
    current: aos_sandbox_source_provider_security::CurrentProviderRequestV1,
    ledger: &ProviderLedgerV1<'_>,
    key: &AttemptKeyV1,
    attempt: &AttemptRecordV1,
    response_sequence: u64,
) -> Result<aos_sandbox_source_provider_security::ProviderOutcomeAuthorizationV1, ProviderLedgerError>
{
    let attempt_key = crate::format::attempt_key(key);
    let attempt_record = crate::format::encode_attempt(attempt);
    let snapshot = ledger.journal.snapshot()?;
    let authorization = security_session.authorize_reserved_request(
        current,
        &ledger.journal,
        snapshot,
        &attempt_key,
        &attempt_record,
        response_sequence,
    )?;
    Ok(authorization)
}

/// Reauthenticates the original at Requested before the native dispatch cut.
pub(crate) fn reauthorize_requested_native_reservation(
    ledger: &mut ProviderLedgerV1<'_>,
    permit: crate::DurableAcquireEffectPermitV1,
    original: &SignedSourceProviderRequestV1,
    current_catalog: (&[u8], &[u8]),
) -> Result<crate::DurableAcquireEffectPermitV1, ProviderLedgerError> {
    reauthorize_native_reservation(
        ledger,
        permit,
        original,
        current_catalog,
        crate::native_completion::NativeReplyPhase::Requested,
    )
}

/// Reauthenticates the original at the exact retained Prepared cut.
pub(crate) fn reauthorize_prepared_native_reservation(
    ledger: &mut ProviderLedgerV1<'_>,
    permit: crate::DurableAcquireEffectPermitV1,
    original: &SignedSourceProviderRequestV1,
    current_catalog: (&[u8], &[u8]),
) -> Result<crate::DurableAcquireEffectPermitV1, ProviderLedgerError> {
    reauthorize_native_reservation(
        ledger,
        permit,
        original,
        current_catalog,
        crate::native_completion::NativeReplyPhase::Prepared,
    )
}

fn reauthorize_native_reservation(
    ledger: &mut ProviderLedgerV1<'_>,
    permit: crate::DurableAcquireEffectPermitV1,
    original: &SignedSourceProviderRequestV1,
    current_catalog: (&[u8], &[u8]),
    phase: crate::native_completion::NativeReplyPhase,
) -> Result<crate::DurableAcquireEffectPermitV1, ProviderLedgerError> {
    let identity = crate::native_completion::NativeReplyIdentity::for_request(
        original,
        permit.completion_attempt_digest,
    )?;
    ledger.native_reply_custody.require_reserved(identity)?;
    let disposition = ledger.verify_and_admit_with_origin(
        original,
        &[],
        Some(current_catalog),
        None,
        Some(crate::native_completion::NativeReplyReauthentication { identity, phase }),
    )?;
    if !matches!(disposition, ProviderAdmissionDispositionV1::Recover(
        ProviderRecoveryWorkV1::ObserveApplying { acquisition_id, effect_id }
    ) if acquisition_id == permit.plan.acquisition_id() && effect_id == permit.plan.effect_id())
    {
        return Err(ProviderLedgerError::Equivocation);
    }
    let signing_authorization = ledger
        .recovery_authorizations
        .remove(&permit.completion_attempt_digest)
        .ok_or(ProviderLedgerError::Unavailable)?;
    Ok(crate::DurableAcquireEffectPermitV1 {
        plan: permit.plan,
        completion_session_binding: permit.completion_session_binding,
        completion_attempt_digest: permit.completion_attempt_digest,
        reservation_digest: permit.reservation_digest,
        journal_snapshot: ledger.journal.snapshot()?,
        completion_capacity: CompletionCapacityV1::NativeDispatch,
        signing_authorization,
    })
}

// A failed currentness check must keep custody installed so later recovery can
// still find the exact session, even when the session itself has been poisoned.
fn take_checked_completion_session<S>(
    sessions: &mut BTreeMap<[u8; 16], S>,
    holder_id: [u8; 16],
    check: impl FnOnce(&mut S) -> Result<bool, ProviderLedgerError>,
) -> Result<S, ProviderLedgerError> {
    let mut installed =
        sessions
            .remove(&holder_id)
            .ok_or(ProviderLedgerError::InvalidTransition(
                "missing current completion session",
            ))?;
    match check(&mut installed) {
        Ok(true) => Ok(installed),
        Ok(false) => {
            sessions.insert(holder_id, installed);
            Err(ProviderLedgerError::Equivocation)
        }
        Err(error) => {
            sessions.insert(holder_id, installed);
            Err(error)
        }
    }
}

#[cfg(test)]
mod completion_session_tests {
    use super::*;

    #[test]
    fn projection_failure_keeps_the_exact_installed_session() {
        let holder_id = [7; 16];
        let mut sessions = BTreeMap::from([(holder_id, 41_u64)]);

        let error = take_checked_completion_session(&mut sessions, holder_id, |installed| {
            *installed += 1;
            Err(ProviderLedgerError::Security(
                aos_sandbox_source_provider_security::SourceProviderSecurityError::Currentness,
            ))
        })
        .unwrap_err();

        assert!(matches!(
            error,
            ProviderLedgerError::Security(
                aos_sandbox_source_provider_security::SourceProviderSecurityError::Currentness
            )
        ));
        assert_eq!(sessions.get(&holder_id), Some(&42));
    }
}

impl ProviderLedgerV1<'_> {
    pub(crate) fn with_current_completion_session<R>(
        &mut self,
        holder_id: [u8; 16],
        expected_session_binding: ObjectDigest,
        complete: impl FnOnce(
            &mut Self,
            &mut aos_sandbox_source_provider_security::CurrentProviderIngressSessionV1,
        ) -> Result<R, ProviderLedgerError>,
    ) -> Result<R, ProviderLedgerError> {
        let mut installed =
            take_checked_completion_session(&mut self.current_sessions, holder_id, |installed| {
                let current = installed.session.current_projection()?;
                Ok(current.session_binding() == expected_session_binding)
            })?;
        let result = complete(self, &mut installed.session);
        self.current_sessions.insert(holder_id, installed);
        result
    }

    /// Authenticates and durably admits one provider request under owner-held state.
    ///
    /// This facade invokes protocol verification itself, cross-checks the sealed
    /// ingress projection against recovered protected heads, and consumes the
    /// verified request by value. No public API accepts an independently
    /// assembled verified request.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for authentication failure, current-head
    /// drift, replay equivocation, invalid transitions, limits, or sync failure.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_and_admit_request(
        &mut self,
        signed_request: &SignedSourceProviderRequestV1,
        descriptor_roles: &[SourceProviderDescriptorRole],
    ) -> Result<ProviderAdmissionDispositionV1, ProviderLedgerError> {
        self.verify_and_admit_request_with_catalog(signed_request, descriptor_roles, None)
    }

    pub(crate) fn verify_and_admit_request_with_catalog(
        &mut self,
        signed_request: &SignedSourceProviderRequestV1,
        descriptor_roles: &[SourceProviderDescriptorRole],
        current_catalog: Option<(&[u8], &[u8])>,
    ) -> Result<ProviderAdmissionDispositionV1, ProviderLedgerError> {
        self.verify_and_admit_with_origin(
            signed_request,
            descriptor_roles,
            current_catalog,
            None,
            None,
        )
    }

    pub(crate) fn verify_and_admit_original_packet(
        &mut self,
        packet: &crate::FixedProviderAuthenticatedSourceRequestV1,
        current_catalog: Option<(&[u8], &[u8])>,
    ) -> Result<ProviderAdmissionDispositionV1, ProviderLedgerError> {
        self.verify_and_admit_with_origin(packet.signed(), &[], current_catalog, Some(packet), None)
    }

    fn verify_and_admit_with_origin(
        &mut self,
        signed_request: &SignedSourceProviderRequestV1,
        descriptor_roles: &[SourceProviderDescriptorRole],
        current_catalog: Option<(&[u8], &[u8])>,
        original_packet: Option<&crate::FixedProviderAuthenticatedSourceRequestV1>,
        native_reauthentication: Option<crate::native_completion::NativeReplyReauthentication>,
    ) -> Result<ProviderAdmissionDispositionV1, ProviderLedgerError> {
        self.ensure_open()?;
        let original_native_packet = original_packet.is_some()
            && signed_request.method() == SourceProviderMethod::Acquire
            && decode_acquire_request(signed_request.subject()).is_ok_and(|request| {
                request.acquisition_version()
                    == aos_sandbox_source_provider_protocol::ACQUIRE_SOURCE_REQUEST_VERSION_V3
            });
        let expectation = request_sequence_expectation(self, signed_request)?;
        let holder_id = signed_request.signer().authority_id();
        let mut installed = self.current_sessions.remove(&holder_id).ok_or(
            ProviderLedgerError::InvalidTransition("no current security-branded holder session"),
        )?;
        let current =
            installed
                .session
                .verify_current_request(signed_request, expectation, descriptor_roles);
        let result = current
            .map_err(ProviderLedgerError::from)
            .and_then(|current| {
                let method = match current.verified() {
                    VerifiedProviderRequestV1::Acquire(_) => SourceProviderMethod::Acquire,
                    VerifiedProviderRequestV1::Release(_) => SourceProviderMethod::Release,
                    VerifiedProviderRequestV1::Inventory(_) => SourceProviderMethod::Inventory,
                };
                match method {
                    SourceProviderMethod::Acquire => crate::acquire::reserve_acquire(
                        self,
                        &mut installed.session,
                        current,
                        current_catalog,
                        original_packet,
                        native_reauthentication,
                    ),
                    SourceProviderMethod::Release => {
                        crate::release::reserve_release(self, &mut installed.session, current)
                    }
                    SourceProviderMethod::Inventory => {
                        crate::inventory::reserve_inventory(self, &mut installed.session, current)
                    }
                    SourceProviderMethod::Hello => Err(ProviderLedgerError::Equivocation),
                }
            });
        let admitted_original_native = result.is_ok() && original_native_packet;
        let result = match result {
            Ok(disposition) => match installed.session.current_projection() {
                Ok(projection)
                    if self
                        .recovered
                        .sessions
                        .get(&(projection.provider().authority_id(), holder_id))
                        .is_some_and(|session| {
                            session.session_binding == projection.session_binding()
                        }) =>
                {
                    installed.supersession = None;
                    Ok(disposition)
                }
                Ok(_) => Err(ProviderLedgerError::Equivocation),
                Err(error) => Err(error.into()),
            },
            Err(error) => Err(error),
        };
        if admitted_original_native && result.is_err() {
            // The final peer/session check follows reservation admission.
            // Preserve the occupied rows and original hot clock on failure.
            self.poison_runtime();
        }
        if !original_native_packet || !self.poisoned {
            self.current_sessions.insert(holder_id, installed);
        }
        result
    }
}

fn request_sequence_expectation(
    ledger: &ProviderLedgerV1<'_>,
    signed: &SignedSourceProviderRequestV1,
) -> Result<ProviderRequestSequenceExpectationV1, ProviderLedgerError> {
    request_sequence_expectation_at(&ledger.journal, &ledger.recovered, signed)
}

/// Shares exact replay/Fresh classification with original ingress observations.
pub(crate) fn request_sequence_expectation_at(
    journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
    recovered: &crate::model::RecoveredProviderLedgerV1,
    signed: &SignedSourceProviderRequestV1,
) -> Result<ProviderRequestSequenceExpectationV1, ProviderLedgerError> {
    let journal_snapshot = journal.snapshot()?;
    journal.validate_source_provider_authority_snapshot(&journal_snapshot)?;
    request_sequence_expectation_from_recovered_v5(recovered, signed)
}

/// Compares request sequence DATA after the caller authenticates its complete cut.
///
/// This pure projection supplies no snapshot, currentness or owner authority.
pub(crate) fn request_sequence_expectation_from_recovered_v5(
    recovered: &crate::model::RecoveredProviderLedgerV1,
    signed: &SignedSourceProviderRequestV1,
) -> Result<ProviderRequestSequenceExpectationV1, ProviderLedgerError> {
    let (session_binding, sequence, request_id) = match signed.method() {
        SourceProviderMethod::Acquire => {
            let request = decode_acquire_request(signed.subject())
                .map_err(|_| ProviderLedgerError::Equivocation)?;
            (
                request.session_binding(),
                request.sequence(),
                request.request_id(),
            )
        }
        SourceProviderMethod::Release => {
            let request = decode_release_request(signed.subject())
                .map_err(|_| ProviderLedgerError::Equivocation)?;
            (
                request.session_binding(),
                request.sequence(),
                request.request_id(),
            )
        }
        SourceProviderMethod::Inventory => {
            let request = decode_inventory_request(signed.subject())
                .map_err(|_| ProviderLedgerError::Equivocation)?;
            (
                request.session_binding(),
                request.sequence(),
                request.request_id(),
            )
        }
        SourceProviderMethod::Hello => return Err(ProviderLedgerError::Equivocation),
    };
    let identity = (
        recovered.authority.provider.authority_id(),
        signed.signer().authority_id(),
    );
    let signed_digest = digest_signed_request(signed);
    if let Some(retained) = recovered.attempts.values().find(|attempt| {
        attempt.provider.authority_id() == identity.0
            && attempt.holder.authority_id() == identity.1
            && attempt.method == signed.method()
            && attempt.request_id == request_id
    }) {
        if retained.signed_request_digest != signed_digest
            || retained.signed_request != signed.to_canonical_bytes()
        {
            // Request identity is holder-authority scoped, not signing-key
            // scoped. Rotation cannot create a second meaning for one ID.
            return Err(ProviderLedgerError::Equivocation);
        }
    }
    let session = recovered.sessions.get(&identity);
    let key = AttemptKeyV1 {
        provider_id: identity.0,
        holder_id: identity.1,
        root_record_key_id: signed.signer().key_id(),
        method: signed.method() as u8,
        request_id,
    };
    if let (Some(session), Some(attempt)) = (session, recovered.attempts.get(&key)) {
        return Ok(ProviderRequestSequenceExpectationV1::exact_replay(
            session_binding,
            attempt.request_sequence,
            request_id,
            signed_digest,
            session.next_request_sequence,
        )?);
    }
    let expected = session.map_or(1, |head| {
        if head.session_binding == session_binding {
            head.next_request_sequence
        } else {
            1
        }
    });
    if sequence != expected {
        return Err(ProviderLedgerError::Equivocation);
    }
    Ok(ProviderRequestSequenceExpectationV1::fresh(expected)?)
}

pub(crate) fn validate_projection(
    ledger: &ProviderLedgerV1<'_>,
    projection: &VerifiedProviderIngressProjectionV1,
) -> Result<Option<HolderSessionHeadRecordV1>, ProviderLedgerError> {
    let (existing, same_session) =
        projection_session_at(&ledger.configuration, &ledger.recovered, projection)?;
    if !same_session {
        if let Some(head) = &existing {
            let _ = validate_supersession(ledger, projection, head)?;
        }
    }
    Ok(existing)
}

/// Returns the unchanged current graph comparison without a supersession grant.
pub(crate) fn projection_session_at(
    configuration: &crate::state::ProtectedProviderConfigurationV1,
    recovered: &crate::model::RecoveredProviderLedgerV1,
    projection: &VerifiedProviderIngressProjectionV1,
) -> Result<(Option<HolderSessionHeadRecordV1>, bool), ProviderLedgerError> {
    let authority = &recovered.authority;
    if !configuration.matches_authority_and_catalog(authority, &recovered.catalog) {
        return Err(ProviderLedgerError::ConfigurationMismatch);
    }
    let root_writer = projection.actual_writer_root_mount_process();
    let current_matches = projection.provider_authority() == &authority.provider
        && projection.trust_generation() == authority.trust_generation
        && projection.trust_digest() == authority.trust_digest
        && projection.revocation_generation() == authority.revocation_generation
        && projection.revocation_digest() == authority.revocation_digest
        && projection.route_id() == authority.route_id
        && projection.route_generation() == authority.route_generation
        && projection.route_digest() == authority.route_digest
        && projection.resource_namespace_digest() == authority.resource_namespace_digest
        && projection.proof_class_capabilities() == authority.proof_class_capabilities
        && projection.supports_recursive() == authority.supports_recursive
        && projection.supports_kernel_coupled() == authority.supports_kernel_coupled
        && projection.ordered_signers()[2] == authority.provider_hello_signer
        && projection.ordered_signers()[3] == authority.provider_outcome_signer
        && projection.verified_at_seconds() >= authority.valid_from_seconds
        && projection.current_valid_until_seconds() <= authority.valid_until_seconds
        && projection.current_valid_until_seconds() > projection.verified_at_seconds()
        && root_writer.pidfd_live();
    if !current_matches {
        return Err(ProviderLedgerError::ConfigurationMismatch);
    }
    let identity = (
        projection.provider_authority().authority_id(),
        projection.root_mount_authority().authority_id(),
    );
    let existing = recovered.sessions.get(&identity).cloned();
    let reused_history = recovered
        .session_history
        .keys()
        .any(|(_, _, binding)| *binding == projection.session_binding())
        && existing
            .as_ref()
            .is_none_or(|current| current.session_binding != projection.session_binding());
    if reused_history {
        return Err(ProviderLedgerError::Equivocation);
    }
    let same_session = if let Some(head) = &existing {
        head.provider == *projection.provider_authority()
            && head.holder == *projection.root_mount_authority()
            && head.session_binding == projection.session_binding()
            && head.boot_id
                == projection
                    .signed_provider_hello()
                    .subject()
                    .kernel_boot_id()
            && head.root_process_instance == projection.root_mount_process_instance()
            && head.provider_process_instance == projection.provider_process_instance()
            && head.root_writer.uid == root_writer.uid()
            && head.root_writer.gid == root_writer.gid()
            && head.root_writer.tgid == root_writer.tgid()
            && head.root_writer.start_time_ticks == root_writer.start_time_ticks()
            && head.root_writer.cgroup_digest == root_writer.cgroup_digest()
            && head.route_id == projection.route_id()
            && head.route_generation == projection.route_generation()
            && head.route_digest == projection.route_digest()
            && head.resource_namespace_digest == projection.resource_namespace_digest()
            && head.trust_generation == projection.trust_generation()
            && head.trust_digest == projection.trust_digest()
            && head.revocation_generation == projection.revocation_generation()
            && head.revocation_digest == projection.revocation_digest()
            && head.signer_set_commitment == projection.signer_set_commitment()
            && head.signers == *projection.ordered_signers()
            && head.root_hello_digest == projection.root_mount_hello_digest()
            && head.provider_hello_digest == projection.provider_hello_digest()
            && head.root_hello == projection.signed_root_mount_hello().to_canonical_bytes()
            && head.provider_hello == projection.signed_provider_hello().to_canonical_bytes()
    } else {
        true
    };
    Ok((existing, same_session))
}

pub(crate) fn validate_session_capacity(
    ledger: &ProviderLedgerV1<'_>,
    existing: &Option<HolderSessionHeadRecordV1>,
    projection: &VerifiedProviderIngressProjectionV1,
) -> Result<(), ProviderLedgerError> {
    validate_session_capacity_at(&ledger.configuration, &ledger.recovered, existing, projection)
}

/// Reuses the unchanged session-count policy under the genuine original owner.
///
/// # Errors
///
/// Rejects exhausted current-holder or retained-session identity limits.
pub(crate) fn validate_session_capacity_at(
    configuration: &crate::state::ProtectedProviderConfigurationV1,
    recovered: &crate::model::RecoveredProviderLedgerV1,
    existing: &Option<HolderSessionHeadRecordV1>,
    projection: &VerifiedProviderIngressProjectionV1,
) -> Result<(), ProviderLedgerError> {
    if existing.is_none()
        && recovered.sessions.len() >= configuration.limits().maximum_holders()
    {
        return Err(ProviderLedgerError::LimitExceeded("holder sessions"));
    }
    let creates_history = existing
        .as_ref()
        .is_none_or(|session| session.session_binding != projection.session_binding());
    if creates_history
        && recovered.session_history.len()
            >= configuration.limits().maximum_retained_identities()
    {
        return Err(ProviderLedgerError::LimitExceeded(
            "retained session identities",
        ));
    }
    Ok(())
}

pub(crate) fn new_session_from_projection(
    projection: &VerifiedProviderIngressProjectionV1,
    provider_execution_identity: (u32, u64),
    previous: Option<&HolderSessionHeadRecordV1>,
    supersession_evidence_digest: Option<ObjectDigest>,
    next_request_sequence: u64,
) -> Result<HolderSessionHeadRecordV1, ProviderLedgerError> {
    let writer = projection.actual_writer_root_mount_process();
    let (
        revision,
        session_generation,
        predecessor_session_binding,
        request_sequence_floor,
        response_sequence_floor,
        acquisition_sequence_floor,
        next_acquisition_sequence,
    ) = match previous {
        Some(previous) => (
            previous
                .revision
                .checked_add(1)
                .ok_or(ProviderLedgerError::InvalidTransition(
                    "session revision exhausted",
                ))?,
            previous.session_generation.checked_add(1).ok_or(
                ProviderLedgerError::InvalidTransition("session generation exhausted"),
            )?,
            Some(previous.session_binding),
            1,
            1,
            previous.acquisition_sequence_floor,
            previous.next_acquisition_sequence,
        ),
        None => (1, 1, None, 1, 1, 1, 1),
    };
    if predecessor_session_binding.is_some() != supersession_evidence_digest.is_some() {
        return Err(ProviderLedgerError::InvalidTransition(
            "session replacement evidence shape",
        ));
    }
    Ok(HolderSessionHeadRecordV1 {
        revision,
        session_generation,
        provider: projection.provider_authority().clone(),
        holder: projection.root_mount_authority().clone(),
        session_binding: projection.session_binding(),
        predecessor_session_binding,
        supersession_evidence_digest,
        boot_id: projection
            .signed_provider_hello()
            .subject()
            .kernel_boot_id(),
        root_process_instance: projection.root_mount_process_instance(),
        provider_process_instance: projection.provider_process_instance(),
        provider_process_id: provider_execution_identity.0,
        provider_start_time_ticks: provider_execution_identity.1,
        provider_execution_commitment:
            aos_sandbox_source_provider_protocol::provider_execution_commitment_v1(
                projection
                    .signed_provider_hello()
                    .subject()
                    .kernel_boot_id(),
                provider_execution_identity.0,
                provider_execution_identity.1,
                projection.provider_process_instance(),
            ),
        root_writer: WriterIdentityV1 {
            uid: writer.uid(),
            gid: writer.gid(),
            tgid: writer.tgid(),
            start_time_ticks: writer.start_time_ticks(),
            cgroup_digest: writer.cgroup_digest(),
        },
        route_id: projection.route_id(),
        route_generation: projection.route_generation(),
        route_digest: projection.route_digest(),
        resource_namespace_digest: projection.resource_namespace_digest(),
        trust_generation: projection.trust_generation(),
        trust_digest: projection.trust_digest(),
        revocation_generation: projection.revocation_generation(),
        revocation_digest: projection.revocation_digest(),
        signers: projection.ordered_signers().clone(),
        signer_set_commitment: projection.signer_set_commitment(),
        request_sequence_floor,
        response_sequence_floor,
        acquisition_sequence_floor,
        next_acquisition_sequence,
        next_request_sequence,
        next_response_sequence: 1,
        pending_attempt_digest: None,
        last_completed_attempt_digest: None,
        root_hello_digest: projection.root_mount_hello_digest(),
        provider_hello_digest: projection.provider_hello_digest(),
        root_hello: projection.signed_root_mount_hello().to_canonical_bytes(),
        provider_hello: projection.signed_provider_hello().to_canonical_bytes(),
    })
}

pub(crate) fn prepare_session(
    ledger: &ProviderLedgerV1<'_>,
    projection: &VerifiedProviderIngressProjectionV1,
    provider_execution_identity: (u32, u64),
    existing: Option<HolderSessionHeadRecordV1>,
    first_request_sequence: u64,
) -> Result<(HolderSessionHeadRecordV1, bool), ProviderLedgerError> {
    match existing {
        Some(existing) if existing.session_binding == projection.session_binding() => {
            prepare_original_session(
                projection, provider_execution_identity, Some(existing), first_request_sequence,
            )
        }
        Some(existing) => {
            let digest = validate_supersession(ledger, projection, &existing)?;
            let session = new_session_from_projection(
                projection,
                provider_execution_identity,
                Some(&existing),
                Some(digest),
                first_request_sequence,
            )?;
            Ok((session, true))
        }
        None => prepare_original_session(
            projection, provider_execution_identity, None, first_request_sequence,
        ),
    }
}

/// Reuses genuine same-Session or absence preparation without supersession.
///
/// # Errors
///
/// Rejects a different Session, execution identity or invalid new-session data.
pub(crate) fn prepare_original_session(
    projection: &VerifiedProviderIngressProjectionV1,
    provider_execution_identity: (u32, u64),
    existing: Option<HolderSessionHeadRecordV1>,
    first_request_sequence: u64,
) -> Result<(HolderSessionHeadRecordV1, bool), ProviderLedgerError> {
    match existing {
        Some(existing) => {
            if existing.session_binding != projection.session_binding()
                || (
                    existing.provider_process_id,
                    existing.provider_start_time_ticks,
                ) != provider_execution_identity
            {
                return Err(ProviderLedgerError::Equivocation);
            }
            Ok((existing, false))
        }
        None => Ok((
            new_session_from_projection(
                projection,
                provider_execution_identity,
                None,
                None,
                first_request_sequence,
            )?,
            true,
        )),
    }
}

fn validate_supersession(
    ledger: &ProviderLedgerV1<'_>,
    projection: &VerifiedProviderIngressProjectionV1,
    previous: &HolderSessionHeadRecordV1,
) -> Result<ObjectDigest, ProviderLedgerError> {
    let installed = ledger
        .current_sessions
        .get(&projection.root_mount_authority().authority_id())
        .ok_or(ProviderLedgerError::InvalidTransition(
            "replacement session is not runtime-owned",
        ))?;
    if let Some(death) = &installed.recovered_execution_death {
        if !death.matches(
            previous.boot_id,
            previous.provider_process_id,
            previous.provider_start_time_ticks,
            previous.provider_process_instance,
        ) {
            return Err(ProviderLedgerError::Equivocation);
        }
        return Ok(recovery_death_supersession_digest(previous, projection));
    }
    if previous.pending_attempt_digest.is_some() {
        return Err(ProviderLedgerError::InvalidTransition(
            "pending session replacement requires opaque execution death",
        ));
    }
    if let Ok(fence) = ledger
        .configuration
        .exact_session_revocation_fence(previous)
    {
        return fence.consume_for(previous);
    }
    let evidence =
        installed
            .supersession
            .as_ref()
            .ok_or(ProviderLedgerError::InvalidTransition(
                "session replacement requires supersession evidence",
            ))?;
    if evidence.provider_id() != projection.provider_authority().authority_id()
        || evidence.holder_id() != projection.root_mount_authority().authority_id()
        || evidence.prior_session_binding() != previous.session_binding
        || evidence.replacement_session_binding() != projection.session_binding()
        || evidence.prior_root_process_instance() != previous.root_process_instance
    {
        return Err(ProviderLedgerError::Equivocation);
    }
    supersession_evidence_digest(evidence)
}

fn recovery_death_supersession_digest(
    previous: &HolderSessionHeadRecordV1,
    projection: &VerifiedProviderIngressProjectionV1,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.source-provider.session-recovery-death.v1\0");
    hasher.update(previous.provider.authority_id());
    hasher.update(previous.holder.authority_id());
    hasher.update(previous.session_binding.as_bytes());
    hasher.update(projection.session_binding().as_bytes());
    hasher.update(previous.boot_id);
    hasher.update(previous.provider_process_id.to_be_bytes());
    hasher.update(previous.provider_start_time_ticks.to_be_bytes());
    hasher.update(previous.provider_process_instance);
    hasher.update(previous.provider_execution_commitment.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn supersession_evidence_digest(
    evidence: &ProviderSessionSupersessionEvidenceV1,
) -> Result<ObjectDigest, ProviderLedgerError> {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.source-provider.session-supersession.v1\0");
    hasher.update(evidence.provider_id());
    hasher.update(evidence.holder_id());
    hasher.update(evidence.prior_session_binding().as_bytes());
    hasher.update(evidence.replacement_session_binding().as_bytes());
    hasher.update(evidence.prior_root_process_instance());
    let digest: [u8; 32] = hasher.finalize().into();
    if digest == [0; 32] {
        return Err(ProviderLedgerError::Corrupt(
            "zero session supersession digest",
        ));
    }
    Ok(ObjectDigest::from_bytes(digest))
}

pub(crate) fn classify_attempt(
    ledger: &ProviderLedgerV1<'_>,
    key: &AttemptKeyV1,
    attempt_digest: ObjectDigest,
    signed_request_digest: ObjectDigest,
    typed_request_digest: ObjectDigest,
    signed_request: &[u8],
) -> Result<Option<ProviderAdmissionDispositionV1>, ProviderLedgerError> {
    let Some(existing) = ledger.recovered.attempts.get(key) else {
        return Ok(None);
    };
    if existing.attempt_digest != attempt_digest
        || existing.signed_request_digest != signed_request_digest
        || existing.typed_request_digest != typed_request_digest
        || (!existing.signed_request.is_empty() && existing.signed_request != signed_request)
    {
        return Err(ProviderLedgerError::Equivocation);
    }
    let current_session = ledger.recovered.sessions.get(&(
        existing.provider.authority_id(),
        existing.holder.authority_id(),
    ));
    if current_session.is_none_or(|session| session.session_binding != existing.session_binding) {
        return Err(ProviderLedgerError::InvalidTransition(
            "dead or superseded session replay",
        ));
    }
    match existing.state {
        ProviderAttemptStateV1::Reserved => match existing.method {
            SourceProviderMethod::Acquire => {
                let direct = ledger
                    .recovered
                    .acquisitions
                    .values()
                    .find(|record| record.current_attempt_digest == attempt_digest);
                let work = if let Some(record) = direct {
                    ProviderRecoveryWorkV1::ObserveApplying {
                        acquisition_id: record.acquisition_id,
                        effect_id: record.effect_id,
                    }
                } else {
                    let record = ledger
                        .recovered
                        .acquisitions
                        .values()
                        .find(|record| {
                            record.state == crate::ProviderAcquisitionStateV1::Active
                                && record.provider == existing.provider
                                && record.holder == existing.holder
                                && record.normalized_intent.digest()
                                    == existing.operation_intent_digest
                        })
                        .ok_or(ProviderLedgerError::Corrupt(
                            "reserved Acquire has no effect or rebind lineage",
                        ))?;
                    ProviderRecoveryWorkV1::ObserveAcquireRebind {
                        acquisition_id: record.acquisition_id,
                        attempt_digest,
                    }
                };
                Ok(Some(ProviderAdmissionDispositionV1::Recover(work)))
            }
            SourceProviderMethod::Release => Ok(Some(ProviderAdmissionDispositionV1::Recover(
                ProviderRecoveryWorkV1::ObserveReleasing {
                    acquisition_id: ledger
                        .recovered
                        .releases
                        .values()
                        .find(|record| record.attempt_digest == attempt_digest)
                        .ok_or(ProviderLedgerError::Corrupt(
                            "reserved release without intent",
                        ))?
                        .acquisition_id,
                    effect_id: ledger
                        .recovered
                        .releases
                        .values()
                        .find(|record| record.attempt_digest == attempt_digest)
                        .ok_or(ProviderLedgerError::Corrupt(
                            "reserved release without effect",
                        ))?
                        .effect_id,
                },
            ))),
            SourceProviderMethod::Inventory => Ok(Some(ProviderAdmissionDispositionV1::Recover(
                ProviderRecoveryWorkV1::ObserveInventoryReservation { attempt_digest },
            ))),
            SourceProviderMethod::Hello => {
                Err(ProviderLedgerError::Corrupt("retained Hello attempt"))
            }
        },
        ProviderAttemptStateV1::Completed
            if existing.method == SourceProviderMethod::Acquire
                && existing.status
                    == Some(
                        aos_sandbox_source_provider_protocol::SourceProviderStatus::Complete,
                    ) =>
        {
            let response = decode_acquire_response(&existing.completed_response)
                .map_err(|_| ProviderLedgerError::Corrupt("cached Acquire response"))?;
            let acquisition_id = response
                .signed_receipt()
                .and_then(|bytes| {
                    aos_sandbox_source_provider_protocol::SignedSourceProviderReceiptV1::from_canonical_bytes(bytes).ok()
                })
                .map(|receipt| receipt.subject().acquisition_id())
                .ok_or(ProviderLedgerError::Corrupt("cached Acquire receipt"))?;
            let active = ledger.recovered.acquisitions.values().any(|record| {
                record.acquisition_id == acquisition_id
                    && record.state == crate::ProviderAcquisitionStateV1::Active
            });
            if !active {
                return Err(ProviderLedgerError::InvalidTransition(
                    "Acquire replay source is not active",
                ));
            }
            let acquisition = ledger.recovered.acquisitions.values().find(|row| row.acquisition_id == acquisition_id)
                .ok_or(ProviderLedgerError::Unavailable)?;
            validate_native_complete_export_v1(
                acquisition, ledger.recovered.native_completions.get(&acquisition_id), existing,
            ).map_err(map_pure_ledger_error)?;
            Ok(Some(ProviderAdmissionDispositionV1::AcquireReplay(
                DurableAcquireReplayV1 {
                    acquisition_id,
                    attempt_key: attempt_key(key),
                    response: existing.completed_response.clone(),
                    journal_snapshot: ledger.journal.snapshot()?,
                },
            )))
        }
        ProviderAttemptStateV1::Completed
            if existing.method == SourceProviderMethod::Release
                && matches!(
                    existing.status,
                    Some(
                        aos_sandbox_source_provider_protocol::SourceProviderStatus::Pending
                            | aos_sandbox_source_provider_protocol::SourceProviderStatus::Unavailable
                    )
                ) =>
        {
            let release = ledger
                .recovered
                .releases
                .values()
                .find(|record| record.attempt_digest == existing.attempt_digest)
                .ok_or(ProviderLedgerError::Corrupt(
                    "nonterminal Release response has no intent",
                ))?;
            Ok(Some(ProviderAdmissionDispositionV1::CachedRecovery {
                cached: DurableCachedResponseV1 {
                    attempt_key: attempt_key(key),
                    bytes: existing.completed_response.clone(),
                    journal_snapshot: ledger.journal.snapshot()?,
                },
                work: ProviderRecoveryWorkV1::ObserveReleasing {
                    acquisition_id: release.acquisition_id,
                    effect_id: release.effect_id,
                },
            }))
        }
        ProviderAttemptStateV1::Completed => Ok(Some(ProviderAdmissionDispositionV1::Cached(
            DurableCachedResponseV1 {
                attempt_key: attempt_key(key),
                bytes: existing.completed_response.clone(),
                journal_snapshot: ledger.journal.snapshot()?,
            },
        ))),
        ProviderAttemptStateV1::Retired => Err(ProviderLedgerError::InvalidTransition(
            "retired or dead-session replay",
        )),
    }
}

/// Forms initial Applying DATA without performing admission or journal effects.
///
/// The ordinary path preserves zero selection sentinels when no resource is
/// selected; the genuine original path supplies its retained selected resource.
pub(crate) fn reserved_acquisition(
    projection: &VerifiedProviderIngressProjectionV1,
    request: &AcquireSourceRequestV1,
    attempt: &AttemptRecordV1,
    catalog: &CatalogHeadRecordV1,
    plan: &crate::backend::AcquirePlanV1,
    normalized_intent: NormalizedAcquisitionIntentV1,
    selected_resource: Option<&SourceResourceV1>,
) -> AcquisitionRecordV1 {
    let zero_digest = ObjectDigest::from_bytes([0; 32]);

    AcquisitionRecordV1 {
        revision: 1,
        state: ProviderAcquisitionStateV1::Applying,
        provider: projection.provider_authority().clone(),
        holder: projection.root_mount_authority().clone(),
        acquisition_id: request.acquisition_id(),
        acquisition_sequence: request.acquisition_sequence(),
        effect_id: plan.effect_id(),
        normalized_intent,
        effect_attempt_digest: attempt.attempt_digest,
        current_attempt_digest: attempt.attempt_digest,

        lease_attempt_digest: None,
        lease_issue_generation: 0,
        lease_id: None,
        lease_digest: None,
        lease_history: Vec::new(),

        resource_namespace_digest: projection.resource_namespace_digest(),
        resource_id: selected_resource.map_or([0; 32], SourceResourceV1::resource_id),
        resource_generation: selected_resource.map_or(0, SourceResourceV1::resource_generation),
        resource_digest: selected_resource.map_or(zero_digest, SourceResourceV1::resource_digest),
        catalog_generation: catalog.catalog_generation,
        catalog_digest: catalog.catalog_digest,
        selection_generation: selected_resource.map_or(0, SourceResourceV1::selection_generation),
        selection_digest: selected_resource.map_or(zero_digest, SourceResourceV1::selection_digest),

        proof_class: 0,
        proof_digest: zero_digest,
        resource_commitment: zero_digest,
        backend_id: plan.backend_id(),
        backend_lineage_digest: plan.lineage_digest(),
        native_no_dispatch_reservation_digest: None,
        backend_evidence: None,
        reopen_identity: None,
        source_root: None,
        release_effect_id: None,
        signed_lease: Vec::new(),
    }
}

/// Forms Acquire attempt DATA through the existing Reserved-attempt constructor.
pub(crate) fn reserved_acquire_attempt(
    verified: &aos_sandbox_source_provider_protocol::VerifiedProviderAcquireRequestV1,
    root_record_signer: aos_sandbox_source_provider_protocol::SourceProviderSigningKeyV1,
    normalized_intent: &NormalizedAcquisitionIntentV1,
    recovery_bridge: Option<&crate::recovery_bridge::RecoveryBridgeLinkV1>,
) -> AttemptRecordV1 {
    let projection = verified.ingress_projection();
    let request = verified.request();
    let evidence = verified.attempt();

    reserved_attempt(
        projection.provider_authority().clone(),
        projection.root_mount_authority().clone(),
        root_record_signer,
        SourceProviderMethod::Acquire,
        evidence.request_id(),
        evidence.signed_request_digest(),
        aos_sandbox_source_provider_protocol::digest_acquire_request(request),
        normalized_intent.digest(),
        request.acquisition_sequence(),
        evidence.attempt_digest(),
        projection.session_binding(),
        request.sequence(),
        request.deadline_seconds(),
        projection.verified_at_seconds(),
        projection.current_valid_until_seconds(),
        projection.proof_class_capabilities(),
        projection.supports_recursive(),
        projection.supports_kernel_coupled(),
        projection.root_mount_process_instance(),
        projection.provider_process_instance(),
        projection.signer_set_commitment(),
        recovery_bridge,
        evidence.canonical_signed_request().to_vec(),
    )
}

pub(crate) fn reserved_attempt(
    provider: aos_sandbox_source_provider_protocol::SourceProviderAuthorityV1,
    holder: aos_sandbox_source_provider_protocol::SourceProviderAuthorityV1,
    root_record_signer: aos_sandbox_source_provider_protocol::SourceProviderSigningKeyV1,
    method: SourceProviderMethod,
    request_id: [u8; 16],
    signed_request_digest: ObjectDigest,
    typed_request_digest: ObjectDigest,
    operation_intent_digest: ObjectDigest,
    acquisition_sequence: u64,
    attempt_digest: ObjectDigest,
    session_binding: ObjectDigest,
    request_sequence: u64,
    deadline_seconds: i64,
    verified_at_seconds: i64,
    current_valid_until_seconds: i64,
    proof_class_capabilities: u8,
    supports_recursive: bool,
    supports_kernel_coupled: bool,
    root_process_instance: [u8; 16],
    provider_process_instance: [u8; 16],
    signer_set_commitment: ObjectDigest,
    recovery_bridge: Option<&crate::recovery_bridge::RecoveryBridgeLinkV1>,
    signed_request: Vec<u8>,
) -> AttemptRecordV1 {
    AttemptRecordV1 {
        revision: 1,
        state: ProviderAttemptStateV1::Reserved,
        provider,
        holder,
        root_record_signer,
        method,
        status: None,
        request_id,
        signed_request_digest,
        typed_request_digest,
        operation_intent_digest,
        acquisition_sequence,
        attempt_digest,
        session_binding,
        request_sequence,
        response_sequence: None,
        deadline_seconds,
        verified_at_seconds,
        completed_at_seconds: None,
        current_valid_until_seconds,
        proof_class_capabilities,
        supports_recursive,
        supports_kernel_coupled,
        root_process_instance,
        provider_process_instance,
        signer_set_commitment,
        recovery_predecessor_attempt_digest: recovery_bridge.map(|value| value.old_attempt_digest),
        recovery_predecessor_session_binding: recovery_bridge
            .map(|value| value.old_session_binding),
        recovery_fence_digest: recovery_bridge.map(|value| value.fence_digest),
        recovery_fence_class: recovery_bridge.map_or(0, |value| value.fence_class),
        recovery_revocation_generation: recovery_bridge
            .map_or(0, |value| value.revocation_generation),
        recovery_revocation_digest: recovery_bridge
            .map_or(ObjectDigest::from_bytes([0; 32]), |value| {
                value.revocation_digest
            }),
        signed_request_digest_again: signed_request_digest,
        response_digest: None,
        descriptor_commitment: ObjectDigest::from_bytes([0; 32]),
        result_digest: None,
        response_catalog_generation: 0,
        response_catalog_digest: ObjectDigest::from_bytes([0; 32]),
        signed_request,
        completed_response: Vec::new(),
    }
}

pub(crate) fn reserve_session(
    mut session: HolderSessionHeadRecordV1,
    next_request_sequence: u64,
    attempt_digest: ObjectDigest,
) -> Result<HolderSessionHeadRecordV1, ProviderLedgerError> {
    if session.pending_attempt_digest.is_some()
        || session.next_request_sequence.checked_add(1) != Some(next_request_sequence)
        || next_request_sequence == u64::MAX
    {
        return Err(ProviderLedgerError::InvalidTransition(
            "session request sequence",
        ));
    }
    session.revision =
        session
            .revision
            .checked_add(1)
            .ok_or(ProviderLedgerError::InvalidTransition(
                "session revision exhausted",
            ))?;
    session.next_request_sequence = next_request_sequence;
    session.pending_attempt_digest = Some(attempt_digest);
    Ok(session)
}

pub(crate) fn commit_records(
    ledger: &mut ProviderLedgerV1<'_>,
    purpose: &[u8],
    records: Vec<(Vec<u8>, Vec<u8>)>,
) -> Result<ObjectDigest, ProviderLedgerError> {
    commit_mutations_validated(
        ledger,
        purpose,
        records
            .into_iter()
            .map(|(key, value)| (key, Some(value)))
            .collect(),
        None,
    )
}

pub(crate) fn commit_mutations_with_configuration(
    ledger: &mut ProviderLedgerV1<'_>,
    purpose: &[u8],
    records: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    configuration: &crate::ProtectedProviderConfigurationV1,
) -> Result<ObjectDigest, ProviderLedgerError> {
    commit_mutations_validated(ledger, purpose, records, Some(configuration))
}

pub(crate) fn commit_mutations(
    ledger: &mut ProviderLedgerV1<'_>,
    purpose: &[u8],
    records: Vec<(Vec<u8>, Option<Vec<u8>>)>,
) -> Result<ObjectDigest, ProviderLedgerError> {
    commit_mutations_validated(ledger, purpose, records, None)
}

fn commit_mutations_validated(
    ledger: &mut ProviderLedgerV1<'_>,
    purpose: &[u8],
    records: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    validation_configuration: Option<&crate::ProtectedProviderConfigurationV1>,
) -> Result<ObjectDigest, ProviderLedgerError> {
    let prepared = prepare_mutations_validated(ledger, purpose, records, validation_configuration)?;
    crate::native_no_dispatch_capacity::validate_set(
        &ledger.journal,
        &prepared.prospective_recovered,
    )?;
    let preflight = match ledger
        .journal
        .preflight_transactions(std::slice::from_ref(&prepared.transaction))
    {
        Ok(preflight) => preflight,
        Err(error) => {
            ledger.poison_runtime();
            return Err(error.into());
        }
    };
    if let Err(error) = ledger
        .journal
        .validate_preflight_for_effect(&preflight, std::slice::from_ref(&prepared.transaction))
    {
        ledger.poison_runtime();
        return Err(error.into());
    }
    if let Err(error) = ledger.journal.commit(&prepared.transaction) {
        ledger.poison_runtime();
        return Err(error.into());
    }
    let effective_configuration = validation_configuration.unwrap_or(&ledger.configuration);
    if let Err(error) =
        crate::recovery::recover_capacity_checked(&ledger.journal, effective_configuration)
    {
        ledger.poison_runtime();
        return Err(error);
    }
    Ok(prepared.digest)
}

pub(crate) fn prepare_mutations_validated(
    ledger: &ProviderLedgerV1<'_>,
    purpose: &[u8],
    records: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    validation_configuration: Option<&crate::ProtectedProviderConfigurationV1>,
) -> Result<PreparedLedgerMutationV1, ProviderLedgerError> {
    prepare_mutations_with_shape(
        ledger,
        purpose,
        records,
        validation_configuration,
        MutationShapeV1::Ordinary,
    )
}

// The only seven-owner-row exception validates the exact native Release CAS.
// The selector is private; no public count/capability or generic purpose alias
// can widen ordinary transactions.
pub(crate) fn prepare_native_release_admission(
    ledger: &ProviderLedgerV1<'_>,
    records: Vec<(Vec<u8>, Option<Vec<u8>>)>,
) -> Result<PreparedLedgerMutationV1, ProviderLedgerError> {
    prepare_mutations_with_shape(
        ledger,
        b"reserve-native-release-fence-v1",
        records,
        None,
        MutationShapeV1::NativeReleaseFence,
    )
}

fn prepare_mutations_with_shape(
    ledger: &ProviderLedgerV1<'_>,
    purpose: &[u8],
    mut records: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    validation_configuration: Option<&crate::ProtectedProviderConfigurationV1>,
    shape: MutationShapeV1,
) -> Result<PreparedLedgerMutationV1, ProviderLedgerError> {
    if purpose.is_empty() || purpose.len() > 128 {
        return Err(ProviderLedgerError::LimitExceeded(
            "transaction purpose bytes",
        ));
    }
    synchronize_session_history_mutations(&mut records)?;
    let native_release_fence = matches!(shape, MutationShapeV1::NativeReleaseFence);
    let maximum_records = if native_release_fence {
        7
    } else {
        MAXIMUM_TRANSACTION_RECORDS
    };
    if records.is_empty() || records.len() > maximum_records {
        return Err(ProviderLedgerError::LimitExceeded(
            "transaction record count",
        ));
    }
    let total_bytes = records.iter().try_fold(0_usize, |total, (key, value)| {
        total
            .checked_add(key.len())?
            .checked_add(value.as_ref().map_or(0, Vec::len))
    });
    if total_bytes.is_none_or(|bytes| bytes > MAXIMUM_TRANSACTION_BYTES) {
        return Err(ProviderLedgerError::LimitExceeded("transaction bytes"));
    }
    if native_release_fence
        && total_bytes
            .and_then(|bytes| bytes.checked_add(9 * records.len()))
            .is_none_or(|bytes| {
                bytes > crate::ledger::format::MAXIMUM_NATIVE_RELEASE_ADMISSION_OWNER_BYTES_V1
            })
    {
        return Err(ProviderLedgerError::LimitExceeded(
            "native Release admission bytes",
        ));
    }
    for (key, value) in &records {
        if let Some(value) = value {
            let decoded = decode_record(key, value)?;
            if encode_decoded_record(&decoded) != *value {
                return Err(ProviderLedgerError::Corrupt(
                    "proposed record is not canonical for its exact key",
                ));
            }
        }
    }
    ledger.journal.validate_source_provider_authority()?;
    let current =
        aos_sandbox_source_provider_ledger::collect_bounded_records(ledger.journal.records()?)
            .map_err(map_pure_ledger_error)?;
    let mut prospective = current.clone();
    for (key, value) in &records {
        match value {
            Some(value) => {
                prospective.insert(key.clone(), value.clone());
            }
            None => {
                prospective.remove(key);
            }
        }
    }
    if native_release_fence {
        validate_native_release_admission_v1(&current, &prospective)
            .map_err(map_pure_ledger_error)?;
    }
    aos_sandbox_source_provider_ledger::validate_prospective_transition(
        current
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
        prospective
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
    )
    .map_err(|error| match error {
        aos_sandbox_source_provider_ledger::LedgerFormatErrorV1::Corrupt(message) => {
            ProviderLedgerError::Corrupt(message)
        }
        aos_sandbox_source_provider_ledger::LedgerFormatErrorV1::LimitExceeded(message) => {
            ProviderLedgerError::LimitExceeded(message)
        }
        aos_sandbox_source_provider_ledger::LedgerFormatErrorV1::NeedsProvenance(message) => {
            ProviderLedgerError::MigrationNeedsProvenance(message)
        }
    })?;
    let prospective_recovered = crate::recovery::recover_records(
        prospective
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
        validation_configuration.unwrap_or(&ledger.configuration),
    )?;
    let (transaction_id, digest) = canonical_owner_transaction_id(purpose, &records)?;
    let journal_records = records
        .into_iter()
        .map(|(key, value)| match value {
            Some(value) => JournalRecord::put(RecordNamespace::SourceProviderAuthority, key, value),
            None => JournalRecord::delete(RecordNamespace::SourceProviderAuthority, key),
        })
        .collect();
    let transaction = JournalTransaction::new(transaction_id, journal_records)?;
    Ok(PreparedLedgerMutationV1 {
        transaction,
        digest: ObjectDigest::from_bytes(digest),
        prospective_recovered,
    })
}

/// Reuses the canonical owner-transaction identity without granting a mutation.
///
/// # Errors
///
/// Rejects an invalid purpose, canonical record digest or zero transaction ID.
pub(crate) fn canonical_owner_transaction_id(
    purpose: &[u8],
    records: &[(Vec<u8>, Option<Vec<u8>>)],
) -> Result<([u8; 16], [u8; 32]), ProviderLedgerError> {
    if purpose.is_empty() || purpose.len() > 128 {
        return Err(ProviderLedgerError::LimitExceeded("transaction purpose bytes"));
    }
    let mut hasher = Sha256::new();
    hasher.update(TRANSACTION_ID_DOMAIN);
    hasher.update((purpose.len() as u32).to_be_bytes());
    hasher.update(purpose);
    for (key, value) in records {
        hasher.update((key.len() as u32).to_be_bytes());
        hasher.update(key);
        match value {
            Some(value) => {
                hasher.update([1]);
                hasher.update(record_digest(value)?.as_bytes());
            }
            None => {
                hasher.update([0]);
                hasher.update([0; 32]);
            }
        }
    }
    let digest: [u8; 32] = hasher.finalize().into();
    let mut transaction_id = [0_u8; 16];
    transaction_id.copy_from_slice(&digest[..16]);
    if transaction_id == [0; 16] {
        return Err(ProviderLedgerError::Corrupt("zero transaction identity"));
    }
    Ok((transaction_id, digest))
}

fn synchronize_session_history_mutations(
    records: &mut Vec<(Vec<u8>, Option<Vec<u8>>)>,
) -> Result<(), ProviderLedgerError> {
    let mut derived = Vec::new();
    for (record_key, value) in records.iter() {
        let Some(value) = value else {
            continue;
        };
        let DecodedRecordV1::Session(session) = decode_record(record_key, value)? else {
            continue;
        };
        let key = session_history_key(
            session.provider.authority_id(),
            session.holder.authority_id(),
            session.session_binding,
        );
        let value = encode_session_history(&session);
        derived.push((key, Some(value)));
    }
    for (key, value) in derived {
        match records.iter().find(|(candidate, _)| candidate == &key) {
            Some((_, existing)) if existing != &value => {
                return Err(ProviderLedgerError::Corrupt(
                    "session/history mutation mismatch",
                ));
            }
            Some(_) => {}
            None => records.push((key, value)),
        }
    }
    Ok(())
}
