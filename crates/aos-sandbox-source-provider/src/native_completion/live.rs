//! Fixed live Storage origin joined to the existing sealed Acquire completion.
//!
//! Requested precedes dispatch, Prepared precedes the separate challenge spend,
//! and the existing completion builder commits all six owner rows atomically.
//! There is deliberately no Provider Spent append: Prepared plus the exact
//! spent challenge is the recoverable cross-journal cut. The cleanup reserve
//! survives Active. Historical-session recovery and native retirement remain
//! unavailable rather than being mistaken for loss of every original FD.

use std::sync::Arc;

use aos_sandbox_source_provider_protocol::{
    SignedSourceProviderRequestV1, SourceProviderDescriptorRole, SourceProviderProofV1,
    StorageNativeAcquireVerificationV3, StorageZfsHoldReceiptV1,
};
use aos_sandbox_source_provider_security::ReceivedStorageNativeAcquireV3;

use super::*;
use crate::backend_verifier::ProtectedBackendVerifierV1;
use crate::zfs_hold_challenge::{ProtectedZfsHoldChallengesV1, current_seconds};
use crate::zfs_hold_verifier::ProtectedStorageZfsHoldVerifierV1;
use crate::{
    BackendEvidenceClassV1, BackendEvidenceV1, DurableAcquireEffectPermitV1,
    DurableProviderReplyV1, ReopenIdentityV1, SourceProviderBackendV1,
};

/// Keeps live endpoint origin and the exact spent-challenge completion together.
///
/// Only this module constructs the token, after receiving the original FD from
/// the fixed Storage service and joining both protected journals. A verified
/// signed bundle alone cannot construct it.
pub(crate) struct NativeAcquireLiveObservationV3 {
    active: NativeAcquireCompletionRecordV2,
    origin: ReceivedStorageNativeAcquireV3,
    manifest: ProtectedStorageZfsHoldVerifierV1,
    clock: Arc<NativeAcquireClockGuardV1>,
}

impl core::fmt::Debug for NativeAcquireLiveObservationV3 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("NativeAcquireLiveObservationV3([protected origin])")
    }
}

impl NativeAcquireLiveObservationV3 {
    pub(crate) fn reply_identity(&self) -> NativeReplyIdentity {
        NativeReplyIdentity {
            acquisition: self.active.acquisition_id,
            attempt: self.active.attempt_digest,
            session: self.active.session_binding,
            signed_request: self.active.root_request_digest,
        }
    }

    pub(crate) fn revalidate(
        &self,
        descriptor: &aos_sandbox_source_provider_protocol::SourceRootObservationV1,
    ) -> Result<(), ProviderLedgerError> {
        self.origin
            .revalidate()
            .map_err(|_| ProviderLedgerError::Unavailable)?;
        self.manifest.revalidate()?;
        self.clock
            .revalidate(Some(self.origin.reply().receipt().receipt().validity().1))?;
        let now = current_seconds()?;
        let (issued, expires) = self.origin.reply().receipt().receipt().validity();
        if self.origin.reply().acceptance().acceptance().descriptor() != descriptor
            || self.origin.reply().receipt().digest() != self.active.receipt_digest
            || now < issued
            || now < self.active.challenge_issued_seconds
            || now >= expires
            || now >= self.active.challenge_valid_until_seconds
        {
            return Err(ProviderLedgerError::Unavailable);
        }
        Ok(())
    }

    pub(crate) fn completion_record(
        &self,
        ledger: &ProviderLedgerV1<'_>,
        permit: &DurableAcquireEffectPermitV1,
    ) -> Result<NativeAcquireCompletionRecordV2, ProviderLedgerError> {
        if ledger.qualified_native_bridge.is_none()
            || self.active.state != NativeAcquireCompletionStateV2::Active
            || self.active.acquisition_id != permit.plan.acquisition_id()
            || self.active.attempt_digest != permit.completion_attempt_digest
            || self.active.session_binding != permit.completion_session_binding
        {
            return Err(ProviderLedgerError::Unavailable);
        }
        let current = ledger
            .recovered
            .native_completions
            .get(&self.active.acquisition_id)
            .ok_or(ProviderLedgerError::Unavailable)?;
        let acquisition = ledger
            .recovered
            .acquisitions
            .values()
            .find(|row| row.acquisition_id == current.acquisition_id)
            .ok_or(ProviderLedgerError::Unavailable)?;
        crate::ledger::native_completion::validate_native_export_open_v1(
            acquisition,
            Some(current),
        )
        .map_err(crate::transaction::map_pure_ledger_error)?;
        if current.state != NativeAcquireCompletionStateV2::Prepared {
            return Err(ProviderLedgerError::Equivocation);
        }
        current
            .validate_successor(&self.active)
            .map_err(crate::transaction::map_pure_ledger_error)?;
        Ok(self.active.clone())
    }
}

impl ProviderLedgerV1<'_> {
    /// Drives the private first-positive path under both retained owner writers.
    pub(crate) fn execute_native_acquire_v3(
        &mut self,
        challenges: &mut ProtectedZfsHoldChallengesV1,
        permit: DurableAcquireEffectPermitV1,
        original: &SignedSourceProviderRequestV1,
        current_catalog: (&[u8], &[u8]),
        backend: &mut impl SourceProviderBackendV1,
        backend_verifier: Arc<ProtectedBackendVerifierV1>,
    ) -> Result<DurableProviderReplyV1, ProviderLedgerError> {
        self.ensure_open()?;
        let identity =
            NativeReplyIdentity::for_request(original, permit.completion_attempt_digest)?;
        self.native_reply_custody.require_reserved(identity)?;
        let (permit, requested, capacity) =
            self.prepare_native_acquire_request_v2(challenges, permit, original, current_catalog)?;
        let signed = requested
            .canonical_request
            .as_ref()
            .ok_or(ProviderLedgerError::Unavailable)?;
        let clock = Arc::clone(
            &self
                .native_acquire_custody
                .get(&requested.acquisition_id)
                .ok_or(ProviderLedgerError::Unavailable)?
                .clock,
        );
        let manifest = ProtectedStorageZfsHoldVerifierV1::load(backend_verifier)?;
        capacity.require_before_dispatch(self)?;
        clock.require_request(signed)?;

        // An ambiguous send leaves Requested intact. It is not no-dispatch
        // absence and cannot use that identity's settlement or a new nonce.
        let mut received = backend
            .exchange_storage_native_acquire_v2(signed)?
            .ok_or(ProviderLedgerError::Unavailable)?;
        received
            .revalidate()
            .map_err(|_| ProviderLedgerError::Unavailable)?;
        let descriptor = received
            .take_original_descriptor()
            .map_err(|_| ProviderLedgerError::Unavailable)?;
        let mut physical = permit.plan().observe_source_root(descriptor)?;
        let reply = received.reply().clone();
        clock.revalidate(Some(reply.receipt().receipt().validity().1))?;
        let catalog = signed.request().claims().catalog();
        let (resource, snapshot) = catalog
            .select_under_head(
                self.recovered.catalog.catalog_generation,
                self.recovered.catalog.catalog_digest,
                self.recovered.authority.resource_namespace_digest,
                requested.binding_digest,
            )
            .map_err(|_| ProviderLedgerError::Equivocation)?;

        // The protected selection supplies resource and held lineage; only the
        // fixed live owner exchange supplies this fresh Storage cut/readback.
        // Unrelated later Storage writes need not keep its global head current.
        let receipt = reply.receipt().receipt();
        let expected = StorageZfsHoldReceiptV1::new(
            requested.challenge,
            requested.attempt_digest,
            requested.binding_digest,
            resource.clone(),
            snapshot.clone(),
            receipt.head(),
            receipt.validity().0,
            receipt.validity().1,
        )
        .map_err(|_| ProviderLedgerError::Unavailable)?;
        let provider_signer = signed.signer();
        let root_signer = original.signer();
        if provider_signer != &self.recovered.authority.provider_outcome_signer {
            return Err(ProviderLedgerError::Unavailable);
        }
        let provider_key = self
            .configuration
            .currently_eligible_public_key_for(provider_signer)
            .ok_or(ProviderLedgerError::Unavailable)?;
        let root_key = self
            .configuration
            .currently_eligible_public_key_for(root_signer)
            .ok_or(ProviderLedgerError::Unavailable)?;
        let verified = reply
            .verify_for(StorageNativeAcquireVerificationV3 {
                request: signed,
                provider_signer,
                provider_key,
                root_signer,
                root_key,
                storage_verifier: manifest.protocol_verifier()?,
                expected_receipt: &expected,
                observed_descriptor: physical.observation(),
                descriptor_roles: &[SourceProviderDescriptorRole::SourceRoot],
                now_seconds: current_seconds()?,
            })
            .map_err(|_| ProviderLedgerError::Unavailable)?;
        physical.bind_native_acceptance(&verified)?;
        manifest.revalidate()?;
        received
            .revalidate()
            .map_err(|_| ProviderLedgerError::Unavailable)?;
        // Keep our own copy before the Prepared write. A later send/currentness
        // failure leaves real original custody here even if Storage dies. This
        // first-positive slice still requires live Storage origin to complete;
        // unavailability is neither total FD loss nor cleanup authority.
        self.native_acquire_custody
            .get_mut(&requested.acquisition_id)
            .ok_or(ProviderLedgerError::Unavailable)?
            .source_root = Some(physical.retain_original()?);
        clock.revalidate(Some(reply.receipt().receipt().validity().1))?;

        let prepared = match requested.state {
            NativeAcquireCompletionStateV2::Requested => requested
                .prepare_accepted(reply.clone(), &verified)
                .map_err(crate::transaction::map_pure_ledger_error)?,
            NativeAcquireCompletionStateV2::Prepared => {
                requested
                    .validate_verified_acceptance(signed, &verified)
                    .map_err(crate::transaction::map_pure_ledger_error)?;
                if requested.accepted_reply.as_ref() != Some(&reply) {
                    return Err(ProviderLedgerError::Equivocation);
                }
                requested.clone()
            }
            _ => return Err(ProviderLedgerError::Unavailable),
        };
        if prepared != requested {
            self.commit_retained_native_record(b"retain-native-acceptance", &prepared)?;
        }

        // The Provider write invalidated the former authorization. Authenticate
        // the same Root bytes again before any atomic completion is prepared.
        let permit = crate::transaction::reauthorize_prepared_native_reservation(
            self,
            permit,
            original,
            current_catalog,
        )?;
        clock.revalidate(Some(reply.receipt().receipt().validity().1))?;
        let issued = challenges.retained_for(prepared.challenge)?;
        require_exact_challenge(&prepared, issued)?;
        challenges.spend(issued, prepared.receipt_digest)?;
        let spent = challenges.retained_for(prepared.challenge)?;
        require_exact_challenge(&prepared, spent)?;
        if spent.spent_receipt() != Some(prepared.receipt_digest) {
            return Err(ProviderLedgerError::Equivocation);
        }
        let active = prepared
            .advance(NativeAcquireCompletionStateV2::Active)
            .map_err(crate::transaction::map_pure_ledger_error)?;
        let signer = reply.receipt().signer();
        let (authority_id, authority_generation, authority_digest) = signer.authority();
        let evidence = BackendEvidenceV1::new_acquired(
            BackendEvidenceClassV1::ZfsHeldSnapshot,
            authority_id,
            authority_generation,
            authority_digest,
            receipt.head().journal().0,
            reply.receipt().digest(),
            Vec::new(),
        )
        .map_err(|_| ProviderLedgerError::BackendConflict)?;
        let reopen = ReopenIdentityV1::new(
            BackendEvidenceClassV1::ZfsHeldSnapshot,
            permit.plan.backend_id(),
            authority_generation,
            authority_digest,
            resource.resource_id(),
            resource.resource_generation(),
            resource.resource_digest(),
            snapshot.storage_handle(),
            snapshot.storage_version(),
            snapshot.active_hold_digest(),
        )
        .map_err(|_| ProviderLedgerError::BackendConflict)?;
        let proof = SourceProviderProofV1::ZfsHeldSnapshot {
            proof: snapshot,
            topology: verified.topology().clone(),
        };
        let mut observed = permit.plan.seal_observed_acquisition(
            physical,
            resource,
            proof,
            evidence,
            reopen,
            permit.plan.backend_id(),
        )?;
        observed.native = Some(NativeAcquireLiveObservationV3 {
            active,
            origin: received,
            manifest,
            clock,
        });
        // Retain the entire original before even the final session lookup:
        // no validation or completion failure may drop its live endpoint.
        self.native_reply_custody.retain_observed(observed);
        let result = self.with_current_completion_session(
            permit.plan.holder_id(),
            permit.completion_session_binding,
            |ledger, custody| crate::acquire::complete_retained_native(ledger, permit, custody),
        );
        if result.is_err() {
            self.poison_runtime();
        }
        result
    }
}
