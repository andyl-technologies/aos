//! Ordered outcome signatures for the SAME original phase-3 Source owner.
//!
//! The reservoir retains preparation, signature, clock and failure results.
//! Neither its empty construction nor its borrowed DATA accessors grant an
//! operation. Every crypto crossing borrows the genuine Session, Root carrier,
//! verified request, same protected writer/readback and observed mount owner.

use super::*;
use aos_sandbox::journal::{
    OriginalSourceProtectedReadbackV5, SourceOriginalNativeJournalAuthorityV5,
};
use aos_sandbox_core::{ObjectDigest, RawPairedClockSample};
use aos_sandbox_source_provider_protocol::{
    PreparedSourceExportLeaseDataV5, PreparedSourceProviderReceiptDataV5,
    PreparedSourceProviderStatusDataV5, SourceProviderSignatureError,
    digest_acquire_request, digest_provider_proof, source_root_descriptor_commitment_v1,
};
use ed25519_dalek::Signer as _;

#[derive(thiserror::Error)]
enum OriginalCompletionCauseV5 {
    #[error("original completion custody failed")]
    Security(#[from] SourceProviderSecurityError),
    #[error("original completion protected readback failed")]
    Journal(#[from] aos_sandbox::JournalError),
    #[error("original completion canonical signature preparation failed")]
    Signature(#[from] SourceProviderSignatureError),
    #[error("original completion paired clock failed")]
    Clock(#[from] aos_sandbox_core::OwnershipLeaseVerificationError),
}

impl core::fmt::Debug for OriginalCompletionCauseV5 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("OriginalCompletionCauseV5([retained cause])")
    }
}

/// Retains the three fixed original signatures without send or extraction authority.
///
/// Only genuine Session methods can advance this reservoir. Its empty state is
/// nonauthorizing; errors permanently close it and preserve the first cause.
pub struct OriginalProviderCompletionSignaturesV5 {
    next: u8,
    initial: RawPairedClockSample,
    deadline: u64,
    validity: (i64, i64),
    lease_preparation: Option<Result<PreparedSourceExportLeaseDataV5, SourceProviderSignatureError>>,
    receipt_preparation: Option<Result<PreparedSourceProviderReceiptDataV5, SourceProviderSignatureError>>,
    status_preparation: Option<Result<PreparedSourceProviderStatusDataV5, SourceProviderSignatureError>>,
    detached: [Option<[u8; 64]>; 3],
    lease: Option<SignedSourceExportLeaseV1>,
    receipt: Option<SignedSourceProviderReceiptV1>,
    status: Option<SignedSourceProviderStatusV1>,
    response: Option<Result<Vec<u8>, SourceProviderSecurityError>>,
    samples: [Option<Result<RawPairedClockSample, SourceProviderSecurityError>>; 6],
    cause: Option<OriginalCompletionCauseV5>,
}

impl OriginalProviderCompletionSignaturesV5 {
    /// Creates empty retention with comparison DATA from the original upper guard.
    ///
    /// These copied values cannot admit a request, renew a deadline, select a
    /// writer or signer, or bypass any genuine-owner validation.
    #[must_use]
    pub fn pending_original(
        initial: RawPairedClockSample,
        deadline: u64,
        validity: (i64, i64),
    ) -> Self {
        Self {
            next: 0,
            initial,
            deadline,
            validity,
            lease_preparation: None,
            receipt_preparation: None,
            status_preparation: None,
            detached: [None; 3],
            lease: None,
            receipt: None,
            status: None,
            response: None,
            samples: std::array::from_fn(|_| None),
            cause: None,
        }
    }

    /// Borrows the original first typed cause, including parked preparation errors.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(cause) = &self.cause {
            return Some(cause);
        }
        if let Some(Err(cause)) = &self.lease_preparation {
            return Some(cause);
        }
        if let Some(Err(cause)) = &self.receipt_preparation {
            return Some(cause);
        }
        if let Some(Err(cause)) = &self.status_preparation {
            return Some(cause);
        }
        if let Some(Err(cause)) = &self.response {
            return Some(cause);
        }
        self.samples.iter().find_map(|sample| sample.as_ref()?.as_ref().err().map(|cause| cause as _))
    }

    /// Borrows signed DATA; this does not authorize a wire handoff.
    #[must_use]
    pub fn signed_lease(&self) -> Option<&SignedSourceExportLeaseV1> {
        self.lease.as_ref()
    }

    /// Borrows the fully retained response DATA without granting a send.
    #[must_use]
    pub fn response(&self) -> Option<&[u8]> {
        self.response.as_ref()?.as_ref().ok().map(Vec::as_slice)
    }

    /// Returns the actual final signing sample, not a fresh currentness observation.
    #[must_use]
    pub fn completed_at_seconds(&self) -> Option<i64> {
        self.samples[4].as_ref()?.as_ref().ok().map(|sample| sample.wall_seconds())
    }

    fn check_clock(&mut self, index: usize) -> Result<(), OriginalCompletionCauseV5> {
        self.samples[index] = Some(super::super::original_kernel_clock());
        let Some(Ok(later)) = &self.samples[index] else {
            return Err(SourceProviderSecurityError::SessionContinuity.into());
        };
        self.initial.validate_later_sample(*later)?;
        let lease_validity = self.lease.as_ref().map(|lease| lease.subject().validity())
            .or_else(|| self.lease_preparation.as_ref()?.as_ref().ok().map(|prepared| prepared.subject().validity()))
            .unwrap_or(self.validity);
        if later.wall_seconds() < self.validity.0.max(lease_validity.0)
            || later.wall_seconds() >= self.validity.1.min(lease_validity.1)
            || later.boottime_nanoseconds() >= self.deadline
        {
            return Err(SourceProviderSecurityError::SessionContinuity.into());
        }
        Ok(())
    }

    fn begin(&mut self, expected: u8) -> Result<(), OriginalCompletionCauseV5> {
        let previous = std::mem::replace(&mut self.next, u8::MAX);
        if previous != expected || self.failure().is_some() {
            return Err(SourceProviderSecurityError::SessionContinuity.into());
        }
        Ok(())
    }
}

impl CurrentProviderIngressSessionV1 {
    fn require_original_completion_bindings_v5(
        &mut self,
        journal: &SourceOriginalNativeJournalAuthorityV5<'_, '_>,
        readback: &OriginalSourceProtectedReadbackV5,
        root: &CurrentRootPreparedCarrierV1,
        acquire: &CurrentProviderRequestV1,
        physical: &crate::ProviderSourceRootHandoffV1,
        signatures: &OriginalProviderCompletionSignaturesV5,
    ) -> Result<(), OriginalCompletionCauseV5> {
        self.revalidate_root_prepared_carrier_v1(root)?;
        self.revalidate()?;
        physical.revalidate()?;
        let aos_sandbox_source_provider_protocol::VerifiedProviderRequestV1::Acquire(verified)
            = acquire.verified() else {
            return Err(SourceProviderSecurityError::SessionContinuity.into());
        };
        let request = verified.request();
        let projection = verified.ingress_projection();
        let peer = self.current_projection()?;
        let origin = journal.original_completion_signing_basis_v5(readback, request.acquisition_id())?;
        let provenance = origin.initial_floor().original_provenance().claims();
        let key = aos_sandbox_source_provider_ledger::ledger::native_completion::native_completion_key_v2(request.acquisition_id());
        let bytes = readback.rows().get(&(aos_sandbox::RecordNamespace::SourceProviderAuthority, key.clone()))
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let native = aos_sandbox_source_provider_ledger::ledger::native_held_completion::SourceNativeHeldCompletionRecordV1::from_canonical_bytes(&key, bytes)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        let signed = native.original().canonical_request.as_ref()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let acceptance = physical.native_acceptance().ok_or(SourceProviderSecurityError::DescriptorObservation)?;
        let anchor = native.original().original_clock.ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let accepted_reply = native.original().accepted_reply.as_ref().ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let receipt_validity = accepted_reply.receipt().receipt().validity();
        let execution = self.custody.inner().execution().baseline();
        if request.acquisition_version() != aos_sandbox_source_provider_protocol::ACQUIRE_SOURCE_REQUEST_VERSION_V3
            || request.kernel_coupled()
            || !matches!(verified.sequence(), aos_sandbox_source_provider_protocol::VerifiedProviderRequestSequenceV1::Fresh(_))
            || peer.provider() != projection.provider_authority()
            || peer.holder() != projection.root_mount_authority()
            || peer.session_binding() != projection.session_binding()
            || peer.root_process_instance() != projection.root_mount_process_instance()
            || peer.provider_process_instance() != projection.provider_process_instance()
            || acquire.provider_execution_identity() != (execution.pid, execution.start_time_ticks)
            || root.control() != &provenance.root_prepared
            || signed.request().claims() != &provenance.claims
            || signed.request().signed_root_request().to_canonical_bytes() != verified.attempt().canonical_signed_request()
            || signed.request().signed_root_request().signer() != self.custody.inner().root_authority().traffic_signer()
            || native.original().acceptance_payload_digest != acceptance.acceptance_payload_digest()
            || native.original().acceptance_digest != acceptance.signed_acceptance_digest()
            || signatures.initial != anchor.initial()
            || signatures.deadline > anchor.deadline()
            || signatures.deadline <= signatures.initial.boottime_nanoseconds()
            || signatures.validity.0 < provenance.claims.validity().0.max(receipt_validity.0)
            || signatures.validity.1 > provenance.claims.validity().1.min(receipt_validity.1)
            || signatures.validity.1 > projection.current_valid_until_seconds()
            || signatures.validity.1 > request.deadline_seconds()
            || signatures.validity.0 >= signatures.validity.1
        {
            return Err(SourceProviderSecurityError::SessionContinuity.into());
        }
        let (resource, snapshot) = signed.request().claims().catalog().select_under_head(
            signed.request().claims().catalog().generation(),
            signed.request().claims().catalog().digest(),
            signed.request().claims().catalog().namespace_digest(),
            request.binding_digest(),
        ).map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        let lease = signatures.lease.as_ref().map(|lease| lease.subject())
            .or_else(|| signatures.lease_preparation.as_ref()?.as_ref().ok().map(|prepared| prepared.subject()))
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let expected_proof = aos_sandbox_source_provider_protocol::SourceProviderProofV1::ZfsHeldSnapshot {
            proof: snapshot, topology: acceptance.topology().clone(),
        };
        if lease.resource() != &resource || lease.proof() != &expected_proof
            || lease.holder_commitments() != (request.binding_digest(), request.execution_bindings().2)
            || lease.validity().1 > signatures.validity.1
        {
            return Err(SourceProviderSecurityError::SessionContinuity.into());
        }

        // Use the existing catalog signature/current projection engine. The
        // retained complete row is not accepted merely because its own hashes
        // agree with the native request.
        use aos_sandbox_source_provider_ledger::ledger::model::DecodedRecordV1;
        let mut catalog = None;
        for ((namespace, key), value) in readback.rows() {
            if *namespace == aos_sandbox::RecordNamespace::SourceProviderAuthority
                && let Ok(DecodedRecordV1::Catalog(value)) = aos_sandbox_source_provider_ledger::ledger::format::decode_record(key, value)
                && catalog.replace(value).is_some()
            {
                return Err(SourceProviderSecurityError::SessionContinuity.into());
            }
        }
        let catalog = catalog.ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let configuration = self.revalidated_provider_configuration()?;
        let publication = crate::verify_catalog_publication(&configuration, &catalog.canonical_publication)?;
        let current = crate::catalog::current_catalog_projection(&catalog);
        let original_catalog = request.native_catalog().ok_or(SourceProviderSecurityError::SessionContinuity)?;
        use sha2::Digest as _;
        let publication_digest = ObjectDigest::from_bytes(sha2::Sha256::digest(&catalog.canonical_publication).into());
        if !crate::catalog::publication_matches_catalog(&publication, &catalog)
            || original_catalog.head() != current.catalog_head()
            || original_catalog.floor() != current.floor()
            || original_catalog.resource_namespace_digest() != current.scope().1
            || original_catalog.current_head_commitment() != current.head_commitment()
            || original_catalog.canonical_publication_digest() != publication_digest
            || provenance.claims.selection().1 != current.head_commitment()
        {
            return Err(SourceProviderSecurityError::SessionContinuity.into());
        }
        let decode = |key: &[u8]| readback.rows().get(&(
            aos_sandbox::RecordNamespace::SourceProviderAuthority, key.to_vec(),
        )).and_then(|bytes| aos_sandbox_source_provider_ledger::ledger::format::decode_record(key, bytes).ok());
        let witness = &provenance.records;
        let Some(DecodedRecordV1::Attempt(attempt)) = decode(witness[0].key()) else {
            return Err(SourceProviderSecurityError::SessionContinuity.into());
        };
        let Some(DecodedRecordV1::Acquisition(acquisition)) = decode(witness[1].key()) else {
            return Err(SourceProviderSecurityError::SessionContinuity.into());
        };
        let authority_key = aos_sandbox_source_provider_ledger::ledger::format::authority_key(
            acquisition.provider.authority_id(),
        );
        let Some(DecodedRecordV1::Authority(authority)) = decode(&authority_key) else {
            return Err(SourceProviderSecurityError::SessionContinuity.into());
        };
        let generation = authority.last_lease_issue_generation.checked_add(1)
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let expected_id = aos_sandbox_source_provider_ledger::identity::lease_id_v1(
            acquisition.acquisition_id,
            generation,
            acquisition.backend_id,
        ).ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let expected_expiry = lease.validity().0
            .checked_add(acquisition.normalized_intent.requested_lease_seconds() as i64)
            .ok_or(SourceProviderSecurityError::SessionContinuity)?
            .min(attempt.deadline_seconds)
            .min(attempt.current_valid_until_seconds)
            .min(provenance.claims.validity().1)
            .min(receipt_validity.1);
        if lease.lease_id() != expected_id
            || lease.validity().0 < attempt.verified_at_seconds
            || lease.validity().1 != expected_expiry
        {
            return Err(SourceProviderSecurityError::SessionContinuity.into());
        }
        storage_native::require_native_reserved_rows(
            &acquisition, &attempt,
            storage_native::NativeSigningScope {
                provider: projection.provider_authority(), holder: projection.root_mount_authority(),
                attempt: verified.attempt().attempt_digest(), session: projection.session_binding(),
                intent: origin.admission_comparison().original().normalized_intent_digest,
            }, signed.request(), &resource,
        )?;
        self.custody.inner().provider_authority().validate_at(current_unix_seconds()?)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        self.custody.inner().root_authority().validate_at(current_unix_seconds()?)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        Ok(())
    }

    fn end_original_completion_crossing_v5(
        &mut self,
        signatures: &mut OriginalProviderCompletionSignaturesV5,
        result: Result<(), OriginalCompletionCauseV5>,
        next: u8,
    ) -> bool {
        match result {
            Ok(()) => {
                signatures.next = next;
                true
            }
            Err(cause) => {
                if signatures.failure().is_none() {
                    signatures.cause = Some(cause);
                }
                signatures.next = u8::MAX;
                poison_and_close(
                    &mut self.custody,
                    &mut self.carrier,
                    SourceProviderSecurityError::SessionContinuity,
                );
                false
            }
        }
    }

    /// Signs the original lease once after fixed preparation and genuine current cuts.
    ///
    /// The boolean reports progress only; the caller retains this reservoir and
    /// its typed cause. No wire or floor authority is produced.
    #[doc(hidden)]
    pub fn sign_original_completion_lease_v5(
        &mut self,
        journal: &SourceOriginalNativeJournalAuthorityV5<'_, '_>,
        readback: &OriginalSourceProtectedReadbackV5,
        root: &CurrentRootPreparedCarrierV1,
        acquire: &CurrentProviderRequestV1,
        physical: &crate::ProviderSourceRootHandoffV1,
        lease: SourceExportLeaseV1,
        signatures: &mut OriginalProviderCompletionSignaturesV5,
    ) -> bool {
        let result = (|| {
            signatures.begin(0)?;
            let inner = self.custody.inner();
            signatures.lease_preparation = Some(PreparedSourceExportLeaseDataV5::prepare(
                lease, inner.provider_authority().traffic_signer().clone(),
                &inner.outcome_key().signing_key().verifying_key().to_bytes(),
            ));
            let Some(Ok(prepared)) = &signatures.lease_preparation else {
                return Err(SourceProviderSecurityError::SessionContinuity.into());
            };
            let aos_sandbox_source_provider_protocol::VerifiedProviderRequestV1::Acquire(verified) = acquire.verified() else {
                return Err(SourceProviderSecurityError::SessionContinuity.into());
            };
            let lease = prepared.subject();
            if lease.request_identity() != (verified.request().request_id(), digest_acquire_request(verified.request()))
                || lease.provider() != verified.ingress_projection().provider_authority()
                || lease.holder_authority() != verified.request().holder_authority()
                || lease.validity().1 > signatures.validity.1
            {
                return Err(SourceProviderSecurityError::SessionContinuity.into());
            }
            self.require_original_completion_bindings_v5(journal, readback, root, acquire, physical, signatures)?;
            journal.claim_original_completion_lease_v5(readback, verified.request().acquisition_id())?;
            signatures.check_clock(0)?;
            let Some(Ok(prepared)) = &signatures.lease_preparation else {
                return Err(SourceProviderSecurityError::SessionContinuity.into());
            };
            signatures.detached[0] = Some(self.custody.inner().outcome_key().signing_key().sign(prepared.signing_message()).to_bytes());
            if let (Some(Ok(prepared)), Some(raw)) = (signatures.lease_preparation.take(), signatures.detached[0]) {
                signatures.lease = Some(prepared.attach_signature(raw));
            }
            signatures.check_clock(1)?;
            self.require_original_completion_bindings_v5(journal, readback, root, acquire, physical, signatures)?;
            Ok(())
        })();
        self.end_original_completion_crossing_v5(signatures, result, 1)
    }

    /// Signs the original receipt once, retaining the original lease and mount.
    #[doc(hidden)]
    pub fn sign_original_completion_receipt_v5(
        &mut self,
        journal: &SourceOriginalNativeJournalAuthorityV5<'_, '_>,
        readback: &OriginalSourceProtectedReadbackV5,
        root: &CurrentRootPreparedCarrierV1,
        acquire: &CurrentProviderRequestV1,
        physical: &crate::ProviderSourceRootHandoffV1,
        signatures: &mut OriginalProviderCompletionSignaturesV5,
    ) -> bool {
        let result = (|| {
            signatures.begin(1)?;
            let aos_sandbox_source_provider_protocol::VerifiedProviderRequestV1::Acquire(verified) = acquire.verified() else {
                return Err(SourceProviderSecurityError::SessionContinuity.into());
            };
            let lease = signatures.lease.as_ref().ok_or(SourceProviderSecurityError::SessionContinuity)?;
            let observation = physical.observation();
            let receipt = SourceProviderReceiptV1::new(
                verified.request().request_id(), digest_acquire_request(verified.request()),
                verified.request().acquisition_id(), verified.ingress_projection().provider_process_instance(),
                digest_signed_export_lease(lease), lease.to_canonical_bytes(), SourceProviderDescriptorRole::SourceRoot,
                observation.kernel_boot_id(), observation.device(), observation.inode(), observation.unique_mount_id(),
                digest_provider_proof(lease.subject().proof()),
            ).map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
            let inner = self.custody.inner();
            signatures.receipt_preparation = Some(PreparedSourceProviderReceiptDataV5::prepare(
                receipt, inner.provider_authority().traffic_signer().clone(),
                &inner.outcome_key().signing_key().verifying_key().to_bytes(),
            ));
            if !matches!(signatures.receipt_preparation, Some(Ok(_))) {
                return Err(SourceProviderSecurityError::SessionContinuity.into());
            }
            self.require_original_completion_bindings_v5(journal, readback, root, acquire, physical, signatures)?;
            journal.claim_original_completion_receipt_v5(readback, verified.request().acquisition_id())?;
            signatures.check_clock(2)?;
            let Some(Ok(prepared)) = &signatures.receipt_preparation else {
                return Err(SourceProviderSecurityError::SessionContinuity.into());
            };
            signatures.detached[1] = Some(self.custody.inner().outcome_key().signing_key().sign(prepared.signing_message()).to_bytes());
            if let (Some(Ok(prepared)), Some(raw)) = (signatures.receipt_preparation.take(), signatures.detached[1]) {
                signatures.receipt = Some(prepared.attach_signature(raw));
            }
            signatures.check_clock(3)?;
            self.require_original_completion_bindings_v5(journal, readback, root, acquire, physical, signatures)?;
            Ok(())
        })();
        self.end_original_completion_crossing_v5(signatures, result, 2)
    }

    /// Signs the original status once; retained response bytes remain unsent DATA.
    #[doc(hidden)]
    pub fn sign_original_completion_status_v5(
        &mut self,
        journal: &SourceOriginalNativeJournalAuthorityV5<'_, '_>,
        readback: &OriginalSourceProtectedReadbackV5,
        root: &CurrentRootPreparedCarrierV1,
        acquire: &CurrentProviderRequestV1,
        physical: &crate::ProviderSourceRootHandoffV1,
        signatures: &mut OriginalProviderCompletionSignaturesV5,
    ) -> bool {
        let result = (|| {
            signatures.begin(2)?;
            let aos_sandbox_source_provider_protocol::VerifiedProviderRequestV1::Acquire(verified) = acquire.verified() else {
                return Err(SourceProviderSecurityError::SessionContinuity.into());
            };
            let projection = verified.ingress_projection();
            let session_key = aos_sandbox_source_provider_ledger::ledger::format::session_key(
                projection.provider_authority().authority_id(), projection.root_mount_authority().authority_id(),
            );
            let bytes = readback.rows().get(&(aos_sandbox::RecordNamespace::SourceProviderAuthority, session_key.clone()))
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            let aos_sandbox_source_provider_ledger::ledger::model::DecodedRecordV1::Session(session) =
                aos_sandbox_source_provider_ledger::ledger::format::decode_record(&session_key, bytes)
                    .map_err(|_| SourceProviderSecurityError::SessionContinuity)? else {
                return Err(SourceProviderSecurityError::SessionContinuity.into());
            };
            let artifact = signatures.receipt.as_ref().ok_or(SourceProviderSecurityError::SessionContinuity)?.to_canonical_bytes();
            let status = SourceProviderResponseStatusV1::new(
                SourceProviderMethod::Acquire, verified.request().request_id(), verified.attempt().signed_request_digest(),
                SourceProviderStatus::Complete, projection.provider_process_instance(), projection.session_binding(),
                session.next_response_sequence,
                response_result_digest_v1(SourceProviderMethod::Acquire, SourceProviderStatus::Complete, Some(&artifact)),
                source_root_descriptor_commitment_v1(physical.observation()),
            ).map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
            let inner = self.custody.inner();
            signatures.status_preparation = Some(PreparedSourceProviderStatusDataV5::prepare(
                status, inner.provider_authority().traffic_signer().clone(),
                &inner.outcome_key().signing_key().verifying_key().to_bytes(),
            ));
            if !matches!(signatures.status_preparation, Some(Ok(_))) {
                return Err(SourceProviderSecurityError::SessionContinuity.into());
            }
            self.require_original_completion_bindings_v5(journal, readback, root, acquire, physical, signatures)?;
            journal.claim_original_completion_status_v5(readback, verified.request().acquisition_id())?;
            signatures.check_clock(4)?;
            let Some(Ok(prepared)) = &signatures.status_preparation else {
                return Err(SourceProviderSecurityError::SessionContinuity.into());
            };
            signatures.detached[2] = Some(self.custody.inner().outcome_key().signing_key().sign(prepared.signing_message()).to_bytes());
            if let (Some(Ok(prepared)), Some(raw)) = (signatures.status_preparation.take(), signatures.detached[2]) {
                signatures.status = Some(prepared.attach_signature(raw));
            }
            signatures.check_clock(5)?;
            self.require_original_completion_bindings_v5(journal, readback, root, acquire, physical, signatures)?;
            let status = signatures.status.as_ref().ok_or(SourceProviderSecurityError::SessionContinuity)?.clone();
            signatures.response = Some(completion::encode_typed_response(SourceProviderMethod::Acquire, status, Some(artifact)));
            if signatures.response.as_ref().is_some_and(Result::is_err) {
                return Err(SourceProviderSecurityError::SessionContinuity.into());
            }
            Ok(())
        })();
        self.end_original_completion_crossing_v5(signatures, result, 3)
    }
}
