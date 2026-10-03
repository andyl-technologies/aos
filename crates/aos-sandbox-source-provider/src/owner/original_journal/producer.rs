//! Resident original Source producer and its protected pre-dispatch checkpoints.
//!
//! Only the already retained fresh Root1/Acquire pair can start this lane. The
//! actual Session, selected owner, first clock, challenge proposal and each
//! protected append remain owned by the fixed owner on error or unwind. Replay
//! and immutable request bytes cannot construct or resume this live producer.

use aos_sandbox::{JournalError, JournalRecord};
use aos_sandbox_source_provider_ledger::ledger::{
    LedgerFormatErrorV1,
    native_completion::{
        NativeAcquireCompletionRecordV2, OriginalSourceProvenanceClaimsV5,
        OriginalSourceProvenanceV5, native_completion_key_v2,
        propose_original_source_requested_v5,
    },
    native_held_completion::{
        SourceNativeHeldStepV1, propose_native_held_transition_v1,
    },
};
use aos_sandbox_source_provider_protocol::{
    ProviderCatalogManifestErrorV1, ProviderHeldSnapshotCatalogV1,
    SignedStorageNativeAcquireRequestV2, StorageNativeAcquireErrorV2,
    StorageNativeAcquireRequestV2, StorageZfsHoldTransportErrorV1,
    StorageZfsHoldTransportRequestV1, SourceProviderMethod,
    native_held_completion::{
        NativeHeldCompletionErrorV1, NativeHeldOwnerV1,
        SourceSelectedNativeExecutionInputDataV1,
        suffix::NativeHeldCompletionSuffixV1,
        witness::{
            NativeHeldByteWitnessV1, NativeHeldRecordFamilyV1,
            native_held_record_byte_digest_v1,
        },
    },
};
use aos_sandbox_source_provider_security::OriginalNativeSigningErrorV5;

use super::*;
use crate::{
    acquire::{derive_acquire_effect_id, enforce_acquire_limits_at, normalized_intent},
    format::{
        acquisition_key, attempt_key, encode_acquisition, encode_attempt, encode_session,
        encode_session_history, session_history_key, session_key,
    },
    model::{
        AcquisitionKeyV1, AttemptKeyV1, ProviderAuthorityStateV1,
    },
    transaction::{
        canonical_owner_transaction_id, prepare_original_session, projection_session_at,
        reserve_session, reserved_acquire_attempt,
    },
    zfs_hold_challenge::{
        ChallengeRecordV1, StagedZfsHoldChallengeV1, current_seconds, expiry,
    },
};

/// Retains the first actual failure without converting its source to prose.
#[derive(thiserror::Error)]
pub(in crate::owner) enum OriginalProducerErrorV5 {
    #[error("original Source owner failed")]
    Owner(#[from] ProviderLedgerError),
    #[error("original Source journal failed")]
    Journal(#[from] JournalError),
    #[error("original Source canonical ledger failed")]
    Ledger(#[from] LedgerFormatErrorV1),
    #[error("original Source catalog failed")]
    Catalog(#[from] ProviderCatalogManifestErrorV1),
    #[error("original Source claims failed")]
    Claims(#[from] StorageZfsHoldTransportErrorV1),
    #[error("original Source native request failed")]
    Request(#[from] StorageNativeAcquireErrorV2),
    #[error("original Source held archive failed")]
    Held(#[from] NativeHeldCompletionErrorV1),
    #[error("original Source signing failed")]
    Signing(#[from] OriginalNativeSigningErrorV5),
    #[error("original Source current custody failed")]
    Security(#[from] aos_sandbox_source_provider_security::SourceProviderSecurityError),
    #[error("original Source Storage observation failed")]
    Storage(#[from] aos_sandbox_source_provider_security::OriginalStorageOfferErrorV5),
    #[error("original Source Storage receipt comparison failed")]
    Receipt(#[from] aos_sandbox_source_provider_protocol::StorageZfsHoldReceiptErrorV1),
    #[error("original Source bounded retention failed")]
    Retention(#[from] std::collections::TryReserveError),
    #[error("original Source selected archive sync failed")]
    ArchiveSync(#[source] rustix::io::Errno),
    // The actual typed cause remains in the same producer's whole Result slot.
    #[error("original Source selected archive installation failed")]
    SelectedArchive,
    #[error("original Source selected archive postcheck failed")]
    SelectedArchivePostcheck,
}

impl core::fmt::Debug for OriginalProducerErrorV5 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("OriginalProducerErrorV5([retained first cause])")
    }
}

/// Names the temporally distinct original protected crossings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::owner) enum OriginalProducerAppendV5 {
    Applying,
    Requested,
    ChallengeIssued,
    StoragePrepared,
    ChallengeSpent,
    CompletionCommitted,
    HeldPrepared,
    HeldStored,
}

impl OriginalProducerAppendV5 {
    const fn index(self) -> usize {
        match self {
            Self::Applying => 0,
            Self::Requested => 1,
            Self::ChallengeIssued => 2,
            Self::StoragePrepared => 3,
            Self::ChallengeSpent => 4,
            Self::CompletionCommitted => 5,
            Self::HeldPrepared => 6,
            Self::HeldStored => 7,
        }
    }

    pub(super) const fn is_original_held(self) -> bool {
        matches!(self, Self::HeldPrepared | Self::HeldStored)
    }
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum OriginalProducerCheckpointV5 {
    #[default]
    Initial,
    ApplyingReadBack,
    RequestedReadBack,
    ChallengeIssuedReadBack,
}

/// Has no admission constructor: only the actual pending owner installs it.
#[derive(Default)]
pub(super) struct OriginalSourceProducerV5 {
    initial_owners: Option<JournalTransaction>,
    claims: Option<StorageZfsHoldTransportRequestV1>,
    unsigned: Option<StorageNativeAcquireRequestV2>,
    pub(super) signed: Option<SignedStorageNativeAcquireRequestV2>,
    provenance: Option<OriginalSourceProvenanceV5>,
    pub(super) staged: Option<StagedZfsHoldChallengeV1>,
    appends: [Option<PreparedSourceOriginalV5>; 8],
    checkpoint: OriginalProducerCheckpointV5,
    pub(super) physical_plan: Option<crate::backend::AcquirePlanV1>,
    pub(super) selected_execution: Option<SourceSelectedNativeExecutionInputDataV1>,
    pub(super) selected_backend_enrollment: Option<[u8; 928]>,
    pub(super) selected_dedicated_enrollment: Option<[u8; 160]>,
    pub(super) selected_archive_attempted: bool,
    pub(super) selected_archive: Option<Result<
        aos_sandbox_source_provider_security::ProtectedOriginalSelectedInputV1,
        OriginalProducerErrorV5,
    >>,
    pub(super) selected_archive_postcheck: Option<OriginalProducerErrorV5>,
    pub(super) selected_archive_sync_attempted: bool,
    pub(super) selected_archive_file_sync: Option<Result<(), OriginalProducerErrorV5>>,
    pub(super) selected_archive_directory_sync: Option<Result<(), OriginalProducerErrorV5>>,
    pub(super) storage_offer: Option<super::storage_offer::OriginalStorageOfferV5>,
    pub(super) original_completion: Option<super::completion::OriginalSourceCompletionV5>,
}

impl OriginalSourceProducerV5 {
    /// Borrows the original full Applying transaction, not a reconstructed seed.
    pub(super) fn applying_transaction_v5(
        &self,
    ) -> Result<&JournalTransaction, ProviderLedgerError> {
        self.appends[OriginalProducerAppendV5::Applying.index()]
            .as_ref()
            .and_then(|append| append.owners.as_ref())
            .ok_or(ProviderLedgerError::Unavailable)
    }

    pub(super) fn completion_signing_parts_v5(
        &mut self,
    ) -> Result<(&OriginalSourceProtectedReadbackV5, &mut super::completion::OriginalSourceCompletionV5), ProviderLedgerError> {
        let readback = self.appends[OriginalProducerAppendV5::ChallengeSpent.index()].as_ref()
            .and_then(|append| append.readback.as_ref()).ok_or(ProviderLedgerError::Unavailable)?;
        let completion = self.original_completion.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        Ok((readback, completion))
    }

    pub(super) fn held_signing_parts_v5(
        &mut self,
    ) -> Result<(
        &OriginalSourceProtectedReadbackV5,
        &mut super::completion::OriginalSourceCompletionV5,
        &aos_sandbox_source_provider_security::ProtectedOriginalSelectedInputV1,
        &mut super::storage_offer::OriginalStorageOfferV5,
    ), ProviderLedgerError> {
        let readback = self.appends[OriginalProducerAppendV5::HeldPrepared.index()]
            .as_ref().and_then(|append| append.readback.as_ref())
            .ok_or(ProviderLedgerError::Unavailable)?;
        let completion = self.original_completion.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let selected = self.selected_archive.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ProviderLedgerError::Unavailable)?;
        let offer = self.storage_offer.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        Ok((readback, completion, selected, offer))
    }

    pub(super) fn held_delivery_parts_v5(
        &mut self,
    ) -> Result<(
        &OriginalSourceProtectedReadbackV5,
        &mut super::completion::OriginalSourceCompletionV5,
        &aos_sandbox_source_provider_security::ProtectedOriginalSelectedInputV1,
        &mut super::storage_offer::OriginalStorageOfferV5,
    ), ProviderLedgerError> {
        let readback = self.appends[OriginalProducerAppendV5::HeldStored.index()]
            .as_ref().and_then(|append| append.readback.as_ref())
            .ok_or(ProviderLedgerError::Unavailable)?;
        let completion = self.original_completion.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let selected = self.selected_archive.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ProviderLedgerError::Unavailable)?;
        let offer = self.storage_offer.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        Ok((readback, completion, selected, offer))
    }

    pub(super) fn append_mut(
        &mut self,
        step: OriginalProducerAppendV5,
    ) -> Result<&mut PreparedSourceOriginalV5, ProviderLedgerError> {
        self.appends[step.index()].as_mut().ok_or(ProviderLedgerError::Unavailable)
    }

    pub(super) fn readback(
        &self,
        step: OriginalProducerAppendV5,
    ) -> Result<&OriginalSourceProtectedReadbackV5, ProviderLedgerError> {
        self.appends[step.index()].as_ref().and_then(|append| append.readback.as_ref())
            .ok_or(ProviderLedgerError::Unavailable)
    }

    pub(super) fn park(
        &mut self,
        step: OriginalProducerAppendV5,
        transaction: JournalTransaction,
    ) -> Result<(), ProviderLedgerError> {
        PreparedSourceOriginalV5::park(
            &mut Some(transaction),
            &mut None,
            &mut self.appends[step.index()],
        )
    }
}

/// Lends bytes or the retained first failure, never a Storage effect permit.
pub(in crate::owner) enum OriginalProducerObservationV5<'owner> {
    Ready(&'owner SignedStorageNativeAcquireRequestV2),
    Failed(&'owner OriginalProducerErrorV5),
    Closed,
}

// Unlike the first-birth archive guard, this guard spans every original crossing.
// It never moves custody out of the owner, including during unwinding.
pub(super) struct OriginalProducerClosureGuardV5<'owner> {
    pub(super) owner: &'owner mut FixedProviderOwnerV1,
    pub(super) completed: bool,
}

impl Drop for OriginalProducerClosureGuardV5<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.original_ingress.close_original_writer_v5();
            if let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.owner.state.as_mut() {
                if let Some(original) = held.original.as_mut() {
                    original.history.failed = true;
                }
            }
            if let Some(runtime) = self.owner.original_runtime.as_mut() {
                runtime.poison_runtime();
            }
        }
    }
}

impl FixedProviderOwnerV1 {
    /// Advances only the genuine resident original to the pre-dispatch cut.
    ///
    /// Only the genuine original offer path calls this producer. Immutable
    /// catalog input must match the already owned selection. A failure is kept
    /// inside the same owner; subsequent calls cannot restart or recapture time.
    pub(in crate::owner) fn advance_original_source_producer_v5(
        &mut self,
        catalog_rows: &[u8],
    ) -> OriginalProducerObservationV5<'_> {
        if self.original_ingress.producer_failure_v5().is_none()
            && !self.original_ingress.producer_closed_v5()
        {
            let mut guard = OriginalProducerClosureGuardV5 {
                owner: self,
                completed: false,
            };
            match guard.owner.advance_original_source_inner_v5(catalog_rows) {
                Ok(()) => guard.completed = true,
                Err(cause) => guard.owner.original_ingress.retain_producer_failure_v5(cause),
            }
        }

        if let Some(cause) = self.retained_original_producer_failure_v5() {
            return OriginalProducerObservationV5::Failed(cause);
        }
        if self.original_ingress.producer_closed_v5() {
            return OriginalProducerObservationV5::Closed;
        }
        match self.original_source_producer_v5() {
            Ok(producer)
                if producer.checkpoint == OriginalProducerCheckpointV5::ChallengeIssuedReadBack
                    && producer.selected_execution.is_some() =>
            {
                match producer.signed.as_ref() {
                    Some(signed) => OriginalProducerObservationV5::Ready(signed),
                    None => OriginalProducerObservationV5::Closed,
                }
            }
            _ => OriginalProducerObservationV5::Closed,
        }
    }

    pub(super) fn original_source_producer_v5(&self) -> Result<&OriginalSourceProducerV5, ProviderLedgerError> {
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_ref() else {
            return Err(ProviderLedgerError::Unavailable);
        };
        held.original.as_ref().and_then(|original| original.producer.as_ref())
            .ok_or(ProviderLedgerError::Unavailable)
    }

    pub(super) fn original_source_producer_mut_v5(
        &mut self,
    ) -> Result<&mut OriginalSourceProducerV5, ProviderLedgerError> {
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::Unavailable);
        };
        held.original.as_mut().and_then(|original| original.producer.as_mut())
            .ok_or(ProviderLedgerError::Unavailable)
    }

    pub(super) fn require_original_producer_current_v5(&mut self) -> Result<(), OriginalProducerErrorV5> {
        self.require_original_producer_owners_current_v5()?;
        self.require_retained_selected_archive_v1()?;
        Ok(())
    }

    // Internal archive stages reuse every original owner check without asking
    // an incomplete durability barrier to satisfy its own final adapter.
    pub(super) fn require_original_producer_owners_current_v5(
        &mut self,
    ) -> Result<(), OriginalProducerErrorV5> {
        let (root, acquire) = self.original_ingress.borrowed_pair_v5()?;
        let VerifiedProviderRequestV1::Acquire(verified) = acquire.verified() else {
            return Err(ProviderLedgerError::Equivocation.into());
        };
        let signed_root = SignedSourceProviderRequestV1::from_canonical_bytes(
            verified.attempt().canonical_signed_request(),
        ).map_err(ProviderLedgerError::from)?;
        let clock = self.original_ingress.borrowed_clock_v5()?;
        clock.require_original(&signed_root, verified.attempt().attempt_digest())?;
        let producer = self.original_source_producer_v5()?;
        if let Some(claims) = producer.claims.as_ref() {
            // Staged expiry already narrows the original clock before signing.
            clock.revalidate(Some(claims.validity().1))?;
        }
        if let Some(signed) = producer.signed.as_ref() {
            clock.require_request(signed)?;
        }

        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::Unavailable.into());
        };
        held.session.revalidate_root_prepared_carrier_v1(root)?;
        let current = held.session.current_projection()?;
        if current.session_binding() != verified.ingress_projection().session_binding()
            || current.provider_process_instance()
                != verified.ingress_projection().provider_process_instance()
            || current.root_process_instance()
                != verified.ingress_projection().root_mount_process_instance()
        {
            return Err(ProviderLedgerError::Equivocation.into());
        }
        self.observe_original_journal_v5()?;
        Ok(())
    }

    fn advance_original_source_inner_v5(
        &mut self,
        rows: &[u8],
    ) -> Result<(), OriginalProducerErrorV5> {
        if self.original_ingress.borrowed_catalog_v1()? != rows {
            return Err(ProviderLedgerError::Equivocation.into());
        }
        self.original_ingress.retain_original_clock_v5()?;
        self.retain_first_original_runtime_v5()?;
        self.observe_original_journal_v5()?;
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::Unavailable.into());
        };
        let original = held.original.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        if original.producer.is_none() {
            if !original.history.baseline_pending {
                return Err(ProviderLedgerError::InvalidTransition(
                    "historical Source cannot create an original producer",
                ).into());
            }
            original.producer = Some(OriginalSourceProducerV5::default());
        }
        self.require_original_producer_current_v5()?;

        if self.original_source_producer_v5()?.checkpoint == OriginalProducerCheckpointV5::Initial {
            self.prepare_original_applying_v5(rows)?;
            self.append_original_producer_step_v5(OriginalProducerAppendV5::Applying)?;
            self.original_source_producer_mut_v5()?.checkpoint =
                OriginalProducerCheckpointV5::ApplyingReadBack;
        }

        if self.original_source_producer_v5()?.checkpoint
            == OriginalProducerCheckpointV5::ApplyingReadBack
        {
            self.sign_original_producer_request_v5()?;
            self.prepare_original_carrier_v5(OriginalProducerAppendV5::Requested)?;
            self.append_original_producer_step_v5(OriginalProducerAppendV5::Requested)?;
            self.original_source_producer_mut_v5()?.checkpoint =
                OriginalProducerCheckpointV5::RequestedReadBack;
        }

        if self.original_source_producer_v5()?.checkpoint
            == OriginalProducerCheckpointV5::RequestedReadBack
        {
            self.issue_original_producer_challenge_v5()?;
            self.prepare_original_carrier_v5(OriginalProducerAppendV5::ChallengeIssued)?;
            self.append_original_producer_step_v5(OriginalProducerAppendV5::ChallengeIssued)?;
            self.original_source_producer_mut_v5()?.checkpoint =
                OriginalProducerCheckpointV5::ChallengeIssuedReadBack;
        }

        self.require_original_producer_current_v5()?;
        self.require_original_producer_readback_v5()?;
        self.retain_selected_execution_input_v1()?;
        Ok(())
    }

    pub(super) fn append_original_producer_step_v5(
        &mut self,
        step: OriginalProducerAppendV5,
    ) -> Result<(), OriginalProducerErrorV5> {
        self.require_original_producer_step_current_v5(step)?;
        self.prepare_original_journal_append_v5(step)?;
        self.require_original_producer_step_current_v5(step)?;
        self.preflight_original_journal_append_v5(step)?;
        self.require_original_producer_step_current_v5(step)?;
        self.commit_original_journal_append_v5(step)?;
        self.require_original_producer_step_current_v5(step)?;
        Ok(())
    }

    fn require_original_producer_step_current_v5(
        &mut self,
        step: OriginalProducerAppendV5,
    ) -> Result<(), OriginalProducerErrorV5> {
        if step.is_original_held() {
            self.require_original_held_current_v5()
        } else if matches!(step, OriginalProducerAppendV5::ChallengeSpent | OriginalProducerAppendV5::CompletionCommitted) {
            self.require_original_completion_current_v5()
        } else if step == OriginalProducerAppendV5::StoragePrepared {
            self.require_original_offer_current_v5()
        } else {
            // The original first three crossings retain their literal check.
            self.require_original_producer_current_v5()
        }
    }
}

impl FixedProviderOwnerV1 {
    fn prepare_original_applying_v5(
        &mut self,
        rows: &[u8],
    ) -> Result<(), OriginalProducerErrorV5> {
        let (quartet, plan) = self.original_applying_quartet_v5()?;
        let producer = self.original_source_producer_mut_v5()?;
        producer.initial_owners = Some(quartet);
        producer.physical_plan = Some(plan);
        let (root, acquire) = self.original_ingress.borrowed_pair_v5()?;
        let VerifiedProviderRequestV1::Acquire(verified) = acquire.verified() else {
            return Err(ProviderLedgerError::Equivocation.into());
        };
        let request = verified.request();
        let projection = verified.ingress_projection();
        let native = request.native_catalog().ok_or(ProviderLedgerError::Equivocation)?;
        let selection = self.original_ingress.borrowed_selection_v5()?;
        let (publication, publication_digest) = selection.original_publication_projection();
        let catalog = ProviderHeldSnapshotCatalogV1::from_canonical_bytes(rows)?;
        let selected = catalog.select_under_head(
            native.head().0,
            native.head().1,
            native.resource_namespace_digest(),
            request.binding_digest(),
        )?;
        let (resource, snapshot) = selection.original_selected_tuple();
        if publication.catalog_head() != native.head()
            || publication.floor() != native.floor()
            || publication_digest != native.canonical_publication_digest()
            || &selected.0 != resource
            || Some(&selected.1) != snapshot
        {
            return Err(ProviderLedgerError::ConfigurationMismatch.into());
        }

        let signed_root = SignedSourceProviderRequestV1::from_canonical_bytes(
            verified.attempt().canonical_signed_request(),
        ).map_err(ProviderLedgerError::from)?;
        self.original_ingress.borrowed_clock_v5()?
            .require_original(&signed_root, verified.attempt().attempt_digest())?;
        let issued = current_seconds()?;
        let lease_seconds = i64::try_from(request.requested_lease_seconds())
            .map_err(|_| ProviderLedgerError::Unavailable)?;
        let requested_expiry = issued.checked_add(lease_seconds)
            .ok_or(ProviderLedgerError::Unavailable)?;
        let expires = expiry(issued)?
            .min(request.deadline_seconds())
            .min(projection.current_valid_until_seconds())
            .min(requested_expiry);
        let staged = self.hold_challenges.stage(ChallengeRecordV1::new(
            projection.provider_authority().authority_id(),
            projection.root_mount_authority().authority_id(),
            projection.session_binding(),
            verified.attempt().attempt_digest(),
            request.acquisition_id(),
            request.binding_digest(),
            native.current_head_commitment(),
            issued,
            expires,
        ))?;
        // The actual nonce and preflight are resident before any later check.
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::Unavailable.into());
        };
        let original = held.original.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let producer = original.producer.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        producer.staged = Some(staged);
        self.original_ingress.borrowed_clock_v5()?
            .require_original(&signed_root, verified.attempt().attempt_digest())?;
        let challenge = producer.staged.as_ref().ok_or(ProviderLedgerError::Unavailable)?.record();
        let claims = StorageZfsHoldTransportRequestV1::new(
            1,
            challenge.challenge.nonce(),
            verified.attempt().attempt_digest(),
            projection.provider_authority().authority_id(),
            projection.root_mount_authority().authority_id(),
            projection.session_binding(),
            request.acquisition_id(),
            request.binding_digest(),
            native.current_head_commitment(),
            issued,
            expires,
            catalog,
        )?;
        producer.claims = Some(claims);
        producer.unsigned = Some(StorageNativeAcquireRequestV2::new_native_v3(
            producer.claims.as_ref().ok_or(ProviderLedgerError::Unavailable)?.clone(),
            signed_root,
        )?);

        let clock = self.original_ingress.borrowed_clock_v5()?;
        let (initial, original_deadline) = clock.original_sample_and_deadline();
        let challenges = self.hold_challenges.original_history_v5()?;
        let authority = self.journal.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?
            .claim_source_original_native_v5(&challenges)?;
        let quartet = producer.initial_owners.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let provenance = OriginalSourceProvenanceV5::new_untrusted(
            OriginalSourceProvenanceClaimsV5 {
                root_prepared: root.control().clone(),
                claims: producer.claims.as_ref().ok_or(ProviderLedgerError::Unavailable)?.clone(),
                initial,
                original_deadline,
                narrowed_deadline: clock.original_stage_deadline(expires)?,
                journal_sequence: authority.archive_subject(quartet)?.prefix().0,
                configuration: original.history.current.as_ref()
                    .ok_or(ProviderLedgerError::Unavailable)?.deployment_digest(),
                records: quartet_witnesses_v5(quartet)?,
            },
        )?;
        producer.provenance = Some(provenance);
        let floor = authority.derive_initial_original_floor_v5(
            quartet,
            producer.provenance.as_ref().ok_or(ProviderLedgerError::Unavailable)?,
        )?;
        let mut records = quartet.records().to_vec();
        records.push(floor.to_journal_record()?);
        let transaction_id = *quartet.id();
        producer.park(
            OriginalProducerAppendV5::Applying,
            JournalTransaction::new(transaction_id, records)?,
        )?;
        held.session.current_projection()?;
        Ok(())
    }

    fn original_applying_quartet_v5(
        &mut self,
    ) -> Result<(JournalTransaction, crate::backend::AcquirePlanV1), OriginalProducerErrorV5> {
        let (_, acquire) = self.original_ingress.borrowed_pair_v5()?;
        let VerifiedProviderRequestV1::Acquire(verified) = acquire.verified() else {
            return Err(ProviderLedgerError::Equivocation.into());
        };
        let projection = verified.ingress_projection();
        let request = verified.request();
        let evidence = verified.attempt();
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::Unavailable.into());
        };
        let original = held.original.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        if !original.history.baseline_pending {
            return Err(ProviderLedgerError::InvalidTransition("original Applying already ended").into());
        }
        let configuration = original.history.current.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let challenges = self.hold_challenges.original_history_v5()?;
        let authority = self.journal.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?
            .claim_source_original_native_v5(&challenges)?;
        let replay = authority.replayed_origins()?;
        let recovered = crate::recovery::recover_records(
            replay.current_rows().iter()
                .filter(|((namespace, _), _)| *namespace == RecordNamespace::SourceProviderAuthority)
                .map(|((_, key), value)| (key.as_slice(), value.as_slice())),
            configuration,
        )?;
        let (existing, same_session) = projection_session_at(configuration, &recovered, projection)?;
        if !same_session {
            return Err(ProviderLedgerError::ConfigurationMismatch.into());
        }
        crate::transaction::validate_session_capacity_at(
            configuration, &recovered, &existing, projection,
        )?;
        if recovered.authority.state != ProviderAuthorityStateV1::Active {
            return Err(ProviderLedgerError::InvalidTransition("new Acquire is closed").into());
        }
        enforce_acquire_limits_at(
            configuration,
            &recovered,
            projection.root_mount_authority().authority_id(),
        )?;
        if recovered.acquisitions.values().any(|row| row.acquisition_id == request.acquisition_id()) {
            return Err(ProviderLedgerError::Equivocation.into());
        }
        let VerifiedProviderRequestSequenceV1::Fresh(advance) = verified.sequence() else {
            return Err(ProviderLedgerError::Equivocation.into());
        };

        let intent = normalized_intent(verified)?;
        let effect_id = derive_acquire_effect_id(request.acquisition_id(), evidence.attempt_digest())?;
        let backend_id = aos_sandbox_source_provider_ledger::identity::acquire_native_dispatch_id_v2(
            intent.digest(),
            recovered.catalog.catalog_generation,
            recovered.catalog.catalog_digest,
            evidence.attempt_digest(),
        );
        let root_signer = projection.ordered_signers()[1].clone();
        let attempt_identity = AttemptKeyV1 {
            provider_id: projection.provider_authority().authority_id(),
            holder_id: projection.root_mount_authority().authority_id(),
            root_record_key_id: root_signer.key_id(),
            method: SourceProviderMethod::Acquire as u8,
            request_id: evidence.request_id(),
        };
        if recovered.attempts.contains_key(&attempt_identity) {
            return Err(ProviderLedgerError::Equivocation.into());
        }
        let attempt = reserved_acquire_attempt(
            verified,
            root_signer,
            &intent,
            None,
        );
        let (mut session, _) = prepare_original_session(
            projection, acquire.provider_execution_identity(), existing, request.sequence(),
        )?;
        if request.acquisition_sequence() < session.next_acquisition_sequence {
            return Err(ProviderLedgerError::Equivocation.into());
        }
        session.next_acquisition_sequence = request.acquisition_sequence().checked_add(1)
            .ok_or(ProviderLedgerError::InvalidTransition("acquisition sequence exhausted"))?;
        let session = reserve_session(session, advance.next_sequence(), attempt.attempt_digest)?;
        let plan = crate::backend::AcquirePlanV1 {
            provider_id: projection.provider_authority().authority_id(),
            holder_id: projection.root_mount_authority().authority_id(),
            session_binding: projection.session_binding(),
            attempt_digest: attempt.attempt_digest,
            acquisition_id: request.acquisition_id(),
            effect_id,
            normalized_intent_digest: intent.digest(),
            kernel_coupled: intent.kernel_coupled(),
            backend_id,
        };
        let (resource, _) = self.original_ingress.borrowed_selection_v5()?.original_selected_tuple();
        let acquisition = crate::transaction::reserved_acquisition(
            projection,
            request,
            &attempt,
            &recovered.catalog,
            &plan,
            intent,
            Some(resource),
        );
        let acquisition_identity = AcquisitionKeyV1 {
            provider_id: acquisition.provider.authority_id(),
            holder_id: acquisition.holder.authority_id(),
            acquisition_id: acquisition.acquisition_id,
        };
        let records = vec![
            (attempt_key(&attempt_identity), Some(encode_attempt(&attempt))),
            (
                acquisition_key(&acquisition_identity),
                Some(encode_acquisition(&acquisition)),
            ),
            (
                session_key(session.provider.authority_id(), session.holder.authority_id()),
                Some(encode_session(&session)),
            ),
            (
                session_history_key(
                    session.provider.authority_id(),
                    session.holder.authority_id(),
                    session.session_binding,
                ),
                Some(encode_session_history(&session)),
            ),
        ];
        // The caller parks the same plan DATA alongside the unchanged quartet;
        // retaining it adds no effect permit or extra fallible owner lookup.
        Ok((owner_transaction_v5(b"original-source-applying-v5", records)?, plan))
    }
}

pub(super) fn owner_transaction_v5(
    purpose: &[u8],
    records: Vec<(Vec<u8>, Option<Vec<u8>>)>,
) -> Result<JournalTransaction, OriginalProducerErrorV5> {
    // This identity precedes Source5, whose payload itself names admission.
    // The complete transaction's Journal digest still commits the exact floor.
    let (identity, _) = canonical_owner_transaction_id(purpose, &records)?;
    let records = records.into_iter().map(|(key, value)| match value {
        Some(value) => JournalRecord::put(RecordNamespace::SourceProviderAuthority, key, value),
        None => JournalRecord::delete(RecordNamespace::SourceProviderAuthority, key),
    }).collect();
    Ok(JournalTransaction::new(identity, records)?)
}

fn quartet_witnesses_v5(
    quartet: &JournalTransaction,
) -> Result<[NativeHeldByteWitnessV1; 4], OriginalProducerErrorV5> {
    let families = [
        NativeHeldRecordFamilyV1::ProviderAttempt,
        NativeHeldRecordFamilyV1::ProviderAcquisition,
        NativeHeldRecordFamilyV1::ProviderHolder,
        NativeHeldRecordFamilyV1::ProviderHistory,
    ];
    let mut witnesses = Vec::with_capacity(4);
    for (record, family) in quartet.records().iter().zip(families) {
        let bytes = record.value().ok_or(ProviderLedgerError::Equivocation)?;
        witnesses.push(NativeHeldByteWitnessV1::new(
            family,
            record.key().to_vec(),
            native_held_record_byte_digest_v1(family, record.key(), bytes)?,
        )?);
    }
    witnesses.try_into().map_err(|_| ProviderLedgerError::Equivocation.into())
}

impl FixedProviderOwnerV1 {
    fn sign_original_producer_request_v5(&mut self) -> Result<(), OriginalProducerErrorV5> {
        self.require_original_producer_current_v5()?;
        let (root, acquire) = self.original_ingress.borrowed_pair_v5()?;
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::Unavailable.into());
        };
        let producer = held.original.as_mut().and_then(|original| original.producer.as_mut())
            .ok_or(ProviderLedgerError::Unavailable)?;
        let applying = producer.appends[OriginalProducerAppendV5::Applying.index()].as_ref()
            .and_then(|append| append.readback.as_ref()).ok_or(ProviderLedgerError::Unavailable)?;
        let unsigned = producer.unsigned.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let challenges = self.hold_challenges.original_history_v5()?;
        let authority = self.journal.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?
            .claim_source_original_native_v5(&challenges)?;
        held.session.sign_original_storage_native_request_v5(
            &authority, applying, root, acquire, unsigned, &mut producer.signed,
        )?;
        self.require_original_producer_current_v5()?;
        Ok(())
    }

    fn issue_original_producer_challenge_v5(&mut self) -> Result<(), OriginalProducerErrorV5> {
        self.require_original_producer_current_v5()?;
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::Unavailable.into());
        };
        let producer = held.original.as_mut().and_then(|original| original.producer.as_mut())
            .ok_or(ProviderLedgerError::Unavailable)?;
        let requested = producer.appends[OriginalProducerAppendV5::Requested.index()].as_ref()
            .and_then(|append| append.readback.as_ref()).ok_or(ProviderLedgerError::Unavailable)?;
        self.hold_challenges.commit_original_requested_v5(
            self.journal.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?,
            requested,
            producer.signed.as_ref().ok_or(ProviderLedgerError::Unavailable)?,
            producer.staged.as_mut().ok_or(ProviderLedgerError::Unavailable)?,
        )?;
        self.require_original_producer_current_v5()?;
        Ok(())
    }

    fn prepare_original_carrier_v5(
        &mut self,
        step: OriginalProducerAppendV5,
    ) -> Result<(), OriginalProducerErrorV5> {
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::Unavailable.into());
        };
        let producer = held.original.as_mut().and_then(|original| original.producer.as_mut())
            .ok_or(ProviderLedgerError::Unavailable)?;
        let signed = producer.signed.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let acquisition = signed.request().claims().provider_acquisition().1;
        let root = self.original_ingress.borrowed_pair_v5()?.0.control();
        let clock = self.original_ingress.borrowed_clock_v5()?;
        clock.require_request(signed)?;
        let challenges = self.hold_challenges.original_history_v5()?;
        let authority = self.journal.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?
            .claim_source_original_native_v5(&challenges)?;
        let replay = authority.replayed_origins()?;
        let owner_rows = || replay.current_rows().iter()
            .filter(|((namespace, _), _)| *namespace == RecordNamespace::SourceProviderAuthority)
            .map(|((_, key), value)| (key.as_slice(), value.as_slice()));
        let key = native_completion_key_v2(acquisition);
        let record = match step {
            OriginalProducerAppendV5::Requested => {
                let applying = producer.readback(OriginalProducerAppendV5::Applying)?;
                let admission = authority.original_signing_basis_v5(applying, acquisition)?;
                let original = NativeAcquireCompletionRecordV2::requested(
                    signed.clone(),
                    admission.admission_comparison().original().reservation_acquisition_digest,
                    clock.durable_anchor(signed)?,
                )?;
                let suffix = NativeHeldCompletionSuffixV1::new(
                    NativeHeldOwnerV1::Provider, 0, root.scope().flight, None, vec![root.clone()],
                )?;
                SourceNativeHeldCompletionRecordV1::new(original, suffix)?
            }
            OriginalProducerAppendV5::ChallengeIssued => {
                let requested = producer.readback(OriginalProducerAppendV5::Requested)?;
                authority.require_original_requested_readback_v5(requested, signed)?;
                let bytes = replay.current_rows().get(&(
                    RecordNamespace::SourceProviderAuthority, key.clone(),
                )).ok_or(ProviderLedgerError::Unavailable)?;
                let previous = SourceNativeHeldCompletionRecordV1::from_canonical_bytes(&key, bytes)?;
                let mut original = previous.original().clone();
                original.revision = original.revision.checked_add(1)
                    .ok_or(ProviderLedgerError::InvalidTransition("native revision exhausted"))?;
                let suffix = NativeHeldCompletionSuffixV1::new(
                    NativeHeldOwnerV1::Provider,
                    1,
                    previous.suffix().flight(),
                    previous.suffix().prepared().cloned(),
                    previous.suffix().controls().to_vec(),
                )?;
                SourceNativeHeldCompletionRecordV1::new(original, suffix)?
            }
            OriginalProducerAppendV5::Applying | OriginalProducerAppendV5::StoragePrepared
            | OriginalProducerAppendV5::ChallengeSpent | OriginalProducerAppendV5::CompletionCommitted => {
                return Err(ProviderLedgerError::InvalidTransition("Applying is not a carrier").into());
            }
        };
        let bytes = record.to_canonical_bytes()?;
        match step {
            OriginalProducerAppendV5::Requested => {
                let provenance = producer.provenance.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
                propose_original_source_requested_v5(
                    owner_rows(),
                    [(key.as_slice(), Some(bytes.as_slice()))],
                    provenance,
                    provenance.claims().configuration,
                )?;
            }
            OriginalProducerAppendV5::ChallengeIssued => {
                // The pure engine needs the complete after graph; this temporary
                // DATA copy is not an owner, index, or replay-to-live constructor.
                let mut after = owner_rows().map(|(key, value)| (key.to_vec(), value.to_vec()))
                    .collect::<BTreeMap<_, _>>();
                after.insert(key.clone(), bytes.clone());
                let issued = producer.staged.as_ref()
                    .and_then(StagedZfsHoldChallengeV1::original_readback_v5)
                    .ok_or(ProviderLedgerError::Unavailable)?;
                propose_native_held_transition_v1(
                    owner_rows(),
                    after.iter().map(|(key, value)| (key.as_slice(), value.as_slice())),
                    acquisition,
                    SourceNativeHeldStepV1::ChallengeIssued,
                    Some(issued),
                )?;
            }
            OriginalProducerAppendV5::Applying | OriginalProducerAppendV5::StoragePrepared
            | OriginalProducerAppendV5::ChallengeSpent | OriginalProducerAppendV5::CompletionCommitted => {
                return Err(ProviderLedgerError::InvalidTransition("Applying is not a carrier").into());
            }
        }

        let purpose: &[u8] = match step {
            OriginalProducerAppendV5::Requested => b"original-source-requested-v5",
            OriginalProducerAppendV5::ChallengeIssued => b"original-source-challenge-issued-v5",
            OriginalProducerAppendV5::Applying | OriginalProducerAppendV5::StoragePrepared
            | OriginalProducerAppendV5::ChallengeSpent | OriginalProducerAppendV5::CompletionCommitted => {
                return Err(ProviderLedgerError::InvalidTransition("Applying is not a carrier").into());
            }
        };
        let owner_transaction = owner_transaction_v5(purpose, vec![(key, Some(bytes))])?;
        let (before_floor, after_floor) = authority.derive_original_floor_transfer_v5(
            &owner_transaction, acquisition,
        )?;
        let mut records = owner_transaction.records().to_vec();
        records.push(JournalRecord::delete(
            RecordNamespace::GlobalCapacityReservation,
            before_floor.to_journal_record()?.key().to_vec(),
        ));
        records.push(after_floor.to_journal_record()?);
        producer.park(step, JournalTransaction::new(*owner_transaction.id(), records)?)?;
        held.session.current_projection()?;
        Ok(())
    }

    pub(super) fn require_original_producer_readback_v5(&mut self) -> Result<(), OriginalProducerErrorV5> {
        let producer = self.original_source_producer_v5()?;
        let signed = producer.signed.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let readback = producer.readback(OriginalProducerAppendV5::ChallengeIssued)?;
        let key = native_completion_key_v2(signed.request().claims().provider_acquisition().1);
        let bytes = readback.rows().get(&(RecordNamespace::SourceProviderAuthority, key.clone()))
            .ok_or(ProviderLedgerError::Unavailable)?;
        let record = SourceNativeHeldCompletionRecordV1::from_canonical_bytes(&key, bytes)?;
        if record.suffix().phase() != 1
            || record.original().canonical_request.as_ref() != Some(signed)
            || record.suffix().controls().len() != 1
            || record.suffix().controls().first()
                != Some(self.original_ingress.borrowed_pair_v5()?.0.control())
        {
            return Err(ProviderLedgerError::Equivocation.into());
        }
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_ref() else {
            return Err(ProviderLedgerError::Unavailable.into());
        };
        let producer = held.original.as_ref().and_then(|original| original.producer.as_ref())
            .ok_or(ProviderLedgerError::Unavailable)?;
        let challenges = self.hold_challenges.original_history_v5()?;
        // Borrow only disjoint resident owner fields, not the whole owner.
        let journal = self.journal.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?;
        journal.claim_source_original_native_v5(&challenges)?
            .validate_readback(producer.readback(OriginalProducerAppendV5::ChallengeIssued)?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! UNRUN mechanics only: no genuine Session, Journal or original admission.

    use super::*;
    use std::error::Error;

    fn transaction(id: u8) -> JournalTransaction {
        JournalTransaction::new(
            [id; 16],
            vec![JournalRecord::put(
                RecordNamespace::SourceProviderAuthority,
                vec![id],
                vec![id + 1],
            )],
        ).unwrap()
    }

    #[test]
    fn three_original_crossings_have_distinct_resident_slots() {
        let mut producer = OriginalSourceProducerV5::default();
        let steps = [
            OriginalProducerAppendV5::Applying,
            OriginalProducerAppendV5::Requested,
            OriginalProducerAppendV5::ChallengeIssued,
        ];

        for (index, step) in steps.into_iter().enumerate() {
            producer.park(step, transaction(index as u8 + 1)).unwrap();
        }

        for (index, step) in steps.into_iter().enumerate() {
            let append = producer.append_mut(step).unwrap();
            assert_eq!(append.owners.as_ref(), Some(&transaction(index as u8 + 1)));
            assert!(append.readback.is_none());
        }
    }

    #[test]
    fn occupied_original_slot_keeps_the_first_candidate_and_latches_failure() {
        let mut producer = OriginalSourceProducerV5::default();
        producer.park(OriginalProducerAppendV5::Applying, transaction(1)).unwrap();

        assert!(producer.park(OriginalProducerAppendV5::Applying, transaction(2)).is_err());

        let append = producer.append_mut(OriginalProducerAppendV5::Applying).unwrap();
        assert_eq!(append.owners.as_ref(), Some(&transaction(1)));
        assert!(append.failed);
        assert!(append.readback.is_none());
    }

    #[test]
    fn empty_progress_cannot_supply_protected_readback_or_signed_readiness() {
        let producer = OriginalSourceProducerV5::default();

        assert!(producer.readback(OriginalProducerAppendV5::Applying).is_err());
        assert!(producer.readback(OriginalProducerAppendV5::Requested).is_err());
        assert!(producer.readback(OriginalProducerAppendV5::ChallengeIssued).is_err());
        assert!(producer.checkpoint == OriginalProducerCheckpointV5::Initial);
        assert!(producer.signed.is_none());
        assert!(producer.staged.is_none());
    }

    #[test]
    fn original_failure_debug_is_redacted_and_the_typed_source_is_retained() {
        let failure = OriginalProducerErrorV5::Journal(JournalError::JournalTooLarge);

        assert_eq!(format!("{failure:?}"), "OriginalProducerErrorV5([retained first cause])");
        assert!(failure.source().unwrap().downcast_ref::<JournalError>().is_some());
    }

    #[test]
    fn history_default_does_not_contain_a_live_original_producer() {
        let original = OriginalJournalV5::default();

        assert!(!original.history.baseline_pending);
        assert!(original.producer.is_none());
    }
}
