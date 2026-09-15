//! Sealed local lifecycle transitions for AOSMSA02 acquisitions.
//!
//! These transitions consume move-only adapter evidence. The evidence has no
//! public scalar constructor, so journal shape alone cannot claim PID 1
//! descriptor custody, manager readback, or an atomic source-pin/Create effect.

use aos_sandbox::journal::{JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox::mount_manager_startup::{
    FreshManagerSourcePresenceV1, FreshManagerSourceRemovalReceiptV1, LostMountSourceCustodyV1,
    StartupManagerSourcePresenceV1, TerminalMountSourceAbsenceV1,
};
use aos_sandbox_broker::BrokerEffectStatusV1;
use aos_sandbox_core::{BrokerGrantTarget, BrokerVerb, ObjectDigest};
use aos_sandbox_protocol::ValidatedMountRequest;
use aos_sandbox_protocol::mount_source_acquisition_state::validate_mount_source_state_graph_v2;
use aos_sandbox_protocol::semantics::project_final_mount_create_semantics_v1;
use aos_sandbox_source_provider_security::{
    CommittedReopenedMountSourceRootV2, CommittedSourceRootV1,
    CurrentRootMountSourceProviderSessionV1, MountSourceReleaseAuthorityV2,
    MountSourceRemovalPreparationV2, MountSourceRootCustodyV2, NegativeCustodyPostcommitOutcomeV2,
    NegativeCustodyPostcommitRecoveryV2, PreparedMountSourceConsumptionV2,
    PreparedMountSourceRootCustodyV2, ReleasedMountSourceRootV2,
    RetainedMountSourceReleaseForRemovalV2, SourceRootPostcommitOutcomeV2,
    SourceRootPostcommitRecoveryV2, SourceRootPostcommitSuccessV2, VerifiedMountProviderOutcomeV2,
};
use sha2::{Digest as _, Sha256};

use super::SourceAcquisitionTableV2;
use super::format::{MutationTagV2, put_record, seal_record, state_error, transaction_id};
use super::model::{
    ConsumptionEvidenceV2, SourceAcquisitionPhaseV2, SourceAcquisitionRowV2, StoredRecordV2,
};
use super::transition::prepare_mutation;
use super::transition::{MutationIdentityV2, commit_mutation, next_revision};
use super::validation::validate_recovered_table;
use crate::Result;
use crate::authorization::admission_v1::MountAuthorityV1;
use crate::authorization::semantics_v1::{MountCatalogCommitmentV1, canonical_mount_semantics_v1};
use crate::source_pin::{
    SourcePinProofClassV1, SourcePinRowV1, SourcePinRowV1Ext, SourceRealizationEvidenceV1,
    validate_source_consumption_record as validate_source_pin_consumption_record,
};
use crate::state::mount_resource_v1::{
    OperationCorrelationV1,
    validate_source_consumption_record as validate_resource_consumption_record,
};

/// Proves source-pin activation and one exact final Create admission together.
#[doc(hidden)]
#[derive(Debug)]
pub struct SourceConsumptionCommitV2 {
    final_create_request: ValidatedMountRequest,
    transport_request_digest: [u8; 32],
    catalog: MountCatalogCommitmentV1,
    source_pin_record: JournalRecord,
    create_effect_record: JournalRecord,
    create_operation_record: JournalRecord,
}

impl SourceConsumptionCommitV2 {
    /// Retains one typed final Create and its exact prospective records.
    pub(crate) fn new(
        final_create_request: ValidatedMountRequest,
        transport_request_digest: [u8; 32],
        catalog: MountCatalogCommitmentV1,
        source_pin_record: JournalRecord,
        create_effect_record: JournalRecord,
        create_operation_record: JournalRecord,
    ) -> Self {
        Self {
            final_create_request,
            transport_request_digest,
            catalog,
            source_pin_record,
            create_effect_record,
            create_operation_record,
        }
    }
}

/// Returns exact companion records already committed with one consumption.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct CommittedSourceConsumptionV2 {
    records: Vec<JournalRecord>,
}

/// Preserves the prospective Mount table together with sole SourceRoot recovery.
#[must_use = "postcommit outcomes retain sole SourceRoot custody and must be consumed"]
pub(crate) enum SourceAcquisitionPostcommitOutcomeV2 {
    Success(SourceRootPostcommitSuccessV2),
    RecoveryRequired(SourceAcquisitionPostcommitRecoveryV2),
}

/// Retains an exact prospective table until SourceRoot postcommit resealing succeeds.
pub(crate) struct SourceAcquisitionPostcommitRecoveryV2 {
    retained: SourceAcquisitionPostcommitRetainedV2,
}

enum SourceAcquisitionPostcommitRetainedV2 {
    Security(SourceRootPostcommitRecoveryV2),
    Sealed(SourceRootPostcommitSuccessV2),
    SealedConsumption {
        success: SourceRootPostcommitSuccessV2,
        transaction: JournalTransaction,
        predecessor_record: Vec<u8>,
    },
}

/// Publishes companion records only after the composite consumption is exact.
#[must_use = "consumption outcomes retain sole SourceRoot custody and must be consumed"]
pub(crate) enum SourceAcquisitionConsumptionOutcomeV2 {
    Success {
        source_root: SourceRootPostcommitSuccessV2,
        committed: CommittedSourceConsumptionV2,
    },
    RecoveryRequired(SourceAcquisitionConsumptionRecoveryV2),
}

/// Retains unpublished companion records across exact composite resealing.
pub(crate) struct SourceAcquisitionConsumptionRecoveryV2 {
    postcommit: SourceAcquisitionPostcommitRecoveryV2,
    companions: Vec<JournalRecord>,
    transaction: JournalTransaction,
    predecessor_record: Vec<u8>,
}

/// Preserves a manager-negative proof together with its prospective Released row.
#[must_use = "negative-custody outcomes retain terminal proof and must be consumed"]
pub(crate) enum SourceAcquisitionNegativeCustodyOutcomeV2 {
    Success(ReleasedMountSourceRootV2),
    RecoveryRequired(SourceAcquisitionNegativeCustodyRecoveryV2),
}

/// Retains an exact prospective table until negative custody resealing succeeds.
pub(crate) struct SourceAcquisitionNegativeCustodyRecoveryV2 {
    retained: SourceAcquisitionNegativeCustodyRetainedV2,
}

enum SourceAcquisitionNegativeCustodyRetainedV2 {
    Security(NegativeCustodyPostcommitRecoveryV2),
    Sealed(ReleasedMountSourceRootV2),
}

impl CommittedSourceConsumptionV2 {
    /// Returns the exact committed companion records in transaction order.
    #[must_use]
    pub fn records(&self) -> &[JournalRecord] {
        &self.records
    }
}

impl SourceAcquisitionTableV2 {
    /// Converts a complete startup loss proof into cleanup-only Release custody.
    ///
    /// # Errors
    ///
    /// Returns an error if the proof no longer names the exact protected
    /// acquisition or its Complete Acquire lineage.
    pub(crate) fn prepare_lost_source_cleanup_v2(
        &self,
        journal: &aos_sandbox::journal::ProtectedJournalAuthority<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        loss: LostMountSourceCustodyV1,
    ) -> Result<aos_sandbox_source_provider_security::PreparedMountSourceReleaseV2> {
        session
            .prepare_lost_mount_source_release_v2(journal, loss)
            .map_err(|_| state_error("startup loss proof does not authorize cleanup"))
    }

    /// Separates fresh manager removal authority from retained SourceRoot custody.
    #[must_use]
    pub(crate) fn prepare_release_manager_removal_v2(
        release_authority: MountSourceReleaseAuthorityV2,
    ) -> MountSourceRemovalPreparationV2 {
        release_authority.prepare_manager_removal()
    }

    pub(super) fn retain_source_root_postcommit(
        &mut self,
        journal: &aos_sandbox::journal::ProtectedJournalAuthority<'_>,
        outcome: SourceRootPostcommitOutcomeV2,
    ) -> SourceAcquisitionPostcommitOutcomeV2 {
        match outcome {
            SourceRootPostcommitOutcomeV2::Success(success) => {
                if self.synchronize_after_uncertain_postcommit(journal) {
                    SourceAcquisitionPostcommitOutcomeV2::Success(success)
                } else {
                    SourceAcquisitionPostcommitOutcomeV2::RecoveryRequired(
                        SourceAcquisitionPostcommitRecoveryV2 {
                            retained: SourceAcquisitionPostcommitRetainedV2::Sealed(success),
                        },
                    )
                }
            }
            SourceRootPostcommitOutcomeV2::RecoveryRequired(security) => {
                self.synchronize_after_uncertain_postcommit(journal);
                SourceAcquisitionPostcommitOutcomeV2::RecoveryRequired(
                    SourceAcquisitionPostcommitRecoveryV2 {
                        retained: SourceAcquisitionPostcommitRetainedV2::Security(security),
                    },
                )
            }
        }
    }

    fn retain_negative_custody_postcommit(
        &mut self,
        journal: &aos_sandbox::journal::ProtectedJournalAuthority<'_>,
        outcome: NegativeCustodyPostcommitOutcomeV2,
    ) -> SourceAcquisitionNegativeCustodyOutcomeV2 {
        match outcome {
            NegativeCustodyPostcommitOutcomeV2::Success(success) => {
                if self.synchronize_after_uncertain_postcommit(journal) {
                    SourceAcquisitionNegativeCustodyOutcomeV2::Success(success)
                } else {
                    SourceAcquisitionNegativeCustodyOutcomeV2::RecoveryRequired(
                        SourceAcquisitionNegativeCustodyRecoveryV2 {
                            retained: SourceAcquisitionNegativeCustodyRetainedV2::Sealed(success),
                        },
                    )
                }
            }
            NegativeCustodyPostcommitOutcomeV2::RecoveryRequired(security) => {
                self.synchronize_after_uncertain_postcommit(journal);
                SourceAcquisitionNegativeCustodyOutcomeV2::RecoveryRequired(
                    SourceAcquisitionNegativeCustodyRecoveryV2 {
                        retained: SourceAcquisitionNegativeCustodyRetainedV2::Security(security),
                    },
                )
            }
        }
    }

    fn synchronize_after_uncertain_postcommit(
        &mut self,
        journal: &aos_sandbox::journal::ProtectedJournalAuthority<'_>,
    ) -> bool {
        let Ok(records) = journal.records() else {
            return false;
        };
        let Ok(state) = validate_mount_source_state_graph_v2(records) else {
            return false;
        };
        self.acquisitions = state.acquisitions;
        self.holder_sequences = state.holder_sequences;
        self.provider_heads = state.provider_heads;
        self.provider_sessions = state.provider_sessions;
        self.provider_attempts = state.provider_attempts;
        true
    }

    fn synchronize_after_uncertain_consumption(
        &mut self,
        journal: &aos_sandbox::MountSourceConsumptionJournalAuthorityV1<'_>,
    ) -> bool {
        let Ok(records) = journal.records() else {
            return false;
        };
        let Ok(state) = validate_mount_source_state_graph_v2(records) else {
            return false;
        };
        self.acquisitions = state.acquisitions;
        self.holder_sequences = state.holder_sequences;
        self.provider_heads = state.provider_heads;
        self.provider_sessions = state.provider_sessions;
        self.provider_attempts = state.provider_attempts;
        true
    }

    fn retain_source_consumption_postcommit(
        &mut self,
        journal: &aos_sandbox::MountSourceConsumptionJournalAuthorityV1<'_>,
        outcome: SourceRootPostcommitOutcomeV2,
        transaction: JournalTransaction,
        predecessor_record: Vec<u8>,
    ) -> SourceAcquisitionPostcommitOutcomeV2 {
        match outcome {
            SourceRootPostcommitOutcomeV2::Success(success) => {
                if self.synchronize_after_uncertain_consumption(journal) {
                    SourceAcquisitionPostcommitOutcomeV2::Success(success)
                } else {
                    SourceAcquisitionPostcommitOutcomeV2::RecoveryRequired(
                        SourceAcquisitionPostcommitRecoveryV2 {
                            retained: SourceAcquisitionPostcommitRetainedV2::SealedConsumption {
                                success,
                                transaction,
                                predecessor_record,
                            },
                        },
                    )
                }
            }
            SourceRootPostcommitOutcomeV2::RecoveryRequired(security) => {
                self.synchronize_after_uncertain_consumption(journal);
                SourceAcquisitionPostcommitOutcomeV2::RecoveryRequired(
                    SourceAcquisitionPostcommitRecoveryV2 {
                        retained: SourceAcquisitionPostcommitRetainedV2::Security(security),
                    },
                )
            }
        }
    }

    /// Retries one exact SourceRoot seal without discarding sole descriptor custody.
    #[must_use]
    #[doc(hidden)]
    pub(crate) fn reseal_source_root_postcommit_v2(
        &mut self,
        journal: &mut aos_sandbox::journal::ProtectedJournalAuthority<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        recovery: SourceAcquisitionPostcommitRecoveryV2,
    ) -> SourceAcquisitionPostcommitOutcomeV2 {
        match recovery.retained {
            SourceAcquisitionPostcommitRetainedV2::Security(security) => {
                let outcome = session.reseal_mount_source_root_postcommit_v2(journal, security);
                self.retain_source_root_postcommit(journal, outcome)
            }
            SourceAcquisitionPostcommitRetainedV2::Sealed(success) => {
                if self.synchronize_after_uncertain_postcommit(journal) {
                    SourceAcquisitionPostcommitOutcomeV2::Success(success)
                } else {
                    SourceAcquisitionPostcommitOutcomeV2::RecoveryRequired(
                        SourceAcquisitionPostcommitRecoveryV2 {
                            retained: SourceAcquisitionPostcommitRetainedV2::Sealed(success),
                        },
                    )
                }
            }
            SourceAcquisitionPostcommitRetainedV2::SealedConsumption {
                success,
                transaction,
                predecessor_record,
            } => SourceAcquisitionPostcommitOutcomeV2::RecoveryRequired(
                SourceAcquisitionPostcommitRecoveryV2 {
                    retained: SourceAcquisitionPostcommitRetainedV2::SealedConsumption {
                        success,
                        transaction,
                        predecessor_record,
                    },
                },
            ),
        }
    }

    /// Retries an exact composite consumption without publishing uncertain companions.
    #[must_use]
    #[doc(hidden)]
    pub(crate) fn reseal_source_consumption_postcommit_v2(
        &mut self,
        journal: &mut aos_sandbox::MountSourceConsumptionJournalAuthorityV1<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        recovery: SourceAcquisitionConsumptionRecoveryV2,
    ) -> SourceAcquisitionConsumptionOutcomeV2 {
        let SourceAcquisitionConsumptionRecoveryV2 {
            postcommit,
            companions,
            transaction,
            predecessor_record,
        } = recovery;
        let postcommit = match postcommit.retained {
            SourceAcquisitionPostcommitRetainedV2::Security(security) => {
                let outcome =
                    session.reseal_mount_source_consumption_postcommit_v2(journal, security);
                self.retain_source_consumption_postcommit(
                    journal,
                    outcome,
                    transaction.clone(),
                    predecessor_record.clone(),
                )
            }
            SourceAcquisitionPostcommitRetainedV2::SealedConsumption {
                success,
                transaction,
                predecessor_record,
            } => {
                let exact = session
                    .validate_sealed_mount_source_consumption_v2(
                        journal,
                        &success,
                        &transaction,
                        &predecessor_record,
                    )
                    .is_ok()
                    && self.synchronize_after_uncertain_consumption(journal);
                if exact {
                    SourceAcquisitionPostcommitOutcomeV2::Success(success)
                } else {
                    SourceAcquisitionPostcommitOutcomeV2::RecoveryRequired(
                        SourceAcquisitionPostcommitRecoveryV2 {
                            retained: SourceAcquisitionPostcommitRetainedV2::SealedConsumption {
                                success,
                                transaction,
                                predecessor_record,
                            },
                        },
                    )
                }
            }
            retained => SourceAcquisitionPostcommitOutcomeV2::RecoveryRequired(
                SourceAcquisitionPostcommitRecoveryV2 { retained },
            ),
        };
        match postcommit {
            SourceAcquisitionPostcommitOutcomeV2::Success(source_root) => {
                SourceAcquisitionConsumptionOutcomeV2::Success {
                    source_root,
                    committed: CommittedSourceConsumptionV2 {
                        records: companions,
                    },
                }
            }
            SourceAcquisitionPostcommitOutcomeV2::RecoveryRequired(postcommit) => {
                SourceAcquisitionConsumptionOutcomeV2::RecoveryRequired(
                    SourceAcquisitionConsumptionRecoveryV2 {
                        postcommit,
                        companions,
                        transaction,
                        predecessor_record,
                    },
                )
            }
        }
    }

    /// Retries one exact Released seal without discarding manager-negative proof.
    #[must_use]
    #[doc(hidden)]
    pub(crate) fn reseal_negative_custody_postcommit_v2(
        &mut self,
        journal: &mut aos_sandbox::journal::ProtectedJournalAuthority<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        recovery: SourceAcquisitionNegativeCustodyRecoveryV2,
    ) -> SourceAcquisitionNegativeCustodyOutcomeV2 {
        match recovery.retained {
            SourceAcquisitionNegativeCustodyRetainedV2::Security(security) => {
                let outcome = session.reseal_negative_custody_postcommit_v2(journal, security);
                self.retain_negative_custody_postcommit(journal, outcome)
            }
            SourceAcquisitionNegativeCustodyRetainedV2::Sealed(success) => {
                if self.synchronize_after_uncertain_postcommit(journal) {
                    SourceAcquisitionNegativeCustodyOutcomeV2::Success(success)
                } else {
                    SourceAcquisitionNegativeCustodyOutcomeV2::RecoveryRequired(
                        SourceAcquisitionNegativeCustodyRecoveryV2 {
                            retained: SourceAcquisitionNegativeCustodyRetainedV2::Sealed(success),
                        },
                    )
                }
            }
        }
    }

    /// Records PID 1 custody after a Complete Acquire disposition.
    ///
    /// # Errors
    ///
    /// Returns an error for stale state, mismatched opaque evidence, an
    /// outstanding provider query, or a journal failure.
    #[doc(hidden)]
    pub(crate) fn record_descriptor_custody_v2(
        &mut self,
        journal: &mut aos_sandbox::journal::ProtectedJournalAuthority<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        acquisition_id: [u8; 32],
        expected_revision: u64,
        expected_digest: [u8; 32],
        committed_source_root: CommittedSourceRootV1,
        manager_presence: FreshManagerSourcePresenceV1,
    ) -> Result<SourceAcquisitionPostcommitOutcomeV2> {
        let current = self.current_for_cas(acquisition_id, expected_revision, expected_digest)?;
        let evidence = current
            .evidence
            .as_ref()
            .ok_or_else(|| state_error("descriptor custody has no Complete Acquire evidence"))?;
        let owner_reference = current
            .acquire_terminal_attempt
            .ok_or_else(|| state_error("descriptor custody has no terminal Acquire attempt"))?;
        let owner_attempt = self
            .provider_attempts
            .get(&owner_reference.id)
            .ok_or_else(|| state_error("descriptor custody owner attempt is absent"))?;
        let owner_session = self
            .provider_sessions
            .get(&owner_attempt.session_id)
            .ok_or_else(|| state_error("descriptor custody owner session is absent"))?;
        let prepared = committed_source_root
            .prepare_mount_custody(current, owner_attempt, owner_session, manager_presence)
            .map_err(|_| state_error("SourceRoot custody preparation failed"))?;
        self.record_prepared_descriptor_custody_v2(
            journal,
            session,
            acquisition_id,
            expected_revision,
            expected_digest,
            prepared,
        )
    }

    /// Records PID 1 custody for an exact post-crash reopened SourceRoot.
    ///
    /// # Errors
    ///
    /// Returns an error for stale state, mismatched reopened custody, an
    /// outstanding query, or journal/postcommit failure.
    #[doc(hidden)]
    pub(crate) fn record_reopened_descriptor_custody_v2(
        &mut self,
        journal: &mut aos_sandbox::journal::ProtectedJournalAuthority<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        acquisition_id: [u8; 32],
        expected_revision: u64,
        expected_digest: [u8; 32],
        committed_source_root: CommittedReopenedMountSourceRootV2,
        manager_presence: FreshManagerSourcePresenceV1,
    ) -> Result<SourceAcquisitionPostcommitOutcomeV2> {
        let current = self.current_for_cas(acquisition_id, expected_revision, expected_digest)?;
        let evidence = current
            .evidence
            .as_ref()
            .ok_or_else(|| state_error("reopened custody has no Complete Acquire evidence"))?;
        let owner_reference = current
            .acquire_terminal_attempt
            .ok_or_else(|| state_error("reopened custody has no terminal Acquire attempt"))?;
        let owner_attempt = self
            .provider_attempts
            .get(&owner_reference.id)
            .ok_or_else(|| state_error("reopened custody owner attempt is absent"))?;
        let owner_session = self
            .provider_sessions
            .get(&owner_attempt.session_id)
            .ok_or_else(|| state_error("reopened custody owner session is absent"))?;
        let prepared = committed_source_root
            .prepare_mount_custody(current, owner_attempt, owner_session, manager_presence)
            .map_err(|_| state_error("reopened SourceRoot custody preparation failed"))?;
        self.record_prepared_descriptor_custody_v2(
            journal,
            session,
            acquisition_id,
            expected_revision,
            expected_digest,
            prepared,
        )
    }

    /// Adopts an exact startup-captured SourceRoot into descriptor custody.
    ///
    /// # Errors
    ///
    /// Returns an error when the move-only startup presence is stale, does not
    /// name the exact current Complete Acquire row, or the protected commit
    /// cannot be completed or retained for recovery.
    #[doc(hidden)]
    pub(crate) fn record_startup_descriptor_custody_v2(
        &mut self,
        journal: &mut aos_sandbox::journal::ProtectedJournalAuthority<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        manager_presence: StartupManagerSourcePresenceV1,
    ) -> Result<SourceAcquisitionPostcommitOutcomeV2> {
        let manager = manager_presence.custody_evidence();
        let acquisition_id = manager.acquisition_id;
        let expected_revision = manager.acquisition_revision;
        let expected_digest = manager.acquisition_record_digest;
        let prepared = session
            .prepare_startup_mount_source_custody_v2(journal, manager_presence)
            .map_err(|_| state_error("startup SourceRoot custody preparation failed"))?;

        self.record_prepared_descriptor_custody_v2(
            journal,
            session,
            acquisition_id,
            expected_revision,
            expected_digest,
            prepared,
        )
    }

    /// Rebinds startup descriptor custody without changing the durable held phase.
    ///
    /// # Errors
    ///
    /// Returns an error unless the startup capability names the exact current
    /// held row and security accepts the closed same-phase replacement.
    #[doc(hidden)]
    pub(crate) fn adopt_startup_retained_source_v2(
        &mut self,
        journal: &mut aos_sandbox::journal::ProtectedJournalAuthority<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        manager_presence: StartupManagerSourcePresenceV1,
    ) -> Result<SourceAcquisitionPostcommitOutcomeV2> {
        let evidence = manager_presence.custody_evidence();
        let acquisition_id = evidence.acquisition_id;
        let expected_revision = evidence.acquisition_revision;
        let expected_digest = evidence.acquisition_record_digest;
        self.current_for_cas(acquisition_id, expected_revision, expected_digest)?;
        let prepared = session
            .prepare_startup_mount_source_adoption_v2(journal, manager_presence)
            .map_err(|_| state_error("startup retained SourceRoot adoption failed"))?;
        if prepared.predecessor().id != acquisition_id
            || prepared.predecessor().revision != expected_revision
            || prepared.predecessor().record_digest != expected_digest
            || prepared.projection().manager_custody().is_none()
            || prepared.projection().manager_custody_loss().is_some()
        {
            return Err(state_error("startup retained SourceRoot plan differs"));
        }

        let current = self.current_for_cas(acquisition_id, expected_revision, expected_digest)?;
        let (descriptor_custody_digest, positive_custody_digest) = prepared.custody_commitments();
        let mut next = current.clone();
        next.revision = next_revision(current.revision)?;
        next.manager_custody = prepared.projection().manager_custody();
        next.manager_custody_loss = None;
        next.descriptor_custody_digest = Some(*descriptor_custody_digest.as_bytes());
        next.positive_custody_digest = positive_custody_digest.map(|digest| *digest.as_bytes());
        let (transaction, _tentative) =
            self.prepare_row_only_transition(MutationTagV2::StartupCustodyRebind, next)?;
        let outcome =
            session.commit_startup_mount_source_adoption_v2(journal, transaction, prepared);
        Ok(self.retain_source_root_postcommit(journal, outcome))
    }

    fn record_prepared_descriptor_custody_v2(
        &mut self,
        journal: &mut aos_sandbox::journal::ProtectedJournalAuthority<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        acquisition_id: [u8; 32],
        expected_revision: u64,
        expected_digest: [u8; 32],
        prepared: PreparedMountSourceRootCustodyV2,
    ) -> Result<SourceAcquisitionPostcommitOutcomeV2> {
        let current = self.current_for_cas(acquisition_id, expected_revision, expected_digest)?;
        let evidence = current
            .evidence
            .as_ref()
            .ok_or_else(|| state_error("descriptor custody has no Complete Acquire evidence"))?;
        let projection = prepared.projection();
        if current.phase != SourceAcquisitionPhaseV2::PendingQuery
            || current.acquire_terminal_attempt.is_none()
            || !matches!(
                &current.recovery,
                super::model::AcquisitionRecoveryV2::Ready
            )
            || self.row_owns_pending_attempt(current)
            || projection.mount_acquisition_id() != Some(acquisition_id)
            || projection.provider_acquisition()
                != (
                    evidence.provider_acquisition.acquisition_id,
                    evidence.provider_acquisition.acquisition_sequence,
                )
            || projection.lease()
                != (
                    evidence.lease_id,
                    aos_sandbox_core::ObjectDigest::from_bytes(evidence.signed_lease_digest),
                )
            || projection.descriptor_commitment().as_bytes() != &evidence.descriptor_commitment
            || projection.source_realization_handle() != Some(evidence.source_realization_handle)
            || projection.lifecycle_commitment().as_bytes() == &[0; 32]
        {
            return Err(state_error("descriptor custody evidence differs"));
        }

        let mut next = current.clone();
        next.revision = next_revision(current.revision)?;
        next.phase = SourceAcquisitionPhaseV2::DescriptorCustodied;
        next.manager_custody = projection.manager_custody();
        next.manager_custody_loss = projection.manager_custody_loss();
        next.descriptor_custody_digest = Some(*projection.lifecycle_commitment().as_bytes());
        let (transaction, _tentative) =
            self.prepare_row_only_transition(MutationTagV2::Custody, next)?;
        let outcome = session.commit_mount_source_root_custody_v2(journal, transaction, prepared);
        Ok(self.retain_source_root_postcommit(journal, outcome))
    }

    /// Activates a custodied source after authoritative positive readback.
    ///
    /// # Errors
    ///
    /// Returns an error for stale state, mismatched opaque evidence, or a
    /// journal failure.
    #[doc(hidden)]
    pub(crate) fn activate_custodied_source_v2(
        &mut self,
        journal: &mut aos_sandbox::journal::ProtectedJournalAuthority<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        acquisition_id: [u8; 32],
        expected_revision: u64,
        expected_digest: [u8; 32],
        custody: MountSourceRootCustodyV2,
    ) -> Result<SourceAcquisitionPostcommitOutcomeV2> {
        let current = self.current_for_cas(acquisition_id, expected_revision, expected_digest)?;
        let evidence = current
            .evidence
            .as_ref()
            .ok_or_else(|| state_error("positive custody has no provider evidence"))?;
        let prepared = custody
            .prepare_active(session)
            .map_err(|_| state_error("SourceRoot active preparation failed"))?;
        let projection = prepared.projection();
        if current.phase != SourceAcquisitionPhaseV2::DescriptorCustodied
            || projection.mount_acquisition_id() != Some(acquisition_id)
            || projection.descriptor_commitment().as_bytes() != &evidence.descriptor_commitment
            || projection.lifecycle_commitment().as_bytes() == &[0; 32]
        {
            return Err(state_error("positive custody evidence differs"));
        }

        let mut next = current.clone();
        next.revision = next_revision(current.revision)?;
        next.phase = SourceAcquisitionPhaseV2::Active;
        next.positive_custody_digest = Some(*projection.lifecycle_commitment().as_bytes());
        let (transaction, _tentative) =
            self.prepare_row_only_transition(MutationTagV2::Activation, next)?;
        let outcome = session.commit_active_mount_source_root_v2(journal, transaction, prepared);
        Ok(self.retain_source_root_postcommit(journal, outcome))
    }

    /// Atomically consumes an Active acquisition with SourcePin and Create records.
    ///
    /// The caller must apply the returned companion records to its other
    /// in-memory indexes before accepting another request.
    ///
    /// # Errors
    ///
    /// Returns an error for stale state, a mismatched sealed consumption,
    /// wrong companion namespaces, invalid final Create projection, recovery
    /// graph failure, or journal failure.
    #[doc(hidden)]
    pub(crate) fn consume_active_source_v2(
        &mut self,
        journal: &mut aos_sandbox::MountSourceConsumptionJournalAuthorityV1<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        authority: &MountAuthorityV1,
        acquisition_id: [u8; 32],
        expected_revision: u64,
        expected_digest: [u8; 32],
        prepared: PreparedMountSourceConsumptionV2,
        consumption: SourceConsumptionCommitV2,
    ) -> Result<SourceAcquisitionConsumptionOutcomeV2> {
        let current = self.current_for_cas(acquisition_id, expected_revision, expected_digest)?;
        let predecessor_record = put_record(&StoredRecordV2::Acquisition {
            value: current.clone(),
        })?
        .value()
        .ok_or_else(|| state_error("source consumption predecessor encoded as a delete"))?
        .to_vec();
        let evidence = current
            .evidence
            .as_ref()
            .ok_or_else(|| state_error("source consumption has no provider evidence"))?;
        let provider_head = self.head_for_row(current)?;
        let reconciled = provider_head
            .last_reconciliation
            .as_ref()
            .filter(|value| {
                value.projection_epoch == provider_head.current_projection_epoch
                    && value.projection_digest == provider_head.current_projection_digest
                    && value.residual_count == 0
                    && value.conflict_count == 0
            })
            .is_some();
        let final_create = canonical_mount_semantics_v1(
            &consumption.final_create_request,
            Some(consumption.catalog),
            &[],
        )
        .map_err(|_| state_error("final Create semantics are invalid"))?;
        let projected = project_final_mount_create_semantics_v1(final_create.canonical_bytes())
            .map_err(|_| state_error("final Create semantics are invalid"))?;
        let projected_digest: [u8; 32] = Sha256::digest(&projected).into();
        let custody = prepared.projection();
        let request_id = *consumption.final_create_request.header().request_id();
        let request_digest = consumption.transport_request_digest;
        let effect_value = consumption
            .create_effect_record
            .value()
            .ok_or_else(|| state_error("final Create effect is a delete"))?;
        let effect_key: [u8; 16] = consumption
            .create_effect_record
            .key()
            .try_into()
            .map_err(|_| state_error("final Create effect key is malformed"))?;
        let effect = authority
            .open_effect(&effect_key, effect_value)
            .map_err(|_| state_error("final Create effect authentication failed"))?;
        if !reconciled
            || current.phase != SourceAcquisitionPhaseV2::Active
            || custody.mount_acquisition_id() != Some(acquisition_id)
            || custody.source_realization_handle() != Some(evidence.source_realization_handle)
            || custody.provider_acquisition()
                != (
                    evidence.provider_acquisition.acquisition_id,
                    evidence.provider_acquisition.acquisition_sequence,
                )
            || custody.descriptor_commitment().as_bytes() != &evidence.descriptor_commitment
            || custody.lifecycle_commitment().as_bytes() == &[0; 32]
            || projected != current.prospective_mount_template
            || projected_digest == [0; 32]
            || final_create.verb() != BrokerVerb::MountCreate
            || final_create.target() != BrokerGrantTarget::Assignment
            || consumption.create_effect_record.namespace() != RecordNamespace::Effect
            || effect_key != request_id
            || effect.status() != BrokerEffectStatusV1::Pending
            || effect.request_id() != &request_id
            || effect.transport_request_digest().as_bytes() != &request_digest
            || effect.request_digest() != final_create.commitment().digest()
            || effect.plan_digest().as_bytes() != &current.mount_plan_digest
            || effect.lease_digest().as_bytes() != &current.ownership_lease_digest
            || effect.verb() != BrokerVerb::MountCreate
            || effect.target() != BrokerGrantTarget::Assignment
        {
            return Err(state_error("source consumption evidence differs"));
        }

        let source_evidence = source_pin_evidence(evidence)?;
        let binding = aos_sandbox_protocol::SourceRealizationBindingV1::from_canonical_bytes(
            &current.source_binding,
        )
        .map_err(|_| state_error("source acquisition binding is invalid"))?;
        let expected_source_pin =
            SourcePinRowV1::active(&binding, source_evidence, request_id, request_digest)?;
        validate_source_pin_consumption_record(
            &consumption.source_pin_record,
            &expected_source_pin,
        )?;
        let expected_resource = crate::broker::allocated_resource(
            &consumption.final_create_request,
            request_digest,
            evidence.source_kernel_boot_id,
            OperationCorrelationV1 {
                operation_id: request_id,
                request_digest,
            },
            source_evidence,
        )?;
        validate_resource_consumption_record(
            &consumption.create_operation_record,
            &expected_resource,
        )?;

        let companions = vec![
            consumption.source_pin_record,
            consumption.create_effect_record,
            consumption.create_operation_record,
        ];

        let mut next = current.clone();
        next.revision = next_revision(current.revision)?;
        next.phase = SourceAcquisitionPhaseV2::Consumed;
        let holder_sequence_revision =
            self.holder_sequence_revision(next.scope.holder_authority_id);
        let provider_head_revision = provider_head.revision;
        let consumption_transaction_id = transaction_id(
            MutationTagV2::Consumption,
            next.scope.holder_authority_id,
            next.scope.provider_authority_id,
            holder_sequence_revision,
            provider_head_revision,
            Some(acquisition_id),
            Some(next.revision),
            None,
            None,
            None,
        );
        next.consumption = Some(ConsumptionEvidenceV2 {
            holder_sequence_revision,
            provider_head_revision,
            transaction_id: consumption_transaction_id,
            operation_id: request_id,
            transport_request_digest: request_digest,
            final_create_semantics: final_create.canonical_bytes().to_vec(),
            final_create_semantics_digest: *final_create.commitment().digest().as_bytes(),
            source_pin_record_digest: journal_record_digest(&companions[0]),
            create_effect_record_digest: journal_record_digest(&companions[1]),
            create_operation_record_digest: journal_record_digest(&companions[2]),
        });
        let sealed = seal_record(StoredRecordV2::Acquisition { value: next })?;
        let StoredRecordV2::Acquisition { value: next } = sealed else {
            return Err(state_error("sealed lifecycle record kind changed"));
        };
        let mut tentative = self.clone();
        tentative.acquisitions.insert(acquisition_id, next.clone());
        validate_recovered_table(&tentative)?;

        let mut records = Vec::with_capacity(4);
        records.push(put_record(&StoredRecordV2::Acquisition {
            value: next.clone(),
        })?);
        records.extend(companions.clone());
        let transaction = JournalTransaction::new(consumption_transaction_id, records)?;
        let retained_transaction = transaction.clone();
        let consumed = session.commit_mount_source_consumption_v2(journal, transaction, prepared);
        let consumed = self.retain_source_consumption_postcommit(
            journal,
            consumed,
            retained_transaction.clone(),
            predecessor_record.clone(),
        );
        Ok(match consumed {
            SourceAcquisitionPostcommitOutcomeV2::Success(source_root) => {
                SourceAcquisitionConsumptionOutcomeV2::Success {
                    source_root,
                    committed: CommittedSourceConsumptionV2 {
                        records: companions,
                    },
                }
            }
            SourceAcquisitionPostcommitOutcomeV2::RecoveryRequired(postcommit) => {
                SourceAcquisitionConsumptionOutcomeV2::RecoveryRequired(
                    SourceAcquisitionConsumptionRecoveryV2 {
                        postcommit,
                        companions,
                        transaction: retained_transaction,
                        predecessor_record,
                    },
                )
            }
        })
    }

    /// Marks a provider-terminal Release as manager-negative and Released.
    ///
    /// # Errors
    ///
    /// Returns an error for stale state, absent terminal proof, mismatched
    /// opaque manager evidence, or journal failure.
    #[doc(hidden)]
    pub(crate) fn finish_release_v2(
        &mut self,
        journal: &mut aos_sandbox::journal::ProtectedJournalAuthority<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        acquisition_id: [u8; 32],
        expected_revision: u64,
        expected_digest: [u8; 32],
        retained_release: RetainedMountSourceReleaseForRemovalV2,
        terminal_outcome: VerifiedMountProviderOutcomeV2,
        removal: FreshManagerSourceRemovalReceiptV1,
    ) -> Result<SourceAcquisitionNegativeCustodyOutcomeV2> {
        let current = self.current_for_cas(acquisition_id, expected_revision, expected_digest)?;
        let evidence = current
            .evidence
            .as_ref()
            .ok_or_else(|| state_error("release has no provider evidence"))?;
        let prepared = retained_release
            .prepare_negative_custody(journal, session, terminal_outcome, removal)
            .map_err(|_| state_error("manager-negative SourceRoot preparation failed"))?;
        let projection = prepared.projection();
        let is_releasing = current.phase == SourceAcquisitionPhaseV2::Releasing
            || (current.phase == SourceAcquisitionPhaseV2::Faulted
                && current.faulted_from == Some(SourceAcquisitionPhaseV2::Releasing));
        if !is_releasing
            || current.release_proof.is_none()
            || self.row_owns_pending_attempt(current)
            || projection.mount_acquisition_id() != Some(acquisition_id)
            || projection.provider_acquisition()
                != (
                    evidence.provider_acquisition.acquisition_id,
                    evidence.provider_acquisition.acquisition_sequence,
                )
            || projection.descriptor_commitment().as_bytes() != &evidence.descriptor_commitment
            || prepared.negative_custody_digest().as_bytes() == &[0; 32]
        {
            return Err(state_error("release custody evidence differs"));
        }

        let mut next = current.clone();
        next.revision = next_revision(current.revision)?;
        next.phase = SourceAcquisitionPhaseV2::Released;
        next.negative_custody_digest = Some(*prepared.negative_custody_digest().as_bytes());
        if current.phase == SourceAcquisitionPhaseV2::Faulted {
            next.retained_faulted_from = current.faulted_from;
            next.retained_fault_digest = current.fault_digest;
            next.faulted_from = None;
            next.fault_digest = None;
        }
        let (transaction, _tentative) =
            self.prepare_row_only_transition(MutationTagV2::FinishRelease, next)?;
        let outcome = session.commit_released_mount_source_root_v2(journal, transaction, prepared);
        Ok(self.retain_negative_custody_postcommit(journal, outcome))
    }

    /// Finishes cleanup for a SourceRoot proven absent before Release began.
    ///
    /// # Errors
    ///
    /// Returns an error if the loss capability, terminal provider proof, or
    /// current Releasing row no longer names the same acquisition.
    #[doc(hidden)]
    pub(crate) fn finish_lost_release_v2(
        &mut self,
        journal: &mut aos_sandbox::journal::ProtectedJournalAuthority<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        acquisition_id: [u8; 32],
        expected_revision: u64,
        expected_digest: [u8; 32],
        release_authority: MountSourceReleaseAuthorityV2,
        terminal_outcome: VerifiedMountProviderOutcomeV2,
    ) -> Result<SourceAcquisitionNegativeCustodyOutcomeV2> {
        let current = self.current_for_cas(acquisition_id, expected_revision, expected_digest)?;
        let evidence = current
            .evidence
            .as_ref()
            .ok_or_else(|| state_error("lost release has no provider evidence"))?;
        let prepared = release_authority
            .prepare_lost_negative_custody(journal, session, terminal_outcome)
            .map_err(|_| state_error("startup loss does not authorize terminal cleanup"))?;
        let projection = prepared.projection();
        let is_releasing = current.phase == SourceAcquisitionPhaseV2::Releasing
            || (current.phase == SourceAcquisitionPhaseV2::Faulted
                && current.faulted_from == Some(SourceAcquisitionPhaseV2::Releasing));
        if !is_releasing
            || current.manager_custody_loss.is_none()
            || current.release_proof.is_none()
            || self.row_owns_pending_attempt(current)
            || projection.mount_acquisition_id() != Some(acquisition_id)
            || projection.provider_acquisition()
                != (
                    evidence.provider_acquisition.acquisition_id,
                    evidence.provider_acquisition.acquisition_sequence,
                )
            || projection.manager_custody_loss() != current.manager_custody_loss
            || prepared.negative_custody_digest().as_bytes() == &[0; 32]
        {
            return Err(state_error("lost release custody evidence differs"));
        }

        let mut next = current.clone();
        next.revision = next_revision(current.revision)?;
        next.phase = SourceAcquisitionPhaseV2::Released;
        next.negative_custody_digest = Some(*prepared.negative_custody_digest().as_bytes());
        if current.phase == SourceAcquisitionPhaseV2::Faulted {
            next.retained_faulted_from = current.faulted_from;
            next.retained_fault_digest = current.fault_digest;
            next.faulted_from = None;
            next.fault_digest = None;
        }
        let (transaction, _tentative) =
            self.prepare_row_only_transition(MutationTagV2::FinishRelease, next)?;
        let outcome = session.commit_released_mount_source_root_v2(journal, transaction, prepared);
        Ok(self.retain_negative_custody_postcommit(journal, outcome))
    }

    /// Finishes a crash-retained Release from complete startup FD absence.
    ///
    /// The move-only absence proof is minted before activation descriptors are
    /// released and is already bound to the exact current row, terminal
    /// Release/Inventory attempt, and prior manager death. This adapter commits
    /// only the corresponding Released row and preserves the proof across an
    /// ambiguous append through the existing negative-custody outcome.
    ///
    /// # Errors
    ///
    /// Returns an error if the protected row no longer equals the proof, if
    /// security rejects its terminal causality, or if the prospective Released
    /// graph is invalid. A postcommit ambiguity is returned as
    /// `RecoveryRequired`, never as an error that discards the proof.
    #[doc(hidden)]
    pub(crate) fn recover_and_finish_release_absence_v2(
        &mut self,
        journal: &mut aos_sandbox::journal::ProtectedJournalAuthority<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        absence: TerminalMountSourceAbsenceV1,
    ) -> Result<SourceAcquisitionNegativeCustodyOutcomeV2> {
        let projection = absence.projection().clone();
        let subject = projection.subject;
        let acquisition_id = subject.acquisition_id;
        let current = self.current_for_cas(
            acquisition_id,
            subject.acquisition_revision,
            subject.acquisition_record_digest,
        )?;
        let evidence = current
            .evidence
            .as_ref()
            .ok_or_else(|| state_error("recovered release has no provider evidence"))?;
        let provider_acquisition_id = subject.provider_acquisition_id;
        let provider_sequence = subject.provider_acquisition_sequence;
        let realization_handle = subject.source_realization_handle;
        let descriptor_commitment = subject.descriptor_commitment;
        let lease_id = subject.lease_id;
        let lease_digest = subject.lease_digest;
        let is_releasing = current.phase == SourceAcquisitionPhaseV2::Releasing
            || (current.phase == SourceAcquisitionPhaseV2::Faulted
                && current.faulted_from == Some(SourceAcquisitionPhaseV2::Releasing));
        if !is_releasing
            || current.release_proof.is_none()
            || self.row_owns_pending_attempt(current)
            || (provider_acquisition_id, provider_sequence)
                != (
                    current.provider_acquisition.acquisition_id,
                    current.provider_acquisition.acquisition_sequence,
                )
            || realization_handle != evidence.source_realization_handle
            || descriptor_commitment != evidence.descriptor_commitment
            || (lease_id, lease_digest) != (evidence.lease_id, evidence.signed_lease_digest)
        {
            return Err(state_error(
                "startup absence proof differs from release row",
            ));
        }
        let prepared = session
            .prepare_recovered_negative_custody_v2(journal, absence)
            .map_err(|_| state_error("protected startup absence recovery failed"))?;

        let mut next = current.clone();
        next.revision = next_revision(current.revision)?;
        next.phase = SourceAcquisitionPhaseV2::Released;
        next.negative_custody_digest = Some(*prepared.negative_custody_digest().as_bytes());
        if current.phase == SourceAcquisitionPhaseV2::Faulted {
            next.retained_faulted_from = current.faulted_from;
            next.retained_fault_digest = current.fault_digest;
            next.faulted_from = None;
            next.fault_digest = None;
        }
        let (transaction, _tentative) =
            self.prepare_row_only_transition(MutationTagV2::FinishRelease, next)?;
        let outcome = session.commit_released_mount_source_root_v2(journal, transaction, prepared);
        Ok(self.retain_negative_custody_postcommit(journal, outcome))
    }

    /// Records a sanitized fault without erasing provider or custody history.
    ///
    /// # Errors
    ///
    /// Returns an error for stale state, a sentinel fault, a terminal or
    /// already faulted row, unresolved recovery, an outstanding attempt, or a
    /// journal failure.
    #[doc(hidden)]
    pub(crate) fn fault_acquisition_v2(
        &mut self,
        journal: &mut aos_sandbox::journal::ProtectedJournalAuthority<'_>,
        acquisition_id: [u8; 32],
        expected_revision: u64,
        expected_digest: [u8; 32],
        fault_digest: [u8; 32],
    ) -> Result<()> {
        let current = self.current_for_cas(acquisition_id, expected_revision, expected_digest)?;
        if matches!(
            current.phase,
            SourceAcquisitionPhaseV2::Released | SourceAcquisitionPhaseV2::Faulted
        ) || fault_digest == [0; 32]
            || !matches!(
                &current.recovery,
                super::model::AcquisitionRecoveryV2::Ready
            )
            || (current.phase == SourceAcquisitionPhaseV2::PendingQuery
                && current.evidence.is_some())
            || self.row_owns_pending_attempt(current)
        {
            return Err(state_error("source acquisition fault edge is invalid"));
        }

        let mut next = current.clone();
        next.revision = next_revision(current.revision)?;
        next.phase = SourceAcquisitionPhaseV2::Faulted;
        next.faulted_from = Some(current.phase);
        next.fault_digest = Some(fault_digest);
        self.commit_row_only(journal, MutationTagV2::Fault, next)
    }

    pub(super) fn current_for_cas(
        &self,
        acquisition_id: [u8; 32],
        expected_revision: u64,
        expected_digest: [u8; 32],
    ) -> Result<&SourceAcquisitionRowV2> {
        let current = self
            .acquisitions
            .get(&acquisition_id)
            .ok_or_else(|| state_error("source acquisition is absent"))?;
        if current.revision != expected_revision || current.record_digest != expected_digest {
            return Err(state_error("source acquisition compare-and-swap failed"));
        }
        Ok(current)
    }

    pub(super) fn row_owns_pending_attempt(&self, row: &SourceAcquisitionRowV2) -> bool {
        self.provider_heads
            .get(&(
                row.scope.holder_authority_id,
                row.scope.provider_authority_id,
            ))
            .and_then(|head| head.pending_attempt)
            .and_then(|reference| self.provider_attempts.get(&reference.id))
            .is_some_and(|attempt| attempt.owner.owner_id() == row.acquisition_id)
    }

    fn commit_row_only(
        &mut self,
        journal: &mut aos_sandbox::journal::ProtectedJournalAuthority<'_>,
        tag: MutationTagV2,
        next: SourceAcquisitionRowV2,
    ) -> Result<()> {
        let head_revision = self.head_for_row(&next)?.revision;
        let holder_sequence_revision =
            self.holder_sequence_revision(next.scope.holder_authority_id);
        commit_mutation(
            self,
            journal,
            MutationIdentityV2 {
                tag,
                holder_id: next.scope.holder_authority_id,
                provider_id: next.scope.provider_authority_id,
                next_holder_sequence_revision: holder_sequence_revision,
                next_head_revision: head_revision,
                acquisition_id: Some(next.acquisition_id),
                next_row_revision: Some(next.revision),
                attempt_id: None,
                next_attempt_revision: None,
                session_id: None,
            },
            vec![StoredRecordV2::Acquisition { value: next }],
        )
    }

    fn prepare_row_only_transition(
        &self,
        tag: MutationTagV2,
        next: SourceAcquisitionRowV2,
    ) -> Result<(JournalTransaction, SourceAcquisitionTableV2)> {
        let head_revision = self.head_for_row(&next)?.revision;
        let holder_sequence_revision =
            self.holder_sequence_revision(next.scope.holder_authority_id);
        prepare_mutation(
            self,
            MutationIdentityV2 {
                tag,
                holder_id: next.scope.holder_authority_id,
                provider_id: next.scope.provider_authority_id,
                next_holder_sequence_revision: holder_sequence_revision,
                next_head_revision: head_revision,
                acquisition_id: Some(next.acquisition_id),
                next_row_revision: Some(next.revision),
                attempt_id: None,
                next_attempt_revision: None,
                session_id: None,
            },
            vec![StoredRecordV2::Acquisition { value: next }],
        )
    }

    fn head_for_row(
        &self,
        row: &SourceAcquisitionRowV2,
    ) -> Result<&super::model::SourceProviderHeadV2> {
        self.provider_heads
            .get(&(
                row.scope.holder_authority_id,
                row.scope.provider_authority_id,
            ))
            .ok_or_else(|| state_error("source provider head is absent"))
    }

    fn holder_sequence_revision(&self, holder_id: [u8; 16]) -> u64 {
        self.holder_sequences
            .get(&holder_id)
            .map_or(0, |value| value.revision)
    }
}

fn journal_record_digest(record: &JournalRecord) -> [u8; 32] {
    aos_sandbox_protocol::mount_source_acquisition_state::mount_source_consumption_companion_digest_v2(
        record.namespace() as u16,
        record.key(),
        record.value(),
    )
}

fn source_pin_evidence(
    evidence: &super::model::SourceAcquisitionEvidenceV2,
) -> Result<SourceRealizationEvidenceV1> {
    let proof_class = match evidence.proof_class {
        super::model::SourceAcquisitionProofClassV2::ImmutableTree => {
            SourcePinProofClassV1::ImmutableTree
        }
        super::model::SourceAcquisitionProofClassV2::LocalLive => SourcePinProofClassV1::LocalLive,
        super::model::SourceAcquisitionProofClassV2::BestEffortReplica => {
            SourcePinProofClassV1::BestEffortReplica
        }
    };
    let projected = SourceRealizationEvidenceV1 {
        handle: evidence.source_realization_handle,
        physical_proof_digest: evidence.source_physical_proof_digest,
        unique_mount_id: evidence.source_unique_mount_id,
        provider_authority_digest: evidence.historical_lease_signer.signer.authority_digest,
        provider_authority_id: evidence.historical_lease_signer.signer.authority_id,
        provider_authority_generation: evidence.historical_lease_signer.signer.authority_generation,
        provider_resource_id: evidence.provider_resource_id,
        provider_resource_generation: evidence.provider_resource_generation,
        provider_resource_digest: evidence.provider_resource_digest,
        provider_catalog_generation: evidence.provider_catalog_generation,
        provider_catalog_digest: evidence.provider_catalog_digest,
        kernel_boot_id: evidence.source_kernel_boot_id,
        device: evidence.source_device,
        inode: evidence.source_inode,
        proof_class,
    };
    if projected.provider_authority_id == [0; 16] {
        return Err(state_error("source-pin provider authority is absent"));
    }
    Ok(projected)
}

pub(super) fn project_final_create_semantics(bytes: &[u8]) -> Result<Vec<u8>> {
    project_final_mount_create_semantics_v1(bytes)
        .map_err(|_| state_error("final Create semantics are invalid"))
}
