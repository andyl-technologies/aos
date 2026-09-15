//! Atomic provider-outcome receive, verification, and SourceRoot custody.
//!
//! These operations keep carrier descriptors move-only across tentative Mount
//! disposition construction and release custody only after exact protected
//! post-commit validation.

use super::*;

#[path = "outcome/helpers.rs"]
mod helpers;
use helpers::*;

#[path = "outcome/receive.rs"]
mod receive;

fn startup_adoption_capability(
    prepared: crate::PreparedStartupMountSourceAdoptionV2,
) -> Result<crate::RecoveredRetainedMountSourceRootV2, crate::PreparedStartupMountSourceAdoptionV2>
{
    use aos_sandbox_protocol::mount_source_acquisition_state::SourceAcquisitionPhaseV2;

    let manager_presence = Some(prepared.manager_presence);
    if prepared.cleanup_only {
        return Ok(crate::RecoveredRetainedMountSourceRootV2::CleanupOnly(
            crate::PreparedMountSourceReleaseV2 {
                custody: crate::descriptor::ReleaseCustodyV2::Retained {
                    observed: prepared.observed,
                    manager_presence,
                },
                projection: prepared.projection,
            },
        ));
    }
    match prepared.effective_phase {
        SourceAcquisitionPhaseV2::DescriptorCustodied => Ok(
            crate::RecoveredRetainedMountSourceRootV2::DescriptorCustodied(
                crate::MountSourceRootCustodyV2 {
                    observed: prepared.observed,
                    projection: prepared.projection,
                    manager_presence,
                },
            ),
        ),
        SourceAcquisitionPhaseV2::Active => Ok(crate::RecoveredRetainedMountSourceRootV2::Active(
            crate::ActiveMountSourceRootV2 {
                observed: prepared.observed,
                projection: prepared.projection,
                manager_presence,
            },
        )),
        SourceAcquisitionPhaseV2::Consumed => Ok(
            crate::RecoveredRetainedMountSourceRootV2::Consumed(crate::ConsumedMountSourceRootV2 {
                observed: prepared.observed,
                projection: prepared.projection,
                manager_presence,
            }),
        ),
        SourceAcquisitionPhaseV2::Releasing => {
            Ok(crate::RecoveredRetainedMountSourceRootV2::Releasing(
                crate::MountSourceReleaseAuthorityV2 {
                    custody: crate::descriptor::ReleaseCustodyV2::Retained {
                        observed: prepared.observed,
                        manager_presence,
                    },
                    projection: prepared.projection,
                },
            ))
        }
        _ => Err(prepared),
    }
}

impl CurrentRootMountSourceProviderSessionV1 {
    /// Seals a received Complete-Acquire SourceRoot after its exact Mount disposition commits.
    ///
    /// The method consumes both the verified outcome and sole descriptor
    /// custody. It decodes and whole-graph validates the protected namespace,
    /// requires the exact attempt to be `DispositionConsumed`, and reobserves
    /// the descriptor immediately before and after deriving the commit receipt.
    ///
    /// A failed or ambiguous commit returns `RecoveryRequired`, retaining the
    /// verified outcome, sole descriptor, and exact transaction for resealing.
    pub fn commit_received_mount_source_root_v2(
        &mut self,
        journal: &mut aos_sandbox::ProtectedJournalAuthority<'_>,
        transaction: aos_sandbox::JournalTransaction,
        outcome: VerifiedMountProviderOutcomeV2,
        source_root: crate::ObservedSourceRootV1,
    ) -> crate::SourceRootPostcommitOutcomeV2 {
        use aos_sandbox_protocol::mount_source_acquisition_state::{
            ProviderAttemptStateV2, ProviderMethodV2, ProviderQueryOwnerV2, ProviderStatusV2,
            StoredRecordV2, decode_mount_source_state_record_v2,
        };

        let validated = (|| {
            let exact_shape = transaction_has_exact_record_kinds(
                &transaction,
                &[ExactMountRecordKindV2::Attempt],
            ) || transaction_has_exact_record_kinds(
                &transaction,
                &[
                    ExactMountRecordKindV2::Attempt,
                    ExactMountRecordKindV2::Acquisition,
                    ExactMountRecordKindV2::Head,
                ],
            );
            if !exact_shape {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            }
            self.revalidate()?;
            source_root.revalidate(self)?;
            let (attempt_key, attempt_record) = exact_put_record(&transaction, |key, value| {
                matches!(
                    aos_sandbox_protocol::mount_source_acquisition_state::decode_mount_source_state_record_v2(key, value),
                    Ok(aos_sandbox_protocol::mount_source_acquisition_state::StoredRecordV2::ProviderQueryAttempt { .. })
                )
            })
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            let committed_snapshot =
                if journal.get(&attempt_key).ok().flatten() == Some(attempt_record.as_slice()) {
                    validated_mount_state(journal).map_err(|error| self.poison(error))?;
                    journal
                        .snapshot()
                        .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?
                } else {
                    commit_or_read_exact_mount_transaction(journal, &transaction)
                        .map_err(|error| self.poison(error))?
                };
            let graph = validated_mount_state(journal).map_err(|error| self.poison(error))?;
            let attempt = match decode_mount_source_state_record_v2(&attempt_key, &attempt_record) {
                Ok(StoredRecordV2::ProviderQueryAttempt { value }) => value,
                _ => return Err(self.poison(SourceProviderSecurityError::SessionContinuity)),
            };
            let ProviderAttemptStateV2::DispositionConsumed {
                response_sequence,
                verification_anchor,
                status,
                signed_status,
                signed_result,
                ..
            } = &attempt.state
            else {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            };
            let ProviderQueryOwnerV2::Acquire { acquisition_id } = attempt.owner else {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            };
            let signed_status =
                SignedSourceProviderStatusV1::from_canonical_bytes(signed_status)
                    .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            let response = AcquireSourceResponseV1::new(
                signed_status,
                (!signed_result.is_empty()).then_some(signed_result.clone()),
            )
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            let canonical_response = encode_acquire_response(&response);
            let receipt = response
                .signed_receipt()
                .and_then(|bytes| SignedSourceProviderReceiptV1::from_canonical_bytes(bytes).ok())
                .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            let lease = SignedSourceExportLeaseV1::from_canonical_bytes(
                receipt.subject().signed_export_lease(),
            )
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            let source_identity = source_root.disposition_identity();
            let committed_session_binding = graph
                .provider_sessions
                .get(&attempt.session_id)
                .map(|session| ObjectDigest::from_bytes(session.session_binding))
                .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            if attempt.method != ProviderMethodV2::Acquire
                || *status != ProviderStatusV2::Complete
                || *response_sequence != outcome.response_sequence
                || *verification_anchor != outcome.verification_anchor
                || outcome.status != SourceProviderStatus::Complete
                || outcome.canonical_response != canonical_response
                || outcome.acquisition_id != Some(ObjectDigest::from_bytes(acquisition_id))
                || outcome.session_binding != committed_session_binding
                || source_identity.0 != acquisition_id
                || Some(source_identity.1) != outcome.acquisition_sequence
                || source_identity.2 != lease.subject().lease_id()
                || source_identity.3 != digest_signed_export_lease(&lease)
                || source_identity.4 != outcome.session_binding
                || source_identity.5 != outcome.descriptor_commitment
                || source_identity.6
                    != aos_sandbox_source_provider_protocol::provider_response_artifact_digest_v1(
                        SourceProviderMethod::Acquire,
                        &canonical_response,
                    )
                || graph.provider_attempts.get(&attempt.attempt_id) != Some(&attempt)
                || !graph_retains_pending_source_root_custody(&graph, attempt_reference(&attempt))
                || journal
                    .validate_mount_source_acquisition_snapshot(&committed_snapshot)
                    .is_err()
                || journal.get(&attempt_key).ok().flatten() != Some(attempt_record.as_slice())
            {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            }
            source_root.revalidate(self)?;
            let receipt = crate::descriptor::SourceRootDispositionCommitReceiptV1::from_observed(
                &source_root,
            );
            if !receipt.matches(&source_root) {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            }
            Ok(())
        })();
        match validated {
            Ok(()) => crate::SourceRootPostcommitOutcomeV2::Success(
                crate::SourceRootPostcommitSuccessV2::Received(crate::CommittedSourceRootV1 {
                    observed: source_root,
                }),
            ),
            Err(error) => crate::SourceRootPostcommitOutcomeV2::RecoveryRequired(
                crate::SourceRootPostcommitRecoveryV2::new(
                    error,
                    crate::descriptor::SourceRootPostcommitRecoveryPayloadV2::Received {
                        transaction,
                        outcome,
                        source_root,
                    },
                ),
            ),
        }
    }

    /// Seals a reopened SourceRoot after the recovered Mount disposition commits.
    ///
    /// A failed or ambiguous commit returns `RecoveryRequired`, retaining the
    /// recovered outcome, sole reopened descriptor, and exact transaction.
    pub fn commit_reopened_mount_source_root_v2(
        &mut self,
        journal: &mut aos_sandbox::ProtectedJournalAuthority<'_>,
        transaction: aos_sandbox::JournalTransaction,
        outcome: VerifiedMountProviderOutcomeV2,
        source_root: ReopenedMountSourceRootV2,
    ) -> crate::SourceRootPostcommitOutcomeV2 {
        use aos_sandbox_protocol::mount_source_acquisition_state::{
            ProviderAttemptStateV2, ProviderMethodV2, ProviderQueryOwnerV2, ProviderStatusV2,
            StoredRecordV2, decode_mount_source_state_record_v2,
        };

        let validated = (|| {
            let exact_shape = transaction_has_exact_record_kinds(
                &transaction,
                &[ExactMountRecordKindV2::Attempt],
            ) || transaction_has_exact_record_kinds(
                &transaction,
                &[
                    ExactMountRecordKindV2::Attempt,
                    ExactMountRecordKindV2::Acquisition,
                    ExactMountRecordKindV2::Head,
                ],
            );
            if !exact_shape {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            }
            self.revalidate()?;
            source_root
                .revalidate()
                .map_err(|error| self.poison(error))?;
            let (attempt_key, attempt_record) = exact_put_record(&transaction, |key, value| {
                matches!(
                    aos_sandbox_protocol::mount_source_acquisition_state::decode_mount_source_state_record_v2(key, value),
                    Ok(aos_sandbox_protocol::mount_source_acquisition_state::StoredRecordV2::ProviderQueryAttempt { .. })
                )
            })
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            let committed_snapshot =
                if journal.get(&attempt_key).ok().flatten() == Some(attempt_record.as_slice()) {
                    validated_mount_state(journal).map_err(|error| self.poison(error))?;
                    journal
                        .snapshot()
                        .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?
                } else {
                    commit_or_read_exact_mount_transaction(journal, &transaction)
                        .map_err(|error| self.poison(error))?
                };
            let graph = validated_mount_state(journal).map_err(|error| self.poison(error))?;
            let attempt = match decode_mount_source_state_record_v2(&attempt_key, &attempt_record) {
                Ok(StoredRecordV2::ProviderQueryAttempt { value }) => value,
                _ => return Err(self.poison(SourceProviderSecurityError::SessionContinuity)),
            };
            let ProviderAttemptStateV2::DispositionConsumed {
                response_sequence,
                verification_anchor,
                status,
                signed_status,
                signed_result,
                ..
            } = &attempt.state
            else {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            };
            let ProviderQueryOwnerV2::Acquire { acquisition_id } = attempt.owner else {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            };
            let signed_status =
                SignedSourceProviderStatusV1::from_canonical_bytes(signed_status)
                    .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            let canonical_response = encode_acquire_response(
                &AcquireSourceResponseV1::new(
                    signed_status,
                    (!signed_result.is_empty()).then_some(signed_result.clone()),
                )
                .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?,
            );
            let committed_session_binding = graph
                .provider_sessions
                .get(&attempt.session_id)
                .map(|session| ObjectDigest::from_bytes(session.session_binding))
                .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            let committed_lease = decode_acquire_response(&canonical_response)
                .ok()
                .and_then(|response| response.signed_receipt().map(ToOwned::to_owned))
                .and_then(|bytes| SignedSourceProviderReceiptV1::from_canonical_bytes(&bytes).ok())
                .and_then(|receipt| {
                    SignedSourceExportLeaseV1::from_canonical_bytes(
                        receipt.subject().signed_export_lease(),
                    )
                    .ok()
                })
                .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            if attempt.method != ProviderMethodV2::Acquire
                || *status != ProviderStatusV2::Complete
                || *response_sequence != outcome.response_sequence
                || *verification_anchor != outcome.verification_anchor
                || outcome.status != SourceProviderStatus::Complete
                || outcome.canonical_response != canonical_response
                || !graph_retains_pending_source_root_custody(&graph, attempt_reference(&attempt))
                || outcome.acquisition_id != Some(ObjectDigest::from_bytes(acquisition_id))
                || outcome.session_binding != committed_session_binding
                || source_root.acquisition_id != acquisition_id
                || source_root.acquisition_sequence
                    != attempt
                        .provider_acquisition
                        .map(|value| value.acquisition_sequence)
                        .unwrap_or(0)
                || source_root.lease_id != committed_lease.subject().lease_id()
                || source_root.lease_digest != digest_signed_export_lease(&committed_lease)
                || source_root.session_binding != outcome.session_binding
                || source_root.descriptor_commitment != outcome.descriptor_commitment
                || source_root.signed_outcome_digest
                    != aos_sandbox_source_provider_protocol::provider_response_artifact_digest_v1(
                        SourceProviderMethod::Acquire,
                        &canonical_response,
                    )
                || graph.provider_attempts.get(&attempt.attempt_id) != Some(&attempt)
                || journal
                    .validate_mount_source_acquisition_snapshot(&committed_snapshot)
                    .is_err()
                || journal.get(&attempt_key).ok().flatten() != Some(attempt_record.as_slice())
            {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            }
            source_root
                .revalidate()
                .map_err(|error| self.poison(error))?;
            self.revalidate()
        })();
        match validated {
            Ok(()) => crate::SourceRootPostcommitOutcomeV2::Success(
                crate::SourceRootPostcommitSuccessV2::Reopened(
                    CommittedReopenedMountSourceRootV2 {
                        reopened: source_root,
                    },
                ),
            ),
            Err(error) => crate::SourceRootPostcommitOutcomeV2::RecoveryRequired(
                crate::SourceRootPostcommitRecoveryV2::new(
                    error,
                    crate::descriptor::SourceRootPostcommitRecoveryPayloadV2::Reopened {
                        transaction,
                        outcome,
                        source_root,
                    },
                ),
            ),
        }
    }

    /// Seals descriptor custody after Mount commits the exact custodied row.
    ///
    /// A failed or ambiguous commit returns `RecoveryRequired`, retaining the
    /// sole descriptor and exact transaction for resealing.
    pub fn commit_mount_source_root_custody_v2(
        &mut self,
        journal: &mut aos_sandbox::ProtectedJournalAuthority<'_>,
        transaction: aos_sandbox::JournalTransaction,
        prepared: crate::PreparedMountSourceRootCustodyV2,
    ) -> crate::SourceRootPostcommitOutcomeV2 {
        let validated = (|| {
            prepared
                .manager_presence
                .as_ref()
                .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?
                .validate_current(journal)
                .map_err(|error| self.poison(error))?;
            if !transaction_has_exact_record_kinds(
                &transaction,
                &[ExactMountRecordKindV2::Acquisition],
            ) {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            }
            prepared.observed.revalidate_for_session(self)?;
            let committed_snapshot = commit_or_read_exact_mount_transaction(journal, &transaction)
                .map_err(|error| self.poison(error))?;
            let (acquisition_key, acquisition_record) = exact_put_record(
                &transaction,
                |key, value| {
                    matches!(
                        aos_sandbox_protocol::mount_source_acquisition_state::decode_mount_source_state_record_v2(key, value),
                        Ok(aos_sandbox_protocol::mount_source_acquisition_state::StoredRecordV2::Acquisition { .. })
                    )
                },
            )
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            let identities = validate_lifecycle_row(
                journal,
                &committed_snapshot,
                &acquisition_key,
                &acquisition_record,
                &prepared.projection,
                LifecycleStageV2::DescriptorCustodied,
            )
            .map_err(|error| self.poison(error))?;
            prepared.observed.revalidate_for_session(self)?;
            Ok(identities)
        })();
        match validated {
            Ok((mount_acquisition_id, source_realization_handle)) => {
                crate::SourceRootPostcommitOutcomeV2::Success(
                    crate::SourceRootPostcommitSuccessV2::DescriptorCustodied(
                        crate::MountSourceRootCustodyV2 {
                            projection: lifecycle_projection_with_mount_id(
                                &prepared.projection,
                                mount_acquisition_id,
                                source_realization_handle,
                            ),
                            observed: prepared.observed,
                            manager_presence: prepared.manager_presence,
                        },
                    ),
                )
            }
            Err(error) => crate::SourceRootPostcommitOutcomeV2::RecoveryRequired(
                crate::SourceRootPostcommitRecoveryV2::new(
                    error,
                    crate::descriptor::SourceRootPostcommitRecoveryPayloadV2::Lifecycle {
                        transaction,
                        observed: prepared.observed,
                        projection: prepared.projection,
                        manager_presence: prepared.manager_presence,
                        expected_phase:
                            crate::descriptor::SourceRootPostcommitPhaseV2::DescriptorCustodied,
                    },
                ),
            ),
        }
    }

    /// Atomically rebinds startup descriptor custody without changing its held phase.
    ///
    /// A failed or ambiguous commit returns `RecoveryRequired` with the sole
    /// descriptor and exact transaction. The same transaction is safe to pass
    /// back through [`Self::reseal_mount_source_root_postcommit_v2`].
    #[must_use]
    pub fn commit_startup_mount_source_adoption_v2(
        &mut self,
        journal: &mut aos_sandbox::ProtectedJournalAuthority<'_>,
        transaction: aos_sandbox::JournalTransaction,
        prepared: crate::PreparedStartupMountSourceAdoptionV2,
    ) -> crate::SourceRootPostcommitOutcomeV2 {
        use aos_sandbox_protocol::mount_source_acquisition_state::{
            StoredRecordV2, decode_mount_source_state_record_v2,
        };

        let validated = (|| {
            if !transaction_has_exact_record_kinds(
                &transaction,
                &[ExactMountRecordKindV2::Acquisition],
            ) {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            }
            prepared.observed.revalidate_for_session(self)?;
            let (acquisition_key, acquisition_record) =
                exact_put_record(&transaction, |key, value| {
                    matches!(
                        decode_mount_source_state_record_v2(key, value),
                        Ok(StoredRecordV2::Acquisition { .. })
                    )
                })
                .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            let next =
                match decode_mount_source_state_record_v2(&acquisition_key, &acquisition_record) {
                    Ok(StoredRecordV2::Acquisition { value }) => value,
                    _ => return Err(self.poison(SourceProviderSecurityError::SessionContinuity)),
                };
            let next_effective_phase = if next.phase
                == aos_sandbox_protocol::mount_source_acquisition_state::SourceAcquisitionPhaseV2::Faulted
            {
                next.faulted_from
            } else {
                Some(next.phase)
            };
            if next.acquisition_id != prepared.predecessor.id
                || prepared.predecessor.revision.checked_add(1) != Some(next.revision)
                || next_effective_phase != Some(prepared.effective_phase)
                || next.manager_custody != prepared.projection.manager_custody()
                || next.manager_custody_loss.is_some()
                || next.descriptor_custody_digest
                    != Some(*prepared.descriptor_custody_digest.as_bytes())
                || next.positive_custody_digest
                    != prepared
                        .positive_custody_digest
                        .map(|digest| *digest.as_bytes())
            {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            }
            let current_record = journal
                .mount_source_acquisition_get(&acquisition_key)
                .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            if current_record != Some(acquisition_record.as_slice()) {
                let current = current_record
                    .and_then(|record| {
                        decode_mount_source_state_record_v2(&acquisition_key, record).ok()
                    })
                    .and_then(|record| match record {
                        StoredRecordV2::Acquisition { value } => Some(value),
                        _ => None,
                    })
                    .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
                if current.revision != prepared.predecessor.revision
                    || current.record_digest != prepared.predecessor.record_digest
                {
                    return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
                }
            }
            let snapshot = commit_or_read_exact_mount_transaction(journal, &transaction)
                .map_err(|error| self.poison(error))?;
            let graph = validated_mount_state(journal).map_err(|error| self.poison(error))?;
            if graph.acquisitions.get(&next.acquisition_id) != Some(&next)
                || journal
                    .validate_mount_source_acquisition_snapshot(&snapshot)
                    .is_err()
                || journal
                    .mount_source_acquisition_get(&acquisition_key)
                    .ok()
                    .flatten()
                    != Some(acquisition_record.as_slice())
            {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            }
            prepared.observed.revalidate_for_session(self)
        })();

        match validated {
            Ok(()) => match startup_adoption_capability(prepared) {
                Ok(capability) => crate::SourceRootPostcommitOutcomeV2::Success(
                    crate::SourceRootPostcommitSuccessV2::StartupAdopted(capability),
                ),
                Err(prepared) => crate::SourceRootPostcommitOutcomeV2::RecoveryRequired(
                    crate::SourceRootPostcommitRecoveryV2::new(
                        self.poison(SourceProviderSecurityError::SessionContinuity),
                        crate::descriptor::SourceRootPostcommitRecoveryPayloadV2::Lifecycle {
                            transaction,
                            observed: prepared.observed,
                            projection: prepared.projection,
                            manager_presence: Some(prepared.manager_presence),
                            expected_phase:
                                crate::descriptor::SourceRootPostcommitPhaseV2::StartupAdoption {
                                    predecessor: prepared.predecessor,
                                    effective_phase: prepared.effective_phase,
                                    descriptor_custody_digest: prepared.descriptor_custody_digest,
                                    positive_custody_digest: prepared.positive_custody_digest,
                                    cleanup_only: prepared.cleanup_only,
                                },
                        },
                    ),
                ),
            },
            Err(error) => crate::SourceRootPostcommitOutcomeV2::RecoveryRequired(
                crate::SourceRootPostcommitRecoveryV2::new(
                    error,
                    crate::descriptor::SourceRootPostcommitRecoveryPayloadV2::Lifecycle {
                        transaction,
                        observed: prepared.observed,
                        projection: prepared.projection,
                        manager_presence: Some(prepared.manager_presence),
                        expected_phase:
                            crate::descriptor::SourceRootPostcommitPhaseV2::StartupAdoption {
                                predecessor: prepared.predecessor,
                                effective_phase: prepared.effective_phase,
                                descriptor_custody_digest: prepared.descriptor_custody_digest,
                                positive_custody_digest: prepared.positive_custody_digest,
                                cleanup_only: prepared.cleanup_only,
                            },
                    },
                ),
            ),
        }
    }

    /// Seals Active custody after Mount commits exact positive readback.
    ///
    /// A failed or ambiguous commit returns `RecoveryRequired`, retaining the
    /// sole descriptor and exact transaction for resealing.
    pub fn commit_active_mount_source_root_v2(
        &mut self,
        journal: &mut aos_sandbox::ProtectedJournalAuthority<'_>,
        transaction: aos_sandbox::JournalTransaction,
        prepared: crate::PreparedActiveMountSourceRootV2,
    ) -> crate::SourceRootPostcommitOutcomeV2 {
        let validated = (|| {
            if !transaction_has_exact_record_kinds(
                &transaction,
                &[ExactMountRecordKindV2::Acquisition],
            ) {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            }
            prepared
                .observed
                .revalidate_retained()
                .map_err(|error| self.poison(error))?;
            self.revalidate()?;
            let committed_snapshot = commit_or_read_exact_mount_transaction(journal, &transaction)
                .map_err(|error| self.poison(error))?;
            let (acquisition_key, acquisition_record) = exact_put_record(
                &transaction,
                |key, value| {
                    matches!(
                        aos_sandbox_protocol::mount_source_acquisition_state::decode_mount_source_state_record_v2(key, value),
                        Ok(aos_sandbox_protocol::mount_source_acquisition_state::StoredRecordV2::Acquisition { .. })
                    )
                },
            )
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            validate_lifecycle_row(
                journal,
                &committed_snapshot,
                &acquisition_key,
                &acquisition_record,
                &prepared.projection,
                LifecycleStageV2::Active,
            )
            .map_err(|error| self.poison(error))?;
            prepared
                .observed
                .revalidate_retained()
                .map_err(|error| self.poison(error))?;
            self.revalidate()
        })();
        match validated {
            Ok(()) => crate::SourceRootPostcommitOutcomeV2::Success(
                crate::SourceRootPostcommitSuccessV2::Active(crate::ActiveMountSourceRootV2 {
                    observed: prepared.observed,
                    projection: prepared.projection,
                    manager_presence: prepared.manager_presence,
                }),
            ),
            Err(error) => crate::SourceRootPostcommitOutcomeV2::RecoveryRequired(
                crate::SourceRootPostcommitRecoveryV2::new(
                    error,
                    crate::descriptor::SourceRootPostcommitRecoveryPayloadV2::Lifecycle {
                        transaction,
                        observed: prepared.observed,
                        projection: prepared.projection,
                        manager_presence: prepared.manager_presence,
                        expected_phase: crate::descriptor::SourceRootPostcommitPhaseV2::Active,
                    },
                ),
            ),
        }
    }

    /// Seals retained custody after Mount atomically commits source consumption.
    ///
    /// A failed or ambiguous composite commit returns `RecoveryRequired`,
    /// retaining the sole descriptor and exact transaction for resealing.
    pub fn commit_mount_source_consumption_v2(
        &mut self,
        journal: &mut aos_sandbox::MountSourceConsumptionJournalAuthorityV1<'_>,
        transaction: aos_sandbox::JournalTransaction,
        prepared: crate::PreparedMountSourceConsumptionV2,
    ) -> crate::SourceRootPostcommitOutcomeV2 {
        let mut retained_predecessor = None;
        let committed = (|| {
            prepared
                .observed
                .revalidate_retained()
                .map_err(|error| self.poison(error))?;
            self.revalidate()?;
            let first_record = transaction
                .records()
                .first()
                .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            let acquisition_key = first_record.key().to_vec();
            let acquisition_record = first_record
                .value()
                .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?
                .to_vec();
            let predecessor_record = journal
                .get(&acquisition_key)
                .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?
                .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?
                .to_vec();
            retained_predecessor = Some(predecessor_record.clone());
            let predecessor_snapshot = journal
                .snapshot()
                .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            validate_lifecycle_row(
                journal,
                &predecessor_snapshot,
                &acquisition_key,
                &predecessor_record,
                &prepared.projection,
                LifecycleStageV2::Active,
            )
            .map_err(|error| self.poison(error))?;

            let prospective_graph = aos_sandbox_protocol::mount_source_acquisition_state::validate_mount_source_state_graph_v2(
                journal
                    .records()
                    .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?
                    .filter(|(key, _)| *key != acquisition_key.as_slice())
                    .chain(core::iter::once((
                        acquisition_key.as_slice(),
                        acquisition_record.as_slice(),
                    ))),
            )
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            validate_lifecycle_row_in_graph(
                &prospective_graph,
                &acquisition_key,
                &acquisition_record,
                &prepared.projection,
                LifecycleStageV2::Consumed,
            )
            .map_err(|error| self.poison(error))?;
            if !consumption_transaction_id_is_exact(
                &transaction,
                &acquisition_key,
                &acquisition_record,
            ) {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            }

            let preflight = journal
                .preflight(&transaction)
                .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            if !consumption_projection_matches(
                &acquisition_key,
                &acquisition_record,
                &prepared.projection,
                preflight.companion_projection(),
            ) {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            }
            prepared
                .observed
                .revalidate_retained()
                .map_err(|error| self.poison(error))?;
            self.revalidate()?;
            let receipt = journal
                .commit(preflight, &transaction)
                .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            journal
                .validate_receipt(&receipt)
                .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            if !consumption_projection_matches(
                &acquisition_key,
                &acquisition_record,
                &prepared.projection,
                receipt.companion_projection(),
            ) {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            }
            let committed_snapshot = journal
                .snapshot()
                .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            validate_lifecycle_row(
                journal,
                &committed_snapshot,
                &acquisition_key,
                &acquisition_record,
                &prepared.projection,
                LifecycleStageV2::Consumed,
            )
            .map_err(|error| self.poison(error))?;
            prepared
                .observed
                .revalidate_retained()
                .map_err(|error| self.poison(error))?;
            self.revalidate()
        })();
        match committed {
            Ok(()) => crate::SourceRootPostcommitOutcomeV2::Success(
                crate::SourceRootPostcommitSuccessV2::Consumed(crate::ConsumedMountSourceRootV2 {
                    observed: prepared.observed,
                    projection: prepared.projection,
                    manager_presence: prepared.manager_presence,
                }),
            ),
            Err(error) => crate::SourceRootPostcommitOutcomeV2::RecoveryRequired(
                crate::SourceRootPostcommitRecoveryV2::new(
                    error,
                    crate::descriptor::SourceRootPostcommitRecoveryPayloadV2::Consumption {
                        transaction,
                        predecessor_record: retained_predecessor,
                        observed: prepared.observed,
                        projection: prepared.projection,
                        manager_presence: prepared.manager_presence,
                    },
                ),
            ),
        }
    }

    /// Seals purpose-limited Release authority after Mount commits its fence.
    ///
    /// A failed or ambiguous commit returns `RecoveryRequired`, retaining both
    /// the sole descriptor and exact prepared request authorization.
    pub fn commit_mount_source_release_v2(
        &mut self,
        journal: &mut aos_sandbox::ProtectedJournalAuthority<'_>,
        transaction: aos_sandbox::JournalTransaction,
        prepared: crate::PreparedMountSourceReleaseV2,
        request: PreparedMountProviderRequestV2,
    ) -> crate::SourceRootPostcommitOutcomeV2 {
        let validated = (|| {
            if !transaction_has_exact_record_kinds(
                &transaction,
                &[
                    ExactMountRecordKindV2::Attempt,
                    ExactMountRecordKindV2::Acquisition,
                    ExactMountRecordKindV2::Head,
                ],
            ) {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            }
            let (prospective_acquisition_key, prospective_acquisition_record) = exact_put_record(
                &transaction,
                |key, value| {
                    matches!(
                        aos_sandbox_protocol::mount_source_acquisition_state::decode_mount_source_state_record_v2(key, value),
                        Ok(aos_sandbox_protocol::mount_source_acquisition_state::StoredRecordV2::Acquisition { .. })
                    )
                },
            )
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            let already_applied = journal
                .mount_source_acquisition_get(&prospective_acquisition_key)
                .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?
                == Some(prospective_acquisition_record.as_slice());
            if !already_applied {
                prepared.custody.validate_before_commit(journal, self)?;
            }
            self.revalidate()?;
            let committed_snapshot = commit_or_read_exact_mount_transaction(journal, &transaction)
                .map_err(|error| self.poison(error))?;
            let (acquisition_key, acquisition_record) = exact_put_record(
                &transaction,
                |key, value| {
                    matches!(
                        aos_sandbox_protocol::mount_source_acquisition_state::decode_mount_source_state_record_v2(key, value),
                        Ok(aos_sandbox_protocol::mount_source_acquisition_state::StoredRecordV2::Acquisition { .. })
                    )
                },
            )
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            let (attempt_key, attempt_record) = exact_put_record(&transaction, |key, value| {
                matches!(
                    aos_sandbox_protocol::mount_source_acquisition_state::decode_mount_source_state_record_v2(key, value),
                    Ok(aos_sandbox_protocol::mount_source_acquisition_state::StoredRecordV2::ProviderQueryAttempt { .. })
                )
            })
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            let (head_key, head_record) = exact_put_record(&transaction, |key, value| {
                matches!(
                    aos_sandbox_protocol::mount_source_acquisition_state::decode_mount_source_state_record_v2(key, value),
                    Ok(aos_sandbox_protocol::mount_source_acquisition_state::StoredRecordV2::ProviderHead { .. })
                )
            })
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            validate_lifecycle_row(
                journal,
                &committed_snapshot,
                &acquisition_key,
                &acquisition_record,
                &prepared.projection,
                LifecycleStageV2::Releasing,
            )
            .map_err(|error| self.poison(error))?;
            prepared.custody.validate_after_commit(self)?;
            self.revalidate()?;
            request
                .validate_protected_reservation(
                    journal,
                    &committed_snapshot,
                    &attempt_key,
                    &attempt_record,
                    &head_key,
                    &head_record,
                )
                .map_err(|error| self.poison(error))?;
            let attempt = match aos_sandbox_protocol::mount_source_acquisition_state::decode_mount_source_state_record_v2(&attempt_key, &attempt_record) {
                Ok(aos_sandbox_protocol::mount_source_acquisition_state::StoredRecordV2::ProviderQueryAttempt { value }) => value,
                _ => return Err(self.poison(SourceProviderSecurityError::SessionContinuity)),
            };
            Ok((
                committed_snapshot,
                attempt_key,
                attempt_record,
                head_key,
                head_record,
                attempt.session_id,
                attempt.attempt_id,
            ))
        })();
        match validated {
            Ok((
                snapshot,
                attempt_key,
                attempt_record,
                head_key,
                head_record,
                session_id,
                attempt_id,
            )) => crate::SourceRootPostcommitOutcomeV2::Success(
                crate::SourceRootPostcommitSuccessV2::Releasing(
                    crate::CommittedMountSourceReleaseV2 {
                        release_authority: crate::MountSourceReleaseAuthorityV2 {
                            custody: prepared.custody,
                            projection: prepared.projection,
                        },
                        reserved_request: request.bind_reserved(
                            snapshot,
                            attempt_key,
                            attempt_record,
                            head_key,
                            head_record,
                            session_id,
                            attempt_id,
                        ),
                    },
                ),
            ),
            Err(error) => crate::SourceRootPostcommitOutcomeV2::RecoveryRequired(
                crate::SourceRootPostcommitRecoveryV2::new(
                    error,
                    crate::descriptor::SourceRootPostcommitRecoveryPayloadV2::Release {
                        transaction,
                        custody: prepared.custody,
                        projection: prepared.projection,
                        request,
                    },
                ),
            ),
        }
    }

    /// Seals exact Released state after manager descriptor custody was closed.
    ///
    /// A failed or ambiguous commit returns `RecoveryRequired`, retaining the
    /// sole manager-negative proof and exact transaction for resealing.
    pub fn commit_released_mount_source_root_v2(
        &mut self,
        journal: &mut aos_sandbox::ProtectedJournalAuthority<'_>,
        transaction: aos_sandbox::JournalTransaction,
        prepared: crate::PreparedReleasedMountSourceRootV2,
    ) -> crate::NegativeCustodyPostcommitOutcomeV2 {
        let validated = (|| {
            if !transaction_has_exact_record_kinds(
                &transaction,
                &[ExactMountRecordKindV2::Acquisition],
            ) {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            }
            self.revalidate()?;
            let committed_snapshot = commit_or_read_exact_mount_transaction(journal, &transaction)
                .map_err(|error| self.poison(error))?;
            let (acquisition_key, acquisition_record) = exact_put_record(
                &transaction,
                |key, value| {
                    matches!(
                        aos_sandbox_protocol::mount_source_acquisition_state::decode_mount_source_state_record_v2(key, value),
                        Ok(aos_sandbox_protocol::mount_source_acquisition_state::StoredRecordV2::Acquisition { .. })
                    )
                },
            )
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            validate_lifecycle_row(
                journal,
                &committed_snapshot,
                &acquisition_key,
                &acquisition_record,
                &prepared.projection,
                LifecycleStageV2::Released(prepared.negative_custody_digest),
            )
            .map_err(|error| self.poison(error))?;
            self.revalidate()
        })();
        match validated {
            Ok(()) => crate::NegativeCustodyPostcommitOutcomeV2::Success(
                crate::ReleasedMountSourceRootV2 {
                    projection: prepared.projection,
                    negative_custody_digest: prepared.negative_custody_digest,
                },
            ),
            Err(error) => crate::NegativeCustodyPostcommitOutcomeV2::RecoveryRequired(
                crate::NegativeCustodyPostcommitRecoveryV2 {
                    error,
                    transaction,
                    prepared,
                },
            ),
        }
    }

    /// Reseals sole SourceRoot custody against exact durable postcommit state.
    ///
    /// A poisoned or crashed owner passes the opaque recovery value to a freshly
    /// authenticated session. The method never repeats a composite commit when
    /// its exact Consumed successor is already current.
    #[must_use]
    pub fn reseal_mount_source_root_postcommit_v2(
        &mut self,
        journal: &mut aos_sandbox::ProtectedJournalAuthority<'_>,
        recovery: crate::SourceRootPostcommitRecoveryV2,
    ) -> crate::SourceRootPostcommitOutcomeV2 {
        use crate::descriptor::{
            SourceRootPostcommitPhaseV2, SourceRootPostcommitRecoveryPayloadV2,
        };

        match recovery.into_payload() {
            SourceRootPostcommitRecoveryPayloadV2::Received {
                transaction,
                outcome,
                source_root,
            } => self.commit_received_mount_source_root_v2(
                journal,
                transaction,
                outcome,
                source_root,
            ),
            SourceRootPostcommitRecoveryPayloadV2::Reopened {
                transaction,
                outcome,
                source_root,
            } => self.commit_reopened_mount_source_root_v2(
                journal,
                transaction,
                outcome,
                source_root,
            ),
            SourceRootPostcommitRecoveryPayloadV2::Lifecycle {
                transaction,
                observed,
                projection,
                manager_presence,
                expected_phase,
            } => match expected_phase {
                SourceRootPostcommitPhaseV2::DescriptorCustodied => self
                    .commit_mount_source_root_custody_v2(
                        journal,
                        transaction,
                        crate::PreparedMountSourceRootCustodyV2 {
                            observed,
                            projection,
                            manager_presence,
                        },
                    ),
                SourceRootPostcommitPhaseV2::Active => self.commit_active_mount_source_root_v2(
                    journal,
                    transaction,
                    crate::PreparedActiveMountSourceRootV2 {
                        observed,
                        projection,
                        manager_presence,
                    },
                ),
                SourceRootPostcommitPhaseV2::StartupAdoption {
                    predecessor,
                    effective_phase,
                    descriptor_custody_digest,
                    positive_custody_digest,
                    cleanup_only,
                } => {
                    let Some(manager_presence) = manager_presence else {
                        return crate::SourceRootPostcommitOutcomeV2::RecoveryRequired(
                            crate::SourceRootPostcommitRecoveryV2::new(
                                self.poison(SourceProviderSecurityError::SessionContinuity),
                                SourceRootPostcommitRecoveryPayloadV2::Lifecycle {
                                    transaction,
                                    observed,
                                    projection,
                                    manager_presence: None,
                                    expected_phase: SourceRootPostcommitPhaseV2::StartupAdoption {
                                        predecessor,
                                        effective_phase,
                                        descriptor_custody_digest,
                                        positive_custody_digest,
                                        cleanup_only,
                                    },
                                },
                            ),
                        );
                    };
                    self.commit_startup_mount_source_adoption_v2(
                        journal,
                        transaction,
                        crate::PreparedStartupMountSourceAdoptionV2 {
                            observed,
                            projection,
                            manager_presence,
                            predecessor,
                            effective_phase,
                            descriptor_custody_digest,
                            positive_custody_digest,
                            cleanup_only,
                        },
                    )
                }
            },
            SourceRootPostcommitRecoveryPayloadV2::Release {
                transaction,
                custody,
                projection,
                request,
            } => self.commit_mount_source_release_v2(
                journal,
                transaction,
                crate::PreparedMountSourceReleaseV2 {
                    custody,
                    projection,
                },
                request,
            ),
            SourceRootPostcommitRecoveryPayloadV2::Consumption {
                transaction,
                predecessor_record,
                observed,
                projection,
                manager_presence,
            } => crate::SourceRootPostcommitOutcomeV2::RecoveryRequired(
                crate::SourceRootPostcommitRecoveryV2::new(
                    self.poison(SourceProviderSecurityError::SessionContinuity),
                    SourceRootPostcommitRecoveryPayloadV2::Consumption {
                        transaction,
                        predecessor_record,
                        observed,
                        projection,
                        manager_presence,
                    },
                ),
            ),
        }
    }

    /// Reseals an exact composite source consumption through the fixed owner.
    #[must_use]
    #[doc(hidden)]
    pub fn reseal_mount_source_consumption_postcommit_v2(
        &mut self,
        journal: &mut aos_sandbox::MountSourceConsumptionJournalAuthorityV1<'_>,
        recovery: crate::SourceRootPostcommitRecoveryV2,
    ) -> crate::SourceRootPostcommitOutcomeV2 {
        use crate::descriptor::SourceRootPostcommitRecoveryPayloadV2;

        let (transaction, predecessor_record, observed, projection, manager_presence) =
            match recovery.into_payload() {
                SourceRootPostcommitRecoveryPayloadV2::Consumption {
                    transaction,
                    predecessor_record,
                    observed,
                    projection,
                    manager_presence,
                } => (
                    transaction,
                    predecessor_record,
                    observed,
                    projection,
                    manager_presence,
                ),
                payload => {
                    return crate::SourceRootPostcommitOutcomeV2::RecoveryRequired(
                        crate::SourceRootPostcommitRecoveryV2::new(
                            self.poison(SourceProviderSecurityError::SessionContinuity),
                            payload,
                        ),
                    );
                }
            };
        let target = transaction.records().first().and_then(|record| {
            record
                .value()
                .map(|value| (record.key().to_vec(), value.to_vec()))
        });
        let committed_projection = journal
            .validate_committed(
                &transaction,
                predecessor_record.as_deref().unwrap_or_default(),
            )
            .ok()
            .filter(|_| predecessor_record.is_some());
        if let Some((key, value)) = target.filter(|_| {
            committed_projection.as_ref().is_some_and(|current| {
                consumption_projection_matches(
                    transaction.records()[0].key(),
                    transaction.records()[0].value().unwrap_or_default(),
                    &projection,
                    current,
                )
            })
        }) {
            let sealed = (|| {
                let snapshot = journal
                    .snapshot()
                    .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
                validate_lifecycle_row(
                    journal,
                    &snapshot,
                    &key,
                    &value,
                    &projection,
                    LifecycleStageV2::Consumed,
                )
                .map_err(|error| self.poison(error))?;
                observed
                    .revalidate_retained()
                    .map_err(|error| self.poison(error))?;
                self.revalidate()
            })();
            return match sealed {
                Ok(()) => crate::SourceRootPostcommitOutcomeV2::Success(
                    crate::SourceRootPostcommitSuccessV2::Consumed(
                        crate::ConsumedMountSourceRootV2 {
                            observed,
                            projection,
                            manager_presence,
                        },
                    ),
                ),
                Err(error) => crate::SourceRootPostcommitOutcomeV2::RecoveryRequired(
                    crate::SourceRootPostcommitRecoveryV2::new(
                        error,
                        SourceRootPostcommitRecoveryPayloadV2::Consumption {
                            transaction,
                            predecessor_record,
                            observed,
                            projection,
                            manager_presence,
                        },
                    ),
                ),
            };
        }
        if journal
            .contains_transaction(transaction.id())
            .unwrap_or(true)
        {
            let error = self.poison(SourceProviderSecurityError::SessionContinuity);
            return crate::SourceRootPostcommitOutcomeV2::RecoveryRequired(
                crate::SourceRootPostcommitRecoveryV2::new(
                    error,
                    SourceRootPostcommitRecoveryPayloadV2::Consumption {
                        transaction,
                        predecessor_record,
                        observed,
                        projection,
                        manager_presence,
                    },
                ),
            );
        }
        self.commit_mount_source_consumption_v2(
            journal,
            transaction,
            crate::PreparedMountSourceConsumptionV2 {
                observed,
                projection,
                manager_presence,
            },
        )
    }

    /// Revalidates a sealed composite outcome before delayed in-memory publication.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] unless the success is Consumed,
    /// the exact transaction remains durably proven and current in all four
    /// namespaces, and its predecessor and custody projection still correlate.
    #[doc(hidden)]
    pub fn validate_sealed_mount_source_consumption_v2(
        &mut self,
        journal: &aos_sandbox::MountSourceConsumptionJournalAuthorityV1<'_>,
        success: &crate::SourceRootPostcommitSuccessV2,
        transaction: &aos_sandbox::JournalTransaction,
        predecessor_record: &[u8],
    ) -> Result<(), SourceProviderSecurityError> {
        let crate::SourceRootPostcommitSuccessV2::Consumed(consumed) = success else {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        };
        let first = transaction
            .records()
            .first()
            .and_then(|record| record.value().map(|value| (record.key(), value)))
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let companions = journal
            .validate_committed(transaction, predecessor_record)
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        if !consumption_projection_matches(first.0, first.1, &consumed.projection, &companions) {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        if !consumption_transaction_id_is_exact(transaction, first.0, first.1) {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        consumed
            .observed
            .revalidate_retained()
            .map_err(|error| self.poison(error))?;
        self.revalidate()
    }

    /// Reseals a retained manager-negative proof against exact Released state.
    #[must_use]
    pub fn reseal_negative_custody_postcommit_v2(
        &mut self,
        journal: &mut aos_sandbox::ProtectedJournalAuthority<'_>,
        recovery: crate::NegativeCustodyPostcommitRecoveryV2,
    ) -> crate::NegativeCustodyPostcommitOutcomeV2 {
        self.commit_released_mount_source_root_v2(journal, recovery.transaction, recovery.prepared)
    }

    fn verify_provider_outcome_bytes_v2(
        &mut self,
        catalog_journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        authorization: &AuthorizedMountProviderOutcomeV2,
        canonical_response: Vec<u8>,
        source_root_observation: Option<
            aos_sandbox_source_provider_protocol::SourceRootObservationV1,
        >,
    ) -> Result<VerifiedMountProviderOutcomeV2, SourceProviderSecurityError> {
        self.revalidate()?;
        let verification_started = super::current_unix_seconds()?;
        if verification_started < 0
            || (authorization.deadline_policy == OutcomeDeadlinePolicyV2::Fresh
                && verification_started >= authorization.deadline_seconds)
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        if (authorization.method == SourceProviderMethod::Inventory)
            != authorization.inventory_correlations.is_some()
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        let mount_session_id = authorization
            .mount_session_id
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let mount_attempt_id = authorization
            .mount_attempt_id
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let canonical_response_digest =
            aos_sandbox_source_provider_protocol::provider_response_artifact_digest_v1(
                authorization.method,
                &canonical_response,
            );
        let historical_verification_time = match authorization.verification_anchor {
            Some(anchor) => {
                if authorization.deadline_policy != OutcomeDeadlinePolicyV2::RetainedReplay
                    || anchor.verification_started_seconds < 0
                    || anchor.verification_completed_seconds
                        < anchor.verification_started_seconds
                    || anchor.verification_completed_seconds >= authorization.deadline_seconds
                    || anchor.kernel_boot_id != authorization.kernel_boot_id
                    || anchor.trusted_clock_evidence_digest
                        != *authorization.trusted_clock_evidence_digest.as_bytes()
                    || aos_sandbox_protocol::mount_source_acquisition_state::outcome_verification_anchor_digest_v2(
                        &anchor,
                        mount_session_id,
                        mount_attempt_id,
                        authorization.request_sequence,
                        authorization.expected_response_sequence,
                        *canonical_response_digest.as_bytes(),
                    ) != anchor.anchor_digest
                {
                    return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
                }
                anchor.verification_completed_seconds
            }
            None => {
                if authorization.deadline_policy != OutcomeDeadlinePolicyV2::Fresh {
                    return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
                }
                verification_started
            }
        };
        let mut cleanup_only_current_policy = authorization.cleanup_only_current_policy;
        match (
            authorization.method,
            authorization.current_catalog_head_commitment,
            authorization.catalog_floor.as_ref(),
        ) {
            (SourceProviderMethod::Acquire, Some(expected), Some(catalog_floor)) => {
                let configuration = crate::RevalidatedProviderConfigurationV1::capture_root_mount(
                    &mut self.custody,
                    verification_started,
                )
                .map_err(|error| self.poison(error))?;
                let catalog_cleanup_only = match authorization.deadline_policy {
                    OutcomeDeadlinePolicyV2::Fresh => crate::catalog::current_catalog_head_matches(
                        &configuration,
                        catalog_journal,
                        expected,
                    )
                    .then_some(false),
                    OutcomeDeadlinePolicyV2::RetainedReplay => {
                        crate::catalog::retained_catalog_head_cleanup_status(
                            &configuration,
                            catalog_journal,
                            expected,
                            catalog_floor,
                            historical_verification_time,
                        )
                    }
                };
                let Some(catalog_cleanup_only) = catalog_cleanup_only else {
                    return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
                };
                cleanup_only_current_policy |= catalog_cleanup_only;
            }
            (SourceProviderMethod::Acquire, _, _) | (_, Some(_), _) => {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            }
            (_, None, None) => {}
            (_, None, Some(_)) => {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            }
        }
        let (signed_status, artifact) = match authorization.method {
            SourceProviderMethod::Acquire => {
                let response = decode_acquire_response(&canonical_response)
                    .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
                if encode_acquire_response(&response) != canonical_response {
                    return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
                }
                (
                    response.signed_status().clone(),
                    response.signed_receipt().map(ToOwned::to_owned),
                )
            }
            SourceProviderMethod::Release => {
                let response = decode_release_response(&canonical_response)
                    .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
                if encode_release_response(&response) != canonical_response {
                    return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
                }
                (
                    response.signed_status().clone(),
                    response.signed_receipt().map(ToOwned::to_owned),
                )
            }
            SourceProviderMethod::Inventory => {
                let response = decode_inventory_response(&canonical_response)
                    .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
                if encode_inventory_response(&response) != canonical_response {
                    return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
                }
                (
                    response.signed_status().clone(),
                    response.signed_inventory().map(ToOwned::to_owned),
                )
            }
            SourceProviderMethod::Hello => {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            }
        };
        let status = signed_status.subject();
        let expected_descriptor_commitment = source_root_observation
            .as_ref()
            .map(aos_sandbox_source_provider_protocol::source_root_descriptor_commitment_v1)
            .unwrap_or_else(
                aos_sandbox_source_provider_protocol::empty_descriptor_set_commitment_v1,
            );
        let current_authorization_matches = authorization.historical_session.is_some()
            || (authorization.provider == *self.custody.inner().provider_authority().authority()
                && authorization.holder == *self.custody.inner().root_authority().authority()
                && &authorization.provider_outcome_signer
                    == self.custody.inner().provider_authority().traffic_signer()
                && self.custody.inner().trust().keys().iter().any(|entry| {
                    entry.signer() == &authorization.provider_outcome_signer
                        && entry.state()
                            == aos_sandbox_source_provider_protocol::SourceProviderKeyTrustStateV1::Eligible
                })
                && authorization.session_binding == self.session.binding());
        let historical_authorization_matches = authorization
            .historical_session
            .as_ref()
            .is_none_or(|session| {
                session.scope.holder_authority_id == authorization.holder.authority_id()
                    && session.root_mount_authority_generation
                        == authorization.holder.authority_generation()
                    && session.root_mount_authority_digest
                        == *authorization.holder.authority_digest().as_bytes()
                    && session.scope.provider_authority_id == authorization.provider.authority_id()
                    && session.provider_authority_generation
                        == authorization.provider.authority_generation()
                    && session.provider_authority_digest
                        == *authorization.provider.authority_digest().as_bytes()
                    && session.session_binding == *authorization.session_binding.as_bytes()
                    && session.provider_process_instance == authorization.provider_process_instance
                    && session.signers[3].public_key == authorization.provider_outcome_public_key
                    && session.signers[3].key_id == authorization.provider_outcome_signer.key_id()
                    && session.signers[3].key_generation
                        == authorization.provider_outcome_signer.key_generation()
            });
        if signed_status.signer() != &authorization.provider_outcome_signer
            || !current_authorization_matches
            || !historical_authorization_matches
            || status.method() != authorization.method
            || status.request_id() != authorization.request_id
            || status.signed_request_digest() != authorization.signed_request_digest
            || status.session_binding() != authorization.session_binding
            || status.provider_process_instance() != authorization.provider_process_instance
            || status.response_sequence() != authorization.expected_response_sequence
            || status.descriptor_commitment() != expected_descriptor_commitment
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        verify_response_status(&signed_status, &authorization.provider_outcome_public_key)
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        if response_result_digest_v1(authorization.method, status.status(), artifact.as_deref())
            != status.result_digest()
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        let mut terminal_lineages = Vec::new();
        match (authorization.method, artifact.as_deref()) {
            (SourceProviderMethod::Acquire, Some(receipt_bytes)) => {
                let receipt = SignedSourceProviderReceiptV1::from_canonical_bytes(receipt_bytes)
                    .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
                let lease = SignedSourceExportLeaseV1::from_canonical_bytes(
                    receipt.subject().signed_export_lease(),
                )
                .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
                let lease_public_key = if let Some(selection_floor) =
                    authorization.selection_floor.as_ref()
                {
                    let configuration =
                        crate::RevalidatedProviderConfigurationV1::capture_root_mount(
                            &mut self.custody,
                            verification_started,
                        )
                        .map_err(|error| self.poison(error))?;
                    if lease.signer() != selection_floor.outcome_signer() {
                        return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
                    }
                    if authorization.deadline_policy == OutcomeDeadlinePolicyV2::RetainedReplay {
                        let (key, cleanup_only) = historical_recovery_verification_key(
                            &configuration,
                            lease.signer(),
                            lease.subject().issued_seconds(),
                            selection_floor.trust_generation(),
                            selection_floor.trust_digest(),
                            selection_floor.revocation_generation(),
                            selection_floor.revocation_digest(),
                        )
                        .map_err(|error| self.poison(error))?;
                        cleanup_only_current_policy |= cleanup_only;
                        *key
                    } else {
                        *historical_verification_key(
                            &configuration,
                            lease.signer(),
                            lease.subject().issued_seconds(),
                            selection_floor.trust_generation(),
                            selection_floor.trust_digest(),
                            selection_floor.revocation_generation(),
                            selection_floor.revocation_digest(),
                        )
                        .map_err(|error| self.poison(error))?
                    }
                } else if let Some(session) = authorization.historical_session.as_ref() {
                    let retained_outcome_signer = &session.signers[3];
                    if lease.signer().authority_id() != retained_outcome_signer.authority_id
                        || lease.signer().authority_generation()
                            != retained_outcome_signer.authority_generation
                        || lease.signer().authority_digest().as_bytes()
                            != &retained_outcome_signer.authority_digest
                        || lease.signer().key_id() != retained_outcome_signer.key_id
                        || lease.signer().key_generation() != retained_outcome_signer.key_generation
                        || lease.signer().public_key_digest().as_bytes()
                            != &retained_outcome_signer.public_key_fingerprint
                        || lease.signer().usage() != SourceProviderKeyUsageV1::ProviderOutcome
                    {
                        return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
                    }
                    let configuration =
                        crate::RevalidatedProviderConfigurationV1::capture_root_mount(
                            &mut self.custody,
                            verification_started,
                        )
                        .map_err(|error| self.poison(error))?;
                    let (key, cleanup_only) = historical_recovery_verification_key(
                        &configuration,
                        lease.signer(),
                        lease.subject().issued_seconds(),
                        session.trust_generation,
                        ObjectDigest::from_bytes(session.trust_digest),
                        session.revocation_generation,
                        ObjectDigest::from_bytes(session.revocation_digest),
                    )
                    .map_err(|error| self.poison(error))?;
                    cleanup_only_current_policy |= cleanup_only;
                    *key
                } else if lease.signer() == &authorization.provider_outcome_signer {
                    authorization.provider_outcome_public_key
                } else {
                    self.custody
                        .inner()
                        .trust()
                        .keys()
                        .iter()
                        .find(|entry| {
                            entry.signer() == lease.signer()
                                && entry.state() == SourceProviderKeyTrustStateV1::Eligible
                        })
                        .map(|entry| *entry.public_key())
                        .ok_or_else(|| {
                            self.poison(SourceProviderSecurityError::SessionContinuity)
                        })?
                };
                verify_provider_receipt_and_lease(
                    &receipt,
                    &authorization.provider_outcome_public_key,
                    &lease_public_key,
                )
                .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
                if receipt.subject().request_id() != authorization.request_id
                    || receipt.subject().request_digest() != authorization.typed_request_digest
                    || Some(receipt.subject().acquisition_id()) != authorization.acquisition_id
                    || lease.subject().expires_seconds() > authorization.deadline_seconds
                    || lease.subject().provider() != &authorization.provider
                    || lease.subject().holder_authority_id() != authorization.holder.authority_id()
                    || lease.subject().holder_generation()
                        != authorization.holder.authority_generation()
                    || lease.subject().holder_authority_digest()
                        != authorization.holder.authority_digest()
                {
                    return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
                }
                let request = decode_acquire_request(authorization.signed_request.subject())
                    .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
                let catalog_floor = authorization
                    .catalog_floor
                    .as_ref()
                    .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
                let context = SourceProviderVerificationContextV1::new(
                    historical_verification_time,
                    authorization.deadline_seconds,
                    request.node_id(),
                    request.boot_id(),
                    authorization.holder.authority_id(),
                    authorization.holder.authority_generation(),
                    authorization.holder.authority_digest(),
                    request.revocation_digest(),
                    request.sequence(),
                    authorization.expected_response_sequence,
                )
                .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
                if let Some(historical_session) = authorization.historical_session.as_ref() {
                    verify_historical_acquire_equivalent(
                        &authorization.signed_request,
                        &receipt,
                        &lease,
                        historical_session,
                        &authorization.provider,
                        &authorization.holder,
                        catalog_floor,
                        authorization.selection_floor.as_ref(),
                        historical_verification_time,
                        source_root_observation.as_ref(),
                    )
                    .map_err(|error| self.poison(error))?;
                } else {
                    verify_acquire(
                        &authorization.signed_request,
                        &decode_acquire_response(&canonical_response).map_err(|_| {
                            self.poison(SourceProviderSecurityError::SessionContinuity)
                        })?,
                        &self.session,
                        self.custody.inner().trust(),
                        self.custody.inner().root_authority(),
                        self.custody.inner().provider_authority(),
                        self.custody.inner().route(),
                        catalog_floor,
                        authorization.selection_floor.as_ref(),
                        &context,
                        &[SourceProviderDescriptorRole::SourceRoot],
                        source_root_observation.clone(),
                    )
                    .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
                }
            }
            (SourceProviderMethod::Release, Some(receipt_bytes)) => {
                let receipt = SignedSourceReleaseReceiptV1::from_canonical_bytes(receipt_bytes)
                    .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
                verify_release_receipt(&receipt, &authorization.provider_outcome_public_key)
                    .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
                if receipt.subject().request_id() != authorization.request_id
                    || receipt.subject().request_digest() != authorization.typed_request_digest
                    || Some(receipt.subject().lease_id()) != authorization.lease_id
                    || Some(receipt.subject().lease_digest()) != authorization.lease_digest
                    || receipt.subject().provider() != &authorization.provider
                    || receipt.subject().provider_process_instance()
                        != authorization.provider_process_instance
                {
                    return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
                }
                let (
                    Some(acquisition_id),
                    Some(acquisition_sequence),
                    Some(lease_id),
                    Some(lease_digest),
                ) = (
                    authorization.acquisition_id,
                    authorization.acquisition_sequence,
                    authorization.lease_id,
                    authorization.lease_digest,
                )
                else {
                    return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
                };
                terminal_lineages.push(VerifiedTerminalLineageV2 {
                    acquisition_id,
                    acquisition_sequence,
                    lease_id,
                    lease_digest,
                });
            }
            (SourceProviderMethod::Inventory, Some(inventory_bytes)) => {
                let inventory =
                    SignedSourceProviderInventoryV1::from_canonical_bytes(inventory_bytes)
                        .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
                verify_inventory(&inventory, &authorization.provider_outcome_public_key)
                    .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
                if inventory.subject().request_id() != authorization.request_id
                    || inventory.subject().request_digest() != authorization.typed_request_digest
                    || inventory.subject().provider() != &authorization.provider
                    || inventory.subject().holder_authority_id()
                        != authorization.holder.authority_id()
                    || inventory.subject().holder_generation()
                        != authorization.holder.authority_generation()
                    || inventory.subject().holder_authority_digest()
                        != authorization.holder.authority_digest()
                    || inventory.subject().provider_process_instance()
                        != authorization.provider_process_instance
                {
                    return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
                }
                let correlations = authorization
                    .inventory_correlations
                    .as_ref()
                    .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
                for correlation in &correlations.entries {
                    let matching_entry = inventory.subject().entries().iter().find(|entry| {
                        entry.acquisition_id().as_bytes()
                            == &correlation.provider_acquisition.acquisition_id
                            && correlation
                                .lease_id
                                .is_none_or(|lease_id| entry.lease_id() == lease_id)
                            && correlation
                                .signed_lease_digest
                                .is_none_or(|digest| entry.lease_digest().as_bytes() == &digest)
                    });
                    let expectation_matches = match (correlation.expectation, matching_entry) {
                        (
                            aos_sandbox_protocol::mount_source_acquisition_state::InventoryCorrelationExpectationV2::AbsentOrMatchingActive,
                            None,
                        ) => true,
                        (
                            aos_sandbox_protocol::mount_source_acquisition_state::InventoryCorrelationExpectationV2::AbsentOrMatchingActive,
                            Some(entry),
                        ) => entry.state()
                            == aos_sandbox_source_provider_protocol::InventoryLeaseStateV1::Active,
                        (
                            aos_sandbox_protocol::mount_source_acquisition_state::InventoryCorrelationExpectationV2::PresentActiveOrReaping,
                            Some(entry),
                        ) => matches!(
                            entry.state(),
                            aos_sandbox_source_provider_protocol::InventoryLeaseStateV1::Active
                                | aos_sandbox_source_provider_protocol::InventoryLeaseStateV1::Reaping
                        ),
                        (
                            aos_sandbox_protocol::mount_source_acquisition_state::InventoryCorrelationExpectationV2::ReapingReleasedOrAbsent,
                            Some(entry),
                        ) => matches!(
                            entry.state(),
                            aos_sandbox_source_provider_protocol::InventoryLeaseStateV1::Reaping
                                | aos_sandbox_source_provider_protocol::InventoryLeaseStateV1::Released
                        ),
                        (aos_sandbox_protocol::mount_source_acquisition_state::InventoryCorrelationExpectationV2::ReleasedOrAbsent, Some(entry)) => {
                            entry.state()
                                == aos_sandbox_source_provider_protocol::InventoryLeaseStateV1::Released
                        },
                        (
                            aos_sandbox_protocol::mount_source_acquisition_state::InventoryCorrelationExpectationV2::ReapingReleasedOrAbsent
                            | aos_sandbox_protocol::mount_source_acquisition_state::InventoryCorrelationExpectationV2::ReleasedOrAbsent,
                            None,
                        ) => true,
                        _ => false,
                    };
                    if !expectation_matches {
                        return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
                    }
                    let terminal = match matching_entry {
                        Some(entry) => {
                            entry.state()
                                == aos_sandbox_source_provider_protocol::InventoryLeaseStateV1::Released
                        }
                        None => matches!(
                            correlation.expectation,
                            aos_sandbox_protocol::mount_source_acquisition_state::InventoryCorrelationExpectationV2::ReapingReleasedOrAbsent
                                | aos_sandbox_protocol::mount_source_acquisition_state::InventoryCorrelationExpectationV2::ReleasedOrAbsent
                        ),
                    };
                    let recovery_permits_terminal = authorization
                        .recovered_inventory_terminal_rows
                        .as_ref()
                        .is_none_or(|rows| rows.contains(&correlation.mount_acquisition_id));
                    if terminal && recovery_permits_terminal {
                        let (Some(lease_id), Some(lease_digest)) =
                            (correlation.lease_id, correlation.signed_lease_digest)
                        else {
                            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
                        };
                        terminal_lineages.push(VerifiedTerminalLineageV2 {
                            acquisition_id: ObjectDigest::from_bytes(
                                correlation.provider_acquisition.acquisition_id,
                            ),
                            acquisition_sequence: correlation
                                .provider_acquisition
                                .acquisition_sequence,
                            lease_id,
                            lease_digest: ObjectDigest::from_bytes(lease_digest),
                        });
                    }
                }
            }
            (_, None) if status.status() != SourceProviderStatus::Complete => {
                if source_root_observation.is_some() {
                    return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
                }
            }
            _ => {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            }
        }
        if artifact.is_none() && status.status() == SourceProviderStatus::Complete {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        self.revalidate()?;
        let verification_completed = super::current_unix_seconds()?;
        if verification_completed < verification_started
            || (authorization.deadline_policy == OutcomeDeadlinePolicyV2::Fresh
                && verification_completed >= authorization.deadline_seconds)
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        let verification_anchor = match authorization.verification_anchor {
            Some(anchor) => anchor,
            None => {
                let mut anchor = aos_sandbox_protocol::mount_source_acquisition_state::OutcomeVerificationAnchorV2 {
                    verification_started_seconds: verification_started,
                    verification_completed_seconds: verification_completed,
                    kernel_boot_id: authorization.kernel_boot_id,
                    trusted_clock_evidence_digest:
                        *authorization.trusted_clock_evidence_digest.as_bytes(),
                    anchor_digest: [0; 32],
                };
                anchor.anchor_digest = aos_sandbox_protocol::mount_source_acquisition_state::outcome_verification_anchor_digest_v2(
                    &anchor,
                    mount_session_id,
                    mount_attempt_id,
                    authorization.request_sequence,
                    authorization.expected_response_sequence,
                    *canonical_response_digest.as_bytes(),
                );
                anchor
            }
        };
        Ok(VerifiedMountProviderOutcomeV2 {
            canonical_response,
            status: status.status(),
            result_digest: status.result_digest(),
            descriptor_commitment: status.descriptor_commitment(),
            acquisition_id: authorization.acquisition_id,
            acquisition_sequence: authorization.acquisition_sequence,
            session_binding: authorization.session_binding,
            response_sequence: authorization.expected_response_sequence,
            verification_anchor,
            cleanup_only_current_policy,
            terminal_lineages,
        })
    }
}
