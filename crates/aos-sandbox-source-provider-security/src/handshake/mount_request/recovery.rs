//! Protected post-crash Mount outcome reconstruction.
//!
//! Recovery consumes exact typed AOSMSA02 attempt and session records,
//! reconstructs historical verification authority, and never recreates send
//! or request-signing authority.

use super::*;

impl CurrentRootMountSourceProviderSessionV1 {
    /// Reconstructs terminal Released evidence from one exact protected row.
    ///
    /// This recovery creates no descriptor or effect authority. It only proves
    /// that the complete protected graph still contains the exact Released row
    /// and its manager-negative commitment under the current Root-Mount session.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the session unless
    /// the snapshot, record, acquisition lineage, and terminal projection agree.
    pub fn recover_released_mount_source_root_v2(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        journal_snapshot: aos_sandbox::ProtectedJournalSnapshot,
        acquisition_key: Vec<u8>,
        acquisition_record: Vec<u8>,
    ) -> Result<crate::ReleasedMountSourceRootV2, SourceProviderSecurityError> {
        use aos_sandbox_protocol::mount_source_acquisition_state::{
            ProviderAttemptStateV2, ProviderStatusV2, SourceAcquisitionPhaseV2, StoredRecordV2,
            decode_mount_source_state_record_v2,
        };

        self.revalidate()?;
        let graph = validated_mount_state(journal).map_err(|error| self.poison(error))?;
        let row = match decode_mount_source_state_record_v2(&acquisition_key, &acquisition_record) {
            Ok(StoredRecordV2::Acquisition { value }) => value,
            _ => return Err(self.poison(SourceProviderSecurityError::SessionContinuity)),
        };
        let now = super::current_unix_seconds()?;
        let current_projection =
            super::capture_session_projection(self, now).map_err(|error| self.poison(error))?;
        let current_session = graph
            .provider_sessions
            .values()
            .find(|session| {
                super::stored_mount_session_matches_projection(session, &current_projection)
            })
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let current_head = graph
            .provider_heads
            .get(&(
                row.scope.holder_authority_id,
                row.scope.provider_authority_id,
            ))
            .filter(|head| {
                head.scope == row.scope && head.current_session_id == current_session.session_id
            })
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let negative_custody_digest = row
            .negative_custody_digest
            .filter(|digest| digest != &[0; 32])
            .map(ObjectDigest::from_bytes)
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let evidence = row
            .evidence
            .as_ref()
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let acquire_attempt = graph
            .provider_attempts
            .get(&evidence.acquire_attempt.id)
            .filter(|attempt| {
                attempt.revision == evidence.acquire_attempt.revision
                    && attempt.record_digest == evidence.acquire_attempt.record_digest
                    && matches!(
                        attempt.state,
                        ProviderAttemptStateV2::DispositionConsumed {
                            status: ProviderStatusV2::Complete,
                            ..
                        }
                    )
            })
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let acquire_session = graph
            .provider_sessions
            .get(&acquire_attempt.session_id)
            .filter(|session| session.record_digest == acquire_attempt.session_record_digest)
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let signed_outcome_digest = acquire_response_artifact_digest(acquire_attempt)
            .map_err(|error| self.poison(error))?;
        let projection = crate::descriptor::durable_lifecycle_projection(
            &row,
            ObjectDigest::from_bytes(acquire_session.session_binding),
            signed_outcome_digest,
            4,
        )
        .map_err(|error| self.poison(error))?;
        if row.phase != SourceAcquisitionPhaseV2::Released
            || row.release_proof.is_none()
            || current_head.scope != row.scope
            || graph.acquisitions.get(&row.acquisition_id) != Some(&row)
            || journal
                .validate_mount_source_acquisition_snapshot(&journal_snapshot)
                .is_err()
            || journal.get(&acquisition_key).ok().flatten() != Some(acquisition_record.as_slice())
            || super::outcome::helpers::validate_lifecycle_row_in_graph(
                &graph,
                &acquisition_key,
                &acquisition_record,
                &projection,
                super::outcome::helpers::LifecycleStageV2::Released(negative_custody_digest),
            )
            .is_err()
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        self.revalidate()?;
        Ok(crate::ReleasedMountSourceRootV2 {
            projection,
            negative_custody_digest,
        })
    }

    /// Recovers one exact provider outcome from protected Mount history.
    ///
    /// The verifier revalidates current custody, the namespace-40 snapshot,
    /// exact immutable session and attempt records, historical trust ancestry,
    /// all signatures, response shape, and descriptor cardinality. It performs
    /// no provider I/O and recreates no request, send, or signing authority.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the live session for
    /// stale records, caller-supplied scalar drift, revoked or unauthenticated
    /// historical keys, invalid signatures, or substituted artifacts.
    #[allow(clippy::too_many_arguments)]
    pub fn recover_mount_provider_outcome_v2(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        catalog_journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        journal_snapshot: aos_sandbox::ProtectedJournalSnapshot,
        attempt_key: Vec<u8>,
        attempt_record: Vec<u8>,
        session_key: Vec<u8>,
        session_record: Vec<u8>,
        captured: CapturedMountProviderRecoveryOutcomeV2,
    ) -> Result<RecoveredMountProviderOutcomeV2, SourceProviderSecurityError> {
        let CapturedMountProviderRecoveryOutcomeV2 {
            method: captured_method,
            canonical_signed_status,
            canonical_signed_result,
            source_root: reopened_source_root,
            persisted,
        } = captured;
        self.revalidate()?;
        use aos_sandbox_protocol::mount_source_acquisition_state::{
            ProviderAttemptStateV2, ProviderIntentV2, ProviderMethodV2, ProviderQueryOwnerV2,
            StoredRecordV2, decode_mount_source_state_record_v2,
        };

        let graph = validated_mount_state(journal).map_err(|error| self.poison(error))?;
        let attempt = match decode_mount_source_state_record_v2(&attempt_key, &attempt_record) {
            Ok(StoredRecordV2::ProviderQueryAttempt { value }) => value,
            _ => return Err(self.poison(SourceProviderSecurityError::SessionContinuity)),
        };
        let retained_session =
            match decode_mount_source_state_record_v2(&session_key, &session_record) {
                Ok(StoredRecordV2::ProviderSession { value }) => value,
                _ => return Err(self.poison(SourceProviderSecurityError::SessionContinuity)),
            };
        let attempt_reference = aos_sandbox_protocol::mount_source_acquisition_state::RecordRefV2 {
            id: attempt.attempt_id,
            revision: attempt.revision,
            record_digest: attempt.record_digest,
        };
        let head = graph
            .provider_heads
            .get(&(
                attempt.scope.holder_authority_id,
                attempt.scope.provider_authority_id,
            ))
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let (recovered_response_sequence, deadline_policy, verification_anchor) = match &attempt
            .state
        {
            ProviderAttemptStateV2::Reserved if head.pending_attempt == Some(attempt_reference) => {
                (
                    head.next_response_sequence,
                    if persisted.is_some() {
                        OutcomeDeadlinePolicyV2::RetainedReplay
                    } else {
                        OutcomeDeadlinePolicyV2::Fresh
                    },
                    None,
                )
            }
            ProviderAttemptStateV2::DispositionConsumed {
                response_sequence,
                verification_anchor,
                signed_status,
                signed_result,
                ..
            } if signed_status == &canonical_signed_status
                && signed_result == &canonical_signed_result
                && *response_sequence < head.next_response_sequence =>
            {
                (
                    *response_sequence,
                    OutcomeDeadlinePolicyV2::RetainedReplay,
                    Some(*verification_anchor),
                )
            }
            _ => return Err(self.poison(SourceProviderSecurityError::SessionContinuity)),
        };
        if matches!(
            (&attempt.method, &attempt.state),
            (
                ProviderMethodV2::Acquire,
                ProviderAttemptStateV2::DispositionConsumed {
                    status: aos_sandbox_protocol::mount_source_acquisition_state::ProviderStatusV2::Complete,
                    ..
                }
            )
        ) && !super::outcome::helpers::graph_retains_recoverable_source_root_custody(
            &graph,
            attempt_reference,
        ) {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        if recovered_response_sequence == 0
            || attempt.session_id != retained_session.session_id
            || attempt.session_record_digest != retained_session.record_digest
            || attempt.signer_set_commitment != retained_session.signer_set_commitment
            || attempt.trust_digest != retained_session.trust_digest
            || attempt.revocation_digest != retained_session.revocation_digest
            || attempt.route_digest != retained_session.route_digest
            || attempt.process_execution_digest
                != retained_session.provider_execution.process_execution_digest
            || graph.provider_attempts.get(&attempt.attempt_id) != Some(&attempt)
            || graph.provider_sessions.get(&retained_session.session_id) != Some(&retained_session)
            || journal
                .validate_mount_source_acquisition_snapshot(&journal_snapshot)
                .is_err()
            || journal.get(&attempt_key).ok().flatten() != Some(attempt_record.as_slice())
            || journal.get(&session_key).ok().flatten() != Some(session_record.as_slice())
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }

        let signed_request =
            SignedSourceProviderRequestV1::from_canonical_bytes(&attempt.signed_request)
                .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let (method, request_id, request_sequence, deadline_seconds, typed_request_digest) =
            match attempt.method {
                ProviderMethodV2::Acquire => {
                    let request = decode_acquire_request(signed_request.subject())
                        .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
                    (
                        SourceProviderMethod::Acquire,
                        request.request_id(),
                        request.sequence(),
                        request.deadline_seconds(),
                        digest_acquire_request(&request),
                    )
                }
                ProviderMethodV2::Release => {
                    let request = aos_sandbox_source_provider_protocol::decode_release_request(
                        signed_request.subject(),
                    )
                    .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
                    let (sequence, request_id) = request.request_identity();
                    (
                        SourceProviderMethod::Release,
                        request_id,
                        sequence,
                        request.deadline_seconds(),
                        digest_release_request(&request),
                    )
                }
                ProviderMethodV2::Inventory => {
                    let request = aos_sandbox_source_provider_protocol::decode_inventory_request(
                        signed_request.subject(),
                    )
                    .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
                    let (sequence, request_id) = request.request_identity();
                    (
                        SourceProviderMethod::Inventory,
                        request_id,
                        sequence,
                        request.deadline_seconds(),
                        digest_inventory_request(&request),
                    )
                }
            };
        if captured_method != method {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        let verification_anchor = match (verification_anchor, persisted.as_ref()) {
            (Some(anchor), _) => Some(anchor),
            (None, Some(persisted)) => {
                if persisted.method != method
                    || persisted.signed_request_digest != attempt.signed_request_digest
                    || persisted.deadline_seconds != deadline_seconds
                    || persisted.completed_at_seconds < 0
                    || persisted.completed_at_seconds >= deadline_seconds
                {
                    return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
                }
                let mut anchor = aos_sandbox_protocol::mount_source_acquisition_state::OutcomeVerificationAnchorV2 {
                    verification_started_seconds: persisted.completed_at_seconds,
                    verification_completed_seconds: persisted.completed_at_seconds,
                    kernel_boot_id: retained_session.kernel_boot_id,
                    trusted_clock_evidence_digest:
                        retained_session.trusted_clock_evidence_digest,
                    anchor_digest: [0; 32],
                };
                anchor.anchor_digest = aos_sandbox_protocol::mount_source_acquisition_state::outcome_verification_anchor_digest_v2(
                    &anchor,
                    attempt.session_id,
                    attempt.attempt_id,
                    request_sequence,
                    recovered_response_sequence,
                    persisted.response_digest,
                );
                Some(anchor)
            }
            (None, None) => None,
        };
        let (catalog_floor, selection_floor, current_catalog_head_commitment) = match (
            &attempt.method,
            &attempt.acquire_verification_floor,
        ) {
            (ProviderMethodV2::Acquire, Some(floor)) => {
                let (catalog, selection) =
                    aos_sandbox_protocol::mount_source_acquisition_state::protocol_acquire_verification_floor_v2(floor)
                        .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
                (
                    Some(catalog),
                    selection,
                    floor
                        .current_catalog_head_commitment
                        .map(ObjectDigest::from_bytes),
                )
            }
            (ProviderMethodV2::Acquire, None) => {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            }
            (_, None) => (None, None, None),
            (_, Some(_)) => {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            }
        };
        let holder = SourceProviderAuthorityV1::new(
            retained_session.scope.holder_authority_id,
            retained_session.root_mount_authority_generation,
            ObjectDigest::from_bytes(retained_session.root_mount_authority_digest),
        )
        .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let provider = SourceProviderAuthorityV1::new(
            retained_session.scope.provider_authority_id,
            retained_session.provider_authority_generation,
            ObjectDigest::from_bytes(retained_session.provider_authority_digest),
        )
        .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let signer = &retained_session.signers[3];
        let provider_outcome_signer = SourceProviderSigningKeyV1::new(
            signer.authority_id,
            signer.authority_generation,
            ObjectDigest::from_bytes(signer.authority_digest),
            signer.key_id,
            signer.key_generation,
            ObjectDigest::from_bytes(signer.public_key_fingerprint),
            SourceProviderKeyUsageV1::ProviderOutcome,
        )
        .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let configuration = crate::RevalidatedProviderConfigurationV1::capture_root_mount(
            &mut self.custody,
            super::current_unix_seconds()?,
        )
        .map_err(|error| self.poison(error))?;
        let (historical_key, outcome_signer_cleanup_only) = historical_recovery_verification_key(
            &configuration,
            &provider_outcome_signer,
            verification_anchor
                .map(|anchor| anchor.verification_completed_seconds)
                .unwrap_or(retained_session.authenticated_at_seconds),
            retained_session.trust_generation,
            ObjectDigest::from_bytes(retained_session.trust_digest),
            retained_session.revocation_generation,
            ObjectDigest::from_bytes(retained_session.revocation_digest),
        )
        .map_err(|error| self.poison(error))?;
        let root_record_signer = &retained_session.signers[1];
        let root_record_signer_reference = SourceProviderSigningKeyV1::new(
            root_record_signer.authority_id,
            root_record_signer.authority_generation,
            ObjectDigest::from_bytes(root_record_signer.authority_digest),
            root_record_signer.key_id,
            root_record_signer.key_generation,
            ObjectDigest::from_bytes(root_record_signer.public_key_fingerprint),
            SourceProviderKeyUsageV1::RootMountRecord,
        )
        .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let (historical_root_key, request_signer_cleanup_only) =
            historical_recovery_verification_key(
                &configuration,
                &root_record_signer_reference,
                retained_session.authenticated_at_seconds,
                retained_session.trust_generation,
                ObjectDigest::from_bytes(retained_session.trust_digest),
                retained_session.revocation_generation,
                ObjectDigest::from_bytes(retained_session.revocation_digest),
            )
            .map_err(|error| self.poison(error))?;
        verify_request(&signed_request, historical_root_key)
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        if historical_key != &signer.public_key
            || historical_root_key != &root_record_signer.public_key
            || signed_request.signer().authority_id() != root_record_signer.authority_id
            || signed_request.signer().authority_generation()
                != root_record_signer.authority_generation
            || signed_request.signer().authority_digest().as_bytes()
                != &root_record_signer.authority_digest
            || signed_request.signer().key_id() != root_record_signer.key_id
            || signed_request.signer().key_generation() != root_record_signer.key_generation
            || signed_request.signer().usage() != SourceProviderKeyUsageV1::RootMountRecord
            || signed_request.method() != method
            || attempt.request_id != request_id
            || attempt.request_sequence != request_sequence
            || attempt.signed_request_digest != *digest_signed_request(&signed_request).as_bytes()
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }

        let (acquisition_id, lease_id, lease_digest) = match (&attempt.owner, &attempt.intent) {
            (
                ProviderQueryOwnerV2::Acquire { acquisition_id },
                ProviderIntentV2::Acquire { .. },
            ) => (Some(ObjectDigest::from_bytes(*acquisition_id)), None, None),
            (
                ProviderQueryOwnerV2::Release { acquisition_id },
                ProviderIntentV2::Release { value },
            ) => (
                Some(ObjectDigest::from_bytes(*acquisition_id)),
                Some(value.lease_id),
                Some(ObjectDigest::from_bytes(value.signed_lease_digest)),
            ),
            (ProviderQueryOwnerV2::Inventory, ProviderIntentV2::Inventory { .. }) => {
                (None, None, None)
            }
            _ => return Err(self.poison(SourceProviderSecurityError::SessionContinuity)),
        };
        let inventory_correlations = match (&attempt.intent, &attempt.inventory_correlations) {
            (ProviderIntentV2::Inventory { value }, Some(correlations))
                if value.correlation_digest == correlations.digest =>
            {
                Some(correlations.clone())
            }
            (ProviderIntentV2::Inventory { .. }, _) => {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            }
            (_, None) => None,
            (_, Some(_)) => {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            }
        };
        let recovered_inventory_terminal_rows =
            (method == SourceProviderMethod::Inventory
                && deadline_policy == OutcomeDeadlinePolicyV2::RetainedReplay)
                .then(|| {
                    graph
                        .acquisitions
                        .values()
                        .filter_map(|row| match row.release_proof.as_ref() {
                            Some(aos_sandbox_protocol::mount_source_acquisition_state::ReleaseProofV2::ProviderInventory {
                                attempt: proof_attempt,
                                ..
                            }) if proof_attempt.id == attempt.attempt_id
                                && proof_attempt.revision == attempt.revision
                                && proof_attempt.record_digest == attempt.record_digest =>
                            {
                                Some(row.acquisition_id)
                            }
                            _ => None,
                        })
                        .collect::<std::collections::BTreeSet<_>>()
                });
        let authorization = AuthorizedMountProviderOutcomeV2 {
            signed_request,
            method,
            provider,
            holder,
            provider_outcome_public_key: signer.public_key,
            provider_outcome_signer,
            session_binding: ObjectDigest::from_bytes(retained_session.session_binding),
            provider_process_instance: retained_session.provider_process_instance,
            request_id,
            typed_request_digest,
            signed_request_digest: ObjectDigest::from_bytes(attempt.signed_request_digest),
            expected_response_sequence: recovered_response_sequence,
            request_sequence,
            mount_session_id: Some(attempt.session_id),
            mount_attempt_id: Some(attempt.attempt_id),
            kernel_boot_id: retained_session.kernel_boot_id,
            trusted_clock_evidence_digest: ObjectDigest::from_bytes(
                retained_session.trusted_clock_evidence_digest,
            ),
            verification_anchor,
            acquisition_id,
            acquisition_sequence: attempt
                .provider_acquisition
                .map(|value| value.acquisition_sequence),
            lease_id,
            lease_digest,
            deadline_seconds,
            catalog_floor,
            selection_floor,
            current_catalog_head_commitment,
            deadline_policy,
            cleanup_only_current_policy: outcome_signer_cleanup_only || request_signer_cleanup_only,
            inventory_correlations,
            recovered_inventory_terminal_rows,
            historical_session: Some(retained_session),
        };
        let status = SignedSourceProviderStatusV1::from_canonical_bytes(&canonical_signed_status)
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let artifact = (!canonical_signed_result.is_empty()).then_some(canonical_signed_result);
        let canonical_response = match method {
            SourceProviderMethod::Acquire => encode_acquire_response(
                &AcquireSourceResponseV1::new(status, artifact)
                    .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?,
            ),
            SourceProviderMethod::Release => encode_release_response(
                &ReleaseSourceResponseV1::new(status, artifact)
                    .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?,
            ),
            SourceProviderMethod::Inventory => encode_inventory_response(
                &InventorySourceResponseV1::new(status, artifact)
                    .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?,
            ),
            SourceProviderMethod::Hello => {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            }
        };
        if persisted.as_ref().is_some_and(|persisted| {
            persisted.response_digest
                != *aos_sandbox_source_provider_protocol::provider_response_artifact_digest_v1(
                    method,
                    &canonical_response,
                )
                .as_bytes()
        }) {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        let source_observation = reopened_source_root
            .as_ref()
            .map(crate::ProviderSourceRootHandoffV1::observation)
            .cloned();
        let verified = self.verify_provider_outcome_bytes_v2(
            catalog_journal,
            &authorization,
            canonical_response,
            source_observation,
        )?;
        let source_root = match reopened_source_root {
            Some(handoff) => {
                handoff.revalidate().map_err(|error| self.poison(error))?;
                let response = decode_acquire_response(&verified.canonical_response)
                    .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
                let receipt = response
                    .signed_receipt()
                    .and_then(|bytes| {
                        SignedSourceProviderReceiptV1::from_canonical_bytes(bytes).ok()
                    })
                    .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
                let lease = SignedSourceExportLeaseV1::from_canonical_bytes(
                    receipt.subject().signed_export_lease(),
                )
                .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
                Some(ReopenedMountSourceRootV2 {
                    handoff,
                    acquisition_id: receipt.subject().acquisition_id(),
                    acquisition_sequence: attempt
                        .provider_acquisition
                        .map(|value| value.acquisition_sequence)
                        .ok_or_else(|| {
                            self.poison(SourceProviderSecurityError::SessionContinuity)
                        })?,
                    lease_id: lease.subject().lease_id(),
                    lease_digest: digest_signed_export_lease(&lease),
                    session_binding: verified.session_binding,
                    descriptor_commitment: verified.descriptor_commitment,
                    signed_outcome_digest:
                        aos_sandbox_source_provider_protocol::provider_response_artifact_digest_v1(
                            SourceProviderMethod::Acquire,
                            &verified.canonical_response,
                        ),
                })
            }
            None => None,
        };
        self.revalidate()?;
        Ok(RecoveredMountProviderOutcomeV2 {
            verified,
            source_root,
        })
    }

    /// Authorizes recovery of one exact retained manager-held SourceRoot.
    ///
    /// Once Mount has committed descriptor custody, manager ownership no longer
    /// depends on the provider execution remaining alive. This method proves a
    /// unique authenticated historical-session to current-session ancestry and
    /// binds a fresh one-shot authorization to one exact retained acquisition.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the current session
    /// for a stale snapshot, an invalid acquisition phase, missing or ambiguous
    /// session ancestry, descriptor-negative state, or a successor mismatch.
    pub fn authorize_retained_mount_source_root_recovery_v2(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        journal_snapshot: aos_sandbox::ProtectedJournalSnapshot,
        acquisition_key: Vec<u8>,
        acquisition_record: Vec<u8>,
    ) -> Result<RetainedRootRecoveryAuthorizationV2, SourceProviderSecurityError> {
        use aos_sandbox_protocol::mount_source_acquisition_state::{
            StoredRecordV2, decode_mount_source_state_record_v2,
        };

        self.revalidate()?;
        let now = super::current_unix_seconds()?;
        let current_projection =
            super::capture_session_projection(self, now).map_err(|error| self.poison(error))?;
        let graph = super::validated_mount_state(journal).map_err(|error| self.poison(error))?;
        let row = match decode_mount_source_state_record_v2(&acquisition_key, &acquisition_record) {
            Ok(StoredRecordV2::Acquisition { value }) => value,
            _ => return Err(self.poison(SourceProviderSecurityError::SessionContinuity)),
        };
        let evidence = row
            .evidence
            .as_ref()
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let current_session = graph
            .provider_sessions
            .values()
            .find(|session| {
                super::stored_mount_session_matches_projection(session, &current_projection)
            })
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let predecessor_session = graph
            .provider_sessions
            .get(&evidence.session_id)
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let current_head = graph
            .provider_heads
            .get(&(
                row.scope.holder_authority_id,
                row.scope.provider_authority_id,
            ))
            .filter(|head| head.current_session_id == current_session.session_id)
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let session_ancestry_digest =
            unique_authenticated_session_ancestry(&graph, current_session, predecessor_session)
                .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        if current_session.session_id == predecessor_session.session_id
            || current_head.scope != row.scope
            || !super::outcome::helpers::graph_retains_recoverable_source_root_custody(
                &graph,
                evidence.acquire_attempt,
            )
            || graph.acquisitions.get(&row.acquisition_id) != Some(&row)
            || journal
                .validate_mount_source_acquisition_snapshot(&journal_snapshot)
                .is_err()
            || journal
                .mount_source_acquisition_get(&acquisition_key)
                .ok()
                .flatten()
                != Some(acquisition_record.as_slice())
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        self.revalidate()?;
        Ok(RetainedRootRecoveryAuthorizationV2 {
            journal_snapshot,
            acquisition_key,
            acquisition_record,
            acquisition_record_digest: row.record_digest,
            predecessor_session_id: predecessor_session.session_id,
            current_session_id: current_session.session_id,
            session_ancestry_digest,
        })
    }

    /// Restores manager-held descriptor custody after authenticated provider replacement.
    ///
    /// This consumes an outcome already reconstructed by the unified historical
    /// verifier. The old session is resolved from the protected graph rather
    /// than supplied as scalar authority. Exact successor-session ancestry,
    /// acquisition, lease, descriptor, and lifecycle commitments are checked
    /// before the phase-specific move-only capability is returned.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the current session
    /// for stale records, missing or forked successor ancestry,
    /// negative or terminal custody, descriptor drift, or an unsupported phase.
    #[allow(clippy::too_many_arguments)]
    pub fn recover_retained_mount_source_root_v2(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        authorization: RetainedRootRecoveryAuthorizationV2,
        recovered: RecoveredMountProviderOutcomeV2,
    ) -> Result<crate::RecoveredRetainedMountSourceRootV2, SourceProviderSecurityError> {
        use aos_sandbox_protocol::mount_source_acquisition_state::{
            SourceAcquisitionPhaseV2, StoredRecordV2, decode_mount_source_state_record_v2,
        };

        self.revalidate()?;
        let current_time = super::current_unix_seconds()?;
        let current_projection = super::capture_session_projection(self, current_time)
            .map_err(|error| self.poison(error))?;
        let graph = super::validated_mount_state(journal).map_err(|error| self.poison(error))?;
        let RetainedRootRecoveryAuthorizationV2 {
            journal_snapshot,
            acquisition_key,
            acquisition_record,
            acquisition_record_digest,
            predecessor_session_id,
            current_session_id,
            session_ancestry_digest,
        } = authorization;
        let row = match decode_mount_source_state_record_v2(&acquisition_key, &acquisition_record) {
            Ok(StoredRecordV2::Acquisition { value }) => value,
            _ => return Err(self.poison(SourceProviderSecurityError::SessionContinuity)),
        };
        let evidence = row
            .evidence
            .as_ref()
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let source_root = recovered
            .source_root
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let lease_expires_seconds = decode_acquire_response(&recovered.verified.canonical_response)
            .ok()
            .and_then(|response| response.signed_receipt().map(ToOwned::to_owned))
            .and_then(|bytes| SignedSourceProviderReceiptV1::from_canonical_bytes(&bytes).ok())
            .and_then(|receipt| {
                SignedSourceExportLeaseV1::from_canonical_bytes(
                    receipt.subject().signed_export_lease(),
                )
                .ok()
            })
            .map(|lease| lease.subject().expires_seconds())
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let cleanup_only = row.phase
            == aos_sandbox_protocol::mount_source_acquisition_state::SourceAcquisitionPhaseV2::Faulted
            || current_time >= lease_expires_seconds
            || recovered.verified.cleanup_only_current_policy;
        let current_session = graph
            .provider_sessions
            .values()
            .find(|session| {
                super::stored_mount_session_matches_projection(session, &current_projection)
            })
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let predecessor_session = graph
            .provider_sessions
            .get(&evidence.session_id)
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let current_head = graph
            .provider_heads
            .get(&(
                row.scope.holder_authority_id,
                row.scope.provider_authority_id,
            ))
            .filter(|head| head.current_session_id == current_session.session_id)
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let durable_session_ancestry =
            unique_authenticated_session_ancestry(&graph, current_session, predecessor_session);
        if recovered.verified.method != SourceProviderMethod::Acquire
            || recovered.verified.status != SourceProviderStatus::Complete
            || current_session.session_id == predecessor_session.session_id
            || current_session.session_id != current_session_id
            || predecessor_session.session_id != predecessor_session_id
            || durable_session_ancestry != Some(session_ancestry_digest)
            || row.record_digest != acquisition_record_digest
            || current_head.scope != row.scope
            || row.acquire_terminal_attempt != Some(evidence.acquire_attempt)
            || row.negative_custody_digest.is_some()
            || source_root.acquisition_id.as_bytes() != &row.provider_acquisition.acquisition_id
            || source_root.acquisition_sequence != row.provider_acquisition.acquisition_sequence
            || source_root.lease_id != evidence.lease_id
            || source_root.lease_digest.as_bytes() != &evidence.signed_lease_digest
            || source_root.session_binding.as_bytes() != &predecessor_session.session_binding
            || source_root.descriptor_commitment.as_bytes() != &evidence.descriptor_commitment
            || graph.acquisitions.get(&row.acquisition_id) != Some(&row)
            || journal
                .validate_mount_source_acquisition_snapshot(&journal_snapshot)
                .is_err()
            || journal.get(&acquisition_key).ok().flatten() != Some(acquisition_record.as_slice())
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }

        source_root
            .revalidate()
            .map_err(|error| self.poison(error))?;
        let observed = crate::descriptor::RetainedMountSourceRootV2::Reopened(source_root);
        let mount_id = Some(row.acquisition_id);
        let realization = Some(evidence.source_realization_handle);
        let manager_custody = row
            .manager_custody
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let descriptor_projection = crate::descriptor::lifecycle_projection(
            &observed,
            mount_id,
            realization,
            1,
            Some(manager_custody),
        );
        if row.descriptor_custody_digest
            != Some(*descriptor_projection.lifecycle_commitment().as_bytes())
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        let effective_phase = if row.phase == SourceAcquisitionPhaseV2::Faulted {
            if row.fault_digest.is_none()
                || row.retained_faulted_from.is_some()
                || row.retained_fault_digest.is_some()
                || row.release_proof.is_some()
            {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            }
            row.faulted_from
                .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?
        } else {
            if row.faulted_from.is_some() || row.fault_digest.is_some() {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            }
            row.phase
        };
        let restored = match effective_phase {
            SourceAcquisitionPhaseV2::DescriptorCustodied => {
                if cleanup_only {
                    let projection = crate::descriptor::lifecycle_projection(
                        &observed,
                        mount_id,
                        realization,
                        4,
                        Some(manager_custody),
                    );
                    crate::RecoveredRetainedMountSourceRootV2::CleanupOnly(
                        crate::PreparedMountSourceReleaseV2 {
                            custody: crate::descriptor::ReleaseCustodyV2::Retained {
                                observed,
                                manager_presence: Some(
                                    crate::descriptor::ManagerPresenceAuthorityV2::RecoveredHistorical,
                                ),
                            },
                            projection,
                        },
                    )
                } else {
                    crate::RecoveredRetainedMountSourceRootV2::DescriptorCustodied(
                        crate::MountSourceRootCustodyV2 {
                            observed,
                            projection: descriptor_projection,
                            manager_presence: Some(
                                crate::descriptor::ManagerPresenceAuthorityV2::RecoveredHistorical,
                            ),
                        },
                    )
                }
            }
            SourceAcquisitionPhaseV2::Active => {
                let projection = crate::descriptor::lifecycle_projection(
                    &observed,
                    mount_id,
                    realization,
                    2,
                    Some(manager_custody),
                );
                if row.positive_custody_digest
                    != Some(*projection.lifecycle_commitment().as_bytes())
                {
                    return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
                }
                if cleanup_only {
                    let projection = crate::descriptor::lifecycle_projection(
                        &observed,
                        mount_id,
                        realization,
                        4,
                        Some(manager_custody),
                    );
                    crate::RecoveredRetainedMountSourceRootV2::CleanupOnly(
                        crate::PreparedMountSourceReleaseV2 {
                            custody: crate::descriptor::ReleaseCustodyV2::Retained {
                                observed,
                                manager_presence: Some(
                                    crate::descriptor::ManagerPresenceAuthorityV2::RecoveredHistorical,
                                ),
                            },
                            projection,
                        },
                    )
                } else {
                    crate::RecoveredRetainedMountSourceRootV2::Active(
                        crate::ActiveMountSourceRootV2 {
                            observed,
                            projection,
                            manager_presence: Some(
                                crate::descriptor::ManagerPresenceAuthorityV2::RecoveredHistorical,
                            ),
                        },
                    )
                }
            }
            SourceAcquisitionPhaseV2::Consumed => {
                let positive_projection = crate::descriptor::lifecycle_projection(
                    &observed,
                    mount_id,
                    realization,
                    2,
                    Some(manager_custody),
                );
                let projection = crate::descriptor::lifecycle_projection(
                    &observed,
                    mount_id,
                    realization,
                    3,
                    Some(manager_custody),
                );
                if row.positive_custody_digest
                    != Some(*positive_projection.lifecycle_commitment().as_bytes())
                    || row.consumption.is_none()
                {
                    return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
                }
                if cleanup_only {
                    let projection = crate::descriptor::lifecycle_projection(
                        &observed,
                        mount_id,
                        realization,
                        4,
                        Some(manager_custody),
                    );
                    crate::RecoveredRetainedMountSourceRootV2::CleanupOnly(
                        crate::PreparedMountSourceReleaseV2 {
                            custody: crate::descriptor::ReleaseCustodyV2::Retained {
                                observed,
                                manager_presence: Some(
                                    crate::descriptor::ManagerPresenceAuthorityV2::RecoveredHistorical,
                                ),
                            },
                            projection,
                        },
                    )
                } else {
                    crate::RecoveredRetainedMountSourceRootV2::Consumed(
                        crate::ConsumedMountSourceRootV2 {
                            observed,
                            projection,
                            manager_presence: Some(
                                crate::descriptor::ManagerPresenceAuthorityV2::RecoveredHistorical,
                            ),
                        },
                    )
                }
            }
            SourceAcquisitionPhaseV2::Releasing => {
                let projection = crate::descriptor::lifecycle_projection(
                    &observed,
                    mount_id,
                    realization,
                    4,
                    Some(manager_custody),
                );
                let retained_origin_matches = match row.release_from_phase {
                    Some(SourceAcquisitionPhaseV2::DescriptorCustodied) => {
                        row.positive_custody_digest.is_none() && row.consumption.is_none()
                    }
                    Some(SourceAcquisitionPhaseV2::Active) => {
                        let positive_projection = crate::descriptor::lifecycle_projection(
                            &observed,
                            mount_id,
                            realization,
                            2,
                            Some(manager_custody),
                        );
                        row.positive_custody_digest
                            == Some(*positive_projection.lifecycle_commitment().as_bytes())
                            && row.consumption.is_none()
                    }
                    Some(SourceAcquisitionPhaseV2::Consumed) => {
                        let positive_projection = crate::descriptor::lifecycle_projection(
                            &observed,
                            mount_id,
                            realization,
                            2,
                            Some(manager_custody),
                        );
                        row.positive_custody_digest
                            == Some(*positive_projection.lifecycle_commitment().as_bytes())
                            && row.consumption.is_some()
                    }
                    _ => false,
                };
                if row.release_authority.is_none()
                    || row.release_lineage.is_none()
                    || row.release_proof.is_some()
                    || !retained_origin_matches
                {
                    return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
                }
                crate::RecoveredRetainedMountSourceRootV2::Releasing(
                    crate::MountSourceReleaseAuthorityV2 {
                        custody: crate::descriptor::ReleaseCustodyV2::Retained {
                            observed,
                            manager_presence: Some(
                                crate::descriptor::ManagerPresenceAuthorityV2::RecoveredHistorical,
                            ),
                        },
                        projection,
                    },
                )
            }
            _ => return Err(self.poison(SourceProviderSecurityError::SessionContinuity)),
        };
        self.revalidate()?;
        Ok(restored)
    }

    /// Prepares terminal negative custody from a complete startup absence proof.
    ///
    /// This recovery path is intentionally one-way. It accepts only a current
    /// Releasing (or Faulted-from-Releasing) row whose exact Release/Inventory
    /// proof attempt and historical session were authenticated by the consumed
    /// startup inventory capability. It cannot recreate a descriptor, positive
    /// custody, request-signing authority, or provider send authority.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons this session if the
    /// protected graph, current session ancestry, acquisition evidence,
    /// Release/Inventory proof causality, or absence commitment differs from
    /// the capability minted at startup.
    pub fn prepare_recovered_negative_custody_v2(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        absence: aos_sandbox::mount_manager_startup::TerminalMountSourceAbsenceV1,
    ) -> Result<crate::PreparedReleasedMountSourceRootV2, SourceProviderSecurityError> {
        use aos_sandbox_protocol::mount_source_acquisition_state::{
            AcquisitionRecoveryV2, ProviderAttemptStateV2, ProviderMethodV2, ReleaseProofV2,
            SourceAcquisitionPhaseV2,
        };

        self.revalidate()?;
        absence
            .validate_current(journal)
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let projection = absence.projection().clone();
        let graph = validated_mount_state(journal).map_err(|error| self.poison(error))?;
        let subject = projection.subject;
        let mount_acquisition_id = subject.acquisition_id;
        let row = graph
            .acquisitions
            .get(&mount_acquisition_id)
            .filter(|row| {
                row.revision == subject.acquisition_revision
                    && row.record_digest == subject.acquisition_record_digest
            })
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let evidence = row
            .evidence
            .as_ref()
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let provider_acquisition_id = subject.provider_acquisition_id;
        let provider_sequence = subject.provider_acquisition_sequence;
        let realization_handle = subject.source_realization_handle;
        let descriptor_commitment = subject.descriptor_commitment;
        let source_physical_identity = (
            subject.source_kernel_boot_id,
            subject.source_device,
            subject.source_inode,
            subject.source_unique_mount_id,
            true,
        );
        let lease_id = subject.lease_id;
        let lease_digest = subject.lease_digest;
        let proof_attempt_ref = projection.terminal_proof_attempt;
        let proof_session_id = projection.terminal_proof_session_id;
        let proof_session_digest = projection.terminal_proof_session_digest;
        let dead_manager_attempt_ref = projection.last_custody_attempt;
        let dead_manager_session_id = projection.last_custody_session_id;
        let dead_manager_session_digest = projection.last_custody_session_digest;
        let faulted_releasing = row.phase == SourceAcquisitionPhaseV2::Faulted
            && row.faulted_from == Some(SourceAcquisitionPhaseV2::Releasing);
        let row_proof_ref = match row.release_proof.as_ref() {
            Some(ReleaseProofV2::ProviderReceipt { attempt, .. })
            | Some(ReleaseProofV2::ProviderInventory { attempt, .. }) => *attempt,
            None => return Err(self.poison(SourceProviderSecurityError::SessionContinuity)),
        };
        let proof_attempt = graph
            .provider_attempts
            .get(&proof_attempt_ref.id)
            .filter(|attempt| {
                attempt.revision == proof_attempt_ref.revision
                    && attempt.record_digest == proof_attempt_ref.record_digest
                    && attempt.session_id == proof_session_id
                    && matches!(
                        &attempt.state,
                        ProviderAttemptStateV2::DispositionConsumed {
                            status: aos_sandbox_protocol::mount_source_acquisition_state::ProviderStatusV2::Complete,
                            ..
                        }
                    )
            })
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let proof_session = graph
            .provider_sessions
            .get(&proof_session_id)
            .filter(|session| {
                session.record_digest == proof_session_digest
                    && session.record_digest == proof_attempt.session_record_digest
                    && session.scope == row.scope
            })
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let dead_manager_attempt = graph
            .provider_attempts
            .get(&dead_manager_attempt_ref.id)
            .filter(|attempt| {
                attempt.revision == dead_manager_attempt_ref.revision
                    && attempt.record_digest == dead_manager_attempt_ref.record_digest
                    && attempt.method == ProviderMethodV2::Release
                    && attempt.session_id == dead_manager_session_id
                    && matches!(
                        (&attempt.owner, &attempt.intent),
                        (
                            aos_sandbox_protocol::mount_source_acquisition_state::ProviderQueryOwnerV2::Release { acquisition_id },
                            aos_sandbox_protocol::mount_source_acquisition_state::ProviderIntentV2::Release { value }
                        ) if *acquisition_id == row.acquisition_id
                            && value.acquisition_id == row.acquisition_id
                            && value.provider_acquisition == row.provider_acquisition
                    )
            })
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let dead_manager_session = graph
            .provider_sessions
            .get(&dead_manager_session_id)
            .filter(|session| {
                session.record_digest == dead_manager_session_digest
                    && session.record_digest == dead_manager_attempt.session_record_digest
                    && session.scope == row.scope
            })
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let proof_kind_matches = match (
            &row.release_proof,
            proof_attempt.method,
            &proof_attempt.owner,
            &proof_attempt.intent,
        ) {
            (
                Some(ReleaseProofV2::ProviderReceipt { .. }),
                ProviderMethodV2::Release,
                aos_sandbox_protocol::mount_source_acquisition_state::ProviderQueryOwnerV2::Release { acquisition_id },
                aos_sandbox_protocol::mount_source_acquisition_state::ProviderIntentV2::Release { value }
            ) => {
                *acquisition_id == row.acquisition_id
                    && value.acquisition_id == row.acquisition_id
                    && value.provider_acquisition == row.provider_acquisition
            }
            (
                Some(ReleaseProofV2::ProviderInventory { .. }),
                ProviderMethodV2::Inventory,
                aos_sandbox_protocol::mount_source_acquisition_state::ProviderQueryOwnerV2::Inventory,
                aos_sandbox_protocol::mount_source_acquisition_state::ProviderIntentV2::Inventory { value }
            ) => value.scope == row.scope,
            _ => false,
        };
        let acquire_attempt = graph
            .provider_attempts
            .get(&evidence.acquire_attempt.id)
            .filter(|attempt| {
                attempt.revision == evidence.acquire_attempt.revision
                    && attempt.record_digest == evidence.acquire_attempt.record_digest
                    && attempt.method == ProviderMethodV2::Acquire
                    && attempt.session_id == evidence.session_id
                    && matches!(
                        &attempt.state,
                        ProviderAttemptStateV2::DispositionConsumed {
                            status: aos_sandbox_protocol::mount_source_acquisition_state::ProviderStatusV2::Complete,
                            ..
                        }
                    )
            })
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let acquire_session = graph
            .provider_sessions
            .get(&acquire_attempt.session_id)
            .filter(|session| {
                session.record_digest == acquire_attempt.session_record_digest
                    && session.scope == row.scope
            })
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let now = super::current_unix_seconds().map_err(|error| self.poison(error))?;
        let current_projection =
            super::capture_session_projection(self, now).map_err(|error| self.poison(error))?;
        let current_session = graph
            .provider_sessions
            .values()
            .find(|session| {
                super::stored_mount_session_matches_projection(session, &current_projection)
            })
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let current_head = graph
            .provider_heads
            .get(&(
                row.scope.holder_authority_id,
                row.scope.provider_authority_id,
            ))
            .filter(|head| head.current_session_id == current_session.session_id)
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let proof_session_reachable = proof_session.session_id == current_session.session_id
            || unique_authenticated_session_ancestry(&graph, current_session, proof_session)
                .is_some();
        let death_subject_reachable = dead_manager_session.session_id == proof_session.session_id
            || unique_authenticated_session_ancestry(&graph, proof_session, dead_manager_session)
                .is_some();
        let death_subject_matches = match &row.release_proof {
            Some(ReleaseProofV2::ProviderReceipt { .. }) => {
                dead_manager_attempt_ref == proof_attempt_ref
                    && dead_manager_session.session_id == proof_session.session_id
            }
            Some(ReleaseProofV2::ProviderInventory { .. }) => row
                .release_lineage
                .as_ref()
                .is_some_and(|lineage| lineage.tail == dead_manager_attempt_ref),
            None => false,
        };
        if (!faulted_releasing && row.phase != SourceAcquisitionPhaseV2::Releasing)
            || !matches!(&row.recovery, AcquisitionRecoveryV2::Ready)
            || row.negative_custody_digest.is_some()
            || row_proof_ref != proof_attempt_ref
            || !proof_kind_matches
            || !proof_session_reachable
            || !death_subject_reachable
            || !death_subject_matches
            || current_head.scope != row.scope
            || graph.provider_attempts.values().any(|attempt| {
                matches!(&attempt.state, ProviderAttemptStateV2::Reserved)
                    && matches!(
                        attempt.owner,
                        aos_sandbox_protocol::mount_source_acquisition_state::ProviderQueryOwnerV2::Acquire { acquisition_id }
                            | aos_sandbox_protocol::mount_source_acquisition_state::ProviderQueryOwnerV2::Release { acquisition_id }
                            if acquisition_id == row.acquisition_id
                    )
            })
            || (provider_acquisition_id, provider_sequence)
                != (
                    row.provider_acquisition.acquisition_id,
                    row.provider_acquisition.acquisition_sequence,
                )
            || realization_handle != evidence.source_realization_handle
            || descriptor_commitment != evidence.descriptor_commitment
            || source_physical_identity
                != (
                    evidence.source_kernel_boot_id,
                    evidence.source_device,
                    evidence.source_inode,
                    evidence.source_unique_mount_id,
                    true,
                )
            || (lease_id, lease_digest) != (evidence.lease_id, evidence.signed_lease_digest)
            || projection.capture_id == [0; 32]
            || projection.capture_record_digest == [0; 32]
            || projection.death_commitment == [0; 32]
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }

        let signed_outcome_digest = acquire_response_artifact_digest(acquire_attempt)
            .map_err(|error| self.poison(error))?;
        let descriptor_custody = crate::descriptor::durable_lifecycle_projection(
            row,
            ObjectDigest::from_bytes(acquire_session.session_binding),
            signed_outcome_digest,
            1,
        )
        .map_err(|error| self.poison(error))?;
        let positive_custody = crate::descriptor::durable_lifecycle_projection(
            row,
            ObjectDigest::from_bytes(acquire_session.session_binding),
            signed_outcome_digest,
            2,
        )
        .map_err(|error| self.poison(error))?;
        let custody = crate::descriptor::durable_lifecycle_projection(
            row,
            ObjectDigest::from_bytes(acquire_session.session_binding),
            signed_outcome_digest,
            4,
        )
        .map_err(|error| self.poison(error))?;
        if row.descriptor_custody_digest
            != Some(*descriptor_custody.lifecycle_commitment().as_bytes())
            || match row.release_from_phase {
                Some(SourceAcquisitionPhaseV2::DescriptorCustodied) => {
                    row.positive_custody_digest.is_some() || row.consumption.is_some()
                }
                Some(SourceAcquisitionPhaseV2::Active) => {
                    row.positive_custody_digest
                        != Some(*positive_custody.lifecycle_commitment().as_bytes())
                        || row.consumption.is_some()
                }
                Some(SourceAcquisitionPhaseV2::Consumed) => {
                    row.positive_custody_digest
                        != Some(*positive_custody.lifecycle_commitment().as_bytes())
                        || row.consumption.is_none()
                }
                _ => true,
            }
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        let expected_release_commitment = match row.release_from_phase {
            Some(SourceAcquisitionPhaseV2::DescriptorCustodied)
            | Some(SourceAcquisitionPhaseV2::Active)
            | Some(SourceAcquisitionPhaseV2::Consumed) => custody.lifecycle_commitment(),
            _ => return Err(self.poison(SourceProviderSecurityError::SessionContinuity)),
        };
        let mut hasher = Sha256::new();
        hasher.update(b"aos.sandbox.mount.source-root-recovered-negative-custody.v2\0");
        hasher.update(expected_release_commitment.as_bytes());
        hasher.update(proof_attempt_ref.id);
        hasher.update(proof_attempt_ref.revision.to_be_bytes());
        hasher.update(proof_attempt_ref.record_digest);
        hasher.update(dead_manager_attempt_ref.id);
        hasher.update(dead_manager_attempt_ref.revision.to_be_bytes());
        hasher.update(dead_manager_attempt_ref.record_digest);
        hasher.update(projection.capture_id);
        hasher.update(projection.capture_record_digest);
        hasher.update(projection.death_commitment);
        let negative_custody_digest = ObjectDigest::from_bytes(hasher.finalize().into());
        absence
            .validate_current(journal)
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        self.revalidate()?;
        Ok(crate::PreparedReleasedMountSourceRootV2 {
            projection: custody,
            negative_custody_digest,
            fresh_recovery: None,
        })
    }
}

fn acquire_response_artifact_digest(
    attempt: &aos_sandbox_protocol::mount_source_acquisition_state::SourceProviderQueryAttemptV2,
) -> Result<ObjectDigest, SourceProviderSecurityError> {
    let (signed_status, signed_result) = match &attempt.state {
        aos_sandbox_protocol::mount_source_acquisition_state::ProviderAttemptStateV2::DispositionConsumed {
            status: aos_sandbox_protocol::mount_source_acquisition_state::ProviderStatusV2::Complete,
            signed_status,
            signed_result,
            ..
        } if !signed_result.is_empty() => (signed_status, signed_result),
        _ => return Err(SourceProviderSecurityError::SessionContinuity),
    };
    let status = SignedSourceProviderStatusV1::from_canonical_bytes(signed_status)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let response = AcquireSourceResponseV1::new(status, Some(signed_result.clone()))
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    Ok(
        aos_sandbox_source_provider_protocol::provider_response_artifact_digest_v1(
            SourceProviderMethod::Acquire,
            &encode_acquire_response(&response),
        ),
    )
}

fn unique_authenticated_session_ancestry(
    graph: &aos_sandbox_protocol::mount_source_acquisition_state::MountSourceAcquisitionStateV2,
    current_session: &aos_sandbox_protocol::mount_source_acquisition_state::SourceProviderSessionV2,
    predecessor_session: &aos_sandbox_protocol::mount_source_acquisition_state::SourceProviderSessionV2,
) -> Option<ObjectDigest> {
    if current_session.session_id == predecessor_session.session_id
        || current_session.scope != predecessor_session.scope
    {
        return None;
    }

    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.source-provider.mount-retained-session-ancestry.v1\0");
    hasher.update(current_session.scope.holder_authority_id);
    hasher.update(current_session.scope.provider_authority_id);
    let mut cursor = current_session;
    let mut remaining = graph.provider_sessions.len();
    loop {
        hasher.update(cursor.session_id);
        hasher.update(cursor.record_digest);
        hasher.update(cursor.root_mount_authority_generation.to_be_bytes());
        hasher.update(cursor.root_mount_authority_digest);
        hasher.update(cursor.provider_authority_generation.to_be_bytes());
        hasher.update(cursor.provider_authority_digest);
        hasher.update(cursor.trust_generation.to_be_bytes());
        hasher.update(cursor.trust_digest);
        hasher.update(cursor.revocation_generation.to_be_bytes());
        hasher.update(cursor.revocation_digest);
        if cursor.session_id == predecessor_session.session_id {
            return Some(ObjectDigest::from_bytes(hasher.finalize().into()));
        }
        if remaining == 0 {
            return None;
        }
        remaining -= 1;

        let predecessor_id = cursor.predecessor_session_id?;
        if graph
            .provider_sessions
            .values()
            .filter(|candidate| candidate.predecessor_session_id == Some(predecessor_id))
            .count()
            != 1
        {
            return None;
        }
        let predecessor = graph.provider_sessions.get(&predecessor_id)?;
        let holder_succeeds = cursor.root_mount_authority_generation
            > predecessor.root_mount_authority_generation
            || (cursor.root_mount_authority_generation
                == predecessor.root_mount_authority_generation
                && cursor.root_mount_authority_digest == predecessor.root_mount_authority_digest);
        let provider_succeeds = cursor.provider_authority_generation
            > predecessor.provider_authority_generation
            || (cursor.provider_authority_generation == predecessor.provider_authority_generation
                && cursor.provider_authority_digest == predecessor.provider_authority_digest);
        let trust_succeeds = cursor.trust_generation > predecessor.trust_generation
            || (cursor.trust_generation == predecessor.trust_generation
                && cursor.trust_digest == predecessor.trust_digest);
        let revocation_succeeds = cursor.revocation_generation > predecessor.revocation_generation
            || (cursor.revocation_generation == predecessor.revocation_generation
                && cursor.revocation_digest == predecessor.revocation_digest);
        if predecessor.scope != current_session.scope
            || !holder_succeeds
            || !provider_succeeds
            || !trust_succeeds
            || !revocation_succeeds
        {
            return None;
        }
        cursor = predecessor;
    }
}
