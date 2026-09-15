//! Method-specific completion construction, preflight, and protected commit.

use super::*;

fn completion_status_subject(
    authorization: &super::ProviderOutcomeAuthorizationV1,
    status: SourceProviderStatus,
    result_digest: aos_sandbox_core::ObjectDigest,
    descriptor_commitment: aos_sandbox_core::ObjectDigest,
) -> Result<SourceProviderResponseStatusV1, SourceProviderSecurityError> {
    SourceProviderResponseStatusV1::new(
        authorization.method,
        authorization.request_id,
        authorization.signed_request_digest,
        status,
        authorization.provider_process_instance,
        authorization.session_binding,
        authorization.response_sequence,
        result_digest,
        descriptor_commitment,
    )
    .map_err(|_| SourceProviderSecurityError::SessionContinuity)
}

fn encode_typed_response(
    method: SourceProviderMethod,
    signed_status: SignedSourceProviderStatusV1,
    artifact: Option<Vec<u8>>,
) -> Result<Vec<u8>, SourceProviderSecurityError> {
    match method {
        SourceProviderMethod::Acquire => {
            aos_sandbox_source_provider_protocol::AcquireSourceResponseV1::new(
                signed_status,
                artifact,
            )
            .map(|value| encode_acquire_response(&value))
        }
        SourceProviderMethod::Release => {
            aos_sandbox_source_provider_protocol::ReleaseSourceResponseV1::new(
                signed_status,
                artifact,
            )
            .map(|value| encode_release_response(&value))
        }
        SourceProviderMethod::Inventory => {
            aos_sandbox_source_provider_protocol::InventorySourceResponseV1::new(
                signed_status,
                artifact,
            )
            .map(|value| encode_inventory_response(&value))
        }
        SourceProviderMethod::Hello => {
            Err(aos_sandbox_source_provider_protocol::SourceProviderValidationError::ResponseShape)
        }
    }
    .map_err(|_| SourceProviderSecurityError::SessionContinuity)
}

fn completion_records_for_plan(
    journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
    authorization: &super::ProviderOutcomeAuthorizationV1,
    attempt_key: &[u8],
    response: &[u8],
) -> Result<Vec<(Vec<u8>, Vec<u8>)>, SourceProviderSecurityError> {
    validate_authorization_journal(journal, authorization)?;
    if attempt_key.is_empty()
        || attempt_key_commitment(attempt_key) != authorization.attempt_key_commitment
        || !completion_response_matches(authorization, &response)
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    collect_bounded_current_records(journal)
}

fn collect_bounded_current_records(
    journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>, SourceProviderSecurityError> {
    journal
        .validate_source_provider_authority()
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let records = journal
        .records()
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let mut collected = Vec::new();
    let mut aggregate_bytes = 0_usize;
    let mut record_count = 0_usize;

    for (key, value) in records {
        record_count = record_count
            .checked_add(1)
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        aggregate_bytes = aggregate_bytes
            .checked_add(8)
            .and_then(|total| total.checked_add(key.len()))
            .and_then(|total| total.checked_add(value.len()))
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        if record_count > aos_sandbox_source_provider_ledger::limits::MAXIMUM_LEDGER_RECORDS
            || aggregate_bytes
                > aos_sandbox_source_provider_ledger::limits::MAXIMUM_LEDGER_GRAPH_BYTES
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        collected.push((key.to_vec(), value.to_vec()));
    }
    Ok(collected)
}

fn prepare_finalized_builder(
    session: &mut CurrentProviderIngressSessionV1,
    journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
    authorization: &super::ProviderOutcomeAuthorizationV1,
    finalized: aos_sandbox_source_provider_ledger::FinalizedCompletionV1,
) -> Result<ProviderCompletionBuilderV1, SourceProviderSecurityError> {
    use sha2::{Digest as _, Sha256};

    let response = finalized.response().map(ToOwned::to_owned);
    let method = if response.is_some() {
        finalized.method()
    } else {
        authorization.method
    };
    let session_binding = if response.is_some() {
        finalized.session_binding()
    } else {
        authorization.session_binding
    };
    let response_sequence = if response.is_some() {
        finalized.response_sequence()
    } else {
        authorization.response_sequence
    };
    let purpose = finalized.purpose().to_vec();
    let (mutations, _) = finalized.into_parts();
    if purpose.is_empty()
        || purpose.len() > 128
        || mutations.is_empty()
        || mutations.len() > aos_sandbox_source_provider_ledger::limits::MAXIMUM_TRANSACTION_RECORDS
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    let mut aggregate_bytes = 4_usize
        .checked_add(purpose.len())
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    for (key, value) in &mutations {
        let value_bytes = value.as_ref().map_or(0, Vec::len);
        aggregate_bytes = aggregate_bytes
            .checked_add(4)
            .and_then(|total| total.checked_add(key.len()))
            .and_then(|total| total.checked_add(1 + 4))
            .and_then(|total| total.checked_add(value_bytes))
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    }
    if aggregate_bytes > aos_sandbox_source_provider_ledger::limits::MAXIMUM_TRANSACTION_BYTES {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.source-provider.protected-transaction-id.v1\0");
    hasher.update((purpose.len() as u32).to_be_bytes());
    hasher.update(&purpose);
    for (key, value) in &mutations {
        hasher.update((key.len() as u32).to_be_bytes());
        hasher.update(key);
        match value {
            Some(value) => {
                hasher.update([1]);
                hasher.update((value.len() as u32).to_be_bytes());
                hasher.update(value);
            }
            None => hasher.update([0]),
        }
    }
    let transaction_digest: [u8; 32] = hasher.finalize().into();
    let mut transaction_id = [0_u8; 16];
    transaction_id.copy_from_slice(&transaction_digest[..16]);
    if transaction_id == [0; 16] {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    let records = mutations
        .into_iter()
        .map(|(key, value)| match value {
            Some(value) => aos_sandbox::JournalRecord::put(
                aos_sandbox::RecordNamespace::SourceProviderAuthority,
                key,
                value,
            ),
            None => aos_sandbox::JournalRecord::delete(
                aos_sandbox::RecordNamespace::SourceProviderAuthority,
                key,
            ),
        })
        .collect();
    let transaction = aos_sandbox::JournalTransaction::new(transaction_id, records)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    validate_prospective_completion(journal, &transaction)?;
    let transactions = std::slice::from_ref(&transaction);
    let preflight = match journal.preflight_transactions(transactions) {
        Ok(preflight) => preflight,
        Err(_) => {
            return Err(poison_and_close(
                &mut session.custody,
                &mut session.carrier,
                SourceProviderSecurityError::SessionContinuity,
            ));
        }
    };
    if journal
        .validate_preflight_for_effect(&preflight, transactions)
        .is_err()
    {
        return Err(poison_and_close(
            &mut session.custody,
            &mut session.carrier,
            SourceProviderSecurityError::SessionContinuity,
        ));
    }
    let artifact_commitment = response.as_ref().map_or_else(
        || aos_sandbox_core::ObjectDigest::from_bytes(transaction_digest),
        |response| {
            aos_sandbox_source_provider_protocol::provider_response_artifact_digest_v1(
                method, response,
            )
        },
    );
    Ok(ProviderCompletionBuilderV1 {
        transaction,
        preflight,
        transaction_commitment: aos_sandbox_core::ObjectDigest::from_bytes(transaction_digest),
        artifact_commitment,
        reservation_commitment: authorization.reservation_commitment,
        response_sequence,
        method,
        session_binding,
        response,
    })
}

impl<'session, 'journal, 'authority, 'authorization>
    ProviderOwnerSecurityFacadeV1<'session, 'journal, 'authority, 'authorization>
{
    /// Seals and prepares a status-only completion through exact preflight.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] for Complete status, stale
    /// custody, a plan mismatch, invalid canonical graph, or failed preflight.
    pub fn prepare_acquire_status_completion(
        self,
        plan: aos_sandbox_source_provider_ledger::AcquireStatusCompletionPlanV1,
        status: SourceProviderStatus,
    ) -> Result<ProviderCompletionBuilderV1, SourceProviderSecurityError> {
        if status == SourceProviderStatus::Complete
            || self.authorization.method != SourceProviderMethod::Acquire
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        self.authorization.claim_purpose((1 << 4) | (1 << 5))?;
        let result_digest = response_result_digest_v1(self.authorization.method, status, None);
        let subject = completion_status_subject(
            self.authorization,
            status,
            result_digest,
            empty_descriptor_set_commitment_v1(),
        )?;
        let signed_status =
            self.session
                .sign_current_response_status(self.journal, self.authorization, subject)?;
        let response = encode_typed_response(self.authorization.method, signed_status, None)?;
        let current = completion_records_for_plan(
            self.journal,
            self.authorization,
            plan.attempt_key(),
            &response,
        )?;
        let finalized = plan
            .finalize(
                current
                    .iter()
                    .map(|(key, value)| (key.as_slice(), value.as_slice())),
                response,
                None,
            )
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        prepare_finalized_builder(self.session, self.journal, self.authorization, finalized)
    }

    /// Seals and prepares a status-only Release completion through exact preflight.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] for Complete status, stale
    /// custody, a plan mismatch, invalid canonical graph, or failed preflight.
    pub fn prepare_release_status_completion(
        self,
        plan: aos_sandbox_source_provider_ledger::ReleaseStatusCompletionPlanV1,
        status: SourceProviderStatus,
    ) -> Result<ProviderCompletionBuilderV1, SourceProviderSecurityError> {
        if status == SourceProviderStatus::Complete
            || self.authorization.method != SourceProviderMethod::Release
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        self.authorization.claim_purpose((1 << 4) | (1 << 5))?;
        let result_digest = response_result_digest_v1(self.authorization.method, status, None);
        let subject = completion_status_subject(
            self.authorization,
            status,
            result_digest,
            empty_descriptor_set_commitment_v1(),
        )?;
        let signed_status =
            self.session
                .sign_current_response_status(self.journal, self.authorization, subject)?;
        let response = encode_typed_response(self.authorization.method, signed_status, None)?;
        let current = completion_records_for_plan(
            self.journal,
            self.authorization,
            plan.attempt_key(),
            &response,
        )?;
        let finalized = plan
            .finalize(
                current
                    .iter()
                    .map(|(key, value)| (key.as_slice(), value.as_slice())),
                response,
                None,
            )
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        prepare_finalized_builder(self.session, self.journal, self.authorization, finalized)
    }

    /// Seals and prepares a status-only Inventory completion through exact preflight.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] for Complete status, stale
    /// custody, a plan mismatch, invalid canonical graph, or failed preflight.
    pub fn prepare_inventory_status_completion(
        self,
        plan: aos_sandbox_source_provider_ledger::InventoryStatusCompletionPlanV1,
        status: SourceProviderStatus,
    ) -> Result<ProviderCompletionBuilderV1, SourceProviderSecurityError> {
        if status == SourceProviderStatus::Complete
            || self.authorization.method != SourceProviderMethod::Inventory
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        self.authorization.claim_purpose((1 << 4) | (1 << 5))?;
        let result_digest = response_result_digest_v1(self.authorization.method, status, None);
        let subject = completion_status_subject(
            self.authorization,
            status,
            result_digest,
            empty_descriptor_set_commitment_v1(),
        )?;
        let signed_status =
            self.session
                .sign_current_response_status(self.journal, self.authorization, subject)?;
        let response = encode_typed_response(self.authorization.method, signed_status, None)?;
        let current = completion_records_for_plan(
            self.journal,
            self.authorization,
            plan.attempt_key(),
            &response,
        )?;
        let finalized = plan
            .finalize(
                current
                    .iter()
                    .map(|(key, value)| (key.as_slice(), value.as_slice())),
                response,
                None,
            )
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        prepare_finalized_builder(self.session, self.journal, self.authorization, finalized)
    }

    /// Seals an Acquire lease, receipt, and status through exact preflight.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] for stale custody, lineage or
    /// physical-fact mismatch, invalid canonical graph, or failed preflight.
    pub fn prepare_acquire_completion(
        self,
        plan: aos_sandbox_source_provider_ledger::AcquireCompletionPlanV1,
        lease: SourceExportLeaseV1,
        facts: AcquireReceiptFactsV1,
    ) -> Result<ProviderCompletionBuilderV1, SourceProviderSecurityError> {
        self.authorization
            .claim_purpose((1 << 0) | (1 << 1) | (1 << 4) | (1 << 5))?;
        if self.authorization.method != SourceProviderMethod::Acquire
            || self.authorization.acquisition_id != Some(facts.acquisition_id)
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        let signed_lease =
            self.session
                .sign_current_export_lease(self.journal, self.authorization, lease)?;
        let signed_lease_bytes = signed_lease.to_canonical_bytes();
        let lease_digest = digest_signed_export_lease(&signed_lease);
        let receipt = SourceProviderReceiptV1::new(
            self.authorization.request_id,
            self.authorization.typed_request_digest,
            facts.acquisition_id,
            self.authorization.provider_process_instance,
            lease_digest,
            signed_lease_bytes,
            SourceProviderDescriptorRole::SourceRoot,
            facts.kernel_boot_id,
            facts.device,
            facts.inode,
            facts.unique_mount_id,
            facts.observed_proof_digest,
        )
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        let signed_receipt = self.session.sign_current_provider_receipt(
            self.journal,
            self.authorization,
            receipt,
        )?;
        let signed_receipt_bytes = signed_receipt.to_canonical_bytes();
        let result_digest = response_result_digest_v1(
            SourceProviderMethod::Acquire,
            SourceProviderStatus::Complete,
            Some(&signed_receipt_bytes),
        );
        let status = completion_status_subject(
            self.authorization,
            SourceProviderStatus::Complete,
            result_digest,
            facts.descriptor_commitment,
        )?;
        let signed_status =
            self.session
                .sign_current_response_status(self.journal, self.authorization, status)?;
        let response = encode_typed_response(
            SourceProviderMethod::Acquire,
            signed_status,
            Some(signed_receipt_bytes),
        )?;
        let current = completion_records_for_plan(
            self.journal,
            self.authorization,
            plan.attempt_key(),
            &response,
        )?;
        let finalized = plan
            .finalize(
                current
                    .iter()
                    .map(|(key, value)| (key.as_slice(), value.as_slice())),
                response,
                Some(signed_lease),
            )
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        prepare_finalized_builder(self.session, self.journal, self.authorization, finalized)
    }

    /// Seals a Release receipt and response through exact preflight.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] for stale custody, mismatched
    /// Release lineage, invalid canonical graph, or failed preflight.
    pub fn prepare_release_completion(
        self,
        plan: aos_sandbox_source_provider_ledger::ReleaseCompletionPlanV1,
        receipt: SourceReleaseReceiptV1,
    ) -> Result<ProviderCompletionBuilderV1, SourceProviderSecurityError> {
        self.authorization
            .claim_purpose((1 << 2) | (1 << 4) | (1 << 5))?;
        if self.authorization.method != SourceProviderMethod::Release {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        let signed_receipt =
            self.session
                .sign_current_release_receipt(self.journal, self.authorization, receipt)?;
        let artifact = signed_receipt.to_canonical_bytes();
        let result_digest = response_result_digest_v1(
            SourceProviderMethod::Release,
            SourceProviderStatus::Complete,
            Some(&artifact),
        );
        let status = completion_status_subject(
            self.authorization,
            SourceProviderStatus::Complete,
            result_digest,
            empty_descriptor_set_commitment_v1(),
        )?;
        let signed_status =
            self.session
                .sign_current_response_status(self.journal, self.authorization, status)?;
        let response =
            encode_typed_response(SourceProviderMethod::Release, signed_status, Some(artifact))?;
        let current = completion_records_for_plan(
            self.journal,
            self.authorization,
            plan.attempt_key(),
            &response,
        )?;
        let finalized = plan
            .finalize(
                current
                    .iter()
                    .map(|(key, value)| (key.as_slice(), value.as_slice())),
                response,
                None,
            )
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        prepare_finalized_builder(self.session, self.journal, self.authorization, finalized)
    }

    /// Seals an Inventory artifact and response through exact preflight.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] for stale custody, holder or
    /// catalog mismatch, invalid canonical graph, or failed preflight.
    pub fn prepare_inventory_completion(
        self,
        plan: aos_sandbox_source_provider_ledger::InventoryCompletionPlanV1,
        inventory: SourceProviderInventoryV1,
    ) -> Result<ProviderCompletionBuilderV1, SourceProviderSecurityError> {
        self.authorization
            .claim_purpose((1 << 3) | (1 << 4) | (1 << 5))?;
        if self.authorization.method != SourceProviderMethod::Inventory {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        let signed_inventory =
            self.session
                .sign_current_inventory(self.journal, self.authorization, inventory)?;
        let artifact = signed_inventory.to_canonical_bytes();
        let result_digest = response_result_digest_v1(
            SourceProviderMethod::Inventory,
            SourceProviderStatus::Complete,
            Some(&artifact),
        );
        let status = completion_status_subject(
            self.authorization,
            SourceProviderStatus::Complete,
            result_digest,
            empty_descriptor_set_commitment_v1(),
        )?;
        let signed_status =
            self.session
                .sign_current_response_status(self.journal, self.authorization, status)?;
        let response = encode_typed_response(
            SourceProviderMethod::Inventory,
            signed_status,
            Some(artifact),
        )?;
        let current = completion_records_for_plan(
            self.journal,
            self.authorization,
            plan.attempt_key(),
            &response,
        )?;
        let finalized = plan
            .finalize(
                current
                    .iter()
                    .map(|(key, value)| (key.as_slice(), value.as_slice())),
                response,
                None,
            )
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        prepare_finalized_builder(self.session, self.journal, self.authorization, finalized)
    }

    /// Seals a receipt-only terminal Release recovery through exact preflight.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] for stale custody, mismatched
    /// Release lineage, invalid canonical graph, or failed preflight.
    pub fn prepare_release_recovery_completion(
        self,
        plan: aos_sandbox_source_provider_ledger::ReleaseRecoveryCompletionPlanV1,
        receipt: SourceReleaseReceiptV1,
    ) -> Result<ProviderCompletionBuilderV1, SourceProviderSecurityError> {
        self.authorization.claim_purpose((1 << 2) | (1 << 5))?;
        let signed_receipt =
            self.session
                .sign_current_release_receipt(self.journal, self.authorization, receipt)?;
        let current = collect_bounded_current_records(self.journal)?;
        let finalized = plan
            .finalize(
                current
                    .iter()
                    .map(|(key, value)| (key.as_slice(), value.as_slice())),
                signed_receipt,
            )
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        prepare_finalized_builder(self.session, self.journal, self.authorization, finalized)
    }
}

impl ProviderCompletionBuilderV1 {
    /// Commits the exact sealed completion and returns only opaque durability authority.
    ///
    /// Signed artifacts and response bytes remain inside security custody
    /// across preflight and commit. They become transport-eligible only in the
    /// returned move-only committed outcome.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] when preflight is stale, the
    /// exact protected transaction fails, or postcommit currentness/artifact
    /// retention validation fails.
    pub fn commit(
        self,
        journal: &mut aos_sandbox::ProtectedJournalAuthority<'_>,
        session: &mut CurrentProviderIngressSessionV1,
    ) -> Result<super::CommittedProviderOutcomeV1, SourceProviderSecurityError> {
        let transactions = std::slice::from_ref(&self.transaction);
        if journal
            .validate_preflight_for_effect(&self.preflight, transactions)
            .is_err()
        {
            return Err(poison_and_close(
                &mut session.custody,
                &mut session.carrier,
                SourceProviderSecurityError::SessionContinuity,
            ));
        }
        if journal.commit(&self.transaction).is_err() {
            return Err(poison_and_close(
                &mut session.custody,
                &mut session.carrier,
                SourceProviderSecurityError::SessionContinuity,
            ));
        }
        let postcommit = (|| {
            let committed = journal
                .snapshot()
                .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
            journal
                .validate_source_provider_authority_snapshot(&committed)
                .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
            if let Some(response) = &self.response
                && !journal_retains_exact_artifact(journal, response)?
            {
                return Err(SourceProviderSecurityError::SessionContinuity);
            }
            let projection = session.current_projection()?;
            if projection.session_binding() != self.session_binding {
                return Err(SourceProviderSecurityError::SessionContinuity);
            }
            Ok(committed)
        })();
        let committed = match postcommit {
            Ok(committed) => committed,
            Err(error) => {
                return Err(poison_and_close(
                    &mut session.custody,
                    &mut session.carrier,
                    error,
                ));
            }
        };
        Ok(super::CommittedProviderOutcomeV1 {
            transaction_commitment: self.transaction_commitment,
            artifact_commitment: self.artifact_commitment,
            reservation_commitment: self.reservation_commitment,
            response_sequence: self.response_sequence,
            method: self.method,
            session_binding: self.session_binding,
            committed_snapshot: committed,
            response: self.response,
        })
    }
}
