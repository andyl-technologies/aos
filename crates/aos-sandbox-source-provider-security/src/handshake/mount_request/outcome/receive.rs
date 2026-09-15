//! Atomic carrier receive and physical SourceRoot observation.

use super::*;

impl CurrentRootMountSourceProviderSessionV1 {
    /// Atomically receives and verifies one exact provider outcome and descriptors.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the session for a
    /// carrier error, truncation, an extra or missing descriptor, stale
    /// custody/session, invalid signature, response drift, or a mismatched
    /// physical SourceRoot observation.
    pub fn receive_and_verify_provider_outcome_v2(
        &mut self,
        catalog_journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        authorization: AuthorizedMountProviderOutcomeV2,
    ) -> Result<VerifiedReceivedMountProviderOutcomeV2, SourceProviderSecurityError> {
        let received = self
            .carrier
            .receive_optional_source_root()
            .map_err(|failure| {
                let error = match failure {
                    CarrierFailureV1::Retryable => SourceProviderSecurityError::SessionContinuity,
                    CarrierFailureV1::Fatal(error) => error,
                };
                self.poison(error)
            })?;
        let crate::carrier::ReceivedSourceProviderRecordV1 {
            payload,
            mut descriptors,
            execution,
        } = received;
        let acquire_response = (authorization.method == SourceProviderMethod::Acquire)
            .then(|| decode_acquire_response(&payload))
            .transpose()
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let needs_source_root = acquire_response
            .as_ref()
            .is_some_and(|response| response.status() == SourceProviderStatus::Complete);
        if descriptors.len() != usize::from(needs_source_root) {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        if !needs_source_root {
            let verified = self.verify_provider_outcome_bytes_v2(
                catalog_journal,
                &authorization,
                payload,
                None,
            )?;
            return Ok(VerifiedReceivedMountProviderOutcomeV2 {
                verified,
                source_root: None,
            });
        }

        let response = acquire_response
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let receipt = response
            .signed_receipt()
            .and_then(|bytes| SignedSourceProviderReceiptV1::from_canonical_bytes(bytes).ok())
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let lease = SignedSourceExportLeaseV1::from_canonical_bytes(
            receipt.subject().signed_export_lease(),
        )
        .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let expected_observation =
            aos_sandbox_source_provider_protocol::SourceRootObservationV1::new(
                receipt.subject().kernel_boot_id(),
                receipt.subject().device(),
                receipt.subject().inode(),
                receipt.subject().unique_mount_id(),
                true,
                true,
                true,
            )
            .map_err(|_| self.poison(SourceProviderSecurityError::DescriptorObservation))?;
        let descriptor = descriptors
            .pop()
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let record = crate::descriptor::AuthenticatedCompleteAcquireRecordV1 {
            descriptor,
            provider_execution: execution,
            expected_observation,
            descriptor_commitment: response.signed_status().subject().descriptor_commitment(),
            acquisition_id: *receipt.subject().acquisition_id().as_bytes(),
            acquisition_sequence: authorization
                .acquisition_sequence
                .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?,
            lease_id: lease.subject().lease_id(),
            lease_digest: digest_signed_export_lease(&lease),
            session_binding: authorization.session_binding,
            socket_cookie: self.carrier.socket().peer().socket_cookie(),
            signed_outcome_digest:
                aos_sandbox_source_provider_protocol::provider_response_artifact_digest_v1(
                    SourceProviderMethod::Acquire,
                    &payload,
                ),
        };
        let source_root = crate::ObservedSourceRootV1::observe(record, self)?;
        source_root.revalidate(self)?;
        let verified = self.verify_provider_outcome_bytes_v2(
            catalog_journal,
            &authorization,
            payload,
            Some(source_root.protocol_observation().clone()),
        )?;
        if verified.descriptor_commitment
            != aos_sandbox_source_provider_protocol::source_root_descriptor_commitment_v1(
                source_root.protocol_observation(),
            )
        {
            return Err(self.poison(SourceProviderSecurityError::DescriptorObservation));
        }
        Ok(VerifiedReceivedMountProviderOutcomeV2 {
            verified,
            source_root: Some(source_root),
        })
    }
}
