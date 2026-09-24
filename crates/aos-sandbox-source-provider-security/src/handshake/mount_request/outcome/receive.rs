//! Atomic carrier receive and physical SourceRoot observation.

use super::*;

impl CurrentRootMountSourceProviderSessionV1 {
    /// Advances one descriptor-free Inventory reply on the separate provider channel.
    ///
    /// The retained authorization names the exact signed request and response
    /// sequence. A pending receive keeps the sent request in Mount custody;
    /// a fatal carrier or signature failure closes this session without
    /// authorizing a resend or a terminal Inventory row.
    ///
    /// # Errors
    ///
    /// Rejects another method, any transferred descriptor, changed peer or
    /// custody, a malformed frame, or a signed reply that differs from the
    /// retained request and current authenticated transcript.
    pub fn advance_remote_inventory_outcome_v2(
        &mut self,
        authorization: &AuthorizedMountProviderOutcomeV2,
    ) -> Result<Option<VerifiedMountProviderOutcomeV2>, SourceProviderSecurityError> {
        if authorization.method != SourceProviderMethod::Inventory {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        self.revalidate()?;
        let received = match self
            .carrier
            .receive_zero_descriptors(aos_sandbox_source_provider_protocol::MAXIMUM_FRAME_BYTES)
        {
            Ok(received) => received,
            Err(CarrierFailureV1::Retryable) => return Ok(None),
            Err(CarrierFailureV1::Fatal(error)) => return Err(self.poison(error)),
        };
        let verified =
            self.verify_provider_outcome_bytes_v2(None, authorization, received.payload, None)?;
        Ok(Some(verified))
    }

    /// Captures one persisted canonical response under current protected custody.
    ///
    /// This is the cold-restart counterpart of carrier capture. The response
    /// and optional reopened SourceRoot remain nonauthorizing until
    /// [`Self::recover_mount_provider_outcome_v2`] matches them to the exact
    /// durable Mount attempt and historical authenticated session.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] for lost currentness, a
    /// noncanonical response, or wrong SourceRoot cardinality.
    #[doc(hidden)]
    pub fn capture_persisted_mount_provider_outcome_v2(
        &mut self,
        method: SourceProviderMethod,
        payload: Vec<u8>,
        source_root: Option<crate::ProviderSourceRootHandoffV1>,
        persisted: crate::PersistedProviderOutcomeV1,
    ) -> Result<CapturedMountProviderRecoveryOutcomeV2, SourceProviderSecurityError> {
        self.revalidate()?;
        let (canonical_signed_status, canonical_signed_result, needs_source_root) =
            split_canonical_response(method, &payload).map_err(|error| self.poison(error))?;
        if source_root.is_some() != needs_source_root {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }

        Ok(CapturedMountProviderRecoveryOutcomeV2 {
            method,
            canonical_signed_status,
            canonical_signed_result,
            source_root,
            persisted: Some(persisted),
        })
    }

    /// Captures one exact carrier response for durable-attempt recovery.
    ///
    /// This operation performs no historical reconstruction and exposes no
    /// response bytes or descriptor. The opaque result can only be consumed by
    /// [`Self::recover_mount_provider_outcome_v2`] with matching protected
    /// attempt and session records.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] for carrier failure, a
    /// noncanonical response, wrong descriptor cardinality, or invalid
    /// SourceRoot observation.
    pub fn capture_mount_provider_recovery_outcome_v2(
        &mut self,
        method: SourceProviderMethod,
    ) -> Result<CapturedMountProviderRecoveryOutcomeV2, SourceProviderSecurityError> {
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
            execution: _,
        } = received;
        let (canonical_signed_status, canonical_signed_result, needs_source_root) =
            split_canonical_response(method, &payload).map_err(|error| self.poison(error))?;
        if descriptors.len() != usize::from(needs_source_root) {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        let source_root = descriptors
            .pop()
            .map(crate::ProviderSourceRootHandoffV1::observe)
            .transpose()
            .map_err(|error| self.poison(error))?;

        Ok(CapturedMountProviderRecoveryOutcomeV2 {
            method,
            canonical_signed_status,
            canonical_signed_result,
            source_root,
            persisted: None,
        })
    }

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
        authorization: &AuthorizedMountProviderOutcomeV2,
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
                Some(catalog_journal),
                authorization,
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
            Some(catalog_journal),
            authorization,
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

fn split_canonical_response(
    method: SourceProviderMethod,
    payload: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, bool), SourceProviderSecurityError> {
    match method {
        SourceProviderMethod::Acquire => {
            let response = decode_acquire_response(payload)
                .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
            if encode_acquire_response(&response) != payload {
                return Err(SourceProviderSecurityError::SessionContinuity);
            }
            Ok((
                response.signed_status().to_canonical_bytes(),
                response.signed_receipt().unwrap_or_default().to_vec(),
                response.status() == SourceProviderStatus::Complete,
            ))
        }
        SourceProviderMethod::Release => {
            let response = decode_release_response(payload)
                .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
            if encode_release_response(&response) != payload {
                return Err(SourceProviderSecurityError::SessionContinuity);
            }
            Ok((
                response.signed_status().to_canonical_bytes(),
                response.signed_receipt().unwrap_or_default().to_vec(),
                false,
            ))
        }
        SourceProviderMethod::Inventory => {
            let response = decode_inventory_response(payload)
                .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
            if encode_inventory_response(&response) != payload {
                return Err(SourceProviderSecurityError::SessionContinuity);
            }
            Ok((
                response.signed_status().to_canonical_bytes(),
                response.signed_inventory().unwrap_or_default().to_vec(),
                false,
            ))
        }
        SourceProviderMethod::Hello => Err(SourceProviderSecurityError::SessionContinuity),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_source_provider_protocol::{
        SourceProviderResponseStatusV1, empty_descriptor_set_commitment_v1, sign_response_status,
    };
    use ed25519_dalek::SigningKey;

    #[test]
    fn remote_inventory_status_requires_the_pinned_provider_signature() {
        let key = SigningKey::from_bytes(&[17; 32]);
        let wrong_key = SigningKey::from_bytes(&[19; 32]);
        let signer = SourceProviderSigningKeyV1::for_signing_key(
            [1; 16],
            1,
            ObjectDigest::from_bytes([2; 32]),
            [3; 16],
            1,
            SourceProviderKeyUsageV1::ProviderOutcome,
            &key,
        )
        .unwrap();
        let status = SourceProviderResponseStatusV1::new(
            SourceProviderMethod::Inventory,
            [4; 16],
            ObjectDigest::from_bytes([5; 32]),
            SourceProviderStatus::Unavailable,
            [6; 16],
            ObjectDigest::from_bytes([7; 32]),
            1,
            response_result_digest_v1(
                SourceProviderMethod::Inventory,
                SourceProviderStatus::Unavailable,
                None,
            ),
            empty_descriptor_set_commitment_v1(),
        )
        .unwrap();
        let signed = sign_response_status(status, signer, &key).unwrap();
        let reply = InventorySourceResponseV1::new(signed, None).unwrap();
        let payload = encode_inventory_response(&reply);

        let (status_bytes, result, needs_source_root) =
            split_canonical_response(SourceProviderMethod::Inventory, &payload).unwrap();
        let decoded = SignedSourceProviderStatusV1::from_canonical_bytes(&status_bytes).unwrap();
        assert!(result.is_empty());
        assert!(!needs_source_root);
        assert!(verify_response_status(&decoded, &key.verifying_key().to_bytes()).is_ok());
        assert!(verify_response_status(&decoded, &wrong_key.verifying_key().to_bytes()).is_err());
        assert!(split_canonical_response(SourceProviderMethod::Release, &payload).is_err());
    }
}
