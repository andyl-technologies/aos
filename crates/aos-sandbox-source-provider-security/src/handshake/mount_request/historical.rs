//! Protected predecessor-holder acquisition authorization.
//!
//! This module turns exact protected AOSMSA02 records and authenticated
//! historical trust into method-specific, move-only Release and Inventory
//! capabilities. It never grants Acquire, signing, send, or session authority.

use super::*;

impl CurrentRootMountSourceProviderSessionV1 {
    #[allow(clippy::too_many_arguments)]
    fn authorize_historical_mount_acquisition_v2(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        journal_snapshot: aos_sandbox::ProtectedJournalSnapshot,
        acquisition_key: Vec<u8>,
        acquisition_record: Vec<u8>,
        predecessor_session_key: Vec<u8>,
        predecessor_session_record: Vec<u8>,
        predecessor_holder: SourceProviderAuthorityV1,
        acquisition_id: ObjectDigest,
        acquisition_sequence: u64,
        lease_id: [u8; 16],
        lease_digest: ObjectDigest,
        predecessor_authenticated_at_seconds: i64,
        predecessor_trust_generation: u64,
        predecessor_trust_digest: ObjectDigest,
        predecessor_revocation_generation: u64,
        predecessor_revocation_digest: ObjectDigest,
        canonical_signed_root_mount_hello: Vec<u8>,
    ) -> Result<HistoricalMountAcquisitionLineageV2, SourceProviderSecurityError> {
        self.revalidate()?;
        let now = crate::handshake::current_unix_seconds()?;
        let current = capture_session_projection(self, now).map_err(|error| self.poison(error))?;
        let current_holder = current.authority_trust()[0].authority().clone();
        let provider_authority_id = current.authority_trust()[1].authority().authority_id();
        let graph = validated_mount_state(journal).map_err(|error| self.poison(error))?;
        let acquisition = match aos_sandbox_protocol::mount_source_acquisition_state::decode_mount_source_state_record_v2(
            &acquisition_key,
            &acquisition_record,
        ) {
            Ok(aos_sandbox_protocol::mount_source_acquisition_state::StoredRecordV2::Acquisition { value }) => value,
            _ => return Err(self.poison(SourceProviderSecurityError::SessionContinuity)),
        };
        let predecessor_session = match aos_sandbox_protocol::mount_source_acquisition_state::decode_mount_source_state_record_v2(
            &predecessor_session_key,
            &predecessor_session_record,
        ) {
            Ok(aos_sandbox_protocol::mount_source_acquisition_state::StoredRecordV2::ProviderSession { value }) => value,
            _ => return Err(self.poison(SourceProviderSecurityError::SessionContinuity)),
        };
        let historical_hello =
            aos_sandbox_source_provider_protocol::SignedSourceProviderHelloV1::from_canonical_bytes(
                &canonical_signed_root_mount_hello,
            )
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let configuration =
            crate::RevalidatedProviderConfigurationV1::capture_root_mount(&mut self.custody, now)
                .map_err(|error| self.poison(error))?;
        let historical_key = historical_verification_key(
            &configuration,
            historical_hello.signer(),
            predecessor_authenticated_at_seconds,
            predecessor_trust_generation,
            predecessor_trust_digest,
            predecessor_revocation_generation,
            predecessor_revocation_digest,
        )
        .map_err(|error| self.poison(error))?;
        verify_hello(&historical_hello, historical_key)
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;

        let inventory_expectation = historical_inventory_expectation(&acquisition)
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let evidence = acquisition
            .evidence
            .as_ref()
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let stable_successor = current_holder.authority_id() == predecessor_holder.authority_id()
            && current_holder.authority_generation() > predecessor_holder.authority_generation()
            && historical_hello.signer().authority_id() == predecessor_holder.authority_id()
            && historical_hello.signer().authority_generation()
                == predecessor_holder.authority_generation()
            && historical_hello.signer().authority_digest()
                == predecessor_holder.authority_digest();
        let protected_records_match = acquisition_sequence > 0
            && acquisition_id
                == aos_sandbox_source_provider_protocol::source_acquisition_id_v2(
                    predecessor_holder.authority_id(),
                    predecessor_holder.authority_generation(),
                    predecessor_holder.authority_digest(),
                    acquisition_sequence,
                )
            && acquisition.provider_acquisition.holder_authority_id
                == predecessor_holder.authority_id()
            && acquisition.provider_acquisition.holder_authority_generation
                == predecessor_holder.authority_generation()
            && acquisition.provider_acquisition.holder_authority_digest
                == *predecessor_holder.authority_digest().as_bytes()
            && acquisition.provider_acquisition.acquisition_sequence == acquisition_sequence
            && acquisition.provider_acquisition.acquisition_id == *acquisition_id.as_bytes()
            && acquisition.scope.provider_authority_id == provider_authority_id
            && evidence.lease_id == lease_id
            && evidence.signed_lease_digest == *lease_digest.as_bytes()
            && evidence.session_id == predecessor_session.session_id
            && predecessor_session.root_mount_authority_generation
                == predecessor_holder.authority_generation()
            && predecessor_session.root_mount_authority_digest
                == *predecessor_holder.authority_digest().as_bytes()
            && predecessor_session.authenticated_at_seconds == predecessor_authenticated_at_seconds
            && predecessor_session.trust_generation == predecessor_trust_generation
            && predecessor_session.trust_digest == *predecessor_trust_digest.as_bytes()
            && predecessor_session.revocation_generation == predecessor_revocation_generation
            && predecessor_session.revocation_digest == *predecessor_revocation_digest.as_bytes()
            && predecessor_session.signed_root_mount_hello == canonical_signed_root_mount_hello
            && graph.acquisitions.get(&acquisition.acquisition_id) == Some(&acquisition)
            && graph.provider_sessions.get(&predecessor_session.session_id)
                == Some(&predecessor_session)
            && journal
                .validate_mount_source_acquisition_snapshot(&journal_snapshot)
                .is_ok()
            && journal.get(&acquisition_key).ok().flatten() == Some(acquisition_record.as_slice())
            && journal.get(&predecessor_session_key).ok().flatten()
                == Some(predecessor_session_record.as_slice());
        if !stable_successor || !protected_records_match {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }

        let mut authorization = HistoricalMountAcquisitionLineageV2 {
            provider_authority_id,
            current_holder,
            predecessor_holder,
            acquisition_id,
            acquisition_sequence,
            lease_id,
            lease_digest,
            session_binding: self.session.binding(),
            lineage_commitment: ObjectDigest::from_bytes([0; 32]),
            journal_snapshot,
            acquisition_key,
            acquisition_record,
            predecessor_session_key,
            predecessor_session_record,
            inventory_expectation,
        };
        authorization.lineage_commitment = historical_acquisition_commitment(&authorization);
        Ok(authorization)
    }

    /// Authorizes Release of one exact predecessor-holder acquisition.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the session unless
    /// the protected historical lineage and current holder succession verify.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize_historical_mount_release_v2(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        journal_snapshot: aos_sandbox::ProtectedJournalSnapshot,
        acquisition_key: Vec<u8>,
        acquisition_record: Vec<u8>,
        predecessor_session_key: Vec<u8>,
        predecessor_session_record: Vec<u8>,
        predecessor_holder: SourceProviderAuthorityV1,
        acquisition_id: ObjectDigest,
        acquisition_sequence: u64,
        lease_id: [u8; 16],
        lease_digest: ObjectDigest,
        predecessor_authenticated_at_seconds: i64,
        predecessor_trust_generation: u64,
        predecessor_trust_digest: ObjectDigest,
        predecessor_revocation_generation: u64,
        predecessor_revocation_digest: ObjectDigest,
        canonical_signed_root_mount_hello: Vec<u8>,
    ) -> Result<HistoricalMountReleaseAuthorizationV2, SourceProviderSecurityError> {
        let lineage = self.authorize_historical_mount_acquisition_v2(
            journal,
            journal_snapshot,
            acquisition_key,
            acquisition_record,
            predecessor_session_key,
            predecessor_session_record,
            predecessor_holder,
            acquisition_id,
            acquisition_sequence,
            lease_id,
            lease_digest,
            predecessor_authenticated_at_seconds,
            predecessor_trust_generation,
            predecessor_trust_digest,
            predecessor_revocation_generation,
            predecessor_revocation_digest,
            canonical_signed_root_mount_hello,
        )?;
        Ok(HistoricalMountReleaseAuthorizationV2 { lineage })
    }

    /// Authorizes Inventory correlation for one predecessor-holder acquisition.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the session unless
    /// the protected historical lineage and current holder succession verify.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize_historical_mount_inventory_v2(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        journal_snapshot: aos_sandbox::ProtectedJournalSnapshot,
        acquisition_key: Vec<u8>,
        acquisition_record: Vec<u8>,
        predecessor_session_key: Vec<u8>,
        predecessor_session_record: Vec<u8>,
        predecessor_holder: SourceProviderAuthorityV1,
        acquisition_id: ObjectDigest,
        acquisition_sequence: u64,
        lease_id: [u8; 16],
        lease_digest: ObjectDigest,
        predecessor_authenticated_at_seconds: i64,
        predecessor_trust_generation: u64,
        predecessor_trust_digest: ObjectDigest,
        predecessor_revocation_generation: u64,
        predecessor_revocation_digest: ObjectDigest,
        canonical_signed_root_mount_hello: Vec<u8>,
    ) -> Result<HistoricalMountInventoryAuthorizationV2, SourceProviderSecurityError> {
        let lineage = self.authorize_historical_mount_acquisition_v2(
            journal,
            journal_snapshot,
            acquisition_key,
            acquisition_record,
            predecessor_session_key,
            predecessor_session_record,
            predecessor_holder,
            acquisition_id,
            acquisition_sequence,
            lease_id,
            lease_digest,
            predecessor_authenticated_at_seconds,
            predecessor_trust_generation,
            predecessor_trust_digest,
            predecessor_revocation_generation,
            predecessor_revocation_digest,
            canonical_signed_root_mount_hello,
        )?;
        Ok(HistoricalMountInventoryAuthorizationV2 { lineage })
    }
}

pub(super) fn historical_inventory_expectation(
    acquisition: &aos_sandbox_protocol::mount_source_acquisition_state::SourceAcquisitionRowV2,
) -> Option<aos_sandbox_protocol::mount_source_acquisition_state::InventoryCorrelationExpectationV2>
{
    aos_sandbox_protocol::mount_source_acquisition_state::inventory_correlation_for_row_v2(
        acquisition,
    )
    .map(|value| value.expectation)
}
