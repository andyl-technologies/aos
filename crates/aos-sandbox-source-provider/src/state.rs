//! Provider-owned recovered state and protected current configuration.

use std::collections::BTreeMap;

use aos_sandbox::{JournalRecord, JournalTransaction, ProtectedJournalAuthority, RecordNamespace};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    SourceProviderAuthorityTrustStateV1, SourceProviderAuthorityV1, SourceProviderKeyTrustStateV1,
    SourceProviderKeyUsageV1, SourceProviderSigningKeyV1,
};
use aos_sandbox_source_provider_security::{
    CurrentProviderIngressSessionV1, ProviderSessionSupersessionEvidenceV1,
};
use sha2::{Digest as _, Sha256};

use crate::ProviderLedgerError;
use crate::limits::ProviderLedgerLimits;
use crate::model::{
    AuthorityHeadRecordV1, CatalogHeadRecordV1, ProviderRecoveryWorkV1, RecoveredProviderLedgerV1,
};
use crate::{DurableProviderReplyV1, SourceProviderBackendV1};

/// Holds the non-secret protected provider configuration projection.
///
/// This type intentionally has no public constructor. A future production
/// adapter must create it only from protected manifests, current trust/route
/// records, kernel process evidence, and role-specific key custody.
pub struct ProtectedProviderConfigurationV1 {
    provider: SourceProviderAuthorityV1,
    trust_generation: u64,
    trust_digest: ObjectDigest,
    revocation_generation: u64,
    revocation_digest: ObjectDigest,
    route_id: [u8; 16],
    route_generation: u64,
    route_digest: ObjectDigest,
    resource_namespace_digest: ObjectDigest,
    provider_hello_signer: SourceProviderSigningKeyV1,
    provider_outcome_signer: SourceProviderSigningKeyV1,
    valid_from_seconds: i64,
    valid_until_seconds: i64,
    proof_class_capabilities: u8,
    supports_recursive: bool,
    supports_kernel_coupled: bool,
    catalog_generation: u64,
    catalog_digest: ObjectDigest,
    publisher_authority_id: [u8; 16],
    publication_generation: u64,
    publication_receipt_digest: ObjectDigest,
    predecessor_catalog_generation: u64,
    predecessor_catalog_digest: ObjectDigest,
    catalog_floor_generation: u64,
    catalog_floor_digest: ObjectDigest,
    publication_seconds: i64,
    publication_trust_generation: u64,
    publication_trust_digest: ObjectDigest,
    publication_revocation_generation: u64,
    publication_revocation_digest: ObjectDigest,
    publisher_signer: SourceProviderSigningKeyV1,
    canonical_catalog_publication: Vec<u8>,
    historical_public_keys:
        Vec<aos_sandbox_source_provider_security::HistoricalProviderVerificationKeyV1>,
    trust_history: Vec<aos_sandbox_source_provider_security::ProtectedTrustHeadLinkV2>,
    limits: ProviderLedgerLimits,
}

/// Proves one exact retained holder session is durably deauthorized.
///
/// This move-only value is minted only from the protected authenticated trust
/// chain and can be consumed only into session replacement or recovery.
pub(crate) struct ExactSessionRevocationFenceV1 {
    old_session_binding: ObjectDigest,
    old_root_record_signer: SourceProviderSigningKeyV1,
    deactivation_head: (u64, ObjectDigest, u64, ObjectDigest),
    current_head: (u64, ObjectDigest, u64, ObjectDigest),
    commitment: ObjectDigest,
}

impl ExactSessionRevocationFenceV1 {
    pub(crate) fn consume_for(
        self,
        session: &crate::model::HolderSessionHeadRecordV1,
    ) -> Result<ObjectDigest, ProviderLedgerError> {
        if self.old_session_binding != session.session_binding
            || self.old_root_record_signer != session.signers[1]
            || self.deactivation_head
                == (
                    session.trust_generation,
                    session.trust_digest,
                    session.revocation_generation,
                    session.revocation_digest,
                )
            || self.current_head.0 < self.deactivation_head.0
            || self.current_head.2 < self.deactivation_head.2
        {
            return Err(ProviderLedgerError::Equivocation);
        }
        Ok(self.commitment)
    }
}

impl ProtectedProviderConfigurationV1 {
    pub(crate) fn exact_session_revocation_fence(
        &self,
        session: &crate::model::HolderSessionHeadRecordV1,
    ) -> Result<ExactSessionRevocationFenceV1, ProviderLedgerError> {
        let signer = &session.signers[1];
        if signer.usage() != SourceProviderKeyUsageV1::RootMountRecord
            || signer.authority_id() != session.holder.authority_id()
            || signer.authority_generation() != session.holder.authority_generation()
            || signer.authority_digest() != session.holder.authority_digest()
        {
            return Err(ProviderLedgerError::Equivocation);
        }
        let historical = self
            .historical_public_keys
            .iter()
            .find(|candidate| candidate.signer() == signer)
            .ok_or(ProviderLedgerError::ConfigurationMismatch)?;
        let old_head = (
            session.trust_generation,
            session.trust_digest,
            session.revocation_generation,
            session.revocation_digest,
        );
        let current_head = (
            self.trust_generation,
            self.trust_digest,
            self.revocation_generation,
            self.revocation_digest,
        );
        let issuance_head = {
            let (trust_generation, trust_digest) = historical.trust_head();
            let (revocation_generation, revocation_digest) = historical.revocation_head();
            (
                trust_generation,
                trust_digest,
                revocation_generation,
                revocation_digest,
            )
        };
        let key_deactivation = match historical.state_and_successor().0 {
            SourceProviderKeyTrustStateV1::Eligible => None,
            SourceProviderKeyTrustStateV1::Superseded | SourceProviderKeyTrustStateV1::Revoked => {
                Some(historical.state_effective_head())
            }
        };
        let authority_deactivation = match historical.authority_issuance().2 {
            SourceProviderAuthorityTrustStateV1::Trusted => None,
            SourceProviderAuthorityTrustStateV1::Revoked => {
                Some(historical.authority_state_effective_head())
            }
        };
        let index = |head| {
            self.trust_history
                .iter()
                .position(|entry| entry.head() == head)
        };
        let issuance_index =
            index(issuance_head).ok_or(ProviderLedgerError::ConfigurationMismatch)?;
        let old_index = index(old_head).ok_or(ProviderLedgerError::ConfigurationMismatch)?;
        let current_index =
            index(current_head).ok_or(ProviderLedgerError::ConfigurationMismatch)?;
        if issuance_index > old_index || old_index >= current_index {
            return Err(ProviderLedgerError::InvalidTransition(
                "retained session trust ancestry is not current",
            ));
        }
        let deactivation_head = [key_deactivation, authority_deactivation]
            .into_iter()
            .flatten()
            .filter_map(|head| index(head).map(|position| (position, head)))
            .filter(|(position, _)| *position > old_index && *position <= current_index)
            .min_by_key(|(position, _)| *position)
            .map(|(_, head)| head)
            .ok_or(ProviderLedgerError::InvalidTransition(
                "retained session has no authenticated deactivation head",
            ))?;

        let mut hasher = Sha256::new();
        hasher.update(b"aos.sandbox.source-provider.exact-session-revocation-fence.v1\0");
        hasher.update(session.provider.authority_id());
        hasher.update(session.provider.authority_generation().to_be_bytes());
        hasher.update(session.provider.authority_digest().as_bytes());
        hasher.update(session.holder.authority_id());
        hasher.update(session.holder.authority_generation().to_be_bytes());
        hasher.update(session.holder.authority_digest().as_bytes());
        hasher.update(session.session_binding.as_bytes());
        hasher.update(signer.authority_id());
        hasher.update(signer.authority_generation().to_be_bytes());
        hasher.update(signer.authority_digest().as_bytes());
        hasher.update(signer.key_id());
        hasher.update(signer.key_generation().to_be_bytes());
        hasher.update(signer.public_key_digest().as_bytes());
        hasher.update([signer.usage() as u8]);
        for head in [issuance_head, old_head, deactivation_head, current_head] {
            hasher.update(head.0.to_be_bytes());
            hasher.update(head.1.as_bytes());
            hasher.update(head.2.to_be_bytes());
            hasher.update(head.3.as_bytes());
        }
        Ok(ExactSessionRevocationFenceV1 {
            old_session_binding: session.session_binding,
            old_root_record_signer: signer.clone(),
            deactivation_head,
            current_head,
            commitment: ObjectDigest::from_bytes(hasher.finalize().into()),
        })
    }
    /// Builds dormant ledger configuration from two opaque verified projections.
    ///
    /// The custody projection can be minted only by complete FD-relative
    /// protected-custody revalidation. The catalog projection has no public
    /// scalar constructor and is minted only by the authenticated catalog
    /// publication verifier. Neither projection carries a secret or signing
    /// oracle.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] when provider, namespace, catalog,
    /// predecessor, floor, signer, validity, or historical-key facts disagree.
    pub fn from_revalidated_projections(
        custody: aos_sandbox_source_provider_security::RevalidatedProviderConfigurationV1,
        catalog: crate::VerifiedCatalogPublicationV1,
        limits: ProviderLedgerLimits,
    ) -> Result<Self, ProviderLedgerError> {
        // AOSSPL01 version 3 fixes deployment ceilings into the format contract. Until
        // a later version journals an explicit deployment-policy digest,
        // accepting caller-specific ceilings would make recovery ambiguous.
        if limits != ProviderLedgerLimits::default() {
            return Err(ProviderLedgerError::ConfigurationMismatch);
        }
        let (trust_generation, trust_digest) = custody.trust_head();
        let (revocation_generation, revocation_digest) = custody.revocation_head();
        let (route_id, route_generation, route_digest) = custody.route_head();
        let (valid_from_seconds, valid_until_seconds) = custody.validity();
        let (catalog_generation, catalog_digest) = catalog.catalog_head();
        let (publisher_authority_id, publication_generation, publication_receipt_digest) =
            catalog.publication();
        let (predecessor_catalog_generation, predecessor_catalog_digest) = catalog.predecessor();
        let (catalog_floor_generation, catalog_floor_digest) = catalog.catalog_floor();
        let (
            publication_seconds,
            publication_trust_generation,
            publication_trust_digest,
            publication_revocation_generation,
            publication_revocation_digest,
        ) = catalog.issuance();
        let publisher_signer = catalog.publisher_signer().clone();
        let canonical_catalog_publication = catalog.canonical_publication().to_vec();
        if custody.provider() != catalog.provider()
            || custody.resource_namespace_digest() != catalog.resource_namespace_digest()
            || catalog_generation == 0
            || catalog_digest.as_bytes() == &[0; 32]
            || publisher_authority_id == [0; 16]
            || publication_generation == 0
            || publication_receipt_digest.as_bytes() == &[0; 32]
            || publication_seconds < valid_from_seconds
            || publication_seconds >= valid_until_seconds
            || !custody.authenticates_head(
                publication_trust_generation,
                publication_trust_digest,
                publication_revocation_generation,
                publication_revocation_digest,
            )
            || publisher_signer.authority_id() != publisher_authority_id
            || publisher_signer.usage()
                != aos_sandbox_source_provider_protocol::SourceProviderKeyUsageV1::CatalogPublisher
            || catalog_floor_generation == 0
            || catalog_floor_generation > catalog_generation
            || catalog_floor_digest.as_bytes() == &[0; 32]
            || (catalog_generation == catalog_floor_generation
                && catalog_digest != catalog_floor_digest)
            || (predecessor_catalog_generation == 0)
                != (predecessor_catalog_digest.as_bytes() == &[0; 32])
            || (catalog_generation > catalog_floor_generation
                && predecessor_catalog_generation < catalog_floor_generation)
        {
            return Err(ProviderLedgerError::ConfigurationMismatch);
        }
        let historical_public_keys = custody.historical_public_keys().to_vec();
        let trust_history = custody.trust_history().to_vec();
        for (index, entry) in historical_public_keys.iter().enumerate() {
            if historical_public_keys[..index].iter().any(|prior| {
                prior.signer() == entry.signer()
                    || prior.signer().public_key_digest() == entry.signer().public_key_digest()
            }) {
                return Err(ProviderLedgerError::ConfigurationMismatch);
            }
        }
        let configuration = Self {
            provider: custody.provider().clone(),
            trust_generation,
            trust_digest,
            revocation_generation,
            revocation_digest,
            route_id,
            route_generation,
            route_digest,
            resource_namespace_digest: catalog.resource_namespace_digest(),
            provider_hello_signer: custody.provider_hello_signer().clone(),
            provider_outcome_signer: custody.provider_outcome_signer().clone(),
            valid_from_seconds,
            valid_until_seconds,
            proof_class_capabilities: custody.proof_class_capabilities(),
            supports_recursive: custody.supports_recursive(),
            supports_kernel_coupled: custody.supports_kernel_coupled(),
            catalog_generation,
            catalog_digest,
            publisher_authority_id,
            publication_generation,
            publication_receipt_digest,
            predecessor_catalog_generation,
            predecessor_catalog_digest,
            catalog_floor_generation,
            catalog_floor_digest,
            publication_seconds,
            publication_trust_generation,
            publication_trust_digest,
            publication_revocation_generation,
            publication_revocation_digest,
            publisher_signer,
            canonical_catalog_publication,
            historical_public_keys,
            trust_history,
            limits,
        };
        if configuration
            .currently_eligible_public_key_for(&configuration.provider_hello_signer)
            .is_none()
            || configuration
                .currently_eligible_public_key_for(&configuration.provider_outcome_signer)
                .is_none()
            || configuration
                .currently_eligible_public_key_for(&configuration.publisher_signer)
                .is_none()
        {
            return Err(ProviderLedgerError::ConfigurationMismatch);
        }
        Ok(configuration)
    }

    /// Reports whether both durable heads exactly match protected configuration.
    pub(crate) fn matches_authority_and_catalog(
        &self,
        authority: &AuthorityHeadRecordV1,
        catalog: &CatalogHeadRecordV1,
    ) -> bool {
        authority.provider == self.provider
            && authority.trust_generation == self.trust_generation
            && authority.trust_digest == self.trust_digest
            && authority.revocation_generation == self.revocation_generation
            && authority.revocation_digest == self.revocation_digest
            && authority.valid_from_seconds == self.valid_from_seconds
            && authority.valid_until_seconds == self.valid_until_seconds
            && authority.route_id == self.route_id
            && authority.route_generation == self.route_generation
            && authority.route_digest == self.route_digest
            && authority.resource_namespace_digest == self.resource_namespace_digest
            && authority.proof_class_capabilities == self.proof_class_capabilities
            && authority.supports_recursive == self.supports_recursive
            && authority.supports_kernel_coupled == self.supports_kernel_coupled
            && authority.provider_hello_signer == self.provider_hello_signer
            && authority.provider_outcome_signer == self.provider_outcome_signer
            && authority.catalog_generation == self.catalog_generation
            && authority.catalog_digest == self.catalog_digest
            && catalog.provider == self.provider
            && catalog.resource_namespace_digest == self.resource_namespace_digest
            && catalog.catalog_generation == self.catalog_generation
            && catalog.catalog_digest == self.catalog_digest
            && catalog.publisher_authority_id == self.publisher_authority_id
            && catalog.publication_generation == self.publication_generation
            && catalog.publication_receipt_digest == self.publication_receipt_digest
            && catalog.predecessor_catalog_generation == self.predecessor_catalog_generation
            && catalog.predecessor_catalog_digest == self.predecessor_catalog_digest
            && catalog.catalog_floor_generation == self.catalog_floor_generation
            && catalog.catalog_floor_digest == self.catalog_floor_digest
            && catalog.publication_seconds == self.publication_seconds
            && catalog.publication_trust_generation == self.publication_trust_generation
            && catalog.publication_trust_digest == self.publication_trust_digest
            && catalog.publication_revocation_generation == self.publication_revocation_generation
            && catalog.publication_revocation_digest == self.publication_revocation_digest
            && catalog.publisher_signer == self.publisher_signer
            && catalog.canonical_publication == self.canonical_catalog_publication
            && self.catalog_floor_generation > 0
            && self.catalog_floor_generation <= self.catalog_generation
            && self.catalog_floor_digest.as_bytes() != &[0; 32]
            && self.valid_from_seconds >= 0
            && self.valid_until_seconds > self.valid_from_seconds
            && self.proof_class_capabilities != 0
            && self.proof_class_capabilities & !0x0f == 0
            && self
                .currently_eligible_public_key_for(&self.provider_hello_signer)
                .is_some()
            && self
                .currently_eligible_public_key_for(&self.provider_outcome_signer)
                .is_some()
    }

    pub(crate) fn validate_heads(
        &self,
        authority: &AuthorityHeadRecordV1,
        catalog: &CatalogHeadRecordV1,
    ) -> Result<(), ProviderLedgerError> {
        if !self.matches_authority_and_catalog(authority, catalog) {
            return Err(ProviderLedgerError::ConfigurationMismatch);
        }
        Ok(())
    }

    pub(crate) const fn limits(&self) -> ProviderLedgerLimits {
        self.limits
    }

    pub(crate) const fn catalog_floor_generation(&self) -> u64 {
        self.catalog_floor_generation
    }

    pub(crate) const fn catalog_floor_digest(&self) -> ObjectDigest {
        self.catalog_floor_digest
    }

    pub(crate) fn currently_eligible_public_key_for(
        &self,
        signer: &SourceProviderSigningKeyV1,
    ) -> Option<&[u8; 32]> {
        use aos_sandbox_source_provider_protocol::{
            SourceProviderAuthorityTrustStateV1, SourceProviderKeyTrustStateV1,
        };

        self.historical_public_keys
            .iter()
            .find(|entry| {
                let (state, _) = entry.state_and_successor();
                let (_, _, authority_state) = entry.authority_issuance();
                entry.signer() == signer
                    && state == SourceProviderKeyTrustStateV1::Eligible
                    && authority_state == SourceProviderAuthorityTrustStateV1::Trusted
            })
            .map(|entry| entry.public_key())
    }

    pub(crate) fn historical_key_projection_for(
        &self,
        signer: &SourceProviderSigningKeyV1,
    ) -> Option<&aos_sandbox_source_provider_security::HistoricalProviderVerificationKeyV1> {
        self.historical_public_keys
            .iter()
            .find(|entry| entry.signer() == signer)
    }

    pub(crate) fn trust_history(
        &self,
    ) -> &[aos_sandbox_source_provider_security::ProtectedTrustHeadLinkV2] {
        &self.trust_history
    }

    pub(crate) fn historical_public_key_for(
        &self,
        signer: &SourceProviderSigningKeyV1,
        issued_seconds: i64,
        trust_generation: u64,
        trust_digest: ObjectDigest,
        revocation_generation: u64,
        revocation_digest: ObjectDigest,
    ) -> Option<&[u8; 32]> {
        self.historical_public_keys
            .iter()
            .find(|entry| {
                let (issuance_trust_generation, issuance_trust_digest) = entry.trust_head();
                let (issuance_revocation_generation, issuance_revocation_digest) =
                    entry.revocation_head();
                let (valid_from, valid_until) = entry.validity();
                let (authority_from, authority_until, authority_state) = entry.authority_issuance();
                let (state, _) = entry.state_and_successor();
                let artifact_head = (
                    trust_generation,
                    trust_digest,
                    revocation_generation,
                    revocation_digest,
                );
                entry.signer() == signer
                    && issued_seconds >= valid_from.max(authority_from)
                    && issued_seconds < valid_until.min(authority_until)
                    && self.authenticates_trust_ancestry(
                        (
                            issuance_trust_generation,
                            issuance_trust_digest,
                            issuance_revocation_generation,
                            issuance_revocation_digest,
                        ),
                        artifact_head,
                    )
                    && self.artifact_precedes_key_deactivation(entry, state, artifact_head)
                    && self.artifact_precedes_authority_revocation(
                        entry,
                        authority_state,
                        artifact_head,
                    )
            })
            .map(|entry| entry.public_key())
    }

    fn authenticates_trust_ancestry(
        &self,
        issuance: (u64, ObjectDigest, u64, ObjectDigest),
        artifact: (u64, ObjectDigest, u64, ObjectDigest),
    ) -> bool {
        let issuance_index = self
            .trust_history
            .iter()
            .position(|entry| entry.head() == issuance);
        let artifact_index = self
            .trust_history
            .iter()
            .position(|entry| entry.head() == artifact);
        matches!((issuance_index, artifact_index), (Some(left), Some(right)) if left <= right)
    }

    fn artifact_precedes_key_deactivation(
        &self,
        entry: &aos_sandbox_source_provider_security::HistoricalProviderVerificationKeyV1,
        state: aos_sandbox_source_provider_protocol::SourceProviderKeyTrustStateV1,
        artifact: (u64, ObjectDigest, u64, ObjectDigest),
    ) -> bool {
        use aos_sandbox_source_provider_protocol::SourceProviderKeyTrustStateV1;

        if state == SourceProviderKeyTrustStateV1::Eligible {
            return true;
        }
        self.head_precedes(artifact, entry.state_effective_head())
    }

    fn artifact_precedes_authority_revocation(
        &self,
        entry: &aos_sandbox_source_provider_security::HistoricalProviderVerificationKeyV1,
        state: aos_sandbox_source_provider_protocol::SourceProviderAuthorityTrustStateV1,
        artifact: (u64, ObjectDigest, u64, ObjectDigest),
    ) -> bool {
        use aos_sandbox_source_provider_protocol::SourceProviderAuthorityTrustStateV1;

        if state == SourceProviderAuthorityTrustStateV1::Trusted {
            return true;
        }
        self.head_precedes(artifact, entry.authority_state_effective_head())
    }

    fn head_precedes(
        &self,
        earlier: (u64, ObjectDigest, u64, ObjectDigest),
        later: (u64, ObjectDigest, u64, ObjectDigest),
    ) -> bool {
        let earlier_index = self
            .trust_history
            .iter()
            .position(|entry| entry.head() == earlier);
        let later_index = self
            .trust_history
            .iter()
            .position(|entry| entry.head() == later);
        matches!((earlier_index, later_index), (Some(left), Some(right)) if left < right)
    }

    pub(crate) const fn outcome_signer(&self) -> &SourceProviderSigningKeyV1 {
        &self.provider_outcome_signer
    }

    pub(crate) fn deployment_digest(&self) -> ObjectDigest {
        let mut hasher = Sha256::new();
        hasher.update(b"aos.sandbox.source-provider.deployment-configuration.v1\0");
        hash_authority(&mut hasher, &self.provider);
        hasher.update(self.trust_generation.to_be_bytes());
        hasher.update(self.trust_digest.as_bytes());
        hasher.update(self.revocation_generation.to_be_bytes());
        hasher.update(self.revocation_digest.as_bytes());
        hasher.update(self.route_id);
        hasher.update(self.route_generation.to_be_bytes());
        hasher.update(self.route_digest.as_bytes());
        hasher.update(self.resource_namespace_digest.as_bytes());
        hasher.update(self.valid_from_seconds.to_be_bytes());
        hasher.update(self.valid_until_seconds.to_be_bytes());
        hasher.update([
            self.proof_class_capabilities,
            u8::from(self.supports_recursive),
            u8::from(self.supports_kernel_coupled),
            0,
        ]);
        hash_signer(&mut hasher, &self.provider_hello_signer);
        hash_signer(&mut hasher, &self.provider_outcome_signer);
        hasher.update(self.catalog_generation.to_be_bytes());
        hasher.update(self.catalog_digest.as_bytes());
        hasher.update(self.publisher_authority_id);
        hasher.update(self.publication_generation.to_be_bytes());
        hasher.update(self.publication_receipt_digest.as_bytes());
        hasher.update(self.predecessor_catalog_generation.to_be_bytes());
        hasher.update(self.predecessor_catalog_digest.as_bytes());
        hasher.update(self.catalog_floor_generation.to_be_bytes());
        hasher.update(self.catalog_floor_digest.as_bytes());
        hasher.update(self.publication_seconds.to_be_bytes());
        hasher.update(self.publication_trust_generation.to_be_bytes());
        hasher.update(self.publication_trust_digest.as_bytes());
        hasher.update(self.publication_revocation_generation.to_be_bytes());
        hasher.update(self.publication_revocation_digest.as_bytes());
        hash_signer(&mut hasher, &self.publisher_signer);
        hasher.update((self.canonical_catalog_publication.len() as u32).to_be_bytes());
        hasher.update(&self.canonical_catalog_publication);
        hasher.update(self.limits.deployment_digest().as_bytes());
        hasher.update((self.historical_public_keys.len() as u64).to_be_bytes());
        for entry in &self.historical_public_keys {
            hash_signer(&mut hasher, entry.signer());
            hasher.update(entry.public_key());
            let (trust_generation, trust_digest) = entry.trust_head();
            let (revocation_generation, revocation_digest) = entry.revocation_head();
            let (valid_from_seconds, valid_until_seconds) = entry.validity();
            let (state, successor) = entry.state_and_successor();
            let (
                state_trust_generation,
                state_trust_digest,
                state_revocation_generation,
                state_revocation_digest,
            ) = entry.state_effective_head();
            let (authority_from, authority_until, authority_state) = entry.authority_issuance();
            let (
                authority_state_trust_generation,
                authority_state_trust_digest,
                authority_state_revocation_generation,
                authority_state_revocation_digest,
            ) = entry.authority_state_effective_head();
            hasher.update(trust_generation.to_be_bytes());
            hasher.update(trust_digest.as_bytes());
            hasher.update(revocation_generation.to_be_bytes());
            hasher.update(revocation_digest.as_bytes());
            hasher.update(valid_from_seconds.to_be_bytes());
            hasher.update(valid_until_seconds.to_be_bytes());
            hasher.update([state as u8]);
            hasher.update([0; 7]);
            hasher.update(successor.to_be_bytes());
            hasher.update(state_trust_generation.to_be_bytes());
            hasher.update(state_trust_digest.as_bytes());
            hasher.update(state_revocation_generation.to_be_bytes());
            hasher.update(state_revocation_digest.as_bytes());
            hasher.update(authority_from.to_be_bytes());
            hasher.update(authority_until.to_be_bytes());
            hasher.update([authority_state as u8]);
            hasher.update(authority_state_trust_generation.to_be_bytes());
            hasher.update(authority_state_trust_digest.as_bytes());
            hasher.update(authority_state_revocation_generation.to_be_bytes());
            hasher.update(authority_state_revocation_digest.as_bytes());
        }
        hasher.update((self.trust_history.len() as u64).to_be_bytes());
        for entry in &self.trust_history {
            let (trust_generation, trust_digest, revocation_generation, revocation_digest) =
                entry.head();
            let (
                predecessor_trust_generation,
                predecessor_trust_digest,
                predecessor_revocation_generation,
                predecessor_revocation_digest,
            ) = entry.predecessor();
            hasher.update(trust_generation.to_be_bytes());
            hasher.update(trust_digest.as_bytes());
            hasher.update(revocation_generation.to_be_bytes());
            hasher.update(revocation_digest.as_bytes());
            hasher.update(predecessor_trust_generation.to_be_bytes());
            hasher.update(predecessor_trust_digest.as_bytes());
            hasher.update(predecessor_revocation_generation.to_be_bytes());
            hasher.update(predecessor_revocation_digest.as_bytes());
        }
        ObjectDigest::from_bytes(hasher.finalize().into())
    }

    fn same_frozen_authority(&self, other: &Self) -> bool {
        self.provider == other.provider
            && self.route_id == other.route_id
            && self.route_generation == other.route_generation
            && self.route_digest == other.route_digest
            && self.resource_namespace_digest == other.resource_namespace_digest
            && self.proof_class_capabilities == other.proof_class_capabilities
            && self.supports_recursive == other.supports_recursive
            && self.supports_kernel_coupled == other.supports_kernel_coupled
            && self.limits == other.limits
    }
}

fn hash_authority(hasher: &mut Sha256, authority: &SourceProviderAuthorityV1) {
    hasher.update(authority.authority_id());
    hasher.update(authority.authority_generation().to_be_bytes());
    hasher.update(authority.authority_digest().as_bytes());
}

fn hash_signer(hasher: &mut Sha256, signer: &SourceProviderSigningKeyV1) {
    hasher.update(signer.key_id());
    hasher.update([signer.usage() as u8]);
    hasher.update([0; 7]);
    hasher.update(signer.authority_id());
    hasher.update(signer.authority_generation().to_be_bytes());
    hasher.update(signer.authority_digest().as_bytes());
    hasher.update(signer.public_key_digest().as_bytes());
}

fn retained_inventory_catalog_below(
    attempts: &BTreeMap<crate::model::AttemptKeyV1, crate::model::AttemptRecordV1>,
    proposed_floor: u64,
) -> Result<bool, ProviderLedgerError> {
    for attempt in attempts.values().filter(|attempt| {
        attempt.method == aos_sandbox_source_provider_protocol::SourceProviderMethod::Inventory
            && attempt.status
                == Some(aos_sandbox_source_provider_protocol::SourceProviderStatus::Complete)
    }) {
        if attempt.completed_response.is_empty() {
            // The canonical response was already compacted after exact graph
            // tracing. Its tombstone retains catalog identity for audit and
            // idempotency but no longer requires the catalog record itself.
            continue;
        }
        let response = aos_sandbox_source_provider_protocol::decode_inventory_response(
            &attempt.completed_response,
        )
        .map_err(|_| ProviderLedgerError::Corrupt("retained Inventory response"))?;
        let signed = response
            .signed_inventory()
            .and_then(|bytes| {
                aos_sandbox_source_provider_protocol::SignedSourceProviderInventoryV1::from_canonical_bytes(bytes).ok()
            })
            .ok_or(ProviderLedgerError::Corrupt("retained Inventory artifact"))?;
        if signed.subject().catalog_generation() != attempt.response_catalog_generation
            || signed.subject().catalog_digest() != attempt.response_catalog_digest
            || signed.subject().catalog_generation() < proposed_floor
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Owns one recovered protected journal and its validated in-memory graph.
pub struct ProviderLedgerV1<'a> {
    pub(crate) journal: ProtectedJournalAuthority<'a>,
    pub(crate) configuration: ProtectedProviderConfigurationV1,
    pub(crate) recovered: RecoveredProviderLedgerV1,
    pub(crate) current_sessions: BTreeMap<[u8; 16], InstalledProviderSessionV1>,
    pub(crate) pending_acquisitions:
        BTreeMap<ObjectDigest, crate::pending::LivePendingAcquisitionV1>,
    pub(crate) pending_releases: BTreeMap<ObjectDigest, crate::release::LivePendingReleaseV1>,
    pub(crate) recovery_authorizations: BTreeMap<
        ObjectDigest,
        aos_sandbox_source_provider_security::ProviderOutcomeAuthorizationV1,
    >,
    pub(crate) pending_recovery_bridge: Option<crate::recovery_bridge::RecoveryBridgeLinkV1>,
    pub(crate) poisoned: bool,
}

pub(crate) struct DetachedProviderLedgerV1 {
    configuration: ProtectedProviderConfigurationV1,
    recovered: RecoveredProviderLedgerV1,
    current_sessions: BTreeMap<[u8; 16], InstalledProviderSessionV1>,
    pending_acquisitions: BTreeMap<ObjectDigest, crate::pending::LivePendingAcquisitionV1>,
    pending_releases: BTreeMap<ObjectDigest, crate::release::LivePendingReleaseV1>,
    recovery_authorizations: BTreeMap<
        ObjectDigest,
        aos_sandbox_source_provider_security::ProviderOutcomeAuthorizationV1,
    >,
    pending_recovery_bridge: Option<crate::recovery_bridge::RecoveryBridgeLinkV1>,
    poisoned: bool,
}

impl<'a> ProviderLedgerV1<'a> {
    pub(crate) fn detach(self) -> DetachedProviderLedgerV1 {
        DetachedProviderLedgerV1 {
            configuration: self.configuration,
            recovered: self.recovered,
            current_sessions: self.current_sessions,
            pending_acquisitions: self.pending_acquisitions,
            pending_releases: self.pending_releases,
            recovery_authorizations: self.recovery_authorizations,
            pending_recovery_bridge: self.pending_recovery_bridge,
            poisoned: self.poisoned,
        }
    }

    pub(crate) fn attach(
        journal: ProtectedJournalAuthority<'a>,
        detached: DetachedProviderLedgerV1,
    ) -> Self {
        Self {
            journal,
            configuration: detached.configuration,
            recovered: detached.recovered,
            current_sessions: detached.current_sessions,
            pending_acquisitions: detached.pending_acquisitions,
            pending_releases: detached.pending_releases,
            recovery_authorizations: detached.recovery_authorizations,
            pending_recovery_bridge: detached.pending_recovery_bridge,
            poisoned: detached.poisoned,
        }
    }
}

pub(crate) struct InstalledProviderSessionV1 {
    pub(crate) session: CurrentProviderIngressSessionV1,
    pub(crate) supersession: Option<ProviderSessionSupersessionEvidenceV1>,
    pub(crate) recovered_execution_death:
        Option<aos_sandbox_source_provider_security::DeadProviderExecutionV1>,
}

#[path = "state/lifecycle.rs"]
mod lifecycle;
#[path = "state/recovery.rs"]
mod recovery;
#[path = "state/retention.rs"]
mod retention;

fn monotone_head(
    current_generation: u64,
    current_digest: ObjectDigest,
    next_generation: u64,
    next_digest: ObjectDigest,
) -> bool {
    next_generation > current_generation
        || (next_generation == current_generation && next_digest == current_digest)
}

fn verify_catalog_for_transition(
    custody: &aos_sandbox_source_provider_security::RevalidatedProviderConfigurationV1,
    current: &ProtectedProviderConfigurationV1,
    bytes: &[u8],
) -> Result<crate::VerifiedCatalogPublicationV1, ProviderLedgerError> {
    if bytes == current.canonical_catalog_publication {
        let key = custody
            .historical_public_keys()
            .iter()
            .find(|entry| entry.signer() == &current.publisher_signer)
            .ok_or(ProviderLedgerError::ConfigurationMismatch)?;
        Ok(
            aos_sandbox_source_provider_security::verify_retained_catalog_publication(
                custody.trust_history(),
                key,
                bytes,
            )?,
        )
    } else {
        Ok(aos_sandbox_source_provider_security::verify_catalog_publication(custody, bytes)?)
    }
}

fn monotone_signer(
    current: &SourceProviderSigningKeyV1,
    next: &SourceProviderSigningKeyV1,
) -> bool {
    (next == current)
        || (next.authority_id() == current.authority_id()
            && next.authority_generation() == current.authority_generation()
            && next.authority_digest() == current.authority_digest()
            && next.usage() == current.usage()
            && next.key_generation() > current.key_generation())
}

fn authenticated_historical_key_transition(
    current: &aos_sandbox_source_provider_security::HistoricalProviderVerificationKeyV1,
    next: &aos_sandbox_source_provider_security::HistoricalProviderVerificationKeyV1,
) -> bool {
    use aos_sandbox_source_provider_protocol::{
        SourceProviderAuthorityTrustStateV1 as AuthorityState,
        SourceProviderKeyTrustStateV1 as KeyState,
    };

    let (current_key_state, current_successor) = current.state_and_successor();
    let (next_key_state, next_successor) = next.state_and_successor();
    let (current_authority_from, current_authority_until, current_authority_state) =
        current.authority_issuance();
    let (next_authority_from, next_authority_until, next_authority_state) =
        next.authority_issuance();
    let key_state_monotone = match (current_key_state, next_key_state) {
        (KeyState::Eligible, KeyState::Eligible) => current_successor == next_successor,
        (KeyState::Eligible, KeyState::Superseded | KeyState::Revoked) => true,
        (KeyState::Superseded, KeyState::Superseded) => current_successor == next_successor,
        (KeyState::Superseded, KeyState::Revoked) => true,
        (KeyState::Revoked, KeyState::Revoked) => true,
        _ => false,
    };
    let authority_state_monotone = matches!(
        (current_authority_state, next_authority_state),
        (
            AuthorityState::Trusted,
            AuthorityState::Trusted | AuthorityState::Revoked
        ) | (AuthorityState::Revoked, AuthorityState::Revoked)
    );
    current.signer() == next.signer()
        && current.public_key() == next.public_key()
        && current.trust_head() == next.trust_head()
        && current.revocation_head() == next.revocation_head()
        && current.validity() == next.validity()
        && current_authority_from == next_authority_from
        && current_authority_until == next_authority_until
        && ((current_key_state == next_key_state
            && current.state_effective_head() == next.state_effective_head())
            || current_key_state != next_key_state)
        && ((current_authority_state == next_authority_state
            && current.authority_state_effective_head() == next.authority_state_effective_head())
            || current_authority_state != next_authority_state)
        && key_state_monotone
        && authority_state_monotone
}

fn recovery_effect_digest(
    purpose: &[u8],
    acquisition_id: ObjectDigest,
    effect_id: [u8; 16],
    attempt_digest: ObjectDigest,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.source-provider.recovery-effect.v1\0");
    hasher.update((purpose.len() as u32).to_be_bytes());
    hasher.update(purpose);
    hasher.update(acquisition_id.as_bytes());
    hasher.update(effect_id);
    hasher.update(attempt_digest.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}
