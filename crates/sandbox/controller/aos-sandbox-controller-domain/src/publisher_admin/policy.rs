//! Protected current policy and generation state for publisher admission.
//!
//! This store retains immutable canonical policy revisions, atomic current
//! pointers, immutable logical cache-resource and project-revocation bindings,
//! and independent controller-authority and revocation generation chains. It
//! validates the complete namespace before allowing reads. V2 policy revisions
//! retain original compiler input/output provenance as data, not authenticated
//! source-owner evidence. The store does not model publisher instances,
//! publication roots, reservations, or permits.
//!
//! This is a trusted controller-administration facade: its caller authorizes
//! every mutation and must be the sole writer of namespace 8. Replay validates
//! the currently retained records and their contiguous cross-links. It is not
//! cryptographic anti-rollback protection and cannot detect a validly encoded
//! rewrite performed through lower-level journal access.

use aos_sandbox_model::model::{CacheDomain, CacheDomainKind};
use aos_sandbox_model::{
    DecodeLimits, ObjectDescriptor, ObjectDigest, Operation, PrincipalId, ProjectId, ResourceId,
    ResourceKind, RevocationScopeId,
};
use sha2::{Digest as _, Sha256};

use crate::{
    CommitResult, Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace,
};

use aos_sandbox_protocol::publisher_policy::*;
pub(crate) use aos_sandbox_protocol::publisher_policy::project_revocation_digest;
mod model;
use aos_sandbox_protocol::policy_data::PreparedPublisherPolicyRevisionV1;
mod account_coverage;
mod git_upload_capacity;
pub(crate) use git_upload_capacity::{
    require_complete_coverage_read_state_data_v1, require_coverage_native_account_transaction,
};
pub use git_upload_capacity::{
    GitUploadBootstrapAppendV1, GitUploadBootstrapDataRefV1, GitUploadBootstrapErrorV1,
    GitUploadEnrolledAccountAppendV1, VerifiedPublisherPolicySourceV1,
};
mod project_authorization_source_v2;
mod project_authorization_store_v2;
mod project_genesis_error;
#[cfg(any(target_os = "linux", test))]
pub(crate) use project_authorization_store_v2::CurrentSourceTreeSeedPreflightErrorV1;
pub use project_genesis_error::PublisherProjectGenesisErrorV1;
#[cfg(test)]
mod project_authorization_test_fixture;
pub use model::PublisherPolicyError;
mod observation;
pub(crate) use observation::{PublisherPolicyObservationV2, publisher_observation_control_bytes_v2};
pub use aos_sandbox_protocol::publisher_policy::{PublisherControllerHeadV1, PublisherPolicyLimits, PublisherProjectCacheDomainHeadV1, PublisherProjectRevocationHeadV1, PublisherResourceBindingV1, PublisherRevocationHeadV1};
pub use project_authorization_source_v2::{
    ProjectAuthorizationSourceErrorV2, ProjectAuthorizationSourceExpectedV2,
    VerifiedPublisherProjectAuthorizationSourceV2, verify_current_project_authorization_source_v2,
};

/// Provides exclusive access to validated current publisher policy state.
pub struct PublisherPolicyStore<'journal> {
    journal: &'journal mut Journal,
    limits: PublisherPolicyLimits,
    records: usize,
    materialized_bytes: usize,
}

impl<'journal> PublisherPolicyStore<'journal> {
    /// Validates the complete protected publisher-policy namespace.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherPolicyError`] if storage is unprotected or poisoned,
    /// bounds are exceeded, or any family, record, revision chain, current head,
    /// policy-resource or project-revocation cross-link, or canonical encoding
    /// is invalid.
    pub fn load(
        journal: &'journal mut Journal,
        limits: PublisherPolicyLimits,
    ) -> Result<Self, PublisherPolicyError> {
        journal.ensure_protected_authority()?;
        let (records, materialized_bytes) = validate_namespace(super::PublisherReadDataV2::from_state_v2(journal.historical_read_view_v1().materialized_state_v1()), limits)?;
        Ok(Self {
            journal,
            limits,
            records,
            materialized_bytes,
        })
    }

    /// Resolves the current policy for a project.
    ///
    /// # Errors
    ///
    /// Returns a journal or malformed-state error. `Ok(None)` means no policy is current.
    pub fn current_policy(
        &self,
        project: ProjectId,
    ) -> Result<Option<PreparedPublisherPolicyRevisionV1>, PublisherPolicyError> {
        self.journal.ensure_protected_authority()?;
        current_data::current_policy_from_data_v2(super::PublisherReadDataV2::from_state_v2(self.journal.historical_read_view_v1().materialized_state_v1()), project).map_err(PublisherPolicyError::from)
    }

    /// Resolves one immutable cache-resource binding.
    ///
    /// # Errors
    ///
    /// Returns a journal or malformed-state error. `Ok(None)` means the resource is unknown.
    pub fn resource_binding(
        &self,
        resource: ResourceId,
    ) -> Result<Option<PublisherResourceBindingV1>, PublisherPolicyError> {
        self.journal.ensure_protected_authority()?;
        let binding = self
            .journal
            .get(RecordNamespace::PublisherPolicy, &resource_key(resource))
            .map(decode_resource)
            .transpose()?;
        if binding
            .as_ref()
            .is_some_and(|value| value.resource() != resource)
        {
            return Err(PublisherPolicyError::CorruptState);
        }
        Ok(binding)
    }

    /// Resolves the current controller authority head.
    ///
    /// # Errors
    ///
    /// Returns a journal or malformed-state error. `Ok(None)` means no head is installed.
    pub fn controller_head(
        &self,
    ) -> Result<Option<PublisherControllerHeadV1>, PublisherPolicyError> {
        self.journal.ensure_protected_authority()?;
        current_data::controller_head_from_data_v2(super::PublisherReadDataV2::from_state_v2(self.journal.historical_read_view_v1().materialized_state_v1())).map_err(PublisherPolicyError::from)
    }

    /// Resolves one current revocation generation.
    ///
    /// # Errors
    ///
    /// Returns a journal or malformed-state error. `Ok(None)` means the scope is unknown.
    pub fn revocation_head(
        &self,
        scope: RevocationScopeId,
    ) -> Result<Option<PublisherRevocationHeadV1>, PublisherPolicyError> {
        self.journal.ensure_protected_authority()?;
        current_data::revocation_head_from_data_v2(super::PublisherReadDataV2::from_state_v2(self.journal.historical_read_view_v1().materialized_state_v1()), scope).map_err(PublisherPolicyError::from)
    }

    /// Resolves the independent current revocation head bound to one project.
    ///
    /// The mapping and scope generation come from the same protected journal
    /// claim as the current publisher revision. This observation does not hold
    /// other writers across a later policy binding or effect.
    ///
    /// # Errors
    ///
    /// Returns a journal or corrupt-state error for a malformed or dangling
    /// mapping. `Ok(None)` means the trusted publisher has not bound a scope.
    pub fn project_revocation_head(
        &self,
        project: ProjectId,
    ) -> Result<Option<PublisherProjectRevocationHeadV1>, PublisherPolicyError> {
        self.journal.ensure_protected_authority()?;
        let Some(scope) = current_data::project_revocation_scope_from_data_v2(
            super::PublisherReadDataV2::from_state_v2(
                self.journal.historical_read_view_v1().materialized_state_v1(),
            ), project,
        ).map_err(PublisherPolicyError::from)? else {
            return Ok(None);
        };
        self.journal.ensure_protected_authority()?;
        current_data::project_revocation_head_from_scope_data_v2(
            super::PublisherReadDataV2::from_state_v2(
                self.journal.historical_read_view_v1().materialized_state_v1(),
            ), project, scope,
        ).map(Some).map_err(PublisherPolicyError::from)
    }

    /// Resolves the project disclosure choice of the current protected policy.
    ///
    /// This publisher-owned head is not a physical cache-residency head. The
    /// caller must retain the journal claim through any cross-owner authority
    /// decision that relies on it.
    ///
    /// # Errors
    ///
    /// Returns a journal or corrupt-state error, or rejects a current policy
    /// whose project disclosure identity is not the exact project. `Ok(None)`
    /// means no publisher policy is current for the project.
    pub fn project_cache_domain_head(
        &self,
        project: ProjectId,
    ) -> Result<Option<PublisherProjectCacheDomainHeadV1>, PublisherPolicyError> {
        self.journal.ensure_protected_authority()?;
        current_data::project_cache_domain_head_from_data_v2(
            super::PublisherReadDataV2::from_state_v2(
                self.journal.historical_read_view_v1().materialized_state_v1(),
            ), project,
        ).map_err(PublisherPolicyError::from)
    }

    /// Compares a project cache-domain claim with the exact current head.
    ///
    /// This read alone does not retain authority across a later cross-owner
    /// commit or effect handoff.
    ///
    /// # Errors
    ///
    /// Returns a journal or invalid-binding error when current state cannot
    /// establish the protected head. An absent policy returns `Ok(false)`.
    pub fn verify_project_cache_domain_claim(
        &self,
        project: ProjectId,
        claimed: ObjectDigest,
    ) -> Result<bool, PublisherPolicyError> {
        Ok(self
            .project_cache_domain_head(project)?
            .is_some_and(|head| head.digest() == claimed))
    }

    /// Atomically appends a policy revision and advances its exact current head.
    ///
    /// `expected_generation` is `None` only for generation one. This trusted
    /// administrative method additionally requires every effective cache-publish
    /// grant to name an already installed matching resource binding.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherPolicyError`] on CAS failure, a noncontiguous successor,
    /// missing resource cross-link, capacity excess, or journal failure.
    pub fn publish_policy_from_trusted_controller(
        &mut self,
        transaction_id: [u8; 16],
        expected_generation: Option<u64>,
        prepared: &PreparedPublisherPolicyRevisionV1,
    ) -> Result<CommitResult, PublisherPolicyError> {
        self.journal.ensure_protected_authority()?;
        validate_policy_resources_from_data_v2(super::PublisherReadDataV2::from_state_v2(self.journal.historical_read_view_v1().materialized_state_v1()), prepared)?;
        let current = self.current_policy(prepared.project())?;
        validate_successor(
            current
                .as_ref()
                .map(PreparedPublisherPolicyRevisionV1::generation),
            expected_generation,
            prepared.generation(),
        )?;
        let revision_key = policy_revision_key(prepared.project(), prepared.generation());
        if self
            .journal
            .get(RecordNamespace::PublisherPolicy, &revision_key)
            .is_some()
        {
            return Err(PublisherPolicyError::RevisionAlreadyExists);
        }
        let revision_bytes = encode_policy_revision(prepared)?;
        if revision_bytes.len() > self.limits.maximum_record_bytes() {
            return Err(PublisherPolicyError::LimitExceeded("policy revision bytes"));
        }
        let records = vec![
            JournalRecord::put(
                RecordNamespace::PublisherPolicy,
                revision_key,
                revision_bytes,
            ),
            JournalRecord::put(
                RecordNamespace::PublisherPolicy,
                policy_current_key(prepared.project()),
                encode_policy_head(prepared),
            ),
        ];
        self.commit_bounded(transaction_id, records)
    }

    /// Durably installs one immutable cache-resource binding.
    ///
    /// # Errors
    ///
    /// Returns an error if the resource ID was used, bounds are exceeded, or commit fails.
    pub fn install_resource_from_trusted_controller(
        &mut self,
        transaction_id: [u8; 16],
        binding: &PublisherResourceBindingV1,
    ) -> Result<CommitResult, PublisherPolicyError> {
        self.journal.ensure_protected_authority()?;
        let key = resource_key(binding.resource());
        if self
            .journal
            .get(RecordNamespace::PublisherPolicy, &key)
            .is_some()
        {
            return Err(PublisherPolicyError::ResourceAlreadyExists);
        }
        self.commit_bounded(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::PublisherPolicy,
                key,
                encode_resource(binding),
            )],
        )
    }

    /// Atomically advances the immutable-principal controller authority chain.
    ///
    /// # Errors
    ///
    /// Returns an error for zero identity/generation, CAS or contiguity failure,
    /// principal substitution, bounds, or journal failure.
    pub fn advance_controller_from_trusted_controller(
        &mut self,
        transaction_id: [u8; 16],
        expected_generation: Option<u64>,
        next: PublisherControllerHeadV1,
    ) -> Result<CommitResult, PublisherPolicyError> {
        self.journal.ensure_protected_authority()?;
        if next.principal.as_bytes() == &[0; 16] || next.generation == 0 {
            return Err(PublisherPolicyError::InvalidGenerationHead);
        }
        let current = self.controller_head()?;
        validate_successor(
            current.map(|head| head.generation),
            expected_generation,
            next.generation,
        )?;
        if current.is_some_and(|head| head.principal != next.principal) {
            return Err(PublisherPolicyError::ControllerPrincipalMismatch);
        }
        let key = controller_revision_key(next.generation);
        if self
            .journal
            .get(RecordNamespace::PublisherPolicy, &key)
            .is_some()
        {
            return Err(PublisherPolicyError::RevisionAlreadyExists);
        }
        self.commit_bounded(
            transaction_id,
            vec![
                JournalRecord::put(
                    RecordNamespace::PublisherPolicy,
                    key,
                    encode_controller(next, CONTROLLER_REVISION_MAGIC),
                ),
                JournalRecord::put(
                    RecordNamespace::PublisherPolicy,
                    CONTROLLER_CURRENT_KEY.to_vec(),
                    encode_controller(next, CONTROLLER_CURRENT_MAGIC),
                ),
            ],
        )
    }

    /// Atomically advances one independent revocation-scope generation chain.
    ///
    /// # Errors
    ///
    /// Returns an error for zero identity/generation, CAS or contiguity failure,
    /// bounds, or journal failure.
    pub fn advance_revocation_from_trusted_controller(
        &mut self,
        transaction_id: [u8; 16],
        expected_generation: Option<u64>,
        next: PublisherRevocationHeadV1,
    ) -> Result<CommitResult, PublisherPolicyError> {
        self.journal.ensure_protected_authority()?;
        if next.scope.as_bytes() == &[0; 16] || next.generation == 0 {
            return Err(PublisherPolicyError::InvalidGenerationHead);
        }
        let current = self.revocation_head(next.scope)?;
        validate_successor(
            current.map(|head| head.generation),
            expected_generation,
            next.generation,
        )?;
        let key = revocation_revision_key(next.scope, next.generation);
        if self
            .journal
            .get(RecordNamespace::PublisherPolicy, &key)
            .is_some()
        {
            return Err(PublisherPolicyError::RevisionAlreadyExists);
        }
        self.commit_bounded(
            transaction_id,
            vec![
                JournalRecord::put(
                    RecordNamespace::PublisherPolicy,
                    key,
                    encode_revocation(next, REVOCATION_REVISION_MAGIC),
                ),
                JournalRecord::put(
                    RecordNamespace::PublisherPolicy,
                    revocation_current_key(next.scope),
                    encode_revocation(next, REVOCATION_CURRENT_MAGIC),
                ),
            ],
        )
    }

    /// Installs one immutable project-to-revocation-scope binding.
    ///
    /// Only the trusted controller/publisher owner may call this method after
    /// installing both the current project policy and independent scope head.
    /// Public Create requests cannot select or replace this mapping.
    ///
    /// # Errors
    ///
    /// Returns an error for a sentinel, absent current policy or scope head,
    /// an existing mapping, or a failed protected commit.
    pub fn bind_project_revocation_scope_from_trusted_controller(
        &mut self,
        transaction_id: [u8; 16],
        project: ProjectId,
        scope: RevocationScopeId,
    ) -> Result<CommitResult, PublisherPolicyError> {
        self.journal.ensure_protected_authority()?;
        if project.as_bytes() == &[0; 16] || scope.as_bytes() == &[0; 16] {
            return Err(PublisherPolicyError::InvalidProjectRevocationBinding);
        }
        let key = project_revocation_key(project);
        if self
            .journal
            .get(RecordNamespace::PublisherPolicy, &key)
            .is_some()
        {
            return Err(PublisherPolicyError::ProjectRevocationBindingAlreadyExists);
        }
        if self.current_policy(project)?.is_none() || self.revocation_head(scope)?.is_none() {
            return Err(PublisherPolicyError::InvalidProjectRevocationBinding);
        }
        self.commit_bounded(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::PublisherPolicy,
                key,
                encode_project_revocation_binding(project, scope),
            )],
        )
    }

    fn commit_bounded(
        &mut self,
        transaction_id: [u8; 16],
        records: Vec<JournalRecord>,
    ) -> Result<CommitResult, PublisherPolicyError> {
        let (next_records, next_bytes) = self.bounded_replacement_totals(&records)?;
        let transaction =
            JournalTransaction::new(transaction_id, records).map_err(JournalError::from)?;
        let result = self.journal.commit(&transaction)?;
        self.records = next_records;
        self.materialized_bytes = next_bytes;
        Ok(result)
    }

    // Shared namespace arithmetic; ordinary construction remains after checks.
    fn bounded_replacement_totals(
        &self,
        records: &[JournalRecord],
    ) -> Result<(usize, usize), PublisherPolicyError> {
        let mut next_records = self.records;
        let mut next_bytes = self.materialized_bytes;
        for record in records {
            if record.value().is_none()
                || record
                    .value()
                    .is_some_and(|value| value.len() > self.limits.maximum_record_bytes())
            {
                return Err(PublisherPolicyError::LimitExceeded("record bytes"));
            }
            let old = self
                .journal
                .get(RecordNamespace::PublisherPolicy, record.key());
            if old.is_none() {
                next_records = next_records
                    .checked_add(1)
                    .ok_or(PublisherPolicyError::LimitExceeded("record count"))?;
            }
            next_bytes = next_bytes
                .checked_sub(old.map_or(0, |value| record.key().len() + value.len()))
                .and_then(|value| {
                    value.checked_add(record.key().len() + record.value().map_or(0, <[u8]>::len))
                })
                .ok_or(PublisherPolicyError::LimitExceeded("materialized bytes"))?;
        }
        if next_records > self.limits.maximum_records()
            || next_bytes > self.limits.maximum_materialized_bytes()
        {
            return Err(PublisherPolicyError::LimitExceeded(
                "materialized namespace",
            ));
        }
        Ok((next_records, next_bytes))
    }
}


mod cache_domain;
pub use cache_domain::PublisherProjectCacheDomainVerifierV1;

use aos_sandbox_protocol::publisher_policy::record::*;
aos_sandbox_protocol::define_provider_record_helpers_data_recipe_v1!(PublisherPolicyError::CorruptState);

use aos_sandbox_protocol::publisher_policy::replay::{validate_namespace, validate_policy_resources_from_data_v2};

#[cfg(test)]
mod tests;

use aos_sandbox_protocol::publisher_policy::current_data;
pub(crate) use current_data::{current_policy_from_data_v2, controller_head_from_data_v2, revocation_head_from_data_v2};
