//! Protected current policy and generation state for publisher admission.
//!
//! This store retains immutable canonical policy revisions, atomic current
//! pointers, immutable logical cache-resource bindings, and independent
//! controller-authority and revocation generation chains. It validates the
//! complete namespace before allowing reads. It does not model publisher
//! instances, publication roots, source evidence, reservations, or permits.
//!
//! This is a trusted controller-administration facade: its caller authorizes
//! every mutation and must be the sole writer of namespace 8. Replay validates
//! the currently retained records and their contiguous cross-links. It is not
//! cryptographic anti-rollback protection and cannot detect a validly encoded
//! rewrite performed through lower-level journal access.

use aos_sandbox_core::format::{decode_policy, encode_policy};
use aos_sandbox_core::model::{CacheDomain, CacheDomainKind, Policy};
use aos_sandbox_core::{
    DecodeLimits, MediaType, ObjectDescriptor, ObjectDigest, Operation, PrincipalId, ProjectId,
    ResourceId, ResourceKind, RevocationScopeId, descriptor_for_bytes, validate_required_features,
};

use crate::{
    CommitResult, Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace,
};

const POLICY_REVISION_PREFIX: &[u8] = b"policy/revision/";
const POLICY_CURRENT_PREFIX: &[u8] = b"policy/current/";
const RESOURCE_PREFIX: &[u8] = b"resource/";
const CONTROLLER_REVISION_PREFIX: &[u8] = b"controller/revision/";
const CONTROLLER_CURRENT_KEY: &[u8] = b"controller/current";
const REVOCATION_REVISION_PREFIX: &[u8] = b"revocation/revision/";
const REVOCATION_CURRENT_PREFIX: &[u8] = b"revocation/current/";

const POLICY_REVISION_MAGIC: &[u8; 8] = b"AOSPOLR1";
const POLICY_CURRENT_MAGIC: &[u8; 8] = b"AOSPOLH1";
const RESOURCE_MAGIC: &[u8; 8] = b"AOSRESB1";
const CONTROLLER_REVISION_MAGIC: &[u8; 8] = b"AOSCTLR1";
const CONTROLLER_CURRENT_MAGIC: &[u8; 8] = b"AOSCTLH1";
const REVOCATION_REVISION_MAGIC: &[u8; 8] = b"AOSREVR1";
const REVOCATION_CURRENT_MAGIC: &[u8; 8] = b"AOSREVH1";

const MAXIMUM_POLICY_BYTES: usize = 4 * 1024 * 1024;
const MAXIMUM_RECORDS: usize = 65_536;
const MAXIMUM_RECORD_BYTES: usize = MAXIMUM_POLICY_BYTES + 128;
const MAXIMUM_MATERIALIZED_BYTES: usize = 512 * 1024 * 1024;
const MAXIMUM_COLLECTION_ITEMS: usize = 1_024;
const MAXIMUM_TOTAL_ITEMS: usize = 65_536;
const MAXIMUM_STRING_BYTES: usize = 64 * 1024;
const MAXIMUM_DEPTH: usize = 64;

mod model;
pub use model::{
    PreparedPublisherPolicyRevisionV1, PublisherControllerHeadV1, PublisherPolicyError,
    PublisherPolicyLimits, PublisherResourceBindingV1, PublisherRevocationHeadV1,
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
    /// policy-resource cross-link, or canonical encoding is invalid.
    pub fn load(
        journal: &'journal mut Journal,
        limits: PublisherPolicyLimits,
    ) -> Result<Self, PublisherPolicyError> {
        journal.ensure_protected_authority()?;
        let (records, materialized_bytes) = validate_namespace(journal, limits)?;
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
        let Some(head_bytes) = self.journal.get(
            RecordNamespace::PublisherPolicy,
            &policy_current_key(project),
        ) else {
            return Ok(None);
        };
        let head = decode_policy_head(head_bytes)?;
        if head.project != project {
            return Err(PublisherPolicyError::CorruptState);
        }
        let bytes = self
            .journal
            .get(
                RecordNamespace::PublisherPolicy,
                &policy_revision_key(project, head.generation),
            )
            .ok_or(PublisherPolicyError::CorruptState)?;
        let revision = decode_policy_revision(bytes)?;
        if revision.project != project
            || revision.generation != head.generation
            || revision.descriptor.digest() != head.digest
        {
            return Err(PublisherPolicyError::CorruptState);
        }
        validate_policy_resources(self.journal, &revision)?;
        Ok(Some(revision))
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
            .is_some_and(|value| value.resource != resource)
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
        self.journal
            .get(RecordNamespace::PublisherPolicy, CONTROLLER_CURRENT_KEY)
            .map(|bytes| decode_controller(bytes, CONTROLLER_CURRENT_MAGIC))
            .transpose()
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
        let head = self
            .journal
            .get(
                RecordNamespace::PublisherPolicy,
                &revocation_current_key(scope),
            )
            .map(|bytes| decode_revocation(bytes, REVOCATION_CURRENT_MAGIC))
            .transpose()?;
        if head.as_ref().is_some_and(|value| value.scope != scope) {
            return Err(PublisherPolicyError::CorruptState);
        }
        Ok(head)
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
        validate_policy_resources(self.journal, prepared)?;
        let current = self.current_policy(prepared.project)?;
        validate_successor(
            current
                .as_ref()
                .map(PreparedPublisherPolicyRevisionV1::generation),
            expected_generation,
            prepared.generation,
        )?;
        let revision_key = policy_revision_key(prepared.project, prepared.generation);
        if self
            .journal
            .get(RecordNamespace::PublisherPolicy, &revision_key)
            .is_some()
        {
            return Err(PublisherPolicyError::RevisionAlreadyExists);
        }
        let revision_bytes = 84usize
            .checked_add(prepared.canonical_policy.len())
            .ok_or(PublisherPolicyError::LimitExceeded("policy revision bytes"))?;
        if revision_bytes > self.limits.maximum_record_bytes {
            return Err(PublisherPolicyError::LimitExceeded("policy revision bytes"));
        }
        let records = vec![
            JournalRecord::put(
                RecordNamespace::PublisherPolicy,
                revision_key,
                encode_policy_revision(prepared)?,
            ),
            JournalRecord::put(
                RecordNamespace::PublisherPolicy,
                policy_current_key(prepared.project),
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
        let key = resource_key(binding.resource);
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

    fn commit_bounded(
        &mut self,
        transaction_id: [u8; 16],
        records: Vec<JournalRecord>,
    ) -> Result<CommitResult, PublisherPolicyError> {
        let mut next_records = self.records;
        let mut next_bytes = self.materialized_bytes;
        for record in &records {
            if record.value().is_none()
                || record
                    .value()
                    .is_some_and(|value| value.len() > self.limits.maximum_record_bytes)
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
        if next_records > self.limits.maximum_records
            || next_bytes > self.limits.maximum_materialized_bytes
        {
            return Err(PublisherPolicyError::LimitExceeded(
                "materialized namespace",
            ));
        }
        let transaction = JournalTransaction::new(transaction_id, records)?;
        let result = self.journal.commit(&transaction)?;
        self.records = next_records;
        self.materialized_bytes = next_bytes;
        Ok(result)
    }
}

mod record;
use record::*;

mod replay;
use replay::{validate_namespace, validate_policy_resources};

#[cfg(test)]
mod tests;
