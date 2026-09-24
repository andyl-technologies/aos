//! Durable controller-owned publisher capability registry.
//!
//! The registry stores complete validated [`CapabilityRecord`] values in the
//! protected controller journal. Through this facade each capability ID is
//! immutable: an active record may become a tombstone, but neither state may be
//! replaced by a new record. Loading validates the materialized namespace before
//! any lookup is allowed. The trusted controller must make this facade the sole
//! writer of the namespace; generic journal writes do not enforce its history.
//!
//! This is an administrative persistence boundary. Its mutation methods are
//! intended only for an already-authenticated protected controller path. A
//! successful lookup does not authenticate a request, evaluate a capability,
//! establish revocation currentness, or create a publication completion permit.
//!
//! Namespace records use the binary key `"capability/" || capability_id` and
//! one strict canonical JSON value. Version 1 stores a root record; version 2
//! adds a mandatory immutable `parent` identity for an attenuated child:
//!
//! ```text
//! {"version":1,"state":0,"capability":{...complete CapabilityRecord...},
//!  "issuance":null|{...immutable local issuance metadata...},
//!  "claims_digest":null|[...],"runtime":null|{...historical provenance...}}
//! {"version":2,"state":0,"capability":{...complete CapabilityRecord...},
//!  "issuance":null|{...immutable local issuance metadata...},
//!  "claims_digest":null|[...],"runtime":null|{...historical provenance...},
//!  "parent":[...capability identity...]}
//! {"version":3,"state":0,"capability":{...complete CapabilityRecord...},
//!  "issuance":null|{...immutable local issuance metadata...},
//!  "claims_digest":null|[...],"runtime":null|{...historical provenance...},
//!  "parent":[...capability identity...] (if child),"handle":[...32 random bytes...]}
//! ```
//!
//! Issuance metadata and its domain-separated claims digest are either both
//! present or both absent. Runtime evidence requires that pair and additionally
//! references an immutable protected holder decision and the original Host
//! observation's bounded lifetime. Replay revalidates all identity, decision,
//! claim, timing, and historical runtime cross-links. None of these bytes restore
//! live execution pins or prove that the historical holder remains current.
//!
//! State `0` is active and state `1` is revoked. Both state encodings have
//! equal length in every legal record form, so a tombstone consumes no additional
//! materialized-value allowance. Journal append capacity for administrative
//! maintenance remains an external provisioning requirement; a revocation is
//! never reported before its commit.

use std::collections::BTreeMap;
use std::io;

use aos_sandbox_core::{CapabilityId, CapabilityRecord, ChannelBinding, PrincipalId};
use rand::{TryRngCore as _, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    CommitResult, Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace,
};

mod issuance;
mod runtime_issuance;
pub use issuance::{
    IssuanceDecisionMetadataDraftV1, IssuanceDecisionMetadataV1, ValidatedCapabilityIssuanceV1,
};
pub use runtime_issuance::RuntimeIssuanceEvidenceV1;

const RECORD_VERSION_V1: u16 = 1;
const RECORD_VERSION_V2: u16 = 2;
const RECORD_VERSION_V3: u16 = 3;
const HANDLE_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.public-capability-handle.v1\0";
const RECORD_FAMILY: &[u8] = b"capability/";
const RECORD_KEY_BYTES: usize = RECORD_FAMILY.len() + 16;
const MAXIMUM_ENTRIES: usize = 65_536;
const MAXIMUM_RECORD_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_MATERIALIZED_BYTES: usize = 512 * 1024 * 1024;

/// Bounds registry replay and per-mutation encoding work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublisherAuthorityLimits {
    maximum_entries: usize,
    maximum_record_bytes: usize,
    maximum_materialized_bytes: usize,
    runtime_limits: crate::runtime_authority::RuntimeAuthorityLimits,
}

impl PublisherAuthorityLimits {
    pub(crate) const fn runtime_limits(&self) -> crate::runtime_authority::RuntimeAuthorityLimits {
        self.runtime_limits
    }

    /// Constructs limits within the fixed implementation ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAuthorityError::InvalidLimits`] if any limit is zero
    /// or exceeds its implementation ceiling.
    pub fn new(
        maximum_entries: usize,
        maximum_record_bytes: usize,
        maximum_materialized_bytes: usize,
    ) -> Result<Self, PublisherAuthorityError> {
        if maximum_entries == 0
            || maximum_entries > MAXIMUM_ENTRIES
            || maximum_record_bytes == 0
            || maximum_record_bytes > MAXIMUM_RECORD_BYTES
            || maximum_materialized_bytes == 0
            || maximum_materialized_bytes > MAXIMUM_MATERIALIZED_BYTES
        {
            return Err(PublisherAuthorityError::InvalidLimits);
        }
        Ok(Self {
            maximum_entries,
            maximum_record_bytes,
            maximum_materialized_bytes,
            runtime_limits: crate::runtime_authority::RuntimeAuthorityLimits::default(),
        })
    }

    /// Sets independent replay bounds for runtime-issued capabilities' historical provenance.
    ///
    /// Administrative records need no runtime namespace. Records with runtime
    /// evidence additionally require its complete validation within these bounds.
    #[must_use]
    pub const fn with_runtime_limits(
        mut self,
        limits: crate::runtime_authority::RuntimeAuthorityLimits,
    ) -> Self {
        self.runtime_limits = limits;
        self
    }
}

impl Default for PublisherAuthorityLimits {
    fn default() -> Self {
        Self {
            maximum_entries: MAXIMUM_ENTRIES,
            maximum_record_bytes: MAXIMUM_RECORD_BYTES,
            maximum_materialized_bytes: MAXIMUM_MATERIALIZED_BYTES,
            runtime_limits: crate::runtime_authority::RuntimeAuthorityLimits::default(),
        }
    }
}

/// Provides exclusive, validated access to durable publisher capabilities.
pub struct PublisherCapabilityRegistry<'journal> {
    journal: &'journal mut Journal,
    limits: PublisherAuthorityLimits,
    entries: usize,
    materialized_bytes: usize,
    handle_index: BTreeMap<[u8; 32], CapabilityId>,
}

impl<'journal> PublisherCapabilityRegistry<'journal> {
    /// Validates and borrows the complete durable publisher-authority namespace.
    ///
    /// The journal must have been opened through a protected opener. This scan
    /// validates every key and value before returning, retaining aggregate
    /// counters and a bounded digest-to-UID handle index. The exclusive journal
    /// borrow keeps this index current; prepared records commit only after the
    /// registry is dropped and the next load rebuilds it. Lookup decodes the
    /// exact journal record and rechecks its protected holder binding.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAuthorityError`] if the journal is unprotected or
    /// poisoned, limits are exceeded, or any retained key or value is malformed,
    /// unsupported, noncanonical, or bound to a different capability ID.
    pub fn load(
        journal: &'journal mut Journal,
        limits: PublisherAuthorityLimits,
    ) -> Result<Self, PublisherAuthorityError> {
        journal.ensure_protected_authority()?;
        let mut entries = 0_usize;
        let mut materialized_bytes = 0_usize;
        let mut has_runtime_issuance = false;
        let mut handle_index = BTreeMap::new();
        let mut child_counts = BTreeMap::<CapabilityId, u32>::new();
        for (key, value) in journal.records(RecordNamespace::PublisherAuthority) {
            entries = entries
                .checked_add(1)
                .ok_or(PublisherAuthorityError::LimitExceeded("entry count"))?;
            if entries > limits.maximum_entries {
                return Err(PublisherAuthorityError::LimitExceeded("entry count"));
            }
            capability_id_from_key(key)?;
            if value.len() > limits.maximum_record_bytes {
                return Err(PublisherAuthorityError::LimitExceeded("record bytes"));
            }
            materialized_bytes = materialized_bytes
                .checked_add(key.len())
                .and_then(|bytes| bytes.checked_add(value.len()))
                .ok_or(PublisherAuthorityError::LimitExceeded("materialized bytes"))?;
            if materialized_bytes > limits.maximum_materialized_bytes {
                return Err(PublisherAuthorityError::LimitExceeded("materialized bytes"));
            }
            let record = decode_record(key, value, limits.maximum_record_bytes)?;
            if let Some(handle) = record.handle {
                if handle_index
                    .insert(handle_digest(&handle), record.capability.id())
                    .is_some()
                {
                    return Err(PublisherAuthorityError::DuplicateHandle);
                }
            }
            has_runtime_issuance |= record.runtime.is_some();
            if let Some(parent) = record.parent {
                let parent_key = capability_key(parent);
                let parent_bytes = journal
                    .get(RecordNamespace::PublisherAuthority, &parent_key)
                    .ok_or(PublisherAuthorityError::InvalidParentLink)?;
                let parent_record =
                    decode_record(&parent_key, parent_bytes, limits.maximum_record_bytes)?;
                validate_parent_link(&parent_record.capability, &record.capability)?;

                let count = child_counts.entry(parent).or_default();
                *count = count
                    .checked_add(1)
                    .ok_or(PublisherAuthorityError::LimitExceeded("parent fanout"))?;
            }
        }

        for (parent_id, child_count) in child_counts {
            let key = capability_key(parent_id);
            let parent = journal
                .get(RecordNamespace::PublisherAuthority, &key)
                .ok_or(PublisherAuthorityError::InvalidParentLink)?;
            let parent = decode_record(&key, parent, limits.maximum_record_bytes)?;
            if child_count > parent.capability.claims().delegation.maximum_fanout() {
                return Err(PublisherAuthorityError::FanoutExceeded);
            }
        }

        if has_runtime_issuance {
            // Validate the bounded namespace once; individual immutable history
            // lookups cannot interleave with another writer under this borrow.
            crate::runtime_authority::RuntimeAuthorityStore::load(journal, limits.runtime_limits)?;
            for (key, value) in journal.records(RecordNamespace::PublisherAuthority) {
                let record = decode_record(key, value, limits.maximum_record_bytes)?;
                if let Some(runtime) = record.runtime {
                    runtime.validate_provenance(journal, &record.capability)?;
                }
            }
        }

        Ok(Self {
            journal,
            limits,
            entries,
            materialized_bytes,
            handle_index,
        })
    }

    /// Resolves one current active record by its immutable capability ID.
    ///
    /// Returned records are owned so no unvalidated journal bytes escape. The
    /// caller must still authenticate its request and call the capability's
    /// authorization API with controller-owned dynamic context.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAuthorityError::UnknownCapability`] when no ID was
    /// installed, [`PublisherAuthorityError::Revoked`] for a tombstone, or a
    /// fail-closed journal/record error if current authority cannot be trusted.
    pub fn resolve_current(
        &self,
        id: CapabilityId,
    ) -> Result<CapabilityRecord, PublisherAuthorityError> {
        self.journal.ensure_protected_authority()?;
        let key = capability_key(id);
        let value = self
            .journal
            .get(RecordNamespace::PublisherAuthority, &key)
            .ok_or(PublisherAuthorityError::UnknownCapability)?;
        let record = decode_record(&key, value, self.limits.maximum_record_bytes)?;
        match record.state {
            DurableCapabilityStateV1::Active => Ok(record.capability),
            DurableCapabilityStateV1::Revoked => Err(PublisherAuthorityError::Revoked),
        }
    }

    /// Resolves a random handle only for its authenticated holder and certificate key.
    ///
    /// The caller must independently recheck its live TLS peer and then evaluate
    /// policy, expiry, revocation generation, and grants before admitting use.
    ///
    /// # Errors
    ///
    /// Rejects malformed, unknown, revoked, or differently bound handles.
    pub fn resolve_holder_handle(
        &self,
        handle: &[u8],
        holder: PrincipalId,
        binding: ChannelBinding,
    ) -> Result<CapabilityId, PublisherAuthorityError> {
        let record = self.holder_handle_record(handle, holder, binding)?;
        if record.state == DurableCapabilityStateV1::Revoked {
            return Err(PublisherAuthorityError::Revoked);
        }
        Ok(record.capability.id())
    }

    /// Resolves a retired handle only as historical evidence for exact renewal replay.
    ///
    /// The caller must subsequently prove the committed request digest and
    /// operation before using this identity. A retired handle never authorizes
    /// a new operation.
    pub(crate) fn retired_holder_handle_for_replay(
        &self,
        handle: &[u8],
        holder: PrincipalId,
        binding: ChannelBinding,
    ) -> Result<CapabilityRecord, PublisherAuthorityError> {
        let record = self.holder_handle_record(handle, holder, binding)?;
        if record.state != DurableCapabilityStateV1::Revoked {
            return Err(PublisherAuthorityError::InvalidHandle);
        }
        Ok(record.capability)
    }

    fn holder_handle_record(
        &self,
        handle: &[u8],
        holder: PrincipalId,
        binding: ChannelBinding,
    ) -> Result<DecodedCapabilityRecordV1, PublisherAuthorityError> {
        let handle: [u8; 32] = handle
            .try_into()
            .map_err(|_| PublisherAuthorityError::InvalidHandle)?;
        if handle == [0; 32] {
            return Err(PublisherAuthorityError::InvalidHandle);
        }
        self.journal.ensure_protected_authority()?;
        let lookup = handle_digest(&handle);

        let id = *self
            .handle_index
            .get(&lookup)
            .ok_or(PublisherAuthorityError::InvalidHandle)?;
        let key = capability_key(id);
        let value = self
            .journal
            .get(RecordNamespace::PublisherAuthority, &key)
            .ok_or(PublisherAuthorityError::UnknownCapability)?;
        let record = decode_record(&key, value, self.limits.maximum_record_bytes)?;
        if record.handle != Some(handle) {
            return Err(PublisherAuthorityError::InvalidHandle);
        }
        let claims = record.capability.claims();
        if claims.holder != holder || claims.channel_binding != binding {
            return Err(PublisherAuthorityError::HandleHolderMismatch);
        }
        Ok(record)
    }

    /// Returns a current handle for the authenticated holder after protected lookup.
    ///
    /// # Errors
    ///
    /// Rejects absent, revoked, legacy, or differently bound records.
    pub fn holder_handle(
        &self,
        id: CapabilityId,
        holder: PrincipalId,
        binding: ChannelBinding,
    ) -> Result<[u8; 32], PublisherAuthorityError> {
        self.journal.ensure_protected_authority()?;
        let key = capability_key(id);
        let value = self
            .journal
            .get(RecordNamespace::PublisherAuthority, &key)
            .ok_or(PublisherAuthorityError::UnknownCapability)?;
        let record = decode_record(&key, value, self.limits.maximum_record_bytes)?;
        let claims = record.capability.claims();
        if record.state == DurableCapabilityStateV1::Revoked {
            return Err(PublisherAuthorityError::Revoked);
        }
        if claims.holder != holder || claims.channel_binding != binding {
            return Err(PublisherAuthorityError::HandleHolderMismatch);
        }
        record.handle.ok_or(PublisherAuthorityError::InvalidHandle)
    }

    /// Durably installs one controller-issued capability under a fresh ID.
    ///
    /// The caller is the trusted administrative controller path and must have
    /// authenticated and authorized issuance before this call. Existing active
    /// records and tombstones are never replaced, including by identical bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAuthorityError`] for a zero or previously used ID,
    /// exceeded bounds, encoding failure, invalid transaction identity, or a
    /// journal durability failure. Ambiguous durability poisons subsequent reads.
    pub fn install_from_trusted_controller(
        &mut self,
        transaction_id: [u8; 16],
        capability: CapabilityRecord,
    ) -> Result<CommitResult, PublisherAuthorityError> {
        self.install_encoded(transaction_id, capability, None, None)
    }

    /// Prepares one fresh administrative capability record for a larger atomic commit.
    ///
    /// The returned record has passed the same namespace, identity, size, and
    /// canonical-encoding checks as [`Self::install_from_trusted_controller`].
    /// It grants no authority until the caller commits it through the same
    /// exclusively owned protected journal.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAuthorityError`] when protected authority is absent,
    /// the capability is invalid or already retained, or registry limits would
    /// be exceeded.
    pub(crate) fn prepare_install_from_trusted_controller(
        &self,
        capability: CapabilityRecord,
    ) -> Result<JournalRecord, PublisherAuthorityError> {
        self.prepare_install_encoded(capability, None, None, None)
            .map(|prepared| prepared.record)
    }

    /// Prepares one durably parent-linked attenuated child capability.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAuthorityError`] when the parent is absent or
    /// revoked, the child is not a strict structural attenuation, the durable
    /// fanout ceiling is exhausted, or ordinary installation checks fail.
    pub(crate) fn prepare_attenuation_from_trusted_controller(
        &self,
        parent_id: CapabilityId,
        child: CapabilityRecord,
    ) -> Result<JournalRecord, PublisherAuthorityError> {
        let parent_key = capability_key(parent_id);
        let parent_bytes = self
            .journal
            .get(RecordNamespace::PublisherAuthority, &parent_key)
            .ok_or(PublisherAuthorityError::UnknownCapability)?;
        let parent = decode_record(&parent_key, parent_bytes, self.limits.maximum_record_bytes)?;
        if parent.state == DurableCapabilityStateV1::Revoked {
            return Err(PublisherAuthorityError::Revoked);
        }
        validate_parent_link(&parent.capability, &child)?;

        let mut child_count = 0_u32;
        for (key, value) in self.journal.records(RecordNamespace::PublisherAuthority) {
            let retained = decode_record(key, value, self.limits.maximum_record_bytes)?;
            if retained.parent == Some(parent_id) {
                child_count = child_count
                    .checked_add(1)
                    .ok_or(PublisherAuthorityError::FanoutExceeded)?;
            }
        }
        if child_count >= parent.capability.claims().delegation.maximum_fanout() {
            return Err(PublisherAuthorityError::FanoutExceeded);
        }

        self.prepare_install_encoded(child, None, None, Some(parent_id))
            .map(|prepared| prepared.record)
    }

    /// Durably installs a local-session capability with immutable issuance evidence.
    ///
    /// Decision and capability IDs intentionally use identical bytes so audit
    /// lookup needs no second mutable index. Typed identity equality does not
    /// make the random ID an authorization credential.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid metadata or claim cross-links, an already
    /// used capability ID, exceeded bounds, or protected journal failure.
    pub fn install_local_session_from_trusted_controller(
        &mut self,
        transaction_id: [u8; 16],
        capability: CapabilityRecord,
        metadata: IssuanceDecisionMetadataV1,
    ) -> Result<CommitResult, PublisherAuthorityError> {
        let claims_digest = metadata.validate_for(&capability)?;
        self.install_encoded(
            transaction_id,
            capability,
            Some((metadata, claims_digest)),
            None,
        )
    }

    /// Installs provenance only from an intact, already rechecked live scope.
    #[cfg(target_os = "linux")]
    pub(crate) fn install_current_runtime_session(
        &mut self,
        transaction_id: [u8; 16],
        capability: CapabilityRecord,
        metadata: IssuanceDecisionMetadataV1,
        scope: &crate::runtime_scope::CurrentRuntimeScope,
    ) -> Result<CommitResult, PublisherAuthorityError> {
        let claims_digest = metadata.validate_for(&capability)?;
        let runtime = RuntimeIssuanceEvidenceV1::from_scope(scope);
        runtime.validate_for(&metadata)?;
        crate::runtime_authority::RuntimeAuthorityStore::load(
            self.journal,
            self.limits.runtime_limits,
        )?;
        runtime.validate_provenance(self.journal, &capability)?;
        self.install_encoded(
            transaction_id,
            capability,
            Some((metadata, claims_digest)),
            Some(runtime),
        )
    }

    fn install_encoded(
        &mut self,
        transaction_id: [u8; 16],
        capability: CapabilityRecord,
        issuance: Option<(IssuanceDecisionMetadataV1, aos_sandbox_core::ObjectDigest)>,
        runtime: Option<RuntimeIssuanceEvidenceV1>,
    ) -> Result<CommitResult, PublisherAuthorityError> {
        let id = capability.id();
        let prepared = self.prepare_install_encoded(capability, issuance, runtime, None)?;
        let digest = handle_digest(&prepared.handle);
        let transaction = JournalTransaction::new(transaction_id, vec![prepared.record])?;
        let result = self.journal.commit(&transaction)?;
        self.entries += 1;
        self.materialized_bytes = prepared.next_materialized_bytes;
        self.handle_index.insert(digest, id);
        Ok(result)
    }

    fn prepare_install_encoded(
        &self,
        capability: CapabilityRecord,
        issuance: Option<(IssuanceDecisionMetadataV1, aos_sandbox_core::ObjectDigest)>,
        runtime: Option<RuntimeIssuanceEvidenceV1>,
        parent: Option<CapabilityId>,
    ) -> Result<PreparedCapabilityInstallV1, PublisherAuthorityError> {
        self.journal.ensure_protected_authority()?;
        let id = capability.id();
        if id.as_bytes() == &[0; 16] {
            return Err(PublisherAuthorityError::UnspecifiedCapability);
        }
        let key = capability_key(id);
        if self
            .journal
            .get(RecordNamespace::PublisherAuthority, &key)
            .is_some()
        {
            return Err(PublisherAuthorityError::CapabilityIdAlreadyUsed);
        }
        if self.entries >= self.limits.maximum_entries {
            return Err(PublisherAuthorityError::LimitExceeded("entry count"));
        }
        let handle = random_handle()?;
        let digest = handle_digest(&handle);
        if self.handle_index.contains_key(&digest) {
            return Err(PublisherAuthorityError::DuplicateHandle);
        }
        let value = encode_record(
            DurableCapabilityStateV1::Active,
            &capability,
            issuance.as_ref(),
            runtime.as_ref(),
            parent,
            Some(handle),
            self.limits.maximum_record_bytes,
        )?;
        let next_materialized_bytes = self
            .materialized_bytes
            .checked_add(key.len())
            .and_then(|bytes| bytes.checked_add(value.len()))
            .ok_or(PublisherAuthorityError::LimitExceeded("materialized bytes"))?;
        if next_materialized_bytes > self.limits.maximum_materialized_bytes {
            return Err(PublisherAuthorityError::LimitExceeded("materialized bytes"));
        }
        Ok(PreparedCapabilityInstallV1 {
            record: JournalRecord::put(RecordNamespace::PublisherAuthority, key.to_vec(), value),
            next_materialized_bytes,
            handle,
        })
    }

    /// Resolves immutable issuance audit evidence by capability ID.
    ///
    /// Administrative records return `Ok(None)`. Records with issuance evidence
    /// return it even after capability revocation. This is audit data, not
    /// authority to exercise the capability.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown capability, poisoned journal, or
    /// malformed or inconsistent retained evidence.
    pub fn resolve_issuance(
        &self,
        id: CapabilityId,
    ) -> Result<Option<ValidatedCapabilityIssuanceV1>, PublisherAuthorityError> {
        self.journal.ensure_protected_authority()?;
        let key = capability_key(id);
        let value = self
            .journal
            .get(RecordNamespace::PublisherAuthority, &key)
            .ok_or(PublisherAuthorityError::UnknownCapability)?;
        let record = decode_record(&key, value, self.limits.maximum_record_bytes)?;
        Ok(record.issuance.map(|(metadata, claims_digest)| {
            ValidatedCapabilityIssuanceV1::new(
                metadata,
                claims_digest,
                record.state == DurableCapabilityStateV1::Revoked,
                record.runtime,
            )
        }))
    }

    /// Durably replaces one active capability with an irreversible tombstone.
    ///
    /// The tombstone retains the complete original claims for recovery and
    /// administrative audit, and this facade forbids rebinding the ID. This
    /// method performs no authorization itself; only the trusted administrative
    /// controller path may invoke it.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAuthorityError::UnknownCapability`] for an unused ID,
    /// [`PublisherAuthorityError::Revoked`] for an existing tombstone, or
    /// another registry/journal error before reporting durable completion.
    pub fn revoke_from_trusted_controller(
        &mut self,
        transaction_id: [u8; 16],
        id: CapabilityId,
    ) -> Result<CommitResult, PublisherAuthorityError> {
        self.journal.ensure_protected_authority()?;
        let key = capability_key(id);
        let current = self
            .journal
            .get(RecordNamespace::PublisherAuthority, &key)
            .ok_or(PublisherAuthorityError::UnknownCapability)?;
        let current_length = current.len();
        let record = decode_record(&key, current, self.limits.maximum_record_bytes)?;
        if record.state == DurableCapabilityStateV1::Revoked {
            return Err(PublisherAuthorityError::Revoked);
        }
        let value = encode_record(
            DurableCapabilityStateV1::Revoked,
            &record.capability,
            record.issuance.as_ref(),
            record.runtime.as_ref(),
            record.parent,
            record.handle,
            self.limits.maximum_record_bytes,
        )?;
        let next_materialized_bytes = self
            .materialized_bytes
            .checked_sub(current_length)
            .and_then(|bytes| bytes.checked_add(value.len()))
            .ok_or(PublisherAuthorityError::LimitExceeded("materialized bytes"))?;
        if next_materialized_bytes > self.limits.maximum_materialized_bytes {
            return Err(PublisherAuthorityError::LimitExceeded("materialized bytes"));
        }
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::PublisherAuthority,
                key.to_vec(),
                value,
            )],
        )?;
        let result = self.journal.commit(&transaction)?;
        self.materialized_bytes = next_materialized_bytes;
        Ok(result)
    }

    /// Prepares an irreversible tombstone for a larger atomic controller commit.
    ///
    /// The returned record is bound to the exact current active capability and
    /// has passed the same replay, encoding, and capacity checks as
    /// [`Self::revoke_from_trusted_controller`].
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAuthorityError`] when protected authority is absent,
    /// the capability is unknown or already revoked, its record is corrupt, or
    /// registry limits would be exceeded.
    pub(crate) fn prepare_revoke_from_trusted_controller(
        &self,
        id: CapabilityId,
    ) -> Result<JournalRecord, PublisherAuthorityError> {
        self.journal.ensure_protected_authority()?;
        let key = capability_key(id);
        let current = self
            .journal
            .get(RecordNamespace::PublisherAuthority, &key)
            .ok_or(PublisherAuthorityError::UnknownCapability)?;
        let current_length = current.len();
        let record = decode_record(&key, current, self.limits.maximum_record_bytes)?;
        if record.state == DurableCapabilityStateV1::Revoked {
            return Err(PublisherAuthorityError::Revoked);
        }
        let value = encode_record(
            DurableCapabilityStateV1::Revoked,
            &record.capability,
            record.issuance.as_ref(),
            record.runtime.as_ref(),
            record.parent,
            record.handle,
            self.limits.maximum_record_bytes,
        )?;
        let next_materialized_bytes = self
            .materialized_bytes
            .checked_sub(current_length)
            .and_then(|bytes| bytes.checked_add(value.len()))
            .ok_or(PublisherAuthorityError::LimitExceeded("materialized bytes"))?;
        if next_materialized_bytes > self.limits.maximum_materialized_bytes {
            return Err(PublisherAuthorityError::LimitExceeded("materialized bytes"));
        }

        Ok(JournalRecord::put(
            RecordNamespace::PublisherAuthority,
            key.to_vec(),
            value,
        ))
    }

    /// Prepares atomic predecessor revocation and fresh successor installation.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAuthorityError`] when the predecessor is absent or
    /// revoked, the successor is invalid or already retained, or protected
    /// registry limits would be exceeded.
    pub(crate) fn prepare_renewal_from_trusted_controller(
        &self,
        predecessor: CapabilityId,
        successor: CapabilityRecord,
    ) -> Result<[JournalRecord; 2], PublisherAuthorityError> {
        if predecessor == successor.id() {
            return Err(PublisherAuthorityError::CapabilityIdAlreadyUsed);
        }
        let revoke = self.prepare_revoke_from_trusted_controller(predecessor)?;
        let install = self.prepare_install_from_trusted_controller(successor)?;

        Ok([revoke, install])
    }

    /// Reconstructs the exact retained authority record for idempotent admission replay.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherAuthorityError`] when protected authority is absent
    /// or the retained capability record is missing or corrupt.
    pub(crate) fn retained_record_for_atomic_replay(
        &self,
        id: CapabilityId,
    ) -> Result<JournalRecord, PublisherAuthorityError> {
        self.journal.ensure_protected_authority()?;
        let key = capability_key(id);
        let value = self
            .journal
            .get(RecordNamespace::PublisherAuthority, &key)
            .ok_or(PublisherAuthorityError::UnknownCapability)?;
        decode_record(&key, value, self.limits.maximum_record_bytes)?;

        Ok(JournalRecord::put(
            RecordNamespace::PublisherAuthority,
            key.to_vec(),
            value.to_vec(),
        ))
    }
}

struct PreparedCapabilityInstallV1 {
    record: JournalRecord,
    next_materialized_bytes: usize,
    handle: [u8; 32],
}

/// Reports a durable publisher capability registry failure.
#[derive(Debug, thiserror::Error)]
pub enum PublisherAuthorityError {
    /// A runtime-issued capability lost its protected historical binding provenance.
    #[error(transparent)]
    RuntimeAuthority(#[from] crate::runtime_authority::RuntimeAuthorityError),
    /// Registry limits are zero or exceed fixed implementation ceilings.
    #[error("publisher authority registry limits are invalid")]
    InvalidLimits,
    /// A bounded registry dimension was exceeded.
    #[error("publisher authority registry limit exceeded: {0}")]
    LimitExceeded(&'static str),
    /// The protected record uses an unsupported version.
    #[error("unsupported publisher authority record version {0}")]
    UnsupportedVersion(u16),
    /// A protected record has malformed or noncanonical JSON.
    #[error("malformed publisher authority record")]
    MalformedRecord,
    /// A journal key is not the exact capability ID stored in its value.
    #[error("publisher authority record key does not match its capability ID")]
    CapabilityKeyMismatch,
    /// Controller-observed issuance metadata contains a reserved sentinel value.
    #[error("publisher capability issuance metadata is invalid")]
    InvalidIssuanceMetadata,
    /// Issuance evidence does not bind the exact fixed capability claims.
    #[error("publisher capability issuance evidence does not match its claims")]
    IssuanceCrosslinkMismatch,
    /// The reserved all-zero capability ID was supplied.
    #[error("publisher capability ID is unspecified")]
    UnspecifiedCapability,
    /// An immutable capability ID already has an active record or tombstone.
    #[error("publisher capability ID was already used")]
    CapabilityIdAlreadyUsed,
    /// A retained child does not name a valid durable parent capability.
    #[error("publisher capability parent linkage is invalid")]
    InvalidParentLink,
    /// A parent has already issued its maximum durable direct-child count.
    #[error("publisher capability parent fanout is exhausted")]
    FanoutExceeded,
    /// No durable record exists for the requested capability ID.
    #[error("publisher capability is unknown")]
    UnknownCapability,
    /// The requested capability has a durable revocation tombstone.
    #[error("publisher capability is revoked")]
    Revoked,
    /// The random handle source could not provide operating-system entropy.
    #[error("publisher capability handle entropy is unavailable")]
    EntropyUnavailable,
    /// A handle is malformed, absent, or has no matching current record.
    #[error("publisher capability handle is invalid")]
    InvalidHandle,
    /// A retained handle collides with another capability record.
    #[error("publisher capability handle is duplicated")]
    DuplicateHandle,
    /// A handle belongs to another authenticated holder or certificate key.
    #[error("publisher capability handle does not match authenticated holder")]
    HandleHolderMismatch,
    /// The underlying protected journal failed or became unsafe to read.
    #[error("publisher authority journal failed: {0}")]
    Journal(#[from] JournalError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DurableCapabilityStateV1 {
    Active,
    Revoked,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct DurableCapabilityRecordWireV1 {
    version: u16,
    state: u8,
    capability: CapabilityRecord,
    issuance: Option<IssuanceDecisionMetadataV1>,
    claims_digest: Option<aos_sandbox_core::ObjectDigest>,
    runtime: Option<RuntimeIssuanceEvidenceV1>,
    #[serde(default)]
    parent: Option<CapabilityId>,
    #[serde(default)]
    handle: Option<[u8; 32]>,
}

struct DecodedCapabilityRecordV1 {
    state: DurableCapabilityStateV1,
    capability: CapabilityRecord,
    issuance: Option<(IssuanceDecisionMetadataV1, aos_sandbox_core::ObjectDigest)>,
    runtime: Option<RuntimeIssuanceEvidenceV1>,
    parent: Option<CapabilityId>,
    handle: Option<[u8; 32]>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct DurableCapabilityRecordRefV1<'a> {
    version: u16,
    state: u8,
    capability: &'a CapabilityRecord,
    issuance: Option<&'a IssuanceDecisionMetadataV1>,
    claims_digest: Option<aos_sandbox_core::ObjectDigest>,
    runtime: Option<&'a RuntimeIssuanceEvidenceV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent: Option<CapabilityId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    handle: Option<[u8; 32]>,
}

fn validate_parent_link(
    parent: &CapabilityRecord,
    child: &CapabilityRecord,
) -> Result<(), PublisherAuthorityError> {
    let parent_claims = parent.claims();
    let child_claims = child.claims();
    let runtime_scope_is_narrower = parent_claims.sandbox.is_none()
        || (child_claims.sandbox == parent_claims.sandbox
            && child_claims.incarnation == parent_claims.incarnation);
    let assignment_is_narrower = parent_claims.assignment_epoch.is_none()
        || child_claims.assignment_epoch == parent_claims.assignment_epoch;
    let grants_are_narrower = child_claims.grants.iter().all(|child_grant| {
        parent_claims
            .grants
            .iter()
            .any(|parent_grant| parent_grant.covers_attenuation(child_grant))
    });
    if parent.id() == child.id()
        || child_claims.issuer != parent_claims.holder
        || child_claims.audience != parent_claims.audience
        || child_claims.root_subject != parent_claims.root_subject
        || child_claims.project != parent_claims.project
        || child_claims.policy_digest != parent_claims.policy_digest
        || child_claims.revocation_scope != parent_claims.revocation_scope
        || child_claims.revocation_generation != parent_claims.revocation_generation
        || !runtime_scope_is_narrower
        || !assignment_is_narrower
        || child_claims.not_before < parent_claims.not_before
        || child_claims.expires_at > parent_claims.expires_at
        || child_claims.delegation.remaining_depth() >= parent_claims.delegation.remaining_depth()
        || child_claims.delegation.maximum_fanout() > parent_claims.delegation.maximum_fanout()
        || !child_claims
            .delegation
            .resources()
            .is_within(parent_claims.delegation.resources())
        || !grants_are_narrower
    {
        return Err(PublisherAuthorityError::InvalidParentLink);
    }

    Ok(())
}

fn capability_key(id: CapabilityId) -> [u8; RECORD_KEY_BYTES] {
    let mut key = [0_u8; RECORD_KEY_BYTES];
    key[..RECORD_FAMILY.len()].copy_from_slice(RECORD_FAMILY);
    key[RECORD_FAMILY.len()..].copy_from_slice(id.as_bytes());
    key
}

fn capability_id_from_key(key: &[u8]) -> Result<CapabilityId, PublisherAuthorityError> {
    if key.len() != RECORD_KEY_BYTES || !key.starts_with(RECORD_FAMILY) {
        return Err(PublisherAuthorityError::MalformedRecord);
    }
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&key[RECORD_FAMILY.len()..]);
    if bytes == [0; 16] {
        return Err(PublisherAuthorityError::MalformedRecord);
    }
    Ok(CapabilityId::from_bytes(bytes))
}

fn decode_record(
    key: &[u8],
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<DecodedCapabilityRecordV1, PublisherAuthorityError> {
    let key_id = capability_id_from_key(key)?;
    if bytes.len() > maximum_bytes {
        return Err(PublisherAuthorityError::LimitExceeded("record bytes"));
    }
    let decoded: DurableCapabilityRecordWireV1 =
        serde_json::from_slice(bytes).map_err(|_| PublisherAuthorityError::MalformedRecord)?;
    if !matches!(
        decoded.version,
        RECORD_VERSION_V1 | RECORD_VERSION_V2 | RECORD_VERSION_V3
    ) {
        return Err(PublisherAuthorityError::UnsupportedVersion(decoded.version));
    }
    if (decoded.version == RECORD_VERSION_V1 && decoded.parent.is_some())
        || (decoded.version == RECORD_VERSION_V2 && decoded.parent.is_none())
    {
        return Err(PublisherAuthorityError::InvalidParentLink);
    }
    if (decoded.version == RECORD_VERSION_V3) != decoded.handle.is_some()
        || decoded.handle == Some([0; 32])
    {
        return Err(PublisherAuthorityError::InvalidHandle);
    }
    let state = match decoded.state {
        0 => DurableCapabilityStateV1::Active,
        1 => DurableCapabilityStateV1::Revoked,
        _ => return Err(PublisherAuthorityError::MalformedRecord),
    };
    if decoded.capability.id() != key_id {
        return Err(PublisherAuthorityError::CapabilityKeyMismatch);
    }
    let issuance = match (decoded.issuance, decoded.claims_digest) {
        (None, None) => None,
        (Some(metadata), Some(claims_digest)) => {
            if metadata.validate_for(&decoded.capability)? != claims_digest {
                return Err(PublisherAuthorityError::IssuanceCrosslinkMismatch);
            }
            Some((metadata, claims_digest))
        }
        _ => return Err(PublisherAuthorityError::IssuanceCrosslinkMismatch),
    };
    if let Some(runtime) = decoded.runtime.as_ref() {
        let (metadata, _) = issuance
            .as_ref()
            .ok_or(PublisherAuthorityError::IssuanceCrosslinkMismatch)?;
        runtime.validate_for(metadata)?;
    }
    let canonical = encode_record(
        state,
        &decoded.capability,
        issuance.as_ref(),
        decoded.runtime.as_ref(),
        decoded.parent,
        decoded.handle,
        maximum_bytes,
    )?;
    if canonical != bytes {
        return Err(PublisherAuthorityError::MalformedRecord);
    }
    Ok(DecodedCapabilityRecordV1 {
        state,
        capability: decoded.capability,
        issuance,
        runtime: decoded.runtime,
        parent: decoded.parent,
        handle: decoded.handle,
    })
}

fn encode_record(
    state: DurableCapabilityStateV1,
    capability: &CapabilityRecord,
    issuance: Option<&(IssuanceDecisionMetadataV1, aos_sandbox_core::ObjectDigest)>,
    runtime: Option<&RuntimeIssuanceEvidenceV1>,
    parent: Option<CapabilityId>,
    handle: Option<[u8; 32]>,
    maximum_bytes: usize,
) -> Result<Vec<u8>, PublisherAuthorityError> {
    if runtime.is_some() && issuance.is_none() {
        return Err(PublisherAuthorityError::IssuanceCrosslinkMismatch);
    }
    let (metadata, claims_digest) = issuance
        .map(|(metadata, claims_digest)| (Some(metadata), Some(*claims_digest)))
        .unwrap_or((None, None));
    let record = DurableCapabilityRecordRefV1 {
        version: if handle.is_some() {
            RECORD_VERSION_V3
        } else if parent.is_some() {
            RECORD_VERSION_V2
        } else {
            RECORD_VERSION_V1
        },
        state: state.wire_value(),
        capability,
        issuance: metadata,
        claims_digest,
        runtime,
        parent,
        handle,
    };
    let mut writer = BoundedWriter::new(maximum_bytes);
    if serde_json::to_writer(&mut writer, &record).is_err() {
        return if writer.exceeded {
            Err(PublisherAuthorityError::LimitExceeded("record bytes"))
        } else {
            Err(PublisherAuthorityError::MalformedRecord)
        };
    }
    Ok(writer.bytes)
}

fn random_handle() -> Result<[u8; 32], PublisherAuthorityError> {
    for _ in 0..4 {
        let mut handle = [0_u8; 32];
        OsRng
            .try_fill_bytes(&mut handle)
            .map_err(|_| PublisherAuthorityError::EntropyUnavailable)?;
        if handle != [0; 32] {
            return Ok(handle);
        }
    }
    Err(PublisherAuthorityError::EntropyUnavailable)
}

fn handle_digest(handle: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(HANDLE_DIGEST_DOMAIN)
        .chain_update(handle)
        .finalize()
        .into()
}

impl DurableCapabilityStateV1 {
    const fn wire_value(self) -> u8 {
        match self {
            Self::Active => 0,
            Self::Revoked => 1,
        }
    }
}

struct BoundedWriter {
    bytes: Vec<u8>,
    maximum_bytes: usize,
    exceeded: bool,
}

impl BoundedWriter {
    fn new(maximum_bytes: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(maximum_bytes.min(8 * 1024)),
            maximum_bytes,
            exceeded: false,
        }
    }
}

impl io::Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(next_length) = self.bytes.len().checked_add(bytes.len()) else {
            self.exceeded = true;
            return Err(io::Error::other("publisher authority record is too large"));
        };
        if next_length > self.maximum_bytes {
            self.exceeded = true;
            return Err(io::Error::other("publisher authority record is too large"));
        }
        if next_length > self.bytes.capacity() {
            let target_capacity = self
                .bytes
                .capacity()
                .saturating_mul(2)
                .max(next_length)
                .min(self.maximum_bytes);
            self.bytes
                .try_reserve_exact(target_capacity - self.bytes.len())
                .map_err(io::Error::other)?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod issuance_tests;

#[cfg(test)]
pub(crate) mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};

    use aos_sandbox_core::{
        AuditId, CapabilityDraft, ChannelBinding, DelegationLimits, Grant, GrantId, ObjectDigest,
        Operation, OperationSet, PrincipalId, ProjectId, ResourceDimension, ResourceId,
        ResourceKind, ResourceVector, Revision, RevocationScopeId, Selector,
    };
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::JournalLimits;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "aos-publisher-authority-{label}-{}-{}",
                std::process::id(),
                CapabilityId::new()
            ));
            fs::create_dir(&path).unwrap_or_else(|error| panic!("create test directory: {error}"));
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .unwrap_or_else(|error| panic!("protect test directory: {error}"));
            Self(path)
        }

        fn open(&self) -> Journal {
            let uid = fs::metadata(&self.0)
                .unwrap_or_else(|error| panic!("stat test directory: {error}"))
                .uid();
            Journal::open_protected_at_uid(
                &self.0,
                "authority.journal",
                JournalLimits::default(),
                uid,
            )
            .map(|(journal, _)| journal)
            .unwrap_or_else(|error| panic!("open protected test journal: {error}"))
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    pub(crate) fn capability(id: CapabilityId, expires_at: i64) -> CapabilityRecord {
        let grant = Grant::new(
            GrantId::from_bytes([2; 16]),
            ResourceKind::CachePublish,
            OperationSet::one(Operation::Publish),
            Selector::Resource {
                resource: ResourceId::from_bytes([3; 16]),
            },
            false,
        )
        .unwrap_or_else(|error| panic!("create test grant: {error}"));
        CapabilityRecord::issue(CapabilityDraft {
            id,
            issuer: PrincipalId::from_bytes([4; 16]),
            audience: PrincipalId::from_bytes([5; 16]),
            holder: PrincipalId::from_bytes([6; 16]),
            channel_binding: ChannelBinding::new([7; 32]),
            root_subject: PrincipalId::from_bytes([8; 16]),
            project: ProjectId::from_bytes([9; 16]),
            sandbox: None,
            incarnation: None,
            grants: vec![grant],
            policy_digest: ObjectDigest::from_bytes([10; 32]),
            assignment_epoch: None,
            not_before: 100,
            expires_at,
            revocation_scope: RevocationScopeId::from_bytes([11; 16]),
            revocation_generation: Revision::new(12),
            delegation: DelegationLimits::new(
                0,
                0,
                ResourceVector::ZERO.with(ResourceDimension::StorageBytes, 4096),
            ),
            parent_decision: AuditId::from_bytes([13; 16]),
        })
        .unwrap_or_else(|error| panic!("issue test capability: {error}"))
    }

    fn put_raw(journal: &mut Journal, transaction: u8, key: Vec<u8>, value: Vec<u8>) {
        let transaction = JournalTransaction::new(
            [transaction; 16],
            vec![JournalRecord::put(
                RecordNamespace::PublisherAuthority,
                key,
                value,
            )],
        )
        .unwrap_or_else(|error| panic!("create raw transaction: {error}"));
        journal
            .commit(&transaction)
            .unwrap_or_else(|error| panic!("commit raw transaction: {error}"));
    }

    fn reopen(path: &Path) -> Journal {
        let uid = fs::metadata(path)
            .unwrap_or_else(|error| panic!("stat test directory: {error}"))
            .uid();
        Journal::open_protected_at_uid(path, "authority.journal", JournalLimits::default(), uid)
            .map(|(journal, _)| journal)
            .unwrap_or_else(|error| panic!("reopen protected test journal: {error}"))
    }

    #[test]
    fn install_lookup_restart_and_id_collision_are_fail_closed() {
        let directory = TestDirectory::new("install");
        let mut journal = directory.open();
        let id = CapabilityId::from_bytes([1; 16]);
        let original = capability(id, 200);
        {
            let mut registry = PublisherCapabilityRegistry::load(
                &mut journal,
                PublisherAuthorityLimits::default(),
            )
            .unwrap_or_else(|error| panic!("load empty registry: {error}"));
            registry
                .install_from_trusted_controller([1; 16], original.clone())
                .unwrap_or_else(|error| panic!("install capability: {error}"));
            assert_eq!(
                registry
                    .resolve_current(id)
                    .unwrap_or_else(|error| panic!("resolve installed capability: {error}")),
                original
            );
            assert!(matches!(
                registry.install_from_trusted_controller([2; 16], original.clone()),
                Err(PublisherAuthorityError::CapabilityIdAlreadyUsed)
            ));
            assert!(matches!(
                registry.install_from_trusted_controller([3; 16], capability(id, 201)),
                Err(PublisherAuthorityError::CapabilityIdAlreadyUsed)
            ));
        }
        drop(journal);

        let mut reopened = reopen(&directory.0);
        let registry =
            PublisherCapabilityRegistry::load(&mut reopened, PublisherAuthorityLimits::default())
                .unwrap_or_else(|error| panic!("reload registry: {error}"));
        assert_eq!(
            registry
                .resolve_current(id)
                .unwrap_or_else(|error| panic!("resolve reloaded capability: {error}")),
            original
        );
    }

    #[test]
    fn holder_handles_are_distinct_durable_and_bound_to_claims() {
        let directory = TestDirectory::new("holder-handle");
        let mut journal = directory.open();
        let first_id = CapabilityId::from_bytes([21; 16]);
        let second_id = CapabilityId::from_bytes([22; 16]);
        let holder = PrincipalId::from_bytes([6; 16]);
        let binding = ChannelBinding::new([7; 32]);

        let (first_handle, second_handle) = {
            let mut registry = PublisherCapabilityRegistry::load(
                &mut journal,
                PublisherAuthorityLimits::default(),
            )
            .unwrap();
            registry
                .install_from_trusted_controller([21; 16], capability(first_id, 200))
                .unwrap();
            registry
                .install_from_trusted_controller([22; 16], capability(second_id, 200))
                .unwrap();
            let first = registry.holder_handle(first_id, holder, binding).unwrap();
            let second = registry.holder_handle(second_id, holder, binding).unwrap();
            assert_ne!(first, second);
            assert_eq!(
                registry
                    .resolve_holder_handle(&first, holder, binding)
                    .unwrap(),
                first_id
            );
            assert!(matches!(
                registry.resolve_holder_handle(&first, PrincipalId::from_bytes([23; 16]), binding,),
                Err(PublisherAuthorityError::HandleHolderMismatch)
            ));
            assert!(matches!(
                registry.resolve_holder_handle(&first, holder, ChannelBinding::new([24; 32])),
                Err(PublisherAuthorityError::HandleHolderMismatch)
            ));
            (first, second)
        };

        drop(journal);
        let mut reopened = directory.open();
        let mut registry =
            PublisherCapabilityRegistry::load(&mut reopened, PublisherAuthorityLimits::default())
                .unwrap();
        assert_eq!(
            registry.holder_handle(first_id, holder, binding).unwrap(),
            first_handle
        );
        assert_eq!(
            registry.holder_handle(second_id, holder, binding).unwrap(),
            second_handle
        );
        registry
            .revoke_from_trusted_controller([23; 16], first_id)
            .unwrap();
        assert!(matches!(
            registry.resolve_holder_handle(&first_handle, holder, binding),
            Err(PublisherAuthorityError::Revoked)
        ));
    }

    #[test]
    fn revocation_tombstone_survives_restart_and_compaction() {
        let directory = TestDirectory::new("revoke");
        let mut journal = directory.open();
        let id = CapabilityId::from_bytes([14; 16]);
        let original = capability(id, 200);
        let encoded = encode_record(
            DurableCapabilityStateV1::Active,
            &original,
            None,
            None,
            None,
            Some([255; 32]),
            MAXIMUM_RECORD_BYTES,
        )
        .unwrap_or_else(|error| panic!("encode exact-limit record: {error}"));
        let exact_limits =
            PublisherAuthorityLimits::new(1, encoded.len(), RECORD_KEY_BYTES + encoded.len())
                .unwrap_or_else(|error| panic!("construct exact limits: {error}"));
        {
            let mut registry = PublisherCapabilityRegistry::load(&mut journal, exact_limits)
                .unwrap_or_else(|error| panic!("load empty registry: {error}"));
            registry
                .install_from_trusted_controller([1; 16], original.clone())
                .unwrap_or_else(|error| panic!("install capability: {error}"));
            registry
                .revoke_from_trusted_controller([2; 16], id)
                .unwrap_or_else(|error| panic!("revoke capability: {error}"));
            assert!(matches!(
                registry.resolve_current(id),
                Err(PublisherAuthorityError::Revoked)
            ));
            assert!(matches!(
                registry.revoke_from_trusted_controller([3; 16], id),
                Err(PublisherAuthorityError::Revoked)
            ));
            assert!(matches!(
                registry.install_from_trusted_controller([4; 16], original),
                Err(PublisherAuthorityError::CapabilityIdAlreadyUsed)
            ));
        }
        journal
            .compact()
            .unwrap_or_else(|error| panic!("compact authority journal: {error}"));
        drop(journal);

        let mut reopened = reopen(&directory.0);
        let registry =
            PublisherCapabilityRegistry::load(&mut reopened, PublisherAuthorityLimits::default())
                .unwrap_or_else(|error| panic!("reload compacted registry: {error}"));
        assert!(matches!(
            registry.resolve_current(id),
            Err(PublisherAuthorityError::Revoked)
        ));
    }

    #[test]
    fn strict_record_validation_rejects_substitution_and_noncanonical_bytes() {
        let id = CapabilityId::from_bytes([15; 16]);
        let record = capability(id, 200);
        let canonical = encode_record(
            DurableCapabilityStateV1::Active,
            &record,
            None,
            None,
            None,
            None,
            MAXIMUM_RECORD_BYTES,
        )
        .unwrap_or_else(|error| panic!("encode test record: {error}"));
        assert!(canonical.starts_with(b"{\"version\":1,\"state\":0,\"capability\":"));
        assert!(
            canonical.ends_with(b",\"issuance\":null,\"claims_digest\":null,\"runtime\":null}")
        );
        assert_eq!(canonical.len(), 1_120);
        assert_eq!(
            format!("{:x}", Sha256::digest(&canonical)),
            "81c2c669dab2371aaf0ad5fad639de97bd5cd9dbce01d66ea7a578bf902e8919"
        );

        let mut duplicate = b"{\"version\":1,".to_vec();
        duplicate.extend_from_slice(&canonical[1..]);
        assert!(matches!(
            decode_record(&capability_key(id), &duplicate, MAXIMUM_RECORD_BYTES),
            Err(PublisherAuthorityError::MalformedRecord)
        ));

        let capability_field = canonical
            .windows(b",\"capability\":".len())
            .position(|window| window == b",\"capability\":")
            .unwrap_or_else(|| panic!("capability field absent"));
        let mut reordered = b"{\"state\":0,\"version\":1".to_vec();
        reordered.extend_from_slice(&canonical[capability_field..]);
        assert!(matches!(
            decode_record(&capability_key(id), &reordered, MAXIMUM_RECORD_BYTES),
            Err(PublisherAuthorityError::MalformedRecord)
        ));

        for version in [b'0', b'4', b'5'] {
            let mut unknown_version = canonical.clone();
            let position = unknown_version
                .windows(b"\"version\":1".len())
                .position(|window| window == b"\"version\":1")
                .unwrap_or_else(|| panic!("version field absent"));
            unknown_version[position + b"\"version\":".len()] = version;
            assert!(matches!(
                decode_record(&capability_key(id), &unknown_version, MAXIMUM_RECORD_BYTES),
                Err(PublisherAuthorityError::UnsupportedVersion(candidate))
                    if candidate == u16::from(version - b'0')
            ));
        }

        let mut missing_v2_parent = canonical.clone();
        let position = missing_v2_parent
            .windows(b"\"version\":1".len())
            .position(|window| window == b"\"version\":1")
            .unwrap_or_else(|| panic!("version field absent"));
        missing_v2_parent[position + b"\"version\":".len()] = b'2';
        assert!(matches!(
            decode_record(
                &capability_key(id),
                &missing_v2_parent,
                MAXIMUM_RECORD_BYTES
            ),
            Err(PublisherAuthorityError::InvalidParentLink)
        ));

        let mut unknown_state = canonical.clone();
        let position = unknown_state
            .windows(b"\"state\":0".len())
            .position(|window| window == b"\"state\":0")
            .unwrap_or_else(|| panic!("state field absent"));
        unknown_state[position + b"\"state\":".len()] = b'2';
        assert!(matches!(
            decode_record(&capability_key(id), &unknown_state, MAXIMUM_RECORD_BYTES),
            Err(PublisherAuthorityError::MalformedRecord)
        ));

        let mut unknown_field = b"{\"extra\":1,".to_vec();
        unknown_field.extend_from_slice(&canonical[1..]);
        for malformed in [unknown_field, [canonical.clone(), b"\n".to_vec()].concat()] {
            assert!(matches!(
                decode_record(&capability_key(id), &malformed, MAXIMUM_RECORD_BYTES),
                Err(PublisherAuthorityError::MalformedRecord)
            ));
        }
        for field in ["issuance", "claims_digest", "runtime"] {
            let mut missing: serde_json::Value = serde_json::from_slice(&canonical)
                .unwrap_or_else(|error| panic!("decode canonical record: {error}"));
            missing
                .as_object_mut()
                .unwrap_or_else(|| panic!("canonical record is not an object"))
                .remove(field);
            let missing = serde_json::to_vec(&missing)
                .unwrap_or_else(|error| panic!("encode missing-field record: {error}"));
            assert!(matches!(
                decode_record(&capability_key(id), &missing, MAXIMUM_RECORD_BYTES),
                Err(PublisherAuthorityError::MalformedRecord)
            ));
        }
        assert!(matches!(
            decode_record(
                &capability_key(CapabilityId::from_bytes([16; 16])),
                &canonical,
                MAXIMUM_RECORD_BYTES,
            ),
            Err(PublisherAuthorityError::CapabilityKeyMismatch)
        ));
        assert!(matches!(
            decode_record(b"capability/short", &canonical, MAXIMUM_RECORD_BYTES),
            Err(PublisherAuthorityError::MalformedRecord)
        ));

        let mut invalid_capability = canonical.clone();
        let expiry = invalid_capability
            .windows(b"\"expires_at\":200".len())
            .position(|window| window == b"\"expires_at\":200")
            .unwrap_or_else(|| panic!("expiry field absent"));
        let digits = expiry + b"\"expires_at\":".len();
        invalid_capability[digits..digits + 3].copy_from_slice(b"100");
        assert!(matches!(
            decode_record(
                &capability_key(id),
                &invalid_capability,
                MAXIMUM_RECORD_BYTES,
            ),
            Err(PublisherAuthorityError::MalformedRecord)
        ));
    }

    #[test]
    fn replay_rejects_malformed_and_zero_id_records_for_the_entire_facade() {
        let directory = TestDirectory::new("malformed-replay");
        let mut journal = directory.open();
        put_raw(
            &mut journal,
            1,
            capability_key(CapabilityId::from_bytes([17; 16])).to_vec(),
            b"{}".to_vec(),
        );
        assert!(matches!(
            PublisherCapabilityRegistry::load(&mut journal, PublisherAuthorityLimits::default(),),
            Err(PublisherAuthorityError::MalformedRecord)
        ));

        let zero_directory = TestDirectory::new("zero-replay");
        let mut zero_journal = zero_directory.open();
        let zero = capability(CapabilityId::from_bytes([0; 16]), 200);
        let value = encode_record(
            DurableCapabilityStateV1::Active,
            &zero,
            None,
            None,
            None,
            None,
            MAXIMUM_RECORD_BYTES,
        )
        .unwrap_or_else(|error| panic!("encode zero-ID record: {error}"));
        put_raw(
            &mut zero_journal,
            1,
            capability_key(zero.id()).to_vec(),
            value,
        );
        assert!(matches!(
            PublisherCapabilityRegistry::load(
                &mut zero_journal,
                PublisherAuthorityLimits::default(),
            ),
            Err(PublisherAuthorityError::MalformedRecord)
        ));
    }

    #[test]
    fn encoding_and_replay_limits_apply_before_registry_acceptance() {
        let directory = TestDirectory::new("limits");
        let mut journal = directory.open();
        let id = CapabilityId::from_bytes([18; 16]);
        let record = capability(id, 200);
        let encoded = encode_record(
            DurableCapabilityStateV1::Active,
            &record,
            None,
            None,
            None,
            None,
            MAXIMUM_RECORD_BYTES,
        )
        .unwrap_or_else(|error| panic!("encode test record: {error}"));
        let limits =
            PublisherAuthorityLimits::new(1, encoded.len() - 1, MAXIMUM_MATERIALIZED_BYTES)
                .unwrap_or_else(|error| panic!("construct test limits: {error}"));
        {
            let mut registry = PublisherCapabilityRegistry::load(&mut journal, limits)
                .unwrap_or_else(|error| panic!("load empty limited registry: {error}"));
            assert!(matches!(
                registry.install_from_trusted_controller([1; 16], record),
                Err(PublisherAuthorityError::LimitExceeded("record bytes"))
            ));
            assert!(matches!(
                registry.resolve_current(id),
                Err(PublisherAuthorityError::UnknownCapability)
            ));
        }

        put_raw(
            &mut journal,
            2,
            capability_key(id).to_vec(),
            encoded.clone(),
        );
        assert!(matches!(
            PublisherCapabilityRegistry::load(&mut journal, limits),
            Err(PublisherAuthorityError::LimitExceeded("record bytes"))
        ));
        let aggregate_limits =
            PublisherAuthorityLimits::new(1, encoded.len(), RECORD_KEY_BYTES + encoded.len() - 1)
                .unwrap_or_else(|error| panic!("construct aggregate limits: {error}"));
        assert!(matches!(
            PublisherCapabilityRegistry::load(&mut journal, aggregate_limits),
            Err(PublisherAuthorityError::LimitExceeded("materialized bytes"))
        ));

        let second_id = CapabilityId::from_bytes([19; 16]);
        let second = capability(second_id, 200);
        let second_value = encode_record(
            DurableCapabilityStateV1::Active,
            &second,
            None,
            None,
            None,
            None,
            MAXIMUM_RECORD_BYTES,
        )
        .unwrap_or_else(|error| panic!("encode second test record: {error}"));
        put_raw(
            &mut journal,
            3,
            capability_key(second_id).to_vec(),
            second_value,
        );
        let count_limits =
            PublisherAuthorityLimits::new(1, MAXIMUM_RECORD_BYTES, MAXIMUM_MATERIALIZED_BYTES)
                .unwrap_or_else(|error| panic!("construct count limits: {error}"));
        assert!(matches!(
            PublisherCapabilityRegistry::load(&mut journal, count_limits),
            Err(PublisherAuthorityError::LimitExceeded("entry count"))
        ));
    }

    #[test]
    fn zero_id_install_is_rejected_before_any_durable_mutation() {
        let directory = TestDirectory::new("zero-install");
        let mut journal = directory.open();
        let sequence = journal.snapshot_sequence();
        let zero = capability(CapabilityId::from_bytes([0; 16]), 200);
        let mut registry =
            PublisherCapabilityRegistry::load(&mut journal, PublisherAuthorityLimits::default())
                .unwrap_or_else(|error| panic!("load empty registry: {error}"));
        assert!(matches!(
            registry.install_from_trusted_controller([1; 16], zero),
            Err(PublisherAuthorityError::UnspecifiedCapability)
        ));
        assert_eq!(registry.journal.snapshot_sequence(), sequence);
    }
}
