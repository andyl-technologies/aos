//! Protected current runtime-assignment and holder authority.
//!
//! This namespace stores three independently versioned record families:
//!
//! ```text
//! pending/<operation>          = admitted non-authorizing holder intent
//! binding/<sandbox><revision>  = immutable activated binding or tombstone
//! current/<sandbox>            = exact head revision and binding digest
//! ```
//!
//! Pending records derive assignment identity from an ownership-gated
//! authority-publication draft. Activation derives publication and lease facts
//! from the prepared publication. No public API constructs a live binding or
//! supplies a currentness flag. Store loading validates the complete bounded
//! namespace and its durable operation, gate, and publication cross-links.
//! Even a current binding remains controller-local structural evidence: online
//! use must also establish current cryptographic authority and a fresh Host
//! payload-scope observation.

use std::collections::BTreeMap;

use aos_sandbox_core::{ObjectDigest, OperationId, SandboxId};

use crate::publication::{
    AuthorityPublicationDraftV1, PreparedAuthorityPublicationV1, current_in_validated_namespace,
    validate_publication_namespace,
};
use crate::{Journal, JournalError, JournalRecord, RecordNamespace};

mod format;
mod model;
#[cfg(test)]
mod tests;

use format::{
    binding_digest, decode_binding, decode_head, decode_pending, encode_binding, encode_head,
    encode_pending,
};
use model::RuntimeAuthorityHeadV1;
pub(crate) use model::RuntimeAuthorityPendingV1;
pub use model::{
    RuntimeAuthorityBindingV1, RuntimeAuthorityIntentV1, RuntimeAuthorityLimits,
    RuntimeAuthorityStateV1,
};

const PENDING_PREFIX: &[u8] = b"pending/";
const BINDING_PREFIX: &[u8] = b"binding/";
const CURRENT_PREFIX: &[u8] = b"current/";
const PENDING_KEY_BYTES: usize = PENDING_PREFIX.len() + 16;
const BINDING_KEY_BYTES: usize = BINDING_PREFIX.len() + 16 + 8;
const CURRENT_KEY_BYTES: usize = CURRENT_PREFIX.len() + 16;

const PENDING_MAGIC: &[u8; 8] = b"AOSRAP01";
const BINDING_MAGIC: &[u8; 8] = b"AOSRAB01";
const HEAD_MAGIC: &[u8; 8] = b"AOSRAH01";
const PENDING_VERSION: u16 = 1;
const BINDING_VERSION: u16 = 1;
const HEAD_VERSION: u16 = 1;
const BINDING_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.runtime-authority-binding.v1\0";
const INTENT_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.runtime-authority-intent.v1\0";

const MAXIMUM_RECORDS: usize = 1_000_000;
const JOURNAL_RECORD_HEADER_BYTES: usize = 7;
const MAXIMUM_RECORD_BYTES: usize =
    16 * 1024 * 1024 - JOURNAL_RECORD_HEADER_BYTES - BINDING_KEY_BYTES;
const MAXIMUM_MATERIALIZED_BYTES: usize = 512 * 1024 * 1024;

/// Reports invalid intents, compare-and-swap failures, or corrupt protected state.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeAuthorityError {
    /// A compiler intent contains a reserved identity or revision.
    #[error("runtime-authority intent is invalid")]
    InvalidIntent,
    /// Configured replay bounds are zero or exceed fixed implementation ceilings.
    #[error("runtime-authority limits are invalid")]
    InvalidLimits,
    /// A replay or mutation exceeds a configured bound.
    #[error("runtime-authority {0} limit exceeded")]
    LimitExceeded(&'static str),
    /// The protected current revision differs from the admitted expectation.
    #[error("runtime-authority current revision changed")]
    CompareAndSwap,
    /// An origin-to-current history contains a revocation or assignment/holder change.
    #[error("runtime-authority holder continuity was broken")]
    Continuity,
    /// The operation identity already names another pending intent.
    #[error("runtime-authority pending operation already exists")]
    PendingAlreadyExists,
    /// The immutable sandbox revision key was already used.
    #[error("runtime-authority binding revision already exists")]
    BindingAlreadyExists,
    /// Current assignment, pending intent, draft, or prepared publication facts differ.
    #[error("runtime-authority activation context does not match admitted intent")]
    ActivationConflict,
    /// The namespace or one of its durable cross-links is malformed or incomplete.
    #[error("protected runtime-authority state is corrupt")]
    CorruptState,
    /// Protected journal validation or access failed.
    #[error("runtime-authority journal failed: {0}")]
    Journal(#[from] JournalError),
}

/// Provides exclusive access to fully validated runtime-authority state.
pub struct RuntimeAuthorityStore<'journal> {
    journal: &'journal mut Journal,
    limits: RuntimeAuthorityLimits,
    records: usize,
    materialized_bytes: usize,
}

impl<'journal> RuntimeAuthorityStore<'journal> {
    /// Validates and borrows the complete protected runtime-authority namespace.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeAuthorityError`] when protected journal provenance is
    /// unavailable, configured bounds are exceeded, a record is noncanonical,
    /// a revision chain or head is incomplete, or a durable operation, gate, or
    /// authority-publication cross-link is invalid.
    pub fn load(
        journal: &'journal mut Journal,
        limits: RuntimeAuthorityLimits,
    ) -> Result<Self, RuntimeAuthorityError> {
        journal.ensure_protected_authority()?;
        let (records, materialized_bytes) = validate_namespace(journal, limits)?;
        Ok(Self {
            journal,
            limits,
            records,
            materialized_bytes,
        })
    }

    /// Resolves the current immutable binding or revocation tombstone.
    ///
    /// This lookup returns protected structural state, not live authorization.
    /// Callers must additionally verify current cryptographic authority and a
    /// fresh execution-scope observation before issuing or using a channel.
    ///
    /// # Errors
    ///
    /// Returns an error if journal health changed or the indexed head and
    /// immutable binding no longer agree. `Ok(None)` means no head was installed.
    pub fn current(
        &self,
        sandbox: SandboxId,
    ) -> Result<Option<RuntimeAuthorityBindingV1>, RuntimeAuthorityError> {
        self.journal.ensure_protected_authority()?;
        current_from_journal(self.journal, sandbox)
    }

    /// Checks an uninterrupted holder/assignment chain, not live execution authority.
    ///
    /// Both endpoints must match protected records and the latter must be the
    /// current head. Comparing only endpoints would accept revoke/rebind ABA.
    /// Loading the store already bounded and validated every historical row.
    pub(crate) fn validate_continuity(
        &self,
        origin: &RuntimeAuthorityBindingV1,
        current: &RuntimeAuthorityBindingV1,
    ) -> Result<(), RuntimeAuthorityError> {
        if origin.revision() > current.revision()
            || self.current(origin.sandbox())?.as_ref() != Some(current)
            || binding_in_validated_namespace(self.journal, origin.sandbox(), origin.revision())?
                != *origin
        {
            return Err(RuntimeAuthorityError::Continuity);
        }
        for revision in origin.revision()..=current.revision() {
            let binding = binding_in_validated_namespace(self.journal, origin.sandbox(), revision)?;
            if binding.state() != RuntimeAuthorityStateV1::Bound
                || binding.holder() != origin.holder()
                || binding.manifest() != origin.manifest()
            {
                return Err(RuntimeAuthorityError::Continuity);
            }
        }
        Ok(())
    }

    /// Freezes one operation-indexed pending record without committing it.
    ///
    /// Assignment bytes and identity are derived only from `draft`. The
    /// protected current head supplies the actual compare-and-swap predecessor
    /// and next revision. The returned record must be committed atomically with
    /// the operation's desired state, ownership gate, and idempotency decision.
    pub(crate) fn prepare_pending(
        &self,
        operation: OperationId,
        request_digest: [u8; 32],
        draft: &AuthorityPublicationDraftV1,
        intent: &RuntimeAuthorityIntentV1,
    ) -> Result<Vec<JournalRecord>, RuntimeAuthorityError> {
        self.journal.ensure_protected_authority()?;
        if operation.as_bytes() == &[0; 16] || request_digest == [0; 32] {
            return Err(RuntimeAuthorityError::InvalidIntent);
        }
        let key = pending_key(operation);
        if self
            .journal
            .get(RecordNamespace::RuntimeAuthority, &key)
            .is_some()
        {
            return Err(RuntimeAuthorityError::PendingAlreadyExists);
        }

        let manifest = draft.manifest().clone();
        let sandbox = manifest.manifest().sandbox();
        let current = current_from_journal(self.journal, sandbox)?;
        let actual_revision = current.as_ref().map(RuntimeAuthorityBindingV1::revision);
        if actual_revision != intent.expected_revision {
            return Err(RuntimeAuthorityError::CompareAndSwap);
        }
        if intent.state == RuntimeAuthorityStateV1::Revoked && current.is_none() {
            return Err(RuntimeAuthorityError::CompareAndSwap);
        }
        if intent.state == RuntimeAuthorityStateV1::Revoked
            && current
                .as_ref()
                .is_some_and(|prior| prior.manifest() != &manifest)
        {
            return Err(RuntimeAuthorityError::ActivationConflict);
        }
        let revision = actual_revision
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(RuntimeAuthorityError::CorruptState)?;
        let pending = RuntimeAuthorityPendingV1 {
            operation,
            request_digest,
            state: intent.state,
            holder: intent.holder,
            expected_revision: intent.expected_revision,
            revision,
            predecessor_digest: current.as_ref().map(RuntimeAuthorityBindingV1::digest),
            manifest,
            source_draft_digest: draft.digest(),
        };
        let value = encode_pending(&pending)?;
        self.check_addition(&key, &value, 1)?;
        Ok(vec![JournalRecord::put(
            RecordNamespace::RuntimeAuthority,
            key,
            value,
        )])
    }

    /// Freezes immutable binding and current-head records without committing them.
    ///
    /// Legacy ownership-gated operations without a pending runtime-authority
    /// intent return no records. Otherwise every decision comes from the exact
    /// pending record, while publication and lease facts come from `prepared`.
    /// The caller must append the result to the same transaction that activates
    /// the ownership gate and publishes `prepared` as current.
    pub(crate) fn prepare_activation(
        &self,
        operation: OperationId,
        request_digest: [u8; 32],
        draft: &AuthorityPublicationDraftV1,
        prepared: &PreparedAuthorityPublicationV1,
    ) -> Result<Vec<JournalRecord>, RuntimeAuthorityError> {
        self.journal.ensure_protected_authority()?;
        let Some(bytes) = self
            .journal
            .get(RecordNamespace::RuntimeAuthority, &pending_key(operation))
        else {
            return Ok(Vec::new());
        };
        let pending = decode_pending(bytes)?;
        if pending.operation != operation
            || pending.request_digest != request_digest
            || pending.source_draft_digest != draft.digest()
            || &pending.manifest != draft.manifest()
            || prepared.manifest() != draft.manifest()
            || prepared.source_draft_digest() != draft.digest()
        {
            return Err(RuntimeAuthorityError::ActivationConflict);
        }

        let sandbox = pending.sandbox();
        let current = current_from_journal(self.journal, sandbox)?;
        if current.as_ref().map(RuntimeAuthorityBindingV1::revision) != pending.expected_revision
            || current.as_ref().map(RuntimeAuthorityBindingV1::digest) != pending.predecessor_digest
        {
            return Err(RuntimeAuthorityError::CompareAndSwap);
        }
        let binding_key = binding_key(sandbox, pending.revision);
        if self
            .journal
            .get(RecordNamespace::RuntimeAuthority, &binding_key)
            .is_some()
        {
            return Err(RuntimeAuthorityError::BindingAlreadyExists);
        }

        let mut binding = RuntimeAuthorityBindingV1 {
            operation,
            request_digest,
            state: pending.state,
            holder: pending.holder,
            revision: pending.revision,
            predecessor_digest: pending.predecessor_digest,
            manifest: pending.manifest,
            source_draft_digest: prepared.source_draft_digest(),
            publication_digest: prepared.digest(),
            lease_generation: prepared.lease_generation(),
            lease_digest: prepared.lease_digest(),
            digest: ObjectDigest::from_bytes([0; 32]),
        };
        let binding_bytes = encode_binding(&binding)?;
        binding.digest = binding_digest(&binding_bytes);
        let head = RuntimeAuthorityHeadV1 {
            sandbox,
            revision: binding.revision,
            binding_digest: binding.digest,
        };
        let head_key = current_key(sandbox);
        let head_bytes = encode_head(head);
        self.check_activation_addition(&binding_key, &binding_bytes, &head_key, &head_bytes)?;
        Ok(vec![
            JournalRecord::put(
                RecordNamespace::RuntimeAuthority,
                binding_key,
                binding_bytes,
            ),
            JournalRecord::put(RecordNamespace::RuntimeAuthority, head_key, head_bytes),
        ])
    }

    fn check_addition(
        &self,
        key: &[u8],
        value: &[u8],
        added_records: usize,
    ) -> Result<(), RuntimeAuthorityError> {
        if value.len() > self.limits.maximum_record_bytes {
            return Err(RuntimeAuthorityError::LimitExceeded("record bytes"));
        }
        let records = self
            .records
            .checked_add(added_records)
            .ok_or(RuntimeAuthorityError::LimitExceeded("record count"))?;
        if records > self.limits.maximum_records {
            return Err(RuntimeAuthorityError::LimitExceeded("record count"));
        }
        let bytes = self
            .materialized_bytes
            .checked_add(key.len())
            .and_then(|size| size.checked_add(value.len()))
            .ok_or(RuntimeAuthorityError::LimitExceeded("materialized bytes"))?;
        if bytes > self.limits.maximum_materialized_bytes {
            return Err(RuntimeAuthorityError::LimitExceeded("materialized bytes"));
        }
        Ok(())
    }

    fn check_activation_addition(
        &self,
        binding_key: &[u8],
        binding_value: &[u8],
        head_key: &[u8],
        head_value: &[u8],
    ) -> Result<(), RuntimeAuthorityError> {
        if binding_value.len() > self.limits.maximum_record_bytes
            || head_value.len() > self.limits.maximum_record_bytes
        {
            return Err(RuntimeAuthorityError::LimitExceeded("record bytes"));
        }
        let prior_head = self
            .journal
            .get(RecordNamespace::RuntimeAuthority, head_key);
        let added_records = 1 + usize::from(prior_head.is_none());
        let mut projected = self.materialized_bytes;
        projected = projected
            .checked_add(binding_key.len())
            .and_then(|size| size.checked_add(binding_value.len()))
            .ok_or(RuntimeAuthorityError::LimitExceeded("materialized bytes"))?;
        if let Some(prior) = prior_head {
            projected = projected
                .checked_sub(prior.len())
                .and_then(|size| size.checked_add(head_value.len()))
                .ok_or(RuntimeAuthorityError::LimitExceeded("materialized bytes"))?;
        } else {
            projected = projected
                .checked_add(head_key.len())
                .and_then(|size| size.checked_add(head_value.len()))
                .ok_or(RuntimeAuthorityError::LimitExceeded("materialized bytes"))?;
        }
        if self
            .records
            .checked_add(added_records)
            .is_none_or(|records| records > self.limits.maximum_records)
        {
            return Err(RuntimeAuthorityError::LimitExceeded("record count"));
        }
        if projected > self.limits.maximum_materialized_bytes {
            return Err(RuntimeAuthorityError::LimitExceeded("materialized bytes"));
        }
        Ok(())
    }
}

fn validate_namespace(
    journal: &Journal,
    limits: RuntimeAuthorityLimits,
) -> Result<(usize, usize), RuntimeAuthorityError> {
    let mut records = 0_usize;
    let mut materialized_bytes = 0_usize;
    let mut bindings: BTreeMap<[u8; 16], BTreeMap<u64, RuntimeAuthorityBindingV1>> =
        BTreeMap::new();
    let mut heads: BTreeMap<[u8; 16], RuntimeAuthorityHeadV1> = BTreeMap::new();
    let mut pending: BTreeMap<[u8; 16], RuntimeAuthorityPendingV1> = BTreeMap::new();

    for (key, value) in journal.records(RecordNamespace::RuntimeAuthority) {
        records = records
            .checked_add(1)
            .ok_or(RuntimeAuthorityError::LimitExceeded("record count"))?;
        if records > limits.maximum_records || value.len() > limits.maximum_record_bytes {
            return Err(RuntimeAuthorityError::LimitExceeded(
                "record count or bytes",
            ));
        }
        materialized_bytes = materialized_bytes
            .checked_add(key.len())
            .and_then(|bytes| bytes.checked_add(value.len()))
            .ok_or(RuntimeAuthorityError::LimitExceeded("materialized bytes"))?;
        if materialized_bytes > limits.maximum_materialized_bytes {
            return Err(RuntimeAuthorityError::LimitExceeded("materialized bytes"));
        }

        if key.starts_with(PENDING_PREFIX) {
            let operation = operation_from_pending_key(key)?;
            let pending_record = decode_pending(value)?;
            if pending_record.operation != operation {
                return Err(RuntimeAuthorityError::CorruptState);
            }
            crate::reconciler::validate_runtime_authority_pending(journal, &pending_record)
                .map_err(|_| RuntimeAuthorityError::CorruptState)?;
            if pending
                .insert(operation.into_bytes(), pending_record)
                .is_some()
            {
                return Err(RuntimeAuthorityError::CorruptState);
            }
        } else if key.starts_with(BINDING_PREFIX) {
            let (sandbox, revision) = binding_identity_from_key(key)?;
            let binding = decode_binding(value)?;
            if binding.sandbox() != sandbox || binding.revision != revision {
                return Err(RuntimeAuthorityError::CorruptState);
            }
            crate::reconciler::validate_runtime_authority_binding(journal, &binding)
                .map_err(|_| RuntimeAuthorityError::CorruptState)?;
            if bindings
                .entry(*sandbox.as_bytes())
                .or_default()
                .insert(revision, binding)
                .is_some()
            {
                return Err(RuntimeAuthorityError::CorruptState);
            }
        } else if key.starts_with(CURRENT_PREFIX) {
            let sandbox = sandbox_from_current_key(key)?;
            let head = decode_head(value)?;
            if head.sandbox != sandbox || heads.insert(*sandbox.as_bytes(), head).is_some() {
                return Err(RuntimeAuthorityError::CorruptState);
            }
        } else {
            return Err(RuntimeAuthorityError::CorruptState);
        }
    }

    crate::reconciler::validate_runtime_authority_operations(journal)
        .map_err(|_| RuntimeAuthorityError::CorruptState)?;
    if !heads.is_empty() {
        validate_publication_namespace(journal).map_err(|_| RuntimeAuthorityError::CorruptState)?;
    }
    validate_chains(journal, &pending, &bindings, &heads)?;
    Ok((records, materialized_bytes))
}

fn validate_chains(
    journal: &Journal,
    pending: &BTreeMap<[u8; 16], RuntimeAuthorityPendingV1>,
    bindings: &BTreeMap<[u8; 16], BTreeMap<u64, RuntimeAuthorityBindingV1>>,
    heads: &BTreeMap<[u8; 16], RuntimeAuthorityHeadV1>,
) -> Result<(), RuntimeAuthorityError> {
    // Revocation stops the assignment whose holder is being removed, not a
    // replacement assignment that happens to reuse the sandbox identity.
    for intent in pending
        .values()
        .filter(|intent| intent.state == RuntimeAuthorityStateV1::Revoked)
    {
        let prior = intent
            .expected_revision
            .and_then(|revision| {
                bindings
                    .get(intent.sandbox().as_bytes())
                    .and_then(|history| history.get(&revision))
            })
            .ok_or(RuntimeAuthorityError::CorruptState)?;
        if Some(prior.digest) != intent.predecessor_digest || prior.manifest != intent.manifest {
            return Err(RuntimeAuthorityError::CorruptState);
        }
    }
    if bindings.len() != heads.len() || bindings.keys().any(|sandbox| !heads.contains_key(sandbox))
    {
        return Err(RuntimeAuthorityError::CorruptState);
    }
    for (sandbox_bytes, revisions) in bindings {
        let head = heads
            .get(sandbox_bytes)
            .ok_or(RuntimeAuthorityError::CorruptState)?;
        let expected_len =
            usize::try_from(head.revision).map_err(|_| RuntimeAuthorityError::CorruptState)?;
        if revisions.len() != expected_len {
            return Err(RuntimeAuthorityError::CorruptState);
        }
        let mut predecessor = None;
        for revision in 1..=head.revision {
            let binding = revisions
                .get(&revision)
                .ok_or(RuntimeAuthorityError::CorruptState)?;
            if binding.predecessor_digest != predecessor {
                return Err(RuntimeAuthorityError::CorruptState);
            }
            let admitted = pending
                .get(binding.operation.as_bytes())
                .ok_or(RuntimeAuthorityError::CorruptState)?;
            if !binding_matches_pending(binding, admitted) {
                return Err(RuntimeAuthorityError::CorruptState);
            }
            predecessor = Some(binding.digest);
        }
        let current = revisions
            .get(&head.revision)
            .ok_or(RuntimeAuthorityError::CorruptState)?;
        if current.digest != head.binding_digest {
            return Err(RuntimeAuthorityError::CorruptState);
        }
        validate_current_publication(journal, current)?;
    }
    Ok(())
}

fn binding_matches_pending(
    binding: &RuntimeAuthorityBindingV1,
    pending: &RuntimeAuthorityPendingV1,
) -> bool {
    binding.operation == pending.operation
        && binding.request_digest == pending.request_digest
        && binding.state == pending.state
        && binding.holder == pending.holder
        && binding.revision == pending.revision
        && binding.predecessor_digest == pending.predecessor_digest
        && binding.manifest == pending.manifest
        && binding.source_draft_digest == pending.source_draft_digest
}

/// Validates an operation's exact intent commitment against its pending row.
///
/// This reciprocal replay hook lets the operation ledger reject a claimed
/// runtime intent whose protected pending evidence is absent or substituted,
/// without constructing a runtime-authority store recursively.
pub(crate) fn validate_operation_intent(
    journal: &Journal,
    operation: OperationId,
    intent_digest: ObjectDigest,
) -> Result<(), RuntimeAuthorityError> {
    journal.ensure_protected_authority()?;
    let bytes = journal
        .get(RecordNamespace::RuntimeAuthority, &pending_key(operation))
        .ok_or(RuntimeAuthorityError::CorruptState)?;
    let pending = decode_pending(bytes)?;
    if pending.operation != operation || pending.intent_digest() != intent_digest {
        return Err(RuntimeAuthorityError::CorruptState);
    }
    Ok(())
}

/// Requires an activated pending intent's exact immutable decision record.
///
/// The current head may legitimately name a later successor, so this check
/// resolves the revision captured before ownership I/O rather than treating a
/// historical activation as current authority.
pub(crate) fn validate_activated_pending(
    journal: &Journal,
    pending: &RuntimeAuthorityPendingV1,
    publication_digest: ObjectDigest,
    lease_generation: u64,
    lease_digest: ObjectDigest,
) -> Result<(), RuntimeAuthorityError> {
    journal.ensure_protected_authority()?;
    let bytes = journal
        .get(
            RecordNamespace::RuntimeAuthority,
            &binding_key(pending.sandbox(), pending.revision),
        )
        .ok_or(RuntimeAuthorityError::CorruptState)?;
    let binding = decode_binding(bytes)?;
    if !binding_matches_pending(&binding, pending)
        || binding.publication_digest != publication_digest
        || binding.lease_generation != lease_generation
        || binding.lease_digest != lease_digest
    {
        return Err(RuntimeAuthorityError::CorruptState);
    }
    Ok(())
}

fn validate_current_publication(
    journal: &Journal,
    binding: &RuntimeAuthorityBindingV1,
) -> Result<(), RuntimeAuthorityError> {
    let current = current_in_validated_namespace(journal, binding.sandbox())
        .map_err(|_| RuntimeAuthorityError::CorruptState)?
        .ok_or(RuntimeAuthorityError::CorruptState)?;
    if current.digest() != binding.publication_digest
        || current.manifest() != &binding.manifest
        || current.lease_generation() != binding.lease_generation
        || current.lease_digest() != binding.lease_digest
    {
        return Err(RuntimeAuthorityError::CorruptState);
    }
    Ok(())
}

fn current_from_journal(
    journal: &Journal,
    sandbox: SandboxId,
) -> Result<Option<RuntimeAuthorityBindingV1>, RuntimeAuthorityError> {
    let Some(head_bytes) = journal.get(RecordNamespace::RuntimeAuthority, &current_key(sandbox))
    else {
        return Ok(None);
    };
    let head = decode_head(head_bytes)?;
    if head.sandbox != sandbox {
        return Err(RuntimeAuthorityError::CorruptState);
    }
    let binding_bytes = journal
        .get(
            RecordNamespace::RuntimeAuthority,
            &binding_key(sandbox, head.revision),
        )
        .ok_or(RuntimeAuthorityError::CorruptState)?;
    let binding = decode_binding(binding_bytes)?;
    if binding.sandbox() != sandbox
        || binding.revision != head.revision
        || binding.digest != head.binding_digest
    {
        return Err(RuntimeAuthorityError::CorruptState);
    }
    Ok(Some(binding))
}

/// Resolves an immutable revision after complete namespace validation.
///
/// The caller must retain exclusive journal access from validation through
/// this lookup. Historical bindings are audit evidence, not current authority.
pub(crate) fn binding_in_validated_namespace(
    journal: &Journal,
    sandbox: SandboxId,
    revision: u64,
) -> Result<RuntimeAuthorityBindingV1, RuntimeAuthorityError> {
    journal.ensure_protected_authority()?;
    let bytes = journal
        .get(
            RecordNamespace::RuntimeAuthority,
            &binding_key(sandbox, revision),
        )
        .ok_or(RuntimeAuthorityError::CorruptState)?;
    let binding = decode_binding(bytes)?;
    if binding.sandbox() != sandbox || binding.revision() != revision {
        return Err(RuntimeAuthorityError::CorruptState);
    }
    Ok(binding)
}

fn pending_key(operation: OperationId) -> Vec<u8> {
    let mut key = Vec::with_capacity(PENDING_KEY_BYTES);
    key.extend_from_slice(PENDING_PREFIX);
    key.extend_from_slice(operation.as_bytes());
    key
}

fn operation_from_pending_key(key: &[u8]) -> Result<OperationId, RuntimeAuthorityError> {
    if key.len() != PENDING_KEY_BYTES {
        return Err(RuntimeAuthorityError::CorruptState);
    }
    let bytes: [u8; 16] = key[PENDING_PREFIX.len()..]
        .try_into()
        .map_err(|_| RuntimeAuthorityError::CorruptState)?;
    if bytes == [0; 16] {
        return Err(RuntimeAuthorityError::CorruptState);
    }
    Ok(OperationId::from_bytes(bytes))
}

fn binding_key(sandbox: SandboxId, revision: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(BINDING_KEY_BYTES);
    key.extend_from_slice(BINDING_PREFIX);
    key.extend_from_slice(sandbox.as_bytes());
    key.extend_from_slice(&revision.to_be_bytes());
    key
}

fn binding_identity_from_key(key: &[u8]) -> Result<(SandboxId, u64), RuntimeAuthorityError> {
    if key.len() != BINDING_KEY_BYTES {
        return Err(RuntimeAuthorityError::CorruptState);
    }
    let mut cursor = BINDING_PREFIX.len();
    let sandbox = SandboxId::from_bytes(
        key[cursor..cursor + 16]
            .try_into()
            .map_err(|_| RuntimeAuthorityError::CorruptState)?,
    );
    cursor += 16;
    let revision = u64::from_be_bytes(
        key[cursor..]
            .try_into()
            .map_err(|_| RuntimeAuthorityError::CorruptState)?,
    );
    if sandbox.as_bytes() == &[0; 16] || revision == 0 {
        return Err(RuntimeAuthorityError::CorruptState);
    }
    Ok((sandbox, revision))
}

fn current_key(sandbox: SandboxId) -> Vec<u8> {
    let mut key = Vec::with_capacity(CURRENT_KEY_BYTES);
    key.extend_from_slice(CURRENT_PREFIX);
    key.extend_from_slice(sandbox.as_bytes());
    key
}

fn sandbox_from_current_key(key: &[u8]) -> Result<SandboxId, RuntimeAuthorityError> {
    if key.len() != CURRENT_KEY_BYTES {
        return Err(RuntimeAuthorityError::CorruptState);
    }
    let sandbox = SandboxId::from_bytes(
        key[CURRENT_PREFIX.len()..]
            .try_into()
            .map_err(|_| RuntimeAuthorityError::CorruptState)?,
    );
    if sandbox.as_bytes() == &[0; 16] {
        return Err(RuntimeAuthorityError::CorruptState);
    }
    Ok(sandbox)
}
