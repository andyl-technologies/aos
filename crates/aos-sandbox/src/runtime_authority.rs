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

use aos_sandbox_core::{NodeId, ObjectDigest, OperationId, SandboxId};

use crate::publication::{
    AuthorityPublicationDraftV1, PreparedAuthorityPublicationV1,
};
use crate::{Journal, JournalError, JournalRecord, RecordNamespace};

#[allow(
    dead_code,
    reason = "the signed Controller receipt has no production consumer yet"
)]
mod currentness_receipt;
mod format;
mod model;
#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) use currentness_receipt::ControllerRuntimeCurrentnessReceiptV1;

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

use aos_sandbox_protocol::domain_ledger::runtime_authority_history as runtime_data;
use runtime_data::CURRENT_PREFIX;
use runtime_data::ledger_read as runtime_read;
#[cfg(test)]
use runtime_data::MAXIMUM_RECORD_BYTES;

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
    /// A current assignment belongs to a different controller node.
    #[error("current runtime authority belongs to another node")]
    NodeMismatch,
    /// Protected journal validation or access failed.
    #[error("runtime-authority journal failed: {0}")]
    Journal(#[from] JournalError),
}

impl From<runtime_data::RuntimeAuthorityDataErrorV1> for RuntimeAuthorityError {
    fn from(error: runtime_data::RuntimeAuthorityDataErrorV1) -> Self {
        use runtime_data::RuntimeAuthorityDataErrorV1 as D;
        match error {
            D::InvalidIntent => Self::InvalidIntent,
            D::InvalidLimits => Self::InvalidLimits,
            D::LimitExceeded(name) => Self::LimitExceeded(name),
            D::CorruptState => Self::CorruptState,
        }
    }
}

impl From<runtime_read::RuntimeHistoryReadErrorV1> for RuntimeAuthorityError {
    fn from(error: runtime_read::RuntimeHistoryReadErrorV1) -> Self {
        use runtime_read::RuntimeHistoryReadErrorV1 as D;
        match error {
            D::InvalidIntent => Self::InvalidIntent,
            D::InvalidLimits => Self::InvalidLimits,
            D::LimitExceeded(bound) => Self::LimitExceeded(bound),
            D::CorruptState => Self::CorruptState,
            D::Continuity => Self::Continuity,
            D::Poisoned => Self::Journal(JournalError::Poisoned),
            D::ProtectedBoundary => Self::Journal(JournalError::ProtectedBoundary),
        }
    }
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

    /// Returns every protected current binding in sandbox-identity order.
    ///
    /// The result is complete structural state, not live authorization. It is
    /// used when a node-local projection must prove that it did not silently
    /// retain or remove resources for an omitted current assignment.
    pub(crate) fn current_bindings(
        &self,
    ) -> Result<Vec<RuntimeAuthorityBindingV1>, RuntimeAuthorityError> {
        self.journal.ensure_protected_authority()?;

        self.journal
            .records(RecordNamespace::RuntimeAuthority)
            .filter(|(key, _)| key.starts_with(CURRENT_PREFIX))
            .map(|(key, _)| current_from_journal(self.journal, sandbox_from_current_key(key)?))
            .map(|binding| binding?.ok_or(RuntimeAuthorityError::CorruptState))
            .collect()
    }

    /// Validates that every current assignment belongs to the configured node.
    ///
    /// This startup audit grants no execution or mutation authority.
    ///
    /// # Errors
    ///
    /// Returns an error for unhealthy protected state, corrupt current bindings,
    /// or an assignment belonging to a different node.
    pub(crate) fn validate_current_node(
        &self,
        expected_node: NodeId,
    ) -> Result<(), RuntimeAuthorityError> {
        for binding in self.current_bindings()? {
            if binding.manifest().manifest().node() != expected_node {
                return Err(RuntimeAuthorityError::NodeMismatch);
            }
        }

        Ok(())
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
        validate_continuity_in_validated_namespace(self.journal, origin, current)
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
        if actual_revision != intent.data.expected_revision {
            return Err(RuntimeAuthorityError::CompareAndSwap);
        }
        if intent.data.state == RuntimeAuthorityStateV1::Revoked && current.is_none() {
            return Err(RuntimeAuthorityError::CompareAndSwap);
        }
        if intent.data.state == RuntimeAuthorityStateV1::Revoked
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
            data: runtime_data::RuntimeAuthorityPendingV1 {
                operation,
                request_digest,
                state: intent.data.state,
                holder: intent.data.holder,
                expected_revision: intent.data.expected_revision,
                revision,
                predecessor_digest: current.as_ref().map(RuntimeAuthorityBindingV1::digest),
                manifest,
                source_draft_digest: draft.digest(),
            },
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
        if pending.data.operation != operation
            || pending.data.request_digest != request_digest
            || pending.data.source_draft_digest != draft.digest()
            || &pending.data.manifest != draft.manifest()
            || prepared.manifest() != draft.manifest()
            || prepared.source_draft_digest() != draft.digest()
        {
            return Err(RuntimeAuthorityError::ActivationConflict);
        }

        let sandbox = pending.sandbox();
        let current = current_from_journal(self.journal, sandbox)?;
        if current.as_ref().map(RuntimeAuthorityBindingV1::revision) != pending.data.expected_revision
            || current.as_ref().map(RuntimeAuthorityBindingV1::digest) != pending.data.predecessor_digest
        {
            return Err(RuntimeAuthorityError::CompareAndSwap);
        }
        let binding_key = binding_key(sandbox, pending.data.revision);
        if self
            .journal
            .get(RecordNamespace::RuntimeAuthority, &binding_key)
            .is_some()
        {
            return Err(RuntimeAuthorityError::BindingAlreadyExists);
        }

        let mut binding = RuntimeAuthorityBindingV1 {
            data: runtime_data::RuntimeAuthorityBindingV1 {
                operation,
                request_digest,
                state: pending.data.state,
                holder: pending.data.holder,
                revision: pending.data.revision,
                predecessor_digest: pending.data.predecessor_digest,
                manifest: pending.data.manifest,
                source_draft_digest: prepared.source_draft_digest(),
                publication_digest: prepared.digest(),
                lease_generation: prepared.lease_generation(),
                lease_digest: prepared.lease_digest(),
                digest: ObjectDigest::from_bytes([0; 32]),
            },
        };
        let binding_bytes = encode_binding(&binding)?;
        binding.data.digest = binding_digest(&binding_bytes);
        let head = RuntimeAuthorityHeadV1 {
            sandbox,
            revision: binding.data.revision,
            binding_digest: binding.data.digest,
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
        if value.len() > self.limits.data.maximum_record_bytes() {
            return Err(RuntimeAuthorityError::LimitExceeded("record bytes"));
        }
        let records = self
            .records
            .checked_add(added_records)
            .ok_or(RuntimeAuthorityError::LimitExceeded("record count"))?;
        if records > self.limits.data.maximum_records() {
            return Err(RuntimeAuthorityError::LimitExceeded("record count"));
        }
        let bytes = self
            .materialized_bytes
            .checked_add(key.len())
            .and_then(|size| size.checked_add(value.len()))
            .ok_or(RuntimeAuthorityError::LimitExceeded("materialized bytes"))?;
        if bytes > self.limits.data.maximum_materialized_bytes() {
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
        if binding_value.len() > self.limits.data.maximum_record_bytes()
            || head_value.len() > self.limits.data.maximum_record_bytes()
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
            .is_none_or(|records| records > self.limits.data.maximum_records())
        {
            return Err(RuntimeAuthorityError::LimitExceeded("record count"));
        }
        if projected > self.limits.data.maximum_materialized_bytes() {
            return Err(RuntimeAuthorityError::LimitExceeded("materialized bytes"));
        }
        Ok(())
    }
}

pub(crate) fn validate_namespace(
    journal: &Journal,
    limits: RuntimeAuthorityLimits,
) -> Result<(usize, usize), RuntimeAuthorityError> {
    scan_namespace(journal, limits, None).map(|(records, bytes, _)| (records, bytes))
}

// Pending intents and immutable historical bindings also prevent a fresh first
// assignment. Looking only at current(sandbox) would miss both families.
pub(crate) fn assignment_subject_present_v1(
    journal: &Journal,
    sandbox: SandboxId,
) -> Result<bool, RuntimeAuthorityError> {
    scan_namespace(journal, RuntimeAuthorityLimits::default(), Some(sandbox))
        .map(|(_, _, present)| present)
}

fn scan_namespace(
    journal: &Journal,
    limits: RuntimeAuthorityLimits,
    subject: Option<SandboxId>,
) -> Result<(usize, usize, bool), RuntimeAuthorityError> {
    journal
        .runtime_history_read_v1()
        .scan(limits.data, subject)
        .map_err(RuntimeAuthorityError::from)
}


fn binding_matches_pending(
    binding: &RuntimeAuthorityBindingV1,
    pending: &RuntimeAuthorityPendingV1,
) -> bool {
    runtime_read::binding_matches_pending(&binding.data, &pending.data)
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
    journal
        .runtime_history_read_v1()
        .validate_operation_intent(operation, intent_digest)
        .map_err(RuntimeAuthorityError::from)
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
    journal
        .runtime_history_read_v1()
        .validate_activated_pending(
            &pending.data, publication_digest, lease_generation, lease_digest,
        )
        .map_err(RuntimeAuthorityError::from)
}


/// Prices the complete current Runtime/publication structural selection together.
///
/// Actual foreign Effect/publication/assignment codecs and Runtime map nodes
/// may coexist while the complete reader checks crosslinks. The held Journal
/// remains borrowed; no writer, decoder or native authority is created here.
#[must_use]
pub(crate) fn current_publication_receiving_demand_v2(journal: &Journal)
    -> Option<aos_sandbox_core::ResourceVector> {
    use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
    let state = journal.historical_read_view_v1().materialized_state_v1();
    let models = crate::cold_launch_publication::completion::controller_selector_model_bytes_v1(state)?;
    let names = crate::cold_launch_publication::completion::controller_selector_namespace_entries_v1(state)?;
    let maps = runtime_data::namespace_scan_map_receiving_demand_v2(state)?;
    let fixed = std::mem::size_of::<RuntimeAuthorityBindingV1>().checked_mul(2)?
        .checked_add(std::mem::size_of::<crate::publication::CurrentAuthorityPublicationV1>().checked_mul(2)?)?
        .checked_add(std::mem::size_of::<aos_sandbox_protocol::domain_ledger::operation::OperationRecord>().checked_mul(2)?)?;
    maps.checked_add(ResourceVector::ZERO.with(D::MemoryBytes,
        u64::try_from(models.checked_add(fixed)?).ok()?)
        .with(D::MetadataEntries, u64::try_from(names).ok()?)).ok()
}

/// Resolves current structural DATA after the same complete protected namespace check.
///
/// The caller retains the actual Journal and pays its historical model before
/// this read. This lends no writer, native currentness or live execution grant.
///
/// # Errors
/// Refuses unhealthy/nonprotected custody, configured bounds, malformed full
/// history/cross-links or a current head inconsistent with its immutable row.
pub(crate) fn current_readonly_v2(journal: &Journal, limits: RuntimeAuthorityLimits,
    sandbox: SandboxId,
) -> Result<Option<RuntimeAuthorityBindingV1>, RuntimeAuthorityError> {
    journal.ensure_protected_authority()?;
    validate_namespace(journal, limits)?;
    journal.ensure_protected_authority()?;
    current_from_journal(journal, sandbox)
}

fn current_from_journal(
    journal: &Journal,
    sandbox: SandboxId,
) -> Result<Option<RuntimeAuthorityBindingV1>, RuntimeAuthorityError> {
    journal
        .runtime_history_read_v1()
        .current(sandbox)
        .map(|binding| binding.map(|data| RuntimeAuthorityBindingV1 { data }))
        .map_err(RuntimeAuthorityError::from)
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
    journal
        .runtime_history_read_v1()
        .binding(sandbox, revision)
        .map(|data| RuntimeAuthorityBindingV1 { data })
        .map_err(RuntimeAuthorityError::from)
}

/// Reuses the exact uninterrupted holder/assignment check after full replay.
///
/// # Errors
///
/// Rejects changed protected endpoints, unhealthy custody or any revoke/rebind
/// or assignment/holder substitution in the complete intervening chain.
pub(crate) fn validate_continuity_in_validated_namespace(
    journal: &Journal,
    origin: &RuntimeAuthorityBindingV1,
    current: &RuntimeAuthorityBindingV1,
) -> Result<(), RuntimeAuthorityError> {
    journal
        .runtime_history_read_v1()
        .continuity(&origin.data, &current.data)
        .map_err(RuntimeAuthorityError::from)
}

/// Reads only a fully validated exact current binding for a record cross-link.
///
/// # Errors
///
/// Rejects unhealthy/corrupt/oversized history or a noncurrent exact reference.
/// This structural result still requires independent signature/current checks.
pub(crate) fn validated_consumer_binding(
    journal: &Journal,
    reference: DurableRuntimeAuthorityReferenceV1,
) -> Result<RuntimeAuthorityBindingV1, RuntimeAuthorityError> {
    journal.ensure_protected_authority()?;
    validate_namespace(journal, RuntimeAuthorityLimits::default())?;
    let binding = binding_for_durable_reference_in_validated_namespace(journal, reference)?;
    if current_from_journal(journal, reference.sandbox())?.as_ref() != Some(&binding) {
        return Err(RuntimeAuthorityError::Continuity);
    }
    Ok(binding)
}

/// Names one immutable runtime-authority binding without granting current authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DurableRuntimeAuthorityReferenceV1 {
    sandbox: SandboxId,
    revision: u64,
    binding_digest: ObjectDigest,
}

impl DurableRuntimeAuthorityReferenceV1 {
    pub(crate) fn from_binding(binding: &RuntimeAuthorityBindingV1) -> Self {
        Self {
            sandbox: binding.sandbox(),
            revision: binding.revision(),
            binding_digest: binding.digest(),
        }
    }

    pub(crate) const fn from_parts(
        sandbox: SandboxId,
        revision: u64,
        binding_digest: ObjectDigest,
    ) -> Self {
        Self {
            sandbox,
            revision,
            binding_digest,
        }
    }

    pub(crate) const fn sandbox(self) -> SandboxId {
        self.sandbox
    }

    pub(crate) const fn revision(self) -> u64 {
        self.revision
    }

    pub(crate) const fn binding_digest(self) -> ObjectDigest {
        self.binding_digest
    }
}

/// Resolves one immutable runtime-authority reference after namespace validation.
pub(crate) fn binding_for_durable_reference_in_validated_namespace(
    journal: &Journal,
    reference: DurableRuntimeAuthorityReferenceV1,
) -> Result<RuntimeAuthorityBindingV1, RuntimeAuthorityError> {
    let binding = binding_in_validated_namespace(journal, reference.sandbox, reference.revision)?;
    if binding.digest() != reference.binding_digest {
        return Err(RuntimeAuthorityError::CorruptState);
    }
    Ok(binding)
}

#[cfg(test)]
pub(crate) fn binding_for_catalog_test(
    manifest: aos_sandbox_core::CanonicalAssignmentManifestV1,
    state: RuntimeAuthorityStateV1,
) -> RuntimeAuthorityBindingV1 {
    let mut binding = RuntimeAuthorityBindingV1 {
        data: runtime_data::RuntimeAuthorityBindingV1 {
            operation: OperationId::from_bytes([201; 16]),
            request_digest: [202; 32],
            state,
            holder: (state == RuntimeAuthorityStateV1::Bound)
                .then_some(aos_sandbox_core::PrincipalId::from_bytes([203; 16])),
            revision: 1,
            predecessor_digest: None,
            manifest,
            source_draft_digest: ObjectDigest::from_bytes([204; 32]),
            publication_digest: ObjectDigest::from_bytes([205; 32]),
            lease_generation: 1,
            lease_digest: ObjectDigest::from_bytes([206; 32]),
            digest: ObjectDigest::from_bytes([0; 32]),
        },
    };
    let encoded = encode_binding(&binding)
        .unwrap_or_else(|error| panic!("catalog test binding encoding failed: {error}"));
    binding.data.digest = binding_digest(&encoded);
    binding
}

fn pending_key(operation: OperationId) -> Vec<u8> {
    runtime_read::pending_key(operation)
}

fn operation_from_pending_key(key: &[u8]) -> Result<OperationId, RuntimeAuthorityError> {
    runtime_read::operation_from_pending_key(key).map_err(RuntimeAuthorityError::from)
}

fn binding_key(sandbox: SandboxId, revision: u64) -> Vec<u8> {
    runtime_read::binding_key(sandbox, revision)
}

fn binding_identity_from_key(key: &[u8]) -> Result<(SandboxId, u64), RuntimeAuthorityError> {
    runtime_read::binding_identity_from_key(key).map_err(RuntimeAuthorityError::from)
}

fn current_key(sandbox: SandboxId) -> Vec<u8> {
    runtime_read::current_key(sandbox)
}

fn sandbox_from_current_key(key: &[u8]) -> Result<SandboxId, RuntimeAuthorityError> {
    runtime_read::sandbox_from_current_key(key).map_err(RuntimeAuthorityError::from)
}
