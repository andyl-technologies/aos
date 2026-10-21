//! Shares complete historical Runtime namespace and continuity validation.
//!
//! The view borrows the actual native owner, resident index and optional actual
//! protected-location object. Presence/poison checks preserve the established
//! historical guard order; they do not establish physical currentness. Actual
//! private proof owners must independently retain their genuine fixed role,
//! profile, protected-name/full-prefix observation and live Host/session pins.
//! No DATA result constructs an accepted Native scope or effect permission.

use std::collections::BTreeMap;

use aos_sandbox_model::{ObjectDigest, OperationId, SandboxId, RecordNamespace};
use crate::domain_ledger::readonly::{HistoricalLedgerReadViewV1, HistoricalLedgerComparisonV2, HistoricalLedgerRowsDataV2};
use crate::domain_ledger::operation::{decode_operation, decode_operation_key};
use crate::domain_ledger::ownership_gate::OwnershipGateStatusV1;
use crate::publication::ledger_read as publication_read;
use super::crosslinks::{self, RuntimeCrosslinkDataErrorV1};
use super::{
    RuntimeAuthorityBindingV1, RuntimeAuthorityPendingV1, RuntimeAuthorityHeadV1,
    RuntimeAuthorityLimits, RuntimeAuthorityStateV1, RuntimeAuthorityDataErrorV1,
    BINDING_KEY_BYTES, BINDING_PREFIX, CURRENT_KEY_BYTES, CURRENT_PREFIX,
    PENDING_KEY_BYTES, PENDING_PREFIX, decode_binding, decode_head, decode_pending,
};

/// Reports historical Runtime DATA and recorded native guard failures.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeHistoryReadErrorV1 {
    /// A portable intent uses a reserved identity or revision.
    #[error("runtime-authority intent is invalid")]
    InvalidIntent,
    /// Portable limits violate the established fixed schema ceilings.
    #[error("runtime-authority limits are invalid")]
    InvalidLimits,
    /// A replay exceeds the established count or byte limit.
    #[error("runtime-authority {0} limit exceeded")]
    LimitExceeded(&'static str),
    /// A canonical record or complete crosslink is inconsistent.
    #[error("protected runtime-authority state is corrupt")]
    CorruptState,
    /// A retained origin and current historical binding are discontinuous.
    #[error("runtime-authority holder continuity was broken")]
    Continuity,
    /// The actual borrowed native owner records ambiguous mutation state.
    #[error("historical native Runtime ledger is poisoned")]
    Poisoned,
    /// The actual caller-owned protected-location object is absent.
    #[error("historical native Runtime protected location is absent")]
    ProtectedBoundary,
}

impl From<RuntimeAuthorityDataErrorV1> for RuntimeHistoryReadErrorV1 {
    fn from(error: RuntimeAuthorityDataErrorV1) -> Self {
        match error {
            RuntimeAuthorityDataErrorV1::InvalidIntent => Self::InvalidIntent,
            RuntimeAuthorityDataErrorV1::InvalidLimits => Self::InvalidLimits,
            RuntimeAuthorityDataErrorV1::LimitExceeded(bound) => Self::LimitExceeded(bound),
            RuntimeAuthorityDataErrorV1::CorruptState => Self::CorruptState,
        }
    }
}

/// Borrows historical DATA and the actual location object without admitting it.
///
/// Constructing this view does not check rooted names, locks, replay equality,
/// fixed role/original association, trust anchors or current live execution.
/// A private Native proof cannot be constructed from this view or its outputs.
pub struct HistoricalRuntimeLedgerReadV1<'native, P> {
    ledger: HistoricalLedgerReadViewV1<'native>,
    protected: Option<&'native P>,
}

impl<P> Copy for HistoricalRuntimeLedgerReadV1<'_, P> {}

impl<P> Clone for HistoricalRuntimeLedgerReadV1<'_, P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'native, P> HistoricalRuntimeLedgerReadV1<'native, P> {
    /// Borrows actual native/index/location objects as historical comparison inputs.
    pub const fn new(
        ledger: HistoricalLedgerReadViewV1<'native>,
        protected: Option<&'native P>,
    ) -> Self {
        Self { ledger, protected }
    }

    fn comparison_v2(self) -> RuntimeLedgerComparisonV2<'native> {
        RuntimeLedgerComparisonV2 {
            ledger: HistoricalLedgerComparisonV2::Native(self.ledger),
            boundary: if self.protected.is_some() {
                RuntimeComparisonBoundaryV2::NativeProtected
            } else {
                RuntimeComparisonBoundaryV2::NativeAbsent
            },
        }
    }
}

#[derive(Clone, Copy)]
enum RuntimeComparisonBoundaryV2 {
    NativeProtected,
    NativeAbsent,
    HistoricalRows,
    HistoricalPoisoned,
}

#[derive(Clone, Copy)]
struct RuntimeLedgerComparisonV2<'rows> {
    ledger: HistoricalLedgerComparisonV2<'rows>,
    boundary: RuntimeComparisonBoundaryV2,
}

impl<'rows> RuntimeLedgerComparisonV2<'rows> {
    fn from_rows_v2(rows: HistoricalLedgerRowsDataV2<'rows>) -> Self {
        Self { ledger: HistoricalLedgerComparisonV2::Rows(rows),
            boundary: RuntimeComparisonBoundaryV2::HistoricalRows }
    }

    fn ensure_protected_authority(self) -> Result<(), RuntimeHistoryReadErrorV1> {
        if matches!(self.boundary, RuntimeComparisonBoundaryV2::HistoricalPoisoned)
            || self.ledger.native_poisoned_v2()
        {
            return Err(RuntimeHistoryReadErrorV1::Poisoned);
        }
        if matches!(self.boundary, RuntimeComparisonBoundaryV2::NativeAbsent) {
            return Err(RuntimeHistoryReadErrorV1::ProtectedBoundary);
        }
        Ok(())
    }

    fn get(self, namespace: RecordNamespace, key: &[u8]) -> Option<&'rows [u8]> {
        self.ledger.get(namespace, key)
    }

    fn records(self, namespace: RecordNamespace)
        -> impl Iterator<Item = (&'rows [u8], &'rows [u8])> + 'rows
    {
        self.ledger.records(namespace)
    }
}

/// Scans all three Runtime families and their complete historical crosslinks.
///
/// # Errors
///
/// Preserves the original recorded guard, canonical-field or complete-link refusal.
pub fn scan_namespace<P>(
    journal: HistoricalRuntimeLedgerReadV1<'_, P>,
    limits: RuntimeAuthorityLimits,
    subject: Option<SandboxId>,
) -> Result<(usize, usize, bool), RuntimeHistoryReadErrorV1> {
    scan_namespace_comparison_v2(journal.comparison_v2(), limits, subject)
}

fn scan_namespace_comparison_v2(
    journal: RuntimeLedgerComparisonV2<'_>,
    limits: RuntimeAuthorityLimits,
    subject: Option<SandboxId>,
) -> Result<(usize, usize, bool), RuntimeHistoryReadErrorV1> {
    let mut present = false;
    let mut records = 0_usize;
    let mut materialized_bytes = 0_usize;
    let mut bindings: BTreeMap<[u8; 16], BTreeMap<u64, RuntimeAuthorityBindingV1>> =
        BTreeMap::new();
    let mut heads: BTreeMap<[u8; 16], RuntimeAuthorityHeadV1> = BTreeMap::new();
    let mut pending: BTreeMap<[u8; 16], RuntimeAuthorityPendingV1> = BTreeMap::new();

    for (key, value) in journal.records(RecordNamespace::RuntimeAuthority) {
        records = records
            .checked_add(1)
            .ok_or(RuntimeHistoryReadErrorV1::LimitExceeded("record count"))?;
        if records > limits.maximum_records()
            || value.len() > limits.maximum_record_bytes()
        {
            return Err(RuntimeHistoryReadErrorV1::LimitExceeded(
                "record count or bytes",
            ));
        }
        materialized_bytes = materialized_bytes
            .checked_add(key.len())
            .and_then(|bytes| bytes.checked_add(value.len()))
            .ok_or(RuntimeHistoryReadErrorV1::LimitExceeded("materialized bytes"))?;
        if materialized_bytes > limits.maximum_materialized_bytes() {
            return Err(RuntimeHistoryReadErrorV1::LimitExceeded("materialized bytes"));
        }

        if key.starts_with(PENDING_PREFIX) {
            let operation = operation_from_pending_key(key)?;
            let pending_record = decode_pending(value)?;
            present |= subject == Some(pending_record.sandbox());
            if pending_record.operation != operation {
                return Err(RuntimeHistoryReadErrorV1::CorruptState);
            }
            validate_pending_links_comparison_v2(journal, &pending_record)
                .map_err(|_| RuntimeHistoryReadErrorV1::CorruptState)?;
            if pending
                .insert(operation.into_bytes(), pending_record)
                .is_some()
            {
                return Err(RuntimeHistoryReadErrorV1::CorruptState);
            }
        } else if key.starts_with(BINDING_PREFIX) {
            let (sandbox, revision) = binding_identity_from_key(key)?;
            let binding = decode_binding(value)?;
            present |= subject == Some(binding.sandbox());
            if binding.sandbox() != sandbox || binding.revision != revision {
                return Err(RuntimeHistoryReadErrorV1::CorruptState);
            }
            validate_binding_links_comparison_v2(journal, &binding)
                .map_err(|_| RuntimeHistoryReadErrorV1::CorruptState)?;
            if bindings
                .entry(*sandbox.as_bytes())
                .or_default()
                .insert(revision, binding)
                .is_some()
            {
                return Err(RuntimeHistoryReadErrorV1::CorruptState);
            }
        } else if key.starts_with(CURRENT_PREFIX) {
            let sandbox = sandbox_from_current_key(key)?;
            let head = decode_head(value)?;
            present |= subject == Some(head.sandbox);
            if head.sandbox != sandbox || heads.insert(*sandbox.as_bytes(), head).is_some() {
                return Err(RuntimeHistoryReadErrorV1::CorruptState);
            }
        } else {
            return Err(RuntimeHistoryReadErrorV1::CorruptState);
        }
    }

    validate_operation_links_comparison_v2(journal)
        .map_err(|_| RuntimeHistoryReadErrorV1::CorruptState)?;
    if !heads.is_empty() {
        publication_read::scan_publication_namespace_comparison_v2(journal.ledger, None)
            .map_err(|_| RuntimeHistoryReadErrorV1::CorruptState)?;
    }
    validate_chains(journal, &pending, &bindings, &heads)?;
    Ok((records, materialized_bytes, present))
}

fn validate_chains(
    journal: RuntimeLedgerComparisonV2<'_>,
    pending: &BTreeMap<[u8; 16], RuntimeAuthorityPendingV1>,
    bindings: &BTreeMap<[u8; 16], BTreeMap<u64, RuntimeAuthorityBindingV1>>,
    heads: &BTreeMap<[u8; 16], RuntimeAuthorityHeadV1>,
) -> Result<(), RuntimeHistoryReadErrorV1> {
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
            .ok_or(RuntimeHistoryReadErrorV1::CorruptState)?;
        if Some(prior.digest) != intent.predecessor_digest
            || prior.manifest != intent.manifest
        {
            return Err(RuntimeHistoryReadErrorV1::CorruptState);
        }
    }
    if bindings.len() != heads.len() || bindings.keys().any(|sandbox| !heads.contains_key(sandbox))
    {
        return Err(RuntimeHistoryReadErrorV1::CorruptState);
    }
    for (sandbox_bytes, revisions) in bindings {
        let head = heads
            .get(sandbox_bytes)
            .ok_or(RuntimeHistoryReadErrorV1::CorruptState)?;
        let expected_len =
            usize::try_from(head.revision).map_err(|_| RuntimeHistoryReadErrorV1::CorruptState)?;
        if revisions.len() != expected_len {
            return Err(RuntimeHistoryReadErrorV1::CorruptState);
        }
        let mut predecessor = None;
        for revision in 1..=head.revision {
            let binding = revisions
                .get(&revision)
                .ok_or(RuntimeHistoryReadErrorV1::CorruptState)?;
            if binding.predecessor_digest != predecessor {
                return Err(RuntimeHistoryReadErrorV1::CorruptState);
            }
            let admitted = pending
                .get(binding.operation.as_bytes())
                .ok_or(RuntimeHistoryReadErrorV1::CorruptState)?;
            if !binding_matches_pending(binding, admitted) {
                return Err(RuntimeHistoryReadErrorV1::CorruptState);
            }
            predecessor = Some(binding.digest);
        }
        let current = revisions
            .get(&head.revision)
            .ok_or(RuntimeHistoryReadErrorV1::CorruptState)?;
        if current.digest != head.binding_digest {
            return Err(RuntimeHistoryReadErrorV1::CorruptState);
        }
        validate_current_publication(journal, current)?;
    }
    Ok(())
}

/// Compares every binding field committed by its historical pending intent.
pub fn binding_matches_pending(
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

/// Checks a recorded operation intent against its exact pending record.
///
/// # Errors
///
/// Preserves the original recorded guard, canonical-field or complete-link refusal.
pub fn validate_operation_intent<P>(
    journal: HistoricalRuntimeLedgerReadV1<'_, P>,
    operation: OperationId,
    intent_digest: ObjectDigest,
) -> Result<(), RuntimeHistoryReadErrorV1> {
    validate_operation_intent_comparison_v2(journal.comparison_v2(), operation, intent_digest)
}

fn validate_operation_intent_comparison_v2(
    journal: RuntimeLedgerComparisonV2<'_>,
    operation: OperationId,
    intent_digest: ObjectDigest,
) -> Result<(), RuntimeHistoryReadErrorV1> {
    journal.ensure_protected_authority()?;
    let bytes = journal
        .get(RecordNamespace::RuntimeAuthority, &pending_key(operation))
        .ok_or(RuntimeHistoryReadErrorV1::CorruptState)?;
    let pending = decode_pending(bytes)?;
    if pending.operation != operation || pending.intent_digest() != intent_digest {
        return Err(RuntimeHistoryReadErrorV1::CorruptState);
    }
    Ok(())
}

/// Checks a pending record against its immutable activated decision.
///
/// # Errors
///
/// Preserves the original recorded guard, canonical-field or complete-link refusal.
pub fn validate_activated_pending<P>(
    journal: HistoricalRuntimeLedgerReadV1<'_, P>,
    pending: &RuntimeAuthorityPendingV1,
    publication_digest: ObjectDigest,
    lease_generation: u64,
    lease_digest: ObjectDigest,
) -> Result<(), RuntimeHistoryReadErrorV1> {
    validate_activated_pending_comparison_v2(journal.comparison_v2(), pending, publication_digest, lease_generation, lease_digest)
}

fn validate_activated_pending_comparison_v2(
    journal: RuntimeLedgerComparisonV2<'_>,
    pending: &RuntimeAuthorityPendingV1,
    publication_digest: ObjectDigest,
    lease_generation: u64,
    lease_digest: ObjectDigest,
) -> Result<(), RuntimeHistoryReadErrorV1> {
    journal.ensure_protected_authority()?;
    let bytes = journal
        .get(
            RecordNamespace::RuntimeAuthority,
            &binding_key(pending.sandbox(), pending.revision),
        )
        .ok_or(RuntimeHistoryReadErrorV1::CorruptState)?;
    let binding = decode_binding(bytes)?;
    if !binding_matches_pending(&binding, pending)
        || binding.publication_digest != publication_digest
        || binding.lease_generation != lease_generation
        || binding.lease_digest != lease_digest
    {
        return Err(RuntimeHistoryReadErrorV1::CorruptState);
    }
    Ok(())
}

fn validate_current_publication(
    journal: RuntimeLedgerComparisonV2<'_>,
    binding: &RuntimeAuthorityBindingV1,
) -> Result<(), RuntimeHistoryReadErrorV1> {
    let current = publication_read::current_in_validated_namespace_comparison_v2(journal.ledger, binding.sandbox())
        .map_err(|_| RuntimeHistoryReadErrorV1::CorruptState)?
        .ok_or(RuntimeHistoryReadErrorV1::CorruptState)?;
    if current.history().digest() != binding.publication_digest
        || current.history().manifest() != &binding.manifest
        || current.history().lease_generation() != binding.lease_generation
        || current.history().lease_digest() != binding.lease_digest
    {
        return Err(RuntimeHistoryReadErrorV1::CorruptState);
    }
    Ok(())
}

/// Resolves the exact head and immutable binding as historical DATA.
///
/// # Errors
///
/// Preserves the original recorded guard, canonical-field or complete-link refusal.
pub fn current_from_journal<P>(
    journal: HistoricalRuntimeLedgerReadV1<'_, P>,
    sandbox: SandboxId,
) -> Result<Option<RuntimeAuthorityBindingV1>, RuntimeHistoryReadErrorV1> {
    current_from_journal_comparison_v2(journal.comparison_v2(), sandbox)
}

fn current_from_journal_comparison_v2(
    journal: RuntimeLedgerComparisonV2<'_>,
    sandbox: SandboxId,
) -> Result<Option<RuntimeAuthorityBindingV1>, RuntimeHistoryReadErrorV1> {
    let Some(head_bytes) = journal.get(RecordNamespace::RuntimeAuthority, &current_key(sandbox))
    else {
        return Ok(None);
    };
    let head = decode_head(head_bytes)?;
    if head.sandbox != sandbox {
        return Err(RuntimeHistoryReadErrorV1::CorruptState);
    }
    let binding_bytes = journal
        .get(
            RecordNamespace::RuntimeAuthority,
            &binding_key(sandbox, head.revision),
        )
        .ok_or(RuntimeHistoryReadErrorV1::CorruptState)?;
    let binding = decode_binding(binding_bytes)?;
    if binding.sandbox() != sandbox
        || binding.revision != head.revision
        || binding.digest != head.binding_digest
    {
        return Err(RuntimeHistoryReadErrorV1::CorruptState);
    }
    Ok(Some(binding))
}

/// Resolves one exact immutable revision as historical DATA.
///
/// # Errors
///
/// Preserves the original recorded guard, canonical-field or complete-link refusal.
pub fn binding_in_validated_namespace<P>(
    journal: HistoricalRuntimeLedgerReadV1<'_, P>,
    sandbox: SandboxId,
    revision: u64,
) -> Result<RuntimeAuthorityBindingV1, RuntimeHistoryReadErrorV1> {
    binding_in_validated_namespace_comparison_v2(journal.comparison_v2(), sandbox, revision)
}

fn binding_in_validated_namespace_comparison_v2(
    journal: RuntimeLedgerComparisonV2<'_>,
    sandbox: SandboxId,
    revision: u64,
) -> Result<RuntimeAuthorityBindingV1, RuntimeHistoryReadErrorV1> {
    journal.ensure_protected_authority()?;
    let bytes = journal
        .get(
            RecordNamespace::RuntimeAuthority,
            &binding_key(sandbox, revision),
        )
        .ok_or(RuntimeHistoryReadErrorV1::CorruptState)?;
    let binding = decode_binding(bytes)?;
    if binding.sandbox() != sandbox || binding.revision() != revision {
        return Err(RuntimeHistoryReadErrorV1::CorruptState);
    }
    Ok(binding)
}

/// Checks the complete uninterrupted holder and manifest revision interval.
///
/// # Errors
///
/// Preserves the original recorded guard, canonical-field or complete-link refusal.
pub fn validate_continuity_in_validated_namespace<P>(
    journal: HistoricalRuntimeLedgerReadV1<'_, P>,
    origin: &RuntimeAuthorityBindingV1,
    current: &RuntimeAuthorityBindingV1,
) -> Result<(), RuntimeHistoryReadErrorV1> {
    validate_continuity_in_validated_namespace_comparison_v2(journal.comparison_v2(), origin, current)
}

fn validate_continuity_in_validated_namespace_comparison_v2(
    journal: RuntimeLedgerComparisonV2<'_>,
    origin: &RuntimeAuthorityBindingV1,
    current: &RuntimeAuthorityBindingV1,
) -> Result<(), RuntimeHistoryReadErrorV1> {
    if origin.revision() > current.revision() {
        return Err(RuntimeHistoryReadErrorV1::Continuity);
    }
    // Preserve the original Store::current health check and short-circuit order.
    journal.ensure_protected_authority()?;
    if current_from_journal_comparison_v2(journal, origin.sandbox())?.as_ref() != Some(current)
        || binding_in_validated_namespace_comparison_v2(journal, origin.sandbox(), origin.revision())? != *origin
    {
        return Err(RuntimeHistoryReadErrorV1::Continuity);
    }
    for revision in origin.revision()..=current.revision() {
        let binding = binding_in_validated_namespace_comparison_v2(journal, origin.sandbox(), revision)?;
        if binding.state() != RuntimeAuthorityStateV1::Bound
            || binding.holder() != origin.holder()
            || binding.manifest() != origin.manifest()
        {
            return Err(RuntimeHistoryReadErrorV1::Continuity);
        }
    }
    Ok(())
}

/// Encodes the established fixed pending-intent key.
pub fn pending_key(operation: OperationId) -> Vec<u8> {
    let mut key = Vec::with_capacity(PENDING_KEY_BYTES);
    key.extend_from_slice(PENDING_PREFIX);
    key.extend_from_slice(operation.as_bytes());
    key
}

/// Decodes the established fixed pending-intent identity.
///
/// # Errors
///
/// Preserves the original recorded guard, canonical-field or complete-link refusal.
pub fn operation_from_pending_key(key: &[u8]) -> Result<OperationId, RuntimeHistoryReadErrorV1> {
    if key.len() != PENDING_KEY_BYTES {
        return Err(RuntimeHistoryReadErrorV1::CorruptState);
    }
    let bytes: [u8; 16] = key[PENDING_PREFIX.len()..]
        .try_into()
        .map_err(|_| RuntimeHistoryReadErrorV1::CorruptState)?;
    if bytes == [0; 16] {
        return Err(RuntimeHistoryReadErrorV1::CorruptState);
    }
    Ok(OperationId::from_bytes(bytes))
}

/// Encodes the established sandbox-and-revision binding key.
pub fn binding_key(sandbox: SandboxId, revision: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(BINDING_KEY_BYTES);
    key.extend_from_slice(BINDING_PREFIX);
    key.extend_from_slice(sandbox.as_bytes());
    key.extend_from_slice(&revision.to_be_bytes());
    key
}

/// Decodes the exact sandbox-and-revision binding key.
///
/// # Errors
///
/// Preserves the original recorded guard, canonical-field or complete-link refusal.
pub fn binding_identity_from_key(key: &[u8]) -> Result<(SandboxId, u64), RuntimeHistoryReadErrorV1> {
    if key.len() != BINDING_KEY_BYTES {
        return Err(RuntimeHistoryReadErrorV1::CorruptState);
    }
    let mut cursor = BINDING_PREFIX.len();
    let sandbox = SandboxId::from_bytes(
        key[cursor..cursor + 16]
            .try_into()
            .map_err(|_| RuntimeHistoryReadErrorV1::CorruptState)?,
    );
    cursor += 16;
    let revision = u64::from_be_bytes(
        key[cursor..]
            .try_into()
            .map_err(|_| RuntimeHistoryReadErrorV1::CorruptState)?,
    );
    if sandbox.as_bytes() == &[0; 16] || revision == 0 {
        return Err(RuntimeHistoryReadErrorV1::CorruptState);
    }
    Ok((sandbox, revision))
}

/// Encodes the established sandbox current-head key.
pub fn current_key(sandbox: SandboxId) -> Vec<u8> {
    let mut key = Vec::with_capacity(CURRENT_KEY_BYTES);
    key.extend_from_slice(CURRENT_PREFIX);
    key.extend_from_slice(sandbox.as_bytes());
    key
}

/// Decodes the exact sandbox current-head key.
///
/// # Errors
///
/// Preserves the original recorded guard, canonical-field or complete-link refusal.
pub fn sandbox_from_current_key(key: &[u8]) -> Result<SandboxId, RuntimeHistoryReadErrorV1> {
    if key.len() != CURRENT_KEY_BYTES {
        return Err(RuntimeHistoryReadErrorV1::CorruptState);
    }
    let sandbox = SandboxId::from_bytes(
        key[CURRENT_PREFIX.len()..]
            .try_into()
            .map_err(|_| RuntimeHistoryReadErrorV1::CorruptState)?,
    );
    if sandbox.as_bytes() == &[0; 16] {
        return Err(RuntimeHistoryReadErrorV1::CorruptState);
    }
    Ok(sandbox)
}

/// Checks pending DATA and its activated record with original guard ordering.
///
/// # Errors
///
/// Preserves malformed context, actual native guard or activated-link refusal.
pub fn validate_pending_links<P>(
    journal: HistoricalRuntimeLedgerReadV1<'_, P>,
    pending: &RuntimeAuthorityPendingV1,
) -> Result<(), RuntimeCrosslinkDataErrorV1> {
    validate_pending_links_comparison_v2(journal.comparison_v2(), pending)
}

fn validate_pending_links_comparison_v2(
    journal: RuntimeLedgerComparisonV2<'_>,
    pending: &RuntimeAuthorityPendingV1,
) -> Result<(), RuntimeCrosslinkDataErrorV1> {
    let gate = crosslinks::pending_context_comparison_v2(journal.ledger, pending)?;
    if let OwnershipGateStatusV1::Activated {
        publication_digest,
        lease_generation,
        lease_digest,
        ..
    } = gate {
        validate_activated_pending_comparison_v2(
            journal, pending, publication_digest, lease_generation, lease_digest,
        )
            .map_err(RuntimeCrosslinkDataErrorV1::RuntimeHistory)?;
    }
    Ok(())
}

/// Checks binding DATA and its publication with original poison/post ordering.
///
/// # Errors
///
/// Preserves malformed context or the original collapsed publication-link refusal.
pub fn validate_binding_links<P>(
    journal: HistoricalRuntimeLedgerReadV1<'_, P>,
    binding: &RuntimeAuthorityBindingV1,
) -> Result<(), RuntimeCrosslinkDataErrorV1> {
    validate_binding_links_comparison_v2(journal.comparison_v2(), binding)
}

fn validate_binding_links_comparison_v2(
    journal: RuntimeLedgerComparisonV2<'_>,
    binding: &RuntimeAuthorityBindingV1,
) -> Result<(), RuntimeCrosslinkDataErrorV1> {
    let (plan, publication_digest, lease_generation, lease_digest) =
        crosslinks::binding_context_comparison_v2(journal.ledger, binding)?.into_parts();
    publication_read::validate_durable_gate_publication_comparison_v2(
        journal.ledger,
        publication_digest,
        plan.publication_draft(),
        plan.claim(),
        lease_generation,
        lease_digest,
    )
    .map_err(|_| {
        RuntimeCrosslinkDataErrorV1::CorruptLedger("runtime authority publication is corrupt")
    })
}

/// Checks every recorded Runtime intent with the original native guard frontier.
///
/// # Errors
///
/// Preserves flat Operation parser errors and nested Runtime guard/link errors.
pub fn validate_operation_links<P>(
    journal: HistoricalRuntimeLedgerReadV1<'_, P>,
) -> Result<(), RuntimeCrosslinkDataErrorV1> {
    validate_operation_links_comparison_v2(journal.comparison_v2())
}

fn validate_operation_links_comparison_v2(
    journal: RuntimeLedgerComparisonV2<'_>,
) -> Result<(), RuntimeCrosslinkDataErrorV1> {
    for (key, bytes) in journal.records(RecordNamespace::Operation) {
        let operation = decode_operation(bytes)?;
        if let Some(digest) = operation.runtime_intent_digest() {
            validate_operation_intent_comparison_v2(journal, decode_operation_key(key)?, digest)
                .map_err(RuntimeCrosslinkDataErrorV1::RuntimeHistory)?;
        }
    }
    Ok(())
}

/// Validates complete supplied Runtime, publication and operation history DATA.
///
/// No native poison or protected-location assertion is inferred from rows.
/// Actual callers retain their own original reader and independently owed posts.
///
/// # Errors
/// Refuses the same canonical fields, limits, chains and complete crosslinks as
/// the ordinary historical reader. It creates no Runtime store or live proof.
pub fn scan_namespace_rows_data_v2(
    rows: HistoricalLedgerRowsDataV2<'_>,
    limits: RuntimeAuthorityLimits,
) -> Result<(usize, usize, bool), RuntimeHistoryReadErrorV1> {
    scan_namespace_comparison_v2(RuntimeLedgerComparisonV2::from_rows_v2(rows), limits, None)
}

/// Resolves a supplied immutable binding after complete historical validation.
///
/// # Errors
/// Refuses a missing, malformed or substituted binding; authenticates no native
/// location, live holder or current authority from the supplied rows.
pub fn binding_rows_data_v2(
    rows: HistoricalLedgerRowsDataV2<'_>, sandbox: SandboxId, revision: u64,
) -> Result<RuntimeAuthorityBindingV1, RuntimeHistoryReadErrorV1> {
    binding_in_validated_namespace_comparison_v2(
        RuntimeLedgerComparisonV2::from_rows_v2(rows), sandbox, revision)
}

/// Resolves a supplied current Runtime binding through the sole selector.
///
/// Full namespace/link validation and actual native currentness remain the
/// caller's obligations. This returns historical DATA, never a live binding.
///
/// # Errors
/// Rejects the same missing, corrupt or substituted current head and binding
/// as the existing Journal selector, without creating a Journal from rows.
pub fn current_rows_data_v2(
    rows: HistoricalLedgerRowsDataV2<'_>, sandbox: SandboxId,
) -> Result<Option<RuntimeAuthorityBindingV1>, RuntimeHistoryReadErrorV1> {
    current_from_journal_comparison_v2(RuntimeLedgerComparisonV2::from_rows_v2(rows), sandbox)
}

// These diagnostic inputs reproduce the original CPU guard positions. Saved
// flags and rows never authenticate a location, current role or live owner.
fn diagnostic_rows_v2(
    rows: HistoricalLedgerRowsDataV2<'_>, poisoned: bool, protected: bool,
) -> RuntimeLedgerComparisonV2<'_> {
    RuntimeLedgerComparisonV2 {
        ledger: HistoricalLedgerComparisonV2::Rows(rows),
        boundary: if poisoned {
            RuntimeComparisonBoundaryV2::HistoricalPoisoned
        } else if protected {
            RuntimeComparisonBoundaryV2::NativeProtected
        } else {
            RuntimeComparisonBoundaryV2::NativeAbsent
        },
    }
}

/// Replays historical Runtime DATA with saved diagnostic flags at old guard slots.
///
/// # Errors
/// Preserves malformed-row, poison, missing-protection and crosslink failures
/// at the same positions as the native historical comparison. Grants no role.
pub fn scan_namespace_diagnostic_rows_data_v2(
    rows: HistoricalLedgerRowsDataV2<'_>, poisoned: bool, protected: bool,
    limits: RuntimeAuthorityLimits,
) -> Result<(usize, usize, bool), RuntimeHistoryReadErrorV1> {
    scan_namespace_comparison_v2(diagnostic_rows_v2(rows, poisoned, protected), limits, None)
}

/// Resolves historical binding DATA with the original saved diagnostic checks.
///
/// # Errors
/// Preserves the original diagnostic guard and binding decode/identity errors.
pub fn binding_diagnostic_rows_data_v2(
    rows: HistoricalLedgerRowsDataV2<'_>, poisoned: bool, protected: bool,
    sandbox: SandboxId, revision: u64,
) -> Result<RuntimeAuthorityBindingV1, RuntimeHistoryReadErrorV1> {
    binding_in_validated_namespace_comparison_v2(
        diagnostic_rows_v2(rows, poisoned, protected), sandbox, revision)
}

/// Resolves current Runtime DATA while retaining the original guard positions.
///
/// # Errors
/// Preserves head decoding before the historical binding's diagnostic guard.
pub fn current_diagnostic_rows_data_v2(
    rows: HistoricalLedgerRowsDataV2<'_>, poisoned: bool, protected: bool,
    sandbox: SandboxId,
) -> Result<Option<RuntimeAuthorityBindingV1>, RuntimeHistoryReadErrorV1> {
    current_from_journal_comparison_v2(diagnostic_rows_v2(rows, poisoned, protected), sandbox)
}

/// Prices the finite diagnostic comparison/control interfaces, not row backing.
pub fn diagnostic_control_bytes_v2() -> Option<usize> {
    use std::mem::size_of;
    size_of::<RuntimeLedgerComparisonV2<'_>>().checked_mul(3)?
        .checked_add(size_of::<(HistoricalLedgerRowsDataV2<'_>, bool, bool)>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(usize, usize, bool), RuntimeHistoryReadErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<RuntimeAuthorityBindingV1, RuntimeHistoryReadErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<Option<RuntimeAuthorityBindingV1>, RuntimeHistoryReadErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
}
