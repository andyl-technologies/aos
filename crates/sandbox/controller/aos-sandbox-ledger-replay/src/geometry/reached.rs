//! Prices reached Source semantic carriers before the existing typed reducers.
//!
//! This folds borrowed raw State and the actual validated native transaction.
//! It neither parses another journal nor materializes a second map. Receiving
//! authority remains with the genuine Source original's one borrowed ledger.

use std::mem::size_of;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::capacity_family::family::CanonicalCapacityFamily;
use aos_sandbox_protocol::domain_ledger::source_policy_hold::{
    SourceDomainPolicyHoldV1, SourceDomainPolicyV8PendingSettlementV1,
};

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as JournalError;
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;
use aos_sandbox_model::RecordNamespace;

type State = std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

/// Counts actual current and proposed semantic representations without cloning.
///
/// Current and prospective folds can coexist. Both sets are included, including
/// the original value of a DELETE and a PUT replacing an existing key. Each
/// family uses its own actual Rust carrier widths; encoded work is bounded by
/// actual reached bytes. Unclassified rows retain the conservative existing
/// cross-role bound per actual ROW, never per byte of a Source tree or receipt.
/// Native framing, pending records, State, replay-cache and checkpoint custody
/// are separate terms already admitted from the same captured native extent.
///
/// # Errors
/// Rejects checked representation overflow without entering a typed reducer.
pub fn semantic_demand_v1(
    state: &State,
    transaction: Option<&JournalTransaction>,
) -> Result<ResourceVector, JournalError> {
    let mut shape = Shape::default();
    for ((namespace, key), value) in state {
        shape.row(*namespace, key, Some(value))?;
    }
    if let Some(transaction) = transaction {
        for record in transaction.records() {
            shape.row(record.namespace(), record.key(), record.value())?;
        }
    }
    let ordinary = shape.finish()?;
    // The sole links validator can retain a full parent Effect/public request,
    // pending assignment and publication gate together. Existing Source row
    // widths do not bound those foreign graphs. This borrowed fold allocates
    // nothing before the actual receiver admits the resulting complete peak.
    let bytes = aos_sandbox_protocol::domain_ledger::provisioning_resources::
        provisioning_links_reached_receiving_bytes_v1(state, transaction)
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(JournalError::LimitExceeded("provisioning link decoder geometry"))?;
    ordinary.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
        .map_err(|_| JournalError::LimitExceeded("provisioning link decoder geometry"))
}

#[derive(Default)]
struct Shape {
    bytes: usize,
    cells: usize,
}

impl Shape {
    fn row(
        &mut self,
        namespace: RecordNamespace,
        key: &[u8],
        value: Option<&[u8]>,
    ) -> Result<(), JournalError> {
        let invalid = || JournalError::LimitExceeded("Source semantic receiving geometry");
        let encoded = key.len().checked_add(value.map_or(0, <[u8]>::len))
            .ok_or_else(invalid)?;
        let links = size_of::<(Vec<u8>, Vec<u8>, [usize; 3])>();
        let (row_bytes, additional_bytes, additional_cells) = if key.starts_with(b"\0aos-hierarchy-v1\0")
            && super::hierarchy::matches_namespace(key, namespace)
        {
            super::hierarchy::row_geometry(key, value.unwrap_or_default())?
        } else if namespace == RecordNamespace::DesiredState
            && key.starts_with(b"\0aos-source-tree-genesis-")
        {
            (size_of::<crate::genesis::SourceTreeGenesisReceiptV1>()
                + size_of::<crate::replay::source_tree_genesis::SourceGenesisAckV1>()
                + size_of::<crate::replay::source_tree_genesis::SourceGenesisPendingV1>(), 0, 0)
        } else if namespace == RecordNamespace::DesiredState
            && key.starts_with(b"\0aos-source-first-successor-")
        {
            (size_of::<crate::replay::phase_records::SourceFirstSuccessorReceiptV2>()
                + size_of::<crate::replay::phase_records::SourceFirstSuccessorPendingV2>()
                + size_of::<crate::replay::phase_records::SourceFirstSuccessorAckV2>(), 0, 0)
        } else if namespace == RecordNamespace::SourceDomainPolicyHold {
            (size_of::<SourceDomainPolicyHoldV1>()
                + size_of::<SourceDomainPolicyV8PendingSettlementV1>()
                + size_of::<crate::source_domain_challenge::SourceDomainChallengeDataV1>(), 0, 0)
        } else if namespace == RecordNamespace::DesiredState
            && key == b"\0aos-source-domain-root-challenge-v1\0"
        {
            (size_of::<crate::source_domain_challenge::SourceDomainChallengeDataV1>(), 0, 0)
        } else if namespace == RecordNamespace::DesiredState
            && key.starts_with(b"\0aos-source-project-")
        {
            (size_of::<aos_sandbox_protocol::domain_ledger::source_project_history::SourceProjectAdmissionChallengeV1>()
                + size_of::<aos_sandbox_protocol::domain_ledger::source_project_history::SourceProjectAdmissionReservationV1>()
                + size_of::<aos_sandbox_protocol::domain_ledger::source_project_history::SourceProjectAdmissionTerminalV1>(), 0, 0)
        } else if namespace == RecordNamespace::GlobalCapacityReservation {
            (size_of::<CanonicalCapacityFamily>(), 0, 0)
        } else if namespace == RecordNamespace::Idempotency {
            (size_of::<aos_sandbox_protocol::domain_ledger::readonly::IdempotencyDecisionV1>(), 0, 0)
        } else {
            // The same generic Native reducers still inspect foreign families.
            // Do not skip them, silently narrow accepted history, or price them
            // as a cheap Source row merely because the fixed path is Source's.
            let mut maximum = 0;
            for width in super::semantic_rows::native_semantic_row_widths_v1()? {
                maximum = maximum.max(width);
            }
            (maximum, 0, 0)
        };

        // Thirty-two simultaneous matching row carriers cover live/prospective
        // maps, decoded genesis and successor maps, full protected projection,
        // retained tree/lineage heads, key/set joins and repeated comparisons.
        // Encoded copies and geometric collection spare capacity are separate.
        let rows = row_bytes.checked_add(links).and_then(|bytes| bytes.checked_mul(32))
            .and_then(|bytes| bytes.checked_add(additional_bytes)).ok_or_else(invalid)?;
        let bytes = encoded.checked_mul(128).and_then(|bytes| bytes.checked_add(rows))
            .ok_or_else(invalid)?;
        self.bytes = self.bytes.checked_add(bytes).ok_or_else(invalid)?;
        self.cells = self.cells.checked_add(32)
            .and_then(|cells| cells.checked_add(additional_cells)).ok_or_else(invalid)?;
        Ok(())
    }

    fn finish(self) -> Result<ResourceVector, JournalError> {
        let invalid = || JournalError::LimitExceeded("Source semantic receiving geometry");
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(self.bytes).map_err(|_| invalid())?)
            .with(D::MetadataEntries, u64::try_from(self.cells).map_err(|_| invalid())?))
    }
}
