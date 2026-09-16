//! Exact journal transaction assembly for sealed AOSMSA02 transitions.
//!
//! This module owns no signing, trust, kernel, or manager authority. Callers
//! first derive complete successor records from move-only authority tokens;
//! this layer seals those records, validates the entire tentative recovered
//! graph, and commits at most five namespace-40 replacements atomically.

use std::collections::BTreeSet;

use aos_sandbox::journal::{JournalTransaction, ProtectedJournalAuthority};

use super::SourceAcquisitionTableV2;
use super::format::{MutationTagV2, put_record, seal_record, state_error, transaction_id};
use super::model::{
    AcquisitionPredecessorWitnessV2, OwnerPredecessorWitnessV2, ProviderHeadPredecessorWitnessV2,
    RecordRefV2, ReleaseInventoryFenceWitnessV2, SourceAcquisitionRowV2, SourceProviderHeadV2,
    SourceProviderSessionV2, StoredRecordV2,
};
use super::projection::{projection_entries, projection_from_entries};
use super::validation::validate_recovered_table;
use crate::Result;

pub(super) const MAXIMUM_AOSMSA02_MUTATION_RECORDS: usize = 5;

pub(super) struct MutationIdentityV2 {
    pub tag: MutationTagV2,
    pub holder_id: [u8; 16],
    pub provider_id: [u8; 16],
    pub next_holder_sequence_revision: u64,
    pub next_head_revision: u64,
    pub acquisition_id: Option<[u8; 32]>,
    pub next_row_revision: Option<u64>,
    pub attempt_id: Option<[u8; 32]>,
    pub next_attempt_revision: Option<u64>,
    pub session_id: Option<[u8; 32]>,
}

pub(super) fn next_revision(current: u64) -> Result<u64> {
    current
        .checked_add(1)
        .ok_or_else(|| state_error("AOSMSA02 record revision is exhausted"))
}

pub(super) fn record_ref(record: &StoredRecordV2) -> Result<RecordRefV2> {
    match record {
        StoredRecordV2::Acquisition { value } => Ok(RecordRefV2 {
            id: value.acquisition_id,
            revision: value.revision,
            record_digest: value.record_digest,
        }),
        StoredRecordV2::ProviderSession { value } => Ok(RecordRefV2 {
            id: value.session_id,
            revision: value.revision,
            record_digest: value.record_digest,
        }),
        StoredRecordV2::ProviderQueryAttempt { value } => Ok(RecordRefV2 {
            id: value.attempt_id,
            revision: value.revision,
            record_digest: value.record_digest,
        }),
        StoredRecordV2::ProviderHead { .. } | StoredRecordV2::HolderSequence { .. } => Err(
            state_error("AOSMSA02 record kind has no 32-byte record reference"),
        ),
    }
}

pub(super) fn seal(record: StoredRecordV2) -> Result<StoredRecordV2> {
    Ok(seal_record(record)?)
}

pub(super) fn advance_head_projection(
    current: &SourceProviderHeadV2,
    current_rows: &std::collections::BTreeMap<[u8; 32], SourceAcquisitionRowV2>,
    next_rows: &std::collections::BTreeMap<[u8; 32], SourceAcquisitionRowV2>,
) -> Result<SourceProviderHeadV2> {
    let current_entries = projection_entries(current.scope, current_rows);
    let next_entries = projection_entries(current.scope, next_rows);
    if current_entries == next_entries {
        return Ok(current.clone());
    }

    let epoch = current
        .current_projection_epoch
        .checked_add(1)
        .ok_or_else(|| state_error("SourceProvider projection epoch is exhausted"))?;
    let projection = projection_from_entries(current.scope, epoch, &next_entries)?;
    let mut next = current.clone();
    next.revision = next_revision(current.revision)?;
    next.current_projection_epoch = epoch;
    next.current_projection_digest = projection.digest;
    next.last_reconciliation = None;
    Ok(next)
}

pub(super) fn initial_provider_head(
    session: &SourceProviderSessionV2,
    rows: &std::collections::BTreeMap<[u8; 32], SourceAcquisitionRowV2>,
    pending_attempt: RecordRefV2,
) -> Result<SourceProviderHeadV2> {
    let projection =
        projection_from_entries(session.scope, 1, &projection_entries(session.scope, rows))?;
    Ok(SourceProviderHeadV2 {
        revision: 1,
        scope: session.scope,
        holder_authority_generation: session.root_mount_authority_generation,
        holder_authority_digest: session.root_mount_authority_digest,
        provider_authority_generation: session.provider_authority_generation,
        provider_authority_digest: session.provider_authority_digest,
        current_session_id: session.session_id,
        current_session_record_digest: session.record_digest,
        next_request_sequence: 2,
        next_response_sequence: 1,
        pending_attempt: Some(pending_attempt),
        inventory_observation_ordinal: 0,
        inventory_floor: None,
        last_inventory_attempt: None,
        current_projection_epoch: projection.epoch,
        current_projection_digest: projection.digest,
        last_reconciliation: None,
        recovery_barrier: None,
        record_digest: [0; 32],
    })
}

pub(super) fn acquisition_predecessor(row: &SourceAcquisitionRowV2) -> OwnerPredecessorWitnessV2 {
    OwnerPredecessorWitnessV2::Acquisition {
        value: AcquisitionPredecessorWitnessV2 {
            record: RecordRefV2 {
                id: row.acquisition_id,
                revision: row.revision,
                record_digest: row.record_digest,
            },
            acquisition_id: row.acquisition_id,
            provider_acquisition: row.provider_acquisition,
            phase: row.phase,
            scope: row.scope,
            acquire: row.acquire,
            acquire_intent_digest: row.acquire_intent_digest,
            acquire_lineage: row.acquire_lineage.clone(),
            acquire_terminal_attempt: row.acquire_terminal_attempt,
            release: row.release,
            release_authority: row.release_authority,
            release_from_phase: row.release_from_phase,
            release_intent_digest: row.release_intent_digest,
            release_lineage: row.release_lineage.clone(),
            release_terminal_attempt: row.release_terminal_attempt,
            release_inventory_fence: row.release_inventory_fence.as_ref().map(|fence| {
                ReleaseInventoryFenceWitnessV2 {
                    inventory_observation_floor: fence.inventory_observation_floor,
                    projection_epoch: fence.projection_epoch,
                    projection_digest: fence.projection_digest,
                    projection_entry_count: u32::try_from(fence.projection_entries.len())
                        .unwrap_or(u32::MAX),
                }
            }),
            assignment: row.assignment,
            prospective_mount_template_digest: row.prospective_mount_template_digest,
            source_binding_digest: row.source_binding_digest,
            mount_plan_digest: row.mount_plan_digest,
            ownership_lease_digest: row.ownership_lease_digest,
            evidence: row.evidence.clone(),
            manager_custody: row.manager_custody,
            manager_custody_loss: row.manager_custody_loss,
            descriptor_custody_digest: row.descriptor_custody_digest,
            positive_custody_digest: row.positive_custody_digest,
            consumption: row.consumption.clone(),
            release_proof: row.release_proof.clone(),
            negative_custody_digest: row.negative_custody_digest,
            faulted_from: row.faulted_from,
            fault_digest: row.fault_digest,
            retained_faulted_from: row.retained_faulted_from,
            retained_fault_digest: row.retained_fault_digest,
            recovery: row.recovery.clone(),
        },
    }
}

pub(super) fn provider_head_predecessor(head: &SourceProviderHeadV2) -> OwnerPredecessorWitnessV2 {
    OwnerPredecessorWitnessV2::ProviderHead {
        value: ProviderHeadPredecessorWitnessV2 {
            record: RecordRefV2 {
                id: provider_head_record_id(head),
                revision: head.revision,
                record_digest: head.record_digest,
            },
            scope: head.scope,
            holder_authority_generation: head.holder_authority_generation,
            holder_authority_digest: head.holder_authority_digest,
            provider_authority_generation: head.provider_authority_generation,
            provider_authority_digest: head.provider_authority_digest,
            current_session_id: head.current_session_id,
            current_session_record_digest: head.current_session_record_digest,
            next_request_sequence: head.next_request_sequence,
            next_response_sequence: head.next_response_sequence,
            pending_attempt: head.pending_attempt,
            inventory_observation_ordinal: head.inventory_observation_ordinal,
            inventory_floor: head.inventory_floor.clone(),
            last_inventory_attempt: head.last_inventory_attempt,
            current_projection_epoch: head.current_projection_epoch,
            current_projection_digest: head.current_projection_digest,
            last_reconciliation: head.last_reconciliation.clone(),
            recovery_barrier: head.recovery_barrier.clone(),
        },
    }
}

fn provider_head_record_id(head: &SourceProviderHeadV2) -> [u8; 32] {
    let mut id = [0; 32];
    id[..16].copy_from_slice(&head.scope.holder_authority_id);
    id[16..].copy_from_slice(&head.scope.provider_authority_id);
    id
}

pub(super) fn commit_mutation(
    table: &mut SourceAcquisitionTableV2,
    journal: &mut ProtectedJournalAuthority<'_>,
    identity: MutationIdentityV2,
    records: Vec<StoredRecordV2>,
) -> Result<()> {
    let (transaction, tentative) = prepare_mutation(table, identity, records)?;
    journal.commit(&transaction)?;
    *table = tentative;
    Ok(())
}

pub(super) fn prepare_mutation(
    table: &SourceAcquisitionTableV2,
    identity: MutationIdentityV2,
    records: Vec<StoredRecordV2>,
) -> Result<(JournalTransaction, SourceAcquisitionTableV2)> {
    if records.is_empty() || records.len() > MAXIMUM_AOSMSA02_MUTATION_RECORDS {
        return Err(state_error(
            "AOSMSA02 mutation has an invalid closed record count",
        ));
    }

    let sealed = records
        .into_iter()
        .map(|record| -> Result<_> { Ok(seal_record(record)?) })
        .collect::<Result<Vec<_>>>()?;
    let mut keys = BTreeSet::new();
    let journal_records = sealed
        .iter()
        .map(|record| {
            let encoded = put_record(record)?;
            if !keys.insert(encoded.key().to_vec()) {
                return Err(state_error("AOSMSA02 mutation repeats a record key"));
            }
            Ok(encoded)
        })
        .collect::<Result<Vec<_>>>()?;

    let mut tentative = table.clone();
    for record in sealed {
        tentative.apply_record(record);
    }
    validate_recovered_table(&tentative)?;

    let transaction = JournalTransaction::new(
        transaction_id(
            identity.tag,
            identity.holder_id,
            identity.provider_id,
            identity.next_holder_sequence_revision,
            identity.next_head_revision,
            identity.acquisition_id,
            identity.next_row_revision,
            identity.attempt_id,
            identity.next_attempt_revision,
            identity.session_id,
        ),
        journal_records,
    )?;
    Ok((transaction, tentative))
}

impl SourceAcquisitionTableV2 {
    fn apply_record(&mut self, record: StoredRecordV2) {
        match record {
            StoredRecordV2::Acquisition { value } => {
                self.acquisitions.insert(value.acquisition_id, value);
            }
            StoredRecordV2::ProviderHead { value } => {
                self.provider_heads.insert(
                    (
                        value.scope.holder_authority_id,
                        value.scope.provider_authority_id,
                    ),
                    value,
                );
            }
            StoredRecordV2::HolderSequence { value } => {
                self.holder_sequences
                    .insert(value.holder_authority_id, value);
            }
            StoredRecordV2::ProviderSession { value } => {
                self.provider_sessions.insert(value.session_id, value);
            }
            StoredRecordV2::ProviderQueryAttempt { value } => {
                self.provider_attempts.insert(value.attempt_id, value);
            }
        }
    }
}
