//! Opaque adapter evidence for local acquisition lifecycle transitions.
//!
//! Provider cryptography alone cannot establish PID 1 descriptor custody or
//! atomic Create admission. The evidence types here intentionally have no
//! public constructors. Their future constructors belong beside authoritative
//! manager-query and source-pin/Create adapters; until then these transitions
//! are present for recovery modeling but impossible to invoke from production.

use super::*;

/// Proves PID 1 acknowledged custody of the exact acquired SourceRoot.
#[derive(Debug)]
pub struct DescriptorCustodyCommitV1 {
    acquisition_id: [u8; 32],
    descriptor_commitment: [u8; 32],
    custody_digest: [u8; 32],
}

/// Proves an authoritative PID 1 query found the exact custodied descriptor.
#[derive(Debug)]
pub struct PositiveCustodyCommitV1 {
    acquisition_id: [u8; 32],
    descriptor_commitment: [u8; 32],
    custody_digest: [u8; 32],
}

/// Proves source-pin activation and one final Create admission were validated together.
#[derive(Debug)]
pub struct SourceConsumptionCommitV1 {
    acquisition_id: [u8; 32],
    source_realization_handle: [u8; 32],
    source_binding_digest: [u8; 32],
    provider_resource_digest: [u8; 32],
    projected_create_template_digest: [u8; 32],
    final_create_semantics: Vec<u8>,
    source_pin_record: JournalRecord,
    create_effect_record: JournalRecord,
    create_operation_record: JournalRecord,
}

/// Returns the exact companion records committed with one consumed acquisition.
///
/// The caller must apply these records to its source-pin and effect/operation
/// in-memory indexes before servicing another request. This prevents a
/// successful multi-record commit from remaining stale until journal reopen.
#[derive(Clone, Debug)]
pub struct CommittedSourceConsumptionV1 {
    records: Vec<JournalRecord>,
}

impl CommittedSourceConsumptionV1 {
    /// Returns the exact already-committed companion records in transaction order.
    #[must_use]
    pub fn records(&self) -> &[JournalRecord] {
        &self.records
    }
}

/// Proves an authoritative PID 1 query found the exact descriptor absent.
#[derive(Debug)]
pub struct NegativeCustodyCommitV1 {
    acquisition_id: [u8; 32],
    descriptor_commitment: [u8; 32],
    custody_digest: [u8; 32],
}

impl SourceAcquisitionTableV1 {
    /// Records acknowledged PID 1 custody after the complete disposition CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for stale state, noncomplete provider evidence, a
    /// mismatched opaque manager acknowledgement, or journal failure.
    pub fn record_descriptor_custody(
        &mut self,
        journal: &mut Journal,
        acquisition_id: [u8; 32],
        expected_revision: u64,
        expected_digest: [u8; 32],
        custody: &DescriptorCustodyCommitV1,
    ) -> Result<()> {
        let current = self.current_for_cas(acquisition_id, expected_revision, expected_digest)?;
        let evidence = current
            .evidence
            .as_ref()
            .ok_or_else(|| state_error("descriptor custody has no complete provider evidence"))?;
        if current.phase != SourceAcquisitionPhaseV1::PendingQuery
            || current
                .acquire_checkpoint
                .as_ref()
                .is_none_or(|checkpoint| checkpoint.status != ProviderStatusV1::Complete)
            || custody.acquisition_id != acquisition_id
            || custody.descriptor_commitment != evidence.descriptor_commitment
            || custody.custody_digest == [0; 32]
        {
            return Err(state_error("descriptor custody acknowledgement differs"));
        }

        let mut next = current.clone();
        next.revision = next_revision(current.revision)?;
        next.phase = SourceAcquisitionPhaseV1::DescriptorCustodied;
        next.descriptor_custody_digest = Some(custody.custody_digest);
        self.commit_lifecycle(journal, next, Vec::new())
    }

    /// Records an authoritative positive PID 1 readback and activates the source.
    ///
    /// # Errors
    ///
    /// Returns an error for stale state, a non-custodied source, mismatched
    /// opaque readback evidence, or journal failure.
    pub fn activate_custodied_source(
        &mut self,
        journal: &mut Journal,
        acquisition_id: [u8; 32],
        expected_revision: u64,
        expected_digest: [u8; 32],
        custody: &PositiveCustodyCommitV1,
    ) -> Result<()> {
        let current = self.current_for_cas(acquisition_id, expected_revision, expected_digest)?;
        let evidence = current
            .evidence
            .as_ref()
            .ok_or_else(|| state_error("positive custody has no provider evidence"))?;
        if current.phase != SourceAcquisitionPhaseV1::DescriptorCustodied
            || custody.acquisition_id != acquisition_id
            || custody.descriptor_commitment != evidence.descriptor_commitment
            || custody.custody_digest == [0; 32]
        {
            return Err(state_error("positive custody evidence differs"));
        }

        let mut next = current.clone();
        next.revision = next_revision(current.revision)?;
        next.phase = SourceAcquisitionPhaseV1::Active;
        next.positive_custody_digest = Some(custody.custody_digest);
        self.commit_lifecycle(journal, next, Vec::new())
    }

    /// Atomically consumes an Active acquisition with its exact source pin and Create admission.
    ///
    /// # Errors
    ///
    /// Returns an error for stale state, any acquisition/binding/realization
    /// mismatch, wrong companion namespaces, or journal failure.
    pub fn consume_active_source(
        &mut self,
        journal: &mut Journal,
        acquisition_id: [u8; 32],
        expected_revision: u64,
        expected_digest: [u8; 32],
        consumption: SourceConsumptionCommitV1,
    ) -> Result<CommittedSourceConsumptionV1> {
        let current = self.current_for_cas(acquisition_id, expected_revision, expected_digest)?;
        let evidence = current
            .evidence
            .as_ref()
            .ok_or_else(|| state_error("source consumption has no provider evidence"))?;
        let provider_head = self
            .provider_heads
            .get(&(
                current.provider.holder_authority_id,
                current.provider.provider_authority_id,
            ))
            .ok_or_else(|| state_error("source provider head is absent"))?;
        let reconciliation = reconcile_current_inventory(&self.acquisitions, provider_head)?;
        if current.phase != SourceAcquisitionPhaseV1::Active
            || reconciliation.as_ref().is_some_and(|reconciliation| {
                reconciliation.has_authority_conflicts || reconciliation.has_untracked_residuals
            })
            || consumption.acquisition_id != acquisition_id
            || consumption.source_realization_handle != evidence.source_realization_handle
            || consumption.source_binding_digest != current.source_binding_digest
            || consumption.provider_resource_digest != evidence.provider_resource_digest
            || consumption.projected_create_template_digest
                != current.prospective_mount_template_digest
            || project_final_create_semantics(&consumption.final_create_semantics)?
                != current.prospective_mount_template
            || consumption.source_pin_record.namespace() != RecordNamespace::MountSourcePin
            || consumption.create_effect_record.namespace() != RecordNamespace::Effect
            || consumption.create_operation_record.namespace() != RecordNamespace::Operation
        {
            return Err(state_error("source consumption evidence differs"));
        }

        let source_pin_record_digest = journal_record_digest(&consumption.source_pin_record);
        let create_effect_record_digest = journal_record_digest(&consumption.create_effect_record);
        let create_operation_record_digest =
            journal_record_digest(&consumption.create_operation_record);
        let companion_records = vec![
            consumption.source_pin_record,
            consumption.create_effect_record,
            consumption.create_operation_record,
        ];
        let committed_records = companion_records.clone();
        let mut next = current.clone();
        next.revision = next_revision(current.revision)?;
        next.phase = SourceAcquisitionPhaseV1::Consumed;
        next.consumed_source_pin_record_digest = Some(source_pin_record_digest);
        next.consumed_create_effect_record_digest = Some(create_effect_record_digest);
        next.consumed_create_operation_record_digest = Some(create_operation_record_digest);
        self.commit_lifecycle(journal, next, companion_records)?;
        Ok(CommittedSourceConsumptionV1 {
            records: committed_records,
        })
    }

    /// Records Released only after provider terminality and authoritative absence.
    ///
    /// # Errors
    ///
    /// Returns an error for stale state, missing provider terminal evidence,
    /// mismatched opaque manager evidence, or journal failure.
    pub fn finish_release(
        &mut self,
        journal: &mut Journal,
        acquisition_id: [u8; 32],
        expected_revision: u64,
        expected_digest: [u8; 32],
        custody: &NegativeCustodyCommitV1,
    ) -> Result<()> {
        let current = self.current_for_cas(acquisition_id, expected_revision, expected_digest)?;
        let evidence = current
            .evidence
            .as_ref()
            .ok_or_else(|| state_error("release has no provider evidence"))?;
        let provider_head = self
            .provider_heads
            .get(&(
                current.provider.holder_authority_id,
                current.provider.provider_authority_id,
            ))
            .ok_or_else(|| state_error("source provider head is absent"))?;
        let receipt_terminal = current
            .release_checkpoint
            .as_ref()
            .is_some_and(|checkpoint| {
                checkpoint.status == ProviderStatusV1::Complete
                    && current
                        .release_generation
                        .is_some_and(|generation| generation != 0)
            });
        let inventory_terminal = inventory_floor_proves_terminal_release(provider_head, current)?;
        if current.phase != SourceAcquisitionPhaseV1::Releasing
            || !(receipt_terminal || inventory_terminal)
            || custody.acquisition_id != acquisition_id
            || custody.descriptor_commitment != evidence.descriptor_commitment
            || custody.custody_digest == [0; 32]
        {
            return Err(state_error("release custody evidence differs"));
        }

        let mut next = current.clone();
        next.revision = next_revision(current.revision)?;
        next.phase = SourceAcquisitionPhaseV1::Released;
        if !receipt_terminal {
            next.provider_inventory_digest = provider_head.inventory_digest;
            next.provider_inventory_observation_ordinal =
                Some(provider_head.inventory_observation_ordinal);
        }
        next.negative_custody_digest = Some(custody.custody_digest);
        self.commit_lifecycle(journal, next, Vec::new())
    }

    /// Records a sanitized fault while retaining the exact preceding evidence.
    ///
    /// # Errors
    ///
    /// Returns an error for stale state, a sentinel fault, a terminal Released
    /// row, an existing fault, or journal failure.
    pub fn fault_acquisition(
        &mut self,
        journal: &mut Journal,
        acquisition_id: [u8; 32],
        expected_revision: u64,
        expected_digest: [u8; 32],
        fault_digest: [u8; 32],
    ) -> Result<()> {
        let current = self.current_for_cas(acquisition_id, expected_revision, expected_digest)?;
        let head = self
            .provider_heads
            .get(&(
                current.provider.holder_authority_id,
                current.provider.provider_authority_id,
            ))
            .ok_or_else(|| state_error("source provider head is absent"))?;
        let owns_outstanding_query = head.pending_query.as_ref().is_some_and(|pending| {
            matches!(
                pending.owner,
                ProviderQueryOwnerV1::Acquire {
                    acquisition_id: owner
                } | ProviderQueryOwnerV1::Release {
                    acquisition_id: owner
                } if owner == acquisition_id
            )
        });
        if matches!(
            current.phase,
            SourceAcquisitionPhaseV1::Releasing
                | SourceAcquisitionPhaseV1::Released
                | SourceAcquisitionPhaseV1::Faulted
        ) || fault_digest == [0; 32]
            || owns_outstanding_query
        {
            return Err(state_error("source acquisition fault edge is invalid"));
        }

        let mut next = current.clone();
        next.revision = next_revision(current.revision)?;
        next.phase = SourceAcquisitionPhaseV1::Faulted;
        next.faulted_from = Some(current.phase);
        next.fault_digest = Some(fault_digest);
        self.commit_lifecycle(journal, next, Vec::new())
    }

    fn current_for_cas(
        &self,
        acquisition_id: [u8; 32],
        expected_revision: u64,
        expected_digest: [u8; 32],
    ) -> Result<&SourceAcquisitionRowV1> {
        let current = self
            .acquisitions
            .get(&acquisition_id)
            .ok_or_else(|| state_error("source acquisition is absent"))?;
        if current.revision != expected_revision || current.record_digest != expected_digest {
            return Err(state_error("source acquisition compare-and-swap failed"));
        }
        Ok(current)
    }

    fn commit_lifecycle(
        &mut self,
        journal: &mut Journal,
        mut next: SourceAcquisitionRowV1,
        companion_records: Vec<JournalRecord>,
    ) -> Result<()> {
        next.record_digest = acquisition_record_digest(&next)?;
        next.validate()?;
        if companion_records
            .iter()
            .any(|record| record.namespace() == RecordNamespace::MountSourceAcquisition)
        {
            return Err(state_error(
                "lifecycle companion attempted a namespace-40 mutation",
            ));
        }

        let acquisition_id = next.acquisition_id;
        let mut records = Vec::with_capacity(companion_records.len() + 1);
        records.push(put_acquisition(&next)?);
        records.extend(companion_records);
        let transaction =
            JournalTransaction::new(transaction_id(acquisition_id, next.revision), records)?;
        journal.commit(&transaction)?;
        self.acquisitions.insert(acquisition_id, next);
        Ok(())
    }
}

fn journal_record_digest(record: &JournalRecord) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.mount.source-acquisition-companion.v1\0");
    digest.update((record.namespace() as u16).to_be_bytes());
    digest.update((record.key().len() as u64).to_be_bytes());
    digest.update(record.key());
    match record.value() {
        Some(value) => {
            digest.update([1]);
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value);
        }
        None => digest.update([0]),
    }
    digest.finalize().into()
}

pub(super) fn project_final_create_semantics(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut projected = Vec::with_capacity(bytes.len());
    let mut cursor = 0usize;
    for expected_tag in 1_u8..=27 {
        if bytes.get(cursor).copied() != Some(expected_tag) {
            return Err(state_error("final Create semantic tags are not exact"));
        }
        let length_bytes = bytes
            .get(cursor + 1..cursor + 5)
            .ok_or_else(|| state_error("final Create semantics are truncated"))?;
        let length =
            usize::try_from(u32::from_be_bytes(length_bytes.try_into().map_err(
                |_| state_error("final Create semantic length is malformed"),
            )?))
            .map_err(|_| state_error("final Create semantic length overflowed"))?;
        let start = cursor
            .checked_add(5)
            .ok_or_else(|| state_error("final Create semantic length overflowed"))?;
        let end = start
            .checked_add(length)
            .ok_or_else(|| state_error("final Create semantic length overflowed"))?;
        let value = bytes
            .get(start..end)
            .ok_or_else(|| state_error("final Create semantics are truncated"))?;
        projected.push(expected_tag);
        if expected_tag == 13 {
            if length != 32 || value.iter().all(|byte| *byte == 0) {
                return Err(state_error("final Create catalog commitment is invalid"));
            }
            projected.extend_from_slice(&0_u32.to_be_bytes());
        } else {
            projected.extend_from_slice(&(length as u32).to_be_bytes());
            projected.extend_from_slice(value);
        }
        cursor = end;
    }
    if cursor != bytes.len() {
        return Err(state_error("final Create semantics contain trailing bytes"));
    }
    Ok(projected)
}
