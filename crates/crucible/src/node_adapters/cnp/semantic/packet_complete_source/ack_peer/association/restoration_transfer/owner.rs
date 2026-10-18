//! Retains Source phase state and every independent normalized partial owner.
//!
//! The inline attempt is absent before private birth. Its containing bank owner
//! is already charged by the real Source header. No method here can issue a
//! claim, publish a request, verify native custody or construct a final context.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::{
    retained_values::{sum_with_error, value_storage_with_error},
    storage_error::StorageError,
};

pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer::association) struct OriginalSourceRestoreTransferAttempt
{
    prepare_id: Option<Id>,
    commit_id: Option<Id>,
    nonce: [u8; 32],
    generation: U64,
    prepare: SourceTransferPhase,
    commit: SourceTransferPhase,
    inputs_started: bool,
    inputs_verified: bool,
    failed: bool,
}

struct SourceTransferPhase {
    // Request, context, proof, full assigned original and actual receipt.
    normalized: [Option<serde_json::Value>; 5],
    started: bool,
    sealed: bool,
    publishing_started: bool,
    verified: bool,
}

impl SourceTransferPhase {
    fn empty() -> Self {
        Self {
            normalized: std::array::from_fn(|_| None),
            started: false,
            sealed: false,
            publishing_started: false,
            verified: false,
        }
    }

    fn retained_with_error<E: StorageError>(&self, maximum: usize) -> Result<usize, E> {
        let Self {
            normalized,
            started: _,
            sealed: _,
            publishing_started: _,
            verified: _,
        } = self;
        normalized.iter().flatten().try_fold(0usize, |sum, value| {
            sum_with_error::<E, _>(
                [sum, value_storage_with_error::<E>(value, 0, maximum)?],
                maximum,
            )
        })
    }
}

impl OriginalSourceRestoreTransferAttempt {
    fn begin(nonce: [u8; 32]) -> Self {
        Self {
            prepare_id: None,
            commit_id: None,
            nonce,
            // This is the first and only private attempt in this birth. The
            // containing Option cannot be cleared or replaced after failure.
            generation: U64::new(1),
            prepare: SourceTransferPhase::empty(),
            commit: SourceTransferPhase::empty(),
            inputs_started: false,
            inputs_verified: false,
            failed: false,
        }
    }

    pub(super) fn retained_with_error<E: StorageError>(&self, maximum: usize) -> Result<usize, E> {
        let Self {
            prepare_id,
            commit_id,
            nonce: _,
            generation: _,
            prepare,
            commit,
            inputs_started: _,
            inputs_verified: _,
            failed: _,
        } = self;
        sum_with_error::<E, _>(
            [
                prepare_id.as_ref().map_or(0, Id::allocated_capacity),
                commit_id.as_ref().map_or(0, Id::allocated_capacity),
                prepare.retained_with_error::<E>(maximum)?,
                commit.retained_with_error::<E>(maximum)?,
            ],
            maximum,
        )
    }
}

impl super::super::restore_transfer_banks::OriginalRestoreTransferBanks {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer::association) fn retained_signer_storage_with_error<
        E: StorageError,
    >(
        &self,
        maximum: usize,
    ) -> Result<usize, E> {
        self.signer
            .as_ref()
            .map_or(Ok(0), |signer| signer.retained_with_error::<E>(maximum))
    }
}

impl OriginalSourceRestoreTransferAttempt {
    pub(super) fn generation(&self) -> U64 {
        self.generation
    }

    pub(super) fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    pub(super) fn authenticate_ids(
        &self,
        prepare_id: &Id,
        commit_id: &Id,
    ) -> Result<(), RuntimeError> {
        if self.prepare_id.as_ref() != Some(prepare_id)
            || self.commit_id.as_ref() != Some(commit_id)
            || prepare_id == commit_id
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    fn phase(&self, phase: PacketCompleteRestoreTransferPhase) -> &SourceTransferPhase {
        match phase {
            PacketCompleteRestoreTransferPhase::Prepare => &self.prepare,
            PacketCompleteRestoreTransferPhase::Commit => &self.commit,
        }
    }

    fn phase_mut(&mut self, phase: PacketCompleteRestoreTransferPhase) -> &mut SourceTransferPhase {
        match phase {
            PacketCompleteRestoreTransferPhase::Prepare => &mut self.prepare,
            PacketCompleteRestoreTransferPhase::Commit => &mut self.commit,
        }
    }

    pub(super) fn value(
        &self,
        phase: PacketCompleteRestoreTransferPhase,
        index: usize,
    ) -> Result<&serde_json::Value, RuntimeError> {
        self.phase(phase)
            .normalized
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(RuntimeError::OwnerUnavailable)
    }

    pub(super) fn mark_sealed(
        &mut self,
        phase: PacketCompleteRestoreTransferPhase,
    ) -> Result<(), RuntimeError> {
        let state = self.phase_mut(phase);
        if !state.started || state.sealed || state.publishing_started {
            return Err(RuntimeError::OutstandingObligations);
        }
        state.sealed = true;
        Ok(())
    }

    pub(super) fn mark_publishing(
        &mut self,
        phase: PacketCompleteRestoreTransferPhase,
    ) -> Result<(), RuntimeError> {
        let state = self.phase_mut(phase);
        if !state.started || !state.sealed || state.publishing_started {
            return Err(RuntimeError::OutstandingObligations);
        }
        state.publishing_started = true;
        Ok(())
    }

    // Only the effect caller invokes this after actual keyed receipt and final
    // claim/kernel checks. A panic before then leaves failed=true permanently.
    pub(super) fn finish_verified(
        &mut self,
        phase: PacketCompleteRestoreTransferPhase,
    ) -> Result<(), RuntimeError> {
        let state = self.phase_mut(phase);
        if !state.publishing_started
            || state.verified
            || state.normalized.iter().any(Option::is_none)
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        state.verified = true;
        self.failed = false;
        Ok(())
    }

    pub(super) fn authenticate_prepare_verified(&self) -> Result<(), RuntimeError> {
        if self.failed || !self.prepare.verified || self.commit.started {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }
}

impl super::super::restore_transfer_banks::OriginalRestoreTransferBanks {
    pub(super) fn begin_original_prepare(
        &mut self,
        nonce: [u8; 32],
        prepare_id: &Id,
        commit_id: &Id,
    ) -> Result<(), RuntimeError> {
        if self.signer.is_some() || !self.mapping_attempted || !self.mapping_complete {
            return Err(RuntimeError::DuplicateOperation);
        }
        // Store before cloning IDs or validating the actual retained banks.
        // failed remains sticky until a completely verified phase finishes.
        let mut attempt = OriginalSourceRestoreTransferAttempt::begin(nonce);
        attempt.failed = true;
        attempt.prepare.started = true;
        self.signer = Some(attempt);
        let state = self.signer.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        state.prepare_id = Some(prepare_id.clone());
        state.commit_id = Some(commit_id.clone());
        state.authenticate_ids(prepare_id, commit_id)?;
        if self
            .prepare
            .iter()
            .chain(&self.commit)
            .any(|bank| !bank.is_empty())
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    pub(super) fn begin_original_commit(
        &mut self,
        prepare_id: &Id,
        commit_id: &Id,
    ) -> Result<(), RuntimeError> {
        let state = self.signer.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        state.authenticate_ids(prepare_id, commit_id)?;
        state.authenticate_inputs_verified()?;
        state.failed = true;
        state.commit.started = true;
        Ok(())
    }

    pub(super) fn signer(&self) -> Result<&OriginalSourceRestoreTransferAttempt, RuntimeError> {
        self.signer.as_ref().ok_or(RuntimeError::OwnerUnavailable)
    }

    pub(super) fn signer_mut(
        &mut self,
    ) -> Result<&mut OriginalSourceRestoreTransferAttempt, RuntimeError> {
        self.signer.as_mut().ok_or(RuntimeError::OwnerUnavailable)
    }

    pub(in super::super) fn bank(
        &self,
        phase: PacketCompleteRestoreTransferPhase,
        index: usize,
    ) -> Result<&[u8], RuntimeError> {
        match phase {
            PacketCompleteRestoreTransferPhase::Prepare => &self.prepare,
            PacketCompleteRestoreTransferPhase::Commit => &self.commit,
        }
        .get(index)
        .map(Vec::as_slice)
        .ok_or(RuntimeError::OwnerUnavailable)
    }

    pub(super) fn retain_value(
        &mut self,
        phase: PacketCompleteRestoreTransferPhase,
        index: usize,
        value: serde_json::Value,
        maximum: usize,
    ) -> Result<(), RuntimeError> {
        let state = self.signer_mut()?.phase_mut(phase);
        if !state.started || state.verified {
            return Err(RuntimeError::OutstandingObligations);
        }
        let slot = state
            .normalized
            .get_mut(index)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if slot.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        *slot = Some(value);
        // The owner is installed before the fallible canonical-bank operation.
        let state = self.signer.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let value = state.value(phase, index)?;
        let bank = match phase {
            PacketCompleteRestoreTransferPhase::Prepare => &mut self.prepare,
            PacketCompleteRestoreTransferPhase::Commit => &mut self.commit,
        }
        .get_mut(index)
        .ok_or(RuntimeError::ForeignAuthority)?;
        canonical::canonical_json_to_writer(
            value,
            &mut TransferBankWriter {
                bytes: bank,
                maximum,
            },
        )
        .map_err(|_| RuntimeError::ResourceLimit)
    }
}

impl OriginalSourceRestoreTransferAttempt {
    pub(super) fn begin_inputs(&mut self) -> Result<(), RuntimeError> {
        self.authenticate_prepare_verified()?;
        if self.inputs_started {
            return Err(RuntimeError::DuplicateOperation);
        }
        self.failed = true;
        self.inputs_started = true;
        Ok(())
    }

    pub(super) fn finish_inputs(&mut self) -> Result<(), RuntimeError> {
        if !self.failed || !self.inputs_started || self.inputs_verified || self.commit.started {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.inputs_verified = true;
        self.failed = false;
        Ok(())
    }

    pub(super) fn authenticate_inputs_verified(&self) -> Result<(), RuntimeError> {
        self.authenticate_prepare_verified()?;
        if !self.inputs_started || !self.inputs_verified {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    pub(super) fn authenticate_verified(
        &self,
        phase: SourceVerifiedPhase,
    ) -> Result<(), RuntimeError> {
        if self.failed {
            return Err(RuntimeError::OutstandingObligations);
        }
        match phase {
            SourceVerifiedPhase::Prepare => self.authenticate_prepare_verified(),
            SourceVerifiedPhase::Inputs => self.authenticate_inputs_verified(),
            SourceVerifiedPhase::Commit
                if self.prepare.verified && self.inputs_verified && self.commit.verified =>
            {
                Ok(())
            }
            SourceVerifiedPhase::Commit => Err(RuntimeError::OutstandingObligations),
        }
    }
}

pub(super) fn phase_counter_scratch_data() -> usize {
    size_of::<SourceTransferPhase>()
        + size_of::<TransferBankWriter<'static>>()
        + size_of::<std::io::Error>()
        + size_of::<std::io::ErrorKind>()
        + size_of::<std::io::Result<usize>>()
        + size_of::<Result<(), crucible_node_contract::ContractError>>()
        + size_of::<Result<&SourceTransferPhase, RuntimeError>>()
        + size_of::<Result<&mut SourceTransferPhase, RuntimeError>>()
        + size_of::<Result<&OriginalSourceRestoreTransferAttempt, RuntimeError>>()
        + size_of::<Result<&mut OriginalSourceRestoreTransferAttempt, RuntimeError>>()
        + size_of::<[Option<serde_json::Value>; 5]>()
        + size_of::<Result<&serde_json::Value, RuntimeError>>()
        + size_of::<Result<&[u8], RuntimeError>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reserved_data() -> OriginalAckPeerAssociation {
        let mut slot = None;
        OriginalAckPeerAssociation::reserve_into(8192, &mut slot).unwrap();
        let mut owner = slot.unwrap();
        owner.reserve_complete_restore_banks(8192).unwrap();
        owner.reserve_restore_transfer_phase_banks(8192).unwrap();
        owner
    }

    #[test]
    fn failed_source_comparison_retains_partial_tree_and_spent_ids_without_touching_legacy_banks() {
        let mut owner = reserved_data();
        let legacy = owner.restore.as_ref().unwrap().allocated_bytes().unwrap();
        let transfer = owner.restore_transfer_banks.as_mut().unwrap();
        let prepare = Id::new("planned/prepare").unwrap();
        let commit = Id::new("planned/commit").unwrap();
        // This is only the closed private bank-state fixture. It issues no
        // claim, real mapping, Source proof, SDK owner or native permission.
        transfer.mapping_attempted = true;
        transfer.mapping_complete = true;
        transfer
            .begin_original_prepare([3; 32], &prepare, &commit)
            .unwrap();
        let mut text = String::with_capacity(257);
        text.push_str("retained before encoding refuses");
        let capacity = text.capacity();
        let value = serde_json::Value::String(text);

        assert!(
            transfer
                .retain_value(PacketCompleteRestoreTransferPhase::Prepare, 0, value, 1)
                .is_err()
        );

        assert!(
            transfer
                .signer()
                .unwrap()
                .value(PacketCompleteRestoreTransferPhase::Prepare, 0)
                .is_ok()
        );
        assert!(
            transfer
                .retained_signer_storage_with_error::<RuntimeError>(usize::MAX)
                .unwrap()
                >= capacity + prepare.allocated_capacity() + commit.allocated_capacity()
        );
        assert!(
            transfer
                .signer()
                .unwrap()
                .authenticate_prepare_verified()
                .is_err()
        );
        assert!(
            transfer
                .begin_original_prepare([3; 32], &prepare, &commit)
                .is_err()
        );
        assert_eq!(
            owner.restore.as_ref().unwrap().allocated_bytes().unwrap(),
            legacy
        );
        owner
            .restore
            .as_ref()
            .unwrap()
            .authenticate_unpopulated_capture_metadata_with_error::<RuntimeError>()
            .unwrap();
    }

    #[test]
    fn source_attempt_cannot_skip_inputs_or_begin_commit_from_data_presence() {
        let mut owner = reserved_data();
        let transfer = owner.restore_transfer_banks.as_mut().unwrap();
        let prepare = Id::new("planned/prepare").unwrap();
        let commit = Id::new("planned/commit").unwrap();
        transfer.mapping_attempted = true;
        transfer.mapping_complete = true;
        transfer
            .begin_original_prepare([3; 32], &prepare, &commit)
            .unwrap();

        assert!(transfer.begin_original_commit(&prepare, &commit).is_err());
        assert!(transfer.signer_mut().unwrap().finish_inputs().is_err());
        assert!(
            transfer
                .signer()
                .unwrap()
                .authenticate_verified(SourceVerifiedPhase::Prepare)
                .is_err()
        );
        assert!(
            transfer
                .signer()
                .unwrap()
                .authenticate_verified(SourceVerifiedPhase::Inputs)
                .is_err()
        );
        assert!(
            transfer
                .signer()
                .unwrap()
                .authenticate_verified(SourceVerifiedPhase::Commit)
                .is_err()
        );
        assert!(
            transfer
                .signer_mut()
                .unwrap()
                .finish_verified(PacketCompleteRestoreTransferPhase::Prepare)
                .is_err()
        );
        assert!(
            transfer
                .signer()
                .unwrap()
                .value(PacketCompleteRestoreTransferPhase::Prepare, 0)
                .is_err()
        );
    }
}

// Only this newly selected path uses a raw bounded writer. The legacy eleven
// bank helper and its diagnostics remain untouched. ErrorKind keeps this
// typed ResourceLimit path from allocating an OperationFailure diagnostic.
struct TransferBankWriter<'a> {
    bytes: &'a mut Vec<u8>,
    maximum: usize,
}

impl std::io::Write for TransferBankWriter<'_> {
    fn write(&mut self, next: &[u8]) -> std::io::Result<usize> {
        self.bytes
            .len()
            .checked_add(next.len())
            .filter(|end| *end <= self.maximum && *end <= self.bytes.capacity())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::OutOfMemory))?;
        self.bytes.extend_from_slice(next);
        Ok(next.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Borrows every retained Source transfer phase as inert historical DATA.
pub(crate) struct SourceRestoreTransferHistoryData<'a> {
    original: &'a OriginalSourceRestoreTransferAttempt,
}

#[derive(serde::Serialize)]
struct SourceRestoreTransferPhaseHistoryData<'a> {
    normalized: &'a [Option<serde_json::Value>; 5],
    capacities: crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityRows<
        'a,
        [Option<serde_json::Value>],
    >,
    started: bool,
    sealed: bool,
    publishing_started: bool,
    verified: bool,
}

impl SourceTransferPhase {
    fn historical_data(&self) -> SourceRestoreTransferPhaseHistoryData<'_> {
        let Self {
            normalized,
            started,
            sealed,
            publishing_started,
            verified,
        } = self;
        SourceRestoreTransferPhaseHistoryData {
            normalized,
            capacities:
                crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityRows(
                    normalized.as_slice(),
                ),
            started: *started,
            sealed: *sealed,
            publishing_started: *publishing_started,
            verified: *verified,
        }
    }
}

impl OriginalSourceRestoreTransferAttempt {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn historical_data(
        &self,
    ) -> SourceRestoreTransferHistoryData<'_> {
        SourceRestoreTransferHistoryData { original: self }
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn historical_counter_scratch_data()
    -> usize {
        std::mem::size_of::<SourceRestoreTransferHistoryData<'static>>()
            + std::mem::size_of::<SourceRestoreTransferPhaseHistoryData<'static>>()
            + std::mem::size_of::<&OriginalSourceRestoreTransferAttempt>()
            + std::mem::size_of::<&SourceTransferPhase>()
            + crate::node_contract::restored_owner_history::original_restored_owner_capacity_counter_scratch_data()
    }
}

impl serde::Serialize for SourceRestoreTransferHistoryData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let OriginalSourceRestoreTransferAttempt {
            prepare_id,
            commit_id,
            nonce,
            generation,
            prepare,
            commit,
            inputs_started,
            inputs_verified,
            failed,
        } = self.original;
        let mut value = serializer.serialize_struct("SourceRestoreTransferHistory", 12)?;
        value.serialize_field("prepare_id", prepare_id)?;
        value.serialize_field(
            "prepare_id_capacities",
            &crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityRows(
                prepare_id,
            ),
        )?;
        value.serialize_field("commit_id", commit_id)?;
        value.serialize_field(
            "commit_id_capacities",
            &crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityRows(
                commit_id,
            ),
        )?;
        value.serialize_field("nonce", nonce)?;
        value.serialize_field("generation", generation)?;
        value.serialize_field("prepare", &prepare.historical_data())?;
        value.serialize_field("commit", &commit.historical_data())?;
        value.serialize_field("inputs_started", inputs_started)?;
        value.serialize_field("inputs_verified", inputs_verified)?;
        value.serialize_field("failed", failed)?;
        value.serialize_field("schema", "source-private.source-restore-transfer-history/1")?;
        value.end()
    }
}

impl super::super::restore_transfer_banks::OriginalRestoreTransferBanks {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer::association) fn settled17_once_data(
        &self,
    ) -> Result<super::super::settled17_once::TransferOnce17, RuntimeError> {
        use super::super::settled17_once::{TransferOnce17, TransferPhaseOnce17};
        let signer = self.signer.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let phase = |value: &SourceTransferPhase| TransferPhaseOnce17 {
            started: value.started,
            sealed: value.sealed,
            publishing_started: value.publishing_started,
            verified: value.verified,
        };
        Ok(TransferOnce17 {
            mapping_attempted: self.mapping_attempted,
            mapping_complete: self.mapping_complete,
            prepare: phase(&signer.prepare),
            commit: phase(&signer.commit),
            inputs_started: signer.inputs_started,
            inputs_verified: signer.inputs_verified,
            failed: signer.failed,
        })
    }
}
