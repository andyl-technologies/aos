//! Preserves typed capacity geometry for every initialized Source18 phase bank.
//!
//! Inline headers belong to the actual Box and owner-vector allocations. SDK
//! field walks retain their own origin guards. Literal banks use flat capacity
//! walks, so these facts do not measure whole-Source scalar traversal work.

use super::super::retained_values::edition18_tokens::LiteralToken18;
use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::storage_error::StorageError;
use crate::node_contract::restored_owner_history::{
    OriginalOwnerCapacityMetadataData, merge_capacity_metadata_data,
};
use crucible_node_transport::reference_packet::service::complete_restore::import18::bootstrap_ack::PacketNativeImport18BootstrapRetainedData as BootstrapDto;
use crucible_node_transport::{
    client::NativeImport18SourceMetadataData,
    retained_metadata::{
        RetainedProtocolMetadataFacts,
        records::{MetadataCapacityRecord, MetadataRecordKind, PacketRuntimeMetadataRecordBank},
    },
};
use std::mem::align_of;

impl PacketCompleteSemanticSource {
    /// Reports actual phase-bank geometry and optionally appends physical rows.
    ///
    /// Callers first admit the fixed census controls and the actual SDK dynamic
    /// controls from [`Self::native_import18_phase_bank_metadata_counter_data`].
    /// The admitted physical bank retains earlier rows on either outcome. This
    /// component grants no phase action and certifies no complete Source history.
    /// Its capacity-only literal walk supplies no scalar-work restriction.
    ///
    /// # Errors
    /// Refuses foreign Source or SDK origin, a busy Source bank, invalid layout,
    /// checked overflow, traversal exhaustion or unready/exhausted physical rows.
    pub fn native_import18_phase_bank_capacity_data(
        &self,
        bank: Option<&mut PacketRuntimeMetadataRecordBank>,
    ) -> Result<RetainedProtocolMetadataFacts, RuntimeError> {
        self.native_import18_phase_bank_capacity_with_error::<RuntimeError>(bank)
    }

    pub(super) fn native_import18_phase_bank_capacity_with_error<E: StorageError>(
        &self,
        bank: Option<&mut PacketRuntimeMetadataRecordBank>,
    ) -> Result<RetainedProtocolMetadataFacts, E> {
        self.storage_origin_with_error::<E>()?;
        let slot = self
            .native_import18_phase_bank
            .try_borrow()
            .map_err(|_| E::refused("Source18 phase bank already borrowed"))?;
        let facts = match slot.as_ref() {
            Some(owner) => owner.capacity_facts_data(bank).map_err(E::runtime)?,
            None => RetainedProtocolMetadataFacts::default(),
        };
        self.storage_origin_with_error::<E>()?;
        Ok(facts)
    }
}

impl NativeImport18SourcePhaseBank {
    /// Shares the actual census with the constructor's exclusive Source loan.
    ///
    /// # Errors
    /// Refuses foreign SDK origin, invalid geometry or exhausted requested bytes.
    /// The enclosing constructor retains its failed occurrence on every error.
    pub(super) fn retained_backing_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let facts = self.capacity_facts_data(None)?;
        PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
            &facts, maximum,
        )
    }

    fn capacity_facts_data(
        &self,
        bank: Option<&mut PacketRuntimeMetadataRecordBank>,
    ) -> Result<RetainedProtocolMetadataFacts, RuntimeError> {
        let mut census = PhaseCapacityCensus::new(bank);
        census.observe_bank(self)?;
        Ok(census.facts)
    }
}

/// Accumulates independent geometry while lending the same physical bank.
struct PhaseCapacityCensus<'a> {
    facts: RetainedProtocolMetadataFacts,
    bank: Option<&'a mut PacketRuntimeMetadataRecordBank>,
}

impl<'a> PhaseCapacityCensus<'a> {
    fn new(bank: Option<&'a mut PacketRuntimeMetadataRecordBank>) -> Self {
        Self {
            facts: Default::default(),
            bank,
        }
    }

    fn sdk(&mut self, owner: NativeImport18SourceMetadataData<'_>) -> Result<(), RuntimeError> {
        let facts = match self.bank.as_deref_mut() {
            Some(bank) => owner.record_retained_metadata_data(bank),
            None => owner.retained_metadata_data(),
        }
        .map_err(|_| RuntimeError::ResourceLimit)?;
        merge_capacity_metadata_data(&mut self.facts, &facts)
    }

    fn record(&mut self, record: MetadataCapacityRecord) -> Result<(), RuntimeError> {
        let maximum = self
            .bank
            .as_ref()
            .map_or(usize::MAX, |bank| bank.maximum_rows());
        let mut common = OriginalOwnerCapacityMetadataData::new(maximum, self.bank.as_deref_mut());
        common.record(record)?;
        merge_capacity_metadata_data(&mut self.facts, &common.finish())
    }

    fn vector<T>(&mut self, values: &Vec<T>) -> Result<(), RuntimeError> {
        self.record(MetadataCapacityRecord {
            kind: MetadataRecordKind::Vector,
            extent: values.capacity(),
            element_bytes: size_of::<T>(),
            alignment: align_of::<T>(),
        })
    }

    fn literal(
        &mut self,
        attempt: Option<&LiteralValue18TokenAttempt>,
        literal: Option<&LiteralValue18Data>,
    ) -> Result<(), RuntimeError> {
        let maximum = self
            .bank
            .as_ref()
            .map_or(usize::MAX, |bank| bank.maximum_rows());
        let mut common = OriginalOwnerCapacityMetadataData::new(maximum, self.bank.as_deref_mut());
        if let Some(attempt) = attempt {
            attempt.record_backing_capacity_data(&mut common)?;
        }
        if let Some(literal) = literal {
            literal.record_backing_capacity_data(&mut common)?;
        }
        merge_capacity_metadata_data(&mut self.facts, &common.finish())
    }

    fn observe_bank(&mut self, bank: &NativeImport18SourcePhaseBank) -> Result<(), RuntimeError> {
        let NativeImport18SourcePhaseBank {
            row: _,
            started: _,
            retained: _,
            failed: _,
            owners,
        } = bank;
        self.record(MetadataCapacityRecord {
            kind: MetadataRecordKind::Boxed,
            extent: size_of::<NativeImport18SourcePhaseBank>(),
            element_bytes: 1,
            alignment: align_of::<NativeImport18SourcePhaseBank>(),
        })?;
        self.vector(owners)?;
        for owner in owners {
            self.observe_owner(owner)?;
        }
        Ok(())
    }

    fn observe_owner(
        &mut self,
        owner: &NativeImport18SourcePhaseOwner,
    ) -> Result<(), RuntimeError> {
        let NativeImport18SourcePhaseOwner {
            process: _,
            thread: _,
            source: _,
            recipe: _,
            initial: _,
            retention: _,
            bootstrap,
            prepare,
            commit,
            prepare_request,
            commit_request,
            binding,
            sdk_rows,
            prepare_capsule,
            input_upload_started: _,
            input_upload_verified: _,
            failed: _,
        } = owner;
        self.bootstrap(bootstrap)?;
        self.phase(prepare)?;
        self.phase(commit)?;
        self.sdk(NativeImport18SourceMetadataData::SourceInputs {
            request_id: None,
            baseline: None,
            prepare: prepare_request.as_ref(),
            commit: commit_request.as_ref(),
            binding: binding.as_ref(),
        })?;
        for row in sdk_rows.iter().flatten() {
            self.sdk(NativeImport18SourceMetadataData::AssignmentStorage(row))?;
        }
        if let Some(sdk) = prepare_capsule {
            self.sdk(NativeImport18SourceMetadataData::Assignment(sdk))?;
        }
        Ok(())
    }

    fn bootstrap(&mut self, partial: &BootstrapPartials) -> Result<(), RuntimeError> {
        let BootstrapPartials {
            sdk_row,
            sdk_owner,
            started: _,
            assigned: _,
            publishing: _,
            failed: _,
            request_id,
            request,
            context,
            proof,
            result,
            receipt,
            literal_attempt,
            literal,
            encoded,
        } = partial;
        if let Some(row) = sdk_row {
            self.sdk(NativeImport18SourceMetadataData::BootstrapConstruction(row))?;
        }
        if let Some(owner) = sdk_owner {
            self.sdk(NativeImport18SourceMetadataData::Bootstrap(owner))?;
        }
        self.vector(encoded)?;
        self.literal(literal_attempt.as_ref(), literal.as_ref())?;
        self.sdk(NativeImport18SourceMetadataData::SourceInputs {
            request_id: request_id.as_ref(),
            baseline: None,
            prepare: None,
            commit: None,
            binding: None,
        })?;
        for field in [
            request.as_ref().map(BootstrapDto::Request),
            result.as_ref().map(BootstrapDto::Result),
            context.as_ref().map(BootstrapDto::Context),
            proof.as_ref().map(BootstrapDto::Proof),
            receipt.as_ref().map(BootstrapDto::Receipt),
        ]
        .into_iter()
        .flatten()
        {
            self.sdk(NativeImport18SourceMetadataData::BootstrapDto(field))?;
        }
        Ok(())
    }

    fn phase(&mut self, partial: &PhasePartials) -> Result<(), RuntimeError> {
        let PhasePartials {
            request_id,
            baseline,
            normalized,
            started: _,
            assigned: _,
            sealed: _,
            publishing: _,
            verified: _,
            failed: _,
        } = partial;
        self.sdk(NativeImport18SourceMetadataData::SourceInputs {
            request_id: request_id.as_ref(),
            baseline: baseline.as_ref(),
            prepare: None,
            commit: None,
            binding: None,
        })?;
        for LiteralPartial {
            attempt,
            literal,
            encoded,
        } in normalized
        {
            self.vector(encoded)?;
            self.literal(attempt.as_ref(), literal.as_ref())?;
        }
        Ok(())
    }
}

pub(super) fn counter_scratch_data() -> usize {
    NativeImport18SourceMetadataData::counter_scratch_data()
        + OriginalOwnerCapacityMetadataData::counter_scratch_data()
        + size_of::<PhaseCapacityCensus<'static>>()
        + size_of::<&mut PhaseCapacityCensus<'static>>()
        + size_of::<Option<&mut PacketRuntimeMetadataRecordBank>>()
        + size_of::<&Vec<NativeImport18SourcePhaseOwner>>()
        + size_of::<&Vec<u8>>()
        + size_of::<&Vec<Vec<LiteralToken18>>>()
        + size_of::<&Vec<usize>>()
        + size_of::<&String>()
        + size_of::<&mut OriginalOwnerCapacityMetadataData<'static>>()
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<MetadataCapacityRecord>()
        + size_of::<usize>()
}

#[cfg(test)]
#[path = "metadata/tests.rs"]
mod tests;
