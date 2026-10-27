//! Joins original derivation fields and known child geometry in one census.
//!
//! The Source association is checked before rows are written. Failed and empty
//! owning prefixes remain DATA. Opaque worker runtime and kernel resources still
//! require the same original deployment; this is not a complete Source footprint
//! or an Initial, Recipe or native execution grant.

use super::*;
use crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData;
use crucible_node_transport::retained_metadata::{
    RetainedProtocolMetadataFacts,
    records::{MetadataCapacityRecord, MetadataRecordKind, PacketRuntimeMetadataRecordBank},
};
use std::mem::size_of;

impl PacketCompleteSemanticSource {
    /// Observes original derivation fields and their known child capacities.
    ///
    /// The selected bound limits newly observed rows. A supplied physical bank
    /// keeps earlier components and every refused prefix. Actual shared views
    /// receive no alias discount. External runtime custody remains unresolved by
    /// these DATA and must retain the original deployment obligation.
    ///
    /// # Errors
    /// Refuses foreign creation/association, unavailable nested owners, exhausted
    /// rows, unready physical backing or checked geometry/work overflow.
    pub fn native_import18_derivation_known_capacity_data(
        &self,
        maximum_rows: usize,
        bank: Option<&mut PacketRuntimeMetadataRecordBank>,
    ) -> Result<RetainedProtocolMetadataFacts, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        if self.native_import18_derivation.is_some() {
            self.authenticate_isolated_derivation_storage_custody()?;
        }
        let mut census = OriginalOwnerCapacityMetadataData::new(maximum_rows, bank);
        census.observe_inline_data(&self.native_import18_derivation.is_some())?;
        if let Some(state) = &self.native_import18_derivation {
            state.record_known_capacity_data(&mut census)?;
        }
        self.storage_origin_with_error::<RuntimeError>()?;
        if self.native_import18_derivation.is_some() {
            self.authenticate_isolated_derivation_storage_custody()?;
        }
        Ok(census.finish())
    }
}

impl NativeImport18DerivationState {
    fn record_known_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            source,
            process,
            thread,
            attempt,
            private_launch,
            original_launch,
            registration,
            receipt,
            host_reference,
            private_seed,
            private_birth_started,
            source_bank,
            registration_bank,
            job,
            banks,
            stage,
        } = self;
        census.observe_inline_data(source)?;
        census.observe_inline_data(process)?;
        census.observe_inline_data(thread)?;
        census.observe_inline_data(receipt)?;
        census.observe_inline_data(host_reference)?;
        census.observe_inline_data(private_birth_started)?;
        census.observe_inline_data(stage)?;
        census.observe(private_launch)?;

        census.observe_inline_data(&attempt.is_some())?;
        if let Some(attempt) = attempt {
            let layout = attempt.retained_payload_layout_data();
            census.record(MetadataCapacityRecord {
                kind: MetadataRecordKind::Shared,
                extent: layout.size(),
                element_bytes: 1,
                alignment: layout.align(),
            })?;
        }
        census.observe_inline_data(&original_launch.is_some())?;
        if let Some(original) = original_launch {
            original.record_capacity_metadata_data(census)?;
        }
        census.observe_inline_data(&registration.is_some())?;
        if let Some(plan) = registration {
            super::super::metadata::record_registration_capacity_data(plan, census)?;
        }
        census.observe_inline_data(&private_seed.is_some())?;
        if let Some(seed) = private_seed {
            seed.record_retained_capacity_data(census)?;
        }
        census.observe(source_bank)?;
        census.observe(registration_bank)?;

        census.observe_inline_data(&job.is_some())?;
        if let Some(job) = job {
            census.observe_component_capacity_data(|remaining, bank| {
                job.known_capacity_data(remaining, bank)
            })?;
        }
        census.observe_inline_data(&banks.is_some())?;
        if let Some(ranges) = banks {
            for Range { start, end } in ranges {
                census.observe_inline_data(start)?;
                census.observe_inline_data(end)?;
            }
        }
        Ok(())
    }
}

/// Names the concrete field, child-loan and aggregate census controls.
pub(super) fn counter_scratch_data() -> usize {
    OriginalOwnerCapacityMetadataData::counter_scratch_data()
        + super::super::metadata::registration_field_counter_scratch_data()
        + size_of::<&PacketCompleteSemanticSource>()
        + size_of::<&NativeImport18DerivationState>()
        + size_of::<(
            &usize,
            &u32,
            &ThreadId,
            &Option<LinuxPureWorkerAttemptIdentity>,
            &Option<Id>,
            &Option<OriginalSourceBirthLaunch>,
            &Option<PacketCompleteAckHostRegistrationPlan>,
            &Option<RequestReceipt>,
            &Option<[u8; 32]>,
            &Option<birth::OriginalImport18PrivateSeed>,
            &bool,
            &Vec<u8>,
            &Vec<u8>,
            &Option<SourceBirthDerivationJob>,
            &Option<[Range<usize>; 2]>,
            &DerivationStage,
        )>()
        + size_of::<&LinuxPureWorkerAttemptIdentity>()
        + size_of::<std::alloc::Layout>()
        + size_of::<&SourceBirthDerivationJob>() * 2
        + size_of::<&[Range<usize>; 2]>()
        + size_of::<std::slice::Iter<'static, Range<usize>>>()
        + size_of::<(&usize, &usize)>()
        + size_of::<Option<&mut PacketRuntimeMetadataRecordBank>>()
        + size_of::<RetainedProtocolMetadataFacts>()
        + size_of::<Result<RetainedProtocolMetadataFacts, RuntimeError>>()
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<bool>() * 7
        + size_of::<usize>() * 2
}

#[cfg(test)]
#[path = "metadata/tests.rs"]
mod tests;
