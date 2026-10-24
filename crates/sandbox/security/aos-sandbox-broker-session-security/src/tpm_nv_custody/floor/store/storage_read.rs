//! Retains one selected Storage floor check on its original F ledger.
//!
//! Each read uses the sole canonical recipe. Its actual decoded model moves
//! into a private shared DATA owner, retained with every preceding read until
//! the enclosing native/semantic floor operation completes. Whole failure
//! never replaces the archive. Mutation helpers join their actual surviving
//! owners here; neither DATA archive supplies a readiness or mutation grant.

use std::error::Error;
use std::mem::size_of;
use std::sync::Arc;

use aos_sandbox_controller_domain::{Journal, JournalError, StorageReceivingClosedV1};
use aos_sandbox_controller_domain::journal::ProtectedJournalPreopenReplayExtentV1;
use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::floor_sidecar_geometry::FloorSidecarDecodeShapeV1;

use super::{BrokerFloorReadOriginalV1, BrokerSidecarStoreV1, FloorErrorV1,
    FloorProfileV1, StoredFloorDataV1};
use crate::recovery::StorageFloorFinancialSourceV2;

#[derive(Debug, thiserror::Error)]
pub(super) enum DemandError {
    #[error(transparent)]
    Native(#[from] JournalError),
    #[error(transparent)]
    Accounting(#[from] AccountingError),
    #[error("the actual retained Storage sidecar geometry cannot be represented")]
    Shape,
}

#[derive(Clone, Copy)]
enum First { Extent, Geometry, Funding, Body, Resident }

struct StorageFloorReadOriginalV2 {
    metadata: Option<std::io::Result<std::fs::Metadata>>,
    extent: Option<Result<ProtectedJournalPreopenReplayExtentV1, JournalError>>,
    shape: Option<FloorSidecarDecodeShapeV1>,
    demand: Option<Result<ResourceVector, DemandError>>,
    funding: Option<Result<(), StorageReceivingClosedV1>>,
    reader: BrokerFloorReadOriginalV1,
    model: Option<Arc<StoredFloorDataV1>>,
    body: Option<Result<(), FloorErrorV1>>,
    resident: Option<Result<ResourceVector, DemandError>>,
    first: Option<First>,
}

impl StorageFloorReadOriginalV2 {
    fn new() -> Self {
        Self { metadata: None, extent: None, shape: None, demand: None,
            funding: None, reader: BrokerFloorReadOriginalV1::new(), model: None,
            body: None, resident: None, first: None }
    }

    fn fixed_demand() -> Result<ResourceVector, AccountingError> {
        let bytes = size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(size_of::<StoredFloorDataV1>()))
            .and_then(|bytes| bytes.checked_add(size_of::<usize>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(std::mem::align_of::<StoredFloorDataV1>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }

    fn prefix_demand(&mut self, fixed: ResourceVector,
        main_limits: aos_sandbox_controller_domain::JournalLimits) -> Result<ResourceVector, DemandError>
    {
        let extent = self.extent.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(DemandError::Shape)?;
        let shape = BrokerFloorReadOriginalV1::receiving_shape_v1(main_limits, extent)
            .ok_or(DemandError::Shape)?;
        self.shape = Some(shape);
        let memory = shape.inline_bytes.checked_add(shape.heap_bytes)
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(DemandError::Shape)?;
        let files = u64::try_from(shape.open_files).map_err(|_| DemandError::Shape)?;
        let names = u64::try_from(shape.named_entries).map_err(|_| DemandError::Shape)?;
        let typed = ResourceVector::ZERO.with(D::MemoryBytes, memory)
            .with(D::OpenFiles, files).with(D::MetadataEntries, names);
        Ok(fixed.checked_add(extent.dominant_native_receiving_demand_v1()?)?
            .checked_add(extent.dominant_semantic_receiving_demand_v1()?)?
            .checked_add(typed)?)
    }

    fn resident_demand(&self) -> Result<ResourceVector, DemandError> {
        let model = self.model.as_ref().ok_or(DemandError::Shape)?;
        let transaction = model.prepared.as_ref().map(|(_, transaction)| transaction);
        let transaction_bytes = match transaction {
            Some(transaction) => transaction.retained_receiving_bytes_v2()
                .and_then(|bytes| bytes.checked_sub(size_of::<aos_sandbox_controller_domain::JournalTransaction>()))
                .ok_or(DemandError::Shape)?,
            None => 0,
        };
        let bytes = size_of::<Self>().checked_add(size_of::<StoredFloorDataV1>())
            .and_then(|bytes| bytes.checked_add(size_of::<usize>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(std::mem::align_of::<StoredFloorDataV1>()))
            .and_then(|bytes| bytes.checked_add(transaction_bytes))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(DemandError::Shape)?;
        let names = transaction.map_or(0, |transaction| transaction.records().len());
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes)
            .with(D::MetadataEntries, u64::try_from(names).map_err(|_| DemandError::Shape)?))
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Extent => self.metadata.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static))
                .or_else(|| self.extent.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Geometry => self.demand.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Funding => self.funding.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Body => self.reader.failure()
                .or_else(|| self.body.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Resident => self.resident.as_ref()?.as_ref().err().map(|cause| cause as _),
        }
    }
}

pub(super) struct StorageFloorReadProgrammeOriginalV2 {
    reads: Vec<Box<StorageFloorReadOriginalV2>>,
    retained: ResourceVector,
    archive_demand: Option<Result<ResourceVector, DemandError>>,
    archive_funding: Option<Result<(), StorageReceivingClosedV1>>,
    allocation: Option<Result<(), std::collections::TryReserveError>>,
    result: Option<Result<(), FloorErrorV1>>,
    pub(super) mutations: Vec<Box<super::storage_mutation::StorageFloorMutationOriginalV2>>,
    mutation_retained: ResourceVector,
    mutation_active: ResourceVector,
    mutation_fixed: Option<Result<ResourceVector, AccountingError>>,
    mutation_demand: Option<Result<ResourceVector, DemandError>>,
    mutation_funding: Option<Result<(), StorageReceivingClosedV1>>,
    mutation_allocation: Option<Result<(), std::collections::TryReserveError>>,
    mutation_retention: Option<Result<ResourceVector, DemandError>>,
}

impl StorageFloorReadProgrammeOriginalV2 {
    fn new() -> Self {
        Self { reads: Vec::new(), retained: ResourceVector::ZERO,
            archive_demand: None, archive_funding: None, allocation: None, result: None,
            mutations: Vec::new(), mutation_retained: ResourceVector::ZERO,
            mutation_active: ResourceVector::ZERO, mutation_fixed: None, mutation_demand: None,
            mutation_funding: None, mutation_allocation: None, mutation_retention: None }
    }

    fn fixed_demand() -> Result<ResourceVector, AccountingError> {
        let bytes = size_of::<Self>().checked_mul(2)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }

    fn next_archive_demand(&self) -> Result<ResourceVector, DemandError> {
        // reserve_exact may overlap the old allocation and the requested new
        // one. These are actual archive slots, never a Rust-field name quota.
        let next = self.reads.len().checked_add(1).ok_or(DemandError::Shape)?;
        let slots = self.reads.capacity().checked_add(next).ok_or(DemandError::Shape)?;
        let bytes = slots.checked_mul(size_of::<Box<StorageFloorReadOriginalV2>>())
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(DemandError::Shape)?;
        Ok(Self::fixed_demand()?.checked_add(self.retained)?
            .checked_add(self.mutation_retained)?
            .checked_add(self.mutation_active)?
            .checked_add(self.mutation_archive_demand_v2(0)?)?
            .checked_add(StorageFloorReadOriginalV2::fixed_demand()?)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))?)
    }

    fn is_positive(&self) -> bool {
        matches!(self.result, Some(Ok(()))) && self.failure().is_none()
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.archive_demand.as_ref().and_then(|value| value.as_ref().err())
            .map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| self.archive_funding.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.allocation.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.mutation_fixed.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.mutation_demand.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.mutation_funding.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.mutation_allocation.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.reads.iter().find_map(|read| read.failure()))
            .or_else(|| self.mutations.iter().find_map(|mutation| mutation.failure()))
            .or_else(|| self.mutation_retention.as_ref()?.as_ref().err().map(|cause| cause as _))
    }

    fn mutation_archive_demand_v2(&self, additional: usize) -> Result<ResourceVector, DemandError> {
        let next = self.mutations.len().checked_add(additional).ok_or(DemandError::Shape)?;
        let slots = if additional == 0 { self.mutations.capacity() }
            else { self.mutations.capacity().checked_add(next).ok_or(DemandError::Shape)? };
        let bytes = slots.checked_mul(size_of::<Box<super::storage_mutation::StorageFloorMutationOriginalV2>>())
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(DemandError::Shape)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }

    pub(super) fn mutation_complete_demand_v2(&self, required: ResourceVector)
        -> Result<ResourceVector, DemandError>
    {
        let read_slots = self.reads.capacity().checked_mul(size_of::<Box<StorageFloorReadOriginalV2>>())
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(DemandError::Shape)?;
        Ok(Self::fixed_demand()?.checked_add(self.retained)?
            .checked_add(self.mutation_retained)?.checked_add(required)?
            .checked_add(self.mutation_archive_demand_v2(1)?)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, read_slots))?)
    }

    pub(super) fn admit_mutation_v2(&mut self, required: ResourceVector,
        main: &Journal, sidecar: &Journal, receiving: &mut dyn StorageFloorFinancialSourceV2)
        -> Result<(), FloorErrorV1>
    {
        if self.result.is_some() || self.failure().is_some() {
            return Err(FloorErrorV1::Unavailable);
        }
        let required = self.mutation_active.componentwise_max(required);
        self.mutation_demand = Some(self.mutation_complete_demand_v2(required));
        let complete = self.mutation_demand.as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or(FloorErrorV1::Encoding)?;
        self.mutation_funding = Some(receiving.reserve_sidecar_v2(main, sidecar, complete));
        if !matches!(self.mutation_funding, Some(Ok(()))) {
            return Err(FloorErrorV1::Unavailable);
        }
        self.mutation_active = required;
        Ok(())
    }

    pub(super) fn retain_mutation_fixed_v2(&mut self, fixed: Result<ResourceVector, AccountingError>)
        -> Result<ResourceVector, FloorErrorV1>
    {
        if self.failure().is_some() || self.result.is_some() {
            return Err(FloorErrorV1::Unavailable);
        }
        self.mutation_fixed = Some(fixed);
        self.mutation_fixed.as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or(FloorErrorV1::Encoding)
    }

    pub(super) fn reserve_mutation_archive_v2(&mut self) -> Result<(), FloorErrorV1> {
        self.mutation_allocation = Some(self.mutations.try_reserve_exact(1));
        if matches!(self.mutation_allocation, Some(Ok(()))) { Ok(()) }
        else { Err(FloorErrorV1::Unavailable) }
    }

    pub(super) fn retain_mutation_v2(&mut self,
        original: Box<super::storage_mutation::StorageFloorMutationOriginalV2>)
        -> Result<(), FloorErrorV1>
    {
        // The admitted complete equation already checked this addition. Keep
        // the owner before projecting any later bookkeeping refusal.
        self.mutations.push(original);
        let retained = self.mutation_retained.checked_add(self.mutation_active);
        self.mutation_retention = Some(retained.map_err(DemandError::from));
        let retained = self.mutation_retention.as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or(FloorErrorV1::Encoding)?;
        self.mutation_retained = retained;
        self.mutation_active = ResourceVector::ZERO;
        Ok(())
    }
}

impl BrokerSidecarStoreV1 {
    /// Borrows the active retained programme and its real captured writer.
    ///
    /// # Errors
    /// Refuses missing captured custody, an absent/finished programme or any
    /// prior original refusal. The existing owner remains unchanged on error.
    pub(crate) fn require_storage_floor_programme_v3(&self) -> Result<(), FloorErrorV1> {
        let programme = self.selected_read.as_ref().ok_or(FloorErrorV1::Unavailable)?;
        if !self.custody.journal().has_captured_append_custody_v1()
            || programme.result.is_some() || programme.failure().is_some()
        {
            return Err(FloorErrorV1::Unavailable);
        }
        Ok(())
    }

    pub(crate) fn begin_storage_read_programme_v2(&mut self, main: &Journal,
        receiving: &mut dyn StorageFloorFinancialSourceV2) -> Result<(), FloorErrorV1>
    {
        if self.storage_read_failure_v2().is_some()
            || self.selected_read.as_ref().is_some_and(|original| !original.is_positive())
        {
            return Err(FloorErrorV1::Unavailable);
        }
        // Only the enclosing complete native/semantic Result permits physical
        // retirement. Every intermediate read/model survives a later failure.
        self.selected_read = None;
        self.selected_read_fixed = Some(StorageFloorReadProgrammeOriginalV2::fixed_demand());
        let fixed = self.selected_read_fixed.as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or(FloorErrorV1::Encoding)?;
        self.selected_read_preparation = Some(receiving.reserve_sidecar_v2(
            main, self.custody.journal(), fixed,
        ));
        if !matches!(self.selected_read_preparation, Some(Ok(()))) {
            return Err(FloorErrorV1::Unavailable);
        }
        self.selected_read = Some(Box::new(StorageFloorReadProgrammeOriginalV2::new()));
        Ok(())
    }

    pub(crate) fn finish_storage_read_programme_v2<T>(&mut self, result: Result<T, FloorErrorV1>)
        -> Result<T, FloorErrorV1>
    {
        let programme = self.selected_read.as_mut().ok_or(FloorErrorV1::Unavailable)?;
        if programme.result.is_some() { return Err(FloorErrorV1::Unavailable); }
        programme.result = Some(result.as_ref().map(|_| ()).map_err(|cause| *cause));
        if result.is_ok() && programme.failure().is_some() {
            return Err(FloorErrorV1::Unavailable);
        }
        result
    }

    pub(crate) fn read_storage_receiving_v2(&mut self, main: &Journal,
        receiving: &mut dyn StorageFloorFinancialSourceV2, profile: FloorProfileV1)
        -> Result<Arc<StoredFloorDataV1>, FloorErrorV1>
    {
        if self.storage_read_failure_v2().is_some() { return Err(FloorErrorV1::Unavailable); }
        let programme = self.selected_read.as_mut().ok_or(FloorErrorV1::Unavailable)?;
        if programme.result.is_some() { return Err(FloorErrorV1::Unavailable); }
        programme.archive_demand = Some(programme.next_archive_demand());
        let fixed = match programme.archive_demand.as_ref() {
            Some(Ok(demand)) => *demand,
            _ => return Err(FloorErrorV1::Encoding),
        };
        programme.archive_funding = Some(receiving.reserve_sidecar_v2(
            main, self.custody.journal(), fixed,
        ));
        if !matches!(programme.archive_funding, Some(Ok(()))) {
            return Err(FloorErrorV1::Unavailable);
        }
        programme.allocation = Some(programme.reads.try_reserve_exact(1));
        if !matches!(programme.allocation, Some(Ok(()))) { return Err(FloorErrorV1::Unavailable); }
        programme.reads.push(Box::new(StorageFloorReadOriginalV2::new()));
        let original = programme.reads.last_mut().ok_or(FloorErrorV1::Unavailable)?;
        original.extent = Some(self.custody.journal()
            .held_session_receiving_extent_v1(&mut original.metadata));
        if !matches!(original.extent, Some(Ok(_))) {
            original.first = Some(First::Extent);
            return Err(FloorErrorV1::Unavailable);
        }
        original.demand = Some(original.prefix_demand(fixed, self.main_limits));
        let complete = match original.demand.as_ref() {
            Some(Ok(complete)) => *complete,
            _ => {
                original.first = Some(First::Geometry);
                return Err(FloorErrorV1::Encoding);
            }
        };
        original.funding = Some(receiving.reserve_sidecar_v2(
            main, self.custody.journal(), complete,
        ));
        if !matches!(original.funding, Some(Ok(()))) {
            original.first = Some(First::Funding);
            return Err(FloorErrorV1::Unavailable);
        }
        original.body = Some(original.reader.observe_parts_once_v2(
            &mut self.custody, self.main_limits, profile,
        ));
        if !matches!(original.body, Some(Ok(()))) {
            original.first = Some(First::Body);
            return match original.body.as_ref() {
                Some(Err(cause)) => Err(*cause),
                _ => Err(FloorErrorV1::Unavailable),
            };
        }
        let model = match original.reader.take_positive_model_and_retire_raw_v2() {
            Some(model) => model,
            None => {
                original.body = Some(Err(FloorErrorV1::Unavailable));
                original.first = Some(First::Body);
                return Err(FloorErrorV1::Unavailable);
            }
        };
        // This one move retains the sole decoder's actual model. Arc clones
        // below share that DATA; they create no native or currentness proof.
        original.model = Some(Arc::new(model));
        original.resident = Some(original.resident_demand()
            .and_then(|resident| programme.retained.checked_add(resident).map_err(DemandError::from)));
        match original.resident.as_ref() {
            Some(Ok(retained)) => programme.retained = *retained,
            _ => {
                original.first = Some(First::Resident);
                return Err(FloorErrorV1::Encoding);
            }
        }
        original.model.as_ref().map(Arc::clone).ok_or(FloorErrorV1::Unavailable)
    }

    pub(crate) fn storage_read_failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.selected_read_fixed.as_ref().and_then(|value| value.as_ref().err())
            .map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| self.selected_read_preparation.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.selected_read.as_ref()?.failure())
    }
}

#[cfg(test)]
mod mutation_custody_tests {
    use super::*;

    #[test]
    fn parking_a_mutation_does_not_replace_its_rejected_geometry_result() {
        let mut programme = StorageFloorReadProgrammeOriginalV2::new();
        programme.mutation_demand = Some(Err(DemandError::Shape));
        let first = programme.failure().unwrap() as *const dyn Error;
        let original = Box::new(super::super::storage_mutation::StorageFloorMutationOriginalV2::new());

        programme.retain_mutation_v2(original).unwrap();

        assert!(std::ptr::eq(first, programme.failure().unwrap()));
        assert!(matches!(programme.failure().unwrap().downcast_ref::<DemandError>(),
            Some(DemandError::Shape)));
        assert_eq!(programme.mutations.len(), 1);
        assert!(!programme.is_positive());
    }
}
