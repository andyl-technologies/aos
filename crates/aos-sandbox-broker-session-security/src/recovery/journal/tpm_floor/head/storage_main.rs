//! Holds actual main HEAD models and native observations on the original F.
//!
//! The canonical Journal already owns its recovered state and cursor. This
//! adapter borrows those records and uses the existing schema, snapshot,
//! advisory preflight and hash engines. It creates no replay parser or writer.

use super::*;
use std::error::Error;
use std::mem::size_of;

use aos_sandbox::{JournalError, ProtectedJournalCurrentnessOriginalsV1,
    ProtectedJournalPreflight, ProtectedJournalSnapshot, StorageReceivingClosedV1};
use aos_sandbox::journal::{ProtectedJournalPreflightOriginalV2, ProtectedJournalPreopenReplayExtentV1};
use aos_sandbox_core::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::capacity_family::family::CanonicalCapacityReadCaptureV1;

use crate::endpoint::RetainedEndpointRevalidationOriginalV1;
use crate::recovery::journal::{ProtectedBrokerSessionJournalV1, StorageFloorSchemaOriginalV3};
use crate::tpm_nv_custody::{FloorHeadCutOriginalV3, FloorHeadTransactionOriginalV3};
use super::super::storage_receiving::StorageFloorFinancialSourceV2;

#[derive(Debug, thiserror::Error)]
pub(super) enum DemandError {
    #[error(transparent)]
    Native(#[from] JournalError),
    #[error(transparent)]
    Accounting(#[from] AccountingError),
    #[error(transparent)]
    Schema(#[from] BrokerSessionSecurityError),
    #[error("the actual main floor representation cannot be represented")]
    Shape,
}

#[cfg(test)]
mod programme_tests {
    use super::*;

    fn retained_action() -> Box<StorageFloorMainOriginalV3> {
        let mut action = Box::new(StorageFloorMainOriginalV3::new());
        action.records.insert(b"actual-key".to_vec(), b"actual-value".to_vec());
        action
    }

    #[test]
    fn a_failed_main_body_keeps_its_first_cause_and_model_after_later_begin() {
        let mut archive = StorageFloorMainArchiveV3::new();
        archive.begin().unwrap();
        let mut action = retained_action();
        action.body = Some(Err(BrokerSessionSecurityError::Currentness));
        archive.park(action, ResourceVector::ZERO).unwrap();
        archive.result = Some(Err(FloorErrorV1::Unavailable));
        let original = archive.actions[0].records.get(b"actual-key".as_slice()).unwrap().as_ptr();
        let cause = archive.failure().unwrap() as *const dyn Error;

        assert!(archive.begin().is_err());
        assert!(archive.begin().is_err());

        assert_eq!(archive.actions.len(), 1);
        assert_eq!(archive.actions[0].records.get(b"actual-key".as_slice()).unwrap().as_ptr(), original);
        assert!(std::ptr::eq(cause, archive.failure().unwrap() as *const dyn Error));
    }

    #[test]
    fn a_later_enclosing_failure_keeps_the_earlier_positive_model() {
        let mut archive = StorageFloorMainArchiveV3::new();
        archive.begin().unwrap();
        archive.park(retained_action(), ResourceVector::ZERO).unwrap();
        archive.result = Some(Err(FloorErrorV1::Diverged));
        let original = archive.actions[0].records.get(b"actual-key".as_slice()).unwrap().as_ptr();

        assert!(archive.begin().is_err());

        assert_eq!(archive.actions.len(), 1);
        assert_eq!(archive.actions[0].records.get(b"actual-key".as_slice()).unwrap().as_ptr(), original);
        assert!(archive.require_active().is_err());
    }

    #[test]
    fn only_a_complete_positive_programme_can_retire_its_pure_models() {
        let mut archive = StorageFloorMainArchiveV3::new();
        assert!(archive.require_active().is_err());
        archive.begin().unwrap();
        archive.park(retained_action(), ResourceVector::ZERO).unwrap();
        archive.result = Some(Ok(()));

        archive.begin().unwrap();

        assert!(archive.actions.is_empty());
        assert!(archive.require_active().is_ok());
    }
}

pub(in crate::recovery::journal::tpm_floor) struct StorageFloorMainOriginalV3 {
    pub(super) metadata: Option<std::io::Result<std::fs::Metadata>>,
    pub(super) extent: Option<Result<ProtectedJournalPreopenReplayExtentV1, JournalError>>,
    pub(super) demand: Option<Result<ResourceVector, DemandError>>,
    pub(super) schema: StorageFloorSchemaOriginalV3,
    pub(super) endpoint: [RetainedEndpointRevalidationOriginalV1; 2],
    pub(super) rooted: [ProtectedJournalCurrentnessOriginalsV1; 3],
    pub(super) rooted_result: [Option<Result<(), JournalError>>; 3],
    pub(super) identities: [Option<Result<[u8; 32], BrokerSessionSecurityError>>; 2],
    pub(super) names: [ProtectedJournalCurrentnessOriginalsV1; 2],
    pub(super) names_result: [Option<Result<(), JournalError>>; 2],
    pub(in crate::recovery::journal::tpm_floor) capacity: [CanonicalCapacityReadCaptureV1; 2],
    pub(in crate::recovery::journal::tpm_floor) claim: Option<Result<(), JournalError>>,
    pub(super) snapshot: Option<Result<ProtectedJournalSnapshot, JournalError>>,
    pub(super) rows: Option<Result<(), JournalError>>,
    pub(super) records: BTreeMap<Vec<u8>, Vec<u8>>,
    pub(super) prospective: Option<BTreeMap<Vec<u8>, Vec<u8>>>,
    pub(super) current_hash: FloorHeadCutOriginalV3,
    pub(super) target_hash: FloorHeadCutOriginalV3,
    pub(super) transaction_hash: FloorHeadTransactionOriginalV3,
    pub(in crate::recovery::journal::tpm_floor) preflight: ProtectedJournalPreflightOriginalV2,
    pub(in crate::recovery::journal::tpm_floor) token: Option<Result<ProtectedJournalPreflight, JournalError>>,
    pub(super) sequence: Option<Result<u64, FloorErrorV1>>,
    pub(in crate::recovery::journal::tpm_floor) effect: Option<Result<(), JournalError>>,
    pub(in crate::recovery::journal::tpm_floor) commit: Option<Result<(), JournalError>>,
    pub(super) commit_body: Option<Result<(), FloorErrorV1>>,
    pub(super) snapshot_effect: Option<Result<(), JournalError>>,
    pub(super) native_entered: bool,
    pub(super) inner_entered: bool,
    pub(super) body: Option<Result<(FloorCutV1, Option<FloorCutV1>), BrokerSessionSecurityError>>,
}

impl StorageFloorMainOriginalV3 {
    pub(in crate::recovery::journal::tpm_floor) fn validate_commit_names_v3(
        &mut self, journal: &Journal, index: usize,
    ) -> Result<(), FloorErrorV1> {
        if self.names_result[index].is_some() { return Err(FloorErrorV1::Unavailable); }
        self.names_result[index] = Some(journal.validate_held_protected_names_retaining(&mut self.names[index]));
        if matches!(self.names_result[index], Some(Ok(()))) { Ok(()) }
        else { Err(FloorErrorV1::Unavailable) }
    }

    pub(super) fn new() -> Self {
        Self {
            metadata: None, extent: None, demand: None,
            schema: StorageFloorSchemaOriginalV3::new(),
            endpoint: std::array::from_fn(|_| RetainedEndpointRevalidationOriginalV1::default()),
            rooted: std::array::from_fn(|_| ProtectedJournalCurrentnessOriginalsV1::new()),
            rooted_result: std::array::from_fn(|_| None),
            identities: std::array::from_fn(|_| None),
            names: std::array::from_fn(|_| ProtectedJournalCurrentnessOriginalsV1::new()),
            names_result: std::array::from_fn(|_| None),
            capacity: std::array::from_fn(|_| CanonicalCapacityReadCaptureV1::new()),
            claim: None, snapshot: None, rows: None, records: BTreeMap::new(),
            prospective: None, current_hash: FloorHeadCutOriginalV3::new(),
            target_hash: FloorHeadCutOriginalV3::new(),
            transaction_hash: FloorHeadTransactionOriginalV3::new(),
            preflight: ProtectedJournalPreflightOriginalV2::new(), token: None,
            sequence: None, effect: None, commit: None, commit_body: None, snapshot_effect: None,
            native_entered: false, inner_entered: false, body: None,
        }
    }

    fn fixed_demand() -> Result<ResourceVector, AccountingError> {
        let bytes = size_of::<Self>().checked_mul(2)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }

    fn receiving_demand(&self, owner: &ProtectedBrokerSessionJournalV1,
        transaction: Option<&JournalTransaction>) -> Result<ResourceVector, DemandError>
    {
        let extent = self.extent.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(DemandError::Shape)?;
        let transactions = transaction.map(core::slice::from_ref).unwrap_or(&[]);
        let preflight = ProtectedJournalPreflightOriginalV2::receiving_demand_v2(extent, transactions)?;
        let schema = StorageFloorSchemaOriginalV3::receiving_demand_v3(extent)?;
        let endpoint = RetainedEndpointRevalidationOriginalV1::receiving_demand_v1()
            .ok_or(DemandError::Shape)?;
        let rooted = ProtectedJournalCurrentnessOriginalsV1::fixed_demand_v1(
            &owner.directory, &owner.name,
        )?.with(D::MetadataEntries, 0);
        let named = ProtectedJournalCurrentnessOriginalsV1::named_demand_v1(&owner.name)?
            .with(D::MetadataEntries, 0);
        let mut future = extent.native_bytes;
        let mut extra_rows = 0usize;
        let mut native_append = ResourceVector::ZERO;
        if let Some(transaction) = transaction {
            let journal = owner.journal.as_ref().ok_or(DemandError::Shape)?;
            if !journal.has_captured_append_custody_v1() { return Err(DemandError::Shape); }
            let encoded = aos_sandbox_protocol::domain_ledger::transaction::
                encoded_transaction_append_bytes(transaction).map_err(JournalError::from)?;
            future = future.checked_add(encoded).ok_or(DemandError::Shape)?;
            extra_rows = transaction.records().len();
            native_append = journal.captured_append_receiving_demand_v1(encoded)?;
        }
        let physical = usize::try_from(extent.native_bytes).map_err(|_| DemandError::Shape)?;
        let rows = (physical / aos_sandbox_journal::framing::HEADER_BYTES)
            .min(extent.limits.maximum_materialized_records)
            .checked_add(extra_rows).ok_or(DemandError::Shape)?;
        let index = aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1::<Vec<u8>, Vec<u8>>(rows)
            .ok_or(DemandError::Shape)?;
        // Selected mode keeps the exact current model beside its prospective
        // projection. Native's original reduced state/cursor remains separate.
        let map_bytes = usize::try_from(future).ok().and_then(|bytes| bytes.checked_add(index))
            .and_then(|bytes| bytes.checked_mul(2)).and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(DemandError::Shape)?;
        let map_names = rows.checked_mul(2).and_then(|rows| u64::try_from(rows).ok())
            .ok_or(DemandError::Shape)?;
        let (capacity_bytes, _) = CanonicalCapacityReadCaptureV1::receiving_obligations_v1(rows)
            .ok_or(DemandError::Shape)?;
        let capacity_names = CanonicalCapacityReadCaptureV1::receiving_named_entries_v2(rows)
            .and_then(|names| names.checked_mul(2)).and_then(|names| u64::try_from(names).ok())
            .ok_or(DemandError::Shape)?;
        let capacity = ResourceVector::ZERO.with(D::MemoryBytes,
            capacity_bytes.checked_mul(2).and_then(|bytes| u64::try_from(bytes).ok()).ok_or(DemandError::Shape)?)
            .with(D::MetadataEntries, capacity_names);
        let hash = FloorHeadCutOriginalV3::receiving_demand_v3(extent.limits.maximum_key_bytes)
            .ok_or(DemandError::Shape)?;
        let mut demand = Self::fixed_demand()?.checked_add(schema)?.checked_add(preflight)?
            // Two explicit retained probes plus the existing armed endpoint
            // archive reused by both stable-identity comparisons.
            .checked_add(endpoint)?.checked_add(endpoint)?.checked_add(endpoint)?
            .checked_add(rooted)?.checked_add(rooted)?.checked_add(rooted)?
            .checked_add(named)?.checked_add(named)?.checked_add(capacity)?
            .checked_add(hash)?.checked_add(hash)?.checked_add(native_append)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, map_bytes)
                .with(D::MetadataEntries, map_names).with(D::StorageBytes, future))?;
        if let Some(transaction) = transaction {
            demand = demand.checked_add(FloorHeadTransactionOriginalV3::receiving_demand_v3(transaction)
                .ok_or(DemandError::Shape)?)?;
        }
        Ok(demand)
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        fn error<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
            slot.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        error(&self.metadata).or_else(|| error(&self.extent)).or_else(|| error(&self.demand))
            .or_else(|| self.schema.failure()).or_else(|| self.endpoint[0].failure())
            .or_else(|| self.rooted[0].failure()).or_else(|| error(&self.rooted_result[0]))
            .or_else(|| error(&self.identities[0]))
            .or_else(|| self.names[0].failure()).or_else(|| error(&self.names_result[0]))
            .or_else(|| error(&self.claim)).or_else(|| error(&self.snapshot)).or_else(|| error(&self.rows))
            .or_else(|| self.current_hash.failure().map(|cause| cause as _))
            .or_else(|| self.preflight.failure()).or_else(|| error(&self.token))
            .or_else(|| self.transaction_hash.failure().map(|cause| cause as _))
            .or_else(|| error(&self.sequence)).or_else(|| self.target_hash.failure().map(|cause| cause as _))
            .or_else(|| error(&self.effect)).or_else(|| error(&self.snapshot_effect))
            .or_else(|| error(&self.commit)).or_else(|| error(&self.commit_body))
            .or_else(|| self.names[1].failure()).or_else(|| error(&self.names_result[1]))
            .or_else(|| error(&self.identities[1])).or_else(|| self.endpoint[1].failure())
            .or_else(|| self.rooted[1].failure()).or_else(|| error(&self.rooted_result[1]))
            .or_else(|| error(&self.body))
            .or_else(|| self.rooted[2].failure()).or_else(|| error(&self.rooted_result[2]))
    }
}

/// Retains main floor models until the actual enclosing native programme ends.
pub(in crate::recovery::journal) struct StorageFloorMainArchiveV3 {
    actions: Vec<Box<StorageFloorMainOriginalV3>>,
    retained: ResourceVector,
    fixed: Option<Result<ResourceVector, AccountingError>>,
    demand: Option<Result<ResourceVector, DemandError>>,
    funding: Option<Result<(), StorageReceivingClosedV1>>,
    allocation: Option<Result<(), std::collections::TryReserveError>>,
    retention: Option<Result<ResourceVector, AccountingError>>,
    result: Option<Result<(), FloorErrorV1>>,
    started: bool,
    closed: Option<FloorErrorV1>,
}

impl Default for StorageFloorMainArchiveV3 {
    fn default() -> Self { Self::new() }
}

impl StorageFloorMainArchiveV3 {
    fn begin(&mut self) -> Result<(), FloorErrorV1> {
        if self.failure().is_some() || self.started && !matches!(self.result, Some(Ok(()))) {
            self.closed.get_or_insert(FloorErrorV1::Unavailable);
            return Err(FloorErrorV1::Unavailable);
        }
        self.actions.clear();
        self.retained = ResourceVector::ZERO;
        self.result = None;
        self.started = true;
        Ok(())
    }

    fn require_active(&self) -> Result<(), FloorErrorV1> {
        if !self.started || self.result.is_some() || self.failure().is_some() {
            return Err(FloorErrorV1::Unavailable);
        }
        Ok(())
    }

    /// Creates inert inline storage without native entry or allocation.
    pub(in crate::recovery::journal) const fn new() -> Self {
        Self { actions: Vec::new(), retained: ResourceVector::ZERO, fixed: None,
            demand: None, funding: None, allocation: None, retention: None,
            result: None, started: false, closed: None }
    }

    pub(in crate::recovery::journal) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        fn error<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
            slot.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        error(&self.fixed).or_else(|| error(&self.demand)).or_else(|| error(&self.funding))
            .or_else(|| error(&self.allocation)).or_else(|| self.actions.iter().find_map(|action| action.failure()))
            .or_else(|| error(&self.retention)).or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    fn complete_demand(&self, required: ResourceVector) -> Result<ResourceVector, DemandError> {
        let slots = self.actions.capacity().checked_add(self.actions.len())
            .and_then(|slots| slots.checked_add(1)).ok_or(DemandError::Shape)?;
        let bytes = slots.checked_mul(size_of::<Box<StorageFloorMainOriginalV3>>())
            .and_then(|bytes| bytes.checked_add(size_of::<Self>().checked_mul(2)?))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(DemandError::Shape)?;
        Ok(self.retained.checked_add(required)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))?)
    }

    fn admit(&mut self, journal: &Journal, receiving: &mut dyn StorageFloorFinancialSourceV2,
        required: ResourceVector) -> Result<(), FloorErrorV1>
    {
        if !self.started || self.result.is_some() || self.failure().is_some() {
            return Err(FloorErrorV1::Unavailable);
        }
        self.demand = Some(self.complete_demand(required));
        let complete = self.demand.as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or(FloorErrorV1::Encoding)?;
        self.funding = Some(receiving.reserve_main_v3(journal, complete));
        if matches!(self.funding, Some(Ok(()))) { Ok(()) }
        else { Err(FloorErrorV1::Unavailable) }
    }

    fn prepare_action(&mut self, journal: &Journal, receiving: &mut dyn StorageFloorFinancialSourceV2)
        -> Result<Box<StorageFloorMainOriginalV3>, FloorErrorV1>
    {
        self.fixed = Some(StorageFloorMainOriginalV3::fixed_demand());
        let fixed = self.fixed.as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or(FloorErrorV1::Encoding)?;
        self.admit(journal, receiving, fixed)?;
        self.allocation = Some(self.actions.try_reserve_exact(1));
        if !matches!(self.allocation, Some(Ok(()))) { return Err(FloorErrorV1::Unavailable); }
        Ok(Box::new(StorageFloorMainOriginalV3::new()))
    }

    fn park(&mut self, action: Box<StorageFloorMainOriginalV3>, admitted: ResourceVector)
        -> Result<(), FloorErrorV1>
    {
        self.actions.push(action);
        // Every action owns distinct models/FDs. They share this one physical
        // main file, whose full future extent remains on the real F high water.
        self.retention = Some(self.retained.checked_add(admitted.with(D::StorageBytes, 0)));
        self.retained = self.retention.as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or(FloorErrorV1::Encoding)?;
        Ok(())
    }
}

impl ProtectedBrokerSessionJournalV1 {
    pub(in crate::recovery::journal) fn require_storage_floor_main_programme_v3(&self)
        -> Result<(), FloorErrorV1>
    {
        if !self.journal.as_ref().is_some_and(Journal::has_captured_append_custody_v1) {
            return Err(FloorErrorV1::Unavailable);
        }
        self.floor_main.require_active()
    }

    pub(in crate::recovery::journal) fn commit_storage_floor_main_receiving_v3(
        &mut self, transaction: &JournalTransaction,
        receiving: &mut dyn StorageFloorFinancialSourceV2,
    ) -> Result<(), FloorErrorV1> {
        let mut archive = std::mem::take(&mut self.floor_main);
        let result = (|| {
            let mut action = archive.prepare_action(
                self.journal.as_ref().ok_or(FloorErrorV1::Unavailable)?, receiving)?;
            let mut admitted = archive.fixed.as_ref().and_then(|value| value.as_ref().ok())
                .copied().ok_or(FloorErrorV1::Encoding)?;
            let result = (|| {
                action.extent = Some(self.journal.as_ref().ok_or(FloorErrorV1::Unavailable)?
                    .held_session_receiving_extent_v1(&mut action.metadata));
                if !matches!(action.extent, Some(Ok(_))) { return Err(FloorErrorV1::Unavailable); }
                action.demand = Some(action.receiving_demand(self, Some(transaction)));
                let required = action.demand.as_ref().and_then(|value| value.as_ref().ok())
                    .copied().ok_or(FloorErrorV1::Encoding)?;
                archive.admit(self.journal.as_ref().ok_or(FloorErrorV1::Unavailable)?, receiving, required)?;
                admitted = required;
                action.native_entered = true;
                let body = super::super::durable::commit_traffic_transaction_retaining_v3(
                    self.journal.as_mut().ok_or(FloorErrorV1::Unavailable)?, transaction, &mut action);
                action.commit_body = Some(body);
                // A failed append never suppresses its independently owed
                // rooted observation. Both owners stay with the actual main.
                action.rooted_result[2] = Some(self.owner.validate_held_retaining(
                    self.journal.as_ref().ok_or(FloorErrorV1::Unavailable)?,
                    &self.directory, &self.name, &mut action.rooted[2]));
                action.commit_body.as_ref().copied().ok_or(FloorErrorV1::Unavailable)??;
                if !matches!(action.rooted_result[2], Some(Ok(()))) { return Err(FloorErrorV1::Unavailable); }
                Ok(())
            })();
            archive.park(action, admitted)?;
            result
        })();
        self.floor_main = archive;
        result
    }

    pub(in crate::recovery::journal) fn begin_storage_floor_main_programme_v3(&mut self)
        -> Result<(), FloorErrorV1>
    {
        // Only the complete positive outer programme permits these actual
        // native/model owners to retire. The original F bound is never reset.
        self.floor_main.begin()
    }

    pub(in crate::recovery::journal) fn finish_storage_floor_main_programme_v3<T>(&mut self,
        result: Result<T, FloorErrorV1>) -> Result<T, FloorErrorV1>
    {
        let archive = &mut self.floor_main;
        if !archive.started || archive.result.is_some() { return Err(FloorErrorV1::Unavailable); }
        archive.result = Some(result.as_ref().map(|_| ()).map_err(|cause| *cause));
        if result.is_ok() && archive.failure().is_some() { return Err(FloorErrorV1::Unavailable); }
        result
    }

    pub(in crate::recovery::journal) fn tpm_floor_cuts_storage_receiving_v3(&mut self,
        profile: FloorProfileV1, transaction: Option<&JournalTransaction>,
        receiving: &mut dyn StorageFloorFinancialSourceV2)
        -> Result<(FloorCutV1, Option<FloorCutV1>), FloorErrorV1>
    {
        let mut archive = std::mem::take(&mut self.floor_main);
        let result = (|| {
            let mut action = archive.prepare_action(
                self.journal.as_ref().ok_or(FloorErrorV1::Unavailable)?, receiving)?;
            let mut admitted = archive.fixed.as_ref().and_then(|value| value.as_ref().ok())
                .copied().ok_or(FloorErrorV1::Encoding)?;
            let result = (|| {
                action.extent = Some(self.journal.as_ref().ok_or(FloorErrorV1::Unavailable)?
                    .held_session_receiving_extent_v1(&mut action.metadata));
                if !matches!(action.extent, Some(Ok(_))) { return Err(FloorErrorV1::Unavailable); }
                action.demand = Some(action.receiving_demand(self, transaction));
                let required = action.demand.as_ref().and_then(|value| value.as_ref().ok())
                    .copied().ok_or(FloorErrorV1::Encoding)?;
                archive.admit(self.journal.as_ref().ok_or(FloorErrorV1::Unavailable)?, receiving, required)?;
                admitted = required;
                action.native_entered = true;
                let body = self.tpm_floor_cuts_engine_retaining_v3(profile, transaction, &mut action);
                action.body = Some(body);
                if action.native_entered {
                    action.rooted_result[2] = Some(self.owner.validate_held_retaining(
                        self.journal.as_ref().ok_or(FloorErrorV1::Unavailable)?,
                        &self.directory, &self.name, &mut action.rooted[2],
                    ));
                }
                let body = action.body.as_ref().cloned().ok_or(FloorErrorV1::Unavailable)?;
                let cuts = body.map_err(super::super::super::floor_revalidation::floor_error)?;
                if !matches!(action.rooted_result[2], Some(Ok(()))) { return Err(FloorErrorV1::Unavailable); }
                Ok(cuts)
            })();
            archive.park(action, admitted)?;
            result
        })();
        self.floor_main = archive;
        result
    }
}
