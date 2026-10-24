//! Reads complete current Node17 facts for a separately authenticated fresh owner.
//!
//! Parsing produces inert owned records. The actual complete signed Source17
//! reader must conjoin these records with native MAC/protocol/current component
//! correspondence before retaining them in its selected Window. Only the
//! genuine InstalledSettled17 context can issue the fresh node association.

#[path = "restored_settled17/capacity_current17.rs"]
mod capacity_current17;
#[path = "restored_settled17/metadata.rs"]
mod metadata;
#[path = "restored_settled17/raw_storage.rs"]
mod raw_storage;
#[path = "restored_settled17/record.rs"]
mod record;
#[path = "restored_settled17/validation.rs"]
mod validation;
pub(crate) use raw_storage::CnpRestoredNode17RawStorageData;

use crate::node_contract::{NodeRoute, OriginalLineageRuntimeRecord, RuntimeError};
use crate::node_scheduling::SchedulingSnapshot;
use crucible_node_format::{ContentRef, Id, canonical};
use record::NodeRecord17;

/// Retains a complete closed Node17 data record matched to its current common rows.
///
/// This value supplies no live authority, readiness, native adoption or Source
/// authenticity. Its exact signed Source and native correspondence remain
/// independent mandatory predicates of the complete fresh Window.
pub(crate) struct CnpRestoredSettledValidatedNode17 {
    reference: ContentRef,
    route: NodeRoute,
    record: NodeRecord17,
}

impl CnpRestoredSettledValidatedNode17 {
    pub(crate) fn node_data(&self) -> &Id {
        &self.route.node
    }

    pub(crate) fn reference_data(&self) -> &ContentRef {
        &self.reference
    }

    pub(crate) fn retained_semantic_credit_data(&self) -> usize {
        self.record.base.retained_credit
    }

    pub(crate) fn historical_operations_count_data(&self) -> usize {
        self.record.base.operations.len()
    }

    pub(crate) fn historical_inputs_count_data(&self) -> usize {
        self.record.base.inputs.len()
    }

    /// Borrows the first retained common observation for the defining Source join.
    pub(crate) fn first_observation_data(
        &self,
    ) -> Result<&crate::node_scheduling::NativeSchedulingObservation, RuntimeError> {
        self.record
            .observation
            .as_ref()
            .ok_or(RuntimeError::InvalidReceipt)
    }

    /// Borrows every genuinely new Producer owner in its actual saved order.
    pub(crate) fn producer_attempts_data(
        &self,
    ) -> impl ExactSizeIterator<Item = CnpRestoredNode17ProducerAttemptBorrowedData<'_>> {
        self.record.producer_attempts.iter().map(|attempt| {
            let record::HistoricalAdmission17::Admission(admission) = &attempt.admission;
            CnpRestoredNode17ProducerAttemptBorrowedData {
                operation: &admission.operation,
                request: &admission.request,
                slot: attempt.slot,
                retained: attempt.retained.as_ref(),
                scheduling: attempt.scheduling.as_ref(),
            }
        })
    }

    /// Borrows every current observation without collapsing equal independent rows.
    pub(crate) fn current_observations_data(
        &self,
    ) -> impl ExactSizeIterator<
        Item = (
            u64,
            Option<&crate::node_scheduling::NativeSchedulingObservation>,
        ),
    > {
        self.record
            .current_observations
            .iter()
            .map(|row| (row.ordinal, row.retained.as_ref()))
    }

    pub(crate) fn base_observation_data(
        &self,
    ) -> Option<&crate::node_scheduling::NativeSchedulingObservation> {
        self.record
            .base
            .observation
            .as_ref()
            .map(|(_, value)| value)
    }

    pub(crate) fn observe_sequence_data(&self) -> crucible_node_format::U64 {
        self.record.base.observe_sequence
    }

    pub(crate) fn operation_family_data(
        &self,
        operation: &Id,
    ) -> Result<CnpRestoredNode17OperationFamily, RuntimeError> {
        let mut selected = None;
        for row in &self.record.original_operations {
            let record::HistoricalAdmission17::Admission(row) = row;
            if &row.operation == operation {
                set_family(&mut selected, CnpRestoredNode17OperationFamily::Imported)?;
            }
        }
        for row in self.record.base.operations.values() {
            if &row.operation == operation {
                set_family(&mut selected, CnpRestoredNode17OperationFamily::Base)?;
            }
        }
        for row in &self.record.producer_attempts {
            let record::HistoricalAdmission17::Admission(row) = &row.admission;
            if &row.operation == operation {
                set_family(&mut selected, CnpRestoredNode17OperationFamily::Producer)?;
            }
        }
        if let Some(families) = &self.record.restored_families {
            for (map, family) in [
                (
                    &families.imported_operations,
                    CnpRestoredNode17OperationFamily::Imported,
                ),
                (
                    &families.base_operations,
                    CnpRestoredNode17OperationFamily::Base,
                ),
                (
                    &families.producer_operations,
                    CnpRestoredNode17OperationFamily::Producer,
                ),
            ] {
                if map.contains_key(operation) {
                    set_family(&mut selected, family)?;
                }
            }
        }
        selected.ok_or(RuntimeError::InvalidReceipt)
    }

    pub(crate) fn input_family_data(
        &self,
        stage_operation: &Id,
    ) -> Result<CnpRestoredNode17InputFamily, RuntimeError> {
        let mut selected = None;
        for row in &self.record.original_inputs {
            let record::HistoricalBatch17::InputBatch(row) = row;
            if &row.stage_operation == stage_operation {
                set_family(&mut selected, CnpRestoredNode17InputFamily::Imported)?;
            }
        }
        for row in self.record.base.inputs.values() {
            if &row.original.stage_operation == stage_operation {
                set_family(&mut selected, CnpRestoredNode17InputFamily::Base)?;
            }
        }
        if let Some(families) = &self.record.restored_families {
            for (map, family) in [
                (
                    &families.imported_inputs,
                    CnpRestoredNode17InputFamily::Imported,
                ),
                (&families.base_inputs, CnpRestoredNode17InputFamily::Base),
            ] {
                if map.contains_key(stage_operation) {
                    set_family(&mut selected, family)?;
                }
            }
        }
        selected.ok_or(RuntimeError::InvalidReceipt)
    }

    pub(crate) fn family_counts_data(&self) -> Result<[usize; 5], RuntimeError> {
        let mut counts = [
            self.record.original_operations.len(),
            self.record.base.operations.len(),
            self.record.producer_attempts.len(),
            self.record.original_inputs.len(),
            self.record.base.inputs.len(),
        ];
        if let Some(families) = &self.record.restored_families {
            for (count, imported) in counts.iter_mut().zip([
                families.imported_operations.len(),
                families.base_operations.len(),
                families.producer_operations.len(),
                families.imported_inputs.len(),
                families.base_inputs.len(),
            ]) {
                *count = count
                    .checked_add(imported)
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
        }
        Ok(counts)
    }

    /// Borrows the exact immutable inherited root for full Source DAG validation.
    pub(crate) fn inherited_node_reference_data(&self) -> Option<&ContentRef> {
        self.record
            .restored_families
            .as_ref()
            .and_then(|families| families.inherited.as_ref())
    }

    /// Reads the exact body into a retained one-shot decoder before validation.
    ///
    /// The signed Source owner admits `construction_data` with every existing
    /// owner before this call. A refusal leaves all completed decode products
    /// in `pending`; the slot cannot be retried or exchanged for another body.
    ///
    /// # Errors
    /// Refuses occupied slots, changed full-reference bytes, unknown or
    /// noncanonical shape, missing histories, inconsistent common joins or credit.
    pub(crate) fn decode_current_into_data(
        reference: &ContentRef,
        bytes: &[u8],
        route: &NodeRoute,
        runtime: &OriginalLineageRuntimeRecord,
        scheduling: &SchedulingSnapshot,
        maximum_requested_bytes: usize,
        pending: &mut Option<CnpRestoredNode17DecodeAttempt>,
        output: &mut Option<Self>,
    ) -> Result<(), RuntimeError> {
        if pending.is_some() || output.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        let construction = CnpRestoredNode17DecodeConstructionData::quote(
            reference,
            bytes,
            route,
            maximum_requested_bytes,
        )?;
        reference
            .verify(bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        *pending = Some(CnpRestoredNode17DecodeAttempt {
            construction,
            reference: None,
            route: None,
            value: None,
            canonical: None,
            record: None,
            reencoded: None,
        });
        let attempt = pending.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        attempt.reference = Some(reference.clone());
        attempt.route = Some(route.clone());
        attempt.value = Some(
            canonical::parse_json(bytes, maximum_requested_bytes)
                .map_err(|_| RuntimeError::InvalidReceipt)?,
        );
        let value = attempt
            .value
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        attempt.canonical =
            Some(canonical::canonical_json(value).map_err(|_| RuntimeError::InvalidReceipt)?);
        if attempt.canonical.as_deref() != Some(bytes) {
            return Err(RuntimeError::InvalidReceipt);
        }
        attempt.record =
            Some(serde_json::from_slice(bytes).map_err(|_| RuntimeError::InvalidReceipt)?);
        let record = attempt
            .record
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        attempt.reencoded =
            Some(serde_json::to_value(record).map_err(|_| RuntimeError::InvalidReceipt)?);
        if attempt.reencoded.as_ref() != attempt.value.as_ref() {
            return Err(RuntimeError::InvalidReceipt);
        }
        validation::validate(record, route, runtime, scheduling)?;
        // All fallible checks precede the move. Parser DOMs and exact canonical
        // bytes stay retained by the decoder, independently of the output DTO.
        let reference = attempt
            .reference
            .take()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let route = attempt.route.take().ok_or(RuntimeError::OwnerUnavailable)?;
        let record = attempt
            .record
            .take()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        *output = Some(Self {
            reference,
            route,
            record,
        });
        Ok(())
    }
}

/// Retains the actual decoder's independent success and refusal products.
/// No constructor, permission or readiness is issued by this data-only owner.
pub(crate) struct CnpRestoredNode17DecodeAttempt {
    construction: CnpRestoredNode17DecodeConstructionData,
    reference: Option<ContentRef>,
    route: Option<NodeRoute>,
    value: Option<serde_json::Value>,
    canonical: Option<Vec<u8>>,
    record: Option<NodeRecord17>,
    reencoded: Option<serde_json::Value>,
}

impl CnpRestoredNode17DecodeAttempt {
    pub(crate) fn construction_data(&self) -> &CnpRestoredNode17DecodeConstructionData {
        &self.construction
    }
}

#[path = "restored_settled17/construction.rs"]
mod construction;
pub(crate) use construction::CnpRestoredNode17DecodeConstructionData;

/// Borrows one complete current Node Producer row for the independent Source join.
/// These references contain data only and cannot issue an operation or native call.
pub(crate) struct CnpRestoredNode17ProducerAttemptBorrowedData<'a> {
    pub(crate) operation: &'a Id,
    pub(crate) request: &'a crate::node_contract::OperationRequest,
    pub(crate) slot: usize,
    pub(crate) retained: Option<&'a crate::node_contract::OperationOutcome>,
    pub(crate) scheduling: Option<&'a crate::node_scheduling::NativeSchedulingObservation>,
}

/// Selects the actual immutable historical owner of one current operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CnpRestoredNode17OperationFamily {
    Imported,
    Base,
    Producer,
}

/// Selects the actual immutable historical owner of one current input batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CnpRestoredNode17InputFamily {
    Imported,
    Base,
}

fn set_family<T>(slot: &mut Option<T>, value: T) -> Result<(), RuntimeError> {
    if slot.is_some() {
        return Err(RuntimeError::InvalidReceipt);
    }
    *slot = Some(value);
    Ok(())
}

#[path = "restored_settled17/source_join.rs"]
mod source_join;

#[path = "restored_settled17/decoded_storage.rs"]
mod decoded_storage;

#[path = "restored_settled17/initial15.rs"]
mod initial15;
