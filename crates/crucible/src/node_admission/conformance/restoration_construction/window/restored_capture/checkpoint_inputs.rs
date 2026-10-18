//! Retains genuine current Runtime and scheduling objects before owner dispatch.
//!
//! Construction precedes the unchanged whole-Window census. The later archive
//! callback compares both full references and complete bytes against its actual
//! prepared Host and writer objects without allocating or granting Capture.
//!
//! DTO construction is a pure projection under separate constructor credit.
//! A failed temporary owns no modeled state. Returned DTOs, DOMs and canonical
//! output banks stay retained; failure never resets this attempt or its credit.

use super::*;
use crate::node_contract::runtime_owned_counter::OwnedStorage;
use crate::node_contract::{HostSchedulingSource, OriginalInputLineageLimits};
use crate::node_scheduling::SchedulingSnapshot;
use crucible_node_contract::{ContentRef, canonical};
use serde::Serialize;
use std::io::{self, Write};

#[derive(Default)]
struct CanonicalChild {
    started: bool,
    value: Option<serde_json::Value>,
    bytes: Vec<u8>,
    object: Option<InputPayload>,
}

impl CanonicalChild {
    fn construct_data(
        &mut self,
        record: &impl Serialize,
        media: &str,
        maximum_encoded: usize,
    ) -> Result<(), RuntimeError> {
        if std::mem::replace(&mut self.started, true) {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.value = Some(serde_json::to_value(record).map_err(|_| RuntimeError::InvalidReceipt)?);
        self.bytes
            .try_reserve_exact(maximum_encoded)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        if self.bytes.capacity() > maximum_encoded {
            return Err(RuntimeError::ResourceLimit);
        }
        let mut output = RetainedCanonicalWriter {
            bytes: &mut self.bytes,
            maximum: maximum_encoded,
        };
        canonical::canonical_json_to_writer(
            self.value.as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
            &mut output,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        let reference =
            canonical::content_ref(&self.bytes, media).map_err(|_| RuntimeError::InvalidReceipt)?;
        self.object = Some(InputPayload {
            reference,
            bytes: std::mem::take(&mut self.bytes),
        });
        Ok(())
    }

    fn retained_requested_storage_data(&self) -> Result<usize, RuntimeError> {
        let mut total = self.bytes.capacity();
        if let Some(value) = &self.value {
            total = total
                .checked_add(value.owned_storage()?)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        if let Some(object) = &self.object {
            let reference_storage = NodeRuntime::capture_reference_storage(&object.reference)?;
            total = total
                .checked_add(object.bytes.capacity())
                .and_then(|n| n.checked_add(reference_storage))
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        Ok(total)
    }
}

/// Appends within the already retained bank without allowing vector growth.
struct RetainedCanonicalWriter<'a> {
    bytes: &'a mut Vec<u8>,
    maximum: usize,
}

impl Write for RetainedCanonicalWriter<'_> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.len() > self.maximum.saturating_sub(self.bytes.len())
            || input.len() > self.bytes.capacity().saturating_sub(self.bytes.len())
        {
            return Err(io::ErrorKind::WriteZero.into());
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Owns independently funded current snapshots and every initialized encoding.
///
/// Its containing pending attempt is installed before construction starts. A
/// failed constructor keeps all completed siblings, partial banks and once state.
#[derive(Default)]
pub(super) struct OriginalRestoredCaptureCheckpointInputs17 {
    started: bool,
    verified: bool,
    runtime_record: Option<OriginalLineageRuntimeRecord>,
    scheduling_record: Option<SchedulingSnapshot>,
    runtime: CanonicalChild,
    scheduling: CanonicalChild,
}

impl OriginalRestoredCaptureCheckpointInputs17 {
    /// Counts backing independently of the containing attempt's inline fields.
    ///
    /// # Errors
    /// Refuses checked layout overflow or invalid owned-container accounting.
    pub(super) fn retained_requested_storage_data(&self) -> Result<usize, RuntimeError> {
        let Self {
            started: _,
            verified: _,
            runtime_record,
            scheduling_record,
            runtime,
            scheduling,
        } = self;
        let mut total = runtime
            .retained_requested_storage_data()?
            .checked_add(scheduling.retained_requested_storage_data()?)
            .ok_or(RuntimeError::ResourceLimit)?;
        if let Some(record) = runtime_record {
            let backing = NodeRuntime::capture_runtime_record_storage(record)?
                .checked_sub(size_of::<OriginalLineageRuntimeRecord>())
                .ok_or(RuntimeError::ResourceLimit)?;
            total = total
                .checked_add(backing)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        if let Some(record) = scheduling_record {
            let backing = NodeRuntime::capture_scheduling_record_storage(record)?
                .checked_sub(size_of::<SchedulingSnapshot>())
                .ok_or(RuntimeError::ResourceLimit)?;
            total = total
                .checked_add(backing)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        Ok(total)
    }

    /// Constructs solely from the same real Runtime, World, Host and boundary.
    ///
    /// The caller admits this independent constructor row before this call;
    /// none of the six separate ticket-validation windows funds these banks.
    ///
    /// # Errors
    /// Refuses reuse, foreign current owners, unsupported snapshot state,
    /// malformed current records, oversized encodings or constructor failure.
    pub(super) fn construct_data(
        &mut self,
        runtime: &NodeRuntime,
        world: &WorldActivation,
        host: &HostSchedulingSource,
        boundary: &OriginalRestoredCoordinatorBoundary17,
        row: &OriginalRestoredCaptureRuntimeConstructionData,
        lineage_limits: OriginalInputLineageLimits,
        maximum_record_bytes: usize,
    ) -> Result<(), RuntimeError> {
        if std::mem::replace(&mut self.started, true) {
            return Err(RuntimeError::OutstandingObligations);
        }
        row.authenticate_original_data(
            runtime,
            world,
            boundary.cut_data(),
            boundary.ordinal_data(),
        )?;
        boundary.authenticate_runtime_data(runtime, world, host)?;

        self.runtime_record = Some(runtime.original_lineage_runtime_snapshot(
            boundary.cut_data(),
            boundary.ordinal_data(),
            lineage_limits,
            maximum_record_bytes,
        )?);
        self.runtime.construct_data(
            self.runtime_record
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            "application/vnd.crucible.runtime-original-lineage+json;version=7",
            row.maximum_runtime_record_encoded_bytes_data()
                .min(maximum_record_bytes),
        )?;

        self.scheduling_record = Some(runtime.original_lineage_scheduler_snapshot(
            world,
            boundary.cut_data(),
            boundary.ordinal_data(),
        )?);
        self.scheduling.construct_data(
            self.scheduling_record
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            "application/json",
            row.maximum_scheduling_record_encoded_bytes_data()
                .min(maximum_record_bytes),
        )?;

        boundary.authenticate_runtime_data(runtime, world, host)?;
        row.authenticate_original_data(
            runtime,
            world,
            boundary.cut_data(),
            boundary.ordinal_data(),
        )?;
        self.verified = true;
        Ok(())
    }

    /// Lends completed objects without manufacturing a ticket or model grant.
    ///
    /// # Errors
    /// Refuses a failed or incomplete constructor.
    pub(super) fn objects_data(&self) -> Result<(&InputPayload, &InputPayload), RuntimeError> {
        if !self.verified {
            return Err(RuntimeError::OwnerUnavailable);
        }
        Ok((
            self.runtime
                .object
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            self.scheduling
                .object
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
        ))
    }

    /// Joins the preconstructed objects to the archive's actual prepared objects.
    ///
    /// # Errors
    /// Refuses incomplete construction or any reference or byte disagreement.
    pub(super) fn authenticate_writer_objects_data(
        &self,
        runtime: &InputPayload,
        scheduling: &InputPayload,
    ) -> Result<(), RuntimeError> {
        let (expected_runtime, expected_scheduling) = self.objects_data()?;
        if expected_runtime.reference != runtime.reference
            || expected_runtime.bytes != runtime.bytes
            || expected_scheduling.reference != scheduling.reference
            || expected_scheduling.bytes != scheduling.bytes
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}

/// Names the actual constructor, writer and typed-result counter views.
pub(super) fn counter_scratch_data() -> usize {
    size_of::<OriginalRestoredCaptureCheckpointInputs17>()
        + size_of::<CanonicalChild>()
        + size_of::<RetainedCanonicalWriter<'static>>()
        + size_of::<Option<OriginalLineageRuntimeRecord>>()
        + size_of::<Option<SchedulingSnapshot>>()
        + size_of::<Option<serde_json::Value>>()
        + size_of::<Option<InputPayload>>()
        + size_of::<Result<OriginalLineageRuntimeRecord, RuntimeError>>()
        + size_of::<Result<SchedulingSnapshot, RuntimeError>>()
        + size_of::<Result<serde_json::Value, serde_json::Error>>()
        + size_of::<Result<ContentRef, crucible_node_contract::ContractError>>()
        + size_of::<Result<(&'static InputPayload, &'static InputPayload), RuntimeError>>()
        + size_of::<Result<(), crucible_node_contract::ContractError>>()
        + size_of::<io::Result<usize>>()
        + size_of::<io::Result<()>>()
}

#[cfg(test)]
mod canonical_tests {
    use super::*;

    #[test]
    fn short_canonical_bank_keeps_value_prefix_capacity_and_once_state() {
        let record = serde_json::json!({"long":"retained value"});
        let mut child = CanonicalChild::default();
        assert!(
            child
                .construct_data(&record, "application/json", 2)
                .is_err()
        );
        assert!(child.started);
        assert_eq!(child.value.as_ref(), Some(&record));
        assert_eq!(child.bytes.as_slice(), b"{");
        assert_eq!(child.bytes.capacity(), 2);
        assert!(child.object.is_none());
        let retained = child.retained_requested_storage_data().unwrap();
        assert!(retained > child.bytes.capacity());

        assert!(matches!(
            child.construct_data(&record, "application/json", 65_536),
            Err(RuntimeError::OutstandingObligations)
        ));
        assert_eq!(child.bytes.as_slice(), b"{");
        assert_eq!(child.retained_requested_storage_data().unwrap(), retained);
    }

    #[test]
    fn exact_canonical_bank_moves_same_allocation_into_verified_object() {
        let record = serde_json::json!({"first":"complete", "second":[1,2,3]});
        let expected = canonical::canonical_json(&record).unwrap();
        let mut child = CanonicalChild::default();
        child
            .construct_data(&record, "application/json", expected.len())
            .unwrap();
        assert!(child.bytes.is_empty());
        assert_eq!(child.bytes.capacity(), 0);
        let object = child.object.as_ref().unwrap();
        assert_eq!(object.bytes, expected);
        assert_eq!(object.bytes.capacity(), expected.len());
        object.reference.verify(&object.bytes).unwrap();
        let expected_retained = record.owned_storage().unwrap()
            + expected.len()
            + NodeRuntime::capture_reference_storage(&object.reference).unwrap();
        assert_eq!(
            child.retained_requested_storage_data().unwrap(),
            expected_retained
        );
    }
}
