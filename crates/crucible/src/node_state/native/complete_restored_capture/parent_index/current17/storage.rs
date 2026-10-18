//! Prices real header constructors and observes initialized parent-owned heaps.

use super::*;
use crucible_node_contract::{HashRef, OwnerBinding};

pub(super) fn maximum_data(limits: NativeArchiveLimits) -> Result<usize, StateError> {
    let memory = usize::try_from(limits.state.maximum_native_memory_bytes).map_err(schema)?;
    Ok(memory
        .min(limits.state.maximum_total_content_bytes)
        .min(limits.native.maximum_total_record_bytes))
}

pub(super) fn record_maximum_data(
    parent: &ParentArchive17ReadScope<'_, '_>,
) -> Result<usize, StateError> {
    let limits = parent.limits_data()?;
    Ok(limits
        .state
        .maximum_record_bytes
        .min(limits.native.maximum_record_bytes))
}

pub(super) fn body_data<'a>(
    parent: &'a ParentArchive17ReadScope<'_, '_>,
    reference: &ContentRef,
) -> Result<&'a [u8], StateError> {
    let bytes = parent.body_data(reference)?;
    if bytes.is_empty() || bytes.len() > record_maximum_data(parent)? {
        return Err(refused(
            "current17 parent header body exceeds record credit",
        ));
    }
    Ok(bytes)
}

pub(super) fn sum_data<const N: usize>(
    values: [usize; N],
    maximum: usize,
) -> Result<usize, StateError> {
    values.into_iter().try_fold(0usize, |sum, next| {
        sum.checked_add(next)
            .filter(|sum| *sum <= maximum)
            .ok_or_else(|| refused("current17 parent header requested storage overflow"))
    })
}

pub(super) fn raw_storage_data(bytes: &[u8], maximum: usize) -> Result<(usize, usize), StateError> {
    let raw = NodeRuntime::capture_selected_json_decode_storage(
        bytes,
        size_of::<Value>(),
        NodeRuntime::capture_map_node_storage::<String, Value>(),
        maximum,
    )
    .map_err(schema)?;
    let canonical = bytes
        .len()
        .checked_mul(4)
        .and_then(|n| n.checked_add(8))
        .ok_or_else(|| refused("current17 parent header canonical extent overflow"))?;
    sum_data([raw, canonical], maximum)?;
    Ok((raw, canonical))
}

pub(super) fn admit_empty_data(
    parent: &ParentArchive17ReadScope<'_, '_>,
    additional: usize,
    growth: usize,
    maximum: usize,
) -> Result<(), StateError> {
    sum_data(
        [
            parent.retained_content_requested_storage_data()?,
            additional,
            size_of::<ParentCurrent17HeaderAttempt>(),
            growth,
            ParentCurrent17HeaderAttempt::counter_scratch_data(),
        ],
        maximum,
    )
    .map(|_| ())
}

impl ParentCurrent17HeaderAttempt {
    pub(super) fn admit_data(
        &self,
        parent: &ParentArchive17ReadScope<'_, '_>,
        additional: usize,
        growth: usize,
        transient: usize,
    ) -> Result<(), StateError> {
        self.authenticate_parent_data(parent)?;
        sum_data(
            [
                parent.retained_content_requested_storage_data()?,
                additional,
                self.retained_requested_storage_data(self.maximum)
                    .map_err(schema)?,
                growth,
                transient,
                Self::counter_scratch_data(),
            ],
            self.maximum,
        )
        .map(|_| ())
    }

    /// Counts the real header and every initialized partial allocation.
    ///
    /// Includes Self once. An enclosing inline slot subtracts that header when
    /// adding this result to a collector that already owns its fixed layout.
    ///
    /// # Errors
    /// Refuses foreign actor, unsupported defining layout, overflow or the bound.
    pub(in super::super::super) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let Self {
            process,
            thread,
            parent_index,
            parent_manifest,
            records,
            checkpoint,
            host,
            administrative,
            maximum: _,
            verified: _,
        } = self;
        if *process != std::process::id() || *thread != std::thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        let mut total = size_of::<Self>();
        let mut add = |next: usize| {
            total = total
                .checked_add(next)
                .filter(|total| *total <= maximum)
                .ok_or(RuntimeError::ResourceLimit)?;
            Ok::<_, RuntimeError>(())
        };
        for reference in [parent_index, parent_manifest].into_iter().flatten() {
            add(NodeRuntime::capture_reference_storage(reference)?)?;
        }
        for record in records {
            let HeaderRecord17 { value, canonical } = record;
            if let Some(value) = value {
                add(NodeRuntime::original_json_value_requested_storage_data(
                    value, maximum,
                )?)?;
            }
            if let Some(bytes) = canonical {
                add(bytes.capacity())?;
            }
        }
        if let Some(checkpoint) = checkpoint {
            add(checkpoint
                .retained_backing_requested_bytes_data()
                .map_err(|_| RuntimeError::ResourceLimit)?)?;
        }
        if let Some(host) = host {
            add(host.retained_requested_storage_data()?)?;
        }
        if let Some(administrative) = administrative {
            add(NodeRuntime::capture_admin_storage(administrative)?)?;
        }
        if total > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(total)
    }

    /// Names concrete borrowed plans, cursor/visitor controls and decoder headers.
    pub(in super::super::super) fn counter_scratch_data() -> usize {
        size_of::<ParentHeaderTerminal17<'static, 'static>>()
            + size_of::<ParentCurrent17ArchiveData<'static, 'static, 'static>>()
            + size_of::<HeaderRecord17>()
            + size_of::<Value>()
            + size_of::<Vec<u8>>()
            + size_of::<Result<Value, serde_json::Error>>()
            + size_of::<Result<Value, crucible_node_contract::ContractError>>()
            + size_of::<Result<Vec<u8>, crucible_node_contract::ContractError>>()
            + size_of::<Self>()
            + size_of::<&mut Option<Self>>()
            + size_of::<Result<usize, StateError>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<(), StateError>>()
            + size_of::<(&ContentRef, &[u8])>()
            + size_of::<Result<(&ContentRef, &[u8]), StateError>>()
            + size_of::<[HeaderRecord17; 3]>()
            + size_of::<[usize; 2]>()
            + size_of::<std::array::IntoIter<usize, 2>>()
            + size_of::<[usize; 4]>()
            + size_of::<std::array::IntoIter<usize, 4>>()
            + size_of::<[usize; 5]>()
            + size_of::<std::array::IntoIter<usize, 5>>()
            + size_of::<[usize; 6]>()
            + size_of::<std::array::IntoIter<usize, 6>>()
            + size_of::<std::slice::Iter<'static, HeaderRecord17>>()
            + size_of::<std::slice::Iter<'static, NativeOwnerState>>()
            + size_of::<std::iter::Flatten<std::array::IntoIter<&'static Option<ContentRef>, 2>>>()
            + size_of::<CoordinatorCommitmentCheckpoint17>()
            + size_of::<HostSchedulingRestoredContinuationRecord17>()
            + size_of::<RuntimeOriginalCaptureJournal>()
            + size_of::<Result<CoordinatorCommitmentCheckpoint17, StateError>>()
            + size_of::<Result<HostSchedulingRestoredContinuationRecord17, RuntimeError>>()
            + size_of::<Result<RuntimeOriginalCaptureJournal, StateError>>()
            + size_of::<HostSchedulingContinuationLimits>()
            + size_of::<HashRef>()
            + size_of::<&OwnerBinding>()
            + size_of::<blake3::Hasher>()
            + size_of::<blake3::Hash>()
            + size_of::<[u8; 64]>()
            + size_of::<[u8; 20]>()
            + core_decode_credit::scanner_storage()
            + NodeRuntime::original_json_value_counter_scratch_data()
            + NodeRuntime::capture_selected_json_decode_counter_scratch_data()
            + NodeRuntime::capture_serialization_counter_scratch_data()
            + CoordinatorCommitmentCheckpoint17::counter_scratch_data()
            + size_of::<crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::CoordinatorCheckpointStorageData17>()
            + size_of::<Result<crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::CoordinatorCheckpointStorageData17, crucible_node_provider::ProviderError>>()
            + crucible_node_provider::retained_metadata::serialization_storage::original_json_value_storage_extent_counter_scratch_data()
            + crate::node_contract::host_scheduling_restored_continuation_schema17_counter_scratch_data()
            + crucible_node_provider::reference_packet::service::native_snapshot::native_restored_settled17_snapshot_schema_counter_scratch_data()
            + join::counter_scratch_data()
            + admission::counter_scratch_data()
    }
}
