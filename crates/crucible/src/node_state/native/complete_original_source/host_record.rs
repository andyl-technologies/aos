//! Keeps genuine initial Host2 and current Host17 records in distinct owners.

use super::*;
use crate::node_contract::{
    HostSchedulingRestoredContinuationRecord17, HostSchedulingSelection, NodeRuntime,
};
use crate::node_scheduling::{InputPayload, SchedulingSnapshot};

pub(super) enum CompleteHostArchiveRecord {
    InitialInvocation15(Rc<HostSchedulingContinuationRecord>),
    Settled17(Rc<HostSchedulingRestoredContinuationRecord17>),
}

impl CompleteHostArchiveRecord {
    pub(super) fn selection_data(&self) -> &HostSchedulingSelection {
        match self {
            Self::InitialInvocation15(record) => &record.source,
            Self::Settled17(record) => &record.source,
        }
    }

    pub(super) fn runtime_data(&self) -> Result<&OriginalLineageRuntimeRecord, RuntimeError> {
        match self {
            Self::InitialInvocation15(record) => match &record.runtime {
                HostSchedulingRuntimeRecord::OriginalLineage(runtime) => Ok(runtime),
                HostSchedulingRuntimeRecord::Legacy(_) => Err(RuntimeError::UnsupportedFacet),
            },
            Self::Settled17(record) => Ok(&record.runtime),
        }
    }

    pub(super) fn scheduling_data(&self) -> &SchedulingSnapshot {
        match self {
            Self::InitialInvocation15(record) => &record.scheduling,
            Self::Settled17(record) => &record.scheduling,
        }
    }

    pub(super) fn objects_data(&self) -> &[InputPayload] {
        match self {
            Self::InitialInvocation15(record) => &record.objects,
            Self::Settled17(record) => &record.objects,
        }
    }

    pub(super) fn initial_data(&self) -> Result<&HostSchedulingContinuationRecord, RuntimeError> {
        match self {
            Self::InitialInvocation15(record) => Ok(record),
            Self::Settled17(_) => Err(RuntimeError::UnsupportedFacet),
        }
    }

    pub(super) fn restored_data(
        &self,
    ) -> Result<&HostSchedulingRestoredContinuationRecord17, RuntimeError> {
        match self {
            Self::InitialInvocation15(_) => Err(RuntimeError::UnsupportedFacet),
            Self::Settled17(record) => Ok(record),
        }
    }

    pub(super) fn retained_storage_data(&self) -> Result<usize, RuntimeError> {
        let (root, backing) = match self {
            Self::InitialInvocation15(record) => (
                NodeRuntime::capture_shared_allocation_storage::<HostSchedulingContinuationRecord>(
                ),
                NodeRuntime::capture_host_record_storage(record)?,
            ),
            Self::Settled17(record) => (
                NodeRuntime::capture_shared_allocation_storage::<
                    HostSchedulingRestoredContinuationRecord17,
                >(),
                record.retained_requested_storage_data()?,
            ),
        };
        root.checked_add(backing).ok_or(RuntimeError::ResourceLimit)
    }
}

impl serde::Serialize for CompleteHostArchiveRecord {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::InitialInvocation15(record) => {
                serde::Serialize::serialize(record.as_ref(), serializer)
            }
            Self::Settled17(record) => serde::Serialize::serialize(record.as_ref(), serializer),
        }
    }
}

impl crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityWalk
    for CompleteHostArchiveRecord
{
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn FnMut(
            crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityRow,
        ) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        use crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityWalk;
        match self {
            Self::InitialInvocation15(record) => record.as_ref().capacities(depth, sink),
            Self::Settled17(record) => record.as_ref().capacities(depth, sink),
        }
    }
}

impl CompleteOriginalRestorationSource {
    /// Borrows the archived scheduler snapshot from its genuine Host record.
    ///
    /// The initial and settled archive families retain their distinct records.
    /// This historical data loan does not create a live scheduler permission.
    ///
    /// # Errors
    ///
    /// Returns an error when the Source has foreign process or thread custody.
    pub(crate) fn historical_host_scheduling_data(
        &self,
    ) -> Result<&SchedulingSnapshot, RuntimeError> {
        self.inner.authenticate_birth()?;
        Ok(self.inner.host.scheduling_data())
    }
}
