//! Counts a fresh unused capture factory with its real archive-backed Host.
//!
//! The original-only factory visitor remains separate. This observer requires
//! the same source ticket and retains unknown loan/record states as refusals.

use super::*;
use crate::node_qualification::packet_collection::complete::retained::Counter;
use crucible_engine::{node_contract::RuntimeError, node_state::CompleteOriginalRestorationSource};
use std::mem::size_of;

impl PacketCompleteCaptureFactory {
    pub(super) fn original_ticketed_unobserved_restoration_storage_data(
        self: &Rc<Self>,
        archive: &CompleteOriginalRestorationSource,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.authority
            .capture_graph_policy()
            .authenticate_retained_origin_data()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        if self
            .records
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .is_some()
            || self
                .actor_storage_loan
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .is_some()
            || self
                .dependency_storage
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .is_some()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let mut counter = Counter::new(maximum);
        counter.rc(self).map_err(storage_error)?;
        if counter.rc(&self.authority).map_err(storage_error)? {
            self.authority
                .charge_report_startup_retained_storage(&mut counter)
                .map_err(storage_error)?;
        }
        if counter.rc(&self.plan).map_err(storage_error)? {
            counter
                .add(
                    self.plan
                        .retained_allocation_bytes_excluding_authority_precredit_data()?,
                )
                .map_err(storage_error)?;
        }
        if counter.rc(&self.host).map_err(storage_error)? {
            counter
                .add(
                    self.host
                        .retained_restoration_metadata_bytes_excluding_runtime_precredit_data(
                            archive,
                            counter.remaining(),
                        )?,
                )
                .map_err(storage_error)?;
        }
        if let Some(scene) = self
            .authority
            .original_execution_scene_storage_data()
            .map_err(|_| RuntimeError::ForeignAuthority)?
        {
            if counter.rc(&scene).map_err(storage_error)? {
                scene
                    .charge_retained_storage(&mut counter)
                    .map_err(storage_error)?;
            }
        }
        Ok(counter.bytes())
    }

    pub(super) fn original_ticketed_unobserved_counter_scratch_data() -> usize {
        HostSchedulingSource::retained_restoration_metadata_counter_scratch_data()
            + size_of::<Counter>()
            + size_of::<&Rc<Self>>()
            + size_of::<&CompleteOriginalRestorationSource>()
            + size_of::<&Rc<HostSchedulingSource>>()
            + size_of::<std::cell::Ref<'_, Option<PacketCompleteCaptureRecords>>>()
            + size_of::<Result<std::cell::Ref<'_, Option<PacketCompleteCaptureRecords>>, std::cell::BorrowError>>()
            + size_of::<Result<std::cell::Ref<'_, Option<PacketCompleteCaptureRecords>>, RuntimeError>>()
            + size_of::<std::cell::Ref<'_, Option<retained::ActorStorageLoanState>>>()
            + size_of::<Result<std::cell::Ref<'_, Option<retained::ActorStorageLoanState>>, std::cell::BorrowError>>()
            + size_of::<Result<std::cell::Ref<'_, Option<retained::ActorStorageLoanState>>, RuntimeError>>()
            + size_of::<std::cell::Ref<'_, Option<dependencies::OriginalDependencyStorageScope>>>()
            + size_of::<Result<std::cell::Ref<'_, Option<dependencies::OriginalDependencyStorageScope>>, std::cell::BorrowError>>()
            + size_of::<Result<std::cell::Ref<'_, Option<dependencies::OriginalDependencyStorageScope>>, RuntimeError>>()
            + size_of::<Option<Rc<crate::node_qualification::packet_collection::complete::PacketCompleteExecutionScene>>>()
            + size_of::<Result<Option<Rc<crate::node_qualification::packet_collection::complete::PacketCompleteExecutionScene>>, crate::node_qualification::QualificationError>>()
            + size_of::<Result<Option<Rc<crate::node_qualification::packet_collection::complete::PacketCompleteExecutionScene>>, RuntimeError>>()
            + size_of::<Result<usize, crate::node_qualification::QualificationError>>()
            + size_of::<Result<bool, crate::node_qualification::QualificationError>>()
            + size_of::<Result<(), crate::node_qualification::QualificationError>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + 2 * size_of::<usize>()
    }
}

fn storage_error(_: crate::node_qualification::QualificationError) -> RuntimeError {
    RuntimeError::ResourceLimit
}
