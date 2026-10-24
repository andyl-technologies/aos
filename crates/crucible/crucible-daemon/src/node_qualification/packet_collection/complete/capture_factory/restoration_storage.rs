//! Observes the exact unused fresh capture factory during its restoration action.
//!
//! Capture records and dependency/actor callback loans are unsupported in this
//! phase. Their absence is checked intrinsically, not supplied by the caller.
//! The actual authority, plan and Host source are counted; separately observed
//! native Source3 and runtime owners receive no implicit alias refund.

use super::*;
use crate::node_qualification::QualificationError;
use crate::node_qualification::packet_collection::complete::retained::Counter;
use crucible_engine::node_contract::RuntimeError;

impl PacketCompleteCaptureFactory {
    pub(super) fn original_unobserved_restoration_storage_data(
        self: &Rc<Self>,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let Self {
            authority,
            plan,
            host,
            limits: _,
            records,
            process,
            thread,
            actor_storage_loan,
            dependency_storage,
        } = self.as_ref();
        if *process != std::process::id() || *thread != std::thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        authority
            .capture_graph_policy()
            .authenticate_retained_origin_data()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        if records
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .is_some()
            || actor_storage_loan
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .is_some()
            || dependency_storage
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .is_some()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let mut counter = Counter::new(maximum);
        counter.rc(self).map_err(storage_error)?;
        if counter.rc(authority).map_err(storage_error)? {
            authority
                .charge_retained_storage(&mut counter)
                .map_err(storage_error)?;
        }
        if counter.rc(plan).map_err(storage_error)? {
            counter
                .add(plan.retained_allocation_bytes_excluding_authority_precredit_data()?)
                .map_err(storage_error)?;
        }
        if counter.rc(host).map_err(storage_error)? {
            counter
                .add(
                    host.retained_original_metadata_bytes_excluding_runtime_precredit_data(
                        counter.remaining(),
                    )?,
                )
                .map_err(storage_error)?;
        }
        if let Some(scene) = authority
            .original_execution_scene_storage_data()
            .map_err(|_| RuntimeError::ForeignAuthority)?
        {
            if counter.rc(&scene).map_err(storage_error)? {
                scene
                    .charge_retained_storage(&mut counter)
                    .map_err(storage_error)?;
            }
        }
        authority
            .capture_graph_policy()
            .authenticate_retained_origin_data()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        Ok(counter.bytes())
    }

    pub(super) fn original_unobserved_restoration_descriptor_data(
        &self,
    ) -> Result<usize, RuntimeError> {
        let Self {
            authority,
            plan: _,
            host: _,
            limits: _,
            records,
            process,
            thread,
            actor_storage_loan,
            dependency_storage,
        } = self;
        if *process != std::process::id() || *thread != std::thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if records
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .is_some()
            || actor_storage_loan
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .is_some()
            || dependency_storage
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .is_some()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        authority
            .capture_graph_policy()
            .authenticate_retained_origin_data()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        // These are actual retained CurrentFiles descriptors, not configured
        // descriptor credits. The Host source/archive graphs add no OS handle.
        authority
            .capture_graph_policy()
            .original_initial_retained_descriptors_data()
    }
}

fn storage_error(_: QualificationError) -> RuntimeError {
    RuntimeError::ResourceLimit
}
