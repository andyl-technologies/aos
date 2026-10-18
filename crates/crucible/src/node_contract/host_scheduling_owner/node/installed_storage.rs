//! Counts actual selected Host restoration custody after admission/readiness.
//!
//! This raw observer renews no callback, live source, readiness or installation
//! permission. It counts the same archive ticket backing and every retained
//! admission/ready child. Unsupported capture/reclamation owners still refuse.

use super::*;
use crate::node_contract::runtime_owned_counter::{OwnedStorage, RetainedRuntimeCounter};
use crate::node_contract::{NodeRuntime, RuntimeError};
use std::mem::size_of;

impl PreparedHostSchedulingNode {
    pub(super) fn original_installed_restoration_node_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let Self {
            source,
            anchor,
            plan,
            activation,
            route,
            ready,
            retired: _,
            reclamation,
            restoration,
            restoration_installed: _,
            capture_preparation,
            capture_preparation17,
        } = self;
        if source.process != std::process::id()
            || source.owner_thread != std::thread::current().id()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        if source.original_ticket.is_some()
            || source.archive_ticket.is_none()
            || !source.node_created.get()
            || reclamation.is_some()
            || capture_preparation.is_some()
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let original_anchor = source
            .node
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if !std::rc::Weak::ptr_eq(&*original_anchor, &Rc::downgrade(anchor)) {
            return Err(RuntimeError::ForeignAuthority);
        }
        let mut counter = RetainedRuntimeCounter::new(maximum);
        counter.add(NodeRuntime::capture_host_node_metadata_storage(
            activation,
            route,
            ready.as_ref(),
        )?)?;
        let plan = plan.as_ref().ok_or(RuntimeError::UnsupportedFacet)?;
        plan.charge_original_retained_storage_precredit_data(&mut counter)?;
        if let Some(admission) = restoration {
            // These are the actual independently cloned admission fields. A
            // ready or installed flag never makes their retained backing zero.
            let preservation::HostRestorationAdmission {
                source,
                scheduling,
                target,
            } = admission;
            counter.add(source.owned_storage()?)?;
            counter.add(scheduling.owned_storage()?)?;
            counter.add(target.owned_storage()?)?;
        }
        if let Some(snapshot) = capture_preparation17 {
            counter.add(
                snapshot
                    .retained_requested_storage_data()?
                    .checked_sub(size_of::<
                        crate::node_contract::HostSchedulingRestoredContinuation17,
                    >())
                    .ok_or(RuntimeError::ResourceLimit)?,
            )?;
        }
        if counter.rc(source)? {
            counter.add(
                source.retained_ticket_metadata_bytes_excluding_runtime_precredit_data(maximum)?,
            )?;
        }
        Ok(counter.bytes())
    }

    pub(super) fn original_installed_restoration_counter_scratch_data() -> usize {
        size_of::<RetainedRuntimeCounter>()
            + size_of::<std::cell::Ref<'static, std::rc::Weak<()>>>()
            + size_of::<Result<std::cell::Ref<'static, std::rc::Weak<()>>, std::cell::BorrowError>>(
            )
            + size_of::<Result<std::cell::Ref<'static, std::rc::Weak<()>>, RuntimeError>>()
            + size_of::<std::rc::Weak<()>>()
            + size_of::<Option<&preservation::HostRestorationAdmission>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
    }
}
