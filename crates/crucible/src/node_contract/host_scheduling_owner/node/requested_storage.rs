//! Observes actual original node-owned fields before the administrative callback.
//!
//! Source backing is charged through its original Rc by the daemon owner walk.
//! The node's original plan backing is conservatively charged again per view;
//! this explicit overlap does not grant an allocation-identity refund.

use super::*;
use crate::node_contract::{NodeRuntime, RuntimeError};

impl PreparedHostSchedulingNode {
    pub(super) fn original_retained_node_backing(
        &self,
        maximum: usize,
    ) -> Result<usize, OperationFailure> {
        use crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter;
        // Reuse the exact existing supported phase fence without treating its
        // partial metadata total as this node's complete retained owner row.
        self.retained_requested_storage_excluding_source()?;
        let result = (|| -> Result<usize, RuntimeError> {
            let mut counter = RetainedRuntimeCounter::new(maximum);
            counter.add(NodeRuntime::capture_host_node_metadata_storage(
                &self.activation,
                &self.route,
                self.ready.as_ref(),
            )?)?;
            if let Some(plan) = &self.plan {
                plan.charge_original_retained_storage(&mut counter)?;
            }
            if counter.rc(&self.source)? {
                let source = self
                    .source
                    .retained_original_metadata_bytes_excluding_runtime(maximum)
                    .map_err(|_| RuntimeError::UnsupportedFacet)?;
                counter.add(source)?;
            }
            // The source's Weak anchor visitor already includes this actual
            // unit allocation. Its alias here owns no independent child heaps.
            Ok(counter.bytes())
        })()
        .map_err(failure)?;
        self.current()?;
        Ok(result)
    }

    pub(in crate::node_contract::host_scheduling_owner) fn retained_requested_storage_excluding_source(
        &self,
    ) -> Result<usize, OperationFailure> {
        self.current()?;
        if self.source.original_ticket.is_some()
            || self.source.archive_ticket.is_some()
            || self.retired
            || self.reclamation.is_some()
            || self.restoration.is_some()
            || self.restoration_installed
            || self.capture_preparation.is_some()
            || self.capture_preparation17.is_some()
        {
            return Err(failure(
                "complete original Host node storage is not in its stable capture phase",
            ));
        }
        let total = (|| -> Result<usize, RuntimeError> {
            // The original anchor's shared allocation is counted by the source's
            // retained Weak link; this concrete Box owns only the node inline.
            let mut total = std::mem::size_of::<Self>();
            total = total
                .checked_add(NodeRuntime::capture_host_node_metadata_storage(
                    &self.activation,
                    &self.route,
                    self.ready.as_ref(),
                )?)
                .ok_or(RuntimeError::ResourceLimit)?;
            if let Some(plan) = &self.plan {
                total = total
                    .checked_add(
                        plan.retained_allocation_bytes_excluding_authority()
                            .map_err(|_| RuntimeError::ResourceLimit)?,
                    )
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
            Ok(total)
        })()
        .map_err(failure)?;
        self.current()?;
        Ok(total)
    }
}

impl PreparedHostSchedulingNode {
    pub(super) fn original_dormant_node_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        use crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter;
        let Self {
            source: _,
            anchor: _,
            plan: _,
            activation: _,
            route: _,
            ready: _,
            retired: _,
            reclamation: _,
            restoration: _,
            restoration_installed: _,
            capture_preparation: _,
            capture_preparation17: _,
        } = self;
        if self.source.process != std::process::id()
            || self.source.owner_thread != std::thread::current().id()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.ready.is_some()
            || self.reclamation.is_some()
            || self.restoration.is_some()
            || self.restoration_installed
            || self.capture_preparation.is_some()
            || self.capture_preparation17.is_some()
            || self.source.original_ticket.is_some()
            || self.source.archive_ticket.is_some()
            || !self.source.node_created.get()
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let original_anchor = self
            .source
            .node
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if !std::rc::Weak::ptr_eq(&*original_anchor, &Rc::downgrade(&self.anchor)) {
            return Err(RuntimeError::ForeignAuthority);
        }
        let mut counter = RetainedRuntimeCounter::new(maximum);
        counter.add(NodeRuntime::capture_host_node_metadata_storage(
            &self.activation,
            &self.route,
            None,
        )?)?;
        if let Some(plan) = &self.plan {
            plan.charge_original_retained_storage_precredit_data(&mut counter)?;
        } else {
            return Err(RuntimeError::UnsupportedFacet);
        }
        if counter.rc(&self.source)? {
            counter.add(
                self.source
                    .retained_original_metadata_bytes_excluding_runtime_precredit_data(maximum)?,
            )?;
        }
        Ok(counter.bytes())
    }
}

impl PreparedHostSchedulingNode {
    pub(super) fn original_dormant_restoration_node_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        use crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter;
        let Self {
            source: _,
            anchor: _,
            plan: _,
            activation: _,
            route: _,
            ready: _,
            retired: _,
            reclamation: _,
            restoration: _,
            restoration_installed: _,
            capture_preparation: _,
            capture_preparation17: _,
        } = self;
        if self.source.process != std::process::id()
            || self.source.owner_thread != std::thread::current().id()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.ready.is_some()
            || self.reclamation.is_some()
            || self.restoration.is_some()
            || self.restoration_installed
            || self.capture_preparation.is_some()
            || self.capture_preparation17.is_some()
            || self.source.original_ticket.is_some()
            || self.source.archive_ticket.is_none()
            || !self.source.node_created.get()
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let original_anchor = self
            .source
            .node
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if !std::rc::Weak::ptr_eq(&*original_anchor, &Rc::downgrade(&self.anchor)) {
            return Err(RuntimeError::ForeignAuthority);
        }
        let mut counter = RetainedRuntimeCounter::new(maximum);
        counter.add(NodeRuntime::capture_host_node_metadata_storage(
            &self.activation,
            &self.route,
            None,
        )?)?;
        if let Some(plan) = &self.plan {
            plan.charge_original_retained_storage_precredit_data(&mut counter)?;
        } else {
            return Err(RuntimeError::UnsupportedFacet);
        }
        if counter.rc(&self.source)? {
            counter.add(
                self.source
                    .retained_ticket_metadata_bytes_excluding_runtime_precredit_data(maximum)?,
            )?;
        }
        Ok(counter.bytes())
    }
}
