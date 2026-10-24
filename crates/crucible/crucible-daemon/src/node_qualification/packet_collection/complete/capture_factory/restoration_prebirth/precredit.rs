//! Borrows the actual unbound archive/Host tuple with raw precredit errors.

use super::*;
use crucible_engine::node_contract::RuntimeError;

impl PacketCompleteRestorationPrebirth {
    pub(in crate::node_qualification::packet_collection::complete) fn retained_fresh_host_archive_precredit_data(
        &self,
        expected_host: &Rc<crucible_engine::node_contract::HostSchedulingSource>,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        if self.binding_attempted
            || self.runtime_attempted
            || self.fresh_graph.is_some()
            || self.fresh_factory.is_some()
            || self.runtime.is_some()
            || self.failed_runtime.is_some()
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let host = self
            .host
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .source();
        if !Rc::ptr_eq(&host, expected_host) {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.source
            .retained_original_prebirth_storage_data(&host, maximum)
    }
}

impl PacketCompleteRestorationPrebirth {
    pub(in crate::node_qualification::packet_collection::complete) fn retained_host_holder_precredit_data(
        &self,
        original: &Rc<RefCell<Self>>,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        let host = self
            .host
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .source();
        let mut counter = super::super::super::retained::Counter::new(maximum);
        if let Some(publication) = &self.publication {
            counter
                .add(publication.retained_storage_data(counter.remaining())?)
                .map_err(|_| RuntimeError::ResourceLimit)?;
        }
        if let Some(results) = &self.restored_results {
            results
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .charge_retained_storage_data(&mut counter)?;
        }
        if self.restored_results.is_some() {
            Self::charge_restored_actions_data(&self.restored_actions, &mut counter)?;
        }
        counter
            .add(
                self.initial15_control
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?
                    .retained_requested_storage_data(counter.remaining())?,
            )
            .map_err(|_| RuntimeError::ResourceLimit)?;
        counter
            .rc(original)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        if let Some(holder) = &self.report_startup_holder {
            counter
                .weak(holder)
                .map_err(|_| RuntimeError::ResourceLimit)?;
        }
        counter
            .add(self.retained_fresh_host_archive_precredit_data(&host, counter.remaining())?)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        counter
            .add(
                self.factory
                    .retained_host_precredit_data(counter.remaining())?,
            )
            .map_err(|_| RuntimeError::ResourceLimit)?;
        counter
            .rc(&self.code_graph)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let allowance = counter
            .remaining()
            .checked_add(std::mem::size_of_val(self.code_graph.as_ref()))
            .ok_or(RuntimeError::ResourceLimit)?;
        let graph = self
            .code_graph
            .original_retained_requested_storage_data(allowance)?;
        counter
            .add(
                graph
                    .checked_sub(std::mem::size_of_val(self.code_graph.as_ref()))
                    .ok_or(RuntimeError::ResourceLimit)?,
            )
            .map_err(|_| RuntimeError::ResourceLimit)?;
        Ok(counter.bytes())
    }
}

impl PacketCompleteRestorationPrebirth {
    pub(in crate::node_qualification::packet_collection::complete) fn authenticate_native_startup_target_precredit_data(
        &self,
        authority: &InstalledPacketCompleteCollectionAuthority,
        plan: &InstalledConformancePlan,
    ) -> Result<(), RuntimeError> {
        // Authenticate raw creators before following the archive/factory graph.
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        let factory = &self.factory.inner;
        if factory.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if factory.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        factory
            .authority
            .capture_graph_policy()
            .authenticate_retained_origin_data()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        if std::ptr::eq(authority, factory.authority.as_ref())
            || self.binding_attempted
            || self.runtime_attempted
            || self.runtime.is_some()
            || self.failed_runtime.is_some()
            || self.fresh_graph.is_some()
            || self.fresh_factory.is_some()
            || self.native.iter().any(Option::is_none)
            || self.host_ticket.is_some()
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let host = self
            .host
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .source();
        if !Rc::ptr_eq(&host, authority.host_source()) {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.source
            .authenticate_original_prebirth_host_data(&host)?;
        let historical = self.code_graph.plan().evidence();
        let fresh = plan.evidence();
        if historical.plan_ref != fresh.plan_ref
            || historical.refused_ref != fresh.refused_ref
            || historical.sources != fresh.sources
            || historical.world != fresh.world
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        for (ticket, source) in self.native.iter().zip(&authority.roster().sources) {
            if ticket
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .owner()?
                .owner
                != source.installation().owner.owner.id
            {
                return Err(RuntimeError::ForeignAuthority);
            }
        }
        Ok(())
    }
}
