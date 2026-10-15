//! Borrows the actual unbound archive/Host tuple with raw precredit errors.

use super::*;
use crucible::node_contract::RuntimeError;

impl PacketCompleteRestorationPrebirth {
    pub(in crate::node_qualification::packet_collection::complete) fn retained_fresh_host_archive_precredit_data(
        &self,
        expected_host: &Rc<crucible::node_contract::HostSchedulingSource>,
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
