//! Observes the original never-born code factory without formatted failures.

use super::*;
use crate::node_qualification::QualificationError;
use crate::node_qualification::packet_collection::complete::retained::Counter;
use crucible_engine::node_contract::RuntimeError;

impl PacketCompleteArchiveCodeFactory {
    pub(in crate::node_qualification::packet_collection::complete) fn retained_host_precredit_data(
        self: &Rc<Self>,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        if self.inner.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.inner.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        self.inner
            .authority
            .capture_graph_policy()
            .authenticate_retained_origin_data()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        // This exact code-purpose inner factory never owns a live actor, cached
        // Capture or dependency loan. A changed phase remains unknown/refused.
        if self
            .inner
            .records
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .is_some()
            || self
                .inner
                .actor_storage_loan
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .is_some()
            || self
                .inner
                .dependency_storage
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .is_some()
            || self
                .inner
                .authority
                .original_execution_scene_storage_data()
                .map_err(|_| RuntimeError::ForeignAuthority)?
                .is_some()
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let mut counter = Counter::new(maximum);
        counter.rc(self).map_err(storage_failure)?;
        if let Some(graph) = self
            .graph
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .as_ref()
        {
            counter.weak(graph).map_err(storage_failure)?;
        }
        counter.rc(&self.inner).map_err(storage_failure)?;
        if counter.rc(&self.inner.authority).map_err(storage_failure)? {
            counter
                .add(
                    self.inner
                        .authority
                        .original_retained_requested_storage_precredit_data(counter.remaining())?,
                )
                .map_err(storage_failure)?;
        }
        if counter.rc(&self.inner.plan).map_err(storage_failure)? {
            counter
                .add(
                    self.inner
                        .plan
                        .retained_allocation_bytes_excluding_authority_precredit_data()?,
                )
                .map_err(storage_failure)?;
        }
        for source in &self.inner.authority.roster().sources {
            counter
                .add(
                    source.original_complete_code_retained_storage_precredit_data(
                        counter.remaining(),
                    )?,
                )
                .map_err(storage_failure)?;
            if let Some(bytes) = source
                .original_effect_receiver_retained_storage_precredit_data(counter.remaining())?
            {
                counter.add(bytes).map_err(storage_failure)?;
            }
        }
        Ok(counter.bytes())
    }
}

fn storage_failure(_: QualificationError) -> RuntimeError {
    RuntimeError::ResourceLimit
}
