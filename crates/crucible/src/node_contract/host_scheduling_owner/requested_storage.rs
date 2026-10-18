//! Observes the actual original complete Host2 source's owned metadata.
//!
//! The enclosing Rc and actual host-node allocation are caller-owned terms.
//! Scheduler/activation payloads are shared Core owners, not source copies.
//! Weak links retain their control-block allocations even after the live owner
//! is gone; those inline shared roots receive conservative per-view credit.

use super::*;
use crate::node_contract::{NodeRuntime, RuntimeError};

impl HostSchedulingSource {
    /// Counts original complete-source metadata without following shared runtime storage.
    ///
    /// This observes actual capacities and grants no preparation, attachment or
    /// Capture authority. The caller charges this source's actual enclosing Rc
    /// once and separately admits the owning runtime/node/scheduler backings.
    /// Revocation does not free retained metadata, so this data-only observation
    /// does not require a live scheduler or renew a revoked source. Shared weak
    /// root layouts receive conservative per-view credit, never a data clone.
    /// Historical ticket-backed source ownership needs its distinct observer;
    /// it is never silently treated as a zero-byte original source.
    ///
    /// # Errors
    /// Refuses foreign/unsupported sources, historical tickets, busy
    /// attachment storage, unsupported metadata or arithmetic/total overflow.
    pub fn retained_original_metadata_bytes_excluding_runtime(
        &self,
        maximum: usize,
    ) -> Result<usize, OperationFailure> {
        if self.process != std::process::id()
            || self.owner_thread != thread::current().id()
            || self.edition != preservation::Edition::CompleteOriginalLineage
        {
            return Err(failure(
                "complete source metadata belongs to another creator or edition",
            ));
        }
        if self.original_ticket.is_some() || self.archive_ticket.is_some() {
            return Err(failure(
                "historical Host source backing is not an original metadata view",
            ));
        }
        self.retained_original_metadata_bytes_excluding_runtime_precredit_data(maximum)
            .map_err(failure)
    }

    /// Counts the same original Host metadata with allocation-free error values.
    ///
    /// The caller separately admits this observer's fixed scratch and enclosing
    /// Rc storage. This never renews native, scheduler or restoration currency.
    ///
    /// # Errors
    /// Refuses foreign creator or thread, unsupported edition/historical tickets,
    /// busy owners, unsupported metadata or checked storage exhaustion.
    pub fn retained_original_metadata_bytes_excluding_runtime_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        if self.process != std::process::id()
            || self.owner_thread != thread::current().id()
            || self.edition != preservation::Edition::CompleteOriginalLineage
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.original_ticket.is_some() || self.archive_ticket.is_some() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let bytes = (|| -> Result<usize, RuntimeError> {
            let selection = NodeRuntime::capture_host_selection_storage(&self.selection)?
                .checked_sub(std::mem::size_of::<HostSchedulingSelection>())
                .ok_or(RuntimeError::ResourceLimit)?;
            let mut total = selection
                .checked_add(NodeRuntime::capture_hash_storage(&self.world)?)
                .and_then(|bytes| bytes.checked_add(self.prepared_token.allocated_capacity()))
                .ok_or(RuntimeError::ResourceLimit)?;
            if self.node_created.get() {
                // The original Weak retains this allocation after node drop.
                total = total
                    .checked_add(NodeRuntime::capture_shared_allocation_storage::<()>())
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
            if let Some(facet) = &self.preservation_facet {
                total = total
                    .checked_add(facet.retained_requested_storage())
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
            let attached = self
                .attached
                .try_borrow()
                .map_err(|_| RuntimeError::OutstandingObligations)?;
            if let Some(attached) = attached.as_ref() {
                total = total
                    .checked_add(attached.retained_metadata_bytes_excluding_runtime()?)
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
            total = total
                .checked_add(self.retained_dependency_storage()?)
                .ok_or(RuntimeError::ResourceLimit)?;
            if total > maximum {
                return Err(RuntimeError::ResourceLimit);
            }
            Ok(total)
        })()?;
        Ok(bytes)
    }
}

impl HostSchedulingSource {
    /// Names fixed borrowed views used by the raw original metadata observer.
    ///
    /// These are logical counter/borrow headers, excluding compiler recursion,
    /// allocator residency and the independently counted shared runtime owner.
    pub fn retained_original_metadata_counter_scratch_data() -> usize {
        std::mem::size_of::<std::cell::Ref<'static, Option<OriginalSchedulingSource>>>()
            + std::mem::size_of::<
                std::cell::Ref<
                    'static,
                    Option<Rc<capture_dependencies::OriginalHostDependencyPlan>>,
                >,
            >()
            + std::mem::size_of::<[usize; 8]>()
    }
}

impl HostSchedulingSource {
    /// Counts the same archive-ticket-backed Host source before restoration effects.
    ///
    /// The actual ticket must retain the supplied source allocation. This raw
    /// observation includes its archive backing and follows no live callback;
    /// revocation never erases retained ownership or renews effect authority.
    /// The enclosing Host source Rc and shared runtime remain caller terms.
    ///
    /// # Errors
    /// Refuses foreign creators, a different archive, unsupported phases, busy
    /// ownership loans and arithmetic or storage exhaustion.
    pub fn retained_restoration_metadata_bytes_excluding_runtime_precredit_data(
        &self,
        archive: &crate::node_state::CompleteOriginalRestorationSource,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let ticket = self
            .archive_ticket
            .as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?;
        if !Rc::ptr_eq(&ticket.source, &archive.inner) {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.retained_ticket_metadata_bytes_excluding_runtime_precredit_data(maximum)
    }

    pub(super) fn retained_ticket_metadata_bytes_excluding_runtime_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        if self.process != std::process::id()
            || self.owner_thread != thread::current().id()
            || self.edition != preservation::Edition::CompleteOriginalLineage
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.original_ticket.is_some() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let ticket = self
            .archive_ticket
            .as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?;
        ticket.authenticate_birth()?;
        let bytes = (|| -> Result<usize, RuntimeError> {
            let selection = NodeRuntime::capture_host_selection_storage(&self.selection)?
                .checked_sub(std::mem::size_of::<HostSchedulingSelection>())
                .ok_or(RuntimeError::ResourceLimit)?;
            let mut total = selection
                .checked_add(NodeRuntime::capture_hash_storage(&self.world)?)
                .and_then(|bytes| bytes.checked_add(self.prepared_token.allocated_capacity()))
                .ok_or(RuntimeError::ResourceLimit)?;
            if self.node_created.get() {
                // The original Weak retains this allocation after node drop.
                total = total
                    .checked_add(NodeRuntime::capture_shared_allocation_storage::<()>())
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
            if let Some(facet) = &self.preservation_facet {
                total = total
                    .checked_add(facet.retained_requested_storage())
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
            let attached = self
                .attached
                .try_borrow()
                .map_err(|_| RuntimeError::OutstandingObligations)?;
            if let Some(attached) = attached.as_ref() {
                total = total
                    .checked_add(attached.retained_metadata_bytes_excluding_runtime()?)
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
            total = total
                .checked_add(self.retained_archive_capture_dependency_storage_data()?)
                .ok_or(RuntimeError::ResourceLimit)?;
            total = total
                .checked_add(ticket.source.capture_owned_storage()?)
                .ok_or(RuntimeError::ResourceLimit)?;
            if total > maximum {
                return Err(RuntimeError::ResourceLimit);
            }
            Ok(total)
        })()?;
        Ok(bytes)
    }

    /// Names the fixed views of the archive-ticket-backed raw Host census.
    pub fn retained_restoration_metadata_counter_scratch_data() -> usize {
        Self::retained_original_metadata_counter_scratch_data()
            + std::mem::size_of::<Option<&crate::node_state::CompleteOriginalHostTicket>>()
            + std::mem::size_of::<
                Result<&crate::node_state::CompleteOriginalHostTicket, RuntimeError>,
            >()
            + std::mem::size_of::<Result<usize, RuntimeError>>()
            + std::mem::size_of::<Result<(), RuntimeError>>()
    }
}
