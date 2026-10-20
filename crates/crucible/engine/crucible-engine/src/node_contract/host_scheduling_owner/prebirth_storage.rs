//! Observes only genuine unprepared complete Host sources before native birth.
//!
//! The archive tuple counts its same verified source separately. These methods
//! issue no preparation, attachment, scheduler or native permission.

use super::*;
use crate::node_contract::NodeRuntime;
use crate::node_state::CompleteOriginalSource;

impl HostSchedulingSource {
    /// Authenticates original complete Host data before any node or attachment.
    ///
    /// This phase check reads only raw creator IDs and retained ownership state.
    /// It allocates nothing and calls no graph/runtime/policy callback.
    /// Metadata credit remains separate.
    ///
    /// # Errors
    /// Refuses another creator/edition, historical tickets, a spent or revoked
    /// preparation phase, busy ownership loans or any retained attached owner.
    pub fn authenticate_original_report_startup_data(&self) -> Result<(), RuntimeError> {
        self.authenticate_prebirth_storage_data(None)
    }

    pub(crate) fn authenticate_archive_report_startup_data(
        &self,
        archive: &Rc<CompleteOriginalSource>,
    ) -> Result<(), RuntimeError> {
        self.authenticate_prebirth_storage_data(Some(archive))
    }

    pub(super) fn authenticate_prebirth_storage_data(
        &self,
        archive: Option<&Rc<CompleteOriginalSource>>,
    ) -> Result<(), RuntimeError> {
        // Raw creator checks precede all RefCell loans, including refusal paths.
        if self.process != std::process::id() || self.owner_thread != thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.edition != preservation::Edition::CompleteOriginalLineage
            || self.original_ticket.is_some()
            || self.revoked.get()
            || self.node_created.get()
            || self.attachment_attempted.get()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        match (&self.archive_ticket, archive) {
            (None, None) => {}
            (Some(ticket), Some(expected)) if Rc::ptr_eq(&ticket.source, expected) => {
                ticket.authenticate_birth()?;
            }
            _ => return Err(RuntimeError::ForeignAuthority),
        }
        if self
            .attached
            .try_borrow()
            .map_err(|_| RuntimeError::OutstandingObligations)?
            .is_some()
            || self
                .capture_dependencies
                .try_borrow()
                .map_err(|_| RuntimeError::OutstandingObligations)?
                .is_some()
            || self
                .node
                .try_borrow()
                .map_err(|_| RuntimeError::OutstandingObligations)?
                .strong_count()
                != 0
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    pub(crate) fn retained_archive_prebirth_host_storage_data(
        self: &Rc<Self>,
        archive: &Rc<CompleteOriginalSource>,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.authenticate_archive_report_startup_data(archive)?;
        let total = self.retained_prebirth_host_metadata_data(maximum)?;
        self.authenticate_archive_report_startup_data(archive)?;
        Ok(total)
    }

    pub(super) fn retained_prebirth_host_metadata_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        if self.process != std::process::id() || self.owner_thread != thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        let selection = NodeRuntime::capture_host_selection_storage(&self.selection)?
            .checked_sub(std::mem::size_of::<HostSchedulingSelection>())
            .ok_or(RuntimeError::ResourceLimit)?;
        let world = NodeRuntime::capture_hash_storage(&self.world)?;
        // The caller authenticates prebirth emptiness and any SAME archive Rc.
        // Only selection/world/token/facet children remain beneath this root.
        NodeRuntime::capture_shared_allocation_storage::<Self>()
            .checked_add(selection)
            .and_then(|n| n.checked_add(world))
            .and_then(|n| n.checked_add(self.prepared_token.allocated_capacity()))
            .and_then(|n| {
                n.checked_add(
                    self.preservation_facet
                        .as_ref()
                        .map_or(0, |f| f.retained_requested_storage()),
                )
            })
            .filter(|n| *n <= maximum)
            .ok_or(RuntimeError::ResourceLimit)
    }
}
