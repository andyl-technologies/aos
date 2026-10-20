//! Binds a moved initial node to its same retained host-query ticket.
//!
//! The query occurrence remains spent. These raw correspondence checks neither
//! recheck preparation phase nor call the installed holder authority.

use super::*;

impl CompleteOriginalFreshRestoreHostWindow {
    /// Matches the spent ticket to its same moved initial node owners.
    ///
    /// # Errors
    /// Refuses foreign origin, an unspent ticket or changed Source, plan or read owner.
    pub(crate) fn authenticate_original_initial_node_owner_data(
        &self,
        source: &Rc<PacketCompleteSemanticSource>,
        plan: &InstalledConformancePlan,
        original_owner: *const (),
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        if !self.spent || self.original_owner != original_owner {
            return Err(RuntimeError::ForeignAuthority);
        }
        let original_source = self
            .source
            .upgrade()
            .ok_or(RuntimeError::ForeignAuthority)?;
        let original_plan = self
            .plan
            .0
            .upgrade()
            .map(InstalledConformancePlan)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if !Rc::ptr_eq(&original_source, source) || !original_plan.is_same_original_plan_data(plan)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    /// Names the raw ticket comparison's actual weak-upgrade and result views.
    pub(crate) fn original_initial_node_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<&Rc<PacketCompleteSemanticSource>>()
            + size_of::<Rc<PacketCompleteSemanticSource>>()
            + size_of::<Option<Rc<PacketCompleteSemanticSource>>>()
            + size_of::<InstalledConformancePlan>()
            + size_of::<Option<InstalledConformancePlan>>()
            + size_of::<&InstalledConformancePlan>()
            + size_of::<*const ()>()
            + size_of::<std::thread::Thread>()
            + size_of::<std::thread::ThreadId>()
            + size_of::<Result<(), RuntimeError>>()
    }
}
