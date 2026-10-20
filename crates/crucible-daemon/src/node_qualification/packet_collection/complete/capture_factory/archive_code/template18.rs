//! Borrows actual code-factory custody without a currentness or native grant.

use super::*;
use crucible::node_contract::RuntimeError;
use std::mem::size_of;

impl PacketCompleteArchiveCodeFactory {
    pub(in crate::node_qualification::packet_collection::complete) fn authenticate_prebirth_template18_custody_data(
        &self,
        authority: &Rc<InstalledPacketCompleteCollectionAuthority>,
        plan: &Rc<InstalledConformancePlan>,
        graph: &Rc<CompleteArchiveCodeGraph>,
    ) -> Result<(), RuntimeError> {
        // The actual graph was issued and stored by admit_original_code_graph.
        // A copied public plan or same-valued Source cannot replace its owners.
        if self.inner.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.inner.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        if !Rc::ptr_eq(&self.inner.authority, authority)
            || !Rc::ptr_eq(&self.inner.plan, plan)
            || !graph.plan().is_original_plan_data(plan)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let retained = self
            .graph
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = retained
            .as_ref()
            .and_then(std::rc::Weak::upgrade)
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !Rc::ptr_eq(&original, graph) {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(in crate::node_qualification::packet_collection::complete) fn prebirth_template18_custody_counter_scratch_data()
    -> usize {
        size_of::<&Self>()
            + size_of::<&Rc<InstalledPacketCompleteCollectionAuthority>>()
            + size_of::<&Rc<InstalledConformancePlan>>()
            + size_of::<&Rc<CompleteArchiveCodeGraph>>()
            + size_of::<std::cell::Ref<'static, Option<std::rc::Weak<CompleteArchiveCodeGraph>>>>()
            + size_of::<
                Result<
                    std::cell::Ref<'static, Option<std::rc::Weak<CompleteArchiveCodeGraph>>>,
                    std::cell::BorrowError,
                >,
            >()
            + size_of::<
                Result<
                    std::cell::Ref<'static, Option<std::rc::Weak<CompleteArchiveCodeGraph>>>,
                    RuntimeError,
                >,
            >()
            + size_of::<Option<&std::rc::Weak<CompleteArchiveCodeGraph>>>()
            + size_of::<Option<Rc<CompleteArchiveCodeGraph>>>()
            + size_of::<Result<Rc<CompleteArchiveCodeGraph>, RuntimeError>>()
            + size_of::<Rc<CompleteArchiveCodeGraph>>()
            + size_of::<&InstalledConformancePlan>()
            + size_of::<bool>()
            + size_of::<std::thread::Thread>()
            + size_of::<std::thread::ThreadId>()
            + size_of::<u32>()
            + size_of::<Result<(), RuntimeError>>()
    }
}
