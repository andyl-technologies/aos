//! Complete physical queue observation before the scheduler chooses a RUN.

use super::*;

impl<L, B, I> BackendQuantumLoop<L, B, I>
where
    L: std::borrow::Borrow<SingleScheduler> + std::borrow::BorrowMut<SingleScheduler>,
    B: SimulationBackend,
{
    pub(super) fn import_initial_io_inventories(&mut self) -> Result<(), SchedulerError> {
        if self.backend.io_inventory_authority()
            == crate::BackendIoInventoryAuthority::SchedulerOwnedModel
        {
            return Ok(());
        }
        let mut staged = SingleScheduler::clone(self.loop_impl.borrow());
        let nodes = staged
            .nodes
            .iter()
            .filter(|node| node.id.kind == SchedulingNodeKind::Vm)
            .map(|node| node.id.node.clone())
            .collect::<Vec<_>>();
        for node in nodes {
            let inventory = self.backend.observe_node_io_inventory(&node)?;
            if inventory.node != node {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from("physical inventory returned a different requested node"),
                });
            }
            staged.import_initial_io_inventory(inventory)?;
        }
        *self.loop_impl.borrow_mut() = staged;
        Ok(())
    }
}
