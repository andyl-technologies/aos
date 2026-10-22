//! Queries real block and RAM map lifetimes on the original QMP connection.

use super::*;

impl<S: QmpTimeoutStream> QmpClient<S> {
    pub(super) fn query_block_borrowers_under(
        &mut self,
        guard: &HostOperationGuard,
    ) -> Result<QmpHotForkBlockBarrierState, QmpError> {
        let response = self.exchange_under(
            QmpCommand::HotForkBlockBarrier {
                action: HotForkBlockBarrierAction::Query,
            },
            guard,
        )?;
        parse_hot_fork_block_barrier_state(&response.value)
    }
}
