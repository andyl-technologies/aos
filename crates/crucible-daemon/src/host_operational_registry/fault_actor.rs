//! Exact-owner native fault-worker observation and entitled fixture requests.
//!
//! Both routes borrow the live registered control client and its original
//! supervision. An accepted fixture request never supplies cleanup evidence.

use super::*;

impl HostOperationalRegistry {
    pub(super) fn with_native_fault_client<T>(
        &self,
        target: HostRamTarget,
        class: crucible_linux_resource::host_supervision::HostOperationClass,
        observe: impl FnOnce(
            &mut RamControlClient,
            &crucible_linux_resource::host_supervision::HostOperationGuard,
        ) -> Result<T, RamControlError>,
    ) -> Result<T, RamControlError> {
        let owner = self
            .node(target)
            .map_err(|_| RamControlError::AuthorityMismatch)?;
        let guard = owner.supervisor.begin_control(class).map_err(supervision)?;
        let mut client = loop {
            let slice = guard.wait_slice().map_err(supervision)?;
            match owner.client.try_lock() {
                Ok(client) => break client,
                Err(TryLockError::WouldBlock) => {
                    // The same operation bounds lock contention and the RPC;
                    // a healthy concurrent control request does not hide actor failure.
                    std::thread::sleep(slice.min(std::time::Duration::from_millis(1)));
                }
                Err(TryLockError::Poisoned(_)) => {
                    return Err(RamControlError::AuthorityMismatch);
                }
            }
        };
        let client = client.as_mut().ok_or(RamControlError::AuthorityMismatch)?;
        let result = observe(client, &guard)?;
        guard.complete().map_err(supervision)?;
        Ok(result)
    }

    /// Requests an explicitly entitled mutation of this exact native actor.
    ///
    /// # Errors
    /// Refuses stale ownership, absent control, contention, or the native
    /// entitlement/generation check. Acceptance supplies no cleanup proof.
    #[cfg(test)]
    pub(crate) fn test_fault_actor(
        &self,
        target: HostRamTarget,
        entitlement: [u8; 32],
        worker_generation: u64,
        action: crucible_protocol::ram_control::RamControlFaultActorAction,
    ) -> Result<RamControlReply, RamControlError> {
        self.with_native_fault_client(
            target,
            crucible_linux_resource::host_supervision::HostOperationClass::Setup,
            |client, guard| {
                client.test_fault_actor_under(entitlement, worker_generation, action, guard)
            },
        )
    }
}

fn supervision(
    source: crucible_linux_resource::host_supervision::HostSupervisionError,
) -> RamControlError {
    RamControlError::Io(std::io::Error::other(source))
}
