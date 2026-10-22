//! Lends the sole registered RAM client to a real retained checkpoint original.
//!
//! This method is reached through the internal registrar loan, never the
//! operator get/set vocabulary. Index and client contention remain bounded by
//! that same original; no Setup operation or replacement supervisor is created.

use super::*;

impl HostOperationalRegistry {
    pub(super) fn checkpoint_arm_from_original(
        &self,
        loan: crucible_qemu_host::CheckpointArmLoan<'_>,
    ) -> Result<
        crucible_qemu_host::ram_control::CheckpointArmReceipt,
        crucible_qemu_host::CheckpointOriginalError,
    > {
        use crucible_qemu_host::{
            CheckpointOriginalCause, CheckpointOriginalError, CheckpointTransportCause,
        };
        let unavailable = || CheckpointOriginalError {
            source: CheckpointOriginalCause::Transport(CheckpointTransportCause::AuthorityMismatch),
            original_after: None,
        };
        // Both index contention and client contention borrow the real original;
        // no operator request or fresh Setup operation can create this loan.
        let owner = loop {
            let slice = loan.wait_slice()?;
            match self.shared.state.try_lock() {
                Ok(state) => {
                    if state.retired.contains(&loan.target()) {
                        return Err(unavailable());
                    }
                    break state
                        .nodes
                        .get(&loan.target())
                        .cloned()
                        .ok_or_else(unavailable)?;
                }
                Err(TryLockError::WouldBlock) => {
                    std::thread::sleep(slice.min(Duration::from_millis(1)));
                }
                Err(TryLockError::Poisoned(_)) => return Err(unavailable()),
            }
        };
        if !loan.matches_supervisor(&owner.supervisor) {
            return Err(unavailable());
        }
        let mut client = loop {
            let slice = loan.wait_slice()?;
            match owner.client.try_lock() {
                Ok(client) => break client,
                Err(TryLockError::WouldBlock) => {
                    std::thread::sleep(slice.min(Duration::from_millis(1)));
                }
                Err(TryLockError::Poisoned(_)) => return Err(unavailable()),
            }
        };
        client
            .as_mut()
            .ok_or_else(unavailable)?
            .checkpoint_arm(loan)
    }
}
