//! Normalizes operational original-start cap bindings for the independent pager.

use super::*;
use crucible_linux_resource::host_supervision::{HostOperationState, HostOuterCapBinding};

/// Projects one coherent same-kernel operational cap into the bounded wire record.
///
/// # Errors
/// Refuses zero identity/start, completed cap authority, nanosecond overflow or
/// an unrepresentable original-start deadline.
pub fn outer_cap_to_wire(
    binding: HostOuterCapBinding,
) -> Result<RamControlOuterCap, RamControlError> {
    let allowance_ns = binding
        .allowance
        .map(|duration| {
            u64::try_from(duration.as_nanos()).map_err(|_| RamControlError::InvalidFrame)
        })
        .transpose()?;
    let state = match binding.state {
        HostOperationState::Running => RamControlOuterState::Running,
        HostOperationState::Expired => RamControlOuterState::Expired,
        HostOperationState::Canceled => RamControlOuterState::Canceled,
        HostOperationState::Completed => return Err(RamControlError::AuthorityMismatch),
    };
    let cap = RamControlOuterCap {
        cap_id: binding.cap_id,
        revision: binding.revision,
        original_monotonic_ns: binding.original_monotonic_ns,
        allowance_ns,
        state,
    };
    cap.validate()?;
    Ok(cap)
}

impl RamControlClient {
    /// Synchronizes an admitted amendment without changing the original start.
    ///
    /// A finite cleanup allowance contains this exchange even when shortening
    /// the execution cap below elapsed time. The native operation tokens observe
    /// the new revision under the same lock used for authenticated completion.
    ///
    /// # Errors
    /// Refuses malformed binding, transport failure or native authority mismatch.
    pub fn sync_outer_cap(
        &mut self,
        binding: HostOuterCapBinding,
    ) -> Result<RamControlReply, RamControlError> {
        self.exchange(RamControlRequest::SyncOuterCap {
            cap: outer_cap_to_wire(binding)?,
        })
    }

    /// Synchronizes one owner using a caller-retained original cleanup deadline.
    ///
    /// The caller completes the shared guard only after every owner in its
    /// bounded fanout has acknowledged. This method preserves partial framing
    /// and never creates a new deadline for the next owner.
    ///
    /// # Errors
    /// Refuses a non-cleanup guard, malformed binding, expired original scope,
    /// transport failure or authenticated native refusal.
    pub fn sync_outer_cap_under(
        &mut self,
        binding: HostOuterCapBinding,
        guard: &HostOperationGuard,
    ) -> Result<RamControlReply, RamControlError> {
        let status = guard.status().map_err(supervision_error)?;
        if status.class != HostOperationClass::Cleanup {
            return Err(RamControlError::AuthorityMismatch);
        }
        let deadline = self.exchange_deadline(Some(guard))?;
        self.exchange_under(
            RamControlRequest::SyncOuterCap {
                cap: outer_cap_to_wire(binding)?,
            },
            Some(guard),
            deadline,
        )
    }
}
