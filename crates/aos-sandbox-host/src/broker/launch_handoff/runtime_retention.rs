//! Retains the genuine first Launch's final native runtime-pin promotion.
//!
//! Prior volatile runtime continuity is deliberately refused on this first
//! operation. Terminal-backed reentry must finance and retain that full old
//! continuity engine separately; empty DATA cannot manufacture such permission.

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use crate::worker::{HostScopeKernelOriginalV3, PinnedLeaderCloneOriginalV3};
use crate::{HostError, Result};

struct ScopeEntropyV3 {
    bytes: [u8; 32],
    result: Option<std::result::Result<(), rand::rand_core::OsError>>,
}

pub(in crate::broker) struct HostLaunchRuntimeRetentionV3 {
    pub(in crate::broker) duplicate: PinnedLeaderCloneOriginalV3,
    pub(in crate::broker) kernel: HostScopeKernelOriginalV3,
    entropy: [ScopeEntropyV3; super::super::MAXIMUM_SCOPE_HANDLE_ATTEMPTS],
    pub(in crate::broker) entered: bool,
}

impl HostLaunchRuntimeRetentionV3 {
    pub(in crate::broker) fn new() -> Self {
        Self {
            duplicate: PinnedLeaderCloneOriginalV3::new(),
            kernel: HostScopeKernelOriginalV3::new(),
            entropy: std::array::from_fn(|_| ScopeEntropyV3 { bytes: [0; 32], result: None }),
            entered: false,
        }
    }

    pub(in crate::broker) fn entropy_once_v3(&mut self, attempt: usize) -> Result<[u8; 32]> {
        let original = self.entropy.get_mut(attempt)
            .ok_or(HostError::ResourceExhausted)?;
        if original.result.is_some() { return Err(HostError::Fence("scope entropy cannot reenter")); }
        original.result = Some(fill_scope_entropy_v3(&mut original.bytes));
        match original.result.as_ref() {
            Some(Ok(())) => Ok(original.bytes),
            _ => Err(HostError::State("payload scope entropy unavailable".to_owned())),
        }
    }

    pub(in crate::broker) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.duplicate.failure().or_else(|| self.kernel.failure())
            .or_else(|| self.entropy.iter().find_map(|original| {
                original.result.as_ref()?.as_ref().err().map(|cause| cause as _)
            }))
    }

    pub(in crate::broker) fn receiving_demand_v3() -> Option<ResourceVector> {
        use super::super::{HostRuntimeIdentity, RetainedRuntimePins};
        use super::super::guardian_transaction::RetainedHostLimitAttemptV1;
        use crate::worker::PinnedLeader;
        use aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1 as nodes;

        let duplicate = PinnedLeaderCloneOriginalV3::receiving_obligations_v3()?;
        let kernel = HostScopeKernelOriginalV3::receiving_obligations_v3()?;
        // These are three real native custody-map entries. Node geometry is
        // separate from the already financed payload/spec and native pin heaps.
        let index = nodes::<HostRuntimeIdentity, PinnedLeader>(1)?
            .checked_add(nodes::<HostRuntimeIdentity, RetainedRuntimePins>(1)?)?
            .checked_add(nodes::<[u8; 16], RetainedHostLimitAttemptV1>(1)?)?;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(duplicate.0)?.checked_add(kernel.0)?.checked_add(index)?;
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::OpenFiles, u64::try_from(duplicate.1.checked_add(kernel.1)?).ok()?)
            .with(D::MetadataEntries, u64::try_from(kernel.2.checked_add(3)?).ok()?))
    }
}

// Both the ordinary and retained scope-handle loops call this sole native draw.
pub(in crate::broker) fn fill_scope_entropy_v3(bytes: &mut [u8; 32])
    -> std::result::Result<(), rand::rand_core::OsError>
{
    use rand::TryRngCore as _;
    rand::rngs::OsRng.try_fill_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_entropy_attempt_is_kept_and_cannot_be_repeated() {
        let mut original = HostLaunchRuntimeRetentionV3::new();
        let bytes = original.entropy_once_v3(0).unwrap();
        let actual = original.entropy[0].result.as_ref().unwrap() as *const _;

        assert!(original.entropy_once_v3(0).is_err());

        assert_eq!(original.entropy[0].bytes, bytes);
        assert!(matches!(original.entropy[0].result, Some(Ok(()))));
        assert_eq!(original.entropy[0].result.as_ref().unwrap() as *const _, actual);
        assert!(original.entropy_once_v3(super::super::super::MAXIMUM_SCOPE_HANDLE_ATTEMPTS).is_err());
        assert!(original.entropy[1].result.is_none());
    }
}
