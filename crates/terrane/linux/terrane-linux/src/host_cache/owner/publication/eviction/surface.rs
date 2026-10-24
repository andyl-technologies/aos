//! Joins derived indexes to the host's original mixed-allocation FIFO.

use super::{super::invalid, queue::Allocation};
use crate::host_cache::owner::retention::NativeOwnerExecutor;
use std::io;

/// Carries scheduling data while the original owner retains retirement custody.
pub(super) struct Unit {
    /// Inspected allocation metadata and current protection.
    pub(super) allocation: Allocation,
    #[cfg(feature = "surface-fuse")]
    index: crate::structural_index::IndexKey,
}

/// Inspects actual derived jobs without promoting them as consumer reads.
///
/// # Errors
/// Refuses changed original backing, missing custody or unavailable scheduling.
pub(super) fn capture(executor: &NativeOwnerExecutor) -> io::Result<Vec<Unit>> {
    #[cfg(feature = "surface-fuse")]
    {
        crate::host_cache::owner::surface_index::pressure::inventory(executor).map(|allocations| {
            allocations
                .into_iter()
                .map(|(index, allocation)| Unit { allocation, index })
                .collect()
        })
    }
    #[cfg(not(feature = "surface-fuse"))]
    {
        let _ = executor;
        Ok(Vec::new())
    }
}

/// Retires only through the original funded index queue before planner removal.
///
/// # Errors
/// Refuses a missing original job, retained receipts, exposure protection or IO.
pub(super) async fn retire(executor: &mut NativeOwnerExecutor, unit: Unit) -> io::Result<()> {
    #[cfg(feature = "surface-fuse")]
    {
        if !crate::host_cache::owner::surface_index::eviction::retire(executor, unit.index, false)
            .await?
        {
            return Err(invalid("mixed FIFO lost original surface allocation"));
        }
        executor
            .cache
            .queue
            .as_mut()
            .ok_or_else(|| invalid("mixed FIFO absent"))?
            .removed(&unit.allocation.key)
    }
    #[cfg(not(feature = "surface-fuse"))]
    {
        let _ = (executor, unit);
        Err(invalid(
            "surface allocation cannot exist without its native feature",
        ))
    }
}
