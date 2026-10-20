//! Describes the actual callback installer heap allocations before their birth.
//!
//! The roster is allocation geometry, not credit. Its once-issued Native purpose
//! must debit the same containing Source before any listed allocation. Creator
//! stack/TLS, allocator backing, later transport growth, and physical retirement
//! require their separate genuine owners; no listed Arc pays a worker's thread.
// SPDX-License-Identifier: GPL-2.0-only

use std::alloc::Layout;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize};

use crate::StartupSourceError;

use super::live_callbacks::{
    ControlCallbackWitness, LiveVcpuTimeCallbackState, SelectableVmstopHandoff,
    configured_fingerprint_worker_control_layout,
};
use super::{
    LiveCallbackQuiescence, LiveRuntimeTeardownRouter, LiveWorkerQuiescence,
    OwnedCallbackRuntimeState,
};

/// Bounds the closed initial roster, including its optional worker control.
pub(crate) const MAX_RUNTIME_ALLOCATIONS: usize = 14;

/// Identifies the actual typed callback-child birth in the closed roster.
pub(crate) const CALLBACK_CHILD_ALLOCATION: usize = 4;

/// Identifies the actual typed Bridge birth in this closed before-birth roster.
pub(crate) const COMMAND_BRIDGE_ALLOCATION: usize = 5;

/// Identifies the required actual full shared RUN control allocation.
pub(crate) const RUN_CONTROL_ALLOCATION: usize = 11;

/// Identifies the required actual full shared teardown control allocation.
pub(crate) const TEARDOWN_CONTROL_ALLOCATION: usize = 12;

/// Identifies the optional actual full shared worker-control allocation.
pub(crate) const WORKER_CONTROL_ALLOCATION: usize = 13;

/// Retains the configured request span without allocating its own container.
pub(crate) struct RuntimeAllocationRequests {
    layouts: [Layout; MAX_RUNTIME_ALLOCATIONS],
    count: usize,
}

impl RuntimeAllocationRequests {
    /// Derives each actual single allocation from its type and configured extent.
    ///
    /// # Errors
    /// Refuses zero vCPUs or unrepresentable array/shared allocation layouts.
    /// Resource eligibility remains the authentic containing issuer's decision.
    pub(crate) fn configured(
        vcpu_count: u32,
        fingerprint: bool,
    ) -> Result<Self, StartupSourceError> {
        let count = usize::try_from(vcpu_count).map_err(|_| geometry_error())?;
        if count == 0 {
            return Err(geometry_error());
        }
        let initialized_vcpus = Layout::array::<AtomicBool>(count).map_err(|_| geometry_error())?;
        let halted_vcpus = Layout::array::<bool>(count).map_err(|_| geometry_error())?;
        let layouts = [
            // Includes every inline canonical keeper, including Source's
            // workspace owner; adding one changes this actual containing row.
            Layout::new::<OwnedCallbackRuntimeState>(),
            shared_layout::<LiveCallbackQuiescence>()?,
            shared_layout::<LiveWorkerQuiescence>()?,
            shared_layout::<LiveRuntimeTeardownRouter>()?,
            Layout::new::<LiveVcpuTimeCallbackState>(),
            Layout::new::<crate::fault_command::FaultCommandBridge>(),
            initialized_vcpus,
            halted_vcpus,
            shared_layout::<ControlCallbackWitness>()?,
            shared_layout::<SelectableVmstopHandoff>()?,
            shared_layout::<AtomicU64>()?,
            super::required_workers::control_layout()?,
            super::required_workers::control_layout()?,
            if fingerprint {
                configured_fingerprint_worker_control_layout()?
            } else {
                Layout::new::<()>()
            },
        ];
        Ok(Self {
            layouts,
            count: if fingerprint { 14 } else { 13 },
        })
    }

    /// Borrows only the actual configured births; an absent worker has no row.
    pub(crate) fn layouts(&self) -> &[Layout] {
        &self.layouts[..self.count]
    }
}

/// Mirrors the configured Rust shared allocation header, before body alignment.
///
/// Rust 1.98.1's `ArcInner` is `repr(C, align(2))`. This describes the requested
/// allocation layout only; allocator backing or library caches are not inferred.
#[repr(C, align(2))]
struct SharedAllocationHeader {
    strong: AtomicUsize,
    weak: AtomicUsize,
}

/// Describes one complete configured shared header and body allocation.
///
/// # Errors
/// Refuses layout arithmetic overflow before any allocation is attempted.
pub(super) fn shared_layout<T>() -> Result<Layout, StartupSourceError> {
    Layout::new::<SharedAllocationHeader>()
        .extend(Layout::new::<T>())
        .map(|(layout, _)| layout.pad_to_align())
        .map_err(|_| geometry_error())
}

/// Reports the configured shared body offset for geometry corroboration only.
pub(super) const fn shared_data_offset<T>() -> usize {
    let alignment = align_of::<T>();
    (size_of::<SharedAllocationHeader>() + alignment - 1) & !(alignment - 1)
}

fn geometry_error() -> StartupSourceError {
    StartupSourceError::Ownership {
        reason: "configured callback allocation layout is not representable",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_worker_adds_only_its_real_shared_control() {
        let resident = RuntimeAllocationRequests::configured(1, false)
            .unwrap_or_else(|error| panic!("resident layouts should be representable: {error}"));
        let sampled = RuntimeAllocationRequests::configured(1, true)
            .unwrap_or_else(|error| panic!("sampled layouts should be representable: {error}"));

        assert_eq!(resident.layouts().len(), 13);
        assert_eq!(sampled.layouts().len(), MAX_RUNTIME_ALLOCATIONS);
        assert_eq!(resident.layouts(), &sampled.layouts()[..13]);
        assert_eq!(
            sampled.layouts()[0],
            Layout::new::<OwnedCallbackRuntimeState>()
        );
        assert!(
            sampled.layouts()[WORKER_CONTROL_ALLOCATION].size() > size_of::<std::sync::Arc<()>>()
        );
    }

    #[test]
    fn configured_cpu_buffers_scale_without_scaling_fixed_owner_bodies() {
        let one = RuntimeAllocationRequests::configured(1, false)
            .unwrap_or_else(|error| panic!("one-CPU layouts should be representable: {error}"));
        let four = RuntimeAllocationRequests::configured(4, false)
            .unwrap_or_else(|error| panic!("four-CPU layouts should be representable: {error}"));

        for index in [6, 7] {
            assert_eq!(
                four.layouts()[index].size(),
                4 * one.layouts()[index].size()
            );
        }
        for index in [
            0,
            1,
            2,
            3,
            4,
            5,
            8,
            9,
            10,
            RUN_CONTROL_ALLOCATION,
            TEARDOWN_CONTROL_ALLOCATION,
        ] {
            assert_eq!(one.layouts()[index], four.layouts()[index]);
        }
        assert!(RuntimeAllocationRequests::configured(0, false).is_err());
    }
}
