//! Publishes one immutable authenticated pool origin beside its shared allocator.
//!
//! The containing Main prepays this actual Arc body before birth. Its origin is
//! captured while the allocator is uniquely owned, then retained through the
//! same body's lifetime. Origin access never borrows the constructor mutex or
//! creates an operation, account, clock, or additional shared allocation.

// SPDX-License-Identifier: Apache-2.0

use super::*;
use crucible_qemu_host::LinuxQemuNativeWorldPreparationOrigin;
use std::ops::Deref;
use std::sync::atomic::AtomicUsize;

/// Retains the allocator and its immutable origin in the existing shared body.
pub(super) struct SharedHostBody<H> {
    /// Destroys the actual allocator before its final immutable pool alias.
    pub(super) host: Mutex<H>,
    origin: Option<LinuxQemuNativeWorldPreparationOrigin>,
}

impl<H> SharedHostBody<H> {
    /// Wraps an ordinary allocator without a Source admission origin.
    pub(super) fn ordinary(host: H) -> Self {
        Self {
            host: Mutex::new(host),
            origin: None,
        }
    }

    /// Retains the genuine origin captured from this still-unique allocator.
    pub(super) fn with_origin(host: H, origin: LinuxQemuNativeWorldPreparationOrigin) -> Self {
        Self {
            host: Mutex::new(host),
            origin: Some(origin),
        }
    }

    /// Borrows the prepublished real origin, independently of constructor contention.
    ///
    /// Actual Main/family checks still precede Preparation issuance. Mutable
    /// factory/process poison and pool/token identity remain checked beneath the
    /// same saved Preparation after bounded acquisition, before assignment.
    ///
    /// # Errors
    /// Refuses actual mutex poison or the absence of a prepublished origin.
    pub(super) fn world_origin(
        &self,
    ) -> Result<&LinuxQemuNativeWorldPreparationOrigin, QemuVmRealizationError> {
        if self.host.is_poisoned() {
            return Err(QemuVmRealizationError::ExecutorUnavailable {
                operation: "borrow actual Source World Preparation origin",
                message: String::from("host-resource allocator lock is poisoned"),
            });
        }
        self.origin
            .as_ref()
            .ok_or_else(|| QemuVmRealizationError::ExecutorUnavailable {
                operation: "borrow actual Source World Preparation origin",
                message: String::from("shared factory has no prepublished authentic normal pool"),
            })
    }
}

// Existing ordinary allocation/cleanup methods keep their exact mutex behavior.
// Only origin lookup bypasses that mutex, using the separately retained fact.
impl<H> Deref for SharedHostBody<H> {
    type Target = Mutex<H>;

    fn deref(&self) -> &Self::Target {
        &self.host
    }
}

/// Prices this exact single Arc allocation, including its control counters.
pub(super) fn shared_body_extent<H>() -> Option<usize> {
    let (layout, _) = std::alloc::Layout::new::<(AtomicUsize, AtomicUsize)>()
        .extend(std::alloc::Layout::new::<SharedHostBody<H>>())
        .ok()?;
    Some(layout.pad_to_align().size())
}

#[cfg(test)]
mod tests;
