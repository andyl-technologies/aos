//! Derives fixed shared allocation requests for the controller and pager owner.
//!
//! These requests describe allocation layouts; they do not issue credit. The
//! actual retained installer Source must debit its original purpose before the
//! corresponding allocation. Worker channels, creator/TLS/cache storage and FD
//! aliases need their own genuine admission and are not included here.
// SPDX-License-Identifier: GPL-2.0-only

use std::alloc::Layout;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize};

use crate::ram_error::RamError;

use super::{LivePagerController, State, capture::work::OperationRegistry};

mod artifact;

/// Mirrors the header layout of the configured Rust allocation implementation.
///
/// Rust 1.98.1 alloc::sync::ArcInner is repr(C, align(2)), with two atomic
/// reference counts followed by its value. This representation supplies only
/// requested allocation sizes, never allocator backing or physical peak proof.
#[repr(C, align(2))]
struct SharedAllocationHeader {
    strong: AtomicUsize,
    weak: AtomicUsize,
}

/// Identifies one allocation in the closed configured installer request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::paged_ram) enum InstallerControlAllocationKind {
    /// The complete shared controller body and header.
    Controller,
    /// The independent controller state mutex and header.
    ControllerState,
    /// The shared cancellation flag and header.
    Cancellation,
    /// The actual operation registry, including held-work storage.
    OperationRegistry,
    /// The initial pager body, including its queue and capture journal.
    PagerOwner,
    /// The separately shared paging counters and header.
    PagingCounters,
    /// The independently shared active service slot and header.
    ActiveServiceSlot,
}

const ALLOCATION_KINDS: [InstallerControlAllocationKind; 7] = [
    InstallerControlAllocationKind::Controller,
    InstallerControlAllocationKind::ControllerState,
    InstallerControlAllocationKind::Cancellation,
    InstallerControlAllocationKind::OperationRegistry,
    InstallerControlAllocationKind::PagerOwner,
    InstallerControlAllocationKind::PagingCounters,
    InstallerControlAllocationKind::ActiveServiceSlot,
];

/// Describes one requested shared allocation without issuing its capacity.
///
/// Construction is private to the actual configured-type producer. These
/// fields are information, not a Rust-native process protocol or artifact proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct InstallerControlAllocationRequest {
    kind: InstallerControlAllocationKind,
    size: u64,
    alignment: u64,
    count: u64,
}

impl InstallerControlAllocationRequest {
    fn from_layout(kind: InstallerControlAllocationKind, layout: Layout) -> Result<Self, RamError> {
        Ok(Self {
            kind,
            size: u64::try_from(layout.size()).map_err(|_| {
                RamError::Invariant("installer allocation size is not representable")
            })?,
            alignment: u64::try_from(layout.align()).map_err(|_| {
                RamError::Invariant("installer allocation alignment is not representable")
            })?,
            count: 1,
        })
    }

    /// Returns the fixed allocation role.
    pub(in crate::paged_ram) fn kind(self) -> InstallerControlAllocationKind {
        self.kind
    }

    /// Returns the complete requested size, including its shared header.
    pub(crate) fn size(self) -> u64 {
        self.size
    }

    /// Returns the configured complete allocation alignment.
    pub(crate) fn alignment(self) -> u64 {
        self.alignment
    }

    /// Returns the number of births in this fixed request.
    pub(crate) fn count(self) -> u64 {
        self.count
    }
}

/// Retains seven requests derived only from the actual controller and pager types.
///
/// No caller-provided request constructor exists. The matched final artifact
/// and retained native purpose authenticate these same configured requests; the
/// descriptor itself cannot stand in for either of them.
pub(crate) struct InstallerControlRequests {
    allocations: [InstallerControlAllocationRequest; 7],
}

impl InstallerControlRequests {
    /// Borrows the fixed canonical allocation roster without a new allocation.
    pub(crate) fn allocations(&self) -> &[InstallerControlAllocationRequest; 7] {
        &self.allocations
    }

    /// Returns the checked sum of the fixed requested allocation extents.
    ///
    /// # Errors
    /// Refuses noncanonical internal geometry or arithmetic overflow.
    pub(crate) fn required_bytes(&self) -> Result<u64, RamError> {
        self.allocations()
            .iter()
            .zip(ALLOCATION_KINDS)
            .try_fold(0_u64, |sum, (request, kind)| {
                if request.kind() != kind
                    || request.count() != 1
                    || request.size() == 0
                    || !request.alignment().is_power_of_two()
                    || request.size() % request.alignment() != 0
                {
                    return Err(RamError::Invariant(
                        "installer allocation roster is not canonical",
                    ));
                }
                request
                    .size()
                    .checked_mul(request.count())
                    .and_then(|bytes| sum.checked_add(bytes))
                    .ok_or(RamError::Invariant(
                        "installer allocation request sum overflowed",
                    ))
            })
    }
}

/// Derives fixed layout requests before controller or initial pager birth.
///
/// The controller embeds its checkpoint admission and worker handles. Its State,
/// cancellation and registry are separate allocations. The initial pager embeds
/// its queue and retains only two separately allocated controls. Every shared
/// header and body is described once; Arc clones add no new allocation here.
///
/// # Errors
/// Returns an error for unrepresentable shared layouts or request scalars.
pub(super) fn required_control_requests() -> Result<InstallerControlRequests, RamError> {
    let layouts = configured_control_layouts().ok_or(RamError::Invariant(
        "configured installer allocation layouts are not representable",
    ))?;
    let [
        controller,
        state,
        cancellation,
        registry,
        pager,
        counters,
        active,
    ] = layouts;
    let allocations = [
        InstallerControlAllocationRequest::from_layout(ALLOCATION_KINDS[0], controller)?,
        InstallerControlAllocationRequest::from_layout(ALLOCATION_KINDS[1], state)?,
        InstallerControlAllocationRequest::from_layout(ALLOCATION_KINDS[2], cancellation)?,
        InstallerControlAllocationRequest::from_layout(ALLOCATION_KINDS[3], registry)?,
        InstallerControlAllocationRequest::from_layout(ALLOCATION_KINDS[4], pager)?,
        InstallerControlAllocationRequest::from_layout(ALLOCATION_KINDS[5], counters)?,
        InstallerControlAllocationRequest::from_layout(ALLOCATION_KINDS[6], active)?,
    ];
    Ok(InstallerControlRequests { allocations })
}

// Both the nominal request and immutable artifact section use this same
// configured-type roster. Failure yields no valid artifact record or request.
const fn configured_control_layouts() -> Option<[Layout; 7]> {
    let Some(controller) = configured_shared_allocation_layout::<LivePagerController>() else {
        return None;
    };
    let Some(state) = configured_shared_allocation_layout::<Mutex<State>>() else {
        return None;
    };
    let Some(cancellation) = configured_shared_allocation_layout::<AtomicBool>() else {
        return None;
    };
    let Some(registry) = configured_shared_allocation_layout::<OperationRegistry>() else {
        return None;
    };
    let Some([pager, counters, active]) =
        super::super::engine::PausedPagingOwner::configured_control_layouts()
    else {
        return None;
    };
    Some([
        controller,
        state,
        cancellation,
        registry,
        pager,
        counters,
        active,
    ])
}

/// Derives the shared header/body layout without runtime initialization.
///
/// Returns `None` when the complete configured layout is unrepresentable.
pub(in crate::paged_ram) const fn configured_shared_allocation_layout<T>() -> Option<Layout> {
    match Layout::new::<SharedAllocationHeader>().extend(Layout::new::<T>()) {
        Ok((layout, _)) => Some(layout.pad_to_align()),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(64))]
    struct AlignedBody([u8; 65]);

    #[test]
    fn shared_header_padding_precedes_the_actual_aligned_body() {
        let aligned = AlignedBody([0; 65]);
        assert_eq!(aligned.0.len(), 65);

        let header = Layout::new::<SharedAllocationHeader>();
        let body = Layout::new::<AlignedBody>();
        let (expected, offset) = header.extend(body).unwrap();
        let actual = configured_shared_allocation_layout::<AlignedBody>().unwrap();

        assert_eq!(offset % body.align(), 0);
        assert!(offset >= header.size());
        assert_eq!(actual, expected.pad_to_align());
        assert!(actual.size() >= offset + body.size());
        assert_eq!(actual.align(), 64);
    }

    #[test]
    fn installer_request_includes_the_actual_pager_owner_controls() {
        let controller = configured_shared_allocation_layout::<LivePagerController>()
            .unwrap()
            .size()
            + configured_shared_allocation_layout::<Mutex<State>>()
                .unwrap()
                .size()
            + configured_shared_allocation_layout::<AtomicBool>()
                .unwrap()
                .size()
            + configured_shared_allocation_layout::<OperationRegistry>()
                .unwrap()
                .size();
        let pager = super::super::super::engine::PausedPagingOwner::configured_control_layouts()
            .unwrap()
            .iter()
            .map(|layout| layout.size() as u64)
            .sum::<u64>();

        assert!(
            pager > std::mem::size_of::<super::super::super::engine::PausedPagingOwner>() as u64
        );
        assert_eq!(
            required_control_requests()
                .unwrap()
                .required_bytes()
                .unwrap(),
            controller as u64 + pager
        );
        assert!(
            required_control_requests()
                .unwrap()
                .required_bytes()
                .unwrap()
                > controller as u64
        );
    }

    #[test]
    fn operation_registry_request_cannot_reuse_the_old_counter_term() {
        let other_allocations = configured_shared_allocation_layout::<LivePagerController>()
            .unwrap()
            .size()
            + configured_shared_allocation_layout::<Mutex<State>>()
                .unwrap()
                .size()
            + configured_shared_allocation_layout::<AtomicBool>()
                .unwrap()
                .size();
        let old_counter = configured_shared_allocation_layout::<AtomicUsize>()
            .unwrap()
            .size();
        let actual_registry = configured_shared_allocation_layout::<OperationRegistry>()
            .unwrap()
            .size();

        assert!(actual_registry > old_counter);
        assert!(
            required_control_requests()
                .unwrap()
                .required_bytes()
                .unwrap()
                > (other_allocations + old_counter) as u64
        );
    }

    #[test]
    fn closed_roster_preserves_each_actual_layout_and_single_birth() {
        let requests = required_control_requests().unwrap();
        let [pager, counters, active] =
            super::super::super::engine::PausedPagingOwner::configured_control_layouts().unwrap();
        let expected = [
            configured_shared_allocation_layout::<LivePagerController>().unwrap(),
            configured_shared_allocation_layout::<Mutex<State>>().unwrap(),
            configured_shared_allocation_layout::<AtomicBool>().unwrap(),
            configured_shared_allocation_layout::<OperationRegistry>().unwrap(),
            pager,
            counters,
            active,
        ];
        let mut total = 0;

        for ((request, kind), layout) in requests
            .allocations()
            .iter()
            .zip(ALLOCATION_KINDS)
            .zip(expected)
        {
            assert_eq!(request.kind(), kind);
            assert_eq!(request.size(), layout.size() as u64);
            assert_eq!(request.alignment(), layout.align() as u64);
            assert_eq!(request.count(), 1);
            total += request.size();
        }
        assert_eq!(requests.required_bytes().unwrap(), total);
    }

    #[test]
    fn malformed_internal_roster_cannot_become_a_scalar_request() {
        let mut requests = required_control_requests().unwrap();
        requests.allocations.swap(0, 1);
        assert!(requests.required_bytes().is_err());
        requests.allocations.swap(0, 1);
        requests.allocations[0].count = 2;
        assert!(requests.required_bytes().is_err());
        requests.allocations[0].count = 1;
        requests.allocations[0].alignment = 3;
        assert!(requests.required_bytes().is_err());
    }
}
