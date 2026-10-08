//! Actual managed Packed controls and source/pin credits through System free.
//!
//! The same finite HostServiceAllocator pays all selected loans. This component
//! model does not install project quotas or fund its allocator, graph maps,
//! test infrastructure, incoming errors, or enclosing authority controls.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use super::*;
use crate::owned_decode::ResourceLoan;
use crucible_linux_resource::host_services::{HostServiceAllocator, HostServiceLease};
use crucible_linux_resource::test_support::{
    AllocationTrace, OriginalControlSelection, OriginalControlSlot, OriginalControlSnapshot,
    OriginalControlsOutcome, OriginalStaticCounters, TestAllocationObserver,
};

static SERIAL: Mutex<()> = Mutex::new(());
static TRACE: AllocationTrace<512> = AllocationTrace::new();
static CONSTRUCTOR_PAID: AtomicU64 = AtomicU64::new(0);
static SOURCE_PAID: AtomicU64 = AtomicU64::new(0);

const RESIDENT: u64 = 4 * 1024 * 1024;
const TARGET: u64 = 64 * 1024;

struct Loan {
    _lease: HostServiceLease,
    watched: Option<&'static AtomicU64>,
}

impl Drop for Loan {
    fn drop(&mut self) {
        if let Some(counter) = self.watched {
            counter.store(0, Ordering::SeqCst);
        }
    }
}

struct Quota {
    allocator: HostServiceAllocator,
    constructor_bytes: u64,
    source_bytes: AtomicU64,
}

impl StorePhysicalQuotaGuard for Quota {
    fn verify(&self) -> Result<(), StoreError> {
        Ok(())
    }

    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(RESIDENT)
    }

    fn reserve_resources(&self, descriptors: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        let lease = self
            .allocator
            .reserve_resources(0, descriptors, bytes)
            .map_err(|_| StoreError::Quota)?;
        let watched = if descriptors == 0 && bytes == self.constructor_bytes {
            Some(&CONSTRUCTOR_PAID)
        } else if descriptors == 0
            && bytes != 0
            && bytes == self.source_bytes.load(Ordering::SeqCst)
        {
            Some(&SOURCE_PAID)
        } else {
            None
        };
        if let Some(counter) = watched {
            counter.store(bytes, Ordering::SeqCst);
        }
        Ok(ResourceLoan::new(Loan {
            _lease: lease,
            watched,
        }))
    }
}

#[derive(Clone)]
struct Binder(Arc<Quota>);

impl StorePhysicalQuotaBinder for Binder {
    fn bind(
        &self,
        _: &Path,
        _: u32,
        _: u64,
        _: u64,
    ) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        Ok(self.0.clone())
    }
}

#[repr(C)]
struct BackendExtent {
    strong: usize,
    weak: usize,
    backend: PackedBlobBackend,
}

fn build(root: &Path, quota: Arc<Quota>) -> Result<(StoreGraph, StoreGraphAdmin), StoreError> {
    let physical = StoreNodeId::new("physical")?;
    let packed = StoreNodeId::new("packed")?;
    let policy = StorePhysicalQuotaPolicyId::new("model/packed")?;
    let mut binders = StoreGraphPhysicalQuotaBinders::new();
    binders.insert(
        policy.clone(),
        StorePhysicalQuotaBinderHandle::new(Binder(quota)),
    )?;
    StoreGraph::build_with_admin_and_all_capabilities(
        StoreGraphConfig {
            gc_mark_root: None,
            root: physical.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
            nodes: BTreeMap::from([
                (
                    physical,
                    StoreNodeSpec::PhysicalQuota {
                        child: packed.clone(),
                        policy,
                        project_id: 42,
                        maximum_physical_bytes: 128 * 1024,
                        maximum_inodes: 64,
                    },
                ),
                (
                    packed,
                    StoreNodeSpec::Packed {
                        root: root.to_owned(),
                        target_pack_bytes: TARGET,
                    },
                ),
            ]),
        },
        &StoreGraphKeyring::new(),
        &StoreGraphNamespaceAuthorizers::new(),
        &StoreGraphObjectProfilers::new(),
        &binders,
        &StoreGraphS3Clients::new(),
        None,
    )
}

#[test]
fn managed_box_and_backend_control_keep_same_original_purpose_through_both_real_frees() {
    let _serial = SERIAL.lock().unwrap();
    for admin_first in [false, true] {
        for unwind in [false, true] {
            CONSTRUCTOR_PAID.store(0, Ordering::SeqCst);
            let temp = tempfile::TempDir::new().unwrap();
            let bytes = std::mem::size_of::<BackendExtent>() as u64
                + 24
                + "packed".len() as u64
                + 3 * temp.path().as_os_str().len() as u64
                + 2
                + "packs".len() as u64
                + ".packed-admin".len() as u64;
            let quota = Arc::new(Quota {
                allocator: HostServiceAllocator::new(1, 16, RESIDENT).unwrap(),
                constructor_bytes: bytes,
                source_bytes: AtomicU64::new(0),
            });
            let (graph, admin) = TRACE
                .capture(|| build(temp.path(), quota.clone()))
                .unwrap()
                .unwrap();
            assert!(!TRACE.overflowed());
            // The two enclosing graph-bookkeeping reallocations are outside
            // this constructor-purpose proof and remain an explicit hold. The
            // selected fixed Arc/Box controls are unique aligned allocations;
            // neither owns a mutable buffer or can be reallocated.
            assert_eq!(TRACE.reallocations(), 2);
            assert_eq!(CONSTRUCTOR_PAID.load(Ordering::SeqCst), bytes);
            let packed = StoreNodeId::new("packed").unwrap();
            let authority = admin.packed_repack.get(&packed).unwrap();
            let body = authority.body.as_ref().unwrap();
            let box_address = std::ptr::from_ref(body.as_ref()).addr();
            let backend_address = Arc::as_ptr(&body.backend).addr();
            // The actual owner borrow is live here. Earlier freed buffers may
            // have reused the same address, so only the latest containing
            // allocation can be this live Box/Arc. No layout-only selector or
            // address of a later allocation substitutes for the owned value.
            let boxed = TRACE
                .entries()
                .filter(|entry| entry.contains_address(box_address))
                .last()
                .unwrap();
            let backend = TRACE
                .entries()
                .filter(|entry| entry.contains_address(backend_address))
                .last()
                .unwrap();
            assert_eq!(boxed.bytes(), std::mem::size_of::<PackedRepackBody>());
            assert_eq!(boxed.alignment(), std::mem::align_of::<PackedRepackBody>());
            assert_eq!(backend.bytes(), std::mem::size_of::<BackendExtent>());
            let (_, report) = TestAllocationObserver::observe_original_controls(|session| {
                for (slot, identity) in [
                    (OriginalControlSlot::First, boxed.identity()),
                    (OriginalControlSlot::Second, backend.identity()),
                ] {
                    session
                        .arm(
                            slot,
                            OriginalControlSelection::Explicit(identity),
                            OriginalStaticCounters::U64(&CONSTRUCTOR_PAID),
                            true,
                        )
                        .unwrap();
                }
                let close = move || {
                    if admin_first {
                        drop(admin);
                        drop(graph);
                    } else {
                        drop(graph);
                        drop(admin);
                    }
                };
                if unwind {
                    assert!(
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                            let _close_owners = (graph_owner(close),);
                            panic!("intentional managed owner unwind");
                        }))
                        .is_err()
                    );
                } else {
                    close();
                }
            })
            .unwrap();
            assert_eq!(report.outcome, OriginalControlsOutcome::Complete);
            for observed in report.controls {
                let observed = observed.unwrap();
                assert_eq!(observed.before, OriginalControlSnapshot::U64(bytes));
                assert_eq!(observed.after, Some(OriginalControlSnapshot::U64(bytes)));
            }
            assert_eq!(CONSTRUCTOR_PAID.load(Ordering::SeqCst), 0);
            // Every constructor loan has closed, so the exact original ceiling
            // is available again. No new account or donor supplies this probe.
            let recovered = quota.allocator.reserve_resources(0, 16, RESIDENT).unwrap();
            drop(recovered);
        }
    }
}

struct CloseOnDrop<F: FnOnce()>(Option<F>);

fn graph_owner<F: FnOnce()>(close: F) -> CloseOnDrop<F> {
    CloseOnDrop(Some(close))
}

impl<F: FnOnce()> Drop for CloseOnDrop<F> {
    fn drop(&mut self) {
        if let Some(close) = self.0.take() {
            close();
        }
    }
}

#[test]
fn repack_body_preserves_existing_map_value_width() {
    assert_eq!(std::mem::size_of::<PackedRepackBody>(), 24);
    assert_eq!(std::mem::size_of::<StoreGraphPackedRepackAuthority>(), 24);
    assert_eq!(std::mem::align_of::<PackedRepackBody>(), 8);
    assert_eq!(std::mem::align_of::<StoreGraphPackedRepackAuthority>(), 8);
}
