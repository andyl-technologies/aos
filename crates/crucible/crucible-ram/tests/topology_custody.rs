//! Original inventory custody, immutable identity and actual final slice close.

// crucible-lint: allow panic-shortcut -- finite custody fixtures localize failed lifecycle assumptions.
#![allow(clippy::unwrap_used)]

use std::alloc::Layout;
use std::sync::atomic::{AtomicBool, Ordering};

use crucible_host_resources::test_support::{CloseMarkerOutcome, TestAllocationObserver};
use crucible_ram::{
    Limits, MetadataBudget, MetadataReservation, RegionClass, RegionDescriptor, RegionTreeDigest,
    ResourceLoan, RootRecord, Scope, Topology,
};

#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

static INVENTORY_CLOSED: AtomicBool = AtomicBool::new(false);
static EARLY_REFUND: AtomicBool = AtomicBool::new(false);

struct InventoryCredit {
    _charge: MetadataReservation,
}

impl Drop for InventoryCredit {
    fn drop(&mut self) {
        if !INVENTORY_CLOSED.load(Ordering::SeqCst) {
            EARLY_REFUND.store(true, Ordering::SeqCst);
        }
    }
}

#[test]
fn inventory_original_loan_survives_clones_and_rebinding_until_actual_slice_free() {
    // This fixed component loan precedes the actual inventory allocations.
    // Caller-created record vectors and test diagnostics remain separately paid.
    let original = MetadataBudget::new(64 << 10);
    let loan = ResourceLoan::new(InventoryCredit {
        _charge: original.reserve_bytes(64 << 10).unwrap(),
    });
    let region = RegionDescriptor::new("ram", RegionClass::MutableMain, 4096).unwrap();
    let (layout, _) = Layout::new::<[usize; 2]>()
        .extend(Layout::array::<RegionDescriptor>(1).unwrap())
        .unwrap();
    let (inventory, identity, counts) =
        TestAllocationObserver::capture_layout_and_count(layout.pad_to_align(), || {
            Topology::new(vec![region], Limits::default()).unwrap()
        });
    assert_eq!(counts.allocations, 2);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);

    let root = RegionTreeDigest::from_bytes([7; 32]);
    let mut record = RootRecord::new(inventory, Scope::Exact, vec![root]).unwrap();
    let encoded = record.try_encode().unwrap();
    let digest = record.digest();

    // Attachment cannot retroactively cover an already escaped alias. Refusal
    // preserves the supplied original loan without allocating or changing data.
    let earlier_alias = record.topology().clone();
    let (loan, shared_refusal) =
        TestAllocationObserver::count(|| record.retain_topology_resources(loan).unwrap_err());
    assert_eq!(shared_refusal.allocations, 0);
    assert_eq!(shared_refusal.reallocations, 0);
    assert_eq!(original.used_bytes(), 64 << 10);
    drop(earlier_alias);

    let ((), attached) = TestAllocationObserver::count(|| {
        record.retain_topology_resources(loan).unwrap();
    });
    assert_eq!(attached.allocations, 0);
    assert_eq!(attached.reallocations, 0);
    assert_eq!(record.try_encode().unwrap(), encoded);
    assert_eq!(record.digest(), digest);
    let decoded = RootRecord::decode(&encoded, Limits::default()).unwrap();
    assert_eq!(record, decoded);
    assert_eq!(record.topology(), decoded.topology());
    drop(decoded);

    // An unrelated supplied loan cannot replace, refund or mint a successor
    // for the existing inventory loan. The original returned value stays live.
    let replacement = MetadataBudget::new(64 << 10);
    let replacement_loan = ResourceLoan::new(replacement.reserve_bytes(64 << 10).unwrap());
    let (returned, refused) = TestAllocationObserver::count(|| {
        record
            .retain_topology_resources(replacement_loan)
            .unwrap_err()
    });
    assert_eq!(refused.allocations, 0);
    assert_eq!(refused.reallocations, 0);
    assert_eq!(replacement.used_bytes(), 64 << 10);
    assert_eq!(original.used_bytes(), 64 << 10);
    drop(returned);
    assert_eq!(replacement.used_bytes(), 0);
    assert_eq!(original.used_bytes(), 64 << 10);

    let record_alias = record.clone();
    let (inventory, cloned) = TestAllocationObserver::count(|| record.topology().clone());
    assert_eq!(cloned.allocations, 0);
    assert_eq!(cloned.reallocations, 0);
    let inventory_alias = inventory.clone();
    let successor = RootRecord::new(inventory.clone(), Scope::Exact, vec![root]).unwrap();
    assert_eq!(record, successor);
    assert_eq!(
        inventory.regions().as_ptr(),
        record.topology().regions().as_ptr()
    );

    let ((), outcome) = TestAllocationObserver::observe_close_marker_after_free(
        &INVENTORY_CLOSED,
        identity.unwrap(),
        || {
            drop(record);
            drop(record_alias);
            drop(successor);
            drop(inventory);
            assert!(!INVENTORY_CLOSED.load(Ordering::SeqCst));
            assert_eq!(original.used_bytes(), 64 << 10);
            drop(inventory_alias);
        },
    )
    .unwrap();

    assert_eq!(outcome, CloseMarkerOutcome::Published);
    assert!(!EARLY_REFUND.load(Ordering::SeqCst));
    assert_eq!(original.used_bytes(), 0);
}
