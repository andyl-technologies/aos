//! Actual allocator refusals retained by bounded portable RAM decoders.
//!
//! Canonical inputs are constructed before each finite caller admission. The
//! injection targets only fallible vector/string allocation, never an Arc or
//! infallible allocation. These controls establish no physical memory pressure
//! or native resource authority.

// crucible-lint: allow panic-shortcut -- allocation-cause controls localize failed codec assumptions.
#![allow(clippy::unwrap_used)]

use std::alloc::Layout;
use std::collections::TryReserveError;
use std::error::Error;

use crucible_host_resources::test_support::TestAllocationObserver;
use crucible_ram::{
    Limits, MetadataBudget, NodeDigest, PageDigest, PageProof, RamError, RegionClass,
    RegionDescriptor, RegionTreeDigest, RootRecord, Scope, Topology,
};

#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

fn record() -> RootRecord {
    let topology = Topology::new(
        vec![RegionDescriptor::new("ram", RegionClass::MutableMain, 4096).unwrap()],
        Limits::default(),
    )
    .unwrap();
    RootRecord::new(
        topology,
        Scope::Exact,
        vec![RegionTreeDigest::from_bytes([7; 32])],
    )
    .unwrap()
}

fn proof() -> PageProof {
    PageProof::new(
        "ram",
        0,
        4096,
        PageDigest::hash(&[0; 4096]).unwrap(),
        vec![NodeDigest::from_bytes([1; 32]); 2],
    )
    .unwrap()
}

fn retains_allocator_cause<T>(layout: Layout, decode: impl FnOnce() -> Result<T, RamError>) {
    let bytes = RootRecord::decoding_memory_bound(Limits::default()).unwrap();
    let budget = MetadataBudget::new(bytes);
    let credit = budget.reserve_bytes(bytes).unwrap();
    let (result, refused) = TestAllocationObserver::refuse_one_allocation(layout, decode).unwrap();
    assert!(refused, "the exact allocator refusal did not occur");
    let error = result.err().unwrap();
    assert!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<TryReserveError>())
            .is_some(),
        "the actual allocator source was discarded: {error:?}"
    );

    // Refusal aliases remain inline in caller-owned result storage. Their
    // cloning requests neither a diagnostic allocation nor another admission.
    let (alias, counts) = TestAllocationObserver::count(|| error.clone());
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert_eq!(error, alias);
    assert!(alias.source().unwrap().is::<TryReserveError>());
    assert!(
        std::mem::size_of::<RamError>()
            <= std::mem::size_of::<String>() + std::mem::align_of::<String>()
    );
    assert_eq!(budget.used_bytes(), bytes);
    drop(error);
    drop(alias);
    drop(credit);
    assert_eq!(budget.used_bytes(), 0);
}

#[test]
fn root_inventory_vector_refusal_preserves_actual_allocator_source() {
    let bytes = record().try_encode().unwrap();
    assert!(RootRecord::decode(&bytes, Limits::default()).is_ok());

    retains_allocator_cause(Layout::array::<RegionDescriptor>(1).unwrap(), || {
        RootRecord::decode(&bytes, Limits::default())
    });
}

#[test]
fn topology_inventory_vector_refusal_preserves_actual_allocator_source() {
    let bytes = record().topology().encode_inventory();
    assert!(Topology::decode_inventory(&bytes, Limits::default()).is_ok());

    retains_allocator_cause(Layout::array::<RegionDescriptor>(1).unwrap(), || {
        Topology::decode_inventory(&bytes, Limits::default())
    });
}

// These identifier controls exercise the new fallible path only. Injecting a
// refusal into the predecessor's infallible string copy would abort the process.
#[test]
fn root_identifier_refusal_preserves_actual_allocator_source() {
    let bytes = record().try_encode().unwrap();
    assert!(RootRecord::decode(&bytes, Limits::default()).is_ok());

    retains_allocator_cause(Layout::array::<u8>(3).unwrap(), || {
        RootRecord::decode(&bytes, Limits::default())
    });
}

#[test]
fn topology_identifier_refusal_preserves_actual_allocator_source() {
    let bytes = record().topology().encode_inventory();
    assert!(Topology::decode_inventory(&bytes, Limits::default()).is_ok());

    retains_allocator_cause(Layout::array::<u8>(3).unwrap(), || {
        Topology::decode_inventory(&bytes, Limits::default())
    });
}

#[test]
fn selected_root_vector_refusal_preserves_actual_allocator_source() {
    let bytes = record().try_encode().unwrap();
    assert!(RootRecord::decode(&bytes, Limits::default()).is_ok());

    retains_allocator_cause(Layout::array::<RegionTreeDigest>(1).unwrap(), || {
        RootRecord::decode(&bytes, Limits::default())
    });
}

#[test]
fn proof_identifier_refusal_preserves_actual_allocator_source() {
    let bytes = proof().try_encode().unwrap();
    assert!(PageProof::decode(&bytes, Limits::default()).is_ok());

    retains_allocator_cause(Layout::array::<u8>(3).unwrap(), || {
        PageProof::decode(&bytes, Limits::default())
    });
}

#[test]
fn proof_sibling_vector_refusal_preserves_actual_allocator_source() {
    let bytes = proof().try_encode().unwrap();
    assert!(PageProof::decode(&bytes, Limits::default()).is_ok());

    retains_allocator_cause(Layout::array::<NodeDigest>(2).unwrap(), || {
        PageProof::decode(&bytes, Limits::default())
    });
}
