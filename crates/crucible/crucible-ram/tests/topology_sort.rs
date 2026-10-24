//! Checks canonical inventory ordering without temporary sorting allocations.
//!
//! Each finite caller prepays the existing complete decode bound before input
//! construction and retains it through output close. These are portable format
//! and allocation controls, not native admission or physical OOM qualification.

// crucible-lint: allow panic-shortcut -- ordering controls localize failed fixture assumptions.
#![allow(clippy::unwrap_used)]

use crucible_host_resources::test_support::TestAllocationObserver;
use crucible_ram::{
    Limits, MetadataBudget, RamError, RegionClass, RegionDescriptor, RootRecord, Topology,
};

#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

#[derive(Clone, Copy, Debug)]
enum Order {
    Scrambled,
    Sorted,
    Reversed,
    Rotated,
}

fn descriptors(count: usize, unicode: bool) -> Vec<RegionDescriptor> {
    let suffix = if unicode {
        "é".repeat(125)
    } else {
        "x".repeat(250)
    };
    (0..count)
        .map(|index| {
            let identifier = format!("{index:04x}-{suffix}");
            assert_eq!(identifier.len(), 255);
            let class = match index % 4 {
                0 => RegionClass::MutableMain,
                1 => RegionClass::MutableDevice,
                2 => RegionClass::ImmutableImage,
                _ => RegionClass::ContinuationPrivate,
            };
            RegionDescriptor::new(identifier, class, index as u64 + 1).unwrap()
        })
        .collect()
}

fn reorder(regions: &mut [RegionDescriptor], order: Order) {
    match order {
        Order::Scrambled => {
            for index in 0..regions.len() {
                regions.swap(index, (index * 17 + 23) % regions.len());
            }
        }
        Order::Sorted => {}
        Order::Reversed => regions.reverse(),
        Order::Rotated => regions.rotate_left(regions.len() / 3),
    }
}

fn canonical_inventory(regions: &[RegionDescriptor]) -> Vec<u8> {
    let mut bytes = (regions.len() as u32).to_be_bytes().to_vec();
    for region in regions {
        bytes.extend_from_slice(&(region.id().len() as u32).to_be_bytes());
        bytes.extend_from_slice(region.id().as_bytes());
        let (class, mask) = match region.class() {
            RegionClass::MutableMain => (1, 7),
            RegionClass::MutableDevice => (2, 7),
            RegionClass::ImmutableImage => (3, 6),
            RegionClass::ContinuationPrivate => (4, 6),
        };
        bytes.extend_from_slice(&[class, mask]);
        bytes.extend_from_slice(&region.logical_length().to_be_bytes());
    }
    bytes
}

fn assert_ordering(unicode: bool) {
    for count in [64, 4096, 0, 1, 12] {
        for order in [
            Order::Scrambled,
            Order::Sorted,
            Order::Reversed,
            Order::Rotated,
        ] {
            let bytes = RootRecord::decoding_memory_bound(Limits::default()).unwrap();
            let caller = MetadataBudget::new(bytes);
            let original = caller.reserve_bytes(bytes).unwrap();
            let mut regions = descriptors(count, unicode);
            let expected = canonical_inventory(&regions);
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"crucible.ram.topology.v1\0");
            hasher.update(&4096_u32.to_be_bytes());
            hasher.update(&expected);
            reorder(&mut regions, order);

            let (result, counts) =
                TestAllocationObserver::count(|| Topology::new(regions, Limits::default()));
            let topology = result.unwrap();

            assert!(!counts.overflow);
            assert_eq!(counts.allocations, 1, "{count} regions; {order:?}");
            assert_eq!(counts.reallocations, 0);
            assert_eq!(topology.encode_inventory(), expected);
            assert_eq!(topology.digest().as_bytes(), hasher.finalize().as_bytes());
            assert_eq!(
                topology.total_logical_bytes(),
                (count * (count + 1) / 2) as u64
            );
            assert_eq!(caller.used_bytes(), bytes);

            drop(topology);
            drop(original);
            assert_eq!(caller.used_bytes(), 0);
        }
    }
}

#[test]
fn ascii_inventory_ordering_allocates_only_its_shared_output() {
    assert_ordering(false);
}

#[test]
fn utf8_inventory_ordering_allocates_only_its_shared_output() {
    assert_ordering(true);
}

#[test]
fn duplicate_inventory_refusal_needs_no_sorting_allocation() {
    for count in [64, 4096, 2] {
        for order in [
            Order::Scrambled,
            Order::Sorted,
            Order::Reversed,
            Order::Rotated,
        ] {
            let bytes = RootRecord::decoding_memory_bound(Limits::default()).unwrap();
            let caller = MetadataBudget::new(bytes);
            let original = caller.reserve_bytes(bytes).unwrap();
            let mut regions = descriptors(count, true);
            regions[count - 1] = regions[0].clone();
            reorder(&mut regions, order);

            let (result, counts) =
                TestAllocationObserver::count(|| Topology::new(regions, Limits::default()));

            assert_eq!(result, Err(RamError::InvalidOrder));
            assert!(!counts.overflow);
            assert_eq!(counts.allocations, 0, "{count} regions; {order:?}");
            assert_eq!(counts.reallocations, 0);
            assert_eq!(caller.used_bytes(), bytes);

            drop(original);
            assert_eq!(caller.used_bytes(), 0);
        }
    }
}
