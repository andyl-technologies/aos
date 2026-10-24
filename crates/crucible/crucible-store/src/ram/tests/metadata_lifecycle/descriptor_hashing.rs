//! Actual descriptor hashing allocations across all portable scopes and classes.
//!
//! Input strings and root vectors are prepared outside each observation. These
//! controls remove descriptor scratch; inventory ownership and native resource
//! admission retain their existing external contracts.

use super::*;
use crucible_host_resources::test_support::TestAllocationObserver;
use crucible_ram::{RegionTreeDigest, RootRecord};
use std::alloc::Layout;

fn descriptors(count: usize, unicode: bool) -> Vec<RegionDescriptor> {
    let suffix = if unicode {
        "é".repeat(123)
    } else {
        "x".repeat(246)
    };
    (0..count)
        .rev()
        .map(|index| {
            let class = match index % 4 {
                0 => RegionClass::MutableMain,
                1 => RegionClass::MutableDevice,
                2 => RegionClass::ImmutableImage,
                _ => RegionClass::ContinuationPrivate,
            };
            let id = format!("{index:08x}-{suffix}");
            assert_eq!(id.len(), 255);
            RegionDescriptor::new(id, class, (index as u64 + 1) * 4096 - 1).unwrap()
        })
        .collect()
}

#[test]
fn topology_hashing_avoids_descriptor_scratch_for_maximum_utf8_inventory() {
    for count in [0, 1, 12, 4096] {
        for unicode in [false, true] {
            let regions = descriptors(count, unicode);
            let (topology, identity, counts) = TestAllocationObserver::capture_layout_and_count(
                Layout::array::<u8>(269).unwrap(),
                || Topology::new(regions, Limits::default()).unwrap(),
            );

            assert!(!counts.overflow);
            assert!(identity.is_none(), "{count} regions; unicode={unicode}");
            assert_eq!(topology.regions().len(), count);
            assert!(
                topology
                    .regions()
                    .windows(2)
                    .all(|pair| { pair[0].id().as_bytes() < pair[1].id().as_bytes() })
            );
            let encoded = topology.encode_inventory();
            assert_eq!(
                Topology::decode_inventory(&encoded, Limits::default()).unwrap(),
                topology
            );
        }
    }
}

#[test]
fn root_hashing_allocates_no_descriptor_scratch_in_any_scope() {
    for count in [0, 1, 12, 4096] {
        for unicode in [false, true] {
            let topology = Topology::new(descriptors(count, unicode), Limits::default()).unwrap();
            for scope in [Scope::Execution, Scope::Exact, Scope::Lifecycle] {
                let roots = topology
                    .regions()
                    .iter()
                    .filter(|region| scope.includes(region.class()))
                    .enumerate()
                    .map(|(index, _)| {
                        let mut bytes = [0; 32];
                        bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
                        RegionTreeDigest::from_bytes(bytes)
                    })
                    .collect();
                let owned_topology = topology.clone();
                let (root, counts) = TestAllocationObserver::count(|| {
                    RootRecord::new(owned_topology, scope, roots).unwrap()
                });

                assert!(!counts.overflow);
                assert_eq!(
                    counts.allocations, 0,
                    "{count} regions; {scope:?}; unicode={unicode}"
                );
                assert_eq!(counts.reallocations, 0);
                let encoded = root.try_encode().unwrap();
                assert_eq!(encoded.len(), root.encoded_len());
                assert_eq!(
                    RootRecord::decode(&encoded, Limits::default()).unwrap(),
                    root
                );
            }
        }
    }
}
