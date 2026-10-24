//! Canonical descriptor decoding costs and malformed repeated-field refusals.
//!
//! Inputs precede finite caller admission. Allocation counts compare the actual
//! inventory prefix with its complete scoped root; no guest-state, physical OOM
//! or native resource authority is established by these format controls.

// crucible-lint: allow panic-shortcut -- decoder controls localize failed canonical fixture assumptions.
#![allow(clippy::unwrap_used)]

use crucible_host_resources::test_support::TestAllocationObserver;
use crucible_ram::{
    Limits, MetadataBudget, RamError, RegionClass, RegionDescriptor, RegionTreeDigest, RootRecord,
    Scope, Topology,
};

#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

fn record(count: usize, class: RegionClass, unicode: bool, scope: Scope) -> RootRecord {
    let suffix = if unicode {
        "é".repeat(125)
    } else {
        "x".repeat(250)
    };
    let regions = (0..count)
        .map(|index| {
            let identifier = format!("{index:04x}-{suffix}");
            assert_eq!(identifier.len(), 255);
            let length = [1_u64, 4096, 4097, 65_537][index % 4];
            RegionDescriptor::new(identifier, class, length).unwrap()
        })
        .collect();
    let topology = Topology::new(regions, Limits::default()).unwrap();
    let selected = topology
        .regions()
        .iter()
        .filter(|region| scope.includes(region.class()))
        .count();
    RootRecord::new(
        topology,
        scope,
        vec![RegionTreeDigest::from_bytes([7; 32]); selected],
    )
    .unwrap()
}

fn compare_actual_decode_prefix(record: RootRecord) {
    let inventory = record.topology().encode_inventory();
    let canonical = record.try_encode().unwrap();
    let bytes = RootRecord::decoding_memory_bound(Limits::default()).unwrap();
    let budget = MetadataBudget::new(bytes);
    let original = budget.reserve_bytes(bytes).unwrap();

    let (topology, prefix_counts) = TestAllocationObserver::count(|| {
        Topology::decode_inventory(&inventory, Limits::default()).unwrap()
    });
    assert_eq!(&topology, record.topology());
    drop(topology);

    let (decoded, counts) = TestAllocationObserver::count(|| {
        RootRecord::decode(&canonical, Limits::default()).unwrap()
    });

    assert_eq!(decoded, record);
    assert!(!counts.overflow && !prefix_counts.overflow);
    let root_vector = u64::from(!record.region_roots().is_empty());
    assert_eq!(
        (counts.allocations, counts.reallocations),
        (
            prefix_counts.allocations + root_vector,
            prefix_counts.reallocations
        ),
        "root decoding must add only its retained selected-root vector"
    );
    assert_eq!(budget.used_bytes(), bytes);
    drop(decoded);
    drop(original);
    assert_eq!(budget.used_bytes(), 0);
}

#[test]
fn selected_descriptor_checks_allocate_no_identifier_copies() {
    for class in [
        RegionClass::MutableMain,
        RegionClass::MutableDevice,
        RegionClass::ImmutableImage,
        RegionClass::ContinuationPrivate,
    ] {
        for count in [0, 1, 12, Limits::default().max_regions] {
            for unicode in [false, true] {
                for scope in [Scope::Execution, Scope::Exact, Scope::Lifecycle] {
                    compare_actual_decode_prefix(record(count, class, unicode, scope));
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
struct DescriptorPositions {
    identifier: usize,
    class: usize,
    mask: usize,
    length: usize,
}

fn repeated_descriptor_positions(canonical: &[u8]) -> DescriptorPositions {
    // This one-region fixture repeats its literal descriptor exactly twice.
    // Locate those public bytes without duplicating the complete record parser.
    let marker = b"\0\0\0\x03ram";
    let mut offsets = canonical
        .windows(marker.len())
        .enumerate()
        .filter_map(|(offset, bytes)| (bytes == marker).then_some(offset));
    assert!(offsets.next().is_some());
    let offset = offsets.next().unwrap();
    assert!(offsets.next().is_none());

    let identifier = offset + 4;
    let class = identifier + 3;
    let mask = class + 1;
    DescriptorPositions {
        identifier,
        class,
        mask,
        length: mask + 1,
    }
}

struct Mutation {
    name: &'static str,
    apply: fn(&mut [u8], DescriptorPositions),
    expected: RamError,
}

fn mutations() -> [Mutation; 13] {
    [
        Mutation {
            name: "control identifier",
            apply: |bytes, p| bytes[p.identifier] = 0,
            expected: RamError::InvalidRegionId,
        },
        Mutation {
            name: "non-UTF-8 identifier",
            apply: |bytes, p| bytes[p.identifier] = 0xff,
            expected: RamError::InvalidEncoding,
        },
        Mutation {
            name: "foreign valid identifier",
            apply: |bytes, p| bytes[p.identifier] = b's',
            expected: RamError::InvalidEncoding,
        },
        Mutation {
            name: "unsupported class",
            apply: |bytes, p| bytes[p.class] = 0xff,
            expected: RamError::InvalidEncoding,
        },
        Mutation {
            name: "foreign valid class",
            apply: |bytes, p| bytes[p.class] = RegionClass::MutableDevice as u8,
            expected: RamError::InvalidEncoding,
        },
        Mutation {
            name: "wrong coverage mask",
            apply: |bytes, p| bytes[p.mask] = 0,
            expected: RamError::InvalidEncoding,
        },
        Mutation {
            name: "zero logical length",
            apply: |bytes, p| bytes[p.length..p.length + 8].fill(0),
            expected: RamError::InvalidLength,
        },
        Mutation {
            name: "foreign positive logical length",
            apply: |bytes, p| {
                bytes[p.length..p.length + 8].copy_from_slice(&1_u64.to_be_bytes());
            },
            expected: RamError::InvalidEncoding,
        },
        Mutation {
            name: "class refusal precedes invalid identifier",
            apply: |bytes, p| {
                bytes[p.identifier] = 0;
                bytes[p.class] = 0xff;
            },
            expected: RamError::InvalidEncoding,
        },
        Mutation {
            name: "mask refusal precedes invalid identifier",
            apply: |bytes, p| {
                bytes[p.identifier] = 0;
                bytes[p.mask] = 0;
            },
            expected: RamError::InvalidEncoding,
        },
        Mutation {
            name: "identifier refusal precedes invalid geometry",
            apply: |bytes, p| {
                bytes[p.identifier] = 0;
                bytes[p.length..p.length + 8].fill(0);
            },
            expected: RamError::InvalidRegionId,
        },
        Mutation {
            name: "invalid geometry precedes foreign identifier comparison",
            apply: |bytes, p| {
                bytes[p.identifier] = b's';
                bytes[p.length..p.length + 8].fill(0);
            },
            expected: RamError::InvalidLength,
        },
        Mutation {
            name: "invalid identifier precedes foreign class comparison",
            apply: |bytes, p| {
                bytes[p.identifier] = 0;
                bytes[p.class] = RegionClass::MutableDevice as u8;
            },
            expected: RamError::InvalidRegionId,
        },
    ]
}

#[test]
fn selected_descriptor_validation_preserves_original_error_kinds() {
    let topology = Topology::new(
        vec![RegionDescriptor::new("ram", RegionClass::MutableMain, 4096).unwrap()],
        Limits::default(),
    )
    .unwrap();
    let record = RootRecord::new(
        topology,
        Scope::Exact,
        vec![RegionTreeDigest::from_bytes([7; 32])],
    )
    .unwrap();
    let canonical = record.try_encode().unwrap();
    assert_eq!(
        RootRecord::decode(&canonical, Limits::default()).unwrap(),
        record
    );
    let positions = repeated_descriptor_positions(&canonical);

    for mutation in mutations() {
        let mut malformed = canonical.clone();
        (mutation.apply)(&mut malformed, positions);
        let bytes = RootRecord::decoding_memory_bound(Limits::default()).unwrap();
        let budget = MetadataBudget::new(bytes);
        let original = budget.reserve_bytes(bytes).unwrap();

        let error = RootRecord::decode(&malformed, Limits::default()).unwrap_err();

        assert_eq!(error, mutation.expected, "{}", mutation.name);
        assert_eq!(budget.used_bytes(), bytes);
        drop(error);
        drop(original);
        assert_eq!(budget.used_bytes(), 0);
    }
}
