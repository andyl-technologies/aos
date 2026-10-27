//! Retained root allocation accounting and admission before decoding.

// crucible-lint: allow panic-shortcut -- logical allocation fixtures panic at failed checked-format assumptions.
#![allow(clippy::unwrap_used)]

use crucible_ram::{
    Limits, RamError, RegionClass, RegionDescriptor, RegionTreeDigest, RootRecord, Scope, Topology,
};

#[test]
fn root_metadata_includes_actual_retained_root_vector_capacity() {
    let topology = Topology::new(
        vec![RegionDescriptor::new("ram", RegionClass::MutableMain, 4096).unwrap()],
        Limits::default(),
    )
    .unwrap();
    let topology_bytes = topology.metadata_bytes().unwrap();
    let mut roots = Vec::with_capacity(64);
    roots.push(RegionTreeDigest::from_bytes([1; 32]));
    let root_capacity = roots.capacity();
    let record = RootRecord::new(topology, Scope::Exact, roots).unwrap();

    assert_eq!(
        record.metadata_bytes().unwrap(),
        topology_bytes
            + std::mem::size_of::<RootRecord>() as u64
            + (root_capacity * std::mem::size_of::<RegionTreeDigest>()) as u64
    );
}

#[test]
fn decoder_bound_covers_encoded_input_and_retained_root() {
    let topology = Topology::new(
        (0..128)
            .map(|index| {
                RegionDescriptor::new(format!("ram-{index:04}"), RegionClass::MutableMain, 4096)
                    .unwrap()
            })
            .collect(),
        Limits::default(),
    )
    .unwrap();
    let root = RootRecord::new(
        topology,
        Scope::Exact,
        vec![RegionTreeDigest::from_bytes([2; 32]); 128],
    )
    .unwrap();
    let bytes = root.try_encode().unwrap();
    let decoded = RootRecord::decode(&bytes, Limits::default()).unwrap();

    assert!(
        RootRecord::decoding_memory_bound(Limits::default()).unwrap()
            >= bytes.len() as u64 + decoded.metadata_bytes().unwrap()
    );
    assert_eq!(
        RootRecord::decoding_memory_bound(Limits {
            max_record_bytes: usize::MAX,
            ..Limits::default()
        }),
        Err(RamError::Overflow)
    );
}
