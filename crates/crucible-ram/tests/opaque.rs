//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Exercises authenticated sparse hydration independently of guest page reads.

#![allow(clippy::unwrap_used)]

use crucible_ram::{
    Geometry, Limits, MetadataBudget, PageDigest, PageProof, RamError, RamRootDigest, RamSnapshot,
    RegionClass, RegionDescriptor, RegionTree, RegionTreeDigest, RootRecord, Scope, Topology,
    oracle,
};

fn fixture(length: u64, budget: &MetadataBudget) -> (RamSnapshot, RootRecord, Vec<Vec<u8>>) {
    let geometry = Geometry::new(length).unwrap();
    let pages = (0..geometry.page_count())
        .map(|index| vec![(index % 3) as u8; geometry.valid_length(index).unwrap() as usize])
        .collect::<Vec<_>>();
    let digests = pages
        .iter()
        .map(|page| PageDigest::hash(page).unwrap())
        .collect::<Vec<_>>();
    let topology = Topology::new(
        vec![RegionDescriptor::new("ram", RegionClass::MutableMain, length).unwrap()],
        Limits::default(),
    )
    .unwrap();
    let tree = RegionTree::from_page_digests(length, &digests, budget).unwrap();
    let snapshot = RamSnapshot::new(topology, vec![tree], budget).unwrap();
    let record = snapshot.root_record(Scope::Exact).unwrap();
    (snapshot, record, pages)
}

#[test]
fn opaque_snapshot_seeds_scoped_roots_without_page_reads() {
    let full_budget = MetadataBudget::new(65536);
    let (full, record, _) = fixture(4096 * 7 + 3, &full_budget);
    let budget = MetadataBudget::new(1024);
    let lazy = RamSnapshot::from_root_record(&record, &budget).unwrap();
    for scope in [Scope::Execution, Scope::Exact, Scope::Lifecycle] {
        assert_eq!(
            lazy.scoped_root(scope).unwrap(),
            full.scoped_root(scope).unwrap()
        );
    }
    assert!(budget.used_bytes() < 1024);
    assert_eq!(lazy.region_tree("ram").unwrap().node_digest(), None);
    assert_eq!(
        lazy.region_tree("ram").unwrap().page_digest(0),
        Err(RamError::MissingProof)
    );
    assert!(matches!(
        lazy.updated("ram", &[(0, PageDigest::hash(b"new").unwrap())]),
        Err(RamError::MissingProof)
    ));
    drop(lazy);
    assert_eq!(budget.used_bytes(), 0);
}

#[test]
fn opaque_hydration_preserves_changes_and_matches_independent_oracle() {
    let full_budget = MetadataBudget::new(65536);
    let (full, record, mut pages) = fixture(4096 * 7 + 3, &full_budget);
    let budget = MetadataBudget::new(65536);
    let mut lazy = RamSnapshot::from_root_record(&record, &budget).unwrap();
    let frozen = lazy.clone();
    for index in [0, 7, 4, 1, 6, 2, 5, 3] {
        let proof = full
            .region_tree("ram")
            .unwrap()
            .proof("ram", index)
            .unwrap();
        lazy = lazy.hydrated(&proof, &record, record.digest()).unwrap();
        assert_eq!(
            lazy.region_tree("ram").unwrap().page_digest(index).unwrap(),
            proof.page_digest()
        );
        pages[index as usize].fill(17 + index as u8);
        lazy = lazy
            .updated(
                "ram",
                &[(index, PageDigest::hash(&pages[index as usize]).unwrap())],
            )
            .unwrap();
        let root = oracle::recompute(lazy.topology(), Scope::Exact, 8, |_, page, out| {
            out.copy_from_slice(&pages[page as usize]);
            Ok(())
        })
        .unwrap();
        assert_eq!(lazy.scoped_root(Scope::Exact).unwrap(), root);
        let repeated = lazy.hydrated(&proof, &record, record.digest()).unwrap();
        assert_eq!(repeated.scoped_root(Scope::Exact).unwrap(), root);
        assert!(
            repeated
                .region_tree("ram")
                .unwrap()
                .shares_root_with(lazy.region_tree("ram").unwrap())
        );
    }
    assert_eq!(frozen.scoped_root(Scope::Exact).unwrap(), record.digest());
    for index in 0..8 {
        lazy.region_tree("ram")
            .unwrap()
            .proof("ram", index)
            .unwrap()
            .verify(
                &pages[index as usize],
                &lazy.root_record(Scope::Exact).unwrap(),
                lazy.scoped_root(Scope::Exact).unwrap(),
            )
            .unwrap();
    }
}

#[test]
fn opaque_hydration_rejects_foreign_evidence_and_rolls_back_budget() {
    let full_budget = MetadataBudget::new(65536);
    let (full, record, _) = fixture(8195, &full_budget);
    let budget = MetadataBudget::new(65536);
    let lazy = RamSnapshot::from_root_record(&record, &budget).unwrap();
    let proof = full.region_tree("ram").unwrap().proof("ram", 2).unwrap();
    let used = budget.used_bytes();
    let bad = PageProof::new(
        "ram",
        2,
        3,
        PageDigest::hash(b"bad").unwrap(),
        proof.siblings().to_vec(),
    )
    .unwrap();
    assert!(lazy.hydrated(&bad, &record, record.digest()).is_err());
    assert!(
        lazy.hydrated(&proof, &record, RamRootDigest::from_bytes([0; 32]))
            .is_err()
    );
    assert_eq!(budget.used_bytes(), used);
    let small = MetadataBudget::new(used + 1);
    let sparse = RamSnapshot::from_root_record(&record, &small).unwrap();
    assert!(matches!(
        sparse.hydrated(&proof, &record, record.digest()),
        Err(RamError::ResourceLimit)
    ));
    assert_eq!(small.used_bytes(), used);
    assert_eq!(sparse.scoped_root(Scope::Exact).unwrap(), record.digest());
    let mut changed = full
        .updated("ram", &[(2, PageDigest::hash(b"xyz").unwrap())])
        .unwrap();
    let foreign = changed.root_record(Scope::Exact).unwrap();
    let foreign_proof = changed.region_tree("ram").unwrap().proof("ram", 2).unwrap();
    assert!(
        lazy.hydrated(&foreign_proof, &foreign, foreign.digest())
            .is_err()
    );
    changed = changed.updated("ram", &[(2, proof.page_digest())]).unwrap();
    assert_eq!(changed.scoped_root(Scope::Exact).unwrap(), record.digest());
}

#[test]
fn opaque_geometry_and_execution_scope_fail_closed() {
    let budget = MetadataBudget::new(1024);
    let topology = Topology::new(
        vec![RegionDescriptor::new("huge", RegionClass::MutableMain, u64::MAX).unwrap()],
        Limits::default(),
    )
    .unwrap();
    let record = RootRecord::new(
        topology,
        Scope::Exact,
        vec![RegionTreeDigest::from_bytes([37; 32])],
    )
    .unwrap();
    let sparse = RamSnapshot::from_root_record(&record, &budget).unwrap();
    assert_eq!(sparse.scoped_root(Scope::Exact).unwrap(), record.digest());
    assert!(budget.used_bytes() < 1024);
    let execution = sparse.root_record(Scope::Execution).unwrap();
    assert!(matches!(
        RamSnapshot::from_root_record(&execution, &budget),
        Err(RamError::InvalidEncoding)
    ));
}

#[test]
fn snapshot_rejects_independent_tree_accounting_domains() {
    let original = MetadataBudget::new(65536);
    let (full, record, _) = fixture(4096, &original);
    let independent = MetadataBudget::new(65536);
    assert!(original.shares_account_with(&original.clone()));
    assert!(!original.shares_account_with(&independent));
    assert!(matches!(
        RamSnapshot::new(
            record.topology().clone(),
            full.region_trees().to_vec(),
            &independent
        ),
        Err(RamError::MetadataDomain)
    ));
    assert_eq!(independent.used_bytes(), 0);
    assert!(full.metadata_budget().shares_account_with(&original));
    let opaque = RamSnapshot::from_root_record(&record, &independent).unwrap();
    assert!(opaque.metadata_budget().shares_account_with(&independent));
}

#[test]
fn dense_metadata_bound_covers_distinct_versions_and_checks_overflow() {
    let (_, record, _) = fixture(4096 * 7 + 3, &MetadataBudget::new(65536));
    let one = RamSnapshot::maximum_metadata_bytes(record.topology(), 1).unwrap();
    let three = RamSnapshot::maximum_metadata_bytes(record.topology(), 3).unwrap();
    assert_eq!(three, one * 3);
    let budget = MetadataBudget::new(three);
    let (first, _, _) = fixture(4096 * 7 + 3, &budget);
    let second = first
        .updated(
            "ram",
            &(0..8)
                .map(|index| {
                    (
                        index,
                        PageDigest::hash(&vec![89; if index == 7 { 3 } else { 4096 }]).unwrap(),
                    )
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();
    let third = second
        .updated(
            "ram",
            &(0..8)
                .map(|index| {
                    (
                        index,
                        PageDigest::hash(&vec![97; if index == 7 { 3 } else { 4096 }]).unwrap(),
                    )
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();
    assert!(budget.used_bytes() <= three);
    assert_ne!(
        first.scoped_root(Scope::Exact).unwrap(),
        third.scoped_root(Scope::Exact).unwrap()
    );
    assert_eq!(
        RamSnapshot::maximum_metadata_bytes(record.topology(), 0),
        Err(RamError::InvalidLength)
    );
    let huge = Topology::new(
        vec![RegionDescriptor::new("huge", RegionClass::MutableMain, u64::MAX).unwrap()],
        Limits::default(),
    )
    .unwrap();
    assert_eq!(
        RamSnapshot::maximum_metadata_bytes(&huge, u32::MAX),
        Err(RamError::Overflow)
    );
}
