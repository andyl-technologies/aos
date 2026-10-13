//! Qualifies canonical RAM and checkpoint identities through real BLAKE3 dispatch.
//!
//! The upstream testing features select a dispatch ceiling in separate release
//! builds. This fixture checks the actual selected platform before creating RAM
//! or a store. Unsupported CPUs emit a distinct nonexecution record, never a
//! successful identity transcript. Only canonical bytes and IDs enter the
//! transcript; temporary paths, clocks, account IDs and host state do not.

use super::*;
use crucible_ram::{MetadataBudget, PageDigest, RamSnapshot, RegionTree, oracle};
use std::fmt::Write;

fn selected_backend() -> String {
    // This upstream benchmark-only public API observes the same dispatch used
    // by Hasher::new and hash; it neither replaces a platform nor injects state.
    format!("{:?}", blake3::platform::Platform::detect()).to_ascii_lowercase()
}

fn supported_backend(backend: &str) -> bool {
    match backend {
        "portable" => true,
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        "sse2" => std::arch::is_x86_feature_detected!("sse2"),
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        "sse41" => std::arch::is_x86_feature_detected!("sse4.1"),
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        "avx2" => std::arch::is_x86_feature_detected!("avx2"),
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        "sse2" | "sse41" | "avx2" => false,
        _ => panic!("unknown qualification backend"),
    }
}

fn emit(name: &str, bytes: &[u8]) {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").unwrap();
    }
    println!("RAM_IDENTITY {name}={encoded}");
}

fn fill_page(region: &RegionDescriptor, index: u64, bytes: &mut [u8]) {
    let seed = region.id().bytes().fold(index as u8, u8::wrapping_add);
    for (offset, byte) in bytes.iter_mut().enumerate() {
        *byte = seed.wrapping_add((offset % 251) as u8);
    }
}

fn fixture_topology() -> Topology {
    // A genuine many-region exact checkpoint produces a contiguous manifest
    // well above 32 KiB. Its existing ContentId encoder therefore reaches wide
    // hash_many kernels; 4096-byte pages alone fall back below AVX2's width.
    let mut regions: Vec<_> = (0..256)
        .map(|index| {
            RegionDescriptor::new(
                format!("firmware.{index:04}"),
                RegionClass::ImmutableImage,
                3,
            )
            .unwrap()
        })
        .collect();
    regions.push(RegionDescriptor::new("main", RegionClass::MutableMain, 17 * 4096 + 3).unwrap());
    regions.push(RegionDescriptor::new("device", RegionClass::MutableDevice, 4095).unwrap());
    Topology::new(regions, Limits::default()).unwrap()
}

fn fixture_snapshot(topology: &Topology, budget: &MetadataBudget) -> RamSnapshot {
    let trees = topology
        .regions()
        .iter()
        .map(|region| {
            let length = region.logical_length();
            let mut remaining = length;
            let mut digests = Vec::new();
            for index in 0..length.div_ceil(4096) {
                let mut bytes = vec![0; remaining.min(4096) as usize];
                fill_page(region, index, &mut bytes);
                digests.push(PageDigest::hash(&bytes).unwrap());
                remaining -= bytes.len() as u64;
            }
            RegionTree::from_page_digests(length, &digests, budget).unwrap()
        })
        .collect();
    RamSnapshot::new(topology.clone(), trees, budget).unwrap()
}

fn emit_checkpoint(label: &str, store: &RamStore, root: &LeasedRamRoot) {
    let original = fixture_original(store);
    let source = store
        .backend
        .read_with_boundary(&original, root.object_id(), None, &mut || Ok(()))
        .unwrap();
    let bytes = source
        .read_all_with_boundary(&original, MAX_RAM_OBJECT_BYTES, &mut || Ok(()))
        .unwrap();
    assert!(
        bytes.len() > 32 * 1024,
        "checkpoint never reached wide hash input"
    );
    assert!(root.object_id().authenticates(&bytes));
    emit(
        &format!("{label}.object"),
        root.object_id().encode().as_bytes(),
    );
    emit(&format!("{label}.record"), &root.record().encode());
    emit(&format!("{label}.envelope"), &bytes);

    let mut corrupted = bytes.to_vec();
    let middle = corrupted.len() / 2;
    corrupted[middle] ^= 1;
    assert!(!root.object_id().authenticates(&corrupted));
}

#[test]
fn persistent_ram_and_checkpoint_identities_match_selected_blake3_backend() {
    let selected = selected_backend();
    let expected =
        std::env::var("CRUCIBLE_TEST_BLAKE3_BACKEND").unwrap_or_else(|_| selected.clone());
    if !supported_backend(&expected) {
        println!(
            "\nBLAKE3_BACKEND requested={expected} selected={selected} status=not-executed reason=unsupported-cpu"
        );
        return;
    }
    assert_eq!(
        selected, expected,
        "upstream controls did not select the requested backend"
    );
    println!("\nBLAKE3_BACKEND requested={expected} selected={selected} status=executed");

    let bytes: Vec<_> = (0..4096).map(|index| (index % 251) as u8).collect();
    for length in [
        1, 63, 64, 65, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096,
    ] {
        emit(
            &format!("page.{length}"),
            PageDigest::hash(&bytes[..length]).unwrap().as_bytes(),
        );
    }
    let topology = fixture_topology();
    let budget = MetadataBudget::new(8 * 1024 * 1024);
    let snapshot = fixture_snapshot(&topology, &budget);
    for scope in [Scope::Execution, Scope::Exact, Scope::Lifecycle] {
        let record = snapshot.root_record(scope).unwrap();
        let independently_recomputed =
            oracle::recompute(&topology, scope, 1024, |region, index, output| {
                fill_page(region, index, output);
                Ok(())
            })
            .unwrap();
        assert_eq!(record.digest(), independently_recomputed);
        emit(&format!("snapshot.{scope:?}"), &record.encode());
    }

    let directory = tempfile::tempdir().unwrap();
    let store = store(directory.path(), RamStoreLimits::default());
    let retention = Retention::default();
    let root = store
        .capture(
            topology,
            Scope::Exact,
            &mut |region, index, output| {
                fill_page(region, index, output);
                Ok(())
            },
            &retention,
            &fixture_original(&store),
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(
        root.logical_digest(),
        snapshot.scoped_root(Scope::Exact).unwrap()
    );
    emit_checkpoint("checkpoint.initial", &store, &root);

    let changed_bytes = vec![99; 4096];
    let updated_snapshot = snapshot
        .updated("main", &[(3, PageDigest::hash(&changed_bytes).unwrap())])
        .unwrap();
    let updated = store
        .update(
            &root,
            [RamPageChange {
                region_id: "main".into(),
                page_index: 3,
                bytes: changed_bytes.clone(),
            }],
            &retention,
            &fixture_original(&store),
            &mut || Ok(()),
        )
        .unwrap();
    assert_ne!(updated.logical_digest(), root.logical_digest());
    assert_eq!(
        updated.logical_digest(),
        updated_snapshot.scoped_root(Scope::Exact).unwrap()
    );
    emit_checkpoint("checkpoint.updated", &store, &updated);

    for (label, current) in [("initial", &root), ("updated", &updated)] {
        for index in [0, 3, 17] {
            let page = store
                .read_page_with_proof(
                    current,
                    "main",
                    index,
                    &fixture_original(&store),
                    &mut || Ok(()),
                )
                .unwrap();
            page.proof()
                .verify(page.bytes(), current.record(), current.logical_digest())
                .unwrap();
            let mut corrupt = page.bytes().to_vec();
            corrupt[0] ^= 1;
            assert!(
                page.proof()
                    .verify(&corrupt, current.record(), current.logical_digest())
                    .is_err()
            );
            emit(&format!("proof.{label}.{index}"), &page.proof().encode());
        }
    }
    assert_eq!(
        store
            .read_page(&updated, "main", 3, &fixture_original(&store), &mut || Ok(
                ()
            ))
            .unwrap(),
        changed_bytes
    );
    assert_eq!(
        store
            .read_page(&root, "main", 3, &fixture_original(&store), &mut || Ok(()))
            .unwrap(),
        {
            let region = snapshot
                .topology()
                .regions()
                .iter()
                .find(|region| region.id() == "main")
                .unwrap();
            let mut old = vec![0; 4096];
            fill_page(region, 3, &mut old);
            old
        }
    );

    let reopened = store
        .open_with_metadata_resources(
            retention.retain_root(updated.object_id()).unwrap(),
            &fixture_original(&store),
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(reopened.record(), updated.record());
    assert_eq!(
        store
            .verify(&reopened, &fixture_original(&store), &mut || Ok(()))
            .unwrap()
            .logical_bytes,
        snapshot.topology().total_logical_bytes()
    );
    emit_checkpoint("checkpoint.reopened", &store, &reopened);
}
