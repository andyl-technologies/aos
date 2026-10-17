//! Final physical cleanup census and independent immutable fixture audit.

use std::path::Path;

use super::*;

#[test]
#[ignore = "requires completed packaged native QEMU flights"]
fn production_hot_fork_resource_roots_are_clean_after_packaged_flights() {
    let paths = NativeGatePaths::from_environment();
    audit_no_qemu_processes(&paths.qemu);
    let mut cgroup_count = 0;
    let mut runtime_directories = 0;
    let mut catalogs = 0;
    let mut catalog_allocated_bytes = 0;
    let mut registries = 0;
    let mut registry_allocated_bytes = 0;
    let roots = [
        (paths.cgroup_root.clone(), paths.storage_root.clone()),
        (
            required_path("CRUCIBLE_PAGING_CGROUP"),
            required_path("CRUCIBLE_PAGING_STORAGE"),
        ),
    ];
    for (cgroup_root, storage_root) in roots {
        let cgroups = audit_empty_cgroups(&cgroup_root);
        let storage = audit_attempt_storage(&storage_root);
        assert!(
            !cgroups.is_empty(),
            "native gate created no attempt cgroups"
        );
        assert!(
            !storage.runtime_directories.is_empty(),
            "native gate created no attempt-storage lanes"
        );
        // The operator declares paired process and storage namespaces. Empty
        // retained world directories are permitted; unmatched ones are not.
        assert_eq!(
            cgroups, storage.runtime_directories,
            "attempt cgroup hierarchy differs from its declared storage hierarchy"
        );
        cgroup_count += cgroups.len() + 1;
        runtime_directories += storage.runtime_directories.len();
        catalogs += storage.catalogs;
        catalog_allocated_bytes += storage.catalog_allocated_bytes;
        registries += storage.registries;
        registry_allocated_bytes += storage.registry_allocated_bytes;
    }
    let (fixture_objects, fixture_allocated_bytes) = audit_content_store(&paths.artifacts);
    // These are the original block and 9p traffic assets. Durable paged RAM
    // belongs to independently retained catalog namespaces, not this fixture.
    assert_eq!(
        fixture_objects, 2,
        "native forks changed the fixture's two-object content store"
    );

    println!("final_cgroup_count={cgroup_count}");
    println!("final_attempt_storage_directories={runtime_directories}");
    println!("final_attempt_processes=0");
    println!("final_qemu_processes=0");
    println!("final_attempt_descriptors=0");
    println!("final_attempt_process_memory_bytes=0");
    println!("final_attempt_storage_entries=0");
    println!("final_persistent_catalogs={catalogs}");
    println!("final_persistent_catalog_allocated_bytes={catalog_allocated_bytes}");
    println!("final_persistent_registries={registries}");
    println!("final_persistent_registry_allocated_bytes={registry_allocated_bytes}");
    println!("final_fixture_verified_objects={fixture_objects}");
    println!("final_fixture_allocated_bytes={fixture_allocated_bytes}");
}

fn audit_no_qemu_processes(qemu: &Path) {
    let executable = fs::canonicalize(qemu)
        .unwrap_or_else(|error| panic!("resolve {}: {error}", qemu.display()));
    let mut remaining = Vec::new();
    for entry in fs::read_dir("/proc").expect("read final process table") {
        let entry = entry.expect("read process-table entry");
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if fs::read_link(entry.path().join("exe")).is_ok_and(|path| path == executable) {
            remaining.push(pid);
        }
    }
    assert!(
        remaining.is_empty(),
        "packaged QEMU processes survived: {remaining:?}"
    );
}

fn audit_empty_cgroups(root: &Path) -> std::collections::BTreeSet<PathBuf> {
    let mut directories = std::collections::BTreeSet::new();
    inspect_empty_cgroup(root, root, &mut directories);
    directories
}

fn inspect_empty_cgroup(
    root: &Path,
    path: &Path,
    directories: &mut std::collections::BTreeSet<PathBuf>,
) {
    let processes = fs::read_to_string(path.join("cgroup.procs"))
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    assert!(
        processes.trim().is_empty(),
        "QEMU processes remain in {}: {processes}",
        path.display()
    );
    for entry in
        fs::read_dir(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
    {
        let entry = entry.expect("read cgroup child");
        if entry.file_type().expect("inspect cgroup child").is_dir() {
            record_directory(root, &entry.path(), directories);
            inspect_empty_cgroup(root, &entry.path(), directories);
        }
    }
}

struct StorageCensus {
    runtime_directories: std::collections::BTreeSet<PathBuf>,
    catalogs: usize,
    catalog_allocated_bytes: u64,
    registries: usize,
    registry_allocated_bytes: u64,
}

fn audit_attempt_storage(root: &Path) -> StorageCensus {
    let mut census = StorageCensus {
        runtime_directories: std::collections::BTreeSet::new(),
        catalogs: 0,
        catalog_allocated_bytes: 0,
        registries: 0,
        registry_allocated_bytes: 0,
    };
    for entry in
        fs::read_dir(root).unwrap_or_else(|error| panic!("read {}: {error}", root.display()))
    {
        let entry = entry.expect("read attempt-storage lane");
        assert!(
            entry.file_type().expect("inspect storage lane").is_dir(),
            "unexpected attempt-storage root entry {}",
            entry.path().display()
        );
        let name = entry.file_name().into_string().expect("UTF-8 lane name");
        if name == "lost+found" {
            assert!(
                fs::read_dir(entry.path())
                    .expect("inspect filesystem recovery directory")
                    .next()
                    .is_none(),
                "filesystem recovery artifacts survived the native flight"
            );
        } else if let Some(lane) = name.strip_prefix("catalog-") {
            assert!(
                !lane.is_empty() && root.join(lane).is_dir(),
                "persistent catalog lacks its declared runtime lane"
            );
            // A durable claim may deliberately outlive a failed process. This
            // census neither deletes claims nor authenticates RAM closure data.
            census.catalogs += 1;
            census.catalog_allocated_bytes += allocated_tree_bytes(&entry.path());
        } else if let Some(lane) = name.strip_prefix("registry-") {
            assert!(
                !lane.is_empty() && root.join(lane).is_dir(),
                "persistent registry lacks its declared runtime lane"
            );
            census.registries += 1;
            census.registry_allocated_bytes += allocated_tree_bytes(&entry.path());
        } else {
            inspect_empty_runtime_storage(root, &entry.path(), &mut census.runtime_directories);
        }
    }
    census
}

fn inspect_empty_runtime_storage(
    root: &Path,
    path: &Path,
    directories: &mut std::collections::BTreeSet<PathBuf>,
) {
    record_directory(root, path, directories);
    for entry in
        fs::read_dir(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
    {
        let entry = entry.expect("read temporary native storage entry");
        assert!(
            entry
                .file_type()
                .expect("inspect temporary native storage entry")
                .is_dir(),
            "attempt payload survived process reap in {}",
            entry.path().display()
        );
        inspect_empty_runtime_storage(root, &entry.path(), directories);
    }
}

fn record_directory(
    root: &Path,
    path: &Path,
    directories: &mut std::collections::BTreeSet<PathBuf>,
) {
    assert!(
        directories.len() < 65_536,
        "native census exceeds its directory bound"
    );
    assert!(
        directories.insert(
            path.strip_prefix(root)
                .expect("descendant path")
                .to_path_buf()
        )
    );
}

fn audit_content_store(root: &Path) -> (usize, u64) {
    let store = LocalDagStore::new(root);
    let mut objects = 0;

    for entry in
        fs::read_dir(root).unwrap_or_else(|error| panic!("read {}: {error}", root.display()))
    {
        let bucket = entry.expect("read content-store bucket");
        let bucket_name = bucket.file_name().into_string().expect("UTF-8 bucket name");
        assert!(
            bucket
                .file_type()
                .expect("inspect content-store bucket")
                .is_dir()
                && bucket_name.len() == 2
                && bucket_name.bytes().all(|byte| byte.is_ascii_hexdigit())
                && bucket_name == bucket_name.to_ascii_lowercase(),
            "unexpected content-store bucket {}",
            bucket.path().display()
        );

        for entry in fs::read_dir(bucket.path())
            .unwrap_or_else(|error| panic!("read {}: {error}", bucket.path().display()))
        {
            let object = entry.expect("read content-store object");
            let name = object.file_name().into_string().expect("UTF-8 object name");
            let digest = blake3::Hash::from_hex(&name).expect("64-character content hash");
            let key = ContentHash {
                bytes: *digest.as_bytes(),
            };
            assert!(
                object
                    .file_type()
                    .expect("inspect content-store object")
                    .is_file()
                    && name == key.to_hex()
                    && name.starts_with(&bucket_name),
                "unexpected content-store object {}",
                object.path().display()
            );
            store.get(&key).expect("verify stored object content hash");
            objects += 1;
        }
    }
    (objects, allocated_tree_bytes(root))
}

/// Streams physical allocation without retaining a catalog-sized path inventory.
fn allocated_tree_bytes(root: &Path) -> u64 {
    const MAXIMUM_DEPTH: usize = 64;
    const MAXIMUM_ENTRIES: u64 = 64_000_000;

    let allocated_bytes = |path: &Path| {
        let metadata = fs::symlink_metadata(path)
            .unwrap_or_else(|error| panic!("inspect native storage {}: {error}", path.display()));
        assert!(
            metadata.is_dir() || metadata.is_file(),
            "unexpected native storage object {}",
            path.display(),
        );
        metadata
            .blocks()
            .checked_mul(512)
            .expect("physical allocation byte count")
    };
    let read_directory = |path: &Path| {
        fs::read_dir(path)
            .unwrap_or_else(|error| panic!("read native storage {}: {error}", path.display()))
    };
    let mut allocated = allocated_bytes(root);
    let mut entries = 1_u64;
    let mut pending = vec![read_directory(root)];

    while let Some(directory) = pending.last_mut() {
        let Some(entry) = directory.next() else {
            pending.pop();
            continue;
        };
        let entry = entry.expect("read bounded native storage entry");
        entries = entries.checked_add(1).expect("physical census visit count");
        assert!(
            entries <= MAXIMUM_ENTRIES,
            "native storage census visit bound"
        );
        allocated = allocated
            .checked_add(allocated_bytes(&entry.path()))
            .expect("physical allocation census overflow");
        if entry
            .file_type()
            .expect("inspect native storage entry")
            .is_dir()
        {
            assert!(
                pending.len() < MAXIMUM_DEPTH,
                "native storage census depth bound"
            );
            pending.push(read_directory(&entry.path()));
        }
    }
    allocated
}

#[test]
fn final_census_distinguishes_durable_catalogs_from_closed_runtime_directories() {
    let directory = tempfile::tempdir().expect("physical census fixture");
    let storage = directory.path().join("storage");
    let cgroup = directory.path().join("cgroup");
    fs::create_dir_all(storage.join("lane/child")).expect("retained empty runtime hierarchy");
    fs::create_dir_all(storage.join("catalog-lane")).expect("durable catalog namespace");
    fs::write(
        storage.join("catalog-lane/retained-page"),
        b"retained immutable bytes",
    )
    .expect("durable catalog payload");
    fs::create_dir_all(storage.join("registry-lane")).expect("durable registry namespace");
    fs::write(
        storage.join("registry-lane/ledger"),
        b"retained authoritative history",
    )
    .expect("durable registry payload");
    fs::create_dir_all(storage.join("lost+found")).expect("empty filesystem recovery directory");
    fs::create_dir_all(cgroup.join("lane/child")).expect("paired process hierarchy");
    for path in [&cgroup, &cgroup.join("lane"), &cgroup.join("lane/child")] {
        fs::write(path.join("cgroup.procs"), b"").expect("empty component process census");
    }

    let census = audit_attempt_storage(&storage);
    assert_eq!(census.runtime_directories, audit_empty_cgroups(&cgroup));
    assert_eq!(census.runtime_directories.len(), 2);
    assert_eq!(census.catalogs, 1);
    assert!(census.catalog_allocated_bytes > 0);
    assert_eq!(census.registries, 1);
    assert!(census.registry_allocated_bytes > 0);
    assert!(storage.join("catalog-lane/retained-page").exists());
}

#[test]
#[should_panic(expected = "attempt payload survived process reap")]
fn final_census_rejects_retained_native_payload_in_runtime_hierarchy() {
    let directory = tempfile::tempdir().expect("physical census fixture");
    fs::create_dir(directory.path().join("lane")).expect("runtime namespace");
    fs::write(directory.path().join("lane/spill"), b"still retained")
        .expect("unclosed native backing fixture");
    audit_attempt_storage(directory.path());
}

#[test]
#[should_panic(expected = "persistent catalog lacks its declared runtime lane")]
fn final_census_rejects_orphan_catalog_namespace() {
    let directory = tempfile::tempdir().expect("physical census fixture");
    fs::create_dir(directory.path().join("catalog-unknown")).expect("orphan catalog");
    audit_attempt_storage(directory.path());
}
