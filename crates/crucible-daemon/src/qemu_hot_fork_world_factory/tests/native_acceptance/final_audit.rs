//! Final native process, attempt-storage, and content-store census.

use std::path::Path;

use super::*;

#[test]
#[ignore = "requires completed packaged native QEMU flights"]
fn production_hot_fork_resource_roots_are_clean_after_packaged_flights() {
    let paths = NativeGatePaths::from_environment();
    audit_no_qemu_processes(&paths.qemu);
    let cgroup_count = audit_empty_cgroups(&paths.cgroup_root);
    let lane_count = audit_empty_attempt_roots(&paths.storage_root);
    let (store_objects, store_allocated_bytes) = audit_content_store(&paths.artifacts);

    assert!(cgroup_count > 0, "native gate created no attempt cgroups");
    assert!(
        lane_count > 0,
        "native gate created no attempt-storage lanes"
    );
    // The representative fixture publishes exactly one block object and one
    // 9p tree object. Native fork lifecycles have no authority to add roots.
    assert_eq!(
        store_objects, 2,
        "native forks changed the fixture's two-object content store"
    );
    // Both packaged VM scripts create exactly one cgroup and one ext4 lane per
    // named case; an extra cgroup here is a retained attempt hierarchy.
    assert_eq!(
        cgroup_count,
        lane_count + 1,
        "attempt cgroup directories survived their matching storage lanes"
    );

    println!("final_cgroup_count={cgroup_count}");
    println!("final_attempt_storage_lanes={lane_count}");
    println!("final_attempt_processes=0");
    println!("final_qemu_processes=0");
    println!("final_attempt_descriptors=0");
    println!("final_attempt_process_memory_bytes=0");
    println!("final_attempt_storage_entries=0");
    println!("final_store_verified_objects={store_objects}");
    println!("final_store_allocated_bytes={store_allocated_bytes}");
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

fn audit_empty_cgroups(root: &Path) -> usize {
    let processes = fs::read_to_string(root.join("cgroup.procs"))
        .unwrap_or_else(|error| panic!("read {}: {error}", root.display()));
    assert!(
        processes.trim().is_empty(),
        "QEMU processes remain in {}: {processes}",
        root.display()
    );

    let mut count = 1;
    for entry in
        fs::read_dir(root).unwrap_or_else(|error| panic!("read {}: {error}", root.display()))
    {
        let entry = entry.expect("read cgroup child");
        if entry.file_type().expect("inspect cgroup child").is_dir() {
            count += audit_empty_cgroups(&entry.path());
        }
    }
    count
}

fn audit_empty_attempt_roots(root: &Path) -> usize {
    let mut lanes = 0;
    for entry in
        fs::read_dir(root).unwrap_or_else(|error| panic!("read {}: {error}", root.display()))
    {
        let lane = entry.expect("read attempt-storage lane");
        assert!(
            lane.file_type()
                .expect("inspect attempt-storage lane")
                .is_dir(),
            "unexpected attempt-storage root entry {}",
            lane.path().display()
        );
        let mut remaining = fs::read_dir(lane.path())
            .unwrap_or_else(|error| panic!("read {}: {error}", lane.path().display()));
        assert!(
            remaining.next().is_none(),
            "attempt storage survived process reap in {}",
            lane.path().display()
        );
        lanes += 1;
    }
    lanes
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
            let key = ContentHash::from_hex(&name).expect("64-character content hash");
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
