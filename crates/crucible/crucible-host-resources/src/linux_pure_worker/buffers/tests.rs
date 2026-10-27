//! Preserves actual path and private runtime-roster geometry across refusals.

use super::*;
use std::mem::{align_of, size_of};

#[test]
fn original_program_buffers_keep_spare_roster_layout_and_path_capacity() {
    let mut worker = PathBuf::with_capacity(127);
    worker.push("original-worker");
    let mut roots = Vec::with_capacity(5);
    for (name, capacity) in [("runtime-a", 73), ("runtime-b", 89)] {
        let mut path = PathBuf::with_capacity(capacity);
        path.push(name);
        let descriptor: OwnedFd = File::open("/proc/self/exe").unwrap().into();
        roots.push((path, descriptor));
    }
    let original_worker = worker.as_os_str().as_encoded_bytes().as_ptr();
    let original_roots = roots.as_ptr();
    let mut rows = Vec::new();

    program::observe_program_buffers(&worker, &roots, &mut |row| {
        rows.push(row);
        Ok::<_, ()>(())
    })
    .unwrap();

    assert_eq!(rows.len(), 4);
    assert_eq!(rows[0], LinuxPureWorkerBufferCapacityData::bytes(127));
    assert_eq!(
        rows[1],
        LinuxPureWorkerBufferCapacityData {
            capacity: 5,
            element_bytes: size_of::<(PathBuf, OwnedFd)>(),
            alignment: align_of::<(PathBuf, OwnedFd)>(),
        }
    );
    assert_eq!(rows[2], LinuxPureWorkerBufferCapacityData::bytes(73));
    assert_eq!(rows[3], LinuxPureWorkerBufferCapacityData::bytes(89));
    assert_eq!(
        worker.as_os_str().as_encoded_bytes().as_ptr(),
        original_worker
    );
    assert_eq!(roots.as_ptr(), original_roots);

    let mut refused_prefix = Vec::new();
    let result = program::observe_program_buffers(&worker, &roots, &mut |row| {
        if refused_prefix.len() == 2 {
            return Err("no next row");
        }
        refused_prefix.push(row);
        Ok(())
    });
    assert_eq!(result, Err("no next row"));
    assert_eq!(refused_prefix, rows[..2]);
    assert_eq!(roots.as_ptr(), original_roots);
    assert_eq!(roots.len(), 2);
}

#[test]
fn empty_spare_runtime_roster_retains_compiled_element_geometry() {
    let worker = PathBuf::new();
    let roots = Vec::with_capacity(7);
    let mut rows = Vec::new();

    program::observe_program_buffers(&worker, &roots, &mut |row| {
        rows.push(row);
        Ok::<_, ()>(())
    })
    .unwrap();

    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].capacity, 0);
    assert_eq!(rows[1].capacity, 7);
    assert_eq!(rows[1].element_bytes, size_of::<(PathBuf, OwnedFd)>());
    assert_eq!(rows[1].alignment, align_of::<(PathBuf, OwnedFd)>());
    assert!(roots.is_empty());
}
