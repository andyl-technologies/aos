//! Checks retained program DATA without constructing a verified installation.
//!
//! Real descriptors use complete-byte fallback, so no lease notification worker
//! or live Source/program grant is fabricated by these field-walk specimens.

use super::*;
use std::mem::{align_of, size_of};

fn revoked_program() -> LinuxPureWorkerProgram {
    let executable = Path::new("/proc/self/exe");
    let path = |capacity, name| {
        let mut path = PathBuf::with_capacity(capacity);
        path.push(name);
        path
    };
    let mut roots = Vec::with_capacity(5);
    for (name, capacity) in [("retained-a", 73), ("retained-b", 89)] {
        roots.push((path(capacity, name), File::open(executable).unwrap().into()));
    }
    LinuxPureWorkerProgram {
        original: Arc::new(OriginalProgram {
            launcher: Mutex::new(LinuxReadLeaseFile::open(executable, None).unwrap()),
            launcher_measurement: File::open(executable).unwrap(),
            launcher_exec: File::open(executable).unwrap().into(),
            worker: Mutex::new(LinuxReadLeaseFile::open(executable, None).unwrap()),
            worker_measurement: File::open(executable).unwrap(),
            worker_path: path(127, "retained-worker"),
            worker_digest: [7; 32],
            algorithm_digest: [11; 32],
            roots,
            revoked: AtomicBool::new(true),
        }),
    }
}

#[test]
fn revoked_program_capacity_views_keep_original_layout_and_spare_buffers() {
    let program = revoked_program();
    let payload = Arc::as_ptr(&program.original);
    let worker = program
        .original
        .worker_path
        .as_os_str()
        .as_encoded_bytes()
        .as_ptr();
    let roots = program.original.roots.as_ptr();
    let references = Arc::strong_count(&program.original);
    let mut rows = Vec::new();

    let layout = program.retained_payload_layout_data();
    program
        .observe_direct_buffers(&mut |row| {
            rows.push(row);
            Ok::<_, ()>(())
        })
        .unwrap();

    assert_eq!(layout.size(), size_of::<OriginalProgram>());
    assert_eq!(layout.align(), align_of::<OriginalProgram>());
    assert_eq!(rows.len(), 4);
    assert_eq!(rows[0].capacity, 127);
    assert_eq!(rows[1].capacity, 5);
    assert_eq!(rows[1].element_bytes, size_of::<(PathBuf, OwnedFd)>());
    assert_eq!(rows[1].alignment, align_of::<(PathBuf, OwnedFd)>());
    assert_eq!(rows[2].capacity, 73);
    assert_eq!(rows[3].capacity, 89);
    assert_eq!(Arc::as_ptr(&program.original), payload);
    assert_eq!(Arc::strong_count(&program.original), references);
    assert_eq!(
        program
            .original
            .worker_path
            .as_os_str()
            .as_encoded_bytes()
            .as_ptr(),
        worker
    );
    assert_eq!(program.original.roots.as_ptr(), roots);
    assert!(program.original.revoked.load(Ordering::Acquire));
    assert!(program.original.launcher.lock().unwrap().lease().is_none());
}

#[test]
fn repeated_program_views_repeat_rows_and_preserve_callback_refusal_prefix() {
    let program = revoked_program();
    let alias = program.clone();
    let references = Arc::strong_count(&program.original);
    let mut rows = Vec::new();

    for view in [&program, &alias] {
        view.observe_direct_buffers(&mut |row| {
            rows.push(row);
            Ok::<_, ()>(())
        })
        .unwrap();
    }
    assert_eq!(rows.len(), 8);
    assert_eq!(rows[..4], rows[4..]);
    let mut prefix = Vec::new();
    let result = program.observe_direct_buffers(&mut |row| {
        if prefix.len() == 2 {
            return Err("selected row restriction");
        }
        prefix.push(row);
        Ok(())
    });

    assert_eq!(result, Err("selected row restriction"));
    assert_eq!(prefix, rows[..2]);
    assert_eq!(Arc::strong_count(&program.original), references);
    assert!(program.original.revoked.load(Ordering::Acquire));
}

#[test]
fn retained_identity_repeats_program_geometry_without_cloning_or_authentication() {
    let program = revoked_program();
    let identity = program.identity();
    let references = Arc::strong_count(&program.original);
    let mut program_rows = Vec::new();
    let mut identity_rows = Vec::new();

    program
        .observe_direct_buffers(&mut |row| {
            program_rows.push(row);
            Ok::<_, ()>(())
        })
        .unwrap();
    identity
        .observe_direct_buffers(&mut |row| {
            identity_rows.push(row);
            Ok::<_, ()>(())
        })
        .unwrap();

    assert_eq!(
        identity.retained_payload_layout_data(),
        program.retained_payload_layout_data()
    );
    assert_eq!(identity_rows, program_rows);
    assert_eq!(Arc::strong_count(&program.original), references);
    assert!(program.original.revoked.load(Ordering::Acquire));
    assert!(program.original.worker.lock().unwrap().lease().is_none());
    let mut prefix = Vec::new();
    assert_eq!(
        identity.observe_direct_buffers(&mut |row| {
            if prefix.len() == 1 {
                return Err("row restriction");
            }
            prefix.push(row);
            Ok(())
        }),
        Err("row restriction")
    );
    assert_eq!(prefix, program_rows[..1]);
    assert_eq!(Arc::strong_count(&program.original), references);
}
