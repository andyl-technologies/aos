//! Acquires one selected complete executable without a file-sized byte bank.
//!
//! The original metadata length is checked against the measured full reference
//! before any content read. Fixed positional hashing retains all descriptor,
//! namespace and kernel fences. This constructor is private to launch custody.

use super::*;
use crate::node_contract::RuntimeError;
use std::os::unix::ffi::OsStringExt;

impl OriginalExecutable {
    pub(in crate::node_adapters::cnp::semantic) const fn original_native_startup_link_bytes()
    -> usize {
        // Linux path extent plus the deleted-file suffix and one excess byte.
        4096 + b" (deleted)".len() + 1
    }

    pub(in crate::node_adapters::cnp::semantic) fn open_original_native_startup(
        pid: u32,
        expected: &ContentRef,
        kernel: &KernelIdentity,
        scratch: &mut FreshCurrentScratch,
    ) -> Result<Self, RuntimeError> {
        kernel.ensure_fresh_current(scratch)?;
        let path = scratch.proc_path(pid, b"/exe")?;
        let process_path = exact_path(path.to_bytes())?;
        let original = LinuxReadLeaseFile::open(&process_path, None)
            .map_err(|_| RuntimeError::OwnerUnavailable)?;
        let revision = FileRevision::read(
            original
                .file()
                .metadata()
                .map_err(|_| RuntimeError::OwnerUnavailable)?,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        // A changed file cannot choose a larger allocation before this test.
        authenticate_birth_revision(expected, &revision)?;
        let count = scratch.read_original_native_link(pid)?;
        if count >= scratch.original_native_link_data().len() {
            return Err(RuntimeError::ResourceLimit);
        }
        let original_target = exact_path(&scratch.original_native_link_data()[..count])?;
        let guard = Self {
            creator: std::process::id(),
            thread: std::thread::current().id(),
            process_path,
            original_target,
            original,
            revision,
            expected: expected.clone(),
            revoked: Cell::new(false),
            bounded_birth: true,
        };
        guard.fresh_fences(kernel, scratch)?;
        guard.measure_fresh_bytes(scratch)?;
        guard.fresh_fences(kernel, scratch)?;
        Ok(guard)
    }

    pub(in crate::node_adapters::cnp::semantic) fn ensure_kernel_current(
        &self,
        kernel: &KernelIdentity,
    ) -> Result<(), ProviderError> {
        if self.bounded_birth {
            let mut scratch = self
                .fresh_current_scratch()
                .map_err(|_| changed("selected native kernel scratch refused"))?;
            kernel
                .ensure_fresh_current(&mut scratch)
                .map_err(|_| changed("selected native kernel changed"))
        } else {
            kernel.ensure_current()
        }
    }
}

fn exact_path(bytes: &[u8]) -> Result<PathBuf, RuntimeError> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(bytes.len())
        .map_err(|_| RuntimeError::ResourceLimit)?;
    if owned.capacity() > bytes.len() {
        return Err(RuntimeError::ResourceLimit);
    }
    owned.extend_from_slice(bytes);
    Ok(std::ffi::OsString::from_vec(owned).into())
}

fn authenticate_birth_revision(
    expected: &ContentRef,
    revision: &FileRevision,
) -> Result<(), RuntimeError> {
    if expected.length.get() != revision.length
        || expected.hash.algorithm != "blake3-256"
        || expected.hash.domain != "cnp.blob.v1"
        || expected.media_type != "application/octet-stream"
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::OpenOptions,
        io::Write,
        sync::atomic::{AtomicU64, Ordering},
    };

    // This owns only an exclusively created data file. No Child or native
    // capability exists in this test; the guard being tested precedes hashing.
    struct DataFile {
        path: PathBuf,
        file: std::fs::File,
    }
    impl DataFile {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            for _ in 0..64 {
                let ordinal = NEXT.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "aos-native-birth-extent-{}-{ordinal}",
                    std::process::id()
                ));
                match OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(&path)
                {
                    Ok(file) => return Self { path, file },
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("data fixture: {error}"),
                }
            }
            panic!("exclusive data fixture exhausted")
        }
    }
    impl Drop for DataFile {
        fn drop(&mut self) {
            let _cleanup = std::fs::remove_file(&self.path);
        }
    }

    #[test]
    fn actual_file_growth_refuses_before_selected_executable_read() {
        let mut data = DataFile::new();
        data.file.write_all(b"original").unwrap();
        let expected = canonical::content_ref(b"original", "application/octet-stream").unwrap();
        let before = FileRevision::read(data.file.metadata().unwrap()).unwrap();
        authenticate_birth_revision(&expected, &before).unwrap();

        data.file.write_all(b"!").unwrap();
        let changed = FileRevision::read(data.file.metadata().unwrap()).unwrap();
        assert_eq!(
            authenticate_birth_revision(&expected, &changed),
            Err(RuntimeError::InvalidReceipt)
        );
        assert_eq!(expected.length.get(), 8);
        assert_eq!(changed.length, 9);
    }

    #[test]
    fn selected_proc_paths_use_fixed_banks_for_full_pid_range() {
        let mut scratch = FreshCurrentScratch::for_original_native_startup().unwrap();
        for pid in [0, 1, 9, 10, u32::MAX] {
            let expected = format!("/proc/{pid}/exe");
            assert_eq!(
                scratch.proc_path(pid, b"/exe").unwrap().to_bytes(),
                expected.as_bytes()
            );
        }
        assert_eq!(
            scratch.original_native_link_data().len(),
            OriginalExecutable::original_native_startup_link_bytes()
        );
    }
}
