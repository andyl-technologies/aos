//! OS mapping teardown and errno capture.

pub(super) fn unmap_setup_region(ptr: *mut libc::c_void, len: usize) {
    // SAFETY: callers pass an address and length returned by `mmap`.
    unsafe {
        libc::munmap(ptr, len);
    }
}

pub(super) fn last_os_error() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}
use super::*;

pub(super) fn setup_region_backing_identity(
    fd: BorrowedFd<'_>,
) -> Result<SetupRegionBackingIdentity, SetupRegionMapError> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `stat` points to valid writable storage and `fd` is borrowed from
    // a live owned descriptor for the duration of the syscall.
    let result = unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) };
    if result != 0 {
        return Err(SetupRegionMapError::FstatFailed {
            errno: last_os_error(),
        });
    }
    // SAFETY: successful `fstat` initialized the output structure.
    let stat = unsafe { stat.assume_init() };
    let length =
        u64::try_from(stat.st_size).map_err(|_| SetupRegionMapError::NegativeBackingLength {
            backing_len: stat.st_size,
        })?;
    Ok(SetupRegionBackingIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
        length,
    })
}
