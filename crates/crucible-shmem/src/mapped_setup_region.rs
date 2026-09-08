//! Owned setup-region mappings and typed accessors.

use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::ptr::NonNull;

use thiserror::Error;

use crate::region::{helpers::directed_rings, layout_from_setup_region_header};

use super::{
    ACCELERATOR_ENTRY_ALIGN, ACCELERATOR_ENTRY_SIZE, AcceleratorEntry, AcceleratorRingDirection,
    COVERAGE_ENTRY_ALIGN, COVERAGE_ENTRY_SIZE, CoverageEntry, DirectedRing,
    FAULT_COMMAND_SLOT_V1_BYTES, FAULT_EVENT_SLOT_V1_BYTES, FAULT_PAYLOAD_ARENA_HEADER_BYTES,
    FAULT_RESULT_SLOT_V1_BYTES, FINGERPRINT_SAMPLE_SLOT_ALIGN, FINGERPRINT_SAMPLE_SLOT_SIZE,
    FRAME_ENTRY_ALIGN, FRAME_ENTRY_SIZE, FaultCommandSlotV1, FaultEventSlotV1,
    FaultPayloadArenaHeader, FaultResultSlotV1, FingerprintSampleSlot, FrameEntry,
    GUEST_INTROSPECTION_ENTRY_ALIGN, GUEST_INTROSPECTION_ENTRY_SIZE, GuestIntrospectionEntry,
    GuestIntrospectionRingDirection, NODE_SLOT_ALIGN, NODE_SLOT_SIZE, NodeSlot,
    REGION_HEADER_ALIGN, REGION_HEADER_SIZE, RING_HEADER_ALIGN, RING_HEADER_SIZE, RegionHeader,
    RegionLayout, RegionLayoutError, RegionSetupValidationError, RingHeader, SpscRingError,
    ValidatedSetupRegion, WHITEBOX_MARKER_ENTRY_ALIGN, WHITEBOX_MARKER_ENTRY_SIZE,
    WhiteboxMarkerEntry, validate_setup_region_header,
};

#[path = "mapped_setup_region/views.rs"]
mod views;

pub use views::*;
use views::{AcceleratorRingPairMut, GuestIntrospectionRawRingMut, GuestIntrospectionRingPairMut};

#[path = "mapped_setup_region/basic_access.rs"]
mod basic_access;
#[path = "mapped_setup_region/device_rings.rs"]
mod device_rings;
#[path = "mapped_setup_region/fault_transports.rs"]
mod fault_transports;
#[path = "mapped_setup_region/hot_fork.rs"]
mod hot_fork;
pub use hot_fork::{
    HOT_FORK_RING_IMAGE_SCHEMA_VERSION, HotForkChildMappingInstallError,
    HotForkMappingDispositionError, HotForkRingImage, HotForkRingImageError,
    MappedRingIoBarrierSnapshot,
};

impl Drop for MappedSetupRegion {
    fn drop(&mut self) {
        // SAFETY: `getpid` has no pointer preconditions and cannot fail.
        // A DONTFORK child inherits this Rust owner but not its source VMA. It
        // must not unmap an unrelated mapping that later occupied the address.
        if self.mapping_process_id != unsafe { libc::getpid() } {
            return;
        }
        // SAFETY: `ptr` and `len` were returned by `mmap` and are owned by this
        // value until `Drop`.
        unsafe {
            libc::munmap(self.base_ptr().cast::<libc::c_void>(), self.len);
        }
    }
}

/// Maps a setup shared-memory descriptor for exactly the `Setup.region_len`.
///
/// The descriptor's current length is checked before `mmap`, so an immediately
/// short backing file is rejected without touching memory beyond the file.
/// On Linux, a descriptor that supports memfd seals must carry `F_SEAL_SHRINK`
/// before the mapping is touched. Descriptors that do not support seals retain
/// a point-in-time size check, so their callers must separately prevent
/// truncation for the mapping's lifetime.
///
/// # Errors
///
/// Returns [`SetupRegionMapError`] when `region_len` cannot fit in `usize`, is
/// too small for a [`RegionHeader`], the descriptor cannot be inspected or is
/// shorter than `region_len`, or when `mmap` fails or returns a mapping
/// unsuitable for the shared-memory ABI.
pub fn mmap_setup_region(
    fd: BorrowedFd<'_>,
    region_len: u64,
) -> Result<MappedSetupRegion, SetupRegionMapError> {
    let len = usize::try_from(region_len)
        .map_err(|_| SetupRegionMapError::RegionLenTooLarge { region_len })?;
    let minimum_len = REGION_HEADER_SIZE as u64;
    if region_len < minimum_len {
        return Err(SetupRegionMapError::RegionTooSmall {
            region_len,
            minimum_len,
        });
    }

    let backing_identity = setup_region_backing_identity(fd)?;
    if backing_identity.length() < region_len {
        return Err(SetupRegionMapError::BackingTooShort {
            backing_len: backing_identity.length(),
            region_len,
        });
    }
    verify_setup_region_shrink_seal(fd)?;

    // SAFETY: the returned mapping is checked before being wrapped. The fd is
    // borrowed for the syscall only; the mapping owns the resulting address.
    let raw = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd.as_raw_fd(),
            0,
        )
    };
    if raw == libc::MAP_FAILED {
        return Err(SetupRegionMapError::MmapFailed {
            errno: last_os_error(),
        });
    }

    let Some(ptr) = NonNull::new(raw.cast::<u8>()) else {
        unmap_setup_region(raw, len);
        return Err(SetupRegionMapError::NullMapping);
    };
    if !(ptr.as_ptr() as usize).is_multiple_of(REGION_HEADER_ALIGN) {
        unmap_setup_region(raw, len);
        return Err(SetupRegionMapError::UnalignedMapping {
            alignment: REGION_HEADER_ALIGN,
        });
    }

    Ok(MappedSetupRegion {
        address: ptr.as_ptr() as usize,
        len,
        region_len,
        backing_identity,
        // SAFETY: `getpid` has no pointer preconditions and cannot fail.
        mapping_process_id: unsafe { libc::getpid() },
    })
}

#[path = "mapped_setup_region/errors.rs"]
mod errors;

pub use errors::{MappedSetupRegionAccessError, SetupRegionMapError};

#[path = "mapped_setup_region/offsets.rs"]
mod offsets;

use offsets::*;

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::ffi::CString;
    use std::io;
    use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};

    use super::*;

    #[test]
    fn owned_mapping_can_move_to_a_session_thread() {
        fn assert_send<T: Send>() {}
        assert_send::<MappedSetupRegion>();
    }

    #[test]
    fn seal_capable_memfd_must_prevent_shrink_before_mapping()
    -> Result<(), Box<dyn std::error::Error>> {
        let fd = test_memfd()?;
        let region_len = REGION_HEADER_SIZE as u64;
        let truncate = unsafe {
            // SAFETY: `fd` is live and the header size fits in `off_t`.
            libc::ftruncate(fd.as_raw_fd(), REGION_HEADER_SIZE as libc::off_t)
        };
        if truncate != 0 {
            return Err(Box::new(io::Error::last_os_error()));
        }

        assert_eq!(
            mmap_setup_region(fd.as_fd(), region_len).map(|mapped| mapped.region_len()),
            Err(SetupRegionMapError::MissingShrinkSeal { seals: 0 })
        );

        let add_seal = unsafe {
            // SAFETY: `fd` is a live memfd created with `MFD_ALLOW_SEALING`.
            libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, libc::F_SEAL_SHRINK)
        };
        if add_seal != 0 {
            return Err(Box::new(io::Error::last_os_error()));
        }

        let mapped = mmap_setup_region(fd.as_fd(), region_len)?;
        assert_eq!(mapped.region_len(), region_len);
        Ok(())
    }

    #[test]
    fn hot_fork_mapping_disposition_is_reversible() -> Result<(), Box<dyn std::error::Error>> {
        let region_len = REGION_HEADER_SIZE as u64;
        let fd = prepared_test_memfd(region_len)?;

        let mapped = mmap_setup_region(fd.as_fd(), region_len)?;
        assert!(
            !mapping_vm_flags(mapped.address)?
                .iter()
                .any(|flag| flag == "dc")
        );

        mapped.exclude_from_hot_fork_child()?;
        assert!(
            mapping_vm_flags(mapped.address)?
                .iter()
                .any(|flag| flag == "dc")
        );

        mapped.restore_hot_fork_parent_inheritance()?;
        assert!(
            !mapping_vm_flags(mapped.address)?
                .iter()
                .any(|flag| flag == "dc")
        );
        Ok(())
    }

    #[test]
    fn hot_fork_child_installs_private_mapping_at_exact_source_address()
    -> Result<(), Box<dyn std::error::Error>> {
        let region_len = REGION_HEADER_SIZE as u64;
        let source_fd = prepared_test_memfd(region_len)?;
        let destination_fd = prepared_test_memfd(region_len)?;
        let destination_identity = setup_region_backing_identity(destination_fd.as_fd())?;
        let mut mapped = mmap_setup_region(source_fd.as_fd(), region_len)?;
        let source_identity = mapped.backing_identity();

        assert_eq!(
            mapped.install_hot_fork_child_mapping(source_fd.as_fd(), source_identity),
            Err(HotForkChildMappingInstallError::SourceAlias)
        );
        let wrong_identity = SetupRegionBackingIdentity::from_parts(
            destination_identity.device(),
            if destination_identity.inode() == u64::MAX {
                destination_identity.inode() - 1
            } else {
                destination_identity.inode() + 1
            },
            destination_identity.length(),
        )
        .ok_or_else(|| io::Error::other("valid wrong test identity"))?;
        assert!(matches!(
            mapped.install_hot_fork_child_mapping(destination_fd.as_fd(), wrong_identity),
            Err(HotForkChildMappingInstallError::IdentityMismatch { .. })
        ));
        let wrong_length = SetupRegionBackingIdentity::from_parts(
            destination_identity.device(),
            destination_identity.inode(),
            destination_identity.length() + 1,
        )
        .ok_or_else(|| io::Error::other("valid wrong test length"))?;
        assert!(matches!(
            mapped.install_hot_fork_child_mapping(destination_fd.as_fd(), wrong_length),
            Err(HotForkChildMappingInstallError::LengthMismatch { .. })
        ));

        assert_eq!(
            mapped.install_hot_fork_child_mapping(destination_fd.as_fd(), destination_identity,),
            Err(HotForkChildMappingInstallError::AddressOccupied)
        );
        assert_eq!(mapped.backing_identity(), source_identity);

        mapped.exclude_from_hot_fork_child()?;
        // SAFETY: the child performs only bounded descriptor/mapping syscalls,
        // writes one byte, and exits with `_exit` without entering test-harness
        // or allocator teardown. The parent remains the only test runner.
        let child = unsafe { libc::fork() };
        if child < 0 {
            return Err(Box::new(io::Error::last_os_error()));
        }
        if child == 0 {
            let installed = mapped
                .install_hot_fork_child_mapping(destination_fd.as_fd(), destination_identity)
                .is_ok();
            if !installed || mapped.backing_identity() != destination_identity {
                // SAFETY: `_exit` terminates only the fork child and runs no
                // inherited Rust destructors.
                unsafe { libc::_exit(1) };
            }
            // SAFETY: the successful install made this exact byte range live
            // in the child and the mapping is writable.
            unsafe { mapped.base_ptr().write(0x5a) };
            // SAFETY: see the failure exit above.
            unsafe { libc::_exit(0) };
        }

        let mut status = 0;
        let waited = loop {
            // SAFETY: `child` is the positive PID returned to this parent and
            // `status` points to writable storage.
            let waited = unsafe { libc::waitpid(child, &mut status, 0) };
            if waited >= 0 || io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                break waited;
            }
        };
        if waited != child {
            return Err(Box::new(io::Error::last_os_error()));
        }
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);

        let mut destination_byte = 0_u8;
        // SAFETY: the destination fd is live and the one-byte output buffer is
        // valid for the duration of `pread`.
        let read = unsafe {
            libc::pread(
                destination_fd.as_raw_fd(),
                std::ptr::from_mut(&mut destination_byte).cast::<libc::c_void>(),
                1,
                0,
            )
        };
        assert_eq!(read, 1);
        assert_eq!(destination_byte, 0x5a);
        assert_eq!(mapped.backing_identity(), source_identity);
        mapped.restore_hot_fork_parent_inheritance()?;
        Ok(())
    }

    fn mapping_vm_flags(address: usize) -> io::Result<Vec<String>> {
        let smaps = std::fs::read_to_string("/proc/self/smaps")?;
        let mut selected = false;
        for line in smaps.lines() {
            if let Some((range, _rest)) = line.split_once(' ')
                && let Some((start, end)) = range.split_once('-')
                && let (Ok(start), Ok(end)) = (
                    usize::from_str_radix(start, 16),
                    usize::from_str_radix(end, 16),
                )
            {
                selected = start <= address && address < end;
                continue;
            }
            if selected && let Some(flags) = line.strip_prefix("VmFlags: ") {
                return Ok(flags.split_ascii_whitespace().map(str::to_owned).collect());
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "mapped setup region was absent from /proc/self/smaps",
        ))
    }

    fn test_memfd() -> io::Result<OwnedFd> {
        let name = CString::new("crucible-shmem-seal-test")
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let raw_fd = unsafe {
            // SAFETY: `name` is a valid NUL-terminated C string.
            libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
        };
        if raw_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful `memfd_create` returned a new descriptor whose
        // ownership is transferred exactly once into `OwnedFd`.
        Ok(unsafe { OwnedFd::from_raw_fd(raw_fd) })
    }

    fn prepared_test_memfd(region_len: u64) -> io::Result<OwnedFd> {
        let fd = test_memfd()?;
        let length = libc::off_t::try_from(region_len)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        // SAFETY: `fd` is live and `length` was checked for `off_t`.
        if unsafe { libc::ftruncate(fd.as_raw_fd(), length) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a live memfd created with `MFD_ALLOW_SEALING`.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, libc::F_SEAL_SHRINK) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fd)
    }
}
mod os_mapping;
use os_mapping::*;
