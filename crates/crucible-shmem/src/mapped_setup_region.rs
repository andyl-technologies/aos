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
    HOT_FORK_RING_IMAGE_SCHEMA_VERSION, HotForkMappingDispositionError, HotForkRingImage,
    HotForkRingImageError, MappedRingIoBarrierSnapshot,
};

impl Drop for MappedSetupRegion {
    fn drop(&mut self) {
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
        let fd = test_memfd()?;
        let region_len = REGION_HEADER_SIZE as u64;
        let truncate = unsafe {
            // SAFETY: `fd` is live and the header size fits in `off_t`.
            libc::ftruncate(fd.as_raw_fd(), REGION_HEADER_SIZE as libc::off_t)
        };
        if truncate != 0 {
            return Err(Box::new(io::Error::last_os_error()));
        }
        let add_seal = unsafe {
            // SAFETY: `fd` is a live memfd created with `MFD_ALLOW_SEALING`.
            libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, libc::F_SEAL_SHRINK)
        };
        if add_seal != 0 {
            return Err(Box::new(io::Error::last_os_error()));
        }

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
}
mod os_mapping;
use os_mapping::*;
