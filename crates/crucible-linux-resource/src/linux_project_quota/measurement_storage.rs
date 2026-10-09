//! Pins the original loop image, block device and ext4 root as one static domain.
//!
//! Authentication reads existing kernel state; it never formats, mounts, grows
//! or issues backing credit. The private disposable-host operator must install
//! and fund these effects before native birth. These pins remain retained on a
//! failed readback, and abandoning them quarantines the original loan rather
//! than refunding still-live device or namespace authority.

use super::*;
use crate::host_services::HostServiceLease;
use rustix::fs::{StatVfsMountFlags, fstatvfs};
use rustix::ioctl::Updater;

const MAX_HOST_BACKING_BYTES: u64 = 64 << 30;
const LOOP_GET_STATUS64: rustix::ioctl::Opcode = 0x4c05;
const BLKGETSIZE64: rustix::ioctl::Opcode = opcode::read::<u64>(0x12, 114);
const LOOP_AUTOCLEAR: u32 = 4;
const FS_IOC_FIEMAP: rustix::ioctl::Opcode = 0xc020660b;
const FIEMAP_SYNC: u32 = 1;
const FIEMAP_LAST: u32 = 1;
const FIEMAP_UNWRITTEN: u32 = 0x800;
const IMAGE_EXTENTS_PER_READ: usize = 16;
const MAX_IMAGE_EXTENT_READS: usize = 256;

/// Immutable raw-image and usable-data requirements for a private static domain.
///
/// Raw bytes include filesystem overhead; writable bytes are the admitted
/// aggregate native data requirement. This local contract does not account for
/// Source, catalog, registry, swap or evidence sharing the total host disk.
#[derive(Clone, Copy, Debug)]
pub struct MeasurementStorageContract {
    raw_bytes: u64,
    writable_bytes: u64,
    inodes: u64,
}

impl MeasurementStorageContract {
    /// Checks nonzero, bounded raw bytes, writable bytes and inode requirements.
    ///
    /// # Errors
    /// Refuses a missing requirement, writable bytes without overhead room,
    /// more than the fixed sixty-four-GiB whole-host ceiling, or inode overflow.
    pub fn new(
        raw_bytes: u64,
        writable_bytes: u64,
        inodes: u64,
    ) -> Result<Self, MeasurementStorageError> {
        if writable_bytes == 0
            || raw_bytes <= writable_bytes
            || raw_bytes > MAX_HOST_BACKING_BYTES
            || inodes == 0
            || inodes > MAX_PROJECT_QUOTA_INODES
        {
            return Err(MeasurementStorageError::Contract);
        }
        Ok(Self {
            raw_bytes,
            writable_bytes,
            inodes,
        })
    }
}

/// Refusal while the caller retains its existing original domain record.
#[derive(Debug, Error)]
pub enum MeasurementStorageError {
    /// The fixed compiled domain requirements were invalid.
    #[error("invalid static native storage requirements")]
    Contract,
    /// The original loan or operation does not cover this component.
    #[error("static native storage lacks its original preparation purpose")]
    Original,
    /// Pins were already installed, or are not yet installed.
    #[error("static native storage is in the wrong lifecycle state")]
    State,
    /// The image, loop device or root differs from the required binding.
    #[error("static native storage binding differs at {0}")]
    Binding(&'static str),
    /// Original supervision refused a kernel readback.
    #[error("static native storage supervision refused: {0}")]
    Supervision(#[from] HostSupervisionError),
    /// A read-only kernel operation failed.
    #[error("static native storage {operation} failed: {source}")]
    Io {
        /// Fixed operation that failed.
        operation: &'static str,
        /// Original kernel error.
        source: rustix::io::Errno,
        /// Same original post-read refusal, retained after the kernel primary.
        after: Option<HostSupervisionError>,
    },
    /// Existing ext4 project-quota authentication refused the root.
    #[error("static native storage quota binding refused: {source}")]
    Quota {
        /// Original concrete project-quota read failure.
        source: LinuxProjectQuotaError,
        /// Same original post-read refusal, retained after the kernel primary.
        after: Option<HostSupervisionError>,
    },
}

/// Retains the original static storage pins and credit through failed readback.
///
/// This first physical slice deliberately exports no factory root or retirement
/// certificate. The later enclosing genuine factory owner must prove process,
/// project, mount and loop closure under the original Cleanup scope. Until then,
/// dropping installed pins retains them and their loan for the process lifetime.
#[derive(Debug)]
#[must_use = "static storage pins require original physical retirement"]
pub struct MeasurementStoragePins<'operation> {
    operation: &'operation HostOperationGuard,
    image: Option<OwnedFd>,
    device: Option<OwnedFd>,
    root: Option<OwnedFd>,
    contract: MeasurementStorageContract,
    installed: bool,
    authenticated: bool,
    // Last: no original refund can precede physical descriptor destruction.
    original: Option<HostServiceLease>,
}

impl<'operation> MeasurementStoragePins<'operation> {
    /// Saves the original preparation scope and already admitted storage loan.
    ///
    /// Three descriptors and a local readback buffer are component lower bounds,
    /// not full Source, stack, helper, filesystem or birth admission.
    ///
    /// # Errors
    /// Refuses a non-running preparation scope or an insufficient original loan.
    pub fn retain_original(
        original: HostServiceLease,
        contract: MeasurementStorageContract,
        operation: &'operation HostOperationGuard,
    ) -> Result<Self, MeasurementStorageError> {
        preparation_boundary(operation)?;
        if original.file_descriptors() < 3 || original.resident_bytes() < 4096 {
            return Err(MeasurementStorageError::Original);
        }
        Ok(Self {
            operation,
            image: None,
            device: None,
            root: None,
            contract,
            installed: false,
            authenticated: false,
            original: Some(original),
        })
    }

    /// Retains all existing pins before their first fallible authentication read.
    ///
    /// The caller transfers the complete regular image, loop block device and
    /// mounted root. No path reopening, adoption or helper runs here. Failure
    /// retains these same pins in this original owner; it cannot reset for reuse.
    ///
    /// # Errors
    /// Refuses reuse, original cancellation or expiry, sparse/incorrect backing,
    /// wrong loop identity/flags, another mount, inadequate usable capacity, or
    /// absent ext4 project-quota support.
    pub fn bind(
        &mut self,
        image: OwnedFd,
        device: OwnedFd,
        root: OwnedFd,
    ) -> Result<(), MeasurementStorageError> {
        if self.installed {
            return Err(MeasurementStorageError::State);
        }
        self.installed = true;
        self.image = Some(image);
        self.device = Some(device);
        self.root = Some(root);
        self.verify()?;
        self.authenticated = true;
        Ok(())
    }

    /// Reauthenticates the exact retained kernel binding and original scope.
    ///
    /// No scalar result or successful readback issues backing capacity. Complete
    /// enclosing role sums and physical retirement remain separate obligations.
    ///
    /// # Errors
    /// Refuses absent pins, a changed physical binding, insufficient usable
    /// space/inodes, kernel read failure, or original cancellation/expiry.
    pub fn verify(&self) -> Result<(), MeasurementStorageError> {
        // Operation classes are immutable; construction already authenticated
        // this exact borrowed preparation guard. Live checks use its original
        // scalar boundary without allocating monitoring-history vectors.
        self.operation.wait_slice()?;
        let image = self.image.as_ref().ok_or(MeasurementStorageError::State)?;
        let device = self.device.as_ref().ok_or(MeasurementStorageError::State)?;
        let root = self.root.as_ref().ok_or(MeasurementStorageError::State)?;
        let image_stat = kernel_read(self.operation, "inspect original image", fstat(image))?;
        self.operation.wait_slice()?;
        let device_stat = kernel_read(self.operation, "inspect original device", fstat(device))?;
        self.operation.wait_slice()?;
        let root_stat = kernel_read(self.operation, "inspect original root", fstat(root))?;
        self.operation.wait_slice()?;
        if FileType::from_raw_mode(image_stat.st_mode) != FileType::RegularFile
            || FileType::from_raw_mode(device_stat.st_mode) != FileType::BlockDevice
            || FileType::from_raw_mode(root_stat.st_mode) != FileType::Directory
            || root_stat.st_dev != device_stat.st_rdev
            || root_stat.st_ino != 2
        {
            return Err(MeasurementStorageError::Binding(
                "image/device/root identity",
            ));
        }
        let length =
            u64::try_from(image_stat.st_size).map_err(|_| MeasurementStorageError::Contract)?;
        let blocks =
            u64::try_from(image_stat.st_blocks).map_err(|_| MeasurementStorageError::Contract)?;
        check_image_extent(self.contract, length, blocks)?;
        verify_image_coverage(image, length, self.operation)?;
        self.operation.wait_slice()?;

        let loop_info = kernel_read(
            self.operation,
            "read original loop binding",
            loop_status(device),
        )?;
        check_loop_binding(&loop_info, image_stat.st_dev, image_stat.st_ino)?;
        self.operation.wait_slice()?;
        if kernel_read(
            self.operation,
            "read original block extent",
            block_bytes(device),
        )? != self.contract.raw_bytes
        {
            return Err(MeasurementStorageError::Binding("loop block length"));
        }
        self.operation.wait_slice()?;

        let filesystem = kernel_read(self.operation, "identify original ext4 root", fstatfs(root))?;
        self.operation.wait_slice()?;
        if filesystem.f_type != libc::EXT4_SUPER_MAGIC {
            return Err(MeasurementStorageError::Binding("original ext4 filesystem"));
        }
        quota_read(
            self.operation,
            project_quota_info(root, Path::new("static native root")),
        )?;
        self.operation.wait_slice()?;
        let capacity = kernel_read(
            self.operation,
            "inspect usable ext4 capacity",
            fstatvfs(root),
        )?;
        check_usable_capacity(
            self.contract,
            capacity.f_bavail,
            capacity.f_frsize,
            capacity.f_favail,
            capacity.f_flag,
        )?;
        self.operation.wait_slice()?;
        Ok(())
    }
}

impl Drop for MeasurementStoragePins<'_> {
    fn drop(&mut self) {
        if self.installed {
            // A failed read does not establish that the mount/device disappeared.
            // The enclosing failed actor retains this custody until actual cleanup.
            for pin in [&mut self.root, &mut self.device, &mut self.image] {
                if let Some(pin) = pin.take() {
                    std::mem::forget(pin);
                }
            }
            if let Some(original) = self.original.take() {
                std::mem::forget(original);
            }
        }
    }
}

fn preparation_boundary(operation: &HostOperationGuard) -> Result<(), MeasurementStorageError> {
    operation.wait_slice()?;
    if operation.status()?.class != HostOperationClass::Preparation {
        return Err(MeasurementStorageError::Original);
    }
    Ok(())
}

// Every completed read is checked, including failures. A kernel failure stays
// primary while cancellation/expiry at its original post-boundary stays typed.
fn kernel_read<T>(
    original: &HostOperationGuard,
    operation: &'static str,
    result: rustix::io::Result<T>,
) -> Result<T, MeasurementStorageError> {
    let after = original.wait_slice();
    match result {
        Ok(value) => {
            after?;
            Ok(value)
        }
        Err(source) => Err(MeasurementStorageError::Io {
            operation,
            source,
            after: after.err(),
        }),
    }
}

fn quota_read<T>(
    original: &HostOperationGuard,
    result: Result<T, LinuxProjectQuotaError>,
) -> Result<T, MeasurementStorageError> {
    let after = original.wait_slice();
    match result {
        Ok(value) => {
            after?;
            Ok(value)
        }
        Err(source) => Err(MeasurementStorageError::Quota {
            source,
            after: after.err(),
        }),
    }
}

fn check_image_extent(
    contract: MeasurementStorageContract,
    length: u64,
    blocks: u64,
) -> Result<(), MeasurementStorageError> {
    if length != contract.raw_bytes || blocks.checked_mul(512).is_none_or(|bytes| bytes < length) {
        return Err(MeasurementStorageError::Binding(
            "fully allocated original image",
        ));
    }
    Ok(())
}

fn check_usable_capacity(
    contract: MeasurementStorageContract,
    available: u64,
    fragment_bytes: u64,
    inodes: u64,
    flags: StatVfsMountFlags,
) -> Result<(), MeasurementStorageError> {
    if flags.contains(StatVfsMountFlags::RDONLY)
        || fragment_bytes == 0
        || available
            .checked_mul(fragment_bytes)
            .is_none_or(|bytes| bytes < contract.writable_bytes)
        || inodes < contract.inodes
    {
        return Err(MeasurementStorageError::Binding(
            "usable aggregate data/inodes",
        ));
    }
    Ok(())
}

// st_blocks is only a total. Logical coverage must also exclude holes whose
// missing space was compensated by extents beyond EOF. A fixed buffer bounds
// each query; fragmented images beyond this finite setup envelope refuse.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct ImageExtent {
    logical: u64,
    physical: u64,
    length: u64,
    reserved64: [u64; 2],
    flags: u32,
    reserved: [u32; 3],
}

#[repr(C)]
#[derive(Debug)]
struct ImageExtentMap {
    start: u64,
    length: u64,
    flags: u32,
    mapped: u32,
    capacity: u32,
    reserved: u32,
    extents: [ImageExtent; IMAGE_EXTENTS_PER_READ],
}

impl ImageExtentMap {
    fn new(start: u64, length: u64) -> Self {
        Self {
            start,
            length,
            flags: FIEMAP_SYNC,
            mapped: 0,
            capacity: IMAGE_EXTENTS_PER_READ as u32,
            reserved: 0,
            extents: [ImageExtent::default(); IMAGE_EXTENTS_PER_READ],
        }
    }
}

fn verify_image_coverage(
    image: &OwnedFd,
    length: u64,
    original: &HostOperationGuard,
) -> Result<(), MeasurementStorageError> {
    let mut covered = 0;
    for _ in 0..MAX_IMAGE_EXTENT_READS {
        original.wait_slice()?;
        let mut map = ImageExtentMap::new(covered, length - covered);
        // SAFETY: FS_IOC_FIEMAP reads the stable 32-byte repr(C) header and
        // writes at most its declared sixteen 56-byte extents. The complete
        // aligned buffer is live for this ioctl; only scalar UAPI fields cross
        // the kernel boundary. SYNC resolves pending allocation before mapping.
        let result = unsafe {
            ioctl(
                image,
                Updater::<FS_IOC_FIEMAP, ImageExtentMap>::new(&mut map),
            )
        };
        kernel_read(original, "read original logical image extents", result)?;
        covered = advance_image_coverage(&map, covered, length)?;
        if covered == length {
            return Ok(());
        }
    }
    Err(MeasurementStorageError::Binding(
        "logical image extent limit",
    ))
}

fn advance_image_coverage(
    map: &ImageExtentMap,
    mut covered: u64,
    length: u64,
) -> Result<u64, MeasurementStorageError> {
    let count = usize::try_from(map.mapped).map_err(|_| MeasurementStorageError::Contract)?;
    if count == 0 || count > IMAGE_EXTENTS_PER_READ || map.capacity != IMAGE_EXTENTS_PER_READ as u32
    {
        return Err(MeasurementStorageError::Binding(
            "missing logical image extents",
        ));
    }
    for (index, extent) in map.extents[..count].iter().enumerate() {
        let end = extent
            .logical
            .checked_add(extent.length)
            .ok_or(MeasurementStorageError::Contract)?;
        // Unwritten preallocated extents own real disk space. Unknown, delayed,
        // shared, encoded and inline extents cannot establish exclusive backing.
        if extent.length == 0
            || extent.physical == 0
            || extent.flags & !(FIEMAP_LAST | FIEMAP_UNWRITTEN) != 0
            || extent.logical > covered
            || end <= covered
            || (index != 0 && extent.logical != covered)
            || (extent.flags & FIEMAP_LAST != 0 && (index + 1 != count || end < length))
        {
            return Err(MeasurementStorageError::Binding(
                "hole or uncertain logical image extent",
            ));
        }
        covered = end.min(length);
        if covered == length {
            if index + 1 != count {
                return Err(MeasurementStorageError::Binding(
                    "out-of-range logical image extents",
                ));
            }
            return Ok(covered);
        }
    }
    Ok(covered)
}

// Stable Linux syscall UAPI, separate from either process's private objects.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct LoopInfo {
    device: u64,
    inode: u64,
    rdevice: u64,
    offset: u64,
    size_limit: u64,
    number: u32,
    encrypt_type: u32,
    encrypt_key_size: u32,
    flags: u32,
    file_name: [u8; 64],
    crypt_name: [u8; 64],
    encrypt_key: [u8; 32],
    init: [u64; 2],
}

fn check_loop_binding(
    info: &LoopInfo,
    device: u64,
    inode: u64,
) -> Result<(), MeasurementStorageError> {
    if info.device != device
        || info.inode != inode
        || info.offset != 0
        || info.size_limit != 0
        || info.flags != LOOP_AUTOCLEAR
        || info.encrypt_type != 0
        || info.encrypt_key_size != 0
    {
        return Err(MeasurementStorageError::Binding(
            "original full writable autoclear loop image",
        ));
    }
    Ok(())
}

fn loop_status(device: &OwnedFd) -> rustix::io::Result<LoopInfo> {
    // SAFETY: LOOP_GET_STATUS64 writes exactly the stable repr(C) loop_info64
    // UAPI into Getter-owned aligned storage. The retained descriptor is live;
    // unsupported/non-loop descriptors return a kernel error without mutation.
    unsafe { ioctl(device, Getter::<LOOP_GET_STATUS64, LoopInfo>::new()) }
}

fn block_bytes(device: &OwnedFd) -> rustix::io::Result<u64> {
    // SAFETY: BLKGETSIZE64 is a read-only getter writing exactly one u64 into
    // aligned Getter-owned storage; this owner retains the live block descriptor.
    unsafe { ioctl(device, Getter::<BLKGETSIZE64, u64>::new()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_contract_requires_real_filesystem_overhead_room() {
        for (raw, writable, inodes) in [
            (0, 0, 1),
            (4096, 4096, 1),
            (8192, 4096, 0),
            (MAX_HOST_BACKING_BYTES + 1, 4096, 1),
        ] {
            assert!(MeasurementStorageContract::new(raw, writable, inodes).is_err());
        }
        assert!(MeasurementStorageContract::new(8192, 4096, 1).is_ok());
    }

    #[test]
    fn sparse_or_changed_extent_cannot_supply_aggregate_backing() {
        let contract = MeasurementStorageContract::new(8192, 4096, 1).unwrap();
        assert!(check_image_extent(contract, 8192, 16).is_ok());
        for (length, blocks) in [(8192, 15), (4096, 16), (8192, u64::MAX)] {
            assert!(check_image_extent(contract, length, blocks).is_err());
        }
        assert!(check_usable_capacity(contract, 1, 4096, 1, StatVfsMountFlags::empty()).is_ok());
        for (available, fragment, inodes) in
            [(0, 4096, 1), (1, 0, 1), (1, 4096, 0), (u64::MAX, 4096, 1)]
        {
            assert!(
                check_usable_capacity(
                    contract,
                    available,
                    fragment,
                    inodes,
                    StatVfsMountFlags::empty()
                )
                .is_err()
            );
        }
    }

    #[test]
    fn logical_holes_and_readonly_capacity_do_not_authenticate_backing() {
        let contract = MeasurementStorageContract::new(8192, 4096, 1).unwrap();
        // A sufficient total also occurs when the first half is a hole and
        // allocated space after EOF compensates it. The logical map must refuse.
        assert!(check_image_extent(contract, 8192, 32).is_ok());
        let mut map = ImageExtentMap::new(0, 8192);
        map.mapped = 1;
        map.extents[0] = ImageExtent {
            logical: 0,
            physical: 4096,
            length: 8192,
            flags: FIEMAP_LAST | FIEMAP_UNWRITTEN,
            ..ImageExtent::default()
        };
        assert_eq!(advance_image_coverage(&map, 0, 8192).unwrap(), 8192);
        for changed in [
            ImageExtent {
                logical: 4096,
                ..map.extents[0]
            },
            ImageExtent {
                logical: 8192,
                ..map.extents[0]
            },
            ImageExtent {
                length: 4096,
                ..map.extents[0]
            },
            ImageExtent {
                flags: 2,
                ..map.extents[0]
            },
            ImageExtent {
                flags: 4,
                ..map.extents[0]
            },
            ImageExtent {
                flags: 0x2000,
                ..map.extents[0]
            },
            ImageExtent {
                physical: 0,
                ..map.extents[0]
            },
        ] {
            let mut bad = ImageExtentMap::new(0, 8192);
            bad.mapped = 1;
            bad.extents[0] = changed;
            assert!(advance_image_coverage(&bad, 0, 8192).is_err());
        }
        map.mapped = 17;
        assert!(advance_image_coverage(&map, 0, 8192).is_err());
        map.mapped = 0;
        assert!(advance_image_coverage(&map, 0, 8192).is_err());
        assert!(check_usable_capacity(contract, 1, 4096, 1, StatVfsMountFlags::RDONLY).is_err());
        assert_eq!(std::mem::size_of::<ImageExtent>(), 56);
        assert_eq!(std::mem::offset_of!(ImageExtentMap, extents), 32);
        assert_eq!(std::mem::size_of::<ImageExtentMap>(), 928);
    }

    #[test]
    fn actual_image_map_preserves_unsupported_filesystem_refusal() {
        use crate::host_supervision::{
            HOST_OPERATION_CLASS_COUNT, HostOperationBudget, HostOperationBudgets,
        };
        let supervisor = HostOperationSupervisor::new(
            HostOperationBudgets {
                classes: [HostOperationBudget::finite(std::time::Duration::from_secs(60));
                    HOST_OPERATION_CLASS_COUNT],
            },
            None,
        )
        .unwrap();
        let original = supervisor
            .begin_work(HostOperationClass::Preparation, 1)
            .unwrap();
        // Extent accounting needs the workspace backing filesystem rather than
        // an anonymous RAM-backed temporary filesystem with different EOF rules.
        let file = tempfile::tempfile_in(std::env::current_dir().unwrap()).unwrap();
        file.set_len(8192).unwrap();
        rustix::fs::fallocate(&file, rustix::fs::FallocateFlags::KEEP_SIZE, 8192, 8192).unwrap();
        let image: OwnedFd = file.into();
        let stat = fstat(&image).unwrap();
        let contract = MeasurementStorageContract::new(8192, 4096, 1).unwrap();
        let totals = check_image_extent(contract, stat.st_size as u64, stat.st_blocks as u64);
        let hole = verify_image_coverage(&image, 8192, &original);
        match hole {
            Err(MeasurementStorageError::Binding(_)) => {
                // A filesystem supporting FIEMAP must expose the actual hole,
                // whether or not beyond-EOF space contributes to st_blocks.
            }
            Err(MeasurementStorageError::Io {
                source,
                after: None,
                ..
            }) => {
                assert_eq!(source, rustix::io::Errno::OPNOTSUPP);
                println!("ACTUAL_FIEMAP_UNSUPPORTED: no positive physical coverage proof");
            }
            other => panic!("actual logical hole was accepted: {other:?}"),
        }
        println!(
            "BEYOND_EOF_TOTAL_BLOCK_PREDICATE_ACCEPTED={}",
            totals.is_ok()
        );

        rustix::fs::fallocate(&image, rustix::fs::FallocateFlags::KEEP_SIZE, 0, 8192).unwrap();
        match verify_image_coverage(&image, 8192, &original) {
            Ok(()) => println!("ACTUAL_FIEMAP_FULL_RANGE_AUTHENTICATED"),
            Err(MeasurementStorageError::Io {
                source,
                after: None,
                ..
            }) => {
                assert_eq!(source, rustix::io::Errno::OPNOTSUPP);
                println!("ACTUAL_FIEMAP_UNSUPPORTED: installed ext4 control remains required");
            }
            other => panic!("unexpected supported image coverage refusal: {other:?}"),
        }
        println!(
            "FIEMAP_FIXED_BUFFER_BYTES={} MAX_IMAGE_EXTENTS={}",
            std::mem::size_of::<ImageExtentMap>(),
            IMAGE_EXTENTS_PER_READ * MAX_IMAGE_EXTENT_READS
        );
    }

    #[test]
    fn loop_uapi_and_original_identity_are_exact() {
        assert_eq!(std::mem::size_of::<LoopInfo>(), 232);
        assert_eq!(std::mem::align_of::<LoopInfo>(), 8);
        assert_eq!(BLKGETSIZE64, 0x80081272);
        let original = LoopInfo {
            device: 3,
            inode: 7,
            rdevice: 0,
            offset: 0,
            size_limit: 0,
            number: 1,
            encrypt_type: 0,
            encrypt_key_size: 0,
            flags: LOOP_AUTOCLEAR,
            file_name: [0; 64],
            crypt_name: [0; 64],
            encrypt_key: [0; 32],
            init: [0; 2],
        };
        assert!(check_loop_binding(&original, 3, 7).is_ok());
        for changed in [
            LoopInfo {
                inode: 8,
                ..original
            },
            LoopInfo {
                offset: 4096,
                ..original
            },
            LoopInfo {
                size_limit: 8192,
                ..original
            },
            LoopInfo {
                flags: LOOP_AUTOCLEAR | 1,
                ..original
            },
        ] {
            assert!(check_loop_binding(&changed, 3, 7).is_err());
        }
    }

    #[test]
    fn actual_cancellation_retains_transferred_pins_and_original_credit() {
        use crate::host_services::HostServiceAllocator;
        use crate::host_supervision::{
            HOST_OPERATION_CLASS_COUNT, HostOperationBudget, HostOperationBudgets,
        };
        let supervisor = HostOperationSupervisor::new(
            HostOperationBudgets {
                classes: [HostOperationBudget::finite(std::time::Duration::from_secs(60));
                    HOST_OPERATION_CLASS_COUNT],
            },
            None,
        )
        .unwrap();
        let operation = supervisor
            .begin_work(HostOperationClass::Preparation, 1)
            .unwrap();
        let bank = HostServiceAllocator::new(1, 3, 4096).unwrap();
        let original = bank.reserve_resources(0, 3, 4096).unwrap();
        let contract = MeasurementStorageContract::new(8192, 4096, 1).unwrap();
        let mut owner =
            MeasurementStoragePins::retain_original(original, contract, &operation).unwrap();
        let image: OwnedFd = tempfile::tempfile().unwrap().into();
        let device: OwnedFd = tempfile::tempfile().unwrap().into();
        let root: OwnedFd = tempfile::tempfile().unwrap().into();
        supervisor.cancel().unwrap();

        // These deliberately non-device pins would fail physical authentication.
        // Original cancellation must win before the first descriptor read.
        assert!(matches!(
            owner.bind(image, device, root),
            Err(MeasurementStorageError::Supervision(_))
        ));
        assert!(owner.installed && !owner.authenticated);
        assert!(owner.image.is_some() && owner.device.is_some() && owner.root.is_some());
        assert!(bank.reserve_resources(0, 1, 0).is_err());
        assert!(matches!(
            owner.bind(
                tempfile::tempfile().unwrap().into(),
                tempfile::tempfile().unwrap().into(),
                tempfile::tempfile().unwrap().into()
            ),
            Err(MeasurementStorageError::State)
        ));
        drop(owner);
        // No failed readback or destructor proves mount/loop retirement.
        assert!(bank.reserve_resources(0, 1, 0).is_err());
    }

    #[test]
    fn actual_kernel_primary_preserves_original_cancel_and_expiry_after_failure() {
        use crate::host_supervision::{
            HOST_OPERATION_CLASS_COUNT, HostOperationBudget, HostOperationBudgets,
            HostOperationState,
        };
        for cancel in [true, false] {
            let mut budgets = HostOperationBudgets {
                classes: [HostOperationBudget::finite(std::time::Duration::from_secs(60));
                    HOST_OPERATION_CLASS_COUNT],
            };
            let supervisor = HostOperationSupervisor::new(budgets, None).unwrap();
            let operation = supervisor
                .begin_work(HostOperationClass::Preparation, 1)
                .unwrap();
            operation.wait_slice().unwrap();
            let file: OwnedFd = tempfile::tempfile().unwrap().into();
            let primary = loop_status(&file).unwrap_err();
            assert_eq!(primary, rustix::io::Errno::NOTTY);
            if cancel {
                supervisor.cancel().unwrap();
            } else {
                budgets.classes[HostOperationClass::Preparation as usize] =
                    HostOperationBudget::finite(std::time::Duration::from_nanos(1));
                supervisor.update_budgets(0, budgets).unwrap();
            }
            let error =
                kernel_read::<LoopInfo>(&operation, "read original loop binding", Err(primary))
                    .unwrap_err();
            match error {
                MeasurementStorageError::Io {
                    source,
                    after: Some(after),
                    ..
                } => {
                    assert_eq!(source, primary);
                    if cancel {
                        assert!(matches!(
                            after,
                            HostSupervisionError::Terminal {
                                state: HostOperationState::Canceled
                            }
                        ));
                    } else {
                        assert!(matches!(
                            after,
                            HostSupervisionError::DeadlineExpired { .. }
                                | HostSupervisionError::Terminal {
                                    state: HostOperationState::Expired
                                }
                        ));
                    }
                }
                other => panic!("kernel primary or original secondary was lost: {other:?}"),
            }
            let quota_primary = LinuxProjectQuotaError::FilesystemIdentity {
                path: PathBuf::from("original pin"),
            };
            assert!(matches!(
                quota_read::<()>(&operation, Err(quota_primary)),
                Err(MeasurementStorageError::Quota {
                    source: LinuxProjectQuotaError::FilesystemIdentity { .. },
                    after: Some(_)
                })
            ));
        }
        println!(
            "MEASUREMENT_STORAGE_ERROR_BYTES={} PINS_BYTES={}",
            std::mem::size_of::<MeasurementStorageError>(),
            std::mem::size_of::<MeasurementStoragePins<'_>>()
        );
    }

    #[test]
    fn real_regular_descriptor_is_not_accepted_as_a_loop_device() {
        let file: OwnedFd = tempfile::tempfile().unwrap().into();
        assert!(loop_status(&file).is_err());
        assert!(block_bytes(&file).is_err());
    }
}
