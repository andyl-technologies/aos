//! Switches one operator-created block target after genuine native admission.
//!
//! The fixed Linux device-mapper ABI is used only in this disposable-kernel
//! fixture. Every request selects the original UUID and verifies the mounted
//! device, complete geometry and single target before an error table is armed.

use crate::host_supervision::HostOperationGuard;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

const NAME: &[u8] = b"crucible-spill-io";
const UUID: &[u8] = b"crucible-spill-io-disposable-v1";
const SECTORS: u64 = 4_194_304;
const STATUS_TABLE: u32 = 1 << 4;
const BUFFER_FULL: u32 = 1 << 8;
const SKIP_LOCKFS: u32 = 1 << 10;

// Linux include/uapi/linux/dm-ioctl.h: a 312-byte header followed by
// one 40-byte target and its bounded, NUL-terminated parameter string.
#[repr(C)]
#[derive(Clone, Copy)]
struct Header {
    version: [u32; 3],
    data_size: u32,
    data_start: u32,
    target_count: u32,
    open_count: i32,
    flags: u32,
    event_nr: u32,
    padding: u32,
    dev: u64,
    name: [u8; 128],
    uuid: [u8; 129],
    data: [u8; 7],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Target {
    sector_start: u64,
    length: u64,
    status: i32,
    next: u32,
    target_type: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Packet {
    header: Header,
    target: Target,
    parameters: [u8; 64],
}

fn packet(kind: &[u8], parameters: &[u8]) -> Packet {
    assert!(kind.len() < 16 && parameters.len() < 64);
    let mut packet = Packet {
        header: Header {
            version: [4, 0, 0],
            data_size: std::mem::size_of::<Packet>() as u32,
            data_start: std::mem::size_of::<Header>() as u32,
            target_count: 1,
            open_count: 0,
            flags: 0,
            event_nr: 0,
            padding: 0,
            dev: 0,
            name: [0; 128],
            uuid: [0; 129],
            data: [0; 7],
        },
        target: Target {
            sector_start: 0,
            length: SECTORS,
            status: 0,
            next: (std::mem::size_of::<Target>() + 64) as u32,
            target_type: [0; 16],
        },
        parameters: [0; 64],
    };
    packet.header.name[..NAME.len()].copy_from_slice(NAME);
    packet.header.uuid[..UUID.len()].copy_from_slice(UUID);
    packet.target.target_type[..kind.len()].copy_from_slice(kind);
    packet.parameters[..parameters.len()].copy_from_slice(parameters);
    packet
}

/// Retains the original outside-node operator descriptor and allocation credit.
pub struct LinuxDeviceMapperFaultTarget {
    control: File,
    mounted_device: u64,
    linear_parameters: [u8; 64],
    // The original catalog owns this operator I/O, independently of native
    // node task/FD limits. Its credit closes after the actual control FD.
    _credit: crucible_ram::ResourceLoan,
}

impl LinuxDeviceMapperFaultTarget {
    /// Pins the operator-created disposable spill target under existing custody.
    ///
    /// The caller reserves the control descriptor and at least 4096 bytes of
    /// scratch before this call and retains its original loan in `credit`.
    /// Only the fixed `crucible-spill-io-disposable-v1` UUID is admitted.
    ///
    /// # Errors
    /// Refuses an expired original guard, unavailable control device, wrong
    /// mounted device or UUID, and any noncanonical target geometry.
    pub fn open(
        mount: &Path,
        credit: crucible_ram::ResourceLoan,
        guard: &HostOperationGuard,
    ) -> io::Result<Self> {
        boundary(guard)?;
        let mounted_device = std::fs::metadata(mount)?.dev();
        let control = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open("/dev/mapper/control")?;
        if !control.metadata()?.file_type().is_char_device() {
            return Err(io::Error::other(
                "device-mapper control is not a character device",
            ));
        }
        let mut result = Self {
            control,
            mounted_device,
            linear_parameters: [0; 64],
            _credit: credit,
        };
        let table = result.table(guard)?;
        result.verify(&table, b"linear")?;
        result.linear_parameters = table.parameters;
        Ok(result)
    }

    /// Replaces the validated original linear mapping with a real error target.
    ///
    /// # Errors
    /// Refuses an expired original guard, changed identity/geometry, or a kernel
    /// table operation failure. Errors after mutation retain target custody.
    pub fn switch_to_error(&self, guard: &HostOperationGuard) -> io::Result<()> {
        self.verify(&self.table(guard)?, b"linear")?;
        self.install(b"error", &[], guard)?;
        self.verify(&self.table(guard)?, b"error")
    }

    /// Restores the exact original table without releasing any native authority.
    ///
    /// This repairs operator availability only. The caller still proves native
    /// reap, joins, final descriptor closure and quota cleanup independently.
    ///
    /// # Errors
    /// Refuses an expired guard, changed target, unbounded original parameters,
    /// or any kernel table operation failure.
    pub fn restore_operator_availability(&self, guard: &HostOperationGuard) -> io::Result<()> {
        self.verify(&self.table(guard)?, b"error")?;
        let end = self
            .linear_parameters
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| io::Error::other("original linear table is not bounded"))?;
        self.install(b"linear", &self.linear_parameters[..end], guard)?;
        self.verify(&self.table(guard)?, b"linear")
    }

    fn table(&self, guard: &HostOperationGuard) -> io::Result<Packet> {
        let mut request = packet(&[], &[]);
        request.header.flags = STATUS_TABLE;
        self.exchange(12, &mut request, guard)?;
        Ok(request)
    }

    fn verify(&self, table: &Packet, kind: &[u8]) -> io::Result<()> {
        let expected = packet(kind, &[]);
        let major = (table.header.dev >> 8) & 0xfff;
        let minor = (table.header.dev & 0xff) | ((table.header.dev >> 12) & 0xfff00);
        if table.header.flags & BUFFER_FULL != 0
            || table.header.name != expected.header.name
            || table.header.uuid != expected.header.uuid
            || major != u64::from(libc::major(self.mounted_device))
            || minor != u64::from(libc::minor(self.mounted_device))
            || table.header.target_count != 1
            || table.header.data_start != std::mem::size_of::<Header>() as u32
            || table.target.sector_start != 0
            || table.target.length != SECTORS
            || table.target.target_type != expected.target.target_type
        {
            return Err(io::Error::other(
                "device-mapper target differs from admitted spill mount",
            ));
        }
        Ok(())
    }

    fn install(
        &self,
        kind: &[u8],
        parameters: &[u8],
        guard: &HostOperationGuard,
    ) -> io::Result<()> {
        let mut table = packet(kind, parameters);
        self.exchange(9, &mut table, guard)?;
        // Loading the inactive table changes no live I/O. Resume atomically
        // selects it; SKIP_LOCKFS prevents an unrelated filesystem freeze.
        let mut resume = packet(&[], &[]);
        resume.header.flags = SKIP_LOCKFS;
        self.exchange(6, &mut resume, guard)
    }

    fn exchange(
        &self,
        command: u32,
        packet: &mut Packet,
        guard: &HostOperationGuard,
    ) -> io::Result<()> {
        boundary(guard)?;
        // UUID is the sole lookup selector. Linux returns the actual name and
        // dev in its reply; providing a second selector would be invalid.
        packet.header.name.fill(0);
        let request = (3_u64 << 30)
            | ((std::mem::size_of::<Header>() as u64) << 16)
            | (0xfd << 8)
            | u64::from(command);
        // SAFETY: The fixed, fully initialized repr(C) packet has the exact
        // Linux dm_ioctl header/target ABI and remains exclusively borrowed
        // through the syscall. data_size cannot exceed the writable object.
        let result = unsafe {
            libc::ioctl(
                self.control.as_raw_fd(),
                request as libc::c_ulong,
                packet as *mut Packet,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        boundary(guard)
    }
}

fn boundary(guard: &HostOperationGuard) -> io::Result<()> {
    guard.wait_slice().map(|_| ()).map_err(io::Error::other)
}

#[test]
fn operator_table_packet_has_exact_bounded_kernel_geometry() {
    assert_eq!(std::mem::size_of::<Header>(), 312);
    assert_eq!(std::mem::size_of::<Target>(), 40);
    assert_eq!(std::mem::size_of::<Packet>(), 416);
    let error = packet(b"error", &[]);
    assert_eq!(error.header.data_start, 312);
    assert_eq!(error.header.data_size, 416);
    assert_eq!(error.target.next, 104);
    assert_eq!(error.target.length * 512, 2 * 1024 * 1024 * 1024);
    assert_eq!(&error.target.target_type[..6], b"error\0");
    assert_eq!(error.parameters, [0; 64]);
}
