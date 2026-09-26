//! Complete descriptor-table scan, correlation, and ownership transfer.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd as _, AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt as _;

use rustix::fs::{FileType, OFlags};

use crate::boot::KernelBootId;
use crate::inventory::MountId;
use crate::pidfd::SingleThreadedProcess;
use crate::uapi;
use crate::{Error, Result};

use super::execution::{capture_current_and_launcher, revalidate_process};
use super::model::{
    ActivationEnvironmentHintsV1, ClaimedInitialDescriptorV1, ClaimedInitialProcessFdTableV1,
    InitialDescriptorObjectKindV1, InitialDescriptorObservationV1, InitialSocketObservationV1,
    StartupFdCaptureHardLimitsV1,
};

const FD_DIRECTORY: &str = "/proc/self/fd";
const GETDENTS_BUFFER_BYTES: usize = 32 * 1_024;
const LINUX_DIRENT64_HEADER_BYTES: usize = 19;
const MAXIMUM_SOCKADDR_BYTES: usize = 256;
const KCMP_FILE: libc::c_int = 0;

pub(super) unsafe fn claim_initial_process_fd_table(
    limits: StartupFdCaptureHardLimitsV1,
) -> Result<ClaimedInitialProcessFdTableV1> {
    let mut signal_mask = SignalMaskFence::block_all()?;
    // SAFETY: the public constructor's ownership precondition is unchanged by
    // blocking signal delivery for this calling thread.
    let capture = unsafe { claim_with_signals_blocked(limits) };
    signal_mask.restore()?;
    capture
}

unsafe fn claim_with_signals_blocked(
    limits: StartupFdCaptureHardLimitsV1,
) -> Result<ClaimedInitialProcessFdTableV1> {
    let _single_thread = SingleThreadedProcess::verify()?;
    let boot_before = KernelBootId::current()?.into_bytes();
    let boot_time_before_ns = uapi::boottime_nanoseconds()?;
    let realtime_before_ns = realtime_nanoseconds()?;
    let activation_hints = capture_activation_hints(limits.maximum_activation_hint_bytes())?;

    let scanner = rustix::fs::open(
        FD_DIRECTORY,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|source| Error::Syscall {
        operation: "open /proc/self/fd",
        source: source.into(),
    })?;
    let (execution, launcher) = capture_current_and_launcher(boot_before)?;

    let mut internal_numbers = BTreeSet::new();
    insert_fd_number(&mut internal_numbers, scanner.as_fd())?;
    for descriptor in execution
        .internal_fds()
        .into_iter()
        .chain(launcher.internal_fds())
    {
        insert_fd_number(&mut internal_numbers, descriptor)?;
    }

    let first = scan_fd_numbers(
        scanner.as_raw_fd(),
        limits
            .maximum_descriptors()
            .saturating_mul(2)
            .saturating_add(32),
    )?;
    if !internal_numbers.iter().all(|number| first.contains(number)) {
        return Err(Error::invalid(
            "startup FD table",
            "scanner-owned descriptor is absent from the first scan",
        ));
    }
    let external_numbers = first
        .difference(&internal_numbers)
        .copied()
        .collect::<Vec<_>>();
    validate_external_numbers(&external_numbers, limits)?;

    let mut claimed = Vec::with_capacity(external_numbers.len());
    let mut duplicate_numbers = BTreeSet::new();
    for original in &external_numbers {
        let original_descriptor_flags = descriptor_flags(*original)?;
        let duplicated = duplicate_descriptor(*original)?;
        let duplicate_number = fd_number(duplicated.as_raw_fd())?;
        if !duplicate_numbers.insert(duplicate_number) {
            return Err(Error::invalid(
                "startup FD table",
                "duplicate descriptor number was reused",
            ));
        }
        compare_open_file_description(*original, duplicated.as_raw_fd())?;
        let observation =
            observe_descriptor(*original, duplicated.as_fd(), original_descriptor_flags)?;
        claimed.push(ClaimedInitialDescriptorV1 {
            original_number: *original,
            descriptor: duplicated,
            observation,
        });
    }

    let second = scan_fd_numbers(
        scanner.as_raw_fd(),
        limits
            .maximum_descriptors()
            .saturating_mul(2)
            .saturating_add(32),
    )?;
    let mut expected_second = first.clone();
    expected_second.extend(duplicate_numbers.iter().copied());
    if second != expected_second {
        return Err(Error::invalid(
            "startup FD table",
            "descriptor table changed between complete scans",
        ));
    }

    for (original, retained) in external_numbers.iter().zip(&claimed) {
        compare_open_file_description(*original, retained.descriptor.as_raw_fd())?;
        if descriptor_flags(*original)? != retained.observation.descriptor_flags
            || observe_descriptor(
                *original,
                retained.as_fd(),
                retained.observation.descriptor_flags,
            )? != retained.observation
        {
            return Err(Error::invalid(
                "startup FD table",
                "descriptor changed across the observation sandwich",
            ));
        }
    }
    revalidate_process(&execution)?;
    revalidate_process(&launcher)?;
    if !activation_environment_is_clear() {
        return Err(Error::invalid(
            "startup activation environment",
            "activation hints were recreated during capture",
        ));
    }
    let _single_thread = SingleThreadedProcess::verify()?;
    let boot_after = KernelBootId::current()?.into_bytes();
    let boot_time_after_ns = uapi::boottime_nanoseconds()?;
    let realtime_after_ns = realtime_nanoseconds()?;
    if boot_before != boot_after
        || boot_time_before_ns > boot_time_after_ns
        || realtime_before_ns > realtime_after_ns
    {
        return Err(Error::invalid(
            "startup capture time",
            "kernel boot or clocks changed nonmonotonically",
        ));
    }

    // SAFETY: the public constructor's exclusive-ownership precondition covers
    // exactly `external_numbers`. Internal scanner descriptors and fresh
    // duplicates were removed from this set before ownership is assumed.
    unsafe { close_originals(external_numbers)? };

    let scanner_descriptor_numbers = internal_numbers.into_iter().collect();
    Ok(ClaimedInitialProcessFdTableV1 {
        execution,
        launcher,
        descriptors: claimed,
        activation_hints,
        boot_time_before_ns,
        boot_time_after_ns,
        realtime_before_ns,
        realtime_after_ns,
        scanner_descriptor_numbers,
    })
}

struct SignalMaskFence {
    previous: libc::sigset_t,
    active: bool,
}

impl SignalMaskFence {
    fn block_all() -> Result<Self> {
        let mut blocked = MaybeUninit::<libc::sigset_t>::uninit();
        // SAFETY: `blocked` names writable storage for one complete sigset.
        if unsafe { libc::sigfillset(blocked.as_mut_ptr()) } != 0 {
            return Err(Error::syscall("sigfillset startup FD capture"));
        }
        let mut previous = MaybeUninit::<libc::sigset_t>::uninit();
        // SAFETY: sigfillset initialized `blocked`; `previous` is writable for
        // the exact prior calling-thread mask returned by pthread_sigmask.
        let result = unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, blocked.as_ptr(), previous.as_mut_ptr())
        };
        if result != 0 {
            return Err(Error::Syscall {
                operation: "pthread_sigmask block startup FD capture",
                source: std::io::Error::from_raw_os_error(result),
            });
        }
        // SAFETY: successful pthread_sigmask initialized the complete old mask.
        let previous = unsafe { previous.assume_init() };
        Ok(Self {
            previous,
            active: true,
        })
    }

    fn restore(&mut self) -> Result<()> {
        // SAFETY: `previous` is the initialized exact mask returned by the
        // successful block operation; no output mask is requested.
        let result = unsafe {
            libc::pthread_sigmask(
                libc::SIG_SETMASK,
                std::ptr::addr_of!(self.previous),
                std::ptr::null_mut(),
            )
        };
        if result != 0 {
            return Err(Error::Syscall {
                operation: "pthread_sigmask restore startup FD capture",
                source: std::io::Error::from_raw_os_error(result),
            });
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for SignalMaskFence {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: this is the same initialized prior mask as `restore`.
            // Drop is only the unwind/error fallback; ordinary paths report a
            // restoration failure through `restore`.
            unsafe {
                libc::pthread_sigmask(
                    libc::SIG_SETMASK,
                    std::ptr::addr_of!(self.previous),
                    std::ptr::null_mut(),
                );
            }
        }
    }
}

pub(super) fn revalidate_claimed_table(table: &ClaimedInitialProcessFdTableV1) -> Result<()> {
    revalidate_process(&table.execution)?;
    revalidate_process(&table.launcher)?;
    for entry in &table.descriptors {
        if observe_descriptor(
            entry.original_number,
            entry.as_fd(),
            entry.observation.descriptor_flags,
        )? != entry.observation
        {
            return Err(Error::invalid(
                "startup FD table",
                "retained descriptor no longer matches its capture",
            ));
        }
    }
    Ok(())
}

fn validate_external_numbers(
    descriptors: &[u32],
    limits: StartupFdCaptureHardLimitsV1,
) -> Result<()> {
    if descriptors.len() > limits.maximum_descriptors()
        || descriptors
            .last()
            .is_some_and(|number| *number > limits.maximum_descriptor_number())
    {
        return Err(Error::ObservationLimitExceeded {
            object: "initial process descriptor table",
            limit: limits.maximum_descriptors(),
        });
    }
    Ok(())
}

fn insert_fd_number(
    numbers: &mut BTreeSet<u32>,
    descriptor: std::os::fd::BorrowedFd<'_>,
) -> Result<()> {
    let number = fd_number(descriptor.as_raw_fd())?;
    if !numbers.insert(number) {
        return Err(Error::invalid(
            "startup FD table",
            "scanner-owned descriptors alias",
        ));
    }
    Ok(())
}

fn fd_number(raw: RawFd) -> Result<u32> {
    u32::try_from(raw)
        .map_err(|_| Error::invalid("startup FD table", "descriptor number is negative"))
}

fn duplicate_descriptor(original: u32) -> Result<OwnedFd> {
    let original = RawFd::try_from(original)
        .map_err(|_| Error::invalid("startup FD table", "descriptor does not fit RawFd"))?;
    // SAFETY: F_DUPFD_CLOEXEC observes `original` and creates a distinct owned
    // descriptor. The public ownership/race contract keeps `original` open.
    let duplicated = unsafe { libc::fcntl(original, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicated < 0 {
        return Err(Error::syscall("fcntl(F_DUPFD_CLOEXEC) startup FD"));
    }
    // SAFETY: successful F_DUPFD_CLOEXEC returned a fresh descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
}

fn descriptor_flags(number: u32) -> Result<u32> {
    let number = RawFd::try_from(number)
        .map_err(|_| Error::invalid("startup FD table", "descriptor does not fit RawFd"))?;
    // SAFETY: F_GETFD observes a scalar descriptor under the public capture
    // contract and does not borrow or assume ownership of the descriptor.
    let flags = unsafe { libc::fcntl(number, libc::F_GETFD) };
    if flags < 0 {
        return Err(Error::syscall("fcntl(F_GETFD) original startup FD"));
    }
    u32::try_from(flags)
        .map_err(|_| Error::invalid("startup FD table", "descriptor flags are negative"))
}

fn compare_open_file_description(original: u32, duplicate: RawFd) -> Result<()> {
    let original = RawFd::try_from(original)
        .map_err(|_| Error::invalid("startup FD table", "descriptor does not fit RawFd"))?;
    let pid = libc::pid_t::try_from(std::process::id())
        .map_err(|_| Error::invalid("startup FD table", "PID does not fit pid_t"))?;
    // SAFETY: kcmp receives scalar identifiers only. Both FDs remain open
    // under the capture contract and the owned duplicate.
    let comparison = unsafe {
        libc::syscall(
            libc::SYS_kcmp,
            pid,
            pid,
            KCMP_FILE,
            original as libc::c_ulong,
            duplicate as libc::c_ulong,
        )
    };
    if comparison < 0 {
        return Err(Error::syscall("kcmp(KCMP_FILE) startup FD"));
    }
    if comparison != 0 {
        return Err(Error::invalid(
            "startup FD table",
            "original and retained descriptors name different open files",
        ));
    }
    Ok(())
}

fn observe_descriptor(
    original_number: u32,
    descriptor: std::os::fd::BorrowedFd<'_>,
    original_descriptor_flags: u32,
) -> Result<InitialDescriptorObservationV1> {
    let descriptor_flags =
        rustix::io::fcntl_getfd(descriptor).map_err(|source| Error::Syscall {
            operation: "fcntl(F_GETFD) startup FD",
            source: source.into(),
        })?;
    if descriptor_flags.bits() != libc::FD_CLOEXEC as u32 {
        return Err(Error::invalid(
            "startup FD table",
            "retained descriptor is not exactly close-on-exec",
        ));
    }
    let status_flags = rustix::fs::fcntl_getfl(descriptor).map_err(|source| Error::Syscall {
        operation: "fcntl(F_GETFL) startup FD",
        source: source.into(),
    })?;
    let stat = rustix::fs::fstat(descriptor).map_err(|source| Error::Syscall {
        operation: "fstat startup FD",
        source: source.into(),
    })?;
    if stat.st_dev == 0 || stat.st_ino == 0 {
        return Err(Error::invalid(
            "startup FD table",
            "descriptor object has zero physical identity",
        ));
    }
    let file_type = FileType::from_raw_mode(stat.st_mode);
    let object_kind = object_kind(file_type);
    let (unique_mount_id, mount_read_only) = match MountId::from_fd(descriptor) {
        Ok(mount_id) => (Some(mount_id.get()), None),
        Err(_) if object_kind != InitialDescriptorObjectKindV1::Directory => (None, None),
        Err(error) => return Err(error),
    };
    let socket = if object_kind == InitialDescriptorObjectKindV1::Socket {
        Some(observe_socket(descriptor.as_raw_fd())?)
    } else {
        None
    };
    Ok(InitialDescriptorObservationV1 {
        number: original_number,
        descriptor_flags: original_descriptor_flags,
        status_flags: status_flags.bits(),
        object_kind,
        device: stat.st_dev,
        inode: stat.st_ino,
        mode: stat.st_mode,
        special_device: stat.st_rdev,
        size: u64::try_from(stat.st_size)
            .map_err(|_| Error::invalid("startup FD table", "object size is negative"))?,
        unique_mount_id,
        mount_read_only,
        socket,
    })
}

fn object_kind(file_type: FileType) -> InitialDescriptorObjectKindV1 {
    match file_type {
        FileType::RegularFile => InitialDescriptorObjectKindV1::Regular,
        FileType::Directory => InitialDescriptorObjectKindV1::Directory,
        FileType::Socket => InitialDescriptorObjectKindV1::Socket,
        FileType::Fifo => InitialDescriptorObjectKindV1::Fifo,
        FileType::CharacterDevice => InitialDescriptorObjectKindV1::Character,
        FileType::BlockDevice => InitialDescriptorObjectKindV1::Block,
        FileType::Symlink => InitialDescriptorObjectKindV1::Symlink,
        _ => InitialDescriptorObjectKindV1::Other,
    }
}

fn observe_socket(descriptor: RawFd) -> Result<InitialSocketObservationV1> {
    let domain = socket_option(descriptor, libc::SO_DOMAIN, "getsockopt(SO_DOMAIN)")?;
    let socket_type = socket_option(descriptor, libc::SO_TYPE, "getsockopt(SO_TYPE)")?;
    let accepting = socket_option(descriptor, libc::SO_ACCEPTCONN, "getsockopt(SO_ACCEPTCONN)")?;
    let mut address = [0_u8; MAXIMUM_SOCKADDR_BYTES];
    let mut address_length = libc::socklen_t::try_from(address.len())
        .map_err(|_| Error::invalid("startup socket", "sockaddr bound does not fit socklen_t"))?;
    // SAFETY: `address` is writable for its advertised capacity and the
    // descriptor is retained for the call.
    let result =
        unsafe { libc::getsockname(descriptor, address.as_mut_ptr().cast(), &mut address_length) };
    if result != 0 {
        return Err(Error::syscall("getsockname startup FD"));
    }
    let address_length = usize::try_from(address_length)
        .map_err(|_| Error::invalid("startup socket", "sockaddr length overflows"))?;
    if address_length == 0 || address_length > address.len() {
        return Err(Error::MalformedKernelResponse {
            object: "startup socket address",
            message: "kernel returned an invalid sockaddr length".to_owned(),
        });
    }
    Ok(InitialSocketObservationV1 {
        domain: u32::try_from(domain)
            .map_err(|_| Error::invalid("startup socket", "domain is negative"))?,
        socket_type: u32::try_from(socket_type)
            .map_err(|_| Error::invalid("startup socket", "type is negative"))?,
        accepting: accepting != 0,
        local_address: address[..address_length].to_vec(),
    })
}

fn socket_option(descriptor: RawFd, option: libc::c_int, operation: &'static str) -> Result<i32> {
    let mut value = 0_i32;
    let mut length = libc::socklen_t::try_from(std::mem::size_of::<i32>())
        .map_err(|_| Error::invalid("startup socket", "option size overflows"))?;
    // SAFETY: `value` and `length` are valid writable option storage.
    let result = unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_SOCKET,
            option,
            std::ptr::addr_of_mut!(value).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(Error::syscall(operation));
    }
    if usize::try_from(length).ok() != Some(std::mem::size_of::<i32>()) {
        return Err(Error::MalformedKernelResponse {
            object: "startup socket option",
            message: "kernel returned an invalid option length".to_owned(),
        });
    }
    Ok(value)
}

fn scan_fd_numbers(scanner: RawFd, maximum: usize) -> Result<BTreeSet<u32>> {
    // SAFETY: successful seek only resets the retained directory cursor.
    if unsafe { libc::lseek(scanner, 0, libc::SEEK_SET) } < 0 {
        return Err(Error::syscall("lseek /proc/self/fd"));
    }
    let mut numbers = BTreeSet::new();
    let mut buffer = [0_u8; GETDENTS_BUFFER_BYTES];
    loop {
        // SAFETY: `buffer` is writable for its full advertised size and the
        // scanner descriptor remains owned throughout the syscall.
        let length = unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                scanner,
                buffer.as_mut_ptr(),
                buffer.len(),
            )
        };
        if length < 0 {
            return Err(Error::syscall("getdents64 /proc/self/fd"));
        }
        if length == 0 {
            break;
        }
        let length = usize::try_from(length).map_err(|_| Error::MalformedKernelResponse {
            object: "/proc/self/fd",
            message: "getdents length overflows usize".to_owned(),
        })?;
        if length > buffer.len() {
            return Err(Error::MalformedKernelResponse {
                object: "/proc/self/fd",
                message: "getdents exceeded its buffer".to_owned(),
            });
        }
        let mut offset = 0usize;
        while offset < length {
            let remaining = &buffer[offset..length];
            if remaining.len() < LINUX_DIRENT64_HEADER_BYTES {
                return Err(malformed_fd_directory("directory entry is truncated"));
            }
            let record_length =
                usize::from(u16::from_ne_bytes(remaining[16..18].try_into().map_err(
                    |_| malformed_fd_directory("record length is truncated"),
                )?));
            if record_length < LINUX_DIRENT64_HEADER_BYTES || record_length > remaining.len() {
                return Err(malformed_fd_directory("record length is invalid"));
            }
            let name_field = &remaining[LINUX_DIRENT64_HEADER_BYTES..record_length];
            let name_length = name_field
                .iter()
                .position(|byte| *byte == 0)
                .ok_or_else(|| malformed_fd_directory("entry name is not terminated"))?;
            let name = &name_field[..name_length];
            if name != b"." && name != b".." {
                let number = parse_fd_name(name)?;
                if !numbers.insert(number) {
                    return Err(malformed_fd_directory("descriptor number is duplicated"));
                }
                if numbers.len() > maximum {
                    return Err(Error::ObservationLimitExceeded {
                        object: "/proc/self/fd entries",
                        limit: maximum,
                    });
                }
            }
            offset = offset
                .checked_add(record_length)
                .ok_or_else(|| malformed_fd_directory("directory offset overflows"))?;
        }
    }
    Ok(numbers)
}

fn parse_fd_name(name: &[u8]) -> Result<u32> {
    if name.is_empty()
        || (name.len() > 1 && name[0] == b'0')
        || !name.iter().all(u8::is_ascii_digit)
    {
        return Err(malformed_fd_directory(
            "descriptor name is not canonical decimal",
        ));
    }
    std::str::from_utf8(name)
        .map_err(|_| malformed_fd_directory("descriptor name is not UTF-8"))?
        .parse()
        .map_err(|_| malformed_fd_directory("descriptor number overflows u32"))
}

fn capture_activation_hints(maximum: usize) -> Result<ActivationEnvironmentHintsV1> {
    let result = (|| {
        let listen_pid = bounded_environment("LISTEN_PID", maximum)?;
        let used = listen_pid.as_ref().map_or(0, Vec::len);
        let listen_fds = bounded_environment("LISTEN_FDS", maximum.saturating_sub(used))?;
        let used = used.saturating_add(listen_fds.as_ref().map_or(0, Vec::len));
        let listen_fdnames = bounded_environment("LISTEN_FDNAMES", maximum.saturating_sub(used))?;
        Ok(ActivationEnvironmentHintsV1 {
            listen_pid,
            listen_fds,
            listen_fdnames,
        })
    })();
    // SAFETY: the public capture contract requires a single-threaded process
    // and excludes concurrent environment access for the complete call.
    unsafe {
        std::env::remove_var("LISTEN_PID");
        std::env::remove_var("LISTEN_FDS");
        std::env::remove_var("LISTEN_FDNAMES");
    }
    result
}

fn activation_environment_is_clear() -> bool {
    ["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"]
        .into_iter()
        .all(|name| std::env::var_os(name).is_none())
}

fn bounded_environment(name: &str, remaining: usize) -> Result<Option<Vec<u8>>> {
    let Some(value) = std::env::var_os(name) else {
        return Ok(None);
    };
    let bytes = OsStr::new(&value).as_bytes();
    if bytes.len() > remaining {
        return Err(Error::ObservationLimitExceeded {
            object: "startup activation environment",
            limit: remaining,
        });
    }
    Ok(Some(bytes.to_vec()))
}

fn realtime_nanoseconds() -> Result<i128> {
    let time = rustix::time::clock_gettime(rustix::time::ClockId::Realtime);
    let nanoseconds = i128::from(time.tv_nsec);
    if !(0..1_000_000_000).contains(&nanoseconds) {
        return Err(Error::MalformedKernelResponse {
            object: "CLOCK_REALTIME",
            message: "nanoseconds are out of range".to_owned(),
        });
    }
    i128::from(time.tv_sec)
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(nanoseconds))
        .ok_or_else(|| Error::MalformedKernelResponse {
            object: "CLOCK_REALTIME",
            message: "timestamp overflows i128".to_owned(),
        })
}

unsafe fn close_originals(numbers: Vec<u32>) -> Result<()> {
    let mut owners = Vec::with_capacity(numbers.len());
    for number in numbers {
        let number = RawFd::try_from(number)
            .map_err(|_| Error::invalid("startup FD table", "descriptor does not fit RawFd"))?;
        // SAFETY: the public constructor establishes exclusive ownership for
        // every number in this previously scanned external set.
        owners.push(unsafe { OwnedFd::from_raw_fd(number) });
    }
    drop(owners);
    Ok(())
}

fn malformed_fd_directory(message: impl Into<String>) -> Error {
    Error::MalformedKernelResponse {
        object: "/proc/self/fd",
        message: message.into(),
    }
}
