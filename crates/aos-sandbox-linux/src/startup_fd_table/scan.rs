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

use super::execution::{
    ReturnedProcessSlot, capture_current_and_launcher, capture_selected_current_and_launcher,
    revalidate_process, revalidate_selected_process,
};
use super::model::{
    ActivationEnvironmentHintsV1, ClaimedInitialDescriptorV1, ClaimedInitialProcessFdTableV1,
    InitialDescriptorObjectKindV1, InitialDescriptorObservationV1, InitialSocketObservationV1,
    PendingInitialProcessFdTableV2, PendingStartupProcessV2, RetainedStartupProcessV1,
    StartupFdCaptureHardLimitsV1,
};

const FD_DIRECTORY: &str = "/proc/self/fd";
const GETDENTS_BUFFER_BYTES: usize = 32 * 1_024;
const LINUX_DIRENT64_HEADER_BYTES: usize = 19;
const MAXIMUM_SOCKADDR_BYTES: usize = 256;
const KCMP_FILE: libc::c_int = 0;

enum ScanDestination<'owner> {
    Legacy,
    Selected(&'owner mut PendingInitialProcessFdTableV2),
}

// These are disjoint borrows of the one selected reservoir, not another table
// or capture engine. Legacy reserves no external slots and retains its locals.
#[derive(Default)]
struct ScanReservations<'owner> {
    scanner: Option<&'owner mut Option<OwnedFd>>,
    processes: Option<(&'owner mut PendingStartupProcessV2, &'owner mut PendingStartupProcessV2)>,
    hints: Option<&'owner mut Option<ActivationEnvironmentHintsV1>>,
    descriptors: Option<&'owner mut Option<Vec<ClaimedInitialDescriptorV1>>>,
    pending_descriptor: Option<&'owner mut Option<OwnedFd>>,
    first_scan: Option<&'owner mut Option<BTreeSet<u32>>>,
    second_scan: Option<&'owner mut Option<BTreeSet<u32>>>,
    external_numbers: Option<&'owner mut Option<Vec<u32>>>,
    standard: Option<&'owner mut Option<Vec<OwnedFd>>>,
    scanner_numbers: Option<&'owner mut Option<Vec<u32>>>,
    boot_before: Option<&'owner mut Option<u64>>,
    boot_after: Option<&'owner mut Option<u64>>,
    realtime_before: Option<&'owner mut Option<i128>>,
    realtime_after: Option<&'owner mut Option<i128>>,
    scanned: Option<&'owner mut bool>,
}

impl<'owner> ScanReservations<'owner> {
    fn selected(owner: &'owner mut PendingInitialProcessFdTableV2) -> Result<Self> {
        if owner.scanner.is_some() || owner.activation_hints.is_some()
            || owner.descriptors.is_some() || owner.pending_descriptor.is_some()
            || owner.first_scan.is_some() || owner.second_scan.is_some()
            || owner.external_numbers.is_some() || owner.original_standard.is_some()
            || owner.scanner_descriptor_numbers.is_some() || owner.scanned
        {
            return Err(Error::invalid("startup FD capture", "selected reservoir is not empty"));
        }
        Ok(Self {
            scanner: Some(&mut owner.scanner),
            processes: Some((&mut owner.execution, &mut owner.launcher)),
            hints: Some(&mut owner.activation_hints),
            descriptors: Some(&mut owner.descriptors),
            pending_descriptor: Some(&mut owner.pending_descriptor),
            first_scan: Some(&mut owner.first_scan),
            second_scan: Some(&mut owner.second_scan),
            external_numbers: Some(&mut owner.external_numbers),
            standard: Some(&mut owner.original_standard),
            scanner_numbers: Some(&mut owner.scanner_descriptor_numbers),
            boot_before: Some(&mut owner.boot_time_before_ns),
            boot_after: Some(&mut owner.boot_time_after_ns),
            realtime_before: Some(&mut owner.realtime_before_ns),
            realtime_after: Some(&mut owner.realtime_after_ns),
            scanned: Some(&mut owner.scanned),
        })
    }
}

enum CapturedProcesses<'owner> {
    Legacy { launcher: RetainedStartupProcessV1, execution: RetainedStartupProcessV1 },
    Selected { execution: &'owner mut PendingStartupProcessV2, launcher: &'owner mut PendingStartupProcessV2 },
}

impl<'owner> CapturedProcesses<'owner> {
    fn capture(
        destination: Option<(&'owner mut PendingStartupProcessV2, &'owner mut PendingStartupProcessV2)>,
        boot: [u8; 16],
    ) -> Result<Self> {
        match destination {
            None => {
                let (execution, launcher) = capture_current_and_launcher(boot)?;
                Ok(Self::Legacy { launcher, execution })
            }
            Some((execution, launcher)) => {
                capture_selected_current_and_launcher(execution, launcher, boot)?;
                Ok(Self::Selected { execution, launcher })
            }
        }
    }

    fn insert_internal_numbers(&self, numbers: &mut BTreeSet<u32>) -> Result<()> {
        match self {
            Self::Legacy { execution, launcher } => {
                for descriptor in execution.internal_fds().into_iter().chain(launcher.internal_fds()) {
                    insert_fd_number(numbers, descriptor)?;
                }
            }
            Self::Selected { execution, launcher } => {
                for descriptor in execution.internal_fds().chain(launcher.internal_fds()) {
                    insert_fd_number(numbers, descriptor)?;
                }
            }
        }
        Ok(())
    }

    fn revalidate(&mut self) -> Result<()> {
        match self {
            Self::Legacy { execution, launcher } => {
                revalidate_process(execution)?;
                revalidate_process(launcher)
            }
            Self::Selected { execution, launcher } => {
                revalidate_selected_process(execution)?;
                revalidate_selected_process(launcher)
            }
        }
    }

    fn into_legacy(self) -> Result<(RetainedStartupProcessV1, RetainedStartupProcessV1)> {
        match self {
            Self::Legacy { execution, launcher } => Ok((execution, launcher)),
            Self::Selected { .. } => Err(Error::invalid("startup capture", "selected capture is not a legacy claim")),
        }
    }
}

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
    // SAFETY: forwards the same exclusive raw-table contract into the shared
    // recipe. Its closed Legacy branch owns and releases the original locals.
    unsafe { scan_recipe(limits, ScanDestination::Legacy) }?
        .ok_or_else(|| Error::invalid("startup capture", "legacy table owner is absent"))
}

pub(super) unsafe fn capture_selected_initial_table(
    owner: &mut PendingInitialProcessFdTableV2,
    limits: StartupFdCaptureHardLimitsV1,
) -> Result<()> {
    let mut signal_mask = SignalMaskFence::block_all()?;
    // SAFETY: the selected public entry forwards the sole exclusive initial
    // ownership contract. Every returned selected prefix stays in `owner`.
    let capture = unsafe { scan_recipe(limits, ScanDestination::Selected(owner)) };
    if let Err(error) = capture {
        owner.first_failure = Some(error);
    }
    owner.signal_restore = Some(signal_mask.restore());
    if owner.failure().is_some() {
        return Err(Error::invalid("startup FD capture", "selected original capture ended"));
    }
    Ok(())
}

unsafe fn scan_recipe(
    limits: StartupFdCaptureHardLimitsV1,
    destination: ScanDestination<'_>,
) -> Result<Option<ClaimedInitialProcessFdTableV1>> {
    let reservations = match destination {
        ScanDestination::Legacy => ScanReservations::default(),
        ScanDestination::Selected(owner) => ScanReservations::selected(owner)?,
    };
    let ScanReservations {
        scanner: scanner_destination, processes: process_destination, hints: hint_destination,
        descriptors: descriptor_destination, mut pending_descriptor,
        first_scan: first_destination, second_scan: second_destination,
        external_numbers: external_destination, standard: standard_destination,
        scanner_numbers: scanner_number_destination, boot_before: boot_before_destination,
        boot_after: boot_after_destination, realtime_before: realtime_before_destination,
        realtime_after: realtime_after_destination, scanned: scanned_destination,
    } = reservations;
    let _single_thread = SingleThreadedProcess::verify()?;
    let boot_before = KernelBootId::current()?.into_bytes();
    let boot_time_before_ns = uapi::boottime_nanoseconds()?;
    let realtime_before_ns = realtime_nanoseconds()?;
    if let Some(destination) = boot_before_destination { *destination = Some(boot_time_before_ns); }
    if let Some(destination) = realtime_before_destination { *destination = Some(realtime_before_ns); }
    let activation_hints = ReturnedProcessSlot::park(
        capture_activation_hints(limits.maximum_activation_hint_bytes())?, hint_destination,
    );

    let scanner = ReturnedProcessSlot::park(rustix::fs::open(
        FD_DIRECTORY,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|source| Error::Syscall {
        operation: "open /proc/self/fd",
        source: source.into(),
    })?, scanner_destination);
    let mut processes = CapturedProcesses::capture(process_destination, boot_before)?;

    let mut internal_numbers = BTreeSet::new();
    insert_fd_number(&mut internal_numbers, scanner.original()?.as_fd())?;
    processes.insert_internal_numbers(&mut internal_numbers)?;

    let first = ReturnedProcessSlot::park(scan_fd_numbers(
        scanner.original()?.as_raw_fd(),
        limits
            .maximum_descriptors()
            .saturating_mul(2)
            .saturating_add(32),
    )?, first_destination);
    let first_numbers = first.original()?;
    if !internal_numbers.iter().all(|number| first_numbers.contains(number)) {
        return Err(Error::invalid(
            "startup FD table",
            "scanner-owned descriptor is absent from the first scan",
        ));
    }
    let external_numbers = ReturnedProcessSlot::park(first.original()?
        .difference(&internal_numbers)
        .copied()
        .collect::<Vec<_>>(), external_destination);
    validate_external_numbers(external_numbers.original()?, limits)?;

    let mut claimed = ReturnedProcessSlot::park(
        Vec::with_capacity(external_numbers.original()?.len()), descriptor_destination,
    );
    let mut duplicate_numbers = BTreeSet::new();
    for original in external_numbers.original()? {
        let original_descriptor_flags = descriptor_flags(*original)?;
        let duplicated = ReturnedProcessSlot::park(
            duplicate_descriptor(*original)?, pending_descriptor.as_deref_mut(),
        );
        let duplicate_number = fd_number(duplicated.original()?.as_raw_fd())?;
        if !duplicate_numbers.insert(duplicate_number) {
            return Err(Error::invalid(
                "startup FD table",
                "duplicate descriptor number was reused",
            ));
        }
        compare_open_file_description(*original, duplicated.original()?.as_raw_fd())?;
        let observation =
            observe_descriptor(*original, duplicated.original()?.as_fd(), original_descriptor_flags)?;
        let entries = claimed.original_mut()?;
        // The sole allocation occurs before the loop for its exact length.
        // Check capacity before removing the returned descriptor from its slot.
        if entries.len() == entries.capacity() {
            return Err(Error::invalid("startup FD capture", "descriptor capacity is exhausted"));
        }
        let descriptor = duplicated.take_after_checks().ok_or_else(|| {
            Error::invalid("startup FD capture", "returned duplicate is absent")
        })?;
        entries.push(ClaimedInitialDescriptorV1 {
            original_number: *original,
            descriptor,
            observation,
        });
    }

    let second = ReturnedProcessSlot::park(scan_fd_numbers(
        scanner.original()?.as_raw_fd(),
        limits
            .maximum_descriptors()
            .saturating_mul(2)
            .saturating_add(32),
    )?, second_destination);
    let mut expected_second = first.original()?.clone();
    expected_second.extend(duplicate_numbers.iter().copied());
    if second.original()? != &expected_second {
        return Err(Error::invalid(
            "startup FD table",
            "descriptor table changed between complete scans",
        ));
    }

    for (original, retained) in external_numbers.original()?.iter().zip(claimed.original()?) {
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
    processes.revalidate()?;
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
    if let Some(destination) = standard_destination {
        // SAFETY: the same complete external set has exclusive original
        // ownership. Selected retains 0/1/2 at their original numbers.
        unsafe { close_selected_originals(external_numbers.original()?, destination)? };
    } else {
        // SAFETY: the unchanged Legacy branch consumes and closes its whole
        // external set, including the original standard descriptors.
        unsafe { close_originals(external_numbers.into_local()?)? };
    }

    let scanner_descriptor_numbers = internal_numbers.into_iter().collect();
    if let Some(destination) = scanner_number_destination {
        *destination = Some(scanner_descriptor_numbers);
        if let Some(destination) = boot_after_destination { *destination = Some(boot_time_after_ns); }
        if let Some(destination) = realtime_after_destination { *destination = Some(realtime_after_ns); }
        if let Some(destination) = scanned_destination { *destination = true; }
        return Ok(None);
    }
    let (execution, launcher) = processes.into_legacy()?;
    Ok(Some(ClaimedInitialProcessFdTableV1 {
        execution,
        launcher,
        descriptors: claimed.into_local()?,
        activation_hints: activation_hints.into_local()?,
        boot_time_before_ns,
        boot_time_after_ns,
        realtime_before_ns,
        realtime_after_ns,
        scanner_descriptor_numbers,
    }))
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

pub(super) fn with_blocked_signals<T, E: From<Error>>(
    operation: impl FnOnce() -> std::result::Result<T, E>,
) -> std::result::Result<T, E> {
    let mut mask = SignalMaskFence::block_all()?;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation));
    if mask.restore().is_err() {
        std::process::abort();
    }
    match result {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

pub(super) fn require_fixed_worker_descriptor_numbers() -> Result<()> {
    let scanner = rustix::fs::open(
        FD_DIRECTORY,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|source| Error::Syscall {
        operation: "open fixed worker initial FD table",
        source: source.into(),
    })?;
    if scanner.as_raw_fd() < 8 {
        return Err(Error::invalid(
            "fixed FUSE worker startup",
            "a mandatory startup descriptor is absent",
        ));
    }
    let mut expected = (0..8).collect::<BTreeSet<u32>>();
    expected.insert(fd_number(scanner.as_raw_fd())?);
    if scan_fd_numbers(scanner.as_raw_fd(), 9)? != expected {
        return Err(Error::invalid(
            "fixed FUSE worker startup",
            "descriptor table is not stdio plus the exact five roles",
        ));
    }
    Ok(())
}

pub(super) fn revalidate_claimed_table(table: &ClaimedInitialProcessFdTableV1) -> Result<()> {
    revalidate_process(&table.execution)?;
    revalidate_process(&table.launcher)?;
    revalidate_descriptors(&table.descriptors)
}

pub(super) fn revalidate_selected_table(table: &mut PendingInitialProcessFdTableV2) -> Result<()> {
    if !table.scanned {
        return Err(Error::invalid("startup FD table", "selected capture is incomplete"));
    }
    revalidate_selected_process(&mut table.execution)?;
    revalidate_selected_process(&mut table.launcher)?;
    let descriptors = table.descriptors.as_ref().ok_or_else(|| {
        Error::invalid("startup FD table", "selected descriptor table is absent")
    })?;
    revalidate_descriptors(descriptors)
}

pub(super) fn finish_selected_interval(table: &mut PendingInitialProcessFdTableV2) -> Result<()> {
    let expected_boot = table.execution.execution().ok_or_else(|| {
        Error::invalid("startup capture time", "selected self capture is absent")
    })?.kernel_boot_id;
    let boot = KernelBootId::current()?.into_bytes();
    let boot_time = uapi::boottime_nanoseconds()?;
    table.boot_time_after_ns = Some(boot_time);
    let realtime = realtime_nanoseconds()?;
    table.realtime_after_ns = Some(realtime);
    if boot != expected_boot
        || table.boot_time_before_ns.is_none_or(|before| before > boot_time)
        || table.realtime_before_ns.is_none_or(|before| before > realtime)
    {
        return Err(Error::invalid("startup capture time", "kernel boot or clocks changed nonmonotonically"));
    }
    Ok(())
}

fn revalidate_descriptors(descriptors: &[ClaimedInitialDescriptorV1]) -> Result<()> {
    for entry in descriptors {
        if observe_descriptor(
            entry.original_number,
            entry.as_fd(),
            entry.observation.descriptor_flags,
        )? != entry.observation {
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
    let capacity = numbers.len();
    // SAFETY: retains the original consuming iterator and exclusive ownership
    // assertion in the shared raw-adoption body, without a selected reservoir.
    unsafe { adopt_and_close_originals(OriginalNumbers::Legacy(numbers.into_iter()), capacity, None) }
}

unsafe fn close_selected_originals(numbers: &[u32], standard: &mut Option<Vec<OwnedFd>>) -> Result<()> {
    if standard.is_some() {
        return Err(Error::invalid("startup FD table", "original standard slot is occupied"));
    }
    // SAFETY: the selected scanner established the same exclusive original
    // numeric set. Its returned raw owners are parked before every postcheck.
    unsafe {
        adopt_and_close_originals(OriginalNumbers::Selected(numbers.iter().copied()), numbers.len(), Some(standard))
    }
}

enum OriginalNumbers<'numbers> {
    Legacy(std::vec::IntoIter<u32>),
    Selected(std::iter::Copied<std::slice::Iter<'numbers, u32>>),
}

impl Iterator for OriginalNumbers<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Legacy(numbers) => numbers.next(),
            Self::Selected(numbers) => numbers.next(),
        }
    }
}

unsafe fn adopt_and_close_originals(
    numbers: OriginalNumbers<'_>,
    capacity: usize,
    standard: Option<&mut Option<Vec<OwnedFd>>>,
) -> Result<()> {
    let selected = standard.is_some();
    let mut owners = ReturnedProcessSlot::park(Vec::with_capacity(capacity), standard);
    for number in numbers {
        let number = RawFd::try_from(number)
            .map_err(|_| Error::invalid("startup FD table", "descriptor does not fit RawFd"))?;
        let owners = owners.original_mut()?;
        // SAFETY: the public constructor establishes exclusive ownership for
        // every number in this previously scanned external set.
        owners.push(unsafe { OwnedFd::from_raw_fd(number) });
    }
    if selected {
        // Keep exactly the original standard descriptors at 0/1/2. They cannot
        // be reused by a later runtime while the whole pending owner lives.
        // Closing the remaining raw originals follows the completed sandwich.
        owners.original_mut()?.retain(|descriptor| descriptor.as_raw_fd() < 3);
    } else {
        drop(owners);
    }
    Ok(())
}

fn malformed_fd_directory(message: impl Into<String>) -> Error {
    Error::MalformedKernelResponse {
        object: "/proc/self/fd",
        message: message.into(),
    }
}
