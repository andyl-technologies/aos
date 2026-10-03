//! One-shot ownership transfer for fixed descriptors inherited at process start.
//!
//! Systemd activation and the mount namespace helper identify descriptors by
//! fixed process-table numbers. Ownership-transfer functions reserve an exact
//! bounded set, duplicate live entries with `F_DUPFD_CLOEXEC`, and close the
//! originals together. The safe observational startup copier instead leaves
//! originals open but close-on-exec and admits no launcher or descriptor role.
//! Only fresh duplicates become [`OwnedFd`] values.

use std::collections::BTreeSet;
use std::os::fd::{AsFd as _, BorrowedFd, FromRawFd as _, OwnedFd, RawFd};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::{Error, Result};

const SYSTEMD_ACTIVATION_FD_BASE: RawFd = 3;
const MAXIMUM_SYSTEMD_ACTIVATION_DESCRIPTORS: usize = 1_025;
const MOUNT_HELPER_PLAN_FD: RawFd = 3;
const MOUNT_HELPER_DETACHED_MOUNT_FD: RawFd = 4;
const DUPLICATE_FD_MINIMUM: RawFd = 64;

static CLAIMED_DESCRIPTOR_NUMBERS: Mutex<BTreeSet<RawFd>> = Mutex::new(BTreeSet::new());
static INITIAL_ACTIVATION_DUPLICATED: AtomicBool = AtomicBool::new(false);

/// Keeps Controller's fixed six-slot duplicate prefix resident through observation.
///
/// Slots are descriptor DATA, not launch, role or image authority. Construction
/// performs no observation. A failed or abandoned attempt must remain resident
/// until intentional process termination; armed Drop aborts before field release.
#[must_use]
pub struct ControllerInitialActivationTableV1 {
    descriptors: [Option<OwnedFd>; 6],
    count: usize,
    attempted: bool,
    complete: bool,
    failure: Option<Error>,
    armed: bool,
}

impl ControllerInitialActivationTableV1 {
    /// Creates empty fixed storage without reading the descriptor table.
    pub const fn new() -> Self {
        Self {
            descriptors: [None, None, None, None, None, None],
            count: 0,
            attempted: false,
            complete: false,
            failure: None,
            armed: true,
        }
    }

    /// Observes the names-derived prefix of original entries 3 through 8 once.
    ///
    /// # Errors
    /// Keeps the first actual duplication, flag or complete-table refusal.
    /// A repeated call ends observation without touching the process table.
    pub fn observe_once(&mut self, count: usize) -> std::result::Result<(), &Error> {
        if self.attempted {
            self.complete = false;
            return Err(self.failure.get_or_insert_with(|| {
                Error::invalid("Controller initial table", "observation is closed")
            }));
        }
        self.attempted = true;

        let result = {
            let _unwind = AbortInitialCaptureUnwind;
            self.observe_prefix(count)
        };
        match result {
            Ok(()) => {
                self.complete = true;
                Ok(())
            }
            Err(error) => Err(self.failure.get_or_insert(error)),
        }
    }

    /// Borrows the permanently retained first observation failure.
    pub fn failure(&self) -> Option<&Error> {
        self.failure.as_ref()
    }

    /// Moves the complete fixed slots once without another observation.
    ///
    /// The caller parks the returned array before any fallible continuation.
    /// No failed or interrupted observation exposes its successful prefix.
    #[must_use]
    pub fn take_completed_entries(&mut self) -> Option<[Option<OwnedFd>; 6]> {
        if !self.complete
            || self.count > self.descriptors.len()
            || self.descriptors[..self.count].iter().any(Option::is_none)
            || self.descriptors[self.count..].iter().any(Option::is_some)
        {
            return None;
        }
        let descriptors = std::mem::replace(
            &mut self.descriptors, [None, None, None, None, None, None],
        );
        self.complete = false;
        self.armed = false;
        Some(descriptors)
    }

    fn observe_prefix(&mut self, count: usize) -> Result<()> {
        begin_initial_activation_observation()?;
        if count > self.descriptors.len() {
            return Err(Error::invalid("Controller initial table", "count exceeds six slots"));
        }
        self.count = count;
        let numbers = contiguous_numbers(SYSTEMD_ACTIVATION_FD_BASE, count)?;
        for (slot, number) in self.descriptors.iter_mut().zip(&numbers) {
            *slot = Some(duplicate_inherited_descriptor(*number)?);
        }
        for number in &numbers {
            mark_inherited_descriptor_close_on_exec(*number)?;
        }

        use std::os::fd::AsRawFd as _;
        let expected = [0, 1, 2].into_iter().chain(numbers)
            .chain(self.descriptors.iter().flatten().map(|descriptor| descriptor.as_raw_fd()))
            .collect::<BTreeSet<_>>();
        require_initial_table_bookends(&expected)
    }
}

impl Default for ControllerInitialActivationTableV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ControllerInitialActivationTableV1 {
    fn drop(&mut self) {
        if self.armed {
            self.complete = false;
            std::process::abort();
        }
    }
}

struct AbortInitialCaptureUnwind;

impl Drop for AbortInitialCaptureUnwind {
    fn drop(&mut self) {
        if std::thread::panicking() {
            // Returned duplicates are already parked, before this stack unwinds.
            std::process::abort();
        }
    }
}

// The legacy Vec, offline fixed pair and Controller fixed prefix have different
// storage/drop contracts. Their fence and two complete observations are shared.
fn begin_initial_activation_observation() -> Result<()> {
    INITIAL_ACTIVATION_DUPLICATED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| Error::invalid("initial activation table", "already observed"))?;
    Ok(())
}

fn require_initial_table_bookends(expected: &BTreeSet<RawFd>) -> Result<()> {
    require_complete_startup_table(expected)?;
    require_complete_startup_table(expected)
}

/// Retains the fixed two-entry offline-prepare startup observation, including failures.
///
/// This is descriptor DATA, not launcher, role, profile or provisioning authority.
/// The caller parks this owner before calling its one-shot observation. Partial
/// duplicates never leave it; a failed or interrupted observation stays fenced.
pub struct NixOfflinePrepareInitialTableV3 {
    descriptors: [Option<OwnedFd>; 2],
    attempted: bool,
    complete: bool,
    failure: Option<Error>,
}

impl NixOfflinePrepareInitialTableV3 {
    /// Creates empty resident slots without observing or admitting a descriptor.
    pub const fn new() -> Self {
        Self {
            descriptors: [None, None],
            attempted: false,
            complete: false,
            failure: None,
        }
    }

    /// Observes only the original entries 3 and 4 through the shared startup fence.
    ///
    /// Each fresh duplicate is parked before the next fallible operation.
    /// A caught unwind leaves the attempted observation closed; the outer owner
    /// retains that unwind separately, rather than treating it as a returned error.
    ///
    /// # Errors
    /// Returns the retained first error for a repeat, missing entry, kernel failure,
    /// or an unexpected complete descriptor table. No failure permits another try.
    pub fn observe(&mut self) -> std::result::Result<(), &Error> {
        if self.attempted {
            self.complete = false;
            if self.failure.is_none() {
                self.failure = Some(Error::invalid(
                    "offline prepare startup",
                    "observation is already closed",
                ));
            }
        } else {
            self.attempted = true;
            if let Err(error) = self.observe_once() {
                self.failure = Some(error);
            } else {
                self.complete = true;
                return Ok(());
            }
        }

        Err(self.failure.get_or_insert_with(|| {
            Error::invalid("offline prepare startup", "observation did not complete")
        }))
    }

    /// Borrows the complete validated table without releasing either original.
    ///
    /// Failed or interrupted observations expose no partial descriptor.
    pub fn validated_entries(&self) -> Option<[BorrowedFd<'_>; 2]> {
        if !self.complete {
            return None;
        }
        let [Some(first), Some(second)] = &self.descriptors else {
            return None;
        };
        Some([first.as_fd(), second.as_fd()])
    }

    /// Borrows the first returned observation failure, not an unwind receipt.
    pub fn failure(&self) -> Option<&Error> {
        self.failure.as_ref()
    }

    fn observe_once(&mut self) -> Result<()> {
        begin_initial_activation_observation()?;

        for (slot, number) in self.descriptors.iter_mut().zip([3, 4]) {
            *slot = Some(duplicate_inherited_descriptor(number)?);
        }
        for number in [3, 4] {
            mark_inherited_descriptor_close_on_exec(number)?;
        }

        use std::os::fd::AsRawFd as _;
        let expected = [0, 1, 2, 3, 4]
            .into_iter()
            .chain(self.descriptors.iter().flatten().map(|descriptor| descriptor.as_raw_fd()))
            .collect::<BTreeSet<_>>();
        require_initial_table_bookends(&expected)
    }
}

impl Default for NixOfflinePrepareInitialTableV3 {
    fn default() -> Self {
        Self::new()
    }
}

/// Copies the complete initial activation table without taking numeric ownership.
///
/// This observational startup boundary uses the existing safe duplication seam,
/// marks originals close-on-exec, and rejects every other inherited descriptor
/// except standard I/O. It must run in the fixed service's single-threaded
/// startup interval, before opening credentials, journals, or other retained
/// files. Neither the supplied count nor successful observation authenticates
/// a launcher, a descriptor role, or an authorization.
///
/// # Errors
///
/// Rejects repeated attempts, over-limit counts, missing entries, kernel errors,
/// or a complete procfs table that differs from originals, duplicates, standard
/// I/O, and the temporary scanner. A failed attempt cannot be repeated.
pub fn duplicate_initial_activation_table(descriptor_count: usize) -> Result<Vec<OwnedFd>> {
    begin_initial_activation_observation()?;
    if descriptor_count > MAXIMUM_SYSTEMD_ACTIVATION_DESCRIPTORS {
        return Err(Error::invalid(
            "initial activation table",
            "count exceeds ceiling",
        ));
    }

    let numbers = contiguous_numbers(SYSTEMD_ACTIVATION_FD_BASE, descriptor_count)?;
    let descriptors = numbers
        .iter()
        .map(|number| duplicate_inherited_descriptor(*number))
        .collect::<Result<Vec<_>>>()?;
    for number in &numbers {
        mark_inherited_descriptor_close_on_exec(*number)?;
    }

    use std::os::fd::AsRawFd as _;
    let expected = [0, 1, 2]
        .into_iter()
        .chain(numbers)
        .chain(descriptors.iter().map(|descriptor| descriptor.as_raw_fd()))
        .collect::<BTreeSet<_>>();
    require_initial_table_bookends(&expected)?;
    Ok(descriptors)
}

// This is only a closed-set observation, not Mount's ownership-transfer,
// kcmp, executable, or launcher proof from startup_fd_table.
fn require_complete_startup_table(expected: &BTreeSet<RawFd>) -> Result<()> {
    let directory = std::fs::read_dir("/proc/self/fd").map_err(|source| Error::Syscall {
        operation: "enumerate complete initial activation table",
        source,
    })?;
    let scanner_target = std::path::PathBuf::from(format!("/proc/{}/fd", std::process::id()));
    let mut observed = BTreeSet::new();
    let mut scanner_seen = false;
    for entry in directory.take(expected.len() + 2) {
        let entry = entry.map_err(|source| Error::Syscall {
            operation: "read initial activation table entry",
            source,
        })?;
        let number = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<RawFd>().ok())
            .filter(|number| *number >= 0)
            .ok_or_else(|| {
                Error::invalid("initial activation table", "invalid descriptor number")
            })?;
        if expected.contains(&number) {
            if !observed.insert(number) {
                return Err(Error::invalid(
                    "initial activation table",
                    "duplicate entry",
                ));
            }
        } else if !scanner_seen
            && std::fs::read_link(entry.path()).map_err(|source| Error::Syscall {
                operation: "identify initial activation scanner",
                source,
            })? == scanner_target
        {
            scanner_seen = true;
        } else {
            return Err(Error::invalid(
                "initial activation table",
                "unexpected inherited descriptor",
            ));
        }
    }
    require_complete_observation(expected, &observed, scanner_seen)
}

fn require_complete_observation(
    expected: &BTreeSet<RawFd>,
    observed: &BTreeSet<RawFd>,
    scanner_seen: bool,
) -> Result<()> {
    if !scanner_seen || observed != expected {
        return Err(Error::invalid(
            "initial activation table",
            "incomplete descriptor set",
        ));
    }
    Ok(())
}

/// Claims only the closed five-role FUSE worker launch table.
///
/// This transfers descriptor ownership, not Mount provenance, a fresh FUSE
/// connection, a current lease, or read authority. The original table must be
/// exactly stdio and FDs 3 through 7; no environment selects an extra role.
///
/// # Safety
///
/// The caller must be the single-threaded fixed worker startup owner, before
/// constructing any I/O owner for FDs 3 through 7 or installing signal handlers.
/// No other code may mutate that descriptor table until this call returns.
///
/// # Errors
///
/// Returns an error for extra or missing descriptors, multiple threads, a
/// repeated claim, or a kernel capture failure. The caller must exit on failure.
pub unsafe fn claim_fuse_worker_descriptor_table() -> Result<[OwnedFd; 5]> {
    crate::startup_fd_table::with_blocked_signals(|| {
        let _single_thread = crate::pidfd::SingleThreadedProcess::verify()?;
        crate::startup_fd_table::require_fixed_worker_descriptor_numbers()?;
        // SAFETY: the fixed startup owner's contract covers the entire exact
        // role range; the signal fence and thread check preserve table stability.
        let descriptors =
            unsafe { claim_systemd_activation_descriptor_range(0, 5) }?.into_descriptors();
        descriptors
            .try_into()
            .map_err(|_| Error::invalid("fixed FUSE worker startup", "role capture length changed"))
    })
}

/// Owns a bounded contiguous portion of systemd's activation descriptor table.
#[derive(Debug)]
pub struct SystemdActivationDescriptorsV1 {
    descriptors: Vec<OwnedFd>,
}

impl SystemdActivationDescriptorsV1 {
    /// Returns the close-on-exec duplicates in ascending activation order.
    #[must_use]
    pub fn into_descriptors(self) -> Vec<OwnedFd> {
        self.descriptors
    }
}

/// Owns the helper plan and the still-unclassified fixed descriptor roles.
#[derive(Debug)]
pub struct ClaimedMountHelperDescriptorTableV1 {
    plan: OwnedFd,
    detached_mount: Option<OwnedFd>,
    mount_namespace: OwnedFd,
    target_root: OwnedFd,
    target_slot: OwnedFd,
    attachment_anchor: OwnedFd,
    observation: OwnedFd,
}

impl ClaimedMountHelperDescriptorTableV1 {
    /// Separates the sealed plan from descriptors classified by that plan.
    #[must_use]
    pub fn into_plan_and_pending(self) -> (OwnedFd, PendingMountHelperDescriptorTableV1) {
        (
            self.plan,
            PendingMountHelperDescriptorTableV1 {
                detached_mount: self.detached_mount,
                mount_namespace: self.mount_namespace,
                target_root: self.target_root,
                target_slot: self.target_slot,
                attachment_anchor: self.attachment_anchor,
                observation: self.observation,
            },
        )
    }
}

/// Retains fixed helper descriptors until the sealed plan classifies FD 4.
#[derive(Debug)]
pub struct PendingMountHelperDescriptorTableV1 {
    detached_mount: Option<OwnedFd>,
    mount_namespace: OwnedFd,
    target_root: OwnedFd,
    target_slot: OwnedFd,
    attachment_anchor: OwnedFd,
    observation: OwnedFd,
}

impl PendingMountHelperDescriptorTableV1 {
    /// Validates the plan's detached-mount role and completes descriptor admission.
    ///
    /// # Errors
    ///
    /// Returns an error when FD 4's observed presence differs from the sealed
    /// plan. Every retained duplicate closes when this admission fails.
    pub fn admit_plan_roles(
        self,
        requires_detached_mount: bool,
    ) -> Result<MountHelperDescriptorsV1> {
        if self.detached_mount.is_some() != requires_detached_mount {
            return Err(Error::invalid(
                "mount helper descriptor table",
                "detached-mount presence differs from the sealed plan",
            ));
        }

        Ok(MountHelperDescriptorsV1 {
            detached_mount: self.detached_mount,
            mount_namespace: self.mount_namespace,
            target_root: self.target_root,
            target_slot: self.target_slot,
            attachment_anchor: self.attachment_anchor,
            observation: self.observation,
        })
    }
}

/// Owns the fixed helper descriptor roles admitted by the sealed plan.
#[derive(Debug)]
pub struct MountHelperDescriptorsV1 {
    detached_mount: Option<OwnedFd>,
    mount_namespace: OwnedFd,
    target_root: OwnedFd,
    target_slot: OwnedFd,
    attachment_anchor: OwnedFd,
    observation: OwnedFd,
}

/// Fixed helper descriptors in detached-mount, namespace, path, and report order.
pub type MountHelperDescriptorPartsV1 =
    (Option<OwnedFd>, OwnedFd, OwnedFd, OwnedFd, OwnedFd, OwnedFd);

impl MountHelperDescriptorsV1 {
    /// Returns all admitted roles in their fixed semantic order.
    #[must_use]
    pub fn into_parts(self) -> MountHelperDescriptorPartsV1 {
        (
            self.detached_mount,
            self.mount_namespace,
            self.target_root,
            self.target_slot,
            self.attachment_anchor,
            self.observation,
        )
    }
}

/// Claims a bounded contiguous tail of systemd's activation descriptor table.
///
/// `first_offset` skips descriptors already claimed by another subsystem. The
/// returned values preserve ascending activation order, are close-on-exec, and
/// use fresh numbers at or above 64. Every original in the requested range is
/// closed together on success or after any post-reservation failure.
///
/// This function is intended only for the single-threaded startup interval,
/// after the caller has authenticated `LISTEN_PID` and bounded `LISTEN_FDS`.
/// A process may claim disjoint portions of the table, but an attempted number
/// can never be claimed again through this module even if the kernel later
/// reuses it.
///
/// # Safety
///
/// The caller must be the single-threaded process-start owner of every numeric
/// descriptor in the requested range. No `File`, `OwnedFd`, borrowed I/O value,
/// or other owner may already represent any entry, and no thread, signal
/// handler, or concurrent code may open, close, duplicate, or replace a table
/// entry until this function returns. These ownership and table-stability facts
/// cannot be inferred from `LISTEN_FDS` or enforced by the claim registry.
///
/// # Errors
///
/// Returns an error for an overflowing or over-limit range, an overlapping
/// prior claim, a missing entry, descriptor duplication failure, or a poisoned
/// process-local claim registry.
pub unsafe fn claim_systemd_activation_descriptor_range(
    first_offset: usize,
    descriptor_count: usize,
) -> Result<SystemdActivationDescriptorsV1> {
    let end_offset = first_offset
        .checked_add(descriptor_count)
        .ok_or_else(|| Error::invalid("systemd activation range", "descriptor count overflows"))?;
    if end_offset > MAXIMUM_SYSTEMD_ACTIVATION_DESCRIPTORS {
        return Err(Error::invalid(
            "systemd activation range",
            "exceeds the 1025-descriptor ceiling",
        ));
    }
    if descriptor_count == 0 {
        return Ok(SystemdActivationDescriptorsV1 {
            descriptors: Vec::new(),
        });
    }

    let first = SYSTEMD_ACTIVATION_FD_BASE
        .checked_add(raw_fd_from_usize(first_offset)?)
        .ok_or_else(|| Error::invalid("systemd activation range", "first descriptor overflows"))?;
    let numbers = contiguous_numbers(first, descriptor_count)?;
    // SAFETY: forwarded from this function's numeric ownership and stable-table
    // contract for the exact validated systemd range.
    let descriptors = unsafe { duplicate_and_close_claimed(&numbers, |_| Presence::Required) }?
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| Error::MalformedKernelResponse {
            object: "systemd activation descriptor table",
            message: "required descriptor was omitted after admission".to_owned(),
        })?;

    Ok(SystemdActivationDescriptorsV1 { descriptors })
}

/// Claims the mount helper's exact fixed descriptor table in one operation.
///
/// FDs 3 and 5 through 9 must be open. FD 4 may be either open or absent until
/// the sealed plan is decoded. Every present original from 3 through 9 closes
/// together; the result retains only fresh close-on-exec duplicates.
///
/// # Safety
///
/// The caller must be the helper's single-threaded process-start owner of every
/// present descriptor from 3 through 9. No `File`, `OwnedFd`, borrowed I/O
/// value, or other owner may represent those entries, and no thread, signal
/// handler, or concurrent code may open, close, duplicate, or replace them
/// until this function returns. The fixed launcher contract, not the
/// process-local registry, must establish these facts.
///
/// # Errors
///
/// Returns an error for a repeated/overlapping claim, a missing mandatory role,
/// descriptor duplication failure, or a poisoned process-local claim registry.
pub unsafe fn claim_mount_helper_descriptor_table() -> Result<ClaimedMountHelperDescriptorTableV1> {
    let numbers = contiguous_numbers(MOUNT_HELPER_PLAN_FD, 7)?;
    // SAFETY: forwarded from this function's numeric ownership and stable-table
    // contract for the exact fixed helper range.
    let mut descriptors = unsafe {
        duplicate_and_close_claimed(&numbers, |number| {
            if number == MOUNT_HELPER_DETACHED_MOUNT_FD {
                Presence::Optional
            } else {
                Presence::Required
            }
        })
    }?
    .into_iter();

    let plan = next_required(&mut descriptors, "plan")?;
    let detached_mount = descriptors.next().flatten();
    let mount_namespace = next_required(&mut descriptors, "mount namespace")?;
    let target_root = next_required(&mut descriptors, "target root")?;
    let target_slot = next_required(&mut descriptors, "target slot")?;
    let attachment_anchor = next_required(&mut descriptors, "attachment anchor")?;
    let observation = next_required(&mut descriptors, "observation")?;
    if descriptors.next().is_some() {
        return Err(Error::MalformedKernelResponse {
            object: "mount helper descriptor table",
            message: "admission returned too many descriptors".to_owned(),
        });
    }

    Ok(ClaimedMountHelperDescriptorTableV1 {
        plan,
        detached_mount,
        mount_namespace,
        target_root,
        target_slot,
        attachment_anchor,
        observation,
    })
}

/// Duplicates a safely borrowed descriptor into independent close-on-exec ownership.
///
/// The original descriptor remains open and untouched.
/// Launchers that transfer an [`OwnedFd`] with `SCM_RIGHTS` can borrow that
/// owner here and avoid the unsafe numeric claim APIs entirely. This is the
/// dormant safe seam for a future explicit owned-descriptor startup protocol.
///
/// # Errors
///
/// Returns an error when the kernel cannot duplicate `descriptor`.
pub fn duplicate_descriptor(descriptor: BorrowedFd<'_>) -> Result<OwnedFd> {
    rustix::io::fcntl_dupfd_cloexec(descriptor, 0).map_err(|source| Error::Syscall {
        operation: "fcntl(F_DUPFD_CLOEXEC)",
        source: std::io::Error::from_raw_os_error(source.raw_os_error()),
    })
}

/// Duplicates one currently open numeric descriptor into new owned storage.
///
/// The original descriptor remains open and untouched. This compatibility
/// boundary never assumes ownership of `raw`; fixed startup protocols should
/// instead use the closed one-shot claim functions in this module.
///
/// # Errors
///
/// Returns an error when `raw` is negative, closed, or cannot be duplicated.
pub fn duplicate_inherited_descriptor(raw: RawFd) -> Result<OwnedFd> {
    if raw < 0 {
        return Err(Error::invalid(
            "inherited descriptor",
            "number must be non-negative",
        ));
    }

    // SAFETY: F_DUPFD_CLOEXEC only observes `raw` and returns a distinct
    // descriptor. It does not borrow, close, or assume ownership of `raw`.
    let duplicated = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicated < 0 {
        return Err(Error::syscall("fcntl(F_DUPFD_CLOEXEC)"));
    }

    // SAFETY: successful F_DUPFD_CLOEXEC returned a fresh table entry with no
    // existing Rust owner.
    unsafe { owned_fresh_descriptor(duplicated) }
}

/// Marks an inherited numeric descriptor close-on-exec without taking ownership.
///
/// A fixed-role service may retain a fresh owned duplicate while this original
/// table entry remains open. Marking the original prevents a later process
/// effect from inheriting the channel or provisioning credential. The caller
/// must perform this during single-threaded startup so no concurrent code can
/// replace or change the descriptor between the checked kernel operations.
///
/// # Errors
///
/// Returns an error for a negative or closed number, a failed flag update, or
/// a kernel readback that does not retain `FD_CLOEXEC`.
pub fn mark_inherited_descriptor_close_on_exec(raw: RawFd) -> Result<()> {
    if raw < 0 {
        return Err(Error::invalid(
            "inherited descriptor",
            "number must be non-negative",
        ));
    }

    // SAFETY: fcntl observes or changes descriptor-table flags for a numeric
    // entry. It creates no Rust owner or borrowed reference to that entry.
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
    if flags < 0 {
        return Err(Error::syscall("fcntl(F_GETFD)"));
    }
    // SAFETY: the same numeric table entry was checked above during the fixed
    // single-threaded startup interval; no Rust descriptor ownership changes.
    if unsafe { libc::fcntl(raw, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(Error::syscall("fcntl(F_SETFD)"));
    }
    // SAFETY: readback inspects only descriptor-table flags for this entry.
    let observed = unsafe { libc::fcntl(raw, libc::F_GETFD) };
    if observed < 0 {
        return Err(Error::syscall("fcntl(F_GETFD)"));
    }
    if observed & libc::FD_CLOEXEC == 0 {
        return Err(Error::invalid(
            "inherited descriptor",
            "close-on-exec was not retained",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Presence {
    Required,
    Optional,
}

struct ExclusiveRawDescriptors {
    numbers: Vec<RawFd>,
}

impl ExclusiveRawDescriptors {
    /// Reserves numbers whose originals this value will close on drop.
    ///
    /// # Safety
    ///
    /// The caller must exclusively own every present numeric table entry and
    /// keep the descriptor table stable until the returned value is dropped.
    unsafe fn reserve(numbers: &[RawFd]) -> Result<Self> {
        let mut claimed = CLAIMED_DESCRIPTOR_NUMBERS.lock().map_err(|_| {
            Error::invalid(
                "inherited descriptor registry",
                "process-local claim registry is poisoned",
            )
        })?;
        if numbers.iter().any(|number| claimed.contains(number)) {
            return Err(Error::invalid(
                "inherited descriptor range",
                "overlaps a prior claim",
            ));
        }
        claimed.extend(numbers.iter().copied());

        Ok(Self {
            numbers: numbers.to_vec(),
        })
    }
}

impl Drop for ExclusiveRawDescriptors {
    fn drop(&mut self) {
        for number in &self.numbers {
            // SAFETY: the closed startup APIs reserve each fixed table number
            // once and exclusively consume the exact described range. `close`
            // also safely reports EBADF for an admitted optional gap.
            let _ = unsafe { libc::close(*number) };
        }
    }
}

/// Duplicates and closes one exclusively owned numeric descriptor set.
///
/// # Safety
///
/// The caller must exclusively own every present numeric entry in `numbers`,
/// with no existing Rust I/O owner, and must keep the table stable throughout
/// the call.
unsafe fn duplicate_and_close_claimed(
    numbers: &[RawFd],
    expected: impl Fn(RawFd) -> Presence,
) -> Result<Vec<Option<OwnedFd>>> {
    // SAFETY: forwarded from this function's ownership and stability contract.
    let originals = unsafe { ExclusiveRawDescriptors::reserve(numbers) }?;
    let mut present = Vec::with_capacity(numbers.len());
    for number in numbers {
        // SAFETY: F_GETFD observes a scalar table index and reports EBADF for
        // a closed optional entry without borrowing or taking ownership.
        let descriptor_flags = unsafe { libc::fcntl(*number, libc::F_GETFD) };
        if descriptor_flags < 0 {
            let source = std::io::Error::last_os_error();
            if source.raw_os_error() != Some(libc::EBADF) {
                return Err(Error::Syscall {
                    operation: "fcntl(F_GETFD) inherited table",
                    source,
                });
            }
            if expected(*number) == Presence::Required {
                return Err(Error::invalid(
                    "inherited descriptor table",
                    format!("required descriptor {number} is absent"),
                ));
            }
            present.push(false);
        } else {
            present.push(true);
        }
    }

    let mut duplicates = Vec::with_capacity(numbers.len());
    for (number, is_present) in numbers.iter().zip(present) {
        if !is_present {
            duplicates.push(None);
            continue;
        }
        // SAFETY: the complete exact table remains reserved and open through
        // this loop. F_DUPFD_CLOEXEC returns a fresh descriptor at or above 64.
        let duplicated =
            unsafe { libc::fcntl(*number, libc::F_DUPFD_CLOEXEC, DUPLICATE_FD_MINIMUM) };
        if duplicated < 0 {
            return Err(Error::syscall("fcntl(F_DUPFD_CLOEXEC) inherited table"));
        }
        // SAFETY: successful F_DUPFD_CLOEXEC returned a fresh table entry with
        // no existing Rust owner.
        duplicates.push(Some(unsafe { owned_fresh_descriptor(duplicated) }?));
    }

    drop(originals);
    Ok(duplicates)
}

/// Constructs ownership for a descriptor freshly returned by the kernel.
///
/// # Safety
///
/// `raw` must be a live descriptor allocated by the immediately preceding
/// operation, and no Rust I/O owner may already represent it.
unsafe fn owned_fresh_descriptor(raw: RawFd) -> Result<OwnedFd> {
    if raw < 0 {
        return Err(Error::MalformedKernelResponse {
            object: "descriptor duplication",
            message: "kernel returned a negative descriptor".to_owned(),
        });
    }
    // SAFETY: the successful duplication operation returned this fresh table
    // entry and no other Rust owner has been constructed for it.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn contiguous_numbers(first: RawFd, count: usize) -> Result<Vec<RawFd>> {
    if first < SYSTEMD_ACTIVATION_FD_BASE {
        return Err(Error::invalid(
            "inherited descriptor range",
            "must begin at or above descriptor 3",
        ));
    }
    (0..count)
        .map(|offset| {
            first
                .checked_add(raw_fd_from_usize(offset)?)
                .ok_or_else(|| Error::invalid("inherited descriptor range", "number overflows"))
        })
        .collect()
}

fn raw_fd_from_usize(value: usize) -> Result<RawFd> {
    RawFd::try_from(value)
        .map_err(|_| Error::invalid("inherited descriptor range", "number does not fit RawFd"))
}

fn next_required(
    descriptors: &mut impl Iterator<Item = Option<OwnedFd>>,
    role: &'static str,
) -> Result<OwnedFd> {
    descriptors
        .next()
        .flatten()
        .ok_or_else(|| Error::MalformedKernelResponse {
            object: "mount helper descriptor table",
            message: format!("admission omitted the {role} descriptor"),
        })
}

#[cfg(test)]
mod tests {
    use std::io::Read as _;
    use std::os::fd::AsRawFd as _;

    use super::*;

    #[test]
    fn interrupted_offline_slots_stay_closed_without_observing_the_process_table() {
        let mut resident = super::NixOfflinePrepareInitialTableV3::new();
        resident.attempted = true;

        assert!(resident.validated_entries().is_none());
        assert!(resident.observe().is_err());
        assert!(resident.failure().is_some());
        assert!(resident.validated_entries().is_none());
    }

    #[test]
    fn duplication_never_takes_the_callers_original_ownership() {
        let original = std::fs::File::open("/proc/self/exe")
            .unwrap_or_else(|error| panic!("test executable failed: {error}"));
        let raw = original.as_raw_fd();
        let duplicate = duplicate_inherited_descriptor(raw)
            .unwrap_or_else(|error| panic!("descriptor duplication failed: {error}"));
        drop(duplicate);

        let mut original = original;
        let mut byte = [0_u8; 1];
        original
            .read_exact(&mut byte)
            .unwrap_or_else(|error| panic!("original descriptor was invalidated: {error}"));
    }

    #[test]
    fn invalid_descriptor_is_rejected_without_assuming_ownership() {
        assert!(duplicate_inherited_descriptor(i32::MAX).is_err());
    }

    #[test]
    fn complete_initial_activation_observation_rejects_missing_and_extra_entries() {
        let expected = BTreeSet::from([0, 1, 2, 3, 4]);
        assert!(require_complete_observation(&expected, &expected, true).is_ok());
        assert!(require_complete_observation(&expected, &expected, false).is_err());
        assert!(
            require_complete_observation(&expected, &BTreeSet::from([0, 1, 2, 3]), true).is_err()
        );
        assert!(
            require_complete_observation(&expected, &BTreeSet::from([0, 1, 2, 3, 4, 9]), true)
                .is_err()
        );
    }
}
