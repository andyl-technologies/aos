//! One-shot ownership transfer for fixed descriptors inherited at process start.
//!
//! Systemd activation and the mount namespace helper identify descriptors by
//! fixed process-table numbers. This module is the sole boundary that observes
//! those numbers. It first reserves an exact bounded set against repeated or
//! overlapping claims, duplicates every required live entry with
//! `F_DUPFD_CLOEXEC`, and closes every original entry together. Only the fresh
//! duplicates become [`OwnedFd`] values.

use std::collections::BTreeSet;
use std::os::fd::{BorrowedFd, FromRawFd as _, OwnedFd, RawFd};
use std::sync::Mutex;

use crate::{Error, Result};

const SYSTEMD_ACTIVATION_FD_BASE: RawFd = 3;
const MAXIMUM_SYSTEMD_ACTIVATION_DESCRIPTORS: usize = 1_025;
const MOUNT_HELPER_PLAN_FD: RawFd = 3;
const MOUNT_HELPER_DETACHED_MOUNT_FD: RawFd = 4;
const DUPLICATE_FD_MINIMUM: RawFd = 64;

static CLAIMED_DESCRIPTOR_NUMBERS: Mutex<BTreeSet<RawFd>> = Mutex::new(BTreeSet::new());

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
}
