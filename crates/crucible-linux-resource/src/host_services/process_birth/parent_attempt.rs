//! Retains one fixed Parent purpose in the existing authenticated process bank.
//!
//! The permanent process owner stores the pair before covered preparation. Its
//! original unit end encloses the attempt, and uncertain teardown never refunds
//! the pair. Compiled ceilings describe required operator policy; image floors
//! and kernel readbacks do not create this reservation.

use std::fmt;
use std::path::Path;

use super::cpu::{OriginalCpuCounters, OriginalCpuReadError};
use super::{AuthenticatedProcessResources, HostServiceLease, HostServiceLeasePair};

#[derive(Debug)]
pub(super) enum AttemptFailure {
    Occupied,
    OriginalEnd,
    CompiledPurpose,
    Credit(super::HostServiceError),
    Backing(super::backing::BackingRefusal),
    Cpu(OriginalCpuReadError),
    Kernel(std::io::Error),
    Descendant,
}

pub(super) struct AttemptSlot {
    occupied: bool,
    _pair: Option<HostServiceLeasePair>,
    purpose: Option<ParentPurpose>,
    start: Option<u64>,
    end: Option<u64>,
    before: Option<OriginalCpuCounters>,
    first: Option<AttemptFailure>,
    post_expired: bool,
    cpu_delta: Option<OriginalCpuCounters>,
    elapsed_microseconds: Option<u64>,
    backing: super::backing::BackingAccount,
    // Retained outside the consumer through all covered backing effects.
    _backing_debit: Option<std::num::NonZeroU64>,
}

impl AttemptSlot {
    pub(super) const fn new(backing: super::backing::BackingAccount) -> Self {
        Self {
            occupied: false,
            _pair: None,
            purpose: None,
            start: None,
            end: None,
            before: None,
            first: None,
            post_expired: false,
            cpu_delta: None,
            elapsed_microseconds: None,
            backing,
            _backing_debit: None,
        }
    }

    fn retain(&mut self, cause: AttemptFailure) {
        if self.first.is_none() {
            self.first = Some(cause);
        }
    }
}

struct ParentPurpose {
    source_resident: u64,
    source_backing: u64,
    tasks: u64,
    descriptors: u64,
    total_metadata: u64,
}

impl ParentPurpose {
    fn compiled() -> Result<Self, AttemptFailure> {
        Self::from_profile([
            option_env!("CRUCIBLE_PARENT_SOURCE_RESIDENT"),
            option_env!("CRUCIBLE_PARENT_SOURCE_BACKING"),
            option_env!("CRUCIBLE_PARENT_SOURCE_TASKS"),
            option_env!("CRUCIBLE_PARENT_SOURCE_FDS"),
            option_env!("CRUCIBLE_PARENT_TOTAL_METADATA"),
        ])
    }

    fn from_profile(values: [Option<&str>; 5]) -> Result<Self, AttemptFailure> {
        let positive = |value: Option<&str>| {
            value
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|value| *value > 0)
                .ok_or(AttemptFailure::CompiledPurpose)
        };
        let purpose = Self {
            source_resident: positive(values[0])?,
            source_backing: positive(values[1])?,
            tasks: positive(values[2])?,
            descriptors: positive(values[3])?,
            total_metadata: positive(values[4])?,
        };
        let resident = (20_u64 << 30)
            .checked_add(purpose.source_resident)
            .ok_or(AttemptFailure::CompiledPurpose)?;
        let controls = HostServiceLease::metadata_bytes()
            .checked_mul(2)
            .ok_or(AttemptFailure::CompiledPurpose)?;
        if purpose.total_metadata < controls
            || purpose.total_metadata > resident
            || (64_u64 << 30).checked_add(purpose.source_backing).is_none()
        {
            return Err(AttemptFailure::CompiledPurpose);
        }
        Ok(purpose)
    }
}

// Only the trusted compiled operator profile can issue this startup dimension.
// Ordinary profiles with no Parent inputs publish no backing entitlement.
pub(super) fn compiled_backing_capacity() -> Result<Option<u64>, super::ServiceBirthError> {
    backing_capacity_from_profile([
        option_env!("CRUCIBLE_PARENT_SOURCE_RESIDENT"),
        option_env!("CRUCIBLE_PARENT_SOURCE_BACKING"),
        option_env!("CRUCIBLE_PARENT_SOURCE_TASKS"),
        option_env!("CRUCIBLE_PARENT_SOURCE_FDS"),
        option_env!("CRUCIBLE_PARENT_TOTAL_METADATA"),
    ])
}

fn backing_capacity_from_profile(
    values: [Option<&str>; 5],
) -> Result<Option<u64>, super::ServiceBirthError> {
    if values.iter().all(Option::is_none) {
        return Ok(None);
    }
    let purpose = ParentPurpose::from_profile(values).map_err(|_| {
        super::ServiceBirthError::policy("invalid or incomplete original Parent backing contract")
    })?;
    let capacity = (64_u64 << 30)
        .checked_add(purpose.source_backing)
        .ok_or_else(|| {
            super::ServiceBirthError::policy("original Parent backing contract overflows")
        })?;
    Ok(Some(capacity))
}

/// Pins a paid fixed Parent purpose to the same registered process incarnation.
///
/// There is no constructor from scalars, a lease pair, or a cgroup path. The
/// original pair stays in the permanent process owner even if this token drops.
/// This token supplies no native role and is not evidence of physical closure.
pub struct OriginalParentAttempt {
    owner: &'static AuthenticatedProcessResources,
}

/// Reports refusal while the non-clone first cause stays in the permanent slot.
pub struct OriginalParentAttemptRefusal {
    owner: &'static AuthenticatedProcessResources,
}

impl fmt::Debug for OriginalParentAttemptRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for OriginalParentAttemptRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let slot = self
            .owner
            .attempt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        write!(formatter, "original Parent attempt refused: ")?;
        match &slot.first {
            Some(AttemptFailure::Credit(error)) => write!(formatter, "{error}"),
            Some(AttemptFailure::Cpu(error)) => write!(formatter, "{error}"),
            Some(AttemptFailure::Kernel(error)) => write!(formatter, "{error}"),
            Some(AttemptFailure::Backing(cause)) => {
                write!(formatter, "original backing: {cause:?}")
            }
            cause => write!(formatter, "{cause:?}"),
        }?;
        if slot.post_expired {
            write!(formatter, "; separate original postcheck expired")?;
        }
        Ok(())
    }
}

impl std::error::Error for OriginalParentAttemptRefusal {}

impl AuthenticatedProcessResources {
    /// Reserves the compiled Parent purpose once before request preparation.
    ///
    /// The start observation precedes purpose decoding and both actual account
    /// debits. The end is bounded by the existing authenticated unit end. The
    /// caller retains this owner permanently; no failure reissues the attempt.
    ///
    /// # Errors
    /// Refuses repeated entry, clock/counter failure, missing required compiled
    /// purposes, original expiry, or exhausted same-process counters.
    pub fn begin_original_parent(
        &'static self,
    ) -> Result<OriginalParentAttempt, OriginalParentAttemptRefusal> {
        let mut slot = self
            .attempt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let refusal = || OriginalParentAttemptRefusal { owner: self };
        if slot.occupied {
            slot.retain(AttemptFailure::Occupied);
            return Err(refusal());
        }
        slot.occupied = true;
        let result = (|| {
            let start = super::monotonic_microseconds().ok_or(AttemptFailure::OriginalEnd)?;
            slot.start = Some(start);
            slot.end = Some(
                start
                    .checked_add(3_900_000_000)
                    .ok_or(AttemptFailure::OriginalEnd)?
                    .min(self.birth.deadline),
            );
            if !self.is_live() {
                return Err(AttemptFailure::OriginalEnd);
            }
            let mut counter = self
                .birth
                .cpu
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            slot.before = Some(super::cpu::read(&mut counter).map_err(AttemptFailure::Cpu)?);
            let purpose = ParentPurpose::compiled()?;
            let backing = (64_u64 << 30)
                .checked_add(purpose.source_backing)
                .ok_or(AttemptFailure::CompiledPurpose)?;
            let debit = slot
                .backing
                .debit(backing)
                .map_err(AttemptFailure::Backing)?;
            slot._backing_debit = Some(debit);
            let resident = (20_u64 << 30)
                .checked_add(purpose.source_resident)
                .ok_or(AttemptFailure::CompiledPurpose)?;
            let (full, subset) = self
                .resident
                .reserve_native_pair(
                    &self.metadata,
                    purpose.tasks,
                    purpose.descriptors,
                    resident,
                    purpose.total_metadata,
                )
                .map_err(AttemptFailure::Credit)?;
            // Publication precedes every subsequent clock, callback or effect.
            slot._pair = Some(HostServiceLeasePair::new(full, subset));
            slot.purpose = Some(purpose);
            Ok(())
        })();
        let after = super::monotonic_microseconds()
            .is_some_and(|now| slot.end.is_some_and(|end| now < end));
        if let Err(first) = result {
            slot.retain(first);
        }
        if !after {
            slot.post_expired = true;
            slot.retain(AttemptFailure::OriginalEnd);
        }
        if slot.first.is_some() {
            Err(refusal())
        } else {
            Ok(OriginalParentAttempt { owner: self })
        }
    }
}

impl OriginalParentAttempt {
    /// Observes the retained ancestor after the caller's factual physical joins.
    ///
    /// This observes rather than authorizes retirement. The caller must already
    /// have joined its actual children, watchers and physical owner. The loan
    /// remains in permanent custody, including when sampling or the independent
    /// enclosing postcheck fails; this call never releases or renews credit.
    ///
    /// # Errors
    /// Retains IO, malformed/backwards counters, clock failure or original expiry
    /// without replacing an earlier work failure.
    pub fn observe_after_physical_join(&self) -> Result<(), OriginalParentAttemptRefusal> {
        let mut slot = self
            .owner
            .attempt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let result = (|| {
            let mut counter = self
                .owner
                .birth
                .cpu
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let after = super::cpu::read(&mut counter).map_err(AttemptFailure::Cpu)?;
            slot.cpu_delta = Some(
                after
                    .since(slot.before.ok_or(AttemptFailure::Occupied)?)
                    .ok_or(AttemptFailure::Cpu(OriginalCpuReadError::InvalidCounter))?,
            );
            let end = super::monotonic_microseconds().ok_or(AttemptFailure::OriginalEnd)?;
            slot.elapsed_microseconds = Some(
                end.checked_sub(slot.start.ok_or(AttemptFailure::Occupied)?)
                    .ok_or(AttemptFailure::OriginalEnd)?,
            );
            Ok(())
        })();
        if let Err(first) = result {
            slot.retain(first);
        }
        drop(slot);
        self.check_original()
    }

    /// Returns completed independent CPU and wall observations when available.
    ///
    /// The returned scalar result carries no credit, physical closure or role.
    #[must_use]
    pub fn completed_observation(&self) -> Option<(OriginalCpuCounters, u64)> {
        let slot = self
            .owner
            .attempt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Some((slot.cpu_delta?, slot.elapsed_microseconds?))
    }

    /// Checks the retained absolute end without starting another clock.
    ///
    /// # Errors
    /// Refuses original expiry or an already retained first failure.
    pub fn check_original(&self) -> Result<(), OriginalParentAttemptRefusal> {
        let mut slot = self
            .owner
            .attempt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !super::monotonic_microseconds().is_some_and(|now| slot.end.is_some_and(|end| now < end))
        {
            slot.post_expired = true;
            slot.retain(AttemptFailure::OriginalEnd);
        }
        if slot.first.is_some() {
            Err(OriginalParentAttemptRefusal { owner: self.owner })
        } else {
            Ok(())
        }
    }

    /// Returns the remaining duration of the same absolute original end.
    ///
    /// This samples the existing monotonic domain; it never starts a new end.
    ///
    /// # Errors
    /// Retains original expiry or clock uncertainty alongside the first cause.
    pub fn remaining(&self) -> Result<std::time::Duration, OriginalParentAttemptRefusal> {
        self.check_original()?;
        let mut slot = self
            .owner
            .attempt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let remaining = super::monotonic_microseconds().and_then(|now| {
            slot.end
                .and_then(|end| end.checked_sub(now))
                .filter(|value| *value > 0)
        });
        match remaining {
            Some(microseconds) => Ok(std::time::Duration::from_micros(microseconds)),
            None => {
                slot.post_expired = true;
                slot.retain(AttemptFailure::OriginalEnd);
                Err(OriginalParentAttemptRefusal { owner: self.owner })
            }
        }
    }

    /// Checks the requested fixed workload against the same retained ancestor.
    ///
    /// This comparison issues no path capability. Both directory aliases must
    /// identify the existing workload child of the authenticated process root.
    ///
    /// # Errors
    /// Refuses original expiry, missing delegation, kernel failure or a sibling
    /// or replacement directory. The original work cause precedes its postcheck.
    pub fn verify_factory_descendant(
        &self,
        candidate: &Path,
    ) -> Result<(), OriginalParentAttemptRefusal> {
        use std::os::unix::fs::MetadataExt;
        self.check_original()?;
        let result = (|| {
            let child = rustix::fs::openat(
                &self.owner.birth._cgroup,
                "workload",
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|error| AttemptFailure::Kernel(error.into()))?;
            let expected = std::fs::File::from(child)
                .metadata()
                .map_err(AttemptFailure::Kernel)?;
            let actual = std::fs::metadata(candidate).map_err(AttemptFailure::Kernel)?;
            if expected.dev() != actual.dev() || expected.ino() != actual.ino() {
                return Err(AttemptFailure::Descendant);
            }
            Ok(())
        })();
        if let Err(first) = result {
            self.owner
                .attempt
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .retain(first);
        }
        self.check_original()
    }

    /// Checks the nested Parent's exact compiled Source against this reservation.
    ///
    /// # Errors
    /// Refuses a different Source, descriptor or task partition.
    pub fn matches_source(
        &self,
        resident: u64,
        backing: u64,
        tasks: u64,
        descriptors: u64,
    ) -> Result<(), OriginalParentAttemptRefusal> {
        self.check_original()?;
        let mut slot = self
            .owner
            .attempt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !slot.purpose.as_ref().is_some_and(|purpose| {
            purpose.source_resident == resident
                && purpose.source_backing == backing
                && purpose.tasks == tasks
                && purpose.descriptors == descriptors
        }) {
            slot.retain(AttemptFailure::CompiledPurpose);
            return Err(OriginalParentAttemptRefusal { owner: self.owner });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mechanism_owner() -> &'static AuthenticatedProcessResources {
        // This local clock/counter control supplies no usable Parent purpose.
        let original = super::super::super::HostServiceBootstrap::new(4, 12, 4096, 1024)
            .unwrap()
            .reserve_structure(super::super::super::HostServiceBootstrap::control_bytes().unwrap())
            .unwrap();
        let birth = super::super::VerifiedServiceBirth {
            deadline: u64::MAX,
            invocation: [1; 16],
            _cgroup: tempfile::tempfile().unwrap(),
            resident_bytes: 4096,
            metadata_bytes: 1024,
            tasks: 4,
            descriptors: 12,
            cpu: std::sync::Mutex::new(tempfile::tempfile().unwrap()),
        };
        Box::leak(Box::new(birth.publish_original_process(original).unwrap()))
    }

    #[test]
    fn compiled_backing_profile_is_required_complete_and_checked() {
        let complete = [
            Some("1024"),
            Some("4096"),
            Some("1"),
            Some("8"),
            Some("4096"),
        ];

        assert_eq!(backing_capacity_from_profile([None; 5]).unwrap(), None);
        assert_eq!(
            backing_capacity_from_profile(complete).unwrap(),
            Some((64_u64 << 30) + 4096)
        );
        let mut partial = complete;
        partial[4] = None;
        assert!(backing_capacity_from_profile(partial).is_err());
        partial = complete;
        partial[1] = Some("18446744073709551615");
        assert!(backing_capacity_from_profile(partial).is_err());
        partial = complete;
        partial[0] = Some("18446744073709551615");
        assert!(backing_capacity_from_profile(partial).is_err());
    }

    #[test]
    fn backing_remains_debited_on_pair_refusal_failed_close_and_unwind() {
        let owner = mechanism_owner();
        let capacity = (64_u64 << 30) + 4096;
        {
            let mut slot = owner.attempt.lock().unwrap();
            // A local authority fixture, not an installed operator grant.
            slot.backing = super::super::backing::BackingAccount::mechanism(capacity);
            slot._backing_debit = Some(slot.backing.debit(capacity).unwrap());
        }
        let pair = owner
            .resident
            .reserve_native_pair(&owner.metadata, 0, 0, u64::MAX, 512);
        assert!(pair.is_err());
        {
            let mut slot = owner.attempt.lock().unwrap();
            slot.retain(AttemptFailure::Kernel(std::io::Error::from_raw_os_error(
                13,
            )));
        }
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _slot = owner.attempt.lock().unwrap();
                panic!("physical close uncertainty");
            }))
            .is_err()
        );
        let mut slot = owner
            .attempt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        slot.retain(AttemptFailure::OriginalEnd);

        assert_eq!(slot._backing_debit.unwrap().get(), capacity);
        assert_eq!(
            slot.backing.debit(1),
            Err(super::super::backing::BackingRefusal::Exhausted)
        );
        assert!(
            matches!(&slot.first, Some(AttemptFailure::Kernel(error)) if error.raw_os_error() == Some(13))
        );
    }

    #[test]
    fn remaining_does_not_renew_end_or_replace_first_cause() {
        let owner = mechanism_owner();
        let now = super::super::monotonic_microseconds().unwrap();
        let end = now.checked_add(1_000_000).unwrap();
        owner.attempt.lock().unwrap().end = Some(end);
        let original = OriginalParentAttempt { owner };

        let remaining = original.remaining().unwrap();

        assert!(remaining <= std::time::Duration::from_secs(1));
        assert_eq!(owner.attempt.lock().unwrap().end, Some(end));
        {
            let mut slot = owner.attempt.lock().unwrap();
            slot.end = Some(0);
            slot.retain(AttemptFailure::Kernel(std::io::Error::from_raw_os_error(
                13,
            )));
        }
        assert!(original.remaining().is_err());
        let slot = owner.attempt.lock().unwrap();
        assert_eq!(slot.end, Some(0));
        assert!(slot.post_expired);
        assert!(
            matches!(&slot.first, Some(AttemptFailure::Kernel(error)) if error.raw_os_error() == Some(13))
        );
    }

    #[test]
    fn completion_observes_same_pinned_counter_without_refunding_pair() {
        use std::io::Write as _;
        let owner = mechanism_owner();
        let pair = owner
            .metadata
            .reserve_paired_bytes(&owner.resident, 128)
            .unwrap();
        {
            let mut slot = owner.attempt.lock().unwrap();
            slot._pair = Some(HostServiceLeasePair::new(pair.1, pair.0));
            slot.before = Some(OriginalCpuCounters {
                usage_microseconds: 10,
                user_microseconds: 4,
                system_microseconds: 6,
            });
            slot.start = Some(super::super::monotonic_microseconds().unwrap());
            slot.end = Some(u64::MAX);
        }
        owner
            .birth
            .cpu
            .lock()
            .unwrap()
            .write_all(b"usage_usec 30\nuser_usec 12\nsystem_usec 18\n")
            .unwrap();
        let original = OriginalParentAttempt { owner };

        original.observe_after_physical_join().unwrap();

        assert_eq!(
            original.completed_observation().unwrap().0,
            OriginalCpuCounters {
                usage_microseconds: 20,
                user_microseconds: 8,
                system_microseconds: 12,
            }
        );
        assert!(owner.attempt.lock().unwrap()._pair.is_some());
        let retained_before = owner.resident.reserve_resources(0, 0, 4096).is_err();
        assert!(retained_before);
    }
}
