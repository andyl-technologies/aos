//! Retains Storage's loan of the original PID1 aggregate bootstrap envelope.
//!
//! The image policy and sealed delivery are DATA until rejoined with the
//! existing fixed Storage invocation and the live original PID1 producer.
//! This owner never creates a Project/Sandbox or native-effect reservation.
//! The aggregate was paid once by PID1 before jobs, socket activation and
//! startup capture; opening Storage does not charge the node again.

use std::fs::File;
use std::os::fd::OwnedFd;

use super::ResourceReservationErrorV1;
use super::bootstrap::{self, OriginalEnrollment};
use crate::normal_root::{
    NormalRootStartupErrorV1, StorageWorkerParentDataV3, observe_fixed_storage_resource_parent_v1,
};

type ParentObservation = Result<(StorageWorkerParentDataV3, [u8; 16]), NormalRootStartupErrorV1>;

/// Retains the same original pair assigned to the fixed Storage invocation.
///
/// Construction is restricted to Core's first complete inherited-table
/// capture. No caller file, resource vector, capsule or receipt creates it.
/// Failed admission retains its whole observations and both original files.
/// Loans borrow this owner, so its files cannot be disposed during a loan.
/// Ordinary descriptor disposal never refunds the shared bootstrap envelope
/// or reconstructs the once-only original PID1 recipient.
#[must_use]
pub struct StorageComponentEnvelopeOriginalV1 {
    policy: File,
    enrollment: File,
    process: u32,
    admission: Option<StorageComponentPostV1>,
    closed: bool,
}

impl StorageComponentEnvelopeOriginalV1 {
    pub(crate) fn from_original_table(policy: OwnedFd, enrollment: OwnedFd) -> Self {
        Self {
            policy: policy.into(),
            enrollment: enrollment.into(),
            process: std::process::id(),
            admission: None,
            closed: false,
        }
    }

    /// Admits the original recipient and complete aggregate bootstrap policy once.
    ///
    /// The outer startup reservoir parks this owner before calling this method.
    /// All independent observations are retained before any cause is selected.
    ///
    /// # Errors
    /// Borrows the earliest process, PID1, original file or policy refusal.
    /// A repeated call closes admission without observing or reopening files.
    pub fn admit_once(&mut self) -> Result<(), &(dyn std::error::Error + 'static)> {
        if self.admission.is_some() {
            self.closed = true;
        } else {
            self.admission = Some(self.observe());
        }
        self.require_admitted()
    }

    /// Borrows the paid pre-open envelope without detaching its producer owner.
    ///
    /// The loan covers only the configured aggregate bootstrap interval. It
    /// does not replace current Project ancestry or contacted native-suffix
    /// admission. The caller retains the loan and each whole independent post.
    ///
    /// # Errors
    /// Refuses absent, failed, repeated or foreign-process admission.
    pub fn borrow_preopen(
        &self,
    ) -> Result<StorageComponentEnvelopeLoanV1<'_>, &(dyn std::error::Error + 'static)> {
        self.require_admitted()?;
        Ok(StorageComponentEnvelopeLoanV1 { original: self })
    }

    fn require_admitted(&self) -> Result<(), &(dyn std::error::Error + 'static)> {
        let admission = self.admission.as_ref().ok_or(&CLOSED as &(dyn std::error::Error + 'static))?;
        admission.require_current()?;
        if self.closed || self.process != std::process::id() {
            return Err(&CLOSED);
        }
        Ok(())
    }

    fn observe(&self) -> StorageComponentPostV1 {
        // The pair stays held even when the first independent owner has debt.
        let before = observe_fixed_storage_resource_parent_v1();
        let original = bootstrap::observe_original_pair(&self.policy, &self.enrollment);
        let after = observe_fixed_storage_resource_parent_v1();
        let binding = (|| {
            let (before, before_producer) = before.as_ref()
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let original = original.as_ref()
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let (after, after_producer) = after.as_ref()
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            if self.process != std::process::id() || before != after
                || before_producer != after_producer
                || original.recipient_invocation != before.invocation()
                || original.identity.invocation != *before_producer
            {
                return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
            }
            if let Some(previous) = &self.admission {
                let previous = previous.original.as_ref()
                    .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
                if original != previous {
                    return Err(ResourceReservationErrorV1::Conflict);
                }
            }
            Ok(())
        })();
        StorageComponentPostV1 { before, original, after, binding }
    }
}

/// Borrows the original paid bootstrap owner across a pre-open crossing.
///
/// The loan is not clonable and has no release, refresh or refund operation.
/// It exposes neither the original descriptors nor a standalone paid vector.
#[must_use]
pub struct StorageComponentEnvelopeLoanV1<'original> {
    original: &'original StorageComponentEnvelopeOriginalV1,
}

impl StorageComponentEnvelopeLoanV1<'_> {
    /// Observes the same original recipient and files without replacing debt.
    ///
    /// The caller parks the entire returned post before projecting a failure
    /// and keeps this loan through its native outcome and independent posts.
    #[must_use]
    pub fn observe_current(&self) -> StorageComponentPostV1 {
        self.original.observe()
    }
}

/// Retains complete original observations at one paid bootstrap frontier.
///
/// A successful post is comparison DATA tied to the still-borrowed loan. It
/// cannot independently fund work or open a native protected boundary.
#[must_use]
pub struct StorageComponentPostV1 {
    before: ParentObservation,
    original: Result<OriginalEnrollment, ResourceReservationErrorV1>,
    after: ParentObservation,
    binding: Result<(), ResourceReservationErrorV1>,
}

impl StorageComponentPostV1 {
    /// Borrows the earliest cause in the fixed observation order.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.before.as_ref().err().map(|error| error as &(dyn std::error::Error + 'static))
            .or_else(|| self.original.as_ref().err().map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.after.as_ref().err().map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.binding.as_ref().err().map(|error| error as &(dyn std::error::Error + 'static)))
    }

    /// Requires all same-original bootstrap comparisons without copying errors.
    ///
    /// # Errors
    /// Borrows the first original refusal; later independent debt stays resident.
    pub fn require_current(&self) -> Result<(), &(dyn std::error::Error + 'static)> {
        match self.failure() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

static CLOSED: ResourceReservationErrorV1 = ResourceReservationErrorV1::EnrollmentUnavailable;
