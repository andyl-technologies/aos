//! Records controller return before independent original observations.
//!
//! Each canonical progress owner takes the launch's prepaid cause storage before
//! observing publication or entering its provider. Erased failures retain the
//! independent accounting finalizer without linking that storage back to the
//! launch, including when the actual provider error itself retains the launch.

use super::*;
use crate::launch_cleanup::LaunchCleanup;
use crucible_host_resources::host_supervision::HostSupervisionError;

pub use crate::launch_cleanup::{RamControlRetirementHistory, RamControlRetirementRecord};
use crate::launch_cleanup::ControllerReturnJournal;

/// Keeps one controller's bounded physical return and raw history.
#[derive(Debug)]
pub struct RamControlRetirementProgress {
    cleanup: Option<LaunchCleanup>,
    cause: Option<
        crucible_engine::SharedOperationalCause<crate::launch_cleanup::ControllerReturnCause>,
    >,
    journal: ControllerReturnJournal,
    entered: bool,
    disposition: RamControlRetirementDisposition,
    history: RamControlRetirementRecord,
    version: u8,
    reported: u8,
}

impl Default for RamControlRetirementProgress {
    fn default() -> Self {
        Self::new()
    }
}

impl RamControlRetirementProgress {
    /// Constructs unbound progress without admitting a controller return.
    ///
    /// The launch owner must bind its prepaid storage before any publication
    /// observation or provider entry. [`Self::for_launch`] prepares public callers.
    pub const fn new() -> Self {
        Self {
            cleanup: None,
            cause: None,
            journal: ControllerReturnJournal::empty(),
            entered: false,
            disposition: RamControlRetirementDisposition::NotReturned,
            history: RamControlRetirementRecord {
                first: None,
                before: None,
                after: None,
                uncertain: false,
            },
            version: 0,
            reported: 0,
        }
    }

    /// Binds one progress owner to an already constructed launch allocation.
    ///
    /// Construction allocates nothing and grants no physical return. The launch
    /// must have admitted its complete control peak before creating its custody.
    ///
    /// # Errors
    /// Refuses a launch whose canonical controller progress was already claimed.
    pub fn for_launch(custody: &crate::QemuRamLaunchCustody) -> Result<Self, RamControlError> {
        let mut progress = Self::new();
        if !progress.bind(&custody.cleanup) {
            return Err(RamControlError::AuthorityMismatch);
        }
        Ok(progress)
    }

    pub(crate) fn bind(&mut self, cleanup: &LaunchCleanup) -> bool {
        if let Some(retained) = &self.cleanup {
            return retained.same_return_owner(cleanup);
        }
        let Some(storage) = cleanup.claim_controller_return() else {
            return false;
        };
        self.cause = Some(storage.cause);
        self.journal = storage.journal;
        self.cleanup = Some(cleanup.clone());
        true
    }

    pub(crate) const fn unavailable() -> RamControlRetirementHistory {
        RamControlRetirementHistory::unavailable()
    }

    /// Retains an unavailable publication observation without returning custody.
    pub(crate) fn refuse_publication(
        &mut self,
        first: RamControlError,
    ) -> (bool, Result<(), RamControlRetirementHistory>) {
        let Some(cause) = &self.cause else {
            return (false, Err(Self::unavailable()));
        };
        if self.history.first.is_none() {
            cause.source_ref().retain(first);
            self.history.first = Some(cause.backend_cause());
            self.version += 1;
        }
        if !self.history.uncertain {
            self.history.uncertain = true;
            self.version += 1;
        }
        (false, Err(self.journal.snapshot(&self.history)))
    }

    /// Returns the same controller without renewing or completing its Original.
    ///
    /// The caller has already proved the actual child and source return. This
    /// disposes owned custody rather than admitting new guest work, so expired
    /// boundary observations do not undo or prohibit this physical return.
    ///
    /// # Errors
    /// The status retains provider and independent boundary failures. Unknown
    /// effects are never replayed; a successful return is saved before post.
    /// Unprepared progress and a registration from another launch fail closed
    /// before entering the provider.
    pub fn return_controller(
        &mut self,
        registration: &RamControlRegistration,
        original: Option<RamCleanupOriginal<'_>>,
    ) -> (bool, Result<(), RamControlRetirementHistory>) {
        let prepared = self
            .cleanup
            .as_ref()
            .is_some_and(|cleanup| cleanup.matches_return_registration(registration));
        let Some(cause) = self.cause.as_ref().filter(|_| prepared) else {
            return (false, Err(Self::unavailable()));
        };
        if self.disposition == RamControlRetirementDisposition::Returned {
            return self.observation();
        }
        if self.entered && self.disposition == RamControlRetirementDisposition::Unknown {
            if !self.history.uncertain {
                self.history.uncertain = true;
                self.version += 1;
            }
            return self.observation();
        }
        let before = check(original).err();
        if self.history.before.is_none() && before.is_some() {
            self.history.before = before;
            self.version += 1;
        }
        self.entered = true;
        self.disposition = RamControlRetirementDisposition::Unknown;
        let returned = registration
            .registrar
            .prepare_retirement_after_cleanup(registration.target);
        self.disposition = returned.disposition;
        if self.history.first.is_none()
            && let Some(first) = returned.failure
        {
            cause.source_ref().retain(first);
            self.history.first = Some(cause.backend_cause());
            self.version += 1;
        }
        if returned.disposition == RamControlRetirementDisposition::Unknown {
            self.history.uncertain = true;
            self.version += 1;
        }
        // Preserve the provider's actual physical output before this check.
        let after = check(original).err();
        if self.history.after.is_none() && after.is_some() {
            self.history.after = after;
            self.version += 1;
        }
        self.observation()
    }

    fn observation(&mut self) -> (bool, Result<(), RamControlRetirementHistory>) {
        let returned = self.disposition == RamControlRetirementDisposition::Returned;
        let failed = self.history.first.is_some()
            || self.history.before.is_some()
            || self.history.after.is_some()
            || self.history.uncertain;
        if failed && (!returned || self.version != self.reported) {
            self.reported = self.version;
            (returned, Err(self.journal.snapshot(&self.history)))
        } else {
            (returned, Ok(()))
        }
    }
}

fn check(original: Option<RamCleanupOriginal<'_>>) -> Result<(), HostSupervisionError> {
    let original = original.ok_or(HostSupervisionError::Unavailable)?;
    original.verify()
}

#[cfg(test)]
mod tests;
