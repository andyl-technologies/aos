//! Records controller return before independent original observations.

use super::*;
use crucible_engine::BackendOperationalCause;
use crucible_host_resources::host_supervision::HostSupervisionError;

/// Preserves controller-return failures separately from actual physical return.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
#[error("RAM controller return refused: {self:?}")]
pub struct RamControlRetirementHistory {
    /// Exact first provider error, retained through later physical closure.
    pub first: Option<BackendOperationalCause>,
    /// First saved-original boundary refusal before the return.
    pub before: Option<HostSupervisionError>,
    /// Independent saved-original refusal after the returned disposition.
    pub after: Option<HostSupervisionError>,
    /// Whether an entered return lacks a physical disposition.
    pub uncertain: bool,
}

/// Keeps one controller's bounded physical return and raw history.
#[derive(Debug)]
pub struct RamControlRetirementProgress {
    entered: bool,
    disposition: RamControlRetirementDisposition,
    history: RamControlRetirementHistory,
    version: u8,
    reported: u8,
}

impl Default for RamControlRetirementProgress {
    fn default() -> Self {
        Self::new()
    }
}

impl RamControlRetirementProgress {
    /// Constructs unentered return custody before the containing body is born.
    pub const fn new() -> Self {
        Self {
            entered: false,
            disposition: RamControlRetirementDisposition::NotReturned,
            history: RamControlRetirementHistory {
                first: None,
                before: None,
                after: None,
                uncertain: false,
            },
            version: 0,
            reported: 0,
        }
    }

    /// Retains an unavailable publication observation without returning custody.
    pub(crate) fn refuse_publication(
        &mut self,
        first: RamControlError,
    ) -> (bool, Result<(), RamControlRetirementHistory>) {
        if self.history.first.is_none() {
            self.history.first = Some(BackendOperationalCause::new(first));
            self.version += 1;
        }
        if !self.history.uncertain {
            self.history.uncertain = true;
            self.version += 1;
        }
        (false, Err(self.history.clone()))
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
    pub fn return_controller(
        &mut self,
        registration: &RamControlRegistration,
        original: Option<RamCleanupOriginal<'_>>,
    ) -> (bool, Result<(), RamControlRetirementHistory>) {
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
            self.history.first = Some(BackendOperationalCause::new(first));
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
            (returned, Err(self.history.clone()))
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
