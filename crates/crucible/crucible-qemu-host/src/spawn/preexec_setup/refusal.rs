//! Keeps a pre-exec refusal in the launch's original prepaid allocation.
//!
//! The small public error borrows its unchanged cause from a single-publication
//! record. Its destructor closes the actual local owner outside the owner mutex.
//! Unknown receiver retirement retains this same record through abandonment;
//! ordinary final destruction closes diagnostics before containing credit returns.
// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::fmt;
use std::sync::Mutex;

use super::{HostSupervisionError, PreexecSetupCause, PreparedPreexecSetup, SourceHostControlLease};
use crate::launch_cleanup::LaunchCleanup;

/// Preserves the actual first cause, independent postcut and prepaid local owner.
#[derive(Debug)]
pub(crate) struct PreexecFailureRecord {
    /// Preserves the initiating refusal independently of the final postcut.
    pub(super) cause: PreexecSetupCause,
    /// Preserves the same original operation's separately observed postcut.
    pub(super) original_after: Option<HostSupervisionError>,
    owner: Mutex<Option<PreparedPreexecSetup>>,
    // The complete diagnostic and local owner close before this original loan.
    _control: Option<SourceHostControlLease>,
}

/// Retains the same immutable cause after uncertain descriptor retirement.
#[derive(Debug)]
pub(super) struct PreexecFailureHistory {
    cleanup: LaunchCleanup,
}

impl PreexecFailureHistory {
    /// Borrows the physically retained failure; the linear publisher ran first.
    ///
    /// # Panics
    /// Panics if an internal caller constructs history before publication.
    pub(super) fn record(&self) -> &PreexecFailureRecord {
        match self.cleanup.preexec_failure() {
            Some(record) => record,
            None => unreachable!("failure history follows its sole publication"),
        }
    }
}

/// Retains prepared physical owners with the first cause and independent postcut.
///
/// The error uses storage admitted before pre-exec work. Formatting and source
/// inspection borrow the actual cause without allocating a replacement owner.
pub struct PreexecSetupError {
    // None denotes the actual failed linear-recipient claim before local work.
    history: Option<PreexecFailureHistory>,
}

impl PreexecSetupError {
    /// Reports a consumed linear recipient before any new local work begins.
    pub(super) fn recipient_unavailable() -> Self {
        Self { history: None }
    }

    /// Publishes only after the owner's unique pre-exec recipient was claimed.
    ///
    /// # Panics
    /// Panics if an internal caller supplies an owner without its original launch.
    pub(super) fn retain(
        mut owner: PreparedPreexecSetup,
        cause: PreexecSetupCause,
        original_after: Option<HostSupervisionError>,
    ) -> Self {
        let cleanup = match &owner.cleanup {
            Some(cleanup) => cleanup.clone(),
            None => unreachable!("prepared pre-exec work retains its containing launch"),
        };
        let control = owner.control.take();
        owner.failure = Some(PreexecFailureHistory {
            cleanup: cleanup.clone(),
        });

        // The unique PreparedPreexecSetup consumes itself on its first refusal.
        // No observer can publish again or lock the actual local owner.
        cleanup.retain_preexec_failure(PreexecFailureRecord {
            cause,
            original_after,
            owner: Mutex::new(Some(owner)),
            _control: control,
        });
        Self {
            history: Some(PreexecFailureHistory { cleanup }),
        }
    }
}

impl fmt::Display for PreexecSetupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(history) = &self.history {
            let record = history.record();
            write!(
                formatter,
                "pre-exec handover refused: {}; original: {:?}",
                record.cause, record.original_after
            )
        } else {
            formatter.write_str("pre-exec handover refused: the original recipient is unavailable")
        }
    }
}

impl fmt::Debug for PreexecSetupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("PreexecSetupError");
        if let Some(history) = &self.history {
            let record = history.record();
            debug
                .field("cause", &record.cause)
                .field("original_after", &record.original_after);
        } else {
            debug.field("recipient_unavailable", &true);
        }
        debug.finish_non_exhaustive()
    }
}

impl Error for PreexecSetupError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.history
            .as_ref()
            .map(|history| &history.record().cause as &(dyn Error + 'static))
    }
}

impl Drop for PreexecSetupError {
    fn drop(&mut self) {
        if let Some(history) = &self.history {
            let owner = match history.record().owner.lock() {
                Ok(mut owner) => owner.take(),
                Err(poisoned) => poisoned.into_inner().take(),
            };
            // Alias closes and abandonment publication cannot run under a lock.
            // The cause and original control stay in this same funded record.
            drop(owner);
        }
    }
}
