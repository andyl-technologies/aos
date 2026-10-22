//! Preserves typed module failures separately from report and body lifetimes.
//!
//! The same inline state is used by actual entered callbacks and the final
//! destruction preflight. Its receipt is negative health only: it neither owns
//! a destroyed control nor supplies physical return or operation authority.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;

/// Keeps failed health after its actual payload/body has been disposed.
#[derive(Clone, Copy, Default)]
pub(super) struct ModuleHealth {
    failed: bool,
}

impl ModuleHealth {
    pub(super) const fn failed(self) -> bool {
        self.failed
    }

    /// Reports permanent negative module health without retaining a dead body.
    ///
    /// # Errors
    /// Returns only the saved module-failure receipt; success grants no custody.
    pub(super) fn check(self) -> Result<(), Error> {
        if self.failed {
            Err(Error::ModuleHealth)
        } else {
            Ok(())
        }
    }
}

#[derive(Default)]
pub(super) struct History {
    pub(super) ready_status: Option<i32>,
    pub(super) module_health: ModuleHealth,
    pub(super) creation: Option<i32>,
    pub(super) transfer: Option<i32>,
    pub(super) handoff: Option<i32>,
    pub(super) handoff_moved: bool,
    pub(super) handoff_commit: Option<i32>,
    pub(super) close: Option<i32>,
    pub(super) join: Option<i32>,
    pub(super) observation: Option<i32>,
    pub(super) identity_return: Option<i32>,
    pub(super) snapshot: Option<abi::Status>,
    pub(super) installation_post: Option<crate::StartupSourceError>,
    pub(super) handoff_post: Option<crate::StartupSourceError>,
    pub(super) constructor_panic: Option<Box<dyn Any + Send>>,
}

impl History {
    pub(super) fn receipt(&self) -> Receipt {
        Receipt {
            ready_status: self.ready_status,
            module_failed: self.module_health.failed(),
            creation: self.creation,
            transfer: self.transfer,
            handoff: self.handoff,
            handoff_moved: self.handoff_moved,
            handoff_commit: self.handoff_commit,
            close: self.close,
            join: self.join,
            observation: self.observation,
            identity_return: self.identity_return,
            native: self.snapshot,
            installation_post: self.installation_post,
            handoff_post: self.handoff_post,
            constructor_panicked: self.constructor_panic.is_some(),
        }
    }

    /// Keeps health sticky even after actual identity consumption permits cleanup.
    ///
    /// # Errors
    /// Preserves Native/Original primary errors and the independent module fact.
    pub(super) fn health(&self) -> Result<(), Error> {
        if let Some(journal) = self.snapshot {
            let statuses = [
                journal.first_status,
                journal.post_status,
                journal.control_status,
                journal.control_lifetime_status,
                journal.destructor_status,
                journal.destruction_first_status,
                journal.funding_status,
                journal.task_return_status,
                journal.stack_retire_status,
                journal.handoff_status,
                journal.handoff_post_status,
                journal.close_status,
                journal.close_post_status,
                journal.transfer_post_status,
                journal.join_post_status,
                journal.destruction_post_status,
                journal.unmap_post_status,
                journal.mask_restore_status,
                journal.attr_destroy_status,
            ];
            if let Some(status) = statuses.into_iter().find(|status| *status != 0) {
                return native_status("retained native health", status);
            }
            // A canceled parked entry is actual closure, not an attempted read.
            if journal.entry_status != 0
                && !(journal.entry_status == -libc::ECANCELED && journal.closing == 1)
            {
                return native_status("entered worker result", journal.entry_status);
            }
        }
        if let Some(source) = self.installation_post.or(self.handoff_post) {
            return Err(Error::Original { source });
        }
        self.module_health.check()
    }
}

/// Distinguishes the one owning report from subsequent factual observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TerminalReport {
    Healthy,
    FirstFailure,
    ReportedFailure,
}

#[derive(Default)]
pub(super) struct State {
    pub(super) first: Option<FailureKind>,
    pub(super) registration: Option<crate::ram_error::RamError>,
    pub(super) read: Option<crate::PluginTeardownError>,
    pub(super) teardown: Option<crate::PluginTeardownError>,
    pub(super) ownership: Option<&'static str>,
    pub(super) interruption_error: Option<crate::StartupSourceError>,
    pub(super) native: [Option<i32>; 4],
    pub(super) entry_panic: Option<Box<dyn Any + Send>>,
    pub(super) control_panic: Option<Box<dyn Any + Send>>,
    pub(super) close_panic: Option<Box<dyn Any + Send>>,
    pub(super) handoff_panic: Option<Box<dyn Any + Send>>,
    pub(super) interruption: Option<RuntimeInterruptReceipt>,
    pub(super) read_attempted: bool,
    pub(super) handoff_attempted: bool,
    pub(super) handoff_committed_status: Option<i32>,
    pub(super) report_issued: bool,
}

impl State {
    pub(super) fn refuse(&mut self, cause: Cause) {
        let kind = match cause {
            Cause::Registration(error) => {
                self.registration.get_or_insert(error);
                FailureKind::Registration
            }
            Cause::Read(error) => {
                self.read.get_or_insert(error);
                FailureKind::Read
            }
            Cause::Teardown(error) => {
                self.teardown.get_or_insert(error);
                FailureKind::Teardown
            }
            Cause::Native { cut, status } => {
                self.native[cut as usize].get_or_insert(status);
                FailureKind::Native
            }
            Cause::Ownership(reason) => {
                self.ownership.get_or_insert(reason);
                FailureKind::Ownership
            }
            Cause::Interruption(error) => {
                self.interruption_error.get_or_insert(error);
                FailureKind::Interruption
            }
            Cause::Panic => FailureKind::Panic,
        };
        self.first.get_or_insert(kind);
    }

    /// Saves the permanent receipt before an owning output or Native post.
    pub(super) fn terminal_report(&mut self, receipt: &mut ModuleHealth) -> TerminalReport {
        if self.first.is_none() {
            return TerminalReport::Healthy;
        }
        receipt.failed = true;
        if self.report_issued {
            TerminalReport::ReportedFailure
        } else {
            self.report_issued = true;
            TerminalReport::FirstFailure
        }
    }

    /// Refuses an error born after an earlier terminal check before actual Drop.
    pub(super) fn destruction_ready(&self) -> bool {
        self.first.is_none() || self.report_issued
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_qemu_protocol::ControlLifecycleState;

    fn read_failure() -> crate::PluginTeardownError {
        crate::PluginTeardownError::HostQuitNotObserved {
            state: ControlLifecycleState::RunningViaSharedMemory,
        }
    }

    #[test]
    fn module_failure_survives_report_payload_and_body_lifetimes() {
        let mut module = State::default();
        let mut owner = History::default();
        // Copied zero status is only an input to this negative classifier; it
        // is never supplied to a Native birth, current or physical return API.
        owner.snapshot = Some(abi::Status::default());
        let cause = read_failure();
        module.refuse(Cause::Read(cause.clone()));
        assert_eq!(module.read.as_ref(), Some(&cause));
        assert!(!module.destruction_ready());

        assert_eq!(
            module.terminal_report(&mut owner.module_health),
            TerminalReport::FirstFailure
        );
        assert_eq!(
            module.terminal_report(&mut owner.module_health),
            TerminalReport::ReportedFailure
        );
        assert!(module.destruction_ready());
        // The copied journal has no Native failure to mask a lost module error.
        assert_eq!(owner.snapshot.map(|value| value.first_status), Some(0));
        assert_eq!(owner.snapshot.map(|value| value.entry_status), Some(0));
        // Only the local journal/body is disposed here. This test issues no
        // Native owner, frame, thread, Source role or physical-return fact.
        drop(module);

        assert!(matches!(owner.health(), Err(Error::ModuleHealth)));
        assert!(owner.module_health.failed());
    }

    #[test]
    fn failure_after_healthy_check_blocks_drop_until_the_next_actual_report() {
        let mut module = State::default();
        let mut owner = History::default();
        // Copied zero status is only an input to this negative classifier; it
        // is never supplied to a Native birth, current or physical return API.
        owner.snapshot = Some(abi::Status::default());
        assert_eq!(
            module.terminal_report(&mut owner.module_health),
            TerminalReport::Healthy
        );
        assert!(module.destruction_ready());
        assert!(owner.health().is_ok());

        let cause = read_failure();
        module.refuse(Cause::Read(cause.clone()));
        assert!(!module.destruction_ready());
        assert_eq!(module.read.as_ref(), Some(&cause));
        assert!(
            !owner.module_health.failed(),
            "the earlier check cannot observe a future failure"
        );

        assert_eq!(
            module.terminal_report(&mut owner.module_health),
            TerminalReport::FirstFailure
        );
        assert!(module.destruction_ready());
        drop(module);
        assert!(matches!(owner.health(), Err(Error::ModuleHealth)));
    }
}
