//! Holds the selected original child through one retained process descriptor.
//!
//! Acquisition is private to the original birth reservation while it still owns
//! the unreaped `Child`. No other reaper receives that handle or waits for this
//! child. This is the same exclusive-parent invariant used by ordinary `Child`
//! custody, made explicit before replacing its retained implementation backing.
//! Later observation and reaping use only the retained descriptor, never a PID
//! lookup. This module grants no source, executable, namespace or group authority.

use std::{os::fd::OwnedFd, process::Child, thread::ThreadId};

use crucible_node_transport::ProviderError;

use super::{current::KernelIdentity, executable_guard::OriginalExecutable};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OriginalExit {
    Exited(u8),
    Signaled { signal: u8, core_dumped: bool },
}

impl OriginalExit {
    fn status(self) -> std::process::ExitStatus {
        use std::os::unix::process::ExitStatusExt;

        let raw = match self {
            Self::Exited(code) => i32::from(code) << 8,
            Self::Signaled {
                signal,
                core_dumped,
            } => i32::from(signal) | if core_dumped { 0x80 } else { 0 },
        };
        std::process::ExitStatus::from_raw(raw)
    }
}

pub(super) struct OriginalChild {
    descriptor: Option<OwnedFd>,
    process: u32,
    thread: ThreadId,
    exit: Option<OriginalExit>,
    failed: bool,
}

impl OriginalChild {
    /// Prepares a replacement while the birth reservation still owns `child`.
    ///
    /// The caller owns the same newly spawned, unreaped child exclusively. It
    /// retains that handle on every error and installs this result before
    /// dropping the old handle. No callback or cleanup worker runs in between.
    ///
    /// # Errors
    /// Refuses another original child, retained parent streams, unsupported
    /// descriptor acquisition, terminal birth or changed kernel/executable custody.
    pub(super) fn capture(
        child: &Child,
        original_pid: u32,
        identity: &KernelIdentity,
        executable: &OriginalExecutable,
    ) -> Result<Self, ProviderError> {
        Self::capture_with_checkpoint(child, original_pid, identity, executable, || Ok(()))
    }

    // The only production checkpoint is the closed no-op above. A private
    // refusal checkpoint lets controls verify ownership after actual fd acquisition.
    fn capture_with_checkpoint(
        child: &Child,
        original_pid: u32,
        identity: &KernelIdentity,
        executable: &OriginalExecutable,
        checkpoint: impl FnOnce() -> Result<(), ProviderError>,
    ) -> Result<Self, ProviderError> {
        executable.ensure_origin()?;
        if child.id() != original_pid
            || child.stdin.is_some()
            || child.stdout.is_some()
            || child.stderr.is_some()
        {
            return Err(ProviderError::Correlation(
                "selected original child identity or parent streams differ",
            ));
        }
        executable.ensure_kernel_current(identity)?;
        executable.ensure_current(identity)?;

        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsFd;

            use rustix::process::{Pid, PidfdFlags, WaitId, WaitIdOptions, pidfd_open, waitid};

            let pid = i32::try_from(child.id())
                .ok()
                .and_then(Pid::from_raw)
                .ok_or(ProviderError::Correlation(
                    "selected original child PID is invalid",
                ))?;
            // This acquisition is restricted to the still-owned original birth.
            // Exclusive parent reaping keeps its PID reserved even if it exits.
            let process = std::process::id();
            let thread = std::thread::current().id();
            let descriptor = pidfd_open(pid, PidfdFlags::empty()).map_err(std::io::Error::from)?;
            // The provisional owner also protects refusal paths: a copied
            // process leaks its duplicate rather than closing the parent's alias.
            let original = Self {
                descriptor: Some(descriptor),
                process,
                thread,
                exit: None,
                failed: false,
            };
            original.ensure_origin()?;
            let descriptor = original
                .descriptor
                .as_ref()
                .ok_or(ProviderError::Correlation(
                    "selected original descriptor is absent after acquisition",
                ))?;
            let terminal = waitid(
                WaitId::PidFd(descriptor.as_fd()),
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
            )
            .map_err(std::io::Error::from)?;
            if terminal.is_some() {
                return Err(ProviderError::Correlation(
                    "selected original child exited before descriptor transfer",
                ));
            }
            checkpoint()?;
            // Reuse all existing complete executable, kernel and namespace
            // checks before the caller may move or drop its original Child.
            executable.ensure_kernel_current(identity)?;
            executable.ensure_current(identity)?;
            executable.ensure_origin()?;
            original.ensure_origin()?;
            Ok(original)
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _checkpoint = checkpoint;
            Err(ProviderError::Correlation(
                "selected original process descriptors are unsupported on this platform",
            ))
        }
    }

    fn ensure_origin(&self) -> Result<(), ProviderError> {
        if self.process != std::process::id() {
            return Err(ProviderError::Correlation(
                "original child descriptor belongs to another process",
            ));
        }
        if self.thread != std::thread::current().id() {
            return Err(ProviderError::Correlation(
                "original child descriptor belongs to another thread",
            ));
        }
        Ok(())
    }

    /// Checks original, nonterminal descriptor custody without a kernel operation.
    ///
    /// # Errors
    /// Refuses foreign creators, completed reaping or unresolved descriptor waits.
    pub(super) fn ensure_unreaped(&self) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        if self.exit.is_some() || self.failed || self.descriptor.is_none() {
            return Err(ProviderError::Correlation(
                "original child descriptor is terminal or unresolved",
            ));
        }
        Ok(())
    }

    /// Observes the concrete inline owner without following its kernel object.
    ///
    /// # Errors
    /// Refuses another original process or creator thread.
    pub(super) fn retained_metadata_data(&self) -> Result<(), ProviderError> {
        self.ensure_origin()
    }

    /// Reaps once through the same descriptor and retains its typed terminal value.
    ///
    /// # Errors
    /// Refuses foreign creators, unsupported or unresolved descriptor state and
    /// unexpected kernel results. Interruptions retain the same pending descriptor.
    pub(super) fn try_wait(&mut self) -> Result<Option<std::process::ExitStatus>, ProviderError> {
        self.ensure_origin()?;
        if let Some(exit) = self.exit {
            return Ok(Some(exit.status()));
        }
        if self.failed {
            return Err(ProviderError::Correlation(
                "original child descriptor wait is unresolved",
            ));
        }

        let result = self.wait_once();
        match result {
            Ok(Some(exit)) => {
                self.exit = Some(exit);
                Ok(Some(exit.status()))
            }
            Ok(None) => Ok(None),
            Err(ProviderError::Io(error)) if error.kind() == std::io::ErrorKind::Interrupted => {
                // A later poll may retry this same retained descriptor. No
                // numeric reacquisition or successful reap is inferred.
                Err(ProviderError::Io(error))
            }
            Err(error) => {
                // ECHILD and every other failed descriptor observation are not
                // a reap receipt. Keep custody and never retry by numeric PID.
                self.failed = true;
                Err(error)
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn wait_once(&self) -> Result<Option<OriginalExit>, ProviderError> {
        use std::os::fd::AsFd;

        use rustix::process::{WaitId, WaitIdOptions, waitid};

        let descriptor = self.descriptor.as_ref().ok_or(ProviderError::Correlation(
            "original child descriptor was transferred",
        ))?;
        let Some(status) = waitid(
            WaitId::PidFd(descriptor.as_fd()),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG,
        )
        .map_err(std::io::Error::from)?
        else {
            return Ok(None);
        };
        let exit =
            if let Some(code) = status.exit_status() {
                OriginalExit::Exited(u8::try_from(code).map_err(|_| {
                    ProviderError::Correlation("original child exit code is invalid")
                })?)
            } else if let Some(signal) = status.terminating_signal() {
                let signal = u8::try_from(signal)
                    .ok()
                    .filter(|signal| *signal > 0 && *signal < 128)
                    .ok_or(ProviderError::Correlation(
                        "original child terminating signal is invalid",
                    ))?;
                OriginalExit::Signaled {
                    signal,
                    core_dumped: status.dumped(),
                }
            } else {
                return Err(ProviderError::Correlation(
                    "original child wait returned a nonterminal status",
                ));
            };
        Ok(Some(exit))
    }

    #[cfg(not(target_os = "linux"))]
    fn wait_once(&self) -> Result<Option<OriginalExit>, ProviderError> {
        Err(ProviderError::Correlation(
            "selected original process descriptors are unsupported on this platform",
        ))
    }
}

impl Drop for OriginalChild {
    fn drop(&mut self) {
        if self.ensure_origin().is_err() {
            // A copied foreign owner cannot close a descriptor or reap on behalf
            // of its parent. The original parent retains its actual descriptor.
            std::mem::forget(self.descriptor.take());
        }
    }
}

#[cfg(test)]
mod tests;

impl OriginalChild {
    pub(super) fn retained_descriptor_views_precredit_data(
        &self,
    ) -> Result<usize, crate::node_contract::RuntimeError> {
        use crate::node_contract::RuntimeError;
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        Ok(usize::from(self.descriptor.is_some()))
    }
}
