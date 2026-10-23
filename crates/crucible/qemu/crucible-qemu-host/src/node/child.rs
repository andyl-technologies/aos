//! Construction, natural waits and terminal cleanup for one owned child.
//!
//! The declaration remains in the parent so sibling owners keep its field scope.

use super::*;

impl QemuNodeChild {
    /// Wraps a fixture process with the same unique wait authority as QEMU.
    ///
    /// This constructor is available only with the `test-support` feature.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub const fn from_test_process(child: Child) -> Self {
        Self::new(child)
    }

    /// Takes ownership of a spawned QEMU child process.
    #[must_use]
    // crucible-lint: allow rust-allow -- non-Linux builds do not construct child wrappers in this target.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) const fn new(child: Child) -> Self {
        Self {
            child: source_child::OwnedNodeChild::Ordinary(child),
            reaped: false,
            #[cfg(target_os = "linux")]
            ram_source: None,
            #[cfg(target_os = "linux")]
            ram_source_start: None,
            #[cfg(target_os = "linux")]
            launch_cleanup: None,
            #[cfg(target_os = "linux")]
            original_plugin_startup: None,
            #[cfg(target_os = "linux")]
            preexec_setup: None,
            #[cfg(target_os = "linux")]
            checkpoint_original: None,
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn from_authenticated_source(
        child: crucible_host_resources::host_services::process_birth::AuthenticatedSourceChild,
    ) -> Self {
        Self {
            child: source_child::OwnedNodeChild::Source(child),
            reaped: false,
            ram_source: None,
            #[cfg(target_os = "linux")]
            ram_source_start: None,
            launch_cleanup: None,
            original_plugin_startup: None,
            preexec_setup: None,
            checkpoint_original: None,
        }
    }

    pub(crate) fn take_guarded_probe_pipes(
        &mut self,
    ) -> Result<
        (
            std::process::ChildStdin,
            std::process::ChildStdout,
            std::process::ChildStderr,
        ),
        crate::QemuSpawnError,
    > {
        let source_child::OwnedNodeChild::Ordinary(child) = &mut self.child else {
            return Err(crate::spawn::helper_receiver::helper_custody_refusal());
        };
        let missing = |operation| crate::QemuSpawnError::Io {
            operation,
            source: std::io::Error::other("configured pipe was unavailable"),
        };
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| missing("open guarded QEMU probe stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| missing("open guarded QEMU probe stdout"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| missing("open guarded QEMU probe stderr"))?;
        Ok((stdin, stdout, stderr))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn retain_launch_cleanup(&mut self, cleanup: crate::launch_cleanup::LaunchCleanup) {
        cleanup.child_started();
        self.launch_cleanup = Some(cleanup);
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn retain_preexec_setup(
        &mut self,
        owner: crate::spawn::preexec_setup::PreparedPreexecSetup,
    ) {
        self.preexec_setup = Some(owner);
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn retain_original_plugin_startup(
        &mut self,
        startup: crate::spawn::OriginalPluginStartup,
    ) {
        self.original_plugin_startup = Some(startup);
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn standing_source_supervision(
        &self,
    ) -> Result<
        Option<crate::spawn::source_supervision::OriginalSourceSupervision>,
        crate::spawn::PluginStartupError,
    > {
        self.original_plugin_startup
            .as_ref()
            .map(|startup| startup.standing().cloned())
            .transpose()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn complete_original_plugin_startup(
        &self,
    ) -> Result<(), crucible_host_resources::host_supervision::HostSupervisionError> {
        if let Some(startup) = &self.original_plugin_startup {
            startup.complete()?;
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn device_digest_workspace_setup_view(
        &self,
    ) -> Result<
        Option<std::sync::Arc<crate::spawn::DeviceDigestWorkspaceBody>>,
        crate::spawn::PluginStartupError,
    > {
        self.original_plugin_startup
            .as_ref()
            .map(crate::spawn::OriginalPluginStartup::workspace_view)
            .transpose()
            .map(Option::flatten)
    }

    pub(super) fn mark_reaped(&mut self) {
        self.reaped = true;
        #[cfg(target_os = "linux")]
        if let Some(original) = self.checkpoint_original.as_mut() {
            original.retire_after_reap();
        }
        #[cfg(target_os = "linux")]
        if let Some(startup) = self.original_plugin_startup.as_mut() {
            startup.retire_workspace_after_reap();
        }
        #[cfg(target_os = "linux")]
        if let Some(cleanup) = &self.launch_cleanup {
            cleanup.child_reaped();
        }
    }

    #[cfg(target_os = "linux")]
    pub(super) fn check_ram_source(&self) -> Result<(), crate::ram_source::QemuRamSourceError> {
        if let Some(source) = &self.ram_source {
            source.check_health()?;
        }
        Ok(())
    }

    /// Returns whether the owned child has been reaped by this wrapper.
    #[must_use]
    pub const fn reaped(&self) -> bool {
        self.reaped
    }

    /// Returns the operating-system process identifier of the owned child.
    #[must_use]
    pub fn process_id(&self) -> u32 {
        self.child.id()
    }

    /// Polls for a natural child exit without sending a signal.
    ///
    /// A returned status is the exact `waitpid` result and marks this wrapper
    /// reaped, so dropping it cannot hide the outcome with kill-and-wait
    /// cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`QemuShutdownTargetError`] when the child was already reaped or
    /// the nonblocking wait fails.
    pub fn try_wait_natural_exit(
        &mut self,
    ) -> Result<Option<std::process::ExitStatus>, QemuShutdownTargetError> {
        self.try_wait_natural_exit_raw()
            .map_err(ChildNaturalWaitFailure::into_shutdown_error)
    }

    /// Polls the same owned child without formatting or replacing its I/O error.
    ///
    /// # Errors
    /// Refuses a previously reaped child or returns the actual wait error.
    pub(crate) fn try_wait_natural_exit_raw(
        &mut self,
    ) -> Result<Option<std::process::ExitStatus>, ChildNaturalWaitFailure> {
        if self.reaped {
            return Err(ChildNaturalWaitFailure::AlreadyReaped);
        }
        match self.child.try_wait() {
            Ok(Some(status)) => {
                self.mark_reaped();
                Ok(Some(status))
            }
            Ok(None) => Ok(None),
            Err(source) => Err(ChildNaturalWaitFailure::Io(source)),
        }
    }

    pub(super) fn send_sigterm(&mut self) -> Result<(), QemuShutdownTargetError> {
        signal_child(self.child.id(), libc::SIGTERM, "send SIGTERM")
    }

    pub(super) fn send_sigkill(&mut self) -> Result<(), QemuShutdownTargetError> {
        signal_child(self.child.id(), libc::SIGKILL, "send SIGKILL")
    }

    pub(super) fn wait_for_exit(
        &mut self,
        _rung: QemuShutdownRung,
        timeout: Duration,
    ) -> Result<QemuChildWait, QemuShutdownTargetError> {
        let state = wait_child(&mut self.child, timeout)?;
        if state == QemuChildWait::Exited {
            self.mark_reaped();
        }
        Ok(state)
    }

    pub(super) fn reap(&mut self, timeout: Duration) -> Result<QemuReap, QemuShutdownTargetError> {
        if self.reaped {
            return Ok(QemuReap::Reaped);
        }

        match wait_child(&mut self.child, timeout)? {
            QemuChildWait::Exited => {
                self.mark_reaped();
                Ok(QemuReap::Reaped)
            }
            QemuChildWait::StillRunning => Ok(QemuReap::StillAlive),
        }
    }

    /// Performs one actual SIGKILL and nonblocking reap observation.
    ///
    /// The component test retains the actual child until reap. This method
    /// creates no operation or independent wait deadline.
    ///
    /// # Errors
    /// Returns an actual signal or nonblocking wait failure; exit alone never
    /// substitutes for the successful reap observation.
    #[cfg(all(test, feature = "private-measurement-domain"))]
    pub(crate) fn kill_and_poll_reap(&mut self) -> Result<bool, QemuShutdownTargetError> {
        if self.reaped {
            return Ok(true);
        }
        let killed = self.child.kill();
        match self.child.try_wait() {
            Ok(Some(_)) => {
                self.mark_reaped();
                Ok(true)
            }
            Ok(None) => {
                killed.map_err(|source| {
                    QemuShutdownTargetError::new("kill stopped QEMU child", source.to_string())
                })?;
                Ok(false)
            }
            Err(source) => Err(QemuShutdownTargetError::new(
                "poll stopped QEMU child reap",
                source.to_string(),
            )),
        }
    }

    /// Force-kills and synchronously reaps a failed fresh realization.
    ///
    /// This failure-only path deliberately has no reap timeout: returning an
    /// assembly error while abandoning this process would leave a live child or
    /// zombie owned by the long-running host. Ordinary node shutdown remains
    /// bounded by [`QemuShutdownPolicy`].
    pub(crate) fn force_kill_and_reap_failed_realization(
        &mut self,
    ) -> Result<(), QemuShutdownTargetError> {
        if self.reaped {
            return Ok(());
        }
        // A kill error can mean the child exited between the factory failure
        // and this call. Waiting is still mandatory and decides whether the
        // child was actually reaped.
        let _kill_result = self.child.kill();
        self.child.wait().map_err(|error| {
            QemuShutdownTargetError::new("reap failed QEMU realization", error.to_string())
        })?;
        self.mark_reaped();
        Ok(())
    }

    /// Force-kills and boundedly reaps one failed attempt helper process.
    ///
    /// A timeout deliberately leaves this wrapper unreaped so the caller can
    /// transfer its unique direct-child wait authority into the attempt owner.
    /// Repeated calls retry cleanup with that same authority; successful reap
    /// makes subsequent calls no-ops.
    ///
    /// # Errors
    ///
    /// Returns [`QemuShutdownTargetError`] if waiting fails or the original
    /// child remains alive after the bounded wait. The caller must retain this
    /// wrapper and its attempt resource enforcement until cleanup succeeds.
    pub fn force_kill_and_reap_failed_helper(
        &mut self,
        timeout: Duration,
    ) -> Result<(), QemuShutdownTargetError> {
        if self.reaped {
            return Ok(());
        }
        let _kill_result = self.child.kill();
        match wait_child(&mut self.child, timeout)? {
            QemuChildWait::Exited => {
                self.mark_reaped();
                Ok(())
            }
            QemuChildWait::StillRunning => Err(QemuShutdownTargetError::new(
                "reap failed QEMU helper",
                "child remained alive after SIGKILL and the bounded wait",
            )),
        }
    }
}

impl Drop for QemuNodeChild {
    fn drop(&mut self) {
        // Force-kill (SIGKILL) and reap within a hard deadline. A blocking
        // `wait()` here would hang teardown indefinitely on a wedged child;
        // `wait_child` polls non-blockingly up to `DROP_REAP_DEADLINE` and then
        // abandons. `reaped` stays false on abandonment so the wrapper never
        // claims a reap it did not observe; the process was already SIGKILL'd,
        // so the OS reaps the zombie once it leaves any uninterruptible section.
        // The destructor has no error channel and this crate's lint bans direct
        // stderr diagnostics, so an abandonment is intentionally silent.
        if !self.reaped {
            let _ = self.child.kill();
            if let Ok(QemuChildWait::Exited) = wait_child(&mut self.child, DROP_REAP_DEADLINE) {
                self.mark_reaped();
            }
        }
        #[cfg(target_os = "linux")]
        if !self.reaped {
            if let Some(cleanup) = &self.launch_cleanup {
                cleanup.quarantine();
            }
            // A destructor cannot transfer quarantine ownership. Keep the
            // immutable backing alive rather than revoke pages from an
            // indeterminate process after the bounded fallback expires.
            if let Some(source) = self.ram_source.take() {
                source.retain_for_unreaped_receiver();
            }
            if let Some(owner) = self.preexec_setup.take() {
                // Close local aliases while the preborn recipient retains the
                // uncertain receiver's exact handover history and original loan.
                drop(owner);
            }
            if let Some(startup) = self.original_plugin_startup.take() {
                // An uncertain child may still borrow the original operation
                // and event role; retain its account through containment.
                std::mem::forget(startup);
            }
        }
    }
}
