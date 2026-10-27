//! Reports opt-in test phases using the operation's actual injected clock.
//!
//! Observations add no storage operation, exclusion or publication authority.
//! Their local scope origins never change the original request deadline.
//!
//! `TERRANE_REF_PHASE_TRACE=stages` omits native traces and scopes starting at
//! `ordinary-record-start`, `payload-namespace-start` or
//! `content-get-exclusion-submitted`. Retained phases append a separate process
//! clock observation; injected clock fields and deadline inputs remain unchanged.
//! Other present values retain verbose tracing, and absence disables tracing.

use crate::store::Clock;
use std::time::Duration;

/// Reports opt-in native test phases without supplying publication authority.
pub(crate) struct PhaseTrace<'a, C: Clock> {
    clock: &'a C,
    reference: String,
    candidate: Option<terrane_format::identity::Digest>,
    started: Duration,
    last: Duration,
    enabled: bool,
    stages_only: bool,
}

impl<'a, C: Clock> PhaseTrace<'a, C> {
    /// Starts an opt-in observation from the supplied injected clock.
    ///
    /// # Panics
    /// Panics if enabled diagnostics cannot write to standard error.
    pub(crate) fn new(
        clock: &'a C,
        reference: &str,
        candidate: Option<terrane_format::identity::Digest>,
        started: Option<Duration>,
        phase: &str,
    ) -> Self {
        let setting = std::env::var_os("TERRANE_REF_PHASE_TRACE");
        let stages_only = setting.as_deref() == Some(std::ffi::OsStr::new("stages"));
        let enabled = setting.is_some()
            && !(stages_only
                && matches!(
                    phase,
                    "ordinary-record-start"
                        | "payload-namespace-start"
                        | "content-get-exclusion-submitted"
                ));
        let now = if enabled {
            clock.monotonic()
        } else {
            Duration::ZERO
        };
        let mut trace = Self {
            clock,
            reference: reference.to_owned(),
            candidate,
            started: started.unwrap_or(now),
            last: now,
            enabled,
            stages_only,
        };
        trace.mark(phase);
        trace
    }

    /// Reports one actual phase boundary when test tracing is enabled.
    ///
    /// # Panics
    /// Panics if enabled diagnostics cannot write to standard error.
    pub(crate) fn mark(&mut self, phase: &str) {
        if !self.enabled {
            return;
        }
        let now = self.clock.monotonic();
        if self.stages_only {
            eprintln!(
                "ref-phase ref={} candidate={:?} start={:?} at={:?} elapsed={:?} delta={:?} phase={phase} process_at={:?}",
                self.reference,
                self.candidate,
                self.started,
                now,
                now.checked_sub(self.started),
                now.checked_sub(self.last),
                crate::diagnostic_clock::tick(),
            );
        } else {
            eprintln!(
                "ref-phase ref={} candidate={:?} start={:?} at={:?} elapsed={:?} delta={:?} phase={phase}",
                self.reference,
                self.candidate,
                self.started,
                now,
                now.checked_sub(self.started),
                now.checked_sub(self.last),
            );
        }
        self.last = now;
    }
}

impl<C: Clock> Drop for PhaseTrace<'_, C> {
    fn drop(&mut self) {
        self.mark("scope-exit");
    }
}

/// Reports test-only native boundaries using a separate process monotonic clock.
///
/// This clock never supplies deadline input. Scope exit describes the observed
/// object lifetime, not release of all duplicated native exclusion descriptors.
pub(crate) struct NativeTrace {
    started: Option<crate::diagnostic_clock::Tick>,
    scope: u64,
    path: std::path::PathBuf,
    role: &'static str,
    owner_task: String,
}

impl NativeTrace {
    /// Opens an opt-in observation without acquiring a filesystem capability.
    ///
    /// # Panics
    /// Panics if enabled diagnostics cannot write to standard error.
    pub(crate) fn new(path: &std::path::Path, role: &'static str) -> Self {
        static NEXT_SCOPE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let setting = std::env::var_os("TERRANE_REF_PHASE_TRACE");
        let enabled =
            setting.is_some() && setting.as_deref() != Some(std::ffi::OsStr::new("stages"));
        #[cfg(feature = "tokio")]
        let owner_task = format!("{:?}", tokio::task::try_id());
        #[cfg(not(feature = "tokio"))]
        let owner_task = "unavailable".to_owned();
        let trace = Self {
            owner_task,
            started: enabled.then(crate::diagnostic_clock::tick),
            scope: NEXT_SCOPE.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            path: path.to_path_buf(),
            role,
        };
        trace.mark("entry");
        trace
    }

    /// Reports a boundary without consulting or changing the injected clock.
    ///
    /// # Panics
    /// Panics if enabled diagnostics cannot write to standard error.
    pub(crate) fn mark(&self, phase: &str) {
        let Some(started) = self.started else {
            return;
        };
        #[cfg(feature = "tokio")]
        let task = tokio::task::try_id();
        #[cfg(not(feature = "tokio"))]
        let task: Option<()> = None;
        eprintln!(
            "native-phase scope={} role={} path={:?} owner_task={} current_task={task:?} thread={:?} process_at={:?} elapsed={:?} phase={phase}",
            self.scope,
            self.role,
            self.path,
            self.owner_task,
            std::thread::current().id(),
            crate::diagnostic_clock::tick(),
            crate::diagnostic_clock::elapsed(started),
        );
    }
}

impl Drop for NativeTrace {
    fn drop(&mut self) {
        self.mark("object-scope-exit");
    }
}
