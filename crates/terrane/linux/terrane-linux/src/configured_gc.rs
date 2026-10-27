//! Runs confined local marking, retirement and recurring protected recovery.
//!
//! [`preflight`] checks a complete local GC configuration without I/O. Startup
//! installs the irreversible kernel boundary before creating Tokio or reopening
//! the repository with public verification keys. The scheduler retains one
//! original collector session across fresh cycles and recurring maintenance.
//! Each native producer independently qualifies every effect; scheduling hints
//! and decoded status never supply authority.
//!
//! This component handles local mark/sweep and recovery. Pack compaction, remote
//! stores and host-tier collection remain separate implementation obligations.
//! Its existence does not establish complete GC-role or RFC conformance.
//! Callers provide a fresh, single-threaded, capability-free process with trusted
//! procfs and no unconfined descriptor-sharing peers. A failure after attempting
//! confinement requires process termination.

mod error;
mod preflight;
mod scheduler;

pub use error::Error;
pub use preflight::preflight;

use std::{fmt, io};

use terrane_format::gc::Windows;
use terrane_sdk::{config::Config, config::gc::LocalCollector, role::Role};

use crate::quota_confinement;

/// Borrows validated scheduling inputs without native authority or open resources.
pub struct ValidatedCollector<'config> {
    config: &'config Config,
    settings: &'config LocalCollector,
    windows: Windows,
}

impl fmt::Debug for ValidatedCollector<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedCollector")
            .field("settings", &self.settings)
            .field("windows", &self.windows)
            .finish_non_exhaustive()
    }
}

impl ValidatedCollector<'_> {
    /// Runs local collection until SIGINT or SIGTERM and joins native work.
    ///
    /// Installs confinement before its current-thread executor, credentials or
    /// repository state. Calls `on_ready` once after the first mark cycle reaches
    /// durable sweep phase. Readiness does not mean that every retirement or
    /// recurring residue has finished. Shutdown cancels the active operation;
    /// its original session guard prevents later publication by queued work.
    /// The confinement receipt remains retained until executor shutdown joins
    /// all blocking work. A stopped lease remains selected until normal expiry.
    ///
    /// # Errors
    /// Refuses an existing executor, failed confinement or runtime creation,
    /// invalid native repository state, lost collector authority, signal or
    /// notification failure and any failed collection operation. A failure after
    /// confinement is attempted requires termination of the calling process.
    pub fn start(self, on_ready: impl FnOnce() -> io::Result<()> + 'static) -> Result<(), Error> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(Error::Refused("collector startup requires a fresh process"));
        }
        let installed = quota_confinement::install().map_err(Error::Io)?;
        installed.check_current().map_err(Error::Io)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(Error::Io)?;
        let outcome = runtime.block_on(scheduler::run(&self, &installed, Box::new(on_ready)));

        // Cancellation drops the original Session operation first. Joining the
        // executor then retains confinement through every queued native effect.
        drop(runtime);
        installed.check_current().map_err(Error::Io)?;
        outcome
    }
}

/// Runs supported configured local collection with pure preflight before effects.
///
/// # Errors
/// Preserves configuration refusals from [`preflight`] and terminal startup,
/// collector, notification and shutdown failures from [`ValidatedCollector::start`].
pub fn run_service(
    config: &Config,
    selected_role: Role,
    on_ready: impl FnOnce() -> io::Result<()> + 'static,
) -> Result<(), Error> {
    preflight(config, selected_role)?.start(on_ready)
}
