//! Composes confined, configured SDK snapshots over an existing local repository.
//!
//! [`preflight()`] rejects the entire unsupported configuration before any native
//! effects. [`run`] then installs the irreversible kernel boundary before Tokio,
//! credential reads, repository reopening or filesystem presentation. It prepares
//! every exposure before starting any endpoint, using only each exposure's file
//! capability. Repository reopening temporarily reads private authority records,
//! including signing seeds, then drops the returned signing handle. Exposure
//! preparation never substitutes that authority's token for an exposure capability.
//!
//! This component supports only the exact local file-bucket leaf, explicit local
//! trust and compiled read-only pinned SDK surface. An explicit native host tier
//! may supply same-domain resident content under `reassembly = "never"`; current
//! references and Original verification retain the opened original repository.
//! Whole-object native preparation remains a separate serving integration.
//! Completion means durable snapshots whose actual handles have drained and
//! stopped. It never parks a pretend daemon or advertises host-tier readiness.
//!
//! Callers supply a fresh single-threaded, capability-free process with trusted
//! procfs, dedicated identity and no unconfined descriptor-sharing peers. A
//! failure after attempting confinement requires process termination; the fixed
//! policy cannot be undone to try another role.

mod error;
mod preflight;
mod tokens;

pub use error::{Error, FailureKind};
pub use preflight::preflight;
pub use tokens::TOKEN_FILE_BYTE_BUDGET;

use std::{
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use terrane_sdk::{
    bucket::BucketBinding,
    config::Config,
    repository::Repository,
    role::Role,
    store::{Store, TokioClock, TokioLocalFs},
    surface::{ExposureStatus, PreparedExposures, ServingHandle},
};

use crate::{
    configured::NativeCachePlan,
    quota_confinement::{self, Installed},
};

/// Borrows a completely preflighted configuration without native authority.
///
/// The plan can be inspected or dropped without installing a filter, reading
/// credentials, opening repository state or starting any executor.
pub struct ValidatedSdk<'config> {
    config: &'config Config,
    cache: Option<NativeCachePlan>,
}

impl ValidatedSdk<'_> {
    /// Runs confined SDK presentation in the fresh calling process.
    ///
    /// Creates a current-thread Tokio executor only after successful kernel
    /// installation. Blocking native adapters inherit that already installed
    /// boundary. The receipt survives executor shutdown and all native effects.
    ///
    /// # Errors
    /// Rejects an existing executor, failed confinement, unreadable exposure
    /// credentials, denied or invalid repository state, and presentation errors.
    /// After an error requiring process exit, the caller must terminate rather
    /// than retrying startup or executing another program in this process.
    pub fn start(self) -> Result<CompletedSdk, Error> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(Error::refused(FailureKind::ExistingRuntime));
        }
        let installed = Arc::new(
            quota_confinement::install()
                .map_err(|error| Error::io(FailureKind::Confinement, error))?,
        );
        installed
            .check_current()
            .map_err(|error| Error::io(FailureKind::ConfinementChanged, error))?;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| Error::io(FailureKind::Runtime, error))?;
        let outcome = runtime.block_on(start_exposures(self.config, &installed, self.cache));
        // Runtime drop joins its blocking work while the real receipt remains
        // retained. No asynchronous filesystem action outlives this boundary.
        drop(runtime);
        installed
            .check_current()
            .map_err(|error| Error::io(FailureKind::ConfinementChanged, error))?;
        let snapshots = outcome?;
        Ok(CompletedSdk {
            installed,
            snapshots,
        })
    }
}

impl fmt::Debug for ValidatedSdk<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedSdk")
            .field("exposures", &self.config.exposures().len())
            .finish_non_exhaustive()
    }
}

/// Runs one supported configured SDK composition synchronously.
///
/// Performs whole-config pure preflight before any irreversible bootstrap.
/// Successful return describes completed durable snapshots, not an active
/// daemon, endpoint accept loop or native host-cache readiness.
///
/// # Errors
/// Returns configuration refusals without effects, or terminal native startup
/// errors as described by [`ValidatedSdk::start`].
pub fn run(config: &Config, selected_role: Role) -> Result<CompletedSdk, Error> {
    preflight(config, selected_role)?.start()
}

/// Holds completed SDK snapshots and their genuine process confinement receipt.
///
/// The actual drained and stopped handles remain owned here. Their directories
/// persist after this result is dropped; dropping the receipt does not undo the
/// kernel policy, which remains installed for the lifetime of this process.
pub struct CompletedSdk {
    installed: Arc<Installed>,
    snapshots: Vec<CompletedSnapshot>,
}

impl CompletedSdk {
    /// Borrows the completed snapshots in their original configuration order.
    ///
    /// # Errors
    /// Rejects another process or unavailable or changed native confinement.
    pub fn snapshots(&self) -> Result<&[CompletedSnapshot], Error> {
        self.installed
            .check_current()
            .map_err(|error| Error::io(FailureKind::ConfinementChanged, error))?;
        Ok(&self.snapshots)
    }
}

impl fmt::Debug for CompletedSdk {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompletedSdk")
            .field("snapshots", &self.snapshots.len())
            .finish_non_exhaustive()
    }
}

/// Owns the stopped handle and identity of one durable pinned SDK snapshot.
pub struct CompletedSnapshot {
    id: String,
    endpoint: PathBuf,
    handle: ServingHandle,
}

impl CompletedSnapshot {
    /// Returns the configured exposure identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the durable presentation directory.
    pub fn endpoint(&self) -> &Path {
        &self.endpoint
    }

    /// Returns status from the actual drained and stopped SDK handle.
    pub fn status(&self) -> ExposureStatus {
        self.handle.status()
    }
}

impl fmt::Debug for CompletedSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = self.handle.status();
        formatter
            .debug_struct("CompletedSnapshot")
            .field("commit", &status.commit)
            .field("state", &status.state)
            .finish_non_exhaustive()
    }
}

async fn start_exposures(
    config: &Config,
    installed: &Arc<Installed>,
    cache: Option<NativeCachePlan>,
) -> Result<Vec<CompletedSnapshot>, Error> {
    installed
        .check_current()
        .map_err(|error| Error::io(FailureKind::ConfinementChanged, error))?;
    let repository = config
        .open_local_repository(Role::Serve, TokioLocalFs, TokioClock)
        .await
        .map_err(Error::local)?;
    if let Some(plan) = cache {
        let domain = &config
            .local_repository()
            .ok_or_else(|| Error::refused(FailureKind::NativeCacheConfiguration))?
            .domain;
        let mut caches = plan
            .open(Arc::clone(installed))
            .await
            .map_err(|error| Error::io(FailureKind::NativeCacheOpen, error))?;
        let cache = caches
            .remove(domain)
            .ok_or_else(|| Error::refused(FailureKind::NativeCacheOpen))?;
        let repository = repository.with_read_cache(cache.into_content());
        return present(config, installed, &repository).await;
    }
    present(config, installed, &repository).await
}

async fn present<S: Store + Sync + BucketBinding>(
    config: &Config,
    installed: &Installed,
    repository: &Repository<S, TokioClock, TokioLocalFs>,
) -> Result<Vec<CompletedSnapshot>, Error> {
    let resolver = tokens::FileTokens { installed };
    let prepared = PreparedExposures::prepare(repository, config.exposures(), &resolver)
        .await
        .map_err(|error| Error::repository(FailureKind::Preparation, error))?;
    let handles = prepared
        .start(repository)
        .await
        .map_err(|error| Error::repository(FailureKind::Presentation, error))?;

    // SDK checkout has completed all filesystem work before returning a handle.
    // Stop every real handle even if an unexpected lifecycle failure occurs;
    // no active service is manufactured from this completed operation.
    let mut failure = None;
    for handle in &handles {
        if let Err(error) = handle.drain(Duration::ZERO) {
            failure.get_or_insert_with(|| Error::repository(FailureKind::Completion, error));
        }
        if let Err(error) = handle.stop() {
            failure.get_or_insert_with(|| Error::repository(FailureKind::Completion, error));
        }
    }
    if let Some(error) = failure {
        return Err(error);
    }
    if handles.len() != config.exposures().len() {
        return Err(Error::refused(FailureKind::Completion));
    }
    Ok(config
        .exposures()
        .iter()
        .zip(handles)
        .map(|(exposure, handle)| CompletedSnapshot {
            id: exposure.id.clone(),
            endpoint: exposure.endpoint.address.clone().into(),
            handle,
        })
        .collect())
}

#[cfg(test)]
mod tests;
