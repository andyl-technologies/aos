//! Composes confined, configured SDK snapshots over an existing local repository.
//!
//! [`preflight()`] rejects the entire unsupported configuration before any native
//! effects. [`run`] then installs the irreversible kernel boundary before Tokio,
//! credential reads, repository reopening or filesystem presentation. It prepares
//! every exposure before starting any endpoint, using only each exposure's file
//! capability. Repository reopening uses explicit public issuer keys and a
//! separately configured startup Read, without loading private signing state.
//! Exposure preparation never substitutes that startup Read for an exposure capability.
//!
//! This component supports only the exact local file-bucket leaf, explicit local
//! trust and compiled read-only pinned SDK surface. An explicit native host tier
//! may supply same-domain resident content and actual policy-selected objects; current
//! references and Original verification retain the opened original repository.
//! Bounded lower reads verify bodies before actual native admission and enforce
//! explicit circuit policy. Native object reads retain genuine backing through
//! verified plaintext reads and completed cache handoff.
//! [`run`] returns durable snapshots whose actual handles have drained and
//! stopped. [`run_service`] additionally retains the original recovered native
//! workers for ongoing cache maintenance until a process shutdown signal.
//!
//! Callers supply a fresh single-threaded, capability-free process with trusted
//! procfs, dedicated identity and no unconfined descriptor-sharing peers. A
//! failure after attempting confinement requires process termination; the fixed
//! policy cannot be undone to try another role.

mod error;
mod preflight;
mod service;
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
    surface::{ExposureStatus, PreparedExposures, ServingHandle, TokenResolver},
};

use crate::{
    configured::NativeCachePlan,
    host_cache::NativeReadPolicy,
    quota_confinement::{self, Installed},
};

/// Borrows a completely preflighted configuration without native authority.
///
/// The plan can be inspected or dropped without installing a filter, reading
/// credentials, opening repository state or starting any executor.
pub struct ValidatedSdk<'config> {
    config: &'config Config,
    startup_token: &'config str,
    #[cfg(feature = "surface-fuse")]
    maintenance: Option<crate::configured_maintenance::Plan>,
    cache: Option<(
        NativeCachePlan,
        NativeReadPolicy,
        terrane_sdk::host::cache::ReassemblyMode,
    )>,
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
        self.start_with(None)
    }

    fn start_with(self, notification: Option<service::Ready>) -> Result<CompletedSdk, Error> {
        #[cfg(feature = "surface-fuse")]
        if self.maintenance.is_some() && notification.is_none() {
            return Err(Error::refused(FailureKind::NativeCacheConfiguration));
        }
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
        let outcome = runtime.block_on(start_exposures(
            self.config,
            self.startup_token,
            &installed,
            self.cache,
            notification,
            #[cfg(feature = "surface-fuse")]
            self.maintenance,
        ));
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

/// Maintains the original native cache owners after completing pinned SDK snapshots.
///
/// Requires the same fully supported local composition as [`run`], including
/// explicit native cache resources. The callback observes completed, stopped
/// snapshot handles only after every native domain has recovered and resumed.
/// The original physical owners then continue periodic expiry and retirement
/// until SIGINT or SIGTERM. Shutdown closes admission and joins the original workers
/// before returning.
/// This does not operate a network endpoint or a live SDK presentation handle.
///
/// # Errors
/// Returns pure preflight or missing-cache refusals before confinement, and the
/// terminal startup errors described by [`ValidatedSdk::start`]. Signal setup,
/// callback, bounded owner health and shutdown failures also require process exit.
pub fn run_service(
    config: &Config,
    selected_role: Role,
    on_ready: impl FnOnce(&[CompletedSnapshot]) -> std::io::Result<()> + 'static,
) -> Result<CompletedSdk, Error> {
    let plan = preflight(config, selected_role)?;
    if plan.cache.is_none() {
        return Err(Error::refused(FailureKind::NativeCacheConfiguration));
    }
    plan.start_with(Some(Box::new(on_ready)))
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
    startup_token: &str,
    installed: &Arc<Installed>,
    cache: Option<(
        NativeCachePlan,
        NativeReadPolicy,
        terrane_sdk::host::cache::ReassemblyMode,
    )>,
    notification: Option<service::Ready>,
    #[cfg(feature = "surface-fuse")] maintenance: Option<crate::configured_maintenance::Plan>,
) -> Result<Vec<CompletedSnapshot>, Error> {
    installed
        .check_current()
        .map_err(|error| Error::io(FailureKind::ConfinementChanged, error))?;
    let resolver = tokens::FileTokens { installed };
    let token = resolver
        .resolve(startup_token)
        .await
        .map_err(|error| Error::repository(FailureKind::RepositoryOpen, error))?;
    let repository = config
        .open_local_reader(Role::Serve, &token, TokioLocalFs, TokioClock)
        .await
        .map_err(Error::local)?;
    drop(token);
    if let Some((plan, policy, mode)) = cache {
        let domain = &config
            .local_repository()
            .ok_or_else(|| Error::refused(FailureKind::NativeCacheOpen))?
            .domain;
        if plan.chunk_profile(domain) != Some(repository.chunk_profile()) {
            return Err(Error::refused(FailureKind::NativeCacheProfile));
        }
        let repository = repository
            .with_read_storage_policy(Arc::new(crate::host_cache::NativeSealedReadPolicy));
        // Check every signed storage requirement before opening a native domain.
        // Retain these exact private preparations across the read-driver adapter.
        let resolver = tokens::FileTokens { installed };
        let prepared = PreparedExposures::prepare(&repository, config.exposures(), &resolver)
            .await
            .map_err(|error| Error::repository(FailureKind::Preparation, error))?;
        let mut caches = plan
            .open(Arc::clone(installed))
            .await
            .map_err(|error| Error::io(FailureKind::NativeCacheOpen, error))?;
        let cache = caches
            .remove(domain)
            .ok_or_else(|| Error::refused(FailureKind::NativeCacheOpen))?;
        let mut presentation = None;
        let mut retained = None;
        let repository = repository.with_read_driver(|original| {
            let driver = cache.into_content().with_lower(original.clone(), policy);
            retained = Some(driver.clone());
            presentation = Some(Arc::new(driver.presentation(mode))
                as Arc<dyn terrane_sdk::repository::ObjectPresentation>);
            driver
        });
        let repository = repository.with_object_presentation(
            presentation.ok_or_else(|| Error::refused(FailureKind::NativeCacheOpen))?,
        );
        let retained = retained.ok_or_else(|| Error::refused(FailureKind::NativeCacheOpen))?;
        let snapshots = present_prepared(config, &repository, prepared).await?;
        let mut owners: std::collections::BTreeMap<_, _> = caches
            .iter()
            .map(|(domain, cache)| (domain.as_str(), cache.content().ready().owner()))
            .collect();
        owners.insert(domain.as_str(), retained.native().ready().owner());
        service::maintain(
            notification,
            installed,
            &snapshots,
            &owners,
            #[cfg(feature = "surface-fuse")]
            maintenance,
        )
        .await?;

        // These are the original owners, including domains without exposures.
        // Keep them alive through service shutdown and join before runtime drop.
        drop(repository);
        drop(retained);
        drop(caches);
        return Ok(snapshots);
    }
    if notification.is_some() {
        return Err(Error::refused(FailureKind::NativeCacheConfiguration));
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
    present_prepared(config, repository, prepared).await
}

async fn present_prepared<S: Store + Sync + BucketBinding>(
    config: &Config,
    repository: &Repository<S, TokioClock, TokioLocalFs>,
    prepared: PreparedExposures,
) -> Result<Vec<CompletedSnapshot>, Error> {
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
