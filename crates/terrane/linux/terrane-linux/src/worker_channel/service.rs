//! Owns authenticated backing requests through preparation, cache handoff and drain.
//!
//! One local runtime task retains the original repository, native driver, mapped root
//! and private worker channel. Individual kernel open deadlines do not own this
//! task. Dropping its supervisor handle requests shutdown without aborting an
//! accepted preparation. Its original LocalSet and runtime must remain alive and
//! driven until shutdown completes; mapped indexes never cross thread boundaries.

use super::{PendingRequest, RequestedBacking, WorkerChannel};
use crate::host_cache::{
    NativeExposureLease, NativeMetadataOwner, NativeReadDriver, NativeRootIndex,
};
#[cfg(feature = "native-test-fixtures")]
use std::io::Write as _;
use std::{io, rc::Rc, time::Duration};
use terrane_format::surface::{View, ViewTarget};
use terrane_sdk::{
    bucket::BucketBinding,
    host::cache::ReassemblyMode,
    repository::{Error, Repository, RootNodeLimits},
    store::{Clock, ContentStore, LocalFs, Store},
};
use tokio::{
    runtime::Handle,
    sync::oneshot,
    task::{JoinHandle, LocalSet},
    time::{MissedTickBehavior, interval, timeout},
};

/// Bounds repository metadata selection and missing-file publication separately.
pub struct Options {
    /// Maximum wait for each original signed metadata preparation.
    pub metadata_budget: Duration,
    /// Maximum total cold fetch, native admission, release grace and sealing time.
    pub fetch_budget: Duration,
    /// Explicit operator reassembly mode, independently checked against signed policy.
    pub reassembly: ReassemblyMode,
    /// Absolute Unix-second file grant deadline, bounded by the live exposure.
    pub file_expires: u64,
    /// Finite canonical metadata inventory bounds for complete-root requests.
    pub root_limits: RootNodeLimits,
}

impl Options {
    fn validate(&self) -> io::Result<()> {
        for budget in [self.metadata_budget, self.fetch_budget] {
            if budget.is_zero()
                || budget > Duration::from_secs(300)
                || !budget.subsec_nanos().is_multiple_of(1_000_000)
            {
                return Err(invalid(
                    "worker service budgets require one through 300000 milliseconds",
                ));
            }
        }
        if self.file_expires == 0
            || self.file_expires > i64::MAX as u64
            || self.root_limits.max_entries == 0
            || self.root_limits.max_metadata_bytes == 0
            || self.root_limits.max_path_bytes == 0
        {
            return Err(invalid(
                "worker service requires finite root bounds and a file deadline",
            ));
        }
        Ok(())
    }
}

/// Retains original serving inputs without reconstructing repository authority.
///
/// The credential is the exposure's configured read capability. Every request
/// performs a fresh scoped SDK preparation against the mapped signed commit and
/// closes that same Read after native backing preparation. Field possession does
/// not authorize another exposure, path, domain or final descriptor disclosure.
/// This value intentionally has no Debug implementation exposing its credential.
pub struct Context<S: Store, C: Clock, F: LocalFs, D> {
    /// Original repository whose guard authorizes every selected path.
    pub repository: Rc<Repository<S, C, F>>,
    /// Original mapped root whose admission and signed commit define the exposure.
    pub served: Rc<NativeRootIndex>,
    /// Original recovered native driver with its trusted routed lower store.
    pub driver: NativeReadDriver<D>,
    /// Exposure capability supplied by trusted configuration, never a worker packet.
    pub token: Vec<u8>,
    /// Original surface name used by repository authorization.
    pub surface: String,
    /// Explicit finite request bounds and selected reassembly requirements.
    pub options: Options,
}

/// Supervises a runtime-owned request loop without cancelling accepted fetches.
///
/// Dropping this handle requests drain and detaches the join handle. The runtime
/// task still owns its original preparations until they finish or fail, including
/// cache handoff after a refused closing Read. A process supervisor keeps the
/// original LocalSet and runtime alive, drives their tasks, and awaits
/// [`Self::stop`] before terminating them. Abrupt process
/// or runtime termination leaves durable obligations for genuine recovery.
///
/// This task grants no launch, mount or kernel-reference closure authority. The
/// exposure supervisor separately stops its original worker and retains physical
/// custody until authenticated closure. Drain and final Send remain serialized
/// by the native owner, even while an accepted cold preparation finishes later.
pub struct Service {
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Result<(), Error>>>,
}

impl Service {
    /// Starts one owned request loop for an original authenticated worker channel.
    ///
    /// Startup validates finite bounds and the original mapped exposure before
    /// spawning. The task performs no content fetch until an authenticated file
    /// request passes a fresh scoped selection. Idle waiting has no request timeout;
    /// the task checks the original durable exposure every second, so expiry,
    /// external drain or owner failure also closes an idle worker channel.
    /// The caller drives `local` until this service finishes; its mapped index
    /// and all request futures stay on that original local executor.
    ///
    /// # Errors
    /// Refuses an absent Tokio runtime, invalid bounds, a foreign mapped exposure
    /// or changed original index backing. Runtime shutdown and per-request native,
    /// authorization or transport failures are reported by [`Self::wait`].
    pub fn start<S, C, F, D>(
        local: &LocalSet,
        channel: WorkerChannel,
        context: Context<S, C, F, D>,
    ) -> io::Result<Self>
    where
        S: Store + Sync + 'static,
        C: Clock + Sync + 'static,
        F: LocalFs + Sync + 'static,
        D: ContentStore + BucketBinding + 'static,
    {
        Handle::try_current().map_err(io::Error::other)?;
        context.options.validate()?;
        if channel.exposure.commit() != context.served.commit()
            || channel.exposure.key() != context.served.key()
        {
            return Err(invalid(
                "worker service mapped root differs from its original exposure",
            ));
        }
        context.served.check_native_backing()?;
        let (stop, receive) = oneshot::channel();
        Ok(Self {
            stop: Some(stop),
            task: Some(local.spawn_local(async move {
                #[cfg(feature = "native-test-fixtures")]
                let started = tokio::time::Instant::now();

                let result = run(channel, context, receive).await;

                // A dropped fixture supervisor detaches this task. Retain its
                // original terminal result when the runtime finishes driving it.
                #[cfg(feature = "native-test-fixtures")]
                let _ = writeln!(
                    io::stderr(),
                    "WORKER_SERVICE_RESULT elapsed_ms={} result={result:?}",
                    started.elapsed().as_millis(),
                );
                result
            })),
        })
    }

    /// Reports whether the owned loop has already returned, without joining it.
    pub fn is_finished(&self) -> bool {
        self.task.as_ref().is_none_or(JoinHandle::is_finished)
    }

    /// Waits for the original loop without cancelling it when this wait is dropped.
    ///
    /// The join handle stays in this supervisor across cancellation. The caller
    /// may wait again or request stop while the original preparation continues.
    ///
    /// # Errors
    /// Returns request, native drain, authorization, transport and task failures.
    /// Refuses a second join after the original task result was consumed.
    pub async fn wait(&mut self) -> Result<(), Error> {
        let task = self
            .task
            .as_mut()
            .ok_or_else(|| invalid("worker service already joined"))?;
        let result = task.await;
        self.task.take();
        result.map_err(|error| Error::Io(io::Error::other(error)))?
    }

    /// Requests durable drain and waits for every already accepted preparation.
    ///
    /// The native owner acknowledges drain before the task resumes a pending
    /// preparation. That work may still seal and cache content, but its final
    /// disclosure cannot succeed after the acknowledged drain. A pending refusal
    /// is returned rather than being mistaken for successful preparation.
    ///
    /// # Errors
    /// Preserves all errors from [`Self::wait`], including a pending preparation
    /// refused because this stop request drained its original exposure.
    pub async fn stop(&mut self) -> Result<(), Error> {
        self.request_stop();
        self.wait().await
    }

    fn request_stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        self.request_stop();
        // JoinHandle drop detaches; the runtime retains the original work.
    }
}

async fn run<S, C, F, D>(
    mut channel: WorkerChannel,
    context: Context<S, C, F, D>,
    mut stop: oneshot::Receiver<()>,
) -> Result<(), Error>
where
    S: Store + Sync,
    C: Clock + Sync,
    F: LocalFs + Sync,
    D: ContentStore + BucketBinding,
{
    let exposure = channel.exposure.clone();
    let owner = context.driver.native().ready().owner();
    let unavailable = wait_until_unavailable(owner, &exposure, context.options.metadata_budget);
    tokio::pin!(unavailable);

    let outcome = loop {
        let request = tokio::select! {
            biased;
            _ = &mut stop => break Ok(()),
            error = &mut unavailable => break Err(Error::Io(error)),
            received = channel.receive_ready() => match received {
                Ok(request) => request,
                Err(error) => break Err(Error::Io(error)),
            },
        };
        let preparation = prepare(request, &context);
        tokio::pin!(preparation);
        tokio::select! {
            biased;
            _ = &mut stop => {
                let drained = owner.drain_surface_exposure(&exposure).await.map_err(Error::Io);
                // Keep polling the original operation after drain. In particular,
                // its cold producer still attempts cache handoff on refusal.
                let prepared = preparation.await;
                return prepared.and(drained);
            }
            error = &mut unavailable => {
                let drained = owner.drain_surface_exposure(&exposure).await.map_err(Error::Io);
                // Expiry stops disclosure, but cannot cancel an accepted cold
                // producer before its original cache handoff completes.
                let prepared = preparation.await;
                return prepared.and(drained).and(Err(Error::Io(error)));
            }
            prepared = &mut preparation => {
                if let Err(error) = prepared {
                    break Err(error);
                }
            }
        }
    };
    let drained = owner
        .drain_surface_exposure(&exposure)
        .await
        .map_err(Error::Io);
    outcome.and(drained)
}

async fn wait_until_unavailable(
    owner: &NativeMetadataOwner,
    exposure: &NativeExposureLease,
    budget: Duration,
) -> io::Error {
    let mut checks = interval(Duration::from_secs(1));
    checks.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        checks.tick().await;
        // Query the original serialized owner rather than a cached deadline:
        // renewal and generation changes must be observed from durable state.
        match timeout(budget, owner.check_surface_exposure(exposure)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return error,
            Err(_) => return io::ErrorKind::TimedOut.into(),
        }
    }
}

async fn prepare<S, C, F, D>(
    request: PendingRequest<'_>,
    context: &Context<S, C, F, D>,
) -> Result<(), Error>
where
    S: Store + Sync,
    C: Clock + Sync,
    F: LocalFs + Sync,
    D: ContentStore + BucketBinding,
{
    let target = ViewTarget::Commit(context.served.commit());
    match request.request().backing() {
        RequestedBacking::Index => {
            let selection = timeout(
                context.options.metadata_budget,
                context.repository.prepare_root_read(
                    &target,
                    &context.token,
                    &context.surface,
                    context.options.root_limits,
                ),
            )
            .await
            .map_err(|_| Error::Io(io::ErrorKind::TimedOut.into()))??;
            request
                .grant_index(
                    context.driver.native().ready().owner(),
                    &context.served,
                    selection,
                )
                .await
        }
        RequestedBacking::File { path, .. } => {
            let view = View {
                target,
                subtree: Vec::new(),
                policy: None,
            };
            let selection = timeout(
                context.options.metadata_budget,
                context
                    .repository
                    .prepare_file_read(&view, path, &context.token, &context.surface),
            )
            .await
            .map_err(|_| Error::Io(io::ErrorKind::TimedOut.into()))??;
            request
                .grant_file_with_fetch(
                    &context.driver,
                    &context.served,
                    selection,
                    context.options.reassembly,
                    context.options.fetch_budget,
                    context.options.file_expires,
                )
                .await
        }
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
