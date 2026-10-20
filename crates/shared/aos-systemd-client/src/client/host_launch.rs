//! Retains the actual finite Host launch connection and SDK constructor prefix.
//!
//! Neither the schedule nor this native receiver supplies role authority or
//! payment. The enclosing real Launch original admits it before allocation/IO.

use super::*;
use crate::manager_proxy::{JobRemovedStream, ReloadingStream};
pub use zbus::connection::{HostLaunchReceiveScheduleV2, HostLaunchEffectWriteGateV3};

/// Selects the finite RPC roster of one existing Host launch SDK operation.
///
/// The selector describes transport representation only. It supplies neither
/// role permission nor payment, and the real caller retains its original cutoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostSystemdCallV2 {
    /// Starts one Guardian and awaits its job on the same client.
    GuardianStart,
    /// Starts a payload between two reference-held Guardian observations.
    PayloadStart,
    /// Runs the exact referenced identity/property observation once.
    ExactObserve,
    /// Runs the existing unreferenced final-absence observation once.
    PostUnrefObserve,
    /// Runs the exact stop, job, identity and Unref recipe once.
    ExactStop,
    /// Runs one complete ordinary sandbox observation on the same client.
    SandboxObserve,
    /// Reads one live supervisor policy with the unique PID 1 bookends.
    SupervisorPolicy,
}

impl HostSystemdCallV2 {
    /// Bounds the fixed requests of the closed launch method vocabulary.
    ///
    /// D-Bus names have 255-byte limits. The shared producers use at most eight
    /// header fields and four body strings; generated systemd unit object paths
    /// additionally allow three-byte escaping of each unit-name byte. This
    /// excludes the single StartTransientUnit property request, priced separately.
    #[must_use]
    pub const fn fixed_request_wire_bytes_v2() -> Option<usize> {
        Some(16 + 8 * (8 + 4 + 255 + 1) + 4 * (3 * 255 + 128 + 16))
    }

    /// Checks one property request and the remaining fixed request aggregate.
    ///
    /// This uses the same finite method roster as [`Self::receiving_schedule_v2`].
    /// Only GuardianStart and PayloadStart carry one property request. The
    /// returned schedule enforces both the largest frame and the aggregate
    /// before serialization allocation, retained Message cloning and native IO.
    /// Zero extra asynchronous noise is legal; the original bus/job/terminal
    /// receive slots remain separately included by the shared roster.
    ///
    /// # Errors
    /// Rejects zero or overflowing extents and any canonical schedule refusal.
    pub fn receiving_schedule_with_request_bounds_v2(
        self,
        maximum_message_bytes: usize,
        property_request_bytes: usize,
        fixed_request_bytes: usize,
        maximum_materialized_bytes: usize,
        asynchronous_noise_messages: usize,
    ) -> Result<HostLaunchReceiveScheduleV2> {
        let property = matches!(self, Self::GuardianStart | Self::PayloadStart);
        if fixed_request_bytes == 0 || (property && property_request_bytes == 0) {
            return Err(Error::HostLaunchRetained("empty request extent"));
        }
        let maximum_request_bytes = if property {
            property_request_bytes.max(fixed_request_bytes)
        } else { fixed_request_bytes };
        let schedule = self.receiving_schedule_v2(maximum_message_bytes,
            maximum_request_bytes, maximum_materialized_bytes, asynchronous_noise_messages)?;
        let outgoing = schedule.raw_data_v2().outgoing_messages();
        let fixed = outgoing.checked_sub(usize::from(property))
            .and_then(|count| count.checked_mul(fixed_request_bytes))
            .and_then(|bytes| bytes.checked_add(if property { property_request_bytes } else { 0 }))
            .ok_or(Error::HostLaunchRetained("request aggregate overflow"))?;
        schedule.with_outgoing_wire_bytes_v2(fixed).map_err(Error::from)
    }

    /// Checks the operation's complete finite constructor/RPC/disposition roster.
    ///
    /// The caller supplies already-admitted wire extents and asynchronous noise
    /// space as passive DATA. The roster includes Hello, the original owner/PID
    /// query, Subscribe, two unique-name AddMatch requests and both RemoveMatch
    /// requests. Non-exact clients additionally send Unsubscribe. Exact clients
    /// release their reference and close their same connection. One unused
    /// receive slot separates normal completion from finite noise exhaustion.
    ///
    /// # Errors
    /// Rejects overflow or any extent rejected by the canonical raw constructor.
    pub fn receiving_schedule_v2(
        self,
        maximum_message_bytes: usize,
        maximum_request_bytes: usize,
        maximum_materialized_bytes: usize,
        asynchronous_noise_messages: usize,
    ) -> Result<HostLaunchReceiveScheduleV2> {
        let (outgoing, jobs, outgoing_files): (usize, usize, usize) = match self {
            Self::GuardianStart => (10, 1, 11),
            Self::PayloadStart | Self::ExactStop => (33, 1, if self == Self::PayloadStart { 7 } else { 0 }),
            Self::ExactObserve => (22, 0, 0),
            Self::PostUnrefObserve => (19, 0, 0),
            Self::SandboxObserve => (22, 0, 0),
            // The common connection owns nine setup/disposition calls. The
            // active service observer adds twelve identity bookends and the
            // twelve policy properties used by the sole Host validator.
            Self::SupervisorPolicy => (9 + 12 + 12, 0, 0),
        };
        let incoming = outgoing.checked_add(jobs).and_then(|value| value.checked_add(3))
            .and_then(|value| value.checked_add(asynchronous_noise_messages))
            .ok_or(Error::HostLaunchRetained("receive schedule overflow"))?;
        HostLaunchReceiveScheduleV2::new(
            outgoing, incoming, maximum_message_bytes, maximum_request_bytes,
            maximum_materialized_bytes, outgoing_files,
        ).map_err(Error::from)
    }
}

/// Describes passive complete SDK/native receiving demand before construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostSystemdConnectionFootprintV2 {
    /// Raw transport, concrete decoder, SDK/control/task and construction bytes.
    pub memory_bytes: usize,
    /// Original socket/raw-refusal and actual outgoing descriptor peak.
    pub open_files: usize,
    /// Fixed socket namespace plus bounded job/reference map entries.
    pub metadata_entries: usize,
    /// Maximum fixed AUTH and complete outgoing/incoming wire traffic.
    pub network_bytes: usize,
    /// Conservative complete native/SDK diagnostic and trace rendering bytes.
    pub maximum_log_bytes: usize,
}

const DISPOSITION_SLOTS: usize = 8;

struct DispositionOutcomeV2 {
    stage: &'static str,
    result: std::sync::OnceLock<Result<()>>,
    task_result: Option<Arc<std::sync::OnceLock<std::result::Result<(), tokio::task::JoinError>>>>,
    task_join_selected: AtomicBool,
}

impl DispositionOutcomeV2 {
    fn cause_v2(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if self.task_join_selected.load(Ordering::Acquire) {
            return self.task_result.as_ref()?.get()?.as_ref().err().map(|cause| cause as _);
        }
        self.result.get()?.as_ref().err().map(|cause| cause as _)
    }
}

pub(super) struct HostSystemdTaskV2 {
    pub(super) handle: Option<JoinHandle<()>>,
    pub(super) result: Arc<std::sync::OnceLock<std::result::Result<(), tokio::task::JoinError>>>,
}

pub(super) struct HostSystemdDispositionV2 {
    pub(super) tasks: Arc<AsyncMutex<Vec<HostSystemdTaskV2>>>,
    pub(super) spawned_tasks: usize,
    pub(super) stops: Vec<oneshot::Sender<()>>,
    streams_finished: bool,
    pub(super) task_results: [Arc<std::sync::OnceLock<std::result::Result<(), tokio::task::JoinError>>>; 2],
    outcomes: Vec<Arc<DispositionOutcomeV2>>,
    first_failure: Arc<std::sync::OnceLock<Arc<DispositionOutcomeV2>>>,
}

impl HostSystemdDispositionV2 {
    fn new() -> Self {
        Self {
            tasks: Arc::new(AsyncMutex::new(Vec::with_capacity(2))),
            spawned_tasks: 0,
            stops: Vec::with_capacity(2),
            streams_finished: false,
            task_results: std::array::from_fn(|_| Arc::new(std::sync::OnceLock::new())),
            outcomes: Vec::with_capacity(DISPOSITION_SLOTS),
            first_failure: Arc::new(std::sync::OnceLock::new()),
        }
    }
}

/// Retains the destination before one already-owed native disposition starts.
/// This is mechanical custody; it neither pays nor authorizes an operation.
pub(crate) struct HostSystemdDispositionSlotV2 {
    outcome: Arc<DispositionOutcomeV2>,
    first_failure: Arc<std::sync::OnceLock<Arc<DispositionOutcomeV2>>>,
}

impl HostSystemdDispositionSlotV2 {
    fn complete_join_v2(self, result: std::result::Result<(), tokio::task::JoinError>) -> Result<()> {
        let failed = result.is_err();
        let Some(original) = self.outcome.task_result.as_ref() else { std::process::abort(); };
        // Park the actual JoinError before selecting its prearmed outcome and
        // before entering the next independently owed task completion.
        if original.set(result).is_err() { std::process::abort(); }
        self.outcome.task_join_selected.store(failed, Ordering::Release);
        self.complete(if failed {
            Err(Error::HostLaunchRetained("stream task completion"))
        } else { Ok(()) })
    }

    pub(crate) fn complete(self, result: Result<()>) -> Result<()> {
        let failed = result.is_err();
        // The non-Clone slot is private and consumed once. Store the actual
        // result before any diagnostic or later fallible cleanup operation.
        if self.outcome.result.set(result).is_err() { std::process::abort(); }
        if failed {
            let _ = self.first_failure.set(Arc::clone(&self.outcome));
            Err(Error::HostLaunchRetained(self.outcome.stage))
        } else {
            Ok(())
        }
    }
}

impl SystemdClient {
    pub(crate) fn arm_host_disposition_v2(
        &self,
        stage: &'static str,
    ) -> Result<Option<HostSystemdDispositionSlotV2>> {
        let Some(original) = self.host_launch.as_ref() else { return Ok(None); };
        arm_disposition_v2(original, stage).map(Some)
    }

    pub(crate) async fn finish_host_streams_v2(&self) -> Result<()> {
        let Some(original) = self.host_launch.as_ref() else { return Ok(()); };
        finish_streams_v2(original).await
    }

}

fn arm_disposition_v2(
    original: &Arc<Mutex<HostSystemdDispositionV2>>,
    stage: &'static str,
) -> Result<HostSystemdDispositionSlotV2> {
    arm_disposition_engine_v2(original, stage, None)
}

fn arm_task_disposition_v2(
    original: &Arc<Mutex<HostSystemdDispositionV2>>,
    result: &Arc<std::sync::OnceLock<std::result::Result<(), tokio::task::JoinError>>>,
) -> Result<HostSystemdDispositionSlotV2> {
    arm_disposition_engine_v2(original, "stream task completion", Some(Arc::clone(result)))
}

fn arm_disposition_engine_v2(
    original: &Arc<Mutex<HostSystemdDispositionV2>>,
    stage: &'static str,
    task_result: Option<Arc<std::sync::OnceLock<std::result::Result<(), tokio::task::JoinError>>>>,
) -> Result<HostSystemdDispositionSlotV2> {
    let mut owner = original.lock()
        .map_err(|_| Error::HostLaunchRetained("disposition borrowed"))?;
    if owner.outcomes.len() == DISPOSITION_SLOTS {
        return Err(Error::HostLaunchRetained("disposition destinations exhausted"));
    }
    let outcome = Arc::new(DispositionOutcomeV2 {
        stage,
        result: std::sync::OnceLock::new(),
        task_result,
        task_join_selected: AtomicBool::new(false),
    });
    owner.outcomes.push(Arc::clone(&outcome));
    Ok(HostSystemdDispositionSlotV2 {
        outcome,
        first_failure: Arc::clone(&owner.first_failure),
    })
}

// The same two selected stream tasks finish their actual RemoveMatch work
// before connection close. Timeout cancels and then joins the same task; no
// detached task or positive native reuse is inferred from a failed join.
async fn finish_streams_v2(original: &Arc<Mutex<HostSystemdDispositionV2>>) -> Result<()> {
    let tasks = {
        let mut owner = original.lock()
            .map_err(|_| Error::HostLaunchRetained("stream disposition borrowed"))?;
        if owner.streams_finished { return Ok(()); }
        owner.streams_finished = true;
        for stop in owner.stops.drain(..) { let _ = stop.send(()); }
        Arc::clone(&owner.tasks)
    };
    let mut first = None;
    let mut tasks = tasks.lock().await;
    for task in tasks.iter_mut() {
        let slot = arm_task_disposition_v2(original, &task.result)?;
        let handle = task.handle.as_mut()
            .ok_or(Error::HostLaunchRetained("task handle missing"))?;
        // Await by mutable borrow of the resident field. Cancellation leaves
        // the SAME JoinHandle inside this owner, never a detached local.
        let completion = match tokio::time::timeout(Duration::from_secs(5), &mut *handle).await {
            Ok(result) => slot.complete_join_v2(result),
            Err(_) => {
                // This timeout precedes the independently owed abort/join;
                // the later cancelled JoinError remains owned but cannot
                // replace this outcome's selected first source.
                let refused = slot.complete(Err(Error::ExactUnitTimeout("stream task completion")));
                handle.abort();
                let result = (&mut *handle).await;
                if task.result.set(result).is_err() { std::process::abort(); }
                refused
            }
        };
        // Both paths park the actual Result before disposing this completed
        // handle. A negative first task never skips the independently owed next.
        drop(task.handle.take());
        if first.is_none() { first = completion.err(); }
    }
    match first { Some(error) => Err(error), None => Ok(()) }
}

struct SetupOriginalV2 {
    connection: Option<zbus::Connection>,
    manager: Option<ManagerProxy<'static>>,
    identity_bus: Option<zbus::fdo::DBusProxy<'static>>,
    identity_name: Option<zbus::names::BusName<'static>>,
    identity_owner: Option<zbus::names::OwnedUniqueName>,
    jobs: Option<Arc<Mutex<JobRegistry>>>,
    reloading: Option<Arc<AtomicBool>>,
    event_tx: Option<mpsc::UnboundedSender<()>>,
    event_rx: Option<mpsc::UnboundedReceiver<()>>,
    job_removed: Option<JobRemovedStream>,
    reloading_stream: Option<ReloadingStream>,
    disposition: Arc<Mutex<HostSystemdDispositionV2>>,
}

impl SetupOriginalV2 {
    fn new(disposition: Arc<Mutex<HostSystemdDispositionV2>>) -> Self {
        Self {
            connection: None,
            manager: None,
            identity_bus: None,
            identity_name: None,
            identity_owner: None,
            jobs: None,
            reloading: None,
            event_tx: None,
            event_rx: None,
            job_removed: None,
            reloading_stream: None,
            disposition,
        }
    }
}

/// Retains one actual native transport and every reached SDK setup original.
pub struct HostSystemdConnectionOriginalV2 {
    native: zbus::connection::HostLaunchConnectionOriginalV2,
    setup: SetupOriginalV2,
    client: Option<SystemdClient>,
    failure: Option<Error>,
    native_selected: bool,
    entered: bool,
    disposed: bool,
    exact_taken: bool,
    disposition_native_selected: bool,
    completed_disposition: bool,
    native_disposal_entered: bool,
    storage_compaction_entered: bool,
}

impl HostSystemdConnectionOriginalV2 {
    /// Describes complete finite native/SDK storage and traffic before allocation.
    #[must_use]
    pub fn receiving_footprint_v2(schedule: HostLaunchReceiveScheduleV2) -> Option<HostSystemdConnectionFootprintV2> {
        // Selected property consumers use the shared finite typed schema;
        // signal/job/path DTOs have separate bounded carrier slack here.
        let raw = schedule.raw_data_v2();
        let decoded = super::fixed_property::decoded_geometry_for_schedule_v2(raw.maximum_materialized_bytes(), raw.incoming_messages())?.0;
        let carriers = raw.incoming_messages().checked_mul(
            64 * 1024 + 8 * std::mem::size_of::<String>() + 4 * std::mem::size_of::<JobOutcome>())?;
        let maps = raw.incoming_messages().checked_add(raw.outgoing_messages())?;
        // AUTH uses the same one aggregate send and receive ceiling as the
        // existing native engine. Message debug/error rendering can escape raw
        // text; each bounded frame also has fixed diagnostic header space.
        let traffic = schedule.maximum_outgoing_wire_bytes_v2()
            .checked_add(raw.incoming_messages().checked_mul(raw.maximum_message_bytes())?)?
            .checked_add(zbus::connection::ControllerPropertyReceiveAttemptV1::AUTH_BYTES.checked_mul(2)?)?;
        let diagnostic_bytes = traffic.checked_mul(64)?
            .checked_add(maps.checked_mul(4096)?)?;
        Some(HostSystemdConnectionFootprintV2 {
            memory_bytes: schedule.receiving_storage_bytes_v2()?.checked_add(decoded)?.checked_add(carriers)?
                .checked_add(2 * std::mem::size_of::<Self>())?
                .checked_add(2 * std::mem::size_of::<SystemdClient>())?
                .checked_add(2 * std::mem::size_of::<HostSystemdDispositionV2>())?
                .checked_add(8 * std::mem::size_of::<usize>())?
                .checked_add(2 * 64 * 1024)?
                .checked_add(2 * raw.maximum_request_bytes())?
                .checked_add(DISPOSITION_SLOTS * (2 * std::mem::size_of::<DispositionOutcomeV2>() + 4 * std::mem::size_of::<usize>()))?
                .checked_add(2 * std::mem::size_of::<oneshot::Sender<()>>())?
                .checked_add(4 * std::mem::size_of::<HostSystemdTaskV2>())?
                .checked_add(4 * std::mem::size_of::<std::sync::OnceLock<std::result::Result<(), tokio::task::JoinError>>>())?
                .checked_add(16 * std::mem::size_of::<usize>())?,
            open_files: schedule.maximum_native_files_v2()?,
            // Match the canonical fixed-property invoice: native request/job
            // keys plus bounded decoded dynamic record/array entries. Rust
            // controls, Arcs and signature carriers remain byte provision.
            metadata_entries: maps.checked_add(raw.maximum_materialized_bytes().div_ceil(2))?.checked_add(1)?,
            network_bytes: traffic,
            maximum_log_bytes: diagnostic_bytes,
        })
    }

    /// Bounds the compact retained original after proven physical storage disposal.
    ///
    /// This is memory DATA for the same immutable schedule. Namespace/traffic
    /// invoices remain cumulative; the enclosing real phase must verify its
    /// matching opaque compacted token before sharing any sequential byte peak.
    #[must_use]
    pub fn compacted_receiving_bytes_v2(schedule: HostLaunchReceiveScheduleV2) -> Option<usize> {
        zbus::connection::HostLaunchConnectionOriginalV2::compacted_storage_bytes_v2(schedule)?
            .checked_add(2 * std::mem::size_of::<Self>())?
            .checked_add(2 * std::mem::size_of::<HostSystemdDispositionV2>())?
            .checked_add(DISPOSITION_SLOTS.checked_mul(
                2 * std::mem::size_of::<DispositionOutcomeV2>() + 4 * std::mem::size_of::<usize>())?)?
            .checked_add(4 * std::mem::size_of::<HostSystemdTaskV2>())?
            .checked_add(4 * std::mem::size_of::<std::sync::OnceLock<std::result::Result<(), tokio::task::JoinError>>>())?
            // These empty Vecs retain their original capacities after drain.
            // Their carriers are inline, but their backing and Arc/Mutex
            // controls remain actual resident storage until the whole owner drops.
            .checked_add(2 * std::mem::size_of::<oneshot::Sender<()>>())?
            .checked_add(DISPOSITION_SLOTS * std::mem::size_of::<Arc<DispositionOutcomeV2>>())?
            .checked_add(std::mem::size_of::<AsyncMutex<Vec<HostSystemdTaskV2>>>())?
            .checked_add(std::mem::size_of::<Mutex<HostSystemdDispositionV2>>())?
            .checked_add(std::mem::size_of::<std::sync::OnceLock<Arc<DispositionOutcomeV2>>>())?
            // Arc headers: disposition, task table, two join results,
            // first-failure slot and each completed outcome.
            .checked_add((5 + DISPOSITION_SLOTS) * 2 * std::mem::size_of::<usize>())
    }

    /// Allocates the caller's already-admitted finite representation without IO.
    #[must_use]
    pub fn new(schedule: HostLaunchReceiveScheduleV2) -> Self {
        let disposition = Arc::new(Mutex::new(HostSystemdDispositionV2::new()));
        Self { native: zbus::connection::HostLaunchConnectionOriginalV2::new(schedule),
            setup: SetupOriginalV2::new(disposition), client: None,
            failure: None, native_selected: false, entered: false, disposed: false, exact_taken: false, disposition_native_selected: false, completed_disposition: false, native_disposal_entered: false, storage_compaction_entered: false }
    }

    /// Bounds the mechanical effect-clock gate's carrier construction overlap.
    ///
    /// The normal raw/SDK footprint includes its inline storage. The actual
    /// caller separately admits its concrete gate owner and finite clock lane.
    #[must_use]
    pub fn effect_write_gate_receiving_bytes_v3() -> Option<usize> {
        zbus::connection::HostLaunchConnectionOriginalV2::effect_write_gate_receiving_bytes_v3()
    }

    /// Borrows the immutable native-attempt limit of this prearmed original.
    #[must_use]
    pub fn effect_write_attempt_limit_v3(&self) -> Option<usize> {
        self.native.effect_write_attempt_limit_v3()
    }

    /// Arms the actual caller's finite original-clock gate before connection.
    ///
    /// Only StartTransientUnit and StopUnit writes use this gate. Every reached
    /// syscall, including readiness/partial-write retries, consumes one of the
    /// same prepaid attempts; AUTH and independently owed disposition retain
    /// their original behavior. The gate supplies no effect permission.
    ///
    /// # Errors
    /// Retains the exact raw returned error and refuses reentry, zero capacity
    /// or an entered/failed connection. No spent attempt is restored.
    pub fn arm_effect_write_gate_v3(
        &mut self, gate: Arc<dyn HostLaunchEffectWriteGateV3>, maximum_attempts: usize,
    ) -> Result<()> {
        if self.entered || self.failure.is_some() {
            return Err(Error::HostLaunchRetained("effect write gate reentry"));
        }
        match self.native.arm_effect_write_gate_v3(gate, maximum_attempts) {
            Ok(()) => Ok(()),
            Err(cause) => {
                let returned = Error::SystemdUnavailable(cause);
                self.native_selected = self.native_failure_for_returned_v2(&returned)
                    .is_ok_and(|original| original.is_some());
                self.failure = Some(returned);
                Err(Error::HostLaunchRetained("effect write gate"))
            }
        }
    }

    /// Connects once, then runs the original Manager/Subscribe/stream recipe.
    ///
    /// # Errors
    /// Returns a closed marker while retaining the actual native or SDK cause,
    /// reached manager/stream prefix and the same original socket. `deadline`
    /// only bounds IO; the real caller derives it from its original cutoff.
    pub async fn connect_once_v2(&mut self, deadline: tokio::time::Instant) -> Result<()> {
        if self.entered || self.failure.is_some() { return Err(Error::HostLaunchRetained("connection reentry")); }
        self.entered = true;
        let mut cancellation = self.native.cancellation_fence_v2();
        let result = tokio::time::timeout_at(deadline, async {
            self.native.connect_once_v2(deadline).await.map_err(Error::SystemdUnavailable)?;
            let conn = self.native.connection_v2().ok_or(Error::HostLaunchRetained("connection missing"))?.clone();
            self.setup.connection = Some(conn.clone());
            let (bus, name, owner) = super::service_properties::capture_pid1_owner_v2(&conn).await?;
            self.setup.identity_bus = Some(bus);
            self.setup.identity_name = Some(name);
            self.setup.identity_owner = Some(owner.clone());
            let manager = ManagerProxy::builder(&conn).destination(owner)?
                .cache_properties(CacheProperties::No).build().await?;
            // The common recipe parks the actual manager before Subscribe.
            Self::construct_client(conn, manager, &mut self.setup).await
        }).await.unwrap_or_else(|_| Err(Error::ExactUnitTimeout("connection setup")));
        match result {
            Ok(client) => { self.client = Some(client); cancellation.complete(); Ok(()) }
            Err(error) => {
                // Select only this exact returned native marker at the actual
                // constructor frontier. A generic SDK error cannot borrow a
                // later independently owed cleanup failure.
                self.native_selected = self.native_failure_for_returned_v2(&error)
                    .is_ok_and(|original| original.is_some());
                self.failure = Some(error);
                self.native.end_v2();
                Err(Error::HostLaunchRetained("connection"))
            }
        }
    }

    async fn construct_client(conn: zbus::Connection, manager: ManagerProxy<'static>, state: &mut SetupOriginalV2) -> Result<SystemdClient> {
        systemd_setup_recipe!(Retained, state, conn, manager)
    }

    /// Borrows the same actual connected client without a second native open.
    #[must_use]
    pub fn client_v2(&self) -> Option<&SystemdClient> { self.client.as_ref() }

    /// Borrows the actual constructor error at its returned first frontier.
    #[must_use]
    pub fn constructor_failure_v2(&self) -> Option<&Error> { self.failure.as_ref() }

    /// Reports whether that first returned frontier selected the raw native cause.
    #[must_use]
    pub fn native_failure_is_selected_v2(&self) -> bool { self.native_selected }

    /// Borrows the same resident socket/AUTH/raw parser cause.
    ///
    /// # Errors
    /// Reports an unavailable native slot instead of resetting poisoned custody.
    pub fn native_failure_v2(&self) -> std::result::Result<Option<zbus::connection::socket::LauncherImageFailureLoanV1<'_>>,
        zbus::connection::socket::LauncherImageFailureUnavailableV1> { self.native.failure_v2() }

    /// Borrows a native cause only for this original's exact returned marker.
    ///
    /// Earlier guard/property/semantic errors and markers from another original
    /// never select a later raw failure. The actual returned error remains the
    /// caller's chronological result; this only exposes its resident source.
    ///
    /// # Errors
    /// Reports unavailable native custody instead of healing or observing it.
    pub fn native_failure_for_returned_v2(&self, returned: &Error) -> std::result::Result<
        Option<zbus::connection::socket::LauncherImageFailureLoanV1<'_>>,
        zbus::connection::socket::LauncherImageFailureUnavailableV1>
    {
        let raw = match returned {
            Error::Zbus(cause) | Error::SystemdUnavailable(cause) => Some(cause),
            Error::Fdo(zbus::fdo::Error::ZBus(cause)) => Some(cause),
            _ => None,
        };
        if !raw.is_some_and(|cause| self.native.matches_returned_failure_v2(cause)) {
            return Ok(None);
        }
        let original = self.native.failure_v2()?;
        if original.as_ref().is_some_and(|cause| matches!(cause.cause(),
            zbus::connection::socket::LauncherImageFailureRefV1::Ended))
        { return Ok(None); }
        Ok(original)
    }

    /// Transfers the same disposable connection into the existing exact engine.
    ///
    /// No new connection or native shutdown descriptor is created. The caller
    /// retains this original and the returned operation result through all posts,
    /// then joins its actual SDK tasks with `finish_connection_once_v2`.
    ///
    /// # Errors
    /// Rejects missing/failed connection setup, repeated transfer or disposition.
    pub fn take_exact_client_once_v2(&mut self) -> Result<crate::ExactUnitClient> {
        if self.exact_taken || self.disposed || self.failure.is_some() {
            return Err(Error::HostLaunchRetained("exact connection transfer refused"));
        }
        let client = self.client.take()
            .ok_or(Error::HostLaunchRetained("connected client missing"))?;
        self.exact_taken = true;
        Ok(crate::ExactUnitClient::from_host_launch_v2(
            client, self.native.cancellation_fence_v2(),
        ))
    }

    /// Closes the same connection and joins its two actual SDK tasks once.
    ///
    /// This is an owed negative-capable disposition. Its fixed timeout does not
    /// extend any positive launch deadline. Exact operations already close their
    /// same connection; this entry then only joins the actual parked handles.
    /// The original must remain resident through independent upper posts.
    ///
    /// # Errors
    /// Refuses reentry or a missing client, pending job, or failed physical
    /// disposition. All reached outcomes remain in their prearmed destinations.
    pub async fn finish_connection_once_v2(&mut self) -> Result<()> {
        if self.disposed { return Err(Error::HostLaunchRetained("disposition reentry")); }
        self.disposed = true;
        let mut first = None;
        if let Some(client) = self.client.as_ref() {
            // Arm both destinations before the first native entry. The close
            // remains independently owed when Unsubscribe or job checks fail.
            let unsubscribe = client.arm_host_disposition_v2("Unsubscribe reply")?;
            let close = client.arm_host_disposition_v2("connection close")?;
            {
                match client.jobs.lock() {
                    Ok(jobs) if !jobs.waiters.is_empty() => {
                        first = Some(Error::HostLaunchRetained("job reply pending"));
                    }
                    Err(_) => { first = Some(Error::HostLaunchRetained("jobs borrowed")); }
                    Ok(_) => {}
                }
            }
            let result = tokio::time::timeout(
                Duration::from_secs(5), client.manager.unsubscribe(),
            ).await.map_err(|_| Error::ExactUnitTimeout("Unsubscribe reply"))
                .and_then(|result| result.map_err(Error::from));
            let result = match unsubscribe {
                Some(slot) => slot.complete(result),
                None => result,
            };
            if first.is_none() { first = result.err(); }

            let streams = client.finish_host_streams_v2().await;
            if first.is_none() { first = streams.err(); }

            let result = tokio::time::timeout(
                Duration::from_secs(5), client.conn.clone().close(),
            ).await.map_err(|_| Error::ExactUnitTimeout("connection close"))
                .and_then(|result| result.map_err(Error::from));
            let result = match close {
                Some(slot) => slot.complete(result),
                None => result,
            };
            if first.is_none() { first = result.err(); }
        } else if !self.exact_taken {
            first = Some(Error::HostLaunchRetained("client missing"));
        }
        if self.client.is_none() {
            let streams = finish_streams_v2(&self.setup.disposition).await;
            if first.is_none() { first = streams.err(); }
        }
        self.native.end_v2();
        // The selected client never owns detached handles. The task field
        // and actual joined Results remain in this original through posts.
        drop(self.client.take());
        let original = self.disposition_failure_v2()
            .map_err(|_| Error::HostLaunchRetained("disposition borrowed"))?;
        if first.is_none() && original.cause_v2().is_some() {
            first = Some(Error::HostLaunchRetained("disposition"));
        }
        let closed = original.0.outcomes.iter().any(|outcome|
            outcome.stage == "connection close" && matches!(outcome.result.get(), Some(Ok(()))));
        let all_outcomes_complete = original.0.outcomes.iter().all(|outcome| outcome.result.get().is_some());
        if (!closed || !all_outcomes_complete || !original.0.task_results.iter().all(|result| matches!(result.get(), Some(Ok(()))))) && first.is_none() {
            first = Some(Error::HostLaunchRetained("native disposition incomplete"));
        }
        drop(original);
        if first.is_none() {
            match self.native.failure_v2() {
                Ok(Some(cause)) if matches!(cause.cause(),
                    zbus::connection::socket::LauncherImageFailureRefV1::Ended) => {}
                Ok(Some(_)) => {
                    self.disposition_native_selected = true;
                    first = Some(Error::HostLaunchRetained("native disposition"));
                }
                Err(_) => { first = Some(Error::HostLaunchRetained("native custody unavailable")); }
                Ok(None) => {}
            }
        }
        match first {
            Some(error) => Err(error),
            None => { self.completed_disposition = true; Ok(()) }
        }
    }

    /// Prepares physical disposal after this actual completed native interval.
    ///
    /// The real Host caller first completes every independent upper post and
    /// verifies its matching private financial/native phase. This token only
    /// disposes these actual native leaves; it supplies no authority or credit.
    ///
    /// # Errors
    /// Rejects incomplete/failed disposition or repeated native disposal. The
    /// original's native end, schedule and financial association never reset.
    pub fn prepare_positive_native_disposal_v2(&mut self) -> Result<HostSystemdNativeDisposalV2<'_>> {
        if !self.completed_disposition || self.failure.is_some() || self.native_disposal_entered {
            return Err(Error::HostLaunchRetained("positive native disposal refused"));
        }
        {
            let disposition = self.setup.disposition.try_lock()
                .map_err(|_| Error::HostLaunchRetained("native disposition borrowed"))?;
            if disposition.spawned_tasks != 2
                || !disposition.task_results.iter().all(|result| matches!(result.get(), Some(Ok(()))))
            {
                return Err(Error::HostLaunchRetained("SDK task results incomplete"));
            }
            let tasks = disposition.tasks.try_lock()
                .map_err(|_| Error::HostLaunchRetained("SDK task originals borrowed"))?;
            if tasks.len() != 2 || tasks.iter().any(|task| task.handle.is_some()) {
                return Err(Error::HostLaunchRetained("SDK task originals incomplete"));
            }
        }
        self.native_disposal_entered = true;
        Ok(HostSystemdNativeDisposalV2 { original: self })
    }

    /// Releases completed transport buffers after the same native disposal proof.
    ///
    /// All local caller bookends/unit/readback/reference operations and the
    /// genuine matching private phase must already be positive. Returned
    /// semantic results are independently owned and separately priced; none
    /// borrow these transport buffers. The whole Launch after stays owed.
    ///
    /// # Errors
    /// Refuses reentry, mismatched/incomplete local outcomes or incoming native
    /// aliases. Failed/ambiguous originals keep their storage and actual cause.
    pub fn compact_positive_storage_once_v2(&mut self, proof: HostSystemdNativeDisposedV2)
        -> Result<HostSystemdStorageCompactedV2>
    {
        if self.storage_compaction_entered || !self.completed_disposition
            || self.failure.is_some() || self.client.is_some()
            || self.setup.connection.is_some() || self.setup.manager.is_some()
            || self.setup.identity_bus.is_some() || self.setup.job_removed.is_some()
            || self.setup.reloading_stream.is_some() || self.setup.jobs.is_some()
            || self.setup.reloading.is_some() || self.setup.event_tx.is_some()
            || self.setup.event_rx.is_some()
        {
            return Err(Error::HostLaunchRetained("positive storage compaction refused"));
        }
        self.storage_compaction_entered = true;
        {
            let disposition = self.setup.disposition.try_lock()
                .map_err(|_| Error::HostLaunchRetained("compaction disposition borrowed"))?;
            if disposition.spawned_tasks != 2
                || disposition.task_results.iter().any(|result| !matches!(result.get(), Some(Ok(()))))
                || disposition.outcomes.iter().any(|outcome| !matches!(outcome.result.get(), Some(Ok(()))))
            { return Err(Error::HostLaunchRetained("compaction outcomes incomplete")); }
            let tasks = disposition.tasks.try_lock()
                .map_err(|_| Error::HostLaunchRetained("compaction task originals borrowed"))?;
            if tasks.len() != 2 || tasks.iter().any(|task| task.handle.is_some()) {
                return Err(Error::HostLaunchRetained("compaction task originals incomplete"));
            }
        }
        let native = self.native.compact_positive_storage_once_v2(proof.native)
            .map_err(|_| Error::HostLaunchRetained("native storage compaction"))?;
        // Owned unique-name copies are no longer borrowed by a task/proxy or
        // method result. All semantic outputs own their separate decoded DATA.
        drop(self.setup.identity_name.take());
        drop(self.setup.identity_owner.take());
        Ok(HostSystemdStorageCompactedV2 { native })
    }

    /// Borrows the same actual native/storage compaction refusal without IO.
    #[must_use]
    pub fn storage_compaction_failure_v2(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.native.storage_compaction_failure_v2()
    }

    /// Borrows the actual socket-reader/unique native disposition refusal.
    #[must_use]
    pub fn native_disposal_failure_v2(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.native.native_disposal_failure_v2()
    }

    /// Reports an actual selected raw source at the final disposition frontier.
    ///
    /// Earlier primary and stored SDK errors remain selected by their callers.
    #[must_use]
    pub fn native_disposition_failure_is_selected_v2(&self) -> bool {
        self.disposition_native_selected
    }

    /// Borrows real retained release/close/task outcomes without performing IO.
    ///
    /// # Errors
    /// Refuses an unavailable disposition slot without recovering its mutex.
    pub fn disposition_failure_v2(&self) -> std::result::Result<HostSystemdDispositionFailureLoanV2<'_>, HostSystemdDispositionUnavailableV2> {
        self.setup.disposition.try_lock().map(HostSystemdDispositionFailureLoanV2)
            .map_err(|_| HostSystemdDispositionUnavailableV2)
    }
}

/// Owns one non-Clone local native-disposal opportunity on the same original.
pub struct HostSystemdNativeDisposalV2<'original> {
    original: &'original mut HostSystemdConnectionOriginalV2,
}

impl HostSystemdNativeDisposalV2<'_> {
    /// Joins the actual reader and closes unique socket/message FD leaves once.
    ///
    /// Prepared-property and other upper native owners are independent and must
    /// retire only at their matching genuine positive frontier. This never
    /// refunds a ledger or changes spent traffic, bytes, serials or end state.
    ///
    /// # Errors
    /// Retains the original and actual cause on an outstanding alias, reader
    /// failure, incomplete shutdown or refused physical socket/message disposal.
    pub async fn dispose_once_v2(self) -> Result<HostSystemdNativeDisposedV2> {
        let original = self.original;
        if original.client.is_some() || original.setup.job_removed.is_some()
            || original.setup.reloading_stream.is_some()
        {
            return Err(Error::HostLaunchRetained("SDK native aliases still entered"));
        }
        // These exact aliases have passed all local outcomes and upper posts.
        // The raw original keeps the socket until its exclusive checked close.
        drop(original.setup.identity_bus.take());
        drop(original.setup.manager.take());
        drop(original.setup.connection.take());
        let native = original.native.retire_positive_native_once_v2().await
            .map_err(|_| Error::HostLaunchRetained("native physical disposal"))?;
        Ok(HostSystemdNativeDisposedV2 { native })
    }
}

/// Binds actual physical native retirement to the same completed SDK original.
///
/// This non-Clone resource-disposal proof creates no semantic or financial grant.
pub struct HostSystemdNativeDisposedV2 {
    native: zbus::connection::HostLaunchNativeDisposedV2,
}

impl HostSystemdNativeDisposedV2 {
    /// Checks the actual native original identity without observing anything.
    #[must_use]
    pub fn belongs_to_v2(&self, original: &HostSystemdConnectionOriginalV2) -> bool {
        self.native.belongs_to_v2(&original.native)
    }
}

/// Binds completed buffer disposal to the same actual SDK/native original.
///
/// This non-Clone transport-storage proof creates no semantic or financial grant.
pub struct HostSystemdStorageCompactedV2 {
    native: zbus::connection::HostLaunchStorageCompactedV2,
}

impl HostSystemdStorageCompactedV2 {
    /// Checks the exact compacted origin without observing or granting anything.
    #[must_use]
    pub fn belongs_to_v2(&self, original: &HostSystemdConnectionOriginalV2) -> bool {
        original.storage_compaction_entered && self.native.belongs_to_v2(&original.native)
    }
}

/// Borrows the real same-connection disposal outcomes without a retry/reset.
pub struct HostSystemdDispositionFailureLoanV2<'owner>(std::sync::MutexGuard<'owner, HostSystemdDispositionV2>);

impl HostSystemdDispositionFailureLoanV2<'_> {
    /// Borrows a stored source only for its actual returned cleanup marker.
    ///
    /// An earlier guard, identity, property, or job error remains the caller's
    /// selected source; a later owed cleanup error cannot replace that cause.
    #[must_use]
    pub fn cause_for_returned_v2(&self, returned: &Error) -> Option<&(dyn std::error::Error + 'static)> {
        let Error::HostLaunchRetained(stage) = returned else { return None; };
        if *stage == "disposition" { return self.cause_v2(); }
        self.0.outcomes.iter().find_map(|outcome| {
            if outcome.stage != *stage { return None; }
            outcome.cause_v2()
        })
    }

    /// Borrows the earliest stored physical release/close/task error.
    #[must_use]
    pub fn cause_v2(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(outcome) = self.0.first_failure.get() {
            if let Some(cause) = outcome.cause_v2() { return Some(cause); }
        }
        self.0.task_results.iter().filter_map(|result| result.get().and_then(|result| result.as_ref().err()))
            .next().map(|error| error as _)
    }
}

/// Reports unavailable custody without recovering or replacing its contents.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("retained Systemd disposition is borrowed or poisoned")]
pub struct HostSystemdDispositionUnavailableV2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_call_rosters_include_constructor_disposition_jobs_and_noise() {
        for (call, outgoing, jobs, files) in [
            (HostSystemdCallV2::GuardianStart, 10, 1, 11),
            (HostSystemdCallV2::PayloadStart, 33, 1, 7),
            (HostSystemdCallV2::ExactObserve, 22, 0, 0),
            (HostSystemdCallV2::PostUnrefObserve, 19, 0, 0),
            (HostSystemdCallV2::ExactStop, 33, 1, 0),
            (HostSystemdCallV2::SandboxObserve, 22, 0, 0),
        ] {
            let schedule = call.receiving_schedule_v2(65536, 65536, 65536, 9).unwrap();
            let raw = schedule.raw_data_v2();
            assert_eq!(raw.outgoing_messages(), outgoing);
            assert_eq!(raw.incoming_messages(), outgoing + jobs + 3 + 9);
            // The native connect original retains one additional same-OFD alias.
            assert_eq!(schedule.maximum_native_files_v2(), Some(5 + files));
            let footprint = HostSystemdConnectionOriginalV2::receiving_footprint_v2(schedule).unwrap();
            assert!(footprint.memory_bytes > schedule.receiving_storage_bytes_v2().unwrap());
            assert_eq!(footprint.open_files, 5 + files);
        }
        assert!(HostSystemdCallV2::ExactObserve.receiving_schedule_v2(65536, 65536, 65536, usize::MAX).is_err());
    }

    #[test]
    fn completion_order_selects_actual_earlier_cause_before_prearmed_close() {
        let original = Arc::new(Mutex::new(HostSystemdDispositionV2::new()));
        let close = arm_disposition_v2(&original, "connection close").unwrap();
        let stream = arm_disposition_v2(&original, "stream task completion").unwrap();

        assert!(stream.complete(Err(Error::ExactUnitTimeout("earlier stream"))).is_err());
        assert!(close.complete(Err(Error::ExactUnitTimeout("later close"))).is_err());

        let loan = HostSystemdDispositionFailureLoanV2(original.lock().unwrap());
        assert!(matches!(loan.cause_v2().unwrap().downcast_ref::<Error>(),
            Some(Error::ExactUnitTimeout("earlier stream"))));
        assert!(loan.cause_for_returned_v2(&Error::InvalidSandboxUnit("earlier primary".to_owned())).is_none());
        assert!(matches!(loan.cause_for_returned_v2(&Error::HostLaunchRetained("connection close"))
            .unwrap().downcast_ref::<Error>(), Some(Error::ExactUnitTimeout("later close"))));
    }

    #[tokio::test]
    async fn cancellation_keeps_the_same_unjoined_handle_in_the_native_owner() {
        let original = Arc::new(Mutex::new(HostSystemdDispositionV2::new()));
        let (tasks, result) = {
            let mut owner = original.lock().unwrap();
            owner.spawned_tasks = 1;
            (Arc::clone(&owner.tasks), Arc::clone(&owner.task_results[0]))
        };
        let handle = tokio::spawn(std::future::pending::<()>());
        let actual_id = handle.id();
        tasks.lock().await.push(HostSystemdTaskV2 { handle: Some(handle), result });

        let cancelled = tokio::time::timeout(Duration::ZERO, finish_streams_v2(&original)).await;
        assert!(cancelled.is_err());
        let mut tasks = tasks.lock().await;
        let task = &mut tasks[0];
        let handle = task.handle.as_mut().unwrap();
        assert_eq!(handle.id(), actual_id);
        assert!(task.result.get().is_none());

        // Fixture cleanup consumes the very same handle. Production keeps the
        // cancelled original quarantined rather than resetting its once state.
        handle.abort();
        let result = (&mut *handle).await;
        assert!(result.as_ref().unwrap_err().is_cancelled());
        task.result.set(result).unwrap();
        drop(task.handle.take());
    }

    #[tokio::test]
    async fn entered_stream_finish_is_insufficient_without_both_real_join_results() {
        let schedule = HostSystemdCallV2::ExactObserve.receiving_schedule_v2(65536, 65536, 65536, 1).unwrap();
        let mut original = HostSystemdConnectionOriginalV2::new(schedule);
        // Even an accidentally repeated outer completion cannot stand in for
        // the actual two resident task Results and disposed handle originals.
        original.completed_disposition = true;
        original.setup.disposition.lock().unwrap().streams_finished = true;

        assert!(original.prepare_positive_native_disposal_v2().is_err());
        assert!(!original.native_disposal_entered);

        let disposition = Arc::clone(&original.setup.disposition);
        let mut owner = disposition.lock().unwrap();
        owner.spawned_tasks = 2;
        owner.task_results[0].set(Ok(())).unwrap();
        assert!(owner.task_results[1].get().is_none());
        drop(owner);
        assert!(original.prepare_positive_native_disposal_v2().is_err());
        assert!(!original.native_disposal_entered);
    }

}

#[cfg(test)]
mod aggregate_request_tests {
    use super::*;

    #[test]
    fn one_property_request_is_not_multiplied_by_fixed_rpc_count() {
        let fixed = HostSystemdCallV2::fixed_request_wire_bytes_v2().unwrap();
        for call in [HostSystemdCallV2::GuardianStart, HostSystemdCallV2::PayloadStart,
            HostSystemdCallV2::ExactObserve, HostSystemdCallV2::PostUnrefObserve,
            HostSystemdCallV2::ExactStop, HostSystemdCallV2::SandboxObserve]
        {
            let schedule = call.receiving_schedule_with_request_bounds_v2(
                4096, 128 * 1024, fixed, 4096, 0).unwrap();
            let count = schedule.raw_data_v2().outgoing_messages();
            let property = matches!(call, HostSystemdCallV2::GuardianStart | HostSystemdCallV2::PayloadStart);
            assert_eq!(schedule.maximum_outgoing_wire_bytes_v2(),
                if property { 128 * 1024 + (count - 1) * fixed } else { count * fixed });
            let footprint = HostSystemdConnectionOriginalV2::receiving_footprint_v2(schedule).unwrap();
            assert_eq!(footprint.network_bytes, schedule.maximum_outgoing_wire_bytes_v2()
                + schedule.raw_data_v2().incoming_messages() * 4096
                + 2 * zbus::connection::ControllerPropertyReceiveAttemptV1::AUTH_BYTES);
        }
        assert!(HostSystemdCallV2::PayloadStart.receiving_schedule_with_request_bounds_v2(
            4096, usize::MAX, fixed, 4096, 0).is_err());
    }
}

#[cfg(test)]
mod constructor_native_marker_tests {
    use super::*;

    #[test]
    fn generic_constructor_errors_never_select_normal_ended_custody() {
        let schedule = HostSystemdCallV2::ExactObserve
            .receiving_schedule_v2(4096, 4096, 4096, 0).unwrap();
        let original = HostSystemdConnectionOriginalV2::new(schedule);
        original.native.end_v2();
        for returned in [Error::Zbus(zbus::Error::InvalidReply),
            Error::SystemdUnavailable(zbus::Error::InvalidReply),
            Error::HostLaunchRetained("earlier SDK guard")]
        {
            assert!(original.native_failure_for_returned_v2(&returned).unwrap().is_none());
        }
    }
}

#[cfg(test)]
mod task_join_cause_tests {
    use super::*;

    async fn cancelled_join() -> tokio::task::JoinError {
        let mut handle = tokio::spawn(std::future::pending::<()>());
        handle.abort();
        (&mut handle).await.unwrap_err()
    }

    #[tokio::test]
    async fn actual_earlier_join_error_survives_later_same_stage_timeout() {
        let original = Arc::new(Mutex::new(HostSystemdDispositionV2::new()));
        let joined = Arc::clone(&original.lock().unwrap().task_results[0]);
        let first = arm_task_disposition_v2(&original, &joined).unwrap();
        let actual = cancelled_join().await;
        let task_id = actual.id();
        assert!(first.complete_join_v2(Err(actual)).is_err());
        let stored = std::ptr::from_ref(joined.get().unwrap().as_ref().unwrap_err());
        let later = arm_disposition_v2(&original, "stream task completion").unwrap();
        assert!(later.complete(Err(Error::ExactUnitTimeout("later stream"))).is_err());

        let loan = HostSystemdDispositionFailureLoanV2(original.lock().unwrap());
        for cause in [loan.cause_v2(), loan.cause_for_returned_v2(
            &Error::HostLaunchRetained("stream task completion"))]
        {
            let actual = cause.unwrap().downcast_ref::<tokio::task::JoinError>().unwrap();
            assert!(actual.is_cancelled());
            assert_eq!(actual.id(), task_id);
            assert_eq!(std::ptr::from_ref(actual), stored);
        }
    }

    #[tokio::test]
    async fn actual_timeout_precedes_its_owed_abort_join_result() {
        let original = Arc::new(Mutex::new(HostSystemdDispositionV2::new()));
        let joined = Arc::clone(&original.lock().unwrap().task_results[0]);
        let slot = arm_task_disposition_v2(&original, &joined).unwrap();
        assert!(slot.complete(Err(Error::ExactUnitTimeout("stream task completion"))).is_err());
        joined.set(Err(cancelled_join().await)).unwrap();

        let loan = HostSystemdDispositionFailureLoanV2(original.lock().unwrap());
        assert!(matches!(loan.cause_for_returned_v2(
            &Error::HostLaunchRetained("stream task completion"))
            .unwrap().downcast_ref::<Error>(), Some(Error::ExactUnitTimeout("stream task completion"))));
        assert!(joined.get().unwrap().as_ref().unwrap_err().is_cancelled());
    }
}
