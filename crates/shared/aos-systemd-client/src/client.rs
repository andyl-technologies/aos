//! `SystemdClient` — a typed async client for `org.freedesktop.systemd1`.
//!
//! One [`SystemdClient`] is constructed per apm invocation. It owns a single
//! `zbus::Connection`, subscribes to manager signals, and runs background
//! tasks that forward `JobRemoved` / `Reloading` events into shared state.
//! Method callers `await` on a per-job oneshot; the stream task owns the
//! signal stream continuously, dodging the "stream not polled" hang.
//!
//! The selected Controller property owner retains one readonly, unsubscribed
//! attempt. Its bounded transport and whole Results are DATA, not paid authority.

use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::StreamExt;
use tokio::sync::{Mutex as AsyncMutex, mpsc, oneshot};
use tokio::task::JoinHandle;
use zbus::proxy::CacheProperties;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

use crate::error::{Error, Result, is_no_such_unit};
use crate::manager_proxy::{ListUnitsEntry, ManagerProxy, ServiceProxy, UnitProxy};

#[cfg(target_os = "linux")]
pub use host_launch::{HostSystemdCallV2, HostLaunchEffectWriteGateV3, HostSystemdConnectionOriginalV2, HostSystemdConnectionFootprintV2,
    HostSystemdNativeDisposalV2, HostSystemdNativeDisposedV2, HostSystemdStorageCompactedV2,
    HostSystemdDispositionFailureLoanV2, HostSystemdDispositionUnavailableV2, HostLaunchReceiveScheduleV2};
mod service_properties;
pub use service_properties::{ServicePropertiesReadOriginalV2, ServicePropertiesReadClosedV2,
    ServiceControlGroupReadOriginalV2};
mod fixed_property;
#[cfg(target_os = "linux")]
mod readonly_manager;

#[cfg(target_os = "linux")]
mod host_inventory;
#[cfg(target_os = "linux")]
pub use host_inventory::{HostRuntimeDiscoveryOriginalV5, HostRuntimeDiscoveryRefusalV5, NetworkWorkerCensusOriginalV4, NetworkWorkerCensusRefusalV4};
#[cfg(target_os = "linux")]
pub use readonly_manager::{ReadonlyPropertyManagerOriginalV2, ReadonlyPropertyReceiveScheduleV2};
#[cfg(target_os = "linux")]
mod property_worker;
#[cfg(target_os = "linux")]
pub use property_worker::{
    SharedFixedPid1PropertyProviderV1,
    FixedPid1PropertyArchiveV1, FixedPid1PropertyErrorV1, FixedPid1PropertyGrowthErrorV1,
    FixedPid1PropertyGeometryV1, FixedPid1PropertyValuesV1, FixedPid1PropertyActionOutcomeV1,
    FixedPid1PropertyFailureViewV1, FixedPid1PropertyJoinOutcomeV1, FixedPid1PropertyWorkerSlotV1,
};
pub(crate) use service_properties::{
    ServicePropertyBookendV1, capture_mount_fd_store_bookend_v1,
};
mod git_source_socket;
pub use git_source_socket::GitSourceSocketObservationV1;
#[cfg(target_os = "linux")]
mod source_launcher_image;
#[cfg(target_os = "linux")]
pub use source_launcher_image::{
    CompletedOwnUnitPid1ImageV1, OwnUnitPid1ImageAttemptV1,
    OwnUnitPid1ImageEndedV1, OwnUnitPid1ImageFailureV1,
};

#[macro_use]
mod connection_recipe;

#[cfg(target_os = "linux")]
mod host_launch;

/// Selects one fixed service observed by Controller's startup owner.
///
/// This DATA selector grants no service authority or kernel cgroup identity.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerAttachmentServiceV1 {
    /// Selects the installed Host broker's exact unit.
    Host,
    /// Selects the installed Mount broker's exact unit.
    Mount,
}

#[cfg(target_os = "linux")]
impl ControllerAttachmentServiceV1 {
    fn unit_name(self) -> &'static str {
        match self {
            Self::Host => "aos-sandbox-hostd.service",
            Self::Mount => "aos-sandbox-mountd.service",
        }
    }
}

#[cfg(target_os = "linux")]
enum FixedServicePropertyQueryV1<'query> {
    Startup { name: &'query str, pid: u32, service: &'query [&'query str], unit: &'query [&'query str] },
    Ownership,
}

#[cfg(target_os = "linux")]
enum ControllerServiceQueryV1 {
    Attachment(ControllerAttachmentServiceV1),
    Publisher,
}

/// Retains one readonly Controller/PID-1 property observation and its originals.
///
/// The caller creates this DATA owner before spawning or entering a prepaid
/// observation. Whole constructor/property Results and the original bounded
/// transport survive returned errors and cancellation; this type issues no
/// resource payment, peer authority, currentness or permission.
#[cfg(target_os = "linux")]
pub struct ControllerPropertyObserverAttemptV1 {
    transport: zbus::connection::ControllerPropertyReceiveAttemptV1,
    constructor: Option<Result<Option<SystemdClient>>>,
    properties: Option<Result<(Arc<Vec<OwnedValue>>, Arc<Vec<OwnedValue>>)>>,
    control_group: Option<Result<ServiceControlGroupObservation>>,
    publisher_control_group: Option<Result<Option<ServiceControlGroupObservation>>>,
    connect_attempted: bool,
    observe_attempted: bool,
}

#[cfg(target_os = "linux")]
impl ControllerPropertyObserverAttemptV1 {
    /// Maximum bytes in one retained message, checked before frame growth.
    pub const MESSAGE_BYTES: usize =
        zbus::connection::ControllerPropertyReceiveAttemptV1::MESSAGE_BYTES;
    /// Maximum aggregate raw AUTH receive bytes.
    pub const AUTH_BYTES: usize =
        zbus::connection::ControllerPropertyReceiveAttemptV1::AUTH_BYTES;
    /// Maximum incoming frames retained by one original.
    pub const INCOMING_MESSAGES: usize =
        zbus::connection::ControllerPropertyReceiveAttemptV1::INCOMING_MESSAGES;
    /// Maximum outgoing messages, including the one Hello.
    pub const OUTGOING_MESSAGES: usize =
        zbus::connection::ControllerPropertyReceiveAttemptV1::OUTGOING_MESSAGES;
    /// Default raw receive-prefix byte capacity, separate from framed messages.
    pub const RAW_PREFIX_BYTES: usize =
        zbus::connection::ControllerPropertyReceiveAttemptV1::RAW_PREFIX_BYTES;

    /// Reports the same native constructor's raw-prefix and frame byte widths.
    ///
    /// These passive DATA include raw carryover/reallocation overlap. They
    /// create no transport, original, grant, decoder or allocator proof.
    #[must_use]
    pub fn raw_receive_bytes_for_materialization(maximum: usize) -> (usize, usize) {
        zbus::connection::ControllerPropertyReceiveAttemptV1::
            raw_receive_bytes_for_materialization(maximum)
    }

    /// Returns this owner's inline representation size, not its heap/peak demand.
    #[must_use]
    pub fn inline_bytes() -> usize {
        std::mem::size_of::<Self>()
    }

    /// Reports the two actual successful property's shared Vec/control owners.
    ///
    /// Element storage is separate. This passive layout DATA creates neither
    /// a property read nor resource authority, and includes no heap estimate.
    #[must_use]
    pub fn shared_property_owner_bytes_v1() -> usize {
        2 * (std::mem::size_of::<Vec<OwnedValue>>() + 2 * std::mem::size_of::<usize>())
    }

    /// Reports decoded storage for the actual small selected property schema.
    ///
    /// Includes concrete decoder growth, moved table values, dynamic tuple
    /// signatures, hostile bounded header signatures and partial-record slack.
    /// Raw/native/runtime/request storage is separate. This passive DATA does
    /// not admit a read, identify a payer or measure allocator internals.
    /// Returns `None` on overflow or outside the existing one-message small
    /// materialization lane. Default/full and ordinary budgets are unchanged.
    #[must_use]
    pub fn fixed_property_decoded_geometry_v1(materialized_bytes: usize)
        -> Option<(usize, usize)>
    {
        fixed_property::decoded_geometry_v1(materialized_bytes)
    }

    /// Prearms one fixed DATA attempt without opening a socket or spawning a task.
    ///
    /// The bounded transport storage is real resident allocation, not a payment
    /// proof. A genuine caller-owned resource interval must precede this call.
    #[must_use]
    pub fn empty() -> Self {
        Self::with_materialization_limit(Self::MESSAGE_BYTES * Self::INCOMING_MESSAGES)
    }

    /// Restricts raw frame bytes admitted to dynamic property materialization.
    ///
    /// This is a nonauthorizing DATA ceiling. A genuine caller must separately
    /// price raw capture, runtime, native paths and decoder/value/error storage
    /// before constructing this attempt. The original transport and property
    /// Results remain resident on refusal; no wire ceiling changes.
    #[must_use]
    pub fn with_materialization_limit(maximum_materialized_frame_bytes: usize) -> Self {
        Self {
            transport: zbus::connection::ControllerPropertyReceiveAttemptV1::with_materialization_limit(
                maximum_materialized_frame_bytes,
            ),
            constructor: None,
            properties: None,
            control_group: None,
            publisher_control_group: None,
            connect_attempted: false,
            observe_attempted: false,
        }
    }

    /// Reports admitted raw bytes, their ceiling and any first refused increment.
    ///
    /// This borrows numeric transport DATA without extracting the Connection.
    #[must_use]
    pub fn materialization_extent(&self) -> (usize, usize, Option<usize>) {
        self.transport.materialization_extent()
    }

    /// Constructs one readonly client on the fixed system bus without Subscribe.
    ///
    /// # Errors
    /// Refuses repeated/fenced entry. The actual constructor Result stays in
    /// this owner; the returned refusal does not replace its native cause.
    ///
    /// # Panics
    /// Panics if polled outside a Tokio runtime with its I/O driver enabled.
    pub async fn connect(&mut self) -> Result<()> {
        let mut cancellation = self.transport.cancellation_fence();
        if self.connect_attempted || self.transport.has_ended() {
            self.transport.end();
            return Err(Error::Zbus(zbus::Error::InvalidReply));
        }
        self.connect_attempted = true;

        self.constructor = Some(self.connect_inner().await.map(Some));
        if matches!(self.constructor.as_ref(), Some(Err(_))) {
            self.transport.end();
            return Err(Error::Zbus(zbus::Error::InvalidReply));
        }
        cancellation.complete();
        Ok(())
    }

    async fn connect_inner(&mut self) -> Result<SystemdClient> {
        let conn = self.transport.connect().await.map_err(Error::SystemdUnavailable)?;
        SystemdClient::readonly_from_connection_v2(conn).await
    }

    /// Performs one shared startup-property kernel with authentic PID-1 bookends.
    ///
    /// No proxy cache, subscription, listener or background job task is entered.
    /// Each separate profile requires its own prepaid attempt; this flight
    /// retains the fixed 30-property-RPC-plus-Hello ceiling.
    ///
    /// # Errors
    /// Refuses a repeated, unconnected, malformed or fenced observation. The
    /// complete actual property Result remains resident before this projection.
    pub async fn observe_pid1_service_startup_properties(
        &mut self,
        name: &str,
        expected_main_pid: u32,
        service_properties: &[&str],
        unit_properties: &[&str],
    ) -> Result<()> {
        self.observe_property_recipe_v1(FixedServicePropertyQueryV1::Startup {
            name, pid: expected_main_pid, service: service_properties, unit: unit_properties,
        }).await
    }

    /// Observes only the active fixed local Ownership profile through PID1.
    ///
    /// This discovers MainPID inside the same authentic active-unit bookends;
    /// returned properties remain comparison DATA, without role or funding.
    ///
    /// # Errors
    /// Retains the actual constructor/property failure or refuses reentry.
    ///
    /// # Panics
    /// Panics if polled without the actual Tokio IO/time drivers enabled.
    pub async fn observe_fixed_ownership_profile_v1(&mut self) -> Result<()> {
        self.observe_property_recipe_v1(FixedServicePropertyQueryV1::Ownership).await
    }

    async fn observe_property_recipe_v1(&mut self, query: FixedServicePropertyQueryV1<'_>) -> Result<()> {
        let mut cancellation = self.transport.cancellation_fence();
        if self.observe_attempted || self.transport.has_ended() {
            self.transport.end();
            return Err(Error::Zbus(zbus::Error::InvalidReply));
        }
        self.observe_attempted = true;

        let result = match self.constructor.as_ref() {
            Some(Ok(Some(client))) => match query {
                FixedServicePropertyQueryV1::Startup { name, pid, service, unit } =>
                    client.observe_pid1_service_startup_properties(name, pid, service, unit).await,
                FixedServicePropertyQueryV1::Ownership =>
                    service_properties::observe_fixed_ownership_profile_v1(client).await,
            },
            _ => Err(Error::Zbus(zbus::Error::InvalidReply)),
        };
        self.properties = Some(result.map(|(service, unit)| {
            (Arc::new(service), Arc::new(unit))
        }));
        if matches!(self.properties.as_ref(), Some(Err(_))) {
            self.transport.end();
            return Err(Error::Zbus(zbus::Error::InvalidReply));
        }
        cancellation.complete();
        Ok(())
    }

    /// Observes one fixed active Host/Mount locator through the same bounded transport.
    ///
    /// The unique manager owner must be PID1. Its exact unit ID, nonzero
    /// invocation, active state and discovered MainPID must remain equal around
    /// ControlGroup. The returned locator remains DATA; the actual role must
    /// join its retained cgroup, pidfd, credentials and independent second read.
    ///
    /// # Errors
    /// Retains the whole original constructor/property error and transport
    /// prefixes on disconnected, repeated, cancelled or changed observation.
    ///
    /// # Panics
    /// Panics if polled outside a Tokio runtime with its IO driver enabled.
    pub async fn observe_controller_attachment_service_v1(
        &mut self,
        role: ControllerAttachmentServiceV1,
    ) -> Result<()> {
        self.observe_control_group_once(ControllerServiceQueryV1::Attachment(role)).await
    }

    /// Observes only the installed Publisher using the same bounded PID1 engine.
    ///
    /// A stable non-active unit is a retained successful absence. Active units
    /// have the same exact unique-PID1 ControlGroup/MainPID/invocation bookends
    /// as the fixed Host/Mount reader. This yields locator DATA, not authority.
    ///
    /// # Errors
    /// Retains the whole original native result and transport prefixes on
    /// disconnected, repeated, malformed, cancelled or changed observation.
    ///
    /// # Panics
    /// Panics if polled outside a Tokio runtime with its IO driver enabled.
    pub async fn observe_controller_publisher_service_v1(&mut self) -> Result<()> {
        self.observe_control_group_once(ControllerServiceQueryV1::Publisher).await
    }

    async fn observe_control_group_once(&mut self, purpose: ControllerServiceQueryV1) -> Result<()> {
        let mut cancellation = self.transport.cancellation_fence();
        if self.observe_attempted || self.transport.has_ended() {
            self.transport.end();
            return Err(Error::Zbus(zbus::Error::InvalidReply));
        }
        self.observe_attempted = true;
        let failed = match purpose {
            ControllerServiceQueryV1::Attachment(role) => {
                self.control_group = Some(match self.constructor.as_ref() {
                    Some(Ok(Some(client))) => service_properties::observe_active_control_group(
                        client, role.unit_name(),
                    ).await,
                    _ => Err(Error::Zbus(zbus::Error::InvalidReply)),
                });
                matches!(self.control_group.as_ref(), Some(Err(_)))
            }
            ControllerServiceQueryV1::Publisher => {
                self.publisher_control_group = Some(match self.constructor.as_ref() {
                    Some(Ok(Some(client))) => service_properties::observe_optional_active_control_group(
                        client, "aos-view-publisher.service",
                    ).await,
                    _ => Err(Error::Zbus(zbus::Error::InvalidReply)),
                });
                matches!(self.publisher_control_group.as_ref(), Some(Err(_)))
            }
        };
        if failed {
            self.transport.end();
            return Err(Error::Zbus(zbus::Error::InvalidReply));
        }
        cancellation.complete();
        Ok(())
    }

    /// Borrows the complete original fixed Publisher locator-or-absence Result.
    pub fn publisher_service_result_v1(
        &self,
    ) -> Option<&Result<Option<ServiceControlGroupObservation>>> {
        self.publisher_control_group.as_ref()
    }

    /// Borrows the complete original active-service locator Result as DATA.
    pub fn control_group_result_v1(&self) -> Option<&Result<ServiceControlGroupObservation>> {
        self.control_group.as_ref()
    }

    /// Borrows the constructor's actual error, or reports its parked success.
    ///
    /// This does not expose the retained client or an extracted Connection.
    pub fn constructor_result(&self) -> Option<std::result::Result<(), &Error>> {
        self.constructor.as_ref().map(|result| result.as_ref().map(|_| ()))
    }

    /// Borrows the complete original decoded property Result as diagnostic DATA.
    ///
    /// Successful tables share the same immutable Vec owners with read-only
    /// DATA projections. Cloning these Arcs never recursively clones a value.
    pub fn property_result(
        &self,
    ) -> Option<&Result<(Arc<Vec<OwnedValue>>, Arc<Vec<OwnedValue>>)>> {
        self.properties.as_ref()
    }

    /// Arms the same original transport fence for an outer timeout or cancellation.
    ///
    /// The caller completes this fence only after parking the whole attempt and
    /// its returned Result. Dropping an unfinished fence permanently ends it.
    #[must_use]
    pub fn cancellation_fence(&self) -> zbus::connection::FixedLauncherImageCancellationV1 {
        self.transport.cancellation_fence()
    }

    /// Reports the original transport's explicitly completed clean end as DATA.
    ///
    /// This performs no IO or end action. Native/protocol failure, unavailable
    /// custody and poisoned slots remain false, even after shutdown. Callers
    /// separately retain and check the original shutdown and property Results;
    /// this projection grants no role authority or resource settlement.
    #[must_use]
    pub fn transport_ended_cleanly_v1(&self) -> bool {
        matches!(self.transport_failure(), Ok(Some(failure)) if matches!(
            failure.cause(), zbus::connection::socket::LauncherImageFailureRefV1::Ended,
        ))
    }

    /// Borrows the actual native/parser cause without reconnecting or extracting it.
    ///
    /// # Errors
    /// Reports a borrowed or poisoned native slot without healing that slot.
    pub fn transport_failure(&self) -> std::result::Result<
        Option<zbus::connection::socket::LauncherImageFailureLoanV1<'_>>,
        zbus::connection::socket::LauncherImageFailureUnavailableV1,
    > {
        self.transport.failure()
    }

    /// Borrows the original one-shot shutdown Results, separately from first cause.
    pub fn shutdown_outcomes(&self) -> (
        Option<&std::io::Result<()>>,
        Option<&std::io::Result<()>>,
    ) {
        self.transport.shutdown_outcomes()
    }

    /// Reports permanent cancellation/failure fencing without I/O.
    #[must_use]
    pub fn has_ended(&self) -> bool {
        self.transport.has_ended()
    }

    /// Disposes completed property-observer connections and the native socket.
    ///
    /// Called after the actual worker Runtime and completed cancellation guard
    /// have been destroyed. Native exclusivity is checked mechanically; raw
    /// bytes, property Arcs, native/error Results and clean end stay resident.
    /// Host/Mount queries and ordinary Systemd clients retain their old path.
    ///
    /// # Errors
    /// Returns a marker if a complete property flight or unique native owner
    /// is unavailable. [`Self::native_socket_retirement_outcome_v1`] retains the
    /// actual transport refusal after native disposition is entered.
    pub fn retire_positive_native_socket_once_v1(&mut self) -> std::result::Result<(), ()> {
        if !matches!(self.properties, Some(Ok(_)))
            || !matches!(self.constructor, Some(Ok(Some(_))))
            || !self.transport_ended_cleanly_v1()
            || !matches!(self.shutdown_outcomes(), (Some(Ok(())), None))
            || self.transport.socket_retirement_outcome().is_some()
        {
            return Err(());
        }
        // This drops both the readonly client's direct Connection and its
        // Manager proxy clone. Keep the actual constructor's successful
        // outcome as Ok(None); the separate native outcome records disposal.
        if let Some(Ok(client)) = self.constructor.as_mut() {
            drop(client.take());
        }
        self.transport.retire_ended_socket_once()
    }

    /// Borrows the original once-only native socket disposition outcome.
    #[must_use]
    pub fn native_socket_retirement_outcome_v1(&self) -> Option<&std::result::Result<
        (), zbus::connection::socket::ControllerSocketRetirementErrorV1,
    >> {
        self.transport.socket_retirement_outcome()
    }

    /// Ends the same original transport without releasing any retained Result.
    pub fn end(&self) {
        self.transport.end();
    }
}

#[cfg(target_os = "linux")]
impl Drop for ControllerPropertyObserverAttemptV1 {
    fn drop(&mut self) {
        self.transport.end();
    }
}

const SYSTEMD_ALREADY_SUBSCRIBED: &str = "org.freedesktop.systemd1.AlreadySubscribed";
const PINNED_COMPLETION_LIMIT: usize = 1_024;

/// Classification of a systemd job's terminal `result`, per the `job_result`
/// table in systemd's `src/core/job.h`. We name only the four cases
/// switch-to-configuration-ng classifies explicitly; everything else
/// (`canceled`, `skipped`, `assert`, `frozen`, …) lands in `Unknown` with the
/// raw label preserved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobResult {
    /// The job completed successfully (`"done"`).
    Done,
    /// The job failed (`"failed"`).
    Failed,
    /// The job hit its timeout (`"timeout"`).
    Timeout,
    /// A dependency of the job failed (`"dependency"`).
    Dependency,
    /// Any other terminal result, with the raw systemd label preserved.
    Unknown(String),
}

impl JobResult {
    /// Parse a systemd `result` string.
    pub fn from_systemd(s: &str) -> Self {
        match s {
            "done" => Self::Done,
            "failed" => Self::Failed,
            "timeout" => Self::Timeout,
            "dependency" => Self::Dependency,
            other => Self::Unknown(other.to_string()),
        }
    }

    /// The systemd label for this result (round-trips `from_systemd`).
    pub fn label(&self) -> &str {
        match self {
            Self::Done => "done",
            Self::Failed => "failed",
            Self::Timeout => "timeout",
            Self::Dependency => "dependency",
            Self::Unknown(s) => s,
        }
    }

    /// Whether the job completed successfully.
    pub fn is_done(&self) -> bool {
        matches!(self, Self::Done)
    }
}

impl serde::Serialize for JobResult {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.label())
    }
}

/// The outcome of a unit lifecycle operation: the submitted job's object path
/// plus its classified terminal result.
#[derive(Debug, Clone)]
pub struct JobOutcome {
    /// Object path of the job systemd enqueued for the operation.
    pub job_path: OwnedObjectPath,
    /// Classified terminal result from the job's `JobRemoved` signal.
    pub result: JobResult,
}

/// Classifies a unit's exact systemd `ActiveState` while preserving new labels.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UnitActiveState {
    /// The unit is fully active.
    Active,
    /// The unit is active while reloading its configuration.
    Reloading,
    /// The unit is fully inactive.
    Inactive,
    /// The unit entered a failed state.
    Failed,
    /// The unit is still activating.
    Activating,
    /// The unit is still deactivating.
    Deactivating,
    /// The unit is in systemd's maintenance state.
    Maintenance,
    /// The unit is refreshing its state.
    Refreshing,
    /// The manager returned an unrecognized future state.
    Unknown(String),
}

impl UnitActiveState {
    /// Classifies one raw systemd `ActiveState` label without discarding it.
    #[must_use]
    pub fn from_systemd(state: &str) -> Self {
        match state {
            "active" => Self::Active,
            "reloading" => Self::Reloading,
            "inactive" => Self::Inactive,
            "failed" => Self::Failed,
            "activating" => Self::Activating,
            "deactivating" => Self::Deactivating,
            "maintenance" => Self::Maintenance,
            "refreshing" => Self::Refreshing,
            other => Self::Unknown(other.to_string()),
        }
    }

    /// Returns the exact systemd label represented by this state.
    #[must_use]
    pub fn label(&self) -> &str {
        match self {
            Self::Active => "active",
            Self::Reloading => "reloading",
            Self::Inactive => "inactive",
            Self::Failed => "failed",
            Self::Activating => "activating",
            Self::Deactivating => "deactivating",
            Self::Maintenance => "maintenance",
            Self::Refreshing => "refreshing",
            Self::Unknown(state) => state,
        }
    }

    /// Reports whether the unit is fully active.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }
}

/// Identifies one system bus lifetime and the exact systemd service owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagerIncarnation {
    bus_id: String,
    owner: String,
}

impl ManagerIncarnation {
    /// Returns the D-Bus GUID identifying this bus lifetime.
    #[must_use]
    pub fn bus_id(&self) -> &str {
        &self.bus_id
    }

    /// Returns systemd's unique service owner within the bus lifetime.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Returns an opaque durable token suitable for provider assignment identity.
    #[must_use]
    pub fn token(&self) -> String {
        format!("bus:{};owner:{}", self.bus_id, self.owner)
    }
}

/// A unit found in a failed (or failed-and-auto-restarting) state by
/// [`SystemdClient::failed_units`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct FailedUnit {
    /// Unit name, including the type suffix (e.g. `foo.service`).
    pub name: String,
    /// `ActiveState` at scan time (`"failed"`, or `"activating"` for the
    /// auto-restart case).
    pub active_state: String,
    /// `SubState` at scan time (e.g. `"auto-restart"`).
    pub sub_state: String,
    /// `ExecMainStatus` for `.service` units (exit status of the main
    /// process); `None` for non-services or if the read failed.
    pub exec_main_status: Option<i32>,
    /// Captured `systemctl status` output for human display.
    pub status_dump: String,
}

/// Reports one stable manager observation of an active service's cgroup locator.
///
/// The path and PID are not kernel authority. A consumer must open the cgroup
/// beneath a trusted cgroup-v2 root and verify the pinned PID's exact membership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceControlGroupObservation {
    /// Systemd's cgroup path relative to the cgroup-v2 root, with a leading slash.
    pub control_group: String,
    /// Service main PID observed before and after its cgroup property.
    pub main_pid: NonZeroU32,
    /// Current systemd activation identity observed before and after.
    pub invocation_id: [u8; 16],
}

/// Retains one fixed offline Nix absence observation and its partial DATA.
///
/// Empty construction performs no I/O and establishes no authority. The fixed
/// reader parks returned property pairs, actual absence errors and unexpected
/// raw replies here before later checks. Library pre-return intervals remain
/// outside this holder; it proves neither population retirement nor currentness.
pub struct NixOfflineAbsenceObservationV5 {
    attempted: bool,
    complete: bool,
    controller: Option<(Vec<OwnedValue>, Vec<OwnedValue>)>,
    nix_owner: Option<(Vec<OwnedValue>, Vec<OwnedValue>)>,
    absence: [Option<Error>; 2],
    owner_path: Option<OwnedObjectPath>,
    raw_reply: Option<zbus::Message>,
    first_failure: Option<Error>,
}

impl NixOfflineAbsenceObservationV5 {
    /// Creates empty fixed DATA slots without admitting an observation.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            attempted: false,
            complete: false,
            controller: None,
            nix_owner: None,
            absence: [None, None],
            owner_path: None,
            raw_reply: None,
            first_failure: None,
        }
    }

    /// Borrows checked Controller and optional Nix-owner property DATA.
    ///
    /// # Errors
    /// Refuses an unfinished, failed or interrupted observation. Absence is
    /// represented only after both original named errors and PID1 bookends.
    pub fn properties(&self) -> Result<(
        &(Vec<OwnedValue>, Vec<OwnedValue>),
        Option<&(Vec<OwnedValue>, Vec<OwnedValue>)>,
    )> {
        if !self.complete || self.first_failure.is_some() {
            return Err(Error::InvalidSandboxUnit("offline Nix observation is fenced".to_owned()));
        }
        let controller = self.controller.as_ref().ok_or_else(|| {
            Error::InvalidSandboxUnit("offline Controller observation is absent".to_owned())
        })?;
        Ok((controller, self.nix_owner.as_ref()))
    }

    /// Borrows the first actual failure without releasing returned originals.
    pub fn failure(&self) -> Option<&Error> {
        self.first_failure.as_ref()
    }

    /// Borrows the two original named absence errors as diagnostic DATA.
    pub fn absence_errors(&self) -> &[Option<Error>; 2] {
        &self.absence
    }
}

impl Default for NixOfflineAbsenceObservationV5 {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a post-run failed-unit scan.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FailedUnitsReport {
    /// All units found in a failed (or failing-and-retrying) state.
    pub failed: Vec<FailedUnit>,
}

impl FailedUnitsReport {
    /// Returns `true` if no failed units were found.
    pub fn is_empty(&self) -> bool {
        self.failed.is_empty()
    }
}

/// Automatic-restart policy of a `.service` unit, read to size the settle
/// deadline in a post-activation health gate.
#[derive(Debug, Clone)]
pub struct RestartPolicy {
    /// `RestartSec` — the backoff systemd waits before each automatic restart.
    pub restart_sec: Duration,
    /// `NRestarts` — automatic restarts performed so far.
    pub n_restarts: u32,
}

/// Terminal classification of a unit that was observed in `auto-restart`,
/// returned by [`SystemdClient::wait_until_settled`] after waiting out the
/// unit's `RestartSec` backoff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettleOutcome {
    /// The unit reached `active` — it recovered on a retry.
    Recovered {
        /// `NRestarts` observed once the unit went active.
        n_restarts: u32,
    },
    /// The unit reached terminal `failed` (systemd gave up restarting it).
    Failed,
    /// The unit was still auto-restarting when the deadline elapsed — it is
    /// not converging within the budget.
    StillRestarting,
}

/// Shared job-tracking state.
///
/// `waiters` holds the oneshot sender for jobs we've submitted and are awaiting.
/// `completed` holds results for `JobRemoved` events that arrived *before* the
/// submitting call had a chance to register its waiter — the method reply
/// (carrying the job path) and the `JobRemoved` signal are dispatched on
/// independent tasks, so the signal can win the race. Keeping a completed-map
/// makes the wait race-free: the submitter checks `completed` under the same
/// lock before inserting a waiter.
#[derive(Default)]
struct JobRegistry {
    waiters: BTreeMap<String, oneshot::Sender<JobResult>>,
    completed: BTreeMap<String, JobResult>,
    /// Set once the `JobRemoved` signal stream closes — i.e. the bus connection
    /// died. No further `JobRemoved` will ever arrive, so any pending or future
    /// waiter can never be satisfied. Read under the same lock as `waiters` so
    /// the close-side drain and the `await_job` registration are serialized:
    /// every awaiter either gets drained or sees `closed` before parking, and
    /// none is left to hang. The canonical case is the reconcile restarting
    /// `dbus.service` and killing the very bus it was driving.
    closed: bool,
}

#[derive(Default)]
struct PinnedJobRegistry {
    /// Awaiters grouped by job path. systemd may merge concurrent requests and
    /// return the same path to each caller, so one completion wakes the group.
    waiters: BTreeMap<String, BTreeMap<u64, oneshot::Sender<JobResult>>>,
    /// Results that raced ahead of one or more outstanding method replies.
    completed: BTreeMap<String, JobResult>,
    /// Calls whose method reply has not exposed the job path yet.
    active_submissions: usize,
    /// Total lifecycle calls holding one bounded registry reservation.
    pending_calls: usize,
    next_waiter_id: u64,
    closed: bool,
    /// Set when unrelated signals exhaust the bounded early-completion map.
    overflowed: bool,
}

struct PinnedSubmission {
    jobs: Arc<Mutex<PinnedJobRegistry>>,
    before_reply: bool,
    waiter: Option<(String, u64)>,
    pending: bool,
}

enum PinnedRegistration {
    Completed(JobResult),
    Pending(oneshot::Receiver<JobResult>),
}

impl PinnedSubmission {
    fn begin(jobs: &Arc<Mutex<PinnedJobRegistry>>) -> Result<Self> {
        let mut registry = lock_pinned_registry(jobs);
        if registry.overflowed {
            return Err(Error::JobCompletionOverflow);
        }
        if registry.closed {
            return Err(Error::JobSenderDropped("manager signal stream".to_string()));
        }
        if registry.pending_calls >= PINNED_COMPLETION_LIMIT {
            return Err(Error::JobCompletionOverflow);
        }
        registry.pending_calls += 1;
        registry.active_submissions += 1;

        Ok(Self {
            jobs: Arc::clone(jobs),
            before_reply: true,
            waiter: None,
            pending: true,
        })
    }

    fn register(&mut self, path_key: &str) -> Result<PinnedRegistration> {
        let mut registry = lock_pinned_registry(&self.jobs);
        registry.active_submissions = registry.active_submissions.saturating_sub(1);
        self.before_reply = false;

        if registry.overflowed {
            return Err(Error::JobCompletionOverflow);
        }
        if let Some(result) = registry.completed.get(path_key).cloned() {
            if registry.active_submissions == 0 {
                registry.completed.clear();
            }
            registry.pending_calls = registry.pending_calls.saturating_sub(1);
            self.pending = false;
            return Ok(PinnedRegistration::Completed(result));
        }
        if registry.closed {
            return Err(Error::JobSenderDropped(path_key.to_string()));
        }
        if registry.active_submissions == 0 {
            registry.completed.clear();
        }

        let waiter_id = registry.next_waiter_id;
        registry.next_waiter_id = registry
            .next_waiter_id
            .checked_add(1)
            .ok_or(Error::JobCompletionOverflow)?;
        let (sender, receiver) = oneshot::channel();
        registry
            .waiters
            .entry(path_key.to_string())
            .or_default()
            .insert(waiter_id, sender);
        self.waiter = Some((path_key.to_string(), waiter_id));

        Ok(PinnedRegistration::Pending(receiver))
    }

    fn finish(&mut self) {
        let mut registry = lock_pinned_registry(&self.jobs);
        registry.pending_calls = registry.pending_calls.saturating_sub(1);
        self.waiter = None;
        self.pending = false;
    }
}

impl Drop for PinnedSubmission {
    fn drop(&mut self) {
        if self.pending {
            let mut registry = lock_pinned_registry(&self.jobs);
            if self.before_reply {
                registry.active_submissions = registry.active_submissions.saturating_sub(1);
            }
            if let Some((path, waiter_id)) = self.waiter.take()
                && let Some(waiters) = registry.waiters.get_mut(&path)
            {
                waiters.remove(&waiter_id);
                if waiters.is_empty() {
                    registry.waiters.remove(&path);
                }
            }
            registry.pending_calls = registry.pending_calls.saturating_sub(1);
            if registry.active_submissions == 0 {
                registry.completed.clear();
            }
        }
    }
}

/// Typed async client for `org.freedesktop.systemd1`.
pub struct SystemdClient {
    pub(crate) conn: zbus::Connection,
    pub(crate) manager: ManagerProxy<'static>,
    jobs: Arc<Mutex<JobRegistry>>,
    reloading: Arc<AtomicBool>,
    /// One tick per observed `JobRemoved`, regardless of whether a waiter was
    /// registered. Drained by [`SystemdClient::settle`] to tell "bus quiet"
    /// from "bus still chattering" without inspecting the job map.
    job_event_rx: AsyncMutex<mpsc::UnboundedReceiver<()>>,
    /// Background signal-listener tasks; aborted on drop.
    tasks: Vec<JoinHandle<()>>,
    // Selected readonly clients never subscribe or enter unsubscribe-on-drop.
    readonly_controller: bool,
    #[cfg(target_os = "linux")]
    host_launch: Option<Arc<Mutex<host_launch::HostSystemdDispositionV2>>>,
}

/// A listener-free capability for one caller-selected systemd bus.
///
/// The connection itself fixes the manager scope. Native catalogs retain this
/// capability and create bounded unique-owner pins from it; they never replace
/// a supplied user, container, or initrd transport with the host system bus.
#[derive(Clone)]
pub struct SystemdManagerConnection {
    conn: zbus::Connection,
}

/// A lifecycle client bound to one exact systemd service owner.
///
/// Calls are addressed to the owner's D-Bus unique name, and job completion
/// signals flow into a registry owned only by this pin. This keeps an unrelated
/// `JobRemoved` from a replacement manager from completing an earlier call
/// that happened to receive the same object path.
pub struct PinnedSystemdManager {
    conn: zbus::Connection,
    incarnation: ManagerIncarnation,
    manager: ManagerProxy<'static>,
    jobs: Arc<Mutex<PinnedJobRegistry>>,
    job_task: JoinHandle<()>,
}

impl SystemdClient {
    pub(crate) fn uses_fixed_property_decoding_v2(&self) -> bool {
        #[cfg(target_os = "linux")]
        if self.host_launch.is_some() { return true; }
        self.readonly_controller
    }

    pub(crate) fn is_retained_host_launch_v2(&self) -> bool {
        #[cfg(target_os = "linux")]
        { self.host_launch.is_some() }
        #[cfg(not(target_os = "linux"))]
        { false }
    }


    // Both selected transport owners use this exact readonly constructor. The
    // resulting manager remains on the caller's existing Runtime/Connection;
    // it subscribes to nothing and spawns no background signal-handler worker.
    #[cfg(target_os = "linux")]
    async fn readonly_from_connection_v2(conn: zbus::Connection) -> Result<Self> {
        let manager = ManagerProxy::builder(&conn)
            .cache_properties(CacheProperties::No)
            .build()
            .await?;
        Ok(Self::readonly_from_manager_v8(conn, manager))
    }

    // The finite inventory already holds its actual unique-PID1 manager. It
    // shares the same inert readonly client fields without resolving another
    // destination, adding a transport query or subscribing to signals.
    #[cfg(target_os = "linux")]
    fn readonly_from_manager_v8(conn: zbus::Connection, manager: ManagerProxy<'static>) -> Self {
        let (_, event_rx) = mpsc::unbounded_channel::<()>();

        Self {
            conn,
            manager,
            jobs: Arc::new(Mutex::new(JobRegistry {
                closed: true,
                ..JobRegistry::default()
            })),
            reloading: Arc::new(AtomicBool::new(false)),
            job_event_rx: AsyncMutex::new(event_rx),
            tasks: Vec::new(),
            readonly_controller: true,
            #[cfg(target_os = "linux")]
            host_launch: None,
        }
    }

    /// Open the system bus, build the Manager proxy, `Subscribe()`, and start
    /// the background signal-handler tasks.
    ///
    /// Uses the shared **system bus** (`/run/dbus/system_bus_socket`), the same
    /// transport nixpkgs `switch-to-configuration-ng` uses. (systemd's private
    /// socket would decouple us from `dbus.service`, but it is a *direct*, non-
    /// bus endpoint whose message framing zbus 5 cannot round-trip — it rejects
    /// systemd's sender field as an invalid unique name. We therefore avoid
    /// restarting the bus in the first place: `dbus.service` is `reloadIfChanged`
    /// so the reconcile reloads rather than restarts it, and a connection that
    /// dies mid-reconcile anyway is surfaced as a `JobSenderDropped` error
    /// rather than an indefinite hang.)
    ///
    /// # Errors
    ///
    /// Returns [`Error::SystemdUnavailable`] if the system bus cannot be
    /// reached (e.g. `/run/dbus/system_bus_socket` is absent), or any
    /// error from [`SystemdClient::from_connection`].
    pub async fn connect() -> Result<Self> {
        let conn = zbus::Connection::system()
            .await
            .map_err(Error::SystemdUnavailable)?;
        Self::from_connection(conn).await
    }

    /// Connects a Nix offline observer to the fixed bus without incoming FDs.
    ///
    /// The Unix reader rejects ancillary control before authentication and
    /// every subsequent message read. The fixed address has no environment
    /// override or alternate transport. This constructs a DATA transport only;
    /// the caller still owns genuine startup, approval and current custody.
    /// Ordinary [`Self::connect`] behavior is unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SystemdUnavailable`] for address, connection or
    /// authentication failures, including terminal incoming-control rejection,
    /// or any error from [`Self::from_connection`].
    ///
    /// # Panics
    ///
    /// Panics if polled outside a Tokio runtime with its I/O driver enabled.
    #[cfg(target_os = "linux")]
    pub async fn connect_nix_offline_hardware_observer() -> Result<Self> {
        let conn = zbus::connection::Builder::address("unix:path=/run/dbus/system_bus_socket")
            .map_err(Error::SystemdUnavailable)?
            .reject_incoming_unix_fds()
            .build()
            .await
            .map_err(Error::SystemdUnavailable)?;

        Self::from_connection(conn).await
    }

    /// Build a client around a caller-supplied connection. Used by the unit
    /// tests to inject one end of a p2p pair pointing at a `FakeSystemd`; also
    /// a legitimate embedding API. Unconditionally `pub` so the integration
    /// test crate (a separate compilation unit) can reach it.
    ///
    /// # Errors
    ///
    /// Returns an error if the Manager proxy cannot be built, if the
    /// `Subscribe()` call fails, or if the signal streams cannot be
    /// established.
    pub async fn from_connection(conn: zbus::Connection) -> Result<Self> {
        let manager = ManagerProxy::new(&conn).await?;
        Self::from_manager_connection(conn, manager).await
    }

    /// Uses only the sender established by the fixed worker private handshake.
    #[cfg(target_os = "linux")]
    pub(crate) async fn from_worker_private_connection(conn: zbus::Connection) -> Result<Self> {
        // A well-known destination makes zbus resolve GetNameOwner through a
        // bus daemon. The direct PID 1 connection has no such daemon; its
        // role-specific sender must also be the exact signal-stream source.
        let manager = ManagerProxy::builder(&conn)
            .destination(":1.0")?
            .build()
            .await?;
        Self::from_manager_connection(conn, manager).await
    }

    async fn from_manager_connection(
        conn: zbus::Connection,
        manager: ManagerProxy<'static>,
    ) -> Result<Self> {
        systemd_setup_recipe!(Local, unused, conn, manager)
    }

    // ---- Unit lifecycle ---------------------------------------------------
    // Each submits the job, awaits JobRemoved, classifies, and returns. Mode is
    // "replace" except `isolate_unit`.

    /// Start `name` (mode `"replace"`) and await the job's terminal result.
    ///
    /// # Errors
    ///
    /// Returns an error if the D-Bus call fails (e.g. `NoSuchUnit`) or if
    /// the bus connection dies while awaiting the job's `JobRemoved`.
    /// A job that finishes with `failed`/`timeout`/... is *not* an error;
    /// inspect [`JobOutcome::result`].
    pub async fn start_unit(&self, name: &str) -> Result<JobOutcome> {
        let path = self.manager.start_unit(name, "replace").await?;
        self.await_job(path).await
    }

    /// Queue a start job for `name` without awaiting the job result.
    ///
    /// This matches `systemctl start --no-block`: systemd validates and queues
    /// the job, then the caller continues while the unit reaches its terminal
    /// state asynchronously.
    ///
    /// # Errors
    ///
    /// Returns an error if the D-Bus call fails, for example when systemd
    /// rejects the unit name or cannot queue the job.
    pub async fn start_unit_no_wait(&self, name: &str) -> Result<()> {
        self.manager.start_unit(name, "replace").await?;
        Ok(())
    }

    /// Stop `name` (mode `"replace"`) and await the job's terminal result.
    ///
    /// # Errors
    ///
    /// Same contract as [`SystemdClient::start_unit`].
    pub async fn stop_unit(&self, name: &str) -> Result<JobOutcome> {
        let path = self.manager.stop_unit(name, "replace").await?;
        self.await_job(path).await
    }

    /// Restart `name` (mode `"replace"`) and await the job's terminal result.
    ///
    /// # Errors
    ///
    /// Same contract as [`SystemdClient::start_unit`].
    pub async fn restart_unit(&self, name: &str) -> Result<JobOutcome> {
        let path = self.manager.restart_unit(name, "replace").await?;
        self.await_job(path).await
    }

    /// Reload `name` (mode `"replace"`) and await the job's terminal result.
    ///
    /// # Errors
    ///
    /// Same contract as [`SystemdClient::start_unit`].
    pub async fn reload_unit(&self, name: &str) -> Result<JobOutcome> {
        let path = self.manager.reload_unit(name, "replace").await?;
        self.await_job(path).await
    }

    /// Start `name` in `"isolate"` mode (stop everything not required by
    /// it, like `systemctl isolate`) and await the job's terminal result.
    ///
    /// # Errors
    ///
    /// Same contract as [`SystemdClient::start_unit`].
    pub async fn isolate_unit(&self, name: &str) -> Result<JobOutcome> {
        let path = self.manager.start_unit(name, "isolate").await?;
        self.await_job(path).await
    }

    /// Register interest in `path` and await its `JobRemoved`. Race-free: if
    /// the result already landed in `completed`, return it immediately. There
    /// is no caller-side timeout — per switch-to-configuration-ng's contract,
    /// "this job is in flight; we wait for systemd's answer." Callers wanting
    /// an upper bound wrap this in `tokio::time::timeout` themselves.
    pub(crate) async fn await_job(&self, path: OwnedObjectPath) -> Result<JobOutcome> {
        let path_key = path.as_str().to_owned();
        let rx = {
            let mut reg = self.jobs.lock().unwrap();
            if let Some(result) = reg.completed.remove(&path_key) {
                return Ok(JobOutcome {
                    job_path: path,
                    result,
                });
            }
            // The signal stream already closed (bus died) — no JobRemoved can
            // arrive, so don't park a waiter that would never wake.
            if reg.closed {
                return Err(Error::JobSenderDropped(path.as_str().to_string()));
            }
            let (tx, rx) = oneshot::channel();
            reg.waiters.insert(path_key, tx);
            rx
        };
        let result = rx
            .await
            .map_err(|_| Error::JobSenderDropped(path.as_str().to_string()))?;
        Ok(JobOutcome {
            job_path: path,
            result,
        })
    }

    // ---- Manager-level operations ----------------------------------------

    /// `Manager.Reload()` — equivalent to `systemctl daemon-reload`.
    ///
    /// # Errors
    ///
    /// Returns an error if the D-Bus call fails.
    pub async fn daemon_reload(&self) -> Result<()> {
        self.manager.reload().await?;
        Ok(())
    }

    /// Clear the "failed" state of all units (`systemctl reset-failed`).
    ///
    /// # Errors
    ///
    /// Returns an error if the D-Bus call fails.
    pub async fn reset_failed(&self) -> Result<()> {
        self.manager.reset_failed().await?;
        Ok(())
    }

    /// Clear the "failed" state of a single unit.
    ///
    /// # Errors
    ///
    /// Returns an error if the D-Bus call fails (e.g. `NoSuchUnit`).
    pub async fn reset_failed_unit(&self, name: &str) -> Result<()> {
        self.manager.reset_failed_unit(name).await?;
        Ok(())
    }

    /// Queue a reboot. Like `systemctl reboot`, this returns once systemd has
    /// *queued* the reboot, not when it happens; the caller then exits cleanly
    /// or is killed as systemd tears the system down.
    ///
    /// # Errors
    ///
    /// Returns an error if the D-Bus call fails.
    pub async fn reboot(&self) -> Result<()> {
        self.manager.reboot().await?;
        Ok(())
    }

    // ---- Inspection -------------------------------------------------------

    /// Returns the current bus and service-owner incarnation of systemd.
    ///
    /// A D-Bus unique name is unique only during one bus lifetime and may be
    /// reused after restart. This token therefore combines the bus GUID with
    /// the current unique owner of `org.freedesktop.systemd1`. Callers can
    /// persist and recheck it across reconnection without confusing two bus
    /// lifetimes that both assigned a name such as `:1.0`.
    ///
    /// # Errors
    ///
    /// Returns an error when the bus daemon cannot resolve
    /// `org.freedesktop.systemd1` to a current unique owner.
    pub async fn manager_incarnation(&self) -> Result<ManagerIncarnation> {
        read_manager_incarnation(&self.conn).await
    }

    /// Whether `name`'s `ActiveState == "active"`. A unit that isn't loaded
    /// (systemd returns `NoSuchUnit`) counts as not-active — matching
    /// `systemctl is-active` on an unknown unit.
    ///
    /// # Errors
    ///
    /// Returns an error if the D-Bus calls fail for any reason other than
    /// `NoSuchUnit`.
    pub async fn is_active(&self, name: &str) -> Result<bool> {
        match self.manager.get_unit(name).await {
            Ok(path) => {
                let unit = UnitProxy::builder(&self.conn)
                    .path(path)?
                    .cache_properties(CacheProperties::No)
                    .build()
                    .await?;
                Ok(unit.active_state().await? == "active")
            }
            Err(e) if is_no_such_unit(&e) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Reads one property from a unit's `org.freedesktop.systemd1.Unit`
    /// interface and returns its exact D-Bus value. Callers convert the
    /// [`OwnedValue`] according to the property's declared type.
    ///
    /// # Errors
    ///
    /// Returns an error if the unit is not loaded (`NoSuchUnit`), if the
    /// property does not exist, or if the D-Bus calls fail.
    pub async fn unit_property(&self, name: &str, prop: &str) -> Result<OwnedValue> {
        let path = self.manager.get_unit(name).await?;
        let props = zbus::fdo::PropertiesProxy::builder(&self.conn)
            .destination("org.freedesktop.systemd1")?
            .path(path)?
            .build()
            .await?;
        let iface = zbus::names::InterfaceName::try_from("org.freedesktop.systemd1.Unit")
            .expect("static interface name is valid");
        Ok(props.get(iface, prop).await?)
    }

    /// Reads service properties from one PID 1-owned systemd bus generation.
    ///
    /// The manager destination is its unique bus name, not the replaceable
    /// well-known name. The owner and service identity are checked on both
    /// sides of the read; callers still recheck any kernel objects they pin.
    ///
    /// # Errors
    ///
    /// Rejects a non-service name, a manager not owned by PID 1, an inactive
    /// or changing service, an absent property, or any D-Bus failure.
    pub async fn observe_pid1_service_properties(
        &self,
        name: &str,
        expected_main_pid: u32,
        properties: &[&str],
    ) -> Result<Vec<OwnedValue>> {
        let (values, _) = service_properties::observe(
            self,
            name,
            expected_main_pid,
            properties,
            &[],
            service_properties::ObservationPhase::Active,
        )
        .await?;
        Ok(values)
    }

    /// Observes only the fixed Controller Git Source socket at unique PID 1.
    ///
    /// The uncached fixed properties and active/listening invocation must be
    /// unchanged across readback. The result is data; the original listener,
    /// configured Controller identity and immutable fragment need separate pins.
    ///
    /// # Errors
    /// Rejects a missing, substituted, changed, transient or overridden socket,
    /// wrong fixed profile, non-PID-1 manager, timeout or D-Bus failure.
    ///
    /// # Panics
    /// Panics if polled without a Tokio runtime with its time driver enabled.
    pub async fn observe_fixed_controller_git_source_socket_v1(
        &self,
    ) -> Result<GitSourceSocketObservationV1> {
        git_source_socket::observe(self).await
    }

    /// Reads PID 1's exact starting or running service and unit properties.
    ///
    /// Startup accepts only `activating/start`; running accepts only
    /// `active/running`. The unique PID 1 bus owner, unit ID, invocation,
    /// main PID, and state must remain equal around the reads. This permits
    /// checks before a notify service reports ready, without granting readiness
    /// or freezing properties against a later administrative reload.
    ///
    /// # Errors
    ///
    /// Rejects a missing or substituted service, another startup substate,
    /// changing invocation or state, a missing property, or any bus failure.
    pub async fn observe_pid1_service_startup_properties(
        &self,
        name: &str,
        expected_main_pid: u32,
        service_properties: &[&str],
        unit_properties: &[&str],
    ) -> Result<(Vec<OwnedValue>, Vec<OwnedValue>)> {
        service_properties::observe(
            self,
            name,
            expected_main_pid,
            service_properties,
            unit_properties,
            service_properties::ObservationPhase::StartingOrRunning,
        )
        .await
    }

    /// Observes only the two fixed Nix runtime units in the inactive/dead phase.
    ///
    /// The same unique-PID-1 observer brackets each uncached read with its unit,
    /// state, main PID and invocation. Missing units fail; zero invocation is
    /// accepted only here. These properties are DATA, not population or drain
    /// authority. A genuine offline owner separately checks fixed kernel cgroups.
    ///
    /// # Errors
    /// Rejects missing, nonstopped, changed or schematically invalid units,
    /// a non-PID-1 manager, unavailable properties or a D-Bus failure.
    pub async fn observe_fixed_stopped_nix_units_v3(
        &self,
    ) -> Result<[(Vec<OwnedValue>, Vec<OwnedValue>); 2]> {
        service_properties::observe_stopped_nix(self).await
    }

    /// Observes the stopped Controller and stopped or uninstalled Nix owner.
    ///
    /// Only the fixed Nix owner may be absent. That alternative requires the
    /// same unique PID1's exact `NoSuchUnit` and `FileNotFound` method errors.
    /// Both errors enter the caller's resident DATA slots before subsequent
    /// checks. Neither absence nor these properties prove population retirement.
    ///
    /// # Errors
    /// Rejects reused slots, a missing Controller, any other method error,
    /// changed PID1 ownership, a live unit or mismatched property signatures.
    /// Earlier parked method errors remain borrowed caller-owned originals.
    pub async fn observe_fixed_offline_nix_units_v5<'observation>(
        &self,
        observation: &'observation mut NixOfflineAbsenceObservationV5,
    ) -> std::result::Result<(), &'observation Error> {
        if observation.attempted {
            observation.complete = false;
            return Err(observation.first_failure.get_or_insert_with(|| {
                Error::InvalidSandboxUnit("offline Nix observation is fenced".to_owned())
            }));
        }
        observation.attempted = true;
        let result = service_properties::observe_offline_nix(self, observation).await;
        match result {
            Ok(()) => {
                observation.complete = true;
                Ok(())
            }
            Err(error) => Err(observation.first_failure.get_or_insert(error)),
        }
    }

    /// Observes an active service's exact unit, invocation, main PID, and cgroup.
    ///
    /// The returned path is only a locator. Consumers must retain and validate
    /// the kernel cgroup object and PID separately; a service restart after this
    /// call does not preserve either observation.
    ///
    /// # Errors
    ///
    /// Rejects a missing, inactive, substituted, or changing service, an
    /// invalid cgroup path or invocation, or a D-Bus exchange failure.
    pub async fn observe_service_control_group(
        &self, name: &str,
    ) -> Result<ServiceControlGroupObservation> {
        service_properties::ServiceControlGroupReadOriginalV2::new()
            .observe_body(self, name).await
    }

    /// List units filtered by active states and shell-glob name patterns;
    /// empty slices mean "no filter".
    ///
    /// # Errors
    ///
    /// Returns an error if the D-Bus call fails.
    pub async fn list_units_by_patterns(
        &self,
        states: &[&str],
        patterns: &[&str],
    ) -> Result<Vec<ListUnitsEntry>> {
        Ok(self
            .manager
            .list_units_by_patterns(states, patterns)
            .await?)
    }

    /// Whether systemd is currently reloading (last observed `Reloading`
    /// signal). Useful for callers that want to wait out a daemon reload.
    pub fn is_reloading(&self) -> bool {
        self.reloading.load(Ordering::SeqCst)
    }

    /// Post-run failed-unit scan, cribbed from switch-to-configuration-ng
    /// (`main.rs:2464-2526` / `get_active_units`):
    ///
    /// 1. List *all* units, skip ones that are `inactive` or `followed`.
    /// 2. A unit is failed if `ActiveState == "failed"`, OR it's a `.service`
    ///    in `SubState == "auto-restart"` whose `ExecMainStatus` is non-zero
    ///    (it previously failed to start and is waiting to retry).
    /// 3. Capture `systemctl status` text for each, for human display.
    ///
    /// NOTE: filtering on `states = ["failed"]` alone (as the spec sketched in
    /// §5.8) would MISS the auto-restart case, whose `ActiveState` is
    /// `activating`, not `failed`. We mirror STC and scan all units.
    ///
    /// # Errors
    ///
    /// Returns an error if the unit listing fails. Per-unit property reads
    /// and status captures are best-effort and never fail the scan.
    pub async fn failed_units(&self) -> Result<FailedUnitsReport> {
        let units = self.manager.list_units_by_patterns(&[], &[]).await?;
        let mut failed = Vec::new();
        for u in units {
            if !u.followed.is_empty() || u.active_state == "inactive" {
                continue;
            }
            let is_service = u.name.ends_with(".service");

            // Read ExecMainStatus once (used for both classification and the
            // report). Best-effort: a unit can disappear between list and read.
            let exec_main_status = if is_service {
                match ServiceProxy::builder(&self.conn)
                    .path(u.object_path.clone())?
                    .cache_properties(CacheProperties::No)
                    .build()
                    .await
                {
                    Ok(svc) => svc.exec_main_status().await.ok(),
                    Err(_) => None,
                }
            } else {
                None
            };

            let is_failed = u.active_state == "failed"
                || (u.sub_state == "auto-restart"
                    && is_service
                    && exec_main_status.map(|s| s != 0).unwrap_or(false));

            if !is_failed {
                continue;
            }

            failed.push(FailedUnit {
                status_dump: systemctl_status(&u.name).await,
                name: u.name,
                active_state: u.active_state,
                sub_state: u.sub_state,
                exec_main_status,
            });
        }
        Ok(FailedUnitsReport { failed })
    }

    /// Drain the signal stream until it goes quiet (250 ms per-message patience
    /// window) or 90 s elapses, returning the count of late `JobRemoved`
    /// events seen. Mirrors switch-to-configuration-ng's settle window
    /// (`main.rs:2452-2462`). Invoke after the last submit + wait so late
    /// events still get counted/reported.
    ///
    /// # Errors
    ///
    /// Currently infallible (always returns `Ok`); the `Result` is kept
    /// for forward compatibility with bus-error reporting.
    pub async fn settle(&self) -> Result<usize> {
        let mut count = 0usize;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
        let mut rx = self.job_event_rx.lock().await;
        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                break;
            }
            let tick = Duration::from_millis(250).min(deadline - now);
            match tokio::time::timeout(tick, rx.recv()).await {
                Ok(Some(())) => count += 1,
                // Channel closed (bus died) or the patience window elapsed
                // with no new event: the bus is quiet, we're done.
                Ok(None) | Err(_) => break,
            }
        }
        Ok(count)
    }

    /// Read the automatic-restart policy of a `.service` unit off its
    /// `org.freedesktop.systemd1.Service` interface.
    ///
    /// # Errors
    ///
    /// Returns an error if the unit is not loaded (`NoSuchUnit`) or the D-Bus
    /// property reads fail.
    pub async fn restart_policy(&self, name: &str) -> Result<RestartPolicy> {
        let path = self.manager.get_unit(name).await?;
        let svc = ServiceProxy::builder(&self.conn)
            .path(path)?
            .cache_properties(CacheProperties::No)
            .build()
            .await?;
        Ok(RestartPolicy {
            restart_sec: Duration::from_micros(svc.restart_usec().await?),
            n_restarts: svc.n_restarts().await.unwrap_or(0),
        })
    }

    /// Wait up to `budget` for an auto-restarting unit to settle to a terminal
    /// state, polling its `ActiveState`/`SubState` every 250 ms.
    ///
    /// A `.service` caught in `SubState == "auto-restart"` is mid-backoff, not
    /// terminally failed: its next start may succeed. This resolves that
    /// ambiguity by waiting until the unit leaves `auto-restart` and reaches
    /// `active` ([`SettleOutcome::Recovered`]) or `failed`
    /// ([`SettleOutcome::Failed`]) — or the budget elapses
    /// ([`SettleOutcome::StillRestarting`]). A unit that has left `auto-restart`
    /// but is still mid-start (`activating`) keeps the poll going until it
    /// terminalizes.
    ///
    /// Transient D-Bus read errors (e.g. the unit momentarily unloaded between
    /// restarts) are tolerated: the poll retries until the deadline. Infallible
    /// by construction — every path resolves to a [`SettleOutcome`].
    pub async fn wait_until_settled(&self, name: &str, budget: Duration) -> SettleOutcome {
        let deadline = tokio::time::Instant::now() + budget;
        loop {
            // Only act once the unit has left `auto-restart`; while it's still
            // mid-backoff (or a read transiently fails) we fall through and poll
            // again. A unit that left auto-restart but isn't yet active/failed
            // (mid start job) also falls through until it terminalizes.
            let settled = self
                .unit_active_sub(name)
                .await
                .ok()
                .filter(|(_, sub)| sub != "auto-restart");
            if let Some((active, _)) = settled {
                if active == "active" {
                    let n_restarts = self
                        .restart_policy(name)
                        .await
                        .map(|p| p.n_restarts)
                        .unwrap_or(0);
                    return SettleOutcome::Recovered { n_restarts };
                }
                if active == "failed" {
                    return SettleOutcome::Failed;
                }
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return SettleOutcome::StillRestarting;
            }
            tokio::time::sleep(Duration::from_millis(250).min(deadline - now)).await;
        }
    }

    /// Read `(ActiveState, SubState)` off a unit's `Unit` interface with
    /// properties uncached, so each poll reflects the live state.
    ///
    /// # Errors
    ///
    /// Returns an error if the unit is not loaded (`NoSuchUnit`) or the D-Bus
    /// property reads fail.
    async fn unit_active_sub(&self, name: &str) -> Result<(String, String)> {
        let path = self.manager.get_unit(name).await?;
        let unit = UnitProxy::builder(&self.conn)
            .path(path)?
            .cache_properties(CacheProperties::No)
            .build()
            .await?;
        Ok((unit.active_state().await?, unit.sub_state().await?))
    }
}

impl PinnedSystemdManager {
    /// Opens the host system bus and pins its current systemd manager owner.
    ///
    /// # Errors
    ///
    /// Returns an error if the system bus is unavailable or the manager cannot
    /// be identified, subscribed, and rechecked on the new connection.
    pub async fn connect() -> Result<Self> {
        SystemdManagerConnection::system().await?.pin().await
    }

    /// Pins the current systemd manager on a caller-supplied bus connection.
    ///
    /// The connection must be attached to a real D-Bus broker because manager
    /// identity uses the bus GUID and unique-name owner.
    ///
    /// # Errors
    ///
    /// Returns an error if the manager cannot be identified, subscribed, or
    /// rechecked on the supplied connection.
    pub async fn from_connection(conn: zbus::Connection) -> Result<Self> {
        let incarnation = read_manager_incarnation(&conn).await?;
        let manager = ManagerProxy::builder(&conn)
            .destination(incarnation.owner.clone())?
            .build()
            .await?;

        // Subscription state belongs to this bus connection and manager
        // process, not to the proxy object. Addressing Subscribe to the unique
        // owner proves which process accepted it and keeps replacement owners
        // outside this pin's signal stream.
        if let Err(error) = manager.subscribe().await
            && !is_already_subscribed(&error)
        {
            return Err(error.into());
        }

        let mut job_removed = manager.receive_job_removed().await?;
        let jobs = Arc::new(Mutex::new(PinnedJobRegistry::default()));
        let jobs_for_task = Arc::clone(&jobs);
        let job_task = tokio::spawn(async move {
            while let Some(signal) = job_removed.next().await {
                let Ok(args) = signal.args() else { continue };
                let path_key = args.job.as_str().to_owned();
                let result = JobResult::from_systemd(&args.result);
                route_pinned_completion(&jobs_for_task, path_key, result);
            }

            let mut registry = lock_pinned_registry(&jobs_for_task);
            registry.closed = true;
            registry.waiters.clear();
        });

        let pinned = Self {
            conn,
            incarnation,
            manager,
            jobs,
            job_task,
        };
        pinned.ensure_current().await?;
        Ok(pinned)
    }

    /// Returns the bus and manager identity held by this pin.
    #[must_use]
    pub fn incarnation(&self) -> &ManagerIncarnation {
        &self.incarnation
    }

    /// Loads one exact unit definition without starting the unit.
    ///
    /// This is a preparation operation for a newly published unit after a
    /// daemon reload. The returned identity is the loaded object path, and the
    /// unit's canonical `Id` must equal `name` so aliases cannot acquire
    /// lifecycle authority.
    ///
    /// # Errors
    ///
    /// Returns an error when the manager incarnation changed, systemd cannot
    /// load the unit, or the requested name resolves as an alias.
    pub async fn load_unit(&self, name: &str) -> Result<String> {
        self.ensure_current().await?;
        let path = self.manager.load_unit(name).await?;
        let identity = path.as_str().to_string();
        let unit = UnitProxy::builder(&self.conn)
            .destination(self.incarnation.owner.clone())?
            .path(path)?
            .cache_properties(CacheProperties::No)
            .build()
            .await?;
        let canonical_name = unit.id().await?;
        if canonical_name != name {
            return Err(Error::UnitAlias {
                requested: name.to_string(),
                canonical: canonical_name,
            });
        }
        Ok(identity)
    }

    /// Loads and retains a canonical unit without starting it.
    ///
    /// Unlike `LoadUnit`, systemd's `RefUnit` loads and references the unit in
    /// one operation. The reference prevents an inactive unit from being
    /// collected between subsequent identity and property reads. It lasts
    /// until this manager's D-Bus connection closes, including its clones.
    /// This operation does not validate a resource revision or grant lifecycle
    /// authority; callers must still validate their owned definition.
    ///
    /// # Errors
    ///
    /// Returns an error if the manager changes, loading or referencing fails,
    /// or the requested name resolves to an alias. An acquired reference stays
    /// attached to the connection even if a later identity check fails.
    pub async fn load_referenced_unit(&self, name: &str) -> Result<String> {
        self.ensure_current().await?;
        self.manager.ref_unit(name).await?;
        self.unit_identity(name).await
    }

    /// Reloads manager configuration through this exact manager incarnation.
    ///
    /// # Errors
    ///
    /// Returns an error when the manager changes before or during the reload,
    /// or when systemd rejects the request.
    pub async fn daemon_reload(&self) -> Result<()> {
        self.ensure_current().await?;
        self.manager.reload().await?;
        self.ensure_current().await
    }

    /// Requests re-execution of this exact manager incarnation.
    ///
    /// The systemd D-Bus method intentionally has no reply. Callers must drop
    /// this pin and establish a new one, then prove that its incarnation differs
    /// before treating the re-execution as complete.
    ///
    /// # Errors
    ///
    /// Returns an error when the manager changed before the request or rejects
    /// the no-reply call.
    pub async fn reexecute(&self) -> Result<()> {
        self.ensure_current().await?;
        self.manager.reexecute().await?;
        Ok(())
    }

    /// Starts a unit through the pinned owner and awaits its exact job result.
    ///
    /// # Errors
    ///
    /// Returns an error if the manager incarnation changed, the call fails, or
    /// the pinned signal stream closes before the job result arrives.
    pub async fn start_unit(&self, name: &str) -> Result<JobOutcome> {
        self.ensure_current().await?;
        let submission = self.begin_submission()?;
        let path = self.manager.start_unit(name, "replace").await?;
        self.await_submission(submission, path).await
    }

    /// Stops a unit through the pinned owner and awaits its exact job result.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`PinnedSystemdManager::start_unit`].
    pub async fn stop_unit(&self, name: &str) -> Result<JobOutcome> {
        self.ensure_current().await?;
        let submission = self.begin_submission()?;
        let path = self.manager.stop_unit(name, "replace").await?;
        self.await_submission(submission, path).await
    }

    /// Restarts a unit through the pinned owner and awaits its exact job result.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`PinnedSystemdManager::start_unit`].
    pub async fn restart_unit(&self, name: &str) -> Result<JobOutcome> {
        self.ensure_current().await?;
        let submission = self.begin_submission()?;
        let path = self.manager.restart_unit(name, "replace").await?;
        self.await_submission(submission, path).await
    }

    /// Reloads a unit through the pinned owner and awaits its exact job result.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`PinnedSystemdManager::start_unit`].
    pub async fn reload_unit(&self, name: &str) -> Result<JobOutcome> {
        self.ensure_current().await?;
        let submission = self.begin_submission()?;
        let path = self.manager.reload_unit(name, "replace").await?;
        self.await_submission(submission, path).await
    }

    /// Starts one canonical unit after rechecking its admission-qualified identity.
    ///
    /// # Errors
    ///
    /// Returns an error if `name` is an alias, the unit object changed since
    /// admission, the manager incarnation changed, or the job does not complete.
    pub async fn start_unit_exact(
        &self,
        name: &str,
        expected_identity: &str,
    ) -> Result<JobOutcome> {
        let unit = self.exact_unit(name, expected_identity).await?;
        let submission = self.begin_submission()?;
        let path = unit.start("replace").await?;
        self.await_submission(submission, path).await
    }

    /// Starts one canonical unit after rechecking its object and loaded revision.
    ///
    /// `expected_revision` is the semantic revision encoded by the canonical
    /// AOS `file:` receipt URI in the unit's parsed `Documentation=` property.
    ///
    /// # Errors
    ///
    /// Returns an error if the unit identity or loaded revision changed, the
    /// revision marker is missing or ambiguous, or the job does not complete.
    pub async fn start_unit_exact_revision(
        &self,
        name: &str,
        expected_identity: &str,
        expected_revision: &str,
    ) -> Result<JobOutcome> {
        let unit = self
            .exact_unit_revision(name, expected_identity, expected_revision)
            .await?;
        let submission = self.begin_submission()?;
        let path = unit.start("replace").await?;
        self.await_submission(submission, path).await
    }

    /// Starts one canonical unit only when its loaded definition is current.
    ///
    /// # Errors
    ///
    /// Returns an error if the unit identity changed, systemd reports that a
    /// daemon reload is needed, or the job does not complete.
    pub async fn start_unit_exact_current(
        &self,
        name: &str,
        expected_identity: &str,
    ) -> Result<JobOutcome> {
        let unit = self.exact_unit(name, expected_identity).await?;
        if unit.need_daemon_reload().await? {
            return Err(Error::UnitNeedsDaemonReload {
                unit: name.to_string(),
            });
        }
        let submission = self.begin_submission()?;
        let path = unit.start("replace").await?;
        self.await_submission(submission, path).await
    }

    /// Stops one canonical unit after rechecking its admission-qualified identity.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::start_unit_exact`].
    pub async fn stop_unit_exact(&self, name: &str, expected_identity: &str) -> Result<JobOutcome> {
        let unit = self.exact_unit(name, expected_identity).await?;
        let submission = self.begin_submission()?;
        let path = unit.stop("replace").await?;
        self.await_submission(submission, path).await
    }

    /// Stops one canonical unit after rechecking its object and loaded revision.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::start_unit_exact_revision`].
    pub async fn stop_unit_exact_revision(
        &self,
        name: &str,
        expected_identity: &str,
        expected_revision: &str,
    ) -> Result<JobOutcome> {
        let unit = self
            .exact_unit_revision(name, expected_identity, expected_revision)
            .await?;
        let submission = self.begin_submission()?;
        let path = unit.stop("replace").await?;
        self.await_submission(submission, path).await
    }

    /// Restarts one canonical unit after rechecking its admission-qualified identity.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::start_unit_exact`].
    pub async fn restart_unit_exact(
        &self,
        name: &str,
        expected_identity: &str,
    ) -> Result<JobOutcome> {
        let unit = self.exact_unit(name, expected_identity).await?;
        let submission = self.begin_submission()?;
        let path = unit.restart("replace").await?;
        self.await_submission(submission, path).await
    }

    /// Restarts one canonical unit after rechecking its object and loaded revision.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::start_unit_exact_revision`].
    pub async fn restart_unit_exact_revision(
        &self,
        name: &str,
        expected_identity: &str,
        expected_revision: &str,
    ) -> Result<JobOutcome> {
        let unit = self
            .exact_unit_revision(name, expected_identity, expected_revision)
            .await?;
        let submission = self.begin_submission()?;
        let path = unit.restart("replace").await?;
        self.await_submission(submission, path).await
    }

    /// Reloads one canonical unit after rechecking its admission-qualified identity.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::start_unit_exact`].
    pub async fn reload_unit_exact(
        &self,
        name: &str,
        expected_identity: &str,
    ) -> Result<JobOutcome> {
        let unit = self.exact_unit(name, expected_identity).await?;
        let submission = self.begin_submission()?;
        let path = unit.reload("replace").await?;
        self.await_submission(submission, path).await
    }

    /// Reloads one canonical unit after rechecking its object and loaded revision.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::start_unit_exact_revision`].
    pub async fn reload_unit_exact_revision(
        &self,
        name: &str,
        expected_identity: &str,
        expected_revision: &str,
    ) -> Result<JobOutcome> {
        let unit = self
            .exact_unit_revision(name, expected_identity, expected_revision)
            .await?;
        let submission = self.begin_submission()?;
        let path = unit.reload("replace").await?;
        self.await_submission(submission, path).await
    }

    /// Reports whether a unit is active according to the pinned owner.
    ///
    /// An unloaded unit is inactive.
    ///
    /// # Errors
    ///
    /// Returns an error if the manager incarnation changed or the D-Bus
    /// inspection fails for a reason other than `NoSuchUnit`.
    pub async fn is_active(&self, name: &str) -> Result<bool> {
        self.ensure_current().await?;
        match self.manager.get_unit(name).await {
            Ok(path) => {
                let unit = UnitProxy::builder(&self.conn)
                    .destination(self.incarnation.owner.clone())?
                    .path(path)?
                    .cache_properties(CacheProperties::No)
                    .build()
                    .await?;
                Ok(unit.active_state().await? == "active")
            }
            Err(error) if is_no_such_unit(&error) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    /// Reports activity only after rechecking a canonical qualified unit identity.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::start_unit_exact`], plus failures
    /// while reading the unit's active state.
    pub async fn is_active_exact(&self, name: &str, expected_identity: &str) -> Result<bool> {
        Ok(self
            .active_state_exact(name, expected_identity)
            .await?
            .is_active())
    }

    /// Returns a unit's exact active state after rechecking its qualified identity.
    ///
    /// Unknown future systemd labels remain available through
    /// [`UnitActiveState::Unknown`] instead of being collapsed into inactivity.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::start_unit_exact`], plus failures
    /// while reading the unit's active state.
    pub async fn active_state_exact(
        &self,
        name: &str,
        expected_identity: &str,
    ) -> Result<UnitActiveState> {
        let unit = self.exact_unit(name, expected_identity).await?;
        Ok(UnitActiveState::from_systemd(&unit.active_state().await?))
    }

    /// Returns the cgroup of an exact loaded service unit.
    ///
    /// # Errors
    ///
    /// Returns an error when the manager or unit identity changed, the unit is
    /// not a service, or its cgroup property cannot be read.
    pub async fn service_control_group_exact(
        &self,
        name: &str,
        expected_identity: &str,
    ) -> Result<String> {
        self.exact_unit(name, expected_identity).await?;
        let service = ServiceProxy::builder(&self.conn)
            .destination(self.incarnation.owner.clone())?
            .path(expected_identity)?
            .cache_properties(CacheProperties::No)
            .build()
            .await?;
        let control_group = service.control_group().await?;
        self.exact_unit(name, expected_identity).await?;
        Ok(control_group)
    }

    /// Reports whether one exact loaded unit needs a manager reload.
    ///
    /// The property is read without a proxy cache from the canonical unit
    /// object selected during admission.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::start_unit_exact`], plus failures
    /// while reading systemd's `NeedDaemonReload` property.
    pub async fn needs_daemon_reload_exact(
        &self,
        name: &str,
        expected_identity: &str,
    ) -> Result<bool> {
        let unit = self.exact_unit(name, expected_identity).await?;
        Ok(unit.need_daemon_reload().await?)
    }

    /// Returns the fragment and drop-ins loaded for one exact unit object.
    ///
    /// The values come from the pinned manager without a proxy cache, so a
    /// caller can compare its loaded definition with the image's unit tree.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::start_unit_exact`], plus failures
    /// while reading the unit's definition paths.
    pub async fn unit_definition_paths_exact(
        &self,
        name: &str,
        expected_identity: &str,
    ) -> Result<(String, Vec<String>)> {
        let unit = self.exact_unit(name, expected_identity).await?;
        Ok((unit.fragment_path().await?, unit.drop_in_paths().await?))
    }

    /// Returns a unit's active state after checking its object and loaded revision.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::start_unit_exact_revision`], plus
    /// failures while reading the unit's active state.
    pub async fn active_state_exact_revision(
        &self,
        name: &str,
        expected_identity: &str,
        expected_revision: &str,
    ) -> Result<UnitActiveState> {
        let unit = self
            .exact_unit_revision(name, expected_identity, expected_revision)
            .await?;
        Ok(UnitActiveState::from_systemd(&unit.active_state().await?))
    }

    /// Resolves a configured unit name to systemd's canonical object identity.
    ///
    /// The resolved object's canonical `Id` must equal `name`, so aliases are
    /// rejected before they can become durable resource bindings.
    ///
    /// # Errors
    ///
    /// Returns an error when the manager incarnation changed or the unit cannot
    /// be resolved by the pinned owner.
    pub async fn unit_identity(&self, name: &str) -> Result<String> {
        let (identity, canonical_name) = self.resolve_unit_identity(name).await?;
        if canonical_name != name {
            return Err(Error::UnitAlias {
                requested: name.to_string(),
                canonical: canonical_name,
            });
        }
        Ok(identity)
    }

    /// Resolves a canonical unit and verifies the revision parsed by systemd.
    ///
    /// This reads the uncached `Documentation` property from the loaded unit
    /// object. Exactly one entry must equal the canonical AOS `file:` receipt
    /// URI for this unit and revision; missing, duplicate, or conflicting AOS
    /// receipt markers fail closed.
    ///
    /// # Errors
    ///
    /// Returns an error when the manager changed, the name is an alias, the
    /// unit is not loaded, or its loaded AOS revision is absent or differs.
    pub async fn unit_identity_at_revision(
        &self,
        name: &str,
        expected_revision: &str,
    ) -> Result<String> {
        let (identity, unit) = self.resolve_unit(name).await?;
        require_unit_revision(name, &unit.documentation().await?, expected_revision)?;
        Ok(identity)
    }

    async fn exact_unit<'a>(
        &'a self,
        name: &str,
        expected_identity: &str,
    ) -> Result<UnitProxy<'a>> {
        self.ensure_current().await?;
        let path = self.manager.get_unit(name).await?;
        let actual = path.as_str().to_string();
        let unit = UnitProxy::builder(&self.conn)
            .destination(self.incarnation.owner.clone())?
            .path(path)?
            .cache_properties(CacheProperties::No)
            .build()
            .await?;
        let canonical_name = unit.id().await?;
        if canonical_name != name {
            return Err(Error::UnitAlias {
                requested: name.to_string(),
                canonical: canonical_name,
            });
        }
        if actual != expected_identity {
            return Err(Error::UnitIdentityChanged {
                unit: name.to_string(),
                expected: expected_identity.to_string(),
                actual,
            });
        }
        Ok(unit)
    }

    async fn exact_unit_revision<'a>(
        &'a self,
        name: &str,
        expected_identity: &str,
        expected_revision: &str,
    ) -> Result<UnitProxy<'a>> {
        let unit = self.exact_unit(name, expected_identity).await?;
        require_unit_revision(name, &unit.documentation().await?, expected_revision)?;
        Ok(unit)
    }

    async fn resolve_unit_identity(&self, name: &str) -> Result<(String, String)> {
        let (identity, unit) = self.resolve_unit(name).await?;
        let canonical_name = unit.id().await?;
        Ok((identity, canonical_name))
    }

    async fn resolve_unit<'a>(&'a self, name: &str) -> Result<(String, UnitProxy<'a>)> {
        self.ensure_current().await?;
        let path = self.manager.get_unit(name).await?;
        let identity = path.as_str().to_string();
        let unit = UnitProxy::builder(&self.conn)
            .destination(self.incarnation.owner.clone())?
            .path(path)?
            .cache_properties(CacheProperties::No)
            .build()
            .await?;
        let canonical_name = unit.id().await?;
        if canonical_name != name {
            return Err(Error::UnitAlias {
                requested: name.to_string(),
                canonical: canonical_name,
            });
        }
        Ok((identity, unit))
    }

    async fn ensure_current(&self) -> Result<()> {
        if read_manager_incarnation(&self.conn).await? == self.incarnation {
            Ok(())
        } else {
            Err(Error::ManagerIncarnationChanged)
        }
    }

    fn begin_submission(&self) -> Result<PinnedSubmission> {
        PinnedSubmission::begin(&self.jobs)
    }

    async fn await_submission(
        &self,
        mut submission: PinnedSubmission,
        path: OwnedObjectPath,
    ) -> Result<JobOutcome> {
        let path_key = path.as_str().to_owned();
        let receiver = match submission.register(&path_key)? {
            PinnedRegistration::Completed(result) => {
                return Ok(JobOutcome {
                    job_path: path,
                    result,
                });
            }
            PinnedRegistration::Pending(receiver) => receiver,
        };
        let result = match receiver.await {
            Ok(result) => result,
            Err(_) if lock_pinned_registry(&self.jobs).overflowed => {
                return Err(Error::JobCompletionOverflow);
            }
            Err(_) => return Err(Error::JobSenderDropped(path.as_str().to_string())),
        };
        submission.finish();
        Ok(JobOutcome {
            job_path: path,
            result,
        })
    }
}

const UNIT_REVISION_RECEIPT_PREFIX: &str = "file:/etc/aos/ability-revisions/";

fn require_unit_revision(
    unit: &str,
    documentation: &[String],
    expected_revision: &str,
) -> Result<()> {
    let mut revisions = documentation
        .iter()
        .filter(|entry| entry.starts_with(UNIT_REVISION_RECEIPT_PREFIX));
    let Some(actual) = revisions.next() else {
        return Err(Error::UnitRevisionUnknown {
            unit: unit.to_string(),
        });
    };
    if revisions.next().is_some() {
        return Err(Error::UnitRevisionUnknown {
            unit: unit.to_string(),
        });
    }
    let expected = unit_revision_receipt_uri(unit, expected_revision).ok_or_else(|| {
        Error::UnitRevisionUnknown {
            unit: unit.to_string(),
        }
    })?;
    if actual != &expected {
        return Err(Error::UnitRevisionChanged {
            unit: unit.to_string(),
            expected,
            actual: (*actual).clone(),
        });
    }
    Ok(())
}

fn unit_revision_receipt_uri(unit: &str, revision: &str) -> Option<String> {
    let digest = revision.strip_prefix("sha256:")?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return None;
    }
    Some(format!(
        "{UNIT_REVISION_RECEIPT_PREFIX}{}/sha256/{digest}",
        encode_uri_path_segment(unit)
    ))
}

fn encode_uri_path_segment(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

impl SystemdManagerConnection {
    /// Opens an explicit host system-bus capability without starting listeners.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SystemdUnavailable`] when the host system bus cannot be
    /// reached.
    pub async fn system() -> Result<Self> {
        let conn = zbus::Connection::system()
            .await
            .map_err(Error::SystemdUnavailable)?;
        Ok(Self { conn })
    }

    /// Wraps a caller-selected bus connection without changing its scope.
    #[must_use]
    pub const fn from_connection(conn: zbus::Connection) -> Self {
        Self { conn }
    }

    /// Pins the current manager on this exact connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the manager cannot be identified, subscribed, or
    /// rechecked on the retained connection.
    pub async fn pin(&self) -> Result<PinnedSystemdManager> {
        PinnedSystemdManager::from_connection(self.conn.clone()).await
    }
}

impl Drop for PinnedSystemdManager {
    fn drop(&mut self) {
        self.job_task.abort();
    }
}

async fn read_manager_incarnation(conn: &zbus::Connection) -> Result<ManagerIncarnation> {
    let proxy = zbus::fdo::DBusProxy::new(conn).await?;
    let service =
        zbus::names::BusName::try_from("org.freedesktop.systemd1").map_err(zbus::Error::from)?;
    let bus = proxy.get_id().await?;
    let owner = proxy.get_name_owner(service).await?;
    Ok(ManagerIncarnation {
        bus_id: bus.to_string(),
        owner: owner.to_string(),
    })
}

fn is_already_subscribed(error: &zbus::Error) -> bool {
    matches!(error, zbus::Error::MethodError(name, _, _) if name.as_str() == SYSTEMD_ALREADY_SUBSCRIBED)
}

fn lock_pinned_registry(
    registry: &Mutex<PinnedJobRegistry>,
) -> std::sync::MutexGuard<'_, PinnedJobRegistry> {
    registry
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn route_pinned_completion(jobs: &Mutex<PinnedJobRegistry>, path_key: String, result: JobResult) {
    let mut registry = lock_pinned_registry(jobs);
    let waiters = registry.waiters.remove(&path_key).unwrap_or_default();
    for sender in waiters.into_values() {
        let _ = sender.send(result.clone());
    }

    if registry.active_submissions == 0 {
        return;
    }
    if registry.completed.contains_key(&path_key)
        || registry.completed.len() < PINNED_COMPLETION_LIMIT
    {
        registry.completed.insert(path_key, result);
        return;
    }

    registry.overflowed = true;
    registry.completed.clear();
    registry.waiters.clear();
}

impl Drop for SystemdClient {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        if let Some(original) = self.host_launch.as_ref() {
            for task in &self.tasks { task.abort(); }
            let Ok(mut original) = original.lock() else { std::process::abort() };
            if !self.tasks.is_empty() { std::process::abort(); }
            let Ok(tasks) = original.tasks.try_lock() else { std::process::abort() };
            for task in tasks.iter() {
                if let Some(handle) = task.handle.as_ref() { handle.abort(); }
            }
            return;
        }
        if self.readonly_controller {
            return;
        }

        // Stop the background listeners.
        for task in &self.tasks {
            task.abort();
        }
        // Best-effort Unsubscribe. Drop can't await, so spawn a detached,
        // time-boxed task (only if we're inside a runtime). The manager proxy
        // holds an Arc to the connection internals, keeping it alive long
        // enough for the call.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let manager = self.manager.clone();
            handle.spawn(async move {
                let _ = tokio::time::timeout(Duration::from_secs(2), manager.unsubscribe()).await;
            });
        }
        let _ = &self.conn;
    }
}

/// Capture `systemctl status --no-pager --full <unit>` for human display. This
/// is the *only* `systemctl` shell-out remaining after this spec lands —
/// D-Bus introspection of the journal would be substantial extra work and the
/// resulting text is for display only, never policy.
async fn systemctl_status(unit: &str) -> String {
    match tokio::process::Command::new("systemctl")
        .args(["status", "--no-pager", "--full", unit])
        .output()
        .await
    {
        Ok(out) => String::from_utf8_lossy(&out.stdout).into_owned(),
        Err(e) => format!("(failed to capture `systemctl status {unit}`: {e})"),
    }
}

#[cfg(all(test, target_os = "linux"))]
mod publisher_observer_tests {
    use super::*;

    #[test]
    fn ended_publisher_transport_refuses_before_any_constructor_or_pid1_read() {
        let mut attempt = ControllerPropertyObserverAttemptV1::with_materialization_limit(64 * 1024);
        attempt.end();
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());

        for _ in 0..2 {
            let result = {
                let mut observation = std::pin::pin!(attempt.observe_controller_publisher_service_v1());
                std::future::Future::poll(observation.as_mut(), &mut context)
            };

            assert!(matches!(result, std::task::Poll::Ready(Err(_))));
            assert!(attempt.constructor_result().is_none());
            assert!(attempt.publisher_service_result_v1().is_none());
            assert!(attempt.control_group_result_v1().is_none());
            assert!(attempt.has_ended());
        }
    }
}

// Network FD-store shares the actual fixed schema and unique-PID1 sampler.
// These crate-private adapters expose no general property program or proxy.
#[cfg(target_os = "linux")]
pub(crate) fn network_fd_store_decoded_geometry_v4(materialized: usize, incoming: usize)
    -> Option<(usize, usize)>
{
    fixed_property::decoded_geometry_for_schedule_v2(materialized, incoming)
}

#[cfg(target_os = "linux")]
pub(crate) async fn network_fd_store_manager_post_v4(connection: &zbus::Connection) -> Result<()> {
    service_properties::capture_pid1_owner_v2(connection).await.map(|_| ())
}

#[cfg(target_os = "linux")]
pub(crate) use service_properties::{capture_network_fd_store_bookend_v4,
    capture_fixed_inventory_fd_store_bookend_v2, FixedFdStoreRoleV2};

#[cfg(test)]
mod pinned_tests {
    use super::*;

    #[test]
    fn loaded_unit_revision_requires_one_exact_marker() {
        let revision = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let marker = unit_revision_receipt_uri("example.service", revision).unwrap();

        require_unit_revision("example.service", &[marker.clone()], revision).unwrap();
        assert!(matches!(
            require_unit_revision("example.service", &[], revision),
            Err(Error::UnitRevisionUnknown { .. })
        ));
        assert!(matches!(
            require_unit_revision(
                "example.service",
                &[marker.clone(), marker.clone(),],
                revision,
            ),
            Err(Error::UnitRevisionUnknown { .. })
        ));
        assert!(matches!(
            require_unit_revision(
                "example.service",
                &[
                    marker,
                    unit_revision_receipt_uri(
                        "example.service",
                        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    )
                    .unwrap(),
                ],
                revision,
            ),
            Err(Error::UnitRevisionUnknown { .. })
        ));
        assert!(matches!(
            require_unit_revision(
                "example.service",
                &[unit_revision_receipt_uri(
                    "example.service",
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                )
                .unwrap()],
                revision,
            ),
            Err(Error::UnitRevisionChanged { .. })
        ));
    }

    #[test]
    fn unrelated_early_completions_fail_closed_at_the_bound() {
        let jobs = Mutex::new(PinnedJobRegistry {
            active_submissions: 1,
            pending_calls: 1,
            ..PinnedJobRegistry::default()
        });

        for index in 0..PINNED_COMPLETION_LIMIT {
            route_pinned_completion(&jobs, format!("/unrelated/{index}"), JobResult::Done);
        }
        assert_eq!(
            lock_pinned_registry(&jobs).completed.len(),
            PINNED_COMPLETION_LIMIT
        );

        route_pinned_completion(&jobs, "/overflow".to_string(), JobResult::Done);
        let registry = lock_pinned_registry(&jobs);
        assert!(registry.overflowed);
        assert!(registry.completed.is_empty());
    }

    #[test]
    fn idle_pinned_registry_discards_unrelated_completions() {
        let jobs = Mutex::new(PinnedJobRegistry::default());

        route_pinned_completion(&jobs, "/unrelated/1".to_string(), JobResult::Done);

        assert!(lock_pinned_registry(&jobs).completed.is_empty());
    }

    #[test]
    fn never_completing_calls_are_bounded_across_registered_waiters() {
        let jobs = Arc::new(Mutex::new(PinnedJobRegistry::default()));
        let mut calls = Vec::with_capacity(PINNED_COMPLETION_LIMIT);

        for index in 0..PINNED_COMPLETION_LIMIT {
            let mut submission = PinnedSubmission::begin(&jobs).unwrap();
            let registration = submission.register(&format!("/job/{index}")).unwrap();
            assert!(matches!(registration, PinnedRegistration::Pending(_)));
            calls.push(submission);
        }

        let registry = lock_pinned_registry(&jobs);
        assert_eq!(registry.pending_calls, PINNED_COMPLETION_LIMIT);
        assert_eq!(
            registry.waiters.values().map(BTreeMap::len).sum::<usize>(),
            PINNED_COMPLETION_LIMIT
        );
        drop(registry);
        assert!(matches!(
            PinnedSubmission::begin(&jobs),
            Err(Error::JobCompletionOverflow)
        ));

        drop(calls);
        let registry = lock_pinned_registry(&jobs);
        assert_eq!(registry.pending_calls, 0);
        assert!(registry.waiters.is_empty());
    }

    #[test]
    fn dropping_an_awaiting_call_removes_its_waiter() {
        let jobs = Arc::new(Mutex::new(PinnedJobRegistry::default()));
        let mut submission = PinnedSubmission::begin(&jobs).unwrap();
        let registration = submission.register("/job/cancelled").unwrap();
        assert!(matches!(registration, PinnedRegistration::Pending(_)));
        assert_eq!(lock_pinned_registry(&jobs).pending_calls, 1);

        drop(submission);

        let registry = lock_pinned_registry(&jobs);
        assert_eq!(registry.pending_calls, 0);
        assert!(registry.waiters.is_empty());
    }

    #[tokio::test]
    async fn duplicate_job_path_completion_wakes_every_waiter() {
        let jobs = Arc::new(Mutex::new(PinnedJobRegistry::default()));
        let mut first = PinnedSubmission::begin(&jobs).unwrap();
        let mut second = PinnedSubmission::begin(&jobs).unwrap();
        let PinnedRegistration::Pending(first_receiver) = first.register("/job/merged").unwrap()
        else {
            panic!("first call unexpectedly completed before a signal");
        };
        let PinnedRegistration::Pending(second_receiver) = second.register("/job/merged").unwrap()
        else {
            panic!("second call unexpectedly completed before a signal");
        };

        route_pinned_completion(&jobs, "/job/merged".to_string(), JobResult::Done);

        assert_eq!(first_receiver.await.unwrap(), JobResult::Done);
        assert_eq!(second_receiver.await.unwrap(), JobResult::Done);
        first.finish();
        second.finish();
        let registry = lock_pinned_registry(&jobs);
        assert_eq!(registry.pending_calls, 0);
        assert!(registry.waiters.is_empty());
    }

    #[tokio::test]
    async fn merged_early_completion_reaches_a_later_method_reply() {
        let jobs = Arc::new(Mutex::new(PinnedJobRegistry::default()));
        let mut first = PinnedSubmission::begin(&jobs).unwrap();
        let mut second = PinnedSubmission::begin(&jobs).unwrap();
        let PinnedRegistration::Pending(first_receiver) = first.register("/job/merged").unwrap()
        else {
            panic!("first call unexpectedly completed before a signal");
        };

        route_pinned_completion(&jobs, "/job/merged".to_string(), JobResult::Done);

        let PinnedRegistration::Completed(second_result) = second.register("/job/merged").unwrap()
        else {
            panic!("early completion was not retained for the pending method reply");
        };
        assert_eq!(first_receiver.await.unwrap(), JobResult::Done);
        assert_eq!(second_result, JobResult::Done);
        first.finish();
        let registry = lock_pinned_registry(&jobs);
        assert_eq!(registry.pending_calls, 0);
        assert!(registry.completed.is_empty());
        assert!(registry.waiters.is_empty());
    }
}
