//! Retains the fixed Network descriptor-store observation on the shared reader.
//!
//! The selected caller is the synchronous fixed service main. Its already-paid
//! current-thread Runtime and raw connection remain here through all failures
//! and independent service posts; no secondary inspector thread or bus address
//! is selected by caller DATA. Ordinary inspector threading remains unchanged.

use super::*;
use std::sync::Arc;
use zbus::connection::socket::{LauncherImageFailureLoanV1, LauncherImageFailureRefV1};
use zbus::connection::{NetworkFdStoreConnectionOriginalV4, NetworkFdStoreReceiveScheduleV4};

/// Reports a refused original without moving any native failure out of custody.
#[derive(Debug, thiserror::Error)]
#[error("fixed Network descriptor-store inspection is incomplete or refused")]
pub struct NetworkFdStoreInspectionRefusalV4;

/// Describes actual finite connection, Runtime, decoder and traffic liabilities.
#[derive(Clone, Copy, Debug)]
pub struct NetworkFdStoreFootprintV4 {
    /// Complete native collector, typed rows, Runtime and construction bytes.
    pub memory_bytes: usize,
    /// Socket, connect alias, native control prefix and current-thread driver.
    pub open_files: usize,
    /// Dynamic decoded row/map namespace entries and fixed bus socket name.
    pub metadata_entries: usize,
    /// AUTH and enforced finite outgoing/incoming wire traffic.
    pub network_bytes: usize,
    /// Source-bounded native/SDK error rendering and frame diagnostic output.
    pub maximum_log_bytes: usize,
}

/// Borrows the exact resident native or SDK first cause without flattening it.
pub enum NetworkFdStoreFailureViewV4<'held> {
    /// The original raw transport retains its native or protocol source.
    Native(LauncherImageFailureLoanV1<'held>),
    /// A typed Runtime, SDK, deadline or local invariant failure stays resident.
    Cause(&'held (dyn std::error::Error + 'static)),
}

impl std::fmt::Debug for NetworkFdStoreFailureViewV4<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NetworkFdStoreFailureViewV4")
    }
}

impl std::fmt::Display for NetworkFdStoreFailureViewV4<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Native(original) => match original.cause() {
                LauncherImageFailureRefV1::Native(cause) => {
                    std::fmt::Display::fmt(cause, formatter)
                }
                LauncherImageFailureRefV1::Protocol(cause) => {
                    std::fmt::Display::fmt(cause, formatter)
                }
                LauncherImageFailureRefV1::Ended => {
                    formatter.write_str("original Network transport ended")
                }
            },
            Self::Cause(cause) => std::fmt::Display::fmt(cause, formatter),
        }
    }
}

impl std::error::Error for NetworkFdStoreFailureViewV4<'_> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Native(original) => match original.cause() {
                LauncherImageFailureRefV1::Native(cause) => Some(cause),
                LauncherImageFailureRefV1::Protocol(cause) => Some(cause),
                LauncherImageFailureRefV1::Ended => None,
            },
            Self::Cause(cause) => Some(*cause),
        }
    }
}

use crate::client::FixedFdStoreRoleV2 as Role;

#[derive(Clone, Copy)]
enum First {
    Runtime,
    Connect,
    Snapshot(usize),
    Close,
    Disposal,
    Closed,
}

#[derive(Clone, Copy)]
enum SnapshotFirst {
    Before,
    Body,
    After,
    Timeout,
}

struct Observation {
    before: Option<crate::Result<crate::client::ServicePropertyBookendV1<'static>>>,
    dump: Option<Result<zbus::Message, zbus::Error>>,
    parts: SnapshotPartsV1,
    returned: Option<Result<FdStoreSnapshot, SnapshotReadErrorV1>>,
    after: Option<crate::Result<()>>,
    timeout: Option<tokio::time::error::Elapsed>,
    first: Option<SnapshotFirst>,
    native_selected: bool,
    taken: bool,
}

impl Observation {
    fn new() -> Self {
        Self {
            before: None,
            dump: None,
            parts: SnapshotPartsV1::default(),
            returned: None,
            after: None,
            timeout: None,
            first: None,
            native_selected: false,
            taken: false,
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            SnapshotFirst::Before => self.before.as_ref()?.as_ref().err().map(|cause| cause as _),
            SnapshotFirst::Body => self
                .dump
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as _)
                .or_else(|| {
                    self.returned
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                }),
            SnapshotFirst::After => self.after.as_ref()?.as_ref().err().map(|cause| cause as _),
            SnapshotFirst::Timeout => self.timeout.as_ref().map(|cause| cause as _),
        }
    }
}

/// Owns two fixed Network FD-store snapshots and every reached native prefix.
///
/// The real Network startup or request F admits the complete supplier before
/// `connect_once_v4`. The owner authenticates PID1 and its actual same service
/// process; it supplies neither a namespace, descriptor-store mutation permit,
/// resource grant nor replacement operation. Its local success does not finish
/// independently owed outer F posts.
#[must_use = "retain actual Runtime, bus and snapshot failures through outer posts"]
pub struct NetworkFdStoreInspectionOriginalV4 {
    role: Role,
    native: Option<NetworkFdStoreConnectionOriginalV4>,
    runtime: Option<std::io::Result<Arc<tokio::runtime::Runtime>>>,
    connection: Option<zbus::Connection>,
    connect: Option<Result<(), zbus::Error>>,
    connect_timeout: Option<tokio::time::error::Elapsed>,
    snapshots: [Observation; 2],
    next_snapshot: usize,
    deadline: Option<tokio::time::Instant>,
    closed: Option<crate::Error>,
    close: Option<Result<(), zbus::Error>>,
    close_timeout: Option<tokio::time::error::Elapsed>,
    disposal: Option<Result<(), ()>>,
    first: Option<First>,
    connect_native_selected: bool,
    entered: bool,
}

impl NetworkFdStoreInspectionOriginalV4 {
    pub(crate) fn worker_census_runtime_v4(&self) -> Option<Arc<tokio::runtime::Runtime>> {
        if !matches!(self.role, Role::Network) || !self.entered { return None; }
        self.runtime.as_ref()?.as_ref().ok().map(Arc::clone)
    }

    /// Creates inline empty destinations without IO or dynamic allocation.
    #[must_use]
    pub fn new() -> Self { Self::new_for_role_v2(Role::Network) }

    /// Returns restrictive finite wire extents for a zero-store observation.
    ///
    /// Larger native replies retain refusal rather than growing this bound.
    pub fn fixed_schedule_shape_v2() -> Option<(usize, usize)> {
        let raw = NetworkFdStoreReceiveScheduleV4::new(16, 16).ok()?.raw_data_v4();
        Some((raw.maximum_request_bytes(), raw.incoming_messages()))
    }

    /// Creates only the fixed Mount inventory observation destination.
    ///
    /// No receiving, native IO or service authority follows from construction.
    #[must_use]
    pub fn new_mount_inventory_v2() -> Self { Self::new_for_role_v2(Role::Mount) }

    fn new_for_role_v2(role: Role) -> Self {
        Self {
            role,
            native: None,
            runtime: None,
            connection: None,
            connect: None,
            connect_timeout: None,
            snapshots: std::array::from_fn(|_| Observation::new()),
            next_snapshot: 0,
            deadline: None,
            closed: None,
            close: None,
            close_timeout: None,
            disposal: None,
            first: None,
            connect_native_selected: false,
            entered: false,
        }
    }

    /// Checks passive finite extents and returns their complete pre-entry cost.
    ///
    /// Wire/materialization ceilings are restrictive DATA selected against the
    /// actual original capacity. Exhaustion retains the true raw refusal; this
    /// helper does not assert that every possible systemd reply will fit them.
    #[must_use]
    pub fn receiving_footprint_v4(
        maximum_message_bytes: usize,
        maximum_materialized_bytes: usize,
    ) -> Option<NetworkFdStoreFootprintV4> {
        let schedule =
            NetworkFdStoreReceiveScheduleV4::new(maximum_message_bytes, maximum_materialized_bytes)
                .ok()?;
        let raw = schedule.raw_data_v4();
        // The same raw native prefix enforces a cumulative receive ceiling;
        // it cannot read every frame at its maximum after that prefix is full.
        // Keep the failed terminal primary header and both AUTH directions.
        let traffic = raw
            .outgoing_messages()
            .checked_mul(raw.maximum_request_bytes())?
            .checked_add(raw.raw_receive_bytes_v2().0)?
            .checked_add(zbus::connection::ControllerPropertyReceiveAttemptV1::AUTH_BYTES)?;
        // A row contains seven numeric values and two strings. Even empty
        // strings need their wire length/terminator; no valid array element can
        // be smaller than these scalar fields. The entire raw extent separately
        // covers both strings' backing, malformed length and decoder overlap.
        let minimum_row = 6 * 4 + 8 + 2 * (4 + 1);
        let rows = maximum_materialized_bytes / minimum_row;
        let row_carriers = rows
            .checked_add(1)?
            .checked_mul(3 * std::mem::size_of::<RawFdStoreRow>())?;
        let (decoded_memory, decoded_namespaces) =
            crate::client::network_fd_store_decoded_geometry_v4(
                maximum_materialized_bytes,
                raw.incoming_messages(),
            )?;
        let memory = schedule
            .receiving_storage_bytes_v4()?
            .checked_add(2 * std::mem::size_of::<Self>())?
            .checked_add(
                tokio::runtime::Builder::default_current_thread_io_time_receiving_bytes_v4()?,
            )?
            .checked_add(2 * std::mem::size_of::<zbus::Connection>())?
            .checked_add(row_carriers)?
            .checked_add(maximum_materialized_bytes.checked_mul(4)?)?
            .checked_add(decoded_memory)?;
        Some(NetworkFdStoreFootprintV4 {
            memory_bytes: memory,
            // The current-thread runtime uses the existing IO/time driver:
            // epoll owner + cloned registry, eventfd, global signal pair and
            // per-driver receiver duplicate. The global pair may remain even
            // when a private constructor prefix unwinds; no failure credit is
            // exposed here. Count all six separately from raw bus IO.
            open_files: schedule.maximum_native_files_v4()?.checked_add(6)?,
            metadata_entries: rows
                .checked_mul(2)?
                .checked_add(raw.outgoing_messages())?
                .checked_add(decoded_namespaces)?
                .checked_add(1)?,
            network_bytes: traffic,
            maximum_log_bytes: traffic.checked_mul(64)?.checked_add(
                raw.incoming_messages()
                    .checked_add(raw.outgoing_messages())?
                    .checked_mul(4096)?,
            )?,
        })
    }

    /// Connects the fixed native collector on this actual synchronous main.
    ///
    /// The enclosing real owner must admit `receiving_footprint_v4` first and
    /// derive `deadline` from its unchanged original signed/native cutoff.
    ///
    /// # Errors
    /// Retains Runtime, socket/AUTH/builder, deadline or reentry refusal.
    pub fn connect_once_v4(
        &mut self,
        maximum_message_bytes: usize,
        maximum_materialized_bytes: usize,
        deadline: tokio::time::Instant,
        original_boottime_cutoff: u64,
        original_wall_expiry: Option<i64>,
    ) -> Result<(), NetworkFdStoreInspectionRefusalV4> {
        if self.entered || tokio::runtime::Handle::try_current().is_ok() {
            self.closed.get_or_insert(crate::Error::HostLaunchRetained(
                "Network inspector must enter once on its synchronous main",
            ));
            self.first.get_or_insert(First::Closed);
            return Err(NetworkFdStoreInspectionRefusalV4);
        }
        self.entered = true;
        self.deadline = Some(deadline);
        let schedule = match NetworkFdStoreReceiveScheduleV4::new(
            maximum_message_bytes,
            maximum_materialized_bytes,
        ) {
            Ok(schedule) => schedule,
            Err(cause) => {
                self.connect = Some(Err(cause));
                self.first = Some(First::Connect);
                return Err(NetworkFdStoreInspectionRefusalV4);
            }
        };
        self.native = Some(match self.role {
            Role::Network => NetworkFdStoreConnectionOriginalV4::new(schedule),
            Role::Mount => NetworkFdStoreConnectionOriginalV4::new_mount_inventory_v2(schedule),
        });
        self.runtime = Some(
            tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .map(Arc::new),
        );
        let runtime = match self.runtime.as_ref() {
            Some(Ok(runtime)) => Arc::clone(runtime),
            _ => {
                self.first = Some(First::Runtime);
                return Err(NetworkFdStoreInspectionRefusalV4);
            }
        };
        let Some(native) = self.native.as_mut() else {
            std::process::abort()
        };
        let mut cancellation = native.cancellation_fence_v4();
        match runtime.block_on(async {
            tokio::time::timeout_at(
                deadline,
                native.connect_once_v4(deadline, original_boottime_cutoff, original_wall_expiry),
            )
            .await
        }) {
            Ok(result) => self.connect = Some(result),
            Err(cause) => self.connect_timeout = Some(cause),
        }
        if matches!(self.connect, Some(Ok(()))) && self.connect_timeout.is_none() {
            self.connection = native.connection_v4().cloned();
            if self.connection.is_some() {
                cancellation.complete();
                return Ok(());
            }
        }
        self.connect_native_selected = self
            .connect
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .is_some_and(|cause| native.matches_returned_failure_v4(cause));
        self.first = Some(First::Connect);
        Err(NetworkFdStoreInspectionRefusalV4)
    }

    /// Executes the next fixed same-process bookend/dump/after interval once.
    ///
    /// Every entered capture invokes its independent after attempt, including
    /// failed capture/body and an expired mechanical deadline. The original
    /// raw connection rejects any IO after its permanent negative fence.
    ///
    /// # Errors
    /// Keeps the first actual native/SDK/decode/deadline source and later posts.
    pub fn snapshot_next_once_v4(&mut self) -> Result<(), NetworkFdStoreInspectionRefusalV4> {
        self.snapshot_next_engine_v2(false)
    }

    /// Attempts the separately prepaid second observation after a body refusal.
    ///
    /// A permanently fenced native transport still refuses every IO. The
    /// actual second SDK/native destination is attempted without clearing or
    /// replacing the original first cause or constructing another connection.
    ///
    /// # Errors
    /// Retains missing connection, expiry, native refusal or invalid ordering.
    pub fn snapshot_owed_next_once_v2(&mut self) -> Result<(), NetworkFdStoreInspectionRefusalV4> {
        if self.next_snapshot != 1 { return Err(NetworkFdStoreInspectionRefusalV4); }
        self.snapshot_next_engine_v2(true)
    }

    fn snapshot_next_engine_v2(&mut self, owed: bool) -> Result<(), NetworkFdStoreInspectionRefusalV4> {
        if (!owed && self.first.is_some()) || self.next_snapshot == self.snapshots.len() {
            self.closed.get_or_insert(crate::Error::HostLaunchRetained(
                "Network snapshot interval closed",
            ));
            self.first.get_or_insert(First::Closed);
            return Err(NetworkFdStoreInspectionRefusalV4);
        }
        let index = self.next_snapshot;
        self.next_snapshot += 1;
        let runtime = match self.runtime.as_ref() {
            Some(Ok(runtime)) => Arc::clone(runtime),
            _ => return Err(NetworkFdStoreInspectionRefusalV4),
        };
        let Some(connection) = self.connection.as_ref() else {
            return Err(NetworkFdStoreInspectionRefusalV4);
        };
        let Some(deadline) = self.deadline else {
            return Err(NetworkFdStoreInspectionRefusalV4);
        };
        let Some(native) = self.native.as_ref() else {
            return Err(NetworkFdStoreInspectionRefusalV4);
        };
        let mut cancellation = native.cancellation_fence_v4();
        let observation = &mut self.snapshots[index];
        runtime.block_on(observe_network_snapshot(
            connection,
            native,
            deadline,
            observation,
            self.role,
        ));
        if observation.first.is_some() {
            self.first.get_or_insert(First::Snapshot(index));
            return Err(NetworkFdStoreInspectionRefusalV4);
        }
        cancellation.complete();
        Ok(())
    }

    /// Borrows only the completed snapshot from the preceding positive interval.
    #[must_use]
    pub fn completed_snapshot_v4(&self) -> Option<&FdStoreSnapshot> {
        if self.first.is_some() || self.next_snapshot == 0 {
            return None;
        }
        let observation = &self.snapshots[self.next_snapshot - 1];
        if observation.first.is_some() || !matches!(observation.after, Some(Ok(()))) {
            return None;
        }
        observation.returned.as_ref()?.as_ref().ok()
    }

    /// Returns the actual completed same-process recipient invocation.
    ///
    /// This is comparison DATA, never a native or service authority.
    #[must_use]
    pub fn completed_invocation_data_v2(&self) -> Option<[u8; 16]> {
        self.completed_snapshot_v4()?;
        self.snapshots[self.next_snapshot - 1].before.as_ref()?.as_ref().ok()?
            .invocation().try_into().ok()
    }

    /// Borrows a stable SDK cause or the exact retained native marker.
    ///
    /// Use `failure_view_v4` to render a raw native cause whose archive guard
    /// cannot be returned as a temporary `&dyn Error`.
    #[must_use]
    pub fn failure_cause_v2(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.failure_view_v4()? {
            NetworkFdStoreFailureViewV4::Cause(cause) => Some(cause),
            NetworkFdStoreFailureViewV4::Native(_) => Some(&NetworkFdStoreInspectionRefusalV4),
        }
    }

    /// Moves the actual completed metadata snapshot once into its role owner.
    ///
    /// This transfers only the decoder's existing typed backing. The raw
    /// connection, messages and service originals remain here through owed
    /// posts; a snapshot grants no descriptor or mutation authority.
    #[must_use]
    pub fn take_completed_snapshot_once_v4(&mut self) -> Option<FdStoreSnapshot> {
        if self.first.is_some() || self.next_snapshot == 0 {
            return None;
        }
        let observation = &mut self.snapshots[self.next_snapshot - 1];
        if observation.taken
            || observation.first.is_some()
            || !matches!(observation.after, Some(Ok(())))
            || !matches!(observation.returned, Some(Ok(_)))
        {
            return None;
        }
        observation.taken = true;
        match observation.returned.take() {
            Some(Ok(snapshot)) => Some(snapshot),
            _ => std::process::abort(),
        }
    }

    /// Closes and joins only after all snapshots and actual upper posts succeed.
    ///
    /// No resource refund or release authority follows from this local native
    /// disposition. Failed or aliased prefixes remain resident, as does Runtime.
    ///
    /// # Errors
    /// Retains close, deadline, reader-join or actual ownership refusal.
    pub fn finish_positive_native_once_v4(
        &mut self,
    ) -> Result<(), NetworkFdStoreInspectionRefusalV4> {
        if self.first.is_some()
            || self.close.is_some()
            || self.close_timeout.is_some()
            || self.disposal.is_some()
            || self.next_snapshot == 0
        {
            return Err(NetworkFdStoreInspectionRefusalV4);
        }
        let Some(Ok(runtime)) = self.runtime.as_ref() else {
            return Err(NetworkFdStoreInspectionRefusalV4);
        };
        let runtime = Arc::clone(runtime);
        let Some(deadline) = self.deadline else {
            return Err(NetworkFdStoreInspectionRefusalV4);
        };
        let Some(connection) = self.connection.as_ref() else {
            return Err(NetworkFdStoreInspectionRefusalV4);
        };
        // Construct the timeout while the same Runtime is entered.
        match runtime
            .block_on(async { tokio::time::timeout_at(deadline, connection.clone().close()).await })
        {
            Ok(result) => self.close = Some(result),
            Err(cause) => self.close_timeout = Some(cause),
        }
        if !matches!(self.close, Some(Ok(()))) || self.close_timeout.is_some() {
            self.first = Some(First::Close);
            return Err(NetworkFdStoreInspectionRefusalV4);
        }
        // All original per-snapshot posts are positive. These proxies share the
        // bus only; they supply no later global native input and can close now.
        for observation in &mut self.snapshots {
            drop(observation.before.take());
        }
        drop(self.connection.take());
        let Some(native) = self.native.as_mut() else {
            std::process::abort()
        };
        self.disposal = Some(runtime.block_on(native.retire_positive_native_once_v4()));
        if matches!(self.disposal, Some(Ok(()))) {
            Ok(())
        } else {
            self.first = Some(First::Disposal);
            Err(NetworkFdStoreInspectionRefusalV4)
        }
    }

    /// Borrows exact resident cause selection without replacing its source.
    #[must_use]
    pub fn failure_view_v4(&self) -> Option<NetworkFdStoreFailureViewV4<'_>> {
        let native_selected = match self.first? {
            First::Connect => self.connect_native_selected,
            First::Snapshot(index) => self.snapshots[index].native_selected,
            First::Close => self
                .close
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .is_some_and(|cause| {
                    self.native
                        .as_ref()
                        .is_some_and(|native| native.matches_returned_failure_v4(cause))
                }),
            _ => false,
        };
        if native_selected {
            if let Some(native) = self.native.as_ref() {
                if let Ok(Some(cause)) = native.failure_v4() {
                    if !matches!(cause.cause(), LauncherImageFailureRefV1::Ended) {
                        return Some(NetworkFdStoreFailureViewV4::Native(cause));
                    }
                }
            }
        }
        let cause: &(dyn std::error::Error + 'static) = match self.first? {
            First::Runtime => self.runtime.as_ref()?.as_ref().err()?,
            First::Connect => match self
                .connect
                .as_ref()
                .and_then(|result| result.as_ref().err())
            {
                Some(cause) => cause,
                None => self.connect_timeout.as_ref()?,
            },
            First::Snapshot(index) => self.snapshots[index].failure()?,
            First::Close => match self.close.as_ref().and_then(|result| result.as_ref().err()) {
                Some(cause) => cause,
                None => self.close_timeout.as_ref()?,
            },
            First::Disposal => self
                .native
                .as_ref()?
                .native_disposal_failure_v4()
                .unwrap_or(&NetworkFdStoreInspectionRefusalV4),
            First::Closed => self.closed.as_ref()?,
        };
        Some(NetworkFdStoreFailureViewV4::Cause(cause))
    }
}

fn sdk_native_marker(error: &crate::Error, native: &NetworkFdStoreConnectionOriginalV4) -> bool {
    // Only the actual private same-original marker qualifies. Wrapping in the
    // typed SDK/FDO source chain cannot turn a pure earlier SDK error into it.
    let mut source: &(dyn std::error::Error + 'static) = error;
    loop {
        if source
            .downcast_ref::<zbus::Error>()
            .is_some_and(|cause| native.matches_returned_failure_v4(cause))
        {
            return true;
        }
        match source.source() {
            Some(next) => source = next,
            None => return false,
        }
    }
}

async fn observe_network_snapshot(
    connection: &zbus::Connection,
    native: &NetworkFdStoreConnectionOriginalV4,
    deadline: tokio::time::Instant,
    observation: &mut Observation,
    role: Role,
) {
    let before = tokio::time::timeout_at(
        deadline,
        crate::client::capture_fixed_inventory_fd_store_bookend_v2(connection, role),
    )
    .await;
    match before {
        Ok(result) => observation.before = Some(result),
        Err(cause) => observation.timeout = Some(cause),
    }
    if let Some(Ok(original)) = observation.before.as_ref() {
        match tokio::time::timeout_at(
            deadline,
            read_systemd_snapshot_from_original(
                connection,
                role.unit(),
                original.destination(),
                Some(original.unit_path()),
                SnapshotReadStorageV1::Network {
                    dump: &mut observation.dump,
                    parts: &mut observation.parts,
                },
            ),
        )
        .await
        {
            Ok(result) => {
                observation.returned = Some(result.map_err(|cause| match cause {
                    SnapshotReadFailureV1::Retained(cause) => cause,
                    SnapshotReadFailureV1::Legacy(_) => {
                        SnapshotReadErrorV1::Refused("Network snapshot used ordinary storage")
                    }
                }))
            }
            Err(cause) => observation.timeout = Some(cause),
        }
        if !matches!(observation.returned, Some(Ok(_))) {
            observation.first = Some(if observation.timeout.is_some() {
                SnapshotFirst::Timeout
            } else {
                SnapshotFirst::Body
            });
            observation.native_selected = observation
                .dump
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .is_some_and(|cause| native.matches_returned_failure_v4(cause))
                || observation
                    .returned
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .is_some_and(|cause| {
                        matches!(cause, SnapshotReadErrorV1::Bus { source, .. }
                        if native.matches_returned_failure_v4(source))
                    });
        }
        // The actual body/first marker is parked before the independently owed
        // final service identity observation, including body or clock refusal.
        match tokio::time::timeout_at(deadline, original.finish()).await {
            Ok(result) => observation.after = Some(result),
            Err(cause) => {
                if observation.timeout.is_none() {
                    observation.timeout = Some(cause);
                }
            }
        }
    } else {
        observation.first = Some(if observation.timeout.is_some() {
            SnapshotFirst::Timeout
        } else {
            SnapshotFirst::Before
        });
        observation.native_selected = observation
            .before
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .is_some_and(|cause| sdk_native_marker(cause, native));
        // No complete service baseline exists. Still invoke the independent
        // PID1 identity attempt on the same original transport, with the same
        // original mechanical cutoff. It cannot make this negative positive.
        match tokio::time::timeout_at(
            deadline,
            crate::client::network_fd_store_manager_post_v4(connection),
        )
        .await
        {
            Ok(result) => observation.after = Some(result.map(|_| ())),
            Err(cause) => {
                if observation.timeout.is_none() {
                    observation.timeout = Some(cause);
                }
            }
        }
    }
    if observation.first.is_none() && !matches!(observation.after, Some(Ok(()))) {
        observation.first = Some(if observation.timeout.is_some() {
            SnapshotFirst::Timeout
        } else {
            SnapshotFirst::After
        });
        observation.native_selected = observation
            .after
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .is_some_and(|cause| sdk_native_marker(cause, native));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::os::fd::AsRawFd;
    use std::process::Command;

    const CHILD_MODE: &str = "AOS_NETWORK_FDSTORE_RUNTIME_FAULT_CHILD_V4";
    const TEST_NAME: &str =
        "fd_store::network_original::tests::runtime_constructor_private_unwind_has_no_fd_credit";

    #[test]
    fn runtime_constructor_private_unwind_has_no_fd_credit() {
        let Some(mode) = std::env::var_os(CHILD_MODE) else {
            let executable = std::env::current_exe().unwrap();
            let status = Command::new(&executable)
                .args(["--exact", TEST_NAME, "--nocapture"])
                .env(CHILD_MODE, "returned-error")
                .status()
                .unwrap();
            assert!(status.success());

            let panic = Command::new(executable)
                .args(["--exact", TEST_NAME, "--nocapture"])
                .env(CHILD_MODE, "cold-global-panic")
                .output()
                .unwrap();
            assert!(!panic.status.success());
            assert!(String::from_utf8_lossy(&panic.stderr).contains("failed to create UnixStream"));
            return;
        };

        // This child is isolated from every other test. Warm the process-global
        // signal pair only in the returned-Err cases; its two originals remain
        // in the baseline census after the temporary Runtime is dropped.
        let cold = mode == "cold-global-panic";
        if !cold {
            drop(
                tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build()
                    .unwrap(),
            );
        }
        let original_limit = rustix::process::getrlimit(rustix::process::Resource::Nofile);
        let maximum_fd = std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .map(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .parse::<u64>()
                    .unwrap()
            })
            .max()
            .unwrap();
        let test_limit = rustix::process::Rlimit {
            current: Some(maximum_fd + 32),
            maximum: original_limit.maximum,
        };
        let cases: &[usize] = if cold { &[3] } else { &[0, 1, 2, 3] };
        for available in cases {
            rustix::process::setrlimit(rustix::process::Resource::Nofile, test_limit).unwrap();
            let mut fillers = Vec::new();
            loop {
                match File::open("/dev/null") {
                    Ok(file) => fillers.push(file),
                    Err(cause) => {
                        assert_eq!(cause.raw_os_error(), Some(libc::EMFILE));
                        break;
                    }
                }
            }
            for _ in 0..*available {
                drop(fillers.pop().unwrap());
            }
            let expected_files: Vec<_> = fillers.iter().map(AsRawFd::as_raw_fd).collect();
            let mut original = NetworkFdStoreInspectionOriginalV4::new();
            let entered = original.connect_once_v4(
                1024,
                8192,
                tokio::time::Instant::now() + std::time::Duration::from_secs(1),
                u64::MAX,
                None,
            );
            // A cold signal-pair allocation with only its three driver slots
            // available must panic in the dependency's existing expect. No
            // provider success or synthetic owning ioError is accepted for it.
            assert!(
                !cold,
                "the cold global-pair constructor unexpectedly returned"
            );
            assert!(entered.is_err());
            rustix::process::setrlimit(rustix::process::Resource::Nofile, original_limit).unwrap();

            let Some(Err(cause)) = original.runtime.as_ref() else {
                panic!("the actual Runtime construction error must remain owned");
            };
            assert_eq!(cause.raw_os_error(), Some(libc::EMFILE));
            let first = cause as *const std::io::Error;
            assert!(matches!(original.first, Some(First::Runtime)));
            assert!(original.connection.is_none());
            assert!(original.connect.is_none());
            assert!(
                original
                    .connect_once_v4(1024, 8192, tokio::time::Instant::now(), u64::MAX, None,)
                    .is_err()
            );
            assert_eq!(
                first,
                original.runtime.as_ref().unwrap().as_ref().unwrap_err() as *const std::io::Error
            );
            for descriptor in expected_files {
                assert!(
                    rustix::io::fcntl_getfd(
                        fillers
                            .iter()
                            .find(|file| file.as_raw_fd() == descriptor)
                            .unwrap()
                    )
                    .is_ok()
                );
            }
            // Restoring only the test's soft limit permits the read-dir probe.
            // Every private Runtime constructor FD must already have closed;
            // the global pair remains in the pre-case baseline.
            let open = std::fs::read_dir("/proc/self/fd").unwrap().count();
            let expected = usize::try_from(test_limit.current.unwrap()).unwrap() - available + 1;
            assert_eq!(open, expected);
            drop(fillers);
        }
    }
}
