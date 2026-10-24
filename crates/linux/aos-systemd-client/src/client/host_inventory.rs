//! Retains Host and Network absence discovery on one purpose-closed reducer.
//!
//! The existing manager listing decoder and PID1 ownership bookends run on the
//! shared finite readonly collector. A genuine Host read prepays all storage and
//! wire before entry. A residual listing is retained quarantine, never absence,
//! adoption, cleanup permission or an instruction to retry.

use super::*;
mod owned_cleanup;
use owned_cleanup::OwnedCleanupOriginalV8;
use crate::manager_proxy::ListUnitsEntry;
use zbus::connection::{
    HostInventoryConnectionOriginalV5, HostInventoryReceiveScheduleV5,
    NetworkWorkerCensusConnectionOriginalV4, NetworkWorkerCensusReceiveScheduleV4,
};

use crate::sandbox::RUNTIME_INVENTORY_PATTERNS_V5 as PATTERNS;
type Owner = (
    zbus::fdo::DBusProxy<'static>,
    zbus::names::BusName<'static>,
    zbus::names::OwnedUniqueName,
);

/// Reports refusal while the whole native/typed discovery prefix stays owned.
#[derive(Debug, thiserror::Error)]
#[error("complete Host runtime absence discovery refused")]
pub struct HostRuntimeDiscoveryRefusalV5;

#[derive(Clone, Copy)]
enum Purpose {
    Host,
    HostOwned([u8; 16]),
    Network,
}

impl Purpose {
    fn patterns(self) -> &'static [&'static str] {
        match self {
            Self::Host | Self::HostOwned(_) => &PATTERNS,
            Self::Network => &[
                "aos-sandbox-network-worker@*.service",
                "aos-sandbox-network-observation-worker@*.service",
            ],
        }
    }
}

#[derive(Clone, Copy)]
enum Schedule {
    Host(HostInventoryReceiveScheduleV5),
    Network(NetworkWorkerCensusReceiveScheduleV4),
}

impl Schedule {
    fn new(purpose: Purpose, message: usize, materialized: usize) -> zbus::Result<Self> {
        match purpose {
            Purpose::Host => {
                HostInventoryReceiveScheduleV5::new(message, materialized).map(Self::Host)
            }
            Purpose::HostOwned(incarnation) => {
                HostInventoryReceiveScheduleV5::for_owned_cleanup_v8(message, materialized, incarnation)
                    .map(Self::Host)
            }
            Purpose::Network => {
                NetworkWorkerCensusReceiveScheduleV4::new(message, materialized).map(Self::Network)
            }
        }
    }

    fn raw_data_v5(self) -> zbus::connection::ReadonlyPropertyReceiveScheduleV2 {
        match self {
            Self::Host(schedule) => schedule.raw_data_v5(),
            Self::Network(schedule) => schedule.raw_data_v4(),
        }
    }

    fn receiving_storage_bytes_v5(self) -> Option<usize> {
        match self {
            Self::Host(schedule) => schedule.receiving_storage_bytes_v5(),
            Self::Network(schedule) => schedule.receiving_storage_bytes_v4(),
        }
    }

    fn maximum_native_files_v5(self) -> Option<usize> {
        match self {
            Self::Host(schedule) => schedule.maximum_native_files_v5(),
            Self::Network(schedule) => schedule.maximum_native_files_v4(),
        }
    }
}

enum Native {
    Host(HostInventoryConnectionOriginalV5),
    Network(NetworkWorkerCensusConnectionOriginalV4),
}

impl Native {
    fn new(schedule: Schedule) -> Self {
        match schedule {
            Schedule::Host(schedule) => {
                Self::Host(HostInventoryConnectionOriginalV5::new(schedule))
            }
            Schedule::Network(schedule) => {
                Self::Network(NetworkWorkerCensusConnectionOriginalV4::new(schedule))
            }
        }
    }

    async fn connect_once_v5(
        &mut self,
        deadline: tokio::time::Instant,
        cutoff: u64,
        wall: Option<i64>,
    ) -> zbus::Result<()> {
        match self {
            Self::Host(native) => native.connect_once_v5(deadline, cutoff, wall).await,
            Self::Network(native) => native.connect_once_v4(deadline, cutoff, wall).await,
        }
    }

    fn connection_v5(&self) -> Option<&zbus::Connection> {
        match self {
            Self::Host(native) => native.connection_v5(),
            Self::Network(native) => native.connection_v4(),
        }
    }

    fn matches_returned_failure_v5(&self, cause: &zbus::Error) -> bool {
        match self {
            Self::Host(native) => native.matches_returned_failure_v5(cause),
            Self::Network(native) => native.matches_returned_failure_v4(cause),
        }
    }

    fn cancellation_fence_v5(&self) -> zbus::connection::FixedLauncherImageCancellationV1 {
        match self {
            Self::Host(native) => native.cancellation_fence_v5(),
            Self::Network(native) => native.cancellation_fence_v4(),
        }
    }

    fn failure_v5(
        &self,
    ) -> std::result::Result<
        Option<zbus::connection::socket::LauncherImageFailureLoanV1<'_>>,
        zbus::connection::socket::LauncherImageFailureUnavailableV1,
    > {
        match self {
            Self::Host(native) => native.failure_v5(),
            Self::Network(native) => native.failure_v4(),
        }
    }

    fn native_disposal_failure_v5(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Host(native) => native.native_disposal_failure_v5(),
            Self::Network(native) => native.native_disposal_failure_v4(),
        }
    }

    async fn retire_positive_native_once_v5(&mut self) -> std::result::Result<(), ()> {
        match self {
            Self::Host(native) => native.retire_positive_native_once_v5().await,
            Self::Network(native) => native.retire_positive_native_once_v4().await,
        }
    }
}

#[derive(Clone, Copy)]
enum First {
    Connect,
    Before,
    Listing(usize),
    After,
    AfterReload,
    Timeout(usize),
    Close,
    Disposal,
    Closed,
    OwnedUnit(usize, usize),
    OwnedPair,
}

/// Owns both complete listings and the actual same unique-PID1 connection.
#[must_use = "retain the full raw/typed discovery original through Host posts"]
struct RuntimeDiscoveryOriginalV5 {
    purpose: Purpose,
    owned: Option<OwnedCleanupOriginalV8>,
    native: Option<Native>,
    connection: Option<zbus::Connection>,
    connect: Option<zbus::Result<()>>,
    before: Option<Result<Owner>>,
    manager: Option<ManagerProxy<'static>>,
    manager_result: Option<Result<()>>,
    preparation: Option<Result<()>>,
    after_result: Option<Result<()>>,
    reload: [Option<zbus::Result<bool>>; 2],
    listings: [Option<Result<Vec<ListUnitsEntry>>>; 2],
    listing_check: [Option<Result<()>>; 2],
    after: Option<Result<Owner>>,
    owner_check: Option<Result<()>>,
    timeout: [Option<tokio::time::error::Elapsed>; 7],
    deadline: Option<tokio::time::Instant>,
    next: usize,
    close: Option<zbus::Result<()>>,
    disposal: Option<std::result::Result<(), ()>>,
    first: Option<First>,
    returned_native: bool,
    entered: bool,
    after_entered: bool,
}

impl RuntimeDiscoveryOriginalV5 {
    /// Creates inert destinations without native IO or dynamic allocation.
    #[must_use]
    fn new(purpose: Purpose) -> Self {
        Self {
            purpose,
            owned: match purpose {
                Purpose::HostOwned(incarnation) => Some(OwnedCleanupOriginalV8::new(incarnation)),
                _ => None,
            },
            native: None,
            connection: None,
            connect: None,
            before: None,
            manager: None,
            manager_result: None,
            preparation: None,
            after_result: None,
            reload: std::array::from_fn(|_| None),
            listings: std::array::from_fn(|_| None),
            listing_check: std::array::from_fn(|_| None),
            after: None,
            owner_check: None,
            timeout: std::array::from_fn(|_| None),
            deadline: None,
            next: 0,
            close: None,
            disposal: None,
            first: None,
            returned_native: false,
            entered: false,
            after_entered: false,
        }
    }

    /// Borrows the sole native D-Bus parser's existing message extent range.
    #[must_use]
    const fn message_extent_range_v5() -> (usize, usize) {
        HostInventoryReceiveScheduleV5::message_extent_range_v5()
    }

    /// Bounds actual transport, listing decoders, constructor and wire storage.
    ///
    /// The genuine original chooses these restrictive extents against its own
    /// remaining capacity. No row-count ceiling or new resource grant is made.
    #[must_use]
    fn receiving_footprint_v5(
        purpose: Purpose,
        message: usize,
        materialized: usize,
    ) -> Option<HostSystemdConnectionFootprintV2> {
        let schedule = Schedule::new(purpose, message, materialized).ok()?;
        let raw = schedule.raw_data_v5();
        // Each concrete (ssssssouso) record needs nine length+NUL strings and
        // one u32, before alignment. Three carrier planes dominate Vec growth.
        let rows = materialized.checked_div(9 * 5 + 4)?.checked_add(1)?;
        let decoded = rows
            .checked_mul(3 * std::mem::size_of::<ListUnitsEntry>())?
            .checked_add(materialized.checked_mul(3)?)?;
        let header = super::fixed_property::decoded_geometry_for_schedule_v2(
            materialized,
            raw.incoming_messages(),
        )?
        .0;
        let traffic = raw
            .outgoing_messages()
            .checked_mul(raw.maximum_request_bytes())?
            .checked_add(raw.raw_receive_bytes_v2().0)?
            .checked_add(
                zbus::connection::ControllerPropertyReceiveAttemptV1::AUTH_BYTES.checked_mul(2)?,
            )?;
        let owned = match purpose {
            Purpose::HostOwned(_) => OwnedCleanupOriginalV8::receiving_memory_v8(materialized)?,
            _ => 0,
        };
        let owned_metadata = match purpose {
            Purpose::HostOwned(_) => super::fixed_property::decoded_geometry_for_schedule_v2(
                materialized, raw.incoming_messages(),
            )?.1,
            _ => 0,
        };
        Some(HostSystemdConnectionFootprintV2 {
            memory_bytes: schedule
                .receiving_storage_bytes_v5()?
                .checked_add(decoded)?
                .checked_add(header)?
                .checked_add(owned)?
                .checked_add(2 * std::mem::size_of::<Self>())?
                .checked_add(4 * std::mem::size_of::<Owner>())?
                .checked_add(4 * std::mem::size_of::<ManagerProxy<'static>>())?
                .checked_add(4 * std::mem::size_of::<zbus::Connection>())?
                .checked_add(4 * raw.maximum_request_bytes())?,
            open_files: schedule.maximum_native_files_v5()?,
            // Actual native socket components, unit names and request/reply
            // correlation keys. Owned mode also supplies the canonical fixed
            // property's reached typed-entry geometry; it grants no new rows.
            metadata_entries: 3usize
                .checked_add(rows)?
                .checked_add(raw.outgoing_messages())?
                .checked_add(raw.incoming_messages())?
                .checked_add(owned_metadata)?,
            network_bytes: traffic,
            maximum_log_bytes: traffic.checked_mul(64)?.checked_add(24 * 4096)?,
        })
    }

    /// Opens the same paid fixed readonly connection and PID1 bookend once.
    ///
    /// # Errors
    /// Retains native connect/AUTH, owner, reload, timeout and reentry errors.
    /// The cutoff is the actual unchanged Host read header's native horizon.
    ///
    /// # Panics
    /// Panics if polled outside a Tokio Runtime with IO and time enabled.
    async fn begin_once_v5(
        &mut self,
        message: usize,
        materialized: usize,
        deadline: tokio::time::Instant,
        original_boottime_cutoff: u64,
        original_wall_expiry: Option<i64>,
    ) -> std::result::Result<(), HostRuntimeDiscoveryRefusalV5> {
        if self.entered {
            return self.refuse(First::Closed);
        }
        self.entered = true;
        self.deadline = Some(deadline);
        let schedule = match Schedule::new(self.purpose, message, materialized) {
            Ok(schedule) => schedule,
            Err(cause) => {
                self.connect = Some(Err(cause));
                return self.refuse(First::Connect);
            }
        };
        self.native = Some(Native::new(schedule));
        let Some(native) = self.native.as_mut() else {
            std::process::abort();
        };
        let mut cancellation = native.cancellation_fence_v5();
        match tokio::time::timeout_at(
            deadline,
            native.connect_once_v5(deadline, original_boottime_cutoff, original_wall_expiry),
        )
        .await
        {
            Ok(result) => self.connect = Some(result),
            Err(cause) => self.timeout[0] = Some(cause),
        }
        if let Some(Err(cause)) = self.connect.as_ref() {
            self.returned_native = native.matches_returned_failure_v5(cause);
        }
        if self.timeout[0].is_some() {
            return self.refuse(First::Timeout(0));
        }
        if !matches!(self.connect, Some(Ok(()))) {
            return self.refuse(First::Connect);
        }
        self.connection = native.connection_v5().cloned();
        let Some(connection) = self.connection.clone() else {
            return self.refuse(First::Connect);
        };
        match tokio::time::timeout_at(deadline, async {
            self.before = Some(super::service_properties::capture_pid1_owner_v2(&connection).await);
            let owner = match self.before.as_ref() {
                Some(Ok(owner)) => owner.2.clone(),
                _ => {
                    return Err(Error::HostLaunchRetained(
                        "Host discovery PID1 before failed",
                    ));
                }
            };
            self.manager_result = Some(
                async {
                    self.manager = Some(
                        ManagerProxy::builder(&connection)
                            .destination(owner)?
                            .cache_properties(CacheProperties::No)
                            .build()
                            .await?,
                    );
                    Ok(())
                }
                .await,
            );
            if let (Some(owned), Some(manager)) = (self.owned.as_mut(), self.manager.as_ref()) {
                owned.construct_client_once_v8(connection.clone(), manager.clone());
            }
            let Some(manager) = self.manager.as_ref() else {
                return Err(Error::HostLaunchRetained("Host discovery manager failed"));
            };
            self.reload[0] = Some(
                manager
                    .inner()
                    .get_uncached_property_typed::<bool>("Reloading")
                    .await,
            );
            if !matches!(self.reload[0], Some(Ok(false))) {
                return Err(Error::HostLaunchRetained(
                    "Host discovery reload before failed",
                ));
            }
            Ok(())
        })
        .await
        {
            Ok(result) => self.preparation = Some(result),
            Err(cause) => self.timeout[3] = Some(cause),
        }
        if self.timeout[3].is_some() {
            return self.refuse(First::Timeout(3));
        }
        if !matches!(self.preparation, Some(Ok(()))) {
            return self.refuse(First::Before);
        }
        cancellation.complete();
        Ok(())
    }

    /// Captures the next complete listing through the ordinary manager decoder.
    ///
    /// The second listing is independently attempted after a nonempty first
    /// listing. Whole raw/materialization refusal remains on this connection.
    ///
    /// # Errors
    /// Refuses any residual, malformed complete listing, timeout or extra call.
    ///
    /// # Panics
    /// Panics if polled outside a Tokio Runtime with IO and time enabled.
    async fn observe_next_once_v5(
        &mut self,
    ) -> std::result::Result<(), HostRuntimeDiscoveryRefusalV5> {
        if !self.entered || self.next == 2 || self.after_entered {
            return self.refuse(First::Closed);
        }
        let slot = self.next;
        self.next += 1;
        let (Some(manager), Some(deadline)) = (self.manager.as_ref(), self.deadline) else {
            return self.refuse(First::Listing(slot));
        };
        let mut cancellation = self
            .native
            .as_ref()
            .ok_or(HostRuntimeDiscoveryRefusalV5)?
            .cancellation_fence_v5();
        match tokio::time::timeout_at(
            deadline,
            crate::sandbox::discovery::collect_runtime_listing_v5(manager, self.purpose.patterns()),
        )
        .await
        {
            Ok(result) => self.listings[slot] = Some(result),
            Err(cause) => self.timeout[slot + 1] = Some(cause),
        }
        if self.listings[slot]
            .as_ref()
            .is_some_and(|result| result.is_ok())
        {
            cancellation.complete();
        }
        if self.owned.is_some() {
            self.observe_owned_round_v8(slot, deadline).await;
        }
        self.listing_check[slot] = Some(match self.listings[slot].as_ref() {
            Some(Ok(rows)) => match self.owned.as_ref() {
                Some(owned) => owned.require_listing_v8(slot, rows),
                None => crate::sandbox::discovery::require_empty_runtime_listing_v5(rows),
            },
            _ => Err(Error::HostLaunchRetained(
                "Host complete discovery listing failed",
            )),
        });
        if self.timeout[slot + 1].is_some() {
            return self.refuse(First::Timeout(slot + 1));
        }
        if !matches!(self.listing_check[slot], Some(Ok(()))) {
            if self.first.is_none() {
                if let Some(Err(Error::Zbus(cause))) = self.listings[slot].as_ref() {
                    self.returned_native = self
                        .native
                        .as_ref()
                        .is_some_and(|native| native.matches_returned_failure_v5(cause));
                }
            }
            return self.refuse(First::Listing(slot));
        }
        Ok(())
    }

    /// Retains the independently owed reload/unique-PID1 bookend.
    ///
    /// # Errors
    /// Refuses changed ownership, reload, failed or incomplete discovery. Earlier
    /// failures remain first even when the independently owed post also fails.
    ///
    /// # Panics
    /// Panics if polled outside a Tokio Runtime with IO and time enabled.
    async fn observe_after_once_v5(
        &mut self,
    ) -> std::result::Result<(), HostRuntimeDiscoveryRefusalV5> {
        if !self.entered || self.after_entered {
            return self.refuse(First::Closed);
        }
        self.after_entered = true;
        let Some(deadline) = self.deadline else {
            return self.refuse(First::After);
        };
        let mut cancellation = self
            .native
            .as_ref()
            .map(|native| native.cancellation_fence_v5());
        // Each after destination owns its own deadline outcome. A timed-out
        // reload must not cancel the independently owed PID1 owner attempt.
        if let Some(manager) = self.manager.as_ref() {
            match tokio::time::timeout_at(
                deadline,
                manager
                    .inner()
                    .get_uncached_property_typed::<bool>("Reloading"),
            )
            .await
            {
                Ok(result) => {
                    self.reload[1] = Some(result);
                    if !matches!(self.reload[1], Some(Ok(false))) {
                        let _ = self.refuse(First::AfterReload);
                    }
                }
                Err(cause) => {
                    self.timeout[4] = Some(cause);
                    self.first.get_or_insert(First::Timeout(4));
                }
            }
        }
        if let Some(connection) = self.connection.as_ref() {
            match tokio::time::timeout_at(
                deadline,
                super::service_properties::capture_pid1_owner_v2(connection),
            )
            .await
            {
                Ok(result) => self.after = Some(result),
                Err(cause) => {
                    self.timeout[6] = Some(cause);
                    self.first.get_or_insert(First::Timeout(6));
                }
            }
        }
        self.after_result = Some(Ok(()));
        if self.timeout[4].is_none() && self.timeout[6].is_none() {
            if let Some(cancellation) = cancellation.as_mut() {
                cancellation.complete();
            }
        }
        self.owner_check = Some(match (self.before.as_ref(), self.after.as_ref()) {
            (Some(Ok(before)), Some(Ok(after)))
                if before.2 == after.2 && matches!(self.reload[1], Some(Ok(false))) =>
            {
                Ok(())
            }
            _ => Err(Error::HostLaunchRetained(
                "Host discovery PID1/reload bookend changed",
            )),
        });
        if self.timeout[4].is_some() {
            return self.refuse(First::Timeout(4));
        }
        if self.timeout[6].is_some() {
            return self.refuse(First::Timeout(6));
        }
        if !matches!(self.owner_check, Some(Ok(()))) {
            return self.refuse(First::After);
        }
        if let Some(owned) = self.owned.as_mut() {
            owned.compare_pair_once_v8();
            if !owned.completed_pair_v8() {
                let _ = self.refuse(First::OwnedPair);
            }
        }
        if self.first.is_some() || self.next != 2 {
            return Err(HostRuntimeDiscoveryRefusalV5);
        }
        Ok(())
    }

    /// Borrows a complete actual residual listing for quarantine inspection.
    #[must_use]
    fn residual_listing_v5(&self, slot: usize) -> Option<&[ListUnitsEntry]> {
        self.listings
            .get(slot)?
            .as_ref()?
            .as_ref()
            .ok()
            .map(Vec::as_slice)
    }

    /// Ends the completed query body before the independently owed Host posts.
    ///
    /// # Errors
    /// Retains the actual close/timeout failure and never closes a failed or
    /// incomplete query as a positive result.
    ///
    /// # Panics
    /// Panics if polled outside a Tokio Runtime with IO and time enabled.
    async fn close_positive_body_once_v5(
        &mut self,
    ) -> std::result::Result<(), HostRuntimeDiscoveryRefusalV5> {
        if self.first.is_some() || !self.after_entered || self.next != 2 || self.close.is_some() {
            return self.refuse(First::Closed);
        }
        self.manager = None;
        if let Some(owned) = self.owned.as_mut() {
            owned.drop_positive_client_v8();
        }
        self.before = None;
        self.after = None;
        let (Some(connection), Some(deadline)) = (self.connection.take(), self.deadline) else {
            return self.refuse(First::Close);
        };
        match tokio::time::timeout_at(deadline, connection.close()).await {
            Ok(result) => self.close = Some(result),
            Err(cause) => self.timeout[5] = Some(cause),
        }
        if self.timeout[5].is_some() {
            return self.refuse(First::Timeout(5));
        }
        if !matches!(self.close, Some(Ok(()))) {
            return self.refuse(First::Close);
        }
        Ok(())
    }

    /// Disposes only the same positive native leaves after all enclosing posts.
    ///
    /// # Errors
    /// Refuses incomplete discovery and retains actual reader/disposal failures.
    ///
    /// # Panics
    /// Panics if polled outside a Tokio Runtime with IO and time enabled.
    async fn dispose_positive_once_v5(
        &mut self,
    ) -> std::result::Result<(), HostRuntimeDiscoveryRefusalV5> {
        if self.first.is_some() || !matches!(self.close, Some(Ok(()))) || self.disposal.is_some() {
            return self.refuse(First::Closed);
        }
        if let Some(native) = self.native.as_mut() {
            self.disposal = Some(native.retire_positive_native_once_v5().await);
        }
        if !matches!(self.disposal, Some(Ok(()))) {
            return self.refuse(First::Disposal);
        }
        Ok(())
    }

    /// Reports actual complete discovery and physical positive disposal.
    #[must_use]
    fn completed_v5(&self) -> bool {
        self.first.is_none()
            && self.after_entered
            && self.next == 2
            && matches!(self.disposal, Some(Ok(())))
    }

    /// Borrows the first typed local/decoder cause without native IO.
    #[must_use]
    fn failure_v5(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Connect => self
                .connect
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Before => self
                .before
                .as_ref()
                .and_then(|r| r.as_ref().err())
                .map(|c| c as _)
                .or_else(|| self.manager_result.as_ref()?.as_ref().err().map(|c| c as _))
                .or_else(|| self.reload[0].as_ref()?.as_ref().err().map(|c| c as _))
                .or_else(|| self.preparation.as_ref()?.as_ref().err().map(|c| c as _))
                .or(Some(&HostRuntimeDiscoveryRefusalV5)),
            First::Listing(slot) => self.listings[slot]
                .as_ref()
                .and_then(|r| r.as_ref().err())
                .map(|c| c as _)
                .or_else(|| {
                    self.listing_check[slot]
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|c| c as _)
                }),
            First::AfterReload => self.reload[1]
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as _)
                .or(Some(&HostRuntimeDiscoveryRefusalV5)),
            First::After => self
                .after
                .as_ref()
                .and_then(|r| r.as_ref().err())
                .map(|c| c as _)
                .or_else(|| self.reload[1].as_ref()?.as_ref().err().map(|c| c as _))
                .or_else(|| self.owner_check.as_ref()?.as_ref().err().map(|c| c as _)),
            First::Timeout(slot) => self.timeout.get(slot)?.as_ref().map(|cause| cause as _),
            First::Close => self.close.as_ref()?.as_ref().err().map(|c| c as _),
            First::Disposal => self.native.as_ref()?.native_disposal_failure_v5(),
            First::Closed => Some(&HostRuntimeDiscoveryRefusalV5),
            First::OwnedUnit(round, role) => self.owned.as_ref()?.unit_failure_v8(round, role)
                .or(Some(&HostRuntimeDiscoveryRefusalV5)),
            First::OwnedPair => self.owned.as_ref()?.pair_failure_v8(),
        }
    }

    /// Borrows the actual raw native cause when its source was selected first.
    ///
    /// # Errors
    /// Reports unavailable borrowed/poisoned native custody without replacing it.
    fn native_failure_v5(
        &self,
    ) -> std::result::Result<
        Option<zbus::connection::socket::LauncherImageFailureLoanV1<'_>>,
        zbus::connection::socket::LauncherImageFailureUnavailableV1,
    > {
        if !self.returned_native {
            return Ok(None);
        }
        match self.native.as_ref() {
            Some(native) => native.failure_v5(),
            None => Ok(None),
        }
    }

    fn refuse(&mut self, first: First) -> std::result::Result<(), HostRuntimeDiscoveryRefusalV5> {
        if self.first.is_none() {
            let returned = match first {
                First::OwnedUnit(round, role) => self.owned.as_ref()
                    .and_then(|owned| owned.unit_error_v8(round, role))
                    .and_then(owned_cleanup::zbus_cause_v8),
                First::Before => self
                    .before
                    .as_ref()
                    .and_then(|r| r.as_ref().err())
                    .and_then(|cause| match cause {
                        Error::Zbus(cause) => Some(cause),
                        _ => None,
                    })
                    .or_else(|| self.reload[0].as_ref()?.as_ref().err()),
                First::AfterReload => self.reload[1]
                    .as_ref()
                    .and_then(|result| result.as_ref().err()),
                First::After => self
                    .after
                    .as_ref()
                    .and_then(|r| r.as_ref().err())
                    .and_then(|cause| match cause {
                        Error::Zbus(cause) => Some(cause),
                        _ => None,
                    })
                    .or_else(|| self.reload[1].as_ref()?.as_ref().err()),
                First::Close => self.close.as_ref().and_then(|result| result.as_ref().err()),
                _ => None,
            };
            if let Some(cause) = returned {
                self.returned_native = self
                    .native
                    .as_ref()
                    .is_some_and(|native| native.matches_returned_failure_v5(cause));
            }
            self.first = Some(first);
        }
        Err(HostRuntimeDiscoveryRefusalV5)
    }
}

/// Owns the complete Host inventory pair on the shared discovery reducer.
#[must_use = "retain the full raw/typed discovery original through Host posts"]
pub struct HostRuntimeDiscoveryOriginalV5 {
    inner: RuntimeDiscoveryOriginalV5,
}

impl HostRuntimeDiscoveryOriginalV5 {
    /// Creates inert destinations without IO or dynamic allocation.
    pub fn new() -> Self {
        Self {
            inner: RuntimeDiscoveryOriginalV5::new(Purpose::Host),
        }
    }

    /// Returns the canonical native parser's message extent range.
    pub const fn message_extent_range_v5() -> (usize, usize) {
        RuntimeDiscoveryOriginalV5::message_extent_range_v5()
    }

    /// Bounds the same Host collector, decoder and complete native storage.
    pub fn receiving_footprint_v5(
        message: usize,
        materialized: usize,
    ) -> Option<HostSystemdConnectionFootprintV2> {
        RuntimeDiscoveryOriginalV5::receiving_footprint_v5(Purpose::Host, message, materialized)
    }

    /// Creates inert destinations for the two-role readonly cleanup census.
    ///
    /// The incarnation is comparison DATA. The enclosing Host original must
    /// fund this profile and join protected history and fresh native ownership.
    #[must_use]
    pub fn new_for_owned_cleanup_v8(incarnation: [u8; 16]) -> Self {
        Self { inner: RuntimeDiscoveryOriginalV5::new(Purpose::HostOwned(incarnation)) }
    }

    /// Derives the complete decode extent from this actual native profile's replies.
    #[must_use]
    pub fn materialization_extent_for_owned_cleanup_v8(
        incarnation: [u8; 16], message: usize,
    ) -> Option<usize> {
        let schedule = Schedule::new(Purpose::HostOwned(incarnation), message, message).ok()?;
        message.checked_mul(schedule.raw_data_v5().incoming_messages())
    }

    /// Bounds the selected readonly profile and its same-parser unit observations.
    #[must_use]
    pub fn receiving_footprint_for_owned_cleanup_v8(
        incarnation: [u8; 16], message: usize, materialized: usize,
    ) -> Option<HostSystemdConnectionFootprintV2> {
        RuntimeDiscoveryOriginalV5::receiving_footprint_v5(
            Purpose::HostOwned(incarnation), message, materialized,
        )
    }

    /// Borrows a reached exact-role observation without granting effect permission.
    #[must_use]
    pub fn owned_unit_observation_v8(
        &self, round: usize, role: crate::sandbox::ExactUnitRole,
    ) -> Option<&crate::sandbox::PostUnrefUnitObservation> {
        self.inner.owned.as_ref()?.observation_v8(round, role)
    }

    /// Reports the completed owned-profile pair, distinct from total absence.
    #[must_use]
    pub fn completed_owned_cleanup_v8(&self) -> bool {
        matches!(self.inner.purpose, Purpose::HostOwned(_)) && self.inner.completed_v5()
    }

    /// Borrows the closed owned-profile rounds while their native leaves remain held.
    ///
    /// This supports a fresh cleanup's before-effect ownership comparison. It
    /// does not retire native leaves or complete independently owed Source
    /// posts; the enclosing cleanup retains this entire original through them.
    ///
    /// # Errors
    /// Refuses another profile, incomplete/failed rounds, missing PID1 posts or
    /// an unclosed native body.
    pub fn closed_owned_observations_v1(&self) -> std::result::Result<[
        (&crate::sandbox::PostUnrefUnitObservation, &crate::sandbox::PostUnrefUnitObservation); 2
    ], HostRuntimeDiscoveryRefusalV5> {
        use crate::sandbox::ExactUnitRole;
        if !matches!(self.inner.purpose, Purpose::HostOwned(_))
            || self.inner.first.is_some() || !self.inner.after_entered || self.inner.next != 2
            || !matches!(self.inner.close, Some(Ok(())))
        { return Err(HostRuntimeDiscoveryRefusalV5); }
        let round = |index| -> std::result::Result<_, HostRuntimeDiscoveryRefusalV5> {
            Ok((self.owned_unit_observation_v8(index, ExactUnitRole::Payload)
                .ok_or(HostRuntimeDiscoveryRefusalV5)?,
                self.owned_unit_observation_v8(index, ExactUnitRole::Guardian)
                .ok_or(HostRuntimeDiscoveryRefusalV5)?))
        };
        Ok([round(0)?, round(1)?])
    }

    /// Opens the fixed Host collector and its PID1 bookend once.
    ///
    /// # Errors
    /// Retains native setup, ownership, reload, timeout and reentry failure.
    ///
    /// # Panics
    /// Requires a Tokio Runtime with IO and time enabled.
    pub async fn begin_once_v5(
        &mut self,
        message: usize,
        materialized: usize,
        deadline: tokio::time::Instant,
        cutoff: u64,
    ) -> std::result::Result<(), HostRuntimeDiscoveryRefusalV5> {
        self.inner
            .begin_once_v5(message, materialized, deadline, cutoff, None)
            .await
    }

    /// Delegates the actual Host interval to the sole discovery reducer.
    ///
    /// # Errors
    /// Retains malformed, incomplete, changed, expired or native failure.
    ///
    /// # Panics
    /// Requires a Tokio Runtime with IO and time enabled.
    pub async fn observe_next_once_v5(
        &mut self,
    ) -> std::result::Result<(), HostRuntimeDiscoveryRefusalV5> {
        self.inner.observe_next_once_v5().await
    }

    /// Delegates the actual Host interval to the sole discovery reducer.
    ///
    /// # Errors
    /// Retains malformed, incomplete, changed, expired or native failure.
    ///
    /// # Panics
    /// Requires a Tokio Runtime with IO and time enabled.
    pub async fn observe_after_once_v5(
        &mut self,
    ) -> std::result::Result<(), HostRuntimeDiscoveryRefusalV5> {
        self.inner.observe_after_once_v5().await
    }

    /// Delegates the actual Host interval to the sole discovery reducer.
    ///
    /// # Errors
    /// Retains malformed, incomplete, changed, expired or native failure.
    ///
    /// # Panics
    /// Requires a Tokio Runtime with IO and time enabled.
    pub async fn close_positive_body_once_v5(
        &mut self,
    ) -> std::result::Result<(), HostRuntimeDiscoveryRefusalV5> {
        self.inner.close_positive_body_once_v5().await
    }

    /// Delegates the actual Host interval to the sole discovery reducer.
    ///
    /// # Errors
    /// Retains malformed, incomplete, changed, expired or native failure.
    ///
    /// # Panics
    /// Requires a Tokio Runtime with IO and time enabled.
    pub async fn dispose_positive_once_v5(
        &mut self,
    ) -> std::result::Result<(), HostRuntimeDiscoveryRefusalV5> {
        self.inner.dispose_positive_once_v5().await
    }

    /// Borrows a complete residual listing for quarantine inspection.
    pub fn residual_listing_v5(&self, slot: usize) -> Option<&[ListUnitsEntry]> {
        self.inner.residual_listing_v5(slot)
    }

    /// Reports the actual complete pair and physical native disposal.
    pub fn completed_v5(&self) -> bool {
        matches!(self.inner.purpose, Purpose::Host) && self.inner.completed_v5()
    }

    /// Requires the closed two-round total-absence body without retiring its leaves.
    ///
    /// The enclosing Source-after and final native disposition remain owed.
    /// This borrows only this collector's actual completed native observations.
    ///
    /// # Errors
    /// Refuses another profile, residuals, incomplete posts or an unclosed body.
    pub fn require_closed_absence_v1(&self) -> std::result::Result<(),HostRuntimeDiscoveryRefusalV5> {
        if !matches!(self.inner.purpose,Purpose::Host) || self.inner.first.is_some()
            || !self.inner.after_entered || self.inner.next != 2 || !matches!(self.inner.close,Some(Ok(())))
            || !(0..2).all(|round|self.inner.residual_listing_v5(round).is_some_and(|rows|rows.is_empty()))
        { return Err(HostRuntimeDiscoveryRefusalV5); }
        Ok(())
    }

    /// Borrows the actual first local or SDK cause.
    pub fn failure_v5(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.failure_v5()
    }

    /// Borrows the exact selected raw first cause.
    ///
    /// # Errors
    /// Reports unavailable native custody without replacing the original.
    pub fn native_failure_v5(
        &self,
    ) -> std::result::Result<
        Option<zbus::connection::socket::LauncherImageFailureLoanV1<'_>>,
        zbus::connection::socket::LauncherImageFailureUnavailableV1,
    > {
        self.inner.native_failure_v5()
    }
}

impl Default for HostRuntimeDiscoveryOriginalV5 {
    fn default() -> Self {
        Self::new()
    }
}

/// Reports an incomplete fixed Network worker census while originals remain held.
#[derive(Debug, thiserror::Error)]
#[error("complete Network worker census refused")]
pub struct NetworkWorkerCensusRefusalV4;

/// Owns both complete Network worker listings on the existing inventory Runtime.
///
/// This reader loads no unit, takes no reference and mutates no manager state.
/// It cannot construct a Runtime or accept a bare Handle. Its only synchronous
/// entry borrows the actual retained descriptor-store inspection owner.
#[must_use = "retain the whole census original through all fixed-service posts"]
pub struct NetworkWorkerCensusOriginalV4 {
    inner: RuntimeDiscoveryOriginalV5,
    runtime: Option<std::sync::Arc<tokio::runtime::Runtime>>,
    entered: bool,
    runtime_refused: bool,
}

impl NetworkWorkerCensusOriginalV4 {
    /// Derives a restrictive complete empty-census wire shape from the actual native schedule.
    ///
    /// The native parser minimum alone cannot contain a complete empty D-Bus
    /// reply. The existing fixed header/name/request envelope dominates the
    /// empty listing, ownership and boolean replies. Oversized errors, noise
    /// and residual listings still fail closed at the admitted raw boundary.
    #[must_use]
    pub fn fixed_empty_census_shape_v4() -> Option<(usize, usize)> {
        let minimum = Self::message_extent_range_v4().0;
        let raw = Schedule::new(Purpose::Network, minimum, minimum)
            .ok()?
            .raw_data_v5();
        let message = raw.maximum_request_bytes();
        Some((message, message.checked_mul(raw.incoming_messages())?))
    }

    /// Creates inert destinations without IO or allocation.
    pub fn new() -> Self {
        Self {
            inner: RuntimeDiscoveryOriginalV5::new(Purpose::Network),
            runtime: None,
            entered: false,
            runtime_refused: false,
        }
    }

    /// Returns the actual native parser's message extent range.
    pub const fn message_extent_range_v4() -> (usize, usize) {
        RuntimeDiscoveryOriginalV5::message_extent_range_v5()
    }

    /// Bounds the real census collector and decoder; the existing Runtime is paid by its own owner.
    pub fn receiving_footprint_v4(
        message: usize,
        materialized: usize,
    ) -> Option<HostSystemdConnectionFootprintV2> {
        let mut footprint = RuntimeDiscoveryOriginalV5::receiving_footprint_v5(
            Purpose::Network,
            message,
            materialized,
        )?;
        footprint.memory_bytes = footprint
            .memory_bytes
            .checked_add(2 * std::mem::size_of::<Self>())?;
        Some(footprint)
    }

    /// Enters the census on the actual descriptor-store owner's synchronous Runtime.
    ///
    /// # Errors
    /// Refuses missing Runtime, reentry, active asynchronous context or an actual native/body failure.
    pub fn begin_on_inventory_runtime_once_v4(
        &mut self,
        inventory: &crate::fd_store::NetworkFdStoreInspectionOriginalV4,
        message: usize,
        materialized: usize,
        deadline: tokio::time::Instant,
        cutoff: u64,
        wall: Option<i64>,
    ) -> std::result::Result<(), NetworkWorkerCensusRefusalV4> {
        if self.entered || tokio::runtime::Handle::try_current().is_ok() {
            self.runtime_refused = true;
            return Err(NetworkWorkerCensusRefusalV4);
        }
        self.entered = true;
        self.runtime = inventory.worker_census_runtime_v4();
        let Some(runtime) = self.runtime.as_ref().cloned() else {
            self.runtime_refused = true;
            return Err(NetworkWorkerCensusRefusalV4);
        };
        runtime
            .block_on(
                self.inner
                    .begin_once_v5(message, materialized, deadline, cutoff, wall),
            )
            .map_err(|_| NetworkWorkerCensusRefusalV4)
    }

    /// Enters the actual next census destination on the same retained Runtime.
    ///
    /// # Errors
    /// Refuses unavailable Runtime or retains the original native/body failure.
    pub fn observe_next_once_v4(
        &mut self,
    ) -> std::result::Result<(), NetworkWorkerCensusRefusalV4> {
        let Some(runtime) = self.runtime.as_ref().cloned() else {
            return Err(NetworkWorkerCensusRefusalV4);
        };
        runtime
            .block_on(self.inner.observe_next_once_v5())
            .map_err(|_| NetworkWorkerCensusRefusalV4)
    }

    /// Enters the actual next census destination on the same retained Runtime.
    ///
    /// # Errors
    /// Refuses unavailable Runtime or retains the original native/body failure.
    pub fn observe_after_once_v4(
        &mut self,
    ) -> std::result::Result<(), NetworkWorkerCensusRefusalV4> {
        let Some(runtime) = self.runtime.as_ref().cloned() else {
            return Err(NetworkWorkerCensusRefusalV4);
        };
        runtime
            .block_on(self.inner.observe_after_once_v5())
            .map_err(|_| NetworkWorkerCensusRefusalV4)
    }

    /// Enters the actual next census destination on the same retained Runtime.
    ///
    /// # Errors
    /// Refuses unavailable Runtime or retains the original native/body failure.
    pub fn close_positive_body_once_v4(
        &mut self,
    ) -> std::result::Result<(), NetworkWorkerCensusRefusalV4> {
        let Some(runtime) = self.runtime.as_ref().cloned() else {
            return Err(NetworkWorkerCensusRefusalV4);
        };
        runtime
            .block_on(self.inner.close_positive_body_once_v5())
            .map_err(|_| NetworkWorkerCensusRefusalV4)
    }

    /// Enters the actual next census destination on the same retained Runtime.
    ///
    /// # Errors
    /// Refuses unavailable Runtime or retains the original native/body failure.
    pub fn dispose_positive_once_v4(
        &mut self,
    ) -> std::result::Result<(), NetworkWorkerCensusRefusalV4> {
        let Some(runtime) = self.runtime.as_ref().cloned() else {
            return Err(NetworkWorkerCensusRefusalV4);
        };
        runtime
            .block_on(self.inner.dispose_positive_once_v5())
            .map_err(|_| NetworkWorkerCensusRefusalV4)
    }

    /// Reports the actual complete census and positive native disposal.
    pub fn completed_v4(&self) -> bool {
        !self.runtime_refused && self.inner.completed_v5()
    }

    /// Borrows a complete residual listing, including unknown/stale worker names.
    pub fn residual_listing_v4(&self, slot: usize) -> Option<&[ListUnitsEntry]> {
        self.inner.residual_listing_v5(slot)
    }

    /// Borrows the chronological SDK or local cause without flattening it.
    pub fn failure_v4(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.failure_v5().or_else(|| {
            self.runtime_refused
                .then_some(&NetworkWorkerCensusRefusalV4 as _)
        })
    }

    /// Borrows the exact selected native cause on its actual collector.
    ///
    /// # Errors
    /// Reports unavailable borrowed native custody without replacing it.
    pub fn native_failure_v4(
        &self,
    ) -> std::result::Result<
        Option<zbus::connection::socket::LauncherImageFailureLoanV1<'_>>,
        zbus::connection::socket::LauncherImageFailureUnavailableV1,
    > {
        self.inner.native_failure_v5()
    }
}

impl Default for NetworkWorkerCensusOriginalV4 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(pattern: &str, name: &str) -> bool {
        pattern.len() == name.len()
            && pattern
                .bytes()
                .zip(name.bytes())
                .all(|(p, n)| p == b'?' || p == n)
    }

    #[test]
    fn owed_timeout_keeps_the_exact_earlier_slot_selected() {
        let mut original = RuntimeDiscoveryOriginalV5::new(Purpose::Network);
        assert!(original.refuse(First::Timeout(3)).is_err());
        assert!(original.refuse(First::Timeout(1)).is_err());
        assert!(matches!(original.first, Some(First::Timeout(3))));

        let mut original = RuntimeDiscoveryOriginalV5::new(Purpose::Network);
        original.reload[1] = Some(Ok(true));
        assert!(original.refuse(First::AfterReload).is_err());
        assert!(original.refuse(First::Timeout(6)).is_err());
        assert!(matches!(original.first, Some(First::AfterReload)));
    }

    #[test]
    fn fixed_purposes_select_disjoint_complete_native_patterns() {
        assert_eq!(Purpose::Host.patterns(), &PATTERNS);
        assert_eq!(
            Purpose::Network.patterns(),
            &[
                "aos-sandbox-network-worker@*.service",
                "aos-sandbox-network-observation-worker@*.service",
            ]
        );
        let schedule = Schedule::new(Purpose::Network, 4096, 8192).unwrap();
        assert_eq!(schedule.raw_data_v5().outgoing_messages(), 9);
        assert_eq!(schedule.raw_data_v5().incoming_messages(), 12);

        let owned = Schedule::new(Purpose::HostOwned([1; 16]), 4096, 8192).unwrap();
        assert_eq!(owned.raw_data_v5().outgoing_messages(), 53);
        assert_eq!(owned.raw_data_v5().incoming_messages(), 56);
        assert!(Schedule::new(Purpose::HostOwned([0; 16]), 4096, 8192).is_err());
        let original = HostRuntimeDiscoveryOriginalV5::new_for_owned_cleanup_v8([1; 16]);
        assert!(!original.completed_v5());
        assert!(!original.completed_owned_cleanup_v8());
        assert!(original.closed_owned_observations_v1().is_err());
        assert!(original.require_closed_absence_v1().is_err());
        let empty=HostRuntimeDiscoveryOriginalV5::new();
        assert!(empty.closed_owned_observations_v1().is_err());
        assert!(empty.require_closed_absence_v1().is_err());
    }

    #[test]
    fn census_cannot_construct_or_replace_an_inventory_runtime() {
        let inventory = crate::fd_store::NetworkFdStoreInspectionOriginalV4::new();
        let mut census = NetworkWorkerCensusOriginalV4::new();
        let deadline = tokio::time::Instant::now();
        assert!(
            census
                .begin_on_inventory_runtime_once_v4(&inventory, 4096, 8192, deadline, 1, None,)
                .is_err()
        );
        assert!(census.runtime.is_none());
        assert!(census.inner.native.is_none());
        assert!(
            census
                .failure_v4()
                .unwrap()
                .is::<NetworkWorkerCensusRefusalV4>()
        );
        assert!(
            census
                .begin_on_inventory_runtime_once_v4(&inventory, 4096, 8192, deadline, 1, None,)
                .is_err()
        );
        assert!(census.runtime.is_none());
        assert!(census.inner.native.is_none());
        assert!(
            census
                .failure_v4()
                .unwrap()
                .is::<NetworkWorkerCensusRefusalV4>()
        );
        assert!(census.entered);
    }

    #[test]
    fn discovery_patterns_cover_the_actual_shared_unit_grammar() {
        let unit = crate::sandbox::SandboxUnitName::from_incarnation([0xab; 16]);
        let worker = crate::sandbox::FuseWorkerUnitNameV1::from_instance([0xcd; 16]).unwrap();
        assert!(matches(PATTERNS[0], unit.as_str()));
        assert!(matches(PATTERNS[1], unit.guardian()));
        assert!(matches(PATTERNS[2], worker.as_str()));
        for name in [
            "aos-sandbox-hostd.service",
            "aos-sandbox-storaged.service",
            "aos-sandbox-mountd.service",
        ] {
            assert!(!PATTERNS.iter().any(|pattern| matches(pattern, name)));
        }

        // An invalid but width-matching identity remains an unknown native row.
        assert!(matches(
            PATTERNS[0],
            &format!("aos-sandbox-{}.service", "z".repeat(32))
        ));
    }
}
