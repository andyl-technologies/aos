//! Retains one finite readonly manager on its original connection and Runtime.
//!
//! Constructor results, raw receive/native failures and later monotone byte
//! growth all belong to the SAME underlying connection. This owner creates no
//! worker, independent connection, role, account, payment or authority. A real
//! enclosing original prepays before construction and before each extension.

use std::sync::Arc;

use super::{Error, Result, SystemdClient};

pub use zbus::connection::ReadonlyPropertyReceiveScheduleV2;

/// Retains one actual readonly manager and its whole native constructor outcome.
///
/// Its schedule is representation DATA. It cannot establish the enclosing
/// service's role, genuine funding, currentness, Session or effect permission.
#[must_use = "retain the original manager/native failure through enclosing posts"]
pub struct ReadonlyPropertyManagerOriginalV2 {
    transport: zbus::connection::ControllerPropertyReceiveAttemptV1,
    constructor: Option<Result<Arc<SystemdClient>>>,
    attempted: bool,
}

impl ReadonlyPropertyManagerOriginalV2 {
    /// Reports dominant raw and fixed typed-property decode bytes for this schedule.
    ///
    /// The actual same-connection constructor and property schema supply both
    /// terms. Runtime/Connection internals and enclosing native/currentness work
    /// remain separately priced. This DATA creates no permission or payment.
    #[must_use]
    pub fn receiving_memory_bytes_v2(schedule: ReadonlyPropertyReceiveScheduleV2) -> Option<usize> {
        use std::mem::size_of;

        let decoded = super::fixed_property::decoded_geometry_for_schedule_v2(
            schedule.maximum_materialized_bytes(), schedule.incoming_messages(),
        )?.0;
        schedule.receiving_storage_bytes_v2()?
            .checked_add(decoded)?
            .checked_add(2 * size_of::<Self>())?
            .checked_add(readonly_client_storage_v2()?)
    }

    /// Prearms the same bounded raw receiver without connecting or spawning.
    ///
    /// The actual enclosing original must admit this storage before calling.
    #[must_use]
    pub fn new(schedule: ReadonlyPropertyReceiveScheduleV2) -> Self {
        Self {
            transport: zbus::connection::ControllerPropertyReceiveAttemptV1::with_schedule_v2(schedule),
            constructor: None,
            attempted: false,
        }
    }

    /// Constructs one readonly manager on this original's actual connection.
    ///
    /// # Errors
    /// Refuses repeated/fenced entry and retains the original constructor error.
    /// Native connect/AUTH/raw receive errors stay in this same transport owner.
    ///
    /// # Panics
    /// Panics if polled outside a Tokio Runtime with its IO driver enabled.
    pub async fn connect_once(&mut self) -> Result<()> {
        if self.attempted || self.transport.has_ended() {
            self.transport.end();
            return Err(Error::Zbus(zbus::Error::InvalidReply));
        }
        self.attempted = true;
        let mut cancellation = self.transport.cancellation_fence();
        self.constructor = Some(async {
            let connection = self.transport.connect().await.map_err(Error::SystemdUnavailable)?;
            SystemdClient::readonly_from_connection_v2(connection).await.map(Arc::new)
        }.await);
        if matches!(self.constructor, Some(Err(_))) {
            self.transport.end();
            return Err(Error::Zbus(zbus::Error::InvalidReply));
        }
        cancellation.complete();
        Ok(())
    }

    /// Borrows the actual successfully constructed manager without a new connection.
    #[must_use]
    pub fn client_v2(&self) -> Option<&Arc<SystemdClient>> {
        match self.constructor.as_ref()? {
            Ok(manager) => Some(manager),
            Err(_) => None,
        }
    }

    /// Borrows the original whole constructor cause without replacing it.
    #[must_use]
    pub fn constructor_failure_v2(&self) -> Option<&Error> {
        self.constructor.as_ref()?.as_ref().err()
    }

    /// Extends this SAME receiver after separate genuine enclosing prepayment.
    ///
    /// # Errors
    /// Refuses failed/ended/reentrant or decreasing representation growth. The
    /// original raw/arithmetic/reserve cause remains in the native owner.
    pub fn raise_materialization_limit_v2(&self, maximum: usize) -> Result<()> {
        if !self.attempted || !matches!(self.constructor, Some(Ok(_))) {
            self.transport.end();
            return Err(Error::Zbus(zbus::Error::InvalidReply));
        }
        self.transport.raise_materialization_limit_v2(maximum).map_err(Error::Zbus)
    }

    /// Parks a recurring raw/result window after genuine enclosing payment.
    ///
    /// # Errors
    /// Refuses missing/ended manager, pending RPCs or repeated entry.
    pub fn begin_readonly_interval_v2(&self) -> Result<()> {
        if self.client_v2().is_none() { return Err(Error::Zbus(zbus::Error::InvalidReply)); }
        self.transport.begin_readonly_interval_v2().map_err(Error::Zbus)
    }

    /// Disposes the same positive window after whole authenticated completion.
    ///
    /// # Errors
    /// Refuses negative/borrowed/pending native custody without healing it.
    pub fn retire_readonly_interval_v2(&self) -> Result<()> {
        if self.client_v2().is_none() { return Err(Error::Zbus(zbus::Error::InvalidReply)); }
        self.transport.retire_readonly_interval_v2().map_err(Error::Zbus)
    }

    /// Reports the same admitted bytes, cumulative bound and first refused increment.
    #[must_use]
    pub fn materialization_extent_v2(&self) -> (usize, usize, Option<usize>) {
        self.transport.materialization_extent()
    }

    /// Borrows actual retained native/raw failure custody without another read.
    ///
    /// # Errors
    /// Refuses a borrowed or poisoned native failure slot without healing it.
    pub fn transport_failure_v2(&self) -> std::result::Result<
        Option<zbus::connection::socket::LauncherImageFailureLoanV1<'_>>,
        zbus::connection::socket::LauncherImageFailureUnavailableV1,
    > {
        self.transport.failure()
    }

    // The shared worker keeps the same original cancellation fence across
    // every actual query await, including timeout and unwinding.
    pub(super) fn cancellation_fence_v1(&self) -> zbus::connection::FixedLauncherImageCancellationV1 {
        self.transport.cancellation_fence()
    }

    // Only the shared fixed-query worker calls this after its own operation
    // fails or times out. Whole native/raw failure custody remains here.
    pub(super) fn end_retaining_v1(&self) {
        self.transport.end();
    }

    /// Reports terminal fencing without replacing the manager or its raw state.
    #[must_use]
    pub fn has_ended_v2(&self) -> bool {
        self.transport.has_ended()
    }

    /// Reports this original's actual inline storage, excluding its raw heap.
    #[must_use]
    pub const fn inline_bytes_v2() -> usize {
        std::mem::size_of::<Self>()
    }
}

// Both readonly constructors use this same passive carrier invoice. It covers
// the closed job registry and the existing channel/Arc control words; transport
// and schema decoders are supplied separately by their actual owners.
pub(super) fn readonly_client_storage_v2() -> Option<usize> {
    use std::mem::size_of;

    size_of::<SystemdClient>()
        .checked_add(size_of::<super::JobRegistry>())?
        .checked_add(size_of::<bool>())?
        .checked_add(6 * size_of::<usize>())
}
