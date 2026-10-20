//! Opens the real first-local Network namespace Store under the same F startup.
//!
//! The intrinsic Common has already proved the exact initial descriptor table
//! with no saved tail. This constructor captures the actual host namespace and
//! requires the authenticated manager's complete inventory to be empty. It
//! creates neither activation DATA nor namespace or service permission.

use super::*;
use std::sync::Arc;

use aos_sandbox_broker::receiving::{
    FixedServiceOperationClosedV4 as Closed, FixedServiceReceivingCaptureV1,
};
use aos_sandbox_core::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::pidfd::CurrentNetworkNamespaceOriginalV4;
use aos_systemd::fd_store::NetworkFdStoreInspectionOriginalV4;

use super::acquisition_clock::NetworkStartupAcquisitionClockV4;
use super::retaining::{
    NetworkNamespaceStoreFailureV4, NetworkNamespaceStoreRefusalV4, StoreReadBoundsV4,
};
use super::systemd::SystemdNotifier;
use super::systemd::notifier_original::NotifierOpeningV4;

#[derive(Clone, Copy)]
enum First {
    Entry,
    Shape,
    Funding,
    ClockBefore,
    Host,
    Notifier,
    Sdk,
    Parse,
    Inventory,
    Disposal,
    ClockAfter,
    Closed,
}

/// Retains the real selected first-local Store constructor and its failed inputs.
#[must_use = "retain every native prefix through the actual startup after"]
pub struct NetworkNamespaceStoreOpeningOriginalV4 {
    entry: Option<Result<(), Closed>>,
    shape: Option<Result<ResourceVector, AccountingError>>,
    funding: Option<Result<(), Closed>>,
    clock: NetworkStartupAcquisitionClockV4,
    clock_before: Option<Result<(), super::acquisition_clock::NetworkStartupClockRefusalV4>>,
    clock_after: Option<Result<(), super::acquisition_clock::NetworkStartupClockRefusalV4>>,
    host: CurrentNetworkNamespaceOriginalV4,
    notifier_opening: NotifierOpeningV4,
    notifier: Option<Arc<SystemdNotifier>>,
    sdk: NetworkFdStoreInspectionOriginalV4,
    parsed: Option<Result<StoreSnapshot, NetworkNamespaceStoreError>>,
    returned: Option<Result<SystemdNetworkNamespaceStore, NetworkNamespaceStoreError>>,
    closed: Option<NetworkNamespaceStoreRefusalV4>,
    first: Option<First>,
    entered: bool,
    taken: bool,
}

impl NetworkNamespaceStoreOpeningOriginalV4 {
    /// Creates inline empty destinations without IO or native/model allocation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entry: None,
            shape: None,
            funding: None,
            clock: NetworkStartupAcquisitionClockV4::new(),
            clock_before: None,
            clock_after: None,
            host: CurrentNetworkNamespaceOriginalV4::new(),
            notifier_opening: Default::default(),
            notifier: None,
            sdk: NetworkFdStoreInspectionOriginalV4::new(),
            parsed: None,
            returned: None,
            closed: None,
            first: None,
            entered: false,
            taken: false,
        }
    }

    /// Bounds actual native, fixed decode, future Store model and constructor terms.
    ///
    /// `maximum_entries` is the existing protected Network configuration DATA;
    /// the actual manager must independently report exactly that same maximum.
    #[must_use]
    pub fn receiving_demand_v4(maximum_entries: usize) -> Option<ResourceVector> {
        let bounds = StoreReadBoundsV4::for_capacity(maximum_entries)?;
        let (memory, files, names) = CurrentNetworkNamespaceOriginalV4::receiving_obligations_v4()?;
        bounds
            .demand_v4(maximum_entries, std::mem::size_of::<Self>())?
            .checked_add(NetworkStartupAcquisitionClockV4::receiving_demand_v4()?)
            .ok()?
            .checked_add(
                ResourceVector::ZERO
                    .with(
                        D::MemoryBytes,
                        u64::try_from(
                            memory
                                .checked_add(NotifierOpeningV4::receiving_bytes_v4()?)?
                                .checked_add(
                                    2 * (std::mem::size_of::<SystemdNotifier>()
                                        + 2 * std::mem::size_of::<usize>()),
                                )?,
                        )
                        .ok()?,
                    )
                    .with(D::OpenFiles, u64::try_from(files.checked_add(1)?).ok()?)
                    .with(
                        D::MetadataEntries,
                        u64::try_from(names.checked_add(1)?).ok()?,
                    ),
            )
            .ok()
    }

    /// Opens the fixed first-local Store on the genuine current Network startup.
    ///
    /// The caller prepays this destination's compiled header before `new`.
    /// This method then adds its full source-derived contribution to the SAME
    /// startup F before observing any clock, namespace, notify socket or bus.
    ///
    /// # Errors
    /// Retains all actual startup/native/model failures and always enters the
    /// independent clock after once its primary acquisition was entered.
    pub fn prepare_once_v4(
        &mut self,
        maximum_entries: usize,
        startup: &mut FixedServiceReceivingCaptureV1<Closed>,
    ) -> Result<(), NetworkNamespaceStoreRefusalV4> {
        if self.entered {
            self.closed.get_or_insert(NetworkNamespaceStoreRefusalV4);
            self.first.get_or_insert(First::Closed);
            return Err(NetworkNamespaceStoreRefusalV4);
        }
        self.entered = true;
        self.entry = Some(startup.require_network_startup_current_v4());
        if !matches!(self.entry, Some(Ok(()))) {
            self.first = Some(First::Entry);
            return Err(NetworkNamespaceStoreRefusalV4);
        }
        self.shape = Some(Self::receiving_demand_v4(maximum_entries).ok_or(
            AccountingError::ArithmeticOverflow {
                dimension: D::MemoryBytes,
            },
        ));
        let Some(Ok(shape)) = self.shape.as_ref() else {
            self.first = Some(First::Shape);
            return Err(NetworkNamespaceStoreRefusalV4);
        };
        self.funding = Some(startup.require_additional_startup_representation_v4(*shape));
        if !matches!(self.funding, Some(Ok(()))) {
            self.first = Some(First::Funding);
            return Err(NetworkNamespaceStoreRefusalV4);
        }
        let horizon = self.clock.begin_once_v4();
        self.clock_before = Some(
            horizon
                .as_ref()
                .map(|_| ())
                .map_err(|_| super::acquisition_clock::NetworkStartupClockRefusalV4),
        );
        match horizon {
            Ok(horizon) => {
                if self.host.capture_once_v4().is_err() {
                    self.first = Some(First::Host);
                } else {
                    match self.notifier_opening.prepare_once_v4() {
                        Ok(notifier) => self.notifier = Some(Arc::new(notifier)),
                        Err(_) => self.first = Some(First::Notifier),
                    }
                }
                if self.first.is_none() {
                    let Some(bounds) = StoreReadBoundsV4::for_capacity(maximum_entries) else {
                        std::process::abort()
                    };
                    if self
                        .sdk
                        .connect_once_v4(
                            bounds.message,
                            bounds.materialized,
                            horizon.deadline,
                            horizon.boottime_cutoff,
                            None,
                        )
                        .is_err()
                        || self.sdk.snapshot_next_once_v4().is_err()
                    {
                        self.first = Some(First::Sdk);
                    } else if let Some(snapshot) = self.sdk.take_completed_snapshot_once_v4() {
                        self.parsed = Some(super::format::parse_systemd_snapshot(
                            snapshot.maximum_entries,
                            snapshot.reported_entries,
                            snapshot.rows,
                        ));
                        if !matches!(self.parsed, Some(Ok(_))) {
                            self.first = Some(First::Parse);
                        }
                    } else {
                        self.first = Some(First::Sdk);
                    }
                }
                if self.first.is_none() {
                    self.returned = Some(self.finish_inventory(maximum_entries));
                    if !matches!(self.returned, Some(Ok(_))) {
                        self.first = Some(First::Inventory);
                    }
                }
            }
            Err(_) => self.first = Some(First::ClockBefore),
        }
        // No same-healthy gate can suppress this prepaid, independent original.
        self.clock_after = Some(self.clock.finish_once_v4());
        if !matches!(self.clock_after, Some(Ok(()))) {
            self.first.get_or_insert(First::ClockAfter);
        }
        // Every local readback and the independently owed acquisition pair
        // succeeded. No outer native F post consumes the bus/driver leaves.
        if self.first.is_none() && self.sdk.finish_positive_native_once_v4().is_err() {
            self.first = Some(First::Disposal);
        }
        if self.first.is_none() {
            Ok(())
        } else {
            Err(NetworkNamespaceStoreRefusalV4)
        }
    }

    fn finish_inventory(
        &self,
        maximum: usize,
    ) -> Result<SystemdNetworkNamespaceStore, NetworkNamespaceStoreError> {
        let Some(host) = self.host.namespace_v4() else {
            return Err(NetworkNamespaceStoreError::Poisoned);
        };
        let Some(notifier) = self.notifier.as_ref().map(Arc::clone) else {
            return Err(NetworkNamespaceStoreError::Poisoned);
        };
        let Some(Ok(snapshot)) = self.parsed.as_ref() else {
            return Err(NetworkNamespaceStoreError::Poisoned);
        };
        // An actual complete initial-table proof came from this same intrinsic
        // Common, not an empty activation DTO. The manager still must prove the
        // identical empty set and the exact configured store maximum.
        let initial = BTreeMap::new();
        validate_initial_store_inputs(&initial, maximum, host.identity())?;
        let backend = SystemdStoreBackend::selected_from_notifier_v4(notifier);
        let core = StoreCore::finish_initial_observation(
            backend,
            initial,
            maximum,
            host.identity(),
            snapshot,
        )?;
        Ok(SystemdNetworkNamespaceStore { core })
    }

    /// Moves only the actual completed Store once; native originals remain held.
    #[must_use]
    pub fn take_completed_once_v4(&mut self) -> Option<SystemdNetworkNamespaceStore> {
        if self.first.is_some() || self.taken || !matches!(self.returned, Some(Ok(_))) {
            return None;
        }
        self.taken = true;
        match self.returned.take() {
            Some(Ok(store)) => Some(store),
            _ => std::process::abort(),
        }
    }

    /// Identifies the earlier actual F debit instead of replacing native causes.
    #[must_use]
    pub fn original_failure_selected_v4(&self) -> bool {
        matches!(self.first, Some(First::Funding))
    }

    /// Borrows the exact retained native or semantic first cause.
    #[must_use]
    pub fn failure_view_v4(&self) -> Option<NetworkNamespaceStoreFailureV4<'_>> {
        if matches!(self.first?, First::Sdk | First::Disposal) {
            return self
                .sdk
                .failure_view_v4()
                .map(NetworkNamespaceStoreFailureV4::Systemd);
        }
        let cause: &(dyn std::error::Error + 'static) = match self.first? {
            First::Entry => self.entry.as_ref()?.as_ref().err()?,
            First::Shape => self.shape.as_ref()?.as_ref().err()?,
            First::Funding => self.funding.as_ref()?.as_ref().err()?,
            First::ClockBefore | First::ClockAfter => self.clock.failure()?,
            First::Host => self.host.failure()?,
            First::Notifier => self.notifier_opening.failure()?,
            First::Parse => self.parsed.as_ref()?.as_ref().err()?,
            First::Inventory => self.returned.as_ref()?.as_ref().err()?,
            First::Closed => self.closed.as_ref()?,
            First::Sdk | First::Disposal => return None,
        };
        Some(NetworkNamespaceStoreFailureV4::Cause(cause))
    }
}
