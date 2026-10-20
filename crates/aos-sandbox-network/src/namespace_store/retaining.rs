//! Retains one selected Store mutation on the existing inventory reducer.
//!
//! The same real namespace Store and F interval remain the owners. Restrictive
//! wire bounds pay the complete two-read/notify/barrier recipe before entry;
//! they do not authenticate a namespace or grant a mutation. Partial native
//! effects, first causes and the independent manager after remain resident.

use super::format::parse_systemd_snapshot;
use super::*;
use std::cell::RefCell;
use std::os::fd::AsFd as _;
use std::sync::Arc;

use aos_sandbox_broker::receiving::{
    FixedServiceOperationClosedV4 as Closed, NetworkServiceReceivingLoanV4,
};
use aos_sandbox_core::{
    AccountingError, RawPairedClockSample, ResourceDimension as D, ResourceVector,
};
use aos_systemd::fd_store::{NetworkFdStoreFailureViewV4, NetworkFdStoreInspectionOriginalV4};

use super::systemd::SystemdNotifier;
use super::systemd::notifier_original::{
    BarrierAttemptV4, NotifyAttemptV4, barrier_engine, notify_engine,
};

/// Reports a refusal while the actual Store originals remain owned.
#[derive(Debug, thiserror::Error)]
#[error("selected Network namespace Store is incomplete or refused")]
pub struct NetworkNamespaceStoreRefusalV4;

/// Borrows the exact original SDK/native or typed semantic failure.
pub enum NetworkNamespaceStoreFailureV4<'held> {
    /// Keeps the same raw native error guard alive while formatting it.
    Systemd(NetworkFdStoreFailureViewV4<'held>),
    /// Borrows the actual retained native or semantic error.
    Cause(&'held (dyn std::error::Error + 'static)),
}

impl std::fmt::Debug for NetworkNamespaceStoreFailureV4<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NetworkNamespaceStoreFailureV4")
    }
}

impl std::fmt::Display for NetworkNamespaceStoreFailureV4<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Systemd(cause) => std::fmt::Display::fmt(cause, formatter),
            Self::Cause(cause) => std::fmt::Display::fmt(cause, formatter),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct StoreReadBoundsV4 {
    pub(super) message: usize,
    pub(super) materialized: usize,
}

impl StoreReadBoundsV4 {
    pub(super) fn for_capacity(maximum: usize) -> Option<Self> {
        if maximum == 0 || maximum > MAXIMUM_RETAINED_NETWORK_NAMESPACES {
            return None;
        }
        // First-local input has no saved tail. The only accepted role is a
        // typed nsfs Network namespace: its native diagnostic name is net:[N].
        // These remain enforced restrictive extents, not a promise that every
        // alternate diagnostic/error body from PID1 fits the selected profile.
        let diagnostic = b"net:["
            .len()
            .checked_add(u64::MAX.ilog10() as usize + 1)?
            .checked_add(b"]".len())?;
        let row = NetworkNamespaceStoreName::maximum_bytes_v4()
            .checked_add(diagnostic)?
            .checked_add(6 * std::mem::size_of::<u32>() + std::mem::size_of::<u64>())?
            .checked_add(2 * (std::mem::size_of::<u32>() + 1))?
            .checked_add(9 * 8)?;
        let schedule = zbus::connection::NetworkFdStoreReceiveScheduleV4::new(16, 16).ok()?;
        let fixed = schedule.raw_data_v4().maximum_request_bytes();
        // The canonical fixed header has eight possible fields, each with a
        // maximum255-byte D-Bus name/signature plus type/length/alignment.
        let header = 16usize.checked_add(8 * (8 + 4 + 255 + 1))?;
        let dump = maximum.checked_mul(row)?.checked_add(header)?;
        let message = dump.max(fixed);
        let materialized = message.checked_mul(2)?.checked_add(
            fixed.checked_mul(schedule.raw_data_v4().incoming_messages().checked_sub(2)?)?,
        )?;
        Some(Self {
            message,
            materialized,
        })
    }

    pub(super) fn demand_v4(self, maximum: usize, header: usize) -> Option<ResourceVector> {
        use aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1 as nodes;
        let sdk = NetworkFdStoreInspectionOriginalV4::receiving_footprint_v4(
            self.message,
            self.materialized,
        )?;
        // Current inventory, proposed clone, both parsed observations and
        // their one-slot growth/error plane retain distinct source backing.
        let maps = nodes::<NetworkNamespaceStoreName, NamespaceIdentity>(maximum.checked_mul(5)?)?;
        let indices = nodes::<(u64, u64), ()>(maximum.checked_mul(2)?)?;
        let text = maximum
            .checked_mul(NetworkNamespaceStoreName::maximum_bytes_v4())?
            .checked_mul(5)?;
        let bytes = header
            .checked_mul(2)?
            .checked_add(sdk.memory_bytes)?
            .checked_add(
                super::systemd::notifier_original::mutation_receiving_bytes_v4(
                    NetworkNamespaceStoreName::maximum_bytes_v4(),
                )?,
            )?
            .checked_add(maps)?
            .checked_add(indices)?
            .checked_add(text)?;
        Some(
            ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
                .with(
                    D::OpenFiles,
                    u64::try_from(sdk.open_files.checked_add(3)?).ok()?,
                )
                .with(
                    D::MetadataEntries,
                    u64::try_from(
                        sdk.metadata_entries
                            .checked_add(maximum.checked_mul(7)?)?
                            .checked_add(1)?,
                    )
                    .ok()?,
                )
                .with(
                    D::NetworkBytes,
                    u64::try_from(sdk.network_bytes.checked_add(2 * 256)?).ok()?,
                )
                .with(
                    D::LogBytes,
                    u64::try_from(sdk.maximum_log_bytes.checked_add(4 * 4096)?).ok()?,
                ),
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub(super) enum StoreClockErrorV4 {
    #[error("Network namespace Store original cutoff expired or changed")]
    Expired,
    #[error("Network namespace Store finite barrier wait exhausted")]
    Exhausted,
}

pub(super) struct StoreNativeFenceV4 {
    baseline: RawPairedClockSample,
    deadline: u64,
    wall_expiry: Option<i64>,
    pub(super) before_boot: Option<rustix::time::Timespec>,
    pub(super) before_wall: Option<rustix::time::Timespec>,
    pub(super) failure: Option<StoreClockErrorV4>,
    polls: usize,
    pub(super) poll_result: Option<Result<usize, rustix::io::Errno>>,
}

impl StoreNativeFenceV4 {
    pub(super) fn new(
        sample: RawPairedClockSample,
        deadline: u64,
        wall_expiry: Option<i64>,
    ) -> Self {
        Self {
            baseline: sample,
            deadline,
            wall_expiry,
            before_boot: None,
            before_wall: None,
            failure: None,
            polls: 0,
            poll_result: None,
        }
    }

    pub(super) fn check(&mut self) -> Result<(), rustix::io::Errno> {
        if self.failure.is_some() {
            return Err(rustix::io::Errno::TIMEDOUT);
        }
        self.before_boot = Some(rustix::time::clock_gettime(rustix::time::ClockId::Boottime));
        self.before_wall = Some(rustix::time::clock_gettime(rustix::time::ClockId::Realtime));
        let boot = self.before_boot.as_ref().and_then(|value| {
            u64::try_from(value.tv_sec)
                .ok()
                .and_then(|seconds| seconds.checked_mul(1_000_000_000))
                .and_then(|seconds| {
                    u64::try_from(value.tv_nsec)
                        .ok()
                        .and_then(|fraction| seconds.checked_add(fraction))
                })
        });
        if boot
            .is_none_or(|boot| boot < self.baseline.boottime_nanoseconds() || boot >= self.deadline)
            || self.before_wall.as_ref().is_none_or(|wall| {
                wall.tv_sec < self.baseline.wall_seconds()
                    || self.wall_expiry.is_some_and(|expiry| wall.tv_sec >= expiry)
            })
        {
            self.failure = Some(StoreClockErrorV4::Expired);
            return Err(rustix::io::Errno::TIMEDOUT);
        }
        Ok(())
    }

    fn wait_barrier(
        &mut self,
        waiter: &std::os::fd::OwnedFd,
        byte: &mut [u8; 1],
    ) -> Result<usize, rustix::io::Errno> {
        // The old mechanical five-second barrier has at most500 ten-ms waits.
        // All positive scalar/empty poll temporaries can be replaced after
        // their full check; no later post consumes them. A negative is held.
        for _ in 0..500 {
            self.check()?;
            self.polls += 1;
            let mut polls = [rustix::event::PollFd::new(
                waiter,
                rustix::event::PollFlags::IN,
            )];
            let timeout = rustix::time::Timespec {
                tv_sec: 0,
                tv_nsec: 10_000_000,
            };
            self.poll_result = Some(rustix::event::poll(&mut polls, Some(&timeout)));
            let count = match self.poll_result.as_ref() {
                Some(Ok(count)) => *count,
                Some(Err(cause)) => return Err(*cause),
                None => std::process::abort(),
            };
            self.check()?;
            if count != 0 {
                // The absolute gate occurs after readiness and immediately
                // before the actual nonblocking native receive.
                return rustix::net::recv(waiter, byte, rustix::net::RecvFlags::DONTWAIT)
                    .map(|(bytes, _)| bytes);
            }
        }
        self.failure = Some(StoreClockErrorV4::Exhausted);
        Err(rustix::io::Errno::TIMEDOUT)
    }
}

#[derive(Clone, Copy)]
enum First {
    Entry,
    Funding,
    Horizon,
    Clock,
    Sdk,
    Parse,
    Notify,
    Barrier,
    Semantic,
    Disposal,
    Closed,
}

/// Owns one real fixed Store notify/barrier/whole-readback attempt.
#[must_use = "retain native uncertainty and independently owed posts"]
pub struct NetworkNamespaceStoreMutationOriginalV4 {
    notifier: Option<Arc<SystemdNotifier>>,
    sdk: NetworkFdStoreInspectionOriginalV4,
    bounds: Option<StoreReadBoundsV4>,
    shape: Option<Result<ResourceVector, AccountingError>>,
    entry: Option<Result<(), Closed>>,
    funding: Option<Result<(), Closed>>,
    horizon: Option<Result<(RawPairedClockSample, u64), Closed>>,
    wall: Option<Result<Option<i64>, Closed>>,
    fence: Option<StoreNativeFenceV4>,
    notify: NotifyAttemptV4,
    barrier: BarrierAttemptV4,
    payload: Option<String>,
    parsed: [Option<Result<StoreSnapshot, NetworkNamespaceStoreError>>; 2],
    next_snapshot: usize,
    semantic: Option<Result<NetworkNamespaceStoreOutcome, NetworkNamespaceStoreError>>,
    owed_inventory: Option<Result<(), NetworkNamespaceStoreError>>,
    closed: Option<NetworkNamespaceStoreRefusalV4>,
    first: Option<First>,
    entered: bool,
    taken: bool,
}

impl NetworkNamespaceStoreMutationOriginalV4 {
    /// Creates inert destinations without IO, cloning or allocation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            notifier: None,
            sdk: NetworkFdStoreInspectionOriginalV4::new(),
            bounds: None,
            shape: None,
            entry: None,
            funding: None,
            horizon: None,
            wall: None,
            fence: None,
            notify: Default::default(),
            barrier: Default::default(),
            payload: None,
            parsed: std::array::from_fn(|_| None),
            next_snapshot: 0,
            semantic: None,
            owed_inventory: None,
            closed: None,
            first: None,
            entered: false,
            taken: false,
        }
    }

    /// Reports the actual complete two-snapshot/notify/barrier native invoice.
    #[must_use]
    pub fn receiving_demand_v4(maximum_entries: usize) -> Option<ResourceVector> {
        StoreReadBoundsV4::for_capacity(maximum_entries)?
            .demand_v4(maximum_entries, std::mem::size_of::<Self>())
    }

    /// Selects only an actual earlier F entry/payment/effect-clock source.
    #[must_use]
    pub fn original_failure_selected_v4(&self) -> bool {
        (matches!(self.first, Some(First::Funding)) && matches!(self.funding, Some(Err(_))))
            || matches!(self.first, Some(First::Horizon))
            || (matches!(self.first, Some(First::Notify))
                && matches!(self.notify.gate, Some(Err(_))))
            || (matches!(self.first, Some(First::Barrier))
                && matches!(self.barrier.sent.gate, Some(Err(_))))
    }

    /// Borrows the exact resident first cause without a new observation.
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
            First::Funding => self
                .shape
                .as_ref()
                .and_then(|shape| shape.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static))
                .or_else(|| {
                    self.funding
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                })?,
            First::Horizon => self
                .horizon
                .as_ref()
                .and_then(|horizon| horizon.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static))
                .or_else(|| self.wall.as_ref()?.as_ref().err().map(|cause| cause as _))?,
            First::Clock => self.fence.as_ref()?.failure.as_ref()?,
            First::Parse => self
                .parsed
                .iter()
                .find_map(|parsed| parsed.as_ref()?.as_ref().err())?,
            First::Notify => self
                .notify
                .failure()
                .or_else(|| self.semantic.as_ref()?.as_ref().err().map(|cause| cause as _))
                .unwrap_or(&NetworkNamespaceStoreRefusalV4),
            First::Barrier => self
                .fence
                .as_ref()
                .and_then(|fence| fence.failure.as_ref())
                .map(|cause| cause as &(dyn std::error::Error + 'static))
                .or_else(|| self.barrier.failure())
                .or_else(|| self.semantic.as_ref()?.as_ref().err().map(|cause| cause as _))
                .unwrap_or(&NetworkNamespaceStoreRefusalV4),
            First::Semantic => self.semantic.as_ref()?.as_ref().err()?,
            First::Closed => self.closed.as_ref()?,
            First::Sdk | First::Disposal => return None,
        };
        Some(NetworkNamespaceStoreFailureV4::Cause(cause))
    }
}

struct SelectedBackendV4<'borrow, 'operation> {
    destroy: bool,
    original: RefCell<&'borrow mut NetworkNamespaceStoreMutationOriginalV4>,
    loan: RefCell<&'borrow mut NetworkServiceReceivingLoanV4<'operation>>,
}

impl StoreBackend for SelectedBackendV4<'_, '_> {
    fn snapshot(&self) -> Result<StoreSnapshot, String> {
        let mut original = self.original.borrow_mut();
        let index = original.next_snapshot;
        if index >= original.parsed.len() {
            return Err("Network snapshot roster exhausted".to_owned());
        }
        original.next_snapshot += 1;
        if original.sdk.snapshot_next_once_v4().is_err() {
            original.first.get_or_insert(First::Sdk);
            return Err("original Network FDStore SDK refusal retained".to_owned());
        }
        let Some(snapshot) = original.sdk.take_completed_snapshot_once_v4() else {
            original.first.get_or_insert(First::Sdk);
            return Err("completed Network FDStore snapshot is absent".to_owned());
        };
        original.parsed[index] = Some(parse_systemd_snapshot(
            snapshot.maximum_entries,
            snapshot.reported_entries,
            snapshot.rows,
        ));
        if !matches!(original.parsed[index], Some(Ok(_))) {
            original.first.get_or_insert(First::Parse);
            return Err("actual Network Store metadata parser refusal retained".to_owned());
        }
        match original.parsed[index].take() {
            Some(Ok(snapshot)) => Ok(snapshot),
            _ => std::process::abort(),
        }
    }

    fn store(
        &self,
        name: &NetworkNamespaceStoreName,
        descriptor: BorrowedFd<'_>,
    ) -> Result<(), BackendMutationError> {
        if self.destroy {
            return Err(BackendMutationError::NotSent("Destroy cannot store custody".to_owned()));
        }
        self.notify_selected_v2(name, Some(descriptor))
    }

    fn remove(&self, name: &NetworkNamespaceStoreName) -> Result<(), BackendMutationError> {
        if !self.destroy {
            return Err(BackendMutationError::NotSent("Prepare cannot remove custody".to_owned()));
        }
        self.notify_selected_v2(name, None)
    }
}

impl SelectedBackendV4<'_, '_> {
    fn notify_selected_v2(
        &self,
        name: &NetworkNamespaceStoreName,
        descriptor: Option<BorrowedFd<'_>>,
    ) -> Result<(), BackendMutationError> {
        let mut original = self.original.borrow_mut();
        let Some(notifier) = original.notifier.as_ref().map(Arc::clone) else {
            return Err(BackendMutationError::NotSent(
                "fixed notifier absent".to_owned(),
            ));
        };
        original.payload = Some(match descriptor {
            Some(_) => format!("FDSTORE=1\nFDPOLL=0\nFDNAME={}", name.as_str()),
            None => format!("FDSTOREREMOVE=1\nFDNAME={}", name.as_str()),
        });
        // Move only pure text temporarily; the actual notifier/native slots
        // stay on this same owner before each fallible primitive.
        let Some(payload) = original.payload.take() else {
            std::process::abort()
        };
        let mut loan = self.loan.borrow_mut();
        let mut gate = || loan.observe_network_worker_effect_clock_v4().map(|_| ());
        let sent = notify_engine(
            &notifier,
            payload.as_bytes(),
            descriptor,
            &mut original.notify,
            Some(&mut gate),
        );
        original.payload = Some(payload);
        if let Err(cause) = sent {
            original.first.get_or_insert(First::Notify);
            return Err(if original.notify.written.is_some() {
                BackendMutationError::Ambiguous(cause)
            } else {
                BackendMutationError::NotSent(cause)
            });
        }
        let NetworkNamespaceStoreMutationOriginalV4 { barrier, fence, .. } = &mut **original;
        let Some(fence) = fence.as_mut() else {
            std::process::abort()
        };
        let mut wait =
            |waiter: &std::os::fd::OwnedFd, byte: &mut [u8; 1]| fence.wait_barrier(waiter, byte);
        if let Err(cause) = barrier_engine(&notifier, barrier, Some(&mut gate), Some(&mut wait)) {
            original.first.get_or_insert(First::Barrier);
            return Err(BackendMutationError::Ambiguous(cause));
        }
        Ok(())
    }

}

impl SystemdNetworkNamespaceStore {
    /// Quotes the same configured retained store programme before worker birth.
    pub(crate) fn mutation_receiving_demand_data_v2(&self) -> Option<ResourceVector> {
        NetworkNamespaceStoreMutationOriginalV4::receiving_demand_v4(self.core.maximum_entries)
    }

    /// Confirms one namespace through the same Store reducer under actual F.
    ///
    /// This prices/current-checks the real native operation; dispatch authority
    /// still comes from the existing verified coordinator/worker caller.
    ///
    /// # Errors
    /// Keeps all reached native/SDK/semantic failures and independent afters.
    pub fn store_retaining_once_v4(
        &self,
        name: &NetworkNamespaceStoreName,
        namespace: &NamespaceFd,
        loan: &mut NetworkServiceReceivingLoanV4<'_>,
        original: &mut NetworkNamespaceStoreMutationOriginalV4,
    ) -> Result<NetworkNamespaceStoreOutcome, NetworkNamespaceStoreRefusalV4> {
        self.mutate_retaining_once_v2(name, Some(namespace), loan, original)
    }

    /// Removes custody through the same whole-store reducer and native posts.
    ///
    /// # Errors
    /// Retains wrong-purpose, payer, manager transport, native or inventory refusal.
    pub(crate) fn remove_retaining_once_v2(
        &self,
        name: &NetworkNamespaceStoreName,
        loan: &mut NetworkServiceReceivingLoanV4<'_>,
        original: &mut NetworkNamespaceStoreMutationOriginalV4,
    ) -> Result<NetworkNamespaceStoreOutcome, NetworkNamespaceStoreRefusalV4> {
        self.mutate_retaining_once_v2(name, None, loan, original)
    }

    fn mutate_retaining_once_v2(
        &self,
        name: &NetworkNamespaceStoreName,
        namespace: Option<&NamespaceFd>,
        loan: &mut NetworkServiceReceivingLoanV4<'_>,
        original: &mut NetworkNamespaceStoreMutationOriginalV4,
    ) -> Result<NetworkNamespaceStoreOutcome, NetworkNamespaceStoreRefusalV4> {
        if original.entered {
            original
                .closed
                .get_or_insert(NetworkNamespaceStoreRefusalV4);
            original.first.get_or_insert(First::Closed);
            return Err(NetworkNamespaceStoreRefusalV4);
        }
        original.entered = true;
        original.entry = Some(match namespace {
            Some(_) => loan.require_network_prepare_current_v4(),
            None => loan.require_network_destroy_current_v4(),
        });
        if !matches!(original.entry, Some(Ok(()))) {
            original.first = Some(First::Entry);
            return Err(NetworkNamespaceStoreRefusalV4);
        }
        original.shape = Some(
            NetworkNamespaceStoreMutationOriginalV4::receiving_demand_v4(self.core.maximum_entries)
                .ok_or(AccountingError::ArithmeticOverflow {
                    dimension: D::MemoryBytes,
                }),
        );
        let Some(Ok(shape)) = original.shape.as_ref() else {
            original.first = Some(First::Funding);
            return Err(NetworkNamespaceStoreRefusalV4);
        };
        original.funding = Some(loan.require_additional_representation_v4(*shape));
        if !matches!(original.funding, Some(Ok(()))) {
            original.first = Some(First::Funding);
            return Err(NetworkNamespaceStoreRefusalV4);
        }
        original.notifier = self.core.backend.selected_notifier_v4();
        if original.notifier.is_none() {
            original.semantic = Some(Err(NetworkNamespaceStoreError::Poisoned));
            original.first = Some(First::Semantic);
            return Err(NetworkNamespaceStoreRefusalV4);
        }
        original.horizon = Some(loan.retained_network_horizon_data_v4());
        original.wall = Some(loan.retained_network_wall_ceiling_data_v4());
        let (Some(Ok((sample, deadline))), Some(Ok(wall))) =
            (original.horizon.as_ref(), original.wall.as_ref())
        else {
            original.first = Some(First::Horizon);
            return Err(NetworkNamespaceStoreRefusalV4);
        };
        let sample = *sample;
        let deadline = *deadline;
        let wall = *wall;
        original.fence = Some(StoreNativeFenceV4::new(sample, deadline, wall));
        original.bounds = StoreReadBoundsV4::for_capacity(self.core.maximum_entries);
        let Some(bounds) = original.bounds else {
            std::process::abort()
        };
        // Compute the coarse timeout from a fresh deny-only native scalar,
        // while keeping the actual paired source and original signed D. Start
        // Instant before that observation so it cannot extend the native bound.
        let reference = tokio::time::Instant::now();
        let Some(fence) = original.fence.as_mut() else {
            std::process::abort()
        };
        if fence.check().is_err() {
            original.first = Some(First::Clock);
            return Err(NetworkNamespaceStoreRefusalV4);
        }
        let Some(boot) = fence.before_boot.as_ref() else {
            std::process::abort()
        };
        let current_boot = u64::try_from(boot.tv_sec)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .and_then(|seconds| {
                u64::try_from(boot.tv_nsec)
                    .ok()
                    .and_then(|fraction| seconds.checked_add(fraction))
            })
            .ok_or(NetworkNamespaceStoreRefusalV4)?;
        let remaining = deadline
            .checked_sub(current_boot)
            .ok_or(NetworkNamespaceStoreRefusalV4)?;
        let mechanical = reference
            .checked_add(std::time::Duration::from_nanos(
                remaining.min(5_000_000_000),
            ))
            .ok_or(NetworkNamespaceStoreRefusalV4)?;
        if original
            .sdk
            .connect_once_v4(
                bounds.message,
                bounds.materialized,
                mechanical,
                deadline,
                wall,
            )
            .is_err()
        {
            original.first = Some(First::Sdk);
            return Err(NetworkNamespaceStoreRefusalV4);
        }
        let backend = SelectedBackendV4 {
            destroy: namespace.is_none(),
            original: RefCell::new(original),
            loan: RefCell::new(loan),
        };
        let result = match namespace {
            Some(namespace) => self.core.store_using_v4(name, namespace, &backend),
            None => self.core.remove_using_v4(name, &backend),
        };
        {
            let mut original = backend.original.borrow_mut();
            original.semantic = Some(result);
            if !matches!(original.semantic, Some(Ok(_))) {
                original.first.get_or_insert(First::Semantic);
            }
        }
        // An entered notification can have affected PID1 even when the send or
        // barrier refused. Independently attempt the prepaid second inventory;
        // it can never turn that earlier uncertainty into success.
        let owes_inventory = {
            let original = backend.original.borrow();
            original.notify.written.is_some() && original.next_snapshot == 1
        };
        if owes_inventory {
            let after = backend
                .snapshot()
                .map(|_| ())
                .map_err(NetworkNamespaceStoreError::Systemd);
            backend.original.borrow_mut().owed_inventory = Some(after);
        }
        let mut original = backend.original.borrow_mut();
        if original.first.is_none() && original.sdk.finish_positive_native_once_v4().is_err() {
            original.first = Some(First::Disposal);
        }
        if original.first.is_some() {
            return Err(NetworkNamespaceStoreRefusalV4);
        }
        original.taken = true;
        original
            .semantic
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or(NetworkNamespaceStoreRefusalV4)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_configured_store_capacity_has_an_admissible_closed_wire_shape() {
        assert!(StoreReadBoundsV4::for_capacity(0).is_none());
        assert!(StoreReadBoundsV4::for_capacity(MAXIMUM_RETAINED_NETWORK_NAMESPACES + 1).is_none());
        for maximum in [1, 2, 8, 64, MAXIMUM_RETAINED_NETWORK_NAMESPACES] {
            let bounds = StoreReadBoundsV4::for_capacity(maximum).unwrap();
            let actual = zbus::connection::NetworkFdStoreReceiveScheduleV4::new(
                bounds.message,
                bounds.materialized,
            )
            .unwrap();
            assert_eq!(actual.raw_data_v4().outgoing_messages(), 37);
            assert_eq!(actual.raw_data_v4().incoming_messages(), 40);
            assert!(
                NetworkNamespaceStoreMutationOriginalV4::receiving_demand_v4(maximum).is_some()
            );
        }
    }
}
