//! Fresh Stop containment on the same occupied, possibly poisoned Capture F.
//!
//! The initial actual Capture flight pays every native destination and arms
//! distinct observer operations before setup. Fresh signed Stop permission can
//! later contain only that original's READY and aggregate. Neither native
//! quiescence nor its receipt retires the incomplete output, old errors or debt.

use super::*;
use aos_sandbox_broker::{BrokerAdmissionError, VerifiedStorageCaptureStopCleanupV4};
use aos_sandbox_model::{ObjectDigest, RawPairedClockSample};
use aos_sandbox_linux::cgroup::{CgroupKillAttemptV1, CgroupKillRefusalV1};
use aos_sandbox_linux::seqpacket::bounded::{BoundedRecordError, wait_capture_worker_exit_v3};
use sha2::{Digest as _, Sha256};

// Six fixed observations surround containment, wait, population and final F
// post. Each actual bounded kill write has its own additional native gate.
const FIXED_CLOCKS: usize = 6;
const CLOCKS: usize = FIXED_CLOCKS + CgroupKillAttemptV1::maximum_bounded_write_attempts_v4();
const AFTER_KILL: usize = CLOCKS - 5;
const BEFORE_WAIT: usize = CLOCKS - 4;
const AFTER_WAIT: usize = CLOCKS - 3;
const BEFORE_POPULATION: usize = CLOCKS - 2;
const AFTER_POST: usize = CLOCKS - 1;

#[derive(Debug, thiserror::Error)]
enum ClockError {
    #[error("fresh Stop paired clock is unavailable or stale")]
    Stale,
    #[error(transparent)]
    Native(aos_linux_descriptors::Error),
}

impl aos_sandbox_broker::kernel_clock::KernelPairedClockErrorV1 for ClockError {
    fn stale() -> Self {
        Self::Stale
    }
    fn kernel(cause: aos_linux_descriptors::Error) -> Self {
        Self::Native(cause)
    }
}

type Clock = aos_sandbox_broker::kernel_clock::RetainedKernelPairedClockAttemptV1<ClockError>;

struct ClockSlot {
    native: Clock,
    pair: Option<Result<RawPairedClockSample, ClockError>>,
    cut: Option<Result<(), BrokerAdmissionError>>,
}

impl ClockSlot {
    fn new() -> Self {
        Self {
            native: Clock::default(),
            pair: None,
            cut: None,
        }
    }

    fn observe(
        &mut self,
        permission: &VerifiedStorageCaptureStopCleanupV4,
    ) -> Result<(), StorageReceivingClosedV1> {
        if self.pair.is_some() {
            return Err(StorageReceivingClosedV1);
        }
        self.pair = Some(self.native.observe_once(None));
        let Some(Ok(pair)) = self.pair.as_ref() else {
            return Err(StorageReceivingClosedV1);
        };
        self.cut = Some(permission.require_current_sample_v4(pair));
        if matches!(self.cut, Some(Ok(()))) {
            Ok(())
        } else {
            Err(StorageReceivingClosedV1)
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.native
            .failure()
            .or_else(|| self.pair.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.cut.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

#[derive(Clone, Copy)]
enum First {
    Payment,
    Binding,
    Observer(usize),
    Clock(usize),
    BeforeAlive,
    Kill,
    Wait,
    Alive,
    Population,
}

/// Borrows actual negative native evidence while incomplete Capture debt stays.
///
/// Only the same-F native operation below can construct this evidence. It
/// proves worker death and empty/retired population under fresh Stop permission,
/// not pipe EOF, stream readback, complete output or positive F disposal.
pub struct StorageCaptureStopQuiescenceV4 {
    source: ObjectDigest,
    request: [u8; 16],
    frame: [u8; 32],
    native: ObjectDigest,
    final_pair: RawPairedClockSample,
}

impl StorageCaptureStopQuiescenceV4 {
    /// Returns the exact original full Source944 commitment.
    #[must_use]
    pub const fn source_digest_v4(&self) -> ObjectDigest {
        self.source
    }

    /// Returns the actual fresh Stop request whose permission bounded cleanup.
    #[must_use]
    pub const fn stop_request_id_v4(&self) -> &[u8; 16] {
        &self.request
    }

    /// Returns the exact authenticated forwarding frame commitment.
    #[must_use]
    pub const fn frame_digest_v4(&self) -> &[u8; 32] {
        &self.frame
    }

    /// Returns the privately constructed native containment commitment.
    #[must_use]
    pub const fn native_cleanup_digest_v4(&self) -> ObjectDigest {
        self.native
    }

    /// Returns the actual fresh Stop paired sample after the independent F post.
    #[must_use]
    pub const fn final_sample_v4(&self) -> &RawPairedClockSample {
        &self.final_pair
    }
}

pub(super) struct CaptureStopNativeOriginalV4 {
    source: Option<ObjectDigest>,
    demand: Option<Result<ResourceVector, aos_sandbox_model::AccountingError>>,
    payment: Option<Result<(), aos_sandbox_model::AccountingError>>,
    preparation: [Option<Result<(), StorageReceivingClosedV1>>; 2],
    observer: [StorageObserverOperationOriginalV1; 2],
    posts: [Option<Result<(), StorageReceivingClosedV1>>; 2],
    clocks: [ClockSlot; CLOCKS],
    binding: Option<Result<(), StorageReceivingClosedV1>>,
    population_owner: Option<Result<(), aos_linux_descriptors::Error>>,
    before_alive: Option<Result<bool, aos_linux_descriptors::Error>>,
    kill: CgroupKillAttemptV1,
    kill_result: Option<Result<(), CgroupKillRefusalV1>>,
    kill_gate: Option<StorageReceivingClosedV1>,
    wait: Option<Result<(), BoundedRecordError>>,
    alive: Option<Result<bool, aos_linux_descriptors::Error>>,
    population: CgroupPopulationObservationV1,
    population_result: Option<Result<(), CgroupPopulationObservationRefusalV1>>,
    proof: Option<StorageCaptureStopQuiescenceV4>,
    entered: bool,
    first: Option<First>,
}

impl CaptureStopNativeOriginalV4 {
    pub(super) fn new() -> Self {
        Self {
            source: None,
            demand: None,
            payment: None,
            preparation: [None, None],
            observer: std::array::from_fn(|_| {
                StorageObserverOperationOriginalV1::with_repeated_fixed_names_v1()
            }),
            posts: [None, None],
            clocks: std::array::from_fn(|_| ClockSlot::new()),
            binding: None,
            population_owner: None,
            before_alive: None,
            kill: CgroupKillAttemptV1::new(),
            kill_result: None,
            kill_gate: None,
            wait: None,
            alive: None,
            population: CgroupPopulationObservationV1::new(),
            population_result: None,
            proof: None,
            entered: false,
            first: None,
        }
    }

    pub(super) fn receiving_demand_v4() -> Option<ResourceVector> {
        let bytes = std::mem::size_of::<Self>()
            .checked_add(CgroupKillAttemptV1::requested_bytes_v1()?)?
            .checked_add(CgroupPopulationObservationV1::requested_bytes_v1()?)?
            .checked_add(Clock::dominant_requested_bytes_v1()?.checked_mul(CLOCKS)?)?;
        let files = CgroupKillAttemptV1::maximum_retained_files_v1()
            .checked_add(Clock::MAXIMUM_RETAINED_FILES_V1.checked_mul(CLOCKS)?)?;
        Some(
            ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
                .with(D::OpenFiles, u64::try_from(files).ok()?)
                .with(
                    D::MetadataEntries,
                    u64::try_from(CgroupKillAttemptV1::METADATA_ENTRIES_V1).ok()?,
                )
                // One control reader coexists with the occupied worker; its
                // two distinct observers pay their own operation reservoirs.
                .with(D::ConcurrentOperations, 1),
        )
    }

    fn clock(&mut self, index: usize, permission: &VerifiedStorageCaptureStopCleanupV4) -> bool {
        let positive = self.clocks[index].observe(permission).is_ok();
        if !positive {
            self.first.get_or_insert(First::Clock(index));
        }
        positive
    }

    fn contain(
        &mut self,
        ready: &ReceivedRecord,
        cgroup: &RetainedCgroupAnchor,
        population: &CgroupPopulationMonitor,
        permission: &VerifiedStorageCaptureStopCleanupV4,
    ) {
        if self.clock(0, permission) && self.first.is_none() {
            // Only an actual false observation of this same READY pidfd skips
            // mutation. An alive or uncertain worker keeps the existing kill
            // path; uncertainty remains the first cause beside all later debt.
            if self.requires_kill_v4(ready.subject().pidfd()) {
                let mut index = 1;
                let Self {
                    clocks,
                    kill,
                    kill_result,
                    kill_gate,
                    ..
                } = self;
                let mut current = || {
                    let slot = clocks.get_mut(index).ok_or(StorageReceivingClosedV1)?;
                    index += 1;
                    slot.observe(permission)
                };
                let (result, gate) = kill.capture_bounded_with_current_cut_v4(cgroup, &mut current);
                *kill_result = Some(result);
                *kill_gate = gate;
                if !matches!(self.kill_result, Some(Ok(()))) {
                    self.first.get_or_insert(if self.kill_gate.is_some() {
                        First::Clock(index - 1)
                    } else {
                        First::Kill
                    });
                }
            }
        }
        // Every entered primary has an independent after-clock destination.
        // A native failure keeps priority over its later after observation.
        self.clock(AFTER_KILL, permission);
        if self.clock(BEFORE_WAIT, permission) {
            self.wait = Some(wait_capture_worker_exit_v3(
                ready.subject().pidfd(),
                permission.cutoff_v4(),
            ));
            if !matches!(self.wait, Some(Ok(()))) {
                self.first.get_or_insert(First::Wait);
            }
            self.clock(AFTER_WAIT, permission);
        }
        if self.clock(BEFORE_POPULATION, permission) {
            observe_quiescence_native_v4(
                ready,
                population,
                &mut self.alive,
                &mut self.population,
                &mut self.population_result,
            );
            if !matches!(self.alive, Some(Ok(false))) {
                self.first.get_or_insert(First::Alive);
            }
            if !matches!(self.population_result, Some(Ok(())))
                || !capture::capture_quiescence_data_v3(
                    self.alive
                        .as_ref()
                        .and_then(|result| result.as_ref().ok())
                        .copied(),
                    self.population.state(),
                )
            {
                self.first.get_or_insert(First::Population);
            }
        }
    }

    fn requires_kill_v4(&mut self, pidfd: &aos_linux_descriptors::pidfd::PidFd) -> bool {
        self.before_alive = Some(pidfd.is_alive());
        if matches!(self.before_alive, Some(Err(_))) {
            self.first.get_or_insert(First::BeforeAlive);
        }
        !matches!(self.before_alive, Some(Ok(false)))
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Payment => self
                .demand
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as _)
                .or_else(|| {
                    self.payment
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                }),
            First::Binding => self
                .population_owner
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as _)
                .or(Some(&StorageReceivingClosedV1)),
            First::Observer(index) => self.observer[index].failure().or_else(|| {
                self.posts[index]
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            }),
            First::Clock(index) => self.clocks[index]
                .failure()
                .or(Some(&StorageReceivingClosedV1)),
            First::BeforeAlive => self
                .before_alive
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Kill => self.kill.native_failure_v2(),
            First::Wait => self.wait.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Alive => self
                .alive
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _)
                .or(Some(&StorageReceivingClosedV1)),
            First::Population => self
                .population
                .failure()
                .or(Some(&StorageReceivingClosedV1)),
        }
    }
}

// One native death/population recipe serves both positive precommit and fresh
// Stop containment. A parsed report or raw DATA cannot supply these results.
pub(super) fn observe_quiescence_native_v4(
    ready: &ReceivedRecord,
    population: &CgroupPopulationMonitor,
    alive: &mut Option<Result<bool, aos_linux_descriptors::Error>>,
    observation: &mut CgroupPopulationObservationV1,
    result: &mut Option<Result<(), CgroupPopulationObservationRefusalV1>>,
) {
    *alive = Some(ready.subject().pidfd().is_alive());
    *result = Some(population.observe_state_retaining_v1(observation));
}

impl super::super::state_recovery::StorageStateRecoveryEncodingLoanV1<'_, '_> {
    /// Prepays one finite cancellation liability before actual Capture effects.
    ///
    /// The same current State, actual signed60 and private verified lifetime
    /// bind this once-only reservation. It creates no worker, new effect,
    /// State operation, account or cleanup permission. Later fresh Stop must
    /// independently authorize the occupied original before native cancellation.
    ///
    /// # Errors
    /// Refuses a changed actual60/State/source, repeated preparation, unrelated
    /// dimensions or the same monotone ledger's real capacity refusal.
    pub fn prepare_capture_stop_liability_v4(
        &mut self,
        state: &crate::Journal,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        verified: &aos_sandbox_broker::VerifiedStorageCaptureLifetimeV3,
        upper: ResourceVector,
    ) -> Result<(), StorageReceivingClosedV1> {
        if !capture::matches_actual_capture_request_v3(request, verified) {
            return Err(StorageReceivingClosedV1);
        }
        let loan = self.receiving_capture_worker_v3(state)?;
        let receiving = loan.receiving()?;
        let physical = &mut receiving.physical_worker;
        let cleanup = &mut physical.capture_stop;
        if cleanup.source.is_some() || physical.kind.is_some() || physical.operation.is_some() {
            return Err(StorageReceivingClosedV1);
        }
        cleanup.source = Some(verified.source_v3().source_digest_v2());
        let shape = ResourceVector::ZERO
            .with(D::MemoryBytes, upper.get(D::MemoryBytes))
            .with(D::OpenFiles, upper.get(D::OpenFiles))
            .with(D::MetadataEntries, upper.get(D::MetadataEntries))
            .with(D::OutputBytes, upper.get(D::OutputBytes))
            .with(D::NetworkBytes, upper.get(D::NetworkBytes));
        if shape != upper {
            cleanup.first.get_or_insert(First::Binding);
            physical.first.get_or_insert(WorkerFailure::CaptureStop);
            receiving.first.get_or_insert(Failure::PhysicalWorker);
            return Err(StorageReceivingClosedV1);
        }
        cleanup.demand = Some(upper.checked_add(Self::capture_stop_native_demand_v4()?));
        let Some(demand) = cleanup
            .demand
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
        else {
            cleanup.first.get_or_insert(First::Payment);
            physical.first.get_or_insert(WorkerFailure::CaptureStop);
            receiving.first.get_or_insert(Failure::PhysicalWorker);
            return Err(StorageReceivingClosedV1);
        };
        cleanup.payment = Some(receiving.ledger.reserve(demand).map_err(|cause| *cause));
        if !matches!(cleanup.payment, Some(Ok(()))) {
            cleanup.first.get_or_insert(First::Payment);
            physical.first.get_or_insert(WorkerFailure::CaptureStop);
            receiving.first.get_or_insert(Failure::PhysicalWorker);
            return Err(StorageReceivingClosedV1);
        }
        loan.prepare_capture_stop_observers_v4()
    }

    fn capture_stop_native_demand_v4() -> Result<ResourceVector, StorageReceivingClosedV1> {
        CaptureStopNativeOriginalV4::receiving_demand_v4().ok_or(StorageReceivingClosedV1)
    }
}

impl StoragePrepareReceivingLoanV1<'_> {
    pub(super) fn require_capture_stop_liability_v4(
        &mut self,
        verified: &aos_sandbox_broker::VerifiedStorageCaptureLifetimeV3,
    ) -> Result<(), StorageReceivingClosedV1> {
        let receiving = self.receiving()?;
        let cleanup = &receiving.physical_worker.capture_stop;
        if cleanup.source == Some(verified.source_v3().source_digest_v2())
            && matches!(cleanup.payment, Some(Ok(())))
            && cleanup
                .preparation
                .iter()
                .all(|result| matches!(result, Some(Ok(()))))
        {
            Ok(())
        } else {
            Err(StorageReceivingClosedV1)
        }
    }

    pub(super) fn prepare_capture_stop_observers_v4(
        &mut self,
    ) -> Result<(), StorageReceivingClosedV1> {
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.original.recipient.as_mut()
        else {
            return Err(StorageReceivingClosedV1);
        };
        for index in 0..2 {
            let cleanup = &mut receiving.physical_worker.capture_stop;
            cleanup.preparation[index] = Some(
                cleanup.observer[index].prepare_once_v1(&mut receiving.ledger, &receiving.lifetime),
            );
            if !matches!(cleanup.preparation[index], Some(Ok(()))) {
                cleanup.first.get_or_insert(First::Observer(index));
                receiving
                    .physical_worker
                    .first
                    .get_or_insert(WorkerFailure::CaptureStop);
                receiving.first.get_or_insert(Failure::PhysicalWorker);
                return Err(StorageReceivingClosedV1);
            }
        }
        Ok(())
    }

    fn observe_capture_stop_post_v4(
        &mut self,
        index: usize,
    ) -> Result<(), StorageReceivingClosedV1> {
        let Some(StorageResourceRecipientCustodyV1::Receiving {
            component,
            receiving,
        }) = self.original.recipient.as_mut()
        else {
            return Err(StorageReceivingClosedV1);
        };
        let Some(initial) = receiving
            .before
            .as_ref()
            .and_then(|result| result.as_ref().ok())
        else {
            return Err(StorageReceivingClosedV1);
        };
        let cleanup = &mut receiving.physical_worker.capture_stop;
        cleanup.posts[index] = Some(cleanup.observer[index].observe_prepared_once_v1(
            &receiving.lifetime,
            &self.original.custody,
            component,
            initial,
            &receiving.containment,
        ));
        if matches!(cleanup.posts[index], Some(Ok(()))) {
            Ok(())
        } else {
            cleanup.first.get_or_insert(First::Observer(index));
            Err(StorageReceivingClosedV1)
        }
    }

    /// Contains only this occupied Capture worker under actual fresh Stop.
    ///
    /// This once-only negative branch uses destinations and observer flights
    /// prepaid before initial Capture effects. The old error/open/accounting
    /// latches remain unchanged; no ordinary healthy reentry or new operation
    /// occurs. The actual receiver separately owes channel, alias and Output
    /// posts and must keep all incomplete output debt after this call.
    ///
    /// # Errors
    /// Rejects another READY, Source, State, Output or aggregate, repeated use,
    /// missing prepayment, expired Stop permission, and any native uncertainty.
    /// Every entered native prefix and independently owed F post stays owned.
    pub fn observe_capture_stop_quiescence_v4(
        &mut self,
        resident: &StorageResidentCaptureWorkerV2,
        state: &crate::Journal,
        output: &crate::Journal,
        cgroup: &RetainedCgroupAnchor,
        population: &CgroupPopulationMonitor,
        permission: &VerifiedStorageCaptureStopCleanupV4,
    ) -> Result<(), StorageReceivingClosedV1> {
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.original.recipient.as_mut()
        else {
            return Err(StorageReceivingClosedV1);
        };
        let physical = &mut receiving.physical_worker;
        let cleanup = &mut physical.capture_stop;
        if cleanup.entered {
            return Err(StorageReceivingClosedV1);
        }
        // Latch before any binding refusal. A second signed Stop cannot reset
        // this branch, its native destinations or previously spent capacity.
        cleanup.entered = true;
        let ready = match (physical.capture_ready.as_ref(), resident.ready.as_ref()) {
            (Some(original), Some(ready)) if std::sync::Arc::ptr_eq(original, ready) => ready,
            _ => {
                cleanup.first.get_or_insert(First::Binding);
                return Err(StorageReceivingClosedV1);
            }
        };
        cleanup.population_owner = Some(population.require_same_cgroup(cgroup));
        let binding = cleanup.source == Some(permission.source_digest_v4())
            && matches!(cleanup.payment, Some(Ok(())))
            && !resident.completed
            && physical.capture_resident
            && physical.kind == Some(WorkerKind::Capture)
            && physical.operation.is_some()
            && physical
                .capture_source
                .is_some_and(|(source, _)| source == permission.source_digest_v4())
            && physical
                .aggregate_worker
                .anchor()
                .is_some_and(|anchor| anchor.kernel_id() == cgroup.kernel_id())
            && receiving.startup.state_recovery_ready_v1(state)
            && receiving.startup.output_currentness_ready_v1(output)
            && matches!(cleanup.population_owner, Some(Ok(())))
            && cleanup
                .preparation
                .iter()
                .all(|result| matches!(result, Some(Ok(()))));
        cleanup.binding = Some(if binding {
            Ok(())
        } else {
            Err(StorageReceivingClosedV1)
        });
        if !binding {
            cleanup.first.get_or_insert(First::Binding);
        }
        let _ = ready;
        // Entering negative containment irreversibly fences the positive
        // Capture branch. Existing earlier causes win and every old operation,
        // resident READY, native prefix and spent debit remain occupied.
        physical.first.get_or_insert(WorkerFailure::CaptureStop);
        receiving.first.get_or_insert(Failure::PhysicalWorker);
        self.original.open = false;
        let before = self.observe_capture_stop_post_v4(0);
        if binding && before.is_ok() {
            let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
                self.original.recipient.as_mut()
            else {
                std::process::abort()
            };
            let Some(ready) = resident.ready.as_ref() else {
                std::process::abort()
            };
            receiving
                .physical_worker
                .capture_stop
                .contain(ready, cgroup, population, permission);
        }
        // This post is owed even when the before/body/native permission fails.
        let _ = self.observe_capture_stop_post_v4(1);
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.original.recipient.as_mut()
        else {
            std::process::abort()
        };
        let cleanup = &mut receiving.physical_worker.capture_stop;
        cleanup.clock(AFTER_POST, permission);
        if cleanup.first.is_some() {
            return Err(StorageReceivingClosedV1);
        }
        let Some(Ok(final_pair)) = cleanup.clocks[AFTER_POST].pair.as_ref() else {
            return Err(StorageReceivingClosedV1);
        };
        let mut digest = Sha256::new();
        digest.update(b"aos-storage-capture-stop-native-v4\0");
        digest.update(permission.frame_digest_v4());
        digest.update(permission.source_digest_v4().as_bytes());
        digest.update(permission.request_id_v4());
        digest.update(cgroup.kernel_id().to_be_bytes());
        digest.update(
            resident
                .ready
                .as_ref()
                .ok_or(StorageReceivingClosedV1)?
                .payload(),
        );
        digest.update(final_pair.wall_seconds().to_be_bytes());
        digest.update(final_pair.boottime_nanoseconds().to_be_bytes());
        digest.update([0, 0]); // actual dead pidfd and empty/retired population
        cleanup.proof = Some(StorageCaptureStopQuiescenceV4 {
            source: permission.source_digest_v4(),
            request: *permission.request_id_v4(),
            frame: *permission.frame_digest_v4(),
            native: ObjectDigest::from_bytes(digest.finalize().into()),
            final_pair: *final_pair,
        });
        Ok(())
    }

    /// Borrows actual one-shot negative evidence without releasing old debt.
    #[must_use]
    pub fn capture_stop_quiescence_v4(&self) -> Option<&StorageCaptureStopQuiescenceV4> {
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.original.recipient.as_ref()
        else {
            return None;
        };
        let cleanup = &receiving.physical_worker.capture_stop;
        if cleanup.first.is_some() {
            return None;
        }
        cleanup.proof.as_ref()
    }

    /// Borrows this negative branch's native cause beside the earlier failure.
    #[must_use]
    pub fn capture_stop_failure_v4(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.original.recipient.as_ref()
        else {
            return Some(&StorageReceivingClosedV1);
        };
        receiving.physical_worker.capture_stop.failure()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_linux_descriptors::pidfd::PidFd;
    use std::num::NonZeroU32;
    use std::os::fd::{AsFd as _, AsRawFd as _};

    const CHILD_ENV: &str = "AOS_CAPTURE_STOP_PIDFD_TEST_V4";
    const CHILD_TEST: &str = "normal_root::storage_worker_origin::receiving::physical_worker::capture_stop::tests::liveness_child_v4";

    // The fixture owns every child on assertion/refusal paths as well.
    struct Child(std::process::Child);

    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn liveness_child_v4() {
        if std::env::var_os(CHILD_ENV).is_some() {
            loop {
                std::thread::park();
            }
        }
    }

    #[test]
    fn same_retained_already_dead_pidfd_skips_kill_without_creating_proof() {
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg(CHILD_TEST)
                .arg("--nocapture")
                .env(CHILD_ENV, "1")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        let pidfd = PidFd::open(NonZeroU32::new(child.0.id()).unwrap()).unwrap();
        let descriptor = pidfd.as_fd().as_raw_fd();
        assert!(pidfd.is_alive().unwrap());
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        let mut original = CaptureStopNativeOriginalV4::new();

        assert!(!original.requires_kill_v4(&pidfd));

        assert_eq!(pidfd.as_fd().as_raw_fd(), descriptor);
        assert!(matches!(original.before_alive, Some(Ok(false))));
        assert!(original.kill_result.is_none());
        assert!(original.first.is_none());
        assert!(original.proof.is_none());
        assert!(!pidfd.is_alive().unwrap());
    }

    #[test]
    fn actual_live_pidfd_still_requires_the_containment_path() {
        let pidfd = PidFd::open(NonZeroU32::new(std::process::id()).unwrap()).unwrap();
        let mut original = CaptureStopNativeOriginalV4::new();

        assert!(original.requires_kill_v4(&pidfd));

        assert!(matches!(original.before_alive, Some(Ok(true))));
        assert!(original.proof.is_none());
        assert!(original.kill_result.is_none());
    }
}
