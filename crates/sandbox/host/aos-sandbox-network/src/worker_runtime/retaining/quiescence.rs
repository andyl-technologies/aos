//! Shares the actual dead-and-empty worker reducer with retained cleanup.
//!
//! A successful kill never proves quiescence. The selected caller must already
//! hold the exact validated READY child scope and prepay both natural/negative
//! observation destinations before issuing any worker request.

use super::super::*;
use aos_sandbox_broker::receiving::{
    FixedServiceOperationClosedV4, NetworkServiceReceivingLoanV4,
    NetworkWorkerCleanupClockScopeV4,
};
use aos_sandbox_linux::cgroup::{
    CgroupKillAttemptV1, CgroupKillRefusalV1, CgroupPopulationObservationV1,
};
use aos_sandbox_linux::seqpacket::NetworkWorkerNativeCutoffV4;
use aos_linux_descriptors::pidfd::PidFd;

pub(in crate::worker_runtime) trait WorkerQuiescenceNativeV4 {
    fn alive(
        &mut self,
        process: &PidFd,
    ) -> Result<bool, NetworkWorkerRuntimeError>;
    fn population(
        &mut self,
        population: &CgroupPopulationMonitor,
    ) -> Result<bool, NetworkWorkerRuntimeError>;
    fn kill(&mut self, cgroup: &RetainedCgroupAnchor) -> Result<(), NetworkWorkerRuntimeError>;
    fn deadline(&mut self, timeout: Duration) -> Result<u64, NetworkWorkerRuntimeError>;
    fn now(&mut self) -> Result<u64, NetworkWorkerRuntimeError>;
    fn before_sample(&mut self) -> Result<(), NetworkWorkerRuntimeError> {
        Ok(())
    }
}

pub(in crate::worker_runtime) fn quiesce_engine_v4(
    subject: &KernelAuthorizedRecordSubject,
    cgroup: &RetainedCgroupAnchor,
    population: &CgroupPopulationMonitor,
    native: &mut impl WorkerQuiescenceNativeV4,
) -> Result<(), NetworkWorkerRuntimeError> {
    quiesce_process_engine_v2(subject.pidfd(), cgroup, population, native)
}

fn quiesce_process_engine_v2(
    process: &PidFd,
    cgroup: &RetainedCgroupAnchor,
    population: &CgroupPopulationMonitor,
    native: &mut impl WorkerQuiescenceNativeV4,
) -> Result<(), NetworkWorkerRuntimeError> {
    native.before_sample()?;
    if !native.alive(process)? && native.population(population)? {
        return Ok(());
    }
    if let Err(error) = native.kill(cgroup) {
        native.before_sample()?;
        if !native.alive(process)? && native.population(population)? {
            return Ok(());
        }
        return Err(error);
    }
    wait_process_engine_v2(process, population, QUIESCENCE_TIMEOUT, native)
}

pub(in crate::worker_runtime) fn wait_engine_v4(
    subject: &KernelAuthorizedRecordSubject,
    population: &CgroupPopulationMonitor,
    timeout: Duration,
    native: &mut impl WorkerQuiescenceNativeV4,
) -> Result<(), NetworkWorkerRuntimeError> {
    wait_process_engine_v2(subject.pidfd(), population, timeout, native)
}

fn wait_process_engine_v2(
    process: &PidFd,
    population: &CgroupPopulationMonitor,
    timeout: Duration,
    native: &mut impl WorkerQuiescenceNativeV4,
) -> Result<(), NetworkWorkerRuntimeError> {
    let deadline = native.deadline(timeout)?;
    loop {
        native.before_sample()?;
        if !native.alive(process)? && native.population(population)? {
            return Ok(());
        }
        let remaining = deadline
            .checked_sub(native.now()?)
            .filter(|remaining| *remaining != 0)
            .ok_or_else(|| {
                NetworkWorkerRuntimeError::Quiescence(
                    "Network worker quiescence deadline elapsed".to_owned(),
                )
            })?;
        std::thread::sleep(Duration::from_nanos(remaining).min(QUIESCENCE_POLL_INTERVAL));
    }
}

pub(in crate::worker_runtime) struct LocalQuiescenceV4;

impl WorkerQuiescenceNativeV4 for LocalQuiescenceV4 {
    fn alive(
        &mut self,
        process: &PidFd,
    ) -> Result<bool, NetworkWorkerRuntimeError> {
        Ok(process.is_alive()?)
    }
    fn population(
        &mut self,
        population: &CgroupPopulationMonitor,
    ) -> Result<bool, NetworkWorkerRuntimeError> {
        cgroup_is_quiescent(population)
    }
    fn kill(&mut self, cgroup: &RetainedCgroupAnchor) -> Result<(), NetworkWorkerRuntimeError> {
        Ok(cgroup.kill_all()?)
    }
    fn deadline(&mut self, timeout: Duration) -> Result<u64, NetworkWorkerRuntimeError> {
        deadline_after(timeout)
    }
    fn now(&mut self) -> Result<u64, NetworkWorkerRuntimeError> {
        boottime_now_nanoseconds()
    }
}

#[derive(Clone, Copy)]
enum First {
    Clock,
    Alive,
    Population,
    Kill,
    Gate,
    Recipe,
    Closed,
}

struct PhaseOriginalV4 {
    alive: Option<aos_linux_descriptors::Result<bool>>,
    population: CgroupPopulationObservationV1,
    population_result:
        Option<Result<(), aos_sandbox_linux::cgroup::CgroupPopulationObservationRefusalV1>>,
    clock: Option<aos_linux_descriptors::Result<u64>>,
    returned: Option<Result<(), NetworkWorkerRuntimeError>>,
    closed: Option<NetworkWorkerRuntimeError>,
    samples: usize,
    limit: usize,
    first: Option<First>,
}

impl PhaseOriginalV4 {
    fn new(limit: usize) -> Self {
        Self {
            alive: None,
            population: CgroupPopulationObservationV1::new(),
            population_result: None,
            clock: None,
            returned: None,
            closed: None,
            samples: 0,
            limit,
            first: None,
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Clock => self.clock.as_ref()?.as_ref().err().map(|error| error as _),
            First::Alive => self.alive.as_ref()?.as_ref().err().map(|error| error as _),
            First::Population => self.population.failure(),
            First::Closed => self.closed.as_ref().map(|error| error as _),
            First::Recipe => self
                .returned
                .as_ref()?
                .as_ref()
                .err()
                .map(|error| error as _),
            First::Kill | First::Gate => None,
        }
    }
}

pub(crate) struct WorkerQuiescenceOriginalV4 {
    natural: PhaseOriginalV4,
    cleanup: PhaseOriginalV4,
    kill: CgroupKillAttemptV1,
    killed: Option<Result<(), CgroupKillRefusalV1>>,
    gate: Option<FixedServiceOperationClosedV4>,
    issued: aos_sandbox_linux::cgroup::IssuedCgroupQuiescenceAttemptV2,
    issued_result: Option<Result<(), NetworkWorkerRuntimeError>>,
}

impl WorkerQuiescenceOriginalV4 {
    pub(crate) fn new() -> Self {
        Self {
            natural: PhaseOriginalV4::new(102),
            cleanup: PhaseOriginalV4::new(503),
            kill: CgroupKillAttemptV1::new(),
            killed: None,
            gate: None,
            issued: aos_sandbox_linux::cgroup::IssuedCgroupQuiescenceAttemptV2::new(),
            issued_result: None,
        }
    }

    pub(crate) fn receiving_obligations_v4() -> Option<(usize, usize, usize)> {
        let (issued_bytes, issued_files, issued_names) =
            aos_sandbox_linux::cgroup::IssuedCgroupQuiescenceAttemptV2::receiving_obligations_v2()?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(CgroupPopulationObservationV1::requested_bytes_v1()?.checked_mul(2)?)?
            .checked_add(CgroupKillAttemptV1::requested_bytes_v1()?)?
            .checked_add(NetworkWorkerNativeCutoffV4::receiving_bytes_v4()?.checked_mul(4)?)?
            .checked_add(issued_bytes)?;
        // The monitor is separately acquired and held. These are the two
        // actual active/control files and their canonical native names.
        Some((bytes, CgroupKillAttemptV1::maximum_retained_files_v1().checked_add(issued_files)?,
            2usize.checked_add(issued_names)?))
    }

    pub(super) fn natural_once_v4(
        &mut self,
        subject: &KernelAuthorizedRecordSubject,
        population: &CgroupPopulationMonitor,
        cutoff: NetworkWorkerNativeCutoffV4,
    ) -> Result<(), NetworkWorkerRuntimeError> {
        self.natural_birth_once_v2(subject.pidfd(), population, cutoff)
    }

    pub(crate) fn natural_birth_once_v2(
        &mut self,
        process: &PidFd,
        population: &CgroupPopulationMonitor,
        cutoff: NetworkWorkerNativeCutoffV4,
    ) -> Result<(), NetworkWorkerRuntimeError> {
        if self.natural.returned.is_some() {
            self.natural.closed.get_or_insert_with(marker);
            self.natural.first.get_or_insert(First::Closed);
            return Err(marker());
        }
        let mut native = RetainedQuiescenceV4 {
            phase: &mut self.natural,
            cutoff,
            kill: None,
            killed: None,
            gate: None,
            loan: None,
            cleanup_scope: None,
        };
        let returned = wait_process_engine_v2(process, population, NATURAL_EXIT_TIMEOUT, &mut native);
        native.phase.returned = Some(returned);
        if matches!(native.phase.returned, Some(Ok(()))) && native.phase.first.is_none() {
            Ok(())
        } else {
            native.phase.first.get_or_insert(First::Recipe);
            Err(marker())
        }
    }

    // Only the containing validated READY owner calls this method. Its input
    // pins are held continuously; no caller path, runtime payload or new target
    // can be adopted here. The paid same-source native gate can only deny.
    pub(super) fn cleanup_once_v4(
        &mut self,
        subject: &KernelAuthorizedRecordSubject,
        cgroup: &RetainedCgroupAnchor,
        population: &CgroupPopulationMonitor,
        cutoff: NetworkWorkerNativeCutoffV4,
        loan: &mut NetworkServiceReceivingLoanV4<'_>,
        cleanup_scope: &mut NetworkWorkerCleanupClockScopeV4,
    ) -> Result<(), NetworkWorkerRuntimeError> {
        self.cleanup_birth_once_v2(
            subject.pidfd(),
            cgroup,
            population,
            cutoff,
            loan,
            cleanup_scope,
        )
    }

    pub(super) fn cleanup_birth_once_v2(
        &mut self,
        process: &PidFd,
        cgroup: &RetainedCgroupAnchor,
        population: &CgroupPopulationMonitor,
        cutoff: NetworkWorkerNativeCutoffV4,
        loan: &mut NetworkServiceReceivingLoanV4<'_>,
        cleanup_scope: &mut NetworkWorkerCleanupClockScopeV4,
    ) -> Result<(), NetworkWorkerRuntimeError> {
        if self.cleanup.returned.is_some() {
            self.cleanup.closed.get_or_insert_with(marker);
            self.cleanup.first.get_or_insert(First::Closed);
            return Err(marker());
        }
        let mut native = RetainedQuiescenceV4 {
            phase: &mut self.cleanup,
            cutoff,
            kill: Some(&mut self.kill),
            killed: Some(&mut self.killed),
            gate: Some(&mut self.gate),
            loan: Some(loan),
            cleanup_scope: Some(cleanup_scope),
        };
        let returned = quiesce_process_engine_v2(process, cgroup, population, &mut native);
        native.phase.returned = Some(returned);
        if matches!(native.phase.returned, Some(Ok(()))) && native.phase.first.is_none() {
            Ok(())
        } else {
            native.phase.first.get_or_insert(First::Recipe);
            Err(marker())
        }
    }

    // Only the Broker's issued-birth scoped callback enters this lane. Its
    // actual pins and consumed same-operation prearm stay resident there.
    // No effect-current deadline is consulted by this disabling disposition.
    pub(crate) fn cleanup_issued_birth_once_v2(
        &mut self,
        process: &PidFd,
        cgroup: &RetainedCgroupAnchor,
        population: &CgroupPopulationMonitor,
    ) -> Result<(), NetworkWorkerRuntimeError> {
        if self.issued_result.is_some() { return Err(marker()); }
        self.issued_result = Some(self.issued.capture_once_v2(process, cgroup, population)
            .map_err(|_| marker()));
        if matches!(self.issued_result, Some(Ok(()))) { Ok(()) } else { Err(marker()) }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.natural
            .failure()
            .or_else(|| self.issued.failure())
            .or_else(|| match self.cleanup.first? {
                First::Kill => self.kill.native_failure_v2(),
                First::Gate => self.gate.as_ref().map(|error| error as _),
                _ => self.cleanup.failure(),
            })
    }

    pub(super) fn original_failure_selected_v4(&self) -> bool {
        self.natural.failure().is_none()
            && matches!(self.cleanup.first, Some(First::Gate))
    }
}

fn marker() -> NetworkWorkerRuntimeError {
    NetworkWorkerRuntimeError::Protocol("whole worker quiescence original retained")
}

struct RetainedQuiescenceV4<'held, 'loan, 'financial> {
    phase: &'held mut PhaseOriginalV4,
    cutoff: NetworkWorkerNativeCutoffV4,
    kill: Option<&'held mut CgroupKillAttemptV1>,
    killed: Option<&'held mut Option<Result<(), CgroupKillRefusalV1>>>,
    gate: Option<&'held mut Option<FixedServiceOperationClosedV4>>,
    loan: Option<&'loan mut NetworkServiceReceivingLoanV4<'financial>>,
    cleanup_scope: Option<&'loan mut NetworkWorkerCleanupClockScopeV4>,
}

impl WorkerQuiescenceNativeV4 for RetainedQuiescenceV4<'_, '_, '_> {
    fn alive(
        &mut self,
        process: &PidFd,
    ) -> Result<bool, NetworkWorkerRuntimeError> {
        self.phase.alive = Some(process.is_alive());
        match self.phase.alive.as_ref() {
            Some(Ok(alive)) => Ok(*alive),
            _ => {
                self.phase.first.get_or_insert(First::Alive);
                Err(marker())
            }
        }
    }

    fn population(
        &mut self,
        monitor: &CgroupPopulationMonitor,
    ) -> Result<bool, NetworkWorkerRuntimeError> {
        if self.phase.population.state().is_some() {
            // This exact same-OFD read/parser scope was wholly positive. No
            // later post consumes its temporary bytes or scalar result.
            self.phase.population = CgroupPopulationObservationV1::new();
        }
        self.phase.population_result =
            Some(monitor.observe_state_retaining_v1(&mut self.phase.population));
        if !matches!(self.phase.population_result, Some(Ok(()))) {
            self.phase.first.get_or_insert(First::Population);
            return Err(marker());
        }
        Ok(matches!(
            self.phase.population.state(),
            Some(CgroupPopulationState::Empty | CgroupPopulationState::Retired)
        ))
    }

    fn kill(&mut self, cgroup: &RetainedCgroupAnchor) -> Result<(), NetworkWorkerRuntimeError> {
        let (Some(kill), Some(killed), Some(gate), Some(loan), Some(cleanup_scope)) = (
            &mut self.kill,
            &mut self.killed,
            &mut self.gate,
            &mut self.loan,
            &mut self.cleanup_scope,
        ) else {
            return Err(marker());
        };
        let cutoff = self.cutoff;
        let phase = &mut self.phase;
        let mut current = || {
            phase.clock = Some(cutoff.observe_native_v4());
            if !matches!(phase.clock, Some(Ok(_))) {
                phase.first.get_or_insert(First::Clock);
                // The actual rejected scalar pair remains on phase.clock.
                return Err(None);
            }
            loan.observe_owed_network_worker_cleanup_clock_v4(cleanup_scope)
                .map(|_| ())
                .map_err(Some)
        };
        let (result, refused) = kill.capture_bounded_with_current_cut_v4(cgroup, &mut current);
        **killed = Some(result);
        if let Some(Some(error)) = refused {
            **gate = Some(error);
            phase.first.get_or_insert(First::Gate);
        }
        if matches!(**killed, Some(Ok(()))) {
            Ok(())
        } else {
            phase.first.get_or_insert(First::Kill);
            Err(marker())
        }
    }

    fn deadline(&mut self, timeout: Duration) -> Result<u64, NetworkWorkerRuntimeError> {
        self.now()?
            .checked_add(u64::try_from(timeout.as_nanos()).map_err(|_| marker())?)
            .map(|local| local.min(self.cutoff.original_deadline_v4()))
            .ok_or_else(marker)
    }

    fn now(&mut self) -> Result<u64, NetworkWorkerRuntimeError> {
        self.phase.clock = Some(self.cutoff.observe_native_v4());
        match self.phase.clock.as_ref() {
            Some(Ok(now)) => Ok(*now),
            _ => {
                self.phase.first.get_or_insert(First::Clock);
                Err(marker())
            }
        }
    }

    fn before_sample(&mut self) -> Result<(), NetworkWorkerRuntimeError> {
        if self.phase.samples >= self.phase.limit {
            self.phase.first.get_or_insert(First::Recipe);
            return Err(marker());
        }
        self.phase.samples += 1;
        self.now().map(|_| ())
    }
}
