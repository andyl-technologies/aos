//! Shares exact pin-worker termination with retained native observation slots.
//!
//! Kill success alone is never completion. The actual retained pidfd and
//! same cgroup.events OFD must prove death and empty/retired population. Local
//! positive wait samples can be disposed after their complete wait boundary;
//! refused samples, kill partials and all outer service posts remain owned.

use super::*;
use aos_sandbox_linux::cgroup::{
    CgroupKillAttemptV1, CgroupKillRefusalV1, CgroupPopulationObservationV1,
};

#[derive(Clone, Copy)]
enum First { Alive, Population, Kill, Clock, Wait, Sequence }

pub(super) struct WorkerExitOriginalV1 {
    alive: Option<Result<bool, aos_linux_descriptors::Error>>,
    population: CgroupPopulationObservationV1,
    population_result: Option<Result<(), aos_sandbox_linux::cgroup::CgroupPopulationObservationRefusalV1>>,
    kill: CgroupKillAttemptV1,
    kill_result: Option<Result<(), CgroupKillRefusalV1>>,
    clock: Option<rustix::time::Timespec>,
    clock_value: Option<Result<u64, ZfsWorkerError>>,
    readiness: crate::pin_worker::readiness::WorkerReadinessOriginalV1,
    wait: Option<Result<(), ZfsWorkerError>>,
    result: Option<Result<(), ZfsWorkerError>>,
    first: Option<First>,
    entered: bool,
    cutoff: Option<u64>,
}

impl WorkerExitOriginalV1 {
    pub(super) fn new() -> Self {
        Self { alive: None, population: CgroupPopulationObservationV1::new(),
            population_result: None, kill: CgroupKillAttemptV1::new(), kill_result: None,
            clock: None, clock_value: None,
            readiness: crate::pin_worker::readiness::WorkerReadinessOriginalV1::new(),
            wait: None, result: None,
            first: None, entered: false, cutoff: None }
    }

    pub(super) fn wait_once(&mut self, subject: &KernelAuthorizedRecordSubject,
        population: &CgroupPopulationMonitor, timeout: Duration, cutoff: u64,
    ) -> Result<(), ZfsWorkerError> {
        if self.entered { return Err(marker()); }
        self.entered = true;
        self.cutoff = Some(cutoff);
        self.result = Some(wait_with(subject, population, timeout, &mut Disposition::Retained(self)));
        if matches!(self.result, Some(Ok(()))) { Ok(()) } else {
            self.first.get_or_insert(First::Sequence);
            Err(marker())
        }
    }

    pub(super) fn quiesce_once(&mut self, subject: &KernelAuthorizedRecordSubject,
        anchor: &RetainedCgroupAnchor, population: &CgroupPopulationMonitor,
    ) -> Result<(), ZfsWorkerError> {
        if self.entered { return Err(marker()); }
        self.entered = true;
        self.result = Some(quiesce_with(subject, anchor, population, &mut Disposition::Retained(self)));
        if matches!(self.result, Some(Ok(()))) { Ok(()) } else {
            self.first.get_or_insert(First::Sequence);
            Err(marker())
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Alive => self.alive.as_ref()?.as_ref().err().map(|error| error as _),
            First::Population => self.population.failure(),
            First::Kill => self.kill.failure().map(|error| error as _),
            First::Clock => self.clock_value.as_ref()?.as_ref().err().map(|error| error as _),
            First::Wait => self.readiness.failure()
                .or_else(|| self.wait.as_ref()?.as_ref().err().map(|error| error as _)),
            First::Sequence => self.result.as_ref()?.as_ref().err().map(|error| error as _),
        }
    }

    pub(super) fn requested_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(CgroupPopulationObservationV1::requested_bytes_v1()?)?
            .checked_add(CgroupKillAttemptV1::requested_bytes_v1()?)?
            .checked_add(crate::pin_worker::readiness::WorkerReadinessOriginalV1::requested_bytes_v1()?)?
            .checked_add(8 * 256)
    }
}

// Private mechanical disposition: the selected caller can construct a sink
// only after the actual Native flight has paid it. This is never authority.
enum Disposition<'a> { Ordinary, Retained(&'a mut WorkerExitOriginalV1) }

impl Disposition<'_> {
    fn alive(&mut self, subject: &KernelAuthorizedRecordSubject) -> Result<bool, ZfsWorkerError> {
        let Self::Retained(owner) = self else { return subject.pidfd().is_alive().map_err(Into::into); };
        if matches!(owner.alive, Some(Err(_))) { return Err(marker()); }
        owner.alive = Some(subject.pidfd().is_alive());
        match owner.alive.as_ref() {
            Some(Ok(value)) => Ok(*value),
            _ => { owner.first.get_or_insert(First::Alive); Err(marker()) }
        }
    }

    fn population(&mut self, monitor: &CgroupPopulationMonitor) -> Result<CgroupPopulationState, ZfsWorkerError> {
        let Self::Retained(owner) = self else { return monitor.state().map_err(Into::into); };
        if owner.population.state().is_some() {
            // The previous local native read and parse completed positively.
            owner.population = CgroupPopulationObservationV1::new();
            owner.population_result = None;
        }
        owner.population_result = Some(monitor.observe_state_retaining_v1(&mut owner.population));
        match owner.population.state() {
            Some(value) if matches!(owner.population_result, Some(Ok(()))) => Ok(value),
            _ => { owner.first.get_or_insert(First::Population); Err(marker()) }
        }
    }

    fn kill(&mut self, anchor: &RetainedCgroupAnchor) -> Result<(), aos_linux_descriptors::Error> {
        let Self::Retained(owner) = self else { return anchor.kill_all(); };
        owner.kill_result = Some(owner.kill.capture_once(anchor));
        if matches!(owner.kill_result, Some(Ok(()))) { Ok(()) } else {
            owner.first.get_or_insert(First::Kill);
            Err(aos_linux_descriptors::Error::InvalidInput {
                field: "pin worker cancellation", message: "original cause retained".into(),
            })
        }
    }

    fn clock(&mut self) -> Result<u64, ZfsWorkerError> {
        let Self::Retained(owner) = self else { return boottime_now_nanoseconds(); };
        if matches!(owner.clock_value, Some(Err(_))) { return Err(marker()); }
        let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        owner.clock = Some(now);
        owner.clock_value = Some(crate::pin_worker::boottime_from_timespec_v1(now));
        match owner.clock_value.as_ref() {
            Some(Ok(value)) => Ok(*value),
            _ => { owner.first.get_or_insert(First::Clock); Err(marker()) }
        }
    }

    fn wait(&mut self, subject: &KernelAuthorizedRecordSubject, deadline: u64) -> Result<(), ZfsWorkerError> {
        let Self::Retained(owner) = self else {
            return wait_before(subject.pidfd().as_fd(),
                rustix::event::PollFlags::IN | rustix::event::PollFlags::RDNORM, deadline);
        };
        if matches!(owner.wait, Some(Ok(()))) && owner.readiness.is_complete() {
            owner.readiness = crate::pin_worker::readiness::WorkerReadinessOriginalV1::new();
            owner.wait = None;
        }
        owner.wait = Some(crate::pin_worker::readiness::wait_with_originals_v1(
            subject.pidfd().as_fd(),
            rustix::event::PollFlags::IN | rustix::event::PollFlags::RDNORM,
            deadline, Some(&mut owner.readiness),
        ));
        if matches!(owner.wait, Some(Ok(()))) { Ok(()) } else {
            owner.first.get_or_insert(First::Wait); Err(marker())
        }
    }

    fn positive_deadline(&mut self, deadline: u64) -> Result<(), ZfsWorkerError> {
        if matches!(self, Self::Ordinary) { return Ok(()); }
        deadline.checked_sub(self.clock()?).filter(|remaining| *remaining != 0)
            .ok_or(ZfsWorkerError::Protocol("workspace pin worker quiescence deadline elapsed"))?;
        Ok(())
    }
}

pub(super) fn ordinary_quiesce(subject: &KernelAuthorizedRecordSubject,
    anchor: &RetainedCgroupAnchor, population: &CgroupPopulationMonitor,
) -> Result<(), ZfsWorkerError> {
    quiesce_with(subject, anchor, population, &mut Disposition::Ordinary)
}

fn quiesce_with(subject: &KernelAuthorizedRecordSubject,
    anchor: &RetainedCgroupAnchor, population: &CgroupPopulationMonitor,
    observation: &mut Disposition<'_>,
) -> Result<(), ZfsWorkerError> {
    if is_quiescent(subject, population, observation)? { return Ok(()); }
    if let Err(kill_error) = observation.kill(anchor) {
        return match is_quiescent(subject, population, observation) {
            Ok(true) => Ok(()),
            Ok(false) => Err(kill_error.into()),
            Err(proof_error) => Err(ZfsWorkerError::Quiescence(format!(
                "cgroup kill failed and the quiescence recheck also failed; kill: {kill_error}; recheck: {proof_error}"
            ))),
        };
    }
    wait_with(subject, population, QUIESCENCE_TIMEOUT, observation)
}

fn is_quiescent(subject: &KernelAuthorizedRecordSubject,
    population: &CgroupPopulationMonitor, observation: &mut Disposition<'_>,
) -> Result<bool, ZfsWorkerError> {
    if observation.alive(subject)? { return Ok(false); }
    match observation.population(population)? {
        CgroupPopulationState::Empty | CgroupPopulationState::Retired => Ok(true),
        CgroupPopulationState::Populated => Ok(false),
    }
}

pub(super) fn ordinary_wait(subject: &KernelAuthorizedRecordSubject,
    population: &CgroupPopulationMonitor, timeout: Duration,
) -> Result<(), ZfsWorkerError> {
    wait_with(subject, population, timeout, &mut Disposition::Ordinary)
}

fn wait_with(subject: &KernelAuthorizedRecordSubject, population: &CgroupPopulationMonitor,
    timeout: Duration, observation: &mut Disposition<'_>,
) -> Result<(), ZfsWorkerError> {
    let deadline = observation.clock()?.checked_add(timeout.as_nanos() as u64)
        .ok_or(ZfsWorkerError::Protocol("workspace pin quiescence deadline overflowed"))?;
    let deadline = match observation {
        Disposition::Retained(original) => original.cutoff.map_or(deadline, |cutoff| deadline.min(cutoff)),
        Disposition::Ordinary => deadline,
    };
    loop {
        let worker_alive = observation.alive(subject)?;
        let state = observation.population(population)?;
        if !worker_alive && matches!(state, CgroupPopulationState::Empty | CgroupPopulationState::Retired) {
            return observation.positive_deadline(deadline);
        }
        let remaining = deadline.checked_sub(observation.clock()?)
            .filter(|remaining| *remaining != 0)
            .ok_or(ZfsWorkerError::Protocol("workspace pin worker quiescence deadline elapsed"))?;
        if worker_alive { observation.wait(subject, deadline)?; }
        else { std::thread::sleep(Duration::from_nanos(remaining).min(QUIESCENCE_POLL_INTERVAL)); }
    }
}

fn marker() -> ZfsWorkerError {
    ZfsWorkerError::Protocol("pin worker termination original retained")
}
