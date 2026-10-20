//! Shares exact Stop kernel preparation and confirmation with retained custody.
//!
//! The ordinary entry consumes its proof at the existing boundary. The selected
//! entry parks every reached root, child, membership, pidfd and population read
//! on the same prepaid SDK row. No returned boolean retires these native pins.

use super::*;
use aos_sandbox_linux::cgroup::{
    CgroupChildOriginalV2, CgroupPopulationMonitorOriginalV3, CgroupPopulationObservationV1,
    CgroupRootOriginalV2, RuntimeScopeMembershipOriginalV1,
};
use aos_sandbox_linux::pidfd::PidFdOpenAttemptV1;

type Native<T> = std::result::Result<T, aos_sandbox_linux::Error>;

macro_rules! stop_root {
    (Local, $root:ident, $original:ident) => {
        CgroupV2Root::from_owned($root.as_fd().try_clone_to_owned()
            .map_err(|error| HostError::Worker(error.to_string()))?)
            .map_err(|error| HostError::Worker(error.to_string()))?
    };
    (Retained, $root:ident, $original:ident) => {{
        $original.duplicate = Some($root.as_fd().try_clone_to_owned());
        let descriptor = match $original.duplicate.take() {
            Some(Ok(descriptor)) => descriptor,
            Some(Err(error)) => {
                $original.duplicate = Some(Err(error));
                return Err(closed("Stop cgroup root duplication failed; original retained"));
            }
            None => return Err(closed("Stop cgroup root duplication is absent")),
        };
        $original.root.admit_once(descriptor)
            .map_err(|_| closed("Stop cgroup root admission failed; original retained"))?;
        $original.completed_root = Some($original.root.take_completed_once()
            .ok_or_else(|| closed("Stop cgroup root is incomplete"))?);
        $original.completed_root.as_ref().ok_or_else(|| closed("Stop cgroup root is absent"))?
    }};
}

macro_rules! stop_child {
    (Local, $root:ident, $path:expr, $original:ident) => {
        $root.resolve(Path::new($path.as_str().trim_start_matches('/')))
            .map_err(|error| HostError::Worker(error.to_string()))?
    };
    (Retained, $root:ident, $path:expr, $original:ident) => {{
        $original.child.resolve_once($root, Path::new($path.as_str().trim_start_matches('/')))
            .map_err(|_| closed("Stop cgroup resolution failed; original retained"))?;
        $original.completed_child = Some($original.child.take_completed_once()
            .ok_or_else(|| closed("Stop cgroup resolution is incomplete"))?);
        $original.completed_child.as_ref().ok_or_else(|| closed("Stop cgroup is absent"))?
    }};
}

macro_rules! stop_monitor {
    (Local, $cgroup:ident, $original:ident, $population:ident) => {
        let $population = $cgroup.population_monitor()
            .map_err(|error| HostError::Worker(error.to_string()))?;
    };
    (Retained, $cgroup:ident, $original:ident, $population:ident) => {
        $original.monitor.capture_once_v3($cgroup)
            .map_err(|_| closed("Stop population monitor failed; original retained"))?;
        $original.completed_monitor = Some($original.monitor.take_completed_once_v3()
            .ok_or_else(|| closed("Stop population monitor is incomplete"))?);
    };
}

// The metavariable names keep the ordinary owning locals in the caller's
// lexical scope, preserving their old drop order on each subsequent refusal.
macro_rules! stop_prepare_recipe {
    ($mode:ident, $input:ident, $observation:ident, $original:ident, $population:ident) => {{
        let expected_path = $observation.cgroup.clone()
            .ok_or_else(|| HostError::Worker("exact stop target has no realized cgroup".to_owned()))?;
        let root = stop_root!($mode, $input, $original);
        let cgroup = stop_child!($mode, root, expected_path, $original);
        stop_monitor!($mode, cgroup, $original, $population);
        stop_prepare_finish!($mode, $original, $observation, cgroup, expected_path, $population)
    }};
}

macro_rules! stop_prepare_finish {
    (Local, $original:ident, $observation:ident, $cgroup:ident, $path:ident, $population:ident) => {{
        let leader = $observation.main_pid.map(|pid| pin_stop_leader(&$cgroup, pid)).transpose()?;
        Ok(PreparedStopQuiescence { leader, population: $population, expected_path: $path })
    }};
    (Retained, $original:ident, $observation:ident, $cgroup:ident, $path:ident, $population:ident) => {{
        if let Some(pid) = $observation.main_pid {
            $original.leader.capture_once_v3($cgroup, pid)?;
        }
        $original.expected_path = Some($path);
        Ok(())
    }};
}

macro_rules! stop_alive {
    (Local, $original:ident, $leader:ident) => {
        $leader.is_alive().map_err(|error| HostError::Worker(error.to_string()))?
    };
    (Retained, $original:ident, $leader:ident) => {{
        $original.alive = Some($leader.is_alive());
        match $original.alive.as_ref() {
            Some(Ok(alive)) => *alive,
            _ => return Err(closed("Stop leader liveness failed; original retained")),
        }
    }};
}

macro_rules! stop_population {
    (Local, $original:ident, $population:expr) => {
        $population.state().map_err(|error| HostError::Worker(error.to_string()))?
    };
    (Retained, $original:ident, $population:expr) => {{
        $population.observe_state_retaining_v1(&mut $original.population)
            .map_err(|_| closed("Stop population read failed; original retained"))?;
        $original.population.state().ok_or_else(|| closed("Stop population read is incomplete"))?
    }};
}

macro_rules! stop_absence {
    (Local, $root:ident, $path:expr, $original:ident) => {
        verify_retired_cgroup_absence($root, $path)?;
    };
    (Retained, $root:ident, $path:expr, $original:ident) => {
        verify_absent_cgroup_original_v3($root, $path, Some(&mut $original.absence),
            "retired exact cgroup path names a replacement object")?;
    };
}

macro_rules! stop_confirm_recipe {
    ($mode:ident, $root:ident, $observation:ident, $path:expr, $leader:expr,
        $population:expr, $original:ident) => {{
        if !$observation.is_intermediate_terminal() || $observation.cgroup.as_ref() != Some($path) {
            return Ok(false);
        }
        if let Some(leader) = $leader && stop_alive!($mode, $original, leader) {
            return Ok(false);
        }
        match stop_population!($mode, $original, $population) {
            CgroupPopulationState::Empty => Ok(true),
            CgroupPopulationState::Populated => Ok(false),
            CgroupPopulationState::Retired => {
                stop_absence!($mode, $root, $path, $original);
                Ok(true)
            }
        }
    }};
}

pub(super) fn prepare_local(
    cgroup_root: &BeneathRoot, observation: &ExactUnitObservation,
) -> Result<PreparedStopQuiescence> {
    stop_prepare_recipe!(Local, cgroup_root, observation, unused, population)
}

pub(super) fn confirm_local(
    cgroup_root: &BeneathRoot, observation: &ExactUnitObservation, proof: PreparedStopQuiescence,
) -> Result<bool> {
    stop_confirm_recipe!(Local, cgroup_root, observation, &proof.expected_path,
        proof.leader, proof.population, unused)
}

struct StopLeaderOriginalV3 {
    opening: PidFdOpenAttemptV1,
    process: Option<PidFd>,
    membership: RuntimeScopeMembershipOriginalV1,
    primary: Option<Result<()>>,
}

impl StopLeaderOriginalV3 {
    fn new() -> Self {
        Self { opening: PidFdOpenAttemptV1::new(), process: None,
            membership: RuntimeScopeMembershipOriginalV1::new(), primary: None }
    }

    fn capture_once_v3(&mut self, cgroup: &RetainedCgroupAnchor, pid: NonZeroU32) -> Result<()> {
        self.primary = Some((|| {
            self.opening.capture_once(pid).map_err(|_| closed("Stop pidfd opening failed; original retained"))?;
            self.process = Some(self.opening.take_validated().ok_or_else(|| closed("Stop pidfd is incomplete"))?);
            let process = self.process.as_ref().ok_or_else(|| closed("Stop pidfd is absent"))?;
            self.membership.capture_once(cgroup, process, None)
                .map_err(|_| closed("Stop exact membership failed; original retained"))?;
            let identity = self.membership.completed_info().ok_or_else(|| closed("Stop membership is incomplete"))?;
            require_stop_leader_identity_v3(identity, pid)
        })());
        if matches!(self.primary, Some(Ok(()))) { Ok(()) } else {
            Err(closed("Stop leader failed; original retained"))
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.opening.failure().map(|cause| cause as _)
            .or_else(|| self.membership.failure().map(|cause| cause as _))
            .or_else(|| error(&self.primary))
    }
}

// Every reached collector stays on its actual SDK row until a whole local
// native/SDK proof permits dropping its temporary leaves. Failed jobs and
// ambiguous prepared outcomes keep that same row occupied.
pub(in crate::worker) struct StopQuiescenceOriginalV3 {
    duplicate: Option<std::io::Result<OwnedFd>>,
    root: CgroupRootOriginalV2,
    completed_root: Option<CgroupV2Root>,
    child: CgroupChildOriginalV2,
    completed_child: Option<RetainedCgroupAnchor>,
    monitor: CgroupPopulationMonitorOriginalV3,
    completed_monitor: Option<CgroupPopulationMonitor>,
    leader: StopLeaderOriginalV3,
    expected_path: Option<SandboxCgroupPath>,
    alive: Option<Native<bool>>,
    population: CgroupPopulationObservationV1,
    absence: super::super::launch::ExactCgroupAbsenceOriginalV2,
    prepare: Option<Result<()>>,
    confirm: Option<Result<bool>>,
    refusal: Option<HostError>,
    owned_inventory: Option<Result<()>>,
    owned_terminal_population: Option<CgroupPopulationObservationV1>,
    cleanup_alive: Option<Native<bool>>,
    cleanup_population: Option<Result<bool>>,
    cleanup_confirm: Option<Result<bool>>,
    cleanup_absence: Option<super::super::launch::ExactCgroupAbsenceOriginalV2>,
}

impl StopQuiescenceOriginalV3 {
    pub(in crate::worker) fn new() -> Self {
        Self {
            duplicate: None, root: CgroupRootOriginalV2::new(), completed_root: None,
            child: CgroupChildOriginalV2::new(), completed_child: None,
            monitor: CgroupPopulationMonitorOriginalV3::new(), completed_monitor: None,
            leader: StopLeaderOriginalV3::new(), expected_path: None, alive: None,
            population: CgroupPopulationObservationV1::new(),
            absence: super::super::launch::ExactCgroupAbsenceOriginalV2::new(),
            prepare: None, confirm: None, refusal: None, owned_inventory: None,
            owned_terminal_population: None,
            cleanup_alive: None, cleanup_population: None, cleanup_confirm: None, cleanup_absence: None,
        }
    }

    pub(in crate::worker) fn prepare_once_v3(
        &mut self, root: &BeneathRoot, observation: &ExactUnitObservation,
    ) -> Result<()> {
        if self.prepare.is_some() || self.owned_inventory.is_some() {
            self.refusal.get_or_insert_with(|| closed("Stop preparation cannot reenter"));
            return Err(closed("Stop preparation cannot reenter"));
        }
        self.prepare = Some((|| { stop_prepare_recipe!(Retained, root, observation, self, unused) })());
        if matches!(self.prepare, Some(Ok(()))) { Ok(()) } else {
            Err(closed("Stop preparation failed; original retained"))
        }
    }

    pub(in crate::worker) fn confirm_once_v3(
        &mut self, root: &BeneathRoot, observation: &ExactUnitObservation,
    ) -> Result<bool> {
        if self.refusal.is_some() || self.confirm.is_some() || self.owned_inventory.is_some()
            || !matches!(self.prepare, Some(Ok(()))) {
            self.refusal.get_or_insert_with(|| closed("Stop confirmation lacks its original preparation"));
            return Err(closed("Stop confirmation lacks its original preparation"));
        }
        self.confirm = Some((|| {
            let path = self.expected_path.as_ref().ok_or_else(|| closed("Stop path is absent"))?;
            let leader = self.leader.process.as_ref();
            let population = self.completed_monitor.as_ref().ok_or_else(|| closed("Stop monitor is absent"))?;
            stop_confirm_recipe!(Retained, root, observation, path, leader, population, self)
        })());
        match self.confirm.as_ref() {
            Some(Ok(result)) => Ok(*result),
            _ => Err(closed("Stop confirmation failed; original retained")),
        }
    }

    pub(in crate::worker) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        error(&self.duplicate).or_else(|| self.root.failure().map(|cause| cause as _))
            .or_else(|| self.child.failure().map(|cause| cause as _))
            .or_else(|| self.monitor.failure())
            .or_else(|| self.leader.failure())
            .or_else(|| error(&self.prepare))
            .or_else(|| error(&self.alive))
            .or_else(|| self.population.failure())
            .or_else(|| self.absence.failure())
            .or_else(|| error(&self.confirm))
            .or_else(|| error(&self.owned_inventory))
            .or_else(|| self.refusal.as_ref().map(|cause| cause as _))
            .or_else(|| error(&self.cleanup_alive))
            .or_else(|| if matches!(self.cleanup_alive, Some(Ok(true))) {
                error(&self.cleanup_confirm)
            } else { None })
            .or_else(|| self.owned_terminal_population.as_ref().and_then(CgroupPopulationObservationV1::failure))
            .or_else(|| self.cleanup_absence.as_ref().and_then(|original|original.failure()))
            .or_else(|| error(&self.cleanup_population))
            .or_else(|| error(&self.cleanup_confirm))
    }

    pub(in crate::worker) fn capture_owned_inventory_once_v8(
        &mut self, root: &BeneathRoot, observation: &ExactUnitObservation,
    ) -> Result<()> {
        if self.owned_inventory.is_some() || self.prepare.is_some() || self.confirm.is_some() {
            self.refusal.get_or_insert_with(|| closed("Host owned role probe cannot reenter"));
            return Err(closed("Host owned role probe cannot reenter"));
        }
        self.owned_inventory = Some((|| {
            if observation.state != aos_systemd_client::ExactUnitState::ActiveRunning
                || observation.main_pid.is_none()
                || observation.binding.is_none()
                || observation.invocation_id.is_none()
            {
                return Err(closed("Host owned role is not a current bound live manager target"));
            }
            // This is the same readonly preparation used before exact Stop:
            // fresh root/child, real PIDFD and exact membership/liveness.
            self.prepare_once_v3(root, observation)?;
            let monitor = self.completed_monitor.as_ref()
                .ok_or_else(|| closed("Host owned role population monitor is absent"))?;
            monitor.observe_state_retaining_v1(&mut self.population)
                .map_err(|_| closed("Host owned role population read failed; original retained"))?;
            if self.population.state() != Some(CgroupPopulationState::Populated)
                || self.leader.membership.completed_info().is_none()
                || self.leader.process.is_none()
            {
                return Err(closed("Host owned role lacks current live exact cgroup membership"));
            }
            Ok(())
        })());
        if matches!(self.owned_inventory, Some(Ok(()))) {
            Ok(())
        } else {
            Err(closed("Host owned role native probe failed; original retained"))
        }
    }

    pub(in crate::worker) fn owned_inventory_anchor_v8(&self) -> Option<&RetainedCgroupAnchor> {
        if !matches!(self.owned_inventory, Some(Ok(()))) || self.failure().is_some() {
            return None;
        }
        self.completed_child.as_ref()
    }

    pub(in crate::worker) fn cleanup_post_receiving_demand_v1()
    -> Option<aos_sandbox_model::ResourceVector> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        ResourceVector::ZERO
            .with(
                D::MemoryBytes,
                u64::try_from(CgroupPopulationObservationV1::requested_bytes_v1()?).ok()?,
            )
            .checked_add(super::super::launch::ExactCgroupAbsenceOriginalV2::receiving_demand_v2()?)
            .ok()
    }

    pub(in crate::worker) fn confirm_owned_cleanup_absence_once_v1(
        &mut self,
        root: &BeneathRoot,
    ) -> Result<()> {
        if self.owned_inventory.is_none() {
            self.refusal.get_or_insert_with(|| {
                closed("cleanup death check lacks its same live ownership probe")
            });
            return Err(closed(
                "cleanup death check lacks its same live ownership probe",
            ));
        }
        self.confirm_cleanup_native_absence_once_v1(root)
    }

    pub(in crate::worker) fn confirm_prepared_cleanup_absence_once_v1(
        &mut self,
        root: &BeneathRoot,
    ) -> Result<()> {
        // Missing/foreign/residual SDK paths can finish before preparing any
        // native owner. Such an untouched destination has no synthetic PIDFD.
        if self.owned_inventory.is_none()
            && self.prepare.is_none()
            && self.confirm.is_none()
            && self.expected_path.is_none()
            && self.completed_root.is_none()
            && self.failure().is_none()
        {
            return Ok(());
        }
        if self.owned_inventory.is_some() {
            self.refusal
                .get_or_insert_with(|| closed("SDK cleanup cannot adopt an inventory probe"));
            return Err(closed("SDK cleanup cannot adopt an inventory probe"));
        }
        self.confirm_cleanup_native_absence_once_v1(root)
    }

    fn confirm_cleanup_native_absence_once_v1(&mut self, root: &BeneathRoot) -> Result<()> {
        if self.cleanup_confirm.is_some() {
            if matches!(self.cleanup_confirm, Some(Ok(true))) {
                self.refusal
                    .get_or_insert_with(|| closed("cleanup native post cannot reenter"));
            }
            return Err(closed("cleanup native post cannot reenter"));
        }
        if !matches!(self.prepare, Some(Ok(()))) && !self.has_cleanup_native_owner_v1() {
            self.refusal.get_or_insert_with(|| {
                closed("cleanup death check lacks its same prepared native owner")
            });
            return Err(closed(
                "cleanup death check lacks its same prepared native owner",
            ));
        }
        self.owned_terminal_population = Some(CgroupPopulationObservationV1::new());
        self.cleanup_confirm = Some((|| {
            let leader_dead = if let Some(leader) = self.leader.process.as_ref() {
                self.cleanup_alive = Some(leader.is_alive());
                matches!(self.cleanup_alive, Some(Ok(false)))
            } else {
                true
            };
            // This held monitor has its own prepaid post. A live or failed
            // PIDFD observation cannot suppress its native population read.
            self.cleanup_population = Some((|| {
                let monitor = self
                    .completed_monitor
                    .as_ref()
                    .ok_or_else(|| closed("cleanup original population monitor is absent"))?;
                let observation = self
                    .owned_terminal_population
                    .as_mut()
                    .ok_or_else(|| closed("cleanup population destination is absent"))?;
                monitor
                    .observe_state_retaining_v1(observation)
                    .map_err(|_| {
                        closed("cleanup original population read failed; native result retained")
                    })?;
                match observation.state() {
                    Some(CgroupPopulationState::Empty) => Ok(true),
                    Some(CgroupPopulationState::Retired) => {
                        let path = self
                            .expected_path
                            .as_ref()
                            .ok_or_else(|| closed("cleanup original cgroup path is absent"))?;
                        self.cleanup_absence =
                            Some(super::super::launch::ExactCgroupAbsenceOriginalV2::new());
                        verify_absent_cgroup_original_v3(
                            root,
                            path,
                            self.cleanup_absence.as_mut(),
                            "cleanup retired cgroup path names a replacement object",
                        )?;
                        Ok(true)
                    }
                    _ => Err(closed(
                        "cleanup original cgroup still has tasks or an unknown population",
                    )),
                }
            })());
            if !leader_dead {
                return Err(closed("cleanup original PIDFD is not observed dead"));
            }
            // Partial preparation may owe actual native observations but can
            // never become a completed ownership or positive disposal proof.
            if !matches!(self.prepare, Some(Ok(()))) {
                return Err(closed("cleanup native preparation remains incomplete"));
            }
            if matches!(self.cleanup_population, Some(Ok(true))) {
                Ok(true)
            } else {
                Err(closed(
                    "cleanup original population post refused; native result retained",
                ))
            }
        })());
        if matches!(self.cleanup_confirm, Some(Ok(true))) {
            Ok(())
        } else {
            Err(closed(
                "cleanup original death/population proof refused; all native results retained",
            ))
        }
    }

    pub(in crate::worker) fn require_cleanup_native_posts_v1(&self) -> Result<()> {
        let untouched = self.prepare.is_none()
            && self.confirm.is_none()
            && self.expected_path.is_none()
            && self.completed_root.is_none();
        if self.owned_inventory.is_some()
            || self.failure().is_some()
            || (!untouched && !matches!(self.cleanup_confirm, Some(Ok(true))))
        {
            return Err(closed(
                "cleanup native post has not completed on this SDK owner",
            ));
        }
        Ok(())
    }

    pub(in crate::worker) fn has_cleanup_native_owner_v1(&self) -> bool {
        self.leader.process.is_some() || self.completed_monitor.is_some()
    }

    pub(in crate::worker) fn receiving_demand_v3() -> Option<aos_sandbox_model::ResourceVector> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        let name = SandboxUnitName::from_incarnation([0; 16]);
        let path_bytes = name.guardian_cgroup_path().as_str().len().max(name.cgroup_path().as_str().len());
        let mut bound = (std::mem::size_of::<std::sync::Mutex<Self>>().checked_mul(2)?
            .checked_add(2 * std::mem::size_of::<std::sync::Arc<std::sync::Mutex<Self>>>())?
            .checked_add(2 * std::mem::size_of::<std::sync::MutexGuard<'static, Self>>())?
            .checked_add(2 * std::mem::size_of::<usize>())?
            .checked_add(2 * path_bytes)?
            .checked_add(2 * std::mem::size_of::<StopQuiescenceCompletedV4>())?
            .checked_add(2 * std::mem::size_of::<StopQuiescenceDisposedV4>())?
            .checked_add(2 * std::mem::size_of::<PidFdOpenAttemptV1>())?
            .checked_add(CgroupPopulationObservationV1::requested_bytes_v1()?)?, 1usize, 0usize);
        for next in [
            CgroupRootOriginalV2::receiving_obligations_v2()?,
            CgroupChildOriginalV2::receiving_obligations_v2(path_bytes)?,
            CgroupPopulationMonitorOriginalV3::receiving_obligations_v3()?,
            RuntimeScopeMembershipOriginalV1::exact_receiving_demand_v1()?,
        ] {
            bound = (bound.0.checked_add(next.0)?, bound.1.checked_add(next.1)?, bound.2.checked_add(next.2)?);
        }
        ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bound.0).ok()?)
            .with(D::OpenFiles, u64::try_from(bound.1).ok()?)
            .with(D::MetadataEntries, u64::try_from(bound.2).ok()?)
            .checked_add(super::super::launch::ExactCgroupAbsenceOriginalV2::receiving_demand_v2()?).ok()
    }
}

pub(super) fn require_stop_leader_identity_v3(identity: aos_sandbox_linux::pidfd::PidFdInfo, pid: NonZeroU32) -> Result<()> {
    if identity.pid() != pid.get() || identity.thread_group_id() != pid.get() {
        return Err(HostError::Worker("exact stop MainPID is not its pinned process leader".to_owned()));
    }
    Ok(())
}

fn error<T, E: std::error::Error + 'static>(slot: &Option<std::result::Result<T, E>>)
    -> Option<&(dyn std::error::Error + 'static)>
{
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

fn closed(message: &'static str) -> HostError { HostError::Fence(message) }

// These private same-original proofs concern temporary native disposition,
// never target absence, execution authority or financial capacity.
pub(in crate::worker) struct StopQuiescenceCompletedV4 {
    origin: std::sync::Weak<std::sync::Mutex<StopQuiescenceOriginalV3>>,
    row: usize,
}

pub(in crate::worker) struct StopQuiescenceDisposedV4 {
    origin: std::sync::Weak<std::sync::Mutex<StopQuiescenceOriginalV3>>,
    row: usize,
}

impl StopQuiescenceOriginalV3 {
    fn completed_temporary_v4(&self, outcome: &aos_systemd_client::ExactStopOutcome) -> bool {
        if self.failure().is_some() {
            return false;
        }
        match outcome {
            aos_systemd_client::ExactStopOutcome::AwaitingAbsence(observation) => {
                matches!(self.prepare, Some(Ok(())))
                    && matches!(self.confirm, Some(Ok(true)))
                    && self.expected_path.as_ref() == observation.cgroup.as_ref()
            }
            aos_systemd_client::ExactStopOutcome::MissingManagerObject
            | aos_systemd_client::ExactStopOutcome::Foreign(_)
            | aos_systemd_client::ExactStopOutcome::Residual(_) => {
                // These SDK branches may return before the first native
                // preparation. Only the actually untouched collector retires.
                self.prepare.is_none() && self.confirm.is_none()
                    && self.expected_path.is_none() && self.completed_root.is_none()
            }
            aos_systemd_client::ExactStopOutcome::JobFailed(_) => false,
        }
    }

    pub(in crate::worker) fn prepare_temporary_disposal_v4(
        original: &std::sync::Arc<std::sync::Mutex<Self>>,
        row: usize,
        outcome: &aos_systemd_client::ExactStopOutcome,
    ) -> Result<Option<StopQuiescenceCompletedV4>> {
        if std::sync::Arc::strong_count(original) != 1 {
            return Err(closed("Stop native collector still has an actual borrower"));
        }
        let guard = original.try_lock()
            .map_err(|_| closed("Stop native collector is still borrowed or poisoned"))?;
        if !guard.completed_temporary_v4(outcome) {
            return Ok(None);
        }
        Ok(Some(StopQuiescenceCompletedV4 {
            origin: std::sync::Arc::downgrade(original),
            row,
        }))
    }
}

impl StopQuiescenceCompletedV4 {
    pub(in crate::worker) fn dispose_from_row_v4(
        self,
        slot: &mut Option<std::sync::Arc<std::sync::Mutex<StopQuiescenceOriginalV3>>>,
    ) -> Result<StopQuiescenceDisposedV4> {
        let original = slot.as_ref().ok_or_else(|| closed("Stop native collector disappeared"))?;
        if std::sync::Arc::as_ptr(original) != self.origin.as_ptr()
            || std::sync::Arc::strong_count(original) != 1
        {
            return Err(closed("Stop native disposal differs from its exact completed original"));
        }
        // Every fallible SDK/native/local association check preceded this
        // owning move. The row is exclusively borrowed and retains the proof.
        drop(slot.take());
        Ok(StopQuiescenceDisposedV4 { origin: self.origin, row: self.row })
    }
}

impl StopQuiescenceDisposedV4 {
    pub(in crate::worker) fn belongs_to_row_v4(&self, row: usize) -> bool {
        self.row == row && self.origin.upgrade().is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_references(path: &Path) -> usize {
        std::fs::read_dir("/proc/self/fd").unwrap().filter_map(|entry| {
            std::fs::read_link(entry.unwrap().path()).ok()
        }).filter(|observed| observed == path).count()
    }

    #[test]
    fn rejected_stop_root_keeps_actual_duplicate_and_first_native_cause() {
        let directory = tempfile::tempdir().unwrap();
        let input = BeneathRoot::from_owned(std::fs::File::open(directory.path()).unwrap().into()).unwrap();
        let observation = ExactUnitObservation {
            role: ExactUnitRole::Payload,
            object_path: "/org/freedesktop/systemd1/unit/test".try_into().unwrap(),
            binding: Some([11; 32]),
            invocation_id: Some([13; 16]),
            active_state: "active".to_owned(),
            sub_state: "running".to_owned(),
            state: ExactUnitState::ActiveRunning,
            cgroup: Some(SandboxUnitName::from_incarnation([17; 16]).cgroup_path()),
            main_pid: NonZeroU32::new(std::process::id()),
        };
        let mut original = StopQuiescenceOriginalV3::new();
        assert_eq!(open_references(directory.path()), 1);

        assert!(original.prepare_once_v3(&input, &observation).is_err());

        assert_eq!(open_references(directory.path()), 2);
        let cause = original.failure().unwrap().downcast_ref::<aos_sandbox_linux::Error>().unwrap() as *const _;
        assert!(original.completed_root.is_none());
        assert!(original.completed_monitor.is_none());
        assert!(!original.completed_temporary_v4(&aos_systemd_client::ExactStopOutcome::MissingManagerObject));
        assert!(original.confirm_once_v3(&input, &observation).is_err());
        assert!(original.prepare_once_v3(&input, &observation).is_err());
        assert_eq!(open_references(directory.path()), 2);
        assert_eq!(original.failure().unwrap().downcast_ref::<aos_sandbox_linux::Error>().unwrap() as *const _, cause);
    }

    #[test]
    fn failed_fresh_owned_probe_cannot_supply_an_anchor_or_ordinary_stop_completion() {
        let directory = tempfile::tempdir().unwrap();
        let root = BeneathRoot::from_owned(std::fs::File::open(directory.path()).unwrap().into()).unwrap();
        let name = SandboxUnitName::from_incarnation([17; 16]);
        let observation = ExactUnitObservation {
            role: ExactUnitRole::Payload,
            object_path: "/org/freedesktop/systemd1/unit/test".try_into().unwrap(),
            binding: Some([11; 32]), invocation_id: Some([13; 16]),
            active_state: "active".to_owned(), sub_state: "running".to_owned(),
            state: aos_systemd_client::ExactUnitState::ActiveRunning,
            cgroup: Some(name.cgroup_path()),
            main_pid: NonZeroU32::new(std::process::id()),
        };
        let mut original = StopQuiescenceOriginalV3::new();

        assert!(original.capture_owned_inventory_once_v8(&root, &observation).is_err());
        let cause = original.failure().unwrap() as *const dyn std::error::Error as *const ();
        assert!(original.owned_inventory_anchor_v8().is_none());
        assert!(!original.completed_temporary_v4(&aos_systemd_client::ExactStopOutcome::MissingManagerObject));
        assert!(original.confirm_once_v3(&root, &observation).is_err());
        assert!(original.capture_owned_inventory_once_v8(&root, &observation).is_err());
        assert_eq!(original.failure().unwrap() as *const dyn std::error::Error as *const (), cause);
        assert!(original.owned_inventory_anchor_v8().is_none());
        assert!(original.confirm_owned_cleanup_absence_once_v1(&root).is_err());
        assert_eq!(original.failure().unwrap() as *const dyn std::error::Error as *const (), cause);
        assert!(original.owned_terminal_population.is_none());
        assert!(original.confirm_prepared_cleanup_absence_once_v1(&root).is_err());
        assert_eq!(original.failure().unwrap() as *const dyn std::error::Error as *const (), cause);
        assert!(original.cleanup_alive.is_none());
        assert!(original.cleanup_population.is_none());
    }

    #[test]
    fn live_held_pidfd_still_attempts_its_independent_monitor_post_and_keeps_first_cause() {
        let directory = tempfile::tempdir().unwrap();
        let root =
            BeneathRoot::from_owned(std::fs::File::open(directory.path()).unwrap().into()).unwrap();
        let mut original = StopQuiescenceOriginalV3::new();
        original.prepare = Some(Ok(()));
        original.leader.process =
            Some(PidFd::open(NonZeroU32::new(std::process::id()).unwrap()).unwrap());

        // The deliberately missing monitor refuses independently after the
        // actual live PIDFD poll. Neither failure can produce a native proof.
        assert!(
            original
                .confirm_prepared_cleanup_absence_once_v1(&root)
                .is_err()
        );

        assert!(matches!(original.cleanup_alive, Some(Ok(true))));
        assert!(matches!(original.cleanup_population, Some(Err(_))));
        assert!(original.leader.process.is_some());
        assert!(original.alive.is_none());
        assert!(original.confirm.is_none());
        let cause = original.failure().unwrap() as *const dyn std::error::Error as *const ();
        assert!(matches!(
            original.failure().unwrap().downcast_ref::<HostError>(),
            Some(HostError::Fence(
                "cleanup original PIDFD is not observed dead"
            ))
        ));
        assert!(
            original
                .confirm_prepared_cleanup_absence_once_v1(&root)
                .is_err()
        );
        assert_eq!(
            original.failure().unwrap() as *const dyn std::error::Error as *const (),
            cause
        );
        assert!(matches!(original.cleanup_alive, Some(Ok(true))));
        assert!(matches!(original.cleanup_population, Some(Err(_))));
    }

    #[test]
    fn earlier_sdk_native_refusal_keeps_its_cause_while_independent_posts_are_attempted() {
        let directory = tempfile::tempdir().unwrap();
        let root =
            BeneathRoot::from_owned(std::fs::File::open(directory.path()).unwrap().into()).unwrap();
        let mut original = StopQuiescenceOriginalV3::new();
        original.prepare = Some(Ok(()));
        original.confirm = Some(Err(closed("earlier SDK native refusal")));
        original.leader.process =
            Some(PidFd::open(NonZeroU32::new(std::process::id()).unwrap()).unwrap());
        let cause = original.failure().unwrap() as *const dyn std::error::Error as *const ();

        assert!(
            original
                .confirm_prepared_cleanup_absence_once_v1(&root)
                .is_err()
        );

        assert!(matches!(original.cleanup_alive, Some(Ok(true))));
        assert!(matches!(original.cleanup_population, Some(Err(_))));
        assert_eq!(
            original.failure().unwrap() as *const dyn std::error::Error as *const (),
            cause
        );
        assert!(original.leader.process.is_some());
        assert!(original.alive.is_none());
    }

    #[test]
    fn partial_preparation_observes_its_actual_pidfd_but_never_completes_native_posts() {
        let directory = tempfile::tempdir().unwrap();
        let root =
            BeneathRoot::from_owned(std::fs::File::open(directory.path()).unwrap().into()).unwrap();
        let mut original = StopQuiescenceOriginalV3::new();
        original.prepare = Some(Err(closed("partial preparation refused membership")));
        original.leader.process =
            Some(PidFd::open(NonZeroU32::new(std::process::id()).unwrap()).unwrap());
        let cause = original.failure().unwrap() as *const dyn std::error::Error as *const ();

        assert!(
            original
                .confirm_prepared_cleanup_absence_once_v1(&root)
                .is_err()
        );

        assert!(matches!(original.cleanup_alive, Some(Ok(true))));
        assert!(matches!(original.cleanup_population, Some(Err(_))));
        assert_eq!(
            original.failure().unwrap() as *const dyn std::error::Error as *const (),
            cause
        );
        assert!(original.require_cleanup_native_posts_v1().is_err());
        assert!(original.leader.process.is_some());
    }
}
