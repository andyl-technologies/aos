//! Connects the existing paid Gate installation to its actual native SSH birth.
//!
//! Failed source/birth/receipt prefixes stay on main's existing installation
//! original. Only the standing scope moves to the existing timeout actor;
//! no mutex needed by that actor spans libc or receipt processing.

use super::*;
use crate::ledger::{Ledger, ProcessRecord};
use crate::GuestProcessEffectErrorV1;
use aos_sandbox_linux::guest_cgroup::{
    GuestPayloadCgroupCustodyV1, GuestRuntimeTopologyOriginalV1,
    GuestSshBirthSourceOriginalV1, GuestSshScopeOriginalV1, GuestSshStandingOriginalV1,
};
use aos_sandbox_linux::seqpacket::descriptor_subject::{
    GuestSshBootstrapOriginalV1, GuestSshListenerCustodyV1,
};

#[derive(Default)]
pub(crate) struct SelectedDaemonStartupOriginalV1 {
    source: GuestSshBirthSourceOriginalV1,
    birth: Option<GuestSshScopeOriginalV1>,
    bootstrap: GuestSshBootstrapOriginalV1,
    standing: Option<GuestSshStandingOriginalV1>,
    identity: aos_sandbox_linux::pidfd::PidFdProcessIdentityOriginalV1,
    body: Option<Result<(), GuestProcessEffectErrorV1>>,
    listeners: Option<GuestSshListenerCustodyV1>,
    monitor: Option<MonitorInstallationV2>,
    coordinates: Option<(u32, u64)>,
}

pub(super) struct SelectedListenerOriginalV1 {
    birth: GuestSshScopeOriginalV1,
    listeners: Option<GuestSshListenerCustodyV1>,
}

impl SelectedListenerOriginalV1 {
    pub(super) fn recheck(&mut self) -> Result<(), OpenSshGatePhysicalErrorV1> {
        self.listeners.as_mut().ok_or(OpenSshGatePhysicalErrorV1::DaemonUnavailable)?
            .recheck_once_v1(&self.birth)
            .map_err(|_| OpenSshGatePhysicalErrorV1::DaemonUnavailable)
    }
}

pub(crate) struct SelectedRunningOpenSshGateV1 {
    original: Arc<std::sync::Mutex<SelectedListenerOriginalV1>>,
    installation: MonitorInstallationV2,
    binding: OpenSshGateBindingV1,
    coordinates: (u32, u64),
    retired: bool,
}

impl SelectedDaemonStartupOriginalV1 {
    pub(crate) fn start_once(
        &mut self,
        binding: OpenSshGateBindingV1,
        process: &ProcessRecord,
        ledger: &Ledger,
        topology: &GuestRuntimeTopologyOriginalV1,
        payload: &GuestPayloadCgroupCustodyV1,
        execution_root: &aos_sandbox_linux::cgroup::RetainedCgroupAnchor,
        startup_cutoff: u64,
        read: &mut OpenSshDaemonStartupOriginalV1,
        current: &mut dyn FnMut() -> Result<(), GuestProcessEffectErrorV1>,
    ) -> Result<SelectedRunningOpenSshGateV1, GuestProcessEffectErrorV1> {
        if self.body.is_some() {
            return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
        }
        self.body = Some(self.start_inner(&binding, process, ledger, topology, payload,
            execution_root, startup_cutoff, read, current));
        if !matches!(self.body, Some(Ok(()))) {
            self.bootstrap.fence_failed_owner_once_v1();
            ledger.request_ssh_retirement_v1(process.execution);
            return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
        }
        let birth = self.birth.take().ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
        let listeners = self.listeners.take().ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
        let original = Arc::new(std::sync::Mutex::new(SelectedListenerOriginalV1 {
            birth, listeners: Some(listeners),
        }));
        let mut installation = self.monitor.take().ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
        installation.selected = Some(Arc::clone(&original));
        Ok(SelectedRunningOpenSshGateV1 {
            original, installation, binding,
            coordinates: self.coordinates.ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?,
            retired: false,
        })
    }

    fn start_inner(
        &mut self,
        binding: &OpenSshGateBindingV1,
        process: &ProcessRecord,
        ledger: &Ledger,
        topology: &GuestRuntimeTopologyOriginalV1,
        payload: &GuestPayloadCgroupCustodyV1,
        execution_root: &aos_sandbox_linux::cgroup::RetainedCgroupAnchor,
        startup_cutoff: u64,
        read: &mut OpenSshDaemonStartupOriginalV1,
        current: &mut dyn FnMut() -> Result<(), GuestProcessEffectErrorV1>,
    ) -> Result<(), GuestProcessEffectErrorV1> {
        current()?;
        let installed = check_installed_files_with(binding, &mut |path, maximum, executable| {
            read.read_fixed(path, maximum, executable)
        })?;
        let executable = read.read_fixed(&canonicalize_physical_path(SSHD_PATH)?, MAXIMUM_EXECUTABLE_BYTES, true)?;
        let session = read.read_fixed(&canonicalize_physical_path(SSHD_SESSION_PATH)?, MAXIMUM_EXECUTABLE_BYTES, true)?;
        if read.read.as_ref().is_some_and(|original| !original.completed_v3()) {
            return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
        }
        // Only the complete same-FD/name/hash/EOF read phase retires here.
        // Its file cannot silently coexist with the later clone source plane.
        drop(read.read.take());
        current()?;
        let (plan, future_files) = ledger.ssh_birth_inputs_v1(process)?;
        let execution_cutoff = process.lifetime.as_ref()
            .ok_or(GuestProcessEffectErrorV1::InvalidRequest)?.deadline_boottime_nanoseconds;
        let startup_cutoff = startup_cutoff.min(execution_cutoff);
        topology.capture_ssh_birth_source_once_v1(payload, execution_root, &mut self.source,
            plan.source_copied_files_data_v1(), plan.source_highest_fd_data_v1(), future_files)?;
        current()?;
        self.birth = Some(GuestSshScopeOriginalV1::new());
        let birth = self.birth.as_mut().ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
        birth.prepare_once_v1(&self.source, execution_root, process.execution,
            plan.memory_bytes_data_v1(), plan.per_process_nofile_data_v1(),
            startup_cutoff, execution_cutoff, binding.expires_at)?;
        self.bootstrap.prepare_once_v1(birth, &plan.encode_data_v1(), binding.port)?;
        self.standing = Some(birth.take_standing_once_v1()?);

        // This is the actual original Process slot, before libc. Both gates
        // drop their live-map guard on return; the native call borrows only
        // main's birth and the private bootstrap endpoint created above.
        ledger.park_ssh_standing_once_v1(process, &mut self.standing)?;
        current()?;
        self.bootstrap.spawn_once_v1(birth)?;
        loop {
            current()?;
            if self.bootstrap.advance_once_v1(birth)? { break; }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        ledger.complete_ssh_startup_once_v1(process, &self.bootstrap)?;
        self.listeners = Some(self.bootstrap.take_listener_custody_once_v1(birth)?);
        current()?;
        self.identity.capture_once(birth.child_pidfd_v1()?)
            .map_err(|_| GuestProcessEffectErrorV1::AmbiguousEffect)?;
        let identity = self.identity.identity().ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
        if Some(identity.pid()) != birth.child_id_data_v1() {
            return Err(GuestProcessEffectErrorV1::InvalidRequest);
        }
        self.coordinates = Some((identity.pid(), identity.start_time_ticks()));
        drop(std::mem::take(&mut self.identity));
        self.monitor = Some(MonitorInstallationV2 {
            listener: birth.share_child_pidfd_v1()?,
            configuration_device: installed.configuration.device,
            configuration_inode: installed.configuration.inode,
            session_executable: MeasuredExecutable::opened(&session),
            listener_executable: MeasuredExecutable::opened(&executable),
            gate_executable: MeasuredExecutable::opened(&installed.gate_executable),
            selected: None,
        });
        current()?;
        Ok(())
    }

    pub(crate) fn poll_retirement(&mut self, ledger: &Ledger, execution: [u8; 16])
        -> Result<bool, GuestProcessEffectErrorV1>
    {
        ledger.request_ssh_retirement_v1(execution);
        match self.birth.as_mut() {
            Some(birth) => ledger.poll_ssh_retirement_v1(execution, birth),
            None => Ok(false),
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.failure()
            .or_else(|| self.birth.as_ref()?.failure())
            .or_else(|| self.bootstrap.failure())
            .or_else(|| self.standing.as_ref()?.failure())
            .or_else(|| self.listeners.as_ref()?.failure())
            .or_else(|| self.identity.failure().map(|cause| cause as _))
            .or_else(|| self.body.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

impl SelectedRunningOpenSshGateV1 {
    pub(crate) fn coordinates(&self) -> (u32, u64) { self.coordinates }

    pub(crate) fn require_selected_readback_ready_v1(&self) -> Result<(), OpenSshGatePhysicalErrorV1> {
        if self.retired { Err(OpenSshGatePhysicalErrorV1::DaemonUnavailable) } else { Ok(()) }
    }

    pub(crate) fn physical_readback(
        &mut self, claim: &OpenSshGateClaimV1, challenge: [u8; 32],
        route_digest: [u8; 32], channel_binding: [u8; 32],
    ) -> Result<OpenSshGateReadbackV1, OpenSshGatePhysicalErrorV1> {
        if claim.binding != self.binding || claim.route_digest != route_digest
            || (claim.sshd_pid, claim.sshd_start_ticks) != self.coordinates
        { return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation); }
        let runtime = self.monitor_runtime(claim)?;
        runtime.require_current()?;
        let host = read_protected_file(Path::new(HOST_KEY_PATH), 16 * 1024, false)?;
        if host.mode & 0o077 != 0 { return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation); }
        Ok(OpenSshGateReadbackV1 {
            challenge, route_digest, channel_binding, binding: self.binding.clone(),
            physical: OpenSshGatePhysicalStateV1 {
                sshd_pid: self.coordinates.0, sshd_start_ticks: self.coordinates.1,
                sshd_executable_digest: self.installation.listener_executable.digest,
                gate_executable_digest: self.installation.gate_executable.digest,
                host_private_key_digest: host.digest(),
            },
        })
    }

    pub(crate) fn monitor_runtime(&self, claim: &OpenSshGateClaimV1)
        -> Result<OpenSshMonitorRuntimeV2, OpenSshGatePhysicalErrorV1>
    {
        if claim.binding != self.binding || (claim.sshd_pid, claim.sshd_start_ticks) != self.coordinates {
            return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation);
        }
        Ok(OpenSshMonitorRuntimeV2 { installation: self.installation.clone(), claim: claim.clone() })
    }

    pub(crate) fn poll_retirement(&mut self, ledger: &Ledger)
        -> Result<bool, GuestProcessEffectErrorV1>
    {
        if self.retired { return Ok(true); }
        ledger.request_ssh_retirement_v1(self.binding.execution_id);
        // The daemon and its installation own the two local Arc references.
        // Every original monitor/runtime borrower must physically retire first.
        // Check this before taking either mutex: an existing monitor can use
        // the same native owner while holding its own execution observations.
        // Standing containment remains independently selected above.
        if Arc::strong_count(&self.original) != 2 || Arc::weak_count(&self.original) != 0
            || Arc::strong_count(&self.installation.listener) != 2
            || Arc::weak_count(&self.installation.listener) != 0
        { return Ok(false); }
        let mut original = self.original.lock().map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
        if !ledger.poll_ssh_retirement_v1(self.binding.execution_id, &mut original.birth)? {
            return Ok(false);
        }
        drop(original.listeners.take());
        self.retired = true;
        Ok(true)
    }
}
