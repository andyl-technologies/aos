//! Shares the shifted-payload native conjunction and its positive disposal.
//!
//! The actual payload/supervisor input pins outlive this local inspection.
//! Only a whole validated record and both genuine kernel bookends permit
//! disposal of these temporary Host/ns/map/stat originals. Failed prefixes
//! remain resident and cannot provide the next native window's proof.

use std::sync::Arc;

use aos_sandbox_linux::pidfd::{NamespaceFd, PidFdNamespaceOriginalV2, PidFdProcessIdentityOriginalV1};

use super::*;
use crate::worker::launch::HostLaunchWorkerReceivingV2;
use crate::worker::service_probe::ServiceNamespaceProbeOriginalV2;

type Native<T> = std::result::Result<T, aos_linux_descriptors::Error>;

macro_rules! shifted_kernel {
    (Local, $original:ident, $temporary:ident, $receiving:ident, $payload:ident, $supervisor:ident, $slot:expr) => {
        $payload.recheck_kernel($supervisor)?
    };
    (Retained, $original:ident, $temporary:ident, $receiving:ident, $payload:ident, $supervisor:ident, $slot:expr) => {{
        $original.kernel[$slot] = Some($receiving.recheck_payload_v2($payload, $supervisor).await);
        if !matches!($original.kernel[$slot], Some(Ok(()))) {
            return Err(closed("shifted kernel bookend failed; original remains resident"));
        }
    }};
}

macro_rules! shifted_identity {
    (Local, $original:ident, $temporary:ident, $payload:ident, $slot:expr) => {
        aos_sandbox_linux::pidfd::process_identity(&($payload.pidfd())).map_err(|error| HostError::Worker(error.to_string()))?
    };
    (Retained, $original:ident, $temporary:ident, $payload:ident, $slot:expr) => {{
        $temporary.identities[$slot].capture_once($payload.pidfd())
            .map_err(|_| closed("shifted process identity failed; original retained"))?;
        $temporary.identities[$slot].identity().ok_or_else(|| closed("shifted process identity is incomplete"))?
    }};
}

macro_rules! shifted_host {
    (Local, $original:ident, $temporary:ident) => { crate::worker::PidfdNamespaceAccessProbe::current_service()? };
    (Retained, $original:ident, $temporary:ident) => {{
        $temporary.host.capture_once()?;
        $temporary.host.completed().ok_or_else(|| closed("shifted host namespace probe is incomplete"))?
    }};
}

macro_rules! shifted_namespace {
    (Local, $original:ident, $temporary:ident, $payload:ident, $field:ident, $slot:expr, $kind:ident) => {
        aos_sandbox_linux::pidfd::namespace(&($payload.pidfd()), NamespaceKind::$kind).map_err(|error| HostError::Worker(error.to_string()))?
    };
    (Retained, $original:ident, $temporary:ident, $payload:ident, $field:ident, $slot:expr, $kind:ident) => {{
        $temporary.namespaces[$slot].capture_once($payload.pidfd(), NamespaceKind::$kind)
            .map_err(|_| closed("shifted namespace ioctl failed; original retained"))?;
        $temporary.$field = Some($temporary.namespaces[$slot].take_completed_once()
            .ok_or_else(|| closed("shifted namespace ioctl is incomplete"))?);
        $temporary.$field.as_ref().ok_or_else(|| closed("shifted namespace pin is absent"))?
    }};
}

macro_rules! shifted_map {
    (Local, $original:ident, $temporary:ident, $before:ident, $slot:expr, $kind:expr, $start:ident, $count:ident) => {
        read_exact_id_map($before.pid(), $kind, $start, $count)?
    };
    (Retained, $original:ident, $temporary:ident, $before:ident, $slot:expr, $kind:expr, $start:ident, $count:ident) => {{
        $temporary.map_results[$slot] = Some(read_exact_id_map_retaining_v2(
            $before.pid(), $kind, $start, $count, &mut $temporary.maps[$slot],
        ));
        if !matches!($temporary.map_results[$slot], Some(Ok(()))) {
            return Err(closed("shifted ID-map observation failed; original retained"));
        }
    }};
}

macro_rules! shifted_alive {
    (Local, $original:ident, $temporary:ident, $payload:ident) => {
        $payload.pidfd().is_alive().map_err(|error| HostError::Worker(error.to_string()))?
    };
    (Retained, $original:ident, $temporary:ident, $payload:ident) => {{
        $temporary.alive = Some($payload.pidfd().is_alive());
        match $temporary.alive.as_ref() {
            Some(Ok(alive)) => *alive,
            _ => return Err(closed("shifted liveness failed; native cause retained")),
        }
    }};
}

macro_rules! shifted_recipe {
    ($identity:expr, $spec:expr, $invocation:expr, $supervisor:expr, $payload:expr, $proof:expr,
        $mode:ident, $original:ident, $temporary:ident, $receiving:ident) => {{
        let identity = $identity;
        let spec = $spec;
        let invocation_id = $invocation;
        let supervisor = $supervisor;
        let payload = $payload;
        let proof = $proof;
        if spec.name()
            != &aos_systemd_client::SandboxUnitName::from_incarnation(*identity.incarnation_id())
            || !proof.validate()
        {
            return Err(HostError::Worker(
                "shifted proof has foreign launch scope".to_owned(),
            ));
        }
        let launch_binding = spec
            .launch_binding()
            .ok_or_else(|| HostError::Worker("shifted proof requires a bound launch".to_owned()))?;
        shifted_kernel!($mode, $original, $temporary, $receiving, payload, supervisor, 0);
        let before = shifted_identity!($mode, $original, $temporary, payload, 0);
        if before.pid() != proof.payload.pid
            || before.thread_group_id() != proof.payload.thread_group_id
            || before.parent_pid() != proof.payload.parent_pid
            || before.cgroup_id() != Some(proof.payload.cgroup_id)
            || before.start_time_ticks() != proof.payload.start_time_ticks
        {
            return Err(HostError::Worker(
                "shifted payload differs from launch proof".to_owned(),
            ));
        }

        // These four ioctls are performed by the actual Host service against
        // the actual shifted payload, never against a phase-zero surrogate.
        let host = shifted_host!($mode, $original, $temporary);
        let user = shifted_namespace!($mode, $original, $temporary, payload, user, 0, User);
        let mount = shifted_namespace!($mode, $original, $temporary, payload, mount, 1, Mount);
        let network = shifted_namespace!($mode, $original, $temporary, payload, network, 2, Network);
        let pid = shifted_namespace!($mode, $original, $temporary, payload, pid, 3, Pid);
        if user.identity() != payload.user().identity()
            || mount.identity() != payload.mount().identity()
            || network.identity() != payload.network().identity()
            || pid.identity() != payload.pid().identity()
            || namespace_snapshot(user.identity()) != proof.user_namespace
            || namespace_snapshot(mount.identity()) != proof.mount_namespace
            || namespace_snapshot(network.identity()) != proof.network_namespace
            || user.identity() == host.user().identity()
            || pid.identity() == host.pid().identity()
        {
            return Err(HostError::Worker(
                "payload is not in the pinned shifted namespaces".to_owned(),
            ));
        }

        let (host_id_start, mapping_count) = spec.private_user_range();
        shifted_map!($mode, $original, $temporary, before, 0, "uid_map", host_id_start, mapping_count);
        shifted_map!($mode, $original, $temporary, before, 1, "gid_map", host_id_start, mapping_count);

        let after = shifted_identity!($mode, $original, $temporary, payload, 1);
        if before != after
            || !shifted_alive!($mode, $original, $temporary, payload)
        {
            return Err(HostError::Worker(
                "shifted payload changed during inspection".to_owned(),
            ));
        }
        shifted_kernel!($mode, $original, $temporary, $receiving, payload, supervisor, 1);

        let record = ShiftedPayloadInspectionRecordV1 {
            version: VERSION,
            host_boot_id: proof.host_boot_id,
            sandbox_id: *identity.sandbox_id(),
            incarnation_id: *identity.incarnation_id(),
            assignment_epoch: identity.assignment_epoch(),
            desired_generation: identity.desired_generation(),
            assignment_digest: *identity.assignment_digest(),
            launch_binding,
            invocation_id,
            payload_pid: before.pid(),
            payload_parent_pid: before.parent_pid(),
            payload_start_time_ticks: before.start_time_ticks(),
            payload_cgroup_id: before.cgroup_id().ok_or_else(|| {
                HostError::Worker("kernel omitted shifted payload cgroup ID".to_owned())
            })?,
            user_namespace: namespace_snapshot(user.identity()),
            mount_namespace: namespace_snapshot(mount.identity()),
            network_namespace: namespace_snapshot(network.identity()),
            pid_namespace: namespace_snapshot(pid.identity()),
            host_user_namespace: namespace_snapshot(host.user().identity()),
            host_pid_namespace: namespace_snapshot(host.pid().identity()),
            host_uid_start: host_id_start,
            host_gid_start: host_id_start,
            mapping_count,
        };
        record.validate()?;
        Ok(VerifiedShiftedPayloadInspectionV1 { record })

    }};
}

pub(super) fn inspect_local(
    identity: &HostRuntimeIdentity,
    spec: &SandboxUnitSpec,
    invocation_id: [u8; 16],
    supervisor: &PinnedLeader,
    payload: &PinnedPayloadLeader,
    proof: &RuntimeProofSnapshot,
) -> Result<VerifiedShiftedPayloadInspectionV1> {
    shifted_recipe!(identity, spec, invocation_id, supervisor, payload, proof, Local, unused, unused, unused)
}

struct ShiftedTemporaryV2 {
    identities: [PidFdProcessIdentityOriginalV1; 2],
    host: ServiceNamespaceProbeOriginalV2,
    namespaces: [PidFdNamespaceOriginalV2; 4],
    user: Option<NamespaceFd>,
    mount: Option<NamespaceFd>,
    network: Option<NamespaceFd>,
    pid: Option<NamespaceFd>,
    maps: [ShiftedIdMapOriginalV2; 2],
    map_results: [Option<Result<()>>; 2],
    alive: Option<Native<bool>>,
}

impl ShiftedTemporaryV2 {
    fn new() -> Self {
        Self {
            identities: std::array::from_fn(|_| PidFdProcessIdentityOriginalV1::new()),
            host: ServiceNamespaceProbeOriginalV2::new(),
            namespaces: std::array::from_fn(|_| PidFdNamespaceOriginalV2::new()),
            user: None,
            mount: None,
            network: None,
            pid: None,
            maps: std::array::from_fn(|_| ShiftedIdMapOriginalV2::new()),
            map_results: std::array::from_fn(|_| None),
            alive: None,
        }
    }

    fn complete(&self) -> bool {
        self.failure().is_none()
            && self.identities.iter().all(|identity| identity.identity().is_some())
            && self.host.completed().is_some()
            && self.user.is_some() && self.mount.is_some()
            && self.network.is_some() && self.pid.is_some()
            && self.map_results.iter().all(|result| matches!(result, Some(Ok(()))))
            && matches!(self.alive, Some(Ok(true)))
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.identities[0].failure()
            .or_else(|| self.host.failure())
            .or_else(|| self.namespaces.iter().find_map(|original| original.failure().map(|cause| cause as _)))
            .or_else(|| self.maps.iter().find_map(|original| original.failure()))
            .or_else(|| self.identities[1].failure())
            .or_else(|| error(&self.alive))
    }
}

/// Records physical disposal of one completed local temporary native prefix.
pub(in crate::worker) struct ShiftedNativeDisposedV2 {
    original: Arc<()>,
    slot: usize,
    witness: ShiftedPayloadInspectionRecordV1,
}

impl ShiftedNativeDisposedV2 {
    pub(in crate::worker) fn belongs_to_v2(&self, original: &ShiftedPayloadOriginalV2, slot: usize) -> bool {
        self.slot == slot && original.slot == slot && Arc::ptr_eq(&self.original, &original.original)
            && original.temporary.is_none()
    }
}

pub(in crate::worker) struct ShiftedPayloadOriginalV2 {
    original: Arc<()>,
    slot: usize,
    entered: bool,
    temporary: Option<Box<ShiftedTemporaryV2>>,
    kernel: [Option<Result<()>>; 2],
    primary: Option<Result<VerifiedShiftedPayloadInspectionV1>>,
    disposed: Option<ShiftedNativeDisposedV2>,
    disposal: Option<Result<()>>,
    refusal: Option<HostError>,
}

impl ShiftedPayloadOriginalV2 {
    pub(in crate::worker) fn new(slot: usize) -> Self {
        Self {
            original: Arc::new(()),
            slot,
            entered: false,
            temporary: Some(Box::new(ShiftedTemporaryV2::new())),
            kernel: std::array::from_fn(|_| None),
            primary: None,
            disposed: None,
            disposal: None,
            refusal: None,
        }
    }

    pub(in crate::worker) async fn inspect_once(
        &mut self,
        identity: &HostRuntimeIdentity,
        spec: &SandboxUnitSpec,
        invocation_id: [u8; 16],
        supervisor: &PinnedLeader,
        payload: &PinnedPayloadLeader,
        proof: &RuntimeProofSnapshot,
        receiving: &mut HostLaunchWorkerReceivingV2<'_, '_>,
    ) -> Result<()> {
        if self.entered {
            self.refusal.get_or_insert_with(|| closed("shifted inspection cannot reenter"));
            return Err(closed("shifted inspection cannot reenter"));
        }
        self.entered = true;
        self.primary = Some(async {
            let temporary = self.temporary.as_deref_mut()
                .ok_or_else(|| closed("shifted native owner is absent"))?;
            shifted_recipe!(identity, spec, invocation_id, supervisor, payload, proof, Retained, self, temporary, receiving)
        }.await);
        if !matches!(self.primary, Some(Ok(_))) {
            return Err(closed("shifted inspection failed; native originals retained"));
        }
        self.disposal = Some(self.dispose_positive_once_v2());
        if matches!(self.disposal, Some(Ok(()))) { Ok(()) } else {
            Err(closed("shifted native disposal refused; original result retained"))
        }
    }

    fn dispose_positive_once_v2(&mut self) -> Result<()> {
        if self.refusal.is_some() || self.disposed.is_some()
            || !self.kernel.iter().all(|result| matches!(result, Some(Ok(()))))
            || !self.temporary.as_ref().is_some_and(|temporary| temporary.complete())
        {
            return Err(closed("shifted inspection has no complete positive native prefix"));
        }
        let witness = self.primary.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(|| closed("shifted inspection has no verified record"))?.record.clone();

        // No later caller/global post reads these Host probe, fresh payload
        // namespaces, proc/stat or map temporary owners. The actual payload
        // and supervisor inputs remain independently held by the readback.
        // The exact validated witness survives this real physical disposal.
        drop(self.temporary.take());
        self.disposed = Some(ShiftedNativeDisposedV2 {
            original: Arc::clone(&self.original), slot: self.slot, witness,
        });
        Ok(())
    }

    pub(in crate::worker) fn disposal_proof(&self) -> Option<&ShiftedNativeDisposedV2> {
        let proof = self.disposed.as_ref()?;
        (self.refusal.is_none() && self.temporary.is_none()
            && matches!(self.disposal, Some(Ok(())))
            && self.kernel.iter().all(|result| matches!(result, Some(Ok(())))))
            .then_some(proof)
    }

    pub(in crate::worker) fn take_completed_once(&mut self) -> Option<VerifiedShiftedPayloadInspectionV1> {
        let proof = self.disposal_proof()?;
        if !proof.belongs_to_v2(self, self.slot)
            || !self.primary.as_ref().is_some_and(|result| result.as_ref()
                .is_ok_and(|verified| verified.record == proof.witness))
        { return None; }
        self.primary.take()?.ok()
    }

    pub(in crate::worker) fn completed_for_parent_disposal_v4(&self) -> bool {
        self.primary.is_none() && self.disposal_proof().is_some() && self.failure().is_none()
    }

    pub(in crate::worker) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        error(&self.kernel[0])
            .or_else(|| self.temporary.as_ref().and_then(|temporary| temporary.failure()))
            .or_else(|| error(&self.kernel[1]))
            .or_else(|| error(&self.primary))
            .or_else(|| error(&self.disposal))
            .or_else(|| self.refusal.as_ref().map(|cause| cause as _))
    }

    pub(in crate::worker) fn receiving_obligations_v2() -> Option<(usize, usize, usize)> {
        let mut bound = (std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(2 * std::mem::size_of::<ShiftedTemporaryV2>())?
            .checked_add(4 * std::mem::size_of::<usize>())?
            .checked_add(2 * MAXIMUM_RECORD_BYTES)?, 0_usize, 0_usize);
        let identity = PidFdProcessIdentityOriginalV1::receiving_footprint_v1()?;
        // Each identity observation retains one actual /proc/PID/stat name.
        let identity = (identity.0, identity.1, 1_usize);
        for next in [
            identity,
            identity,
            ServiceNamespaceProbeOriginalV2::receiving_obligations_v2()?,
            ShiftedIdMapOriginalV2::receiving_obligations_v2()?,
            ShiftedIdMapOriginalV2::receiving_obligations_v2()?,
        ].into_iter().chain(std::iter::repeat_n(PidFdNamespaceOriginalV2::receiving_obligations_v2()?, 4)) {
            bound = (bound.0.checked_add(next.0)?, bound.1.checked_add(next.1)?, bound.2.checked_add(next.2)?);
        }
        Some(bound)
    }
}

fn error<T, E: std::error::Error + 'static>(slot: &Option<std::result::Result<T, E>>)
    -> Option<&(dyn std::error::Error + 'static)>
{
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

fn closed(message: &'static str) -> HostError { HostError::Fence(message) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_real_map_prefix_cannot_dispose_or_replace_its_native_owner() {
        let mut original = ShiftedPayloadOriginalV2::new(0);
        let temporary = original.temporary.as_mut().unwrap();
        let address = &**temporary as *const ShiftedTemporaryV2;
        // No kernel UID map can contain a zero-length range. The existing
        // real File/open/bounded read completes before this exact mismatch.
        temporary.map_results[0] = Some(read_exact_id_map_retaining_v2(
            std::process::id(), "uid_map", u32::MAX, 0, &mut temporary.maps[0],
        ));
        assert!(matches!(temporary.map_results[0], Some(Err(_))));
        let first = original.failure().unwrap().downcast_ref::<HostError>().unwrap() as *const _;

        assert!(original.dispose_positive_once_v2().is_err());

        assert_eq!(&**original.temporary.as_ref().unwrap() as *const ShiftedTemporaryV2, address);
        assert!(original.disposal_proof().is_none());
        assert!(!original.completed_for_parent_disposal_v4());
        assert!(original.take_completed_once().is_none());
        assert_eq!(original.failure().unwrap().downcast_ref::<HostError>().unwrap() as *const _, first);
        assert!(original.dispose_positive_once_v2().is_err());
        assert_eq!(&**original.temporary.as_ref().unwrap() as *const ShiftedTemporaryV2, address);
    }
}
