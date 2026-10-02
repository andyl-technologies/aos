//! systemd-backed runtime execution and exact Guardian/payload proof.
//!
//! This module owns manager calls, exact-unit observation and stop quiescence,
//! and the Linux descriptor proof assembled after a guarded payload start.

use super::*;

// One verification recipe preserves Local's lexical ownership while the retained
// disposition parks returned originals before the next fallible observation.
macro_rules! verification_slot {
    (Local, park_observation, $s:ident, $v:ident) => {};
    (Retained, park_observation, $s:ident, $v:ident) => { $s.observation = Some($v); };
    (Local, observation, $s:ident, $v:ident) => { $v };
    (Retained, observation, $s:ident, $v:ident) => {
        $s.observation.as_ref().ok_or_else(|| resident_readback_missing("observation"))?
    };
    (Local, park_payload, $s:ident, $v:ident) => {};
    (Retained, park_payload, $s:ident, $v:ident) => { $s.pending_payload = Some($v); };
    (Local, payload, $s:ident, $v:ident) => { &$v };
    (Retained, payload, $s:ident, $v:ident) => {
        $s.pending_payload.as_ref().ok_or_else(|| resident_readback_missing("payload"))?
    };
    (Local, park_proof, $s:ident, $v:ident) => {};
    (Retained, park_proof, $s:ident, $v:ident) => { $s.proof = Some($v); };
    (Local, park_shifted, $s:ident, $v:ident) => {};
    (Retained, park_shifted, $s:ident, $v:ident) => { $s.shifted = Some($v); };
    (Local, join_payload, $s:ident, $o:ident, $p:ident) => { $o.payload = Some($p); };
    (Retained, join_payload, $s:ident, $o:ident, $p:ident) => {};
    (Local, limits, $s:ident, $w:ident, $spec:ident) => {};
    (Retained, limits, $s:ident, $w:ident, $spec:ident) => {
        $w.capture_service_limits($spec, $s)?;
    };
    (Local, limits_after, $s:ident, $w:ident, $spec:ident, $identity:ident, $after:ident) => {};
    (Retained, limits_after, $s:ident, $w:ident, $spec:ident, $identity:ident, $after:ident) => {
        $w.recheck_service_limits($spec, $s)?;
        if $w.observe_bound_payload($identity).await? != $after {
            return Err(HostError::Worker(
                "bound payload manager changed during final limit bookend".to_owned(),
            ));
        }
    };
    (Local, finish, $s:ident, $after:ident, $id:ident, $o:ident, $p:ident, $shift:ident) => {
        Ok(BoundPayloadVerification {
            binding: $after.binding,
            invocation_id: $id,
            observation: $o,
            proof: $p,
            shifted_payload_inspection: Some($shift),
        })
    };
    (Retained, finish, $s:ident, $after:ident, $id:ident, $o:ident, $p:ident, $shift:ident) => {{
        if $s.observation.is_none() || $s.pending_payload.is_none()
            || $s.proof.is_none() || $s.shifted.is_none()
        {
            return Err(resident_readback_missing("final assembly"));
        }
        // All fields were checked together. No observation or allocation lies
        // between the exclusive takes and their move into the resident result.
        let (Some(mut observation), Some(payload), Some(proof), Some(shifted)) = (
            $s.observation.take(), $s.pending_payload.take(), $s.proof.take(), $s.shifted.take(),
        ) else { std::process::abort() };
        observation.payload = Some(payload);
        $s.verification = Some(BoundPayloadVerification {
            binding: $after.binding,
            invocation_id: $id,
            observation,
            proof,
            shifted_payload_inspection: Some(shifted),
        });
        Ok(())
    }};
}

macro_rules! verify_bound_payload_recipe {
    ($worker:ident, $client:ident, $spec:ident, $pins:ident, $identity:ident, $mode:ident, $state:ident) => {{
        let expected_binding = $spec.launch_binding().ok_or_else(|| {
            HostError::Worker("Host 1.0 payload spec lost its launch binding".to_owned())
        })?;
        let exact_before = $worker.observe_bound_payload($identity).await?;
        if exact_before.binding != Some(expected_binding)
            || exact_before.state != GuardianObservedState::ActiveRunning
        {
            return Err(HostError::Worker(
                "bound payload is foreign, absent, or non-running".to_owned(),
            ));
        }
        let invocation_id = exact_before.invocation_id.ok_or_else(|| {
            HostError::Worker("bound payload has no invocation identity".to_owned())
        })?;

        let mut observation = $worker.observe_with_client($client, $identity).await?;
        verification_slot!($mode, park_observation, $state, observation);
        if verification_slot!($mode, observation, $state, observation).invocation_id != Some(invocation_id)
            || !matches!(verification_slot!($mode, observation, $state, observation).state, ObservedRuntimeState::Ready)
        {
            return Err(HostError::Worker(
                "bound payload changed before kernel proof construction".to_owned(),
            ));
        }
        let leader = verification_slot!($mode, observation, $state, observation).leader.as_ref().ok_or_else(|| {
            HostError::Worker("bound payload has no pinned supervisor".to_owned())
        })?;
        let payload = verify_supervisor_pins(
            &$worker.cgroup_root,
            $pins,
            leader,
            $spec.payload_root_continuity_policy(),
        )?;
        verification_slot!($mode, park_payload, $state, payload);
        let proof = runtime_proof_snapshot($pins, leader, verification_slot!($mode, payload, $state, payload))?;
        verification_slot!($mode, park_proof, $state, proof);
        let shifted_payload_inspection = VerifiedShiftedPayloadInspectionV1::inspect(
            $identity,
            $spec,
            invocation_id,
            leader,
            verification_slot!($mode, payload, $state, payload),
            &proof,
        )?;
        verification_slot!($mode, park_shifted, $state, shifted_payload_inspection);
        verification_slot!($mode, join_payload, $state, observation, payload);
        verification_slot!($mode, limits, $state, $worker, $spec);

        let exact_after = $worker.observe_bound_payload($identity).await?;
        if exact_after != exact_before {
            return Err(HostError::Worker(
                "bound payload manager identity changed during kernel proof".to_owned(),
            ));
        }
        verification_slot!($mode, limits_after, $state, $worker, $spec, $identity, exact_after);
        verification_slot!($mode, finish, $state, exact_after, invocation_id, observation, proof, shifted_payload_inspection)
    }};
}

macro_rules! bound_call_finish {
    (LocalStart, $worker:ident, $client:ident, $spec:ident, $pins:ident, $identity:ident, $state:ident) => {
        Ok(CurrentJobDone {
            verification: $worker.verify_bound_payload(&$client, $spec, $pins, $identity).await?,
        })
    };
    (LocalProve, $worker:ident, $client:ident, $spec:ident, $pins:ident, $identity:ident, $state:ident) => {
        Ok(RecoveredExactProof {
            verification: $worker.verify_bound_payload(&$client, $spec, $pins, $identity).await?,
        })
    };
    (Retained, $worker:ident, $client:ident, $spec:ident, $pins:ident, $identity:ident, $state:ident) => {
        {
            let retained_client = &$client;
            verify_bound_payload_recipe!($worker, retained_client, $spec, $pins, $identity, Retained, $state)
        }
    };
}

macro_rules! start_bound_payload_recipe {
    ($worker:ident, $spec:ident, $pins:ident, $identity:ident, $guardian_invocation_id:ident,
        $before_effect:ident, $mode:ident, $state:ident) => {{
        let initial = $worker.observe_bound_payload($identity).await?;
        if initial.state != GuardianObservedState::Absent {
            return Err(HostError::Worker(
                "fresh payload start requires proven manager and cgroup absence".to_owned(),
            ));
        }

        let binding = $spec.launch_binding().ok_or_else(|| {
            HostError::Worker("bound payload spec has no Guardian launch binding".to_owned())
        })?;
        let guardian = ExactUnitTarget::new(binding, $guardian_invocation_id)
            .map_err(|error| worker_error(&error))?;
        let outcome = ExactUnitClient::connect()
            .await
            .map_err(|error| worker_error(&error))?
            .start_payload_guarded($spec, guardian, $before_effect)
            .await
            .map_err(|error| match error {
                ExactStartError::Guard(error) => error,
                ExactStartError::Systemd(error) => worker_error(&error),
            })?;
        if outcome.result != JobResult::Done {
            return Err(HostError::Worker(format!(
                "bound payload start job completed as {:?}",
                outcome.result
            )));
        }

        let client = SystemdClient::connect()
            .await
            .map_err(|error| worker_error(&error))?;

        bound_call_finish!($mode, $worker, client, $spec, $pins, $identity, $state)
    }};
}

macro_rules! prove_bound_payload_recipe {
    ($worker:ident, $spec:ident, $pins:ident, $identity:ident, $mode:ident, $state:ident) => {{
        let client = SystemdClient::connect()
            .await
            .map_err(|error| worker_error(&error))?;

        bound_call_finish!($mode, $worker, client, $spec, $pins, $identity, $state)
    }};
}

fn resident_readback_missing(field: &str) -> HostError {
    HostError::Worker(format!("resident payload readback lost {field}"))
}

fn retain_native_limit_result<T>(
    result: aos_sandbox_linux::Result<T>,
    failure: &mut Option<aos_sandbox_linux::Error>,
) -> Result<T> {
    result.map_err(|error| {
        if failure.is_none() {
            *failure = Some(error);
        }
        resident_readback_missing("native cgroup observation; cause retained")
    })
}

fn check_limit_membership(state: &mut BoundPayloadReadbackV1) -> Result<()> {
    let observation = state.observation.as_ref()
        .ok_or_else(|| resident_readback_missing("membership observation"))?;
    let leader = observation.leader.as_ref()
        .ok_or_else(|| resident_readback_missing("membership supervisor"))?;
    let payload = state.pending_payload.as_ref()
        .ok_or_else(|| resident_readback_missing("membership payload"))?;
    let service = state.anchors[3].as_ref()
        .ok_or_else(|| resident_readback_missing("membership service"))?;
    retain_native_limit_result(
        service.verify_descendant_membership(leader.pidfd(), Path::new("supervisor")),
        &mut state.native_failure,
    )?;
    let anchor = state.payload_anchor.as_ref()
        .ok_or_else(|| resident_readback_missing("payload anchor"))?;
    if anchor.kernel_id() != payload.cgroup.identity().inode {
        return Err(HostError::Worker("payload subtree is not beneath the retained service".to_owned()));
    }
    let membership = if payload.relative_cgroup_hint.is_empty() {
        anchor.verify_exact_membership(&payload.pidfd)
    } else {
        anchor.verify_descendant_membership(&payload.pidfd, Path::new(&payload.relative_cgroup_hint))
    };
    retain_native_limit_result(membership, &mut state.native_failure)?;
    Ok(())
}

fn required_limit_control<'a>(
    readback: &'a CgroupLimitReadbackV1,
    index: usize,
    control: CgroupLimitControlV1,
    missing: &mut Option<(usize, CgroupLimitControlV1)>,
) -> Result<&'a [u8]> {
    readback.bytes(control).ok_or_else(|| {
        *missing = Some((index, control));
        resident_readback_missing("required control; missing-file cause retained")
    })
}

fn require_limit_topology(
    readback: &CgroupLimitReadbackV1,
    index: usize,
    missing: &mut Option<(usize, CgroupLimitControlV1)>,
) -> Result<()> {
    let controllers = required_limit_control(
        readback, index, CgroupLimitControlV1::Controllers, missing,
    )?;
    let enabled = required_limit_control(
        readback, index, CgroupLimitControlV1::SubtreeControl, missing,
    )?;
    for required in [b"cpu".as_slice(), b"pids".as_slice(), b"memory".as_slice()] {
        for observed in [controllers, enabled] {
            let Some(body) = observed.strip_suffix(b"\n") else {
                return Err(resident_readback_missing("controller newline"));
            };
            if !body.split(|byte| *byte == b' ').any(|word| word == required) {
                return Err(HostError::Worker("required cgroup controller is absent or disabled".to_owned()));
            }
        }
    }
    // The installed worker's mount-root provenance is unchanged. Root-only
    // absence is retained as ENOENT, never synthesized as an unlimited value.
    if index == 0 && readback.bytes(CgroupLimitControlV1::Type)
        .is_some_and(|bytes| bytes != b"domain\n")
    {
        return Err(HostError::Worker("root topology is not a domain cgroup".to_owned()));
    }
    if index != 0 {
        if required_limit_control(readback, index, CgroupLimitControlV1::Type, missing)? != b"domain\n" {
            return Err(HostError::Worker("service ancestry is not a domain cgroup".to_owned()));
        }
        for control in [
            CgroupLimitControlV1::PidsMax, CgroupLimitControlV1::CpuWeight,
            CgroupLimitControlV1::MemoryHigh, CgroupLimitControlV1::MemoryMax,
        ] {
            required_limit_control(readback, index, control, missing)?;
        }
    }
    Ok(())
}

fn limit_decimal(readback: &CgroupLimitReadbackV1, control: CgroupLimitControlV1) -> Result<u64> {
    let bytes = readback.bytes(control).and_then(|record| record.strip_suffix(b"\n"))
        .ok_or_else(|| resident_readback_missing("finite control"))?;
    std::str::from_utf8(bytes).ok().and_then(|text| text.parse().ok())
        .ok_or_else(|| HostError::Worker("service control is not a finite decimal".to_owned()))
}

fn fixed_limit_paths(service: &SandboxCgroupPath) -> [&str; 4] {
    [
        ".",
        "aos.slice",
        "aos.slice/aos-sandboxes.slice",
        service.as_str().trim_start_matches('/'),
    ]
}

impl RetainedPayloadWorkerV1<'_> {
    pub(crate) fn start<'a>(
        &'a self,
        spec: &'a SandboxUnitSpec,
        pins: &'a LaunchPins,
        identity: &'a HostRuntimeIdentity,
        guardian_invocation_id: [u8; 16],
        before_effect: &'a mut (dyn FnMut() -> Result<()> + Send),
        state: &'a mut BoundPayloadReadbackV1,
    ) -> impl std::future::Future<Output = Result<()>> + Send + 'a {
        let admission = begin_resident_readback(state);
        async move {
            admission?;
            let worker = self.worker;
            let result = async {
                start_bound_payload_recipe!(worker, spec, pins, identity, guardian_invocation_id,
                    before_effect, Retained, state)
            }.await;
            finish_resident_readback(state, result)
        }
    }

    pub(crate) fn prove<'a>(
        &'a self,
        spec: &'a SandboxUnitSpec,
        pins: &'a LaunchPins,
        identity: &'a HostRuntimeIdentity,
        state: &'a mut BoundPayloadReadbackV1,
    ) -> impl std::future::Future<Output = Result<()>> + Send + 'a {
        let admission = begin_resident_readback(state);
        async move {
            admission?;
            let worker = self.worker;
            let result = async {
                prove_bound_payload_recipe!(worker, spec, pins, identity, Retained, state)
            }.await;
            finish_resident_readback(state, result)
        }
    }
}

fn begin_resident_readback(state: &mut BoundPayloadReadbackV1) -> Result<()> {
    if state.phase != BoundReadbackPhaseV1::Fresh {
        return Err(resident_readback_missing("fresh verification point"));
    }
    // This runs before the future exists, including unpolled cancellation.
    state.phase = BoundReadbackPhaseV1::Checking;
    Ok(())
}

fn finish_resident_readback(state: &mut BoundPayloadReadbackV1, result: Result<()>) -> Result<()> {
    match result {
        Ok(()) => {
            state.phase = BoundReadbackPhaseV1::Ready;
            Ok(())
        }
        Err(error) => {
            state.failure = Some(error);
            state.phase = BoundReadbackPhaseV1::Failed;
            let cause = state.failure_cause().ok_or_else(|| {
                resident_readback_missing("first verification failure")
            })?;
            Err(HostError::Worker(format!("original payload verification failed: {cause}")))
        }
    }
}

impl SystemdOneShotWorker {
    /// Constructs a worker around a pre-opened cgroup-v2 mount root.
    #[must_use]
    pub const fn new(cgroup_root: BeneathRoot) -> Self {
        Self { cgroup_root }
    }

    pub(super) async fn observe_with_client(
        &self,
        client: &SystemdClient,
        identity: &HostRuntimeIdentity,
    ) -> Result<WorkerObservation> {
        let name = SandboxUnitName::from_incarnation(*identity.incarnation_id());
        let Some(observation) = client
            .observe_sandbox_unit(&name)
            .await
            .map_err(|error| worker_error(&error))?
        else {
            self.verify_absent_cgroup(&name)?;
            return Ok(WorkerObservation {
                state: ObservedRuntimeState::Absent,
                invocation_id: None,
                leader: None,
                payload: None,
            });
        };
        let payload_freezer = if observation.active_state == "active" {
            let cgroup = observation.cgroup.as_ref().ok_or_else(|| {
                HostError::Worker("active sandbox unit has no exact cgroup".to_owned())
            })?;
            Some(
                resolve_payload_cgroup(&self.cgroup_root, cgroup)?
                    .freezer_state()
                    .map_err(|error| HostError::Worker(error.to_string()))?,
            )
        } else {
            None
        };
        let state = classify_state(&observation, payload_freezer);
        let leader = match observation.supervisor_pid {
            Some(pid) => Some(self.pin_leader(identity, &observation, pid)?),
            None if matches!(
                state,
                ObservedRuntimeState::Starting
                    | ObservedRuntimeState::Ready
                    | ObservedRuntimeState::Frozen
            ) =>
            {
                return Err(HostError::Worker(
                    "active sandbox unit has no supervisor MainPID".to_owned(),
                ));
            }
            None => None,
        };
        Ok(WorkerObservation {
            state,
            invocation_id: observation.invocation_id,
            leader,
            payload: None,
        })
    }

    async fn observe_guardian_with_client(
        &self,
        client: &SystemdClient,
        identity: &HostRuntimeIdentity,
    ) -> Result<GuardianObservation> {
        let name = SandboxUnitName::from_incarnation(*identity.incarnation_id());
        let Some(observation) = client
            .observe_guardian_unit(&name)
            .await
            .map_err(|error| worker_error(&error))?
        else {
            self.verify_absent_exact_cgroup(name.guardian_cgroup_path())?;
            return Ok(GuardianObservation {
                binding: None,
                invocation_id: None,
                state: GuardianObservedState::Absent,
            });
        };
        Ok(project_guardian_observation(observation))
    }

    async fn observe_bound_role(
        &self,
        identity: &HostRuntimeIdentity,
        role: ExactUnitRole,
    ) -> Result<GuardianObservation> {
        let name = SandboxUnitName::from_incarnation(*identity.incarnation_id());
        let observation = ExactUnitClient::connect()
            .await
            .map_err(|error| worker_error(&error))?
            .observe_exact_unit(&name, role)
            .await
            .map_err(|error| worker_error(&error))?;
        let Some(observation) = observation else {
            let path = match role {
                ExactUnitRole::Guardian => name.guardian_cgroup_path(),
                ExactUnitRole::Payload => name.cgroup_path(),
            };
            self.verify_absent_exact_cgroup(path)?;
            return Ok(GuardianObservation {
                binding: None,
                invocation_id: None,
                state: GuardianObservedState::Absent,
            });
        };
        Ok(project_exact_observation(observation))
    }

    async fn verify_bound_payload(
        &self,
        client: &SystemdClient,
        spec: &SandboxUnitSpec,
        pins: &LaunchPins,
        identity: &HostRuntimeIdentity,
    ) -> Result<BoundPayloadVerification> {
        verify_bound_payload_recipe!(self, client, spec, pins, identity, Local, unused)
    }

    fn capture_service_limits(
        &self,
        spec: &SandboxUnitSpec,
        state: &mut BoundPayloadReadbackV1,
    ) -> Result<()> {
        // Root/directory constructors still have their existing pre-return
        // acquisition gaps. Every successfully returned owner is parked here
        // before the next gate; fixed regular-file acquisition is retained below.
        let descriptor = self.cgroup_root.as_fd().try_clone_to_owned()
            .map_err(|source| HostError::Descriptor {
                operation: "duplicate limit-readback cgroup root",
                source,
            })?;
        state.root = Some(retain_native_limit_result(
            CgroupV2Root::from_owned(descriptor), &mut state.native_failure,
        )?);
        let root = state.root.as_ref().ok_or_else(|| resident_readback_missing("cgroup root"))?;
        let service_path = spec.name().cgroup_path();
        let paths = fixed_limit_paths(&service_path);
        for (index, path) in paths.iter().enumerate() {
            state.anchors[index] = Some(retain_native_limit_result(
                root.resolve(Path::new(path)), &mut state.native_failure,
            )?);
            let anchor = state.anchors[index].as_ref()
                .ok_or_else(|| resident_readback_missing("cgroup ancestor"))?;
            state.limits[index].capture(anchor)
                .map_err(|_| resident_readback_missing("native control capture; cause retained"))?;
            require_limit_topology(&state.limits[index], index, &mut state.missing_control)?;
        }
        let service = state.anchors[3].as_ref()
            .ok_or_else(|| resident_readback_missing("service anchor"))?;
        state.payload_anchor = Some(retain_native_limit_result(
            service.resolve_descendant(Path::new("payload")), &mut state.native_failure,
        )?);
        check_limit_membership(state)?;
        let limits = &state.limits[3];
        let expected = spec.resources();
        if limit_decimal(limits, CgroupLimitControlV1::PidsMax)? != expected.tasks_max()
            || limit_decimal(limits, CgroupLimitControlV1::CpuWeight)? != expected.cpu_weight().get()
        {
            return Err(HostError::Worker("service task limit or CPU weight differs from original Spec".to_owned()));
        }
        // Memory bytes remain paired with the actual original byte request in
        // the resident PreparedLaunch. No page conversion/equality is invented.
        Ok(())
    }

    fn recheck_service_limits(
        &self,
        spec: &SandboxUnitSpec,
        state: &mut BoundPayloadReadbackV1,
    ) -> Result<()> {
        check_limit_membership(state)?;
        for index in 0..4 {
            let anchor = state.anchors[index].as_ref()
                .ok_or_else(|| resident_readback_missing("final ancestor"))?;
            state.limits[index].recheck(anchor)
                .map_err(|_| resident_readback_missing("native control bookend; cause retained"))?;
        }
        let root = state.root.as_ref().ok_or_else(|| resident_readback_missing("final root"))?;
        let service_path = spec.name().cgroup_path();
        for (index, path) in fixed_limit_paths(&service_path).iter().enumerate() {
            state.anchor_bookends[index] = Some(retain_native_limit_result(
                root.resolve(Path::new(path)), &mut state.native_failure,
            )?);
            let (Some(original), Some(bookend)) = (&state.anchors[index], &state.anchor_bookends[index]) else {
                return Err(resident_readback_missing("ancestor bookend"));
            };
            if original.kernel_id() != bookend.kernel_id() {
                return Err(HostError::Worker("named service ancestry changed during limit readback".to_owned()));
            }
        }
        check_limit_membership(state)
    }

    pub(super) fn verify_absent_cgroup(&self, name: &SandboxUnitName) -> Result<()> {
        self.verify_absent_exact_cgroup(name.cgroup_path())
    }

    fn verify_absent_exact_cgroup(&self, path: SandboxCgroupPath) -> Result<()> {
        let descriptor = self
            .cgroup_root
            .as_fd()
            .try_clone_to_owned()
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let root = CgroupV2Root::from_owned(descriptor)
            .map_err(|error| HostError::Worker(error.to_string()))?;
        match root.resolve(Path::new(path.as_str().trim_start_matches('/'))) {
            Err(aos_sandbox_linux::Error::Syscall { source, .. })
                if source.raw_os_error() == Some(rustix::io::Errno::NOENT.raw_os_error()) =>
            {
                // A missing manager object is not containment evidence by
                // itself. Require the exact runtime cgroup to be absent and
                // recheck the live cgroup-v2 anchor after that observation.
                root.resolve(Path::new("."))
                    .map_err(|error| HostError::Worker(error.to_string()))?;
                Ok(())
            }
            Ok(_) => Err(HostError::Worker(
                "systemd unit is absent but its runtime cgroup still exists".to_owned(),
            )),
            Err(error) => Err(HostError::Worker(error.to_string())),
        }
    }

    fn pin_leader(
        &self,
        identity: &HostRuntimeIdentity,
        observation: &SandboxUnitObservation,
        pid: NonZeroU32,
    ) -> Result<PinnedLeader> {
        let invocation_id = observation.invocation_id.ok_or_else(|| {
            HostError::Worker("sandbox leader has no systemd invocation ID".to_owned())
        })?;
        let cgroup = observation.cgroup.as_ref().ok_or_else(|| {
            HostError::Worker("sandbox leader has no verified unit cgroup".to_owned())
        })?;
        let supervisor = cgroup.supervisor_subgroup();
        let supervisor_relative = supervisor.as_str().trim_start_matches('/');
        let supervisor = self
            .cgroup_root
            .resolve(Path::new(supervisor_relative), ResolveOptions::directory())
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let pidfd = PidFd::open(pid).map_err(|error| HostError::Worker(error.to_string()))?;
        let info = pidfd
            .info()
            .map_err(|error| HostError::Worker(error.to_string()))?;
        if info.pid() != pid.get() || info.thread_group_id() != pid.get() {
            return Err(HostError::Worker(
                "systemd MainPID is not the pinned thread-group leader".to_owned(),
            ));
        }
        let cgroup_id = info
            .cgroup_id()
            .ok_or_else(|| HostError::Worker("kernel omitted leader cgroup identity".to_owned()))?;
        if cgroup_id != supervisor.identity().inode {
            return Err(HostError::Worker(
                "pinned leader is outside the expected supervisor cgroup".to_owned(),
            ));
        }
        if !pidfd
            .is_alive()
            .map_err(|error| HostError::Worker(error.to_string()))?
        {
            return Err(HostError::Worker(
                "sandbox supervisor exited during identity validation".to_owned(),
            ));
        }

        let mut digest = Sha256::new();
        digest.update(b"aos.sandbox.host.leader.v1\0");
        digest.update(identity.incarnation_id());
        digest.update(invocation_id);
        digest.update(cgroup_id.to_le_bytes());
        digest.update(pid.get().to_le_bytes());
        Ok(PinnedLeader {
            handle: digest.finalize().into(),
            pidfd,
            cgroup: cgroup.clone(),
        })
    }
}

pub(super) struct LinuxPayloadInspector<'a> {
    pub(super) payload_root: &'a BeneathRoot,
}

impl PayloadInspectionBackend for LinuxPayloadInspector<'_> {
    type Proof = PinnedPayloadLeader;

    fn snapshot(&self) -> Result<Vec<PayloadCandidate>> {
        let duplicate = self
            .payload_root
            .as_fd()
            .try_clone_to_owned()
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let root = BeneathRoot::from_owned(duplicate)
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let mut pending = VecDeque::from([(root, String::new())]);
        let mut candidates = Vec::new();
        let mut directories = 0_usize;
        while let Some((directory, relative_cgroup_hint)) = pending.pop_front() {
            directories = directories
                .checked_add(1)
                .ok_or_else(|| HostError::Worker("payload cgroup count overflow".to_owned()))?;
            if directories > MAXIMUM_PAYLOAD_CGROUPS {
                return Err(HostError::Worker(
                    "payload cgroup tree exceeds its fixed bound".to_owned(),
                ));
            }
            let cgroup_id = directory.identity().inode;
            let processes = directory
                .open_regular(Path::new("cgroup.procs"))
                .and_then(|file| file.read_bounded(MAXIMUM_CGROUP_PROCS_BYTES))
                .map_err(|error| HostError::Worker(error.to_string()))?;
            for pid in parse_cgroup_processes(&processes)? {
                if candidates.len() >= MAXIMUM_PAYLOAD_PROCESSES {
                    return Err(HostError::Worker(
                        "payload process snapshot exceeds its fixed bound".to_owned(),
                    ));
                }
                candidates.push(PayloadCandidate {
                    pid,
                    cgroup_id,
                    relative_cgroup_hint: relative_cgroup_hint.clone(),
                });
            }

            // Resolution pins use O_PATH. Dir::read_from preserves that flag,
            // but getdents requires a readable descriptor. Open only the pinned
            // directory itself, never a reconstructed pathname or parent hint.
            let readable = rustix::fs::openat(
                directory.as_fd(),
                ".",
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|error| {
                HostError::Worker(format!("open payload cgroup for reading: {error}"))
            })?;
            let entries = rustix::fs::Dir::new(readable)
                .map_err(|error| HostError::Worker(format!("iterate payload cgroup: {error}")))?;
            for entry in entries {
                let entry = entry.map_err(|error| {
                    HostError::Worker(format!("read payload cgroup entry: {error}"))
                })?;
                let name = entry.file_name().to_bytes();
                if matches!(name, b"." | b"..") {
                    continue;
                }
                match entry.file_type() {
                    rustix::fs::FileType::Directory => {
                        let name = std::str::from_utf8(name).map_err(|_| {
                            HostError::Worker("payload cgroup name is not UTF-8".to_owned())
                        })?;
                        let child = directory
                            .resolve(Path::new(name), ResolveOptions::directory())
                            .map_err(|error| HostError::Worker(error.to_string()))?;
                        let relative = if relative_cgroup_hint.is_empty() {
                            name.to_owned()
                        } else {
                            format!("{relative_cgroup_hint}/{name}")
                        };
                        if relative.len() > 4096 {
                            return Err(HostError::Worker(
                                "payload cgroup hint exceeds its fixed bound".to_owned(),
                            ));
                        }
                        pending.push_back((
                            BeneathRoot::from_resolved(child)
                                .map_err(|error| HostError::Worker(error.to_string()))?,
                            relative,
                        ));
                    }
                    rustix::fs::FileType::Unknown => {
                        return Err(HostError::Worker(
                            "payload cgroup returned an unknown directory-entry type".to_owned(),
                        ));
                    }
                    _ => {}
                }
            }
        }
        Ok(candidates)
    }

    fn prove(&self, candidate: PayloadCandidate) -> Result<(PayloadEvidence, Option<Self::Proof>)> {
        let pidfd =
            PidFd::open(candidate.pid).map_err(|error| HostError::Worker(error.to_string()))?;
        let info = pidfd
            .info()
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let cgroup_id = info.cgroup_id().ok_or_else(|| {
            HostError::Worker("kernel omitted payload cgroup identity".to_owned())
        })?;
        let nested_pid = read_nested_pid(candidate.pid)?;
        if nested_pid != 1 {
            return Ok((
                PayloadEvidence {
                    pid: candidate.pid,
                    thread_group_id: info.thread_group_id(),
                    parent_pid: info.parent_pid(),
                    cgroup_id,
                    nested_pid,
                    root_device: 0,
                    root_inode: 0,
                    network_device: 0,
                    network_inode: 0,
                },
                None,
            ));
        }
        // Both `/proc/PID/root` traversal and PIDFD_GET_* namespace ioctls are
        // ptrace-policy gated. EPERM/EACCES propagate as a failed proof: this
        // boundary never falls back to a numeric PID, machined metadata, setns,
        // or a broad capability grant.
        let root = open_payload_root(candidate.pid)?;
        let root_identity =
            rustix::fs::fstat(&root).map_err(|error| HostError::Worker(error.to_string()))?;
        let network = pidfd
            .namespace(NamespaceKind::Network)
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let mount = pidfd
            .namespace(NamespaceKind::Mount)
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let user = pidfd
            .namespace(NamespaceKind::User)
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let pid = pidfd
            .namespace(NamespaceKind::Pid)
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let network_identity = network.identity();
        let final_info = pidfd
            .info()
            .map_err(|error| HostError::Worker(error.to_string()))?;
        if final_info != info {
            return Err(HostError::Worker(
                "payload pidfd identity changed during proof".to_owned(),
            ));
        }
        Ok((
            PayloadEvidence {
                pid: candidate.pid,
                thread_group_id: info.thread_group_id(),
                parent_pid: info.parent_pid(),
                cgroup_id,
                nested_pid,
                root_device: root_identity.st_dev,
                root_inode: root_identity.st_ino,
                network_device: network_identity.device,
                network_inode: network_identity.inode,
            },
            Some(PinnedPayloadLeader {
                pidfd,
                cgroup: BeneathRoot::from_owned(
                    self.payload_root
                        .as_fd()
                        .try_clone_to_owned()
                        .map_err(|error| HostError::Worker(error.to_string()))?,
                )
                .map_err(|error| HostError::Worker(error.to_string()))?,
                relative_cgroup_hint: candidate.relative_cgroup_hint,
                root,
                network,
                mount,
                pid,
                user,
            }),
        ))
    }

    fn is_alive(&self, proof: &Self::Proof) -> Result<bool> {
        proof
            .pidfd
            .is_alive()
            .map_err(|error| HostError::Worker(error.to_string()))
    }
}

fn parse_cgroup_processes(bytes: &[u8]) -> Result<Vec<NonZeroU32>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| HostError::Worker("cgroup.procs is not UTF-8".to_owned()))?;
    let mut processes = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        if line.bytes().any(|byte| !byte.is_ascii_digit()) {
            return Err(HostError::Worker(
                "cgroup.procs contains a noncanonical PID".to_owned(),
            ));
        }
        let pid = line
            .parse::<u32>()
            .ok()
            .and_then(NonZeroU32::new)
            .ok_or_else(|| HostError::Worker("cgroup.procs contains an invalid PID".to_owned()))?;
        processes.push(pid);
    }
    Ok(processes)
}

pub(super) fn read_nested_pid(pid: NonZeroU32) -> Result<u32> {
    let path = format!("/proc/{pid}/status");
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| HostError::Worker(error.to_string()))?;
    let mut bytes = Vec::new();
    File::from(descriptor)
        .take((MAXIMUM_PROC_STATUS_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| HostError::Worker(error.to_string()))?;
    if bytes.len() > MAXIMUM_PROC_STATUS_BYTES {
        return Err(HostError::Worker(
            "payload proc status exceeds its fixed bound".to_owned(),
        ));
    }
    parse_nested_pid(&bytes, pid)
}

pub(super) fn parse_nested_pid(bytes: &[u8], host_pid: NonZeroU32) -> Result<u32> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| HostError::Worker("payload proc status is not UTF-8".to_owned()))?;
    let mut matches = text
        .lines()
        .filter_map(|line| line.strip_prefix("NSpid:\t"));
    let value = matches
        .next()
        .ok_or_else(|| HostError::Worker("payload proc status omitted NSpid".to_owned()))?;
    if matches.next().is_some() {
        return Err(HostError::Worker(
            "payload proc status repeated NSpid".to_owned(),
        ));
    }
    let values = value
        .split('\t')
        .map(|part| part.parse::<u32>())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| HostError::Worker("payload proc status has invalid NSpid".to_owned()))?;
    if values.first() != Some(&host_pid.get()) {
        return Err(HostError::Worker(
            "payload proc status host PID contradicts its pidfd".to_owned(),
        ));
    }
    values
        .last()
        .copied()
        .ok_or_else(|| HostError::Worker("payload proc status has empty NSpid".to_owned()))
}

pub(super) fn open_payload_root(pid: NonZeroU32) -> Result<OwnedFd> {
    let path = format!("/proc/{pid}/root");
    rustix::fs::open(
        path,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| HostError::Worker(error.to_string()))
}

#[async_trait]
impl HostWorker for SystemdOneShotWorker {
    fn retained_payload_worker(&self) -> Option<RetainedPayloadWorkerV1<'_>> {
        Some(RetainedPayloadWorkerV1 { worker: self })
    }

    async fn execute(
        &self,
        fence: &ValidatedAssignmentFence,
        operation: WorkerOperation,
        before_effect: &mut (dyn FnMut() -> Result<()> + Send),
    ) -> Result<WorkerObservation> {
        let client = SystemdClient::connect()
            .await
            .map_err(|error| worker_error(&error))?;
        let identity = HostRuntimeIdentity::from(fence);
        let name = SandboxUnitName::from_incarnation(*identity.incarnation_id());
        match operation {
            WorkerOperation::Launch { spec, pins } => {
                let root_policy = spec.payload_root_continuity_policy();
                let backend = SystemdLaunchBackend {
                    worker: self,
                    client: &client,
                    identity: &identity,
                    name: &name,
                };
                let mut verify = |observation: &WorkerObservation, pins: &LaunchPins| {
                    let leader = observation.leader.as_ref().ok_or_else(|| {
                        HostError::Worker(
                            "started nspawn supervisor has no pinned leader".to_owned(),
                        )
                    })?;
                    verify_supervisor_pins(&self.cgroup_root, pins, leader, root_policy)
                };
                return reconcile_launch(&backend, &spec, &pins, before_effect, &mut verify).await;
            }
            operation => {
                let current = self.observe_with_client(&client, &identity).await?;
                match operation {
                    WorkerOperation::Stop | WorkerOperation::Kill
                        if current.state == ObservedRuntimeState::Absent =>
                    {
                        return Ok(current);
                    }
                    WorkerOperation::Stop => {
                        before_effect()?;
                        ensure_done(
                            &client
                                .stop_sandbox_unit(&name)
                                .await
                                .map_err(|error| worker_error(&error))?,
                        )?;
                    }
                    WorkerOperation::Freeze if current.state == ObservedRuntimeState::Frozen => {
                        return Ok(current);
                    }
                    WorkerOperation::Freeze => {
                        let payload =
                            resolve_payload_cgroup(&self.cgroup_root, &name.cgroup_path())?;
                        before_effect()?;
                        payload
                            .request_freezer_state(CgroupFreezerState::Frozen)
                            .map_err(|error| HostError::Worker(error.to_string()))?;
                        await_payload_freezer(&payload, CgroupFreezerState::Frozen).await?;
                    }
                    WorkerOperation::Thaw if current.state == ObservedRuntimeState::Ready => {
                        return Ok(current);
                    }
                    WorkerOperation::Thaw => {
                        let payload =
                            resolve_payload_cgroup(&self.cgroup_root, &name.cgroup_path())?;
                        before_effect()?;
                        payload
                            .request_freezer_state(CgroupFreezerState::Thawed)
                            .map_err(|error| HostError::Worker(error.to_string()))?;
                        await_payload_freezer(&payload, CgroupFreezerState::Thawed).await?;
                    }
                    WorkerOperation::Kill => {
                        before_effect()?;
                        client
                            .kill_sandbox_unit(&name)
                            .await
                            .map_err(|error| worker_error(&error))?;
                    }
                    WorkerOperation::Launch { .. } => {
                        return Err(HostError::Worker(
                            "launch operation escaped its reconciliation path".to_owned(),
                        ));
                    }
                }
            }
        }
        self.observe_with_client(&client, &identity).await
    }

    async fn observe(&self, identity: &HostRuntimeIdentity) -> Result<WorkerObservation> {
        let client = SystemdClient::connect()
            .await
            .map_err(|error| worker_error(&error))?;
        self.observe_with_client(&client, identity).await
    }

    async fn refresh_payload_scope(
        &self,
        identity: &HostRuntimeIdentity,
        invocation_id: [u8; 16],
        supervisor: &PinnedLeader,
        payload: &PinnedPayloadLeader,
    ) -> Result<WorkerObservation> {
        let client = SystemdClient::connect()
            .await
            .map_err(|error| worker_error(&error))?;
        let mut observation = self.observe_with_client(&client, identity).await?;
        if !matches!(
            observation.state,
            ObservedRuntimeState::Ready | ObservedRuntimeState::Frozen
        ) || observation.invocation_id != Some(invocation_id)
        {
            return Err(HostError::Worker(
                "retained payload invocation is no longer current".to_owned(),
            ));
        }
        let current_supervisor = observation.leader.as_ref().ok_or_else(|| {
            HostError::Worker("current runtime has no pinned supervisor".to_owned())
        })?;
        if current_supervisor.handle() != supervisor.handle()
            || current_supervisor
                .pidfd
                .info()
                .map_err(|error| HostError::Worker(error.to_string()))?
                != supervisor
                    .pidfd
                    .info()
                    .map_err(|error| HostError::Worker(error.to_string()))?
        {
            return Err(HostError::Worker(
                "retained payload supervisor is no longer current".to_owned(),
            ));
        }

        let current_payload = resolve_payload_root(&self.cgroup_root, &current_supervisor.cgroup)?;
        if current_payload.identity() != payload.cgroup.identity() {
            return Err(HostError::Worker(
                "payload subtree differs from its retained anchor".to_owned(),
            ));
        }
        let root = rustix::fs::fstat(payload.root.as_fd())
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let network = payload.network.identity();
        let supervisor_info = current_supervisor
            .pidfd
            .info()
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let refreshed = inspect_quiesced_payload(&payload.cgroup, |inspector| {
            discover_payload_leader(
                inspector,
                supervisor_info.pid(),
                (root.st_dev, root.st_ino),
                (network.device, network.inode),
            )
        })?;
        if refreshed
            .pidfd
            .info()
            .map_err(|error| HostError::Worker(error.to_string()))?
            != payload
                .pidfd
                .info()
                .map_err(|error| HostError::Worker(error.to_string()))?
            || refreshed.mount.identity() != payload.mount.identity()
            || refreshed.relative_cgroup_hint != payload.relative_cgroup_hint
        {
            return Err(HostError::Worker(
                "payload PID 1 changed since launch verification".to_owned(),
            ));
        }
        refreshed.recheck_kernel(current_supervisor)?;
        observation.payload = Some(refreshed);
        Ok(observation)
    }

    async fn observe_guardian(
        &self,
        identity: &HostRuntimeIdentity,
    ) -> Result<GuardianObservation> {
        let client = SystemdClient::connect()
            .await
            .map_err(|error| worker_error(&error))?;
        self.observe_guardian_with_client(&client, identity).await
    }

    async fn start_guardian(
        &self,
        spec: &GuardianUnitSpec,
        identity: &HostRuntimeIdentity,
        before_effect: &mut (dyn FnMut() -> Result<()> + Send),
    ) -> Result<GuardianStartObservation> {
        let client = SystemdClient::connect()
            .await
            .map_err(|error| worker_error(&error))?;
        let outcome = client
            .start_guardian_unit_guarded(spec, before_effect)
            .await
            .map_err(|error| match error {
                GuardianStartError::Guard(error) => error,
                GuardianStartError::Systemd(error) => worker_error(&error),
            })?;
        let observation = self.observe_guardian_with_client(&client, identity).await?;
        Ok(GuardianStartObservation {
            job_done: outcome.result == JobResult::Done,
            observation,
        })
    }

    async fn observe_bound_payload(
        &self,
        identity: &HostRuntimeIdentity,
    ) -> Result<GuardianObservation> {
        self.observe_bound_role(identity, ExactUnitRole::Payload)
            .await
    }

    async fn start_bound_payload(
        &self,
        spec: &SandboxUnitSpec,
        pins: &LaunchPins,
        identity: &HostRuntimeIdentity,
        guardian_invocation_id: [u8; 16],
        before_effect: &mut (dyn FnMut() -> Result<()> + Send),
    ) -> Result<CurrentJobDone> {
        start_bound_payload_recipe!(self, spec, pins, identity, guardian_invocation_id,
            before_effect, LocalStart, unused)
    }

    async fn prove_bound_payload(
        &self,
        spec: &SandboxUnitSpec,
        pins: &LaunchPins,
        identity: &HostRuntimeIdentity,
    ) -> Result<RecoveredExactProof> {
        prove_bound_payload_recipe!(self, spec, pins, identity, LocalProve, unused)
    }

    async fn recover_completed_payload(
        &self,
        identity: &HostRuntimeIdentity,
        binding: [u8; 32],
        guardian_invocation_id: [u8; 16],
        payload_invocation_id: [u8; 16],
        expected_proof: CompletedRuntimeProof,
    ) -> Result<RecoveredExactProof> {
        let expected_proof = expected_proof.snapshot();
        let guardian_before = self.observe_guardian(identity).await?;
        let payload_before = self.observe_bound_payload(identity).await?;
        require_completed_unit("Guardian", guardian_before, binding, guardian_invocation_id)?;
        require_completed_unit("payload", payload_before, binding, payload_invocation_id)?;

        let client = SystemdClient::connect()
            .await
            .map_err(|error| worker_error(&error))?;
        let mut observation = self.observe_with_client(&client, identity).await?;
        if observation.invocation_id != Some(payload_invocation_id)
            || !matches!(
                observation.state,
                ObservedRuntimeState::Ready | ObservedRuntimeState::Frozen
            )
        {
            return Err(HostError::Worker(
                "completed payload manager identity is no longer live and stable".to_owned(),
            ));
        }
        let supervisor = observation.leader.as_ref().ok_or_else(|| {
            HostError::Worker("completed payload has no pinned supervisor".to_owned())
        })?;
        let supervisor_info = supervisor
            .pidfd
            .process_identity()
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let payload_root = resolve_payload_root(&self.cgroup_root, &supervisor.cgroup)?;
        let payload = inspect_quiesced_payload(&payload_root, |inspector| {
            recover_payload_leader(inspector, supervisor_info.pid(), expected_proof)
        })?;
        payload.recheck_kernel(supervisor)?;
        let proof = runtime_proof_snapshot_with_workspace_mount_id(
            expected_proof.workspace_mount_id,
            supervisor,
            &payload,
        )?;
        if proof != expected_proof {
            return Err(HostError::Worker(
                "recovered runtime differs from its authenticated durable proof".to_owned(),
            ));
        }
        observation.payload = Some(payload);

        let guardian_after = self.observe_guardian(identity).await?;
        let payload_after = self.observe_bound_payload(identity).await?;
        if guardian_after != guardian_before || payload_after != payload_before {
            return Err(HostError::Worker(
                "completed Guardian/payload identity changed during recovery".to_owned(),
            ));
        }
        Ok(RecoveredExactProof {
            verification: BoundPayloadVerification {
                binding: payload_after.binding,
                invocation_id: payload_invocation_id,
                observation,
                proof,
                shifted_payload_inspection: None,
            },
        })
    }

    async fn stop_exact_unit(
        &self,
        identity: &HostRuntimeIdentity,
        role: ExactUnitRole,
        binding: [u8; 32],
        invocation_id: [u8; 16],
    ) -> Result<ExactWorkerStopOutcome> {
        let name = SandboxUnitName::from_incarnation(*identity.incarnation_id());
        let target =
            ExactUnitTarget::new(binding, invocation_id).map_err(|error| worker_error(&error))?;
        let prepared = Mutex::new(None::<PreparedStopQuiescence>);
        let mut prepare = |observation: &ExactUnitObservation| {
            let proof = prepare_stop_quiescence(&self.cgroup_root, observation)?;
            *prepared
                .lock()
                .map_err(|_| HostError::Worker("stop proof lock is poisoned".to_owned()))? =
                Some(proof);
            Ok(())
        };
        let mut confirm = |observation: &ExactUnitObservation| {
            let proof = prepared
                .lock()
                .map_err(|_| HostError::Worker("stop proof lock is poisoned".to_owned()))?
                .take()
                .ok_or_else(|| {
                    HostError::Worker("exact stop lost its pre-submission kernel pins".to_owned())
                })?;
            confirm_stop_quiescence(&self.cgroup_root, observation, proof)
        };
        let outcome = ExactUnitClient::connect()
            .await
            .map_err(|error| worker_error(&error))?
            .stop_exact_unit_prepared(&name, role, target, &mut prepare, &mut confirm)
            .await
            .map_err(|error| match error {
                ExactStopError::Systemd(error) => worker_error(&error),
                ExactStopError::Quiescence(error) => error,
            })?;
        Ok(match outcome {
            ExactStopOutcome::MissingManagerObject => ExactWorkerStopOutcome::Missing,
            ExactStopOutcome::Foreign(observation) => {
                ExactWorkerStopOutcome::Foreign(project_exact_observation(observation))
            }
            ExactStopOutcome::JobFailed(_) => {
                ExactWorkerStopOutcome::Residual(self.observe_bound_role(identity, role).await?)
            }
            ExactStopOutcome::Residual(observation) => {
                ExactWorkerStopOutcome::Residual(project_exact_observation(observation))
            }
            ExactStopOutcome::AwaitingAbsence(observation) => {
                ExactWorkerStopOutcome::AwaitingAbsence(project_exact_observation(observation))
            }
        })
    }

    async fn observe_post_unref(
        &self,
        identity: &HostRuntimeIdentity,
        role: ExactUnitRole,
    ) -> Result<GuardianObservation> {
        let name = SandboxUnitName::from_incarnation(*identity.incarnation_id());
        let observation = ExactUnitClient::connect()
            .await
            .map_err(|error| worker_error(&error))?
            .observe_after_unref(&name, role)
            .await
            .map_err(|error| worker_error(&error))?;
        match observation {
            PostUnrefUnitObservation::Absent => {
                let path = match role {
                    ExactUnitRole::Guardian => name.guardian_cgroup_path(),
                    ExactUnitRole::Payload => name.cgroup_path(),
                };
                self.verify_absent_exact_cgroup(path)?;
                Ok(GuardianObservation {
                    binding: None,
                    invocation_id: None,
                    state: GuardianObservedState::Absent,
                })
            }
            PostUnrefUnitObservation::Present(observation) => {
                Ok(project_exact_observation(observation))
            }
        }
    }
}

fn project_guardian_observation(observation: GuardianUnitObservation) -> GuardianObservation {
    let state = match (
        observation.active_state.as_str(),
        observation.sub_state.as_str(),
    ) {
        ("active", "running") => GuardianObservedState::ActiveRunning,
        ("activating", _) => GuardianObservedState::Activating,
        ("inactive", _) => GuardianObservedState::TerminalInactive,
        ("failed", _) => GuardianObservedState::TerminalFailed,
        _ => GuardianObservedState::Other,
    };
    GuardianObservation {
        binding: observation.binding,
        invocation_id: observation.invocation_id,
        state,
    }
}

fn project_exact_observation(observation: ExactUnitObservation) -> GuardianObservation {
    GuardianObservation {
        binding: observation.binding,
        invocation_id: observation.invocation_id,
        state: match observation.state {
            ExactUnitState::ActiveRunning => GuardianObservedState::ActiveRunning,
            ExactUnitState::Activating => GuardianObservedState::Activating,
            ExactUnitState::TerminalInactive => GuardianObservedState::TerminalInactive,
            ExactUnitState::TerminalFailed => GuardianObservedState::TerminalFailed,
            ExactUnitState::Other => GuardianObservedState::Other,
        },
    }
}

struct PreparedStopQuiescence {
    leader: Option<PidFd>,
    population: CgroupPopulationMonitor,
    expected_path: SandboxCgroupPath,
}

fn prepare_stop_quiescence(
    cgroup_root: &BeneathRoot,
    observation: &ExactUnitObservation,
) -> Result<PreparedStopQuiescence> {
    let expected_path = observation
        .cgroup
        .clone()
        .ok_or_else(|| HostError::Worker("exact stop target has no realized cgroup".to_owned()))?;
    let root = CgroupV2Root::from_owned(
        cgroup_root
            .as_fd()
            .try_clone_to_owned()
            .map_err(|error| HostError::Worker(error.to_string()))?,
    )
    .map_err(|error| HostError::Worker(error.to_string()))?;
    let cgroup = root
        .resolve(Path::new(expected_path.as_str().trim_start_matches('/')))
        .map_err(|error| HostError::Worker(error.to_string()))?;
    let population = cgroup
        .population_monitor()
        .map_err(|error| HostError::Worker(error.to_string()))?;
    let leader = observation
        .main_pid
        .map(|pid| pin_stop_leader(&cgroup, pid))
        .transpose()?;
    Ok(PreparedStopQuiescence {
        leader,
        population,
        expected_path,
    })
}

pub(super) fn pin_stop_leader(cgroup: &RetainedCgroupAnchor, pid: NonZeroU32) -> Result<PidFd> {
    let process = PidFd::open(pid).map_err(|error| HostError::Worker(error.to_string()))?;
    let identity = cgroup
        .verify_exact_membership(&process)
        .map_err(|error| HostError::Worker(error.to_string()))?;
    if identity.pid() != pid.get() || identity.thread_group_id() != pid.get() {
        return Err(HostError::Worker(
            "exact stop MainPID is not its pinned process leader".to_owned(),
        ));
    }
    Ok(process)
}

fn confirm_stop_quiescence(
    cgroup_root: &BeneathRoot,
    observation: &ExactUnitObservation,
    proof: PreparedStopQuiescence,
) -> Result<bool> {
    if !observation.is_intermediate_terminal()
        || observation.cgroup.as_ref() != Some(&proof.expected_path)
    {
        return Ok(false);
    }
    if let Some(leader) = proof.leader
        && leader
            .is_alive()
            .map_err(|error| HostError::Worker(error.to_string()))?
    {
        return Ok(false);
    }
    match proof
        .population
        .state()
        .map_err(|error| HostError::Worker(error.to_string()))?
    {
        CgroupPopulationState::Empty => Ok(true),
        CgroupPopulationState::Populated => Ok(false),
        CgroupPopulationState::Retired => {
            verify_retired_cgroup_absence(cgroup_root, &proof.expected_path)?;
            Ok(true)
        }
    }
}

fn verify_retired_cgroup_absence(
    cgroup_root: &BeneathRoot,
    expected_path: &SandboxCgroupPath,
) -> Result<()> {
    let root = CgroupV2Root::from_owned(
        cgroup_root
            .as_fd()
            .try_clone_to_owned()
            .map_err(|error| HostError::Worker(error.to_string()))?,
    )
    .map_err(|error| HostError::Worker(error.to_string()))?;
    match root.resolve(Path::new(expected_path.as_str().trim_start_matches('/'))) {
        Err(aos_sandbox_linux::Error::Syscall { source, .. })
            if source.raw_os_error() == Some(rustix::io::Errno::NOENT.raw_os_error()) => {}
        Ok(_) => {
            return Err(HostError::Worker(
                "retired exact cgroup path names a replacement object".to_owned(),
            ));
        }
        Err(error) => return Err(HostError::Worker(error.to_string())),
    }
    root.resolve(Path::new("."))
        .map_err(|error| HostError::Worker(error.to_string()))?;
    Ok(())
}

pub(super) fn verify_supervisor_pins(
    cgroup_root: &BeneathRoot,
    pins: &LaunchPins,
    leader: &PinnedLeader,
    _root_policy: PayloadRootContinuityPolicyV1,
) -> Result<PinnedPayloadLeader> {
    // The unforgeable policy witness couples this point-in-time root check to
    // the immutable command which prevents PID 1 and descendants from later
    // replacing their root. Binary identity is checked below before the
    // payload observation is accepted.
    let pidfd = &leader.pidfd;
    let info = pidfd
        .info()
        .map_err(|error| HostError::Worker(error.to_string()))?;
    let executable_path = format!("/proc/{}/exe", info.pid());
    let executable = rustix::fs::open(
        executable_path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| HostError::Worker(error.to_string()))?;
    let expected = rustix::fs::fstat(pins.executable())
        .map_err(|error| HostError::Worker(error.to_string()))?;
    let observed =
        rustix::fs::fstat(&executable).map_err(|error| HostError::Worker(error.to_string()))?;
    if (expected.st_dev, expected.st_ino) != (observed.st_dev, observed.st_ino) {
        return Err(HostError::Worker(
            "nspawn supervisor executable differs from its pin".to_owned(),
        ));
    }

    let network = pidfd
        .namespace(NamespaceKind::Network)
        .map_err(|error| HostError::Worker(error.to_string()))?;
    if network.identity() != pins.network().identity() {
        return Err(HostError::Worker(
            "nspawn supervisor network namespace differs from its pin".to_owned(),
        ));
    }
    let root = rustix::fs::fstat(pins.workspace())
        .map_err(|error| HostError::Worker(error.to_string()))?;
    let exported_root = rustix::fs::fstat(pins.transferred_root())
        .map_err(|error| HostError::Worker(error.to_string()))?;
    if (root.st_dev, root.st_ino) != (exported_root.st_dev, exported_root.st_ino) {
        return Err(HostError::Worker(
            "exported root mount differs from the retained workspace".to_owned(),
        ));
    }
    let network = pins.network().identity();
    let payload_root = resolve_payload_root(cgroup_root, &leader.cgroup)?;
    let payload = inspect_quiesced_payload(&payload_root, |inspector| {
        discover_payload_leader(
            inspector,
            info.pid(),
            (root.st_dev, root.st_ino),
            (network.device, network.inode),
        )
    })?;
    // The nspawn supervisor deliberately remains outside the guest root, so
    // `/proc/<supervisor>/root` is not evidence for the container root. The
    // root guarantee here is instead the owned descriptor transferred through
    // the fixed supervisor-only root FD role and retained until this
    // post-start check. Guest-root comparison must wait for payload PID 1
    // discovery and pinning; treating the supervisor root as equivalent would
    // be a false proof.
    if !payload
        .pidfd()
        .is_alive()
        .map_err(|error| HostError::Worker(error.to_string()))?
    {
        return Err(HostError::Worker(
            "payload PID 1 exited during launch identity validation".to_owned(),
        ));
    }
    if !pidfd
        .is_alive()
        .map_err(|error| HostError::Worker(error.to_string()))?
    {
        return Err(HostError::Worker(
            "nspawn supervisor exited during launch identity validation".to_owned(),
        ));
    }
    payload.recheck_kernel(leader)?;
    Ok(payload)
}

fn runtime_proof_snapshot(
    pins: &LaunchPins,
    supervisor: &PinnedLeader,
    payload: &PinnedPayloadLeader,
) -> Result<RuntimeProofSnapshot> {
    let workspace_mount_id = MountId::from_fd(pins.workspace())
        .map_err(|error| HostError::Worker(error.to_string()))?
        .get();
    runtime_proof_snapshot_with_workspace_mount_id(workspace_mount_id, supervisor, payload)
}

pub(crate) fn runtime_proof_snapshot_with_workspace_mount_id(
    workspace_mount_id: u64,
    supervisor: &PinnedLeader,
    payload: &PinnedPayloadLeader,
) -> Result<RuntimeProofSnapshot> {
    let supervisor_identity = supervisor
        .pidfd
        .process_identity()
        .map_err(|error| HostError::Worker(error.to_string()))?;
    let payload_identity = payload
        .pidfd
        .process_identity()
        .map_err(|error| HostError::Worker(error.to_string()))?;
    let supervisor_cgroup_id = supervisor_identity
        .cgroup_id()
        .ok_or_else(|| HostError::Worker("kernel omitted supervisor cgroup identity".to_owned()))?;
    let payload_cgroup_id = payload_identity
        .cgroup_id()
        .ok_or_else(|| HostError::Worker("kernel omitted payload cgroup identity".to_owned()))?;
    let payload_root_mount_id = MountId::from_fd(payload.root.as_fd())
        .map_err(|error| HostError::Worker(error.to_string()))?
        .get();
    let network = payload.network.identity();
    let mount = payload.mount.identity();
    let user = payload.user.identity();
    let snapshot = RuntimeProofSnapshot {
        host_boot_id: KernelBootId::current()
            .map_err(|error| HostError::Worker(error.to_string()))?
            .into_bytes(),
        supervisor: ProcessProofSnapshot {
            pid: supervisor_identity.pid(),
            thread_group_id: supervisor_identity.thread_group_id(),
            parent_pid: supervisor_identity.parent_pid(),
            cgroup_id: supervisor_cgroup_id,
            start_time_ticks: supervisor_identity.start_time_ticks(),
        },
        payload: ProcessProofSnapshot {
            pid: payload_identity.pid(),
            thread_group_id: payload_identity.thread_group_id(),
            parent_pid: payload_identity.parent_pid(),
            cgroup_id: payload_cgroup_id,
            start_time_ticks: payload_identity.start_time_ticks(),
        },
        supervisor_cgroup_id,
        payload_cgroup_id,
        workspace_mount_id,
        payload_root_mount_id,
        network_namespace: NamespaceProofSnapshot {
            device: network.device,
            inode: network.inode,
        },
        mount_namespace: NamespaceProofSnapshot {
            device: mount.device,
            inode: mount.inode,
        },
        user_namespace: NamespaceProofSnapshot {
            device: user.device,
            inode: user.inode,
        },
    };
    if !snapshot.validate() {
        return Err(HostError::Worker(
            "bound payload kernel proof contains a sentinel or contradiction".to_owned(),
        ));
    }
    Ok(snapshot)
}

fn require_completed_unit(
    role: &str,
    observation: GuardianObservation,
    binding: [u8; 32],
    invocation_id: [u8; 16],
) -> Result<()> {
    if observation.binding != Some(binding)
        || observation.invocation_id != Some(invocation_id)
        || observation.state != GuardianObservedState::ActiveRunning
    {
        return Err(HostError::Worker(format!(
            "completed {role} no longer matches its exact active durable identity"
        )));
    }
    Ok(())
}

fn resolve_payload_root(
    cgroup_root: &BeneathRoot,
    service: &SandboxCgroupPath,
) -> Result<BeneathRoot> {
    let payload = service.payload_subgroup();
    let relative = payload.as_str().trim_start_matches('/');
    let resolved = cgroup_root
        .resolve(Path::new(relative), ResolveOptions::directory())
        .map_err(|error| HostError::Worker(error.to_string()))?;
    BeneathRoot::from_resolved(resolved).map_err(|error| HostError::Worker(error.to_string()))
}

fn resolve_payload_cgroup(
    cgroup_root: &BeneathRoot,
    service: &SandboxCgroupPath,
) -> Result<RetainedCgroupAnchor> {
    let payload = resolve_payload_root(cgroup_root, service)?;
    CgroupV2Root::try_from(payload)
        .and_then(|root| root.resolve(Path::new(".")))
        .map_err(|error| HostError::Worker(error.to_string()))
}

fn inspect_quiesced_payload<T>(
    payload_root: &BeneathRoot,
    inspect: impl FnOnce(&LinuxPayloadInspector<'_>) -> Result<T>,
) -> Result<T> {
    // A normal payload may fork continuously. Freeze only its delegated
    // subtree so the two bounded process snapshots form one stable proof while
    // the nspawn supervisor remains available to the host.
    let root = CgroupV2Root::from_owned(
        payload_root
            .as_fd()
            .try_clone_to_owned()
            .map_err(|error| HostError::Worker(error.to_string()))?,
    )
    .map_err(|error| HostError::Worker(error.to_string()))?;
    let payload = root
        .resolve(Path::new("."))
        .map_err(|error| HostError::Worker(error.to_string()))?;
    let initial_state = payload
        .freezer_state()
        .map_err(|error| HostError::Worker(error.to_string()))?;

    if initial_state == CgroupFreezerState::Thawed {
        payload
            .request_freezer_state(CgroupFreezerState::Frozen)
            .map_err(|error| HostError::Worker(error.to_string()))?;
        await_payload_freezer_blocking(&payload, CgroupFreezerState::Frozen)?;
    }

    let result = inspect(&LinuxPayloadInspector { payload_root });
    if initial_state == CgroupFreezerState::Frozen {
        return result;
    }

    let thaw = payload
        .request_freezer_state(CgroupFreezerState::Thawed)
        .map_err(|error| HostError::Worker(error.to_string()))
        .and_then(|()| await_payload_freezer_blocking(&payload, CgroupFreezerState::Thawed));
    match (result, thaw) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(primary), Err(cleanup)) => Err(HostError::Worker(format!(
            "{primary}; additionally failed to thaw payload after inspection: {cleanup}"
        ))),
    }
}

fn await_payload_freezer_blocking(
    payload: &RetainedCgroupAnchor,
    expected: CgroupFreezerState,
) -> Result<()> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        let observed = payload
            .freezer_state()
            .map_err(|error| HostError::Worker(error.to_string()))?;
        if observed == expected {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(HostError::Worker(format!(
                "payload cgroup did not reach {expected:?} freezer state"
            )));
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

async fn await_payload_freezer(
    payload: &RetainedCgroupAnchor,
    expected: CgroupFreezerState,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        let observed = payload
            .freezer_state()
            .map_err(|error| HostError::Worker(error.to_string()))?;
        if observed == expected {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(HostError::Worker(format!(
                "payload cgroup did not reach {expected:?} freezer state"
            )));
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}
