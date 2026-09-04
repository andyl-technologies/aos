//! Durable ordering and replay for fixed host runtime effects.

use std::collections::BTreeMap;

use aos_proto::aos::sandbox::local::v1::{
    AssignmentFence, InventoryRuntimeResponse, RuntimeAction, RuntimeObservation, RuntimeState,
};
use aos_sandbox_broker::{BrokerAuthorizationFenceV1, BrokerEffectIntentV2, BrokerEffectStatusV2};
use aos_sandbox_core::{ProtocolVersion, RawPairedClockSample};
use aos_sandbox_linux::pidfd::PidFd;
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;
use aos_sandbox_protocol::{
    PeerCredentials, PeerPolicy, ValidatedAssignmentFence, ValidatedRuntimeRequest,
    decode_runtime_request,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::authorization::HostAuthorityV1;
use crate::authorization::semantics_v1::runtime_handle_v1;
use crate::plan::{HostCatalog, NspawnConfig, ResolvedLaunchResources};
use crate::state::{Admission, HostState, HostStateStore};
use crate::worker::{
    HostRuntimeIdentity, HostWorker, ObservedRuntimeState, PinnedLeader, WorkerObservation,
    WorkerOperation,
};
use crate::{HostError, Result};

const MAXIMUM_INVENTORY_RUNTIMES: usize = 1_024;

/// Applies validated runtime requests through durable fixed-function effects.
pub struct HostBroker<C, S, W> {
    catalog: C,
    store: S,
    worker: W,
    authority: HostAuthorityV1,
    nspawn: Option<NspawnConfig>,
    state: HostState,
    leaders: BTreeMap<[u8; 32], PidFd>,
}

impl<C, S, W> HostBroker<C, S, W>
where
    C: HostCatalog,
    S: HostStateStore,
    W: HostWorker,
{
    /// Loads durable state and constructs a broker with no inherited handles.
    ///
    /// # Errors
    ///
    /// Returns an error when the state snapshot is unavailable or invalid.
    pub fn open(
        catalog: C,
        store: S,
        worker: W,
        nspawn: Option<NspawnConfig>,
        authority: HostAuthorityV1,
    ) -> Result<Self> {
        let state = store.load()?;
        state.validate_authenticated(&authority)?;
        Ok(Self {
            catalog,
            store,
            worker,
            authority,
            nspawn,
            state,
            leaders: BTreeMap::new(),
        })
    }

    /// Reports whether phase-0 evidence permits this process to advertise launch.
    #[must_use]
    pub const fn launch_available(&self) -> bool {
        self.nspawn.is_some()
    }

    /// Validates, fences, applies, and durably completes one runtime request.
    ///
    /// The caller must supply credentials read from the accepted Unix socket,
    /// never serialized peer claims. Returned bytes are a bounded
    /// `RuntimeObservation` protobuf suitable for one `SOCK_SEQPACKET` reply.
    ///
    /// # Errors
    ///
    /// Returns an error before effects for hostile input, peer mismatch,
    /// stale/equivocating fences, request-ID conflicts, or catalog failures.
    /// Worker and durable-state failures leave a persisted pending intent that
    /// the exact request can safely reconcile.
    pub async fn apply_runtime(
        &mut self,
        request_bytes: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        mut trusted_clock: impl FnMut() -> Result<RawPairedClockSample> + Send,
    ) -> Result<Vec<u8>> {
        if protocol_version != ProtocolVersion::new(1, 1) {
            return Err(HostError::Authority(
                aos_sandbox_broker::BrokerAdmissionError::RequestMismatch,
            ));
        }
        // Deadline-free decoding is used only to locate an already authenticated
        // complete record. No pending or new effect consumes this value.
        let replay_request = decode_runtime_request(request_bytes, peer, policy, 0)?;
        let request_id = *replay_request.header().request_id();
        let request_digest: [u8; 32] = Sha256::digest(request_bytes).into();

        let existing_effect = self
            .state
            .effect(&request_id)
            .map(|bytes| self.authority.open_effect(&request_id, bytes))
            .transpose()?;
        if let Some(effect) = &existing_effect {
            validate_effect_request(effect, request_digest)?;
            if effect.status() == BrokerEffectStatusV2::Complete {
                return Ok(effect.receipt().to_vec());
            }
        }

        let admission_clock = trusted_clock()?;
        let request = decode_runtime_request(
            request_bytes,
            peer,
            policy,
            admission_clock.boottime_nanoseconds(),
        )?;
        let action = action_code(request.action());

        let operation = self.compile_operation(&request)?;
        let prior_fence_bytes = if existing_effect.is_some() {
            self.state.request_authorization(&request_id)
        } else {
            self.state.prior_authorization(request.fence().sandbox_id())
        };
        let pending_fence = if existing_effect.is_some() {
            Some(self.authority.open_fence(
                request.fence().sandbox_id(),
                prior_fence_bytes.ok_or_else(|| {
                    HostError::State(
                        "pending request lost its authenticated assignment fence".to_owned(),
                    )
                })?,
            )?)
        } else {
            None
        };
        let admitted = self.authority.admit(
            artifacts,
            &request,
            request_bytes,
            protocol_version,
            &admission_clock,
            prior_fence_bytes,
        )?;
        if let Some(existing) = &existing_effect {
            validate_effect_refresh(existing, &admitted.effect)?;
            validate_pending_fence_refresh(
                pending_fence.as_ref().ok_or_else(|| {
                    HostError::State("pending request has no authenticated fence".to_owned())
                })?,
                &admitted.fence,
            )?;
        }
        let sealed_fence = self
            .authority
            .seal_fence(request.fence().sandbox_id(), &admitted.fence)?;
        let sealed_effect = self.authority.seal_effect(&request_id, &admitted.effect)?;

        let mut proposed = self.state.clone();
        match proposed.admit(
            request.fence(),
            request_id,
            request_digest,
            action,
            sealed_fence,
            sealed_effect,
        )? {
            Admission::New | Admission::Pending => {}
            Admission::Complete(_) => {
                return Err(HostError::Fence(
                    "completed replay status contradicts authenticated effect",
                ));
            }
        }
        self.store.commit(&proposed)?;
        self.state = proposed.clone();

        let effect = admitted.effect;
        let observation = {
            let authority = &self.authority;
            let mut before_effect = || {
                authority
                    .check_before_effect(&effect, &mut || {
                        trusted_clock()
                            .map_err(|_| aos_sandbox_broker::BrokerAdmissionError::FenceRejected)
                    })
                    .map_err(HostError::from)
            };
            self.worker
                .execute(request.fence(), operation, &mut before_effect)
                .await?
        };
        let sequence = proposed.next_observation_sequence(*request.fence().incarnation_id())?;
        let response = self.encode_observation(request.fence(), sequence, observation)?;
        let response_limit = usize::try_from(request.header().maximum_response_bytes())
            .map_err(|_| HostError::State("response limit does not fit usize".to_owned()))?;
        if response.len() > response_limit {
            return Err(HostError::State(
                "runtime observation exceeds the admitted response bound".to_owned(),
            ));
        }
        let completed = effect
            .complete(response.clone())
            .map_err(|_| HostError::Fence("completed host effect is invalid"))?;
        let sealed_completed = self.authority.seal_effect(&request_id, &completed)?;
        proposed.complete(
            request_id,
            request_digest,
            sealed_completed,
            response.clone(),
        )?;
        self.store.commit(&proposed)?;
        self.state = proposed;
        Ok(response)
    }

    /// Resolves a live leader handle retained by this broker process.
    ///
    /// Handles intentionally expire across broker restart and are never
    /// serialized as descriptor integers.
    #[must_use]
    pub fn leader(&self, handle: &[u8; 32]) -> Option<&PidFd> {
        self.leaders.get(handle)
    }

    pub(crate) async fn observe_runtime(
        &mut self,
        identity: HostRuntimeIdentity,
        supplied_handle: [u8; 32],
        maximum_response_bytes: u32,
    ) -> Result<Vec<u8>> {
        if runtime_handle(&identity) != supplied_handle || !self.state.contains_runtime(&identity) {
            return Err(HostError::UnknownHandle);
        }
        let observation = self.worker.observe(&identity).await?;
        let mut proposed = self.state.clone();
        let sequence = proposed.next_observation_sequence(*identity.incarnation_id())?;
        let (response, leader) = project_observation(&identity, sequence, observation);
        let bytes = response.encode_to_vec();
        ensure_response_bound(&bytes, maximum_response_bytes)?;

        self.store.commit(&proposed)?;
        self.state = proposed;
        self.retain_leader(leader);
        Ok(bytes)
    }

    pub(crate) async fn inventory_runtime(
        &mut self,
        maximum_response_bytes: u32,
    ) -> Result<Vec<u8>> {
        let identities = self.state.runtime_inventory();
        if identities.len() > MAXIMUM_INVENTORY_RUNTIMES {
            return Err(HostError::ResourceExhausted);
        }
        let mut identities = identities
            .into_iter()
            .map(|identity| (runtime_handle(&identity), identity))
            .collect::<Vec<_>>();
        identities.sort_unstable();

        let mut proposed = self.state.clone();
        let mut runtimes = Vec::with_capacity(identities.len());
        let mut leaders = Vec::new();
        for (_, identity) in identities {
            let observation = self.worker.observe(&identity).await?;
            let sequence = proposed.next_observation_sequence(*identity.incarnation_id())?;
            let (runtime, leader) = project_observation(&identity, sequence, observation);
            runtimes.push(runtime);
            if let Some(leader) = leader {
                leaders.push(leader);
            }
        }
        let bytes = InventoryRuntimeResponse {
            runtimes,
            ..Default::default()
        }
        .encode_to_vec();
        ensure_response_bound(&bytes, maximum_response_bytes)?;

        self.store.commit(&proposed)?;
        self.state = proposed;
        for leader in leaders {
            self.retain_leader(Some(leader));
        }
        Ok(bytes)
    }

    fn compile_operation(&self, request: &ValidatedRuntimeRequest) -> Result<WorkerOperation> {
        Ok(match request.action() {
            RuntimeAction::RUNTIME_ACTION_LAUNCH => {
                let nspawn = self.nspawn.as_ref().ok_or_else(|| {
                    HostError::InvalidPlan("nspawn backend readiness is unavailable".to_owned())
                })?;
                let plan = request.launch_plan().ok_or(HostError::InvalidPlan(
                    "validated launch request lost its launch plan".to_owned(),
                ))?;
                let resolved: ResolvedLaunchResources =
                    self.catalog.resolve(request.fence(), plan)?;
                WorkerOperation::Launch(Box::new(nspawn.compile_resolved(
                    request.fence(),
                    plan,
                    resolved,
                )?))
            }
            RuntimeAction::RUNTIME_ACTION_STOP => WorkerOperation::Stop,
            RuntimeAction::RUNTIME_ACTION_FREEZE => WorkerOperation::Freeze,
            RuntimeAction::RUNTIME_ACTION_THAW => WorkerOperation::Thaw,
            RuntimeAction::RUNTIME_ACTION_KILL => WorkerOperation::Kill,
            RuntimeAction::RUNTIME_ACTION_UNSPECIFIED => {
                return Err(HostError::InvalidPlan(
                    "validated request contains unspecified action".to_owned(),
                ));
            }
        })
    }

    fn encode_observation(
        &mut self,
        fence: &ValidatedAssignmentFence,
        sequence: u64,
        observation: WorkerObservation,
    ) -> Result<Vec<u8>> {
        let identity = HostRuntimeIdentity::from(fence);
        let (response, leader) = project_observation(&identity, sequence, observation);
        let bytes = response.encode_to_vec();
        self.retain_leader(leader);
        if bytes.is_empty() {
            return Err(HostError::State(
                "runtime observation encoded to an empty receipt".to_owned(),
            ));
        }
        Ok(bytes)
    }

    fn retain_leader(&mut self, leader: Option<PinnedLeader>) {
        if let Some(leader) = leader {
            let (handle, pidfd) = leader.into_parts();
            self.leaders.insert(handle, pidfd);
        }
    }
}

fn project_observation(
    identity: &HostRuntimeIdentity,
    sequence: u64,
    observation: WorkerObservation,
) -> (RuntimeObservation, Option<PinnedLeader>) {
    let mut response = RuntimeObservation {
        runtime_handle: runtime_handle(identity).to_vec(),
        fence: Some(AssignmentFence {
            sandbox_id: identity.sandbox_id().to_vec(),
            incarnation_id: identity.incarnation_id().to_vec(),
            assignment_epoch: identity.assignment_epoch(),
            desired_generation: identity.desired_generation(),
            assignment_digest: identity.assignment_digest().to_vec(),
            ..Default::default()
        })
        .into(),
        state: protocol_state(observation.state).into(),
        observation_sequence: sequence,
        ..Default::default()
    };
    if let Some(leader) = &observation.leader {
        response.leader_handle = leader.handle().to_vec();
    }
    (response, observation.leader)
}

fn ensure_response_bound(bytes: &[u8], maximum_response_bytes: u32) -> Result<()> {
    let maximum = usize::try_from(maximum_response_bytes)
        .map_err(|_| HostError::State("response limit does not fit usize".to_owned()))?;
    if bytes.len() > maximum {
        return Err(HostError::ResourceExhausted);
    }
    Ok(())
}

fn validate_effect_request(effect: &BrokerEffectIntentV2, request_digest: [u8; 32]) -> Result<()> {
    if effect.transport_request_digest().as_bytes() != &request_digest {
        return Err(HostError::Fence(
            "request ID was reused with different transport bytes",
        ));
    }
    Ok(())
}

fn validate_effect_refresh(
    existing: &BrokerEffectIntentV2,
    refreshed: &BrokerEffectIntentV2,
) -> Result<()> {
    if existing.status() != BrokerEffectStatusV2::Pending
        || existing.transport_request_digest() != refreshed.transport_request_digest()
        || existing.request_digest() != refreshed.request_digest()
        || existing.verb() != refreshed.verb()
        || existing.target() != refreshed.target()
    {
        return Err(HostError::Fence(
            "pending replay changed its authenticated effect semantics",
        ));
    }
    Ok(())
}

fn validate_pending_fence_refresh(
    existing: &BrokerAuthorizationFenceV1,
    refreshed: &BrokerAuthorizationFenceV1,
) -> Result<()> {
    if existing.assignment() != refreshed.assignment()
        || existing.node() != refreshed.node()
        || existing.plan_digest() != refreshed.plan_digest()
        || existing.ownership_authority() != refreshed.ownership_authority()
    {
        return Err(HostError::Fence(
            "pending replay changed its authenticated authority lineage",
        ));
    }
    Ok(())
}

fn action_code(action: RuntimeAction) -> u8 {
    match action {
        RuntimeAction::RUNTIME_ACTION_LAUNCH => 1,
        RuntimeAction::RUNTIME_ACTION_STOP => 2,
        RuntimeAction::RUNTIME_ACTION_FREEZE => 3,
        RuntimeAction::RUNTIME_ACTION_THAW => 4,
        RuntimeAction::RUNTIME_ACTION_KILL => 5,
        RuntimeAction::RUNTIME_ACTION_UNSPECIFIED => 0,
    }
}

fn protocol_state(state: ObservedRuntimeState) -> RuntimeState {
    match state {
        ObservedRuntimeState::Absent => RuntimeState::RUNTIME_STATE_ABSENT,
        ObservedRuntimeState::Starting => RuntimeState::RUNTIME_STATE_STARTING,
        ObservedRuntimeState::Ready => RuntimeState::RUNTIME_STATE_READY,
        ObservedRuntimeState::Frozen => RuntimeState::RUNTIME_STATE_FROZEN,
        ObservedRuntimeState::Stopping => RuntimeState::RUNTIME_STATE_STOPPING,
        ObservedRuntimeState::Exited => RuntimeState::RUNTIME_STATE_EXITED,
        ObservedRuntimeState::Failed => RuntimeState::RUNTIME_STATE_FAILED,
    }
}

fn runtime_handle(identity: &HostRuntimeIdentity) -> [u8; 32] {
    runtime_handle_v1(
        identity.incarnation_id(),
        identity.assignment_epoch(),
        identity.assignment_digest(),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use aos_proto::aos::sandbox::local::v1::{
        ApplyRuntimeRequest, Audience, BrokerAuthorizationArtifactsV1, BrokerMethod,
        BrokerRequestEnvelope, Feature, ResourceLimit,
    };
    use aos_sandbox_core::format::{
        encode_broker_authorization_plan, encode_ownership_lease, encode_signature,
        encode_trust_policy,
    };
    use aos_sandbox_core::model::{
        KeyReference, KeyUsage, SignaturePurpose, SignatureStatement, StableKeyId, TrustPolicy,
    };
    use aos_sandbox_core::{
        AssignmentEpoch, BrokerAssignment, BrokerAudience, BrokerAuthorizationPlan, BrokerGrant,
        DecodeLimits, DesiredGeneration, IncarnationId, LeaseAssignment, MediaType, NodeId,
        ObjectDigest, OwnershipLease, OwnershipLeaseTrustAnchor, PortableMediaType, ProtocolId,
        RawClockProvenance, RevocationScopeId, SandboxId, TrustScopeId, descriptor_for_bytes,
        sign_statement,
    };
    use aos_sandbox_protocol::session::decode_request_envelope;
    use async_trait::async_trait;
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::plan::{
        ResolvedIdentityAllocation, ResolvedLaunchResources, ResolvedNetwork, ResolvedWorkspace,
    };

    #[derive(Clone, Default)]
    struct MemoryStore(Arc<Mutex<HostState>>);

    impl HostStateStore for MemoryStore {
        fn load(&self) -> Result<HostState> {
            Ok(self.0.lock().unwrap().clone())
        }

        fn commit(&self, state: &HostState) -> Result<()> {
            *self.0.lock().unwrap() = state.clone();
            Ok(())
        }
    }

    struct FixedCatalog;

    impl HostCatalog for FixedCatalog {
        fn resolve(
            &self,
            _fence: &ValidatedAssignmentFence,
            plan: &aos_sandbox_protocol::ValidatedRuntimePlan,
        ) -> Result<ResolvedLaunchResources> {
            if plan.workspace_handle() != &[6; 32] {
                return Err(HostError::Catalog("unknown workspace".to_owned()));
            }
            if plan.network_handle() != &[7; 32] {
                return Err(HostError::Catalog("unknown network".to_owned()));
            }
            Ok(ResolvedLaunchResources {
                workspace: ResolvedWorkspace {
                    root_directory: "/run/aos/sandbox-pins/workspaces/test-root".to_owned(),
                    device: 1,
                    inode: 2,
                },
                network: ResolvedNetwork {
                    namespace_path: "/run/aos/sandbox-pins/netns/test-net".to_owned(),
                    device: 3,
                    inode: 4,
                },
                identity: ResolvedIdentityAllocation {
                    range_start: 65_536,
                    range_size: 65_536,
                    catalog_generation: 1,
                },
            })
        }
    }

    #[derive(Clone, Default)]
    struct FakeWorker {
        calls: Arc<AtomicUsize>,
        fail_next: Arc<AtomicBool>,
        observe_calls: Arc<Mutex<Vec<[u8; 16]>>>,
        fail_observe_at: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl HostWorker for FakeWorker {
        async fn execute(
            &self,
            fence: &ValidatedAssignmentFence,
            operation: WorkerOperation,
            before_effect: &mut (dyn FnMut() -> Result<()> + Send),
        ) -> Result<WorkerObservation> {
            let WorkerOperation::Launch(spec) = operation else {
                panic!("test expected launch operation");
            };
            assert_eq!(
                spec.executable(),
                "/nix/store/aos-systemd/bin/systemd-nspawn"
            );
            let expected_machine = format!(
                "--machine=aos-{}",
                fence
                    .incarnation_id()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            );
            let expected_arguments = [
                "--boot",
                "--quiet",
                "--keep-unit",
                "--register=no",
                "--settings=no",
                expected_machine.as_str(),
                "--directory=/run/aos/sandbox-pins/workspaces/test-root",
                "--private-users=65536:65536",
                "--private-users-ownership=map",
                "--notify-ready=yes",
                "--selinux-context=system_u:system_r:aos_sandbox_payload_t:s0",
                "--no-new-privileges=yes",
                "--drop-capability=CAP_AUDIT_CONTROL,CAP_AUDIT_READ,CAP_AUDIT_WRITE,CAP_BLOCK_SUSPEND,CAP_BPF,CAP_CHECKPOINT_RESTORE,CAP_DAC_READ_SEARCH,CAP_IPC_LOCK,CAP_IPC_OWNER,CAP_LEASE,CAP_LINUX_IMMUTABLE,CAP_MAC_ADMIN,CAP_MAC_OVERRIDE,CAP_MKNOD,CAP_NET_ADMIN,CAP_NET_BROADCAST,CAP_NET_RAW,CAP_PERFMON,CAP_SYSLOG,CAP_SYS_ADMIN,CAP_SYS_BOOT,CAP_SYS_CHROOT,CAP_SYS_MODULE,CAP_SYS_NICE,CAP_SYS_PACCT,CAP_SYS_PTRACE,CAP_SYS_RAWIO,CAP_SYS_RESOURCE,CAP_SYS_TIME,CAP_SYS_TTY_CONFIG,CAP_WAKE_ALARM",
                "--system-call-filter=~@mount @module @raw-io @reboot bpf perf_event_open ptrace setns unshare",
                "--aos-payload-seccomp-profile=aos-sandbox-payload-v1",
            ];
            assert_eq!(spec.arguments(), expected_arguments);
            assert_eq!(
                spec.root_directory(),
                "/run/aos/sandbox-pins/workspaces/test-root"
            );
            assert_eq!(
                spec.network_namespace_path(),
                "/run/aos/sandbox-pins/netns/test-net"
            );
            before_effect()?;
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_next.swap(false, Ordering::SeqCst) {
                return Err(HostError::Worker("injected crash boundary".to_owned()));
            }
            Ok(WorkerObservation {
                state: ObservedRuntimeState::Ready,
                invocation_id: Some([9; 16]),
                leader: None,
            })
        }

        async fn observe(&self, identity: &HostRuntimeIdentity) -> Result<WorkerObservation> {
            let call = {
                let mut calls = self.observe_calls.lock().unwrap();
                calls.push(*identity.sandbox_id());
                calls.len()
            };
            if self.fail_observe_at.load(Ordering::SeqCst) == call {
                return Err(HostError::Worker("injected observation failure".to_owned()));
            }
            Ok(WorkerObservation {
                state: ObservedRuntimeState::Ready,
                invocation_id: Some([9; 16]),
                leader: None,
            })
        }
    }

    fn nspawn() -> NspawnConfig {
        NspawnConfig::for_tests("/nix/store/aos-systemd/bin/systemd-nspawn").unwrap()
    }

    fn policy() -> PeerPolicy {
        PeerPolicy {
            uid: 100,
            gid: Some(200),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        }
    }

    fn peer() -> PeerCredentials {
        PeerCredentials {
            uid: 100,
            gid: 200,
            pid: Some(300),
        }
    }

    const TEST_NODE: NodeId = NodeId::from_bytes([31; 16]);
    const TEST_WALL_SECONDS: i64 = 150;
    const TEST_BOOTTIME_NANOSECONDS: u64 = 100;

    struct AuthorityFixture {
        plan_key: SigningKey,
        lease_key: SigningKey,
        alternate_lease_key: SigningKey,
        plan_signer: KeyReference,
        lease_signer: KeyReference,
        alternate_lease_signer: KeyReference,
        plan_policy: Vec<u8>,
        plan_policy_descriptor: aos_sandbox_core::ObjectDescriptor,
        plan_scope: TrustScopeId,
        lease_policy: Vec<u8>,
        lease_policy_descriptor: aos_sandbox_core::ObjectDescriptor,
        lease_scope: TrustScopeId,
        revocation_scope: RevocationScopeId,
    }

    impl AuthorityFixture {
        fn new() -> Self {
            let plan_key = SigningKey::from_bytes(&[41; 32]);
            let lease_key = SigningKey::from_bytes(&[42; 32]);
            let alternate_lease_key = SigningKey::from_bytes(&[52; 32]);
            let plan_signer = key_reference(
                "host-plan-controller",
                3,
                KeyUsage::BrokerAuthorization,
                &plan_key,
            );
            let lease_signer = key_reference(
                "host-ownership-authority",
                7,
                KeyUsage::OwnershipLease,
                &lease_key,
            );
            let alternate_lease_signer = key_reference(
                "host-ownership-alternate",
                8,
                KeyUsage::OwnershipLease,
                &alternate_lease_key,
            );
            let plan_scope = TrustScopeId::from_bytes([43; 16]);
            let lease_scope = TrustScopeId::from_bytes([44; 16]);
            let (plan_policy, plan_policy_descriptor) = trust_policy(
                plan_scope,
                SignaturePurpose::BrokerAuthorization,
                plan_signer.clone(),
            );
            let (lease_policy, lease_policy_descriptor) = trust_policy_many(
                lease_scope,
                SignaturePurpose::OwnershipLease,
                vec![lease_signer.clone(), alternate_lease_signer.clone()],
            );
            Self {
                plan_key,
                lease_key,
                alternate_lease_key,
                plan_signer,
                lease_signer,
                alternate_lease_signer,
                plan_policy,
                plan_policy_descriptor,
                plan_scope,
                lease_policy,
                lease_policy_descriptor,
                lease_scope,
                revocation_scope: RevocationScopeId::from_bytes([45; 16]),
            }
        }

        fn authority(&self) -> HostAuthorityV1 {
            let plan_anchor = aos_sandbox_core::BrokerPlanTrustAnchor::from_trusted_configuration(
                self.plan_policy.clone(),
                self.plan_policy_descriptor.clone(),
                self.plan_scope,
                self.plan_signer.clone(),
                self.plan_key.verifying_key().to_bytes(),
                self.revocation_scope,
                DecodeLimits::default(),
            )
            .unwrap();
            let lease_anchor = OwnershipLeaseTrustAnchor::from_trusted_configuration(
                self.lease_policy.clone(),
                self.lease_policy_descriptor.clone(),
                self.lease_scope,
                self.lease_signer.clone(),
                self.lease_key.verifying_key().to_bytes(),
                DecodeLimits::default(),
            )
            .unwrap();
            HostAuthorityV1::new(plan_anchor, lease_anchor, TEST_NODE, [46; 16], [47; 32]).unwrap()
        }

        fn artifacts(
            &self,
            request_bytes: &[u8],
            lease_generation: u64,
        ) -> ValidatedUntrustedAuthorizationArtifacts {
            self.artifacts_with_lease_authority(request_bytes, lease_generation, false)
        }

        fn artifacts_with_lease_authority(
            &self,
            request_bytes: &[u8],
            lease_generation: u64,
            alternate: bool,
        ) -> ValidatedUntrustedAuthorizationArtifacts {
            let validated =
                decode_runtime_request(request_bytes, peer(), policy(), TEST_BOOTTIME_NANOSECONDS)
                    .unwrap();
            let semantics =
                crate::authorization::semantics_v1::canonical_host_semantics_v1(&validated)
                    .unwrap();
            let assignment = BrokerAssignment::new(
                SandboxId::from_bytes(*validated.fence().sandbox_id()),
                IncarnationId::from_bytes(*validated.fence().incarnation_id()),
                AssignmentEpoch::new(validated.fence().assignment_epoch()),
                DesiredGeneration::new(validated.fence().desired_generation()),
                ObjectDigest::from_bytes(*validated.fence().assignment_digest()),
            )
            .unwrap();
            let grant = BrokerGrant::new(
                semantics.verb(),
                semantics.target(),
                semantics.commitment(),
                u32::try_from(request_bytes.len()).unwrap(),
                0,
            )
            .unwrap();
            let (lease_signer, lease_key) = if alternate {
                (&self.alternate_lease_signer, &self.alternate_lease_key)
            } else {
                (&self.lease_signer, &self.lease_key)
            };
            let plan = BrokerAuthorizationPlan::new(
                BrokerAudience::Host,
                ProtocolId::HostBroker,
                ProtocolVersion::new(1, 1),
                assignment,
                TEST_NODE,
                lease_signer.clone(),
                vec![grant],
                ObjectDigest::from_bytes([48; 32]),
                self.revocation_scope,
                100,
                300,
                Vec::new(),
            )
            .unwrap();
            let broker_plan = encode_broker_authorization_plan(&plan);
            let broker_plan_signature = signed_object(
                &broker_plan,
                PortableMediaType::BrokerAuthorizationPlan,
                self.plan_scope,
                self.plan_signer.clone(),
                SignaturePurpose::BrokerAuthorization,
                &self.plan_policy_descriptor,
                &self.plan_key,
            );
            let lease = OwnershipLease::new(
                LeaseAssignment::new(
                    assignment.sandbox(),
                    assignment.incarnation(),
                    assignment.epoch(),
                    assignment.digest(),
                )
                .unwrap(),
                TEST_NODE,
                lease_generation,
                100,
                300,
                10,
                [u8::try_from(lease_generation).unwrap_or(255); 16],
            )
            .unwrap();
            let ownership_lease = encode_ownership_lease(&lease);
            let ownership_lease_signature = signed_object(
                &ownership_lease,
                PortableMediaType::OwnershipLease,
                self.lease_scope,
                lease_signer.clone(),
                SignaturePurpose::OwnershipLease,
                &self.lease_policy_descriptor,
                lease_key,
            );
            validated_artifacts(BrokerAuthorizationArtifactsV1 {
                broker_plan,
                broker_plan_signature,
                ownership_lease,
                ownership_lease_signature,
                ..Default::default()
            })
        }
    }

    fn key_reference(id: &str, generation: u64, usage: KeyUsage, key: &SigningKey) -> KeyReference {
        KeyReference::new(
            StableKeyId::new(id.to_owned()).unwrap(),
            generation,
            ObjectDigest::from_bytes(Sha256::digest(key.verifying_key().as_bytes()).into()),
            usage,
        )
    }

    fn trust_policy(
        scope: TrustScopeId,
        purpose: SignaturePurpose,
        signer: KeyReference,
    ) -> (Vec<u8>, aos_sandbox_core::ObjectDescriptor) {
        trust_policy_many(scope, purpose, vec![signer])
    }

    fn trust_policy_many(
        scope: TrustScopeId,
        purpose: SignaturePurpose,
        mut signers: Vec<KeyReference>,
    ) -> (Vec<u8>, aos_sandbox_core::ObjectDescriptor) {
        signers.sort_by(|left, right| {
            (left.stable_key_id(), left.generation())
                .cmp(&(right.stable_key_id(), right.generation()))
        });
        let bytes =
            encode_trust_policy(&TrustPolicy::new(scope, purpose, signers, Vec::new()).unwrap());
        let descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned()).unwrap(),
            &bytes,
        );
        (bytes, descriptor)
    }

    #[allow(clippy::too_many_arguments)]
    fn signed_object(
        bytes: &[u8],
        media_type: PortableMediaType,
        scope: TrustScopeId,
        signer: KeyReference,
        purpose: SignaturePurpose,
        policy: &aos_sandbox_core::ObjectDescriptor,
        key: &SigningKey,
    ) -> Vec<u8> {
        let subject = descriptor_for_bytes(
            MediaType::new(media_type.as_str().to_owned()).unwrap(),
            bytes,
        );
        let statement = SignatureStatement::new(
            subject,
            scope,
            signer,
            purpose,
            100,
            Some(300),
            policy.clone(),
        )
        .unwrap();
        encode_signature(&sign_statement(statement, key).unwrap())
    }

    fn validated_artifacts(
        artifacts: BrokerAuthorizationArtifactsV1,
    ) -> ValidatedUntrustedAuthorizationArtifacts {
        let envelope = BrokerRequestEnvelope {
            method: BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME.into(),
            body: vec![1],
            authorization: Some(artifacts).into(),
            ..Default::default()
        };
        decode_request_envelope(&envelope.encode_to_vec(), ProtocolId::HostBroker, 0)
            .unwrap()
            .authorization()
            .unwrap()
            .clone()
    }

    fn clock() -> RawPairedClockSample {
        clock_at(TEST_WALL_SECONDS, TEST_BOOTTIME_NANOSECONDS)
    }

    fn clock_at(wall_seconds: i64, boottime_nanoseconds: u64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([49; 16]).unwrap(),
            [50; 16],
            wall_seconds,
            boottime_nanoseconds,
        )
        .unwrap()
    }

    async fn apply<C: HostCatalog, S: HostStateStore, W: HostWorker>(
        broker: &mut HostBroker<C, S, W>,
        fixture: &AuthorityFixture,
        request_bytes: &[u8],
    ) -> Result<Vec<u8>> {
        apply_generation(broker, fixture, request_bytes, 1).await
    }

    async fn apply_generation<C: HostCatalog, S: HostStateStore, W: HostWorker>(
        broker: &mut HostBroker<C, S, W>,
        fixture: &AuthorityFixture,
        request_bytes: &[u8],
        lease_generation: u64,
    ) -> Result<Vec<u8>> {
        let artifacts = fixture.artifacts(request_bytes, lease_generation);
        broker
            .apply_runtime(
                request_bytes,
                &artifacts,
                ProtocolVersion::new(1, 1),
                peer(),
                policy(),
                || Ok(clock()),
            )
            .await
    }

    fn runtime_identity(request_bytes: &[u8]) -> HostRuntimeIdentity {
        let request =
            decode_runtime_request(request_bytes, peer(), policy(), TEST_BOOTTIME_NANOSECONDS)
                .unwrap();
        HostRuntimeIdentity::from(request.fence())
    }

    fn request(request_id: u8, generation: u64, digest: u8) -> Vec<u8> {
        request_with_identity(request_id, generation, digest, 65_536, 65_536)
    }

    fn request_with_identity(
        request_id: u8,
        generation: u64,
        digest: u8,
        uid_range_start: u32,
        uid_range_size: u32,
    ) -> Vec<u8> {
        request_with_sandbox(
            request_id,
            generation,
            digest,
            2,
            uid_range_start,
            uid_range_size,
        )
    }

    fn request_with_sandbox(
        request_id: u8,
        generation: u64,
        digest: u8,
        sandbox_id: u8,
        uid_range_start: u32,
        uid_range_size: u32,
    ) -> Vec<u8> {
        let mut request = ApplyRuntimeRequest::default();
        let header = request.header.get_or_insert_default();
        header.protocol_major = 1;
        header.protocol_minor = 1;
        header.request_id = vec![request_id; 16];
        header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
        header.deadline_boottime_nanoseconds = 1000;
        header.maximum_response_bytes = 4096;
        let fence = request.fence.get_or_insert_default();
        fence.sandbox_id = vec![sandbox_id; 16];
        fence.incarnation_id = vec![sandbox_id.wrapping_add(1); 16];
        fence.assignment_epoch = 1;
        fence.desired_generation = generation;
        fence.assignment_digest = vec![digest; 32];
        request.action = RuntimeAction::RUNTIME_ACTION_LAUNCH.into();
        let plan = request.launch_plan.get_or_insert_default();
        let root = plan.root_image.get_or_insert_default();
        root.media_type = "application/vnd.aos.sandbox.view.v1+cbor".to_owned();
        root.sha256 = vec![5; 32];
        root.encoded_size = 10;
        plan.workspace_handle = vec![6; 32];
        plan.network_handle = vec![7; 32];
        plan.uid_range_start = uid_range_start;
        plan.uid_range_size = uid_range_size;
        plan.limits = vec![
            ResourceLimit {
                dimension: 2,
                value: 128,
                ..Default::default()
            },
            ResourceLimit {
                dimension: 3,
                value: 1 << 30,
                ..Default::default()
            },
            ResourceLimit {
                dimension: 4,
                value: 100,
                ..Default::default()
            },
            ResourceLimit {
                dimension: 9,
                value: 1024,
                ..Default::default()
            },
        ];
        plan.required_features.push(Feature {
            namespace: "aos.sandbox.runtime.linux-systemd".to_owned(),
            major: 1,
            minor: 0,
            ..Default::default()
        });
        request.encode_to_vec()
    }

    #[tokio::test]
    async fn completed_request_replays_without_a_second_effect() {
        let fixture = AuthorityFixture::new();
        let store = MemoryStore::default();
        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        let mut broker = HostBroker::open(
            FixedCatalog,
            store.clone(),
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        let bytes = request(1, 1, 4);
        let first = apply(&mut broker, &fixture, &bytes).await.unwrap();
        let replay = apply(&mut broker, &fixture, &bytes).await.unwrap();
        assert_eq!(first, replay);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let reopened_worker = FakeWorker::default();
        let reopened_calls = reopened_worker.calls.clone();
        let mut reopened = HostBroker::open(
            FixedCatalog,
            store,
            reopened_worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        assert_eq!(apply(&mut reopened, &fixture, &bytes).await.unwrap(), first);
        assert_eq!(reopened_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn observation_requires_the_exact_durable_runtime_handle() {
        let fixture = AuthorityFixture::new();
        let worker = FakeWorker::default();
        let observations = worker.observe_calls.clone();
        let mut broker = HostBroker::open(
            FixedCatalog,
            MemoryStore::default(),
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        let bytes = request(1, 1, 4);
        apply(&mut broker, &fixture, &bytes).await.unwrap();
        let identity = runtime_identity(&bytes);
        let handle = runtime_handle(&identity);

        assert!(matches!(
            broker.observe_runtime(identity, [99; 32], 4_096).await,
            Err(HostError::UnknownHandle)
        ));
        assert!(observations.lock().unwrap().is_empty());
        let encoded = broker
            .observe_runtime(identity, handle, 4_096)
            .await
            .unwrap();
        let observation = RuntimeObservation::decode_from_slice(&encoded).unwrap();
        assert_eq!(observation.runtime_handle, handle);
        assert_eq!(observation.observation_sequence, 2);
        assert_eq!(observations.lock().unwrap().as_slice(), &[[2; 16]]);
    }

    #[tokio::test]
    async fn inventory_is_complete_ordered_bounded_and_atomic_on_failure() {
        let fixture = AuthorityFixture::new();
        let worker = FakeWorker::default();
        let store = MemoryStore::default();
        let mut broker = HostBroker::open(
            FixedCatalog,
            store,
            worker.clone(),
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        let first = request(1, 1, 4);
        let second = request_with_sandbox(2, 1, 4, 8, 65_536, 65_536);
        apply(&mut broker, &fixture, &first).await.unwrap();
        apply(&mut broker, &fixture, &second).await.unwrap();

        worker.fail_observe_at.store(2, Ordering::SeqCst);
        assert!(matches!(
            broker.inventory_runtime(4_096).await,
            Err(HostError::Worker(_))
        ));
        worker.fail_observe_at.store(0, Ordering::SeqCst);
        worker.observe_calls.lock().unwrap().clear();

        let encoded = broker.inventory_runtime(4_096).await.unwrap();
        let inventory = InventoryRuntimeResponse::decode_from_slice(&encoded).unwrap();
        assert_eq!(inventory.runtimes.len(), 2);
        assert!(
            inventory
                .runtimes
                .windows(2)
                .all(|pair| pair[0].runtime_handle < pair[1].runtime_handle)
        );
        assert!(
            inventory
                .runtimes
                .iter()
                .all(|runtime| runtime.observation_sequence == 2)
        );
        assert!(matches!(
            broker.inventory_runtime(1).await,
            Err(HostError::ResourceExhausted)
        ));
    }

    #[tokio::test]
    async fn empty_inventory_is_a_complete_empty_protobuf() {
        let fixture = AuthorityFixture::new();
        let mut broker = HostBroker::open(
            FixedCatalog,
            MemoryStore::default(),
            FakeWorker::default(),
            None,
            fixture.authority(),
        )
        .unwrap();
        let bytes = broker.inventory_runtime(4_096).await.unwrap();
        assert!(bytes.is_empty());
        assert!(
            InventoryRuntimeResponse::decode_from_slice(&bytes)
                .unwrap()
                .runtimes
                .is_empty()
        );
    }

    #[tokio::test]
    async fn authenticated_complete_receipt_replays_after_effect_deadline() {
        let fixture = AuthorityFixture::new();
        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        let mut broker = HostBroker::open(
            FixedCatalog,
            MemoryStore::default(),
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        let bytes = request(1, 1, 4);
        let artifacts = fixture.artifacts(&bytes, 1);
        let first = broker
            .apply_runtime(
                &bytes,
                &artifacts,
                ProtocolVersion::new(1, 1),
                peer(),
                policy(),
                || Ok(clock()),
            )
            .await
            .unwrap();
        let replay = broker
            .apply_runtime(
                &bytes,
                &artifacts,
                ProtocolVersion::new(1, 1),
                peer(),
                policy(),
                || {
                    Err(HostError::State(
                        "complete replay unexpectedly sampled the effect clock".to_owned(),
                    ))
                },
            )
            .await
            .unwrap();

        assert_eq!(replay, first);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn expired_new_request_cannot_use_the_complete_replay_path() {
        let fixture = AuthorityFixture::new();
        let store = MemoryStore::default();
        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        let bytes = request(1, 1, 4);
        let artifacts = fixture.artifacts(&bytes, 1);
        let mut broker = HostBroker::open(
            FixedCatalog,
            store.clone(),
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();

        assert!(
            broker
                .apply_runtime(
                    &bytes,
                    &artifacts,
                    ProtocolVersion::new(1, 1),
                    peer(),
                    policy(),
                    || Ok(clock_at(TEST_WALL_SECONDS, 1_000)),
                )
                .await
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(store.load().unwrap(), HostState::default());
    }

    #[tokio::test]
    async fn pending_request_reconciles_after_worker_failure() {
        let fixture = AuthorityFixture::new();
        let store = MemoryStore::default();
        let worker = FakeWorker::default();
        worker.fail_next.store(true, Ordering::SeqCst);
        let bytes = request(1, 1, 4);
        let mut broker = HostBroker::open(
            FixedCatalog,
            store.clone(),
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        assert!(apply(&mut broker, &fixture, &bytes).await.is_err());

        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        let mut reopened = HostBroker::open(
            FixedCatalog,
            store,
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        assert!(apply(&mut reopened, &fixture, &bytes).await.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_sandbox_cannot_admit_two_pending_transitions() {
        let fixture = AuthorityFixture::new();
        let store = MemoryStore::default();
        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        worker.fail_next.store(true, Ordering::SeqCst);
        let mut broker = HostBroker::open(
            FixedCatalog,
            store,
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        assert!(
            apply(&mut broker, &fixture, &request(1, 1, 4))
                .await
                .is_err()
        );
        assert!(
            apply(&mut broker, &fixture, &request(2, 2, 5))
                .await
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn stale_generation_and_request_id_equivocation_fail_before_effect() {
        let fixture = AuthorityFixture::new();
        let store = MemoryStore::default();
        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        let mut broker = HostBroker::open(
            FixedCatalog,
            store,
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        apply(&mut broker, &fixture, &request(1, 2, 4))
            .await
            .unwrap();
        assert!(
            apply(&mut broker, &fixture, &request(2, 1, 4))
                .await
                .is_err()
        );
        assert!(
            apply(&mut broker, &fixture, &request(1, 3, 5))
                .await
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn backend_without_readiness_does_not_offer_launch() {
        let fixture = AuthorityFixture::new();
        let broker = HostBroker::open(
            FixedCatalog,
            MemoryStore::default(),
            FakeWorker::default(),
            None,
            fixture.authority(),
        )
        .unwrap();
        assert!(!broker.launch_available());
    }

    #[tokio::test]
    async fn unready_launch_fails_before_durable_intent_or_effect() {
        let fixture = AuthorityFixture::new();
        let store = MemoryStore::default();
        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        let mut broker = HostBroker::open(
            FixedCatalog,
            store.clone(),
            worker,
            None,
            fixture.authority(),
        )
        .unwrap();
        assert!(
            apply(&mut broker, &fixture, &request(1, 1, 4))
                .await
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(store.load().unwrap(), HostState::default());
    }

    #[tokio::test]
    async fn requested_identity_must_equal_catalog_allocation() {
        let fixture = AuthorityFixture::new();
        let store = MemoryStore::default();
        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        let mut broker = HostBroker::open(
            FixedCatalog,
            store.clone(),
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        assert!(
            apply(
                &mut broker,
                &fixture,
                &request_with_identity(1, 1, 4, 131_072, 65_536),
            )
            .await
            .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(store.load().unwrap(), HostState::default());
    }

    #[tokio::test]
    async fn signed_authority_rejects_wrong_signature_body_and_protocol() {
        let fixture = AuthorityFixture::new();
        let bytes = request(1, 1, 4);
        let valid = fixture.artifacts(&bytes, 1);
        let mut signature = valid.broker_plan_signature().to_vec();
        let last = signature.len() - 1;
        signature[last] ^= 1;
        let wrong_signature = validated_artifacts(BrokerAuthorizationArtifactsV1 {
            broker_plan: valid.broker_plan().to_vec(),
            broker_plan_signature: signature,
            ownership_lease: valid.ownership_lease().to_vec(),
            ownership_lease_signature: valid.ownership_lease_signature().to_vec(),
            ..Default::default()
        });
        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        let mut broker = HostBroker::open(
            FixedCatalog,
            MemoryStore::default(),
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        assert!(
            broker
                .apply_runtime(
                    &bytes,
                    &wrong_signature,
                    ProtocolVersion::new(1, 1),
                    peer(),
                    policy(),
                    || Ok(clock()),
                )
                .await
                .is_err()
        );
        assert!(
            broker
                .apply_runtime(
                    &bytes,
                    &valid,
                    ProtocolVersion::new(1, 0),
                    peer(),
                    policy(),
                    || Ok(clock()),
                )
                .await
                .is_err()
        );
        assert!(
            broker
                .apply_runtime(
                    &request(2, 1, 5),
                    &valid,
                    ProtocolVersion::new(1, 1),
                    peer(),
                    policy(),
                    || Ok(clock()),
                )
                .await
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn authority_expiry_after_intent_prevents_the_systemd_effect() {
        let fixture = AuthorityFixture::new();
        let bytes = request(1, 1, 4);
        let artifacts = fixture.artifacts(&bytes, 1);
        let store = MemoryStore::default();
        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        let mut broker = HostBroker::open(
            FixedCatalog,
            store.clone(),
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        let mut samples = 0;
        let result = broker
            .apply_runtime(
                &bytes,
                &artifacts,
                ProtocolVersion::new(1, 1),
                peer(),
                policy(),
                || {
                    samples += 1;
                    Ok(if samples == 1 {
                        clock()
                    } else {
                        clock_at(300, 200)
                    })
                },
            )
            .await;
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(store.load().unwrap().effect(&[1; 16]).is_some());

        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        let mut expired_at_admission = HostBroker::open(
            FixedCatalog,
            MemoryStore::default(),
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        assert!(
            expired_at_admission
                .apply_runtime(
                    &bytes,
                    &artifacts,
                    ProtocolVersion::new(1, 1),
                    peer(),
                    policy(),
                    || Ok(clock_at(300, TEST_BOOTTIME_NANOSECONDS)),
                )
                .await
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn effect_time_clock_identity_substitution_fails_closed() {
        let fixture = AuthorityFixture::new();
        let bytes = request(1, 1, 4);
        let artifacts = fixture.artifacts(&bytes, 1);
        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        let mut broker = HostBroker::open(
            FixedCatalog,
            MemoryStore::default(),
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        let mut samples = 0;
        assert!(
            broker
                .apply_runtime(
                    &bytes,
                    &artifacts,
                    ProtocolVersion::new(1, 1),
                    peer(),
                    policy(),
                    || {
                        samples += 1;
                        if samples == 1 {
                            return Ok(clock());
                        }
                        RawPairedClockSample::new_untrusted(
                            RawClockProvenance::new_untrusted([59; 16]).unwrap(),
                            [60; 16],
                            TEST_WALL_SECONDS,
                            TEST_BOOTTIME_NANOSECONDS,
                        )
                        .map_err(|error| HostError::State(error.to_string()))
                    },
                )
                .await
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn pending_replay_refreshes_lease_but_rejects_rollback_and_authority_substitution() {
        let fixture = AuthorityFixture::new();
        let store = MemoryStore::default();
        let bytes = request(1, 1, 4);
        let worker = FakeWorker::default();
        worker.fail_next.store(true, Ordering::SeqCst);
        let mut broker = HostBroker::open(
            FixedCatalog,
            store.clone(),
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        assert!(
            apply_generation(&mut broker, &fixture, &bytes, 2)
                .await
                .is_err()
        );

        let rollback = fixture.artifacts(&bytes, 1);
        assert!(
            broker
                .apply_runtime(
                    &bytes,
                    &rollback,
                    ProtocolVersion::new(1, 1),
                    peer(),
                    policy(),
                    || Ok(clock()),
                )
                .await
                .is_err()
        );
        let substituted = fixture.artifacts_with_lease_authority(&bytes, 3, true);
        assert!(
            broker
                .apply_runtime(
                    &bytes,
                    &substituted,
                    ProtocolVersion::new(1, 1),
                    peer(),
                    policy(),
                    || Ok(clock()),
                )
                .await
                .is_err()
        );

        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        let mut reopened = HostBroker::open(
            FixedCatalog,
            store,
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        assert!(
            apply_generation(&mut reopened, &fixture, &bytes, 3)
                .await
                .is_ok()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn authenticated_effect_tamper_and_relocation_fail_closed() {
        let fixture = AuthorityFixture::new();
        let store = MemoryStore::default();
        let worker = FakeWorker::default();
        worker.fail_next.store(true, Ordering::SeqCst);
        let mut broker = HostBroker::open(
            FixedCatalog,
            store.clone(),
            worker.clone(),
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        let first = request(1, 1, 4);
        assert!(apply(&mut broker, &fixture, &first).await.is_err());
        worker.fail_next.store(true, Ordering::SeqCst);
        let second = request_with_sandbox(2, 1, 4, 8, 65_536, 65_536);
        assert!(apply(&mut broker, &fixture, &second).await.is_err());
        store.0.lock().unwrap().swap_effects(&[1; 16], &[2; 16]);
        assert!(
            HostBroker::open(
                FixedCatalog,
                store.clone(),
                FakeWorker::default(),
                Some(nspawn()),
                fixture.authority(),
            )
            .is_err()
        );

        store.0.lock().unwrap().swap_effects(&[1; 16], &[2; 16]);
        store.0.lock().unwrap().corrupt_effect(&[1; 16]);
        assert!(
            HostBroker::open(
                FixedCatalog,
                store,
                FakeWorker::default(),
                Some(nspawn()),
                fixture.authority(),
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn startup_rejects_corrupt_or_deleted_authorization_fences() {
        let fixture = AuthorityFixture::new();
        let store = MemoryStore::default();
        let worker = FakeWorker::default();
        worker.fail_next.store(true, Ordering::SeqCst);
        let mut broker = HostBroker::open(
            FixedCatalog,
            store.clone(),
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        let request = request(1, 1, 4);
        assert!(apply(&mut broker, &fixture, &request).await.is_err());
        let valid_state = store.load().unwrap();

        let corrupt = MemoryStore(Arc::new(Mutex::new(valid_state.clone())));
        corrupt.0.lock().unwrap().corrupt_fence(&[2; 16]);
        assert!(
            HostBroker::open(
                FixedCatalog,
                corrupt,
                FakeWorker::default(),
                Some(nspawn()),
                fixture.authority(),
            )
            .is_err()
        );

        let relocated = MemoryStore(Arc::new(Mutex::new(valid_state.clone())));
        let worker = FakeWorker::default();
        worker.fail_next.store(true, Ordering::SeqCst);
        let mut broker = HostBroker::open(
            FixedCatalog,
            relocated.clone(),
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        let second = request_with_sandbox(2, 1, 4, 8, 65_536, 65_536);
        assert!(apply(&mut broker, &fixture, &second).await.is_err());
        relocated.0.lock().unwrap().swap_fences(&[2; 16], &[8; 16]);
        assert!(
            HostBroker::open(
                FixedCatalog,
                relocated,
                FakeWorker::default(),
                Some(nspawn()),
                fixture.authority(),
            )
            .is_err()
        );

        let deleted = MemoryStore(Arc::new(Mutex::new(valid_state)));
        deleted.0.lock().unwrap().remove_fence(&[2; 16]);
        assert!(
            HostBroker::open(
                FixedCatalog,
                deleted,
                FakeWorker::default(),
                Some(nspawn()),
                fixture.authority(),
            )
            .is_err()
        );
    }
}
