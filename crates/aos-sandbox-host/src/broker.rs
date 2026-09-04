//! Durable ordering and replay for fixed host runtime effects.

use std::collections::BTreeMap;

use aos_proto::aos::sandbox::local::v1::{
    AssignmentFence, RuntimeAction, RuntimeObservation, RuntimeState,
};
use aos_sandbox_linux::pidfd::PidFd;
use aos_sandbox_protocol::{
    PeerCredentials, PeerPolicy, ValidatedAssignmentFence, ValidatedRuntimeRequest,
    decode_runtime_request,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::plan::{HostCatalog, NspawnConfig};
use crate::state::{Admission, HostState, HostStateStore};
use crate::worker::{HostWorker, ObservedRuntimeState, WorkerObservation, WorkerOperation};
use crate::{HostError, Result};

/// Applies validated runtime requests through durable fixed-function effects.
pub struct HostBroker<C, S, W> {
    catalog: C,
    store: S,
    worker: W,
    nspawn: NspawnConfig,
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
    pub fn open(catalog: C, store: S, worker: W, nspawn: NspawnConfig) -> Result<Self> {
        let state = store.load()?;
        Ok(Self {
            catalog,
            store,
            worker,
            nspawn,
            state,
            leaders: BTreeMap::new(),
        })
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
        peer: PeerCredentials,
        policy: PeerPolicy,
        now_boottime_nanoseconds: u64,
    ) -> Result<Vec<u8>> {
        let request =
            decode_runtime_request(request_bytes, peer, policy, now_boottime_nanoseconds)?;
        let request_id = *request.header().request_id();
        let request_digest: [u8; 32] = Sha256::digest(request_bytes).into();
        let action = action_code(request.action());

        let mut proposed = self.state.clone();
        match proposed.admit(request.fence(), request_id, request_digest, action)? {
            Admission::Complete(receipt) => return Ok(receipt),
            Admission::Pending => {}
            Admission::New => {
                self.store.commit(&proposed)?;
                self.state = proposed.clone();
            }
        }

        let operation = self.compile_operation(&request)?;
        let observation = self.worker.execute(request.fence(), operation).await?;
        let sequence = proposed.next_observation_sequence(*request.fence().incarnation_id())?;
        let response = self.encode_observation(request.fence(), sequence, observation)?;
        proposed.complete(request_id, request_digest, response.clone())?;
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

    fn compile_operation(&self, request: &ValidatedRuntimeRequest) -> Result<WorkerOperation> {
        Ok(match request.action() {
            RuntimeAction::RUNTIME_ACTION_LAUNCH => {
                let plan = request.launch_plan().ok_or(HostError::InvalidPlan(
                    "validated launch request lost its launch plan".to_owned(),
                ))?;
                WorkerOperation::Launch(Box::new(self.nspawn.compile(
                    &self.catalog,
                    request.fence(),
                    plan,
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
        let mut response = RuntimeObservation {
            runtime_handle: runtime_handle(fence).to_vec(),
            fence: Some(AssignmentFence {
                sandbox_id: fence.sandbox_id().to_vec(),
                incarnation_id: fence.incarnation_id().to_vec(),
                assignment_epoch: fence.assignment_epoch(),
                desired_generation: fence.desired_generation(),
                assignment_digest: fence.assignment_digest().to_vec(),
                ..Default::default()
            })
            .into(),
            state: protocol_state(observation.state).into(),
            observation_sequence: sequence,
            ..Default::default()
        };
        if let Some(leader) = observation.leader {
            let (handle, pidfd) = leader.into_parts();
            response.leader_handle = handle.to_vec();
            self.leaders.insert(handle, pidfd);
        }
        let bytes = response.encode_to_vec();
        if bytes.is_empty() {
            return Err(HostError::State(
                "runtime observation encoded to an empty receipt".to_owned(),
            ));
        }
        Ok(bytes)
    }
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

fn runtime_handle(fence: &ValidatedAssignmentFence) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.host.runtime.v1\0");
    digest.update(fence.incarnation_id());
    digest.update(fence.assignment_epoch().to_le_bytes());
    digest.update(fence.assignment_digest());
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use aos_proto::aos::sandbox::local::v1::{
        ApplyRuntimeRequest, Audience, Feature, ResourceLimit,
    };
    use async_trait::async_trait;

    use super::*;
    use crate::plan::{PayloadSecurityProfile, ResolvedNetwork, ResolvedWorkspace};

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
        fn resolve_workspace(
            &self,
            plan: &aos_sandbox_protocol::ValidatedRuntimePlan,
        ) -> Result<ResolvedWorkspace> {
            if plan.workspace_handle() != &[6; 32] {
                return Err(HostError::Catalog("unknown workspace".to_owned()));
            }
            Ok(ResolvedWorkspace {
                root_directory: "/var/lib/aos/sandboxes/root".to_owned(),
            })
        }

        fn resolve_network(
            &self,
            plan: &aos_sandbox_protocol::ValidatedRuntimePlan,
        ) -> Result<ResolvedNetwork> {
            if plan.network_handle() != &[7; 32] {
                return Err(HostError::Catalog("unknown network".to_owned()));
            }
            Ok(ResolvedNetwork {
                namespace_path: "/run/aos/netns/pinned".to_owned(),
            })
        }

        fn validate_attachments(
            &self,
            _plan: &aos_sandbox_protocol::ValidatedRuntimePlan,
        ) -> Result<()> {
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct FakeWorker {
        calls: Arc<AtomicUsize>,
        fail_next: Arc<AtomicBool>,
    }

    #[async_trait]
    impl HostWorker for FakeWorker {
        async fn execute(
            &self,
            _fence: &ValidatedAssignmentFence,
            operation: WorkerOperation,
        ) -> Result<WorkerObservation> {
            let WorkerOperation::Launch(spec) = operation else {
                panic!("test expected launch operation");
            };
            assert_eq!(
                spec.executable(),
                "/nix/store/aos-systemd/bin/systemd-nspawn"
            );
            assert!(
                spec.arguments()
                    .iter()
                    .any(|value| value == "--settings=no")
            );
            assert!(
                spec.arguments()
                    .iter()
                    .any(|value| value == "--aos-payload-filter=private-user-v1")
            );
            assert_eq!(spec.network_namespace_path(), "/run/aos/netns/pinned");
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

        async fn observe(&self, _fence: &ValidatedAssignmentFence) -> Result<WorkerObservation> {
            Ok(WorkerObservation {
                state: ObservedRuntimeState::Ready,
                invocation_id: Some([9; 16]),
                leader: None,
            })
        }
    }

    fn nspawn() -> NspawnConfig {
        NspawnConfig::new(
            "/nix/store/aos-systemd/bin/systemd-nspawn",
            "aos_sandbox_payload_t",
            PayloadSecurityProfile::PrivateUserBaseline,
            Duration::from_secs(30),
            Duration::from_secs(10),
        )
        .unwrap()
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

    fn request(request_id: u8, generation: u64, digest: u8) -> Vec<u8> {
        let mut request = ApplyRuntimeRequest::default();
        let header = request.header.get_or_insert_default();
        header.protocol_major = 1;
        header.protocol_minor = 0;
        header.request_id = vec![request_id; 16];
        header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
        header.deadline_boottime_nanoseconds = 1000;
        header.maximum_response_bytes = 4096;
        let fence = request.fence.get_or_insert_default();
        fence.sandbox_id = vec![2; 16];
        fence.incarnation_id = vec![3; 16];
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
        plan.uid_range_start = 65_536;
        plan.uid_range_size = 65_536;
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
        let store = MemoryStore::default();
        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        let mut broker = HostBroker::open(FixedCatalog, store.clone(), worker, nspawn()).unwrap();
        let bytes = request(1, 1, 4);
        let first = broker
            .apply_runtime(&bytes, peer(), policy(), 10)
            .await
            .unwrap();
        let replay = broker
            .apply_runtime(&bytes, peer(), policy(), 10)
            .await
            .unwrap();
        assert_eq!(first, replay);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let reopened_worker = FakeWorker::default();
        let reopened_calls = reopened_worker.calls.clone();
        let mut reopened =
            HostBroker::open(FixedCatalog, store, reopened_worker, nspawn()).unwrap();
        assert_eq!(
            reopened
                .apply_runtime(&bytes, peer(), policy(), 10)
                .await
                .unwrap(),
            first
        );
        assert_eq!(reopened_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn pending_request_reconciles_after_worker_failure() {
        let store = MemoryStore::default();
        let worker = FakeWorker::default();
        worker.fail_next.store(true, Ordering::SeqCst);
        let bytes = request(1, 1, 4);
        let mut broker = HostBroker::open(FixedCatalog, store.clone(), worker, nspawn()).unwrap();
        assert!(
            broker
                .apply_runtime(&bytes, peer(), policy(), 10)
                .await
                .is_err()
        );

        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        let mut reopened = HostBroker::open(FixedCatalog, store, worker, nspawn()).unwrap();
        assert!(
            reopened
                .apply_runtime(&bytes, peer(), policy(), 10)
                .await
                .is_ok()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn stale_generation_and_request_id_equivocation_fail_before_effect() {
        let store = MemoryStore::default();
        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        let mut broker = HostBroker::open(FixedCatalog, store, worker, nspawn()).unwrap();
        broker
            .apply_runtime(&request(1, 2, 4), peer(), policy(), 10)
            .await
            .unwrap();
        assert!(
            broker
                .apply_runtime(&request(2, 1, 4), peer(), policy(), 10)
                .await
                .is_err()
        );
        assert!(
            broker
                .apply_runtime(&request(1, 3, 5), peer(), policy(), 10)
                .await
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
