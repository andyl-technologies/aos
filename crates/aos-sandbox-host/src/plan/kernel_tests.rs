//! Explicit VM qualification of the production compiler and systemd worker.
//!
//! This test pins the real packaged nspawn, not the unit-test executable. It
//! deliberately does not construct `BackendReadiness`: a successful launch is
//! only one prerequisite, not evidence of deployed MAC or ownership enforcement.
//! The fleet fixture supplies an inert guardian dependency and prepared root
//! and network objects. No production feature or constructor bypasses readiness.

#![allow(
    clippy::unwrap_used,
    reason = "Explicit VM qualification assertions panic."
)]

use aos_proto::aos::sandbox::local::v1::{
    ApplyRuntimeRequest, Audience, Feature, ResourceLimit, RuntimeAction,
};
use aos_sandbox_linux::mount::DetachedMount;
use aos_sandbox_linux::path::BeneathRoot;
use aos_sandbox_linux::pidfd::NamespaceKind;
use aos_sandbox_protocol::{PeerCredentials, PeerPolicy, decode_runtime_request};
use buffa::Message as _;

use super::*;
use crate::worker::{
    HostRuntimeIdentity, HostWorker, ObservedRuntimeState, SystemdOneShotWorker, WorkerOperation,
};

const INCARNATION: [u8; 16] = [0x61; 16];
const WORKSPACE: &str = "/run/aos/sandbox-pins/workspaces/qualification";
const NETWORK: &str = "/run/aos/sandbox-pins/netns/qualification";

fn directory(path: &str) -> OwnedFd {
    open(
        path,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap()
}

fn resources() -> ResolvedLaunchResources {
    let workspace = directory(WORKSPACE);
    let stat = fstat(&workspace).unwrap();
    // The privileged root publisher must supply a transferable mount, not an
    // attached directory from another mount namespace. This fixture performs
    // that preparation explicitly; it does not add capabilities to hostd.
    let source = BeneathRoot::from_owned(workspace)
        .unwrap()
        .resolve(
            std::path::Path::new("."),
            aos_sandbox_linux::path::ResolveOptions::directory(),
        )
        .unwrap();
    let detached = DetachedMount::clone_from(&source, true).unwrap();
    let workspace = detached.as_fd().try_clone_to_owned().unwrap();
    let workspace =
        ResolvedWorkspace::from_pinned(WORKSPACE.to_owned(), stat.st_dev, stat.st_ino, workspace)
            .unwrap();
    let network = open(NETWORK, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()).unwrap();
    let network = NamespaceFd::from_owned(network, NamespaceKind::Network).unwrap();
    let identity = network.identity();
    let network =
        ResolvedNetwork::from_pinned(NETWORK.to_owned(), identity.device, identity.inode, network)
            .unwrap();
    ResolvedLaunchResources {
        workspace,
        network,
        identity: ResolvedIdentityAllocation {
            range_start: 655_360,
            range_size: 65_536,
            catalog_generation: 1,
        },
    }
}

fn launch_request(now: u64) -> Vec<u8> {
    let mut request = ApplyRuntimeRequest::default();
    let header = request.header.get_or_insert_default();
    header.protocol_major = 1;
    header.protocol_minor = 2;
    header.request_id = vec![0x62; 16];
    header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
    header.deadline_boottime_nanoseconds = now.checked_add(90_000_000_000).unwrap();
    header.maximum_response_bytes = 4096;
    let fence = request.fence.get_or_insert_default();
    fence.sandbox_id = vec![0x60; 16];
    fence.incarnation_id = INCARNATION.to_vec();
    fence.assignment_epoch = 1;
    fence.desired_generation = 1;
    fence.assignment_digest = vec![0x63; 32];
    request.action = RuntimeAction::RUNTIME_ACTION_LAUNCH.into();
    let plan = request.launch_plan.get_or_insert_default();
    let root = plan.root_image.get_or_insert_default();
    root.media_type = "application/vnd.aos.sandbox.view.v1+cbor".to_owned();
    root.sha256 = vec![0x64; 32];
    root.encoded_size = 10;
    plan.workspace_handle = vec![0x65; 32];
    plan.network_handle = vec![0x66; 32];
    plan.uid_range_start = 655_360;
    plan.uid_range_size = 65_536;
    plan.limits = [
        (PROCESSES, 4096),
        (MEMORY, 1 << 30),
        (CPU_WEIGHT, 100),
        (OPEN_FILES, 4096),
    ]
    .into_iter()
    .map(|(dimension, value)| ResourceLimit {
        dimension: u32::from(dimension),
        value,
        ..Default::default()
    })
    .collect();
    plan.required_features.push(Feature {
        namespace: "aos.sandbox.runtime.linux-systemd".to_owned(),
        major: 1,
        minor: 0,
        ..Default::default()
    });
    request.encode_to_vec()
}

#[tokio::test]
#[ignore = "requires the sandbox-host-worker fleet VM and its explicit prepared objects"]
async fn production_compiler_worker_launch_refresh_and_stop() {
    assert_eq!(
        std::env::var("AOS_SANDBOX_WORKER_QUALIFICATION").unwrap(),
        "1"
    );
    assert!(rustix::process::geteuid().is_root());
    let executable = std::env::var("AOS_SANDBOX_QUALIFICATION_NSPAWN").unwrap();
    validate_fixed_nspawn_path(&executable).unwrap();
    // A test-only candidate config exercises production compilation. It does
    // not mint the readiness token that the real service requires to launch.
    let config = NspawnConfig {
        executable_pin: Arc::new(open_executable_pin(&executable).unwrap()),
        timeout_start: Duration::from_secs(60),
        timeout_stop: Duration::from_secs(15),
    };
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let now =
        u64::try_from(now.tv_sec).unwrap() * 1_000_000_000 + u64::try_from(now.tv_nsec).unwrap();
    let body = launch_request(now);
    let request = decode_runtime_request(
        &body,
        PeerCredentials {
            uid: 0,
            gid: 0,
            pid: Some(std::process::id()),
        },
        PeerPolicy {
            uid: 0,
            gid: Some(0),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        },
        now,
    )
    .unwrap();
    let prepared = config
        .compile_resolved(request.fence(), request.launch_plan().unwrap(), resources())
        .unwrap();
    let worker =
        SystemdOneShotWorker::new(BeneathRoot::from_owned(directory("/sys/fs/cgroup")).unwrap());
    let identity = HostRuntimeIdentity::from(request.fence());
    assert_eq!(
        worker.observe(&identity).await.unwrap().state,
        ObservedRuntimeState::Absent
    );
    // Manager absence alone must not hide a remaining kernel cgroup. In
    // particular, the hyphenated slice has a systemd-created aos.slice parent.
    let cgroup = format!(
        "/sys/fs/cgroup{}",
        SandboxUnitName::from_incarnation(INCARNATION)
            .cgroup_path()
            .as_str()
    );
    std::fs::create_dir(&cgroup).unwrap();
    assert!(worker.observe(&identity).await.is_err());
    std::fs::remove_dir(&cgroup).unwrap();
    assert_eq!(
        worker.observe(&identity).await.unwrap().state,
        ObservedRuntimeState::Absent
    );
    let (spec, pins) = prepared.into_parts();
    let mut effect_checks = 0;
    let mut before_effect = || {
        effect_checks += 1;
        Ok(())
    };
    let launched = worker
        .execute(
            request.fence(),
            WorkerOperation::Launch {
                spec: Box::new(spec),
                pins,
            },
            &mut before_effect,
        )
        .await;
    assert!(launched.is_ok(), "production launch failed: {launched:?}");
    let launched = launched.unwrap();
    assert_eq!(launched.state, ObservedRuntimeState::Ready);
    let supervisor = launched.leader.as_ref().unwrap();
    let payload = launched.payload.as_ref().unwrap();
    let invocation = launched.invocation_id.unwrap();
    payload.recheck_kernel(supervisor).unwrap();
    assert_ne!(
        supervisor.pidfd().info().unwrap().pid(),
        payload.pidfd().info().unwrap().pid()
    );

    let refreshed = worker
        .refresh_payload_scope(&identity, invocation, supervisor, payload)
        .await
        .unwrap();
    assert_eq!(refreshed.invocation_id, Some(invocation));
    assert!(payload.has_same_cgroup(refreshed.payload.as_ref().unwrap()));
    let frozen = worker
        .execute(request.fence(), WorkerOperation::Freeze, &mut before_effect)
        .await
        .unwrap();
    assert_eq!(frozen.state, ObservedRuntimeState::Frozen);
    worker
        .refresh_payload_scope(&identity, invocation, supervisor, payload)
        .await
        .unwrap();
    let thawed = worker
        .execute(request.fence(), WorkerOperation::Thaw, &mut before_effect)
        .await
        .unwrap();
    assert_eq!(thawed.state, ObservedRuntimeState::Ready);
    let stopped = worker
        .execute(request.fence(), WorkerOperation::Stop, &mut before_effect)
        .await
        .unwrap();
    assert!(matches!(
        stopped.state,
        ObservedRuntimeState::Absent | ObservedRuntimeState::Exited
    ));
    assert_eq!(effect_checks, 4);
    assert!(
        !payload.pidfd().is_alive().unwrap(),
        "stopped payload is still alive"
    );
    assert!(
        !supervisor.pidfd().is_alive().unwrap(),
        "stopped supervisor is still alive"
    );
    assert!(payload.recheck_kernel(supervisor).is_err());
    assert!(
        worker
            .refresh_payload_scope(&identity, invocation, supervisor, payload)
            .await
            .is_err()
    );
}
