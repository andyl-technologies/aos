//! End-to-end control-client transport conformance and determinism tests.

use super::*;

#[tokio::test(flavor = "current_thread")]
async fn reference_client_conformance_drives_full_lifecycle_across_transports_with_simdouble_backend()
 {
    assert_qemu_node_implements_simulation_backend_contract();

    let sim_double_client = InProcessLifecycleClient::new(reference_lifecycle_control_plane(
        "crucible-reference-simdouble",
        |_scenario, _seed| ReferenceSimDoubleLoop::new(),
    ));
    let rpc_server = spawn_http2_lifecycle_server().await;
    let rpc_client = RpcControlClient::new(RpcEndpoint::http2(rpc_server.endpoint()))
        .unwrap_or_else(|error| panic!("reference RPC client should build: {error}"));

    let sim_double = run_reference_client_conformance(&sim_double_client, "SimDouble").await;
    let rpc = run_reference_client_conformance(&rpc_client, "HTTP2-RPC").await;

    assert_reference_conformance_equivalent(&sim_double, &rpc);
    assert_eq!(sim_double.transport, ControlTransportKind::InProcess);
    assert_eq!(rpc.transport, ControlTransportKind::Http2Rpc);
}
#[tokio::test(flavor = "current_thread")]
async fn api_nondeterminism_gate_proves_transport_observers_wall_clock_and_read_only_traffic_do_not_perturb_state()
 {
    let quiet_in_process = InProcessLifecycleClient::new(lifecycle_control_plane());
    let noisy_in_process = InProcessLifecycleClient::new(lifecycle_control_plane());
    let quiet_rpc_server = spawn_http2_lifecycle_server().await;
    let quiet_rpc = RpcControlClient::new(RpcEndpoint::http2(quiet_rpc_server.endpoint()))
        .unwrap_or_else(|error| panic!("quiet nondeterminism RPC client should build: {error}"));
    let rpc_server = spawn_http2_lifecycle_server().await;
    let noisy_rpc = RpcControlClient::new(RpcEndpoint::http2(rpc_server.endpoint()))
        .unwrap_or_else(|error| panic!("nondeterminism RPC client should build: {error}"));
    let arrival_rpc_server = spawn_http2_lifecycle_server().await;
    let arrival_rpc = RpcControlClient::new(RpcEndpoint::http2(arrival_rpc_server.endpoint()))
        .unwrap_or_else(|error| {
            panic!("arrival-order nondeterminism RPC client should build: {error}")
        });
    let baseline =
        drive_api_nondeterminism_projection(&quiet_in_process, ApiDeterminismTraffic::Quiet).await;
    let noisy_in_process =
        drive_api_nondeterminism_projection(&noisy_in_process, ApiDeterminismTraffic::Noisy).await;
    let quiet_rpc =
        drive_api_nondeterminism_projection(&quiet_rpc, ApiDeterminismTraffic::Quiet).await;
    let noisy_rpc =
        drive_api_nondeterminism_projection(&noisy_rpc, ApiDeterminismTraffic::Noisy).await;
    let arrival_rpc =
        drive_rpc_arrival_permutation_projection(&arrival_rpc, &arrival_rpc_server).await;
    let quiet_causal =
        drive_streaming_causal_subsequence_projection(ApiDeterminismTraffic::Quiet).await;
    let noisy_causal =
        drive_streaming_causal_subsequence_projection(ApiDeterminismTraffic::Noisy).await;

    assert_eq!(baseline.transport, ControlTransportKind::InProcess);
    assert_eq!(noisy_in_process.transport, ControlTransportKind::InProcess);
    assert_eq!(quiet_rpc.transport, ControlTransportKind::Http2Rpc);
    assert_eq!(noisy_rpc.transport, ControlTransportKind::Http2Rpc);
    assert_eq!(arrival_rpc.transport, ControlTransportKind::Http2Rpc);
    assert_eq!(
        baseline.normalized(),
        noisy_in_process.normalized(),
        "in-process read-only traffic, observer load, and scheduling gaps must not perturb State",
    );
    assert_eq!(
        baseline.normalized(),
        quiet_rpc.normalized(),
        "quiet RPC transport must match the quiet in-process projection",
    );
    assert_eq!(
        baseline.normalized(),
        noisy_rpc.normalized(),
        "RPC transport and independent observer/request arrival order must not perturb State",
    );
    assert_eq!(
        baseline.normalized(),
        arrival_rpc.normalized(),
        "server-observed RPC read/mutate order permutations must not perturb the boundary command projection",
    );
    assert_eq!(
        quiet_causal, noisy_causal,
        "read-only traffic and undrained observers must not perturb the causal event projection",
    );
    assert!(
        !quiet_causal.causal_events.is_empty(),
        "causal projection must be non-vacuous"
    );
}

#[test]
fn control_client_rejects_rpc_major_version_mismatch_on_both_transports() {
    let (in_process, _actor) = in_process_client_fixture();
    let rpc = RpcControlClient::new(RpcEndpoint::http2("http://127.0.0.1:65535"))
        .unwrap_or_else(|error| panic!("HTTP/2 RPC client should build: {error}"));
    let incompatible = HelloRequest::new(
        "api-control-client-test",
        crucible_api::ProtocolVersion {
            major: RPC_PROTOCOL_VERSION.major.saturating_add(1),
            minor: RPC_PROTOCOL_VERSION.minor,
            patch: RPC_PROTOCOL_VERSION.patch,
            build: RPC_PROTOCOL_VERSION.build,
        },
    );

    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap_or_else(|error| panic!("current-thread runtime should build: {error}"));
    let in_process_error = runtime
        .block_on(in_process.hello(incompatible.clone()))
        .expect_err("in-process client should reject major mismatch");
    let rpc_error = runtime
        .block_on(rpc.hello(incompatible))
        .expect_err("RPC client should reject major mismatch");

    assert_eq!(in_process_error, rpc_error);
}
