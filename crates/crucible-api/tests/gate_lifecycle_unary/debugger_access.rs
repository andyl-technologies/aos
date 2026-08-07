//! Session-owned debugger authorization and authenticated RPC lifecycle tests.

use super::*;

#[tokio::test(flavor = "current_thread")]
async fn debugger_access_is_session_owned_and_generation_guarded() {
    let mut control_plane = lifecycle_control_plane();
    let created = control_plane
        .create_session(CreateSessionRequest::scenario_ref(
            "api-lifecycle-scenario",
            Seed::from_u64(151),
        ))
        .await
        .unwrap_or_else(|error| panic!("create session should start actor: {error}"));
    let controller = DebugClientId::new("x509-sha256:controller")
        .unwrap_or_else(|error| panic!("controller identity should be valid: {error}"));
    let other = DebugClientId::new("x509-sha256:other")
        .unwrap_or_else(|error| panic!("other identity should be valid: {error}"));
    let controller_role = DebugRole::new([
        DebugCapability::Observe,
        DebugCapability::Control,
        DebugCapability::Mutate,
    ]);

    let lease = control_plane
        .acquire_debug_controller(created.session, controller.clone(), &controller_role)
        .unwrap_or_else(|error| panic!("controller should acquire lease: {error}"));
    let retry = control_plane
        .acquire_debug_controller(created.session, controller, &controller_role)
        .unwrap_or_else(|error| panic!("same controller retry should be idempotent: {error}"));
    assert_eq!(lease, retry);
    control_plane
        .authorize_debug_controller_operation(
            created.session,
            &lease,
            &controller_role,
            DebugCapability::Mutate,
        )
        .unwrap_or_else(|error| panic!("current lease should authorize mutate: {error}"));

    let busy = control_plane
        .acquire_debug_controller(created.session, other, &controller_role)
        .expect_err("a second controller must be rejected");
    assert!(matches!(
        busy,
        LifecycleApiError::DebugAccess {
            source: DebugCoordinatorError::ControllerBusy { .. }
        }
    ));

    control_plane
        .release_debug_controller(created.session, &lease)
        .unwrap_or_else(|error| panic!("current lease should release: {error}"));
    let stale = control_plane
        .release_debug_controller(created.session, &lease)
        .expect_err("released generation must be stale");
    assert!(matches!(
        stale,
        LifecycleApiError::DebugAccess {
            source: DebugCoordinatorError::StaleControllerLease
        }
    ));

    control_plane
        .destroy_session(DestroySessionRequest::new(created.session))
        .await
        .unwrap_or_else(|error| panic!("cleanup destroy should stop actor: {error}"));
}
#[tokio::test(flavor = "current_thread")]
async fn trusted_http2_debug_controller_uses_server_side_identity_and_lease() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|error| panic!("test listener should bind: {error}"));
    let address = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("test listener should have an address: {error}"));
    let mut policy = DebugAuthorizationPolicy::deny_all();
    policy.grant_trusted_unauthenticated_role(DebugRole::new([
        DebugCapability::Observe,
        DebugCapability::Control,
    ]));
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(serve_lifecycle_http2_with_debug_policy_until_shutdown(
        listener,
        lifecycle_control_plane(),
        LifecycleServerMode::read_write(),
        policy,
        async move {
            let _ = shutdown_receiver.await;
        },
    ));
    let client = RpcControlClient::new(RpcEndpoint::http2(format!("http://{address}")))
        .unwrap_or_else(|error| panic!("test RPC client should build: {error}"));
    let scenario = crucible::happy_path_scenario()
        .unwrap_or_else(|error| panic!("happy-path scenario should build: {error}"))
        .scenario;
    let created = client
        .create_session(CreateSessionRequest::inline_form(
            scenario.clone(),
            scenario.seed(),
        ))
        .await
        .unwrap_or_else(|error| panic!("RPC create should start session: {error}"));

    let acquisition = DebugControllerAcquisition::new();
    let lease = client
        .acquire_debug_controller(created.session, &acquisition)
        .await
        .unwrap_or_else(|error| panic!("trusted controller should acquire lease: {error}"));
    assert_eq!(lease.lease().client.as_str(), "trusted-unauthenticated");
    assert_eq!(
        client
            .acquire_debug_controller(created.session, &acquisition)
            .await
            .unwrap_or_else(|error| panic!("acquisition retry should succeed: {error}")),
        lease,
    );
    let concurrent_acquisition = DebugControllerAcquisition::new();
    let concurrent = client
        .clone()
        .acquire_debug_controller(created.session, &concurrent_acquisition)
        .await
        .unwrap_or_else(|error| panic!("concurrent acquisition should succeed: {error}"));
    assert_eq!(concurrent.lease(), lease.lease());
    client
        .attach_debugger(
            created.session,
            &lease,
            &NodeId {
                name: String::from("server"),
            },
        )
        .await
        .unwrap_or_else(|error| panic!("controller should attach debugger: {error}"));
    client
        .attach_debugger(
            created.session,
            &lease,
            &NodeId {
                name: String::from("server"),
            },
        )
        .await
        .unwrap_or_else(|error| panic!("debug attach retry should be idempotent: {error}"));
    assert!(
        client
            .attach_debugger(
                created.session,
                &lease,
                &NodeId {
                    name: String::from("different-node"),
                },
            )
            .await
            .is_err(),
        "an attached debugger must reject a retry for a different node"
    );
    let repositioned = client
        .debug_goto(
            created.session,
            &lease,
            &crucible::DebugCoordinate::virtual_time(VirtualTime::default()),
        )
        .await
        .unwrap_or_else(|error| {
            panic!("authenticated goto must dispatch through the actor: {error}")
        });
    assert_eq!(repositioned.landed.configuration.len(), 64);
    assert_eq!(repositioned.landed.runtime_state.len(), 64);
    assert_eq!(repositioned.landed.requested_coordinate, "virtual-time:0");
    assert_eq!(repositioned.landed.virtual_time_ticks, 0);
    assert_eq!(repositioned.landed.schedule_prefix_len, 0);
    assert_eq!(repositioned.landed.gateway_generation, 2);
    assert_eq!(repositioned.landed.retired_world_cleanup, "reaped");
    assert_eq!(repositioned.target_event_sequence, None);
    client
        .release_debug_controller(created.session, &lease)
        .await
        .unwrap_or_else(|error| panic!("current RPC lease should release: {error}"));
    assert!(
        client
            .attach_debugger(
                created.session,
                &lease,
                &NodeId {
                    name: String::from("server"),
                },
            )
            .await
            .is_err(),
        "a released acquisition must not borrow a sibling holder's generation"
    );
    client
        .attach_debugger(
            created.session,
            &concurrent,
            &NodeId {
                name: String::from("server"),
            },
        )
        .await
        .unwrap_or_else(|error| panic!("concurrent acquisition must survive release: {error}"));
    client
        .release_debug_controller(created.session, &concurrent)
        .await
        .unwrap_or_else(|error| panic!("final concurrent acquisition should release: {error}"));
    assert!(
        client
            .release_debug_controller(created.session, &lease)
            .await
            .is_ok(),
        "a release retry should be idempotent while its tombstone is retained"
    );

    let _ = shutdown_sender.send(());
    server
        .await
        .unwrap_or_else(|error| panic!("server task should join: {error}"))
        .unwrap_or_else(|error| panic!("server should shut down cleanly: {error}"));
}
