//! Cancellation-safety regressions for controller ownership transitions.

use super::*;

#[tokio::test]
async fn cancelled_acquire_cannot_leave_an_untracked_controller() -> Result<(), Box<dyn Error>> {
    let mut state = test_state(LifecycleServerMode::read_write());
    let role = DebugRole::new([DebugCapability::Observe, DebugCapability::Control]);
    state
        .debug_authorization
        .grant_trusted_unauthenticated_role(role.clone());
    let scenario = crucible::happy_path_scenario()?.scenario;
    let session = state
        .control_plane
        .lock()
        .await
        .create_session(CreateSessionRequest::inline_form(
            scenario.clone(),
            scenario.seed(),
        ))
        .await?
        .session;
    let holder = uuid::Uuid::from_u128(111);
    let request = format!(
        "crucible.rpc/debug-controller-acquire-request\nsession-id={}\nepoch={}\nseed={}\nholder={}\n",
        session.id.value,
        session.epoch,
        session.seed.to_hex(),
        holder,
    );
    let blocked_holders = state.debug_holders.lock().await;
    let handler_state = state.clone();
    let handler = tokio::spawn(async move {
        handle_debug_controller_acquire(State(handler_state), None, rpc_request(request)).await
    });
    wait_until_control_lock_is_held(&state).await;
    handler.abort();
    assert!(handler.await.is_err());
    drop(blocked_holders);

    assert!(!state.debug_holders.lock().await.has_active_session(session));
    let controller_client = DebugClientId::new("trusted-unauthenticated")?;
    state
        .control_plane
        .lock()
        .await
        .acquire_debug_controller(session, controller_client, &role)?;
    Ok(())
}

#[tokio::test]
async fn cancelled_final_release_preserves_holder_and_controller() -> Result<(), Box<dyn Error>> {
    let mut state = test_state(LifecycleServerMode::read_write());
    let role = DebugRole::new([DebugCapability::Observe, DebugCapability::Control]);
    state
        .debug_authorization
        .grant_trusted_unauthenticated_role(role.clone());
    let scenario = crucible::happy_path_scenario()?.scenario;
    let session = state
        .control_plane
        .lock()
        .await
        .create_session(CreateSessionRequest::inline_form(
            scenario.clone(),
            scenario.seed(),
        ))
        .await?
        .session;
    let controller_client = DebugClientId::new("trusted-unauthenticated")?;
    let lease = state.control_plane.lock().await.acquire_debug_controller(
        session,
        controller_client,
        &role,
    )?;
    let holder = uuid::Uuid::from_u128(112);
    state
        .debug_holders
        .lock()
        .await
        .register(session, lease.clone(), holder)?;
    let request = format!(
        "crucible.rpc/debug-controller-release-request\nsession-id={}\nepoch={}\nseed={}\ngeneration={}\nholder={}\n",
        session.id.value,
        session.epoch,
        session.seed.to_hex(),
        lease.generation,
        holder,
    );
    let blocked_holders = state.debug_holders.lock().await;
    let handler_state = state.clone();
    let handler = tokio::spawn(async move {
        handle_debug_controller_release(State(handler_state), None, rpc_request(request)).await
    });
    wait_until_control_lock_is_held(&state).await;
    handler.abort();
    assert!(handler.await.is_err());
    drop(blocked_holders);

    state
        .debug_holders
        .lock()
        .await
        .authorize(session, &lease, holder)?;
    let other = DebugClientId::new("other-controller")?;
    assert!(
        state
            .control_plane
            .lock()
            .await
            .acquire_debug_controller(session, other, &role)
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn cancelled_request_retains_gate_until_enqueued_operation_finishes()
-> Result<(), Box<dyn Error>> {
    let state = test_state(LifecycleServerMode::read_write());
    let scenario = crucible::happy_path_scenario()?.scenario;
    let session = state
        .control_plane
        .lock()
        .await
        .create_session(CreateSessionRequest::inline_form(
            scenario.clone(),
            scenario.seed(),
        ))
        .await?
        .session;
    let guard = debug_operation_guard(&state, session).await;
    let (started_sender, started_receiver) = tokio::sync::oneshot::channel();
    let finish = Arc::new(tokio::sync::Notify::new());
    let operation_finish = Arc::clone(&finish);
    let request = tokio::spawn(async move {
        complete_debug_operation(guard, async move {
            let _ = started_sender.send(());
            operation_finish.notified().await;
        })
        .await
    });
    started_receiver.await?;
    request.abort();
    assert!(request.await.is_err());

    let waiting_state = state.clone();
    let mut handoff =
        tokio::spawn(async move { debug_operation_guard(&waiting_state, session).await });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(10), &mut handoff)
            .await
            .is_err(),
        "controller handoff must remain blocked after the request future is cancelled"
    );
    finish.notify_one();
    let acquired = tokio::time::timeout(std::time::Duration::from_secs(1), handoff)
        .await?
        .map_err(|error| format!("operation-gate task failed: {error}"))?;
    drop(acquired);
    Ok(())
}
