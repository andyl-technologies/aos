//! Unit tests for `SystemdClient` driven by an in-process `FakeSystemd` over a
//! zbus p2p connection. See `common/mod.rs` for the harness.

mod common;

use std::time::Duration;

use aos_systemd::{Error, JobResult, SandboxResources, SandboxUnitName, SandboxUnitSpec};
use common::Harness;

/// Cap every client await so a logic bug surfaces as a fast failure rather
/// than a hung test.
async fn with_timeout<F, T>(fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    tokio::time::timeout(Duration::from_secs(5), fut)
        .await
        .expect("operation timed out (likely a missed signal / Subscribe bug)")
}

async fn wait_until<F: Fn() -> bool>(pred: F) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline {
        if pred() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("condition not satisfied within timeout");
}

#[tokio::test]
async fn subscribe_called_before_signal_streams() {
    // Regression guard for the §5.4 pitfall: Subscribe() must be issued during
    // connect, before anything else. (The fake's subscribe-gated emission also
    // means every job test below implicitly proves Subscribe enabled signals.)
    let h = Harness::new().await;
    let calls = h.calls();
    assert_eq!(
        calls.first().map(String::as_str),
        Some("subscribe"),
        "Subscribe must be the first manager call; got {calls:?}"
    );
}

#[tokio::test]
async fn job_done() {
    let h = Harness::new().await;
    h.set_next_result("done");
    let outcome = with_timeout(h.client.restart_unit("foo.service"))
        .await
        .unwrap();
    assert_eq!(outcome.result, JobResult::Done);
}

#[tokio::test]
async fn job_failed() {
    let h = Harness::new().await;
    h.set_next_result("failed");
    let outcome = with_timeout(h.client.start_unit("foo.service"))
        .await
        .unwrap();
    assert_eq!(outcome.result, JobResult::Failed);
}

#[tokio::test]
async fn job_timeout() {
    let h = Harness::new().await;
    h.set_next_result("timeout");
    let outcome = with_timeout(h.client.start_unit("foo.service"))
        .await
        .unwrap();
    assert_eq!(outcome.result, JobResult::Timeout);
}

#[tokio::test]
async fn job_dependency() {
    let h = Harness::new().await;
    h.set_next_result("dependency");
    let outcome = with_timeout(h.client.start_unit("foo.service"))
        .await
        .unwrap();
    assert_eq!(outcome.result, JobResult::Dependency);
}

#[tokio::test]
async fn job_unknown_preserves_label() {
    let h = Harness::new().await;
    h.set_next_result("canceled");
    let outcome = with_timeout(h.client.restart_unit("foo.service"))
        .await
        .unwrap();
    assert_eq!(outcome.result, JobResult::Unknown("canceled".to_string()));
    assert_eq!(outcome.result.label(), "canceled");
}

#[tokio::test]
async fn settle_drains_late_messages() {
    let h = Harness::new().await;
    // Five standalone JobRemoved events with no awaiter.
    for i in 0..5 {
        h.emit_job_removed(100 + i, "late.service", "done").await;
    }
    let drained = with_timeout(h.client.settle()).await.unwrap();
    assert_eq!(drained, 5, "settle should count all five late events");
}

#[tokio::test]
async fn reloading_flag_flips() {
    let h = Harness::new().await;
    assert!(!h.client.is_reloading());

    h.emit_reloading(true).await;
    wait_until(|| h.client.is_reloading()).await;

    h.emit_reloading(false).await;
    wait_until(|| !h.client.is_reloading()).await;
}

#[tokio::test]
async fn concurrent_jobs_route_by_path() {
    // Ten concurrent jobs, alternating done/failed by unit name. Each awaiter
    // must wake with *its own* result — the core path-keyed-routing property.
    let h = Harness::new().await;
    for i in 0..10 {
        let result = if i % 2 == 0 { "done" } else { "failed" };
        h.set_unit_result(&format!("u{i}.service"), result);
    }

    let futures = (0..10)
        .map(|i| h.client.restart_unit(format!("u{i}.service").leak()))
        .collect::<Vec<_>>();
    let outcomes = with_timeout(futures_util::future::join_all(futures)).await;

    for (i, outcome) in outcomes.into_iter().enumerate() {
        let outcome = outcome.unwrap();
        let expected = if i % 2 == 0 {
            JobResult::Done
        } else {
            JobResult::Failed
        };
        assert_eq!(outcome.result, expected, "unit u{i} routed to wrong result");
    }
}

#[tokio::test]
async fn bus_drop_with_pending_waiter_returns_error_not_hang() {
    // Regression guard for the dbus.service self-restart hang: the reconcile
    // drives systemd over the system bus and one of the units it restarts is
    // dbus.service itself. Restarting the bus tears down the connection, so the
    // job's terminal `JobRemoved` never arrives. The client MUST surface this
    // as `JobSenderDropped` (the bus-died-mid-flight contract in error.rs),
    // NOT park the awaiter forever.
    //
    // We model it deterministically: suppress the fake's terminal signal so the
    // job stays "in flight", then close the server connection out from under
    // the in-flight `restart_unit`. Without the fix the await never resolves and
    // `with_timeout` fires; with it, the await returns `JobSenderDropped`.
    let h = Harness::new().await;
    h.suppress_job_emission();

    let result = with_timeout(async {
        // Drive the restart concurrently with the connection drop. The restart
        // first issues the (successful) RestartUnit call — registering a waiter
        // — then parks on the missing JobRemoved; only then do we kill the bus.
        let (res, ()) = tokio::join!(h.client.restart_unit("dbus.service"), async {
            wait_until(|| h.calls().contains(&"restart_unit".to_string())).await;
            // Let the method reply land and the waiter register before the drop.
            tokio::time::sleep(Duration::from_millis(100)).await;
            h.close_server().await;
        });
        res
    })
    .await;

    match result {
        Err(Error::JobSenderDropped(unit)) => {
            assert!(
                unit.contains("job/"),
                "JobSenderDropped should name the orphaned job path; got {unit:?}"
            );
        }
        other => panic!("expected JobSenderDropped after bus drop, got {other:?}"),
    }
}

#[tokio::test]
async fn reboot_calls_manager_reboot() {
    // Replaces the old microVM systemctl-binary reboot assertion: prove apm
    // issues Manager.Reboot over D-Bus, without actually rebooting anything.
    let h = Harness::new().await;
    with_timeout(h.client.reboot()).await.unwrap();
    assert!(
        h.calls().contains(&"reboot".to_string()),
        "expected a reboot call; got {:?}",
        h.calls()
    );
}

#[tokio::test]
async fn daemon_reload_calls_manager_reload() {
    let h = Harness::new().await;
    with_timeout(h.client.daemon_reload()).await.unwrap();
    assert!(h.calls().contains(&"reload".to_string()));
}

#[tokio::test]
async fn reset_failed_calls_through() {
    let h = Harness::new().await;
    with_timeout(h.client.reset_failed()).await.unwrap();
    assert!(h.calls().contains(&"reset_failed".to_string()));
}

#[tokio::test]
async fn transient_sandbox_uses_typed_exact_transport() {
    let h = Harness::new().await;
    let name = SandboxUnitName::from_incarnation([0x42; 16]);
    let resources = SandboxResources::new(512, 1024, 64, 100).unwrap();
    let spec = SandboxUnitSpec::new(
        name.clone(),
        "/nix/store/test-systemd/bin/systemd-nspawn",
        vec!["--settings=no".into(), "--boot".into()],
        "/proc/123/fd/7",
        resources,
        Duration::from_secs(30),
        Duration::from_secs(10),
    )
    .unwrap();

    let outcome = with_timeout(h.client.start_sandbox_unit(&spec))
        .await
        .unwrap();
    assert_eq!(outcome.result, JobResult::Done);

    let request = h.state.transient_request.lock().unwrap().clone().unwrap();
    assert_eq!(request.0, name.as_str());
    assert_eq!(request.1, "fail");
    assert!(request.2.contains(&("ExecStart".into(), "a(sasb)".into())));
    assert!(request.2.contains(&("BindsTo".into(), "as".into())));
    assert!(request.2.contains(&("MemoryMax".into(), "t".into())));
}

#[tokio::test]
async fn sandbox_freeze_and_thaw_use_manager_methods() {
    let h = Harness::new().await;
    let name = SandboxUnitName::from_incarnation([7; 16]);
    with_timeout(h.client.freeze_sandbox_unit(&name))
        .await
        .unwrap();
    with_timeout(h.client.thaw_sandbox_unit(&name))
        .await
        .unwrap();

    let calls = h.calls();
    assert!(calls.contains(&"freeze_unit".to_string()));
    assert!(calls.contains(&"thaw_unit".to_string()));
}

#[tokio::test]
async fn sandbox_observation_reads_typed_live_properties() {
    let h = Harness::new().await;
    let name = SandboxUnitName::from_incarnation([7; 16]);
    let observation = with_timeout(h.client.observe_sandbox_unit(&name))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(observation.active_state, "active");
    assert_eq!(observation.sub_state, "running");
    assert_eq!(observation.supervisor_pid.unwrap().get(), 4242);
    assert_eq!(observation.invocation_id, Some([9; 16]));
    assert_eq!(
        observation.cgroup.unwrap().as_str(),
        format!("/aos-sandboxes.slice/{}", name.as_str())
    );
}
