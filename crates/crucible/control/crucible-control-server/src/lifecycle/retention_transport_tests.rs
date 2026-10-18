//! Checks admitted builder destruction on actual async cancellation boundaries.

use super::*;
use crucible_control_api::admitted_output::test_support::tracked_fixture_budget;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Waker};

type DestructionOrder = Arc<std::sync::Mutex<Vec<(&'static str, bool)>>>;

struct Probe {
    label: &'static str,
    used: Arc<AtomicU64>,
    minimum: Arc<AtomicU64>,
    order: DestructionOrder,
}

impl Drop for Probe {
    fn drop(&mut self) {
        self.order.lock().unwrap().push((
            self.label,
            self.used.load(Ordering::SeqCst) >= self.minimum.load(Ordering::SeqCst),
        ));
    }
}

async fn cancel_builder_request(after_lock_poll: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Semantic payloads use a separate fixture account so they cannot hide an
    // early return of the actual builder/capability allocation account.
    let (source, configuration, checkpoint) = {
        let _scope = crucible_engine::test_support::fixture_decode_scope(64 * 1024 * 1024)?;
        let source = crucible_engine::happy_path_scenario()?.scenario;
        let configuration = Configuration::genesis(source.scenario_def());
        let checkpoint = Checkpoint::from_recorded_configuration(
            &configuration,
            None,
            VirtualTime::default(),
            BTreeMap::new(),
            CheckpointKind::Fat,
            BTreeMap::new(),
        )?;
        (source, configuration, checkpoint)
    };
    let seed = source.scenario_def().seed();
    let client = InProcessLifecycleClient::new(LifecycleControlPlane::new(
        "ordered-builder-cancellation",
        Vec::new(),
        |_scenario: &ScenarioDef, _seed| QuiescentLifecycleLoop::new(),
    ));
    let order = Arc::new(std::sync::Mutex::new(Vec::new()));
    let minimum = Arc::new(AtomicU64::new(1));
    let (budget, used) = tracked_fixture_budget(4096)?;
    let scope = budget.enter();
    let capability = Probe {
        label: "capability",
        used: used.clone(),
        minimum: minimum.clone(),
        order: order.clone(),
    };
    let retention = SessionLifetimeRetention::try_new_admitted(capability)?;
    let captured = Probe {
        label: "builder",
        used: used.clone(),
        minimum: minimum.clone(),
        order: order.clone(),
    };
    let builder = move || {
        drop(captured);
        Ok::<_, std::convert::Infallible>(QuiescentLifecycleLoop::new())
    };
    crucible_engine::owned_decode::charge_bytes(std::alloc::Layout::for_value(&builder).size() as u64)?;
    let builder = Box::new(builder);
    minimum.store(used.load(Ordering::SeqCst), Ordering::SeqCst);

    let held = client.control_plane.lock().await;
    let mut pending = Box::pin(
        client.admit_authenticated_read_only_session_with_decode_budget(
            source,
            configuration,
            checkpoint,
            seed,
            (builder, retention, Some(budget.clone())),
        ),
    );
    drop(scope);
    drop(budget);
    if after_lock_poll {
        let mut context = Context::from_waker(Waker::noop());
        assert!(pending.as_mut().poll(&mut context).is_pending());
    }
    assert!(order.lock().unwrap().is_empty());
    drop(pending);

    assert_eq!(
        *order.lock().unwrap(),
        vec![("builder", true), ("capability", true)]
    );
    assert_eq!(used.load(Ordering::SeqCst), 0);
    drop(held);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn unpolled_builder_request_keeps_account_until_builder_and_capability_drop()
-> Result<(), Box<dyn std::error::Error>> {
    cancel_builder_request(false).await
}

#[tokio::test(flavor = "current_thread")]
async fn builder_request_canceled_while_waiting_for_plane_keeps_the_same_order()
-> Result<(), Box<dyn std::error::Error>> {
    cancel_builder_request(true).await
}
