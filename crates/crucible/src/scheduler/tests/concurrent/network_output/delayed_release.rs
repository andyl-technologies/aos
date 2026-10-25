//! Canonical log position of a frame released from adapter custody.

use super::*;

const DELAYED_RELEASE_TICKS: u64 = 30;

#[derive(Clone)]
struct DelayedReleaseInterceptor(Rc<RefCell<Vec<Vec<u64>>>>);

impl BackendNetworkOutputInterceptor<SingleScheduler, TestConcurrentBackend>
    for DelayedReleaseInterceptor
{
    fn intercept_network_outputs(
        &mut self,
        scheduler: &mut SingleScheduler,
        _backend: &mut TestConcurrentBackend,
        _frontier: VirtualTime,
        _pending_outputs: &mut Vec<BackendNetworkOutput>,
        outputs: &mut Vec<BackendNetworkOutput>,
    ) -> Result<Vec<SchedulerEventLogAppend>, SchedulerError> {
        // Each release records which delivery orders the log already holds.
        for _ in outputs.iter() {
            self.0
                .borrow_mut()
                .push(delivery_order_times(scheduler.configuration()));
        }
        outputs.clear();
        Ok(Vec::new())
    }
}

fn delivery_order_times(configuration: &Configuration) -> Vec<u64> {
    configuration
        .schedule
        .decision_history()
        .iter()
        .filter_map(|decision| match decision {
            Decision::DeliveryOrder(order) => Some(order.at.ticks),
            _ => None,
        })
        .collect()
}

/// Drives a consumer with deliveries at 20 and 40 beside a source holding a
/// frame in adapter custody until 30. `source_timer` adds a source-local
/// boundary, which changes only how the host splits the source's RUNs.
fn delayed_release_log(source_timer: Option<u64>) -> (Vec<Vec<u64>>, Vec<u64>) {
    let consumer = scheduler_node("c-consumer", SchedulingNodeKind::Vm);
    let network = scheduler_node("link", SchedulingNodeKind::Network);
    let scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "network-output-delayed-release",
        16,
        SimInstant { ticks: 64 },
        vec![
            test_scenario_node(
                "c-consumer",
                0,
                SchedulerNodeActivity::Runnable,
                NetworkLookahead::Infinite,
                ExactLocalEvent::TimerDeadline {
                    virtual_time: SimInstant { ticks: 64 },
                },
            ),
            test_scenario_node(
                "x-source",
                0,
                SchedulerNodeActivity::Runnable,
                NetworkLookahead::Infinite,
                source_timer.map_or(ExactLocalEvent::NoArmedTimer, |ticks| {
                    ExactLocalEvent::TimerDeadline {
                        virtual_time: SimInstant { ticks },
                    }
                }),
            ),
        ],
        vec![
            event(20, &consumer, &network, 1, b"first"),
            event(40, &consumer, &network, 2, b"second"),
        ],
    ))
    .unwrap_or_else(|error| panic!("delayed-release scenario should build: {error}"));
    let releases = Rc::new(RefCell::new(Vec::new()));
    // Control 3 keeps a clock per node, as the QEMU contract does.
    let mut backend = TestConcurrentBackend::new(false);
    backend.control_v3 = true;
    let mut adapter = BackendQuantumLoop::with_network_output_interceptor(
        scheduler,
        backend,
        DelayedReleaseInterceptor(Rc::clone(&releases)),
    );

    let opportunity = ContentHash::from_bytes(b"delayed-release");
    let mut held = BackendNetworkOutput {
        source: NodeId {
            name: String::from("x-source"),
        },
        destination: NodeId {
            name: String::from("c-consumer"),
        },
        emit_icount: Icount { retired: 0 },
        sequence: 0,
        payload: vec![1],
        route: None,
        fault_continuation: BackendNetworkFaultContinuation::default(),
    };
    held.fault_continuation
        .cursor_mut()
        .defer_until(DELAYED_RELEASE_TICKS, opportunity);
    adapter.network_transaction_parts_mut().3.push(held);

    for _ in 0..16 {
        let configuration = adapter.loop_impl().configuration().clone();
        adapter
            .drive_concurrent_quantum(
                QuantumRequest {
                    configuration,
                    control: Vec::new(),
                },
                2,
            )
            .unwrap_or_else(|error| panic!("delayed-release quantum should drive: {error}"));
        let delivered = delivery_order_times(adapter.loop_impl().configuration());
        if delivered.len() == 2 && !releases.borrow().is_empty() {
            break;
        }
    }

    let delivered = delivery_order_times(adapter.loop_impl().configuration());
    let releases = releases.borrow().clone();
    (releases, delivered)
}

#[test]
fn a_custody_release_takes_one_log_position_however_the_source_runs_split() {
    let (unsplit_releases, unsplit_orders) = delayed_release_log(None);
    let (split_releases, split_orders) = delayed_release_log(Some(35));

    assert_eq!(unsplit_orders, [20, 40]);
    assert_eq!(split_orders, [20, 40]);
    assert_eq!(
        unsplit_releases, split_releases,
        "a RUN split must not move the release in the log"
    );
    // The frame resumes at 30, so it follows the delivery at 20 and precedes
    // the one at 40.
    assert_eq!(unsplit_releases, [vec![20]]);
}
