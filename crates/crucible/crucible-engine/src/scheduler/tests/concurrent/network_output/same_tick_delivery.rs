//! Log order of a node's delivery and its own output at one virtual time.

use super::*;

/// Delivery-order times the log held when each frame was admitted, with the
/// coordinate the frame was evaluated at.
type AdmissionViews = Rc<RefCell<Vec<(u64, Vec<u64>)>>>;

/// Records which deliveries precede each admitted frame, then drops it.
#[derive(Clone)]
struct SameTickInterceptor(AdmissionViews);

impl BackendNetworkOutputInterceptor<SingleScheduler, TestConcurrentBackend>
    for SameTickInterceptor
{
    fn intercept_network_outputs(
        &mut self,
        scheduler: &mut SingleScheduler,
        _backend: &mut TestConcurrentBackend,
        frontier: VirtualTime,
        _pending_outputs: &mut Vec<BackendNetworkOutput>,
        outputs: &mut Vec<BackendNetworkOutput>,
    ) -> Result<Vec<SchedulerEventLogAppend>, SchedulerError> {
        for _ in outputs.iter() {
            self.0
                .borrow_mut()
                .push((frontier.ticks, delivered_times(scheduler.configuration())));
        }
        outputs.clear();
        Ok(Vec::new())
    }
}

fn delivered_times(configuration: &Configuration) -> Vec<u64> {
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

fn timer(at: Option<u64>) -> ExactLocalEvent {
    at.map_or(ExactLocalEvent::NoArmedTimer, |ticks| {
        ExactLocalEvent::TimerDeadline {
            virtual_time: SimInstant { ticks },
        }
    })
}

/// One way the host can split the RUNs around the shared time.
#[derive(Clone, Copy, Debug)]
struct Split {
    /// Local timer on the node that receives and transmits.
    node_timer: Option<u64>,
    /// Local timer on an unrelated peer, which changes publication order.
    peer_timer: Option<u64>,
    /// Coordinate the node's frame is emitted at.
    emit: u64,
    /// Adapter custody release, when the frame is held past its emission.
    release: Option<u64>,
}

/// Drives node `m-node` with a delivery at 40 and its own frame released at
/// 40, and returns the admission views.
fn same_tick_views(split: Split) -> AdmissionViews {
    let node = scheduler_node("m-node", SchedulingNodeKind::Vm);
    let network = scheduler_node("link", SchedulingNodeKind::Network);
    let scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "network-output-same-tick-delivery",
        16,
        SimInstant { ticks: 64 },
        vec![
            test_scenario_node(
                "m-node",
                0,
                SchedulerNodeActivity::Runnable,
                NetworkLookahead::Infinite,
                timer(split.node_timer),
            ),
            test_scenario_node(
                "z-peer",
                0,
                SchedulerNodeActivity::Runnable,
                NetworkLookahead::Infinite,
                timer(split.peer_timer),
            ),
        ],
        vec![event(40, &node, &network, 1, b"same-tick")],
    ))
    .unwrap_or_else(|error| panic!("same-tick scenario should build: {error}"));
    let views = Rc::new(RefCell::new(Vec::new()));
    let mut backend = TestConcurrentBackend::new(false);
    // Control 3 keeps a clock per node, as the QEMU contract does.
    backend.control_v3 = true;
    let backend = if split.release.is_none() {
        backend.with_network_output_to("m-node", "z-peer", split.emit)
    } else {
        backend
    };
    let mut adapter = BackendQuantumLoop::with_network_output_interceptor(
        scheduler,
        backend,
        SameTickInterceptor(Rc::clone(&views)),
    );
    if let Some(release) = split.release {
        let mut held = BackendNetworkOutput {
            source: NodeId {
                name: String::from("m-node"),
            },
            destination: NodeId {
                name: String::from("z-peer"),
            },
            emit_icount: Icount {
                retired: split.emit,
            },
            sequence: 0,
            payload: vec![1],
            route: None,
            fault_continuation: BackendNetworkFaultContinuation::default(),
        };
        held.fault_continuation
            .cursor_mut()
            .defer_until(release, ContentHash::from_bytes(b"same-tick-custody"));
        adapter.network_transaction_parts_mut().3.push(held);
    }

    for _ in 0..16 {
        // The production loop releases queued frames before every quantum.
        adapter
            .settle_pending_network_outputs_at_current_frontier()
            .unwrap_or_else(|error| panic!("same-tick settlement should commit: {error}"));
        let configuration = adapter.loop_impl().configuration().clone();
        adapter
            .drive_concurrent_quantum(
                QuantumRequest {
                    configuration,
                    control: Vec::new(),
                },
                2,
            )
            .unwrap_or_else(|error| panic!("same-tick quantum should drive: {error}"));
        if !views.borrow().is_empty()
            && delivered_times(adapter.loop_impl().configuration()).contains(&40)
        {
            break;
        }
    }

    views
}

#[test]
fn a_delivery_precedes_the_nodes_own_frame_at_that_time_however_runs_split() {
    let mut splits = Vec::new();
    for node_timer in [None, Some(20), Some(39), Some(40)] {
        for peer_timer in [None, Some(39), Some(40)] {
            splits.push(Split {
                node_timer,
                peer_timer,
                emit: 40,
                release: None,
            });
            splits.push(Split {
                node_timer,
                peer_timer,
                emit: 30,
                release: Some(40),
            });
        }
    }

    for split in splits {
        let views = same_tick_views(split);
        let views = views.borrow();
        assert_eq!(views.len(), 1, "one frame is admitted with {split:?}");
        let (coordinate, delivered) = &views[0];
        assert_eq!(
            *coordinate, 40,
            "the frame is evaluated at 40 with {split:?}"
        );
        assert_eq!(
            delivered,
            &vec![40],
            "the delivery at 40 is logged before the frame admitted at 40 with {split:?}"
        );
    }
}
