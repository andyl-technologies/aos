//! Fault coordinate an admitted frame is evaluated at.

use super::*;

/// Frame sequence and the coordinate it was intercepted at, in call order.
type InterceptedCoordinates = Rc<RefCell<Vec<(u64, u64)>>>;

/// Records the coordinate each frame is intercepted at, then drops it.
#[derive(Clone)]
struct CoordinateInterceptor(InterceptedCoordinates);

impl BackendNetworkOutputInterceptor<SingleScheduler, TestConcurrentBackend>
    for CoordinateInterceptor
{
    fn intercept_network_outputs(
        &mut self,
        _scheduler: &mut SingleScheduler,
        _backend: &mut TestConcurrentBackend,
        frontier: VirtualTime,
        _pending_outputs: &mut Vec<BackendNetworkOutput>,
        outputs: &mut Vec<BackendNetworkOutput>,
    ) -> Result<Vec<SchedulerEventLogAppend>, SchedulerError> {
        for output in outputs.iter() {
            self.0.borrow_mut().push((output.sequence, frontier.ticks));
        }
        outputs.clear();
        Ok(Vec::new())
    }
}

type CoordinateAdapter =
    BackendQuantumLoop<SingleScheduler, TestConcurrentBackend, CoordinateInterceptor>;

/// Builds a source that transmits at 30 to a receiver. An idle receiver's
/// clock lags at 0; a runnable one keeps pace. `source_timer` changes only how
/// the host splits the source's RUNs.
fn coordinate_adapter(
    receiver: SchedulerNodeActivity,
    source_timer: Option<u64>,
) -> (CoordinateAdapter, InterceptedCoordinates) {
    let scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "network-output-admission-coordinate",
        16,
        SimInstant { ticks: 64 },
        vec![
            test_scenario_node(
                "i-receiver",
                0,
                receiver,
                NetworkLookahead::Infinite,
                ExactLocalEvent::NoArmedTimer,
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
        Vec::new(),
    ))
    .unwrap_or_else(|error| panic!("admission-coordinate scenario should build: {error}"));
    let coordinates = Rc::new(RefCell::new(Vec::new()));
    let mut backend =
        TestConcurrentBackend::new(false).with_network_output_to("x-source", "i-receiver", 30);
    backend.control_v3 = true;
    let adapter = BackendQuantumLoop::with_network_output_interceptor(
        scheduler,
        backend,
        CoordinateInterceptor(Rc::clone(&coordinates)),
    );

    (adapter, coordinates)
}

fn drive(adapter: &mut CoordinateAdapter) {
    let configuration = adapter.loop_impl().configuration().clone();
    adapter
        .drive_concurrent_quantum(
            QuantumRequest {
                configuration,
                control: Vec::new(),
            },
            2,
        )
        .unwrap_or_else(|error| panic!("admission-coordinate quantum should drive: {error}"));
}

#[test]
fn a_frame_is_evaluated_at_its_release_time_beside_a_lagging_idle_clock() {
    for source_timer in [None, Some(30), Some(40)] {
        let (mut adapter, coordinates) =
            coordinate_adapter(SchedulerNodeActivity::Idle, source_timer);

        for _ in 0..8 {
            drive(&mut adapter);
            if !coordinates.borrow().is_empty() {
                break;
            }
        }

        assert_eq!(
            *coordinates.borrow(),
            [(0, 30)],
            "a frame emitted at 30 is evaluated at 30 with timer {source_timer:?}"
        );
    }
}

#[test]
fn a_frame_admitted_after_its_release_time_is_evaluated_at_that_time() {
    let (mut adapter, coordinates) = coordinate_adapter(SchedulerNodeActivity::Runnable, Some(20));
    for _ in 0..8 {
        drive(&mut adapter);
        if adapter.committed_frontier().ticks >= 20 {
            break;
        }
    }
    let frontier = adapter.committed_frontier().ticks;
    assert!(
        frontier >= 20,
        "the frontier should pass 20, reached {frontier}"
    );
    coordinates.borrow_mut().clear();

    // A frame released at 10 that no earlier publication admitted is admitted
    // now, at a frontier past its release time.
    let source = NodeId {
        name: String::from("x-source"),
    };
    adapter.retain_pending_network_output_times(&source, vec![(7, VirtualTime { ticks: 10 })]);
    adapter
        .network_transaction_parts_mut()
        .3
        .push(BackendNetworkOutput {
            source,
            destination: NodeId {
                name: String::from("i-receiver"),
            },
            emit_icount: Icount { retired: 10 },
            sequence: 7,
            payload: vec![1],
            route: None,
            fault_continuation: BackendNetworkFaultContinuation::default(),
        });
    adapter
        .settle_pending_network_outputs_at_current_frontier()
        .unwrap_or_else(|error| panic!("the late frame should settle: {error}"));

    assert_eq!(*coordinates.borrow(), [(7, 10)]);
}
