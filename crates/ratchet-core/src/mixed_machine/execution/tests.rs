//! Executable mixed-machine contract tests.

use super::super::*;
use super::*;
use crate::syntax::Span;
use crate::{FrameId, IrId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestValue {
    Int(i64),
    Bool(bool),
    Null,
    Node(u8),
    Closure(u8),
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("test runtime rejected a value")]
struct TestRuntimeError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TestForceTarget(u16);

#[derive(Debug)]
struct TestRuntime {
    frames: Vec<Vec<TestValue>>,
    published: Vec<(TestForceTarget, u8, TestValue)>,
    aborted: Vec<(TestForceTarget, u8)>,
    decline_force: bool,
    decline_call: bool,
    decline_call_at: Option<u64>,
    callable_inspections: u64,
    fail_claimed_load: bool,
    panic_claimed_load: bool,
    forced_shape: MixedForceShape,
    forced_work_override: Option<MixedCodeIdentity>,
    force_ready: bool,
    fail_publish: bool,
}

impl TestRuntime {
    fn new() -> Self {
        Self {
            frames: vec![vec![TestValue::Node(9)], vec![TestValue::Int(40)]],
            published: Vec::new(),
            aborted: Vec::new(),
            decline_force: false,
            decline_call: false,
            decline_call_at: None,
            callable_inspections: 0,
            fail_claimed_load: false,
            panic_claimed_load: false,
            forced_shape: MixedForceShape::Node,
            forced_work_override: None,
            force_ready: false,
            fail_publish: false,
        }
    }
}

impl MixedMachineRuntime for TestRuntime {
    type Value = TestValue;
    type Frame = usize;
    type ForceTarget = TestForceTarget;
    type UpdateToken = u8;
    type Error = TestRuntimeError;

    fn integer(&mut self, value: i64) -> Result<Self::Value, Self::Error> {
        Ok(TestValue::Int(value))
    }

    fn boolean(&mut self, value: bool) -> Self::Value {
        TestValue::Bool(value)
    }

    fn null(&mut self) -> Self::Value {
        TestValue::Null
    }

    fn load_local(&mut self, frame: Self::Frame, slot: u32) -> Result<Self::Value, Self::Error> {
        if frame == 1 && self.panic_claimed_load {
            panic!("injected claimed-work panic");
        }
        if frame == 1 && self.fail_claimed_load {
            return Err(TestRuntimeError);
        }
        self.frames
            .get(frame)
            .and_then(|values| values.get(slot as usize))
            .copied()
            .ok_or(TestRuntimeError)
    }

    fn load_upvalue(
        &mut self,
        frame: Self::Frame,
        depth: u32,
        slot: u32,
    ) -> Result<Self::Value, Self::Error> {
        let Some(parent) = frame.checked_sub(depth as usize) else {
            return Err(TestRuntimeError);
        };
        self.load_local(parent, slot)
    }

    fn add_integer(
        &mut self,
        left: Self::Value,
        right: Self::Value,
    ) -> Result<Self::Value, Self::Error> {
        let (TestValue::Int(left), TestValue::Int(right)) = (left, right) else {
            return Err(TestRuntimeError);
        };
        left.checked_add(right)
            .map(TestValue::Int)
            .ok_or(TestRuntimeError)
    }

    fn integer_less_than(
        &mut self,
        left: Self::Value,
        right: Self::Value,
    ) -> Result<Self::Value, Self::Error> {
        let (TestValue::Int(left), TestValue::Int(right)) = (left, right) else {
            return Err(TestRuntimeError);
        };
        Ok(TestValue::Bool(left < right))
    }

    fn decode_boolean(&mut self, value: Self::Value) -> Result<bool, Self::Error> {
        let TestValue::Bool(value) = value else {
            return Err(TestRuntimeError);
        };
        Ok(value)
    }

    fn begin_force(
        &mut self,
        subject: Self::Value,
        guards: MixedForceGuards,
    ) -> Result<
        MixedForceAction<Self::Value, Self::Frame, Self::ForceTarget, Self::UpdateToken>,
        Self::Error,
    > {
        if self.decline_force {
            return Ok(MixedForceAction::Declined);
        }
        match subject {
            value if self.force_ready => Ok(MixedForceAction::Ready(value)),
            TestValue::Node(token) => Ok(MixedForceAction::Claimed {
                target: TestForceTarget(1_000 + u16::from(token)),
                shape: self.forced_shape,
                work: self
                    .forced_work_override
                    .unwrap_or_else(|| guards.for_shape(self.forced_shape)),
                frame: 1,
                update: token,
            }),
            value => Ok(MixedForceAction::Ready(value)),
        }
    }

    fn inspect_callable(
        &mut self,
        callable: Self::Value,
    ) -> Result<MixedCallable<Self::Frame>, Self::Error> {
        self.callable_inspections = self.callable_inspections.saturating_add(1);
        if self.decline_call || self.decline_call_at == Some(self.callable_inspections) {
            return Ok(MixedCallable::Declined);
        }
        match callable {
            TestValue::Closure(id) => Ok(MixedCallable::Materialized {
                code: code(u32::from(id)),
                frame: 0,
            }),
            _ => Ok(MixedCallable::Declined),
        }
    }

    fn publish_update(
        &mut self,
        target: &Self::ForceTarget,
        token: &Self::UpdateToken,
        value: Self::Value,
    ) -> Result<(), Self::Error> {
        if self.fail_publish {
            return Err(TestRuntimeError);
        }
        self.published.push((*target, *token, value));
        Ok(())
    }

    fn abort_update(&mut self, target: Self::ForceTarget, token: Self::UpdateToken) {
        self.aborted.push((target, token));
    }
}

fn source(id: u32) -> MixedSource {
    MixedSource::new([3; 32], IrId::new(id), Span::new(id, id + 1))
}

fn code(id: u32) -> MixedCodeIdentity {
    MixedCodeIdentity::new(
        [3; 32],
        IrId::new(id),
        IrId::new(id + 1),
        Some(FrameId::new(id)),
        [id as u8; 32],
    )
}

fn executable_force_call_plan() -> MixedModulePlan {
    MixedModulePlan::new(
        MixedModuleKey::new([3; 32], [4; 32], 1),
        MixedPlanBounds::new(8, 2, 2),
        vec![MixedEntry {
            kind: MixedEntryKind::ForceWhnf,
            source: source(0),
            function: MixedFunctionId::new(0),
            frame: None,
            capture_layout_digest: [0; 32],
        }],
        vec![
            MixedFunction {
                source: source(0),
                parameter: MixedValueId::new(0),
                parameter_type: MixedValueType::Value,
                return_type: MixedValueType::Value,
                entry: MixedBlockId::new(0),
                blocks: MixedTableRange::new(0, 6),
            },
            MixedFunction {
                source: source(10),
                parameter: MixedValueId::new(7),
                parameter_type: MixedValueType::Value,
                return_type: MixedValueType::Value,
                entry: MixedBlockId::new(6),
                blocks: MixedTableRange::new(6, 1),
            },
        ],
        vec![
            MixedBlock {
                source: source(0),
                operations: MixedTableRange::new(0, 1),
                terminator: MixedTerminator::ApplyGuarded {
                    function: MixedValueId::new(0),
                    argument: MixedValueId::new(1),
                    result: MixedValueId::new(2),
                    targets: MixedTableRange::new(0, 1),
                    continuation: MixedBlockId::new(1),
                    fallback: MixedStatepointId::new(0),
                },
            },
            MixedBlock {
                source: source(1),
                operations: MixedTableRange::new(1, 0),
                terminator: MixedTerminator::Force {
                    subject: MixedValueId::new(2),
                    result: MixedValueId::new(3),
                    result_type: MixedValueType::Value,
                    guards: MixedForceGuards::new(code(30), code(31), code(32)),
                    ready: MixedBlockId::new(2),
                    node: MixedBlockId::new(3),
                    apply: MixedBlockId::new(4),
                    gen_list: MixedBlockId::new(5),
                    fallback: MixedStatepointId::new(1),
                },
            },
            MixedBlock {
                source: source(2),
                operations: MixedTableRange::new(1, 0),
                terminator: MixedTerminator::Return {
                    value: MixedValueId::new(3),
                },
            },
            MixedBlock {
                source: source(3),
                operations: MixedTableRange::new(1, 1),
                terminator: MixedTerminator::Update {
                    value: MixedValueId::new(4),
                    result: MixedValueId::new(3),
                    next: MixedBlockId::new(2),
                },
            },
            MixedBlock {
                source: source(4),
                operations: MixedTableRange::new(2, 1),
                terminator: MixedTerminator::Update {
                    value: MixedValueId::new(5),
                    result: MixedValueId::new(3),
                    next: MixedBlockId::new(2),
                },
            },
            MixedBlock {
                source: source(5),
                operations: MixedTableRange::new(3, 1),
                terminator: MixedTerminator::Update {
                    value: MixedValueId::new(6),
                    result: MixedValueId::new(3),
                    next: MixedBlockId::new(2),
                },
            },
            MixedBlock {
                source: source(10),
                operations: MixedTableRange::new(4, 0),
                terminator: MixedTerminator::Return {
                    value: MixedValueId::new(7),
                },
            },
        ],
        vec![
            MixedOp::LoadLocal {
                destination: MixedValueId::new(1),
                slot: 0,
            },
            MixedOp::LoadLocal {
                destination: MixedValueId::new(4),
                slot: 0,
            },
            MixedOp::ConstInt {
                destination: MixedValueId::new(5),
                value: 41,
            },
            MixedOp::ConstInt {
                destination: MixedValueId::new(6),
                value: 42,
            },
        ],
        vec![MixedCallTarget {
            code: code(8),
            function: MixedFunctionId::new(1),
            argument_destination: MixedValueId::new(7),
        }],
        vec![
            MixedStatepoint {
                source: source(20),
                resume: MixedBlockId::new(1),
                live_values: Box::new([MixedValueId::new(0), MixedValueId::new(1)]),
                live_virtuals: Box::new([]),
                result: Some(MixedValueId::new(2)),
                result_type: Some(MixedValueType::Value),
                mode: MixedStatepointMode::Resume,
                reason: MixedStatepointReason::UnknownCall,
            },
            MixedStatepoint {
                source: source(21),
                resume: MixedBlockId::new(2),
                live_values: Box::new([MixedValueId::new(2)]),
                live_virtuals: Box::new([]),
                result: Some(MixedValueId::new(3)),
                result_type: Some(MixedValueType::Value),
                mode: MixedStatepointMode::Resume,
                reason: MixedStatepointReason::UnsupportedForce,
            },
        ],
    )
    .expect("test plan validates")
}

#[test]
fn runner_fuses_apply_call_frame_force_update_and_return() {
    let plan = executable_force_call_plan();
    let executable = MixedExecutablePlan::new(&plan).expect("plan is executable");
    let mut runner =
        MixedExecutionRunner::<TestRuntime>::new(executable, 0, TestValue::Closure(8), 0, 2)
            .expect("runner preallocates");
    let mut runtime = TestRuntime::new();

    let storage = runner.storage();
    assert_eq!(storage.value_slots, 16);
    assert_eq!(storage.call_frames, 2);
    assert_eq!(storage.update_tokens, 2);
    assert_eq!(
        runner.run(&mut runtime).expect("execution succeeds"),
        MixedExecutionOutcome::Complete(TestValue::Int(40))
    );
    assert_eq!(
        runtime.published,
        vec![(TestForceTarget(1_009), 9, TestValue::Int(40))]
    );
    assert!(runtime.aborted.is_empty());
    assert_eq!(runner.storage(), storage);
    assert_eq!(
        runner.stats(),
        MixedExecutionStats {
            blocks: 5,
            operations: 2,
            ready_forces: 0,
            claimed_forces: [1, 0, 0],
            updates: 1,
            direct_calls: 1,
            returns: 2,
            side_exits: 0,
        }
    );
    assert!(matches!(
        runner.run(&mut runtime),
        Err(MixedExecutionError::Terminal)
    ));
}

#[test]
fn terminal_runner_reuses_the_exact_fixed_slabs() {
    let plan = executable_force_call_plan();
    let executable = MixedExecutablePlan::new(&plan).expect("plan is executable");
    let mut runner =
        MixedExecutionRunner::<TestRuntime>::new(executable, 0, TestValue::Closure(8), 0, 2)
            .expect("runner preallocates");
    let storage = runner.storage();
    let slot_address = runner.slots.as_ptr();
    let activation_address = runner.activations.as_ptr();
    let update_address = runner.updates.as_ptr();

    assert!(matches!(
        runner.restart(0, TestValue::Closure(8), 0),
        Err(MixedExecutionError::Active)
    ));
    let mut first_runtime = TestRuntime::new();
    assert_eq!(
        runner.run(&mut first_runtime).expect("first run succeeds"),
        MixedExecutionOutcome::Complete(TestValue::Int(40))
    );

    runner
        .restart(0, TestValue::Closure(8), 0)
        .expect("terminal workspace restarts");
    assert_eq!(runner.storage(), storage);
    assert_eq!(runner.slots.as_ptr(), slot_address);
    assert_eq!(runner.activations.as_ptr(), activation_address);
    assert_eq!(runner.updates.as_ptr(), update_address);
    assert_eq!(runner.stats(), MixedExecutionStats::default());

    let mut second_runtime = TestRuntime::new();
    assert_eq!(
        runner
            .run(&mut second_runtime)
            .expect("reused run succeeds"),
        MixedExecutionOutcome::Complete(TestValue::Int(40))
    );
    assert_eq!(
        second_runtime.published,
        vec![(TestForceTarget(1_009), 9, TestValue::Int(40))]
    );
    assert_eq!(runner.storage(), storage);
    assert_eq!(runner.slots.as_ptr(), slot_address);
    assert_eq!(runner.activations.as_ptr(), activation_address);
    assert_eq!(runner.updates.as_ptr(), update_address);
}

#[test]
fn guard_exit_preserves_live_values_and_resumes() {
    let plan = executable_force_call_plan();
    let executable = MixedExecutablePlan::new(&plan).expect("plan is executable");
    let mut runner =
        MixedExecutionRunner::<TestRuntime>::new(executable, 0, TestValue::Closure(8), 0, 2)
            .expect("runner preallocates");
    let mut runtime = TestRuntime::new();
    runtime.decline_call = true;

    let MixedExecutionOutcome::SideExit(exit) =
        runner.run(&mut runtime).expect("guard exit succeeds")
    else {
        panic!("call guard must side-exit");
    };
    assert_eq!(exit.statepoint(), MixedStatepointId::new(0));
    assert_eq!(exit.cause(), MixedExecutionSideExitCause::Guard);
    assert_eq!(
        runner.suspended_value(MixedValueId::new(1)),
        Some(TestValue::Node(9))
    );

    runtime.decline_call = false;
    runner
        .resume(Some(TestValue::Int(17)))
        .expect("oracle result resumes");
    assert_eq!(
        runner
            .run(&mut runtime)
            .expect("resumed execution succeeds"),
        MixedExecutionOutcome::Complete(TestValue::Int(17))
    );
}

#[test]
fn fixed_call_capacity_exits_before_call_entry() {
    let plan = executable_force_call_plan();
    let executable = MixedExecutablePlan::new(&plan).expect("plan is executable");
    let mut runner =
        MixedExecutionRunner::<TestRuntime>::new(executable, 0, TestValue::Closure(8), 0, 1)
            .expect("one activation is valid");
    let mut runtime = TestRuntime::new();

    let MixedExecutionOutcome::SideExit(exit) =
        runner.run(&mut runtime).expect("capacity exit succeeds")
    else {
        panic!("call capacity must side-exit");
    };
    assert_eq!(exit.statepoint(), MixedStatepointId::new(0));
    assert_eq!(exit.cause(), MixedExecutionSideExitCause::CallCapacity);
    assert!(runtime.published.is_empty());
}

#[test]
fn virtual_object_producers_are_not_misrepresented_as_executable() {
    let mut plan = executable_force_call_plan();
    plan.operations[0] = MixedOp::VirtualClosure {
        destination: MixedValueId::new(1),
        body: MixedFunctionId::new(1),
    };
    assert!(matches!(
        MixedExecutablePlan::new(&plan),
        Err(MixedExecutionAdmissionError::VirtualObject { operation: 0 })
    ));
}

#[test]
fn runtime_error_aborts_claimed_updates() {
    let plan = executable_force_call_plan();
    let executable = MixedExecutablePlan::new(&plan).expect("plan is executable");
    let mut runner =
        MixedExecutionRunner::<TestRuntime>::new(executable, 0, TestValue::Closure(8), 0, 2)
            .expect("runner preallocates");
    let mut runtime = TestRuntime::new();
    runtime.fail_claimed_load = true;

    assert!(matches!(
        runner.run(&mut runtime),
        Err(MixedExecutionError::Runtime(TestRuntimeError))
    ));
    assert_eq!(runtime.aborted, vec![(TestForceTarget(1_009), 9)]);
    assert!(matches!(
        runner.run(&mut runtime),
        Err(MixedExecutionError::Terminal)
    ));
    runtime.fail_claimed_load = false;
    runner
        .restart(0, TestValue::Closure(8), 0)
        .expect("failed activation releases its workspace");
    assert_eq!(
        runner
            .run(&mut runtime)
            .expect("workspace recovers after abort"),
        MixedExecutionOutcome::Complete(TestValue::Int(40))
    );
    assert_eq!(
        runtime.published,
        vec![(TestForceTarget(1_009), 9, TestValue::Int(40))]
    );
}

#[test]
fn panic_aborts_claimed_updates_before_unwinding() {
    let plan = executable_force_call_plan();
    let executable = MixedExecutablePlan::new(&plan).expect("plan is executable");
    let mut runner =
        MixedExecutionRunner::<TestRuntime>::new(executable, 0, TestValue::Closure(8), 0, 2)
            .expect("runner preallocates");
    let mut runtime = TestRuntime::new();
    runtime.panic_claimed_load = true;

    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = runner.run(&mut runtime);
    }));
    assert!(outcome.is_err());
    assert_eq!(runtime.aborted, vec![(TestForceTarget(1_009), 9)]);
}

#[test]
fn all_force_shapes_and_ready_edge_execute_their_static_successors() {
    for (shape, expected, shape_counts) in [
        (MixedForceShape::Apply, 41, [0, 1, 0]),
        (MixedForceShape::GenListElemAtAddOne, 42, [0, 0, 1]),
    ] {
        let plan = executable_force_call_plan();
        let executable = MixedExecutablePlan::new(&plan).expect("plan is executable");
        let mut runner =
            MixedExecutionRunner::<TestRuntime>::new(executable, 0, TestValue::Closure(8), 0, 2)
                .expect("runner preallocates");
        let mut runtime = TestRuntime::new();
        runtime.forced_shape = shape;
        assert_eq!(
            runner.run(&mut runtime).expect("shape executes"),
            MixedExecutionOutcome::Complete(TestValue::Int(expected))
        );
        assert_eq!(runner.stats().claimed_forces, shape_counts);
    }

    let plan = executable_force_call_plan();
    let executable = MixedExecutablePlan::new(&plan).expect("plan is executable");
    let mut runner =
        MixedExecutionRunner::<TestRuntime>::new(executable, 0, TestValue::Closure(8), 0, 2)
            .expect("runner preallocates");
    let mut runtime = TestRuntime::new();
    runtime.force_ready = true;
    assert_eq!(
        runner.run(&mut runtime).expect("ready edge executes"),
        MixedExecutionOutcome::Complete(TestValue::Node(9))
    );
    assert_eq!(runner.stats().ready_forces, 1);
    assert_eq!(runner.stats().claimed_forces, [0, 0, 0]);
}

#[test]
fn force_guard_exit_resumes_without_a_claim() {
    let plan = executable_force_call_plan();
    let executable = MixedExecutablePlan::new(&plan).expect("plan is executable");
    let mut runner =
        MixedExecutionRunner::<TestRuntime>::new(executable, 0, TestValue::Closure(8), 0, 2)
            .expect("runner preallocates");
    let mut runtime = TestRuntime::new();
    runtime.decline_force = true;

    let MixedExecutionOutcome::SideExit(exit) =
        runner.run(&mut runtime).expect("force guard exits")
    else {
        panic!("force guard must side-exit");
    };
    assert_eq!(exit.statepoint(), MixedStatepointId::new(1));
    assert!(runtime.published.is_empty());
    assert!(runtime.aborted.is_empty());
    runner
        .resume(Some(TestValue::Int(55)))
        .expect("oracle force result resumes");
    assert_eq!(
        runner.run(&mut runtime).expect("resumed force completes"),
        MixedExecutionOutcome::Complete(TestValue::Int(55))
    );
}

#[test]
fn mismatched_claimed_work_aborts_before_static_successor_execution() {
    let plan = executable_force_call_plan();
    let executable = MixedExecutablePlan::new(&plan).expect("plan is executable");
    let mut runner =
        MixedExecutionRunner::<TestRuntime>::new(executable, 0, TestValue::Closure(8), 0, 2)
            .expect("runner preallocates");
    let mut runtime = TestRuntime::new();
    runtime.forced_work_override = Some(code(99));

    assert!(matches!(
        runner.run(&mut runtime),
        Err(MixedExecutionError::ForceIdentityMismatch)
    ));
    assert_eq!(runtime.aborted, vec![(TestForceTarget(1_009), 9)]);
    assert!(runtime.published.is_empty());
    assert_eq!(runner.stats().updates, 0);
}

#[test]
fn nested_call_guard_rolls_back_owned_force_before_oracle_restart() {
    let mut plan = executable_force_call_plan();
    plan.operations = vec![MixedOp::LoadLocal {
        destination: MixedValueId::new(1),
        slot: 0,
    }]
    .into_boxed_slice();
    for block in &mut plan.blocks {
        block.operations = MixedTableRange::new(1, 0);
    }
    plan.blocks[0].operations = MixedTableRange::new(0, 1);
    let MixedTerminator::Force {
        node,
        apply,
        gen_list,
        ..
    } = &mut plan.blocks[1].terminator
    else {
        panic!("sample force expected");
    };
    *node = MixedBlockId::new(3);
    *apply = MixedBlockId::new(3);
    *gen_list = MixedBlockId::new(3);
    plan.blocks[3].terminator = MixedTerminator::ApplyGuarded {
        function: MixedValueId::new(0),
        argument: MixedValueId::new(1),
        result: MixedValueId::new(4),
        targets: MixedTableRange::new(0, 1),
        continuation: MixedBlockId::new(4),
        fallback: MixedStatepointId::new(0),
    };
    plan.blocks[4].terminator = MixedTerminator::Update {
        value: MixedValueId::new(4),
        result: MixedValueId::new(3),
        next: MixedBlockId::new(5),
    };
    plan.blocks[5].terminator = MixedTerminator::Jump {
        target: MixedBlockId::new(2),
    };
    plan.statepoints[0].live_values = Box::new([MixedValueId::new(0)]);
    plan.statepoints[0].result = None;
    plan.statepoints[0].result_type = None;
    plan.statepoints[0].mode = MixedStatepointMode::RestartEntry { entry: 0 };
    plan.validate().expect("rollback plan validates");

    let executable = MixedExecutablePlan::new(&plan).expect("plan is executable");
    let mut runner =
        MixedExecutionRunner::<TestRuntime>::new(executable, 0, TestValue::Closure(8), 0, 2)
            .expect("runner preallocates");
    let mut runtime = TestRuntime::new();
    runtime.decline_call_at = Some(2);

    assert_eq!(
        runner.run(&mut runtime).expect("rollback succeeds"),
        MixedExecutionOutcome::Restart {
            entry: 0,
            statepoint: MixedStatepointId::new(0),
        }
    );
    assert_eq!(runtime.aborted, vec![(TestForceTarget(1_009), 9)]);
    assert!(runtime.published.is_empty());
    assert!(matches!(
        runner.run(&mut runtime),
        Err(MixedExecutionError::Terminal)
    ));
}

#[test]
fn publication_failure_aborts_the_still_owned_token() {
    let plan = executable_force_call_plan();
    let executable = MixedExecutablePlan::new(&plan).expect("plan is executable");
    let mut runner =
        MixedExecutionRunner::<TestRuntime>::new(executable, 0, TestValue::Closure(8), 0, 2)
            .expect("runner preallocates");
    let mut runtime = TestRuntime::new();
    runtime.fail_publish = true;

    assert!(matches!(
        runner.run(&mut runtime),
        Err(MixedExecutionError::Runtime(TestRuntimeError))
    ));
    assert_eq!(runtime.aborted, vec![(TestForceTarget(1_009), 9)]);
    assert!(runtime.published.is_empty());
}

/// Executes the sample plan's guarded success path without plan dispatch.
///
/// This is deliberately test-only: it is the direct-control denominator for
/// the ignored PMU probes below, not an alternate production evaluator.
#[inline(never)]
fn direct_force_call_success(
    runtime: &mut TestRuntime,
    callable: TestValue,
) -> Result<TestValue, TestRuntimeError> {
    let argument = runtime.load_local(0, 0)?;
    let MixedCallable::Materialized {
        code: observed_code,
        frame: _,
    } = runtime.inspect_callable(callable)?
    else {
        return Err(TestRuntimeError);
    };
    if observed_code != code(8) {
        return Err(TestRuntimeError);
    }

    let guards = MixedForceGuards::new(code(30), code(31), code(32));
    match runtime.begin_force(argument, guards)? {
        MixedForceAction::Ready(value) => Ok(value),
        MixedForceAction::Claimed {
            target,
            shape: MixedForceShape::Node,
            work,
            frame,
            update,
        } if work == guards.node => {
            let value = match runtime.load_local(frame, 0) {
                Ok(value) => value,
                Err(error) => {
                    runtime.abort_update(target, update);
                    return Err(error);
                }
            };
            if let Err(error) = runtime.publish_update(&target, &update, value) {
                runtime.abort_update(target, update);
                return Err(error);
            }
            Ok(value)
        }
        MixedForceAction::Claimed { target, update, .. } => {
            runtime.abort_update(target, update);
            Err(TestRuntimeError)
        }
        MixedForceAction::Declined => Err(TestRuntimeError),
    }
}

fn transition_probe_iterations() -> u64 {
    std::env::var("AOS_MIXED_TRANSITION_PROBE_ITERATIONS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(5_000_000)
}

fn checksum_value(checksum: u64, value: TestValue) -> u64 {
    let payload = match value {
        TestValue::Int(value) => value as u64,
        TestValue::Bool(value) => u64::from(value),
        TestValue::Null => 0,
        TestValue::Node(value) | TestValue::Closure(value) => u64::from(value),
    };
    checksum.rotate_left(7) ^ payload
}

#[test]
fn direct_transition_denominator_matches_plan_success_semantics() {
    let mut runtime = TestRuntime::new();
    assert_eq!(
        direct_force_call_success(&mut runtime, TestValue::Closure(8))
            .expect("direct success path executes"),
        TestValue::Int(40)
    );
    assert_eq!(
        runtime.published,
        vec![(TestForceTarget(1_009), 9, TestValue::Int(40))]
    );
    assert!(runtime.aborted.is_empty());
    assert_eq!(runtime.callable_inspections, 1);
}

#[test]
#[ignore = "run under perf stat to measure reusable mixed-plan transition cost"]
fn mixed_runner_transition_cost_probe() {
    let iterations = transition_probe_iterations();
    let plan = executable_force_call_plan();
    let executable = MixedExecutablePlan::new(&plan).expect("plan is executable");
    let mut runner =
        MixedExecutionRunner::<TestRuntime>::new(executable, 0, TestValue::Closure(8), 0, 2)
            .expect("runner preallocates");
    let mut runtime = TestRuntime::new();
    let mut checksum = 0u64;

    for iteration in 0..iterations {
        let MixedExecutionOutcome::Complete(value) =
            runner.run(&mut runtime).expect("probe iteration executes")
        else {
            panic!("probe must complete without a side exit");
        };
        checksum = checksum_value(checksum, value);
        runtime.published.clear();
        if iteration + 1 != iterations {
            runner
                .restart(0, TestValue::Closure(8), 0)
                .expect("fixed slabs restart");
        }
    }
    std::hint::black_box((&runner, &runtime));
    eprintln!(
        "mixed_transition_probe mode=runner iterations={iterations} checksum={checksum} \
         blocks_per_iteration=5"
    );
}

#[test]
#[ignore = "run under perf stat as the direct generated-control denominator"]
fn direct_transition_cost_probe() {
    let iterations = transition_probe_iterations();
    let mut runtime = TestRuntime::new();
    let mut checksum = 0u64;

    for _ in 0..iterations {
        let value = direct_force_call_success(&mut runtime, TestValue::Closure(8))
            .expect("direct probe iteration executes");
        checksum = checksum_value(checksum, value);
        runtime.published.clear();
    }
    std::hint::black_box(&runtime);
    eprintln!(
        "mixed_transition_probe mode=direct iterations={iterations} checksum={checksum} \
         blocks_per_iteration=1"
    );
}

#[test]
#[ignore = "run under perf stat as the loop and test-process control"]
fn empty_transition_cost_probe() {
    let iterations = transition_probe_iterations();
    let mut checksum = 0u64;

    for iteration in 0..iterations {
        checksum = std::hint::black_box(checksum.rotate_left(7) ^ iteration);
    }
    eprintln!(
        "mixed_transition_probe mode=empty iterations={iterations} checksum={checksum} \
         blocks_per_iteration=0"
    );
}
