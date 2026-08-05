//! Plugin registration sequence tests.

use super::*;

use std::io::{Cursor, Read, Write};

use crucible_protocol::{CONTROL_PROTOCOL_VERSION, HostMsg, control_encode_host_msg};
use crucible_shmem::{ABI_VERSION, KIND_VM, NodeSlot, authorize_advance_ceiling};

mod coverage_cases;

#[test]
fn registration_order_accepts_fixed_happy_path() {
    let mut sequence = PluginRegistrationSequence::new();

    record_fixed_sequence(&mut sequence);

    assert_eq!(
        sequence.completed_steps(),
        PluginRegistrationSequence::fixed_order()
    );
    assert!(sequence.is_complete());
    assert!(matches!(
        sequence.finish(),
        Ok(PluginRegistrationReady { .. })
    ));
}

#[test]
fn registration_ready_token_consumes_sequence() {
    let mut sequence = PluginRegistrationSequence::new();
    record_fixed_sequence(&mut sequence);

    let ready = match sequence.finish() {
        Ok(ready) => ready,
        Err(error) => panic!("completed registration should finish: {error}"),
    };
    let _ownership = crate::PluginTimeControlOwnership::acquired_after_registration(ready);
}

#[test]
fn registration_order_parse_step_uses_fail_closed_args() {
    let mut sequence = PluginRegistrationSequence::new();

    let args = match sequence.parse_arguments("simfd=3,slot=1,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111") {
        Ok(args) => args,
        Err(error) => panic!("valid arguments should parse and record: {error}"),
    };

    assert_eq!(args.sim_fd(), 3);
    assert_eq!(args.slot(), 1);
    assert_eq!(
        sequence.completed_steps(),
        &[PluginRegistrationStep::ParseArguments]
    );

    let mut failed = PluginRegistrationSequence::new();
    let error = failed
        .parse_arguments("slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111")
        .err()
        .unwrap_or_else(|| panic!("missing simfd should fail"));
    let PluginRegistrationSequenceError::StepFailed { failure } = error else {
        panic!("expected step-scoped parse failure, got {error:?}");
    };
    assert_eq!(failure.step(), PluginRegistrationStep::ParseArguments);
    assert!(
        failure
            .diagnostic()
            .contains("missing required plugin argument `simfd`")
    );
    assert!(failed.is_failed());
    assert_eq!(
        failed.record_step(PluginRegistrationStep::ControlHandshake),
        Err(PluginRegistrationSequenceError::AfterFailure {
            failed_step: PluginRegistrationStep::ParseArguments,
            blocked_step: PluginRegistrationStep::ControlHandshake,
        })
    );
}

#[test]
fn registration_order_performs_control_handshake_after_parse() {
    let mut sequence = PluginRegistrationSequence::new();
    let args = sequence
        .parse_arguments("simfd=3,slot=1,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111")
        .unwrap_or_else(|error| panic!("valid arguments should parse: {error}"));
    let mut io = handshake_io(1, 4);

    let handshake = sequence
        .perform_control_handshake(&mut io, &args)
        .unwrap_or_else(|error| panic!("handshake should succeed: {error}"));

    assert_eq!(handshake.proto_version(), CONTROL_PROTOCOL_VERSION);
    assert_eq!(handshake.abi_version(), ABI_VERSION);
    assert_eq!(handshake.slot_index(), 1);
    assert_eq!(handshake.launch_slot(), 1);
    assert_eq!(handshake.node_count(), 4);
    assert!(!io.written().is_empty());
    assert_eq!(io.flush_count(), 1);
    assert_eq!(
        sequence.completed_steps(),
        &[
            PluginRegistrationStep::ParseArguments,
            PluginRegistrationStep::ControlHandshake,
        ]
    );
}

#[test]
fn registration_order_rejects_control_handshake_before_parse_without_io() {
    let mut sequence = PluginRegistrationSequence::new();
    let args = registration_args(
        "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111",
    );
    let mut io = handshake_io(0, 1);

    assert_eq!(
        sequence.perform_control_handshake(&mut io, &args),
        Err(PluginRegistrationSequenceError::OutOfOrderStep {
            expected: PluginRegistrationStep::ParseArguments,
            actual: PluginRegistrationStep::ControlHandshake,
        })
    );
    assert!(io.written().is_empty());
    assert_eq!(io.flush_count(), 0);
}

#[test]
fn registration_order_fails_loud_when_handshake_slot_disagrees_with_launch_args() {
    let mut sequence = PluginRegistrationSequence::new();
    let args = sequence
        .parse_arguments("simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111")
        .unwrap_or_else(|error| panic!("valid arguments should parse: {error}"));
    let mut io = handshake_io(1, 2);

    let error = sequence
        .perform_control_handshake(&mut io, &args)
        .err()
        .unwrap_or_else(|| panic!("slot mismatch should fail"));
    let PluginRegistrationSequenceError::StepFailed { failure } = error else {
        panic!("expected step failure, got {error:?}");
    };

    assert_eq!(failure.step(), PluginRegistrationStep::ControlHandshake);
    assert!(failure.diagnostic().contains("launch slot 0"));
    assert!(failure.diagnostic().contains("handshake slot 1"));
    assert_eq!(
        sequence.record_step(PluginRegistrationStep::RequestTimeControl),
        Err(PluginRegistrationSequenceError::AfterFailure {
            failed_step: PluginRegistrationStep::ControlHandshake,
            blocked_step: PluginRegistrationStep::RequestTimeControl,
        })
    );
}

#[test]
fn registration_order_rejects_handshake_before_parse() {
    let mut sequence = PluginRegistrationSequence::new();

    assert_eq!(
        sequence.record_step(PluginRegistrationStep::ControlHandshake),
        Err(PluginRegistrationSequenceError::OutOfOrderStep {
            expected: PluginRegistrationStep::ParseArguments,
            actual: PluginRegistrationStep::ControlHandshake,
        })
    );
    assert!(sequence.completed_steps().is_empty());
    assert!(sequence.is_failed());
    assert_eq!(
        sequence.record_step(PluginRegistrationStep::ParseArguments),
        Err(PluginRegistrationSequenceError::AfterFailure {
            failed_step: PluginRegistrationStep::ControlHandshake,
            blocked_step: PluginRegistrationStep::ParseArguments,
        })
    );
}

#[test]
fn registration_order_aborts_without_later_steps_after_failure() {
    let mut sequence = PluginRegistrationSequence::new();
    if let Err(error) = sequence.record_step(PluginRegistrationStep::ParseArguments) {
        panic!("parse step should record: {error}");
    }

    let error = sequence.fail_step(PluginRegistrationStep::ControlHandshake, "closed socket");
    let PluginRegistrationSequenceError::StepFailed { failure } = error else {
        panic!("expected handshake failure, got {error:?}");
    };

    assert_eq!(failure.step(), PluginRegistrationStep::ControlHandshake);
    assert_eq!(failure.diagnostic(), "closed socket");
    assert_eq!(
        sequence.record_step(PluginRegistrationStep::RequestTimeControl),
        Err(PluginRegistrationSequenceError::AfterFailure {
            failed_step: PluginRegistrationStep::ControlHandshake,
            blocked_step: PluginRegistrationStep::RequestTimeControl,
        })
    );
    assert_eq!(
        sequence.completed_steps(),
        &[PluginRegistrationStep::ParseArguments]
    );
}

#[test]
fn registration_order_requires_boot_barrier_before_first_instruction() {
    let mut sequence = PluginRegistrationSequence::new();
    let _setup_ack = record_steps_through_setup_ack(&mut sequence);

    assert_eq!(
        sequence.record_step(PluginRegistrationStep::FirstVisibleInstruction),
        Err(PluginRegistrationSequenceError::OutOfOrderStep {
            expected: PluginRegistrationStep::WaitBootBarrier,
            actual: PluginRegistrationStep::FirstVisibleInstruction,
        })
    );
}

#[test]
fn registration_order_requires_boot_barrier_wait_helper() {
    let mut sequence = PluginRegistrationSequence::new();
    let _setup_ack = record_steps_through_setup_ack(&mut sequence);

    let error = sequence
        .record_step(PluginRegistrationStep::WaitBootBarrier)
        .err()
        .unwrap_or_else(|| panic!("direct boot-barrier record should fail"));
    let PluginRegistrationSequenceError::StepFailed { failure } = error else {
        panic!("expected boot-barrier step failure, got {error:?}");
    };

    assert_eq!(failure.step(), PluginRegistrationStep::WaitBootBarrier);
    assert!(failure.diagnostic().contains("wake_signal futex"));
    assert_eq!(
        sequence.record_step(PluginRegistrationStep::FirstVisibleInstruction),
        Err(PluginRegistrationSequenceError::AfterFailure {
            failed_step: PluginRegistrationStep::WaitBootBarrier,
            blocked_step: PluginRegistrationStep::FirstVisibleInstruction,
        })
    );
}

#[test]
fn registration_order_waits_boot_barrier_before_first_instruction() {
    let mut sequence = PluginRegistrationSequence::new();
    let setup_ack = record_steps_through_setup_ack(&mut sequence);
    let slot = boot_barrier_slot(3);

    let release = sequence
        .wait_boot_barrier(setup_ack, &slot, 0)
        .unwrap_or_else(|error| panic!("boot barrier should release: {error}"));

    assert_eq!(
        release.first_guest_icount(),
        crate::BOOT_BARRIER_FIRST_GUEST_ICOUNT
    );
    assert_eq!(release.released_ceiling(), 3);
    if let Err(error) = sequence.record_step(PluginRegistrationStep::FirstVisibleInstruction) {
        panic!("first instruction sentinel should record after boot barrier: {error}");
    }
    assert_eq!(
        sequence.completed_steps(),
        PluginRegistrationSequence::fixed_order()
    );
}

#[test]
fn registration_order_requires_ready_setup_ack_helper() {
    let mut sequence = PluginRegistrationSequence::new();
    record_steps_through_wake_fd(&mut sequence);
    let args = registration_args(
        "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111",
    );
    sequence
        .register_callbacks_for_test(
            &args,
            Some(registration_test_deadline),
            Some(registration_test_direct_advance),
            CoverageCapabilities::none(),
        )
        .unwrap_or_else(|error| panic!("exact deadline capability should register: {error}"));

    let error = sequence
        .record_step(PluginRegistrationStep::SendSetupAck)
        .err()
        .unwrap_or_else(|| panic!("direct ready-ack record should fail"));
    let PluginRegistrationSequenceError::StepFailed { failure } = error else {
        panic!("expected ready-ack step failure, got {error:?}");
    };

    assert_eq!(failure.step(), PluginRegistrationStep::SendSetupAck);
    assert!(failure.diagnostic().contains("SetupAck(0)"));
    assert!(failure.diagnostic().contains("callback tokens"));
    assert_eq!(
        sequence.record_step(PluginRegistrationStep::WaitBootBarrier),
        Err(PluginRegistrationSequenceError::AfterFailure {
            failed_step: PluginRegistrationStep::SendSetupAck,
            blocked_step: PluginRegistrationStep::WaitBootBarrier,
        })
    );
}

#[test]
fn registration_order_rejects_callback_registration_without_exact_deadline_capability() {
    let mut sequence = PluginRegistrationSequence::new();
    record_steps_through_wake_fd(&mut sequence);

    let error = sequence.record_step(PluginRegistrationStep::RegisterCallbacks);

    let Err(PluginRegistrationSequenceError::StepFailed { failure }) = error else {
        panic!("direct callback registration should fail, got {error:?}");
    };
    assert_eq!(failure.step(), PluginRegistrationStep::RegisterCallbacks);
    assert!(failure.diagnostic().contains("exact deadline"));
    assert!(failure.diagnostic().contains("queued idle-advance"));
    assert_eq!(
        sequence.record_step(PluginRegistrationStep::SendSetupAck),
        Err(PluginRegistrationSequenceError::AfterFailure {
            failed_step: PluginRegistrationStep::RegisterCallbacks,
            blocked_step: PluginRegistrationStep::SendSetupAck,
        })
    );
}

#[test]
fn registration_order_reuses_canonical_time_control_plan() {
    assert_eq!(
        PluginRegistrationSequence::fixed_order(),
        &CANONICAL_TIME_CONTROL_REGISTRATION_ORDER
    );
    assert_eq!(
        PluginRegistrationSequence::validate_canonical_plan(),
        Ok(())
    );
}

#[test]
fn registration_order_records_callbacks_after_exact_deadline_capability_check() {
    let mut sequence = PluginRegistrationSequence::new();
    record_steps_through_wake_fd(&mut sequence);
    let args = registration_args(
        "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111",
    );

    let capabilities = match sequence.register_callbacks_for_test(
        &args,
        Some(registration_test_deadline),
        Some(registration_test_direct_advance),
        CoverageCapabilities::none(),
    ) {
        Ok(capabilities) => capabilities,
        Err(error) => panic!("exact deadline capability should register callbacks: {error}"),
    };

    assert_eq!(
        capabilities.exact_deadline_reader().read_next_deadline(),
        Ok(crate::ExactDeadlineReport::Armed { deadline_ns: 777 })
    );
    assert_eq!(
        capabilities.coverage_registration_plan(),
        CoverageRegistrationPlan::Disabled
    );
    assert_eq!(capabilities.coverage_callback(), None);
    assert_eq!(
        sequence.completed_steps(),
        &[
            PluginRegistrationStep::ParseArguments,
            PluginRegistrationStep::ControlHandshake,
            PluginRegistrationStep::RequestTimeControl,
            PluginRegistrationStep::ReceiveSetup,
            PluginRegistrationStep::MapSharedMemory,
            PluginRegistrationStep::ArmWakeFd,
            PluginRegistrationStep::RegisterCallbacks,
        ]
    );
}

#[test]
fn registration_order_fails_loud_when_exact_deadline_capability_missing() {
    let mut sequence = PluginRegistrationSequence::new();
    record_steps_through_wake_fd(&mut sequence);
    let args = registration_args(
        "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111",
    );

    let error = sequence
        .register_callbacks_for_test(
            &args,
            None,
            Some(registration_test_direct_advance),
            CoverageCapabilities::none(),
        )
        .err()
        .unwrap_or_else(|| panic!("missing exact deadline capability should fail"));
    let PluginRegistrationSequenceError::StepFailed { failure } = error else {
        panic!("expected registration step failure, got {error:?}");
    };

    assert_eq!(failure.step(), PluginRegistrationStep::RegisterCallbacks);
    assert!(
        failure
            .diagnostic()
            .contains(crate::QEMU_PLUGIN_CLOCK_DEADLINE_SYMBOL)
    );
    assert_eq!(
        sequence.record_step(PluginRegistrationStep::SendSetupAck),
        Err(PluginRegistrationSequenceError::AfterFailure {
            failed_step: PluginRegistrationStep::RegisterCallbacks,
            blocked_step: PluginRegistrationStep::SendSetupAck,
        })
    );
}

#[test]
fn registration_order_fails_loud_when_queued_idle_advance_missing() {
    let mut sequence = PluginRegistrationSequence::new();
    record_steps_through_wake_fd(&mut sequence);
    let args = registration_args(
        "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111",
    );

    let error = sequence
        .register_callbacks_for_test(
            &args,
            Some(registration_test_deadline),
            None,
            CoverageCapabilities::none(),
        )
        .err()
        .unwrap_or_else(|| panic!("missing queued idle advance should fail"));
    let PluginRegistrationSequenceError::StepFailed { failure } = error else {
        panic!("expected registration step failure, got {error:?}");
    };

    assert_eq!(failure.step(), PluginRegistrationStep::RegisterCallbacks);
    assert!(
        failure
            .diagnostic()
            .contains(crate::QEMU_PLUGIN_ADVANCE_TIME_NS_SYMBOL)
    );
    assert_eq!(
        sequence.record_step(PluginRegistrationStep::SendSetupAck),
        Err(PluginRegistrationSequenceError::AfterFailure {
            failed_step: PluginRegistrationStep::RegisterCallbacks,
            blocked_step: PluginRegistrationStep::SendSetupAck,
        })
    );
}

#[test]
fn registration_coverage_on_requires_basic_block_callback_capability() {
    let mut sequence = PluginRegistrationSequence::new();
    record_steps_through_wake_fd(&mut sequence);
    let args = registration_args(
        "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,coverage=on",
    );

    let error = sequence
        .register_callbacks_for_test(
            &args,
            Some(registration_test_deadline),
            Some(registration_test_direct_advance),
            CoverageCapabilities::none(),
        )
        .err()
        .unwrap_or_else(|| panic!("coverage on without TCG exec should fail"));
    let PluginRegistrationSequenceError::StepFailed { failure } = error else {
        panic!("expected registration step failure, got {error:?}");
    };

    assert_eq!(failure.step(), PluginRegistrationStep::RegisterCallbacks);
    assert!(
        failure
            .diagnostic()
            .contains(crate::QEMU_PLUGIN_REGISTER_VCPU_TB_TRANS_CB_SYMBOL)
    );
    assert_eq!(
        sequence.record_step(PluginRegistrationStep::SendSetupAck),
        Err(PluginRegistrationSequenceError::AfterFailure {
            failed_step: PluginRegistrationStep::RegisterCallbacks,
            blocked_step: PluginRegistrationStep::SendSetupAck,
        })
    );
}

#[test]
fn registration_coverage_on_builds_basic_block_callback_token() {
    let mut sequence = PluginRegistrationSequence::new();
    record_steps_through_wake_fd(&mut sequence);
    let args = registration_args(
        "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,coverage=on",
    );
    let capabilities = sequence
        .register_callbacks_for_test(
            &args,
            Some(registration_test_deadline),
            Some(registration_test_direct_advance),
            registration_test_coverage_capabilities(),
        )
        .unwrap_or_else(|error| panic!("coverage on should register TCG exec: {error}"));

    assert_eq!(
        capabilities.coverage_registration_plan(),
        CoverageRegistrationPlan::Install {
            map_entries: crate::DEFAULT_COVERAGE_MAP_ENTRIES,
        }
    );
    assert!(
        capabilities
            .coverage_registration_plan()
            .installs_callback()
    );
    assert_eq!(
        capabilities
            .coverage_callback()
            .map(CoverageCallback::map_entries),
        Some(crate::DEFAULT_COVERAGE_MAP_ENTRIES)
    );
}

fn record_steps_through_wake_fd(sequence: &mut PluginRegistrationSequence) {
    for step in [
        PluginRegistrationStep::ParseArguments,
        PluginRegistrationStep::ControlHandshake,
        PluginRegistrationStep::RequestTimeControl,
        PluginRegistrationStep::ReceiveSetup,
        PluginRegistrationStep::MapSharedMemory,
        PluginRegistrationStep::ArmWakeFd,
    ] {
        if let Err(error) = sequence.record_step(step) {
            panic!("prerequisite step {step:?} should record: {error}");
        }
    }
}

fn record_steps_through_setup_ack(
    sequence: &mut PluginRegistrationSequence,
) -> PluginReadySetupAck {
    record_steps_through_wake_fd(sequence);
    let args = registration_args(
        "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111",
    );
    if let Err(error) = sequence.register_callbacks_for_test(
        &args,
        Some(registration_test_deadline),
        Some(registration_test_direct_advance),
        CoverageCapabilities::none(),
    ) {
        panic!("exact deadline capability should register callbacks: {error}");
    }
    sequence
        .record_test_ready_setup_ack()
        .unwrap_or_else(|error| panic!("setup ack step should record: {error}"))
}

fn record_fixed_sequence(sequence: &mut PluginRegistrationSequence) {
    let setup_ack = record_steps_through_setup_ack(sequence);
    let slot = boot_barrier_slot(2);
    if let Err(error) = sequence.wait_boot_barrier(setup_ack, &slot, 0) {
        panic!("boot barrier should release: {error}");
    }
    if let Err(error) = sequence.record_step(PluginRegistrationStep::FirstVisibleInstruction) {
        panic!("canonical first-instruction step should record: {error}");
    }
}

extern "C" fn registration_test_deadline() -> i64 {
    777
}

extern "C" fn registration_test_direct_advance(_target_virtual_ns: i64) -> std::os::raw::c_int {
    0
}

fn registration_test_coverage_capabilities() -> CoverageCapabilities {
    CoverageCapabilities::basic_blocks(crate::QemuBasicBlockCoverageApis::new(
        registration_test_register_tb_trans_cb,
        registration_test_register_tb_exec_cond_cb,
        registration_test_tb_vaddr,
        registration_test_tb_n_insns,
        registration_test_tb_get_insn,
        registration_test_insn_size,
        registration_test_icount_at_tb_entry,
        registration_test_register_flush_cb,
        registration_test_scoreboard_new,
        registration_test_scoreboard_free,
        registration_test_u64_set,
    ))
}

extern "C" fn registration_test_register_tb_trans_cb(
    _plugin_id: crate::QemuPluginId,
    _callback: Option<crate::QemuVcpuTbTransCbFn>,
) {
}

extern "C" fn registration_test_register_tb_exec_cond_cb(
    _tb: *mut crate::QemuPluginTb,
    _callback: Option<crate::QemuVcpuTbExecCbFn>,
    _flags: std::os::raw::c_int,
    _condition: std::os::raw::c_int,
    _entry: crate::QemuPluginU64,
    _immediate: u64,
    _userdata: *mut std::os::raw::c_void,
) {
}

extern "C" fn registration_test_scoreboard_new(
    _element_size: usize,
) -> *mut crate::QemuPluginScoreboard {
    std::ptr::NonNull::dangling().as_ptr()
}

extern "C" fn registration_test_scoreboard_free(_score: *mut crate::QemuPluginScoreboard) {}

extern "C" fn registration_test_u64_set(
    _entry: crate::QemuPluginU64,
    _vcpu_index: std::os::raw::c_uint,
    _value: u64,
) {
}

extern "C" fn registration_test_tb_vaddr(_tb: *const crate::QemuPluginTb) -> u64 {
    0
}

extern "C" fn registration_test_tb_n_insns(_tb: *const crate::QemuPluginTb) -> usize {
    0
}

extern "C" fn registration_test_tb_get_insn(
    _tb: *const crate::QemuPluginTb,
    _index: usize,
) -> *mut crate::QemuPluginInsn {
    std::ptr::null_mut()
}

extern "C" fn registration_test_insn_size(_insn: *const crate::QemuPluginInsn) -> usize {
    0
}

extern "C" fn registration_test_icount_at_tb_entry(
    _tb_insns: u64,
    entry_icount: *mut u64,
) -> std::os::raw::c_int {
    if entry_icount.is_null() {
        return -1;
    }
    // SAFETY: this test stub just validated the output pointer.
    unsafe { *entry_icount = 0 };
    0
}

extern "C" fn registration_test_register_flush_cb(
    _plugin_id: crate::QemuPluginId,
    _callback: crate::QemuPluginSimpleCbFn,
) {
}

fn registration_args(raw: &str) -> PluginArgs {
    PluginArgs::parse(raw).unwrap_or_else(|error| panic!("test args should parse: {error}"))
}

fn boot_barrier_slot(max_advance_icount: u64) -> NodeSlot {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, max_advance_icount, None)
        .unwrap_or_else(|error| panic!("boot barrier ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
        .unwrap_or_else(|error| panic!("boot barrier ceiling should publish: {error}"));
    slot
}

fn handshake_io(slot_index: u32, node_count: u32) -> ScriptedIo {
    ScriptedIo::from_input(control_encode_host_msg(&HostMsg::HelloAck {
        proto_version: CONTROL_PROTOCOL_VERSION,
        abi_version: ABI_VERSION,
        slot_index,
        node_count,
    }))
}

struct ScriptedIo {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
    flush_count: usize,
}

impl ScriptedIo {
    fn from_input(input: Vec<u8>) -> Self {
        Self {
            input: Cursor::new(input),
            output: Vec::new(),
            flush_count: 0,
        }
    }

    fn written(&self) -> Vec<u8> {
        self.output.clone()
    }

    const fn flush_count(&self) -> usize {
        self.flush_count
    }
}

impl Read for ScriptedIo {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(buffer)
    }
}

impl Write for ScriptedIo {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.output.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.flush_count += 1;
        Ok(())
    }
}
