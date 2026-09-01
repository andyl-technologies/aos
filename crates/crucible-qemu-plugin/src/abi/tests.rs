//! QEMU plugin ABI boundary tests.

use super::*;

use std::ffi::CString;
use std::ptr::NonNull;

mod capabilities;

const QEMU_TARGET_X86_64: &[u8] = b"x86_64\0";

const fn qemu_info_fixture(smp_vcpus: c_int, api_min: c_int, api_cur: c_int) -> QemuPluginInfo {
    QemuPluginInfo {
        target_name: QEMU_TARGET_X86_64.as_ptr().cast(),
        version: QemuPluginApiVersionRange {
            min: api_min,
            cur: api_cur,
        },
        system_emulation: true,
        system: QemuPluginSystemInfo {
            smp_vcpus,
            max_vcpus: smp_vcpus,
        },
    }
}

fn call_qemu_plugin_install(
    info: *const QemuPluginInfo,
    argc: c_int,
    argv: *mut *mut c_char,
) -> c_int {
    // SAFETY: tests pass live fixture pointers and `CString`-backed argv,
    // or null boundary cases rejected before either pointer is dereferenced.
    unsafe { qemu_plugin_install(7, info, argc, argv) }
}

fn plugin_argv(args: &[&str]) -> (Vec<CString>, Vec<*mut c_char>) {
    let strings = args
        .iter()
        .map(|arg| {
            CString::new(*arg).unwrap_or_else(|error| {
                panic!("test plugin arg should not contain interior NUL: {error}")
            })
        })
        .collect::<Vec<_>>();
    let ptrs = strings
        .iter()
        .map(|arg| arg.as_ptr().cast_mut())
        .collect::<Vec<_>>();
    (strings, ptrs)
}

fn valid_plugin_argv() -> (Vec<CString>, Vec<*mut c_char>) {
    plugin_argv(&[
        "simfd=3",
        "slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576",
        "shmemfd=4",
        "wakefd=5",
        "whitebox=off",
        "coverage=off",
    ])
}

fn call_qemu_plugin_install_with_valid_args(info: *const QemuPluginInfo) -> c_int {
    let (_strings, mut argv) = valid_plugin_argv();
    call_qemu_plugin_install(info, argv.len() as c_int, argv.as_mut_ptr())
}

fn parse_install_plugin_args_for_test(
    argc: c_int,
    argv: *mut *mut c_char,
) -> Result<PluginArgs, QemuPluginAbiError> {
    // SAFETY: tests pass argv vectors backed by live `CString` fixtures, or
    // null boundary cases rejected before reading.
    unsafe { parse_install_plugin_args(argc, argv) }
}

#[test]
fn abi_install_parses_qemu_plugin_argv_before_runtime_activation() {
    let (_strings, mut split_argv) = plugin_argv(&[
        "simfd=3",
        "slot=2,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576",
        "shmemfd=4",
        "wakefd=5",
        "whitebox=off",
        "coverage=on",
    ]);

    let args =
        parse_install_plugin_args_for_test(split_argv.len() as c_int, split_argv.as_mut_ptr())
            .unwrap_or_else(|error| panic!("split QEMU argv should parse: {error}"));

    assert_eq!(args.sim_fd(), 3);
    assert_eq!(args.slot(), 2);
    assert_eq!(
        args.inherited_fds(),
        Some(crate::PluginInheritedFds {
            shmem_fd: 4,
            wake_fd: 5,
        })
    );
    assert!(!args.whitebox().is_on());
    assert!(args.coverage().is_on());

    let (_strings, mut single_argv) = plugin_argv(&[
        "simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576,shmemfd=4,wakefd=5,whitebox=on,whitebox_setup=x86-port-00e7-unclaimed-v1,coverage=off",
    ]);
    let args = parse_install_plugin_args_for_test(1, single_argv.as_mut_ptr())
        .unwrap_or_else(|error| panic!("single QEMU argv should parse: {error}"));

    assert_eq!(args.sim_fd(), 3);
    assert_eq!(args.slot(), 0);
    assert!(args.whitebox().is_on());
    assert!(!args.coverage().is_on());
}

#[test]
fn abi_install_plugin_argv_fails_closed_for_missing_and_malformed_args() {
    assert_eq!(
        parse_install_plugin_args_for_test(0, std::ptr::null_mut()).map(|_args| ()),
        Err(QemuPluginAbiError::PluginArgs {
            source: PluginArgsParseError::MissingRequiredKey {
                key: PLUGIN_ARG_SIMFD,
            },
        })
    );

    let (_strings, mut missing_slot) = plugin_argv(&["simfd=3"]);
    assert_eq!(
        parse_install_plugin_args_for_test(1, missing_slot.as_mut_ptr()).map(|_args| ()),
        Err(QemuPluginAbiError::PluginArgs {
            source: PluginArgsParseError::MissingRequiredKey { key: "slot" },
        })
    );

    let mut null_entry = [std::ptr::null_mut()];
    assert_eq!(
        parse_install_plugin_args_for_test(1, null_entry.as_mut_ptr()).map(|_args| ()),
        Err(QemuPluginAbiError::NullArgvEntry { index: 0 })
    );

    let invalid_utf8 = CString::new(vec![0xff]).unwrap_or_else(|error| {
        panic!("test invalid UTF-8 argument should not contain interior NUL: {error}")
    });
    let mut invalid_utf8_argv = [invalid_utf8.as_ptr().cast_mut()];
    assert_eq!(
        parse_install_plugin_args_for_test(1, invalid_utf8_argv.as_mut_ptr()).map(|_args| ()),
        Err(QemuPluginAbiError::InvalidArgvUtf8 { index: 0 })
    );
}

#[cfg(unix)]
#[test]
fn abi_install_diagnostics_preserve_distinct_typed_failure_causes() {
    let boundary = crate::runtime::PluginLiveBoundaryError::Abi(QemuPluginAbiError::NoVcpus);
    let callbacks = crate::runtime::PluginLiveBoundaryError::Runtime(
        crate::PluginRuntimeInstallError::OwnedCallbacks {
            source: crate::OwnedCallbackRegistrationError::AdaptersUnavailable {
                families: crate::REQUIRED_OWNED_CALLBACK_FAMILIES,
            },
        },
    );

    let boundary_diagnostic = crate::runtime::install_failure_diagnostic(&boundary);
    let callback_diagnostic = crate::runtime::install_failure_diagnostic(&callbacks);
    assert!(boundary_diagnostic.contains("execution model has no vCPUs"));
    assert!(callback_diagnostic.contains("required callback adapters are unavailable"));
    assert!(callback_diagnostic.contains("network TX/RX"));
    assert_ne!(boundary_diagnostic, callback_diagnostic);
}

#[test]
fn abi_install_entrypoint_validates_raw_boundary_and_builds_inert_model() {
    #[cfg(unix)]
    let _runtime_state = crate::runtime::isolate_runtime_state_for_test();
    let info = NonNull::<QemuPluginInfo>::dangling().as_ptr();
    let valid_info = qemu_info_fixture(1, 1, QEMU_PLUGIN_API_VERSION);

    assert_eq!(
        validate_install_boundary(info, 0, std::ptr::null_mut()),
        Ok(())
    );
    assert_eq!(
        call_qemu_plugin_install_with_valid_args(&valid_info),
        QEMU_PLUGIN_INSTALL_ERROR
    );
    assert!(
        install_inert_scaffold_from_qemu_info(
            &valid_info,
            QemuTcgThreading::SingleThreadedRoundRobin
        )
        .is_ok()
    );
    assert_eq!(
        call_qemu_plugin_install(std::ptr::null(), 0, std::ptr::null_mut()),
        QEMU_PLUGIN_INSTALL_ERROR
    );
    assert_eq!(
        call_qemu_plugin_install(info, -1, std::ptr::null_mut()),
        QEMU_PLUGIN_INSTALL_ERROR
    );
    assert_eq!(
        call_qemu_plugin_install(info, 1, std::ptr::null_mut()),
        QEMU_PLUGIN_INSTALL_ERROR
    );
}

#[cfg(unix)]
#[test]
fn abi_install_trampoline_contains_panics_and_releases_reversible_reservation() {
    let _runtime_state = crate::runtime::isolate_runtime_state_for_test();
    let status =
        run_install_trampoline(|| -> Result<_, crate::runtime::PluginLiveBoundaryError> {
            let _reservation = crate::runtime::reserve_runtime()?;
            panic!("injected install panic");
        });

    assert_eq!(status, QEMU_PLUGIN_INSTALL_ERROR);
    assert!(crate::runtime::reserve_runtime().is_ok());
}

#[cfg(unix)]
#[test]
fn abi_install_trampoline_contains_panics_and_blocks_second_install_attempt() {
    let _runtime_state = crate::runtime::isolate_runtime_state_for_test();
    let status =
        run_install_trampoline(|| -> Result<_, crate::runtime::PluginLiveBoundaryError> {
            let mut reservation = crate::runtime::reserve_runtime()?;
            reservation.mark_irreversible();
            panic!("injected install panic after irreversible side effect");
        });

    assert_eq!(status, QEMU_PLUGIN_INSTALL_ERROR);
    assert!(matches!(
        crate::runtime::reserve_runtime(),
        Err(crate::PluginRuntimeInstallError::RuntimeAlreadyReserved)
    ));
}

#[test]
fn abi_qemu_install_path_validates_execution_model_before_success() {
    let single_vcpu = qemu_info_fixture(1, 1, QEMU_PLUGIN_API_VERSION);
    let multi_vcpu = qemu_info_fixture(4, 1, QEMU_PLUGIN_API_VERSION);
    let no_vcpu = qemu_info_fixture(0, 1, QEMU_PLUGIN_API_VERSION);
    let unsupported_api =
        qemu_info_fixture(1, QEMU_PLUGIN_API_VERSION + 1, QEMU_PLUGIN_API_VERSION + 1);

    assert_eq!(
        install_required_deadline_scaffold_from_qemu_info(
            &single_vcpu,
            QemuTcgThreading::SingleThreadedRoundRobin,
            Some(abi_test_deadline),
        )
        .map(|state| state.exact_deadline_reader().is_some()),
        Ok(true)
    );
    assert_eq!(
        install_required_deadline_scaffold_from_qemu_info(
            &multi_vcpu,
            QemuTcgThreading::SingleThreadedRoundRobin,
            Some(abi_test_deadline),
        )
        .map(|state| state.lifecycle_core().execution_model().smp_vcpus()),
        Ok(4)
    );
    assert_eq!(
        install_required_deadline_scaffold_from_qemu_info(
            &no_vcpu,
            QemuTcgThreading::SingleThreadedRoundRobin,
            Some(abi_test_deadline),
        )
        .map(|_state| ()),
        Err(QemuPluginAbiError::NoVcpus)
    );
    assert_eq!(
        install_required_deadline_scaffold_from_qemu_info(
            &unsupported_api,
            QemuTcgThreading::SingleThreadedRoundRobin,
            Some(abi_test_deadline),
        )
        .map(|_state| ()),
        Err(QemuPluginAbiError::UnsupportedPluginApi {
            min: QEMU_PLUGIN_API_VERSION + 1,
            cur: QEMU_PLUGIN_API_VERSION + 1,
            required: QEMU_PLUGIN_API_VERSION,
        })
    );
}

#[test]
fn abi_observed_execution_model_accepts_only_exact_single_threaded_rr_proof() {
    let valid_info = qemu_info_fixture(4, 1, QEMU_PLUGIN_API_VERSION);

    assert_eq!(
        observed_execution_model(&valid_info, || Some(abi_test_single_threaded_rr)),
        QemuPluginExecutionModel::validate(4, QemuTcgThreading::SingleThreadedRoundRobin)
    );
    assert_eq!(
        observed_execution_model(&valid_info, || Some(abi_test_not_single_threaded_rr)),
        Err(QemuPluginAbiError::MultiThreadedTcg)
    );
    assert_eq!(
        observed_execution_model(&valid_info, || {
            Some(abi_test_noncanonical_threading_proof)
        }),
        Err(QemuPluginAbiError::MultiThreadedTcg)
    );
}

#[test]
fn abi_observed_execution_model_fails_closed_without_threading_proof() {
    let valid_info = qemu_info_fixture(1, 1, QEMU_PLUGIN_API_VERSION);

    assert_eq!(
        observed_execution_model(&valid_info, || None),
        Err(QemuPluginAbiError::RuntimeApiCapability {
            symbol: QEMU_PLUGIN_SINGLE_THREADED_RR_SYMBOL,
        })
    );
}

#[test]
fn abi_observed_execution_model_rejects_user_mode_before_capability_lookup() {
    let mut user_mode_info = qemu_info_fixture(1, 1, QEMU_PLUGIN_API_VERSION);
    user_mode_info.system_emulation = false;

    assert_eq!(
        observed_execution_model(&user_mode_info, || {
            panic!("user-mode validation must precede capability lookup")
        }),
        Err(QemuPluginAbiError::NotSystemEmulation)
    );
}

#[test]
fn abi_execution_model_requires_single_threaded_tcg_not_single_vcpu_only() {
    let single =
        match QemuPluginExecutionModel::validate(1, QemuTcgThreading::SingleThreadedRoundRobin) {
            Ok(model) => model,
            Err(error) => panic!("single-vCPU RR-TCG should validate: {error}"),
        };
    let multi =
        match QemuPluginExecutionModel::validate(4, QemuTcgThreading::SingleThreadedRoundRobin) {
            Ok(model) => model,
            Err(error) => panic!("multi-vCPU RR-TCG should validate: {error}"),
        };

    assert!(single.is_single_vcpu());
    assert!(!multi.is_single_vcpu());
    assert_eq!(multi.smp_vcpus(), 4);
    assert_eq!(
        QemuPluginExecutionModel::validate(0, QemuTcgThreading::SingleThreadedRoundRobin),
        Err(QemuPluginAbiError::NoVcpus)
    );
    assert_eq!(
        QemuPluginExecutionModel::validate(1, QemuTcgThreading::MultiThreadedTcg),
        Err(QemuPluginAbiError::MultiThreadedTcg)
    );
}

#[test]
fn abi_safe_scaffold_shim_rejects_invalid_models() {
    let single_vcpu = qemu_info_fixture(1, 1, QEMU_PLUGIN_API_VERSION);
    let multi_vcpu = qemu_info_fixture(4, 1, QEMU_PLUGIN_API_VERSION);
    let no_vcpu = qemu_info_fixture(0, 1, QEMU_PLUGIN_API_VERSION);
    let negative_vcpu = qemu_info_fixture(-1, 1, QEMU_PLUGIN_API_VERSION);

    assert!(
        install_inert_scaffold_from_qemu_info(
            &single_vcpu,
            QemuTcgThreading::SingleThreadedRoundRobin
        )
        .is_ok()
    );
    assert!(
        install_inert_scaffold_from_qemu_info(
            &multi_vcpu,
            QemuTcgThreading::SingleThreadedRoundRobin
        )
        .is_ok()
    );
    assert_eq!(
        install_inert_scaffold_from_qemu_info(&no_vcpu, QemuTcgThreading::SingleThreadedRoundRobin)
            .map(|_state| ()),
        Err(QemuPluginAbiError::NoVcpus)
    );
    assert_eq!(
        install_inert_scaffold_from_qemu_info(
            &negative_vcpu,
            QemuTcgThreading::SingleThreadedRoundRobin
        )
        .map(|_state| ()),
        Err(QemuPluginAbiError::NoVcpus)
    );
    assert_eq!(
        install_inert_scaffold_from_qemu_info(&single_vcpu, QemuTcgThreading::MultiThreadedTcg)
            .map(|_state| ()),
        Err(QemuPluginAbiError::MultiThreadedTcg)
    );
}

#[test]
fn abi_state_partition_keeps_device_callbacks_immutable_and_reentrant_safe() {
    let model =
        match QemuPluginExecutionModel::validate(1, QemuTcgThreading::SingleThreadedRoundRobin) {
            Ok(model) => model,
            Err(error) => panic!("test execution model should validate: {error}"),
        };
    let state = match install_inert_scaffold(model) {
        Ok(state) => state,
        Err(error) => panic!("inert scaffold should install: {error}"),
    };

    assert_eq!(
        state.lifecycle_core().phase(),
        PluginLifecyclePhase::InstalledInert
    );
    assert_eq!(state.lifecycle_core().execution_model(), model);
    assert!(state.exact_deadline_reader().is_none());
    assert!(state.queued_idle_advance().is_none());
    assert!(state.preemption_injector().is_none());
    assert!(state.vcpu_introspector().is_none());
    for kind in OWNED_DEVICE_CALLBACK_KINDS {
        let callback = state.device_callbacks().callback_for(kind);
        callback(7, std::ptr::null_mut());
    }
}

extern "C" fn abi_test_deadline() -> i64 {
    4096
}

extern "C" fn abi_test_single_threaded_rr() -> c_int {
    1
}

extern "C" fn abi_test_not_single_threaded_rr() -> c_int {
    0
}

extern "C" fn abi_test_noncanonical_threading_proof() -> c_int {
    2
}

extern "C" fn abi_test_direct_advance(_target_virtual_ns: i64) -> c_int {
    0
}

extern "C" fn abi_test_inject_preemption(
    _at_icount: u64,
    _deadline_icount: u64,
    _ceiling_icount: u64,
    _raw_kind: c_uint,
    _arg0: u32,
    _arg1: u32,
    _arg2: u32,
) -> c_int {
    0
}

extern "C" fn abi_test_read_vcpu_regs(
    _vcpu_id: u32,
    _out_register_bytes: *mut u8,
    _out_register_capacity: usize,
    _out_register_len: *mut usize,
    _out_retired_instruction_count: *mut u64,
) -> c_int {
    0
}

extern "C" fn abi_test_rr_cursor(_out_cursor: *mut crate::QemuRoundRobinCursor) -> c_int {
    0
}

extern "C" fn abi_test_icount_raw() -> u64 {
    17
}

extern "C" fn abi_test_force_vcpu_exit() {}

extern "C" fn abi_test_register_wake_fd(_fd: c_int) -> c_int {
    0
}

extern "C" fn abi_test_register_tcg_exec_cb(
    _callback: Option<QemuTcgExecCbFn>,
    _userdata: *mut c_void,
) {
}

struct TestClockDeadlineSymbolGuard;

impl TestClockDeadlineSymbolGuard {
    fn install(symbol: QemuClockDeadlineFn) -> Self {
        set_test_clock_deadline_symbol(Some(symbol));
        Self
    }
}

impl Drop for TestClockDeadlineSymbolGuard {
    fn drop(&mut self) {
        set_test_clock_deadline_symbol(None);
    }
}
