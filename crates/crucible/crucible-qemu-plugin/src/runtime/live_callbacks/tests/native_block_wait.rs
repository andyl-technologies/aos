//! Joined native coroutine, registered waiter and idle-completion cases.
//!
//! The ignored test requires the source-built selected-native unit library.
//! Each case has its own process because QEMU's main loop and coroutine pools
//! own process-lifetime state. CPU execution and raw calibration are providers;
//! the timer list, block coroutine and registered Rust callbacks are original.
//! After `rr_wait_io_event`, the fixture invokes the original idle-settlement
//! helper in the same order as the selected outer RR loop. The outer TCG loop
//! and its CPU-work fixed-point drain are omitted providers, not executed code.

use super::*;

use std::ffi::CStr;
use std::os::unix::ffi::OsStrExt as _;
use std::process::Command;

const UNIT_LIBRARY: &str = "CRUCIBLE_BLOCK_WAIT_NATIVE_UNIT_LIBRARY";
const UNIT_CASE: &str = "CRUCIBLE_BLOCK_WAIT_NATIVE_UNIT_CASE";

#[repr(C)]
struct Callbacks {
    wait: extern "C" fn(u32, *mut c_void),
    complete: extern "C" fn(std::os::raw::c_int, i64, *mut c_void),
    idle: extern "C" fn(u32, u64, *mut c_void),
    current: extern "C" fn(*mut c_void) -> u64,
    publish: extern "C" fn(u64, *mut c_void),
    userdata: *mut c_void,
}

#[derive(Debug, Default)]
#[repr(C)]
struct NativeResult {
    polls: u32,
    delivered: u32,
    due_timer_callbacks: u32,
    doorbell_reads: u32,
    completion_callbacks: u32,
    cpu_kicks: u32,
    result: i64,
    completed_coordinate: u64,
}

struct NativeLibrary(std::ptr::NonNull<c_void>);

impl NativeLibrary {
    fn open() -> Self {
        let path = std::env::var_os(UNIT_LIBRARY)
            .unwrap_or_else(|| panic!("{UNIT_LIBRARY} must name the source-built native unit"));
        let path = CString::new(path.as_bytes())
            .unwrap_or_else(|error| panic!("native unit path must have no NUL: {error}"));
        // SAFETY: the owned C string stays live for this synchronous loader call.
        let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        Self(
            std::ptr::NonNull::new(handle)
                .unwrap_or_else(|| panic!("source-built native unit must load: {}", Self::error())),
        )
    }

    fn error() -> String {
        // SAFETY: dlerror returns a loader-owned NUL-terminated string or null.
        let message = unsafe { libc::dlerror() };
        if message.is_null() {
            return "no loader error was supplied".into();
        }
        // SAFETY: the non-null loader string remains live until the next loader call.
        unsafe { CStr::from_ptr(message) }
            .to_string_lossy()
            .into_owned()
    }

    /// Loads one function from the private joined-unit adapter.
    ///
    /// # Safety
    ///
    /// `T` must be the complete `extern "C"` function-pointer type declared for
    /// `name` in `block-wait-completion.h`, including its argument and result
    /// layouts. The library and resolved symbol must remain loaded through every
    /// invocation and retained callback that uses the returned function pointer.
    unsafe fn function<T: Copy>(&self, name: &CStr) -> T {
        // SAFETY: the native library is retained for the entire child process.
        let symbol = unsafe { libc::dlsym(self.0.as_ptr(), name.as_ptr()) };
        assert!(
            !symbol.is_null(),
            "native symbol {name:?}: {}",
            Self::error()
        );
        assert_eq!(std::mem::size_of::<T>(), std::mem::size_of_val(&symbol));
        // SAFETY: each call supplies the exact private C adapter prototype. This
        // assertion and the native header constrain the pointer-size conversion.
        unsafe { std::mem::transmute_copy(&symbol) }
    }
}

// The library intentionally stays mapped until this isolated child exits:
// QEMU coroutine-pool cleanup retains native callbacks at thread teardown.

extern "C" fn observe_current(userdata: *mut c_void) -> u64 {
    callback_userdata_or_abort(userdata)
        .slot
        .get()
        .snapshot()
        .current_icount
}

extern "C" fn publish_device_deadline(deadline: u64, userdata: *mut c_void) {
    callback_userdata_or_abort(userdata)
        .slot
        .get()
        .store_device_completion_deadline_tick(deadline);
}

fn run_joined_case(due_timer: bool) {
    let native = NativeLibrary::open();
    // SAFETY: these signatures exactly match block-wait-completion.h and the
    // original native timer-witness record; the library outlives every callback.
    let (raw, deadline, enqueue, arm, query, run) = unsafe {
        (
            native.function::<extern "C" fn() -> u64>(c"block_wait_unit_raw"),
            native.function::<extern "C" fn() -> i64>(c"block_wait_unit_deadline"),
            native.function::<extern "C" fn(i64) -> std::os::raw::c_int>(c"block_wait_unit_enqueue"),
            native.function::<crate::QemuArmVirtualTimerWitnessFn>(c"block_wait_unit_arm_timer"),
            native.function::<crate::QemuQueryVirtualTimerWitnessFn>(c"block_wait_unit_query_timer"),
            native.function::<extern "C" fn(*const Callbacks, bool, *mut NativeResult) -> std::os::raw::c_int>(c"block_wait_unit_run"),
        )
    };

    // These are the original loaded native APIs, outside their admitted idle
    // and completion callback scopes. They must not mint a witness here.
    let mut generation = 41;
    assert_eq!(arm(200, 200, &mut generation), -libc::EPERM);
    assert_eq!(generation, 0);
    assert_eq!(arm(-1, 0, &mut generation), -libc::EINVAL);
    let mut record = crate::QemuVirtualTimerWitnessRecord::default();
    assert_eq!(query(1, &mut record), -libc::EPERM);

    let slot = Box::new(NodeSlot::new(KIND_VM));
    let ceiling = authorize_advance_ceiling(0, 1000, None)
        .unwrap_or_else(|error| panic!("test ceiling: {error}"));
    slot.publish_scheduler_advance(ceiling, AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test scheduler publication: {error}"));
    slot.publish_reached_icount(100)
        .unwrap_or_else(|error| panic!("test initial coordinate: {error}"));
    slot.mark_device_io_active();
    let layout = RegionLayout::for_config(RegionConfig::new(1, 2))
        .unwrap_or_else(|error| panic!("test region: {error}"));
    let header = Box::new(RegionHeader::new(layout));
    let (sender, _receiver) = mpsc::channel();
    let mut state = test_live_state_with_teardown(0, 1, 2, &header, &slot, sender)
        .unwrap_or_else(|error| panic!("original live callback state: {error}"));
    state.icount_raw = raw;
    state.exact_deadline = ExactDeadlineReader::require(Some(deadline))
        .unwrap_or_else(|error| panic!("native timer capability: {error}"));
    state.queued_idle_advance = QueuedIdleAdvance::require(Some(enqueue))
        .unwrap_or_else(|error| panic!("native advance capability: {error}"));
    state.virtual_timer_witness = crate::QemuVirtualTimerWitness::require(Some(arm), Some(query))
        .unwrap_or_else(|error| panic!("original native witness capability: {error}"));
    state
        .on_vcpu_init(0)
        .unwrap_or_else(|error| panic!("original vCPU initialization: {error}"));
    let state = Box::new(state);
    let callbacks = Callbacks {
        wait: crucible_qemu_plugin_live_block_wait_cb,
        complete: crucible_qemu_plugin_live_time_advance_completion_cb,
        idle: crucible_qemu_plugin_live_vcpu_idle_cb,
        current: observe_current,
        publish: publish_device_deadline,
        userdata: std::ptr::from_ref(state.as_ref()).cast_mut().cast(),
    };

    let mut result = NativeResult::default();
    let status = run(&callbacks, due_timer, &mut result);

    assert_eq!(status, 0, "joined native ownership: {result:?}");
    assert_eq!(result.delivered, 1, "one original response");
    assert_eq!(result.completion_callbacks, 1, "one original completion");
    assert_eq!(result.result, 1);
    assert_eq!(result.completed_coordinate, 200);
    assert!(
        result.polls >= 2,
        "original wake must re-poll after parking"
    );
    assert_eq!(result.due_timer_callbacks, u32::from(due_timer));
    assert!(!state.idle_advance_is_pending());
    println!("joined native due_timer={due_timer} result={result:?}");
}

#[test]
#[ignore = "requires the selected source-built native coroutine/timer unit"]
fn live_block_wait_joins_native_coroutine_and_idle_completion() {
    if let Some(case) = std::env::var_os(UNIT_CASE) {
        match case.to_str() {
            Some("publication-after-park") => run_joined_case(false),
            Some("already-due-timer") => run_joined_case(true),
            _ => panic!("unknown joined native case"),
        }
        return;
    }
    let executable = std::env::current_exe()
        .unwrap_or_else(|error| panic!("current GPL unit executable: {error}"));
    let module = module_path!()
        .strip_prefix("crucible_qemu_plugin::")
        .unwrap_or_else(|| panic!("expected original plugin test module"));
    let test = format!("{module}::live_block_wait_joins_native_coroutine_and_idle_completion");
    for case in ["publication-after-park", "already-due-timer"] {
        let output = Command::new(&executable)
            .args(["--ignored", "--exact", &test, "--nocapture"])
            .env(UNIT_CASE, case)
            .env("RUST_BACKTRACE", "0")
            .output()
            .unwrap_or_else(|error| panic!("joined native child: {error}"));
        assert!(output.stdout.len() <= 32768 && output.stderr.len() <= 32768);
        assert!(
            output.status.success(),
            "{case}: status={}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
