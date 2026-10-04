//! Bounded observations of original time ownership and native idle waits.
//!
//! The opt-in observer registers a first-TB callback after original time-control
//! acquisition. TB entry is already debited, so its receipt keeps both the
//! observed charge and QEMU's public, exact entry count. Idle observations begin
//! only at an original `NextAuthenticatedIdle` request. At most 60 wait pairs
//! and two ownership rows are emitted, each at most 256 bytes (31,232 bytes).
//! This witness qualifies fresh processes, not fork-child inheritance.
//! Missing observations fail the external gate; they never control the guest.

use std::io::{self, Write};
use std::os::raw::{c_int, c_uint, c_void};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::{QemuIcountAtTbEntryFn, QemuIcountRawFn, QemuPluginId, QemuPluginTb};

pub(super) const ENVIRONMENT: &str = "CRUCIBLE_TIME_OWNERSHIP_WITNESS";
const MAX_WAIT_PAIRS: u64 = 60;
const MAX_ROW_BYTES: usize = 256;
type TranslationCallback = extern "C" fn(*mut QemuPluginTb, *mut c_void);
type ExecutionCallback = extern "C" fn(c_uint, *mut c_void);
type RegisterTranslation = extern "C" fn(QemuPluginId, TranslationCallback, *mut c_void);
type RegisterExecution = extern "C" fn(*mut QemuPluginTb, ExecutionCallback, c_int, *mut c_void);
type TbLength = extern "C" fn(*const QemuPluginTb) -> usize;
type HasTimeControl = extern "C" fn() -> bool;
type ObserveTicks = extern "C" fn() -> i64;

#[derive(Clone, Copy)]
struct Apis {
    register_translation: RegisterTranslation,
    register_execution: RegisterExecution,
    tb_length: TbLength,
    entry_count: QemuIcountAtTbEntryFn,
    raw_count: QemuIcountRawFn,
    observe_ticks: ObserveTicks,
    owns_time: HasTimeControl,
}

struct Witness {
    apis: Apis,
    first_entry: AtomicBool,
    idle_active: AtomicBool,
    waits: AtomicU64,
}

static WITNESS: OnceLock<Witness> = OnceLock::new();

impl Witness {
    const fn new(apis: Apis) -> Self {
        Self {
            apis,
            first_entry: AtomicBool::new(false),
            idle_active: AtomicBool::new(false),
            waits: AtomicU64::new(0),
        }
    }

    fn first_tb(&self, vcpu: u32, instructions: u64, output: &mut impl Write) {
        if self.first_entry.swap(true, Ordering::Relaxed) {
            return;
        }
        let mut entry_raw = 0;
        let entry_status = (self.apis.entry_count)(instructions, &mut entry_raw);
        let charged_raw = (self.apis.raw_count)();
        let charged_ps = (self.apis.observe_ticks)();
        let owned = (self.apis.owns_time)();
        row(
            output,
            format_args!(
                "phase=first-tb pid={} vcpu={vcpu} tb={instructions} entry_status={entry_status} entry_raw={entry_raw} charged_raw={charged_raw} charged_ps={charged_ps} owned={}",
                std::process::id(),
                u8::from(owned),
            ),
        );
    }

    fn begin_wait(&self, next_idle: bool, vcpu: u32, output: &mut impl Write) -> Option<Wait> {
        if next_idle {
            self.idle_active.store(true, Ordering::Relaxed);
        }
        if !self.idle_active.load(Ordering::Relaxed) {
            return None;
        }
        let index = self
            .waits
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |index| {
                (index < MAX_WAIT_PAIRS).then_some(index + 1)
            })
            .ok()?;
        let wait = Wait { index, vcpu };
        row(
            output,
            format_args!(
                "phase=idle-before pid={} vcpu={vcpu} wait={index} raw={} ps={}",
                std::process::id(),
                (self.apis.raw_count)(),
                (self.apis.observe_ticks)(),
            ),
        );
        Some(wait)
    }

    fn end_wait(&self, wait: Wait, status: i32, output: &mut impl Write) {
        row(
            output,
            format_args!(
                "phase=idle-after pid={} vcpu={} wait={} status={status} raw={} ps={}",
                std::process::id(),
                wait.vcpu,
                wait.index,
                (self.apis.raw_count)(),
                (self.apis.observe_ticks)(),
            ),
        );
    }
}

fn row(output: &mut impl Write, fields: std::fmt::Arguments<'_>) {
    let mut bytes = [0_u8; MAX_ROW_BYTES];
    let mut cursor = io::Cursor::new(bytes.as_mut_slice());
    if writeln!(cursor, "CRUCIBLE-TIME-OWNER-V1 {fields}").is_ok() {
        let length = cursor.position() as usize;
        // A closed diagnostic sink must not replace the original callback result.
        let _ = output.write_all(&bytes[..length]);
    }
}

/// Installs observations after the original registration path acquired control.
pub(super) fn install(plugin_id: QemuPluginId) {
    // crucible-lint: allow host-nondeterminism-state -- the exact opt-in is cached once and affects only diagnostic callbacks.
    let enabled = std::env::var(ENVIRONMENT).as_deref() == Ok("1");
    if !enabled {
        return;
    }
    let mut output = io::stderr().lock();
    if let Some(witness) = prepare(enabled, resolve_apis, &mut output) {
        let apis = witness.apis;
        if WITNESS.set(witness).is_ok() {
            (apis.register_translation)(plugin_id, translate, std::ptr::null_mut());
        }
    }
}

fn prepare(
    enabled: bool,
    resolve: impl FnOnce() -> Option<Apis>,
    output: &mut impl Write,
) -> Option<Witness> {
    if !enabled {
        return None;
    }
    let Some(apis) = resolve() else {
        row(
            output,
            format_args!("phase=unavailable pid={}", std::process::id()),
        );
        return None;
    };
    row(
        output,
        format_args!(
            "phase=acquired pid={} raw={} ps={} owned={}",
            std::process::id(),
            (apis.raw_count)(),
            (apis.observe_ticks)(),
            u8::from((apis.owns_time)()),
        ),
    );
    Some(Witness::new(apis))
}

fn resolve_apis() -> Option<Apis> {
    macro_rules! symbol {
        ($name:literal, $type:ty) => {{
            // SAFETY: the name is a static NUL-terminated public QEMU export.
            let address =
                unsafe { libc::dlsym(libc::RTLD_DEFAULT, concat!($name, "\0").as_ptr().cast()) };
            if address.is_null() {
                return None;
            }
            // SAFETY: each exact selected QEMU declaration matches its alias.
            unsafe { std::mem::transmute::<*mut c_void, $type>(address) }
        }};
    }
    Some(Apis {
        register_translation: symbol!("qemu_plugin_register_vcpu_tb_trans_cb", RegisterTranslation),
        register_execution: symbol!("qemu_plugin_register_vcpu_tb_exec_cb", RegisterExecution),
        tb_length: symbol!("qemu_plugin_tb_n_insns", TbLength),
        entry_count: symbol!("qemu_plugin_icount_at_tb_entry", QemuIcountAtTbEntryFn),
        raw_count: symbol!("qemu_plugin_icount_raw", QemuIcountRawFn),
        observe_ticks: symbol!("qemu_plugin_sim_tick_observed", ObserveTicks),
        owns_time: symbol!("qemu_plugin_has_time_control", HasTimeControl),
    })
}

extern "C" fn translate(tb: *mut QemuPluginTb, _userdata: *mut c_void) {
    let Some(witness) = WITNESS.get() else { return };
    if tb.is_null() || witness.first_entry.load(Ordering::Relaxed) {
        return;
    }
    let count = (witness.apis.tb_length)(tb);
    if count != 0 {
        // The callback's opaque userdata contains only the translated TB length.
        (witness.apis.register_execution)(tb, execute, 0, count as *mut c_void);
    }
}

extern "C" fn execute(vcpu: c_uint, userdata: *mut c_void) {
    if let Some(witness) = WITNESS.get()
        && !witness.first_entry.load(Ordering::Relaxed)
    {
        witness.first_tb(vcpu, userdata as usize as u64, &mut io::stderr().lock());
    }
}

pub(super) struct Wait {
    index: u64,
    vcpu: u32,
}

pub(super) fn begin_wait(next_idle: bool, vcpu: u32) -> Option<Wait> {
    let witness = WITNESS.get()?;
    if (!next_idle && !witness.idle_active.load(Ordering::Relaxed))
        || witness.waits.load(Ordering::Relaxed) >= MAX_WAIT_PAIRS
    {
        return None;
    }
    witness.begin_wait(next_idle, vcpu, &mut io::stderr().lock())
}

pub(super) fn end_wait(wait: Option<Wait>, status: Option<super::QemuIdleWakeWaitStatus>) {
    if let (Some(witness), Some(wait)) = (WITNESS.get(), wait) {
        witness.end_wait(
            wait,
            status.map_or(-1, super::QemuIdleWakeWaitStatus::into_raw),
            &mut io::stderr().lock(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    extern "C" fn register_translation(
        _id: QemuPluginId,
        _cb: TranslationCallback,
        _data: *mut c_void,
    ) {
    }
    extern "C" fn register_execution(
        _tb: *mut QemuPluginTb,
        _cb: ExecutionCallback,
        _flags: c_int,
        _data: *mut c_void,
    ) {
    }
    extern "C" fn tb_length(_tb: *const QemuPluginTb) -> usize {
        3
    }
    extern "C" fn entry_count(tb: u64, entry: *mut u64) -> c_int {
        assert_eq!(tb, 3);
        // SAFETY: the production observer passes its live local output scalar.
        unsafe {
            *entry = 0;
        }
        0
    }
    extern "C" fn raw_count() -> u64 {
        3
    }
    extern "C" fn ticks() -> i64 {
        150
    }
    extern "C" fn owns_time() -> bool {
        true
    }
    extern "C" fn no_owner() -> bool {
        false
    }

    fn apis() -> Apis {
        Apis {
            register_translation,
            register_execution,
            tb_length,
            entry_count,
            raw_count,
            observe_ticks: ticks,
            owns_time,
        }
    }

    #[test]
    fn disabled_does_not_resolve_query_or_emit() {
        let called = Cell::new(false);
        let mut output = Vec::new();
        let witness = prepare(
            false,
            || {
                called.set(true);
                Some(apis())
            },
            &mut output,
        );
        assert!(witness.is_none());
        assert!(!called.get());
        assert!(output.is_empty());
    }

    #[test]
    fn missing_and_false_ownership_remain_explicit_observations() {
        let mut output = Vec::new();
        assert!(prepare(true, || None, &mut output).is_none());
        assert!(
            String::from_utf8(output)
                .unwrap_or_else(|error| panic!("observer receipt must be UTF-8: {error}"))
                .contains("phase=unavailable")
        );

        let mut output = Vec::new();
        let witness = prepare(
            true,
            || {
                Some(Apis {
                    owns_time: no_owner,
                    ..apis()
                })
            },
            &mut output,
        )
        .unwrap_or_else(|| panic!("complete fixture APIs must prepare the witness"));
        witness.first_tb(0, 3, &mut output);
        let rows = String::from_utf8(output)
            .unwrap_or_else(|error| panic!("observer receipt must be UTF-8: {error}"));
        assert_eq!(rows.lines().count(), 2);
        assert!(rows.lines().all(|line| line.ends_with("owned=0")));
    }

    #[test]
    fn first_tb_preserves_charged_count_and_exact_entry_once() {
        let witness = Witness::new(apis());
        let mut output = Vec::new();
        witness.first_tb(0, 3, &mut output);
        witness.first_tb(0, 3, &mut output);
        let rows = String::from_utf8(output)
            .unwrap_or_else(|error| panic!("observer receipt must be UTF-8: {error}"));
        assert_eq!(rows.lines().count(), 1);
        assert!(
            rows.contains("tb=3 entry_status=0 entry_raw=0 charged_raw=3 charged_ps=150 owned=1")
        );
    }

    #[test]
    fn maximum_width_first_tb_receipt_remains_complete_and_bounded() {
        extern "C" fn maximum_entry(_tb: u64, entry: *mut u64) -> c_int {
            // SAFETY: the observer supplies a live local output scalar.
            unsafe {
                *entry = u64::MAX;
            }
            c_int::MIN
        }
        extern "C" fn maximum_raw() -> u64 {
            u64::MAX
        }
        extern "C" fn minimum_ticks() -> i64 {
            i64::MIN
        }
        let witness = Witness::new(Apis {
            entry_count: maximum_entry,
            raw_count: maximum_raw,
            observe_ticks: minimum_ticks,
            ..apis()
        });
        let mut output = Vec::new();

        witness.first_tb(u32::MAX, u64::MAX, &mut output);

        assert!(output.len() <= MAX_ROW_BYTES);
        let receipt = String::from_utf8(output)
            .unwrap_or_else(|error| panic!("observer receipt must be UTF-8: {error}"));
        assert_eq!(receipt.lines().count(), 1);
        assert!(receipt.contains("entry_status=-2147483648 entry_raw=18446744073709551615"));
        assert!(receipt.ends_with("charged_ps=-9223372036854775808 owned=1\n"));
    }

    #[test]
    fn original_next_idle_activates_finitely_bounded_wait_pairs() {
        let witness = Witness::new(apis());
        let mut output = Vec::new();
        assert!(witness.begin_wait(false, 0, &mut output).is_none());
        assert!(output.is_empty());
        for index in 0..MAX_WAIT_PAIRS {
            let wait = witness
                .begin_wait(index == 0, 0, &mut output)
                .unwrap_or_else(|| panic!("original idle must admit wait {index}"));
            assert_eq!(wait.index, index);
            witness.end_wait(wait, 0, &mut output);
        }
        for _ in 0..5 {
            assert!(witness.begin_wait(true, 0, &mut output).is_none());
        }
        assert_eq!(witness.waits.load(Ordering::Relaxed), MAX_WAIT_PAIRS);
        assert_eq!(output.iter().filter(|byte| **byte == b'\n').count(), 120);
        assert!(
            output
                .split_inclusive(|byte| *byte == b'\n')
                .all(|row| row.len() <= MAX_ROW_BYTES)
        );
        assert!(output.len() <= 120 * MAX_ROW_BYTES);
    }

    #[test]
    fn broken_sink_does_not_change_observer_completion() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let witness = Witness::new(apis());
        witness.first_tb(0, 3, &mut Broken);
        let wait = witness
            .begin_wait(true, 0, &mut Broken)
            .unwrap_or_else(|| panic!("sink failure must not refuse the diagnostic wait"));
        witness.end_wait(wait, 10, &mut Broken);
        assert!(witness.first_entry.load(Ordering::Relaxed));
        assert_eq!(witness.waits.load(Ordering::Relaxed), 1);
    }
}
