//! SPDX-License-Identifier: GPL-2.0-only
//! Directed advisory storage controls; no native lifecycle or TCG claims.

use super::*;

fn inventory(witness: &Witness) -> std::sync::MutexGuard<'_, Inventory> {
    witness
        .inventory
        .lock()
        .unwrap_or_else(|error| panic!("advisory inventory lock: {error}"))
}

fn witness(allowance: usize, active: Option<(u64, u32)>) -> Witness {
    Witness {
        budget: allowance,
        pid: std::process::id(),
        provider: None,
        inventory: Mutex::new(Inventory {
            active,
            ..Inventory::default()
        }),
    }
}

#[test]
fn admission_requires_both_exact_existing_opt_ins_and_caps_its_own_stream() {
    assert_eq!(budget(None, Some(OsStr::new("64"))), 0);
    assert_eq!(budget(Some(OsStr::new("1")), None), 0);
    for invalid in ["0", "257", "064", "+64", "64 ", "1ms"] {
        assert_eq!(budget(Some(OsStr::new("1")), Some(OsStr::new(invalid))), 0);
    }
    assert_eq!(budget(Some(OsStr::new("1")), Some(OsStr::new("1"))), 1);
    assert_eq!(
        budget(Some(OsStr::new("1")), Some(OsStr::new("64"))),
        MAX_ROWS
    );
    assert_eq!(budget(Some(OsStr::new("true")), Some(OsStr::new("64"))), 0);
}

#[test]
fn no_pending_disabled_busy_or_foreign_pid_never_retains_a_record() {
    let disabled = witness(0, Some((2, 0)));
    let absent = witness(MAX_ROWS, None);
    assert!(
        disabled
            .retain(Phase::RustEntry, 0, None, None, None, None)
            .is_none()
    );
    assert!(
        absent
            .retain(Phase::RustEntry, 0, None, None, None, None)
            .is_none()
    );

    let mut foreign = witness(MAX_ROWS, Some((2, 0)));
    foreign.pid = foreign.pid.wrapping_add(1);
    assert!(
        foreign
            .retain(Phase::RustEntry, 0, None, None, None, None)
            .is_none()
    );

    let busy = witness(MAX_ROWS, Some((2, 0)));
    let _held = inventory(&busy);
    assert!(
        busy.retain(Phase::RustEntry, 0, None, None, None, None)
            .is_none()
    );
}

#[test]
fn duplicate_suppression_preserves_first_order_and_changed_request_or_indices() {
    let witness = witness(MAX_ROWS, Some((2, 0)));
    let first = witness.retain(Phase::ReplyEnter, 0, Some(3), Some(150), Some((0, 1)), None);
    assert!(first.is_some());
    assert!(
        witness
            .retain(Phase::ReplyEnter, 0, Some(3), Some(150), Some((0, 1)), None)
            .is_none()
    );
    let consumed = witness.retain(
        Phase::ReplyReturn,
        0,
        Some(3),
        Some(150),
        Some((1, 1)),
        None,
    );
    assert!(consumed.is_some());

    inventory(&witness).active = Some((3, 0));
    let next = witness.retain(Phase::ReplyEnter, 0, Some(3), Some(150), Some((0, 1)), None);
    assert!(next.is_some());
    let inventory = inventory(&witness);
    assert_eq!(inventory.count, 3);
    assert_eq!(inventory.rows[0], first);
    assert_eq!(inventory.rows[1], consumed);
    assert_eq!(inventory.rows[2], next);
}

#[test]
fn fixed_budget_refuses_before_capture_without_replenishment() {
    let witness = witness(2, Some((2, 0)));
    assert!(
        witness
            .retain(Phase::RustEntry, 0, None, None, None, None)
            .is_some()
    );
    assert!(
        witness
            .retain(Phase::PauseReturn, 0, None, None, None, None)
            .is_some()
    );
    inventory(&witness).active = Some((3, 0));
    assert!(
        witness
            .retain(Phase::ProviderUnavailable, 0, None, None, None, None)
            .is_none()
    );
    assert_eq!(inventory(&witness).count, 2);
}

#[test]
fn native_state_changes_are_distinct_and_unknown_seams_are_not_admitted() {
    let witness = witness(MAX_ROWS, Some((2, 0)));
    let mut native = NativeState {
        generation: 7,
        stop_state: 2,
        runstate: 4,
        cpu: 0,
        flags: 2,
        result: 0,
    };
    let first = witness.retain(Phase::Stopped, 0, None, None, None, Some(native));
    native.stop_state = 3;
    let changed = witness.retain(Phase::Stopped, 0, None, None, None, Some(native));
    assert!(first.is_some() && changed.is_some());
    assert_ne!(first, changed);
    for value in [0, 8, u32::MAX] {
        assert!(Phase::native(value).is_none());
    }
    for value in 1..=7 {
        assert!(Phase::native(value).is_some());
    }
}

#[test]
fn maximum_width_record_fits_the_literal_byte_cap() -> io::Result<()> {
    let record = Record {
        phase: Phase::PrepareStartReturn,
        pid: u32::MAX,
        sequence: u64::MAX,
        request_vcpu: u32::MAX,
        vcpu: u32::MAX,
        raw: Some(u64::MAX),
        ps: Some(u64::MAX),
        indices: Some((u64::MAX, u64::MAX)),
        native: Some(NativeState {
            generation: u64::MAX,
            stop_state: u32::MAX,
            runstate: u32::MAX,
            cpu: u32::MAX,
            flags: u32::MAX,
            result: i32::MIN,
        }),
    };
    let mut bytes = [0; MAX_ROW_BYTES];
    let mut output = io::Cursor::new(bytes.as_mut_slice());
    record.write_to(&mut output)?;
    let length = output.position() as usize;
    assert!(length <= MAX_ROW_BYTES);
    assert_eq!(bytes[length - 1], b'\n');
    Ok(())
}

#[test]
fn exhausted_capture_still_unregisters_after_original_completion_and_native_return() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    static UNREGISTRATIONS: AtomicUsize = AtomicUsize::new(0);
    extern "C" fn unregister(observer: Option<NativeObserver>) {
        if observer.is_none() {
            UNREGISTRATIONS.fetch_add(1, Ordering::Relaxed);
        }
    }

    let mut witness = witness(1, Some((2, 0)));
    witness.provider = Some(unregister);
    assert!(
        witness
            .retain(Phase::Pending, 0, Some(3), Some(150), None, None)
            .is_some()
    );

    // The authentic completion changes observer lifetime without adding a row.
    witness.reply_completed();
    assert!(
        witness
            .retain(
                Phase::ReplyCompleted,
                0,
                None,
                Some(150),
                Some((1, 1)),
                None
            )
            .is_none()
    );
    witness.finish_rust_return(Phase::RunningReturn);
    assert_eq!(inventory(&witness).active, Some((2, 0)));
    assert_eq!(UNREGISTRATIONS.load(Ordering::Relaxed), 0);

    assert!(
        witness
            .retain(Phase::NativeReturn, 0, None, None, None, None)
            .is_none()
    );
    witness.close_completed();
    witness.close_completed();
    let inventory = inventory(&witness);
    assert_eq!(inventory.active, None);
    assert_eq!(inventory.count, 1);
    assert_eq!(UNREGISTRATIONS.load(Ordering::Relaxed), 1);
}

#[test]
fn exhausted_capture_without_provider_closes_at_original_rust_return() {
    let witness = witness(1, Some((2, 0)));
    assert!(
        witness
            .retain(Phase::Pending, 0, Some(3), Some(150), None, None)
            .is_some()
    );

    // Earlier returns do not invent an original completed reply.
    witness.finish_rust_return(Phase::RunningReturn);
    assert_eq!(inventory(&witness).active, Some((2, 0)));
    witness.reply_completed();
    witness.finish_rust_return(Phase::RunningReturn);
    assert_eq!(inventory(&witness).active, None);
    assert_eq!(inventory(&witness).count, 1);
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
#[test]
fn refused_regular_file_capture_preserves_callers_thread_local_errno() -> io::Result<()> {
    use std::fs::{File, OpenOptions};

    let path = std::env::temp_dir().join(format!(
        "selectable-resume-errno-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let owner = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    let readonly = File::open(&path)?;
    std::fs::remove_file(&path)?;
    let capture = destination(&readonly)?;
    assert_eq!(capture.metadata()?.len(), 0);
    assert_eq!(
        (&capture)
            .write(b"refused")
            .err()
            .map(|error| error.raw_os_error()),
        Some(Some(libc::EBADF))
    );

    let restore_test_errno =
        ErrnoGuard::preserve().unwrap_or_else(|| panic!("supported errno slot missing"));
    let slot = restore_test_errno.slot;
    // SAFETY: the guard retains this test thread's live errno slot.
    unsafe { *slot.as_ptr() = libc::E2BIG };
    Record {
        phase: Phase::ReplyCompleted,
        pid: std::process::id(),
        sequence: 2,
        request_vcpu: 0,
        vcpu: 0,
        raw: None,
        ps: Some(150),
        indices: Some((1, 1)),
        native: None,
    }
    .capture_to(&readonly);
    // SAFETY: the same guard retains this thread-local slot after capture.
    let observed = unsafe { *slot.as_ptr() };

    assert_eq!(observed, libc::E2BIG);
    assert_eq!(owner.metadata()?.len(), 0);
    Ok(())
}
