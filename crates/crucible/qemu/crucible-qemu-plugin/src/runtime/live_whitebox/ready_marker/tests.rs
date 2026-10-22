//! Ready-provider refusal and actual deferred-stop custody regressions.

use std::cell::Cell;

use super::*;

thread_local! {
    static READY_CALLS: Cell<u32> = const { Cell::new(0) };
    static EXIT_CALLS: Cell<u32> = const { Cell::new(0) };
    static NAME_ADDRESS: Cell<usize> = const { Cell::new(0) };
    static NAME_LENGTH: Cell<usize> = const { Cell::new(0) };
    static OBSERVED_ICOUNT: Cell<u64> = const { Cell::new(0) };
}

extern "C" fn ready_ok(name: *const c_char, length: usize, icount: u64) -> i32 {
    READY_CALLS.set(READY_CALLS.get() + 1);
    NAME_ADDRESS.set(name as usize);
    NAME_LENGTH.set(length);
    OBSERVED_ICOUNT.set(icount);
    0
}

extern "C" fn ready_refused(name: *const c_char, length: usize, icount: u64) -> i32 {
    ready_ok(name, length, icount);
    -libc::ESTALE
}

extern "C" fn exit_ok() -> i32 {
    EXIT_CALLS.set(EXIT_CALLS.get() + 1);
    0
}

extern "C" fn exit_refused() -> i32 {
    EXIT_CALLS.set(EXIT_CALLS.get() + 1);
    -libc::EBUSY
}

fn reset_calls() {
    READY_CALLS.set(0);
    EXIT_CALLS.set(0);
}

#[test]
fn ready_refusal_retains_the_original_name_without_deferring_a_stop() {
    let handoff = SelectableVmstopHandoff::new();
    let name = String::from("fault.transport.ready");
    let address = name.as_ptr();
    let length = name.len();
    reset_calls();

    let error = observe(name, 93, ready_refused, Some((&handoff, exit_ok))).unwrap_err();

    let LiveWhiteboxError::ReadyMarkerRefused { name, status } = &error else {
        panic!("ready refusal must preserve the original provider result");
    };
    assert_eq!(name.as_ptr(), address);
    assert_eq!(*status, -libc::ESTALE);
    assert_eq!(NAME_ADDRESS.get(), address as usize);
    assert_eq!(NAME_LENGTH.get(), length);
    assert_eq!(OBSERVED_ICOUNT.get(), 93);
    assert_eq!(READY_CALLS.get(), 1);
    assert_eq!(EXIT_CALLS.get(), 0);
    assert!(!handoff.is_pending());
    assert_eq!(
        error.to_string(),
        "safe white-box callback failed: QEMU rejected ready-marker observation `fault.transport.ready` with status -116"
    );
}

#[test]
fn campaign_refusals_preserve_name_and_the_existing_deferred_stop() {
    let handoff = SelectableVmstopHandoff::new();
    let name = String::from("fault.followup.ready");
    let address = name.as_ptr();
    reset_calls();

    let refused = observe(name, 94, ready_ok, Some((&handoff, exit_refused))).unwrap_err();

    let LiveWhiteboxError::CampaignMarkerExitRefused { name, status } = &refused else {
        panic!("TB exit refusal must preserve its original status");
    };
    assert_eq!(name.as_ptr(), address);
    assert_eq!(*status, -libc::EBUSY);
    assert_eq!(READY_CALLS.get(), 1);
    assert_eq!(EXIT_CALLS.get(), 1);
    assert!(!handoff.is_pending());
    assert_eq!(
        refused.to_string(),
        "safe white-box callback failed: QEMU rejected campaign boundary `fault.followup.ready` TB exit with status -16"
    );

    assert_eq!(handoff.defer(exit_ok), Ok(true));
    let name = String::from("fault.transport.ready");
    let address = name.as_ptr();
    reset_calls();

    let collision = observe(name, 95, ready_ok, Some((&handoff, exit_ok))).unwrap_err();

    let LiveWhiteboxError::CampaignMarkerCollision { name } = &collision else {
        panic!("the already deferred stop must retain the collision");
    };
    assert_eq!(name.as_ptr(), address);
    assert_eq!(READY_CALLS.get(), 1);
    assert_eq!(EXIT_CALLS.get(), 0);
    assert!(handoff.is_pending());
    assert_eq!(
        collision.to_string(),
        "safe white-box callback failed: campaign boundary `fault.transport.ready` collided with another deferred VMStop"
    );

    observe(
        "ordinary.event".to_owned(),
        96,
        ready_ok,
        Some((&handoff, exit_ok)),
    )
    .expect("an ordinary event does not request a campaign stop");
    assert!(handoff.is_pending());
    assert_eq!(EXIT_CALLS.get(), 0);
}
