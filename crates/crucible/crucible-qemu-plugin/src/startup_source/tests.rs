//! Exercises the fixed adapter using private fixture tables, not native exports.

use super::*;
use std::fs::File;

extern "C" fn accept(_plugin_id: u64, _plan: i32) -> i32 {
    0
}

extern "C" fn healthy_check(_plugin_id: u64) -> i32 {
    0
}

extern "C" fn refuse_check(_plugin_id: u64) -> i32 {
    -173
}

extern "C" fn bounded_slice(_plugin_id: u64, bounded_ns: *mut u64) -> i32 {
    // SAFETY: the private adapter lends its initialized u64 for this call.
    unsafe { *bounded_ns = 1_234 };
    0
}

extern "C" fn refuse_slice(_plugin_id: u64, _bounded_ns: *mut u64) -> i32 {
    -181
}

extern "C" fn complete(_plugin_id: u64, status: i32) -> i32 {
    assert_eq!(status, 0);
    0
}

fn fixture(check: Check, query_slice: QuerySlice) -> InstallerStartupSource {
    let descriptor = File::open("/dev/null").unwrap();
    let mut owner = InstallerStartupSource::retain_received_plan(73, descriptor.into());
    owner.api = Some(NativeStartupApi {
        acquire: accept,
        check,
        query_slice,
        registration_complete: complete,
    });
    owner.acquisition_attempted = true;
    owner.acquired = true;
    owner
}

#[test]
fn native_refusal_keeps_the_exact_first_signed_status() {
    let owner = fixture(refuse_check, bounded_slice);

    assert_eq!(
        owner.check(),
        Err(StartupSourceError::NativeStatus { status: -173 })
    );
    assert_eq!(
        owner.wait_slice(),
        Err(StartupSourceError::NativeStatus { status: -173 })
    );
    assert_eq!(owner.first_status.load(Ordering::Acquire), -173);
}

#[test]
fn query_refusal_never_uses_its_untouched_output() {
    let owner = fixture(healthy_check, refuse_slice);

    assert_eq!(
        owner.wait_slice(),
        Err(StartupSourceError::NativeStatus { status: -181 })
    );
    assert_eq!(
        owner.check(),
        Err(StartupSourceError::NativeStatus { status: -181 })
    );
}

#[test]
fn successful_slice_uses_only_the_native_bounded_value() {
    let owner = fixture(healthy_check, bounded_slice);

    assert_eq!(owner.wait_slice().unwrap(), Duration::from_nanos(1_234));
}

#[test]
fn registration_completion_is_once_and_keeps_the_same_owner() {
    let mut owner = fixture(healthy_check, bounded_slice);
    let descriptor = owner.plan_fd().unwrap().as_raw_fd();

    owner.registration_complete().unwrap();

    assert_eq!(owner.plan_fd().unwrap().as_raw_fd(), descriptor);
    assert!(matches!(
        owner.registration_complete(),
        Err(StartupSourceError::Ownership { .. })
    ));
    owner.check().unwrap();
}

#[test]
fn repeated_acquisition_refuses_without_replacing_the_plan() {
    let mut owner = fixture(healthy_check, bounded_slice);
    let descriptor = owner.plan_fd().unwrap().as_raw_fd();

    assert!(matches!(
        owner.acquire(),
        Err(StartupSourceError::Ownership { .. })
    ));

    assert_eq!(owner.plan_fd().unwrap().as_raw_fd(), descriptor);
}

#[test]
fn dropping_a_refused_owner_does_not_close_the_actual_descriptor() {
    let owner = fixture(refuse_check, bounded_slice);
    let descriptor = owner.plan_fd().unwrap().as_raw_fd();
    assert!(owner.check().is_err());

    drop(owner);

    // SAFETY: this fixture has no native borrower. Inspection first proves
    // containment retained the real fd; only the fixture explicitly closes it.
    assert!(unsafe { libc::fcntl(descriptor, libc::F_GETFD) } >= 0);
    // SAFETY: the preceding inspection proved this fixture retained the unique fd; no native borrower exists.
    assert_eq!(unsafe { libc::close(descriptor) }, 0);
}

extern "C" fn empty_slice(_plugin_id: u64, _bounded_ns: *mut u64) -> i32 {
    0
}

#[test]
fn invalid_successful_slice_keeps_later_completion_terminal() {
    let mut owner = fixture(healthy_check, empty_slice);

    assert!(matches!(
        owner.wait_slice(),
        Err(StartupSourceError::Ownership { .. })
    ));
    assert!(matches!(
        owner.registration_complete(),
        Err(StartupSourceError::Ownership { .. })
    ));
    assert!(!owner.registration_completed);
}
