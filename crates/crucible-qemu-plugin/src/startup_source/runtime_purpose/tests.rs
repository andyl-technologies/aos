//! Checks Source-owned runtime reservation ordering with test-only native tables.
//!
//! These tests verify inline attempted/holder/first-error custody. Their modeled
//! functions never issue a production containing purpose or pay actual births.
// SPDX-License-Identifier: GPL-2.0-only

use std::cell::RefCell;
use std::os::fd::AsRawFd;

use super::*;
use crate::startup_source::NativeStartupApi;

#[derive(Default)]
struct NativeCuts {
    reserve_status: i32,
    check_status: i32,
    calls: Vec<&'static str>,
    requests: Option<[Request; 3]>,
}

thread_local! {
    static CUTS: RefCell<NativeCuts> = const { RefCell::new(NativeCuts {
        reserve_status: 0, check_status: 0, calls: Vec::new(), requests: None,
    }) };
}

extern "C" fn acquire(_: u64, _: i32) -> i32 {
    0
}
extern "C" fn source_check(_: u64) -> i32 {
    0
}
extern "C" fn slice(_: u64, _: *mut u64) -> i32 {
    -libc::ENOSYS
}
extern "C" fn complete(_: u64, _: i32) -> i32 {
    -libc::ENOSYS
}

extern "C" fn reserve(_: u64, requests: *const Request, output: *mut *mut RuntimePurpose) -> i32 {
    CUTS.with_borrow_mut(|cuts| {
        cuts.calls.push("reserve");
        // SAFETY: the wrapper lends three initialized fixed rows for this call.
        cuts.requests = Some(unsafe { [*requests, *requests.add(1), *requests.add(2)] });
        if cuts.reserve_status == 0 {
            // SAFETY: this test-only non-null identity is never dereferenced or
            // passed to real native code; the wrapper owns its live output slot.
            unsafe {
                output.write(std::ptr::without_provenance_mut(1));
            }
        }
        cuts.reserve_status
    })
}

extern "C" fn check(_: u64, _: *mut RuntimePurpose) -> i32 {
    CUTS.with_borrow_mut(|cuts| {
        cuts.calls.push("check");
        cuts.check_status
    })
}

fn fixture(action: impl FnOnce(&mut InstallerStartupSource)) {
    CUTS.with_borrow_mut(|cuts| *cuts = NativeCuts::default());
    let (stream, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let descriptor = stream.as_raw_fd();
    let mut owner = InstallerStartupSource::retain_received_plan(7, stream.into());
    owner.api = Some(NativeStartupApi {
        acquire,
        check: source_check,
        query_slice: slice,
        registration_complete: complete,
    });
    owner.acquired = true;
    owner.acquisition_attempted = true;

    action(&mut owner);
    drop(owner);

    // SAFETY: the model made no native borrower. Production Drop deliberately
    // retained this actual fixture fd, so the test alone disposes it once.
    assert_eq!(unsafe { libc::close(descriptor) }, 0);
}

fn layouts() -> [Layout; 3] {
    [
        Layout::from_size_align(192, 16).unwrap(),
        Layout::from_size_align(32, 8).unwrap(),
        Layout::from_size_align(80, 16).unwrap(),
    ]
}

#[test]
fn all_three_requests_are_checked_before_the_caller_can_allocate() {
    fixture(|owner| {
        owner
            .reserve_runtime_allocations_using(layouts(), reserve, check)
            .unwrap();
        assert!(owner.runtime_reservation.attempted);
        assert_ne!(owner.runtime_reservation.purpose_address, 0);
        CUTS.with_borrow(|cuts| {
            assert_eq!(cuts.calls, ["reserve", "check"]);
            let requests = cuts.requests.unwrap();
            assert_eq!(requests[0].extent_bytes, 192);
            assert_eq!(requests[0].alignment_bytes, 16);
            assert_eq!(requests[1].extent_bytes, 32);
            assert_eq!(requests[1].alignment_bytes, 8);
            assert_eq!(requests[0].birth_count, 1);
            assert_eq!(requests[1].birth_count, 1);
            assert_eq!(requests[2].extent_bytes, 80);
            assert_eq!(requests[2].alignment_bytes, 16);
            assert_eq!(requests[2].birth_count, 1);
        });
    });
}

#[test]
fn failed_reserve_retains_attempt_and_original_first_cause_without_a_holder() {
    fixture(|owner| {
        CUTS.with_borrow_mut(|cuts| cuts.reserve_status = -libc::ECANCELED);
        assert_eq!(
            owner.reserve_runtime_allocations_using(layouts(), reserve, check),
            Err(StartupSourceError::NativeStatus {
                status: -libc::ECANCELED
            })
        );
        assert!(owner.runtime_reservation.attempted);
        assert_eq!(owner.runtime_reservation.purpose_address, 0);

        CUTS.with_borrow_mut(|cuts| cuts.reserve_status = 0);
        assert_eq!(
            owner.reserve_runtime_allocations_using(layouts(), reserve, check),
            Err(StartupSourceError::NativeStatus {
                status: -libc::ECANCELED
            })
        );
        CUTS.with_borrow(|cuts| assert_eq!(cuts.calls, ["reserve"]));
    });
}

#[test]
fn failed_prebirth_check_retains_genuine_holder_and_forbids_another_debit() {
    fixture(|owner| {
        CUTS.with_borrow_mut(|cuts| cuts.check_status = -libc::ETIME);
        assert_eq!(
            owner.reserve_runtime_allocations_using(layouts(), reserve, check),
            Err(StartupSourceError::NativeStatus {
                status: -libc::ETIME
            })
        );
        assert!(owner.runtime_reservation.attempted);
        assert_ne!(owner.runtime_reservation.purpose_address, 0);

        CUTS.with_borrow_mut(|cuts| cuts.check_status = 0);
        assert_eq!(
            owner.reserve_runtime_allocations_using(layouts(), reserve, check),
            Err(StartupSourceError::NativeStatus {
                status: -libc::ETIME
            })
        );
        CUTS.with_borrow(|cuts| assert_eq!(cuts.calls, ["reserve", "check"]));
    });
}

#[derive(Default)]
struct TerminalCuts {
    calls: Vec<&'static str>,
    observed_identity: Option<(u64, usize)>,
    observation_status: i32,
    journal: InterruptStatus,
}

thread_local! {
    static TERMINAL: RefCell<TerminalCuts> = RefCell::new(TerminalCuts::default());
}

extern "C" fn interrupt(id: u64, purpose: *mut RuntimePurpose, initiating: i32) -> i32 {
    assert_eq!(initiating, -libc::ECANCELED);
    TERMINAL.with_borrow_mut(|cuts| {
        cuts.calls.push("interrupt");
        cuts.observed_identity = Some((id, purpose as usize));
    });
    -libc::ECANCELED
}

extern "C" fn observe_interrupt(
    id: u64,
    purpose: *mut RuntimePurpose,
    output: *mut InterruptStatus,
) -> i32 {
    TERMINAL.with_borrow_mut(|cuts| {
        cuts.calls.push("observe");
        assert_eq!(cuts.observed_identity, Some((id, purpose as usize)));
        if cuts.observation_status == 0 {
            // SAFETY: the adapter lends one initialized fixed output slot.
            unsafe {
                output.write(InterruptStatus {
                    schema_version: cuts.journal.schema_version,
                    struct_size: cuts.journal.struct_size,
                    attempted: cuts.journal.attempted,
                    result: cuts.journal.result,
                    saved_errno: cuts.journal.saved_errno,
                    first_status: cuts.journal.first_status,
                    post_status: cuts.journal.post_status,
                    reserved: cuts.journal.reserved,
                });
            }
        }
        cuts.observation_status
    })
}

fn terminal_fixture(action: impl FnOnce(&mut InstallerStartupSource)) {
    fixture(|owner| {
        TERMINAL.with_borrow_mut(|cuts| {
            *cuts = TerminalCuts {
                journal: InterruptStatus {
                    schema_version: 2,
                    struct_size: size_of::<InterruptStatus>() as u32,
                    attempted: 1,
                    first_status: -libc::ECANCELED,
                    post_status: -libc::ETIME,
                    ..Default::default()
                },
                ..Default::default()
            };
        });
        owner.runtime_reservation.purpose_address = 1;
        owner.runtime_reservation.interrupt = Some(interrupt);
        owner.runtime_reservation.observe_interrupt = Some(observe_interrupt);
        action(owner);
    });
}

#[test]
fn terminal_journal_observation_survives_the_original_refusal() {
    terminal_fixture(|owner| {
        owner
            .first_status
            .store(-libc::ETIME, std::sync::atomic::Ordering::Release);
        assert_eq!(owner.interrupt_runtime_reader(), Ok(true));
        assert_eq!(
            owner.check(),
            Err(StartupSourceError::NativeStatus {
                status: -libc::ETIME
            })
        );
        TERMINAL.with_borrow(|cuts| {
            assert_eq!(cuts.calls, ["interrupt", "observe"]);
            assert_eq!(cuts.observed_identity, Some((7, 1)));
            assert_eq!(cuts.journal.first_status, -libc::ECANCELED);
            assert_eq!(cuts.journal.post_status, -libc::ETIME);
        });
    });
}

#[test]
fn ambiguous_native_shutdown_does_not_allow_a_blocking_reader_join() {
    terminal_fixture(|owner| {
        TERMINAL.with_borrow_mut(|cuts| {
            cuts.journal.result = -1;
            cuts.journal.saved_errno = libc::EINTR;
        });
        assert_eq!(owner.interrupt_runtime_reader(), Ok(false));
        TERMINAL.with_borrow(|cuts| assert_eq!(cuts.calls, ["interrupt", "observe"]));
    });
}

#[test]
fn rejected_or_malformed_observation_cannot_authorize_reader_join() {
    terminal_fixture(|owner| {
        TERMINAL.with_borrow_mut(|cuts| cuts.observation_status = -libc::ESTALE);
        assert_eq!(
            owner.interrupt_runtime_reader(),
            Err(StartupSourceError::NativeStatus {
                status: -libc::ESTALE
            })
        );
        TERMINAL.with_borrow_mut(|cuts| {
            cuts.observation_status = 0;
            cuts.journal.struct_size -= 1;
        });
        assert!(matches!(
            owner.interrupt_runtime_reader(),
            Err(StartupSourceError::Ownership { .. })
        ));
    });
}

#[test]
fn missing_same_runtime_holder_refuses_before_any_native_terminal_call() {
    terminal_fixture(|owner| {
        owner.runtime_reservation.purpose_address = 0;
        assert!(matches!(
            owner.interrupt_runtime_reader(),
            Err(StartupSourceError::Ownership { .. })
        ));
        TERMINAL.with_borrow(|cuts| assert!(cuts.calls.is_empty()));
    });
}

#[test]
fn missing_fixed_control_custody_refuses_before_runtime_reservation() {
    fixture(|owner| {
        assert!(matches!(
            owner.reserve_runtime_allocations(layouts()),
            Err(StartupSourceError::Ownership { .. })
        ));

        assert!(!owner.runtime_reservation.attempted);
        assert_eq!(owner.runtime_reservation.purpose_address, 0);
        CUTS.with_borrow(|cuts| {
            assert!(cuts.calls.is_empty());
            assert!(cuts.requests.is_none());
        });
    });
}
