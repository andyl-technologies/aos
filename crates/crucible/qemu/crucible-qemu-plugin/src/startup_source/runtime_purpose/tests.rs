//! Checks Source-owned runtime reservation ordering with test-only native tables.
//!
//! These tests verify inline attempted/holder/first-error custody. Their modeled
//! functions never issue a production containing purpose or pay actual births.
// SPDX-License-Identifier: GPL-2.0-only

// crucible-lint: allow panic-shortcut -- test fixtures panic to localize reservation custody and installing-admission failures.
#![allow(clippy::unwrap_used)]

use std::cell::RefCell;
use std::os::fd::AsRawFd;
use std::sync::atomic::Ordering;

use super::*;
use crate::startup_source::NativeStartupApi;

#[derive(Default)]
struct NativeCuts {
    source_status: i32,
    source_checks: usize,
    reserve_status: i32,
    publish_on_failure: bool,
    check_status: i32,
    calls: Vec<&'static str>,
    requests: Option<Vec<Request>>,
}

thread_local! {
    static CUTS: RefCell<NativeCuts> = const { RefCell::new(NativeCuts {
        source_status: 0, source_checks: 0, reserve_status: 0, publish_on_failure: false, check_status: 0, calls: Vec::new(), requests: None,
    }) };
}

extern "C" fn acquire(_: u64, _: i32) -> i32 {
    0
}
extern "C" fn source_check(_: u64) -> i32 {
    CUTS.with_borrow_mut(|cuts| {
        cuts.source_checks += 1;
        cuts.source_status
    })
}
extern "C" fn slice(_: u64, _: *mut u64) -> i32 {
    -libc::ENOSYS
}
extern "C" fn complete(_: u64, _: i32) -> i32 {
    -libc::ENOSYS
}

extern "C" fn reserve(
    _: u64,
    requests: *const Request,
    count: usize,
    output: *mut *mut RuntimePurpose,
    claim: *mut *mut CommandClaim,
    child_claim: *mut *mut CallbackChildClaim,
    worker_claim: *mut *mut WorkerClaim,
) -> i32 {
    CUTS.with_borrow_mut(|cuts| {
        cuts.calls.push("reserve");
        // SAFETY: the wrapper lends the complete initialized immutable span.
        cuts.requests = Some(unsafe { std::slice::from_raw_parts(requests, count) }.to_vec());
        if cuts.reserve_status == 0 || cuts.publish_on_failure {
            // SAFETY: this test-only non-null identity is never dereferenced or
            // passed to real native code; the wrapper owns its live output slot.
            unsafe {
                output.write(std::ptr::without_provenance_mut(1));
                claim.write(std::ptr::without_provenance_mut(2));
                child_claim.write(std::ptr::without_provenance_mut(3));
                if cuts
                    .requests
                    .as_ref()
                    .is_some_and(|rows| rows.iter().any(|row| row.role == 3))
                {
                    worker_claim.write(std::ptr::without_provenance_mut(4));
                }
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

fn layouts() -> crate::runtime::prebirth::RuntimeAllocationRequests {
    crate::runtime::prebirth::RuntimeAllocationRequests::configured(1, false).unwrap()
}

#[test]
fn complete_configured_span_is_checked_before_the_caller_can_allocate() {
    fixture(|owner| {
        owner
            .reserve_runtime_allocations_using(layouts().layouts(), reserve, check)
            .unwrap();
        assert!(owner.runtime_reservation.attempted);
        assert_ne!(owner.runtime_reservation.purpose_address, 0);
        assert_ne!(owner.runtime_reservation.command_claim_address, 0);
        assert_ne!(owner.runtime_reservation.callback_child_claim_address, 0);
        CUTS.with_borrow(|cuts| {
            assert_eq!(cuts.calls, ["reserve", "check"]);
            let requests = cuts.requests.as_ref().unwrap();
            let configured = layouts();
            assert_eq!(requests.len(), configured.layouts().len());
            assert_eq!(requests.len(), 11);
            for (request, layout) in requests.iter().zip(configured.layouts()) {
                assert_eq!(request.extent_bytes, layout.size() as u64);
                assert_eq!(request.alignment_bytes, layout.align() as u64);
                assert_eq!(request.birth_count, 1);
            }
        });
    });
}

#[test]
fn failed_reserve_retains_attempt_and_original_first_cause_without_a_holder() {
    fixture(|owner| {
        CUTS.with_borrow_mut(|cuts| cuts.reserve_status = -libc::ECANCELED);
        assert_eq!(
            owner.reserve_runtime_allocations_using(layouts().layouts(), reserve, check),
            Err(StartupSourceError::NativeStatus {
                status: -libc::ECANCELED
            })
        );
        assert!(owner.runtime_reservation.attempted);
        assert_eq!(owner.runtime_reservation.purpose_address, 0);
        assert_eq!(owner.runtime_reservation.command_claim_address, 0);
        assert_eq!(owner.runtime_reservation.callback_child_claim_address, 0);

        CUTS.with_borrow_mut(|cuts| cuts.reserve_status = 0);
        assert_eq!(
            owner.reserve_runtime_allocations_using(layouts().layouts(), reserve, check),
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
            owner.reserve_runtime_allocations_using(layouts().layouts(), reserve, check),
            Err(StartupSourceError::NativeStatus {
                status: -libc::ETIME
            })
        );
        assert!(owner.runtime_reservation.attempted);
        assert_ne!(owner.runtime_reservation.purpose_address, 0);
        assert_ne!(owner.runtime_reservation.command_claim_address, 0);
        assert_ne!(owner.runtime_reservation.callback_child_claim_address, 0);

        CUTS.with_borrow_mut(|cuts| cuts.check_status = 0);
        assert_eq!(
            owner.reserve_runtime_allocations_using(layouts().layouts(), reserve, check),
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
            owner.reserve_runtime_allocations(&layouts()),
            Err(StartupSourceError::Ownership { .. })
        ));

        assert!(!owner.runtime_reservation.attempted);
        assert_eq!(owner.runtime_reservation.purpose_address, 0);
        assert_eq!(owner.runtime_reservation.command_claim_address, 0);
        assert_eq!(owner.runtime_reservation.callback_child_claim_address, 0);
        CUTS.with_borrow(|cuts| {
            assert!(cuts.calls.is_empty());
            assert!(cuts.requests.is_none());
        });
    });
}

#[test]
fn born_negative_reserve_retains_output_before_refusal_and_never_retries() {
    fixture(|owner| {
        CUTS.with_borrow_mut(|cuts| {
            cuts.reserve_status = -libc::ENOMEM;
            cuts.publish_on_failure = true;
        });

        assert_eq!(
            owner.reserve_runtime_allocations_using(layouts().layouts(), reserve, check),
            Err(StartupSourceError::NativeStatus {
                status: -libc::ENOMEM
            }),
        );

        assert!(owner.runtime_reservation.attempted);
        assert_ne!(owner.runtime_reservation.purpose_address, 0);
        assert_ne!(owner.runtime_reservation.command_claim_address, 0);
        assert_ne!(owner.runtime_reservation.callback_child_claim_address, 0);
        assert_eq!(owner.first_status.load(Ordering::Acquire), -libc::ENOMEM);
        CUTS.with_borrow(|cuts| assert_eq!(cuts.calls, ["reserve"]));
        CUTS.with_borrow_mut(|cuts| cuts.reserve_status = 0);
        assert!(
            owner
                .reserve_runtime_allocations_using(layouts().layouts(), reserve, check)
                .is_err()
        );
        CUTS.with_borrow(|cuts| assert_eq!(cuts.calls, ["reserve"]));
    });
}

#[test]
fn absent_and_unrepresentable_spans_refuse_before_native_effects() {
    fixture(|owner| {
        assert!(
            owner
                .reserve_runtime_allocations_using(&[], reserve, check)
                .is_err()
        );
        assert!(
            owner
                .reserve_runtime_allocations_using(&[Layout::new::<()>()], reserve, check)
                .is_err()
        );
        let too_many =
            [Layout::new::<u64>(); crate::runtime::prebirth::MAX_RUNTIME_ALLOCATIONS + 1];
        assert!(
            owner
                .reserve_runtime_allocations_using(&too_many, reserve, check)
                .is_err()
        );
        let huge = Layout::from_size_align(isize::MAX as usize, 1).unwrap();
        assert!(
            owner
                .reserve_runtime_allocations_using(&[huge; 3], reserve, check)
                .is_err()
        );

        assert!(!owner.runtime_reservation.attempted);
        assert_eq!(owner.runtime_reservation.purpose_address, 0);
        assert_eq!(owner.runtime_reservation.command_claim_address, 0);
        assert_eq!(owner.runtime_reservation.callback_child_claim_address, 0);
        CUTS.with_borrow(|cuts| assert!(cuts.calls.is_empty()));
    });
}

#[test]
fn optional_control_is_an_actual_row_not_an_empty_serialized_placeholder() {
    fixture(|owner| {
        let configured =
            crate::runtime::prebirth::RuntimeAllocationRequests::configured(2, true).unwrap();
        owner
            .reserve_runtime_allocations_using(configured.layouts(), reserve, check)
            .unwrap();

        CUTS.with_borrow(|cuts| {
            let requests = cuts.requests.as_ref().unwrap();
            assert_eq!(requests.len(), 12);
            assert_eq!(
                requests.iter().filter(|request| request.role == 1).count(),
                1
            );
            assert_eq!(
                requests[crate::runtime::prebirth::COMMAND_BRIDGE_ALLOCATION].role,
                1
            );
            assert_eq!(
                requests.iter().filter(|request| request.role == 2).count(),
                1
            );
            assert_eq!(
                requests[crate::runtime::prebirth::CALLBACK_CHILD_ALLOCATION].role,
                2
            );
            assert_eq!(
                requests.iter().filter(|request| request.role == 3).count(),
                1
            );
            assert_eq!(
                requests[crate::runtime::prebirth::WORKER_CONTROL_ALLOCATION].role,
                3
            );
            assert_ne!(owner.runtime_reservation.worker_claim_address, 0);
            assert!(requests.iter().all(|request| request.reserved == 0));
            assert!(
                requests
                    .iter()
                    .all(|request| request.extent_bytes > 0 && request.birth_count == 1)
            );
            assert_eq!(
                requests[6].extent_bytes,
                configured.layouts()[6].size() as u64
            );
            assert_eq!(
                requests[11].extent_bytes,
                configured.layouts()[11].size() as u64
            );
        });
    });
}

#[test]
fn storage_custody_does_not_admit_a_birth_after_installing_expiry() {
    fixture(|owner| {
        owner
            .reserve_runtime_allocations_using(layouts().layouts(), reserve, check)
            .unwrap();
        let retained = owner.runtime_reservation.purpose_address;
        CUTS.with_borrow_mut(|cuts| {
            cuts.source_checks = 0;
            cuts.source_status = -libc::ETIME;
        });

        // Pure V3 custody remains valid; it never observes or renews a clock.
        assert_eq!(owner.check_runtime_allocations(), Ok(()));
        CUTS.with_borrow(|cuts| assert_eq!(cuts.source_checks, 0));
        assert_eq!(
            owner.check_runtime_installation(),
            Err(StartupSourceError::NativeStatus {
                status: -libc::ETIME
            }),
        );

        assert_eq!(owner.runtime_reservation.purpose_address, retained);
        CUTS.with_borrow(|cuts| {
            assert_eq!(cuts.source_checks, 1);
            assert_eq!(cuts.calls, ["reserve", "check", "check"]);
        });
    });
}

#[test]
fn missing_fixed_control_never_becomes_a_runtime_birth_allowance() {
    fixture(|owner| {
        owner
            .reserve_runtime_allocations_using(layouts().layouts(), reserve, check)
            .unwrap();
        let retained = owner.runtime_reservation.purpose_address;
        CUTS.with_borrow_mut(|cuts| cuts.source_checks = 0);

        assert!(matches!(
            owner.check_runtime_installation(),
            Err(StartupSourceError::Ownership { .. }),
        ));

        assert_eq!(owner.runtime_reservation.purpose_address, retained);
        CUTS.with_borrow(|cuts| {
            assert_eq!(cuts.source_checks, 1);
            assert_eq!(cuts.calls, ["reserve", "check"]);
        });
    });
}
