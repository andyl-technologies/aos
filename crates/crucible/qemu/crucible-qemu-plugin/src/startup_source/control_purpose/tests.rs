//! Checks actual configured requests and retained native holder ordering.
//!
//! These modeled entry points only exercise the client state machine. They
//! cannot create the native once-carrier purpose or qualify real allocations.
// SPDX-License-Identifier: GPL-2.0-only

use std::cell::RefCell;
use std::os::unix::net::UnixStream;

use super::*;
use crate::startup_source::test_support::InstallerStartupSourceModel;

#[derive(Default)]
struct Cuts {
    reserve_status: i32,
    check_status: i32,
    null_success: bool,
    calls: Vec<&'static str>,
    requests: Option<[Request; 7]>,
}

thread_local! {
    static CUTS: RefCell<Cuts> = RefCell::new(Cuts::default());
}

extern "C" fn reserve(id: u64, requests: *const Request, output: *mut *mut ControlPurpose) -> i32 {
    assert_eq!(id, 7);
    CUTS.with_borrow_mut(|cuts| {
        cuts.calls.push("reserve");
        // SAFETY: the client lends exactly seven initialized configured rows.
        cuts.requests = Some(std::array::from_fn(|index| unsafe { *requests.add(index) }));
        if cuts.reserve_status == 0 && !cuts.null_success {
            // SAFETY: this model-only identity is never dereferenced; the
            // synchronous client lends an initialized output pointer slot.
            unsafe { output.write(std::ptr::without_provenance_mut(17)) };
        }
        cuts.reserve_status
    })
}

extern "C" fn check(id: u64, purpose: *mut ControlPurpose) -> i32 {
    assert_eq!(id, 7);
    assert_eq!(purpose as usize, 17);
    CUTS.with_borrow_mut(|cuts| {
        cuts.calls.push("check");
        cuts.check_status
    })
}

fn fixture(action: impl FnOnce(&mut InstallerStartupSource)) {
    CUTS.with_borrow_mut(|cuts| *cuts = Cuts::default());
    let (received, _peer) = UnixStream::pair().unwrap();
    let mut owner = InstallerStartupSource::retain_received_plan(7, received.into());
    owner.inject_model(InstallerStartupSourceModel::ready());
    owner.acquire().unwrap();

    action(&mut owner);
    // No native borrower exists in this model; close this actual fixture owner.
    drop(owner.plan.take());
}

fn reserve_model(owner: &mut InstallerStartupSource) -> Result<(), StartupSourceError> {
    owner.begin_control_reservation()?;
    let result = owner.reserve_controls(reserve, check);
    owner.retain_control_result(result)
}

#[test]
fn exact_configured_roster_is_admitted_and_checked_before_birth() {
    fixture(|owner| {
        reserve_model(owner).unwrap();
        assert!(owner.control_reservation.attempted);
        assert_eq!(owner.control_reservation.purpose_address, 17);
        CUTS.with_borrow(|cuts| {
            assert_eq!(cuts.calls, ["reserve", "check"]);
            assert_eq!(cuts.requests.unwrap(), configured_requests().unwrap());
        });

        owner.require_installer_control_purpose().unwrap();
        CUTS.with_borrow(|cuts| assert_eq!(cuts.calls, ["reserve", "check", "check"]));
    });
}

#[test]
fn first_reserve_refusal_keeps_attempt_without_publishing_a_holder() {
    fixture(|owner| {
        CUTS.with_borrow_mut(|cuts| cuts.reserve_status = -libc::ENOSPC);
        let expected = Err(StartupSourceError::NativeStatus {
            status: -libc::ENOSPC,
        });
        assert_eq!(reserve_model(owner), expected);
        assert!(owner.control_reservation.attempted);
        assert_eq!(owner.control_reservation.purpose_address, 0);

        CUTS.with_borrow_mut(|cuts| cuts.reserve_status = 0);
        assert_eq!(reserve_model(owner), expected);
        CUTS.with_borrow(|cuts| assert_eq!(cuts.calls, ["reserve"]));
    });
}

#[test]
fn failed_postcut_keeps_native_identity_and_original_first_refusal() {
    fixture(|owner| {
        CUTS.with_borrow_mut(|cuts| cuts.check_status = -libc::ETIME);
        let expected = Err(StartupSourceError::NativeStatus {
            status: -libc::ETIME,
        });
        assert_eq!(reserve_model(owner), expected);
        assert_eq!(owner.control_reservation.purpose_address, 17);

        CUTS.with_borrow_mut(|cuts| cuts.check_status = 0);
        assert_eq!(reserve_model(owner), expected);
        assert_eq!(owner.check_installer_control_purpose(), expected);
        CUTS.with_borrow(|cuts| assert_eq!(cuts.calls, ["reserve", "check"]));
    });
}

#[test]
fn null_success_cannot_admit_birth_or_retry_the_same_attempt() {
    fixture(|owner| {
        CUTS.with_borrow_mut(|cuts| cuts.null_success = true);
        let expected = Err(StartupSourceError::Ownership {
            reason: "native fixed control reservation returned no retained holder",
        });
        assert_eq!(reserve_model(owner), expected);
        assert_eq!(owner.check_installer_control_purpose(), expected);
        assert_eq!(reserve_model(owner), expected);
        CUTS.with_borrow(|cuts| assert_eq!(cuts.calls, ["reserve"]));
    });
}

#[test]
fn successful_reservation_is_checked_again_without_another_debit() {
    fixture(|owner| {
        reserve_model(owner).unwrap();
        assert_eq!(
            reserve_model(owner),
            Err(StartupSourceError::Ownership {
                reason: "fixed control reservation cannot be repeated",
            })
        );
        owner.check_installer_control_purpose().unwrap();
        CUTS.with_borrow(|cuts| assert_eq!(cuts.calls, ["reserve", "check", "check"]));
    });
}

#[test]
fn later_native_refusal_remains_sticky_before_controller_birth() {
    fixture(|owner| {
        reserve_model(owner).unwrap();
        CUTS.with_borrow_mut(|cuts| cuts.check_status = -libc::ECANCELED);
        let expected = Err(StartupSourceError::NativeStatus {
            status: -libc::ECANCELED,
        });
        assert_eq!(owner.check_installer_control_purpose(), expected);

        CUTS.with_borrow_mut(|cuts| cuts.check_status = 0);
        assert_eq!(owner.check_installer_control_purpose(), expected);
        CUTS.with_borrow(|cuts| assert_eq!(cuts.calls, ["reserve", "check", "check"]));
    });
}
