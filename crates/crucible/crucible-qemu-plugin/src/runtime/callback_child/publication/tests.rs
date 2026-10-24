//! Checks negative publication-output custody with explicit component tables.
//!
//! These tables establish no Source eligibility or positive typed permission.
//! No test dereferences its modeled span or calls real Native exports.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use std::cell::RefCell;

#[derive(Default)]
struct Cuts {
    begins: usize,
    currents: usize,
    returns: usize,
    begin_status: i32,
    current_status: i32,
    return_status: i32,
    consume: bool,
    erase_on_negative: bool,
}

thread_local! {
    static CUTS: RefCell<Cuts> = RefCell::new(Cuts::default());
}

fn token() -> *mut Loan {
    std::ptr::without_provenance_mut(1)
}

extern "C" fn begin(
    _: u64,
    _: *mut Storage,
    family: libc::c_int,
    out: *mut *mut Loan,
    serial: *mut u64,
) -> i32 {
    assert_eq!(family, VCPU_INIT_FAMILY);
    CUTS.with_borrow_mut(|cuts| {
        cuts.begins += 1;
        // SAFETY: the actual wrapper supplies distinct live component output cells.
        unsafe {
            out.write(token());
            serial.write(9);
        }
        cuts.begin_status
    })
}

extern "C" fn current(
    _: u64,
    _: *mut Loan,
    _: u64,
    address: *mut *mut c_void,
    bytes: *mut usize,
    align: *mut usize,
) -> i32 {
    CUTS.with_borrow_mut(|cuts| {
        cuts.currents += 1;
        // SAFETY: these are live wrapper-owned output cells. The modeled address
        // is never dereferenced: every current result in these controls refuses.
        unsafe {
            address.write(std::ptr::without_provenance_mut(8));
            bytes.write(1);
            align.write(1);
        }
        cuts.current_status
    })
}

extern "C" fn return_loan(_: u64, out: *mut *mut Loan, _: u64) -> i32 {
    CUTS.with_borrow_mut(|cuts| {
        cuts.returns += 1;
        if cuts.consume || cuts.erase_on_negative {
            // SAFETY: this is the real live local projection owned by this model.
            unsafe { out.write(std::ptr::null_mut()) };
        }
        cuts.return_status
    })
}

fn api() -> Api {
    Api {
        begin,
        current,
        return_loan,
    }
}

fn reset() {
    CUTS.with_borrow_mut(|cuts| *cuts = Cuts::default());
}

#[test]
fn born_negative_begin_retains_pair_and_blocks_reentry_until_return() {
    reset();
    CUTS.with_borrow_mut(|cuts| {
        cuts.begin_status = -libc::EKEYEXPIRED;
        cuts.return_status = -libc::EBUSY;
    });
    let mut owner = Publication::new();

    let first = owner.prepare_using(
        7,
        std::ptr::null_mut(),
        |_| panic!("negative begin cannot invoke typed preparation"),
        api(),
    );
    assert_eq!(first, Err(super::super::status_error(-libc::EKEYEXPIRED)));
    assert_eq!(owner.loan, token());
    assert_eq!(owner.serial, 9);
    let retry = owner.prepare_using(7, std::ptr::null_mut(), |_| Ok(()), api());
    assert_eq!(retry, Err(super::super::status_error(-libc::EBUSY)));
    CUTS.with_borrow(|cuts| {
        assert_eq!(cuts.begins, 1);
        assert_eq!(cuts.currents, 0);
    });

    CUTS.with_borrow_mut(|cuts| {
        cuts.return_status = 0;
        cuts.consume = true;
    });
    assert!(owner.identity_return().is_ok());
    assert!(!owner.retained());
}

#[test]
fn negative_current_saves_span_before_status_without_typed_permission() {
    reset();
    CUTS.with_borrow_mut(|cuts| {
        cuts.current_status = -libc::ETIMEDOUT;
        cuts.return_status = -libc::EBUSY;
    });
    let mut owner = Publication::new();

    let first = owner.prepare_using(
        7,
        std::ptr::null_mut(),
        |_| panic!("negative current cannot invoke typed preparation"),
        api(),
    );
    assert_eq!(first, Err(super::super::status_error(-libc::ETIMEDOUT)));
    assert_eq!(owner.span.address, std::ptr::without_provenance_mut(8));
    assert_eq!(owner.span.bytes, 1);
    assert!(owner.retained());
}

#[test]
fn nonconsuming_return_success_preserves_span_and_serial_debt() {
    reset();
    CUTS.with_borrow_mut(|cuts| cuts.current_status = -libc::ERANGE);
    let mut owner = Publication::new();

    assert_eq!(
        owner.prepare_using(7, std::ptr::null_mut(), |_| Ok(()), api()),
        Err(super::super::status_error(-libc::ERANGE))
    );
    assert_eq!(owner.loan, token());
    assert_eq!(owner.serial, 9);
    assert!(!owner.span.address.is_null());
    assert_eq!(
        owner.identity_return(),
        Err(super::super::status_error(-libc::EPROTO))
    );
}

#[test]
fn erased_negative_return_closes_reuse_and_keeps_original_first_cause() {
    reset();
    CUTS.with_borrow_mut(|cuts| {
        cuts.current_status = -libc::EKEYEXPIRED;
        cuts.return_status = -libc::EIO;
        cuts.erase_on_negative = true;
    });
    let mut owner = Publication::new();

    assert_eq!(
        owner.prepare_using(7, std::ptr::null_mut(), |_| Ok(()), api()),
        Err(super::super::status_error(-libc::EKEYEXPIRED))
    );
    assert_eq!(owner.loan, token());
    assert!(owner.uncertain);
    assert!(owner.retained());
    let prior = CUTS.with_borrow(|cuts| cuts.returns);
    assert!(owner.identity_return().is_err());
    assert_eq!(CUTS.with_borrow(|cuts| cuts.returns), prior);
}
