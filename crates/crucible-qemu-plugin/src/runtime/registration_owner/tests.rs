//! Checks born nominal-owner output custody with explicit component tables.
//!
//! These models issue no genuine Source owner, child span, callback registration,
//! account or Original. Opaque tokens are never dereferenced or sent to Native.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use std::cell::RefCell;

#[derive(Default)]
struct Cuts {
    creates: usize,
    transfers: usize,
    create_status: i32,
    transfer_status: i32,
    current_status: i32,
    return_status: i32,
    consume: bool,
    canonical_field: usize,
}

thread_local! {
    static CUTS: RefCell<Cuts> = RefCell::new(Cuts::default());
}

fn token() -> *mut Owner {
    std::ptr::without_provenance_mut(1)
}

extern "C" fn create(_: u64, _: *mut NativeStorage, output: *mut *mut Owner) -> i32 {
    CUTS.with_borrow_mut(|cuts| {
        cuts.creates += 1;
        // SAFETY: this actual wrapper output cell is live and distinct in the model.
        unsafe { output.write(token()) };
        cuts.create_status
    })
}

extern "C" fn transfer(_: u64, projection: *mut *mut Owner, field: *mut *mut Owner) -> i32 {
    CUTS.with_borrow_mut(|cuts| {
        cuts.transfers += 1;
        // SAFETY: the component table receives distinct live wrapper cells only.
        // It models the pre-post move, without authenticating a real Source bank.
        unsafe {
            field.write(*projection);
            projection.write(std::ptr::null_mut());
        }
        cuts.canonical_field = field as usize;
        cuts.transfer_status
    })
}

extern "C" fn current(_: u64, _: *mut Owner) -> i32 {
    CUTS.with_borrow(|cuts| cuts.current_status)
}

extern "C" fn return_owner(_: u64, field: *mut *mut Owner) -> i32 {
    CUTS.with_borrow(|cuts| {
        if cuts.return_status == 0 && cuts.consume {
            // SAFETY: this is the live local or saved model field supplied by the wrapper.
            unsafe { field.write(std::ptr::null_mut()) };
        }
        cuts.return_status
    })
}

fn api() -> Api {
    Api {
        create,
        transfer,
        current,
        return_owner,
    }
}

fn reset() {
    CUTS.with_borrow_mut(|cuts| *cuts = Cuts::default());
}

#[test]
fn born_negative_owner_keeps_projection_and_blocks_another_creation() {
    reset();
    CUTS.with_borrow_mut(|cuts| cuts.create_status = -libc::ETIMEDOUT);
    let mut owner = RegistrationOwner::new();

    assert_eq!(
        owner.create_using(7, std::ptr::null_mut(), api()),
        Err(status_error(-libc::ETIMEDOUT))
    );
    assert_eq!(owner.creation, token());
    assert_eq!(owner.observed, token());
    assert!(owner.retained());
    assert_eq!(
        owner.create_using(7, std::ptr::null_mut(), api()),
        Err(status_error(-libc::EALREADY))
    );
    CUTS.with_borrow(|cuts| {
        assert_eq!(cuts.creates, 1);
        assert_eq!(cuts.transfers, 0);
    });
}

#[test]
fn negative_transfer_keeps_canonical_destination_until_actual_identity_return() {
    reset();
    CUTS.with_borrow_mut(|cuts| cuts.transfer_status = -libc::EKEYEXPIRED);
    let mut owner = RegistrationOwner::new();

    assert_eq!(
        owner.create_using(7, std::ptr::null_mut(), api()),
        Err(status_error(-libc::EKEYEXPIRED))
    );
    assert!(owner.creation.is_null());
    assert_eq!(owner.observed, token());
    assert!(owner.transfer_attempted);
    CUTS.with_borrow(|cuts| assert_eq!(cuts.canonical_field, owner.holder.get() as usize));

    CUTS.with_borrow_mut(|cuts| cuts.return_status = -libc::EBUSY);
    assert_eq!(owner.identity_return(), Err(status_error(-libc::EBUSY)));
    assert!(owner.retained());
    CUTS.with_borrow_mut(|cuts| {
        cuts.return_status = 0;
        cuts.consume = true;
    });
    assert!(owner.identity_return().is_ok());
    assert!(!owner.retained());
}

#[test]
fn false_nonconsuming_creation_return_cannot_erase_nominal_debt() {
    reset();
    CUTS.with_borrow_mut(|cuts| cuts.create_status = -libc::EKEYEXPIRED);
    let mut owner = RegistrationOwner::new();
    assert!(owner.create_using(7, std::ptr::null_mut(), api()).is_err());

    assert_eq!(owner.identity_return(), Err(status_error(-libc::EPROTO)));
    assert_eq!(owner.creation, token());
    assert!(owner.retained());
}

#[test]
fn nominal_current_refusal_keeps_child_parent_custody_without_typed_permission() {
    reset();
    CUTS.with_borrow_mut(|cuts| cuts.current_status = -libc::ESTALE);
    let mut owner = RegistrationOwner::new();

    assert_eq!(
        owner.create_using(7, std::ptr::null_mut(), api()),
        Err(status_error(-libc::ESTALE))
    );
    assert_eq!(owner.observed, token());
    assert!(owner.creation.is_null());
    assert!(owner.retained());
}
