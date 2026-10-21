//! Checks wrapper custody against a local field-consumption model.
//!
//! Model tokens never enter QEMU and grant no Native, publisher or action
//! authority. These tests exercise the Rust keeper's exact field addresses.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use std::cell::RefCell;

#[derive(Default)]
struct Model {
    creates: usize,
    transfers: usize,
    returns: usize,
    current_checks: usize,
    create_status: i32,
    transfer_status: i32,
    return_status: i32,
    current_status: i32,
    omit_output: bool,
    transfer_consumes: bool,
    creation_field: usize,
    canonical_field: usize,
    returned_field: usize,
}

thread_local! {
    static MODEL: RefCell<Model> = RefCell::new(Model {
        transfer_consumes: true,
        ..Model::default()
    });
}

extern "C" fn create(
    _: u64,
    _: *mut Receive,
    _: u64,
    field: *mut *mut Owner,
    serial: *mut u64,
) -> i32 {
    MODEL.with_borrow_mut(|model| {
        model.creates += 1;
        model.creation_field = field as usize;
        if !model.omit_output {
            // SAFETY: the wrapper supplies distinct live local output cells.
            // This token is never dereferenced or submitted to Native.
            unsafe {
                field.write(std::ptr::without_provenance_mut(3));
                serial.write(41);
            }
        }
        model.create_status
    })
}

extern "C" fn transfer(_: u64, from: *mut *mut Owner, _: u64, to: *mut *mut Owner) -> i32 {
    MODEL.with_borrow_mut(|model| {
        model.transfers += 1;
        model.canonical_field = to as usize;
        if model.transfer_consumes {
            // SAFETY: these are distinct live fields of the pinned test keeper.
            unsafe {
                to.write(from.read());
                from.write(std::ptr::null_mut());
            }
        }
        model.transfer_status
    })
}

extern "C" fn current(_: u64, _: *mut Owner, _: u64) -> i32 {
    MODEL.with_borrow_mut(|model| {
        model.current_checks += 1;
        model.current_status
    })
}

extern "C" fn identity_return(_: u64, field: *mut *mut Owner, _: u64) -> i32 {
    MODEL.with_borrow_mut(|model| {
        model.returns += 1;
        model.returned_field = field as usize;
        if model.return_status == 0 {
            // SAFETY: the wrapper supplies its still-live exact holder field.
            unsafe { field.write(std::ptr::null_mut()) };
        }
        model.return_status
    })
}

fn api() -> Api {
    Api {
        create,
        transfer,
        current,
        identity_return,
    }
}

pub(super) fn fresh_api() -> Api {
    reset(|_| {});
    api()
}

pub(super) fn calls() -> (usize, usize, usize) {
    MODEL.with_borrow(|model| (model.creates, model.transfers, model.returns))
}

fn reset(edit: impl FnOnce(&mut Model)) {
    MODEL.with_borrow_mut(|model| {
        *model = Model {
            transfer_consumes: true,
            ..Model::default()
        };
        edit(model);
    });
}

fn retain(delivery: &mut Delivery) -> Result<(), StartupSourceError> {
    delivery.retain(api(), 7, std::ptr::without_provenance_mut(2), 19)
}

fn status(result: Result<(), StartupSourceError>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(StartupSourceError::NativeStatus { status }) => status,
        Err(error) => panic!("unexpected wrapper error: {error:?}"),
    }
}

#[test]
fn negative_birth_transfers_custody_before_reporting_first_failure() {
    reset(|model| model.create_status = -libc::EAGAIN);
    let mut delivery = Box::pin(Delivery::new());

    assert_eq!(status(retain(&mut delivery)), -libc::EAGAIN);
    assert!(delivery.creation.is_null());
    assert!(!delivery.projection.is_null());
    assert_eq!(status(retain(&mut delivery)), -libc::EAGAIN);

    MODEL.with_borrow(|model| {
        assert_eq!(model.creates, 1);
        assert_eq!(model.transfers, 1);
        assert_eq!(model.current_checks, 0);
    });
    delivery.identity_return(api(), 7).unwrap();
    MODEL.with_borrow(|model| assert_eq!(model.returned_field, model.canonical_field));
    assert!(delivery.projection.is_null());
}

#[test]
fn transfer_refusal_retains_the_exact_creation_output_field() {
    reset(|model| {
        model.transfer_status = -libc::EBUSY;
        model.transfer_consumes = false;
    });
    let mut delivery = Box::pin(Delivery::new());

    assert_eq!(status(retain(&mut delivery)), -libc::EBUSY);
    assert!(!delivery.creation.is_null());
    delivery.identity_return(api(), 7).unwrap();

    MODEL.with_borrow(|model| assert_eq!(model.returned_field, model.creation_field));
    assert!(delivery.creation.is_null());
    assert!(delivery.returned);
}

#[test]
fn negative_transfer_after_consumption_keeps_the_canonical_field() {
    reset(|model| model.transfer_status = -libc::ECANCELED);
    let mut delivery = Box::pin(Delivery::new());

    assert_eq!(status(retain(&mut delivery)), -libc::ECANCELED);
    delivery.identity_return(api(), 7).unwrap();

    MODEL.with_borrow(|model| assert_eq!(model.returned_field, model.canonical_field));
}

#[test]
fn refused_return_preserves_projection_serial_and_canonical_custody() {
    reset(|_| {});
    let mut delivery = Box::pin(Delivery::new());
    retain(&mut delivery).unwrap();
    let projection = delivery.projection;
    let serial = delivery.serial;
    MODEL.with_borrow_mut(|model| model.return_status = -libc::EBUSY);

    assert_eq!(status(delivery.identity_return(api(), 7)), -libc::EBUSY);
    assert_eq!(delivery.projection, projection);
    assert_eq!(delivery.serial, serial);
    assert!(!delivery.returned);
    retain(&mut delivery).unwrap();

    MODEL.with_borrow(|model| {
        assert_eq!(model.creates, 1);
        assert_eq!(model.returned_field, model.canonical_field);
        assert_eq!(model.current_checks, 2);
    });
}

#[test]
fn consumed_delivery_cannot_reissue_from_the_same_retained_receive() {
    reset(|_| {});
    let mut delivery = Box::pin(Delivery::new());
    retain(&mut delivery).unwrap();
    delivery.identity_return(api(), 7).unwrap();

    assert_eq!(status(retain(&mut delivery)), -libc::ESTALE);
    delivery.identity_return(api(), 7).unwrap();

    MODEL.with_borrow(|model| {
        assert_eq!(model.creates, 1);
        assert_eq!(model.returns, 1);
    });
}

#[test]
fn absent_born_output_refuses_rebirth_and_return() {
    reset(|model| model.omit_output = true);
    let mut delivery = Box::pin(Delivery::new());

    assert_eq!(status(retain(&mut delivery)), -libc::EPROTO);
    assert_eq!(status(retain(&mut delivery)), -libc::EPROTO);
    assert_eq!(status(delivery.identity_return(api(), 7)), -libc::EPROTO);

    MODEL.with_borrow(|model| {
        assert_eq!(model.creates, 1);
        assert_eq!(model.transfers, 0);
        assert_eq!(model.returns, 0);
    });
}

#[test]
fn current_refusal_never_releases_or_recreates_delivery() {
    reset(|model| model.current_status = -libc::ESTALE);
    let mut delivery = Box::pin(Delivery::new());

    assert_eq!(status(retain(&mut delivery)), -libc::ESTALE);
    assert_eq!(status(retain(&mut delivery)), -libc::ESTALE);
    assert!(!delivery.projection.is_null());

    MODEL.with_borrow(|model| {
        assert_eq!(model.creates, 1);
        assert_eq!(model.transfers, 1);
        assert_eq!(model.returns, 0);
    });
}
