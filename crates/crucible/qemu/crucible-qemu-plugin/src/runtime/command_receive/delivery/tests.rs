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
    omit_return_consumption: bool,
    current_status: i32,
    omit_output: bool,
    transfer_consumes: bool,
    creation_field: usize,
    canonical_field: usize,
    returned_field: usize,
    ready_returns: usize,
    ready_status: i32,
    ready_output: u32,
    payload_claims: usize,
    payload_returns: usize,
    payload_claim_status: i32,
    payload_return_status: i32,
}

thread_local! {
    static MODEL: RefCell<Model> = RefCell::new(Model {
        transfer_consumes: true,
        ready_output: 1,
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
        if model.return_status == 0 && !model.omit_return_consumption {
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
        payload_claim,
        payload_return,
        ready_return,
    }
}

extern "C" fn ready_return(_: u64, _: *mut Owner, _: u64, output: *mut u32) -> i32 {
    MODEL.with_borrow_mut(|model| {
        model.ready_returns += 1;
        // SAFETY: the wrapper supplies one live aligned local u32 output cell.
        unsafe { output.write(model.ready_output) };
        model.ready_status
    })
}

extern "C" fn payload_claim(_: u64, _: *mut Owner, _: u64) -> i32 {
    MODEL.with_borrow_mut(|model| {
        model.payload_claims += 1;
        model.payload_claim_status
    })
}

extern "C" fn payload_return(_: u64, _: *mut Owner, _: u64) -> i32 {
    MODEL.with_borrow_mut(|model| {
        model.payload_returns += 1;
        model.payload_return_status
    })
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
            ready_output: 1,
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
        assert_eq!(model.payload_claims, 1);
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

#[test]
fn negative_payload_claim_keeps_born_delivery_for_actual_return() {
    reset(|model| model.payload_claim_status = -libc::EIO);
    let mut delivery = Box::pin(Delivery::new());

    assert_eq!(status(retain(&mut delivery)), -libc::EIO);
    assert!(!delivery.projection.is_null());
    assert!(delivery.creation.is_null());
    assert!(delivery.payload_attempted);
    MODEL.with_borrow(|model| assert_eq!(model.payload_claims, 1));

    assert_eq!(status(delivery.identity_return(api(), 7)), 0);
    assert!(delivery.returned);
    MODEL.with_borrow(|model| {
        assert_eq!(model.payload_returns, 1);
        assert_eq!(model.returns, 1);
    });
    assert_eq!(status(retain(&mut delivery)), -libc::EIO);
    MODEL.with_borrow(|model| assert_eq!(model.creates, 1));
}

#[test]
fn payload_post_refusal_saves_real_lifetime_consumption_before_reporting_failure() {
    reset(|model| model.payload_return_status = -libc::ECANCELED);
    let mut delivery = Box::pin(Delivery::new());
    assert_eq!(status(retain(&mut delivery)), 0);

    assert_eq!(status(delivery.identity_return(api(), 7)), -libc::ECANCELED);

    assert!(delivery.returned);
    assert!(delivery.projection.is_null());
    assert_eq!(delivery.serial, 0);
    assert_eq!(delivery.payload_return_status, -libc::ECANCELED);
    assert_eq!(status(delivery.identity_return(api(), 7)), 0);
    assert_eq!(status(retain(&mut delivery)), -libc::ESTALE);
    MODEL.with_borrow(|model| {
        assert_eq!(model.payload_returns, 1);
        assert_eq!(model.returns, 1);
        assert_eq!(model.creates, 1);
    });
}

#[test]
fn retained_payload_refusal_preserves_custody_and_initiating_error() {
    reset(|model| {
        model.payload_return_status = -libc::EIO;
        model.return_status = -libc::EBUSY;
    });
    let mut delivery = Box::pin(Delivery::new());
    assert_eq!(status(retain(&mut delivery)), 0);
    let projection = delivery.projection;
    let serial = delivery.serial;

    assert_eq!(status(delivery.identity_return(api(), 7)), -libc::EIO);

    assert!(!delivery.returned);
    assert_eq!(delivery.projection, projection);
    assert_eq!(delivery.serial, serial);
    // SAFETY: the local model retains this actual pinned field; no Native
    // implementation or foreign canonical field is accessed by the test.
    assert_eq!(unsafe { delivery.holder.get().read() }, projection);
    MODEL.with_borrow(|model| {
        assert_eq!(model.payload_returns, 1);
        assert_eq!(model.returns, 1);
    });
}

#[test]
fn ready_post_refusal_saves_consumption_and_still_attempts_both_actual_returns() {
    reset(|model| model.ready_status = -libc::ECANCELED);
    let mut delivery = Box::pin(Delivery::new());
    retain(&mut delivery).unwrap();

    assert_eq!(status(delivery.identity_return(api(), 7)), -libc::ECANCELED);
    assert!(delivery.ready_returned);
    assert!(delivery.returned);
    assert!(delivery.projection.is_null());
    MODEL.with_borrow(|model| {
        assert_eq!(model.ready_returns, 1);
        assert_eq!(model.payload_returns, 1);
        assert_eq!(model.returns, 1);
    });
}

#[test]
fn refused_ready_return_preserves_first_error_through_real_lifetime_retry() {
    reset(|model| {
        model.ready_status = -libc::EBUSY;
        model.ready_output = 0;
        model.payload_return_status = -libc::ECANCELED;
        model.return_status = -libc::EBUSY;
    });
    let mut delivery = Box::pin(Delivery::new());
    retain(&mut delivery).unwrap();
    let projection = delivery.projection;

    assert_eq!(status(delivery.identity_return(api(), 7)), -libc::EBUSY);
    assert!(!delivery.ready_returned);
    assert!(!delivery.returned);
    assert_eq!(delivery.projection, projection);
    MODEL.with_borrow_mut(|model| {
        model.ready_status = 0;
        model.ready_output = 1;
        model.payload_return_status = 0;
        model.return_status = 0;
    });

    assert_eq!(status(delivery.identity_return(api(), 7)), -libc::EBUSY);
    assert!(delivery.ready_returned);
    assert!(delivery.returned);
    MODEL.with_borrow(|model| {
        assert_eq!(model.ready_returns, 2);
        assert_eq!(model.payload_returns, 2);
        assert_eq!(model.returns, 2);
    });
}

#[test]
fn copied_ready_output_never_substitutes_for_native_lifetime_consumption() {
    reset(|model| model.return_status = -libc::EBUSY);
    let mut delivery = Box::pin(Delivery::new());
    retain(&mut delivery).unwrap();

    assert_eq!(status(delivery.identity_return(api(), 7)), -libc::EBUSY);
    assert!(delivery.ready_returned);
    assert!(!delivery.returned);
    assert!(!delivery.projection.is_null());
}

#[test]
fn malformed_ready_success_reports_protocol_error_after_independent_returns() {
    reset(|model| model.ready_output = 0);
    let mut delivery = Box::pin(Delivery::new());
    retain(&mut delivery).unwrap();

    assert_eq!(status(delivery.identity_return(api(), 7)), -libc::EPROTO);
    assert!(!delivery.ready_returned);
    assert!(delivery.returned);
    MODEL.with_borrow(|model| {
        assert_eq!(model.payload_returns, 1);
        assert_eq!(model.returns, 1);
    });
}

#[test]
fn zero_return_without_canonical_field_consumption_retains_actual_custody() {
    reset(|model| model.omit_return_consumption = true);
    let mut delivery = Box::pin(Delivery::new());
    retain(&mut delivery).unwrap();
    let projection = delivery.projection;
    let serial = delivery.serial;

    assert_eq!(status(delivery.identity_return(api(), 7)), -libc::EPROTO);

    assert!(!delivery.returned);
    assert_eq!(delivery.projection, projection);
    assert_eq!(delivery.serial, serial);
    // SAFETY: the local model owns this pinned keeper's canonical cell.
    assert_eq!(unsafe { delivery.holder.get().read() }, projection);
    MODEL.with_borrow(|model| {
        assert_eq!(model.returned_field, model.canonical_field);
        assert_eq!(model.returns, 1);
        assert_eq!(model.creates, 1);
    });
}

#[test]
fn zero_return_without_creation_field_consumption_retains_failed_transfer() {
    reset(|model| {
        model.transfer_status = -libc::EBUSY;
        model.transfer_consumes = false;
        model.omit_return_consumption = true;
    });
    let mut delivery = Box::pin(Delivery::new());
    assert_eq!(status(retain(&mut delivery)), -libc::EBUSY);
    let projection = delivery.projection;
    let serial = delivery.serial;

    assert_eq!(status(delivery.identity_return(api(), 7)), -libc::EPROTO);

    assert!(!delivery.returned);
    assert_eq!(delivery.creation, projection);
    assert_eq!(delivery.projection, projection);
    assert_eq!(delivery.serial, serial);
    MODEL.with_borrow(|model| {
        assert_eq!(model.returned_field, model.creation_field);
        assert_eq!(model.returns, 1);
        assert_eq!(model.creates, 1);
    });
}
