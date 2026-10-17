//! Exercises negative output custody with scripted component ABI tables.
//!
//! These tables never create a Native Source, valid typed child or authority.
//! They drive born/transfer/current/return errors before any typed registrar.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use std::cell::RefCell;

#[derive(Clone, Copy)]
enum Failure {
    Birth,
    Transfer,
    Current,
    SpanDisposition,
}

struct Script {
    failure: Failure,
    field: *mut *mut Owner,
    receipt_calls: u32,
    current_calls: u32,
    observed_calls: u32,
}

thread_local! {
    static SCRIPT: RefCell<Script> = const { RefCell::new(Script {
        failure: Failure::Birth,
        field: std::ptr::null_mut(),
        receipt_calls: 0,
        current_calls: 0,
        observed_calls: 0,
    }) };
}

fn configure(failure: Failure) {
    SCRIPT.with(|script| {
        *script.borrow_mut() = Script {
            failure,
            field: std::ptr::null_mut(),
            receipt_calls: 0,
            current_calls: 0,
            observed_calls: 0,
        };
    });
}

fn opaque() -> *mut Owner {
    std::ptr::NonNull::<Owner>::dangling().as_ptr()
}

extern "C" fn begin(
    _: u64,
    _: *mut NativeStorage,
    _: Kind,
    output: *mut *mut Owner,
    serial: *mut u64,
) -> i32 {
    // SAFETY: the component caller supplies distinct writable local fields.
    unsafe {
        *output = opaque();
        *serial = 7;
    }
    SCRIPT.with(|script| {
        if matches!(script.borrow().failure, Failure::Birth) {
            -libc::ETIMEDOUT
        } else {
            0
        }
    })
}

extern "C" fn transfer(
    _: u64,
    projection: *mut *mut Owner,
    _: u64,
    _: Kind,
    field: *mut *mut Owner,
) -> i32 {
    // SAFETY: this fixture consumes the actual local projection into the
    // distinct component field. It grants no real canonical Source ownership.
    unsafe {
        *field = *projection;
        *projection = std::ptr::null_mut();
    }
    SCRIPT.with(|script| {
        let mut script = script.borrow_mut();
        script.field = field;
        if matches!(script.failure, Failure::Transfer) {
            -libc::ETIMEDOUT
        } else {
            0
        }
    })
}

extern "C" fn holder_observe(
    _: u64,
    field: *mut *mut Owner,
    _: Kind,
    projection: *mut *mut Owner,
    serial: *mut u64,
) -> i32 {
    SCRIPT.with(|script| assert_eq!(script.borrow().field, field));
    // SAFETY: writable fresh fixture outputs; the opaque pointee is never read.
    unsafe {
        *projection = opaque();
        *serial = 7;
    }
    0
}

extern "C" fn current(
    _: u64,
    _: *mut Owner,
    _: u64,
    _: Kind,
    address: *mut *mut c_void,
    bytes: *mut usize,
    alignment: *mut usize,
) -> i32 {
    SCRIPT.with(|script| script.borrow_mut().current_calls += 1);
    // SAFETY: local outputs receive arbitrary factual geometry before refusal;
    // the always-negative status must prevent formation of a typed reference.
    unsafe {
        *address = opaque().cast();
        *bytes = 19;
        *alignment = 1;
    }
    -libc::ETIMEDOUT
}

extern "C" fn postreceipt(_: u64, _: *mut Owner, _: u64, _: Kind) -> i32 {
    SCRIPT.with(|script| script.borrow_mut().receipt_calls += 1);
    -libc::EBUSY
}

extern "C" fn status_observe(_: u64, _: *mut Owner, _: u64, _: Kind, output: *mut Status) -> i32 {
    SCRIPT.with(|script| script.borrow_mut().observed_calls += 1);
    // SAFETY: the fixture caller supplies this full writable factual record.
    unsafe {
        *output = Status {
            publication_serial: 7,
            first_status: -libc::ETIMEDOUT,
            ..Status::default()
        };
    }
    0
}

extern "C" fn span_return(_: u64, projection: *mut *mut Owner, _: u64, _: Kind) -> i32 {
    SCRIPT.with(|script| match script.borrow().failure {
        Failure::Current => -libc::EBUSY,
        Failure::SpanDisposition => 0, // Deliberately nonconsuming false success.
        _ => {
            // SAFETY: actual component byref output, with no Source pointee use.
            unsafe { *projection = std::ptr::null_mut() };
            0
        }
    })
}

extern "C" fn owner_return(_: u64, _: *mut *mut Owner, _: u64, _: Kind) -> i32 {
    -libc::EBUSY
}

fn api() -> Api {
    Api {
        begin,
        transfer,
        current,
        span_return,
        owner_return,
        holder_observe,
        postreceipt,
        status_observe,
    }
}

fn refuse_typed_child(_: &mut LiveVcpuTimeCallbackState) -> Result<(), LiveVcpuTimeCallbackError> {
    panic!("negative scripted current must never form a typed child");
}

fn preserves_primary_timeout(result: Result<(), LiveVcpuTimeCallbackError>) -> bool {
    matches!(
        result,
        Err(LiveVcpuTimeCallbackError::CallbackRegistrationGroup {
            source: StartupSourceError::NativeStatus { status }
        }) if status == -libc::ETIMEDOUT
    )
}

#[test]
fn born_negative_pair_blocks_reissue_and_retains_creation() {
    configure(Failure::Birth);
    let mut group = Group::new();

    assert!(preserves_primary_timeout(group.install_using(
        1,
        std::ptr::null_mut(),
        Kind::Block,
        refuse_typed_child,
        api()
    )));

    assert_eq!(group.creation, opaque());
    assert_eq!(group.serial, 7);
    assert!(!group.transfer_attempted);
    assert!(
        group
            .install_using(
                1,
                std::ptr::null_mut(),
                Kind::Block,
                refuse_typed_child,
                api()
            )
            .is_err()
    );
    assert!(group.identity_return().is_err());
    SCRIPT.with(|script| assert_eq!(script.borrow().current_calls, 0));
}

#[test]
fn transfer_post_refusal_retains_canonical_owner_and_source_journal() {
    configure(Failure::Transfer);
    let mut group = Group::new();

    assert!(preserves_primary_timeout(group.install_using(
        1,
        std::ptr::null_mut(),
        Kind::Block,
        refuse_typed_child,
        api()
    )));

    assert!(group.creation.is_null());
    assert!(group.span_closed);
    assert!(!group.returned);
    assert!(group.identity_return().is_err());
    assert_eq!(
        group.journal.map(|journal| journal.first_status),
        Some(-libc::ETIMEDOUT)
    );
    SCRIPT.with(|script| {
        let script = script.borrow();
        assert_eq!(script.current_calls, 0);
        assert_eq!(script.receipt_calls, 1);
        assert_eq!(script.observed_calls, 1);
    });
}

#[test]
fn current_post_refusal_keeps_geometry_without_typed_access_or_replay() {
    configure(Failure::Current);
    let mut group = Group::new();

    assert!(preserves_primary_timeout(group.install_using(
        1,
        std::ptr::null_mut(),
        Kind::Block,
        refuse_typed_child,
        api()
    )));

    assert_eq!(group.span.address, opaque().cast());
    assert_eq!(group.span.bytes, 19);
    assert_eq!(group.projection, opaque());
    assert!(!group.span_closed);
    assert!(group.identity_return().is_err());
    assert!(
        group
            .install_using(
                1,
                std::ptr::null_mut(),
                Kind::Block,
                refuse_typed_child,
                api()
            )
            .is_err()
    );
    SCRIPT.with(|script| assert_eq!(script.borrow().current_calls, 1));
}

#[test]
fn nonconsuming_span_success_keeps_uncertain_group_debt() {
    configure(Failure::SpanDisposition);
    let mut group = Group::new();

    assert!(preserves_primary_timeout(group.install_using(
        1,
        std::ptr::null_mut(),
        Kind::Block,
        refuse_typed_child,
        api()
    )));

    assert!(group.uncertain);
    assert!(!group.span_closed);
    assert_eq!(group.projection, opaque());
    assert!(group.identity_return().is_err());
}
