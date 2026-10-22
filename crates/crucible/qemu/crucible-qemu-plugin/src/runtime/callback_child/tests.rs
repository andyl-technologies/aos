//! Exercises child output custody with explicit component-only Native tables.
//!
//! These tables supply no genuine Source/claim/publication and never call real
//! Native exports. Typed placement/rollback controls live with the real common
//! initializer and use separately owned model backing; all remain unrun here.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use std::cell::RefCell;

#[derive(Default)]
struct Cuts {
    creates: usize,
    initializes: usize,
    transfers: usize,
    create_status: i32,
    initialize_post: i32,
    transfer_status: i32,
    return_status: i32,
    consume_return: bool,
    holder: usize,
}

thread_local! {
    static CUTS: RefCell<Cuts> = RefCell::new(Cuts::default());
}

fn token() -> *mut Storage {
    std::ptr::without_provenance_mut(1)
}

extern "C" fn create(
    _: u64,
    _: *mut RuntimePurpose,
    _: *mut CallbackChildClaim,
    _: *mut BridgeStorage,
    out: *mut *mut Storage,
) -> i32 {
    CUTS.with_borrow_mut(|cuts| {
        cuts.creates += 1;
        // SAFETY: the wrapper supplies its live test-only output cell. This
        // opaque model is never dereferenced or sent to genuine Native code.
        unsafe { out.write(token()) };
        cuts.create_status
    })
}

extern "C" fn initialize(
    id: u64,
    child: *mut Storage,
    initializer: abi::Initializer,
    _: abi::Destructor,
    input: *mut std::ffi::c_void,
) -> i32 {
    CUTS.with_borrow_mut(|cuts| cuts.initializes += 1);
    let mut backing = Box::<super::super::live_callbacks::LiveVcpuTimeCallbackState>::new_uninit();
    let layout =
        std::alloc::Layout::new::<super::super::live_callbacks::LiveVcpuTimeCallbackState>();
    let first = initializer(
        id,
        child,
        backing.as_mut_ptr().cast(),
        layout.size(),
        layout.align(),
        std::ptr::null_mut(),
        input,
    );
    let post = CUTS.with_borrow(|cuts| cuts.initialize_post);
    if post != 0 { post } else { first }
}

extern "C" fn mark(_: u64, _: *mut Storage) -> i32 {
    0
}

extern "C" fn transfer(
    _: u64,
    _: *mut RuntimePurpose,
    from: *mut *mut Storage,
    to: *mut *mut Storage,
) -> i32 {
    CUTS.with_borrow_mut(|cuts| {
        cuts.transfers += 1;
        // SAFETY: these are the actual distinct wrapper test cells. Copying
        // this modeled move confers no Source canonical field or account.
        unsafe {
            to.write(*from);
            from.write(std::ptr::null_mut());
        }
        cuts.holder = to as usize;
        cuts.transfer_status
    })
}

extern "C" fn observe(_: u64, _: *mut Storage, out: *mut Status) -> i32 {
    let transferred = CUTS.with_borrow(|cuts| u32::from(cuts.holder != 0));
    // SAFETY: this output is a distinct live local journal in the wrapper.
    unsafe {
        out.write(Status {
            schema_version: 1,
            struct_size: size_of::<Status>() as u32,
            transferred,
            ..Status::default()
        })
    };
    0
}

extern "C" fn holder_observe(_: u64, field: *mut *mut Storage, out: *mut *mut Storage) -> i32 {
    let expected = CUTS.with_borrow(|cuts| cuts.holder);
    if expected != field as usize {
        return -libc::EPERM;
    }
    // SAFETY: the table saved this wrapper-owned cell during its model move;
    // output is a separate live local field, never a native custody alias.
    unsafe { out.write(*field) };
    0
}

extern "C" fn return_storage(_: u64, field: *mut *mut Storage) -> i32 {
    CUTS.with_borrow(|cuts| {
        if cuts.return_status == 0 && cuts.consume_return {
            // SAFETY: this is the exact retained live wrapper test cell.
            unsafe { field.write(std::ptr::null_mut()) };
        }
        cuts.return_status
    })
}

fn api() -> Api {
    Api {
        create,
        initialize,
        placement_begin: mark,
        initialized: mark,
        prefix_rollback: mark,
        transfer,
        current: mark,
        destroyed: mark,
        return_storage,
        observe,
        holder_observe,
    }
}

fn reset() {
    CUTS.with_borrow_mut(|cuts| *cuts = Cuts::default());
}

#[test]
fn born_negative_child_allocation_retains_projection_and_closes_retry() {
    reset();
    CUTS.with_borrow_mut(|cuts| cuts.create_status = -libc::ENOMEM);
    let mut owner = CallbackChild::new();
    let first = owner.create_using(
        (7, std::ptr::null_mut(), std::ptr::null_mut()),
        std::ptr::null_mut(),
        |_, _| Ok(()),
        api(),
    );
    assert_eq!(first, Err(status_error(-libc::ENOMEM)));
    assert_eq!(owner.projection, token());
    assert!(owner.retains_storage());

    let retry = owner.create_using(
        (7, std::ptr::null_mut(), std::ptr::null_mut()),
        std::ptr::null_mut(),
        |_, _| Ok(()),
        api(),
    );
    assert_eq!(retry, Err(status_error(-libc::EALREADY)));
    CUTS.with_borrow(|cuts| {
        assert_eq!(cuts.creates, 1);
        assert_eq!(cuts.initializes, 0);
    });
}

#[test]
fn typed_no_payload_failure_stays_primary_over_independent_initialize_post() {
    reset();
    CUTS.with_borrow_mut(|cuts| cuts.initialize_post = -libc::ETIMEDOUT);
    let mut owner = CallbackChild::new();
    let result = owner.create_using(
        (7, std::ptr::null_mut(), std::ptr::null_mut()),
        std::ptr::null_mut(),
        |_, _| Err(status_error(-libc::ERANGE)),
        api(),
    );
    assert_eq!(result, Err(status_error(-libc::ERANGE)));
    assert_eq!(owner.projection, token());
    CUTS.with_borrow(|cuts| assert_eq!(cuts.transfers, 0));
}

#[test]
fn negative_after_modeled_field_transfer_preserves_destination_until_real_return() {
    reset();
    CUTS.with_borrow_mut(|cuts| cuts.transfer_status = -libc::EKEYEXPIRED);
    let mut owner = CallbackChild::new();
    // The table models output movement only; no typed body is initialized and
    // this control claims no valid Source child or positive publication.
    let result = owner.create_using(
        (7, std::ptr::null_mut(), std::ptr::null_mut()),
        std::ptr::null_mut(),
        |_, _| Ok(()),
        api(),
    );
    assert_eq!(result, Err(status_error(-libc::EKEYEXPIRED)));
    assert!(owner.transfer_attempted);
    assert!(owner.projection.is_null());

    CUTS.with_borrow_mut(|cuts| cuts.return_status = -libc::EBUSY);
    assert!(!owner.identity_return());
    CUTS.with_borrow_mut(|cuts| {
        cuts.return_status = 0;
        cuts.consume_return = true;
    });
    assert!(owner.identity_return());
}

#[test]
fn nonconsuming_success_cannot_erase_retained_child_debt() {
    reset();
    let mut owner = CallbackChild::new();
    owner.id = 7;
    owner.attempted = true;
    owner.api = Some(api());
    owner.projection = token();

    assert!(!owner.identity_return());
    assert_eq!(owner.projection, token());
    CUTS.with_borrow_mut(|cuts| cuts.consume_return = true);
    assert!(owner.identity_return());
    assert!(owner.projection.is_null());
}
