//! Exercises negative physical outputs and identity disposition with a Native fixture.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use std::cell::RefCell;

#[derive(Default)]
struct NativeFixture {
    creation_status: i32,
    empty_outputs: bool,
    owner_only: bool,
    address_only: bool,
    extent_only: bool,
    transfer_status: i32,
    transfer_moves: bool,
    return_status: i32,
    calls: Vec<&'static str>,
}

thread_local! {
    static NATIVE: RefCell<NativeFixture> = RefCell::new(NativeFixture::default());
}

fn mapping() -> *mut Mapping {
    std::ptr::NonNull::<Mapping>::dangling().as_ptr()
}

extern "C" fn create(
    _id: u64,
    owner: *mut *mut Mapping,
    address: *mut *mut c_void,
    extent: *mut usize,
) -> i32 {
    NATIVE.with(|fixture| {
        let mut fixture = fixture.borrow_mut();
        fixture.calls.push("create");
        // SAFETY: these separate outputs are valid for this synchronous Native
        // fixture. The opaque address is never dereferenced or lent as bytes.
        unsafe {
            if !fixture.empty_outputs || fixture.owner_only {
                *owner = mapping();
            }
            if !fixture.empty_outputs || fixture.address_only {
                *address = std::ptr::NonNull::<u8>::dangling().as_ptr().cast();
            }
            if !fixture.empty_outputs || fixture.extent_only {
                *extent = crucible_qemu_protocol::DEVICE_DIGEST_WORKSPACE_BYTES as usize;
            }
        }
        fixture.creation_status
    })
}

extern "C" fn transfer(
    _id: u64,
    _runtime: *mut RuntimePurpose,
    projection: *mut *mut Mapping,
    canonical: *mut *mut Mapping,
) -> i32 {
    NATIVE.with(|fixture| {
        let mut fixture = fixture.borrow_mut();
        fixture.calls.push("transfer");
        if fixture.transfer_moves {
            // SAFETY: only this modeled Native receiver accesses its canonical
            // field; the genuine caller provides distinct valid pointer cells.
            unsafe {
                assert_eq!(*projection, mapping());
                assert!((*canonical).is_null());
                *canonical = *projection;
                *projection = std::ptr::null_mut();
            }
        }
        fixture.transfer_status
    })
}

extern "C" fn current(_id: u64, owner: *mut Mapping) -> i32 {
    assert_eq!(owner, mapping());
    NATIVE.with(|fixture| fixture.borrow_mut().calls.push("current"));
    0
}

extern "C" fn identity_return(_id: u64, holder: *mut *mut Mapping) -> i32 {
    NATIVE.with(|fixture| {
        let mut fixture = fixture.borrow_mut();
        fixture.calls.push("return");
        // SAFETY: this Native fixture alone reads its exact supplied holder;
        // zero consumes it, while a refusal retains its actual pointer value.
        unsafe {
            assert_eq!(*holder, mapping());
            if fixture.return_status == 0 {
                *holder = std::ptr::null_mut();
            }
        }
        fixture.return_status
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

fn runtime() -> *mut RuntimePurpose {
    std::ptr::NonNull::<RuntimePurpose>::dangling().as_ptr()
}

fn setup(fixture: NativeFixture) {
    NATIVE.with(|native| *native.borrow_mut() = fixture);
}

#[test]
fn negative_creation_retains_outputs_until_exact_pretransfer_cleanup() {
    setup(NativeFixture {
        creation_status: -libc::ETIMEDOUT,
        ..NativeFixture::default()
    });
    let mut owner = Box::pin(WorkspaceMapping::new());

    let result = owner.create_using(7, runtime(), api());
    assert!(matches!(
        result,
        Err(DeviceDigestWorkspaceError::Admission { status }) if status == -libc::ETIMEDOUT
    ));
    assert!(!owner.creation.is_null());
    assert!(!owner.address.is_null());
    assert_eq!(owner.extent, 65_536);
    assert!(!owner.transfer_attempted);
    assert!(owner.identity_return().is_ok());
    assert!(owner.returned);
    assert!(owner.creation.is_null());
    assert_eq!(owner.creation_status, Some(-libc::ETIMEDOUT));
    NATIVE.with(|fixture| assert_eq!(fixture.borrow().calls, ["create", "return"]));
}

#[test]
fn empty_negative_creation_settles_only_local_custody_without_retry() {
    setup(NativeFixture {
        creation_status: -libc::ENOKEY,
        empty_outputs: true,
        ..NativeFixture::default()
    });
    let mut owner = Box::pin(WorkspaceMapping::new());

    assert!(matches!(
        owner.create_using(7, runtime(), api()),
        Err(DeviceDigestWorkspaceError::Admission { status }) if status == -libc::ENOKEY
    ));
    assert!(owner.identity_return().is_ok());
    assert!(owner.returned);
    assert!(owner.attempted);
    assert_eq!(owner.creation_status, Some(-libc::ENOKEY));
    assert_eq!(owner.return_status, None);
    assert!(owner.create_using(7, runtime(), api()).is_err());
    assert!(owner.identity_return().is_ok());
    NATIVE.with(|fixture| assert_eq!(fixture.borrow().calls, ["create"]));
}

#[test]
fn partial_or_nonnegative_empty_outputs_cannot_settle_as_no_birth() {
    for (status, owner_only, address_only, extent_only) in [
        (0, false, false, false),
        (1, false, false, false),
        (-libc::ECANCELED, true, false, false),
        (-libc::ECANCELED, false, true, false),
        (-libc::ECANCELED, false, false, true),
    ] {
        setup(NativeFixture {
            creation_status: status,
            empty_outputs: true,
            owner_only,
            address_only,
            extent_only,
            return_status: -libc::ENOKEY,
            ..NativeFixture::default()
        });
        let mut owner = Box::pin(WorkspaceMapping::new());

        assert!(owner.create_using(7, runtime(), api()).is_err());
        assert!(owner.identity_return().is_err());
        assert!(!owner.returned);
        assert_eq!(owner.creation_status, Some(status));
        assert!(owner.attempted);
        assert!(owner.create_using(7, runtime(), api()).is_err());
        NATIVE.with(|fixture| {
            let calls = &fixture.borrow().calls;
            assert_eq!(
                calls,
                if owner_only {
                    &["create", "return"][..]
                } else {
                    &["create"][..]
                }
            );
        });
    }
}

#[test]
fn moved_negative_post_retains_canonical_debt_and_never_replays_birth() {
    setup(NativeFixture {
        transfer_moves: true,
        transfer_status: -libc::ECANCELED,
        return_status: -libc::ENOKEY,
        ..NativeFixture::default()
    });
    let mut owner = Box::pin(WorkspaceMapping::new());

    assert!(matches!(
        owner.create_using(7, runtime(), api()),
        Err(DeviceDigestWorkspaceError::Admission { status }) if status == -libc::ECANCELED
    ));
    assert!(owner.creation.is_null());
    assert!(!owner.observed.is_null());
    assert!(owner.identity_return().is_err());
    assert!(!owner.returned);
    assert_eq!(owner.return_status, Some(-libc::ENOKEY));
    assert_eq!(owner.transfer_status, Some(-libc::ECANCELED));
    assert!(owner.create_using(7, runtime(), api()).is_err());
    NATIVE.with(|fixture| {
        assert_eq!(fixture.borrow().calls, ["create", "transfer", "return"]);
    });
}

#[test]
fn transfer_refusal_before_move_returns_only_the_creation_projection() {
    setup(NativeFixture {
        transfer_status: -libc::EINVAL,
        ..NativeFixture::default()
    });
    let mut owner = Box::pin(WorkspaceMapping::new());

    assert!(owner.create_using(7, runtime(), api()).is_err());
    assert!(!owner.creation.is_null());
    assert!(owner.identity_return().is_ok());
    assert!(owner.returned);
    assert_eq!(owner.transfer_status, Some(-libc::EINVAL));
    NATIVE.with(|fixture| {
        assert_eq!(fixture.borrow().calls, ["create", "transfer", "return"]);
    });
}

#[test]
fn copied_process_disarms_before_any_inherited_native_call() {
    setup(NativeFixture {
        transfer_moves: true,
        ..NativeFixture::default()
    });
    let mut owner = Box::pin(WorkspaceMapping::new());
    assert!(owner.create_using(7, runtime(), api()).is_ok());
    owner.process = std::process::id().wrapping_add(1);

    assert!(owner.current().is_err());
    assert!(owner.identity_return().is_err());
    assert!(owner.disarm_inherited().is_ok());
    assert!(owner.address.is_null());
    assert!(owner.observed.is_null());
    assert!(!owner.returned);
    assert!(owner.disarm_inherited().is_err());
    NATIVE.with(|fixture| {
        assert_eq!(fixture.borrow().calls, ["create", "transfer", "current"]);
    });
}
