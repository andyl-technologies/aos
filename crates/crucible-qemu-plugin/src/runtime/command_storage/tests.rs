//! Checks local negative-output custody without issuing a Native storage owner.
//!
//! Private tables supply only opaque identities; tests never project or invoke
//! an actual Bridge through them. Typed contents/free tests live in placement.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::startup_source::runtime_purpose::{CommandClaim, RuntimePurpose};
use abi::{Destructor, Initializer};
use std::cell::RefCell;

#[derive(Default)]
struct Cuts {
    first: i32,
    current: i32,
    returned: i32,
    born: bool,
    keep_on_success: bool,
    borrows: usize,
    returns: usize,
    creates: usize,
    storage_returns: usize,
}
thread_local! { static CUTS: RefCell<Cuts> = RefCell::new(Cuts::default()); }

extern "C" fn create(
    _: u64,
    _: *mut RuntimePurpose,
    _: *mut CommandClaim,
    out: *mut *mut Storage,
) -> i32 {
    CUTS.with_borrow_mut(|cuts| {
        cuts.creates += 1;
        if cuts.born {
            // SAFETY: the local output slot is live; this opaque token is never
            // dereferenced or passed to actual Native accepting code.
            unsafe {
                out.write(std::ptr::without_provenance_mut(1));
            }
        }
        cuts.first
    })
}
extern "C" fn initialize(
    _: u64,
    _: *mut Storage,
    _: Initializer,
    _: Destructor,
    _: *mut c_void,
) -> i32 {
    -libc::ENOSYS
}
extern "C" fn placement(_: u64, _: *mut Storage) -> i32 {
    -libc::ENOSYS
}
extern "C" fn transfer(
    _: u64,
    _: *mut RuntimePurpose,
    _: *mut *mut Storage,
    _: *mut *mut Storage,
) -> i32 {
    -libc::ENOSYS
}
extern "C" fn borrow(_: u64, _: *mut Storage, out: *mut *mut PhysicalUse, serial: *mut u64) -> i32 {
    CUTS.with_borrow_mut(|cuts| {
        cuts.borrows += 1;
        if cuts.born {
            // SAFETY: local output cells are live and represent no actual loan.
            unsafe {
                out.write(std::ptr::without_provenance_mut(2));
                serial.write(7);
            }
        }
        cuts.first
    })
}
extern "C" fn current(
    _: u64,
    _: *mut PhysicalUse,
    _: u64,
    _: *mut *mut c_void,
    _: *mut usize,
    _: *mut usize,
) -> i32 {
    CUTS.with_borrow(|cuts| cuts.current)
}
extern "C" fn return_use(_: u64, out: *mut *mut PhysicalUse, serial: u64) -> i32 {
    CUTS.with_borrow_mut(|cuts| {
        cuts.returns += 1;
        assert_eq!(serial, 7);
        if cuts.returned == 0 && !cuts.keep_on_success {
            // SAFETY: the exact local output cell is live, with no Native owner.
            unsafe {
                out.write(std::ptr::null_mut());
            }
        }
        cuts.returned
    })
}
extern "C" fn observe(_: u64, _: *mut Storage, _: *mut Status) -> i32 {
    -libc::ENOSYS
}
extern "C" fn holder(_: u64, _: *mut *mut Storage, out: *mut *mut Storage) -> i32 {
    // SAFETY: this is a distinct local projection, never a canonical field.
    unsafe {
        out.write(std::ptr::without_provenance_mut(1));
    }
    0
}
extern "C" fn return_storage(_: u64, _: *mut *mut Storage) -> i32 {
    CUTS.with_borrow_mut(|cuts| cuts.storage_returns += 1);
    -libc::ENOSYS
}

fn table() -> Api {
    Api {
        create,
        initialize,
        placement_begin: placement,
        transfer,
        borrow,
        current,
        return_use,
        observe,
        holder_observe: holder,
        return_storage,
    }
}

fn fixture(cuts: Cuts, action: impl FnOnce(&mut Adapter)) {
    CUTS.with_borrow_mut(|state| *state = cuts);
    let mut owner = CommandStorage::new();
    owner.id = 9;
    owner.api = Some(table());
    // SAFETY: the stack owner is not moved while this isolated adapter is used;
    // no table retains it and no real Native owner or typed body is supplied.
    let mut adapter = unsafe { Adapter::new(&owner) };
    action(&mut adapter);
}

#[test]
fn born_negative_use_is_retained_and_cannot_be_overwritten_by_reborrow() {
    fixture(
        Cuts {
            first: -libc::ECANCELED,
            returned: -libc::EBUSY,
            born: true,
            ..Cuts::default()
        },
        |adapter| {
            let first = adapter.with_bridge(|_| panic!("negative borrow must not touch a Bridge"));
            assert_eq!(first, Err::<(), _>(physical_error(-libc::ECANCELED)));
            assert!(adapter.physical_use.is_some());

            let repeated =
                adapter.with_bridge(|_| panic!("retained loan prohibits another borrow"));
            assert_eq!(repeated, Err::<(), _>(physical_error(-libc::EBUSY)));
            CUTS.with_borrow(|cuts| {
                assert_eq!(cuts.borrows, 1);
                assert_eq!(cuts.returns, 1);
            });
        },
    );
}

#[test]
fn negative_current_returns_the_actual_pair_and_preserves_primary_status() {
    fixture(
        Cuts {
            current: -libc::ERANGE,
            born: true,
            ..Cuts::default()
        },
        |adapter| {
            let result = adapter.with_bridge(|_| panic!("failed current must not touch a Bridge"));
            assert_eq!(result, Err::<(), _>(physical_error(-libc::ERANGE)));
            assert!(adapter.physical_use.is_none());
            CUTS.with_borrow(|cuts| assert_eq!(cuts.returns, 1));
        },
    );
}

#[test]
fn only_explicit_preeffect_contention_is_classified_pending() {
    fixture(
        Cuts {
            first: 1,
            ..Cuts::default()
        },
        |adapter| {
            let result = adapter.with_bridge(|_| panic!("pending use has no Bridge access"));
            assert_eq!(
                result,
                Err::<(), _>(FaultCommandBridgeError::PhysicalStoragePending)
            );
            assert!(adapter.physical_use.is_none());
            CUTS.with_borrow(|cuts| assert_eq!(cuts.returns, 0));
        },
    );
    assert_eq!(
        native_status(-libc::EAGAIN),
        Err(physical_error(-libc::EAGAIN))
    );
    assert_eq!(native_status(1), Err(physical_error(1)));
}

#[test]
fn allocation_negative_keeps_projection_and_closes_repeat_attempts() {
    CUTS.with_borrow_mut(|cuts| {
        *cuts = Cuts {
            first: -libc::ENOMEM,
            born: true,
            ..Cuts::default()
        }
    });
    let mut owner = CommandStorage::new();
    let material = (9, std::ptr::null_mut(), std::ptr::null_mut());
    let first = owner.create_using(
        material,
        || panic!("allocation refusal precedes placement"),
        table(),
    );
    assert_eq!(first, Err(physical_error(-libc::ENOMEM)));
    assert!(!owner.projection.is_null());

    let repeated = owner.create_using(material, || panic!("birth cannot be repeated"), table());
    assert_eq!(repeated, Err(physical_error(-libc::EALREADY)));
    CUTS.with_borrow(|cuts| assert_eq!(cuts.creates, 1));
}

#[test]
fn a_nonconsuming_success_cannot_erase_debt_or_replace_the_primary_error() {
    fixture(
        Cuts {
            current: -libc::ERANGE,
            born: true,
            keep_on_success: true,
            ..Cuts::default()
        },
        |adapter| {
            let first = adapter.with_bridge(|_| panic!("failed current must not touch a Bridge"));
            assert_eq!(first, Err::<(), _>(physical_error(-libc::ERANGE)));
            assert!(adapter.physical_use.is_some());

            let repeated = adapter.with_bridge(|_| panic!("nonconsuming return retains the loan"));
            assert_eq!(repeated, Err::<(), _>(physical_error(-libc::EBUSY)));
            CUTS.with_borrow(|cuts| {
                assert_eq!(cuts.borrows, 1);
                assert_eq!(cuts.returns, 1);
            });
        },
    );
}

#[test]
fn live_local_debt_blocks_source_teardown_until_actual_borrowed_state_drains() {
    crate::fault_command::test_support::with_initialized_bridge(|bridge, _, _| {
        CUTS.with_borrow_mut(|cuts| *cuts = Cuts::default());
        let mut owner = CommandStorage::new();
        owner.api = Some(table());
        let debt = &owner.local_debt_present;

        // The live fixture body exercises the same used loan-local refresh. No
        // fixture API lends a Bridge or authorizes a native Source effect.
        run_borrowed_body(bridge, debt, |body| {
            crate::fault_command::test_support::set_fixture_query_pending(body, 9, true);
            Err::<(), _>(FaultCommandBridgeError::QemuSubmit {
                status: -libc::ECANCELED,
            })
        })
        .unwrap_or_else(|error| {
            assert!(matches!(error, FaultCommandBridgeError::QemuSubmit { .. }))
        });
        assert!(owner.local_debt_present.load(Ordering::Acquire));
        assert!(!owner.identity_return());
        CUTS.with_borrow(|cuts| assert_eq!(cuts.storage_returns, 0));

        run_borrowed_body(bridge, &owner.local_debt_present, |body| {
            crate::fault_command::test_support::set_fixture_query_pending(body, 9, false);
            Ok(())
        })
        .unwrap_or_else(|error| panic!("fixture drain: {error}"));
        assert!(!owner.local_debt_present.load(Ordering::Acquire));
        // The mock Source still refuses: empty local state grants no teardown.
        assert!(!owner.identity_return());
        CUTS.with_borrow(|cuts| assert_eq!(cuts.storage_returns, 1));
    });
}

#[test]
fn stale_empty_preflight_cannot_acknowledge_destruction_of_a_pending_bridge() {
    crate::fault_command::test_support::with_initialized_bridge(|bridge, _, _| {
        crate::fault_command::test_support::set_fixture_query_pending(bridge, 13, true);
        let layout = std::alloc::Layout::new::<FaultCommandBridge>();
        let mut destroyed = 0;

        let status = placement::destroy::<FaultCommandBridge>(
            std::ptr::from_mut(bridge).cast(),
            layout.size(),
            layout.align(),
            &mut destroyed,
        );

        assert_eq!(status, -libc::EBUSY);
        assert_eq!(destroyed, 0);
        assert!(crate::fault_command::test_support::fixture_query_pending(
            bridge, 13
        ));
        // Fixture backing stays alive. An actual Source-entered negative drop
        // would retain its once-attempt debt and never call this callback again.
    });
}
