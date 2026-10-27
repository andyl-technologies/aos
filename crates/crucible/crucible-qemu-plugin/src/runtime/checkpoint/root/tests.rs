//! Exercises Rust custody decisions against a test-only native journal harness.
//!
//! These controls check wrapper ordering and refusal containment. They do not
//! issue a production native root or qualify the actual native cleanup publisher.
// SPDX-License-Identifier: GPL-2.0-or-later

use std::cell::RefCell;

use super::*;

struct Journal {
    stage: u32,
    first: i32,
    post: i32,
    retire_status: i32,
    end_status: i32,
    returned: bool,
    mailbox_restored: bool,
    return_status: i32,
    return_observe_status: i32,
    calls: Vec<&'static str>,
}

thread_local! {
    static JOURNAL: RefCell<Journal> = const { RefCell::new(Journal {
        stage: 1, first: 0, post: 0, retire_status: 0, end_status: 0,
        returned: false, mailbox_restored: true, return_status: 0, return_observe_status: 0,
        calls: Vec::new(),
    }) };
}

fn reset(stage: u32) {
    JOURNAL.with_borrow_mut(|journal| {
        *journal = Journal {
            stage,
            first: 0,
            post: 0,
            retire_status: 0,
            end_status: 0,
            returned: false,
            mailbox_restored: true,
            return_status: 0,
            return_observe_status: 0,
            calls: Vec::new(),
        };
    });
}

extern "C" fn hold(_: u64, output: *mut *mut ProofHandle) -> i32 {
    // SAFETY: the wrapper provides its initialized pointer output; this test-only
    // opaque address is never dereferenced or presented to production native code.
    unsafe {
        output.write(std::ptr::without_provenance_mut(1));
    }
    0
}

extern "C" fn proof_check(_: u64, _: *mut ProofHandle) -> i32 {
    0
}
extern "C" fn return_root(_: u64, _: *mut ProofHandle) -> i32 {
    JOURNAL.with_borrow_mut(|journal| {
        journal.calls.push("return");
        journal.returned = true;
        journal.return_status
    })
}

extern "C" fn return_observe(
    _: u64,
    _: *mut ProofHandle,
    output: *mut CallbackReturnStatus,
) -> i32 {
    JOURNAL.with_borrow_mut(|journal| {
        journal.calls.push("return_observe");
        if journal.return_observe_status != 0 {
            return journal.return_observe_status;
        }
        // SAFETY: the wrapper lends this writable fixed output during the call.
        unsafe {
            output.write(CallbackReturnStatus {
                schema_version: 1,
                struct_size: std::mem::size_of::<CallbackReturnStatus>() as u32,
                returned: u32::from(journal.returned),
                mailbox_restored: u32::from(journal.mailbox_restored),
                first_status: journal.first,
                post_status: journal.post,
                native_transaction_generation: 11,
            });
        }
        0
    })
}
extern "C" fn detach(
    _: u64,
    _: *mut ProofHandle,
    _: Option<PlacementCallback>,
    _: *mut c_void,
    _: *mut PlacementDisposition,
) -> i32 {
    -libc::ENOSYS
}
extern "C" fn restore(_: u64, _: *mut ProofHandle, _: *mut PlacementDisposition) -> i32 {
    -libc::ENOSYS
}

extern "C" fn borrow(
    _: u64,
    _: *mut ProofHandle,
    _: *mut c_void,
    output: *mut *mut ProducerLoan,
) -> i32 {
    JOURNAL.with_borrow_mut(|journal| journal.calls.push("borrow"));
    // SAFETY: the test wrapper supplies this live output, used only as an opaque
    // model identity until the matching test-only end function consumes it.
    unsafe {
        output.write(std::ptr::without_provenance_mut(2));
    }
    0
}

extern "C" fn observe(_: u64, _: *mut ProducerLoan, output: *mut Disposition) -> i32 {
    JOURNAL.with_borrow_mut(|journal| {
        journal.calls.push("observe");
        // SAFETY: the wrapper lends this fixed writable record during the call.
        unsafe {
            output.write(Disposition {
                schema_version: 1,
                struct_size: std::mem::size_of::<Disposition>() as u32,
                state: journal.stage,
                first_status: journal.first,
                post_status: journal.post,
                root_acknowledged: 0,
                native_transaction_generation: 11,
            });
        }
    });
    0
}

extern "C" fn retire(_: u64, _: *mut ProofHandle, _: *mut ProducerLoan) -> i32 {
    JOURNAL.with_borrow_mut(|journal| {
        journal.calls.push("retire");
        journal.stage = 3;
        journal.retire_status
    })
}

extern "C" fn acknowledge(_: u64, _: *mut ProducerLoan) -> i32 {
    JOURNAL.with_borrow_mut(|journal| journal.calls.push("acknowledge"));
    0
}

extern "C" fn end(_: u64, _: *mut ProducerLoan) -> i32 {
    JOURNAL.with_borrow_mut(|journal| {
        journal.calls.push("end");
        journal.end_status
    })
}

fn root() -> NativeRoot {
    RootApi {
        hold,
        check: proof_check,
        detach,
        restore,
        return_root,
        return_observe,
        borrow,
        observe,
        retire,
        acknowledge,
        end,
    }
    .acquire(7, std::ptr::without_provenance_mut(3), 11)
    .unwrap()
}

#[test]
fn negative_original_facts_do_not_hide_physical_cleanup_stage() {
    reset(2);
    JOURNAL.with_borrow_mut(|journal| {
        journal.first = -libc::ECANCELED;
        journal.post = -libc::ETIME;
    });
    let mut root = root();

    assert_eq!(root.observe().unwrap(), RootStage::LocalDisposition);
    assert_eq!(root.first_status.get(), -libc::ECANCELED);
    assert_eq!(root.post_status.get(), -libc::ETIME);
    JOURNAL.with_borrow(|journal| assert_eq!(journal.calls, ["borrow", "observe", "end"]));
}

#[test]
fn local_disposal_failure_prevents_native_root_return() {
    reset(2);
    let mut root = root();

    let result = root.retire_local(|_| Err(RamError::Invariant("actual local loan retained")));

    assert!(result.is_err());
    JOURNAL.with_borrow(|journal| {
        assert_eq!(journal.stage, 2);
        assert_eq!(journal.calls, ["borrow", "observe", "end"]);
    });
}

#[test]
fn negative_retire_reobserves_the_same_advanced_journal() {
    reset(2);
    JOURNAL.with_borrow_mut(|journal| {
        journal.retire_status = -libc::ECANCELED;
    });
    let mut root = root();
    let mut disposed = false;

    let stage = root
        .retire_local(|loan| {
            assert_eq!(loan.transaction(), 11);
            disposed = true;
            Ok(())
        })
        .unwrap();

    assert!(disposed);
    assert_eq!(stage, RootStage::RootReturned);
    JOURNAL.with_borrow(|journal| {
        assert_eq!(
            journal.calls,
            ["borrow", "observe", "retire", "observe", "end"]
        )
    });
}

#[test]
fn root_returned_never_acknowledges_or_repeats_local_disposal() {
    reset(3);
    let mut root = root();

    assert_eq!(
        root.retire_local(|_| panic!("local disposal repeated"))
            .unwrap(),
        RootStage::RootReturned
    );
    assert!(root.acknowledge_retired().is_err());

    assert!(!root.is_acknowledged());
    JOURNAL.with_borrow(|journal| {
        assert!(!journal.calls.contains(&"retire"));
        assert!(!journal.calls.contains(&"acknowledge"));
    });
}

#[test]
fn acknowledgment_ends_the_observer_before_forbidding_future_pointer_reads() {
    reset(4);
    let mut root = root();

    root.acknowledge_retired().unwrap();
    assert!(root.is_acknowledged());
    assert!(root.observe().is_err());
    assert!(root.check_active().is_err());
    assert!(root.return_from_callback().is_err());
    assert!(root.detach(None, std::ptr::null_mut()).is_err());
    root.acknowledge_retired().unwrap();

    JOURNAL.with_borrow(|journal| {
        assert_eq!(journal.calls, ["borrow", "observe", "acknowledge", "end"])
    });
}

#[test]
fn failed_observer_return_retains_root_without_another_borrow() {
    reset(4);
    JOURNAL.with_borrow_mut(|journal| {
        journal.end_status = -libc::EBUSY;
    });
    let mut root = root();

    assert!(root.acknowledge_retired().is_err());
    assert!(!root.is_acknowledged());
    assert!(root.observe().is_err());

    JOURNAL.with_borrow(|journal| {
        assert_eq!(journal.calls, ["borrow", "observe", "acknowledge", "end"])
    });
}

#[test]
fn negative_callback_return_observes_physical_return_without_repeating_it() {
    reset(1);
    JOURNAL.with_borrow_mut(|journal| {
        journal.return_status = -libc::ECANCELED;
        journal.first = -libc::ECANCELED;
        journal.post = -libc::ETIME;
    });
    let root = root();

    assert!(
        matches!(root.return_from_callback(), Err(RamError::Native { status, .. })
        if status == -libc::ECANCELED)
    );
    root.return_from_callback().unwrap();

    assert_eq!(root.first_status.get(), -libc::ECANCELED);
    assert_eq!(root.post_status.get(), -libc::ETIME);
    JOURNAL.with_borrow(|journal| {
        assert_eq!(journal.stage, 1);
        assert_eq!(
            journal.calls,
            [
                "return_observe",
                "return",
                "return_observe",
                "return_observe"
            ]
        );
    });
}

#[test]
fn callback_return_requires_the_same_restored_mailbox() {
    reset(1);
    JOURNAL.with_borrow_mut(|journal| journal.mailbox_restored = false);
    let root = root();

    assert!(root.return_from_callback().is_err());

    JOURNAL.with_borrow(|journal| {
        assert!(!journal.returned);
        assert_eq!(journal.calls, ["return_observe"]);
    });
}

#[test]
fn refused_return_observation_cannot_issue_a_physical_return() {
    reset(1);
    JOURNAL.with_borrow_mut(|journal| journal.return_observe_status = -libc::EBUSY);
    let root = root();

    assert!(root.return_from_callback().is_err());

    JOURNAL.with_borrow(|journal| {
        assert!(!journal.returned);
        assert_eq!(journal.calls, ["return_observe"]);
    });
}
