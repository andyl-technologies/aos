//! Exercises negative output custody with a local journal model, never Native.
//!
//! Opaque tokens are not dereferenced or submitted to QEMU. These controls
//! cannot issue Source membership, an action Original or callback permission.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use std::cell::RefCell;

#[derive(Default)]
struct Cuts {
    creates: usize,
    member_creates: usize,
    member_create_status: i32,
    writer_address: usize,
    member_transfer_status: i32,
    member_field: usize,
    member_returned_field: usize,
    return_status: i32,
    consume: bool,
    creation_status: i32,
    receive_field: usize,
    returned_field: usize,
    progress: ReceiveProgress,
}

thread_local! { static CUTS: RefCell<Cuts> = RefCell::new(Cuts::default()); }

fn member() -> *mut Member {
    std::ptr::without_provenance_mut(1)
}
fn receipt() -> *mut Receive {
    std::ptr::without_provenance_mut(2)
}

extern "C" fn member_create(
    _: u64,
    _: *mut NativeComponent,
    _: Reader,
    writer: Writer,
    out: *mut *mut Member,
) -> i32 {
    // SAFETY: this fixture table receives one distinct live local output cell.
    unsafe {
        out.write(member());
    }
    CUTS.with_borrow_mut(|cuts| {
        cuts.member_creates += 1;
        cuts.writer_address = writer as usize;
        cuts.member_create_status
    })
}

extern "C" fn member_transfer(_: u64, from: *mut *mut Member, to: *mut *mut Member) -> i32 {
    // SAFETY: the actual wrapper passes distinct valid model field addresses.
    unsafe {
        to.write(*from);
        from.write(std::ptr::null_mut());
    }
    CUTS.with_borrow_mut(|cuts| {
        cuts.member_field = to as usize;
        cuts.member_transfer_status
    })
}

extern "C" fn member_current(_: u64, _: *mut Member) -> i32 {
    0
}
extern "C" fn member_return(_: u64, field: *mut *mut Member) -> i32 {
    CUTS.with_borrow_mut(|cuts| {
        cuts.member_returned_field = field as usize;
        -libc::EBUSY
    })
}
extern "C" fn reader(
    _: *mut ControlIntentFacts,
    _: *mut ReceiveProgress,
    _: *mut std::ffi::c_void,
) -> i32 {
    -libc::ENOTSUP
}

extern "C" fn writer(
    _: *const u8,
    _: usize,
    _: *mut super::super::live_callbacks::ParkReturnWriteProgress,
    _: *mut std::ffi::c_void,
) -> i32 {
    -libc::ENOTSUP
}

extern "C" fn receive_create(
    _: u64,
    _: *mut Member,
    out: *mut *mut Receive,
    serial: *mut u64,
) -> i32 {
    CUTS.with_borrow_mut(|cuts| {
        cuts.creates += 1;
        // SAFETY: actual wrapper outputs are distinct fresh live model cells.
        unsafe {
            out.write(receipt());
            serial.write(18 + cuts.creates as u64);
        }
        cuts.creation_status
    })
}

extern "C" fn receive_transfer(
    _: u64,
    from: *mut *mut Receive,
    _: u64,
    to: *mut *mut Receive,
) -> i32 {
    CUTS.with_borrow_mut(|cuts| {
        // SAFETY: the same production wrapper supplies distinct model fields.
        unsafe {
            to.write(*from);
            from.write(std::ptr::null_mut());
        }
        cuts.receive_field = to as usize;
        0
    })
}

extern "C" fn receive_observe(
    _: u64,
    _: *mut Receive,
    serial: u64,
    facts: *mut ControlIntentFacts,
    progress: *mut ReceiveProgress,
    status: *mut Status,
) -> i32 {
    CUTS.with_borrow(|cuts| {
        // SAFETY: the wrapper lends three distinct live output records.
        unsafe {
            facts.write(ControlIntentFacts {
                control_sequence: 0,
                command_producer_ordinal: 0,
                sample_generation: 0,
                installed_sample_generation: 0,
                sampler_configured: 0,
                sample_present: 0,
            });
            progress.write(cuts.progress);
            status.write(Status {
                serial,
                reader_status: cuts.creation_status,
                invocation_attempted: 1,
                invocation_returned: 1,
                progress_valid: 1,
                terminal_uncertain: u32::from(cuts.progress.reader_released == 0),
                ..Status::default()
            });
        }
        0
    })
}

extern "C" fn receive_current(_: u64, _: *mut Receive, _: u64) -> i32 {
    CUTS.with_borrow(|cuts| cuts.creation_status)
}

extern "C" fn receive_return(_: u64, field: *mut *mut Receive, _: u64) -> i32 {
    CUTS.with_borrow_mut(|cuts| {
        cuts.returned_field = field as usize;
        if cuts.return_status == 0 && cuts.consume {
            // SAFETY: this is the exact live model field supplied by the wrapper.
            unsafe {
                field.write(std::ptr::null_mut());
            }
        }
        cuts.return_status
    })
}

fn api() -> Api {
    Api {
        member_create,
        member_transfer,
        member_current,
        member_return,
        receive_create,
        receive_transfer,
        receive_observe,
        receive_current,
        receive_return,
    }
}

fn fixture() -> Box<CommandReceive> {
    // This Box owns only fixture storage. It keeps every model field address
    // stable; no fixture pointer is admitted as genuine Source allocation.
    let mut keeper = Box::new(CommandReceive::new());
    keeper
        .enroll_using(3, std::ptr::null_mut(), reader, writer, api())
        .unwrap();
    keeper
}

#[test]
fn received_zero_facts_survive_negative_post_and_never_reenter_creation() {
    CUTS.with_borrow_mut(|cuts| {
        *cuts = Cuts {
            creation_status: -libc::EAGAIN,
            return_status: -libc::ENOKEY,
            progress: ReceiveProgress {
                post_status: -libc::EAGAIN,
                read_attempted: 1,
                request_received: 1,
                reader_released: 1,
                ..ReceiveProgress::default()
            },
            ..Cuts::default()
        }
    });
    let mut keeper = fixture();

    let observed = keeper.ready_facts();
    assert_eq!(observed.status, -libc::EAGAIN);
    assert_eq!(observed.facts.map(|facts| facts.control_sequence), Some(0));
    assert_eq!(keeper.progress.request_received, 1);
    assert!(keeper.identity_return().is_err());
    assert_eq!(keeper.serial, 19);
    assert_eq!(keeper.ready_facts().status, -libc::EAGAIN);

    CUTS.with_borrow(|cuts| {
        assert_eq!(cuts.creates, 1);
        assert_eq!(cuts.returned_field, cuts.receive_field);
    });
}

#[test]
fn unknown_local_release_retains_owner_and_member_despite_absent_facts() {
    CUTS.with_borrow_mut(|cuts| {
        *cuts = Cuts {
            creation_status: -libc::ENOMEM,
            return_status: -libc::EBUSY,
            progress: ReceiveProgress {
                first_status: -libc::ENOMEM,
                read_attempted: 1,
                request_received: 0,
                reader_released: 0,
                ..ReceiveProgress::default()
            },
            ..Cuts::default()
        }
    });
    let mut keeper = fixture();

    let observed = keeper.ready_facts();
    assert_eq!(observed.status, -libc::ENOMEM);
    assert!(observed.facts.is_none());
    assert!(keeper.identity_return().is_err());
    assert_eq!(keeper.receive, receipt());
    assert_eq!(keeper.member, member());
    assert_eq!(keeper.journal.terminal_uncertain, 1);

    CUTS.with_borrow(|cuts| assert_eq!(cuts.creates, 1));
}

#[test]
fn moved_destination_is_used_after_negative_transfer_without_foreign_field_read() {
    CUTS.with_borrow_mut(|cuts| {
        *cuts = Cuts {
            member_transfer_status: -libc::EIO,
            ..Cuts::default()
        }
    });
    let mut keeper = Box::new(CommandReceive::new());

    assert_eq!(
        keeper.enroll_using(3, std::ptr::null_mut(), reader, writer, api()),
        Err(status_error(-libc::EIO))
    );
    assert!(keeper.member_creation.is_null());
    assert!(keeper.identity_return().is_err());
    assert_eq!(keeper.member, member());
    assert!(keeper.member_attempted);

    CUTS.with_borrow(|cuts| assert_eq!(cuts.member_returned_field, cuts.member_field));
}

#[test]
fn known_no_request_can_reenter_only_after_actual_identity_consumption() {
    CUTS.with_borrow_mut(|cuts| {
        *cuts = Cuts {
            creation_status: -libc::ENOENT,
            return_status: -libc::EBUSY,
            consume: true,
            progress: ReceiveProgress {
                first_status: -libc::ENOENT,
                read_attempted: 1,
                request_received: 0,
                reader_released: 1,
                ..ReceiveProgress::default()
            },
            ..Cuts::default()
        }
    });
    let mut keeper = fixture();

    assert_eq!(keeper.ready_facts().status, -libc::ENOENT);
    assert_eq!(keeper.serial, 19);
    assert_eq!(keeper.ready_facts().status, -libc::ENOENT);
    CUTS.with_borrow(|cuts| assert_eq!(cuts.creates, 1));

    CUTS.with_borrow_mut(|cuts| cuts.return_status = 0);
    assert_eq!(keeper.ready_facts().status, -libc::ENOENT);
    assert_eq!(keeper.serial, 0);
    assert!(!keeper.receive_attempted);
    CUTS.with_borrow_mut(|cuts| {
        cuts.creation_status = -libc::EAGAIN;
        cuts.return_status = -libc::ENOKEY;
        cuts.progress.request_received = 1;
        cuts.progress.first_status = 0;
        cuts.progress.post_status = -libc::EAGAIN;
    });

    assert_eq!(keeper.ready_facts().status, -libc::EAGAIN);
    assert_eq!(keeper.serial, 20);
    CUTS.with_borrow(|cuts| assert_eq!(cuts.creates, 2));
}

#[test]
fn first_member_constructor_receives_the_exact_writer_before_negative_status() {
    CUTS.with_borrow_mut(|cuts| {
        *cuts = Cuts {
            member_create_status: -libc::EAGAIN,
            ..Cuts::default()
        };
    });
    let mut keeper = CommandReceive::new();
    // Retain the actual supplied value; separate function-item conversions may
    // resolve to different addresses in optimized code.
    let supplied_writer = std::hint::black_box(writer as Writer);
    let supplied_address = supplied_writer as *const () as usize;

    let result = keeper.enroll_using(3, std::ptr::null_mut(), reader, supplied_writer, api());

    assert!(result.is_err());
    assert_eq!(keeper.member_creation, member());
    assert_eq!(keeper.member, member());
    assert!(keeper.member_attempted);
    assert!(!keeper.member_transfer_attempted);
    CUTS.with_borrow(|cuts| {
        assert_eq!(cuts.member_creates, 1);
        assert_eq!(cuts.writer_address, supplied_address);
    });
    assert!(
        keeper
            .enroll_using(3, std::ptr::null_mut(), reader, supplied_writer, api())
            .is_err()
    );
    CUTS.with_borrow(|cuts| assert_eq!(cuts.member_creates, 1));
}
