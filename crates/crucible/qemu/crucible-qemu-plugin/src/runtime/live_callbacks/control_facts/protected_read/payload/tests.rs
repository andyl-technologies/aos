//! Exercises actual module payload custody without issuing Native authority.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crucible_qemu_shmem::{KIND_VM, NodeSlot};
use std::pin::Pin;

struct Fixture {
    reader: ProtectedReader,
    holder: *mut Payload,
    serial: u64,
}

fn fixture() -> Pin<Box<Fixture>> {
    Box::pin(Fixture {
        reader: ProtectedReader::new(),
        holder: std::ptr::null_mut(),
        serial: 0,
    })
}

fn request() -> NodeSlot {
    let slot = NodeSlot::new(KIND_VM);
    slot.request_control_boundary(73, Some(9))
        .unwrap_or_else(|error| panic!("publish module request: {error}"));
    slot
}

#[test]
fn canonical_return_destroys_actual_pending_payload_before_consuming_holder() {
    let mut fixture = fixture();
    let fixture = fixture.as_mut().get_mut();
    let slot = request();
    let received = fixture.reader.read(&slot, None);
    assert_eq!(received.status(), 0);

    // SAFETY: the fixture keeps both the actual child and its disjoint holder
    // fields pinned through this purely local custody exchange.
    unsafe {
        fixture
            .reader
            .claim_payload(&mut fixture.holder, &mut fixture.serial)
            .unwrap();
    }
    assert!(!fixture.holder.is_null());
    let canonical_holder = std::ptr::from_mut(&mut fixture.holder);
    fixture
        .reader
        .with_pending_request(|pending| {
            assert_eq!(pending.facts, received.facts.unwrap());
            assert_eq!(pending.canonical_holder, canonical_holder);
        })
        .unwrap();

    // SAFETY: no payload reference escapes the locked borrower above.
    unsafe {
        fixture
            .reader
            .return_payload(&mut fixture.holder, fixture.serial)
            .unwrap();
    }

    assert!(fixture.holder.is_null());
    assert_eq!(
        fixture.reader.with_pending_request(|_| ()),
        Err(-libc::ENOENT)
    );
    assert!(slot.control_boundary_is_requested());
}

#[test]
fn copied_holder_cannot_retire_the_actual_payload() {
    let mut fixture = fixture();
    let fixture = fixture.as_mut().get_mut();
    let slot = request();
    fixture.reader.read(&slot, None);
    // SAFETY: the actual fixture child and canonical field stay pinned.
    unsafe {
        fixture
            .reader
            .claim_payload(&mut fixture.holder, &mut fixture.serial)
            .unwrap();
    }
    let mut copy = fixture.holder;

    // SAFETY: the copied field is writable but deliberately noncanonical.
    let refused = unsafe { fixture.reader.return_payload(&mut copy, fixture.serial) };

    assert_eq!(refused, Err(-libc::ESTALE));
    assert_eq!(copy, fixture.holder);
    fixture.reader.with_pending_request(|_| ()).unwrap();
    assert!(slot.control_boundary_is_requested());
    // SAFETY: only the actual pinned holder can finish this local fixture.
    unsafe {
        fixture
            .reader
            .return_payload(&mut fixture.holder, fixture.serial)
            .unwrap();
    }
}

#[test]
fn stale_serial_retains_holder_and_excludes_replacement() {
    let mut fixture = fixture();
    let fixture = fixture.as_mut().get_mut();
    let slot = request();
    fixture.reader.read(&slot, None);
    // SAFETY: the actual fixture child and its disjoint outputs stay pinned.
    unsafe {
        fixture
            .reader
            .claim_payload(&mut fixture.holder, &mut fixture.serial)
            .unwrap();
    }
    let original = fixture.holder;

    // SAFETY: the exact writable field is deliberately paired with a stale serial.
    let refused = unsafe {
        fixture
            .reader
            .return_payload(&mut fixture.holder, fixture.serial + 1)
    };

    assert_eq!(refused, Err(-libc::ESTALE));
    assert_eq!(fixture.holder, original);
    assert_eq!(fixture.reader.read(&slot, None).status(), -libc::EBUSY);
    // SAFETY: the real serial and unchanged pinned holder remain retained.
    unsafe {
        fixture
            .reader
            .return_payload(&mut fixture.holder, fixture.serial)
            .unwrap();
    }
}

#[test]
fn second_claim_cannot_replace_the_exact_first_holder() {
    let mut fixture = fixture();
    let fixture = fixture.as_mut().get_mut();
    fixture.reader.read(&request(), None);
    // SAFETY: the fixture keeps its actual child and output fields pinned.
    unsafe {
        fixture
            .reader
            .claim_payload(&mut fixture.holder, &mut fixture.serial)
            .unwrap();
    }
    let mut second = std::ptr::null_mut();
    let mut serial = 0;

    // SAFETY: these disjoint empty fields stay live across the refused call.
    let refused = unsafe { fixture.reader.claim_payload(&mut second, &mut serial) };

    assert_eq!(refused, Err(-libc::EALREADY));
    assert!(second.is_null());
    assert_eq!(serial, 0);
    assert!(!fixture.holder.is_null());
    // SAFETY: the first canonical holder is still the only actual owner.
    unsafe {
        fixture
            .reader
            .return_payload(&mut fixture.holder, fixture.serial)
            .unwrap();
    }
}

#[test]
fn negative_read_post_still_transfers_the_actual_retained_payload() {
    let mut fixture = fixture();
    let fixture = fixture.as_mut().get_mut();
    let slot = request();
    let received = fixture.reader.read_with_post_interleave(&slot, None, || {
        slot.acknowledge_control_boundary();
    });
    assert_eq!(received.status(), -libc::EAGAIN);

    // SAFETY: the actual pinned payload and empty canonical outputs are retained
    // despite the independent read post failure. This issues no action loan.
    unsafe {
        fixture
            .reader
            .claim_payload(&mut fixture.holder, &mut fixture.serial)
            .unwrap();
    }

    fixture
        .reader
        .with_pending_request(|pending| assert_eq!(pending.facts, received.facts.unwrap()))
        .unwrap();
    assert!(!fixture.holder.is_null());
    // SAFETY: the retained actual payload has no outstanding local borrower.
    unsafe {
        fixture
            .reader
            .return_payload(&mut fixture.holder, fixture.serial)
            .unwrap();
    }
}

#[test]
fn actual_locked_payload_borrow_refuses_return_without_consumption() {
    let mut fixture = fixture();
    let fixture = fixture.as_mut().get_mut();
    fixture.reader.read(&request(), None);
    // SAFETY: the fixture's actual payload and disjoint outputs stay pinned.
    unsafe {
        fixture
            .reader
            .claim_payload(&mut fixture.holder, &mut fixture.serial)
            .unwrap();
    }
    let original = fixture.holder;

    fixture
        .reader
        .with_pending_request(|_| {
            // SAFETY: this exact field stays live. The actual held journal lock
            // must refuse destruction until its genuine borrower has returned.
            assert_eq!(
                unsafe {
                    fixture
                        .reader
                        .return_payload(&mut fixture.holder, fixture.serial)
                },
                Err(-libc::EBUSY)
            );
        })
        .unwrap();

    assert_eq!(fixture.holder, original);
    fixture.reader.with_pending_request(|_| ()).unwrap();
    // SAFETY: the locked borrower is now closed; the exact holder stays pinned.
    unsafe {
        fixture
            .reader
            .return_payload(&mut fixture.holder, fixture.serial)
            .unwrap();
    }
}

#[test]
fn poisoned_payload_borrow_keeps_actual_pending_owner_and_holder() {
    let mut pinned = fixture();
    let fixture = pinned.as_mut().get_mut();
    fixture.reader.read(&request(), None);
    // SAFETY: the fixture pins the actual child and canonical outputs.
    unsafe {
        fixture
            .reader
            .claim_payload(&mut fixture.holder, &mut fixture.serial)
            .unwrap();
    }
    let original = fixture.holder;
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fixture
            .reader
            .with_pending_request(|_| panic!("actual payload borrower interrupted"))
    }));
    assert!(interrupted.is_err());

    // SAFETY: the original field remains pinned and writable after the unwind.
    let refused = unsafe {
        fixture
            .reader
            .return_payload(&mut fixture.holder, fixture.serial)
    };

    assert_eq!(refused, Err(-libc::EOWNERDEAD));
    assert_eq!(fixture.holder, original);
    let retained = fixture.reader.journal.lock().err().unwrap().into_inner();
    assert!(retained.pending.is_some());
    drop(retained);
    // Uncertain actual ownership cannot be treated as returned for teardown.
    // Preserve this small complete fixture, including its canonical field.
    std::mem::forget(pinned);
}
