//! Exercises the real pinned journal's local borrow and exact field consumption.
//!
//! Component requests grant no Native Main, action Original, publisher loan or
//! acknowledgement. Raw fields remain live through every joined test callback.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crucible_qemu_shmem::{KIND_VM, NodeSlot};
use std::pin::Pin;

struct Fixture {
    reader: ProtectedReader,
    payload: *mut Payload,
    payload_serial: u64,
    holder: *mut PayloadBorrow,
    serial: u64,
    absent: u32,
    returned: u32,
}

fn fixture() -> (Pin<Box<Fixture>>, NodeSlot) {
    let mut fixture = Box::pin(Fixture {
        reader: ProtectedReader::new(),
        payload: std::ptr::null_mut(),
        payload_serial: 0,
        holder: std::ptr::null_mut(),
        serial: 0,
        absent: u32::MAX,
        returned: u32::MAX,
    });
    let slot = NodeSlot::new(KIND_VM);
    slot.request_control_boundary(73, Some(9)).unwrap();
    let inner = fixture.as_mut().get_mut();
    assert_eq!(inner.reader.read(&slot, None).status(), 0);
    // SAFETY: the fixture keeps the complete journal and disjoint canonical
    // output fields at these same pinned addresses throughout every test.
    unsafe {
        inner
            .reader
            .claim_payload(&mut inner.payload, &mut inner.payload_serial)
            .unwrap()
    };
    (fixture, slot)
}

impl Fixture {
    fn acquire(&mut self) -> Result<(), i32> {
        // SAFETY: this pinned fixture owns all exact disjoint canonical fields;
        // no field or payload reference escapes the owning test's local lifetime.
        unsafe {
            self.reader.acquire_payload_borrow(
                &mut self.payload,
                self.payload_serial,
                &mut self.holder,
                &mut self.serial,
                &mut self.absent,
            )
        }
    }

    fn release(&mut self) -> Result<(), i32> {
        // SAFETY: the same fixture retains the actual payload and output fields
        // until this real journal consumes the record and both original fields.
        unsafe {
            self.reader.release_payload_borrow(
                &mut self.payload,
                self.payload_serial,
                &mut self.holder,
                self.serial,
                &mut self.returned,
            )
        }
    }

    fn return_payload(&mut self) -> Result<(), i32> {
        // SAFETY: the original canonical field and pinned child remain live;
        // the real journal independently refuses every outstanding local borrow.
        unsafe {
            self.reader
                .return_payload(&mut self.payload, self.payload_serial)
        }
    }
}

#[test]
fn actual_borrow_blocks_payload_return_until_record_and_both_fields_close() {
    let (mut fixture, slot) = fixture();
    let fixture = fixture.as_mut().get_mut();
    fixture.acquire().unwrap();

    assert!(!fixture.holder.is_null());
    assert_ne!(fixture.serial, 0);
    assert_eq!(fixture.absent, 0);
    assert_eq!(fixture.return_payload(), Err(-libc::EBUSY));
    assert!(!fixture.payload.is_null());

    fixture.release().unwrap();
    assert_eq!(fixture.returned, 1);
    assert!(fixture.holder.is_null());
    assert_eq!(fixture.serial, 0);
    assert!(slot.control_boundary_is_requested());
    assert!(!fixture.payload.is_null());
    assert_eq!(fixture.return_payload(), Ok(()));
    assert!(fixture.payload.is_null());
    assert!(slot.control_boundary_is_requested());
}

#[test]
fn copied_borrow_holder_cannot_consume_the_actual_journal_record() {
    let (mut fixture, _) = fixture();
    let fixture = fixture.as_mut().get_mut();
    fixture.acquire().unwrap();
    let original = fixture.holder;
    let mut copied = original;
    let mut returned = u32::MAX;

    // SAFETY: the copied cell is writable and live, but deliberately differs
    // from the actual output field retained by the real journal.
    let result = unsafe {
        fixture.reader.release_payload_borrow(
            &mut fixture.payload,
            fixture.payload_serial,
            &mut copied,
            fixture.serial,
            &mut returned,
        )
    };
    assert_eq!(result, Err(-libc::ESTALE));
    assert_eq!(returned, 0);
    assert_eq!(copied, original);
    assert_eq!(fixture.holder, original);
    assert_eq!(fixture.return_payload(), Err(-libc::EBUSY));
    fixture.release().unwrap();
    fixture.return_payload().unwrap();
}

#[test]
fn stale_borrow_serial_retains_actual_fields_and_payload() {
    let (mut fixture, _) = fixture();
    let fixture = fixture.as_mut().get_mut();
    fixture.acquire().unwrap();
    let original = fixture.serial;
    let mut returned = u32::MAX;

    // SAFETY: all fields are the actual live originals; only the supplied
    // local serial is deliberately stale, and cannot select another record.
    let result = unsafe {
        fixture.reader.release_payload_borrow(
            &mut fixture.payload,
            fixture.payload_serial,
            &mut fixture.holder,
            original + 1,
            &mut returned,
        )
    };
    assert_eq!(result, Err(-libc::ESTALE));
    assert_eq!(returned, 0);
    assert_eq!(fixture.serial, original);
    assert!(!fixture.holder.is_null());
    assert_eq!(fixture.return_payload(), Err(-libc::EBUSY));
    fixture.release().unwrap();
}

#[test]
fn second_borrow_reports_its_known_absence_without_replacing_the_first() {
    let (mut fixture, _) = fixture();
    let fixture = fixture.as_mut().get_mut();
    fixture.acquire().unwrap();
    let original = (fixture.holder, fixture.serial);
    let mut holder = std::ptr::null_mut();
    let mut serial = 0;
    let mut absent = u32::MAX;

    // SAFETY: the second invocation has its own distinct empty outputs while
    // the pinned child and first actual borrower remain retained.
    let result = unsafe {
        fixture.reader.acquire_payload_borrow(
            &mut fixture.payload,
            fixture.payload_serial,
            &mut holder,
            &mut serial,
            &mut absent,
        )
    };
    assert_eq!(result, Err(-libc::EBUSY));
    assert_eq!(absent, 1);
    assert!(holder.is_null());
    assert_eq!(serial, 0);
    assert_eq!((fixture.holder, fixture.serial), original);
    fixture.release().unwrap();
}

#[test]
fn occupied_acquire_outputs_remain_unknown_and_preserve_the_original_borrow() {
    let (mut fixture, _) = fixture();
    let fixture = fixture.as_mut().get_mut();
    fixture.acquire().unwrap();
    let original = (fixture.holder, fixture.serial);
    assert_eq!(fixture.acquire(), Err(-libc::EINVAL));
    assert_eq!(fixture.absent, 0);
    assert_eq!((fixture.holder, fixture.serial), original);
    fixture.release().unwrap();
}

#[test]
fn exhausted_local_borrow_generation_never_wraps_or_creates_custody() {
    let (mut fixture, _) = fixture();
    let fixture = fixture.as_mut().get_mut();
    fixture.reader.journal.lock().unwrap().borrow_sequence = u64::MAX;
    assert_eq!(fixture.acquire(), Err(-libc::EOVERFLOW));
    assert_eq!(fixture.absent, 1);
    assert!(fixture.holder.is_null());
    assert_eq!(fixture.serial, 0);
    assert_eq!(
        fixture.reader.journal.lock().unwrap().borrow_sequence,
        u64::MAX
    );
    fixture.return_payload().unwrap();
}

#[test]
fn held_actual_journal_refuses_release_without_consuming_any_output() {
    let (mut fixture, _) = fixture();
    let fixture = fixture.as_mut().get_mut();
    fixture.acquire().unwrap();
    let original = (fixture.holder, fixture.serial);
    let guard = fixture.reader.journal.lock().unwrap();
    // SAFETY: the actual fields stay live while the deliberately held journal
    // mutex forces a genuine nonblocking refusal before any record mutation.
    let result = unsafe {
        fixture.reader.release_payload_borrow(
            &mut fixture.payload,
            fixture.payload_serial,
            &mut fixture.holder,
            fixture.serial,
            &mut fixture.returned,
        )
    };
    assert_eq!(result, Err(-libc::EBUSY));
    assert_eq!(fixture.returned, 0);
    assert_eq!((fixture.holder, fixture.serial), original);
    drop(guard);
    fixture.release().unwrap();
}

#[test]
fn poisoned_actual_journal_retains_borrow_and_canonical_payload() {
    let (mut fixture, _) = fixture();
    let fixture = fixture.as_mut().get_mut();
    fixture.acquire().unwrap();
    let original = (fixture.holder, fixture.serial, fixture.payload);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _held = fixture.reader.journal.lock().unwrap();
        panic!("interrupt the actual payload borrower journal");
    }));
    assert!(result.is_err());
    assert_eq!(fixture.release(), Err(-libc::EOWNERDEAD));
    assert_eq!(fixture.returned, 0);
    assert_eq!((fixture.holder, fixture.serial, fixture.payload), original);
    assert_eq!(fixture.return_payload(), Err(-libc::EOWNERDEAD));
}

#[test]
fn foreign_actual_thread_cannot_consume_the_original_borrow() {
    let (mut fixture, _) = fixture();
    let fixture = fixture.as_mut().get_mut();
    fixture.acquire().unwrap();
    let reader = std::ptr::from_ref(&fixture.reader) as usize;
    let payload = std::ptr::from_mut(&mut fixture.payload) as usize;
    let holder = std::ptr::from_mut(&mut fixture.holder) as usize;
    let payload_serial = fixture.payload_serial;
    let serial = fixture.serial;

    std::thread::scope(|scope| {
        scope
            .spawn(move || {
                let mut returned = u32::MAX;
                // SAFETY: the fixture remains pinned and the parent neither reads
                // nor writes its fields until join. Only the actual journal mutex
                // is accessed concurrently; this real foreign actor must refuse.
                let result = unsafe {
                    (&*(reader as *const ProtectedReader)).release_payload_borrow(
                        payload as *mut *mut Payload,
                        payload_serial,
                        holder as *mut *mut PayloadBorrow,
                        serial,
                        &mut returned,
                    )
                };
                assert_eq!(result, Err(-libc::ESTALE));
                assert_eq!(returned, 0);
            })
            .join()
            .unwrap();
    });
    assert!(!fixture.holder.is_null());
    assert_eq!(fixture.serial, serial);
    fixture.release().unwrap();
}

#[test]
fn copied_payload_field_cannot_nominate_the_actual_local_borrow() {
    let (mut fixture, _) = fixture();
    let fixture = fixture.as_mut().get_mut();
    let mut copy = fixture.payload;
    // SAFETY: the copied payload cell is live but deliberately differs from
    // the actual canonical field; every output is a genuine empty fixture cell.
    let result = unsafe {
        fixture.reader.acquire_payload_borrow(
            &mut copy,
            fixture.payload_serial,
            &mut fixture.holder,
            &mut fixture.serial,
            &mut fixture.absent,
        )
    };
    assert_eq!(result, Err(-libc::ESTALE));
    assert_eq!(fixture.absent, 1);
    assert!(fixture.holder.is_null());
    assert_eq!(fixture.serial, 0);
    fixture.acquire().unwrap();
    fixture.release().unwrap();
}

#[test]
fn returned_borrow_serial_cannot_consume_a_later_real_borrow() {
    let (mut fixture, _) = fixture();
    let fixture = fixture.as_mut().get_mut();
    fixture.acquire().unwrap();
    let retired = fixture.serial;
    fixture.release().unwrap();
    fixture.acquire().unwrap();
    let current = fixture.serial;
    assert!(current > retired);
    // SAFETY: the original fields remain pinned, but this call deliberately
    // supplies the already consumed generation instead of the actual new one.
    let result = unsafe {
        fixture.reader.release_payload_borrow(
            &mut fixture.payload,
            fixture.payload_serial,
            &mut fixture.holder,
            retired,
            &mut fixture.returned,
        )
    };
    assert_eq!(result, Err(-libc::ESTALE));
    assert_eq!(fixture.returned, 0);
    assert_eq!(fixture.serial, current);
    assert!(!fixture.holder.is_null());
    fixture.release().unwrap();
}

#[test]
fn contended_acquire_reports_only_its_own_actual_no_mutation() {
    let (mut fixture, _) = fixture();
    let fixture = fixture.as_mut().get_mut();
    let guard = fixture.reader.journal.lock().unwrap();
    // SAFETY: all fields are actual pinned empty outputs; the held mutex forces
    // a genuine refusal before this invocation can create a borrower record.
    let result = unsafe {
        fixture.reader.acquire_payload_borrow(
            &mut fixture.payload,
            fixture.payload_serial,
            &mut fixture.holder,
            &mut fixture.serial,
            &mut fixture.absent,
        )
    };
    assert_eq!(result, Err(-libc::EBUSY));
    assert_eq!(fixture.absent, 1);
    assert!(fixture.holder.is_null());
    assert_eq!(fixture.serial, 0);
    drop(guard);
    fixture.acquire().unwrap();
    fixture.release().unwrap();
}

#[test]
fn altered_original_serial_field_retains_the_actual_borrow_record() {
    let (mut fixture, _) = fixture();
    let fixture = fixture.as_mut().get_mut();
    fixture.acquire().unwrap();
    let original = fixture.serial;
    fixture.serial = 0;
    // SAFETY: both actual fields remain live. The original scalar argument is
    // valid but its deliberately altered output cell must prevent consumption.
    let result = unsafe {
        fixture.reader.release_payload_borrow(
            &mut fixture.payload,
            fixture.payload_serial,
            &mut fixture.holder,
            original,
            &mut fixture.returned,
        )
    };
    assert_eq!(result, Err(-libc::ESTALE));
    assert_eq!(fixture.returned, 0);
    assert!(!fixture.holder.is_null());
    assert_eq!(fixture.return_payload(), Err(-libc::EBUSY));
    fixture.serial = original;
    fixture.release().unwrap();
}
