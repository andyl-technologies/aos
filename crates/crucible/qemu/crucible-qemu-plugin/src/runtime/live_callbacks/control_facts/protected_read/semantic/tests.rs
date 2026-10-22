//! Exercises the real module journal's semantic custody and field consumption.
//!
//! Component sample requests and worker receipt inputs exercise local ownership;
//! they issue no native Main, publisher subscription, Original or RAM permission.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::runtime::live_callbacks::fingerprint_worker::{CaptureReceipt, CaptureReceiptSnapshot};
use crucible_qemu_shmem::{FingerprintSampleSlot, KIND_VM, NodeSlot};
use std::pin::Pin;

struct Fixture {
    reader: ProtectedReader,
    slot: NodeSlot,
    sampler: FingerprintSampleSlot,
    payload: *mut Payload,
    payload_serial: u64,
    borrowed: *mut PayloadBorrow,
    borrow_serial: u64,
    action: *mut FingerprintAction,
    action_serial: u64,
    absent: u32,
    returned: u32,
    final_evidence: FingerprintActionEvidence,
}

impl Fixture {
    fn new() -> Pin<Box<Self>> {
        let mut fixture = Box::pin(Self {
            reader: ProtectedReader::new(),
            slot: NodeSlot::new(KIND_VM),
            sampler: FingerprintSampleSlot::new(),
            payload: std::ptr::null_mut(),
            payload_serial: 0,
            borrowed: std::ptr::null_mut(),
            borrow_serial: 0,
            action: std::ptr::null_mut(),
            action_serial: 0,
            absent: u32::MAX,
            returned: u32::MAX,
            final_evidence: FingerprintActionEvidence::sample(4).unwrap(),
        });
        let inner = fixture.as_mut().get_mut();
        let capture = inner.sampler.request_capture_v1();
        inner
            .slot
            .request_control_boundary(73, Some(capture))
            .unwrap();
        assert_eq!(
            inner
                .reader
                .read(&inner.slot, Some(&inner.sampler))
                .status(),
            0
        );
        // SAFETY: this fixture pins the real journal and every exact original
        // field through all calls; no payload reference or Native grant escapes.
        unsafe {
            inner
                .reader
                .claim_payload(&mut inner.payload, &mut inner.payload_serial)
                .unwrap();
            inner
                .reader
                .acquire_payload_borrow(
                    &mut inner.payload,
                    inner.payload_serial,
                    &mut inner.borrowed,
                    &mut inner.borrow_serial,
                    &mut inner.absent,
                )
                .unwrap();
        }
        fixture
    }

    fn input(&mut self) -> SemanticPayloadBorrow {
        SemanticPayloadBorrow {
            payload_holder: &mut self.payload,
            payload_serial: self.payload_serial,
            borrow_holder: &mut self.borrowed,
            borrow_serial: self.borrow_serial,
        }
    }

    fn enter(&mut self, class: u32, floor: u64) -> Result<FingerprintActionEvidence, i32> {
        let input = self.input();
        // SAFETY: all original inputs/outputs remain in this same pinned owner.
        unsafe {
            self.reader.enter_fingerprint_action(
                input,
                &mut self.action,
                &mut self.action_serial,
                &mut self.absent,
                (class, floor),
            )
        }
    }

    fn post(&mut self) -> Result<(FingerprintActionEvidence, i32, i32), i32> {
        let input = self.input();
        // SAFETY: this is the same actual journal and exact original fields.
        unsafe {
            self.reader
                .post_fingerprint_action(input, &mut self.action, self.action_serial)
        }
    }

    fn observe(
        &mut self,
        worker: CaptureReceiptSnapshot,
    ) -> Result<FingerprintActionEvidence, i32> {
        let input = self.input();
        // SAFETY: the fixture keeps every original field live through observation.
        unsafe {
            self.reader.current_fingerprint_action(
                input,
                &mut self.action,
                self.action_serial,
                worker,
            )
        }
    }

    fn close(&mut self, worker: CaptureReceiptSnapshot) -> Result<(), i32> {
        let input = self.input();
        // SAFETY: original fields remain pinned and disjoint through consumption.
        unsafe {
            self.reader.return_fingerprint_action(
                input,
                &mut self.action,
                &mut self.action_serial,
                &mut self.final_evidence,
                &mut self.returned,
                worker,
            )
        }
    }

    fn dispatch(&self, first: i32) {
        assert_eq!(
            self.reader.begin_semantic_dispatch(
                self.slot.control_boundary_token(),
                self.slot.control_boundary_capture_request(),
            ),
            Ok(true)
        );
        self.reader.finish_semantic_dispatch(first).unwrap();
    }
}

fn quiet(sequence: u64) -> CaptureReceiptSnapshot {
    CaptureReceiptSnapshot {
        sequence,
        returned: [None; 2],
        quiet: true,
        closed: false,
    }
}

fn complete(fixture: &Fixture, epoch: u64, physically_quiet: bool) -> CaptureReceiptSnapshot {
    CaptureReceiptSnapshot {
        sequence: epoch,
        returned: [
            Some(CaptureReceipt {
                epoch,
                capture: fixture.sampler.capture_request_generation(),
                sample_completed: true,
                first: 0,
            }),
            None,
        ],
        quiet: physically_quiet,
        closed: false,
    }
}

#[test]
fn callback_post_and_completion_cannot_replace_actual_worker_return() {
    let mut fixture = Fixture::new();
    let evidence = fixture.enter(4, 0).unwrap();
    assert_eq!(evidence.primary_class, 4);
    assert_eq!(evidence.required_units, 1);
    assert_eq!(evidence.completed_required_units, 0);
    fixture.dispatch(0);
    assert_eq!(fixture.post().unwrap().1, 0);

    assert_eq!(fixture.close(quiet(0)), Err(-libc::EBUSY));
    assert_eq!(fixture.returned, 0);
    assert!(!fixture.action.is_null());
    let published = complete(&fixture, 1, false);
    assert_eq!(
        fixture.observe(published).unwrap().completed_required_units,
        1
    );
    assert_eq!(fixture.close(published), Err(-libc::EBUSY));

    let closed = complete(&fixture, 1, true);
    fixture.close(closed).unwrap();
    assert!(fixture.action.is_null());
    assert_eq!(fixture.action_serial, 0);
    assert_eq!(fixture.returned, 1);
}

#[test]
fn semantic_owner_pins_the_actual_payload_borrow() {
    let mut fixture = Fixture::new();
    fixture.enter(5, 0).unwrap();
    let inner = fixture.as_mut().get_mut();
    // SAFETY: the original payload/borrow fields remain at their pinned addresses.
    let result = unsafe {
        inner.reader.release_payload_borrow(
            &mut inner.payload,
            inner.payload_serial,
            &mut inner.borrowed,
            inner.borrow_serial,
            &mut inner.returned,
        )
    };
    assert_eq!(result, Err(-libc::EBUSY));
    assert!(!fixture.borrowed.is_null());
    assert!(!fixture.action.is_null());
    assert_eq!(fixture.returned, 0);
}

#[test]
fn copied_action_field_cannot_observe_or_consume_the_real_owner() {
    let mut fixture = Fixture::new();
    fixture.enter(4, 0).unwrap();
    let input = fixture.input();
    let mut copied = fixture.action;
    // SAFETY: the copied cell is local and live, but has no canonical custody.
    let result = unsafe {
        fixture.reader.current_fingerprint_action(
            input,
            &mut copied,
            fixture.action_serial,
            quiet(0),
        )
    };
    assert_eq!(result, Err(-libc::ESTALE));
    assert_eq!(copied, fixture.action);
    assert!(!fixture.action.is_null());
}

#[test]
fn copied_serial_cell_cannot_consume_after_genuine_completion() {
    let mut fixture = Fixture::new();
    fixture.enter(5, 0).unwrap();
    fixture.dispatch(0);
    fixture.post().unwrap();
    let closed = complete(&fixture, 1, true);
    let input = fixture.input();
    let serial = fixture.action_serial;
    let inner = fixture.as_mut().get_mut();
    let mut copied_serial = serial;
    // SAFETY: the fixture keeps actual and copied fields live and distinct.
    let result = unsafe {
        inner.reader.return_fingerprint_action(
            input,
            &mut inner.action,
            &mut copied_serial,
            &mut inner.final_evidence,
            &mut inner.returned,
            closed,
        )
    };
    assert_eq!(result, Err(-libc::ESTALE));
    assert_eq!(copied_serial, serial);
    assert_eq!(fixture.action_serial, serial);
    assert_eq!(fixture.returned, 0);
}

#[test]
fn local_serial_exhaustion_refuses_before_semantic_birth() {
    let mut fixture = Fixture::new();
    fixture.reader.journal.lock().unwrap().action_sequence = u64::MAX;
    assert_eq!(fixture.enter(4, 0), Err(-libc::EOVERFLOW));
    assert_eq!(fixture.absent, 1);
    assert!(fixture.action.is_null());
    assert_eq!(fixture.action_serial, 0);
}

#[test]
fn post_requires_actual_dispatch_and_preserves_prework_failure() {
    let mut fixture = Fixture::new();
    fixture.enter(4, 12).unwrap();
    assert_eq!(fixture.post(), Err(-libc::EBUSY));
    fixture.dispatch(-libc::ECANCELED);
    assert_eq!(fixture.post().unwrap().1, -libc::ECANCELED);
    assert_eq!(fixture.post().unwrap().1, -libc::ECANCELED);

    fixture.close(quiet(12)).unwrap();
    assert_eq!(fixture.returned, 1);
    assert!(fixture.action.is_null());
}

#[test]
fn old_or_foreign_capture_receipt_never_completes_this_branch() {
    let mut fixture = Fixture::new();
    fixture.enter(5, 9).unwrap();
    fixture.dispatch(0);
    fixture.post().unwrap();
    let old = complete(&fixture, 9, true);
    assert_eq!(fixture.observe(old).unwrap().completed_required_units, 0);
    assert_eq!(fixture.close(old), Err(-libc::EBUSY));

    let mut foreign = complete(&fixture, 10, true);
    foreign.returned[0].as_mut().unwrap().capture ^= 2;
    assert_eq!(fixture.observe(foreign), Err(-libc::EPROTO));
    assert_eq!(fixture.close(foreign), Err(-libc::EPROTO));
    assert!(!fixture.action.is_null());
    assert_eq!(fixture.returned, 0);
}

#[test]
fn unsupported_class_cannot_echo_a_caller_selected_operation() {
    let mut fixture = Fixture::new();
    assert_eq!(fixture.enter(1, 0), Err(-libc::EOPNOTSUPP));
    assert!(fixture.action.is_null());
    assert_eq!(fixture.action_serial, 0);
    assert_eq!(fixture.absent, 1);
}

#[test]
fn altered_original_serial_and_contended_journal_preserve_custody() {
    let mut fixture = Fixture::new();
    fixture.enter(4, 0).unwrap();
    let serial = fixture.action_serial;
    fixture.action_serial += 1;
    assert_eq!(fixture.observe(quiet(0)), Err(-libc::ESTALE));
    fixture.action_serial = serial;
    let input = fixture.input();
    let action_holder = &mut fixture.action as *mut _;
    let guard = fixture.reader.journal.lock().unwrap();
    // SAFETY: the same pinned fields remain live; contention must refuse first.
    let result = unsafe {
        fixture
            .reader
            .current_fingerprint_action(input, action_holder, serial, quiet(0))
    };
    assert_eq!(result, Err(-libc::EBUSY));
    drop(guard);
    assert!(!fixture.action.is_null());
    assert_eq!(fixture.action_serial, serial);
}

#[test]
fn consumed_semantic_owner_cannot_reissue_from_the_same_retained_payload() {
    let mut fixture = Fixture::new();
    fixture.enter(4, 0).unwrap();
    fixture.dispatch(0);
    fixture.post().unwrap();
    let closed = complete(&fixture, 1, true);
    fixture.close(closed).unwrap();

    assert_eq!(fixture.enter(4, 1), Err(-libc::EALREADY));
    assert!(fixture.action.is_null());
    assert_eq!(fixture.action_serial, 0);
    assert_eq!(fixture.absent, 1);
    assert!(!fixture.borrowed.is_null());
}

#[test]
fn worker_failure_preserves_callback_history_and_reports_real_consumption() {
    let mut fixture = Fixture::new();
    fixture.enter(5, 0).unwrap();
    fixture.dispatch(0);
    assert_eq!(fixture.post().unwrap().1, 0);
    let mut closed = complete(&fixture, 1, true);
    closed.returned[0].as_mut().unwrap().first = -libc::EIO;

    assert_eq!(fixture.observe(closed), Err(-libc::EIO));
    assert_eq!(fixture.post().unwrap().1, 0);
    assert_eq!(fixture.close(closed), Err(-libc::EIO));

    assert!(fixture.action.is_null());
    assert_eq!(fixture.action_serial, 0);
    assert_eq!(fixture.returned, 1);
}

#[test]
fn final_return_preserves_asynchronous_evidence_before_consumption() {
    let mut fixture = Fixture::new();
    fixture.enter(5, 0).unwrap();
    fixture.dispatch(0);
    assert_eq!(fixture.post().unwrap().0.completed_required_units, 0);
    let closed = complete(&fixture, 1, true);

    fixture.close(closed).unwrap();

    assert!(fixture.action.is_null());
    assert_eq!(fixture.returned, 1);
    assert_eq!(fixture.final_evidence.primary_class, 5);
    assert_eq!(fixture.final_evidence.required_units, 1);
    assert_eq!(fixture.final_evidence.completed_required_units, 1);
    assert_eq!(fixture.final_evidence.preparation_present, 0);
}

#[test]
fn failed_unpublished_return_keeps_its_incomplete_unit_and_physical_fact() {
    let mut fixture = Fixture::new();
    fixture.enter(5, 0).unwrap();
    fixture.dispatch(0);
    fixture.post().unwrap();
    let mut closed = complete(&fixture, 1, true);
    let receipt = closed.returned[0].as_mut().unwrap();
    receipt.sample_completed = false;

    assert_eq!(fixture.close(closed), Err(-libc::EPROTO));
    assert!(!fixture.action.is_null());
    assert_eq!(fixture.returned, 0);

    closed.returned[0].as_mut().unwrap().first = -libc::EIO;

    assert_eq!(fixture.close(closed), Err(-libc::EIO));

    assert!(fixture.action.is_null());
    assert_eq!(fixture.returned, 1);
    assert_eq!(fixture.final_evidence.primary_class, 5);
    assert_eq!(fixture.final_evidence.completed_required_units, 0);
}

#[test]
fn failed_dispatch_retains_prequeue_debt_without_requiring_a_born_work_receipt() {
    let mut fixture = Fixture::new();
    fixture.enter(5, 3).unwrap();
    fixture.dispatch(-libc::EIO);
    fixture.post().unwrap();
    let mut no_work = quiet(4);
    no_work.quiet = false;

    assert_eq!(fixture.close(no_work), Err(-libc::EBUSY));
    assert!(!fixture.action.is_null());
    assert_eq!(fixture.returned, 0);

    no_work.quiet = true;
    fixture.close(no_work).unwrap();

    assert!(fixture.action.is_null());
    assert_eq!(fixture.returned, 1);
    assert_eq!(fixture.final_evidence.completed_required_units, 0);
}
