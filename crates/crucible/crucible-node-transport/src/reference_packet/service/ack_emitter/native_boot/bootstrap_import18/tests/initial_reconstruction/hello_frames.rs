//! Exercises actual native Hello bank construction in original bootstrap custody.

use super::super::super::hello_frames::OriginalImport18HelloFramesAdmission;
use super::*;
use std::cell::Cell;

struct Admission<'a> {
    case: &'a str,
    calls: Cell<usize>,
    before: usize,
    row: Cell<Option<[usize; 3]>>,
}

impl OriginalImport18HelloFramesAdmission for Admission<'_> {
    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        row: [usize; 3],
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(1), 0);
        assert!(row.into_iter().all(|axis| axis > 0));
        assert_eq!(original.hello_frames_row, Some(row));
        assert_eq!(original.retained_requested_bytes().unwrap(), self.before);
        self.row.set(Some(row));
        if self.case == "initial_hello_frames_construct_refused" {
            return Err(ProviderError::Conflict("actual Hello literal admission"));
        }
        if self.case == "initial_hello_frames_construct_expired" {
            std::thread::sleep(Duration::from_secs(5));
        }
        Ok(())
    }

    fn finish_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        actual: usize,
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(2), 1);
        assert!(actual <= self.row.get().unwrap()[0]);
        assert_eq!(original.hello_frames_backing_data().unwrap(), actual);
        assert_eq!(
            original.retained_requested_bytes().unwrap(),
            self.before + actual
        );
        if self.case == "initial_hello_frames_finish_refused" {
            return Err(ProviderError::Conflict("actual Hello literal terminal"));
        }
        if self.case == "initial_hello_frames_finish_expired" {
            std::thread::sleep(Duration::from_secs(5));
        }
        Ok(())
    }
}

pub(super) fn construct_for_channel(owner: &mut OriginalImport18RawBootstrap) {
    super::hello_selection::construct_for_frames(owner);
    let admission = Admission {
        case: "initial_hello_frames_complete",
        calls: Cell::new(0),
        before: owner.retained_requested_bytes().unwrap(),
        row: Cell::new(None),
    };
    owner.construct_hello_frames_data(&admission).unwrap();
    assert!(owner.hello_frames_complete);
    assert_eq!(admission.calls.get(), 2);
}

pub(super) fn assert_child(case: &str, owner: &mut OriginalImport18RawBootstrap) {
    if case != "initial_hello_frames_unchecked_roster" {
        super::hello_selection::construct_for_frames(owner);
    }
    let before = owner.retained_requested_bytes().unwrap();
    let pointers = owner.bodies.each_ref().map(|body| body.as_ptr());
    let admission = Admission {
        case,
        calls: Cell::new(0),
        before,
        row: Cell::new(None),
    };
    if case == "initial_hello_frames_before_expired" {
        owner.cut = OperationalDeadline::expired_fixture();
    }
    if case == "initial_hello_frames_occupied" {
        assert!(
            crate::native_hello::OriginalNativeHelloReservation::reserve_into_data(
                0,
                64,
                &mut owner.hello_frames,
            )
            .is_err()
        );
    }
    let outcome = owner.construct_hello_frames_data(&admission);
    let complete = matches!(
        case,
        "initial_hello_frames_complete"
            | "initial_hello_frames_reactive"
            | "initial_hello_frames_callback_refused"
            | "initial_hello_frames_loan_expired"
    );
    assert_eq!(outcome.is_ok(), complete, "{case}: {outcome:?}");
    assert_eq!(owner.hello_frames_complete, complete);
    assert!(owner.hello_frames_started);
    assert_eq!(
        admission.calls.get(),
        match case {
            "initial_hello_frames_unchecked_roster" | "initial_hello_frames_before_expired" => 0,
            "initial_hello_frames_construct_refused" | "initial_hello_frames_construct_expired" =>
                1,
            _ => 2,
        }
    );

    let retained = owner.retained_requested_bytes().unwrap();
    if complete {
        let mut pointer = None;
        let outcome = owner.with_hello_frames_data(|journal| {
            pointer = Some(journal as *const crate::native_hello::OriginalNativeHelloJournal);
            assert!(journal.original_frames().frames().next().is_none());
            assert!(journal.original_literal_frame_digests().is_err());
            if case == "initial_hello_frames_callback_refused" {
                return Err(ProviderError::Conflict("actual Hello literal callback"));
            }
            if case == "initial_hello_frames_loan_expired" {
                std::thread::sleep(Duration::from_secs(5));
            }
            Ok(journal.allocated_bytes())
        });
        assert!(pointer.is_some());
        assert_eq!(
            outcome.is_ok(),
            matches!(
                case,
                "initial_hello_frames_complete" | "initial_hello_frames_reactive"
            )
        );
        if outcome.is_ok() {
            owner
                .with_hello_frames_data(|journal| {
                    assert!(std::ptr::eq(pointer.unwrap(), journal));
                    Ok(())
                })
                .unwrap();
        }
    } else {
        assert!(owner.with_hello_frames_data(|_| Ok(())).is_err());
    }
    assert!(owner.construct_hello_frames_data(&admission).is_err());
    assert_eq!(owner.retained_requested_bytes().unwrap(), retained);
    assert_eq!(owner.bodies.each_ref().map(|body| body.as_ptr()), pointers);
    assert!(owner.inputs.is_empty_data());
    if case == "initial_hello_frames_occupied" {
        assert!(owner.hello_frames.is_some());
        assert_eq!(owner.hello_frames_backing_data().unwrap(), 0);
    }
}

#[test]
fn actual_hello_literals_stay_in_the_same_initial_owner_after_every_outcome() {
    assert!(
        OriginalImport18RawBootstrap::hello_frames_loan_counter_scratch_data::<usize>()
            > size_of::<usize>()
    );
    for case in [
        "initial_hello_frames_complete",
        "initial_hello_frames_reactive",
        "initial_hello_frames_unchecked_roster",
        "initial_hello_frames_before_expired",
        "initial_hello_frames_construct_refused",
        "initial_hello_frames_construct_expired",
        "initial_hello_frames_finish_refused",
        "initial_hello_frames_finish_expired",
        "initial_hello_frames_occupied",
        "initial_hello_frames_callback_refused",
        "initial_hello_frames_loan_expired",
    ] {
        flight(case);
    }
}
