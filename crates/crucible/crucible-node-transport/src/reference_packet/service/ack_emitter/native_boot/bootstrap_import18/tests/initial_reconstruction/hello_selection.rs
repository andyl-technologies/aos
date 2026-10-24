//! Exercises actual retained native Hello selection before negotiation or models.

use super::super::super::hello_selection::OriginalImport18HelloSelectionAdmission;
use super::*;
use std::cell::Cell;

struct Admission<'a> {
    case: &'a str,
    calls: Cell<usize>,
    row: Cell<Option<[usize; 3]>>,
    before: usize,
}

impl OriginalImport18HelloSelectionAdmission for Admission<'_> {
    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        row: [usize; 3],
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(1), 0);
        assert!(original.hello_started);
        assert!(!original.hello_complete);
        assert!(original.hello_declaration.is_some());
        assert_eq!(original.hello_construction_row, Some(row));
        assert_eq!(
            original.retained_requested_bytes().unwrap(),
            self.before + original.hello_selection_backing_data().unwrap()
        );
        assert!(row.into_iter().all(|axis| axis > 0));
        self.row.set(Some(row));
        if let Some(axis) = self.case.strip_prefix("initial_hello_short_") {
            let axis: usize = axis.parse().unwrap();
            let mut allowed = row;
            allowed[axis] -= 1;
            assert!(
                row.into_iter()
                    .zip(allowed)
                    .any(|(demand, limit)| demand > limit)
            );
            return Err(ProviderError::ResourceExhausted(
                "actual Hello selection admission",
            ));
        }
        if self.case == "initial_hello_construct_refused" {
            return Err(ProviderError::Conflict("actual Hello construction"));
        }
        if self.case == "initial_hello_construct_expired" {
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
        assert_eq!(original.hello_selection_backing_data().unwrap(), actual);
        assert!(actual <= self.row.get().unwrap()[0]);
        assert_eq!(
            original.retained_requested_bytes().unwrap(),
            self.before + actual
        );
        if self.case == "initial_hello_finish_refused" {
            return Err(ProviderError::Conflict("actual Hello terminal admission"));
        }
        if self.case == "initial_hello_finish_expired" {
            std::thread::sleep(Duration::from_secs(5));
        }
        Ok(())
    }
}

pub(super) fn construct_for_frames(owner: &mut OriginalImport18RawBootstrap) {
    super::selection::authenticate_for_hello(owner);
    let admission = Admission {
        case: "initial_hello_complete",
        calls: Cell::new(0),
        row: Cell::new(None),
        before: owner.retained_requested_bytes().unwrap(),
    };
    owner.construct_hello_selection_data(&admission).unwrap();
    assert!(owner.hello_complete);
    assert_eq!(admission.calls.get(), 2);
}

pub(super) fn assert_child(case: &str, owner: &mut OriginalImport18RawBootstrap) {
    if case != "initial_hello_unchecked_selection" {
        super::selection::authenticate_for_hello(owner);
    }
    let before = owner.retained_requested_bytes().unwrap();
    let pointers = owner.bodies.each_ref().map(|body| body.as_ptr());
    let admission = Admission {
        case,
        calls: Cell::new(0),
        row: Cell::new(None),
        before,
    };
    if case == "initial_hello_incomplete" {
        owner.initial_reconstructed = false;
    }
    if case == "initial_hello_before_expired" {
        owner.cut = OperationalDeadline::expired_fixture();
    }
    if case == "initial_hello_occupied" {
        owner.hello_selection = Some((Vec::new(), Default::default()));
    }
    let result = owner.construct_hello_selection_data(&admission);
    let complete = matches!(
        case,
        "initial_hello_complete"
            | "initial_hello_reactive"
            | "initial_hello_callback_refused"
            | "initial_hello_loan_expired"
    );
    assert_eq!(result.is_ok(), complete);
    assert_eq!(owner.hello_complete, complete);
    assert!(owner.hello_started);
    assert_eq!(
        admission.calls.get(),
        match case {
            "initial_hello_incomplete"
            | "initial_hello_before_expired"
            | "initial_hello_unchecked_selection" => 0,
            "initial_hello_construct_refused" | "initial_hello_construct_expired" => 1,
            _ if case.starts_with("initial_hello_short_") => 1,
            _ => 2,
        }
    );
    let retained = owner.retained_requested_bytes().unwrap();
    if complete {
        let mut inspected = false;
        let borrowed = owner.with_hello_selection_data(|selection| {
            inspected = true;
            assert!(std::ptr::eq(
                selection,
                owner.hello_selection.as_ref().unwrap()
            ));
            assert!(selection.0.windows(2).all(|pair| pair[0] < pair[1]));
            assert!(selection.0.iter().any(
                |feature| feature.as_str() == "source-owned.packet-native-import-bootstrap/18"
            ));
            assert!(
                selection
                    .1
                    .contains_key("source-owned.packet-native-import-bootstrap-ack-proof/18")
            );
            for feature in selection.1.values() {
                assert!(selection.0.contains(feature));
            }
            if case == "initial_hello_callback_refused" {
                return Err(ProviderError::Conflict("actual Hello selection callback"));
            }
            if case == "initial_hello_loan_expired" {
                std::thread::sleep(Duration::from_secs(5));
            }
            Ok(selection.0.len())
        });
        assert!(inspected);
        assert_eq!(
            borrowed.is_ok(),
            matches!(case, "initial_hello_complete" | "initial_hello_reactive")
        );
    } else {
        assert!(owner.with_hello_selection_data(|_| Ok(())).is_err());
    }
    assert!(owner.construct_hello_selection_data(&admission).is_err());
    assert_eq!(owner.retained_requested_bytes().unwrap(), retained);
    assert_eq!(owner.bodies.each_ref().map(|body| body.as_ptr()), pointers);
    assert!(owner.inputs.is_empty_data());
    if matches!(
        case,
        "initial_hello_finish_refused" | "initial_hello_finish_expired"
    ) {
        assert!(!owner.hello_selection.as_ref().unwrap().0.is_empty());
    }
    if case == "initial_hello_occupied" {
        assert!(owner.hello_selection.as_ref().unwrap().0.is_empty());
    }
}

#[test]
fn native_hello_roster_stays_in_original_initial_custody_on_every_outcome() {
    assert!(
        OriginalImport18RawBootstrap::hello_selection_loan_counter_scratch_data::<usize>()
            > size_of::<usize>()
    );
    for case in [
        "initial_hello_complete",
        "initial_hello_reactive",
        "initial_hello_incomplete",
        "initial_hello_unchecked_selection",
        "initial_hello_before_expired",
        "initial_hello_construct_refused",
        "initial_hello_finish_refused",
        "initial_hello_construct_expired",
        "initial_hello_finish_expired",
        "initial_hello_occupied",
        "initial_hello_callback_refused",
        "initial_hello_loan_expired",
        "initial_hello_short_0",
        "initial_hello_short_1",
        "initial_hello_short_2",
    ] {
        flight(case);
    }
}
