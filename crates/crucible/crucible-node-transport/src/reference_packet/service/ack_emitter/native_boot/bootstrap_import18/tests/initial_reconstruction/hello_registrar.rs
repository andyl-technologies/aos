//! Exercises fresh registrar construction under original inherited bootstrap custody.

use super::super::super::hello_registrar::OriginalImport18HelloRegistrarAdmission;
use super::*;
use crate::handshake::ExtensionHandshake;
use std::cell::Cell;

pub(super) fn prepare_selected(case: &str, selected: &mut Value) {
    // Earlier definition controls deliberately use an inert membership roster.
    // A real issuer also validates strict (ID, edition) order. Preserve the
    // original malformed order in one control to observe its retained failure.
    if case == "initial_hello_registrar_invalid_installation" {
        return;
    }
    for implementation in [
        "/launch/selection/provider/implementation",
        "/launch/selection/realization/bindings/0/compatibility/implementation",
    ] {
        selected.pointer_mut(implementation).unwrap()["formats"]
            .as_array_mut()
            .unwrap()
            .sort_by(|left, right| {
                (
                    left["id"].as_str().unwrap(),
                    left["version"].as_u64().unwrap(),
                )
                    .cmp(&(
                        right["id"].as_str().unwrap(),
                        right["version"].as_u64().unwrap(),
                    ))
            });
    }
}

struct Admission<'a> {
    case: &'a str,
    calls: Cell<usize>,
    before: usize,
    row: Cell<Option<[usize; 3]>>,
}

impl OriginalImport18HelloRegistrarAdmission for Admission<'_> {
    fn quote_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        scratch: usize,
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(1), 0);
        assert!(scratch > 0);
        assert!(original.hello_registrar.row_fixture_data().is_none());
        assert_eq!(original.hello_registrar.retained_backing_data().unwrap(), 0);
        assert_eq!(original.retained_requested_bytes().unwrap(), self.before);
        if self.case == "initial_hello_registrar_quote_refused" {
            return Err(ProviderError::Conflict("registrar quote admission"));
        }
        if self.case == "initial_hello_registrar_quote_expired" {
            std::thread::sleep(Duration::from_secs(5));
        }
        Ok(())
    }

    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        row: [usize; 3],
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(2), 1);
        assert_eq!(original.hello_registrar.row_fixture_data(), Some(row));
        assert!(row.into_iter().all(|axis| axis > 0));
        assert!(original.hello_registrar.wrapper_fixture_data().is_none());
        assert_eq!(original.retained_requested_bytes().unwrap(), self.before);
        self.row.set(Some(row));
        if self.case == "initial_hello_registrar_construct_refused" {
            return Err(ProviderError::Conflict("registrar constructor admission"));
        }
        if self.case == "initial_hello_registrar_construct_expired" {
            std::thread::sleep(Duration::from_secs(5));
        }
        Ok(())
    }

    fn finish_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        actual: usize,
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(3), 2);
        assert_eq!(
            original.hello_registrar.retained_backing_data().unwrap(),
            actual
        );
        assert!(actual <= self.row.get().unwrap()[0]);
        assert_eq!(
            original.retained_requested_bytes().unwrap(),
            self.before + actual
        );
        assert_eq!(
            original.hello_registrar.wrapper_fixture_data().is_some(),
            !matches!(
                self.case,
                "initial_hello_registrar_construct_expired"
                    | "initial_hello_registrar_invalid_installation"
            ),
            "{}: {:?}",
            self.case,
            original.hello_registrar.failure_fixture_data()
        );
        if self.case == "initial_hello_registrar_invalid_installation" {
            assert!(matches!(original.hello_registrar.failure_fixture_data(),
                Some(ProviderError::Contract(crucible_node_format::ContractError::Invalid { field: "formats", reason }))
                    if reason == "set must be strictly sorted with no duplicates"
            ));
            assert!(actual > 0);
        }
        if self.case == "initial_hello_registrar_finish_refused" {
            return Err(ProviderError::Conflict("registrar terminal admission"));
        }
        if self.case == "initial_hello_registrar_finish_expired" {
            std::thread::sleep(Duration::from_secs(5));
        }
        Ok(())
    }
}

pub(super) fn construct_for_sdk_request(owner: &mut OriginalImport18RawBootstrap) {
    super::hello_request::construct_for_registrar(owner);
    let admission = Admission {
        case: "initial_hello_registrar_complete",
        calls: Cell::new(0),
        before: owner.retained_requested_bytes().unwrap(),
        row: Cell::new(None),
    };
    owner.construct_hello_registrar_data(&admission).unwrap();
    assert_eq!(admission.calls.get(), 3);
}

pub(super) fn assert_child(case: &str, owner: &mut OriginalImport18RawBootstrap) {
    if case == "initial_hello_registrar_unchecked_request" {
        super::hello_value::construct_for_request(owner);
    } else {
        super::hello_request::construct_for_registrar(owner);
    }
    let before = owner.retained_requested_bytes().unwrap();
    let bodies = owner.bodies.each_ref().map(|body| body.as_ptr());
    let value = owner.hello_value.value_fixture_data().unwrap() as *const Value;
    let offer = owner
        .hello_request
        .offer_fixture_data()
        .map(std::ptr::from_ref);
    let admission = Admission {
        case,
        calls: Cell::new(0),
        before,
        row: Cell::new(None),
    };
    if case == "initial_hello_registrar_before_expired" {
        owner.cut = OperationalDeadline::expired_fixture();
    }
    let complete = matches!(
        case,
        "initial_hello_registrar_complete"
            | "initial_hello_registrar_reactive"
            | "initial_hello_registrar_callback_refused"
            | "initial_hello_registrar_loan_expired"
            | "initial_hello_registrar_error_loan_expired"
            | "initial_hello_registrar_substituted_cut"
    );

    let outcome = owner.construct_hello_registrar_data(&admission);
    assert_eq!(outcome.is_ok(), complete, "{case}: {outcome:?}");
    assert_eq!(
        admission.calls.get(),
        match case {
            "initial_hello_registrar_unchecked_request"
            | "initial_hello_registrar_before_expired" => 0,
            "initial_hello_registrar_quote_refused" | "initial_hello_registrar_quote_expired" => 1,
            "initial_hello_registrar_construct_refused" => 2,
            _ => 3,
        }
    );
    let retained = owner.retained_requested_bytes().unwrap();
    let wrapper = owner
        .hello_registrar
        .wrapper_fixture_data()
        .map(std::ptr::from_ref);
    if complete {
        assert!(wrapper.is_some());
        if case == "initial_hello_registrar_substituted_cut" {
            owner.cut = OperationalDeadline::after(Duration::from_secs(4)).unwrap();
        }
        let called = Cell::new(false);
        let result = owner.with_hello_registrar_data(|actual| {
            called.set(true);
            assert_eq!(Some(actual as *const ExtensionHandshake), wrapper);
            if matches!(
                case,
                "initial_hello_registrar_loan_expired"
                    | "initial_hello_registrar_error_loan_expired"
            ) {
                std::thread::sleep(Duration::from_secs(5));
            }
            if matches!(
                case,
                "initial_hello_registrar_callback_refused"
                    | "initial_hello_registrar_error_loan_expired"
            ) {
                return Err(ProviderError::Conflict("registrar DATA loan"));
            }
            Ok(())
        });
        assert_eq!(
            called.get(),
            case != "initial_hello_registrar_substituted_cut"
        );
        assert_eq!(
            result.is_ok(),
            matches!(
                case,
                "initial_hello_registrar_complete" | "initial_hello_registrar_reactive"
            )
        );
    } else {
        assert!(owner.with_hello_registrar_data(|_| Ok(())).is_err());
        assert_eq!(
            wrapper.is_some(),
            matches!(
                case,
                "initial_hello_registrar_finish_refused" | "initial_hello_registrar_finish_expired"
            )
        );
    }

    assert!(owner.construct_hello_registrar_data(&admission).is_err());
    assert_eq!(owner.retained_requested_bytes().unwrap(), retained);
    assert_eq!(owner.bodies.each_ref().map(|body| body.as_ptr()), bodies);
    assert_eq!(
        owner
            .hello_value
            .value_fixture_data()
            .map(std::ptr::from_ref),
        Some(value)
    );
    assert_eq!(
        owner
            .hello_request
            .offer_fixture_data()
            .map(std::ptr::from_ref),
        offer
    );
    assert_eq!(
        owner
            .hello_registrar
            .wrapper_fixture_data()
            .map(std::ptr::from_ref),
        wrapper
    );
    assert!(owner.inputs.is_empty_data());
    let mut queued = [0; 14];
    let (_, count) = rustix::net::recv(
        rustix::stdio::stderr(),
        &mut queued[..],
        rustix::net::RecvFlags::PEEK | rustix::net::RecvFlags::DONTWAIT,
    )
    .unwrap();
    assert_eq!(&queued[..count], b"literal suffix");
}

#[test]
fn original_hello_registrar_retains_every_owner_under_all_terminal_guards() {
    for case in [
        "initial_hello_registrar_complete",
        "initial_hello_registrar_reactive",
        "initial_hello_registrar_invalid_installation",
        "initial_hello_registrar_unchecked_request",
        "initial_hello_registrar_before_expired",
        "initial_hello_registrar_quote_refused",
        "initial_hello_registrar_quote_expired",
        "initial_hello_registrar_construct_refused",
        "initial_hello_registrar_construct_expired",
        "initial_hello_registrar_finish_refused",
        "initial_hello_registrar_finish_expired",
        "initial_hello_registrar_callback_refused",
        "initial_hello_registrar_loan_expired",
        "initial_hello_registrar_error_loan_expired",
        "initial_hello_registrar_substituted_cut",
    ] {
        flight(case);
    }
}
