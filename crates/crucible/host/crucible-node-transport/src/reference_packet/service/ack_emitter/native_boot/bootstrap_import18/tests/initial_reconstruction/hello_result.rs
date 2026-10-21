//! Exercises actual Hello result custody through the original inherited sockets.

use super::super::super::hello_result::OriginalImport18HelloResultAdmission;
use super::*;
use crate::handshake::HelloResult;
use std::cell::Cell;

struct Admission<'a> {
    case: &'a str,
    calls: Cell<usize>,
    before: usize,
    row: Cell<Option<[usize; 3]>>,
}

impl OriginalImport18HelloResultAdmission for Admission<'_> {
    fn quote_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        scratch: usize,
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(1), 0);
        assert!(scratch > 0);
        assert!(original.hello_result.row_fixture_data().is_none());
        assert_eq!(original.hello_result.retained_backing_data().unwrap(), 0);
        assert_eq!(original.retained_requested_bytes().unwrap(), self.before);
        if self.case == "initial_hello_result_quote_refused" {
            return Err(ProviderError::Conflict("Hello result quote admission"));
        }
        if self.case == "initial_hello_result_quote_expired" {
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
        assert_eq!(original.hello_result.row_fixture_data(), Some(row));
        assert!(row.into_iter().all(|axis| axis > 0));
        assert!(original.hello_result.result_fixture_data().is_none());
        assert_eq!(original.hello_result.entropy_filled_fixture_data(), 0);
        assert_eq!(original.retained_requested_bytes().unwrap(), self.before);
        self.row.set(Some(row));
        if self.case == "initial_hello_result_construct_refused" {
            return Err(ProviderError::Conflict(
                "Hello result constructor admission",
            ));
        }
        if self.case == "initial_hello_result_construct_expired" {
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
            original.hello_result.retained_backing_data().unwrap(),
            actual
        );
        assert!(actual <= self.row.get().unwrap()[0]);
        assert_eq!(
            original.retained_requested_bytes().unwrap(),
            self.before + actual
        );
        assert_eq!(
            original.hello_result.result_fixture_data().is_some(),
            self.case != "initial_hello_result_construct_expired"
        );
        if self.case == "initial_hello_result_finish_refused" {
            return Err(ProviderError::Conflict("Hello result terminal admission"));
        }
        if self.case == "initial_hello_result_finish_expired" {
            std::thread::sleep(Duration::from_secs(5));
        }
        Ok(())
    }
}

pub(super) fn assert_child(case: &str, owner: &mut OriginalImport18RawBootstrap) {
    if case == "initial_hello_result_unchecked_sdk_request" {
        super::hello_registrar::construct_for_sdk_request(owner);
    } else {
        super::hello_sdk_request::construct_for_result(owner);
    }
    let sdk_request = owner
        .hello_sdk_request
        .request_fixture_data()
        .map(std::ptr::from_ref);
    let before = owner.retained_requested_bytes().unwrap();
    let bodies = owner.bodies.each_ref().map(|body| body.as_ptr());
    let value = owner
        .hello_value
        .value_fixture_data()
        .map(std::ptr::from_ref);
    let offer = owner
        .hello_request
        .offer_fixture_data()
        .map(std::ptr::from_ref);
    let wrapper = owner
        .hello_registrar
        .wrapper_fixture_data()
        .map(std::ptr::from_ref);
    let admission = Admission {
        case,
        calls: Cell::new(0),
        before,
        row: Cell::new(None),
    };
    if case == "initial_hello_result_before_expired" {
        owner.cut = OperationalDeadline::expired_fixture();
    }
    let complete = matches!(
        case,
        "initial_hello_result_complete"
            | "initial_hello_result_reactive"
            | "initial_hello_result_unsorted_versions"
            | "initial_hello_result_optional_feature"
            | "initial_hello_result_larger_limits"
            | "initial_hello_result_callback_refused"
            | "initial_hello_result_loan_expired"
            | "initial_hello_result_error_loan_expired"
            | "initial_hello_result_substituted_cut"
    );

    let outcome = owner.construct_hello_result_data(&admission);

    assert_eq!(outcome.is_ok(), complete, "{case}: {outcome:?}");
    assert_eq!(
        admission.calls.get(),
        match case {
            "initial_hello_result_unchecked_sdk_request"
            | "initial_hello_result_before_expired" => 0,
            "initial_hello_result_quote_refused" | "initial_hello_result_quote_expired" => 1,
            "initial_hello_result_construct_refused" => 2,
            _ => 3,
        }
    );
    let retained = owner.retained_requested_bytes().unwrap();
    let request = owner
        .hello_result
        .result_fixture_data()
        .map(std::ptr::from_ref);
    if complete {
        assert!(request.is_some());
        if case == "initial_hello_result_substituted_cut" {
            owner.cut = OperationalDeadline::after(Duration::from_secs(4)).unwrap();
        }
        let called = Cell::new(false);
        let result = owner.with_hello_result_data(|actual| {
            called.set(true);
            assert_eq!(Some(actual as *const HelloResult), request);
            assert_eq!(actual.controller_nonce.as_slice(), &[19; 32]);
            assert_eq!(actual.provider_nonce.as_slice().len(), 32);
            assert_eq!(owner.hello_result.entropy_filled_fixture_data(), 32);
            assert_eq!(
                actual.provider_identity,
                owner
                    .typed_bodies_data()
                    .unwrap()
                    .launch
                    .launch_data()
                    .selection
                    .provider
            );
            if case == "initial_hello_result_unsorted_versions" {
                owner
                    .with_sdk_hello_request_data(|request| {
                        assert_eq!(request.versions, ["CNP/2", "CNP/1"]);
                        Ok(())
                    })
                    .unwrap();
            }
            if case == "initial_hello_result_optional_feature" {
                assert!(
                    !actual
                        .selected_features
                        .iter()
                        .any(|feature| feature.as_str() == "vendor.unselected/1")
                );
            }
            if case == "initial_hello_result_larger_limits" {
                let selected = owner
                    .with_hello_request_data(|claims, _| Ok(claims.limits))
                    .unwrap();
                assert_eq!(actual.limits, selected);
            }
            if matches!(
                case,
                "initial_hello_result_loan_expired" | "initial_hello_result_error_loan_expired"
            ) {
                std::thread::sleep(Duration::from_secs(5));
            }
            if matches!(
                case,
                "initial_hello_result_callback_refused" | "initial_hello_result_error_loan_expired"
            ) {
                return Err(ProviderError::Conflict("Hello result DATA loan"));
            }
            Ok(())
        });
        assert_eq!(called.get(), case != "initial_hello_result_substituted_cut");
        assert_eq!(
            result.is_ok(),
            matches!(
                case,
                "initial_hello_result_complete"
                    | "initial_hello_result_reactive"
                    | "initial_hello_result_unsorted_versions"
                    | "initial_hello_result_optional_feature"
                    | "initial_hello_result_larger_limits"
            )
        );
    } else {
        assert!(owner.with_hello_result_data(|_| Ok(())).is_err());
        assert_eq!(
            request.is_some(),
            matches!(
                case,
                "initial_hello_result_finish_refused" | "initial_hello_result_finish_expired"
            )
        );
    }

    assert!(owner.construct_hello_result_data(&admission).is_err());
    assert_eq!(owner.retained_requested_bytes().unwrap(), retained);
    assert_eq!(owner.bodies.each_ref().map(|body| body.as_ptr()), bodies);
    assert_eq!(
        owner
            .hello_value
            .value_fixture_data()
            .map(std::ptr::from_ref),
        value
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
    assert_eq!(
        owner
            .hello_result
            .result_fixture_data()
            .map(std::ptr::from_ref),
        request
    );
    assert_eq!(
        owner
            .hello_sdk_request
            .request_fixture_data()
            .map(std::ptr::from_ref),
        sdk_request
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
fn original_hello_result_retains_actual_entropy_and_every_terminal_owner() {
    for case in [
        "initial_hello_result_complete",
        "initial_hello_result_reactive",
        "initial_hello_result_unsorted_versions",
        "initial_hello_result_optional_feature",
        "initial_hello_result_larger_limits",
        "initial_hello_result_unchecked_sdk_request",
        "initial_hello_result_before_expired",
        "initial_hello_result_quote_refused",
        "initial_hello_result_quote_expired",
        "initial_hello_result_construct_refused",
        "initial_hello_result_construct_expired",
        "initial_hello_result_finish_refused",
        "initial_hello_result_finish_expired",
        "initial_hello_result_callback_refused",
        "initial_hello_result_loan_expired",
        "initial_hello_result_error_loan_expired",
        "initial_hello_result_substituted_cut",
    ] {
        flight(case);
    }
}
