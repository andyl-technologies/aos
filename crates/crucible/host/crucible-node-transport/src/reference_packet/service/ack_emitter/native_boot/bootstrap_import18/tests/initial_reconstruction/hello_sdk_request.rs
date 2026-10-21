//! Exercises actual SDK request custody through the original inherited sockets.

use super::super::super::hello_sdk_request::OriginalImport18SdkHelloRequestAdmission;
use super::*;
use crate::handshake::HelloRequest;
use std::cell::Cell;

struct Admission<'a> {
    case: &'a str,
    calls: Cell<usize>,
    before: usize,
    row: Cell<Option<[usize; 3]>>,
}

impl OriginalImport18SdkHelloRequestAdmission for Admission<'_> {
    fn quote_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        scratch: usize,
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(1), 0);
        assert!(scratch > 0);
        assert!(original.hello_sdk_request.row_fixture_data().is_none());
        assert_eq!(
            original.hello_sdk_request.retained_backing_data().unwrap(),
            0
        );
        assert_eq!(original.retained_requested_bytes().unwrap(), self.before);
        if self.case == "initial_hello_sdk_request_quote_refused" {
            return Err(ProviderError::Conflict("SDK request quote admission"));
        }
        if self.case == "initial_hello_sdk_request_quote_expired" {
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
        assert_eq!(original.hello_sdk_request.row_fixture_data(), Some(row));
        assert!(row.into_iter().all(|axis| axis > 0));
        assert!(original.hello_sdk_request.request_fixture_data().is_none());
        assert_eq!(original.retained_requested_bytes().unwrap(), self.before);
        self.row.set(Some(row));
        if self.case == "initial_hello_sdk_request_construct_refused" {
            return Err(ProviderError::Conflict("SDK request constructor admission"));
        }
        if self.case == "initial_hello_sdk_request_construct_expired" {
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
            original.hello_sdk_request.retained_backing_data().unwrap(),
            actual
        );
        assert!(actual <= self.row.get().unwrap()[0]);
        assert_eq!(
            original.retained_requested_bytes().unwrap(),
            self.before + actual
        );
        assert_eq!(
            original.hello_sdk_request.request_fixture_data().is_some(),
            self.case != "initial_hello_sdk_request_construct_expired"
        );
        if self.case == "initial_hello_sdk_request_finish_refused" {
            return Err(ProviderError::Conflict("SDK request terminal admission"));
        }
        if self.case == "initial_hello_sdk_request_finish_expired" {
            std::thread::sleep(Duration::from_secs(5));
        }
        Ok(())
    }
}

pub(super) fn assert_child(case: &str, owner: &mut OriginalImport18RawBootstrap) {
    if case == "initial_hello_sdk_request_unchecked_registrar" {
        super::hello_request::construct_for_registrar(owner);
    } else {
        super::hello_registrar::construct_for_sdk_request(owner);
    }
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
    if case == "initial_hello_sdk_request_before_expired" {
        owner.cut = OperationalDeadline::expired_fixture();
    }
    let complete = matches!(
        case,
        "initial_hello_sdk_request_complete"
            | "initial_hello_sdk_request_reactive"
            | "initial_hello_sdk_request_unsorted_versions"
            | "initial_hello_sdk_request_optional_feature"
            | "initial_hello_sdk_request_larger_limits"
            | "initial_hello_sdk_request_callback_refused"
            | "initial_hello_sdk_request_loan_expired"
            | "initial_hello_sdk_request_error_loan_expired"
            | "initial_hello_sdk_request_substituted_cut"
    );

    let outcome = owner.construct_sdk_hello_request_data(&admission);

    assert_eq!(outcome.is_ok(), complete, "{case}: {outcome:?}");
    assert_eq!(
        admission.calls.get(),
        match case {
            "initial_hello_sdk_request_unchecked_registrar"
            | "initial_hello_sdk_request_before_expired" => 0,
            "initial_hello_sdk_request_quote_refused"
            | "initial_hello_sdk_request_quote_expired" => 1,
            "initial_hello_sdk_request_construct_refused" => 2,
            _ => 3,
        }
    );
    let retained = owner.retained_requested_bytes().unwrap();
    let request = owner
        .hello_sdk_request
        .request_fixture_data()
        .map(std::ptr::from_ref);
    if complete {
        assert!(request.is_some());
        if case == "initial_hello_sdk_request_substituted_cut" {
            owner.cut = OperationalDeadline::after(Duration::from_secs(4)).unwrap();
        }
        let called = Cell::new(false);
        let result = owner.with_sdk_hello_request_data(|actual| {
            called.set(true);
            assert_eq!(Some(actual as *const HelloRequest), request);
            assert_eq!(actual.controller_nonce.as_slice(), &[19; 32]);
            if case == "initial_hello_sdk_request_unsorted_versions" {
                assert_eq!(actual.versions, ["CNP/2", "CNP/1"]);
            }
            if case == "initial_hello_sdk_request_optional_feature" {
                assert_eq!(actual.optional_features[0].as_str(), "vendor.unselected/1");
            }
            if case == "initial_hello_sdk_request_larger_limits" {
                let selected = owner
                    .with_hello_request_data(|claims, _| Ok(claims.limits))
                    .unwrap();
                assert!(actual.limits.requests > selected.requests);
            }
            if matches!(
                case,
                "initial_hello_sdk_request_loan_expired"
                    | "initial_hello_sdk_request_error_loan_expired"
            ) {
                std::thread::sleep(Duration::from_secs(5));
            }
            if matches!(
                case,
                "initial_hello_sdk_request_callback_refused"
                    | "initial_hello_sdk_request_error_loan_expired"
            ) {
                return Err(ProviderError::Conflict("SDK request DATA loan"));
            }
            Ok(())
        });
        assert_eq!(
            called.get(),
            case != "initial_hello_sdk_request_substituted_cut"
        );
        assert_eq!(
            result.is_ok(),
            matches!(
                case,
                "initial_hello_sdk_request_complete"
                    | "initial_hello_sdk_request_reactive"
                    | "initial_hello_sdk_request_unsorted_versions"
                    | "initial_hello_sdk_request_optional_feature"
                    | "initial_hello_sdk_request_larger_limits"
            )
        );
    } else {
        assert!(owner.with_sdk_hello_request_data(|_| Ok(())).is_err());
        assert_eq!(
            request.is_some(),
            matches!(
                case,
                "initial_hello_sdk_request_finish_refused"
                    | "initial_hello_sdk_request_finish_expired"
            )
        );
    }

    assert!(owner.construct_sdk_hello_request_data(&admission).is_err());
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
            .hello_sdk_request
            .request_fixture_data()
            .map(std::ptr::from_ref),
        request
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
fn original_sdk_hello_request_preserves_actual_claims_and_every_terminal_owner() {
    for case in [
        "initial_hello_sdk_request_complete",
        "initial_hello_sdk_request_reactive",
        "initial_hello_sdk_request_unsorted_versions",
        "initial_hello_sdk_request_optional_feature",
        "initial_hello_sdk_request_larger_limits",
        "initial_hello_sdk_request_unchecked_registrar",
        "initial_hello_sdk_request_before_expired",
        "initial_hello_sdk_request_quote_refused",
        "initial_hello_sdk_request_quote_expired",
        "initial_hello_sdk_request_construct_refused",
        "initial_hello_sdk_request_construct_expired",
        "initial_hello_sdk_request_finish_refused",
        "initial_hello_sdk_request_finish_expired",
        "initial_hello_sdk_request_callback_refused",
        "initial_hello_sdk_request_loan_expired",
        "initial_hello_sdk_request_error_loan_expired",
        "initial_hello_sdk_request_substituted_cut",
    ] {
        flight(case);
    }
}
