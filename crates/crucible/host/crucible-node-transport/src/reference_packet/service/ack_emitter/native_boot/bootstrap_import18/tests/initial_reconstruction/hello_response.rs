//! Exercises actual Hello response custody through the original inherited sockets.

use super::super::super::hello_response::OriginalImport18HelloResponseAdmission;
use super::*;
use crate::envelope::Envelope;
use std::cell::Cell;

struct Admission<'a> {
    case: &'a str,
    calls: Cell<usize>,
    before: usize,
    row: Cell<Option<[usize; 3]>>,
}

impl OriginalImport18HelloResponseAdmission for Admission<'_> {
    fn quote_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        scratch: usize,
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(1), 0);
        assert!(scratch > 0);
        assert!(original.hello_response.row_fixture_data().is_none());
        assert_eq!(original.hello_response.retained_backing_data().unwrap(), 0);
        assert_eq!(original.retained_requested_bytes().unwrap(), self.before);
        if self.case == "initial_hello_response_quote_refused" {
            return Err(ProviderError::Conflict("Hello response quote admission"));
        }
        if self.case == "initial_hello_response_quote_expired" {
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
        assert_eq!(original.hello_response.row_fixture_data(), Some(row));
        assert!(row.into_iter().all(|axis| axis > 0));
        assert!(original.hello_response.envelope_fixture_data().is_none());
        assert_eq!(original.retained_requested_bytes().unwrap(), self.before);
        self.row.set(Some(row));
        if self.case == "initial_hello_response_construct_refused" {
            return Err(ProviderError::Conflict(
                "Hello response constructor admission",
            ));
        }
        if self.case == "initial_hello_response_construct_expired" {
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
            original.hello_response.retained_backing_data().unwrap(),
            actual
        );
        assert!(actual <= self.row.get().unwrap()[0]);
        assert_eq!(
            original.retained_requested_bytes().unwrap(),
            self.before + actual
        );
        assert_eq!(
            original.hello_response.envelope_fixture_data().is_some(),
            self.case != "initial_hello_response_construct_expired"
        );
        if self.case == "initial_hello_response_finish_refused" {
            return Err(ProviderError::Conflict("Hello response terminal admission"));
        }
        if self.case == "initial_hello_response_finish_expired" {
            std::thread::sleep(Duration::from_secs(5));
        }
        Ok(())
    }
}

pub(super) fn assert_child(case: &str, owner: &mut OriginalImport18RawBootstrap) {
    if case == "initial_hello_response_unchecked_envelope" {
        super::hello_result::construct_for_envelope(owner);
    } else {
        super::hello_envelope::construct_for_response(owner);
    }
    let sdk_request = owner
        .hello_sdk_request
        .request_fixture_data()
        .map(std::ptr::from_ref);
    let hello_envelope = owner
        .hello_envelope
        .envelope_fixture_data()
        .map(std::ptr::from_ref);
    let hello_result = owner
        .hello_result
        .result_fixture_data()
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
    if case == "initial_hello_response_before_expired" {
        owner.cut = OperationalDeadline::expired_fixture();
    }
    let complete = matches!(
        case,
        "initial_hello_response_complete"
            | "initial_hello_response_reactive"
            | "initial_hello_response_unsorted_versions"
            | "initial_hello_response_optional_feature"
            | "initial_hello_response_larger_limits"
            | "initial_hello_response_callback_refused"
            | "initial_hello_response_loan_expired"
            | "initial_hello_response_error_loan_expired"
            | "initial_hello_response_substituted_cut"
    );

    let outcome = owner.construct_hello_response_data(&admission);

    assert_eq!(outcome.is_ok(), complete, "{case}: {outcome:?}");
    assert_eq!(
        admission.calls.get(),
        match case {
            "initial_hello_response_unchecked_envelope"
            | "initial_hello_response_before_expired" => 0,
            "initial_hello_response_quote_refused" | "initial_hello_response_quote_expired" => 1,
            "initial_hello_response_construct_refused" => 2,
            _ => 3,
        }
    );
    let retained = owner.retained_requested_bytes().unwrap();
    let request = owner
        .hello_response
        .envelope_fixture_data()
        .map(std::ptr::from_ref);
    if complete {
        assert!(request.is_some());
        if case == "initial_hello_response_substituted_cut" {
            owner.cut = OperationalDeadline::after(Duration::from_secs(4)).unwrap();
        }
        let called = Cell::new(false);
        let result = owner.with_hello_response_data(|actual| {
            called.set(true);
            assert_eq!(Some(actual as *const Envelope), request);
            assert_eq!(actual.message, crate::envelope::MessageKind::Response);
            assert_eq!(
                actual.request_id.0.as_ref().unwrap().as_str(),
                "hello/initial"
            );
            assert_eq!(actual.sequence.get(), 1);
            assert_eq!(actual.body["status"], "completed");
            assert_eq!(actual.body["operation_state"], "completed");
            owner
                .with_hello_result_data(|result| {
                    assert_eq!(
                        actual.incarnation_id.0.as_ref(),
                        Some(&result.incarnation_id)
                    );
                    assert_eq!(
                        actual.body["result"]["selected_features"],
                        json!(result.selected_features)
                    );
                    Ok(())
                })
                .unwrap();
            owner
                .with_hello_envelope_data(|request| {
                    assert_eq!(actual.request_id, request.request_id);
                    assert_eq!(std::ptr::from_ref(request), hello_envelope.unwrap());
                    if case == "initial_hello_response_unsorted_versions" {
                        assert_eq!(request.body["versions"], json!(["CNP/2", "CNP/1"]));
                    }
                    if case == "initial_hello_response_optional_feature" {
                        assert_eq!(
                            request.body["optional_features"],
                            json!(["vendor.unselected/1"])
                        );
                    }
                    Ok(())
                })
                .unwrap();
            if matches!(
                case,
                "initial_hello_response_loan_expired" | "initial_hello_response_error_loan_expired"
            ) {
                std::thread::sleep(Duration::from_secs(5));
            }
            if matches!(
                case,
                "initial_hello_response_callback_refused"
                    | "initial_hello_response_error_loan_expired"
            ) {
                return Err(ProviderError::Conflict("Hello response DATA loan"));
            }
            Ok(())
        });
        assert_eq!(
            called.get(),
            case != "initial_hello_response_substituted_cut"
        );
        assert_eq!(
            result.is_ok(),
            matches!(
                case,
                "initial_hello_response_complete"
                    | "initial_hello_response_reactive"
                    | "initial_hello_response_unsorted_versions"
                    | "initial_hello_response_optional_feature"
                    | "initial_hello_response_larger_limits"
            )
        );
    } else {
        assert!(owner.with_hello_response_data(|_| Ok(())).is_err());
        assert_eq!(
            request.is_some(),
            matches!(
                case,
                "initial_hello_response_finish_refused" | "initial_hello_response_finish_expired"
            )
        );
    }

    assert!(owner.construct_hello_response_data(&admission).is_err());
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
            .hello_response
            .envelope_fixture_data()
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
    assert_eq!(
        owner
            .hello_result
            .result_fixture_data()
            .map(std::ptr::from_ref),
        hello_result
    );
    assert_eq!(
        owner
            .hello_envelope
            .envelope_fixture_data()
            .map(std::ptr::from_ref),
        hello_envelope
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
fn original_hello_response_retains_actual_completed_body_and_every_terminal_owner() {
    for case in [
        "initial_hello_response_complete",
        "initial_hello_response_reactive",
        "initial_hello_response_unsorted_versions",
        "initial_hello_response_optional_feature",
        "initial_hello_response_larger_limits",
        "initial_hello_response_unchecked_envelope",
        "initial_hello_response_before_expired",
        "initial_hello_response_quote_refused",
        "initial_hello_response_quote_expired",
        "initial_hello_response_construct_refused",
        "initial_hello_response_construct_expired",
        "initial_hello_response_finish_refused",
        "initial_hello_response_finish_expired",
        "initial_hello_response_callback_refused",
        "initial_hello_response_loan_expired",
        "initial_hello_response_error_loan_expired",
        "initial_hello_response_substituted_cut",
    ] {
        flight(case);
    }
}
