//! Exercises request authentication under actual original socket/bootstrap custody.

use super::super::super::hello_request::OriginalImport18HelloRequestAdmission;
use super::*;
use crate::handshake::EXTENSION_NEGOTIATION_V1;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use std::cell::Cell;

pub(super) fn body_data(case: &str) -> Vec<u8> {
    let selected = operands(case);
    let launch: PacketNative5SourceLaunch =
        serde_json::from_value(selected[1]["launch"].clone()).unwrap();
    let declaration = crate::reference_packet::service::complete_restore::import18::hello::native_import18_hello_declaration_data(&launch).unwrap();
    let mut selection = None;
    declaration
        .retain_selection_into_data(&mut selection)
        .unwrap();
    let mut value = json!({
        "protocol":"CNP/1", "message":"request", "sequence":"1", "method":"hello",
        "session_id":null, "incarnation_id":null, "node_id":null,
        "execution_owner_id":null, "capture_owner_id":null, "operation_id":null,
        "request_id":"hello/initial",
        "body": {
            "versions":["CNP/1"],
            "session_id":launch.selection.realization.bindings[0].authority.session_id,
            "controller_nonce":Bytes::new(vec![19;32]),
            "required_features":selection.unwrap().0, "optional_features":[],
            "limits":launch.limits, "admission_token":launch.admission_token, "extensions":{},
        },
        "extensions":{ EXTENSION_NEGOTIATION_V1:{"format":"1", "required":[], "optional":[]} },
    });
    match case {
        "initial_hello_request_wrong_token" => {
            value["body"]["admission_token"] = json!(Bytes::new(vec![8; 32]))
        }
        "initial_hello_request_wrong_session" => {
            value["body"]["session_id"] = json!("session/other")
        }
        "initial_hello_request_wrong_sequence" => value["sequence"] = json!("2"),
        "initial_hello_request_missing_feature" => {
            value["body"]["required_features"] = json!(["cnp.core/1"])
        }
        "initial_hello_request_resume" => value["body"]["resume_session"] = Value::Null,
        "initial_hello_request_bad_offer" => {
            value["extensions"][EXTENSION_NEGOTIATION_V1]["format"] = json!("2")
        }
        "initial_hello_request_bad_decoder" => {
            value["extensions"][EXTENSION_NEGOTIATION_V1]["optional"] = json!([null])
        }
        _ => {}
    }
    serde_json::to_vec(&value).unwrap()
}

struct Admission<'a> {
    case: &'a str,
    calls: Cell<usize>,
    before: usize,
    row: Cell<Option<[usize; 3]>>,
}

impl OriginalImport18HelloRequestAdmission for Admission<'_> {
    fn quote_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        scratch: usize,
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(1), 0);
        assert!(scratch > 0);
        assert!(original.hello_request.row_fixture_data().is_none());
        assert_eq!(original.hello_request.retained_backing_data().unwrap(), 0);
        assert_eq!(original.retained_requested_bytes().unwrap(), self.before);
        if self.case == "initial_hello_request_quote_refused" {
            return Err(ProviderError::Conflict("request quote admission"));
        }
        if self.case == "initial_hello_request_quote_expired" {
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
        assert_eq!(original.hello_request.row_fixture_data(), Some(row));
        assert!(row.into_iter().all(|axis| axis > 0));
        assert!(original.hello_request.offer_fixture_data().is_none());
        assert_eq!(original.retained_requested_bytes().unwrap(), self.before);
        self.row.set(Some(row));
        if self.case == "initial_hello_request_construct_refused" {
            return Err(ProviderError::Conflict("request constructor admission"));
        }
        if self.case == "initial_hello_request_construct_expired" {
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
            original.hello_request.retained_backing_data().unwrap(),
            actual
        );
        assert!(actual <= self.row.get().unwrap()[0]);
        assert_eq!(
            original.retained_requested_bytes().unwrap(),
            self.before + actual
        );
        if self.case == "initial_hello_request_finish_refused" {
            return Err(ProviderError::Conflict("request terminal admission"));
        }
        if self.case == "initial_hello_request_finish_expired" {
            std::thread::sleep(Duration::from_secs(5));
        }
        Ok(())
    }
}

pub(super) fn assert_child(case: &str, owner: &mut OriginalImport18RawBootstrap) {
    if case != "initial_hello_request_unchecked_value" {
        super::hello_value::construct_for_request(owner);
    }
    let before = owner.retained_requested_bytes().unwrap();
    let raw_pointers = owner.bodies.each_ref().map(|body| body.as_ptr());
    let value_pointer = owner
        .hello_value
        .value_fixture_data()
        .map(|value| value as *const Value);
    let admission = Admission {
        case,
        calls: Cell::new(0),
        before,
        row: Cell::new(None),
    };
    if case == "initial_hello_request_before_expired" {
        owner.cut = OperationalDeadline::expired_fixture();
    }
    let complete = matches!(
        case,
        "initial_hello_request_complete"
            | "initial_hello_request_reactive"
            | "initial_hello_request_callback_refused"
            | "initial_hello_request_loan_expired"
    );

    let outcome = owner.inspect_hello_request_data(&admission);
    assert_eq!(outcome.is_ok(), complete, "{case}: {outcome:?}");
    assert_eq!(
        admission.calls.get(),
        match case {
            "initial_hello_request_unchecked_value" | "initial_hello_request_before_expired" => 0,
            "initial_hello_request_quote_refused" | "initial_hello_request_quote_expired" => 1,
            "initial_hello_request_construct_refused" => 2,
            _ => 3,
        }
    );
    let retained = owner.retained_requested_bytes().unwrap();
    if complete {
        let offer_pointer = owner.hello_request.offer_fixture_data().unwrap()
            as *const crate::handshake::ExtensionOfferV1;
        let result = owner.with_hello_request_data(|claims, offer| {
            assert_eq!(claims.controller_nonce, [19; 32]);
            assert!(std::ptr::eq(offer_pointer, offer));
            assert!(offer.required.is_empty() && offer.optional.is_empty());
            if case == "initial_hello_request_callback_refused" {
                return Err(ProviderError::Conflict("request DATA loan"));
            }
            if case == "initial_hello_request_loan_expired" {
                std::thread::sleep(Duration::from_secs(5));
            }
            Ok(())
        });
        assert_eq!(
            result.is_ok(),
            !matches!(
                case,
                "initial_hello_request_callback_refused" | "initial_hello_request_loan_expired"
            )
        );
        assert!(std::ptr::eq(
            offer_pointer,
            owner.hello_request.offer_fixture_data().unwrap()
        ));
    } else {
        assert!(owner.with_hello_request_data(|_, _| Ok(())).is_err());
        assert_eq!(
            owner.hello_request.offer_fixture_data().is_some(),
            matches!(
                case,
                "initial_hello_request_bad_offer"
                    | "initial_hello_request_finish_refused"
                    | "initial_hello_request_finish_expired"
            )
        );
    }
    assert!(owner.inspect_hello_request_data(&admission).is_err());
    assert_eq!(owner.retained_requested_bytes().unwrap(), retained);
    assert_eq!(
        owner.bodies.each_ref().map(|body| body.as_ptr()),
        raw_pointers
    );
    assert_eq!(
        owner
            .hello_value
            .value_fixture_data()
            .map(|value| value as *const Value),
        value_pointer
    );
    assert!(owner.inputs.is_empty_data());
    let mut queued = [0; 14];
    let (_, count) = rustix::net::recv(
        rustix::stdio::stderr(),
        &mut queued[..],
        rustix::net::RecvFlags::PEEK | rustix::net::RecvFlags::DONTWAIT,
    )
    .unwrap();
    if case == "initial_hello_request_unchecked_value" {
        assert_eq!(&queued[..4], (body_data(case).len() as u32).to_be_bytes());
    } else {
        assert_eq!(&queued[..count], b"literal suffix");
    }
}

#[test]
fn original_hello_request_retains_claims_and_failures_under_every_terminal_guard() {
    for case in [
        "initial_hello_request_complete",
        "initial_hello_request_reactive",
        "initial_hello_request_unchecked_value",
        "initial_hello_request_before_expired",
        "initial_hello_request_quote_refused",
        "initial_hello_request_quote_expired",
        "initial_hello_request_construct_refused",
        "initial_hello_request_construct_expired",
        "initial_hello_request_finish_refused",
        "initial_hello_request_finish_expired",
        "initial_hello_request_callback_refused",
        "initial_hello_request_loan_expired",
        "initial_hello_request_wrong_token",
        "initial_hello_request_wrong_session",
        "initial_hello_request_wrong_sequence",
        "initial_hello_request_missing_feature",
        "initial_hello_request_resume",
        "initial_hello_request_bad_offer",
        "initial_hello_request_bad_decoder",
    ] {
        flight(case);
    }
}
