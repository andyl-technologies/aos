//! Independent portable public-protocol oracles for the installed reference service.

use std::collections::BTreeMap;

use crucible_node_provider::bodies::EffectCertainty;
use crucible_node_provider::conformance::{CheckKind, Expectation, ProbeStep, ReplyAssertion};
use serde_json::{Value, json};

use super::fixture::{NativeService, id};

pub(super) fn hello(service: &NativeService) -> ProbeStep {
    let mut request = envelope(
        service,
        "hello",
        "hello",
        json!({
            "versions":["CNP/1"],"session_id":service.bootstrap.authority.session_id,
            "controller_nonce":{"$binding":"controller-challenge"},"admission_token":{"$binding":"launch-token"},
            "required_features":["cnp.core/1"],"optional_features":["cnp.resume/1"],
            "limits":service.bootstrap.limits,"extensions":{}
        }),
    );
    request["session_id"] = Value::Null;
    request["incarnation_id"] = Value::Null;
    request["sequence"] = json!("1");
    exchange(
        "hello",
        CheckKind::Hello,
        request,
        Expectation::Completed,
        vec![assertion(
            "/body/result/provider_identity",
            serde_json::to_value(&service.profile.provider_manifest).unwrap(),
        )],
        BTreeMap::from([
            ("incarnation".into(), "/body/result/incarnation_id".into()),
            ("resume-token".into(), "/body/result/resume_token".into()),
        ]),
    )
}

pub(super) fn envelope(
    service: &NativeService,
    method: &str,
    request_id: &str,
    body: Value,
) -> Value {
    json!({
        "protocol":"CNP/1","message":"request","session_id":service.bootstrap.authority.session_id,
        "incarnation_id":{"$binding":"incarnation"},"node_id":null,"execution_owner_id":null,"capture_owner_id":null,
        "request_id":request_id,"operation_id":null,"sequence":{"$sequence":"outgoing"},"method":method,"body":body,"extensions":{}
    })
}

pub(super) fn exchange(
    case: &str,
    check: CheckKind,
    request: Value,
    expected: Expectation,
    assertions: Vec<ReplyAssertion>,
    captures: BTreeMap<String, String>,
) -> ProbeStep {
    ProbeStep::Exchange {
        id: id(case),
        check,
        request,
        expected,
        assertions,
        captures,
    }
}

pub(super) fn assertion(pointer: &str, equals: Value) -> ReplyAssertion {
    ReplyAssertion {
        pointer: pointer.into(),
        equals,
    }
}

pub(super) fn error(code: &str) -> Expectation {
    Expectation::Error {
        code: id(code),
        effect: EffectCertainty::NotStarted,
    }
}
