//! Independent portable public-protocol oracles for the installed reference service.

use std::collections::{BTreeMap, BTreeSet};

use crucible_node_contract::Bytes;
use crucible_node_provider::bodies::EffectCertainty;
use crucible_node_provider::conformance::{
    CheckKind, Expectation, ProbePlan, ProbeStep, ReplyAssertion,
};
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

pub(super) fn basic_protocol(service: &NativeService) -> ProbePlan {
    let discover = envelope(
        service,
        "discover",
        "profiles",
        json!({"profile_ids":[],"extensions":{}}),
    );
    let profiles = serde_json::to_value(vec![service.profile.node_manifest.clone()]).unwrap();
    let mut changed = discover.clone();
    changed["body"]["profile_ids"] = json!(["uninstalled-profile"]);
    let mut resume = envelope(
        service,
        "hello",
        "resume",
        json!({
            "versions":["CNP/1"],"session_id":service.bootstrap.authority.session_id,
            "controller_nonce":{"$binding":"resume-challenge"},"admission_token":{"$binding":"launch-token"},
            "required_features":["cnp.core/1","cnp.resume/1"],"optional_features":[],"limits":service.bootstrap.limits,
            "resume_session":{"session_id":service.bootstrap.authority.session_id,"incarnation_id":{"$binding":"incarnation"},
                "resume_token":{"$binding":"resume-token"},"unresolved_operation_ids":[]},"extensions":{}
        }),
    );
    resume["sequence"] = json!("1");
    ProbePlan {
        schema_version: 1,
        fixture: id("source-built-reference-protocol/1"),
        required_checks: BTreeSet::from([
            CheckKind::Hello,
            CheckKind::DescriptorBinding,
            CheckKind::Duplicate,
            CheckKind::Reconnect,
        ]),
        steps: vec![
            hello(service),
            exchange(
                "discover",
                CheckKind::DescriptorBinding,
                discover.clone(),
                Expectation::Completed,
                vec![assertion("/body/result/profiles", profiles.clone())],
                BTreeMap::new(),
            ),
            exchange(
                "unchanged-original",
                CheckKind::Duplicate,
                discover,
                Expectation::Completed,
                vec![assertion("/body/result/profiles", profiles)],
                BTreeMap::new(),
            ),
            exchange(
                "changed-original",
                CheckKind::Duplicate,
                changed,
                error("CONFLICT"),
                Vec::new(),
                BTreeMap::new(),
            ),
            ProbeStep::Disconnect {
                id: id("transport-loss"),
            },
            exchange(
                "resume-original-incarnation",
                CheckKind::Reconnect,
                resume,
                Expectation::Completed,
                vec![
                    assertion(
                        "/body/result/incarnation_id",
                        json!({"$binding":"incarnation"}),
                    ),
                    assertion("/body/result/resumed_operations", json!([])),
                    assertion(
                        "/body/result/limits",
                        serde_json::to_value(service.bootstrap.limits).unwrap(),
                    ),
                ],
                BTreeMap::new(),
            ),
        ],
    }
}

pub(super) fn negotiated_limits(service: &NativeService) -> ProbePlan {
    let limits = json!({"frame_bytes":"4096","nesting":"32","requests":"4",
        "journal_entries":"32","blob_chunk_bytes":"1024"});
    let mut step = hello(service);
    let ProbeStep::Exchange {
        check,
        request,
        assertions,
        ..
    } = &mut step
    else {
        unreachable!("fixture constructs a Hello exchange");
    };
    *check = CheckKind::Limits;
    request["body"]["limits"] = limits.clone();
    assertions.push(assertion("/body/result/limits", limits));

    ProbePlan {
        schema_version: 1,
        fixture: id("source-built-reference-limits/1"),
        required_checks: BTreeSet::from([CheckKind::Limits]),
        steps: vec![step],
    }
}

pub(super) fn unsupported_required_feature(service: &NativeService) -> ProbePlan {
    let mut step = hello(service);
    let ProbeStep::Exchange {
        check,
        request,
        expected,
        assertions,
        captures,
        ..
    } = &mut step
    else {
        unreachable!("fixture constructs a Hello exchange");
    };
    *check = CheckKind::UnsupportedContract;
    request["body"]["required_features"] = json!(["cnp.core/1", "uninstalled.feature/1"]);
    *expected = error("UNSUPPORTED_FEATURE");
    assertions.clear();
    captures.clear();

    ProbePlan {
        schema_version: 1,
        fixture: id("source-built-reference-unsupported/1"),
        required_checks: BTreeSet::from([CheckKind::UnsupportedContract]),
        steps: vec![step],
    }
}

pub(super) fn malformed_stream(service: &NativeService) -> ProbePlan {
    ProbePlan {
        schema_version: 1,
        fixture: id("source-built-reference-malformed/1"),
        required_checks: BTreeSet::from([CheckKind::Hello, CheckKind::Malformed]),
        steps: vec![
            hello(service),
            ProbeStep::Malformed {
                id: id("duplicate-json-key"),
                payload: Bytes::new(br#"{"protocol":"CNP/1","protocol":"foreign"}"#.to_vec()),
                expected: Expectation::Disconnected,
            },
        ],
    }
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
