//! Inert original-admission controls for effect-frontier and response custody.
//!
//! The coordinator issues the actual opaque admission in the existing model
//! runtime. These controls authenticate no Child, SDK lease or native source.

// crucible-lint: allow panic-shortcut -- Failed fixture or retained-state assertions stop these inert controls.
#![allow(clippy::unwrap_used)]

use std::{cell::Cell, collections::BTreeMap};

use crucible_node_contract::{Extensions, Id, OperatingMode, U64, Validate, canonical};
use crucible_node_provider::{bodies::*, envelope::Nullable};

use crate::node_contract::{
    CancelStatus, EffectKnowledge, OperationAdmission, OperationFailure, OperationRequest,
};

use super::*;

fn admission(name: &str) -> OperationAdmission {
    crate::node_contract::test_original_admission(name)
}

fn begin(admission: &OperationAdmission) -> BeginRequest {
    let OperationRequest::ExactRun { start, limit, .. } = admission.request() else {
        panic!("model admission must retain its exact grant");
    };
    let record = admission.activation().record();
    let arguments = ExactRunArguments {
        grant_id: admission.token().operation().clone(),
        participant_ids: vec![Id::new("model-participant").unwrap()],
        realization_id: Id::new("model-realization").unwrap(),
        activation_id: record.activation_id.clone(),
        world_generation: record.generation,
        owner_generation: record.owners[0].generation,
        input_epoch: Id::new("model-input-epoch").unwrap(),
        mode: OperatingMode::Exact,
        ordering_profile: "superdense-v1".into(),
        start: *start,
        limit: *limit,
        boundary_policy: BoundaryPolicy::OrdinaryStop,
        input_authorization: canonical::content_ref(b"{}", "application/json").unwrap(),
        input_watermark: U64::new(0),
    };
    let serde_json::Value::Object(arguments) = serde_json::to_value(arguments).unwrap() else {
        panic!("exact argument serializer must remain an object");
    };
    let begin = BeginRequest {
        kind: BeginKind::ExactRun,
        binding_hash: canonical::json_hash("cnp.owner-binding.v1", &"inert-model-binding").unwrap(),
        owner_generation: record.owners[0].generation,
        activation_id: Nullable(Some(record.activation_id.clone())),
        world_generation: record.generation,
        arguments,
        extensions: Extensions::new(),
    };
    begin.validate().unwrap();
    begin
}

fn original(name: &str) -> OriginalOperation {
    let admission = admission(name);
    let begin = begin(&admission);
    OriginalOperation::prepare(
        &admission,
        begin,
        &mut SemanticCredit::default(),
        1024 * 1024,
    )
    .unwrap()
    .1
}

#[test]
fn overlong_original_begin_id_refuses_before_effect_frontier() {
    let admission = admission(&"a".repeat(124));
    let effects = Cell::new(0);
    let mut rows = BTreeMap::new();
    let prepared = OriginalOperation::prepare(
        &admission,
        begin(&admission),
        &mut SemanticCredit::default(),
        1024 * 1024,
    );
    match prepared {
        Ok((_request, row)) => {
            rows.insert(admission.token().operation().clone(), row);
            effects.set(effects.get() + 1);
        }
        Err(failure) => assert_eq!(failure.effects, EffectKnowledge::None),
    }
    assert!(rows.is_empty());
    assert_eq!(effects.get(), 0);
}

#[test]
fn exact_begin_credit_precedes_retained_attempt_and_first_effect() {
    let admission = admission("credited-begin");
    let body = begin(&admission);
    let extent = super::super::budget::serialized_size(&body, 1024 * 1024).unwrap();
    let effects = Cell::new(0);
    let mut rows = BTreeMap::new();

    let undercredit = OriginalOperation::prepare(
        &admission,
        body.clone(),
        &mut SemanticCredit::default(),
        extent - 1,
    );
    assert_eq!(undercredit.err().unwrap().effects, EffectKnowledge::None);
    assert!(rows.is_empty());
    assert_eq!(effects.get(), 0);

    let (_request, row) =
        OriginalOperation::prepare(&admission, body, &mut SemanticCredit::default(), extent)
            .unwrap();
    rows.insert(admission.token().operation().clone(), row);
    assert_eq!(
        rows[admission.token().operation()]
            .validate_repeated_begin()
            .unwrap_err()
            .effects,
        EffectKnowledge::Unknown
    );
    // This is an inert modeled effect frontier, not an actual native send.
    effects.set(effects.get() + 1);
    assert_eq!(effects.get(), 1);
    assert_eq!(rows.len(), 1);
}

#[test]
fn unresolved_upload_or_dispatch_never_accepts_repeated_begin() {
    let mut row = original("pending-begin");
    assert_eq!(
        row.validate_repeated_begin().unwrap_err().effects,
        EffectKnowledge::Unknown
    );
    assert!(!row.begin_acknowledged);

    let failure = OperationFailure {
        effects: EffectKnowledge::None,
        reason: "installed dispatch read refused".into(),
    };
    row.retain_failure(&failure);
    for _ in 0..2 {
        let retained = row.validate_repeated_begin().unwrap_err();
        assert_eq!(retained.effects, EffectKnowledge::Unknown);
        assert_eq!(retained.reason, failure.reason);
    }
    assert!(!row.begin_acknowledged);
}

#[test]
fn only_known_begin_acknowledgement_accepts_repeated_begin() {
    let mut row = original("known-begin");
    assert!(row.validate_repeated_begin().is_err());
    row.begin_acknowledged = true;
    assert!(row.validate_repeated_begin().is_ok());
}

#[test]
fn unsupported_cancellation_stays_unsupported_without_another_attempt() {
    let mut row = original("unsupported-cancel");
    assert!(row.cancellation_status().is_none());
    row.cancellation = OriginalCancellation::Pending;
    assert_eq!(
        row.complete_cancellation(Ok(false)).unwrap(),
        CancelStatus::Unsupported
    );
    for _ in 0..2 {
        assert_eq!(
            row.cancellation_status().unwrap().unwrap(),
            CancelStatus::Unsupported
        );
    }
}

#[test]
fn pending_and_failed_cancellation_never_report_requested_or_terminal() {
    let mut row = original("uncertain-cancel");
    row.cancellation = OriginalCancellation::Pending;
    assert_eq!(
        row.cancellation_status().unwrap().unwrap_err().effects,
        EffectKnowledge::Unknown
    );
    let original = OperationFailure {
        effects: EffectKnowledge::None,
        reason: "cancel dispatch refused".into(),
    };
    let returned = row.complete_cancellation(Err(original)).unwrap_err();
    assert_eq!(returned.effects, EffectKnowledge::Unknown);
    for _ in 0..2 {
        let retained = row.cancellation_status().unwrap().unwrap_err();
        assert_eq!(retained.effects, returned.effects);
        assert_eq!(retained.reason, returned.reason);
    }
}

#[test]
fn actual_requested_response_alone_establishes_already_requested() {
    let mut row = original("requested-cancel");
    row.cancellation = OriginalCancellation::Pending;
    assert_eq!(
        row.complete_cancellation(Ok(true)).unwrap(),
        CancelStatus::Requested
    );
    assert_eq!(
        row.cancellation_status().unwrap().unwrap(),
        CancelStatus::AlreadyRequested
    );
}

#[test]
fn failed_terminal_decode_retains_unknown_instead_of_terminal_status() {
    let mut row = original("failed-terminal");
    let failure = OperationFailure {
        effects: EffectKnowledge::Unknown,
        reason: "foreign original native outcome".into(),
    };
    row.retain_failure(&failure);
    assert!(row.outcome.is_none());
    let retained = row.cancellation_status().unwrap().unwrap_err();
    assert_eq!(retained.effects, EffectKnowledge::Unknown);
    assert_eq!(retained.reason, failure.reason);
}

#[test]
fn retained_failure_bounds_utf8_without_erasing_uncertainty() {
    let mut row = original("bounded-failure");
    row.retain_failure(&OperationFailure {
        effects: EffectKnowledge::None,
        reason: "é".repeat(3000),
    });
    let retained = row.validate_repeated_begin().unwrap_err();
    assert_eq!(retained.effects, EffectKnowledge::Unknown);
    assert_eq!(retained.reason.len(), 4096);
    assert!(retained.reason.ends_with('é'));
}
