//! Completes the same restored pending permission against its original signed output.
//!
//! No Stage or Begin is resent. The native publication is compared byte for byte
//! before its actual coordinator commit and native acknowledgement are accepted.

#![cfg(test)]

use super::{conditional_profile::ConditionalProfile, conditional_source::InspectionError};
use crucible::{
    node_adapters::transcript::TranscriptAction,
    node_contract::{NodeRuntime, OperationOutcome, OperationToken, Submission},
    node_scheduling::NativePublication,
};
use crucible_node_contract::canonical;
use serde::{Deserialize, Serialize};
use std::task::{Context, Poll, Waker};

#[derive(Deserialize, Serialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum OriginalComplete {
    Outcome(Box<OperationOutcome>),
}

pub(super) fn complete(
    runtime: &mut NodeRuntime,
    token: &OperationToken,
    source: &ConditionalProfile,
) -> Result<NativePublication, InspectionError> {
    let original = source
        .history
        .originals
        .get(&token.route().node)
        .ok_or("original signed suffix node absent")?;
    let mut records = original.transcript().records.iter().filter(|record| {
        record.request.action == TranscriptAction::Complete
            && &record.request.identity == token.operation()
    });
    let record = records
        .next()
        .ok_or("original signed terminal record absent")?;
    if records.next().is_some() || record.response_bytes.len() > 65_536 {
        return Err("original terminal record is ambiguous or exceeds codec credit".into());
    }
    record
        .response
        .verify(&record.response_bytes)
        .map_err(text)?;
    let value = canonical::parse_json(&record.response_bytes, 65_536).map_err(text)?;
    let response: OriginalComplete = serde_json::from_value(value).map_err(text)?;
    if canonical::canonical_json(&serde_json::to_value(&response).map_err(text)?).map_err(text)?
        != record.response_bytes
    {
        return Err("original typed terminal bytes changed".into());
    }
    let OriginalComplete::Outcome(expected) = response;
    let expected_scheduling = expected
        .scheduling
        .as_ref()
        .ok_or("original terminal scheduling absent")?;
    if expected.operation != *token.operation()
        || expected.node != token.route().node
        || expected.owners != original.transcript().origin.route.owners
        || expected_scheduling.node != expected.node
        || expected_scheduling.owners != expected.owners
        || expected_scheduling.publications.len() != 1
    {
        return Err("original FIRST terminal scope differs".into());
    }

    let mut context = Context::from_waker(Waker::noop());
    if !matches!(runtime.poll(token, &mut context), Poll::Pending) {
        return Err("fresh original permission is not still pending".into());
    }
    if runtime.close_quantum(token).map_err(text)? != Submission::Accepted {
        return Err("fresh original Close was not accepted".into());
    }
    let Poll::Ready(Ok(outcome)) = runtime.poll(token, &mut context) else {
        return Err("fresh original terminal outcome unavailable".into());
    };
    let scheduling = outcome
        .scheduling
        .as_ref()
        .ok_or("fresh terminal scheduling absent")?;
    if outcome.operation != *token.operation()
        || outcome.node != token.route().node
        || outcome.owners != token.route().owners
        || scheduling.owners != token.route().owners
        || scheduling.node != token.route().node
        || scheduling.publications != expected_scheduling.publications
    {
        return Err("fresh original suffix publication or live scope changed".into());
    }
    let publication = scheduling
        .publications
        .first()
        .ok_or("fresh original output absent")?
        .clone();
    let receipt = runtime.scheduling_receipt(token).map_err(text)?;
    let commit = runtime.commit_scheduling_receipt(receipt).map_err(text)?;
    runtime
        .acknowledge_scheduled(token, &commit)
        .map_err(text)?;
    Ok(publication)
}

fn text(error: impl std::fmt::Debug) -> InspectionError {
    format!("{error:?}").into()
}
