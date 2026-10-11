//! Value-free custody of actual ordinary storage-work attempts.
//!
//! Offered requests and exposed reply chunks are distinct from delivery and
//! provider work. A typed result has no invented reply MAC. Final context is
//! emitted only by the caller after its existing current SQL checks.
//!
//! ```text
//! Attempt = {version, invocationId, transportCallId, attempt, planId, operation,
//!   endpointScheme, offeredRequestSha256, offeredRequestBytes, replyStatus,
//!   exposedReplySha256, exposedReplyBytes, replyEof, unreadResponse, outcome,
//!   elapsedMicros, observedAtUnixMicros, replyMacAuthentication: null}
//! FinalContext = {version, attempt: Attempt, contextKind, commitments}
//! ```

use std::{collections::BTreeMap, time::Instant};

use serde::Serialize;
use sha2::{Digest as _, Sha256};

use aos_hub_core::storage_work::StorageWorkPlan;

#[cfg(test)]
mod tests;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AttemptRecord {
    version: u8,
    invocation_id: String,
    transport_call_id: String,
    attempt: usize,
    plan_id: String,
    operation: String,
    endpoint_scheme: String,
    offered_request_sha256: String,
    offered_request_bytes: String,
    reply_status: Option<u16>,
    exposed_reply_sha256: String,
    exposed_reply_bytes: String,
    reply_eof: bool,
    unread_response: bool,
    outcome: &'static str,
    elapsed_micros: String,
    reply_mac_authentication: Option<bool>,
    observed_at_unix_micros: Option<String>,
}

/// Holds each attempt's actual exposed prefix until completion or cancellation.
pub(super) struct AttemptObservation {
    record: AttemptRecord,
    hasher: Sha256,
    exposed_bytes: u64,
    started: Instant,
    dispatcher: tracing::Dispatch,
    span: tracing::Span,
}

impl AttemptObservation {
    pub(super) fn new(
        plan: &StorageWorkPlan,
        invocation_id: &str,
        attempt: usize,
        body: &[u8],
        endpoint: &str,
    ) -> Self {
        Self {
            record: AttemptRecord {
                version: 1,
                invocation_id: invocation_id.into(),
                transport_call_id: uuid::Uuid::new_v4().simple().to_string(),
                attempt,
                plan_id: plan.plan_id.clone(),
                operation: plan.operation.kind().into(),
                endpoint_scheme: url::Url::parse(endpoint)
                    .map(|url| url.scheme().to_owned())
                    .unwrap_or_else(|_| "unknown".into()),
                offered_request_sha256: hex::encode(Sha256::digest(body)),
                offered_request_bytes: "0".into(),
                reply_status: None,
                exposed_reply_sha256: hex::encode(Sha256::digest([])),
                exposed_reply_bytes: "0".into(),
                reply_eof: false,
                unread_response: false,
                outcome: "cancelled",
                elapsed_micros: "0".into(),
                reply_mac_authentication: None,
                observed_at_unix_micros: None,
            },
            hasher: Sha256::new(),
            exposed_bytes: 0,
            started: Instant::now(),
            dispatcher: tracing::dispatcher::get_default(Clone::clone),
            span: tracing::Span::current(),
        }
    }

    pub(super) fn call_id(&self) -> &str {
        &self.record.transport_call_id
    }

    pub(super) fn offer(&mut self, bytes: usize) {
        self.record.offered_request_bytes = bytes.to_string();
    }

    pub(super) fn response(&mut self, status: u16) {
        self.record.reply_status = Some(status);
        self.record.unread_response = true;
    }

    /// Hashes only chunks already exposed by the existing HTTP client's stream.
    pub(super) fn exposed(&mut self, chunk: &[u8]) {
        self.hasher.update(chunk);
        self.exposed_bytes = self.exposed_bytes.saturating_add(chunk.len() as u64);
        self.record.unread_response = false;
    }

    pub(super) fn eof(&mut self) {
        self.record.reply_eof = true;
        self.record.unread_response = false;
    }

    pub(super) fn finish(&mut self, outcome: &'static str) {
        self.record.outcome = outcome;
    }

    fn snapshot(&self) -> AttemptRecord {
        let mut record = self.record.clone();
        record.exposed_reply_sha256 = hex::encode(self.hasher.clone().finalize());
        record.exposed_reply_bytes = self.exposed_bytes.to_string();
        record.elapsed_micros = self.started.elapsed().as_micros().to_string();
        record.observed_at_unix_micros = utc_micros();
        record
    }

    /// Carries only the caller's already completed typed and deadline checks.
    pub(super) fn checked(&mut self) -> Option<CheckedObservation> {
        if !self.record.reply_eof || self.record.reply_status != Some(200) {
            return None;
        }
        self.finish("typed_result_checked");
        Some(CheckedObservation {
            record: self.snapshot(),
            dispatcher: self.dispatcher.clone(),
            span: self.span.clone(),
        })
    }
}

impl Drop for AttemptObservation {
    fn drop(&mut self) {
        emit(
            "storage_work_attempt_observed",
            &self.snapshot(),
            &self.dispatcher,
            &self.span,
        );
    }
}

/// Correlates a checked reply with the caller's later, existing SQL fence.
pub(super) struct CheckedObservation {
    record: AttemptRecord,
    dispatcher: tracing::Dispatch,
    span: tracing::Span,
}

impl CheckedObservation {
    pub(super) fn after_sql(self, commitments: BTreeMap<&'static str, String>) {
        if commitments.is_empty()
            || commitments.len() > 16
            || commitments.values().any(|value| {
                value.len() != 64
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
        {
            return;
        }
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct FinalContext {
            version: u8,
            attempt: AttemptRecord,
            context_kind: &'static str,
            commitments: BTreeMap<&'static str, String>,
            completed_at_unix_micros: Option<String>,
        }
        emit(
            "storage_work_final_sql_checked",
            &FinalContext {
                version: 1,
                attempt: self.record,
                context_kind: "surface_fetch_current_sql",
                commitments,
                completed_at_unix_micros: utc_micros(),
            },
            &self.dispatcher,
            &self.span,
        );
    }
}

fn emit(
    marker: &str,
    record: &impl Serialize,
    dispatcher: &tracing::Dispatch,
    span: &tracing::Span,
) {
    let Ok(encoded) = serde_json::to_string(record) else {
        return;
    };
    if encoded.len() > 4096 {
        return;
    }
    let _subscriber = tracing::dispatcher::set_default(dispatcher);
    let _span = span.enter();
    tracing::info!("{marker} {encoded}");
}

fn utc_micros() -> Option<String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|value| value.as_micros().to_string())
}
