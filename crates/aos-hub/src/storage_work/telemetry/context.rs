//! Value-free observations emitted after the caller's final current SQL checks.
//!
//! The receipt correlates already authenticated application bytes with hashes of
//! the exact state checked by the caller. It grants no permission and performs
//! no additional SQL, provider, signature or current-time validation.

use std::collections::BTreeMap;

use serde::Serialize;
use sha2::{Digest as _, Sha256};

use super::AuthenticatedControlBody;

#[cfg(test)]
mod tests;

/// Carries an authenticated transport observation to its existing SQL caller.
pub(in crate::storage_work) struct ControlObservation {
    body: AuthenticatedControlBody,
    dispatcher: tracing::Dispatch,
    span: tracing::Span,
}

impl ControlObservation {
    pub(super) fn new(
        body: AuthenticatedControlBody,
        dispatcher: tracing::Dispatch,
        span: tracing::Span,
    ) -> Self {
        Self {
            body,
            dispatcher,
            span,
        }
    }

    /// Emits only hashes supplied after the caller's existing final SQL checks.
    pub(in crate::storage_work) fn after_sql(
        self,
        context_kind: &'static str,
        commitments: BTreeMap<&'static str, String>,
    ) {
        if !matches!(
            context_kind,
            "external_copy_current_sql"
                | "managed_oci_current_sql"
                | "external_oci_stage_snapshot_checked"
                | "external_oci_stage_writer_checked"
                | "external_oci_source_writer_checked"
                | "external_oci_projection_writer_checked"
                | "external_oci_materialization_source_checked"
                | "external_oci_materialization_control_checked"
                | "external_oci_cleanup_delete_checked"
        ) || commitments.is_empty()
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
        let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
            return;
        };
        let observation = FinalSqlObservation {
            version: 1,
            exchange: self.body,
            context_kind,
            commitments,
            completed_at_unix_micros: now.as_micros().to_string(),
        };
        // Instrumentation failure omits evidence without changing the result.
        let Ok(encoded) = serde_json::to_string(&observation) else {
            return;
        };
        if encoded.len() > 16 * 1024 {
            return;
        }
        let _subscriber = tracing::dispatcher::set_default(&self.dispatcher);
        let _span = self.span.enter();
        tracing::info!("storage_final_sql_checked {encoded}");
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FinalSqlObservation {
    version: u8,
    exchange: AuthenticatedControlBody,
    context_kind: &'static str,
    commitments: BTreeMap<&'static str, String>,
    completed_at_unix_micros: String,
}

/// Hashes a deterministic observational projection without exposing its fields.
pub(in crate::storage_work) fn fact_digest(value: &impl Serialize) -> Option<String> {
    let bytes = serde_json::to_vec(value).ok()?;
    Some(hex::encode(Sha256::digest(bytes)))
}
