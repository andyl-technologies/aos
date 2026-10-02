//! Confined private observations of the actual queued verification input.
//!
//! This do-e2e projection grants no authority. Native authentication, current
//! SQL and the independently captured provider request remain separate joins.
//!
//! The closed observational format has these fields; nested Core values retain
//! their existing serialization. This outline is not an authorization receipt:
//!
//! ```text
//! Projection = {version, attemptId, selection, job, work}
//! Selection = {version, stagingPrefix, expectedSourceSha256, expectedSourceBytes}
//! Job = {canonicalJobSha256, admission, complete, placementId, closedResult}
//! ```

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::{DirectCompleteRequest, DirectUploadAdmission, WireInteger};
use aos_hub_core::storage_authority::external_object::stage::{
    ExternalStageContext, ExternalStageOperation, ExternalStageRequest, ExternalStageResult,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub(crate) const MAX_RECORD_BYTES: usize = 64 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Selection {
    pub version: u32,
    pub staging_prefix: String,
    pub expected_source_sha256: String,
    pub expected_source_bytes: String,
}

impl Selection {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1
                && self.staging_prefix.len() <= 2048
                && self
                    .staging_prefix
                    .split('/')
                    .any(|part| part == ".aos-direct-qualification")
                && self.staging_prefix.ends_with("/.aos-direct-upload")
                && self.staging_prefix.split('/').all(|part| {
                    !part.is_empty()
                        && part != "."
                        && part != ".."
                        && part.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                        })
                })
                && digest_string(&self.expected_source_sha256),
            "verification observation selection differs"
        );
        let bytes: u64 = self.expected_source_bytes.parse()?;
        ensure!(
            (1..=65536).contains(&bytes) && bytes.to_string() == self.expected_source_bytes,
            "verification observation source bound differs"
        );
        Ok(())
    }

    pub(crate) fn matches(&self, work: &ExternalStageRequest) -> bool {
        self.validate().is_ok()
            && self.staging_prefix == work.context.placement.staging_prefix
            && self.expected_source_sha256 == work.context.intent.expected_sha256
            && self.expected_source_bytes == work.context.intent.byte_size.get().to_string()
            && matches!(
                work.operation,
                ExternalStageOperation::VerifyClosedStage { .. }
            )
    }
}

/// Projects genuine job fields without relocating its wasm-only wire schema.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct JobProjection {
    pub canonical_job_sha256: String,
    pub admission: DirectUploadAdmission,
    pub complete: DirectCompleteRequest,
    pub placement_id: WireInteger,
    pub closed_result: ExternalStageResult,
}

impl JobProjection {
    pub(crate) fn validate(&self, work: &ExternalStageRequest) -> Result<()> {
        self.admission.validate(&work.deployment_id)?;
        self.complete.fingerprint()?;
        ensure!(
            digest_string(&self.canonical_job_sha256)
                && self.complete.session.session_id == self.admission.session_id
                && self.complete.session.logical_fingerprint == self.admission.logical_fingerprint
                && work.context
                    == ExternalStageContext::from_admission(
                        &self.admission,
                        self.placement_id,
                        &work.deployment_id
                    )?,
            "verification projection changed original admission"
        );
        let operation = crate::direct_upload::journal::digest(&(
            &self.admission.session_id,
            &self.admission.logical_fingerprint,
            self.placement_id,
            &self.complete.operation_id,
            "verify-stage",
        ))?;
        ensure!(
            work.operation_id == operation,
            "verification operation differs from retained Complete"
        );
        let ExternalStageOperation::VerifyClosedStage {
            close_receipt_digest,
            ..
        } = &work.operation
        else {
            anyhow::bail!("observation is not a verification operation");
        };
        ensure!(
            self.closed_result.version == 1
                && self.closed_result.receipt_digest == *close_receipt_digest,
            "verification close commitment differs"
        );
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Projection {
    pub version: u32,
    pub attempt_id: String,
    pub selection: Selection,
    pub job: JobProjection,
    pub work: ExternalStageRequest,
}

impl Projection {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1
                && self.attempt_id.len() == 32
                && self
                    .attempt_id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                && self.selection.matches(&self.work),
            "verification observation attempt or selection differs"
        );
        // Shape validation at the actual recorded issuance is observational.
        // It is not a current clock, authenticated lease or replay admission.
        self.work.validate(
            &self.work.deployment_id,
            i64::try_from(self.work.issued_at.get())?,
        )?;
        self.job.validate(&self.work)
    }
}

pub(crate) fn digest_string(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn bytes_digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(crate) fn emit<T: Serialize>(record: &T) {
    let bytes = serde_json::to_vec(record);
    match bytes {
        Ok(bytes) if bytes.len() <= MAX_RECORD_BYTES => {
            #[cfg(target_arch = "wasm32")]
            if let Ok(text) = std::str::from_utf8(&bytes) {
                worker::console_log!("direct_verification_fault_observation {}", text);
            }
            #[cfg(test)]
            CAPTURE.with(|capture| capture.borrow_mut().push(bytes));
        }
        _ => {
            #[cfg(target_arch = "wasm32")]
            worker::console_log!("direct_verification_fault_observation {{\"version\":1,\"kind\":\"incomplete\",\"reason\":\"record_bound_or_encoding\"}}");
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn configured(env: &worker::Env, work: &ExternalStageRequest) -> Option<Selection> {
    let value = env.var("HUB_DIRECT_VERIFICATION_FAULT_OBSERVER").ok()?;
    match serde_json::from_str::<Selection>(&value.to_string()) {
        Ok(selection) if selection.matches(work) => Some(selection),
        _ => None,
    }
}

#[cfg(test)]
thread_local! {
    pub(crate) static CAPTURE: std::cell::RefCell<Vec<Vec<u8>>> = const { std::cell::RefCell::new(Vec::new()) };
}
