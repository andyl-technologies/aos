//! Bounded observation of one actual candidate response after typed validation.
//!
//! The response header is observational and is not covered by a reply MAC.
//! A missing, repeated or mismatched response makes this fixture observation
//! unknown. It never changes the controller's authority or transport result.
//!
//! The actual header contains only unsigned observational counters:
//!
//! ```json
//! {"peakBulk":1,"peakMetadata":2,"peakMetadataWhileBulk":2,"admissions":2}
//! ```
//! Its retained record also binds the full selected original, transport call,
//! request/reply byte commitments and a null reply-MAC authentication field.

use std::sync::{Arc, Mutex};

use anyhow::{Context as _, Result, ensure};
use aos_hub_core::mirror_batch::MirrorBatchItem;
use aos_hub_core::mirror_work::{MirrorStep, digest};
use aos_hub_core::storage_work::{StorageWorkOperation, StorageWorkPlan};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Names the actual candidate executor's bounded interval response header.
pub(crate) const HEADER: &str = "x-aos-mirror-candidate-buffers";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BufferInterval {
    peak_bulk: u64,
    peak_metadata: u64,
    peak_metadata_while_bulk: u64,
    admissions: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
/// Correlates an actual checked response and its unsigned interval header.
pub(crate) struct Record {
    version: u8,
    plan_id: String,
    transport_call_id: String,
    job_id: String,
    original_digest: String,
    step_digest: String,
    protected_profile_digest: String,
    request_sha256: String,
    request_bytes: String,
    reply_sha256: String,
    reply_bytes: String,
    response_header_name: &'static str,
    response_header_sha256: String,
    response_header_value: String,
    buffer_interval: BufferInterval,
    reply_mac_authentication: Option<bool>,
}

enum State {
    Empty,
    One(Record),
    Unknown,
}

#[derive(Clone)]
/// Retains at most one interval for one complete selected original and step.
pub(crate) struct Capture {
    expected: MirrorBatchItem,
    state: Arc<Mutex<State>>,
}

impl Capture {
    /// Selects exactly one retained metadata original and UploadParts interval.
    ///
    /// # Errors
    /// Returns an error for invalid, External, empty or oversized originals,
    /// or for a step other than the first single metadata part.
    pub(crate) fn new(expected: MirrorBatchItem) -> Result<Self> {
        expected.original.validate()?;
        ensure!(
            expected.original.external_destination.is_none()
                && (1..=256 * 1024).contains(&expected.original.verification.size())
                && matches!(
                    expected.step,
                    MirrorStep::UploadParts {
                        first_part: 1,
                        maximum_parts: 1
                    }
                ),
            "candidate capture requires one Managed metadata UploadParts original"
        );
        Ok(Self {
            expected,
            state: Arc::new(Mutex::new(State::Empty)),
        })
    }

    /// Records one actual checked response; capture failures remain unknown.
    pub(crate) fn observe(
        &self,
        plan: &StorageWorkPlan,
        call_id: &str,
        header: Result<Vec<u8>>,
        request_hash: &str,
        request_bytes: usize,
        reply: &[u8],
    ) {
        let record = self.checked_record(plan, call_id, header, request_hash, request_bytes, reply);
        if let Ok(mut state) = self.state.lock() {
            *state = match (&*state, record) {
                (State::Empty, Ok(record)) => State::One(record),
                _ => State::Unknown,
            };
        }
    }

    fn checked_record(
        &self,
        plan: &StorageWorkPlan,
        call_id: &str,
        header: Result<Vec<u8>>,
        request_hash: &str,
        request_bytes: usize,
        reply: &[u8],
    ) -> Result<Record> {
        let StorageWorkOperation::MirrorTransferBatch { items } = &plan.operation else {
            anyhow::bail!("candidate capture received another operation");
        };
        ensure!(
            items.as_slice() == std::slice::from_ref(&self.expected),
            "candidate capture changed the selected full original or step"
        );
        let raw = header?;
        ensure!(
            !raw.is_empty() && raw.len() <= 1024,
            "candidate header bound differs"
        );
        let interval: BufferInterval = serde_json::from_slice(&raw)?;
        Ok(Record {
            version: 1,
            plan_id: plan.plan_id.clone(),
            transport_call_id: call_id.to_owned(),
            job_id: self.expected.original.job_id.clone(),
            original_digest: digest(&self.expected.original)?,
            step_digest: digest(&self.expected.step)?,
            protected_profile_digest: self.expected.original.protected_profile_digest.clone(),
            request_sha256: request_hash.to_owned(),
            request_bytes: request_bytes.to_string(),
            reply_sha256: hex::encode(Sha256::digest(reply)),
            reply_bytes: reply.len().to_string(),
            response_header_name: HEADER,
            response_header_sha256: hex::encode(Sha256::digest(&raw)),
            response_header_value: String::from_utf8(raw)?,
            buffer_interval: interval,
            reply_mac_authentication: None,
        })
    }

    /// Returns only an unambiguous actual checked response observation.
    ///
    /// # Errors
    /// Returns an error for missing, repeated, malformed or crossed observations.
    pub(crate) fn finish(&self) -> Result<Record> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("candidate capture poisoned"))?;
        match &*state {
            State::One(record) => Ok(record.clone()),
            _ => anyhow::bail!("candidate response observation remains unknown"),
        }
    }
}

/// Copies exactly one bounded actual response header without consuming its body.
///
/// # Errors
/// Returns an error for a missing, repeated or oversized header.
pub(crate) fn response_header(headers: &reqwest::header::HeaderMap) -> Result<Vec<u8>> {
    let mut values = headers.get_all(HEADER).iter();
    let value = values
        .next()
        .context("actual candidate buffer header absent")?;
    ensure!(
        values.next().is_none() && value.as_bytes().len() <= 1024,
        "actual candidate buffer header repeated or oversized"
    );
    Ok(value.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_refuses_missing_duplicate_and_non_integer_counts() {
        let mut headers = reqwest::header::HeaderMap::new();
        assert!(response_header(&headers).is_err());
        headers.append(HEADER, reqwest::header::HeaderValue::from_static("{}"));
        headers.append(HEADER, reqwest::header::HeaderValue::from_static("{}"));
        assert!(response_header(&headers).is_err());
        for bad in [
            r#"{"peakBulk":1,"peakMetadata":2,"peakMetadataWhileBulk":2,"admissions":true}"#,
            r#"{"peakBulk":1,"peakMetadata":2,"peakMetadataWhileBulk":2,"admissions":2,"configured":2}"#,
        ] {
            assert!(serde_json::from_str::<BufferInterval>(bad).is_err());
        }
        let interval: BufferInterval = serde_json::from_str(
            r#"{"peakBulk":1,"peakMetadata":2,"peakMetadataWhileBulk":2,"admissions":2}"#,
        )
        .unwrap();
        assert_eq!(interval.peak_metadata_while_bulk, 2);
    }

    #[test]
    fn capture_refuses_crossed_original_step_and_repeated_response() {
        use aos_hub_core::mirror_work::{MirrorOriginal, MirrorVerification};
        let mut original = MirrorOriginal {
            version: 1,
            job_id: String::new(),
            copy_operation_id: Some("ab".repeat(16)),
            registry_id: 1,
            registry_resource_version: 2,
            mirror_resource_version: 3,
            upstream_base: "https://upstream.example.org/git/".into(),
            path: "first".into(),
            placement_id: 4,
            placement_resource_version: 5,
            write_spec_version: 6,
            binding_id: 7,
            binding_resource_version: 8,
            placement_prefix: format!(".aos-mirror-qualification/{}/final", "ab".repeat(16)),
            protected_profile_digest: "cd".repeat(32),
            external_destination: None,
            verification: MirrorVerification::Sha256 {
                sha256: "ef".repeat(32),
                size: 8,
            },
        };
        original.job_id = original.identity().unwrap();
        let item = MirrorBatchItem {
            original: original.clone(),
            step: MirrorStep::UploadParts {
                first_part: 1,
                maximum_parts: 1,
            },
        };
        let mut plan = StorageWorkPlan {
            version: 1,
            plan_id: "11".repeat(16),
            deployment_id: "deployment".into(),
            issued_at: 150,
            expires_at: 180,
            placement_id: 4,
            placement_resource_version: 5,
            binding_id: 7,
            binding_resource_version: 8,
            binding_kind: "deployment_r2".into(),
            binding_snapshot_revision: None,
            credential_references: vec![],
            placement_prefix: original.placement_prefix.clone(),
            operation: StorageWorkOperation::MirrorTransferBatch {
                items: vec![item.clone()],
            },
        };
        let header = || {
            Ok(
                br#"{"peakBulk":1,"peakMetadata":2,"peakMetadataWhileBulk":2,"admissions":2}"#
                    .to_vec(),
            )
        };
        let capture = Capture::new(item.clone()).unwrap();
        assert!(capture.finish().is_err());
        capture.observe(
            &plan,
            &"01".repeat(16),
            header(),
            &"02".repeat(32),
            100,
            b"reply",
        );
        let record = capture.finish().unwrap();
        assert_eq!(record.original_digest, digest(&original).unwrap());
        assert_eq!(record.reply_sha256, hex::encode(Sha256::digest(b"reply")));
        assert_eq!(record.reply_mac_authentication, None);
        capture.observe(
            &plan,
            &"01".repeat(16),
            header(),
            &"02".repeat(32),
            100,
            b"reply",
        );
        assert!(capture.finish().is_err());
        let capture = Capture::new(item.clone()).unwrap();
        let mut changed = item;
        changed.step = MirrorStep::Begin;
        plan.operation = StorageWorkOperation::MirrorTransferBatch {
            items: vec![changed],
        };
        capture.observe(
            &plan,
            &"01".repeat(16),
            header(),
            &"02".repeat(32),
            100,
            b"reply",
        );
        assert!(capture.finish().is_err());
        if let StorageWorkOperation::MirrorTransferBatch { items } = &mut plan.operation {
            items[0].step = MirrorStep::UploadParts {
                first_part: 1,
                maximum_parts: 1,
            };
            items[0].original.registry_resource_version += 1;
        }
        let capture = Capture::new(MirrorBatchItem {
            original,
            step: MirrorStep::UploadParts {
                first_part: 1,
                maximum_parts: 1,
            },
        })
        .unwrap();
        capture.observe(
            &plan,
            &"01".repeat(16),
            header(),
            &"02".repeat(32),
            100,
            b"reply",
        );
        assert!(capture.finish().is_err());
    }
}
