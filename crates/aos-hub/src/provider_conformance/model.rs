//! Closed credential-free intent, observation and report formats.
//!
//! ```json
//! {"phase":"late_part_after_complete","result":"denied","status":404}
//! ```

use aos_hub_core::direct_upload::DirectPrivateStagePolicyRef;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Original {
    pub version: u32,
    pub source_kind: String,
    pub executable_sha256: String,
    pub package_version: String,
    pub run_id: String,
    pub started_at: i64,
    pub endpoint: String,
    pub bucket: String,
    pub private_staging_prefix: String,
    pub policy: DirectPrivateStagePolicyRef,
    pub policy_review_sha256: String,
    pub expected_size: u64,
    pub expected_sha256: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Phase {
    CreateSource,
    RejectBadChecksum,
    UploadSourcePart,
    CompleteSource,
    LatePartAfterComplete,
    SourceHead,
    SourceFullRead,
    SourceRangeRead,
    AnonymousRead,
    CreateStreamedCopy,
    UploadStreamedCopyPart,
    CompleteStreamedCopy,
    StreamedCopyHead,
    StreamedCopyFullRead,
    CreateProviderCopy,
    ProviderCopyPart,
    CompleteProviderCopy,
    ProviderCopyHead,
    ProviderCopyFullRead,
    SourceFinalRead,
    CreateAbort,
    Abort,
    LatePartAfterAbort,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Intent {
    pub operation_id: String,
    pub phase: Phase,
    pub request_sha256: String,
    pub authorization_sha256: String,
    pub key: String,
    pub upload_id_sha256: Option<String>,
    pub part_number: Option<u32>,
    pub first_byte: Option<u64>,
    pub size: u64,
    pub expected_sha256: Option<String>,
    pub checksum_md5_base64: Option<String>,
    pub source_etag: Option<String>,
    pub manifest: Vec<PartReceipt>,
}

impl Intent {
    pub fn new(phase: Phase, key: &str) -> Self {
        Self {
            operation_id: uuid::Uuid::new_v4().to_string(),
            phase,
            request_sha256: String::new(),
            authorization_sha256: String::new(),
            key: key.into(),
            upload_id_sha256: None,
            part_number: None,
            first_byte: None,
            size: 0,
            expected_sha256: None,
            checksum_md5_base64: None,
            source_etag: None,
            manifest: Vec::new(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PartReceipt {
    pub part_number: u32,
    pub etag: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ObjectReceipt {
    pub key: String,
    pub etag: String,
    pub provider_version: Option<String>,
    pub size: u64,
    pub sha256: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ResultKind {
    Positive,
    Denied,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Observation {
    pub operation_id: String,
    pub phase: Phase,
    pub result: ResultKind,
    pub status: u16,
    pub response_bytes: u64,
    pub response_sha256: String,
    pub provider_request_id: Option<String>,
    pub error_code: Option<String>,
    pub etag: Option<String>,
    pub provider_version: Option<String>,
    pub actual_size: Option<u64>,
    pub actual_sha256: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ResponseCommitment {
    pub operation_id: String,
    pub phase: Phase,
    pub status: u16,
    pub response_bytes: u64,
    pub response_sha256: String,
    pub provider_request_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Report {
    pub original: Original,
    pub source: ObjectReceipt,
    pub streamed_copy: ObjectReceipt,
    pub provider_copy: ObjectReceipt,
    pub observations: Vec<Observation>,
    pub cleanup_state: String,
}
