//! Lossless closed portable/ProtoJSON projections and generated Debug redaction.

use serde::{de::DeserializeOwned, Serialize};

use crate::hub_v1 as pb;

use super::*;

fn project<T: Serialize, U: DeserializeOwned>(value: &T) -> DirectUploadResult<U> {
    decode_direct_control(&encode_direct_control(value)?)
}

macro_rules! convert {
    ($portable:ty, $proto:ty, $validate:expr) => {
        impl TryFrom<$portable> for $proto {
            type Error = DirectUploadError;

            fn try_from(value: $portable) -> DirectUploadResult<Self> {
                ($validate)(&value)?;
                project(&value)
            }
        }

        impl TryFrom<$proto> for $portable {
            type Error = DirectUploadError;

            fn try_from(value: $proto) -> DirectUploadResult<Self> {
                let projected: Self = project(&value)?;
                ($validate)(&projected)?;
                Ok(projected)
            }
        }
    };
}

convert!(
    DirectGetCapabilities,
    pb::DirectGetCapabilities,
    |value: &DirectGetCapabilities| value.target.validate()
);
convert!(
    DirectUploadIntent,
    pb::DirectUploadIntent,
    |value: &DirectUploadIntent| value.validate()
);
convert!(
    DirectUploadCapabilities,
    pb::DirectUploadCapabilities,
    |value: &DirectUploadCapabilities| value.validate()
);
convert!(
    DirectUploadResponse,
    pb::DirectUploadResponse,
    |value: &DirectUploadResponse| value.validate()
);
convert!(
    DirectBeginBatch,
    pb::DirectBeginBatch,
    |value: &DirectBeginBatch| DirectUploadRequest::BeginBatch(value.clone()).validate()
);
convert!(
    DirectBatch<DirectStatusQuery>,
    pb::DirectStatusBatch,
    |value: &DirectBatch<DirectStatusQuery>| DirectUploadRequest::StatusBatch(value.clone())
        .validate()
);
convert!(
    DirectBatch<DirectGrantPartRequest>,
    pb::DirectGrantPartsBatch,
    |value: &DirectBatch<DirectGrantPartRequest>| DirectUploadRequest::GrantPartsBatch(
        value.clone()
    )
    .validate()
);
convert!(
    DirectBatch<DirectPartReport>,
    pb::DirectReportPartsBatch,
    |value: &DirectBatch<DirectPartReport>| DirectUploadRequest::ReportPartsBatch(value.clone())
        .validate()
);
convert!(
    DirectBatch<DirectCompleteRequest>,
    pb::DirectCompleteBatch,
    |value: &DirectBatch<DirectCompleteRequest>| DirectUploadRequest::CompleteBatch(value.clone())
        .validate()
);
convert!(
    DirectBatch<DirectAbortRequest>,
    pb::DirectAbortBatch,
    |value: &DirectBatch<DirectAbortRequest>| DirectUploadRequest::Abort(value.clone()).validate()
);

impl std::fmt::Debug for pb::DirectPartGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectPartGrant")
            .field("session_id", &self.session_id)
            .field("grant_id", &self.grant_id)
            .field("url", &"[REDACTED]")
            .field("required_headers", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for pb::DirectRequiredHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectRequiredHeader")
            .field("name", &self.name)
            .field("value", &"[REDACTED]")
            .finish()
    }
}
