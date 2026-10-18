//! Reconstructs each native17 field into a retained concrete owner.

use super::*;
use crate::protocol_snapshot::owned11::typed::native17_build::native17_struct;

native17_struct!(ResumeSession {
    session_id: Id,
    incarnation_id: Id,
    resume_token: Bytes,
    unresolved_operation_ids: IdSet,
});

native17_struct!(ResumedOperation {
    operation_id: Id,
    operation_state: OperationState,
    outcome: Nullable<Map<String, Value>>,
});

native17_struct!(HelloResult {
    version: String,
    session_id: Id,
    incarnation_id: Id,
    controller_nonce: Bytes,
    provider_nonce: Bytes,
    selected_features: IdSet,
    limits: Limits,
    resume_token: Nullable<Bytes>,
    provider_identity: ProviderManifest,
    resumed_operations: Vec<ResumedOperation>,
});

native17_struct!(HelloRequest {
    versions: Vec<String>,
    session_id: Id,
    controller_nonce: Bytes,
    required_features: IdSet,
    optional_features: IdSet,
    limits: Limits,
    admission_token: Bytes,
    resume_session: Option<ResumeSession> => omitted,
    extensions: Extensions,
});
