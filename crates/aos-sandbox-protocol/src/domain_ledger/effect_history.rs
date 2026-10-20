//! Owns the complete versioned historical effect record and its commitments.
//!
//! The model contains plans, progress, receipts and retained dispatch data. The
//! context and dispatch modules hold public-mutation and lease-attempt history;
//! the codec reads and writes the closed V2 through V7 record grammar.
//! Native owners retain admission, publication, currentness and executor custody.
//! Historical values alone do not authorize execution or authenticate a receipt.

mod codec;
mod context;
mod dispatch;
#[cfg(target_os = "linux")]
mod lifecycle_terminal;
#[cfg(target_os = "linux")]
pub use lifecycle_terminal::{CreateStoppedRecoveredTerminalDataV1, CreateStoppedRecoveredTerminalDataErrorV1,
    CreateStoppedNativeObservationDataV2, CreateStoppedNativeObservationErrorV2, CreateStoppedTerminalDataErrorV1,
    CreateStoppedTerminalTransactionDataV1, create_stopped_terminal_transaction_id_v1,
    CreateStoppedPreAckTransactionDataV1, create_stopped_pre_ack_transaction_id_v1};

mod lifecycle_completion;
pub use lifecycle_completion::{
    CreateStoppedLifecycleReceiptDataV1, LifecycleEffectReceiptDataV1,
    StopResidualLifecycleReceiptDataV4, STOP_RESIDUAL_LIFECYCLE_RECEIPT_BYTES_V4,
    encode_stop_residual_lifecycle_receipt_v4,
    LIFECYCLE_EFFECT_RECEIPT_BYTES_V1, CREATE_STOPPED_LIFECYCLE_RECEIPT_BYTES_V1,
    encode_lifecycle_effect_receipt_v1, decode_lifecycle_effect_receipt_v1,
    lifecycle_child_effect_commitment_v1,
};
mod model;
/// Owns completed reserved first-Observe Effect extension DATA.
pub mod observe_completion;
mod receiving;
pub use receiving::effect_decoding_receiving_bytes_v1;

pub use codec::{
    decode_effect, encode_effect, effect_body_digest, effect_binding_digest, attempt_token_digest,
    audience_code, audience_from_code, authority_effect_record_bound_v1,
};
#[cfg(target_os = "linux")]
pub use codec::{decode_effect_with_q04, encode_q04_effect, q04_effect_subgate};
pub use context::PublicMutationEffectHistoryV1;
pub use dispatch::{BrokerDispatchAttemptHistoryV1, PreparedAuthorityEffectHistoryV1};
pub use model::{
    AuthorityEffectBindingV1, EffectDomain, EffectPlan, EffectReceipt, EffectState,
    EffectLedgerRecord,
};

/// Bounds the complete encoded effect request to one MiB.
pub const MAXIMUM_REQUEST_BYTES: usize = 1024 * 1024;
/// Bounds executor receipt bytes to 64 KiB.
pub const MAXIMUM_RECEIPT_BYTES: usize = 64 * 1024;
/// Bounds retained UTF-8 diagnostic bytes to 4096 bytes.
pub const MAXIMUM_DIAGNOSTIC_BYTES: usize = 4096;
const EFFECT_VERSION: u8 = 2;
const CONTROLLER_EFFECT_VERSION: u8 = 3;
/// Identifies the record version retaining an Observe child reservation.
pub const RESERVED_OBSERVE_EFFECT_VERSION: u8 = 4;
/// Identifies the record version retaining Controller project-admission metadata.
pub const CONTROLLER_PROJECT_EFFECT_VERSION: u8 = 5;
const CONTROLLER_Q04_EFFECT_VERSION: u8 = 6;
const AUTHORITY_BOUND_FLAG: u8 = 1;
const MAXIMUM_DISPATCH_PACKET_BYTES: usize = MAXIMUM_REQUEST_BYTES;
const BODY_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.effect-body.v1\0";
const BINDING_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.effect-binding.v1\0";
const ATTEMPT_TOKEN_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.effect-attempt-token.v1\0";

/// Reports the original flat passive Effect refusal without Native owned causes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EffectHistoryDataError {
    /// The complete plan or encoded record exceeds bounds or has an invalid identity.
    #[error("invalid reconciliation plan: {0}")]
    InvalidPlan(&'static str),
    /// Retained bytes violate the complete closed historical grammar.
    #[error("corrupt durable effect ledger: {0}")]
    CorruptLedger(&'static str),
    /// Receipt bytes exceed the original executor DATA contract.
    #[error("effect executor violated its output contract: {0}")]
    InvalidExecutorOutput(&'static str),
}

impl From<crate::domain_ledger::project_admission_metadata::ProjectAdmissionMetadataDataErrorV1>
    for EffectHistoryDataError
{
    fn from(
        error: crate::domain_ledger::project_admission_metadata::ProjectAdmissionMetadataDataErrorV1,
    ) -> Self {
        match error {
            crate::domain_ledger::project_admission_metadata::ProjectAdmissionMetadataDataErrorV1::InvalidMetadata =>
                Self::CorruptLedger("invalid Controller project-admission metadata"),
        }
    }
}

#[cfg(test)]
mod tests;
