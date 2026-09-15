//! Dormant immutable environment-generation commitments.
//!
//! The portable core `Environment` describes runtime closure semantics. This
//! module additionally binds the source, lock, selected output, target,
//! facade, policy, and disclosure inputs needed to identify one realization.
//! It is intentionally not connected to execution admission or Nix services.

mod activation_format;
mod checkpoint_format;
mod format;
mod journal;
mod lifecycle;
mod model;
mod protected_evidence;
pub mod protected_journal;
pub(crate) mod protected_owner;

pub use activation_format::{
    decode_environment_activation_v1, encode_environment_activation_v1,
    environment_activation_digest_v1,
};
pub use checkpoint_format::{
    decode_environment_activation_checkpoint_v1, decode_environment_generation_checkpoint_v1,
    encode_environment_activation_checkpoint_v1, encode_environment_generation_checkpoint_v1,
};
pub use format::{
    decode_environment_generation_v1, encode_environment_generation_v1,
    environment_manifest_digest_v1,
};
pub use journal::{
    ENVIRONMENT_JOURNAL_NAMESPACE_V1, EnvironmentAcceptedRecordSetV1, EnvironmentAcceptedRecordV1,
    EnvironmentBootRolloverAuthorityV1, EnvironmentJournalHistoryV1,
    EnvironmentJournalOwnershipRecordV1, EnvironmentJournalRecordKindV1,
    EnvironmentJournalVerifierV1, decode_environment_journal_record_v1,
    encode_environment_journal_record_v1, environment_custodied_payload_digest_v1,
    environment_record_namespace_v1,
};
pub use lifecycle::{
    EnvironmentActivationCheckpointV1, EnvironmentActivationHistoryV1,
    EnvironmentActivationPhaseV1, EnvironmentActivationTransactionV1, EnvironmentBootIdV1,
    EnvironmentGcRootAcknowledgementV1, EnvironmentGenerationLeaseStatusV1,
    EnvironmentGenerationLeaseV1, EnvironmentLeaseConsumerV1, EnvironmentLeaseTimeV1,
    EnvironmentSelectorV1, EnvironmentTrustedTimeV1, MAXIMUM_ENVIRONMENT_ACTIVATION_BYTES,
    MAXIMUM_ENVIRONMENT_ACTIVATION_RECORDS,
};
pub use model::{
    EnvironmentDescriptorRoleV1, EnvironmentFacadeV1, EnvironmentGenerationCheckpointV1,
    EnvironmentGenerationHistoryV1, EnvironmentGenerationManifestV1, EnvironmentHistoryError,
    EnvironmentInputCommitmentV1, EnvironmentManifestDigestV1, EnvironmentModelError,
    EnvironmentPredecessorV1, EnvironmentTargetSystemV1, MAXIMUM_ENVIRONMENT_INPUTS,
    MAXIMUM_INLINE_ENVIRONMENT_BYTES, MAXIMUM_SELECTED_OUTPUT_BYTES, MAXIMUM_TARGET_SYSTEM_BYTES,
    SelectedEnvironmentOutputV1,
};
pub use protected_evidence::{
    EnvironmentProtectedEvidenceErrorV1, EnvironmentProtectedEvidenceOwnerV1,
};
pub use protected_owner::EnvironmentProtectedJournalOwnerV1;
