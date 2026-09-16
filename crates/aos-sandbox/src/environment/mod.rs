//! Dormant immutable environment-generation commitments.
//!
//! The portable core `Environment` describes runtime closure semantics. This
//! module additionally binds the source, lock, selected output, target,
//! facade, policy, and disclosure inputs needed to identify one realization.
//! A fixed-owner seam can gate execution admission and a future constrained
//! Nix build effect; this crate does not activate either effect.

mod activation_format;
mod authority_clock;
mod checkpoint_format;
mod execution;
mod format;
mod journal;
mod lifecycle;
mod model;
mod nix_build_owner;
mod nix_client;
mod nix_effect_adapter;
mod protected_evidence;
pub mod protected_journal;
pub(crate) mod protected_owner;

pub(crate) use authority_clock::{
    FixedLiveAuthorityClockV1, LiveAuthorityClockSampleV1, fixed_live_authority_clock_v1,
    validate_bracketed_samples_v1,
};

pub use activation_format::{
    decode_environment_activation_v1, encode_environment_activation_v1,
    environment_activation_digest_v1,
};
pub use checkpoint_format::{
    decode_environment_activation_checkpoint_v1, decode_environment_generation_checkpoint_v1,
    encode_environment_activation_checkpoint_v1, encode_environment_generation_checkpoint_v1,
};
pub use execution::{
    DormantEnvironmentRuntimeAdmissionConsumerV1, DormantNixBuildEffectV1,
    EnvironmentExecutionAdmissionV1, EnvironmentExecutionErrorV1,
    EnvironmentRuntimeAdmissionOutcomeV1, MAXIMUM_NIX_BUILD_CONTROL_BYTES,
    MAXIMUM_NIX_STORE_OBJECT_NAME_BYTES, MAXIMUM_NIX_STORE_PRESENTATION_OBJECTS,
    NixBuildAuthorityFenceV1, NixBuildEffectHandoffV1, NixBuildEffectOutcomeV1, NixBuildPhaseV1,
    NixBuildPolicyV1, NixBuildPrepareOutcomeV1, NixBuildPrepareRecoveryV1, NixBuildRequestV1,
    NixBuildSettlementOutcomeV1, NixBuildSettlementRecoveryV1, NixBuildSettlementRetryV1,
    NixBuildSettlementUnknownV1, NixBuildStateV1, NixBuildTransportV1, NixStorePathV1,
    NixStorePresentationEntryV1, NixStorePresentationKindV1, ReadOnlyNixStorePresentationV1,
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
pub use nix_build_owner::{
    NixBuildProtectedCapabilityOwnerV1, NixBuildProtectedObservationOwnerV1,
    NixBuildProtectedOwnerErrorV1,
};
pub use nix_client::{
    DENIED_NIX_AUTHORITIES_V1, DeniedNixAuthorityV1, NixClientBoundaryV1,
    NixNarrowingProxyOperationV1, NixNarrowingProxyPolicyV1, NixStoreTrustDomainV1,
    UNTRUSTED_NIX_DAEMON_SETTINGS_V1, UntrustedNixClientConfigurationV1,
};
pub use nix_effect_adapter::{
    ProtectedNixBuildBackendV1, ProtectedNixBuildEffectAdapterV1, ProtectedNixBuildEffectErrorV1,
    ProtectedNixBuildInvocationV1,
};
pub use protected_evidence::{
    EnvironmentProtectedEvidenceErrorV1, EnvironmentProtectedEvidenceOwnerV1,
};
pub use protected_owner::EnvironmentProtectedJournalOwnerV1;
