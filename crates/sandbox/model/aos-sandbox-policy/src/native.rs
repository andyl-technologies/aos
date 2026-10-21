//! Retains actual fixed Root journal custody for protected Policy operations.
//!
//! The optional native owner composes the existing Broker opening/coordinator
//! with the sole full cold semantic replay and the same Root financial original.
//! Its private native fields cannot be adopted from a path, map, comparison
//! stamp or supplied native parts. Portable compilation does not enable it.

mod append;
mod authority;
mod error;
mod protected_transaction;
pub(crate) mod publication;
mod target;
mod startup;
mod root_current;
mod journal;
mod legacy_owner;
mod readonly;

pub use error::PolicyNativeJournalErrorV1;
#[cfg(any(test, feature = "test-fixtures"))]
pub use startup::RootStartupFixedAdmissionFixtureV1;
pub use root_current::{RootCurrentAcceptedOriginalsV1, RootCurrentWriterDemandErrorV1, RootInitialOpenErrorV1, RootOwnedCurrentOriginalV1};
pub use startup::{RootCompletedPolicyListenerBorrowV1, RootCompletedPolicyListenerOriginalV1, RootControllerPeerProvisionOriginalV1, RootCurrentWritersPredecessorV1, RootStartupControllerPeerOriginalV1, RootStartupProvisionErrorV1, RootStartupProvisionOriginalV1, RootStartupJournalOriginalV1, RootStartupCredentialWriterV1,
    RootStartupBindingReadErrorV1, RootStartupCredentialErrorV1, RootStartupJournalErrorV1, RootStartupJournalFailureOriginalV1};

/// Lends comparison queries from the actual completed fixed readonly owner.
pub use readonly::{
    RootCreateStoppedHistoricalOriginalV2, RootFixedNativeReadbackV1,
    DeleteAdmissionAuditInputsDataV3, RootDeleteAuxiliaryRowDataV3,
    RootReadonlyErrorV1, RootReadonlyModelOriginalsV1,
    RootFinalityNativeCutDataV1, RootFinalityReadKindV1, RootFinalityReadOriginalV1,
};
pub use legacy_owner::{PolicyCompilerProtectedOpenReportV1, PolicyCompilerProtectedOwnerV1};
pub use publication::PolicyCompilerJournalErrorV1;
pub use journal::{
    Q04ReadbackFailureV1, RootPolicyJournalServingIdentityV1, RootPolicyJournalConstructionOriginalV1, RootPolicyJournalPurposeV1, RootPolicyJournalV1,
};

pub use target::{
    PolicyTargetCurrentFailureV1, RootOriginalInputLoanV1, RootPolicyHistoryAdmissionFailureV1,
    RootPolicyPublicationErrorV1, RootPolicyPublicationWorkV1,
    RootPolicyTargetConstructionOriginalV1, RootPolicyTargetOriginalV1,
};

/// Retains one reached fixed Root name observation and its original failure.
pub use journal::names::RootPolicyNameObservationOriginalV1;

/// Owns the genuine ordinary Root genesis, successor and current archive loans.
pub use authority::{
    CurrentNixRootArchiveAttemptV1, CurrentRootFirstSourceSuccessorFloorV2,
    CurrentRootProjectSuccessorFloorV3, CurrentRootSourceGenesisFloorV1,
    CurrentRootSourceProjectGenesisFloorV3, RootFirstSourceSuccessorOpeningV2,
    RootFirstSuccessorMutationResultsV2, RootGenesisOpeningFailureV1,
    RootProjectGenesisMutationResultsV3, RootSourceGenesisAuthorityV1, RootStrictGenesisFailureV1,
    fixed_root_source_genesis_recovery_available_v1,
};

pub use authority::{
    RootAuthorityConstructionOriginalV1, RootAuthorityCurrentFailureV1, RootAuthorityErrorV1,
    RootAuthorityGen1LoanV1, RootAuthorityOriginalV1, RootAuthorityQ04FlightOriginalV1,
    RootAuthorityQ04HistoryV1,
};

/// Retains actual Root/Cache terminal reader failures and independent mount debt.
pub use authority::{RootAuthorityCacheTerminalErrorV1, RootAuthorityCacheTerminalOutcomeV1};

/// Identifies which actual owner retains a refused native Root append cause.
pub use authority::RootAuthorityQ04AppendFailureV1;


/// Owns the genuine fixed Policy-state writer and its nonauthorizing structural claims.
pub use publication::{
    CurrentNixPolicyOpeningV1, HeldResolvedRuntimePolicyV1, PolicyCompilerStateReadbackOwnerV1,
};

/// Exposes bounded canonical publication comparison DATA without native grants.
pub use publication::{
    DecodedCandidateHeaderV1, PolicyPublicationPrerequisitesV1,
    Q04IndependentPublicationRecipeV1, compare_recompiled_candidate_derivation_v1,
    q04_independent_publication_data_v1, validated_candidate_body,
};

/// Constructs ordinary private state fixtures through the real fixed native engine.
#[cfg(any(test, feature = "test-fixtures"))]
pub use publication::resolved_policy_fixture as policy_state_test_fixtures;

pub use root_current::RootInitialSubjectFrameBorrowV1;

pub use root_current::{RootInitialPinsBorrowV1, RootInitialPinsErrorV1, RootInitialPolicyInputsErrorV1, RootInitialTrustErrorV1};

pub use root_current::RootInitialSourceQueryErrorV1;

pub use root_current::RootInitialSourceExchangeErrorV1;

pub use root_current::{RootInitialBundleOwnershipErrorV1, RootInitialBundleOwnershipFrameBorrowV1};

/// Retains the finite Initial Cache proof error and same-owner frame stages.
pub use root_current::{RootInitialCacheProofErrorV1, RootInitialCacheProofFrameBorrowV1};

pub use root_current::{
    RootInitialControllerReadonlyErrorV1, RootInitialControllerReadonlyPreparedBorrowV1,
    RootInitialControllerReadonlyReplayBorrowV1,
};

mod no_apply;
pub use no_apply::{RootNoApplyControllerPeerOriginalV2, RootNoApplyStageDataV2,
    RootExecutionNoApplyReadPhaseV2};

/// Borrows the genuine native Root UseAuthorized body and passive proposal inputs.
pub use root_current::{RootInitialUseAuthorizedErrorV1,
    RootInitialUseAuthorizedPreparedBorrowV1, RootInitialUseProspectiveInputsDataV1};

pub use root_current::RootUseReservedErrorV1;

pub use root_current::RootUseAdmittedErrorV1;

pub use root_current::{RootSignedBoundErrorV1, RootSignedInputBorrowV1, RootSignedInputErrorV1};
