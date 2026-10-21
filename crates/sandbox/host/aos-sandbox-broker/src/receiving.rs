//! Shares original native receiving custody and nonauthorizing arithmetic.
//!
//! Semantic journals, signing handlers and Controller grants remain role-owned.
//! The closed Root initial lane admits only its same original fixed enrollment;
//! role-specific semantic stages continue over that actual native owner.

mod boot_preparation;
pub use boot_preparation::{RuntimeBootPreparationSourceCaptureV1, RuntimeBootPreparationStartupRolesV1,
    RuntimeBootPreparationReceivingClosedV1, RuntimeBootPreparationOriginComparisonDataV1};
mod fixed_service_currentness;
mod fixed_service_profile;
mod fixed_service_receiving;
mod fixed_service_operation;
mod network_child_origin;
pub use network_child_origin::{NetworkChildOriginClosedV2, NetworkChildOriginOriginalV2,
    NetworkChildSourceLoanV2, NetworkChildSourceProbeOriginalV2,
    NetworkChildSourceRecordOriginalV2, NetworkChildOperationBindingDataV2,
    NetworkChildSourceAffinityOriginalV2};
pub use fixed_service_operation::FixedServiceInventoryFdStoreEmptyOriginalV2;
pub use fixed_service_operation::HostControlColdClockOriginalV1;
pub use fixed_service_operation::NetworkWorkerInventoryObservationOriginalV4;
pub use fixed_service_operation::{NetworkWorkerBirthOriginalV2, NetworkWorkerBirthPurposeV2, NetworkWorkerBirthReservationV2};
mod network_receiving_aggregate;
mod fixed_service_listener;
mod fixed_service_startup;
mod fixed_service_transfer;
mod names;
mod observation_lifetime;
mod property_archive;
mod root_activation;
mod root_enrollment;
mod root_observation_error;
mod root_profile;
mod root_kernel;
mod root_initial;
mod root_purpose_posts;
pub use root_purpose_posts::{RootPurposePeerPostV1, RootPurposePeerPostsOriginalV1, RootPurposePostErrorV1};
mod root_subject_chunk;
mod root_subject_readiness;
pub use root_subject_readiness::RootSubjectReadinessV1;
mod root_open_clock;
pub use root_open_clock::{RootOpenClockClosedV1, RootOpenClockOriginalV1};
mod root_history_peer;
pub use root_history_peer::{RootHistoryPeerPostNativeOriginalV1, RootAcceptedHistoryBorrowerV1, RootOpenPhysicalBorrowerV1};
pub use root_history_peer::RootHistoryObservationOriginalV1;
pub(crate) mod root_invocation;
mod root_permanent;
mod root_startup_native;
mod root_selected;
mod root_currentness;
mod root_selected_currentness;
pub use root_selected_currentness::{RootSelectedStartupBorrowV1, RootSelectedCurrentnessFailureOriginalV1};
mod root_controller_policy_peer;
pub use root_controller_policy_peer::{RootControllerCurrentBorrowerV1, RootControllerPolicyPeerV1,
    RootSelectedControllerPeerOriginalV1, RootSelectedControllerCurrentSampleV1,
    RootSelectedControllerSubjectSampleV1,
    require_controller_process_identity_data_v1, selected_controller_resource_pair_data_v1,
    selected_controller_nix_profile_data_v1, decode_controller_policy_delivery_data_v1};
mod root_service;
mod pair;
mod representation;
pub mod receiving_limits;

pub use fixed_service_currentness::FixedServiceCurrentnessSampleV1;
pub use observation_lifetime::ObservationLifetimeV1;
pub use property_archive::{FixedPropertyArchiveV1, FixedPropertyArchiveGrowthErrorV1,
    fixed_property_observer_demand_v1 as fixed_property_archive_demand_v1,
    growing_fixed_property_archive_demand_v1};
pub use fixed_service_receiving::FixedServiceReceivingCaptureV1;
pub use fixed_service_operation::{FixedServiceOperationClosedV4, FixedServiceOperationOriginalV4,
    MountAttachmentAnchorReceivingLoanV4, NetworkServiceReceivingLoanV4, NetworkWorkerCleanupClockScopeV4, NetworkWorkerAggregateInitializationRefusalV4,
    MountServiceSessionOpeningLoanV4, NetworkServiceSessionOpeningLoanV4};
pub use fixed_service_listener::FixedServiceListenerOriginalV4;
pub use root_observation_error::RootObservationErrorV1;

mod q04_origin;
pub use q04_origin::{
    RootQ04OrdinaryTransportErrorV1, RootQ04OrdinaryTransportOriginalV1,
    RootQ04OriginBorrowerV1, RootQ04OriginErrorV1, RootQ04OriginInputCurrentLoanV1,
    RootQ04OriginLoanV1, RootQ04OriginNativeStreamLoanV1, RootQ04OriginPurposeV1,
};
pub use root_profile::RootProfileOriginalCaptureV1;
pub use root_initial::{
    RootQ04InputCurrentLoanV1, RootQ04NativeStreamLoanV1, RootQ04TransportOriginalV1,
    RootInitialReceivingOriginalV1, RootStartupServicePostErrorV1, RootSelectedProvisionBorrowV1,
    RootInitialRestoreFailureV1, RootNativeAdmissionErrorV1,
    RootPrearmedHistoryServicePostV1,
    RootInitialStartupFieldsV1, RootInitialStartupPartsV1,
    RootFinancialClosedV1, RootJournalFinancialBorrowV1, RootJournalFinancialOriginalV1,
    RootPolicyFlightDisposalV2, RootPolicyFlightFinancialDisposalV1,
    RootUpperRefusalOriginalV1, RootUpperFailureParkingV1, RootUpperMutationGuardV1,
};
pub use root_kernel::{RootKernelOriginalCaptureV1, RootKernelStartupPartsV1, RootKernelStartupFieldsV1};
pub use root_enrollment::{RootEnrollmentOriginalsV1, RootEnrollmentErrorV1};
pub use root_activation::{RootInitialActivationOriginalsV1, RootInitialActivationErrorV1};
pub use names::{ActivationNamesErrorV1, original_activation_names_v1};
pub use pair::{OriginalEnrollment, OriginalEnrollmentPairAttemptV1, OriginalPairErrorV1, observe_original_pair};
pub use representation::{FixedServiceRepresentationOriginalV1, FixedServiceRepresentationSlotV1, RepresentationDemandDebitV1};

#[cfg(test)]
mod source_profile_tests;
#[cfg(test)]
mod source_exec_transfer_tests;

pub use root_startup_native::{RootLegacyStartupCaptureV1, RootStartupNativeOriginalV1, RootStartupNativeFieldsV1};
pub use root_selected::RootSelectedStartupOriginalV1;

pub use root_startup_native::{read_root_bounded_confinement_data_v1, root_legacy_roles_match_data_v1};
pub use root_service::observe_root_comparison_at_v1;

pub use root_currentness::RootServiceCurrentnessOriginalV1;

mod root_peer_images;

pub use root_peer_images::{RootPeerImageObservationsV1,
    RootPeerImageObservationErrorV1, RootPeerImagesClosedV1};

mod fixed_signer_listener;
pub use fixed_signer_listener::{FixedSignerListenerOriginalV1, FixedSignerListenerClosedV1};

mod operation;
pub use operation::{ComponentReceivingOperationClosedV1, ComponentReceivingOperationLoanV1,
    ComponentReceivingOperationV1, ComponentReceivingOwnedOperationV1};

mod root_peer_observation;
pub use root_peer_observation::{RootPeerConnectionOriginalsV1, RootPeerObservationOriginalsV1,
    ROOT_PEER_PROPERTIES_V1, ROOT_PEER_MATERIALIZED_PROPERTY_BYTES_V1,
    require_root_process_identity_v1};

#[cfg(target_os = "linux")]
mod root_writer;
#[cfg(target_os = "linux")]
pub use root_writer::{
    RootAppendPostAdmissionErrorV1,
    RootAppendFailureOriginalV1, RootCoordinatorWriterV1, RootPreparedAppendV1,
    RootWriterErrorV1, RootWriterOpeningOriginalV1, RootWriterReplayV1, RootWriterPostOriginalV1,
    root_authority_journal_limits_data_v1,
};

/// Retains the same genuine Root replacement and original diagnostic source.
pub use root_writer::{RootPreparedReplacementV1, RootReplacementFailureOriginalV1};

mod root_indexed_transfer;

mod root_subject_geometry;
