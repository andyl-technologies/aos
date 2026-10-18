//! Bounded authenticated controller transport and immutable original request custody.
//!
//! [`ClientSession`] binds actual Unix peer facts to a trusted installed hello
//! verifier. [`ClientCustody`] retains original requests and content across
//! transport replacement. These components do not qualify native execution:
//! the installed node adapter must independently verify complete receipt bytes,
//! owner scope and actual process resources before publishing runtime evidence.

mod content;
mod controller;
pub(crate) use controller::maximum_canonical_ack_framed_bytes;
mod deadline;
pub(crate) mod history_credit;
pub(crate) mod history_encoding17;
mod reference;
mod session;

pub use crate::connection::CanonicalAckCodecMetadataExtent;
pub use content::ClientContent;
pub use controller::{
    CnpController, CnpRegistrarRead, ControllerRoute, InstalledArchivedProtocolState,
    OriginalCanonicalBlobAckEmitter, OriginalCanonicalRestoreInputEmitter,
    OriginalCompleteRestoreInputUpload, OriginalCompleteRestoreInputUploadProspectiveStorageData,
    OriginalCompleteRestoreInputUploadStorageData, OriginalCompleteRestoreUploadBeforeMappingData,
    OriginalCompletedRestoredObservation17Data, OriginalFreshRestorePrepareBindingStorageData,
    OriginalFreshRestoreQuery, OriginalFreshRestoreQueryStorageData,
};
pub use controller::{CompletedOriginalCanonicalAckAdmit, PreparedOriginalCanonicalAckAdmit};
pub use controller::{
    CompletedOriginalCompleteRestore, CompletedOriginalCompleteRestoreTransfer,
    PreparedOriginalCompleteRestore, PreparedOriginalCompleteRestoreTransfer,
};
pub use deadline::{
    DeadlineStream, DeadlineStreamBirthRefusal, ExchangeDeadline, OriginalNative5BirthCut,
    OriginalNative5BirthStream, OriginalNative5BirthStreamRefusal,
};
pub use reference::{
    LineageWindowRequests, ObservationHandle, ObservationLimits, ObservationScope, ObservedContent,
    ObservedRequest, ObservedRequestKey, OriginalConflictLimits, OriginalConflictObservation,
    OriginalConflictObservationHandle, OriginalConflictReservation, OriginalLineageAcknowledgement,
    OriginalLineageEvidence, OriginalLineageObject, OriginalLineageRealization,
    OriginalLineageWindow, OriginalResponseLossObservation, OriginalResponseLossObservationHandle,
    OriginalResponseLossQualification, RecordedReferenceObservation, ReferenceController,
    ReferenceControllerPreparationFailure, ReferenceObservationSnapshot, TransmissionLimits,
    TransmissionObservation, TransmissionObservationHandle,
};
pub use session::{
    ClientCustody, ClientOriginal, ClientPeer, ClientSession, OriginalHelloJournal,
    OriginalNative5CustodyFacts,
};

/// Exposes bounded source-private content decoding data without source rights.
pub use content::compact_cursor;
/// Exposes the explicit data-only content-eight metadata capacity grammar.
pub use content::compact_metadata8;

pub(crate) mod host_startup;
pub use host_startup::{
    OriginalPacketHostStartup, PacketNativeHostStartupInputs, PacketNativeHostStartupStorageData,
    original_packet_host_startup_counter_scratch_data, original_packet_host_startup_storage_data,
};

pub use controller::OriginalPacketHostInitialResponse;

pub use host_startup::{
    OriginalPacketHostInitialAttachmentScope, OriginalPacketHostInitialAttachmentSink,
    PacketNativeHostInitialLifecycleStorageData,
    original_packet_host_initial_lifecycle_counter_scratch_data,
    original_packet_host_initial_socket_counter_scratch_data,
};

/// Counts fixed typed SDK descriptor-observer headers without opening handles.
pub use host_startup::original_packet_host_descriptor_counter_scratch_data;

pub use host_startup::{
    original_host_source_json_counter_scratch_data, original_host_source_json_extent_storage_data,
    original_host_source_json_occurrence_storage_data,
};

/// Names actual assigned activation originals without issuing phase claims.
pub use controller::{
    CompletedOriginalInstalledRestorationActivation,
    CompletedOriginalInstalledRestorationObservation,
    OriginalRestorationActivationTargetBindingData, PreparedOriginalInstalledRestorationActivation,
    PreparedOriginalInstalledRestorationObservation,
};

pub use controller::{
    CompletedOriginalInstalledRestorationUpload, PreparedOriginalInstalledRestorationUpload,
};

/// Exposes retained ordinary suffix originals without issuing execution claims.
pub use controller::{
    OriginalRestoredSuffixBody, OriginalRestoredSuffixHostAttempt,
    OriginalRestoredSuffixHostHistoricalData, PreparedOriginalRestoredSuffixHostAttempt,
};

pub use controller::{
    OriginalCompletedRestoredSettledCaptureData, OriginalRestoredSettledCaptureData,
    PreparedOriginalRestoredSettledCapture, PreparedRestoredSettledCaptureAuxiliaryOriginal,
    RestoredSettledCaptureAuxiliaryBody,
};

pub use controller::{
    OriginalRestoredSettledCaptureConstructionData, OriginalRestoredSettledCaptureProspectiveData,
    RestoredSettledCaptureTypedOwnerData,
};

pub use controller::ControllerSettledHistoryData;

pub(crate) use controller::{
    original_suffix_response_references_counter_scratch_data,
    original_suffix_response_references_data,
};

pub use controller::{
    OriginalObservationReceiveStorageData, OriginalRestoredObservation17AssignmentStorageData,
};
