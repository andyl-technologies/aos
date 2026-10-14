//! Bounded authenticated controller transport and immutable original request custody.
//!
//! [`ClientSession`] binds actual Unix peer facts to a trusted installed hello
//! verifier. [`ClientCustody`] retains original requests and content across
//! transport replacement. These components do not qualify native execution:
//! the installed node adapter must independently verify complete receipt bytes,
//! owner scope and actual process resources before publishing runtime evidence.

mod content;
mod controller;
mod deadline;
pub(crate) mod history_credit;
mod reference;
mod session;

pub use content::ClientContent;
pub use controller::{CnpController, CnpRegistrarRead, ControllerRoute};
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
