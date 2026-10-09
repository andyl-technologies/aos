//! Bounded authenticated controller transport and immutable original request custody.
//!
//! [`ClientSession`] binds actual Unix peer facts to a trusted installed hello
//! verifier. [`ClientCustody`] retains original requests and content across
//! transport replacement. These components do not qualify native execution:
//! the installed node adapter must independently verify complete receipt bytes,
//! owner scope and actual process resources before publishing runtime evidence.

mod content;
mod deadline;
mod reference;
mod session;

pub use content::ClientContent;
pub use deadline::{DeadlineStream, ExchangeDeadline};
pub use reference::{
    ObservationHandle, ObservationLimits, ObservationScope, ObservedContent, ObservedRequest,
    ObservedRequestKey, RecordedReferenceObservation, ReferenceController,
    ReferenceObservationSnapshot, TransmissionLimits, TransmissionObservation,
    TransmissionObservationHandle,
};
pub use session::{ClientCustody, ClientOriginal, ClientPeer, ClientSession};
