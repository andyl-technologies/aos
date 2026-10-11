//! Source-installed translation of generic CNP realization and original operations.
//!
//! The public transport does not define arbitrary role receipt semantics. This
//! module requires a separately installed native oracle and behavioral acceptance
//! authority before mapping a realized provider into common node operations.
//! The legacy checksum realization and receipt dialect remain independent.

mod budget;
mod conformance;
mod implementation;
mod input;
mod lifecycle;
mod node;
mod operations;
mod packet_grant;
mod packet_source;
mod preparation;
mod process;
mod provider;
mod registry;
mod source;
mod state;

pub use conformance::{
    CnpSemanticConformanceAuthority, CnpSemanticConformanceNode, CnpSemanticConformanceProvider,
    InstalledCnpConformanceRole,
};
pub use node::{CnpSemanticAdmissionFailure, CnpSemanticNode};
pub use packet_grant::packet_common_grant_authorization;
pub use packet_source::{PacketNativeWitness, PacketSemanticSource};
pub use provider::{CnpSemanticProvider, CnpSemanticProviderFailure};
pub use registry::{CnpSemanticRegistrationPolicy, CnpSemanticRegistry, InstalledCnpSemanticRole};

pub use preparation::{CnpSemanticPreparation, CnpSemanticPreparationFailure};
pub use process::{
    CnpSemanticAttachmentFailure, CnpSemanticLaunchFailure, CnpSemanticLaunchGuard,
    CnpSemanticLaunchReservation, CnpSemanticProcessCustody, CnpSemanticProcessSlot,
    CnpSemanticReservationFailure, CnpSemanticSourceRead,
};
pub use source::{
    CnpSemanticAcceptance, CnpSemanticInstallation, CnpSemanticRealizationScope, CnpSemanticSource,
    CnpSemanticTransition,
};

use crate::node_contract::{EffectKnowledge, OperationFailure};

fn refused(reason: impl Into<String>) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::None,
        reason: reason.into(),
    }
}

fn unknown(reason: impl std::fmt::Display) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::Unknown,
        reason: reason.to_string(),
    }
}

fn after_effect(mut failure: OperationFailure) -> OperationFailure {
    failure.effects = EffectKnowledge::Unknown;
    failure
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- Fixture assertions reject inconsistent complete source selections.
    // crucible-lint: allow rust-allow -- Test constructors use panics as failed selected-record assertions.
    #[allow(clippy::unwrap_used)]
    mod packet_definition;
    // crucible-lint: allow panic-shortcut -- Selected source roster and actual native Arm controls fail on broken fixture evidence.
    // crucible-lint: allow rust-allow -- Test constructors panic only on inconsistent original setup or failed evidence assertions.
    #[allow(clippy::unwrap_used)]
    mod packet_coordinator;
    // crucible-lint: allow panic-shortcut -- Actual native socket and FIFO witnesses fail on lost originals or forbidden effects.
    // crucible-lint: allow rust-allow -- The source process cohort uses panics only for failed native/test observations.
    mod operational_poll;
    // crucible-lint: allow panic-shortcut -- Actual native socket and FIFO witnesses fail on lost originals or forbidden effects.
    #[allow(clippy::unwrap_used)]
    mod packet_execution;
    // crucible-lint: allow panic-shortcut -- Actual process fixture assertions panic on lost originals or incorrect admission ordering.
    // crucible-lint: allow rust-allow -- Tests report failed native custody assertions by panic.
    #[allow(clippy::unwrap_used)]
    mod packet_preparation;
    // crucible-lint: allow panic-shortcut -- Shared fixture codecs fail on malformed original setup.
    // crucible-lint: allow rust-allow -- Only native/test fixture constructors use panics.
    #[allow(clippy::unwrap_used)]
    mod packet_protocol;
    mod process;
}
