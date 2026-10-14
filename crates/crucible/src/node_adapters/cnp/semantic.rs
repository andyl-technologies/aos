//! Source-installed translation of generic CNP realization and original operations.
//!
//! The public transport does not define arbitrary role receipt semantics. This
//! module requires a separately installed native oracle and behavioral acceptance
//! authority for ordinary mapping into common node operations. A separate
//! opaque collecting route authenticates its original Refused fixture plan and
//! source custody; that route grants no ordinary behavioral qualification.
//! The legacy checksum realization and receipt dialect remain independent.

mod budget;
mod capture;
mod conformance;
mod implementation;
mod input;
mod lifecycle;
mod node;
mod operations;
mod packet_complete_source;
mod packet_connected_source;
mod packet_grant;
mod packet_lineage;
mod packet_source;
mod preparation;
mod process;
mod provider;
mod registry;
mod source;
mod semantic_snapshot;
mod state;
mod world_provider;

pub use capture::CnpSemanticCaptureScope;
pub use semantic_snapshot::{CnpOriginalSemanticSnapshot, CnpSemanticSnapshotReservation};

pub use conformance::{
    CnpSemanticConformanceAuthority, CnpSemanticConformanceNode, CnpSemanticConformanceProvider,
    InstalledCnpConformanceRole,
};
pub use world_provider::{
    CnpSemanticConformanceWorldProvider, CnpSemanticExactConformanceWorldProvider,
    CnpSemanticExactWorldReservation, CnpSemanticExactWorldReservationFailure,
    CnpSemanticWorldPreparationFailure, CnpSemanticWorldReservationFailure,
};

pub use node::{CnpSemanticAdmissionFailure, CnpSemanticNode};
pub use packet_complete_source::{PacketCompleteCaptureBankFacts, PacketCompleteCaptureBankLimits, PacketCompleteEffectReceiverGroup, PacketCompleteEffectReceiverReader, PacketCompleteNativeRecord, PacketCompleteNativeWitness, PacketCompleteSemanticSource, PacketCompleteSourceRole};
pub use packet_connected_source::{
    PacketConnectedInputWitness, PacketConnectedNativeWitness, PacketConnectedSemanticSource,
};
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
    // crucible-lint: allow panic-shortcut -- Actual phased byte/socket controls panic on failed source custody assertions.
    // crucible-lint: allow rust-allow -- Source component fixtures use panics only to reject broken original evidence.
    #[allow(clippy::unwrap_used)]
    mod packet_connected;
    // crucible-lint: allow panic-shortcut -- Actual native datagram/projection assertions fail on lost originals or forbidden phase effects.
    // crucible-lint: allow rust-allow -- These test-only fixture constructors intentionally panic on invalid source evidence.
    #[allow(clippy::unwrap_used)]
    mod packet_connected_source;
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
