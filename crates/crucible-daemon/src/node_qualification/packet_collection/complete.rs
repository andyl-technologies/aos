//! Owns structural collecting bootstrap for native-three/Host2 complete selections.
//!
//! This namespace preserves the connected-four policy and grants no Capture
//! qualification from declarations. Installed source/factory association and
//! selected physical geometry remain independent before ticket dispatch.

mod authority;
mod capture_factory;
mod capture_records;
pub use capture_factory::{
    PacketCompleteArchiveCodeFactory, PacketCompleteCaptureFactory,
    PacketCompleteRestorationPrebirth, PacketCompleteWorldCapture,
};

mod execution;
pub use execution::{
    PacketCompleteExecutionActor, PacketCompleteExecutionError, PacketCompleteExecutionScene,
    PacketCompleteRuntimeAttachmentFailure,
};

mod graph;
mod installed;
mod population;
mod publication;
mod restored_publication;
pub use publication::{PacketCompletePublicationRequest, StoredPacketCompleteResultPublisher};
pub use restored_publication::PacketRestoredProducerPublicationInputs;
mod records;
pub(crate) mod retained;
mod roster;
pub use installed::{
    InstalledCompleteRestoration, InstalledCompleteScene, InstalledCompleteSceneManifest,
    PreparedCompleteRestoration,
};

pub use graph::{
    InstalledPacketCompleteGraphPolicy, PacketCompleteGraphOwner, PacketCompleteGraphRequest,
};
pub use records::{
    packet_complete_independent_graph_contract, packet_complete_measured_graph_proof,
};
pub use roster::PacketCompleteRoster;

use super::QualificationError;

fn refused() -> QualificationError {
    QualificationError::Refused("complete original packet collecting scope unavailable")
}

#[cfg(test)]
mod tests;

pub use authority::{
    InstalledPacketCompleteCollectionAuthority, PacketCompleteCollectionRequest,
    PacketCompleteNativeLaunchInputs, PacketCompleteOriginalSceneInputs,
    PacketCompletePreparationConnection, PacketCompleteReportStartupHolder,
};
pub use population::{PacketCompletePopulationRequest, PacketCompleteWitnessPopulation};

mod witness;
pub use witness::{PacketCompleteNativeOracle, PacketCompleteOracleRequest};

pub use authority::PacketCompleteOriginalSceneSupervisor;

mod construction_diagnostics;

pub use authority::PacketCompleteFreshRestorationInputs;
