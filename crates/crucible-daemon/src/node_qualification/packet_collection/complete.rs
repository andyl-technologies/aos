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
mod population;
mod records;
pub(super) mod retained;
mod roster;

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
    PacketCompletePreparationConnection, PacketCompleteReportStartupHolder,
};
pub use population::{PacketCompletePopulationRequest, PacketCompleteWitnessPopulation};

mod witness;
pub use witness::{PacketCompleteNativeOracle, PacketCompleteOracleRequest};
