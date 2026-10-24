//! Installs a distinct connected packet collecting scope and Refused population.
//!
//! Source metadata, original measured files and concrete native current reads
//! remain separate conjunctions. Neither this source-owned structural installer
//! nor its data-only witness plan supplies ordinary class acceptance or Ready.

use crate::node_qualification::QualificationError;

mod authority;
mod graph;
mod host;
mod population;
mod publication;
mod records;
mod roster;
mod schedule;
mod witness;

pub use authority::{
    InstalledPacketConnectedCollectionAuthority, PacketConnectedCollectionRequest,
};

pub use graph::{
    InstalledPacketConnectedGraphPolicy, PacketConnectedGraphOwner, PacketConnectedGraphRequest,
};
pub use population::{PacketConnectedPopulationRequest, PacketConnectedWitnessPopulation};
pub use records::{
    packet_connected_independent_graph_contract, packet_connected_measured_graph_proof,
};
pub use roster::{PacketConnectedParticipant, PacketConnectedRoster};
pub use schedule::{
    PacketConnectedCase, PacketConnectedCaseKind, PacketConnectedGrant, PacketConnectedSchedule,
};

fn refused() -> QualificationError {
    QualificationError::Refused("complete original connected packet collecting scope unavailable")
}

pub use witness::{PacketConnectedNativeOracle, PacketConnectedOracleRequest};

pub use host::{PacketConnectedHost, PacketConnectedHostRequest};
pub use publication::{PacketConnectedPublicationRequest, StoredPacketConnectedResultPublisher};

pub use super::peer::{
    PacketConnectedPeerLaunchFailure, PacketConnectedPeerLaunchRequest, PreparedPacketConnectedPeer,
};
