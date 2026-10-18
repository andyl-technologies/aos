//! Keeps current logical Producer values separate from live permissions.
//!
//! The strict Producer component joins its actual SDK pairs, unchanged native
//! completed/retired predicates, common mapping and Source transcript. The
//! enclosing Source17 reader must still verify first/current observation,
//! Capture bridge, immutable ancestry and the whole selected installation.

#[path = "logical/producer.rs"]
mod producer;
#[path = "logical/producer_fields.rs"]
mod producer_fields;
#[path = "logical/producer_reader.rs"]
mod producer_reader;

pub(crate) use producer_reader::{
    OriginalSourceRestoredProducerCheckpoint17, OriginalSourceRestoredProducerHistory17Read,
};

#[path = "logical/first_observation_reader.rs"]
mod first_observation_reader;
pub(crate) use first_observation_reader::OriginalSourceRestoredFirstObservationHistory17Read;

#[path = "logical/capture_bridge_reader.rs"]
mod capture_bridge_reader;
pub(crate) use capture_bridge_reader::OriginalSourceRestoredCaptureAdminBridgeHistory17Read;

#[path = "logical/capture_ledger_reader.rs"]
mod capture_ledger_reader;
pub(crate) use capture_ledger_reader::{
    OriginalSourceCaptureHousekeeping17Read, OriginalSourcePreEncoderCaptureHousekeeping17Read,
};

#[path = "logical/source_ancestry.rs"]
mod source_ancestry;
#[path = "logical/source_fields.rs"]
mod source_fields;
#[path = "logical/source_prefix.rs"]
mod source_prefix;
#[path = "logical/source_reader.rs"]
mod source_reader;
pub(crate) use source_fields::{
    OriginalSourceRestoredInstallation17, OriginalSourceRestoredInstallationExpected17,
    OriginalSourceRestoredLimits17,
};
pub(crate) use source_reader::{
    OriginalSourceRestoredSettled17DecodeAttempt, OriginalSourceRestoredSettled17Read,
    OriginalSourceRestoredSettled17ReadInputs,
};

#[path = "logical/source_writer.rs"]
mod source_writer;
pub(in crate::node_adapters::cnp::semantic::packet_complete_source) use source_writer::{
    OriginalSourceRestoredSettled17WriteInputs, OriginalSourceRestoredSettledSemantic17View,
};

#[path = "logical/world.rs"]
mod world;
pub(in crate::node_adapters::cnp::semantic::packet_complete_source) use world::OriginalSourceRestoredWorld17View;
