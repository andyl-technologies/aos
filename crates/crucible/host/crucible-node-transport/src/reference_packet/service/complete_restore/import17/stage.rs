//! Defines distinct stage17 wire DATA under explicit full stage18 selection.
//!
//! The portable vocabulary supplies phase names and separate key domains. Closed
//! binding, context, proof and receipt records bind complete preceding new18
//! import DATA to exact baseline Arm/World/Observe assignments. Their validators,
//! canonical hashes and MACs create no Source grant, native model, current SDK
//! occurrence, physical Hold, released World or accepted observation witness.

pub use crucible_source_birth_data::profile::reference_packet::service::complete_restore::import17::stage::*;

use super::super::PACKET_COMPLETE_RESTORE_ALGORITHM;
use super::{bounded, digest32, same_digest};
use crate::ProviderError;
use crucible_node_format::canonical;

mod assigned;
mod crypto;
mod data;
mod retained;

#[cfg(test)]
mod tests;

pub use assigned::{
    native_import18_stage_assigned_request_digest, native_import18_stage_assigned_response_digest,
};
pub use crypto::{
    PacketNativeImport17StageContext, PacketNativeImport17StageProof,
    PacketNativeImport17StageReceipt, native_import17_stage_proof_data,
    native_import17_stage_receipt_data, verify_native_import17_stage_proof_data,
    verify_native_import17_stage_receipt_data,
};
pub use data::{
    PacketNativeImport17StageBinding, PacketNativeImport17StageCommitData,
    PacketNativeImport17StagePairData, PacketNativeImport17StagePrepareData,
};

fn invalid() -> ProviderError {
    ProviderError::Correlation("complete native stage17 DATA under stage18 selection")
}
