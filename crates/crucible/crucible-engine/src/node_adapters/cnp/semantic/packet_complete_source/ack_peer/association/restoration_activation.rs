//! Signs separately admitted restoration activation from one genuine Source.
//!
//! The Core Window owns each once claim. Source authenticates the completed
//! Commit, signs the real SDK-assigned unsigned activation request, retains its
//! originals and native evidence, and repeats the final member/kernel fence.
//! Its independent owner preserves failed partials without widening legacy11
//! or the existing Prepare/Inputs/Commit signer and without reusing their row.

use super::typed_decoder_backing as typed_backing;
use super::*;
use crate::node_admission::{
    OriginalInstalledRestorationActivationClaim, OriginalInstalledRestorationActivationPhase,
    OriginalInstalledRestorationActivationSigningConstructionInputs,
    OriginalInstalledRestorationActivationSigningInputs,
};
use crate::node_contract::{NodeRuntime, RuntimeError};
use crucible_node_format::{Bytes, ContentRef, Id};
use crucible_node_transport::{
    bodies::ResponseBody,
    reference_packet::{
        control::PacketNative5UnderlyingRecord,
        service::complete_restore::{
            PacketNativeRestoredCommitHold, PacketNativeRestoredRecord,
            activation::{upload::*, *},
        },
    },
};
use std::mem::size_of;

#[path = "restoration_activation/owner.rs"]
mod owner;
pub(super) use owner::OriginalSourceRestorationActivationAttempt;
#[path = "restoration_activation/construction_data.rs"]
mod construction_data;
pub use construction_data::OriginalSourceRestorationActivationConstructionData;
#[path = "restoration_activation/construction.rs"]
mod construction;
#[path = "restoration_activation/projection.rs"]
mod projection;
// Reuses the existing nonallocating closed Strings/Bytes/Value decoder census.
// Neither the legacy signer implementation nor its accounting is changed.
#[path = "restoration_activation/request.rs"]
mod request;
#[path = "restoration_activation/world.rs"]
mod world;
use world::{authenticate_world_command, authenticate_world_manifest};
#[path = "restoration_activation/effect.rs"]
mod effect;
#[path = "restoration_activation/evidence.rs"]
mod evidence;
#[path = "restoration_activation/upload.rs"]
mod upload;
#[path = "restoration_activation/world_content.rs"]
mod world_content;
pub use evidence::OriginalSourceRestorationActivationVerifiedPhase;
use evidence::authenticate_saved_pair;
pub(super) use evidence::with_verified_world_under_read_data;

fn provider_phase(
    phase: OriginalInstalledRestorationActivationPhase,
) -> PacketRestorationActivationPhase {
    match phase {
        OriginalInstalledRestorationActivationPhase::Arm => PacketRestorationActivationPhase::Arm,
        OriginalInstalledRestorationActivationPhase::WorldActivate => {
            PacketRestorationActivationPhase::WorldActivate
        }
    }
}

fn sum<const N: usize>(terms: [usize; N], maximum: usize) -> Result<usize, RuntimeError> {
    crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::sum_with_error::<
        RuntimeError,
        _,
    >(terms, maximum)
}
