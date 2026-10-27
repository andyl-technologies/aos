//! Composes the sole Controller genesis comparison decoder with actual pins.
//!
//! These private adapters preserve the strict and project signed purposes. The
//! genuine Genesis session supplies its retained role key, nonce and UIDs.

use aos_sandbox_ledger_replay::source_signer_data::controller_genesis_readback::{
    self as canonical, ControllerGenesisReadbackDataV1, ControllerGenesisReadbackRecipeV3,
};

use crate::controller_readback::PinnedControllerHoldSignerV1;

use super::super::RootAuthorityErrorV1;

pub(super) fn verify(
    packet: &[u8],
    pin: &PinnedControllerHoldSignerV1,
    nonce: [u8; 16],
    controller_uid: u32,
    source_uid: u32,
) -> Result<ControllerGenesisReadbackDataV1, RootAuthorityErrorV1> {
    verify_with_recipe(
        packet,
        pin,
        nonce,
        controller_uid,
        source_uid,
        ControllerGenesisReadbackRecipeV3::StrictV1,
    )
}

pub(super) fn verify_project_genesis_v3(
    packet: &[u8],
    pin: &PinnedControllerHoldSignerV1,
    nonce: [u8; 16],
    controller_uid: u32,
    source_uid: u32,
) -> Result<ControllerGenesisReadbackDataV1, RootAuthorityErrorV1> {
    verify_with_recipe(
        packet,
        pin,
        nonce,
        controller_uid,
        source_uid,
        ControllerGenesisReadbackRecipeV3::ProjectV3,
    )
}

fn verify_with_recipe(
    packet: &[u8],
    pin: &PinnedControllerHoldSignerV1,
    nonce: [u8; 16],
    controller_uid: u32,
    source_uid: u32,
    recipe: ControllerGenesisReadbackRecipeV3,
) -> Result<ControllerGenesisReadbackDataV1, RootAuthorityErrorV1> {
    canonical::verify_controller_source_genesis_readback_v1(
        packet,
        pin.generation(),
        pin.verifying_key(),
        nonce,
        controller_uid,
        source_uid,
        recipe,
    )
    .map_err(RootAuthorityErrorV1::from)
}

pub(super) fn packet_digest(packet: &[u8]) -> aos_sandbox_model::ObjectDigest {
    aos_sandbox_ledger_replay::data::hash(canonical::DOMAIN, packet)
}
