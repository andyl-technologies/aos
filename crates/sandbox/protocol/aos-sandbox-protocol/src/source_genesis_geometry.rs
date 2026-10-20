//! Canonical fixed geometry of Source genesis comparison records and frames.
//!
//! These lengths describe wire DATA only. They grant no role, live flight,
//! signature verification, financial allowance or original-owner custody.

/// Bounds the unsigned legacy Controller genesis comparison body.
pub const CONTROLLER_SOURCE_GENESIS_BODY_BYTES_V1: usize = 800;
/// Bounds the unsigned legacy Source genesis comparison body.
pub const SOURCE_TREE_GENESIS_BODY_BYTES_V1: usize = 864;
/// Bounds the signed legacy Controller genesis comparison packet.
pub const CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1: usize =
    CONTROLLER_SOURCE_GENESIS_BODY_BYTES_V1 + 64;
/// Bounds the signed full-resource Controller genesis comparison packet.
pub const CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V2: usize =
    CONTROLLER_SOURCE_GENESIS_BODY_BYTES_V1 + 176 + 64;
/// Bounds the signed full-resource Controller Project comparison packet.
pub const CONTROLLER_PROJECT_RESOURCE_READBACK_BYTES_V4: usize =
    CONTROLLER_SOURCE_GENESIS_BODY_BYTES_V1 + 176 + 64;
/// Bounds the signed legacy Source genesis comparison packet.
pub const SOURCE_TREE_GENESIS_READBACK_BYTES_V1: usize = SOURCE_TREE_GENESIS_BODY_BYTES_V1 + 64;
/// Bounds the signed full-resource Source genesis comparison packet.
pub const SOURCE_TREE_GENESIS_READBACK_BYTES_V2: usize =
    SOURCE_TREE_GENESIS_BODY_BYTES_V1 + 176 + 64;
/// Bounds the signed legacy Source Project comparison packet.
pub const SOURCE_PROJECT_GENESIS_READBACK_BYTES_V3: usize = SOURCE_TREE_GENESIS_BODY_BYTES_V1 + 64;
/// Bounds the signed full-resource Source Project comparison packet.
pub const SOURCE_PROJECT_RESOURCE_GENESIS_READBACK_BYTES_V4: usize =
    SOURCE_TREE_GENESIS_BODY_BYTES_V1 + 176 + 64;
/// Bounds the legacy Root Source genesis intent record.
pub const ROOT_SOURCE_GENESIS_INTENT_BYTES_V1: usize = 792;
/// Bounds the legacy Source hierarchy floor record.
pub const SOURCE_HIERARCHY_FLOOR_BYTES_V1: usize = 792;
/// Bounds the full-resource Root Source genesis intent record.
pub const ROOT_SOURCE_GENESIS_INTENT_BYTES_V2: usize = 968;
/// Bounds the full-resource Source hierarchy floor record.
pub const SOURCE_HIERARCHY_FLOOR_BYTES_V2: usize = 968;
