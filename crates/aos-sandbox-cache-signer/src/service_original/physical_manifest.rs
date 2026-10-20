//! Uses the canonical physical manifest DATA shared by actual F and R readers.
//!
//! The native role retains its own original, fixed mount and financial stage.

pub(super) use aos_sandbox_protocol::cache_state::physical_manifest::view_data::{
    PhysicalManifestDataErrorV1, PhysicalManifestLimitsDataV1, PhysicalManifestSnapshotDataV1,
    decode_actual_manifest_v1, dynamic_receiving_demand_v1, quota_derivation_receiving_demand_v1,
};
