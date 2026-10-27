//! Original Broker format names over the single private canonical DATA engine.
//!
//! These aliases preserve Broker-only endpoint/profile and exact version-one
//! claims. They admit no Host producer, currentness, provisioning or physical
//! transport; Host has distinct private typed records.

pub(crate) use crate::tpm_nv_custody::{
    FloorEndpointV1, FloorProfileV1, NV_ATTRIBUTES_WRITTEN,
};
pub(super) use crate::tpm_nv_custody::{
    CHECKPOINT_BYTES, FloorCheckpointV1, FloorCutV1, FloorIntentV1, INTENT_BYTES,
    NV_ATTRIBUTES_DEFINED, PROFILE_BYTES, successor_sequence,
};
