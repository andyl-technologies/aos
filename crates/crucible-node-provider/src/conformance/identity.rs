//! Typed normative CNP projections without treating identity as qualification.

use crucible_node_contract::{
    HashRef, InputBatch, NodeBinding, NodeDescriptor, ObservationBatch, OwnerBinding, Validate,
    WorldBinding,
};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::ProviderError;

use super::super::IdentityKind;

pub(super) fn project(kind: IdentityKind, value: Value) -> Result<HashRef, ProviderError> {
    // Decoding normalizes equivalent accepted numeric version/phase spellings.
    // NodeBinding deliberately projects durable compatibility, not live tokens.
    Ok(match kind {
        IdentityKind::ObservationBatch => decode::<ObservationBatch>(value)?.identity()?,
        IdentityKind::InputBatch => decode::<InputBatch>(value)?.identity()?,
        IdentityKind::NodeBinding => decode::<NodeBinding>(value)?.identity()?,
        IdentityKind::OwnerBinding => decode::<OwnerBinding>(value)?.identity()?,
        IdentityKind::WorldBinding => decode::<WorldBinding>(value)?.identity()?,
        IdentityKind::NodeDescriptor => decode::<NodeDescriptor>(value)?.identity()?,
    })
}

fn decode<T: DeserializeOwned + Validate>(value: Value) -> Result<T, ProviderError> {
    let object: T =
        serde_json::from_value(value).map_err(crucible_node_contract::ContractError::from)?;
    object.validate()?;
    Ok(object)
}
