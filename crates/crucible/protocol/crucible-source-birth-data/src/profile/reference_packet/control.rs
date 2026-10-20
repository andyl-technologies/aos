//! Retains immutable control selections without installing a native control.

use super::service::PacketNative5StorageLimits;
use crate::profile::{ProviderError, bodies::RealizeRequest, handshake::Limits};
use crucible_node_format::*;
use serde::{Deserialize, Serialize};

/// Defines the complete independently installed original native control scope.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketControlSelection {
    /// Names the actual source-selected provider implementation and formats.
    pub provider: ProviderManifest,
    /// Names the complete unchanged realized descriptors, bindings and owners.
    pub realization: RealizationManifest,
    /// Retains the original host-selected realization request.
    pub realize: RealizeRequest,
    /// Names the actual closed native preparation.
    pub prepared_token: Id,
    /// Names the independent host admission, checked before staging.
    pub admission: Id,
    /// Names the exact complete transaction, without granting host publication.
    pub transaction: Id,
    /// Names the original actual native gate.
    pub gate: Id,
    /// Binds the complete source-installed world, never a request-selected subset.
    pub world: HashRef,
    /// Names the independently expected host admission body.
    pub admission_receipt: ContentRef,
}

/// Retains one service-selected native storage and negotiated transport tuple.
///
/// This is inert correlation data. The original service must bind it before any
/// public dispatch, after authenticating its actual connection and allocating
/// its selected banks. Neither decoding nor validation proves those allocations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNative5StorageSelection {
    /// Retains every selected native snapshot, literal bank and journal ceiling.
    pub storage: PacketNative5StorageLimits,
    /// Retains the actual original negotiated receiving limits.
    pub limits: Limits,
}

impl PacketNative5StorageSelection {
    /// Checks the closed selected geometry against implementation hard ceilings.
    ///
    /// # Errors
    /// Refuses unsupported, nonpositive, overflowing or incomplete data geometry.
    pub fn validate(&self) -> Result<(), ProviderError> {
        self.storage.validate(&self.limits)
    }
}
