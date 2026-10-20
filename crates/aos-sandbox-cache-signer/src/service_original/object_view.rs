//! Keeps the private Cache F recipe over the sole shared object-view sampler.
//!
//! The same F stage pays before constructing/entering this owner. The lower
//! sampler owns all actual native results; this wrapper preserves the existing
//! role stopping marker and never exposes an arbitrary target or role grant.

use std::error::Error;
use aos_sandbox_broker::physical_cache_observation::{
    CacheRootObservationDataV1, CacheLockObservationDataV1, CacheManifestObservationDataV1,
    current_view::{CacheObjectViewOriginalV1 as Native, CacheObjectViewClosedV1},
};
use aos_sandbox_core::ResourceVector;
use super::physical_manifest::{PhysicalManifestLimitsDataV1, PhysicalManifestSnapshotDataV1};
use super::CacheSignerReceivingClosedV1 as Closed;

pub(super) struct CacheObjectViewOriginalV1 { native: Native }

impl CacheObjectViewOriginalV1 {
    pub(super) fn new() -> Self { Self { native: Native::cache_signer_v1() } }

    pub(super) fn fixed_receiving_demand_v1() -> Option<ResourceVector> { Native::fixed_receiving_demand_v1() }

    pub(super) fn prepare_once(&mut self, controller_uid: u32) -> Result<(), Closed> {
        self.native.prepare_once(controller_uid).map_err(|_| Closed)
    }

    pub(super) fn prepared_length_v1(&self) -> Result<usize, Closed> {
        self.native.prepared_length_v1().map_err(|_| Closed)
    }

    pub(super) fn read_once(&mut self, limits: PhysicalManifestLimitsDataV1) -> Result<(), Closed> {
        self.native.read_once(limits).map_err(|_| Closed)
    }

    pub(super) fn finish_native_once(&mut self) -> Result<(), Closed> {
        self.native.finish_native_once().map_err(|_| Closed)
    }

    pub(super) fn completed_data_v1(&self) -> Result<PhysicalManifestSnapshotDataV1, Closed> {
        self.native.completed_data_v1().map_err(|_| Closed)
    }

    pub(super) fn require_same_completed_v1(&self, other: &Self) -> Result<(), Closed> {
        self.native.require_same_completed_v1(&other.native).map_err(|_| Closed)
    }

    pub(super) fn observed_identities_v1(&self) -> Result<(
        CacheRootObservationDataV1, CacheLockObservationDataV1, Option<CacheManifestObservationDataV1>,
    ), Closed> { self.native.observed_identities_v1().map_err(|_| Closed) }

    pub(super) fn observed_source_uid_v1(&self) -> Result<u32, Closed> {
        self.native.observed_source_uid_v1().map_err(|_| Closed)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let cause = self.native.failure()?;
        if cause.is::<CacheObjectViewClosedV1>() { Some(&Closed) } else { Some(cause) }
    }
}
