//! Owns the exact signed method31 request transferred from completed M signing.
//!
//! This passive owner has no public constructor and cannot open a Session or
//! enter an effect. The genuine Maintenance transport borrower must rejoin its
//! Root query commitment, current Source/C, original deadline and actual held
//! completed Storage Session before every use.

use aos_sandbox_core::RawPairedClockSample;
use aos_sandbox_ownership_protocol::SignedOwnershipLease;
use aos_sandbox_protocol::authorization_artifact::{
    SignedBrokerPlan, start_resource_plan::StartResourcePlanPreparationDataV1,
};
use sha2::{Digest as _, Sha256};

/// Retains the real signed request under its original Maintenance Root identity.
#[doc(hidden)]
pub struct ControllerMaintenanceStorageRequestOriginalV3 {
    pub(in crate::controller_resource_reservation) preparation: StartResourcePlanPreparationDataV1,
    pub(in crate::controller_resource_reservation) signed: SignedBrokerPlan,
    pub(in crate::controller_resource_reservation) lease: SignedOwnershipLease,
    query: [u8; 32],
    origin: RawPairedClockSample,
    cutoff: u64,
}

impl ControllerMaintenanceStorageRequestOriginalV3 {
    /// Borrows exact request/header DATA from the completed genuine construction.
    #[doc(hidden)]
    pub fn request_data_v3(&self) -> (&[u8], &aos_sandbox_protocol::authorization_artifact::start_resource_plan::StartResourceRequestHeaderDataV2){
        (
            &self.preparation.request_body,
            &self.preparation.request_header,
        )
    }

    /// Borrows exact canonical authorization DATA; this supplies no IO authority.
    #[doc(hidden)]
    pub fn authorization_data_v3(&self) -> [&[u8]; 4] {
        [
            self.signed.canonical_plan(),
            self.signed.canonical_signature(),
            self.lease.canonical_lease(),
            self.lease.canonical_signature(),
        ]
    }

    pub(crate) fn from_completed_construction_v3(
        preparation: StartResourcePlanPreparationDataV1,
        signed: SignedBrokerPlan,
        lease: SignedOwnershipLease,
        query: [u8; 32],
        origin: RawPairedClockSample,
        cutoff: u64,
    ) -> Self {
        Self {
            preparation,
            signed,
            lease,
            query,
            origin,
            cutoff,
        }
    }

    pub(crate) fn commitment_data_v3(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"aos.controller.maintenance-storage-request.v3\0");
        hash.update(self.query);
        hash.update(self.origin.host_boot_id());
        hash.update(self.origin.boottime_nanoseconds().to_be_bytes());
        hash.update(self.cutoff.to_be_bytes());
        for part in [
            self.preparation.request_body.as_slice(),
            self.signed.canonical_plan(),
            self.signed.canonical_signature(),
            self.lease.canonical_lease(),
            self.lease.canonical_signature(),
        ] {
            hash.update((part.len() as u64).to_be_bytes());
            hash.update(part);
        }
        hash.finalize().into()
    }

    pub(crate) fn query_data_v3(&self) -> [u8; 32] {
        self.query
    }

    pub(crate) fn cutoff_data_v3(&self) -> u64 {
        self.cutoff
    }
}
