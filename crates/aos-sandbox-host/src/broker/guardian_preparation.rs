//! Keeps the actual signed Guardian setup on the same paid Host launch.
//!
//! The ordinary and selected routes share one preparation body. This private
//! destination retains native credential sources and pin failures; it neither
//! admits a request nor creates another financial account.

use aos_sandbox_broker::ProtectedBrokerPublicCredentialRevalidationOriginalV1;
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::immutable_file::SealedReadOnlyCredentialCreateOriginalsV1;
use aos_systemd::{GuardianCredentialAcquisitionOriginalV2, GuardianCredentialRole};

use super::GuardianOriginalInputV1;
use crate::{HostError, Result};

pub(super) struct GuardianPreparationOriginalV2 {
    pub(super) public: ProtectedBrokerPublicCredentialRevalidationOriginalV1,
    pub(super) seals: [SealedReadOnlyCredentialCreateOriginalsV1; 4],
    pub(super) seal_results: [Option<Result<()>>; 4],
    pub(super) pins: GuardianCredentialAcquisitionOriginalV2,
    pub(super) entered: bool,
    pub(super) returned: Option<Result<()>>,
    pub(super) first: Option<PreparationFrontierV2>,
    pub(super) frontier: PreparationFrontierV2,
}

#[derive(Clone, Copy)]
pub(super) enum PreparationFrontierV2 {
    Readiness,
    Public,
    Seal(usize),
    Pins,
    Specification,
}

impl GuardianPreparationOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            public: ProtectedBrokerPublicCredentialRevalidationOriginalV1::new(),
            seals: std::array::from_fn(|_| SealedReadOnlyCredentialCreateOriginalsV1::new()),
            seal_results: std::array::from_fn(|_| None),
            pins: GuardianCredentialAcquisitionOriginalV2::new(),
            entered: false,
            returned: None,
            first: None,
            frontier: PreparationFrontierV2::Readiness,
        }
    }

    pub(super) fn receiving_demand_v2(
        original: &GuardianOriginalInputV1<'_>,
        artifacts: &aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts,
    ) -> Result<ResourceVector> {
        let public = ProtectedBrokerPublicCredentialRevalidationOriginalV1::receiving_obligations_v1()
            .ok_or(HostError::ResourceExhausted)?;
        let pins = GuardianCredentialAcquisitionOriginalV2::receiving_obligations_v2()
            .ok_or(HostError::ResourceExhausted)?;
        let fixed = std::mem::size_of::<Self>()
            .checked_mul(2)
            .ok_or(HostError::ResourceExhausted)?;
        let mut demand = ResourceVector::ZERO.with(
            D::MemoryBytes,
            u64::try_from(fixed).map_err(|_| HostError::ResourceExhausted)?,
        );
        demand = demand
            .checked_add(
                crate::state::transition::DurableExecution::launch_namespace_receiving_demand_v1()
                    .ok_or(HostError::ResourceExhausted)?,
            )
            .map_err(|_| HostError::ResourceExhausted)?;
        for (bytes, files, names) in [public, pins] {
            let additional = ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| HostError::ResourceExhausted)?)
                .with(D::OpenFiles, u64::try_from(files).map_err(|_| HostError::ResourceExhausted)?)
                .with(D::MetadataEntries, u64::try_from(names).map_err(|_| HostError::ResourceExhausted)?);
            demand = demand.checked_add(additional)
                .map_err(|_| HostError::ResourceExhausted)?;
        }
        let (plan, signature) = original.guardian_pair()?;
        // Pending durable attempts may lend their original signed bytes. Price
        // the existing per-role maxima as well as the reached request, without
        // reconstructing or relaxing either attempt's semantic validation.
        for (role, bytes, maximum) in [
            (GuardianCredentialRole::BrokerPlan, plan, 256 * 1024),
            (GuardianCredentialRole::BrokerPlanSignature, signature, 64 * 1024),
            (GuardianCredentialRole::OwnershipLease, artifacts.ownership_lease(), 64 * 1024),
            (GuardianCredentialRole::OwnershipLeaseSignature, artifacts.ownership_lease_signature(), 64 * 1024),
        ] {
            let seal = SealedReadOnlyCredentialCreateOriginalsV1::receiving_footprint_v1(
                role.as_str().len(), bytes.len().max(maximum),
            )
            .ok_or(HostError::ResourceExhausted)?;
            let additional = ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(seal.memory_bytes).map_err(|_| HostError::ResourceExhausted)?)
                .with(D::OpenFiles, u64::try_from(seal.open_files).map_err(|_| HostError::ResourceExhausted)?);
            demand = demand.checked_add(additional)
                .map_err(|_| HostError::ResourceExhausted)?;
        }
        Ok(demand)
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let native = match self.first? {
            PreparationFrontierV2::Public => self.public.failure(),
            PreparationFrontierV2::Seal(index) => self.seals[index].failure(),
            PreparationFrontierV2::Pins => self.pins.failure(),
            PreparationFrontierV2::Readiness | PreparationFrontierV2::Specification => None,
        };
        native.or_else(|| self.returned.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}
