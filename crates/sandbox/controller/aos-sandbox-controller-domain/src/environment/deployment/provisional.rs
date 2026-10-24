//! Decodes only historical DATA received on the genuine Root native interval.
//!
//! A standalone value grants no Source mutation or evidence claim. The actual
//! Source publisher requires the continuously held authenticated Root owner.

use std::mem::size_of;
use aos_sandbox_model::{ObjectDescriptor, ResourceDimension as D, ResourceVector};
use super::transport::EnvironmentRootResponseDataV1;
use super::super::*;

pub(crate) struct RootEnvironmentProvisionalDataV1 {
    manifest: EnvironmentGenerationManifestV1,
    activation: EnvironmentActivationTransactionV1,
    evidence: Vec<u8>,
}

impl RootEnvironmentProvisionalDataV1 {
    pub(crate) fn receiving_demand_v1(response: EnvironmentRootResponseDataV1)
        -> Result<ResourceVector, EnvironmentModelError>
    {
        let length = response.body_bytes().map_err(|_| EnvironmentModelError::CorruptEncoding)?;
        let generation = usize::try_from(response.generation_bytes).map_err(|_| EnvironmentModelError::Allocation)?;
        let activation = usize::try_from(response.activation_bytes).map_err(|_| EnvironmentModelError::Allocation)?;
        let evidence = usize::try_from(response.evidence_bytes).map_err(|_| EnvironmentModelError::Allocation)?;
        if generation > super::super::format::MAXIMUM_RECORD_BYTES
            || activation > super::super::activation_format::MAXIMUM_ACTIVATION_RECORD_BYTES
            || evidence > super::super::protected_evidence::maximum_evidence_record_bytes_v1()
        { return Err(EnvironmentModelError::CorruptEncoding); }
        // The generation decoder bounds CBOR reservations by its actual inner
        // extent; activation's sole decoder preflights each fixed-stride count.
        // Eight concrete co-resident planes cover raw input, canonical checks,
        // generation/history, activation/selectors, Source reducer envelope and
        // canonical planner copies. No parser cell is a namespace entry.
        let atom = size_of::<ObjectDescriptor>().max(size_of::<aos_sandbox_model::model::EnvironmentEntry>())
            .max(size_of::<super::super::EnvironmentGenerationLeaseV1>())
            .max(size_of::<super::super::EnvironmentGcRootAcknowledgementV1>());
        let bytes = length.checked_mul(atom).and_then(|bytes| bytes.checked_mul(8))
            .and_then(|bytes| bytes.checked_add(size_of::<Self>().checked_mul(3)?))
            .ok_or(EnvironmentModelError::Allocation)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| EnvironmentModelError::Allocation)?)
            .with(D::NetworkBytes, u64::try_from(length).map_err(|_| EnvironmentModelError::Allocation)?))
    }

    pub(crate) fn decode_v1(response: EnvironmentRootResponseDataV1, body: &[u8])
        -> Result<Self, EnvironmentModelError>
    {
        let (generation, activation, evidence) = response.split_body(body).map_err(|_| EnvironmentModelError::CorruptEncoding)?;
        let manifest = decode_environment_generation_v1(generation)?;
        if encode_environment_generation_v1(&manifest)? != generation || manifest.generation().get() != 1
            || manifest.predecessor().is_some() || manifest.project().as_bytes() != &response.project
            || manifest.sandbox().as_bytes() != &response.sandbox
        { return Err(EnvironmentModelError::InvalidModel); }
        let history = EnvironmentGenerationHistoryV1::from_protected_manifests(vec![manifest.clone()])
            .map_err(|_| EnvironmentModelError::InvalidModel)?;
        let activation_model = decode_environment_activation_v1(activation, &history)?;
        if encode_environment_activation_v1(&activation_model)? != activation
            || activation_model.phase() != EnvironmentActivationPhaseV1::Prepared
            || activation_model.desired().manifest_record() != &manifest
            || activation_model.project() != manifest.project() || activation_model.sandbox() != manifest.sandbox()
            || activation_model.transaction().as_bytes() != &response.operation
            || !activation_model.leases().is_empty()
        { return Err(EnvironmentModelError::InvalidModel); }
        let decoded = super::super::protected_evidence::decode_provisioned_evidence_data_v1(evidence)
            .map_err(|_| EnvironmentModelError::CorruptEncoding)?;
        if decoded.current_boot != super::super::authority_clock::linux_kernel_boot_commitment_v1(response.observed.host_boot_id())
            || decoded.current_time.get() > response.observed.boottime_nanoseconds()
        { return Err(EnvironmentModelError::InvalidModel); }
        Ok(Self { manifest, activation: activation_model, evidence: evidence.to_vec() })
    }

    pub(crate) fn manifest_v1(&self) -> &EnvironmentGenerationManifestV1 { &self.manifest }
    pub(crate) fn prepared_v1(&self) -> &EnvironmentActivationTransactionV1 { &self.activation }
    pub(crate) fn evidence_v1(&self) -> &[u8] { &self.evidence }

    pub(crate) fn valid_until_wall_seconds_v1(&self) -> Result<i64, EnvironmentModelError> {
        let decoded = super::super::protected_evidence::decode_provisioned_evidence_data_v1(&self.evidence)
            .map_err(|_| EnvironmentModelError::CorruptEncoding)?;
        i64::try_from(decoded.valid_until_unix_seconds).map_err(|_| EnvironmentModelError::InvalidModel)
    }

}
