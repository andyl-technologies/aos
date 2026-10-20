//! Materializes only a genuine Root business owner's provisional wire DATA.
//!
//! The same R stage prepays actual canonical body lengths, typed clone peaks
//! and the complete response/closed wire before allocation. Native Sent/EOF,
//! currentness and financial disposition belong to the owning socket caller.

use std::error::Error;
use std::mem::size_of;
use aos_sandbox_core::{ObjectDescriptor, ResourceDimension as D, ResourceId, ResourceVector, Revision};
use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::normal_root::RootEnvironmentStageReceivingV1;
use crate::policy_compiler::environment_root::business::RootEnvironmentBusinessOriginalV1;
use super::super::{EnvironmentActivationPhaseV1, EnvironmentActivationTransactionV1,
    EnvironmentGenerationManifestV1, EnvironmentGcRootAcknowledgementV1, EnvironmentSelectorV1,
    EnvironmentModelError, encode_environment_activation_v1, encode_environment_generation_v1};
use super::transport::{EnvironmentRootOpenDataV1, EnvironmentRootResponseDataV1,
    EnvironmentRootWireErrorV1, RESPONSE_BYTES, CLOSED_BYTES, body_digest};

type Cause = Box<dyn Error>;

#[derive(Debug, thiserror::Error)]
#[error("provisional Root Environment response is unavailable")]
struct Closed;

pub(crate) struct RootEnvironmentResponseOriginalV1 {
    demand: Option<Result<ResourceVector, EnvironmentModelError>>,
    funding: Option<Result<(), crate::normal_root::NormalRootStartupErrorV1>>,
    prepared: Option<Result<EnvironmentActivationTransactionV1, EnvironmentModelError>>,
    generation: Option<Result<Vec<u8>, EnvironmentModelError>>,
    activation: Option<Result<Vec<u8>, EnvironmentModelError>>,
    body: Vec<u8>,
    header: Option<Result<[u8; RESPONSE_BYTES], EnvironmentRootWireErrorV1>>,
    decoded: Option<EnvironmentRootResponseDataV1>,
    primary: Option<Result<(), Cause>>,
    closed: Option<crate::journal::JournalError>,
}

impl RootEnvironmentResponseOriginalV1 {
    pub(crate) fn new() -> Self {
        Self { demand: None, funding: None, prepared: None, generation: None, activation: None,
            body: Vec::new(), header: None, decoded: None, primary: None, closed: None }
    }

    pub(crate) fn prepare_once_v1(&mut self, stage: &mut RootEnvironmentStageReceivingV1<'_, '_>,
        original: &RootEnvironmentBusinessOriginalV1, open: EnvironmentRootOpenDataV1,
    ) -> Result<(), crate::journal::JournalError> {
        if self.demand.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(crate::journal::JournalError::ProtectedBoundary);
            return Err(crate::journal::JournalError::ProtectedBoundary);
        }
        self.primary = Some(self.prepare_inner(stage, original, open));
        if matches!(self.primary, Some(Ok(()))) { Ok(()) }
        else { Err(crate::journal::JournalError::ProtectedBoundary) }
    }

    fn prepare_inner(&mut self, stage: &mut RootEnvironmentStageReceivingV1<'_, '_>,
        original: &RootEnvironmentBusinessOriginalV1, open: EnvironmentRootOpenDataV1,
    ) -> Result<(), Cause> {
        let (manifest, roots, evidence) = original.provisional_v1()?;
        let (operation, execution, observed) = original.provisional_coordinates_v1()?;
        if open.operation != operation { return Err(Closed.into()); }
        self.demand = Some(response_demand_v1(manifest, roots, evidence.len()));
        let demand = self.demand.as_ref().and_then(|value| value.as_ref().ok()).copied().ok_or(Closed)?;
        self.funding = Some(stage.admit_environment_response_once_v1(
            RootContinuationDemandV1::from_demand_v1(demand)));
        if !matches!(self.funding, Some(Ok(()))) { return Err(Closed.into()); }
        // The Root record is a Prepared DATA commitment of actual GC-root
        // acknowledgements. It contains no execution lease and is never adopted
        // as Source Observed; the real Source producer publishes every phase.
        self.prepared = Some((|| {
            let selector = EnvironmentSelectorV1::from_manifest(manifest)?;
            EnvironmentActivationTransactionV1::from_stored(ResourceId::from_bytes(operation),
                manifest.project(), manifest.sandbox(), Revision::new(1), None, selector,
                None, None, Vec::new(), roots.to_vec(), Vec::new(), EnvironmentActivationPhaseV1::Prepared)
        })());
        let prepared = self.prepared.as_ref().and_then(|value| value.as_ref().ok()).ok_or(Closed)?;
        self.generation = Some(encode_environment_generation_v1(manifest));
        self.activation = Some(encode_environment_activation_v1(prepared));
        let generation = self.generation.as_ref().and_then(|value| value.as_ref().ok()).ok_or(Closed)?;
        let activation = self.activation.as_ref().and_then(|value| value.as_ref().ok()).ok_or(Closed)?;
        let length = generation.len().checked_add(activation.len())
            .and_then(|bytes| bytes.checked_add(evidence.len())).ok_or(Closed)?;
        self.body.try_reserve_exact(length)?;
        self.body.extend_from_slice(generation);
        self.body.extend_from_slice(activation);
        self.body.extend_from_slice(evidence);
        let response = EnvironmentRootResponseDataV1 { operation, execution,
            project: *manifest.project().as_bytes(), sandbox: *manifest.sandbox().as_bytes(),
            generation_bytes: u64::try_from(generation.len())?, activation_bytes: u64::try_from(activation.len())?,
            evidence_bytes: u64::try_from(evidence.len())?, observed,
            opening: open.digest()?, body: body_digest(&self.body) };
        self.header = Some(response.encode());
        if !matches!(self.header, Some(Ok(_))) { return Err(Closed.into()); }
        self.decoded = Some(response);
        Ok(())
    }

    pub(crate) fn wire_v1(&self) -> Result<(&[u8; RESPONSE_BYTES], &[u8]), crate::journal::JournalError> {
        if !matches!(self.primary, Some(Ok(()))) || self.closed.is_some() {
            return Err(crate::journal::JournalError::ProtectedBoundary);
        }
        let header = self.header.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(crate::journal::JournalError::ProtectedBoundary)?;
        Ok((header, &self.body))
    }

    pub(crate) fn wire_mut_v1(&mut self)
        -> Result<(&mut [u8; RESPONSE_BYTES], &mut [u8]), crate::journal::JournalError>
    {
        if !matches!(self.primary, Some(Ok(()))) || self.closed.is_some() {
            return Err(crate::journal::JournalError::ProtectedBoundary);
        }
        let header = self.header.as_mut().and_then(|value| value.as_mut().ok())
            .ok_or(crate::journal::JournalError::ProtectedBoundary)?;
        Ok((header, &mut self.body))
    }

    pub(crate) fn complete_digest_v1(&self) -> Result<[u8; 32], EnvironmentRootWireErrorV1> {
        self.decoded.ok_or(EnvironmentRootWireErrorV1)?.complete_digest(&self.body)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        cause(&self.demand).or_else(|| cause(&self.funding)).or_else(|| cause(&self.prepared))
            .or_else(|| cause(&self.generation)).or_else(|| cause(&self.activation)).or_else(|| cause(&self.header))
            .or_else(|| self.primary.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

fn response_demand_v1(manifest: &EnvironmentGenerationManifestV1,
    roots: &[EnvironmentGcRootAcknowledgementV1], evidence: usize,
) -> Result<ResourceVector, EnvironmentModelError> {
    let generation = super::super::format::canonical_generation_bytes_v1(manifest)?;
    let activation = super::super::activation_format::activation_encoded_length_fields_v1(0, roots, 0)?;
    let body = generation.checked_add(activation).and_then(|bytes| bytes.checked_add(evidence))
        .ok_or(EnvironmentModelError::InvalidModel)?;
    // Each item in these already-valid canonical models occupies at least one
    // encoded byte. Four co-resident typed/clone planes use actual largest
    // model atoms; encoded scratch/output have four separate bounded planes.
    let atom = size_of::<ObjectDescriptor>().max(size_of::<EnvironmentGcRootAcknowledgementV1>())
        .max(size_of::<EnvironmentGenerationManifestV1>()).max(size_of::<EnvironmentActivationTransactionV1>());
    let bytes = atom.checked_mul(4).and_then(|atom| atom.checked_add(4))
        .and_then(|atom| body.checked_mul(atom))
        .and_then(|bytes| bytes.checked_add(size_of::<RootEnvironmentResponseOriginalV1>().checked_mul(3)?))
        .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(EnvironmentModelError::InvalidModel)?;
    let wire = body.checked_add(RESPONSE_BYTES).and_then(|bytes| bytes.checked_add(CLOSED_BYTES))
        .and_then(|bytes| bytes.checked_add(1)).and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(EnvironmentModelError::InvalidModel)?;
    Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes).with(D::NetworkBytes, wire))
}

fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}
