//! Owns the concrete Environment compiler, closure and protected evidence body.
//!
//! The accepted Root flight supplies the genuine purpose borrower and retained
//! policy pair. Every next native frontier checks the original Controller
//! horizon with the existing serial kernel-clock owner. Completed evidence is
//! only provisional while the same authenticated Root interval remains held;
//! it becomes no Source lease or lifecycle authorization on its own.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_core::{OperationId, RawPairedClockSample, ResourceDimension as D, ResourceVector};
use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::environment::{EnvironmentGenerationManifestV1, EnvironmentModelError};
use crate::environment::deployment::{RootEnvironmentAcceptedOriginalV1,
    RootEnvironmentDeploymentOriginalV1};
use crate::environment::RootEnvironmentEvidenceOriginalV1;
use crate::journal::JournalError;
use crate::normal_root::RootPolicyAcceptedFlightV1;
use super::super::RootCurrentPolicyInputDataV1;
use super::super::continuation_policy::RootEnvironmentPolicyOriginalV1;
use super::super::provisioning_current::{RootEnvironmentReadonlyContextV1,
    RootEnvironmentCompilerOriginalV1, RootProvisioningNativeViewsV1,
    RootContinuationHorizonDataV1, RootContinuationClockGateV1};

type Cause = Box<dyn Error>;

#[derive(Debug, thiserror::Error)]
#[error("the original Environment execution interval is unavailable")]
pub(crate) struct RootEnvironmentBusinessErrorV1;

/// Carries comparison bounds from the continuously held original C18 operation.
/// Root independently samples its actual kernel and verifies current signed
/// sources; these fields cannot authorize a purpose, lease or native effect.
#[derive(Clone, Copy)]
pub(crate) struct EnvironmentExecutionHorizonDataV1 {
    pub(crate) original: RawPairedClockSample,
    pub(crate) absolute_cutoff: u64,
    pub(crate) expires: i64,
}

impl EnvironmentExecutionHorizonDataV1 {
    fn require_sample(self, sample: RawPairedClockSample) -> Result<(), RootEnvironmentBusinessErrorV1> {
        if self.original.validate_later_sample(sample).is_err()
            || self.absolute_cutoff <= self.original.boottime_nanoseconds()
            || sample.boottime_nanoseconds() >= self.absolute_cutoff
            || sample.wall_seconds() >= self.expires
        {
            return Err(RootEnvironmentBusinessErrorV1);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum First {
    Clock, Readonly, Artifact, Evidence, PolicyFunding,
    Policy, Accepted, NativeViews, Compiler, Materialization,
}

/// Retains actual body and all owed owners until authenticated disposition.
/// No method disposes the Root flight or makes Source publication successful.
pub(crate) struct RootEnvironmentBusinessOriginalV1 {
    horizon: EnvironmentExecutionHorizonDataV1,
    clock: RootContinuationClockGateV1,
    clock_gate: Option<Result<(), RootEnvironmentBusinessErrorV1>>,
    latest: Option<RawPairedClockSample>,
    readonly: RootEnvironmentReadonlyContextV1,
    artifact: Option<Result<RootEnvironmentDeploymentOriginalV1,
        crate::environment::deployment::EnvironmentDeploymentErrorV1>>,
    evidence: Option<Result<RootEnvironmentEvidenceOriginalV1,
        crate::environment::RootEnvironmentEvidenceErrorV1>>,
    policy: RootEnvironmentPolicyOriginalV1,
    policy_funding: Option<Result<(), crate::normal_root::NormalRootStartupErrorV1>>,
    accepted: RootEnvironmentAcceptedOriginalV1,
    native_views: RootProvisioningNativeViewsV1,
    compiler: RootEnvironmentCompilerOriginalV1,
    materialized: Option<Result<EnvironmentGenerationManifestV1, EnvironmentModelError>>,
    primary: Option<Result<(), Cause>>,
    artifact_after: Option<Result<(), crate::environment::deployment::EnvironmentDeploymentErrorV1>>,
    evidence_after: Option<Result<(), crate::environment::RootEnvironmentEvidenceErrorV1>>,
    cache_after: Option<Result<(), JournalError>>,
    model_after: bool,
    policy_after: Option<Result<(), super::super::continuation_policy::RootContinuationPolicyErrorV1>>,
    claim_after: Option<Result<(), crate::environment::deployment::EnvironmentDeploymentErrorV1>>,
    final_check: Option<Result<(), Cause>>,
    first: Option<First>,
    entered: bool,
    after_entered: bool,
    claim_entered: bool,
    closed: Option<RootEnvironmentBusinessErrorV1>,
}

impl RootEnvironmentBusinessOriginalV1 {
    pub(crate) fn new(horizon: EnvironmentExecutionHorizonDataV1) -> Result<Self, JournalError> {
        let bound = RootContinuationHorizonDataV1::from_original_data_v1(horizon.original, horizon.absolute_cutoff)?
            .with_wall_expiry_data_v1(horizon.expires);
        Ok(Self {
            horizon, clock: RootContinuationClockGateV1::new(bound), clock_gate: None, latest: None,
            readonly: RootEnvironmentReadonlyContextV1::new(),
            artifact: None, evidence: None, policy: Default::default(), policy_funding: None,
            accepted: RootEnvironmentAcceptedOriginalV1::new(),
            native_views: RootProvisioningNativeViewsV1::new(),
            compiler: RootEnvironmentCompilerOriginalV1::new(), materialized: None,
            primary: None, artifact_after: None, evidence_after: None, cache_after: None,
            model_after: false, policy_after: None, claim_after: None, final_check: None,
            first: None, entered: false, after_entered: false, claim_entered: false, closed: None,
        })
    }

    // The selected listener prepays the actual dormant constructor before
    // accept; the first purpose stage adds the serial sampler's real peak.
    pub(crate) fn construction_bytes_v1() -> Option<usize> {
        size_of::<Self>().checked_mul(3)
    }

    pub(crate) fn fixed_receiving_demand_v1() -> Result<ResourceVector, JournalError> {
        let bytes = Self::construction_bytes_v1().and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        RootContinuationClockGateV1::receiving_demand_v1()?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
            .map_err(|_| JournalError::JournalTooLarge)
    }

    pub(crate) fn before_response_native_once_v1(&mut self) -> Result<(), RootEnvironmentBusinessErrorV1> {
        if !matches!(self.primary, Some(Ok(()))) || !self.body_after_positive_v1() {
            return Err(RootEnvironmentBusinessErrorV1);
        }
        self.check_original_clock_v1().map_err(|_| RootEnvironmentBusinessErrorV1)
    }

    pub(crate) fn final_clock_v1(&self) -> Result<RawPairedClockSample, RootEnvironmentBusinessErrorV1> {
        self.require_complete_v1()?;
        self.latest.ok_or(RootEnvironmentBusinessErrorV1)
    }

    pub(crate) fn observe_once_v1(&mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        policy_input: &RootCurrentPolicyInputDataV1<'_>, operation: OperationId,
    ) -> Result<(), RootEnvironmentBusinessErrorV1> {
        if self.entered || self.closed.is_some() {
            self.closed.get_or_insert(RootEnvironmentBusinessErrorV1);
            return Err(RootEnvironmentBusinessErrorV1);
        }
        self.entered = true;
        self.primary = Some(self.observe_inner(flight, policy_input, operation));
        // Native post methods are intrinsically once-only and do no work for
        // an unentered child. They remain independent after the first failure.
        self.finish_body_after_once_v1();
        if matches!(self.primary, Some(Ok(()))) && self.body_after_positive_v1() {
            Ok(())
        } else {
            Err(RootEnvironmentBusinessErrorV1)
        }
    }

    fn observe_inner(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        policy_input: &RootCurrentPolicyInputDataV1<'_>, operation: OperationId,
    ) -> Result<(), Cause> {
        self.check_original_clock_v1()?;
        self.first = Some(First::Readonly);
        let mut horizon = RootContinuationHorizonDataV1::from_original_data_v1(
            self.horizon.original, self.horizon.absolute_cutoff)?
            .with_wall_expiry_data_v1(self.horizon.expires);
        self.readonly.observe_once(&mut flight.environment_stage_receiving_v1()?, horizon);
        self.readonly.require_complete_v1()?;
        self.check_original_clock_v1()?;
        self.first = Some(First::Artifact);
        self.artifact = Some(RootEnvironmentDeploymentOriginalV1::begin_once_v1(
            &mut flight.environment_stage_receiving_v1()?));
        self.artifact_mut_v1()?.capture_instruction_once_v1(&mut flight.environment_stage_receiving_v1()?)?;
        self.check_original_clock_v1()?;
        self.first = Some(First::Artifact);
        self.artifact_mut_v1()?.prepare_closure_once_v1(&mut flight.environment_stage_receiving_v1()?)?;

        self.check_original_clock_v1()?;
        self.first = Some(First::Evidence);
        self.evidence = Some(RootEnvironmentEvidenceOriginalV1::begin_once_v1(
            &mut flight.environment_stage_receiving_v1()?));
        let observed = self.evidence_mut_v1()?.clock_v1().ok_or(RootEnvironmentBusinessErrorV1)?;
        self.horizon.require_sample(observed)?;
        self.first = Some(First::PolicyFunding);
        let policy_demand = flight.environment_policy_receiving_demand_v1()?;
        self.policy_funding = Some(flight.environment_stage_receiving_v1()?
            .admit_environment_policy_once_v1(RootContinuationDemandV1::from_demand_v1(policy_demand)));
        if !matches!(self.policy_funding, Some(Ok(()))) { return Err(RootEnvironmentBusinessErrorV1.into()); }
        self.first = Some(First::Policy);
        flight.begin_environment_policy_once_v1(&mut self.policy)?;
        flight.verify_environment_policy_sources_once_v1(&mut self.policy, policy_input, observed)?;
        let signed = self.policy.verified_v1().ok_or(RootEnvironmentBusinessErrorV1)?;
        let policy_expires = signed.0.head().expires_at().min(signed.1.expires_at());
        self.horizon.expires = self.horizon.expires.min(policy_expires);
        horizon = horizon.with_wall_expiry_data_v1(self.horizon.expires);
        self.first = Some(First::Clock);
        self.clock.narrow_horizon_data_v1(horizon)?;
        self.readonly.narrow_wall_expiry_data_v1(self.horizon.expires)?;


        self.check_original_clock_v1()?;
        self.first = Some(First::Accepted);
        self.accepted.observe_once_v1(&mut flight.environment_stage_receiving_v1()?,
            &mut self.readonly, operation, &self.policy)?;
        self.check_original_clock_v1()?;
        self.first = Some(First::NativeViews);
        self.native_views.observe_environment_once(flight.environment_stage_receiving_v1()?,
            &self.readonly, self.accepted.project_v1()?, horizon)?;
        self.check_original_clock_v1()?;
        self.first = Some(First::Compiler);
        self.compiler.observe_once(&mut flight.environment_stage_receiving_v1()?,
            &mut self.readonly, &self.native_views, &self.policy, self.accepted.parent_v1()?, horizon)?;
        // The canonical compiler also selects the Publisher revision's own
        // expiry. Narrow already-live owners before artifact/evidence growth;
        // no BOOTTIME translation can erase this independently verified bound.
        self.horizon.expires = self.horizon.expires.min(self.compiler.expires_at_v1()?);
        horizon = horizon.with_wall_expiry_data_v1(self.horizon.expires);
        self.first = Some(First::Clock);
        self.clock.narrow_horizon_data_v1(horizon)?;
        self.readonly.narrow_wall_expiry_data_v1(self.horizon.expires)?;
        self.check_original_clock_v1()?;
        self.first = Some(First::Materialization);
        self.materialized = Some((|| {
            let template = self.artifact_ref_v1()?.prepared_template_v1()?;
            let parent = self.compiler.parent_v1().map_err(|_| EnvironmentModelError::InvalidModel)?;
            let specification = self.compiler.specification_v1().map_err(|_| EnvironmentModelError::InvalidModel)?;
            let effective = self.compiler.candidate_v1().map_err(|_| EnvironmentModelError::InvalidModel)?
                .portable().policy_descriptor();
            let signed = self.policy.verified_v1().ok_or(EnvironmentModelError::InvalidModel)?;
            template.materialize_v1(parent.assignment().manifest().project(),
                parent.assignment().manifest().sandbox(), specification.environment(),
                specification.root_view(), effective, signed.0.cache_domain())
        })());
        if !matches!(self.materialized, Some(Ok(_))) { return Err(RootEnvironmentBusinessErrorV1.into()); }

        loop {
            self.check_original_clock_v1()?;
            self.first = Some(First::Artifact);
            if !self.artifact_mut_v1()?.capture_next_object_once_v1()? { break; }
        }
        self.first = Some(First::Artifact);
        self.artifact_after = Some(self.artifact_mut_v1()?.finish_available_once_v1());
        if !matches!(self.artifact_after, Some(Ok(()))) { return Err(RootEnvironmentBusinessErrorV1.into()); }
        self.check_original_clock_v1()?;
        self.first = Some(First::Evidence);
        self.evidence_mut_v1()?.prepare_once_v1(&mut flight.environment_stage_receiving_v1()?)?;
        self.check_original_clock_v1()?;
        self.first = Some(First::Evidence);
        let artifact = self.artifact.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(RootEnvironmentBusinessErrorV1)?;
        let evidence = self.evidence.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(RootEnvironmentBusinessErrorV1)?;
        evidence.publish_once_v1(&mut flight.environment_stage_receiving_v1()?, &self.policy, artifact, &self.compiler)?;
        self.first = None;
        Ok(())
    }

    fn check_original_clock_v1(&mut self) -> Result<(), Cause> {
        self.first = Some(First::Clock);
        if matches!(self.clock_gate, Some(Err(_))) { return Err(RootEnvironmentBusinessErrorV1.into()); }
        let sample = self.clock.check_next_once_v1()?;
        self.latest = Some(sample);
        self.clock_gate = Some(self.horizon.require_sample(sample));
        if !matches!(self.clock_gate, Some(Ok(()))) { return Err(RootEnvironmentBusinessErrorV1.into()); }
        if let Ok(expires) = self.compiler.expires_at_v1() {
            if sample.wall_seconds() >= expires {
                self.clock_gate = Some(Err(RootEnvironmentBusinessErrorV1));
                return Err(RootEnvironmentBusinessErrorV1.into());
            }
        }
        self.first = None;
        Ok(())
    }

    fn artifact_mut_v1(&mut self) -> Result<&mut RootEnvironmentDeploymentOriginalV1, RootEnvironmentBusinessErrorV1> {
        self.artifact.as_mut().and_then(|result| result.as_mut().ok()).ok_or(RootEnvironmentBusinessErrorV1)
    }

    fn artifact_ref_v1(&self) -> Result<&RootEnvironmentDeploymentOriginalV1, EnvironmentModelError> {
        self.artifact.as_ref().and_then(|result| result.as_ref().ok()).ok_or(EnvironmentModelError::InvalidModel)
    }

    fn evidence_mut_v1(&mut self) -> Result<&mut RootEnvironmentEvidenceOriginalV1, RootEnvironmentBusinessErrorV1> {
        self.evidence.as_mut().and_then(|result| result.as_mut().ok()).ok_or(RootEnvironmentBusinessErrorV1)
    }

    fn finish_body_after_once_v1(&mut self) {
        if self.after_entered { return; }
        self.after_entered = true;
        if self.artifact_after.is_none() {
            if let Some(Ok(artifact)) = &mut self.artifact {
                self.artifact_after = Some(artifact.finish_available_once_v1());
            }
        }
        if let Some(Ok(evidence)) = &mut self.evidence {
            self.evidence_after = Some(evidence.finish_available_once_v1());
        }
        self.cache_after = Some(self.native_views.finish_environment_after_once_v1());
        self.readonly.finish_models_after_once_v1();
        self.model_after = true;
    }

    fn body_after_positive_v1(&self) -> bool {
        matches!(self.artifact_after, Some(Ok(())))
            && matches!(self.evidence_after, Some(Ok(())))
            && matches!(self.cache_after, Some(Ok(())))
            && self.model_after && self.readonly.final_require_complete_v1().is_ok()
    }

    pub(crate) fn provisional_coordinates_v1(&self)
        -> Result<([u8; 16], [u8; 16], RawPairedClockSample), RootEnvironmentBusinessErrorV1>
    {
        self.provisional_v1()?;
        let operation = self.accepted.operation_v1().map_err(|_| RootEnvironmentBusinessErrorV1)?;
        let execution = self.accepted.execution_v1().map_err(|_| RootEnvironmentBusinessErrorV1)?;
        let clock = self.latest.ok_or(RootEnvironmentBusinessErrorV1)?;
        Ok((*operation.as_bytes(), *execution.as_bytes(), clock))
    }

    /// Lends provisional canonical generation and the actual committed evidence.
    /// These remain DATA while the authenticated Root interval is still open.
    pub(crate) fn provisional_v1(&self) -> Result<(&EnvironmentGenerationManifestV1,
        &[crate::environment::EnvironmentGcRootAcknowledgementV1], &[u8]), RootEnvironmentBusinessErrorV1>
    {
        if !matches!(self.primary, Some(Ok(()))) || !self.body_after_positive_v1() {
            return Err(RootEnvironmentBusinessErrorV1);
        }
        let generation = self.materialized.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(RootEnvironmentBusinessErrorV1)?;
        let (_, acknowledgements) = self.artifact.as_ref().and_then(|result| result.as_ref().ok())
            .and_then(|artifact| artifact.completed_v1()).ok_or(RootEnvironmentBusinessErrorV1)?;
        let evidence = self.evidence.as_ref().and_then(|result| result.as_ref().ok())
            .and_then(|evidence| evidence.completed_record_v1()).ok_or(RootEnvironmentBusinessErrorV1)?;
        Ok((generation, acknowledgements, evidence))
    }

    /// Completes the actual retained policy/artifact interval on either outcome.
    /// The socket owner alone proves authenticated Sent and actual peer EOF;
    /// this method never interprets EOF as successful Source lease publication.
    pub(crate) fn finish_claim_once_v1(&mut self, flight: &RootPolicyAcceptedFlightV1<'_, '_>) {
        if self.claim_entered { return; }
        self.claim_entered = true;
        if let Some(Ok(artifact)) = &mut self.artifact {
            self.claim_after = Some(artifact.finish_claim_after_once_v1());
        }
        self.policy_after = Some(flight.finish_environment_policy_once_v1(&mut self.policy));
        self.final_check = Some((|| {
            self.provisional_v1()?;
            self.compiler.final_require_complete_v1(&self.readonly, &self.native_views, &self.policy)?;
            if !matches!(self.claim_after, Some(Ok(()))) { return Err(RootEnvironmentBusinessErrorV1.into()); }
            self.check_original_clock_v1()?;
            Ok(())
        })());
    }

    pub(crate) fn require_complete_v1(&self) -> Result<(), RootEnvironmentBusinessErrorV1> {
        if self.closed.is_none() && matches!(self.final_check, Some(Ok(()))) { Ok(()) }
        else { Err(RootEnvironmentBusinessErrorV1) }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let selected = match self.first {
            Some(First::Clock) => self.clock.failure().or_else(|| cause(&self.clock_gate)),
            Some(First::Readonly) => self.readonly.failure(),
            Some(First::Artifact) => self.artifact.as_ref().and_then(|result| result.as_ref().ok())
                .and_then(|artifact| artifact.failure()).or_else(|| cause(&self.artifact)),
            Some(First::Evidence) => self.evidence.as_ref().and_then(|result| result.as_ref().ok())
                .and_then(|evidence| evidence.failure()).or_else(|| cause(&self.evidence)),
            Some(First::PolicyFunding) => cause(&self.policy_funding),
            Some(First::Policy) => self.policy.failure(),
            Some(First::Accepted) => self.accepted.failure(),
            Some(First::NativeViews) => self.native_views.failure(),
            Some(First::Compiler) => self.compiler.failure(),
            Some(First::Materialization) => cause(&self.materialized),
            None => None,
        };
        selected.or_else(|| self.primary.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
            .or_else(|| self.artifact.as_ref()?.as_ref().ok()?.failure())
            .or_else(|| self.evidence.as_ref()?.as_ref().ok()?.failure())
            .or_else(|| self.native_views.failure()).or_else(|| self.readonly.failure())
            .or_else(|| self.policy.failure()).or_else(|| cause(&self.claim_after))
            .or_else(|| self.final_check.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}
