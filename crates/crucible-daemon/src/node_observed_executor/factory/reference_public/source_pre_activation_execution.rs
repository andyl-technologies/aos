//! Collects planned adverse controls beneath retained prepared native custody.
//!
//! The caller owns the immutable plan and observation sink before Child. Any
//! error leaves the actual controller and native journals in the same launch
//! guard; the inert snapshot is evidence data and never replaces that custody.

use crucible::node_adapters::cnp::{
    CnpLaunchGuard, CnpPreparedAdverseBody, CnpPreparedAdverseRequest, CnpReferencePreparation,
    CnpReferenceQualification,
};
use crucible::node_contract::{EffectKnowledge, OperationFailure};
use crucible_node_contract::{ClosedGateRecord, ContentRef, canonical};
use crucible_node_provider::{
    ProviderError,
    bodies::{RealizeResult, RequestBody, decode_request},
    client::{ObservationHandle, ObservationLimits, ObservedRequestKey},
    envelope::RequestOrigin,
    reference_service::ReferenceProfile,
};
use serde::Serialize;

use super::{
    installation::SourcePublicReferenceInstallation,
    native::NativePublicEnrollment,
    prepared_gate_evidence::{self, OriginalPreparedGate},
    source_pre_activation_probe::{
        SourcePreActivationProbeObservation, SourcePreActivationProbePlan,
    },
};

const MAXIMUM_OBSERVATION_BYTES: usize = 1024 * 1024;

/// Retains original native premises and data oracles without assigning a verdict.
#[derive(Serialize)]
pub(super) struct OriginalPreparedAdverseObservation {
    schema: &'static str,
    fixture: ContentRef,
    provider_before: NativePublicEnrollment,
    provider_after: NativePublicEnrollment,
    original_snapshot: ContentRef,
    initial_gate: OriginalPreparedGate,
    controls: SourcePreActivationProbeObservation,
    original_plan_objects: Vec<serde_json::Value>,
}

/// Executes the source-planned controls while the original guard owns journals.
///
/// # Errors
/// Refuses changed source fixtures, unavailable native premises, failed or
/// uncertain controls, changed original process scope, incomplete observations
/// or raw-response/oracle disagreement. Original custody remains with the caller.
pub(super) fn collect(
    installed: &SourcePublicReferenceInstallation,
    prepared: &mut CnpReferencePreparation,
    plan: &SourcePreActivationProbePlan,
    observations: &ObservationHandle,
) -> Result<(OriginalPreparedAdverseObservation, Vec<u8>), ProviderError> {
    let expected = SourcePreActivationProbePlan::build(installed)?;
    if expected.reference != plan.reference
        || expected.bytes != plan.bytes
        || expected.objects != plan.objects
        || expected.cases().len() != plan.cases().len()
        || expected
            .cases()
            .iter()
            .zip(plan.cases())
            .any(|(left, right)| {
                left.case != right.case
                    || left.request_id != right.request_id
                    || left.operation_id != right.operation_id
                    || left.method != right.method
                    || left.body != right.body
            })
    {
        return Err(ProviderError::Correlation(
            "original source probe fixture changed",
        ));
    }
    let mut requests = Vec::new();
    requests
        .try_reserve_exact(plan.cases().len())
        .map_err(|_| ProviderError::ResourceExhausted("source probe request credits"))?;
    for case in plan.cases() {
        let body = match decode_request(case.method, &case.body)? {
            RequestBody::Begin(body) => CnpPreparedAdverseBody::UnsupportedBegin(Box::new(body)),
            RequestBody::Observe(body) => CnpPreparedAdverseBody::Observe(Box::new(body)),
            _ => {
                return Err(ProviderError::Correlation(
                    "prepared adverse method outside fixture",
                ));
            }
        };
        requests.push(CnpPreparedAdverseRequest {
            request: case.request_id.clone(),
            operation: case.operation_id.clone(),
            body,
        });
    }
    let initial_gate = prepared_gate_evidence::retain(installed, observations)?;
    let original_gate_bytes = canonical::canonical_json(
        &serde_json::to_value(&initial_gate)
            .map_err(crucible_node_contract::ContractError::from)?,
    )?;
    let before = installed.enrollment()?;
    before.authenticate(&installed.package, &installed.bootstrap.resource_limits)?;
    let qualification = PreparedAdverseQualification { installed, plan };
    #[cfg(test)]
    verify_local_refusals(installed, prepared, &qualification, &requests, observations)?;
    prepared
        .probe_pre_activation(&qualification, &requests)
        .map_err(|failure| ProviderError::Io(std::io::Error::other(failure.reason)))?;
    before.authenticate(&installed.package, &installed.bootstrap.resource_limits)?;
    let after = installed.enrollment()?;
    let retained_gate = prepared_gate_evidence::retain(installed, observations)?;
    let retained_gate_bytes = canonical::canonical_json(
        &serde_json::to_value(&retained_gate)
            .map_err(crucible_node_contract::ContractError::from)?,
    )?;
    if retained_gate_bytes != original_gate_bytes {
        return Err(ProviderError::Correlation(
            "historical original gate bytes changed",
        ));
    }

    let keys = plan
        .cases()
        .iter()
        .map(|case| ObservedRequestKey {
            origin: RequestOrigin::Controller,
            request_id: case.request_id.clone(),
        })
        .collect::<Vec<_>>();
    let snapshot = observations.snapshot(
        &keys,
        &[],
        ObservationLimits {
            maximum_requests: 16,
            maximum_objects: 16,
            maximum_bytes: MAXIMUM_OBSERVATION_BYTES,
        },
    )?;
    let controls = plan.verify(&snapshot)?;
    let bytes = snapshot.encode(MAXIMUM_OBSERVATION_BYTES)?;
    let original_snapshot = canonical::content_ref(&bytes, "application/json")?;
    Ok((
        OriginalPreparedAdverseObservation {
            schema: "crucible.reference.original-pre-activation-probes.v1",
            fixture: plan.reference.clone(),
            provider_before: before,
            provider_after: after,
            original_snapshot,
            initial_gate,
            controls,
            original_plan_objects: plan
                .objects
                .iter()
                .map(|(reference, bytes)| serde_json::json!({"reference":reference,"bytes":bytes}))
                .collect(),
        },
        bytes,
    ))
}

/// Admits only exact original data controls on the privately installed native pair.
struct PreparedAdverseQualification<'a> {
    installed: &'a SourcePublicReferenceInstallation,
    plan: &'a SourcePreActivationProbePlan,
}

impl CnpReferenceQualification for PreparedAdverseQualification<'_> {
    fn authenticate_provider(
        &self,
        guard: &CnpLaunchGuard,
        profile: &ReferenceProfile,
    ) -> Result<(), OperationFailure> {
        self.installed.authenticate_provider(guard, profile)
    }

    fn authenticate_realization(
        &self,
        guard: &CnpLaunchGuard,
        result: &RealizeResult,
        gate: &ClosedGateRecord,
        companion: u32,
    ) -> Result<(), OperationFailure> {
        self.installed
            .authenticate_realization(guard, result, gate, companion)
    }

    fn authenticate_prepared_adverse_probes(
        &self,
        prepared: &CnpReferencePreparation,
        requests: &[CnpPreparedAdverseRequest],
    ) -> Result<(), OperationFailure> {
        let result = (|| {
            let (binding, owner) = self.installed.profile.bind_qualified(
                self.installed.bootstrap.authority.clone(),
                &self.installed.qualifications,
            )?;
            if prepared.descriptor() != &self.installed.profile.descriptor
                || prepared.binding() != &binding
                || prepared.owner_binding() != &owner
                || requests.len() != self.plan.cases().len()
            {
                return Err(ProviderError::Correlation(
                    "original prepared adverse scope changed",
                ));
            }
            for (request, case) in requests.iter().zip(self.plan.cases()) {
                let (method, body) = match &request.body {
                    CnpPreparedAdverseBody::UnsupportedBegin(body) => (
                        crucible_node_provider::envelope::Method::Begin,
                        serde_json::to_value(body),
                    ),
                    CnpPreparedAdverseBody::Observe(body) => (
                        crucible_node_provider::envelope::Method::Observe,
                        serde_json::to_value(body),
                    ),
                };
                let body = body.map_err(crucible_node_contract::ContractError::from)?;
                if request.request != case.request_id
                    || request.operation != case.operation_id
                    || method != case.method
                    || body != serde_json::Value::Object(case.body.clone())
                {
                    return Err(ProviderError::Correlation(
                        "original prepared adverse body changed",
                    ));
                }
            }
            self.installed.enrollment()?.authenticate(
                &self.installed.package,
                &self.installed.bootstrap.resource_limits,
            )
        })();
        result.map_err(|error: ProviderError| OperationFailure {
            effects: EffectKnowledge::None,
            reason: error.to_string(),
        })
    }
}

/// Checks genuine guarded refusal without sending an extra native control.
#[cfg(test)]
fn verify_local_refusals(
    installed: &SourcePublicReferenceInstallation,
    prepared: &mut CnpReferencePreparation,
    qualification: &PreparedAdverseQualification<'_>,
    requests: &[CnpPreparedAdverseRequest],
    observations: &ObservationHandle,
) -> Result<(), ProviderError> {
    let originals = observations.request_keys()?;
    let refused = prepared.probe_pre_activation(installed, requests);
    if !matches!(
        refused,
        Err(OperationFailure {
            effects: EffectKnowledge::None,
            ..
        })
    ) {
        return Err(ProviderError::Correlation(
            "default prepared probe policy did not refuse before dispatch",
        ));
    }
    let mut changed = Vec::with_capacity(requests.len());
    for request in requests {
        let body = match &request.body {
            CnpPreparedAdverseBody::UnsupportedBegin(body) => {
                CnpPreparedAdverseBody::UnsupportedBegin(body.clone())
            }
            CnpPreparedAdverseBody::Observe(body) => CnpPreparedAdverseBody::Observe(body.clone()),
        };
        changed.push(CnpPreparedAdverseRequest {
            request: request.request.clone(),
            operation: request.operation.clone(),
            body,
        });
    }
    let CnpPreparedAdverseBody::Observe(observe) = &mut changed[0].body else {
        return Err(ProviderError::Correlation(
            "prepared fixture initial Observe absent",
        ));
    };
    observe.owner_generation = crucible_node_contract::U64::new(3);
    let refused = prepared.probe_pre_activation(qualification, &changed);
    if !matches!(
        refused,
        Err(OperationFailure {
            effects: EffectKnowledge::None,
            ..
        })
    ) || observations.request_keys()? != originals
    {
        return Err(ProviderError::Correlation(
            "changed prepared fixture reached original dispatch",
        ));
    }
    installed
        .enrollment()?
        .authenticate(&installed.package, &installed.bootstrap.resource_limits)
}
