//! Collects original adverse controls beneath retained provider-only custody.
//!
//! The caller owns the immutable plan and observation sink before Child. Any
//! error leaves the actual controller and native journals in the same launch
//! guard; the inert snapshot is evidence data and never replaces that custody.

use crucible::node_adapters::cnp::{
    CnpLaunchGuard, CnpPreRealizationProbeBody, CnpPreRealizationProbeRequest,
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
    native::ProviderOnlyEnrollment,
    source_probe::{SourceProbeObservation, SourceProbePlan},
};

const MAXIMUM_OBSERVATION_BYTES: usize = 1024 * 1024;

/// Retains original native premises and data oracles without assigning a verdict.
#[derive(Serialize)]
pub(super) struct OriginalSourceProbeObservation {
    schema: &'static str,
    fixture: ContentRef,
    provider_before: ProviderOnlyEnrollment,
    provider_after: ProviderOnlyEnrollment,
    original_snapshot: ContentRef,
    controls: SourceProbeObservation,
}

/// Executes the source-planned controls while the original guard owns journals.
///
/// # Errors
/// Refuses changed source fixtures, unavailable native premises, failed or
/// uncertain controls, changed original process scope, incomplete observations
/// or raw-response/oracle disagreement. Original custody remains with the caller.
pub(super) fn collect(
    installed: &SourcePublicReferenceInstallation,
    guard: &mut CnpLaunchGuard,
    plan: &SourceProbePlan,
    observations: &ObservationHandle,
) -> Result<(OriginalSourceProbeObservation, Vec<u8>), ProviderError> {
    let expected = SourceProbePlan::build(installed)?;
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
            RequestBody::Realize(body) => CnpPreRealizationProbeBody::Realize(Box::new(body)),
            RequestBody::Admit(body) => CnpPreRealizationProbeBody::Admit(Box::new(body)),
            _ => {
                return Err(ProviderError::Correlation(
                    "source probe control outside fixed cohort",
                ));
            }
        };
        requests.push(CnpPreRealizationProbeRequest {
            request: case.request_id.clone(),
            body,
        });
    }
    let provider = guard.provider_pid().ok_or(ProviderError::Correlation(
        "original source probe provider absent",
    ))?;
    let before = ProviderOnlyEnrollment::enroll(
        provider,
        guard.supervision_id(),
        &installed.package,
        &installed.bootstrap.resource_limits,
    )?;
    let qualification = ProbeQualification { installed, plan };
    #[cfg(test)]
    verify_local_authorization_refusals(
        installed,
        guard,
        &qualification,
        &mut requests,
        observations,
        &before,
    )?;
    guard
        .probe_pre_realization(&qualification, &requests)
        .map_err(|failure| ProviderError::Io(std::io::Error::other(failure.reason)))?;
    before.authenticate(&installed.package, &installed.bootstrap.resource_limits)?;
    let after = ProviderOnlyEnrollment::enroll(
        provider,
        guard.supervision_id(),
        &installed.package,
        &installed.bootstrap.resource_limits,
    )?;

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
        OriginalSourceProbeObservation {
            schema: "crucible.reference.original-pre-realization-probes.v1",
            fixture: plan.reference.clone(),
            provider_before: before,
            provider_after: after,
            original_snapshot,
            controls,
        },
        bytes,
    ))
}

/// Narrows the existing native qualification to this original adverse fixture.
struct ProbeQualification<'a> {
    installed: &'a SourcePublicReferenceInstallation,
    plan: &'a SourceProbePlan,
}

impl CnpReferenceQualification for ProbeQualification<'_> {
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

    fn authenticate_pre_realization_probes(
        &self,
        guard: &CnpLaunchGuard,
        requests: &[CnpPreRealizationProbeRequest],
    ) -> Result<(), OperationFailure> {
        let result = (|| {
            if requests.len() != self.plan.cases().len() {
                return Err(ProviderError::Correlation(
                    "original source probe population changed",
                ));
            }
            for (request, case) in requests.iter().zip(self.plan.cases()) {
                let (method, body) = match &request.body {
                    CnpPreRealizationProbeBody::Realize(body) => (
                        crucible_node_provider::envelope::Method::Realize,
                        serde_json::to_value(body),
                    ),
                    CnpPreRealizationProbeBody::Admit(body) => (
                        crucible_node_provider::envelope::Method::Admit,
                        serde_json::to_value(body),
                    ),
                    _ => {
                        return Err(ProviderError::Correlation(
                            "source probe method outside fixed cohort",
                        ));
                    }
                };
                let body = body.map_err(crucible_node_contract::ContractError::from)?;
                if request.request != case.request_id
                    || method != case.method
                    || body != serde_json::Value::Object(case.body.clone())
                {
                    return Err(ProviderError::Correlation(
                        "original source probe body or identity changed",
                    ));
                }
            }
            let provider = guard.provider_pid().ok_or(ProviderError::Correlation(
                "original source probe provider absent",
            ))?;
            ProviderOnlyEnrollment::enroll(
                provider,
                guard.supervision_id(),
                &self.installed.package,
                &self.installed.bootstrap.resource_limits,
            )?;
            Ok(())
        })();
        result.map_err(|error: ProviderError| OperationFailure {
            effects: EffectKnowledge::None,
            reason: error.to_string(),
        })
    }
}

/// Checks refusal before frames against the same actual original provider.
#[cfg(test)]
fn verify_local_authorization_refusals(
    installed: &SourcePublicReferenceInstallation,
    guard: &mut CnpLaunchGuard,
    qualification: &ProbeQualification<'_>,
    requests: &mut [CnpPreRealizationProbeRequest],
    observations: &ObservationHandle,
    before: &ProviderOnlyEnrollment,
) -> Result<(), ProviderError> {
    let original_keys = observations.request_keys()?;
    let refusal = guard.probe_pre_realization(installed, requests);
    if !matches!(refusal, Err(ref failure) if failure.effects == EffectKnowledge::None) {
        return Err(ProviderError::Correlation(
            "default probe policy failed open",
        ));
    }

    let Some(CnpPreRealizationProbeRequest {
        body: CnpPreRealizationProbeBody::Realize(realize),
        ..
    }) = requests.first_mut()
    else {
        return Err(ProviderError::Correlation("original Realize probe absent"));
    };
    let hostile_configuration = realize.configuration.clone();
    realize.configuration = installed.profile.configuration_ref.clone();
    let refusal = guard.probe_pre_realization(qualification, requests);
    if let Some(CnpPreRealizationProbeRequest {
        body: CnpPreRealizationProbeBody::Realize(realize),
        ..
    }) = requests.first_mut()
    {
        realize.configuration = hostile_configuration;
    }
    if !matches!(refusal, Err(ref failure) if failure.effects == EffectKnowledge::None) {
        return Err(ProviderError::Correlation(
            "unplanned valid Realize authorized",
        ));
    }
    if observations.request_keys()? != original_keys {
        return Err(ProviderError::Correlation(
            "refused probe created original frames",
        ));
    }
    before.authenticate(&installed.package, &installed.bootstrap.resource_limits)
}
