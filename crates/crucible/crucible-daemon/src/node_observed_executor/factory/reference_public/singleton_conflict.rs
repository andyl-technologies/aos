//! Collects changed bodies beside three originals from this singleton alone.
//!
//! The plan exists before Child. Every send checks the same native provider-only
//! owner and complete source originals; the shared wire decoder supplies only a
//! byte oracle. Neither it nor the observation handle grants native authority.

use crucible_engine::node_adapters::cnp::{
    CnpLaunchGuard, CnpPreRealizationConflictRequest, CnpReferenceQualification,
};
use crucible_engine::node_contract::{EffectKnowledge, OperationFailure};
use crucible_node_format::{ClosedGateRecord, ContentRef, U64, canonical};
use crucible_node_transport::{
    ProviderError,
    bodies::{RealizeResult, RequestBody, decode_request},
    client::{
        ObservationHandle, ObservationLimits, ObservedRequestKey, OriginalConflictObservationHandle,
    },
    envelope::RequestOrigin,
    reference_service::ReferenceProfile,
};
use serde_json::{Value, json};

use super::{
    installation::SourcePublicReferenceInstallation,
    native::ProviderOnlyEnrollment,
    source_original_conflict_wire::{self, WireOriginal},
    source_probe::SourceProbePlan,
};

const MAXIMUM_BYTES: usize = 4 * 1024 * 1024;

pub(super) struct SingletonConflictPlan {
    pub(super) reference: ContentRef,
    pub(super) bytes: Vec<u8>,
    requests: Vec<CnpPreRealizationConflictRequest>,
}

impl SingletonConflictPlan {
    /// Materializes changed bodies without changing any original request.
    ///
    /// # Errors
    /// Refuses a different source roster, unchanged material or malformed body.
    pub(super) fn build(plan: &SourceProbePlan) -> Result<Self, ProviderError> {
        if plan.cases().len() != 5 {
            return Err(changed());
        }
        let mut requests = Vec::new();
        requests
            .try_reserve_exact(3)
            .map_err(|_| ProviderError::ResourceExhausted("singleton conflict slots"))?;
        for original in plan.cases().iter().take(3) {
            let value = match decode_request(original.method, &original.body)? {
                RequestBody::Realize(mut body) => {
                    body.resource_limits.processes = U64::new(1);
                    serde_json::to_value(body)
                }
                RequestBody::Admit(mut body) => {
                    body.admission_receipt = canonical::content_ref(
                        b"singleton source-owned different admission receipt",
                        "application/octet-stream",
                    )?;
                    serde_json::to_value(body)
                }
                _ => return Err(changed()),
            }
            .map_err(crucible_node_format::ContractError::from)?;
            let body = value.as_object().cloned().ok_or_else(changed)?;
            if body == original.body {
                return Err(changed());
            }
            decode_request(original.method, &body)?;
            requests.push(CnpPreRealizationConflictRequest {
                request: original.request_id.clone(),
                method: original.method,
                body,
            });
        }
        let cases = requests
            .iter()
            .map(|request| {
                json!({
                    "request":request.request,"method":request.method,"body":request.body,
                })
            })
            .collect::<Vec<_>>();
        let bytes = canonical::canonical_json(&json!({
            "schema":"crucible.reference.singleton-pre-realization-conflicts.v1",
            "original_plan":plan.reference,"cases":cases,
            "source":canonical::content_ref(include_bytes!("singleton_conflict.rs"),"text/plain")?,
            "native_premise":"same original provider only before and after every send",
            "wire_oracle":"three original request/response plus changed request/response byte closures",
            "retirement":"same original recorder; incomplete write/read remains held",
            "whole_clause_credit":"NotExecuted",
        }))?;
        Ok(Self {
            reference: canonical::content_ref(&bytes, "application/json")?,
            bytes,
            requests,
        })
    }

    /// Runs this original population once while the caller retains all custody.
    ///
    /// # Errors
    /// Refuses changed source originals, foreign native owners, uncertain wire
    /// outcomes or changed journal bytes. No uncertainty starts a fresh attempt.
    pub(super) fn collect(
        &self,
        installed: &SourcePublicReferenceInstallation,
        guard: &mut CnpLaunchGuard,
        plan: &SourceProbePlan,
        observations: &ObservationHandle,
        conflicts: &OriginalConflictObservationHandle,
    ) -> Result<(Value, Vec<u8>), ProviderError> {
        let regenerated = Self::build(plan)?;
        if self.reference != regenerated.reference || self.bytes != regenerated.bytes {
            return Err(changed());
        }
        let keys = plan
            .cases()
            .iter()
            .map(|case| ObservedRequestKey {
                origin: RequestOrigin::Controller,
                request_id: case.request_id.clone(),
            })
            .collect::<Vec<_>>();
        let original = observations.snapshot(&keys, &[], limits())?;
        plan.verify(&original)?;
        let original_bytes = original.encode(MAXIMUM_BYTES)?;
        let provider = guard.provider_pid().ok_or_else(changed)?;
        let before = ProviderOnlyEnrollment::enroll(
            provider,
            guard.supervision_id(),
            &installed.package,
            &installed.bootstrap.resource_limits,
        )?;
        let policy = ConflictQualification {
            installed,
            requests: &self.requests,
            before: &before,
            observations,
            keys: &keys,
            original_bytes: &original_bytes,
        };
        guard
            .probe_pre_realization_conflicts(&policy, &self.requests)
            .map_err(|error| ProviderError::Io(std::io::Error::other(error.reason)))?;
        before.authenticate(&installed.package, &installed.bootstrap.resource_limits)?;
        let after = ProviderOnlyEnrollment::enroll(
            provider,
            guard.supervision_id(),
            &installed.package,
            &installed.bootstrap.resource_limits,
        )?;
        if observations
            .snapshot(&keys, &[], limits())?
            .encode(MAXIMUM_BYTES)?
            != original_bytes
        {
            return Err(changed());
        }

        let wire = conflicts.snapshot(MAXIMUM_BYTES)?;
        let wire = serde_json::to_value(wire).map_err(crucible_node_format::ContractError::from)?;
        let mut borrowed = Vec::with_capacity(3);
        for request in &self.requests {
            let retained = original
                .evidence
                .requests
                .iter()
                .find(|row| {
                    row.key.origin == RequestOrigin::Controller
                        && row.key.request_id == request.request
                })
                .ok_or_else(changed)?;
            borrowed.push(WireOriginal {
                request: &request.request,
                original_request: &retained.request.reference,
                original_response: &retained.response.0.as_ref().ok_or_else(changed)?.reference,
                connection: &original.evidence.scope.connection_id,
                changed_body: &request.body,
            });
        }
        source_original_conflict_wire::verify_borrowed(&wire, &borrowed)?;
        Ok((
            json!({"schema":"crucible.reference.singleton-original-conflicts.v1",
            "plan":self.reference,"provider_before":before,"provider_after":after,
            "original_snapshot":canonical::content_ref(&original_bytes,"application/json")?,
            "wire":wire,"whole_clause_credit":"NotExecuted"}),
            original_bytes,
        ))
    }
}

struct ConflictQualification<'a> {
    installed: &'a SourcePublicReferenceInstallation,
    requests: &'a [CnpPreRealizationConflictRequest],
    before: &'a ProviderOnlyEnrollment,
    observations: &'a ObservationHandle,
    keys: &'a [ObservedRequestKey],
    original_bytes: &'a [u8],
}

impl CnpReferenceQualification for ConflictQualification<'_> {
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

    fn authenticate_pre_realization_conflicts(
        &self,
        guard: &CnpLaunchGuard,
        requests: &[CnpPreRealizationConflictRequest],
    ) -> Result<(), OperationFailure> {
        let result = (|| {
            if requests.len() != 3
                || requests
                    .iter()
                    .zip(self.requests)
                    .any(|(actual, expected)| {
                        actual.request != expected.request
                            || actual.method != expected.method
                            || actual.body != expected.body
                    })
            {
                return Err(changed());
            }
            self.before.authenticate(
                &self.installed.package,
                &self.installed.bootstrap.resource_limits,
            )?;
            ProviderOnlyEnrollment::enroll(
                guard.provider_pid().ok_or_else(changed)?,
                guard.supervision_id(),
                &self.installed.package,
                &self.installed.bootstrap.resource_limits,
            )?;
            if self
                .observations
                .snapshot(self.keys, &[], limits())?
                .encode(MAXIMUM_BYTES)?
                != self.original_bytes
            {
                return Err(changed());
            }
            Ok(())
        })();
        result.map_err(|error: ProviderError| OperationFailure {
            effects: EffectKnowledge::None,
            reason: error.to_string(),
        })
    }
}

fn limits() -> ObservationLimits {
    ObservationLimits {
        maximum_requests: 16,
        maximum_objects: 16,
        maximum_bytes: MAXIMUM_BYTES,
    }
}

fn changed() -> ProviderError {
    ProviderError::Correlation("singleton original conflict population changed")
}
