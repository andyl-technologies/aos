//! Predeclares the fixed pre-realization adverse cohort and checks original data.
//!
//! These three cases exercise source-defined refusal precedence before a native
//! companion exists. The immutable fixture describes hostile input recipes;
//! separately retained original requests preserve fresh binding identities.
//! Sending requests additionally requires guard-owned controller custody and
//! independent before/after provider-only enrollment. This module sends nothing
//! and confers no absence-of-effects or behavioral qualification certificate.

use std::collections::BTreeMap;

use crucible_node_contract::{ContentRef, Extensions, Id, canonical};
use crucible_node_provider::{
    ProviderError,
    bodies::{
        AdmitRequest, EffectCertainty, OperationState, RealizeRequest, ResponseShape,
        decode_request, decode_response,
    },
    client::RecordedReferenceObservation,
    envelope::{Envelope, Method, RequestOrigin},
};
use serde::Serialize;
use serde_json::{Map, Value};

use super::installation::SourcePublicReferenceInstallation;

const MAXIMUM_FIXTURE_BYTES: usize = 128 * 1024;
const MAXIMUM_CONTROL_BYTES: usize = 1_048_576;

/// Retains reusable fixture bytes separately from fresh original control scope.
pub(super) struct SourceProbePlan {
    pub(super) reference: ContentRef,
    pub(super) bytes: Vec<u8>,
    pub(super) objects: BTreeMap<ContentRef, Vec<u8>>,
    cases: Vec<OriginalProbeCase>,
    session: Id,
    incarnation: Id,
    binding_hash: crucible_node_contract::HashRef,
    provider: ContentRef,
}

/// Retains one pre-materialized original request under its immutable case ID.
pub(super) struct OriginalProbeCase {
    pub(super) case: Id,
    pub(super) request_id: Id,
    pub(super) method: Method,
    pub(super) body: Map<String, Value>,
}

/// Records authenticated original refusal bytes without upgrading their scope.
#[derive(Serialize)]
pub(super) struct SourceProbeObservation {
    pub(super) fixture: ContentRef,
    pub(super) cases: Vec<OriginalProbeObservation>,
}

#[derive(Serialize)]
pub(super) struct OriginalProbeObservation {
    case: Id,
    request: ContentRef,
    response: ContentRef,
    source_error: &'static str,
}

impl SourceProbePlan {
    /// Materializes the exact three cases before any native child allocation.
    ///
    /// The fixture identity deliberately excludes original session/world/owner
    /// incarnation values. Their full untouched values remain in each retained
    /// request; no proof or content reference is normalized or rewritten.
    ///
    /// # Errors
    /// Refuses unavailable installed bindings, unsupported definitions, malformed
    /// original bodies, allocation failure or the finite fixture byte ceiling.
    pub(super) fn build(
        installed: &SourcePublicReferenceInstallation,
    ) -> Result<Self, ProviderError> {
        let changed_configuration = canonical::canonical_json(&serde_json::json!({
            "schema":"crucible.reference.source-probe-invalid-configuration.v1",
            "definition":"different-from-the-source-installed-configuration"
        }))?;
        let configuration = canonical::content_ref(&changed_configuration, "application/json")?;
        if configuration == installed.profile.configuration_ref {
            return Err(ProviderError::Correlation(
                "hostile configuration equals original",
            ));
        }
        let foreign_node = Id::new("source-probe/absent-node")?;
        if installed
            .profile
            .owner
            .participant_ids
            .contains(&foreign_node)
        {
            return Err(ProviderError::Correlation(
                "hostile node belongs to original roster",
            ));
        }
        let source = include_str!("source_probe.rs").as_bytes().to_vec();
        let source_ref = canonical::content_ref(&source, "text/plain")?;
        let bytes = canonical::canonical_json(&serde_json::json!({
            "schema":"crucible.reference.pre-realization-probe-plan.v1",
            "implementation":installed.package.identity(),
            "node":installed.profile.descriptor.id,
            "configuration":installed.profile.configuration_ref,
            "resource_limits":installed.bootstrap.resource_limits,
            "selected_features":super::unit::required_features()?,
            "source":source_ref,
            "stage":"after-authenticated-hello-before-realization",
            "controller_budget_ns":"3000000000",
            "native_premise":"same-original-provider-only-no-companion-census",
            "limitations":["no-general-no-effects-proof","no-native-window-execution","partial-obligation-coverage"],
            "cases":[
                {"case":"configuration-mismatch","method":"realize","change":{"configuration":configuration}},
                {"case":"node-roster-mismatch","method":"realize","change":{"requested_node_ids":[foreign_node]}},
                {"case":"admit-before-realize","method":"admit","change":"none-original-binding-before-realize"}
            ],
            "oracle":{"error":"CONFLICT","effect":"not_started","operation_state":"not_started","retryable":false}
        }))?;
        if bytes.len() > MAXIMUM_FIXTURE_BYTES || source.len() > MAXIMUM_FIXTURE_BYTES {
            return Err(ProviderError::ResourceExhausted(
                "source probe fixture bytes",
            ));
        }
        let reference = canonical::content_ref(&bytes, "application/json")?;
        let (binding, _) = installed.profile.bind_qualified(
            installed.bootstrap.authority.clone(),
            &installed.qualifications,
        )?;
        let realize = RealizeRequest {
            realization_id: installed.bootstrap.authority.realization_id.clone(),
            configuration: installed.profile.configuration_ref.clone(),
            requested_node_ids: installed.profile.owner.participant_ids.clone(),
            resource_limits: installed.bootstrap.resource_limits.clone(),
            extensions: Extensions::new(),
        };
        let mut changed_configuration_request = realize.clone();
        changed_configuration_request.configuration = configuration.clone();
        let mut changed_nodes_request = realize;
        changed_nodes_request.requested_node_ids = vec![foreign_node];
        let admit = AdmitRequest {
            bindings: vec![binding.clone()],
            world_binding_hash: installed.bootstrap.world_binding_hash.clone(),
            admission_receipt: installed.bootstrap.admission_receipt.clone(),
            extensions: Extensions::new(),
        };
        let mut cases = Vec::new();
        cases
            .try_reserve_exact(3)
            .map_err(|_| ProviderError::ResourceExhausted("source probe case allocation"))?;
        for (name, method, body) in [
            (
                "configuration-mismatch",
                Method::Realize,
                object(changed_configuration_request)?,
            ),
            (
                "node-roster-mismatch",
                Method::Realize,
                object(changed_nodes_request)?,
            ),
            ("admit-before-realize", Method::Admit, object(admit)?),
        ] {
            decode_request(method, &body)?;
            cases.push(OriginalProbeCase {
                case: Id::new(format!("reference/pre-realize/{name}"))?,
                request_id: Id::new(format!(
                    "source-probe/{}/{name}",
                    installed.profile.descriptor.id
                ))?,
                method,
                body,
            });
        }
        let objects = BTreeMap::from([
            (reference.clone(), bytes.clone()),
            (source_ref, source),
            (configuration, changed_configuration),
        ]);
        Ok(Self {
            reference,
            bytes,
            objects,
            cases,
            session: installed.bootstrap.authority.session_id.clone(),
            incarnation: installed.bootstrap.authority.incarnation_id.clone(),
            binding_hash: binding.identity()?,
            provider: installed
                .package
                .artifact_content("provider")
                .map_err(|error| ProviderError::Io(std::io::Error::other(error.to_string())))?
                .clone(),
        })
    }

    /// Borrows originals for a guard-owned caller using `owned=false`/no operation.
    pub(super) fn cases(&self) -> &[OriginalProbeCase] {
        &self.cases
    }

    /// Checks the exact source-original response subset, retaining no verdict.
    ///
    /// # Errors
    /// Refuses missing or uncertain originals, another observed source scope,
    /// changed materialized bodies, unmatched replies or any different error.
    /// Native before/after enrollment remains independently mandatory.
    pub(super) fn verify(
        &self,
        observed: &RecordedReferenceObservation,
    ) -> Result<SourceProbeObservation, ProviderError> {
        let scope = &observed.evidence.scope;
        if !observed.recording_complete
            || observed.observed_unknown
            || observed.recording_failure.0.is_some()
            || scope.session_id != self.session
            || scope.incarnation_id != self.incarnation
            || scope.binding_hash != self.binding_hash
            || scope.provider_executable != self.provider
            || scope.selected_features != super::unit::required_features()?
        {
            return Err(ProviderError::Correlation(
                "source probe originals incomplete or foreign",
            ));
        }
        let mut cases = Vec::new();
        cases
            .try_reserve_exact(self.cases.len())
            .map_err(|_| ProviderError::ResourceExhausted("source probe observation allocation"))?;
        for case in &self.cases {
            let mut matches = observed.evidence.requests.iter().filter(|original| {
                original.key.origin == RequestOrigin::Controller
                    && original.key.request_id == case.request_id
            });
            let original = matches
                .next()
                .ok_or(ProviderError::Correlation("source probe original absent"))?;
            if matches.next().is_some() {
                return Err(ProviderError::Correlation(
                    "source probe original duplicated",
                ));
            }
            original
                .request
                .reference
                .verify(original.request.bytes.as_slice())?;
            let request =
                Envelope::decode(original.request.bytes.as_slice(), MAXIMUM_CONTROL_BYTES)?;
            if request.method != case.method
                || request.body != case.body
                || request.session_id.0.as_ref() != Some(&self.session)
                || request.incarnation_id.0.as_ref() != Some(&self.incarnation)
                || request.request_id.0.as_ref() != Some(&case.request_id)
                || request.operation_id.0.is_some()
                || request.node_id.0.is_some()
                || request.execution_owner_id.0.is_some()
                || request.capture_owner_id.0.is_some()
                || !request.extensions.is_empty()
            {
                return Err(ProviderError::Correlation(
                    "source probe original request changed",
                ));
            }
            let response = original
                .response
                .0
                .as_ref()
                .ok_or(ProviderError::Correlation("source probe reply unknown"))?;
            response.reference.verify(response.bytes.as_slice())?;
            let envelope = Envelope::decode(response.bytes.as_slice(), MAXIMUM_CONTROL_BYTES)?;
            request.matches_response(&envelope)?;
            let body = decode_response(&decode_request(case.method, &case.body)?, &envelope.body)?;
            let ResponseShape::Error {
                operation_state,
                error,
                extensions,
            } = body.shape
            else {
                return Err(ProviderError::Correlation(
                    "source probe original unexpectedly succeeded",
                ));
            };
            if operation_state != OperationState::NotStarted
                || error.code != "CONFLICT"
                || error.effect != EffectCertainty::NotStarted
                || error.retryable
                || !extensions.is_empty()
                || body.result.is_some()
            {
                return Err(ProviderError::Correlation(
                    "source probe source refusal differs",
                ));
            }
            cases.push(OriginalProbeObservation {
                case: case.case.clone(),
                request: original.request.reference.clone(),
                response: response.reference.clone(),
                source_error: "CONFLICT",
            });
        }
        Ok(SourceProbeObservation {
            fixture: self.reference.clone(),
            cases,
        })
    }
}

fn object(value: impl Serialize) -> Result<Map<String, Value>, ProviderError> {
    serde_json::to_value(value)
        .map_err(crucible_node_contract::ContractError::from)?
        .as_object()
        .cloned()
        .ok_or(ProviderError::Frame(
            "source probe request is not an object",
        ))
}
