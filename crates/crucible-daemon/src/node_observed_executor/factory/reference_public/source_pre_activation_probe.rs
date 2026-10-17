//! Predeclares unsupported controls beneath original inactive preparation.
//!
//! Exact original envelopes remain distinct from reusable hostile-input recipes.
//! The oracle checks source-defined typed refusals and unchanged public pending
//! observations. Independent native census, original closed-gate provenance and
//! a subsequent first-quantum checksum remain mandatory separate premises. This
//! module sends nothing and issues no absence-of-effects or qualification proof.

use std::collections::BTreeMap;

use crucible_node_contract::{ContentRef, HashRef, Id, U64, canonical};
use crucible_node_provider::{
    ProviderError,
    bodies::{
        EffectCertainty, MethodResult, OperationState, ResponseShape, decode_request,
        decode_response,
    },
    client::RecordedReferenceObservation,
    envelope::{Envelope, Method, RequestOrigin},
};
use serde::Serialize;
use serde_json::{Map, Value, json};

use super::installation::SourcePublicReferenceInstallation;

const MAXIMUM_FIXTURE_BYTES: usize = 128 * 1024;
const MAXIMUM_CONTROL_BYTES: usize = 1_048_576;

/// Retains predeclared recipes and untouched fresh request bodies.
pub(super) struct SourcePreActivationProbePlan {
    pub(super) reference: ContentRef,
    pub(super) bytes: Vec<u8>,
    pub(super) objects: BTreeMap<ContentRef, Vec<u8>>,
    fixture_objects: BTreeMap<ContentRef, Vec<u8>>,
    cases: Vec<OriginalPreparedProbeCase>,
    session: Id,
    incarnation: Id,
    node: Id,
    owner: Id,
    binding: HashRef,
    expected_initial_inventory: ContentRef,
    provider: ContentRef,
}

/// Binds a case to its original owned request and optional operation.
pub(super) struct OriginalPreparedProbeCase {
    pub(super) case: Id,
    pub(super) request_id: Id,
    pub(super) operation_id: Option<Id>,
    pub(super) method: Method,
    pub(super) body: Map<String, Value>,
}

/// Contains source-observed facts without completing a behavioral obligation.
#[derive(Serialize)]
pub(super) struct SourcePreActivationProbeObservation {
    fixture: ContentRef,
    cases: Vec<OriginalPreparedProbeObservation>,
    unchanged_pending_page: bool,
    expected_initial_inventory: ContentRef,
}

#[derive(Serialize)]
struct OriginalPreparedProbeObservation {
    case: Id,
    request: ContentRef,
    response: ContentRef,
    source_result: &'static str,
}

impl SourcePreActivationProbePlan {
    /// Materializes all hostile inputs and read allowances before native spawn.
    ///
    /// # Errors
    /// Refuses a changed source generation, malformed bodies, unsupported fixed
    /// bindings, identifier overflow or unavailable finite fixture credits.
    pub(super) fn build(
        installed: &SourcePublicReferenceInstallation,
    ) -> Result<Self, ProviderError> {
        let bootstrap = &installed.bootstrap;
        if bootstrap.authority.owner_generation != U64::new(1) {
            return Err(ProviderError::Correlation(
                "prepared probe requires source generation one",
            ));
        }
        let (binding, owner_binding) = installed
            .profile
            .bind_qualified(bootstrap.authority.clone(), &installed.qualifications)?;
        let original_owner_hash = owner_binding.identity()?;
        // These independently constructed oracle bytes are not recovered native
        // evidence. Fresh authority remains explicit in this attempt-only object.
        let expected_inventory_bytes = canonical::canonical_json(&json!({
            "schema_version":1, "execution_owner_id":bootstrap.owner_id,
            "owner_binding_hash":original_owner_hash,
            "world_binding_hash":bootstrap.world_binding_hash,
            "activation_id":null, "world_generation":"0", "operation_id":null,
            "grant_id":null, "owner_generation":"1", "revision":"0", "complete":true,
            "input_watermark":"0", "input_epoch":bootstrap.authority.input_epoch,
            "entries":[], "extensions":{}
        }))?;
        let expected_initial_inventory =
            canonical::content_ref(&expected_inventory_bytes, "application/json")?;
        // A valid complete owner binding with a changed durable ownership inventory
        // tests body-scope mismatch, never historical incarnation staleness.
        let mut foreign_owner = owner_binding;
        foreign_owner.ownership_ref =
            canonical::content_ref(b"prepared-probe-foreign-owner-inventory-v1", "text/plain")?;
        let foreign_owner_hash = foreign_owner.identity()?;
        if foreign_owner_hash == original_owner_hash {
            return Err(ProviderError::Correlation(
                "prepared probe owner hash unchanged",
            ));
        }
        let authorization_bytes = canonical::canonical_json(&json!({
            "schema":"crucible.reference.unsupported-exact-probe-input.v1",
            "meaning":"inert-argument-reference-not-an-installed-input-authorization"
        }))?;
        let authorization = canonical::content_ref(&authorization_bytes, "application/json")?;
        let observe = json!({
            "binding_hash":original_owner_hash,
            "owner_generation":"1", "after_observation_sequence":"0",
            "maximum_items":"16", "extensions":{}
        });
        let capture = json!({
            "kind":"capture", "binding_hash":original_owner_hash,
            "owner_generation":"1", "activation_id":bootstrap.activation_id,
            "world_generation":bootstrap.world_generation,
            "arguments":{
                "capture_id":"prepared-probe/capture", "participant_ids":installed.profile.owner.participant_ids,
                "cut_id":"prepared-probe/initial-cut", "cut":{"time_ps":"0","microstep":"0","phase":0},
                "event_ordinal":"0", "ordering_profile":"superdense-v1",
                "preservation_contract":"prepared-probe/unsupported-complete-state"
            }, "extensions":{}
        });
        let exact = json!({
            "kind":"exact_run", "binding_hash":original_owner_hash,
            "owner_generation":"1", "activation_id":bootstrap.activation_id,
            "world_generation":bootstrap.world_generation,
            "arguments":{
                "grant_id":"prepared-probe/exact-grant", "participant_ids":installed.profile.owner.participant_ids,
                "realization_id":bootstrap.authority.realization_id,
                "activation_id":bootstrap.activation_id, "world_generation":bootstrap.world_generation,
                "owner_generation":"1", "input_epoch":"prepared-probe/unsupported-input-epoch",
                "mode":"exact", "ordering_profile":"superdense-v1",
                "start":{"time_ps":"0","microstep":"0","phase":3},
                "limit":{"time_ps":"1","microstep":"0","phase":0},
                "boundary_policy":"ordinary_stop", "input_authorization":authorization, "input_watermark":"0"
            }, "extensions":{}
        });
        let mut wrong_binding = observe.clone();
        wrong_binding["binding_hash"] = serde_json::to_value(foreign_owner_hash)
            .map_err(crucible_node_contract::ContractError::from)?;
        let mut wrong_generation = observe.clone();
        wrong_generation["owner_generation"] = json!("2");
        let mut cases = Vec::new();
        cases
            .try_reserve_exact(6)
            .map_err(|_| ProviderError::ResourceExhausted("prepared probe case allocation"))?;
        for (name, method, operation, body) in [
            ("observe-before", Method::Observe, None, observe.clone()),
            (
                "unsupported-capture",
                Method::Begin,
                Some("capture"),
                capture,
            ),
            ("unsupported-exact", Method::Begin, Some("exact"), exact),
            (
                "owner-binding-mismatch",
                Method::Observe,
                None,
                wrong_binding,
            ),
            (
                "unadmitted-future-generation",
                Method::Observe,
                None,
                wrong_generation,
            ),
            ("observe-after", Method::Observe, None, observe),
        ] {
            let body = object(body)?;
            decode_request(method, &body)?;
            cases.push(OriginalPreparedProbeCase {
                case: Id::new(format!("reference/pre-activate/{name}"))?,
                request_id: Id::new(format!("prepared-probe/{}/{name}", bootstrap.node_id))?,
                operation_id: operation
                    .map(|kind| Id::new(format!("prepared-probe/{}/{kind}", bootstrap.node_id)))
                    .transpose()?,
                method,
                body,
            });
        }
        let source = include_str!("source_pre_activation_probe.rs")
            .as_bytes()
            .to_vec();
        let source_ref = canonical::content_ref(&source, "text/plain")?;
        let bytes = canonical::canonical_json(&json!({
            "schema":"crucible.reference.pre-activation-probe-plan.v1",
            "implementation":installed.package.identity(), "node":bootstrap.node_id,
            "configuration":installed.profile.configuration_ref,
            "resource_limits":bootstrap.resource_limits,
            "selected_features":super::unit::required_features()?, "source":source_ref,
            "stage":"original-realize-and-admit-before-activate",
            "controller_budget_ns":"3000000000", "snapshot_maximum_bytes":"1048576",
            "preparation_seed":{
                "request_recipe":"prepare-realize-{original-realization-id}",
                "origin":"controller", "closure":["closed_gate_receipt","ControlReceipt","ClosedGateRecord","physical_status_ref"],
                "maximum_objects":"4", "maximum_bytes":"1048576",
                "meaning":"original-static-gate-not-fresh-checksum-or-cursor"
            },
            "cases":[
                {"case":"observe-before","method":"observe","change":"none","expected":"completed-empty-page"},
                {"case":"unsupported-capture","method":"begin","change":"unsupported-capture-kind","expected":"UNSUPPORTED_FEATURE"},
                {"case":"unsupported-exact","method":"begin","change":"unsupported-exact-kind","expected":"UNSUPPORTED_FEATURE","input_argument":authorization},
                {"case":"owner-binding-mismatch","method":"observe","change":"different-complete-owner-ownership-ref","expected":"BINDING_MISMATCH"},
                {"case":"unadmitted-future-generation","method":"observe","change":{"actual":"1","supplied":"2"},"expected":"BINDING_MISMATCH"},
                {"case":"observe-after","method":"observe","change":"none","expected":"identical-completed-empty-page"}
            ],
            "pending_oracle_recipe":{"revision":"0","inactive_world_generation":"0","activation":null,"operation":null,"grant":null,"input_watermark":"0","entries":[],"complete":true,"native_original_scope":"owner/world/input-epoch-from-original-bootstrap"},
            "refusal_oracle":{"effect":"not_started","operation_state":"not_started","retryable":false},
            "mandatory_independent_premises":["original-closed-gate-content-closure","same-original-provider-and-companion-kernel-census","later-first-native-quantum-zero-original-receipt","later-zero-input-independent-checksum"],
            "limitations":["no-historical-stale-incarnation-test","no-general-no-effects-proof","no-capture-or-exact-authority","partial-obligation-coverage"]
        }))?;
        if source.len() > MAXIMUM_FIXTURE_BYTES || bytes.len() > MAXIMUM_FIXTURE_BYTES {
            return Err(ProviderError::ResourceExhausted(
                "prepared probe fixture bytes",
            ));
        }
        let reference = canonical::content_ref(&bytes, "application/json")?;
        let fixture_objects = BTreeMap::from([
            (reference.clone(), bytes.clone()),
            (source_ref, source),
            (authorization, authorization_bytes),
        ]);
        let mut objects = fixture_objects.clone();
        objects.insert(expected_initial_inventory.clone(), expected_inventory_bytes);
        Ok(Self {
            objects,
            fixture_objects,
            reference,
            bytes,
            cases,
            session: bootstrap.authority.session_id.clone(),
            incarnation: bootstrap.authority.incarnation_id.clone(),
            node: bootstrap.node_id.clone(),
            owner: bootstrap.owner_id.clone(),
            binding: binding.identity()?,
            expected_initial_inventory,
            provider: installed
                .package
                .artifact_content("provider")
                .map_err(|error| ProviderError::Io(std::io::Error::other(error.to_string())))?
                .clone(),
        })
    }

    /// Borrows the declared reusable fixture/source/hostile argument closure.
    ///
    /// Fresh expected pending-inventory oracle bytes remain in `objects` as
    /// attempt-specific evidence and cannot silently enter this semantic axis.
    pub(super) fn fixture_objects(&self) -> &BTreeMap<ContentRef, Vec<u8>> {
        &self.fixture_objects
    }

    /// Borrows original owned requests for the restricted prepared guard seam.
    pub(super) fn cases(&self) -> &[OriginalPreparedProbeCase] {
        &self.cases
    }

    /// Checks exact original envelopes and source-defined result facts.
    ///
    /// # Errors
    /// Refuses incomplete recordings, foreign original scope, changed requests,
    /// unknown responses, different errors or a changed/nonempty pending page.
    /// Native process and gate premises remain independently mandatory.
    pub(super) fn verify(
        &self,
        observed: &RecordedReferenceObservation,
    ) -> Result<SourcePreActivationProbeObservation, ProviderError> {
        let scope = &observed.evidence.scope;
        if !observed.recording_complete
            || observed.observed_unknown
            || observed.recording_failure.0.is_some()
            || scope.session_id != self.session
            || scope.incarnation_id != self.incarnation
            || scope.binding_hash != self.binding
            || scope.provider_executable != self.provider
            || scope.selected_features != super::unit::required_features()?
        {
            return Err(ProviderError::Correlation(
                "prepared probe originals incomplete or foreign",
            ));
        }
        let mut cases = Vec::new();
        cases.try_reserve_exact(self.cases.len()).map_err(|_| {
            ProviderError::ResourceExhausted("prepared probe observation allocation")
        })?;
        let mut before = None;
        let mut previous_request_sequence = U64::new(0);
        for (index, case) in self.cases.iter().enumerate() {
            let mut matches = observed.evidence.requests.iter().filter(|original| {
                original.key.origin == RequestOrigin::Controller
                    && original.key.request_id == case.request_id
            });
            let original = matches
                .next()
                .ok_or(ProviderError::Correlation("prepared probe original absent"))?;
            if matches.next().is_some() {
                return Err(ProviderError::Correlation(
                    "prepared probe original duplicated",
                ));
            }
            original
                .request
                .reference
                .verify(original.request.bytes.as_slice())?;
            let request =
                Envelope::decode(original.request.bytes.as_slice(), MAXIMUM_CONTROL_BYTES)?;
            if request.sequence <= previous_request_sequence
                || request.method != case.method
                || request.body != case.body
                || request.session_id.0.as_ref() != Some(&self.session)
                || request.incarnation_id.0.as_ref() != Some(&self.incarnation)
                || request.request_id.0.as_ref() != Some(&case.request_id)
                || request.operation_id.0 != case.operation_id
                || request.node_id.0.as_ref() != Some(&self.node)
                || request.execution_owner_id.0.as_ref() != Some(&self.owner)
                || request.capture_owner_id.0.is_some()
                || !request.extensions.is_empty()
            {
                return Err(ProviderError::Correlation(
                    "prepared probe original request changed",
                ));
            }
            previous_request_sequence = request.sequence;
            let response = original
                .response
                .0
                .as_ref()
                .ok_or(ProviderError::Correlation("prepared probe reply unknown"))?;
            response.reference.verify(response.bytes.as_slice())?;
            let envelope = Envelope::decode(response.bytes.as_slice(), MAXIMUM_CONTROL_BYTES)?;
            request.matches_response(&envelope)?;
            let body = decode_response(&decode_request(case.method, &case.body)?, &envelope.body)?;
            let source_result = if index == 0 || index == 5 {
                if !matches!(body.shape, ResponseShape::Completed { .. }) {
                    return Err(ProviderError::Correlation(
                        "prepared observation did not complete",
                    ));
                }
                let Some(MethodResult::Observe(page)) = body.result else {
                    return Err(ProviderError::Correlation(
                        "prepared observation result missing",
                    ));
                };
                if !page.complete
                    || !page.observations.is_empty()
                    || page.inventory_hash != self.expected_initial_inventory.hash
                {
                    return Err(ProviderError::Correlation(
                        "prepared observation not complete and empty",
                    ));
                }
                let page_bytes = canonical::canonical_json(
                    &serde_json::to_value(&page)
                        .map_err(crucible_node_contract::ContractError::from)?,
                )?;
                if index == 0 {
                    before = Some(page_bytes);
                } else if before.as_ref() != Some(&page_bytes) {
                    return Err(ProviderError::Correlation(
                        "prepared pending inventory changed",
                    ));
                }
                "completed-empty-page"
            } else {
                let expected = if index < 3 {
                    "UNSUPPORTED_FEATURE"
                } else {
                    "BINDING_MISMATCH"
                };
                let ResponseShape::Error {
                    operation_state,
                    error,
                    extensions,
                } = body.shape
                else {
                    return Err(ProviderError::Correlation(
                        "prepared hostile request unexpectedly succeeded",
                    ));
                };
                if operation_state != OperationState::NotStarted
                    || error.code != expected
                    || error.effect != EffectCertainty::NotStarted
                    || error.retryable
                    || !extensions.is_empty()
                    || body.result.is_some()
                {
                    return Err(ProviderError::Correlation(
                        "prepared probe source refusal differs",
                    ));
                }
                expected
            };
            cases.push(OriginalPreparedProbeObservation {
                case: case.case.clone(),
                request: original.request.reference.clone(),
                response: response.reference.clone(),
                source_result,
            });
        }
        Ok(SourcePreActivationProbeObservation {
            fixture: self.reference.clone(),
            cases,
            unchanged_pending_page: true,
            expected_initial_inventory: self.expected_initial_inventory.clone(),
        })
    }
}

fn object(value: Value) -> Result<Map<String, Value>, ProviderError> {
    value.as_object().cloned().ok_or(ProviderError::Frame(
        "prepared probe request is not an object",
    ))
}
