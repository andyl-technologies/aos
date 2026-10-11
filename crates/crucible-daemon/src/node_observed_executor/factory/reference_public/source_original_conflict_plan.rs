//! Predeclares changed material under three already completed original IDs.
//!
//! The source recipe changes one named typed body field. It preserves all
//! original envelope identities and does not alter admitted budgets or native
//! work. Fresh original IDs remain attempt data outside the reusable fixture.

use std::collections::BTreeMap;

use crucible::node_adapters::cnp::{CnpCompletedLifecyclePhase, CnpCompletedLifecycleScope};
use crucible_node_contract::{ContentRef, Id, U64, canonical};
use crucible_node_provider::{
    ProviderError,
    bodies::{BeginArguments, RequestBody, decode_request},
};
use serde_json::{Map, Value};

use super::{
    installation::SourcePublicReferenceInstallation,
    source_lifecycle_resend_plan::SourceLifecycleResendPlan,
};

pub(super) const MAXIMUM_CONFLICTS: usize = 3;
pub(super) const MAXIMUM_ARCHIVE_BYTES: usize = 4 * 1024 * 1024;

pub(super) struct SourceOriginalConflictPlan {
    pub(super) reference: ContentRef,
    pub(super) bytes: Vec<u8>,
    pub(super) objects: BTreeMap<ContentRef, Vec<u8>>,
    targets: Vec<(Id, CnpCompletedLifecyclePhase, bool)>,
}

impl SourceOriginalConflictPlan {
    /// Materializes exact source recipes and original targets before Child.
    ///
    /// # Errors
    /// Refuses an incomplete original lifecycle population or encoding failure.
    pub(super) fn build(
        installed: &SourcePublicReferenceInstallation,
        lifecycle: &SourceLifecycleResendPlan,
    ) -> Result<Self, ProviderError> {
        let bytes = canonical::canonical_json(&serde_json::json!({
            "schema":"crucible.reference.source-original-conflict-plan.v1",
            "source_package":installed.package.identity(),
            "targets":[
                {"phase":"prepared","field":"world_generation","change":"checked-original-plus-one"},
                {"phase":"input-accepted","quantum":"1","field":"batch_sequence-and-complete-batch-hash","change":"checked-original-plus-one-and-original-owner-batch-identity"},
                {"phase":"window-completed","quantum":"1","field":"arguments.wall_budget_ns","change":"checked-original-plus-one"}
            ],
            "maximum_probes":MAXIMUM_CONFLICTS,
            "maximum_body_bytes":262144,
            "archive":{"maximum_transmissions":MAXIMUM_CONFLICTS,"maximum_bytes":MAXIMUM_ARCHIVE_BYTES,"before_original_controls":true},
            "original_source":"completed-original-full-typed-closure-and-current-kernel-enrollment",
            "transport":"same-original-envelope-id-and-scope-changed-body-fresh-connection-sequence",
            "expected_refusal":{"code":"CONFLICT","operation_state":"not_started","effect":"not_started"},
            "native_oracle":"unchanged-original-receipts-and-next-native-window-checksum-input-prefix",
            "uncertainty":"sticky-original-custody-before-policy-and-send-no-cache-promotion",
            "exclusions":["reconnect","phase-loss-population","cancellation-race","whole-clause-credit","ordinary-ready"]
        }))?;
        let reference = canonical::content_ref(&bytes, "application/json")?;
        let mut targets = Vec::new();
        targets.try_reserve_exact(14).map_err(|_| {
            ProviderError::ResourceExhausted("original conflict target reservation")
        })?;
        for target in &lifecycle.targets {
            let selected = target.phase == CnpCompletedLifecyclePhase::Prepared
                || matches!(
                    target.phase,
                    CnpCompletedLifecyclePhase::InputAccepted
                        | CnpCompletedLifecyclePhase::WindowCompleted
                ) && target
                    .window
                    .as_ref()
                    .is_some_and(|window| window.grant.quantum == U64::new(1));
            targets.push((target.request.clone(), target.phase, selected));
        }
        if targets.len() != 14
            || targets.iter().filter(|(_, _, selected)| *selected).count() != MAXIMUM_CONFLICTS
        {
            return Err(ProviderError::Correlation(
                "original conflict target population differs",
            ));
        }
        Ok(Self {
            objects: BTreeMap::from([(reference.clone(), bytes.clone())]),
            reference,
            bytes,
            targets,
        })
    }

    pub(super) fn target_population(&self) -> Value {
        Value::Array(
            self.targets
                .iter()
                .map(|(request, phase, selected)| {
                    let phase = match phase {
                        CnpCompletedLifecyclePhase::Prepared => "prepared",
                        CnpCompletedLifecyclePhase::WorldActivated => "world-activated",
                        CnpCompletedLifecyclePhase::InputAccepted => "input-accepted",
                        CnpCompletedLifecyclePhase::WindowCompleted => "window-completed",
                        CnpCompletedLifecyclePhase::PublicationClosed => "publication-closed",
                        CnpCompletedLifecyclePhase::PublicationConsumed => "publication-consumed",
                    };
                    serde_json::json!({"request":request,"phase":phase,"selected":selected})
                })
                .collect(),
        )
    }

    pub(super) fn selects(
        &self,
        scope: &CnpCompletedLifecycleScope,
    ) -> Result<bool, ProviderError> {
        let (_, phase, selected) = self
            .targets
            .iter()
            .find(|(id, _, _)| id == &scope.request_id)
            .ok_or(ProviderError::Correlation(
                "unplanned original conflict hook",
            ))?;
        if *phase != scope.phase {
            return Err(ProviderError::Correlation(
                "original conflict phase differs",
            ));
        }
        Ok(*selected)
    }

    /// Applies the one source-declared typed mutation to an authenticated body.
    ///
    /// # Errors
    /// Refuses a different original kind, integer overflow or invalid resulting
    /// body. This only creates hostile data, never a replacement original.
    pub(super) fn changed_body(
        &self,
        original: &RequestBody,
        owner: &Id,
    ) -> Result<Map<String, Value>, ProviderError> {
        let value = match original {
            RequestBody::Activate(request) => {
                let mut changed = request.clone();
                changed.world_generation = changed.world_generation.checked_add(U64::new(1))?;
                serde_json::to_value(changed)
            }
            RequestBody::Input(request) => {
                let mut changed = request.clone();
                changed.batch_sequence = changed.batch_sequence.checked_add(U64::new(1))?;
                let mut batch = request.verified_batch(owner)?;
                batch.batch_sequence = changed.batch_sequence;
                changed.batch_hash = batch.identity()?;
                changed.verified_batch(owner)?;
                serde_json::to_value(changed)
            }
            RequestBody::Begin(request) => {
                let BeginArguments::QuantumBegin(mut arguments) = request.decoded_arguments()?
                else {
                    return Err(ProviderError::Correlation(
                        "conflict original is not a quantum",
                    ));
                };
                arguments.wall_budget_ns = arguments.wall_budget_ns.checked_add(U64::new(1))?;
                let mut changed = request.clone();
                changed.arguments = object(
                    serde_json::to_value(arguments)
                        .map_err(crucible_node_contract::ContractError::from)?,
                )?;
                serde_json::to_value(changed)
            }
            _ => {
                return Err(ProviderError::Correlation(
                    "unplanned original conflict body",
                ));
            }
        }
        .map_err(crucible_node_contract::ContractError::from)?;
        let body = object(value)?;
        let method = match original {
            RequestBody::Activate(_) => crucible_node_provider::envelope::Method::Activate,
            RequestBody::Input(_) => crucible_node_provider::envelope::Method::Input,
            RequestBody::Begin(_) => crucible_node_provider::envelope::Method::Begin,
            _ => return Err(ProviderError::Correlation("unplanned conflict method")),
        };
        decode_request(method, &body)?;
        Ok(body)
    }
}

fn object(value: Value) -> Result<Map<String, Value>, ProviderError> {
    value
        .as_object()
        .cloned()
        .ok_or(ProviderError::Frame("typed conflict body is not an object"))
}
