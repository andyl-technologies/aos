//! Source-sealed conditional replay definitions, independent of live authority.
//!
//! This builder permits only an explicit implementation/facet substitution.
//! Original model, port, timing, connection and request semantics remain bound to
//! the accepted source. The ordinary profile omits preservation; a separately
//! selected complete replay-model contract preserves its actual cursor and
//! custody. Neither contract restores or upgrades the physical source.

use crucible::node_adapters::transcript::{
    TRANSCRIPT_REPLAY_PRESERVATION_PROFILE, TRANSCRIPT_REPLAY_PROFILE, context_commitment,
    transcript_replay_continuation_schema,
};
use crucible_node_contract::{
    ArtifactIdentity, CapabilityProfile, CaptureScope, Continuation, Extensions, FacetSelection,
    GuaranteeProfile, LiveAuthority, NodeBinding, NodeBindingRef,
};

use super::*;

#[derive(Clone)]
pub(super) struct ReplayProfile {
    pub(super) scenario: NodeScenario,
    pub(super) bindings: Vec<NodeBinding>,
    pub(super) record: ActivationRecord,
    pub(super) enrolled: BTreeMap<Id, InputPayload>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ReplayContract {
    #[cfg(test)]
    OriginalExecution,
    CompleteReplayModel,
}

pub(super) fn build(
    catalog: &InstalledNodeCatalog,
    source: &source_enrollment::VerifiedRecordedWorld,
    execution: ExecutionId,
    contract: ReplayContract,
) -> Result<ReplayProfile, NodeObservedError> {
    let mut scenario = source.scenario.clone();
    let mut content = scenario
        .content
        .iter()
        .map(|object| (object.reference.clone(), object.bytes.clone()))
        .collect::<BTreeMap<_, _>>();
    if contract == ReplayContract::CompleteReplayModel {
        for transcript in source.sources.values() {
            content.insert(transcript.reference().clone(), transcript.bytes().to_vec());
            let origin_bytes =
                canonical::canonical_json(&serde_json::to_value(&transcript.transcript().origin)?)?;
            let origin_ref = context_commitment(&transcript.transcript().origin).map_err(native)?;
            origin_ref.verify(&origin_bytes)?;
            content.insert(origin_ref, origin_bytes);
            for object in &transcript.transcript().origin.context {
                if content
                    .get(&object.reference)
                    .is_some_and(|bytes| bytes != &object.bytes)
                {
                    return Err(refused("original typed context has conflicting body"));
                }
                content.insert(object.reference.clone(), object.bytes.clone());
            }
        }
    }
    let mut bindings = Vec::new();
    let mut enrolled = BTreeMap::new();
    let session = Id::new(format!("session/replay/{}", execution_text(execution)))?;
    let activation_id = Id::new(format!("activation/replay/{}", execution_text(execution)))?;
    let mut owners = Vec::new();
    for selected in &mut scenario.compatibility {
        let original = source
            .source_bindings
            .get(&selected.node_id)
            .ok_or_else(|| refused("accepted source binding disappeared"))?;
        let transcript = source
            .sources
            .get(&selected.node_id)
            .ok_or_else(|| refused("accepted source transcript disappeared"))?;
        let scope = put_json(
            &mut content,
            &serde_json::json!({
                "schema":"crucible.installed-reference-conditional-replay.v1",
                "source_transcript":transcript.reference(),
                "source_binding":transcript.transcript().origin.source_binding,
                "source_context":context_commitment(&transcript.transcript().origin).map_err(native)?,
                "original_world":source.scenario.world.identity()?,
                "host":catalog.host_identity,
                "policy":"exact original requests, inputs and time assignments only; origin uncertainty and nondeterminism remain; no physical fallback or counterfactual execution",
            }),
        )?;
        let mut guarantees: GuaranteeProfile = read_json(&content, &selected.guarantees_ref)?;
        guarantees.conditional_replay = true;
        if contract == ReplayContract::CompleteReplayModel {
            guarantees.capture_scope = CaptureScope::CompleteModel;
            guarantees.continuation = Continuation::Exact;
            guarantees.durable_restart = true;
        }
        guarantees.limitations_ref = scope.clone();
        let guarantee_ref = put_json(&mut content, &guarantees)?;
        let facet = FacetSelection {
            id: Id::new(TRANSCRIPT_REPLAY_PROFILE)?,
            version: 1,
            configuration_ref: scope.clone(),
            guarantees_ref: guarantee_ref.clone(),
            extensions: Extensions::new(),
        };
        let mut capabilities: CapabilityProfile = read_json(&content, &selected.capabilities_ref)?;
        let mut facets = vec![facet.clone()];
        if contract == ReplayContract::CompleteReplayModel {
            let schema = transcript_replay_continuation_schema().map_err(native)?;
            content.insert(
                schema.definition.clone(),
                crucible::node_adapters::transcript::transcript_replay_continuation_definition()
                    .to_vec(),
            );
            selected.implementation.formats.push(schema);
            facets.push(FacetSelection {
                id: Id::new(TRANSCRIPT_REPLAY_PRESERVATION_PROFILE)?,
                version: 1,
                configuration_ref: scope.clone(),
                guarantees_ref: guarantee_ref.clone(),
                extensions: Extensions::new(),
            });
        }
        facets.sort_by(|a, b| a.id.cmp(&b.id));
        selected
            .implementation
            .formats
            .sort_by(|a, b| (&a.id, a.version).cmp(&(&b.id, b.version)));
        capabilities.facets = facets.clone();
        capabilities.requirements_ref = scope.clone();
        selected.capabilities_ref = put_json(&mut content, &capabilities)?;
        selected.guarantees_ref = guarantee_ref;
        selected.profile_ref = scope.clone();
        selected.operating_contract.facets = facets;
        selected.qualification_refs = vec![scope.clone()];
        selected.implementation.implementation_id =
            Id::new("crucible/transcript-reference-linked-v1")?;
        selected.implementation.artifacts = vec![ArtifactIdentity {
            id: Id::new("replay-host")?,
            role: Id::new("replay-host")?,
            content: catalog.host_identity.clone(),
            extensions: Extensions::new(),
        }];
        selected
            .implementation
            .model_definitions
            .push(scope.clone());
        selected.implementation.model_definitions.sort_by(|a, b| {
            (&a.hash.domain, &a.hash.digest).cmp(&(&b.hash.domain, &b.hash.digest))
        });
        selected.implementation.model_definitions.dedup();

        let incarnation = Id::new(format!(
            "incarnation/replay/{}/{}",
            execution_text(execution),
            selected.node_id
        ))?;
        let generation = original
            .authority
            .owner_generation
            .checked_add(U64::new(1))?;
        let owner = OwnerIdentity {
            owner: selected.execution_owner.id.clone(),
            incarnation: incarnation.clone(),
            generation,
        };
        let bytes = canonical::canonical_json(&serde_json::json!({
            "schema":"crucible.installed-replay-cursor-enrollment.v1",
            "source":transcript.reference(),"profile":scope,
            "owner":owner,"cursor":"0","execution":execution_text(execution),
            "host":catalog.host_identity,
        }))?;
        let receipt = canonical::content_ref(&bytes, "application/json")?;
        // Fresh enrollment authenticates operational custody. It remains in
        // the owning allocation, outside execution-independent scenario bytes.
        enrolled.insert(
            selected.node_id.clone(),
            InputPayload {
                reference: receipt.clone(),
                bytes,
            },
        );
        bindings.push(NodeBinding {
            compatibility: selected.clone(),
            authority: LiveAuthority {
                schema_version: 1,
                session_id: session.clone(),
                incarnation_id: incarnation,
                realization_id: Id::new(format!(
                    "realization/replay/{}/{}",
                    execution_text(execution),
                    selected.node_id
                ))?,
                activation_id: None,
                world_generation: U64::new(0),
                owner_generation: generation,
                input_epoch: Id::new(format!(
                    "input/replay/{}/{}",
                    execution_text(execution),
                    selected.node_id
                ))?,
                host_receipt: receipt,
                extensions: Extensions::new(),
            },
            extensions: Extensions::new(),
        });
        owners.push(owner);
    }
    if contract == ReplayContract::CompleteReplayModel {
        let mut ownership: crucible::node_admission::OwnershipPolicy =
            read_json(&content, &scenario.world.ownership_ref)?;
        for owner in &mut ownership.capture_owners {
            owner.complete_model = true;
            owner.unchanged_cut = true;
            owner.exact_continuation = true;
            owner.durable_restart = true;
            owner.isolated_fork = false;
            owner.cut_procedure_ref = bindings
                .iter()
                .find(|binding| binding.compatibility.capture_owner.id == owner.owner_id)
                .ok_or_else(|| refused("replay capture owner has no allocated cursor"))?
                .compatibility
                .profile_ref
                .clone();
        }
        scenario.world.ownership_ref = put_json(&mut content, &ownership)?;
    }
    let binding_refs = bindings
        .iter()
        .map(|binding| {
            Ok(NodeBindingRef {
                node_id: binding.compatibility.node_id.clone(),
                binding_hash: binding.compatibility.identity()?,
                extensions: Extensions::new(),
            })
        })
        .collect::<Result<Vec<_>, NodeObservedError>>()?;
    scenario.world.node_bindings = binding_refs.clone();
    for owner in &mut scenario.owners {
        owner.node_bindings = binding_refs
            .iter()
            .filter(|binding| owner.owner.participant_ids.contains(&binding.node_id))
            .cloned()
            .collect();
    }
    scenario.world.scenario_ref = put_json(
        &mut content,
        &serde_json::json!({
            "schema":"crucible.installed-recorded-world-substitution.v1",
            "source_scenario":source.scenario.world.scenario_ref,
            "source_world":source.scenario.world.identity()?,
            "source_configuration":source.configuration,
            "substitution":"both native implementations replaced by original-boundary conditional replay; original logical models, ports, clock, connections and request IDs unchanged",
            "selected_bindings":binding_refs,
        }),
    )?;
    scenario.content = content
        .into_iter()
        .map(|(reference, bytes)| crate::node_scenario::ScenarioContent { reference, bytes })
        .collect();
    scenario.content.sort_by(|a, b| {
        (&a.reference.hash.domain, &a.reference.hash.digest)
            .cmp(&(&b.reference.hash.domain, &b.reference.hash.digest))
    });
    owners.sort();
    let boundary = source
        .sources
        .values()
        .next()
        .ok_or_else(|| refused("accepted original world disappeared"))?
        .transcript()
        .origin
        .activation
        .boundary;
    let record = ActivationRecord {
        generation: U64::new(1),
        activation_id,
        world_binding_hash: scenario.world.identity()?,
        owners,
        boundary,
    };
    Ok(ReplayProfile {
        scenario,
        bindings,
        record,
        enrolled,
    })
}

fn put_json(
    content: &mut BTreeMap<ContentRef, Vec<u8>>,
    value: &impl Serialize,
) -> Result<ContentRef, NodeObservedError> {
    let bytes = canonical::canonical_json(&serde_json::to_value(value)?)?;
    let reference = canonical::content_ref(&bytes, "application/json")?;
    if content
        .get(&reference)
        .is_some_and(|original| original != &bytes)
    {
        return Err(refused(
            "conditional replay definition changed original object bytes",
        ));
    }
    content.insert(reference.clone(), bytes);
    Ok(reference)
}

fn read_json<T: serde::de::DeserializeOwned>(
    content: &BTreeMap<ContentRef, Vec<u8>>,
    reference: &ContentRef,
) -> Result<T, NodeObservedError> {
    let bytes = content
        .get(reference)
        .ok_or_else(|| refused("accepted source profile object is missing"))?;
    reference.verify(bytes)?;
    Ok(serde_json::from_slice(bytes)?)
}
