//! Checks original Script-to-Block cases against an independent byte array.
//!
//! Installed source bytes define the requests and initial disk. Actual runtime
//! tokens supply producer lineage, staging, consumption, native completion and
//! consumed publication ACK. No observed response computes the expected answer,
//! and this lawful-case collector does not establish a whole RFC requirement.

use std::io::{self, Write};

use crucible_device::block::{BlockOp, BlockRequest, BlockResponse, BlockSnapshot};
use crucible_engine::node_adapters::{HOST_EXACT_PROFILE, ScriptedRequestKind, ScriptedSource};
use crucible_engine::node_contract::{
    ActivationRecord, ExactBoundaryPolicy, OperationOutcome, OperationRequest, OperationToken,
    OriginalInputLineageLimits, OriginalRuntimeWitness, ProgressEvidence, SavedRuntimeActivation,
    StopReason, WorldActivation,
};
use crucible_engine::node_scheduling::event::Delivery;
use crucible_engine::node_scheduling::{InputIdentity, InputPayload};
use crucible_node_format::{ContentRef, HashRef, Id, Position, U64, canonical};
use serde::{Deserialize, Serialize};

use crate::node_qualification::{CaseVerdict, QualificationError};

use super::scope::Gem5CaseScope;

#[cfg(test)]
#[path = "storage_oracle_tests.rs"]
mod tests;

const MAXIMUM_ORIGINAL_GRANTS: usize = 512;
const MAXIMUM_CASE_BYTES: usize = 64 * 1024 * 1024;
const MAXIMUM_NATIVE_BYTES: usize = 4 * 1024 * 1024;
const MAXIMUM_LINEAGE_BYTES: usize = 8 * 1024 * 1024;
const MAXIMUM_SUMMARY_BYTES: usize = 256 * 1024;
const MAXIMUM_PREPARATION_BYTES: usize = 16 * 1024 * 1024;
const SCRIPT_PREFIX: &[u8] = b"crucible.scripted-requests.v1\0";
const DEVICE_PREFIX: &[u8] = b"crucible.device-scheduling-subnode.v1\0";

/// Selects one source-built request and its independently calculated result.
pub(super) struct BlockCaseExpectation {
    index: usize,
    allow_progress: bool,
    script: (ContentRef, Vec<u8>),
    base: (ContentRef, Vec<u8>),
    request: Vec<u8>,
    response: Vec<u8>,
    disk: Vec<u8>,
}

impl BlockCaseExpectation {
    /// Selects the original finite write and its complete resulting disk bytes.
    ///
    /// # Errors
    /// Refuses different installed script/base geometry or malformed source bytes.
    pub(super) fn write_completed(scope: &Gem5CaseScope) -> Result<Self, QualificationError> {
        Self::from_source(scope, 0, false)
    }

    /// Selects the original readback after applying the source-declared write.
    ///
    /// # Errors
    /// Refuses a different installed script/base or unsupported request sequence.
    pub(super) fn read_completed(scope: &Gem5CaseScope) -> Result<Self, QualificationError> {
        Self::from_source(scope, 1, false)
    }

    /// Selects the fixed write before dispatch, allowing a lawful empty horizon.
    ///
    /// # Errors
    /// Refuses unsupported installed source requests or disk geometry.
    pub(super) fn write_progress(scope: &Gem5CaseScope) -> Result<Self, QualificationError> {
        let mut expectation = Self::write_completed(scope)?;
        expectation.allow_progress = true;
        Ok(expectation)
    }

    /// Selects readback after the fixture has observed the original write result.
    ///
    /// # Errors
    /// Refuses unsupported installed source requests or disk geometry.
    pub(super) fn read_progress(scope: &Gem5CaseScope) -> Result<Self, QualificationError> {
        let mut expectation = Self::read_completed(scope)?;
        expectation.allow_progress = true;
        Ok(expectation)
    }

    fn from_source(
        scope: &Gem5CaseScope,
        index: usize,
        allow_progress: bool,
    ) -> Result<Self, QualificationError> {
        let (script_ref, script_bytes, base_ref, base_bytes) = scope.original_storage_sources()?;
        if script_bytes.len() > 1024 || base_bytes.len() != 4096 {
            return Err(refusal(
                "installed Script/Block exceeds the selected source geometry",
            ));
        }
        script_ref.verify(script_bytes)?;
        base_ref.verify(base_bytes)?;
        let (requests, responses, disk) = independent_model(script_bytes, base_bytes)?;

        Ok(Self {
            index,
            allow_progress,
            script: (script_ref.clone(), script_bytes.to_vec()),
            base: (base_ref.clone(), base_bytes.to_vec()),
            request: requests[index].clone(),
            response: responses[index].clone(),
            disk,
        })
    }

    fn kind(&self) -> &'static str {
        match (self.index, self.allow_progress) {
            (0, true) => "gem5.mixed.script-block.write-progress.v1",
            (_, true) => "gem5.mixed.script-block.read-progress.v1",
            (0, false) => "gem5.mixed.script-block.write.v1",
            (_, false) => "gem5.mixed.script-block.readback.v1",
        }
    }

    /// Correlates a declared case with its actual public activation and grant.
    ///
    /// # Errors
    /// Refuses a foreign owner geometry or canonical identity encoding failure.
    pub(super) fn case_id(
        &self,
        activation: &ActivationRecord,
        operation: &Id,
    ) -> Result<String, QualificationError> {
        if activation.owners.len() != 4 {
            return Err(refusal(
                "storage case requires the actual four-owner activation",
            ));
        }
        let identity = canonical::json_hash(
            "crucible.gem5.original-storage-case-identity.v1",
            &serde_json::json!({
                "kind": self.kind(), "activation": SavedRuntimeActivation::from(activation),
                "operation": operation, "script": self.script.0, "base": self.base.0,
            }),
        )?;
        Ok(format!("{}:{}", self.kind(), identity.digest))
    }
}

/// Owns immutable observations from an authentic original storage episode.
pub(super) struct OriginalBlockCase {
    id: String,
    verdict: CaseVerdict,
    observed_expected_response: bool,
    world_binding_hash: HashRef,
    result: (ContentRef, Vec<u8>),
    oracle: (ContentRef, Vec<u8>),
    objects: Vec<(ContentRef, Vec<u8>)>,
}

impl OriginalBlockCase {
    /// Joins actual original input consumption to its later FIFO completion.
    ///
    /// Predecessors are opaque tokens retained by the owning fixture before
    /// dispatch. They are never reconstructed from IDs. The terminal token may
    /// itself contain consumption; the selected input is authenticated once.
    ///
    /// # Errors
    /// Refuses missing/foreign originals, missing source lineage, ambiguous
    /// consumption, unacknowledged work, changed source bodies and finite-credit
    /// overflow. Lawful original observations with a wrong independent result
    /// yield a retained Failed case.
    pub(super) fn collect(
        witness: &mut OriginalRuntimeWitness<'_>,
        terminal_token: &OperationToken,
        predecessor_tokens: &[OperationToken],
        expectation: &BlockCaseExpectation,
        scope: &Gem5CaseScope,
    ) -> Result<Self, QualificationError> {
        if predecessor_tokens.len() >= MAXIMUM_ORIGINAL_GRANTS {
            return Err(refusal("storage case original-grant credit exhausted"));
        }
        let terminal = Episode::read(witness, terminal_token, scope)?;
        let expected_source = BlockCaseExpectation::from_source(
            scope,
            expectation.index,
            expectation.allow_progress,
        )?;
        if expected_source.script != expectation.script
            || expected_source.base != expectation.base
            || expected_source.request != expectation.request
            || expected_source.response != expectation.response
            || expected_source.disk != expectation.disk
        {
            return Err(refusal(
                "storage expectation no longer matches the actual installed source",
            ));
        }

        let mut episodes = Vec::new();
        episodes
            .try_reserve_exact(predecessor_tokens.len() + 1)
            .map_err(evidence_error)?;
        let write_expectation = BlockCaseExpectation::from_source(scope, 0, false)?;
        let mut consumptions: [Option<(&OperationToken, ConsumedInput)>; 2] = [None, None];
        for token in predecessor_tokens
            .iter()
            .chain(std::iter::once(terminal_token))
        {
            if episodes
                .iter()
                .any(|episode: &Episode| episode.outcome.operation == *token.operation())
            {
                return Err(refusal("storage case repeats an original operation token"));
            }
            let episode = Episode::read(witness, token, scope)?;
            if !episode.activation.same_authority(&terminal.activation)
                || token.route() != terminal_token.route()
            {
                return Err(refusal(
                    "storage predecessors do not share the original runtime route",
                ));
            }
            for (index, selected) in [(0, &write_expectation), (expectation.index, expectation)] {
                if let Some(input) = original_consumption(witness, token, selected)? {
                    if let Some((_, previous)) = &consumptions[index] {
                        if previous.delivery != input.delivery
                            || previous.stage_ack != input.stage_ack
                        {
                            return Err(refusal(
                                "storage case repeats the request under different original input custody",
                            ));
                        }
                    } else {
                        consumptions[index] = Some((token, input));
                    }
                }
            }
            episodes.push(episode);
        }
        let episode_body = bounded_json(&episodes, MAXIMUM_LINEAGE_BYTES)?;
        let mut input_objects = Vec::new();
        input_objects
            .try_reserve_exact(520)
            .map_err(evidence_error)?;
        let mut stage_refs = Vec::new();
        stage_refs.try_reserve_exact(2).map_err(evidence_error)?;
        for (_, input) in consumptions.iter().flatten() {
            retain_object(&mut input_objects, input.body.clone())?;
        }
        for (token, input) in consumptions.iter().flatten() {
            let lineage = witness
                .original_input_evidence(
                    token,
                    OriginalInputLineageLimits {
                        maximum_objects: 256,
                        maximum_bytes: MAXIMUM_LINEAGE_BYTES,
                        maximum_edges: 4096,
                    },
                )
                .map_err(evidence_error)?
                .ok_or_else(|| refusal("source-authenticated original Stage closure is absent"))?;
            if lineage.root != input.stage_ack {
                return Err(refusal(
                    "original Stage body changed during source readback",
                ));
            }
            let stage_body = bounded_json(&lineage, MAXIMUM_LINEAGE_BYTES)?;
            stage_refs.push(stage_body.0.clone());
            for object in lineage.objects {
                retain_object(&mut input_objects, (object.reference, object.bytes))?;
            }
            retain_object(&mut input_objects, stage_body)?;
        }
        let write_consumed = consumptions[0].is_some();
        if expectation.index == 1 && !write_consumed {
            return Err(refusal(
                "readback phase lacks authentic original write consumption",
            ));
        }

        let scheduling = terminal
            .outcome
            .scheduling
            .as_ref()
            .ok_or_else(|| refusal("terminal storage scheduling is absent"))?;
        let roots = [scheduling.proof_ref.clone()];
        let first = witness
            .operation_evidence(
                terminal_token,
                &roots,
                U64::new(MAXIMUM_NATIVE_BYTES as u64),
            )
            .map_err(evidence_error)?;
        let receipt: HostReceipt = serde_json::from_value(canonical::parse_json(
            body(&first, &scheduling.proof_ref)?,
            MAXIMUM_NATIVE_BYTES,
        )?)
        .map_err(evidence_error)?;
        if receipt.native.length.get() > MAXIMUM_NATIVE_BYTES as u64
            || receipt.pending_causes.length.get() > MAXIMUM_NATIVE_BYTES as u64
        {
            return Err(refusal("storage receipt dependencies exceed finite credit"));
        }
        let dependencies = witness
            .operation_evidence(
                terminal_token,
                &[receipt.native.clone(), receipt.pending_causes.clone()],
                U64::new((2 * MAXIMUM_NATIVE_BYTES) as u64),
            )
            .map_err(evidence_error)?;
        let disk_matches = disk_matches(
            body(&dependencies, &receipt.native)?,
            expectation,
            write_consumed,
        )?;

        // Source calls can fail or expose changed custody. Repeat the original
        // token/session/activation checks after all reads, before recording data.
        for (token, previous) in predecessor_tokens
            .iter()
            .chain(std::iter::once(terminal_token))
            .zip(&episodes)
        {
            let current = Episode::read(witness, token, scope)?;
            if !current.same_original(previous) {
                return Err(refusal("storage original changed during source collection"));
            }
        }
        for (index, original) in consumptions.iter().enumerate() {
            if let Some((token, input)) = original {
                let selected = if index == 0 {
                    &write_expectation
                } else {
                    expectation
                };
                let current = original_consumption(witness, token, selected)?.ok_or_else(|| {
                    refusal("original input disappeared during source collection")
                })?;
                if current.delivery != input.delivery
                    || current.body != input.body
                    || current.stage_ack != input.stage_ack
                {
                    return Err(refusal("original staged producer custody changed"));
                }
            }
        }
        let selected_input = consumptions[expectation.index].as_ref();
        let facts = storage_facts(
            &terminal,
            selected_input.map(|(_, input)| &input.delivery),
            &receipt,
            expectation,
            disk_matches,
        )?;
        let verdict = if facts.passed {
            CaseVerdict::Passed
        } else {
            CaseVerdict::Failed
        };
        let id = expectation.case_id(terminal.activation.record(), terminal_token.operation())?;
        let oracle = expectation.specification()?;
        let preparation = preparation_body(&terminal.activation)?;
        let result = bounded_json(
            &serde_json::json!({
                "schema": "crucible.gem5.original-storage-case.v1", "case": id,
                "verdict": verdict, "world": terminal.world, "request": terminal.request,
                "outcome": terminal.outcome,
                "input_operation": selected_input.map(|(token, _)| token.operation()),
                "original_stage": selected_input.map(|(_, input)| &input.body.0),
                "stage_native_closures": stage_refs, "original_write_consumed": write_consumed,
                "original_episodes": episode_body.0, "public_preparation": preparation.0,
                "oracle": oracle.0, "facts": facts,
                "complete_prior_receipt_bodies": false, "restoration_observed": false,
                "linux_or_device_parity": false, "complete_requirement_coverage": false,
            }),
            MAXIMUM_SUMMARY_BYTES,
        )?;
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(first.len() + dependencies.len() + input_objects.len() + 6)
            .map_err(evidence_error)?;
        for object in first.into_iter().chain(dependencies) {
            retain_object(&mut objects, (object.reference, object.bytes))?;
        }
        for object in input_objects {
            retain_object(&mut objects, object)?;
        }
        for object in [
            episode_body,
            preparation,
            expectation.script.clone(),
            expectation.base.clone(),
            oracle.clone(),
            result.clone(),
        ] {
            retain_object(&mut objects, object)?;
        }
        Ok(Self {
            id,
            verdict,
            observed_expected_response: facts.passed && facts.independent_response,
            world_binding_hash: terminal.world.world_binding_hash,
            result,
            oracle,
            objects,
        })
    }

    /// Borrows the source-correlated original episode identity.
    pub(super) fn id(&self) -> &str {
        &self.id
    }

    /// Returns the independent original comparison's retained disposition.
    pub(super) fn verdict(&self) -> CaseVerdict {
        self.verdict
    }

    /// Borrows the complete canonical observation body and its identity.
    pub(super) fn result(&self) -> (&ContentRef, &[u8]) {
        (&self.result.0, &self.result.1)
    }

    /// Borrows the independently compiled model and installed input identities.
    pub(super) fn oracle(&self) -> (&ContentRef, &[u8]) {
        (&self.oracle.0, &self.oracle.1)
    }

    /// Borrows all bodies collected by this finite case edition.
    pub(super) fn objects(&self) -> &[(ContentRef, Vec<u8>)] {
        &self.objects
    }

    /// Borrows the complete authentic original world binding.
    pub(super) fn world_binding_hash(&self) -> &HashRef {
        &self.world_binding_hash
    }

    /// Reports whether this original episode completed the declared response.
    ///
    /// Lawful empty horizons remain false. The owning fixture requires both
    /// fixed write and readback response facts before completing its run.
    pub(super) fn observed_expected_response(&self) -> bool {
        self.observed_expected_response
    }

    /// Keeps whole normative coverage open despite a lawful successful case.
    pub(super) fn covers(&self, _requirement: &str) -> bool {
        false
    }
}

impl BlockCaseExpectation {
    /// Binds independent model source and the exact installed immutable inputs.
    ///
    /// # Errors
    /// Refuses source/specification storage beyond the bounded summary account.
    pub(super) fn specification(&self) -> Result<(ContentRef, Vec<u8>), QualificationError> {
        bounded_json(
            &serde_json::json!({
                "schema": "crucible.gem5.independent-storage-oracle.v1", "kind": self.kind(),
                "script": self.script.0, "base": self.base.0,
                "implementation": include_str!("storage_oracle.rs"),
                "request": self.request, "response": self.response,
                "resulting_disk": canonical::content_ref(&self.disk, "application/octet-stream")?,
                "selected_latency_ns": {"read":"1", "write":"1", "per_byte":"1"},
                "expected_completion_delay_ps": "513000",
                "model": "bounded byte-array write followed by read; no BlockDevice execution",
                "coverage": "original lawful Write/Read/FIFO/Stage/commit/ACK observation only",
            }),
            MAXIMUM_SUMMARY_BYTES,
        )
    }
}

#[derive(Serialize)]
struct Episode {
    #[serde(skip)]
    activation: WorldActivation,
    world: SavedRuntimeActivation,
    request: OperationRequest,
    outcome: OperationOutcome,
    acknowledged: bool,
}

impl Episode {
    fn read(
        witness: &mut OriginalRuntimeWitness<'_>,
        token: &OperationToken,
        scope: &Gem5CaseScope,
    ) -> Result<Self, QualificationError> {
        let original = witness
            .original_completed_operation(token)
            .map_err(evidence_error)?;
        let admission = original.admission();
        scope.authenticate_activation(admission.activation())?;
        scope.authenticate_world_hash(&admission.activation().record().world_binding_hash)?;
        scope.authenticate_storage_route(token.route())?;
        let scheduling = original
            .outcome()
            .scheduling
            .as_ref()
            .ok_or_else(|| refusal("storage original scheduling is unavailable"))?;
        if !admission.token().same_authority(token)
            || !original.acknowledged()
            || scheduling.publications.len() > 2
            || scheduling.bounds.len() != 1
            || !scheduling.external_inputs.is_empty()
            || scheduling
                .publications
                .iter()
                .any(|value| value.payload_bytes.len() > 532)
            || scheduling
                .input_progress
                .as_ref()
                .is_some_and(|progress| progress.consumed.len() > 2)
            || original.outcome().retained_outputs.len() > 2
        {
            return Err(refusal(
                "storage original exceeds source-selected episode geometry",
            ));
        }
        Ok(Self {
            activation: admission.activation().clone(),
            world: admission.activation().record().into(),
            request: admission.request().clone(),
            outcome: original.outcome().clone(),
            acknowledged: true,
        })
    }

    fn same_original(&self, previous: &Self) -> bool {
        self.activation.same_authority(&previous.activation)
            && self.request == previous.request
            && self.outcome == previous.outcome
            && self.acknowledged == previous.acknowledged
    }
}

struct ConsumedInput {
    delivery: Delivery,
    stage_ack: ContentRef,
    body: (ContentRef, Vec<u8>),
}

fn original_consumption(
    witness: &mut OriginalRuntimeWitness<'_>,
    token: &OperationToken,
    expectation: &BlockCaseExpectation,
) -> Result<Option<ConsumedInput>, QualificationError> {
    let original = witness
        .original_completed_operation(token)
        .map_err(evidence_error)?;
    let Some(staged) = original.staged_inputs().map_err(evidence_error)? else {
        return Ok(None);
    };
    let batch = staged.batch();
    if batch.deliveries().len() > 2
        || batch.payloads().len() > 2
        || batch
            .payloads()
            .iter()
            .any(|object| object.bytes.len() > 540)
    {
        return Err(refusal(
            "original Script/Block batch exceeds source geometry",
        ));
    }
    let progress = original
        .outcome()
        .scheduling
        .as_ref()
        .and_then(|value| value.input_progress.as_ref());
    let Some(progress) = progress else {
        return Ok(None);
    };
    let matching: Vec<_> =
        batch
            .deliveries()
            .iter()
            .filter(|delivery| {
                batch.payloads().iter().any(|body| {
                    body.reference == delivery.payload && body.bytes == expectation.request
                }) && progress.consumed.contains(&InputIdentity {
                    producer: delivery.producer.clone(),
                    source_sequence: delivery.source_sequence,
                })
            })
            .collect();
    let [delivery] = matching.as_slice() else {
        if matching.is_empty() {
            return Ok(None);
        }
        return Err(refusal(
            "original source request occurs more than once in a consumed cut",
        ));
    };
    let provenance = staged
        .provenance()
        .ok_or_else(|| refusal("original producer provenance is absent"))?;
    let lineage = staged
        .lineage()
        .ok_or_else(|| refusal("original producer FIFO lineage is absent"))?;
    let commit = staged
        .coordinator_commit()
        .ok_or_else(|| refusal("original Stage was not committed"))?;
    if !staged.committed()
        || !original.acknowledged()
        || progress.batch != *batch.batch()
        || progress.consumed.len() > batch.deliveries().len()
        || lineage.publications().len() != batch.deliveries().len()
        || provenance.objects().len() > 256
        || provenance.roots().len() > 256
        || lineage
            .publications()
            .iter()
            .any(|claim| claim.objects.len() > 256 || claim.rows.len() > 256)
        || provenance
            .objects()
            .iter()
            .chain(
                lineage
                    .publications()
                    .iter()
                    .flat_map(|claim| &claim.objects),
            )
            .any(|object| object.bytes.len() > MAXIMUM_NATIVE_BYTES)
        || lineage
            .publications()
            .iter()
            .flat_map(|claim| &claim.rows)
            .try_fold(0usize, |count, row| {
                count.checked_add(row.dependencies.len())
            })
            .is_none_or(|count| count > 4096)
    {
        return Err(refusal(
            "original input lacks committed complete producer/consumer custody",
        ));
    }
    let producer_bytes = provenance
        .objects()
        .iter()
        .chain(
            lineage
                .publications()
                .iter()
                .flat_map(|value| &value.objects),
        )
        .try_fold(0usize, |total, value| total.checked_add(value.bytes.len()))
        .ok_or_else(|| refusal("producer lineage byte sum overflow"))?;
    if producer_bytes > MAXIMUM_LINEAGE_BYTES {
        return Err(refusal(
            "producer lineage exceeds selected retention credit",
        ));
    }
    let index = batch
        .deliveries()
        .iter()
        .position(|value| value == *delivery)
        .ok_or_else(|| refusal("original producer association disappeared"))?;
    let claim = &lineage.publications()[index];
    if delivery.producer.as_str() != "source-a"
        || delivery.consumer.as_str() != "disk-a"
        || delivery.native_sequence.get() != expectation.index as u64
        || delivery.publication.time_ps.get()
            != if expectation.index == 0 {
                10
            } else {
                1_000_000_000
            }
        || claim.event.payload != delivery.payload
        || claim.event.source_sequence != delivery.source_sequence
        || claim.event.publication_position != delivery.publication
        || claim.event.source != delivery.producer_endpoint
        || claim.origin.world_binding_hash
            != original
                .admission()
                .activation()
                .record()
                .world_binding_hash
    {
        return Err(refusal(
            "original publication lineage differs from actual input delivery",
        ));
    }
    let body = bounded_json(
        &serde_json::json!({
            "schema": "crucible.gem5.original-storage-input.v1", "stage": batch.stage_operation(),
            "batch": batch.batch(), "node": batch.node(), "owners": batch.owners(),
            "cutoff": batch.cutoff(), "inventory": batch.inventory(), "deliveries": batch.deliveries(),
            "payloads": batch.payloads(), "stage_ack": staged.acknowledgement(),
            "coordinator_commit": {"stage":commit.stage_operation(), "batch":commit.batch(),
                "node":commit.node(), "inventory":commit.inventory(), "cutoff":commit.cutoff()},
            "producer": {"event":claim.event, "origin":claim.origin, "published":claim.published,
                "objects":claim.objects, "rows":claim.rows},
            "other_producer_occurrences": lineage.publications().iter().map(|claim| serde_json::json!({
                "event": claim.event, "origin":claim.origin, "published":claim.published,
                "objects":claim.objects, "rows":claim.rows,
            })).collect::<Vec<_>>(),
            "provenance_roots": provenance.roots(), "provenance_objects":provenance.objects(),
            "consumption": progress,
        }),
        MAXIMUM_LINEAGE_BYTES,
    )?;
    Ok(Some(ConsumedInput {
        delivery: (*delivery).clone(),
        stage_ack: staged.acknowledgement().proof_ref.clone(),
        body,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostReceipt {
    schema_version: u16,
    profile: String,
    node: Id,
    owners: Vec<crucible_engine::node_contract::OwnerIdentity>,
    boundary: Position,
    native: ContentRef,
    native_sequence: U64,
    input: Option<(Id, ContentRef, U64)>,
    pending_causes: ContentRef,
}

#[derive(Serialize)]
struct StorageFacts {
    passed: bool,
    original_acknowledged: bool,
    lawful_empty_progress: bool,
    exact_grant_and_receipt: bool,
    original_cause_and_fifo: bool,
    independent_response: bool,
    independent_complete_disk_bytes: bool,
}

fn storage_facts(
    episode: &Episode,
    delivery: Option<&Delivery>,
    receipt: &HostReceipt,
    expectation: &BlockCaseExpectation,
    disk_matches: bool,
) -> Result<StorageFacts, QualificationError> {
    let observation = episode
        .outcome
        .scheduling
        .as_ref()
        .ok_or_else(|| refusal("storage scheduling disappeared"))?;
    let (start, limit) = match episode.request {
        OperationRequest::ExactRun {
            start,
            limit,
            boundary_policy: ExactBoundaryPolicy::HorizonPark,
        } => (start, limit),
        _ => {
            return Err(refusal(
                "storage case is not an actual exact original grant",
            ));
        }
    };
    let exact = matches!(episode.outcome.progress,
        ProgressEvidence::Exact { reached, stop: StopReason::HorizonPark }
            if reached == limit && observation.reached == reached && observation.closed_prefix == reached)
        && start < limit
        && receipt.schema_version == 1
        && receipt.profile == HOST_EXACT_PROFILE
        && receipt.node == episode.outcome.node
        && receipt.owners == episode.outcome.owners
        && receipt.boundary == limit
        && observation.node == episode.outcome.node
        && observation.owners == episode.outcome.owners;
    let publications: Vec<_> = observation
        .publications
        .iter()
        .filter(|value| {
            delivery.is_some_and(|delivery| value.causal_parents.as_slice() == [delivery.delivery])
        })
        .collect();
    let (mut causal, mut answer) = (false, false);
    if let (Some(delivery), [publication]) = (delivery, publications.as_slice()) {
        publication.payload.verify(&publication.payload_bytes)?;
        let response = BlockResponse::decode(&publication.payload_bytes).map_err(evidence_error)?;
        let request = BlockRequest::decode(&expectation.request).map_err(evidence_error)?;
        causal = publication.evaluation.is_some_and(|evaluation| {
            evaluation >= start
                && evaluation < limit
                && delivery.delivery.time_ps.get().checked_add(513_000)
                    == Some(evaluation.time_ps.get())
        }) && publication.publication.time_ps > delivery.delivery.time_ps
            && publication.native_sequence.get() == expectation.index as u64
            && receipt.native_sequence.get() > publication.native_sequence.get()
            && episode
                .outcome
                .retained_outputs
                .contains(&publication.publication_id)
            && response.epoch == request.epoch
            && response.request_id == request.request_id
            && response.encode().map_err(evidence_error)? == publication.payload_bytes;
        answer = publication.payload_bytes == expectation.response;
    }
    // The native tuple is retained independently of this input's earlier Stage;
    // a later empty cut may legitimately replace it before response publication.
    let _retained_native_input = &receipt.input;
    let empty_progress = expectation.allow_progress
        && observation.publications.is_empty()
        && episode.outcome.retained_outputs.is_empty();
    let completed = causal
        && answer
        && observation.publications.len() == 1
        && episode.outcome.retained_outputs.len() == 1;
    Ok(StorageFacts {
        passed: episode.acknowledged && exact && disk_matches && (completed || empty_progress),
        original_acknowledged: episode.acknowledged,
        lawful_empty_progress: empty_progress,
        exact_grant_and_receipt: exact,
        original_cause_and_fifo: causal,
        independent_response: answer,
        independent_complete_disk_bytes: disk_matches,
    })
}

/// Retains the fixed request/response pair and independently calculated disk.
type IndependentStorageModel = ([Vec<u8>; 2], [Vec<u8>; 2], Vec<u8>);

fn independent_model(
    script: &[u8],
    base: &[u8],
) -> Result<IndependentStorageModel, QualificationError> {
    if script.len() > 1024 || base.len() != 4096 || base.iter().any(|byte| *byte != 0x11) {
        return Err(refusal(
            "storage model source differs from its fixed bounded initial disk",
        ));
    }
    let source = ScriptedSource::from_script_bytes(script)
        .map_err(|failure| evidence_error(failure.reason))?;
    if source.kind() != ScriptedRequestKind::Block
        || source.requests().len() != 2
        || !script.starts_with(SCRIPT_PREFIX)
        || source.requests()[0].time_ps != 10
        || source.requests()[1].time_ps != 1_000_000_000
    {
        return Err(refusal(
            "storage model does not select the fixed original two-request script",
        ));
    }
    let first = BlockRequest::decode(&source.requests()[0].payload).map_err(evidence_error)?;
    let second = BlockRequest::decode(&source.requests()[1].payload).map_err(evidence_error)?;
    if first.op != BlockOp::Write
        || first.epoch != 0
        || first.request_id != 9
        || first.offset != 0
        || first.count != 512
        || first.data != vec![0x33; 512]
        || second.op != BlockOp::Read
        || second.epoch != 0
        || second.request_id != 10
        || second.offset != 0
        || second.count != 512
        || !second.data.is_empty()
        || first.encode().map_err(evidence_error)? != source.requests()[0].payload
        || second.encode().map_err(evidence_error)? != source.requests()[1].payload
    {
        return Err(refusal(
            "storage independent model refuses a different original request population",
        ));
    }
    let mut disk = base.to_vec();
    disk[..512].copy_from_slice(&first.data);
    let requests = [
        source.requests()[0].payload.clone(),
        source.requests()[1].payload.clone(),
    ];
    // The expectation's wire is assembled from the public ABI, independently
    // of BlockDevice and BlockResponse's production execution/encoding paths.
    let mut responses = [Vec::new(), Vec::new()];
    for (index, request) in [first, second].iter().enumerate() {
        let data = if index == 0 { &[][..] } else { &disk[..512] };
        responses[index].extend_from_slice(&[0, crucible_device::block::BLOCK_ABI_VERSION, 0, 0]);
        responses[index].extend_from_slice(&request.epoch.to_le_bytes());
        responses[index].extend_from_slice(&request.request_id.to_le_bytes());
        responses[index].extend_from_slice(&(data.len() as u32).to_le_bytes());
        responses[index].extend_from_slice(data);
    }
    Ok((requests, responses, disk))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceWire {
    sub_node: String,
    sub_node_kind: u8,
    target: String,
    device_id: String,
    device_kind: u8,
    device: Vec<u8>,
    modeled: Vec<serde_json::Value>,
    resolved: Vec<serde_json::Value>,
}

fn disk_matches(
    bytes: &[u8],
    expectation: &BlockCaseExpectation,
    write_consumed: bool,
) -> Result<bool, QualificationError> {
    if bytes.len() > MAXIMUM_NATIVE_BYTES {
        return Err(refusal(
            "native storage state exceeds bounded case geometry",
        ));
    }
    // Validate the complete source codec before borrowing its exact nested
    // block state. Decoding remains observation; no device is constructed.
    crucible_engine::device_subnode::DeviceSchedulingSubNodeCheckpoint::from_canonical_bytes(bytes)
        .map_err(evidence_error)?;
    let payload = bytes
        .strip_prefix(DEVICE_PREFIX)
        .ok_or_else(|| refusal("native device edition differs"))?;
    let wire: DeviceWire = ciborium::de::from_reader(payload).map_err(evidence_error)?;
    if wire.device_kind != 1
        || wire.device.len() > MAXIMUM_NATIVE_BYTES
        || wire.sub_node != "disk-a"
        || wire.target.is_empty()
        || wire.device_id.is_empty()
        || wire.sub_node_kind == 0
        || wire.modeled.len() > 2
        || wire.resolved.len() > 2
    {
        return Err(refusal(
            "actual native storage state does not match the selected Block shape",
        ));
    }
    let block = BlockSnapshot::from_canonical_bytes(&wire.device).map_err(evidence_error)?;
    if block.device_length != 4096
        || block.base_hash != *blake3::hash(&expectation.base.1).as_bytes()
        || block.full_pages.len() > 1
    {
        return Ok(false);
    }
    let mut actual = expectation.base.1.clone();
    for (page, data) in &block.full_pages {
        let start = usize::try_from(*page)
            .ok()
            .and_then(|page| page.checked_mul(data.len()))
            .ok_or_else(|| refusal("native overlay page offset overflow"))?;
        let end = start
            .checked_add(data.len())
            .ok_or_else(|| refusal("native overlay end overflow"))?;
        let target = actual
            .get_mut(start..end)
            .ok_or_else(|| refusal("native overlay is outside the original disk"))?;
        target.copy_from_slice(data);
    }
    let expected = if write_consumed {
        &expectation.disk
    } else {
        &expectation.base.1
    };
    Ok(actual == *expected)
}

fn preparation_body(
    activation: &WorldActivation,
) -> Result<(ContentRef, Vec<u8>), QualificationError> {
    let owners = activation
        .prepared_owners()
        .filter(|owners| owners.len() == 4)
        .ok_or_else(|| refusal("actual complete public owner barrier is missing"))?;
    let coordinator = activation
        .coordinator_snapshot()
        .ok_or_else(|| refusal("actual original coordinator body is missing"))?;
    if coordinator.bytes.len() > MAXIMUM_PREPARATION_BYTES
        || activation.node_preparations().len() != 4
    {
        return Err(refusal(
            "original preparation exceeds case credit or omits an owner",
        ));
    }
    coordinator.reference.verify(&coordinator.bytes)?;
    bounded_json(
        &serde_json::json!({
            "schema": "crucible.gem5.original-storage-preparation.v1", "owners":owners,
            "nodes":activation.node_preparations(), "coordinator":coordinator,
        }),
        MAXIMUM_PREPARATION_BYTES,
    )
}

fn retain_object(
    objects: &mut Vec<(ContentRef, Vec<u8>)>,
    object: (ContentRef, Vec<u8>),
) -> Result<(), QualificationError> {
    object.0.verify(&object.1)?;
    if let Some(previous) = objects.iter().find(|previous| previous.0 == object.0) {
        if previous.1 != object.1 {
            return Err(refusal(
                "one original storage role retained different bodies",
            ));
        }
        return Ok(());
    }
    let bytes = objects
        .iter()
        .try_fold(object.1.len(), |total, row| total.checked_add(row.1.len()))
        .ok_or_else(|| refusal("storage case aggregate byte sum overflow"))?;
    if bytes > MAXIMUM_CASE_BYTES || objects.len() >= 1024 {
        return Err(refusal("storage case complete body account exhausted"));
    }
    objects.push(object);
    Ok(())
}

fn body<'a>(
    objects: &'a [InputPayload],
    reference: &ContentRef,
) -> Result<&'a [u8], QualificationError> {
    let object = objects
        .iter()
        .find(|object| &object.reference == reference)
        .ok_or_else(|| refusal("original source proof body is missing"))?;
    reference.verify(&object.bytes)?;
    Ok(&object.bytes)
}

fn bounded_json(
    value: &impl Serialize,
    maximum: usize,
) -> Result<(ContentRef, Vec<u8>), QualificationError> {
    let mut writer = BoundedWriter {
        bytes: Vec::new(),
        maximum,
    };
    serde_json::to_writer(&mut writer, value).map_err(evidence_error)?;
    let parsed = canonical::parse_json(&writer.bytes, maximum)?;
    let bytes = canonical::canonical_json(&parsed)?;
    if bytes.len() > maximum {
        return Err(refusal(
            "canonical storage case exceeds finite retention credit",
        ));
    }
    Ok((canonical::content_ref(&bytes, "application/json")?, bytes))
}

struct BoundedWriter {
    bytes: Vec<u8>,
    maximum: usize,
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self
            .bytes
            .len()
            .checked_add(bytes.len())
            .is_none_or(|total| total > self.maximum)
        {
            return Err(io::Error::other("storage oracle byte credit exhausted"));
        }
        self.bytes
            .try_reserve(bytes.len())
            .map_err(io::Error::other)?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn refusal(message: &'static str) -> QualificationError {
    QualificationError::Refused(message)
}

fn evidence_error(error: impl std::fmt::Display) -> QualificationError {
    QualificationError::Evidence(error.to_string())
}
