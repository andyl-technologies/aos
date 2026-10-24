//! Collects terminal RF CPU cases from original common-runtime custody.
//!
//! The source fixture supplies a separately authenticated installed Gem5 scope.
//! The runtime supplies the original grant, committed activation, native proof
//! bytes and consumed publication ACK. Neither a decoded completion nor an
//! expected checksum constructs a case. This edition observes the terminal
//! native prefix; it does not expose every earlier budget prefix or establish
//! Linux, device, restoration or a complete normative obligation.

use std::io::{self, Write};
use std::rc::Rc;

use crucible_engine::node_contract::{
    ActivationRecord, ExactBoundaryPolicy, OperationOutcome, OperationRequest, OperationToken,
    OriginalInputLineageLimits, OriginalRuntimeWitness, ProgressEvidence, SavedRuntimeActivation,
    StopReason, WorldActivation,
};
use crucible_engine::node_scheduling::InputPayload;
use crucible_node_format::{ContentRef, HashRef, Id, Phase, Position, U64, canonical};
use crucible_node_transport::gem5::Gem5Completion;
use serde::Serialize;

use crate::node_qualification::{CaseVerdict, QualificationError};

use super::scope::Gem5CaseScope;

#[path = "lcg.rs"]
mod lcg;

#[cfg(test)]
#[path = "post_output_tests.rs"]
mod post_output_tests;

const MAXIMUM_CASE_BYTES: usize = 64 * 1024 * 1024;
const MAXIMUM_CASE_OBJECTS: usize = 128;
const SOURCE_EXIT_CAUSE: &str = "exiting with last active thread context";

const MAXIMUM_PROOF_BYTES: usize = 4 * 1024 * 1024;
const MAXIMUM_SUMMARY_BYTES: usize = 256 * 1024;
const MAXIMUM_COORDINATOR_BYTES: usize = 16 * 1024 * 1024;
const GUEST_SOURCE: &str = include_str!("guest-source/x86_64.S");
const ORACLE_SOURCE: &str = include_str!("lcg.rs");

#[derive(Clone, Copy)]
enum CaseKind {
    LcgCompleted,
    LcgProgress,
    PostOutputProgress,
    Horizon,
}

/// Selects an independent source-defined terminal predicate.
///
/// A selection is not native enrollment or a passing result. No constructor
/// accepts observed answer bytes, a verdict or a requirement coverage list.
pub(super) struct Gem5CaseExpectation {
    kind: CaseKind,
    predecessor: Option<Rc<OriginalGem5Case>>,
}

impl Gem5CaseExpectation {
    /// Selects the fixed x86 memory workload's original eight-byte publication.
    pub(super) fn lcg_completed() -> Self {
        Self {
            kind: CaseKind::LcgCompleted,
            predecessor: None,
        }
    }

    /// Selects lawful LCG horizon progress or its independently checked output.
    ///
    /// An empty horizon does not establish guest completion. The owning source
    /// run must separately require at least one observed independent LCG output.
    pub(super) fn lcg_progress() -> Self {
        let mut expectation = Self::lcg_completed();
        expectation.kind = CaseKind::LcgProgress;
        expectation
    }

    /// Selects source-defined progress only after a genuine checksum original.
    ///
    /// The immutable case retains its actual token, activation and native body.
    /// Collection reopens that same original on the owning runtime; this alias
    /// carries no new native permission and accepts no caller verdict or flag.
    ///
    /// # Errors
    /// Refuses any prior case that did not pass the independent checksum check.
    pub(super) fn post_output_progress(
        predecessor: Rc<OriginalGem5Case>,
    ) -> Result<Self, QualificationError> {
        if !matches!(predecessor.verdict, CaseVerdict::Passed)
            || !predecessor.observed_lcg_output
            || predecessor.provenance.native.reason != "output"
            || predecessor.provenance.native.output.as_slice() != lcg::expected_output()
        {
            return Err(refusal(
                "post-output selection lacks a genuine checksum original",
            ));
        }
        predecessor.result.0.verify(&predecessor.result.1)?;
        predecessor.oracle.0.verify(&predecessor.oracle.1)?;
        retained_case_body(&predecessor, &predecessor.provenance.native_proof)?;

        Ok(Self {
            kind: CaseKind::PostOutputProgress,
            predecessor: Some(predecessor),
        })
    }

    /// Selects an authentic empty horizon completion at the exclusive ceiling.
    pub(super) fn horizon() -> Self {
        Self {
            kind: CaseKind::Horizon,
            predecessor: None,
        }
    }

    fn id(&self) -> &'static str {
        match self.kind {
            CaseKind::LcgCompleted => "gem5.rf.x86.lcg.terminal-output.v1",
            CaseKind::LcgProgress => "gem5.rf.x86.lcg.original-progress.v1",
            CaseKind::PostOutputProgress => "gem5.rf.x86.lcg.post-output-progress.v1",
            CaseKind::Horizon => "gem5.rf.x86.exclusive-horizon.v1",
        }
    }

    /// Names a source-declared episode before its actual original grant begins.
    ///
    /// The digest correlates a case within the source plan. It does not confer
    /// activation, token or native permission; collection recomputes it from
    /// its actual opaque completed operation and source-authenticated world.
    ///
    /// # Errors
    /// Refuses a different owner geometry or canonical identity encoding failure.
    pub(super) fn case_id(
        &self,
        activation: &ActivationRecord,
        operation: &Id,
    ) -> Result<String, QualificationError> {
        if activation.owners.len() != 4 {
            return Err(refusal(
                "case identity requires the full four-owner original",
            ));
        }

        let original = SavedRuntimeActivation::from(activation);
        let mut declared = serde_json::json!({
            "kind": self.id(),
            "activation": original,
            "operation": operation,
        });
        if let Some(predecessor) = &self.predecessor {
            declared["predecessor_case"] =
                serde_json::to_value(&predecessor.result.0).map_err(evidence_error)?;
        }
        let identity = canonical::json_hash("crucible.gem5.original-case-identity.v1", &declared)?;
        Ok(format!("{}:{}", self.id(), identity.digest))
    }
}

/// Retains one immutable original case with complete collected proof bodies.
///
/// Actual runtime and native custody stay with the collecting fixture. This
/// record contains historical data and cannot execute, ACK, import or qualify
/// an owner. The source qualification issuer must retain uncovered requirements.
pub(super) struct OriginalGem5Case {
    id: String,
    verdict: CaseVerdict,
    world_binding_hash: HashRef,
    observed_lcg_output: bool,
    result: (ContentRef, Vec<u8>),
    oracle: (ContentRef, Vec<u8>),
    objects: Vec<(ContentRef, Vec<u8>)>,
    provenance: OriginalCaseProvenance,
    predecessor: Option<Rc<OriginalGem5Case>>,
}

// Only the actual collector constructs this process-local provenance. It owns
// token/activation aliases and immutable observations, never NodeRuntime itself.
struct OriginalCaseProvenance {
    token: OperationToken,
    activation: WorldActivation,
    request: OperationRequest,
    outcome: OperationOutcome,
    native_proof: ContentRef,
    native: Gem5Completion,
}

impl OriginalGem5Case {
    /// Collects the actual acknowledged original and independently checks it.
    ///
    /// # Errors
    /// Refuses foreign source scope, unavailable originals, changed authority,
    /// unsupported input-bearing CPU cases, missing public preparation or proof
    /// bodies, invalid native wire records and exceeded finite retention credit.
    /// A well-formed original that violates the independent predicate yields a
    /// retained Failed case rather than being filtered out.
    pub(super) fn collect(
        witness: &mut OriginalRuntimeWitness<'_>,
        token: &OperationToken,
        expectation: &Gem5CaseExpectation,
        scope: &Gem5CaseScope,
    ) -> Result<Self, QualificationError> {
        // Discover references under a short real-runtime borrow. Source reads
        // may contain failures and must precede the final completion borrow.
        let snapshot = Snapshot::read(witness, token)?;
        scope.authenticate_cpu_case(
            &snapshot.activation,
            &snapshot.world.world_binding_hash,
            token.route(),
        )?;

        if let Some(predecessor) = &expectation.predecessor {
            authenticate_predecessor(witness, token, &snapshot, predecessor, scope)?;
        }

        let references = snapshot.references()?;
        let evidence = witness
            .operation_evidence(
                token,
                &references,
                U64::new((MAXIMUM_PROOF_BYTES + 8) as u64),
            )
            .map_err(evidence_error)?;
        let inputs = witness
            .original_input_evidence(
                token,
                OriginalInputLineageLimits {
                    maximum_objects: 1,
                    maximum_bytes: 1024,
                    maximum_edges: 0,
                },
            )
            .map_err(evidence_error)?;
        if inputs.is_some() {
            return Err(refusal("RF CPU case unexpectedly retained staged inputs"));
        }

        let completion = witness
            .original_completed_operation(token)
            .map_err(evidence_error)?;
        let original = completion.admission();
        if !original.token().same_authority(token)
            || !original.activation().same_authority(&snapshot.activation)
            || original.request() != &snapshot.request
            || completion.outcome() != &snapshot.outcome
            || completion.acknowledged() != snapshot.acknowledged
            || original.inputs().is_some()
            || completion
                .staged_inputs()
                .map_err(evidence_error)?
                .is_some()
        {
            return Err(refusal(
                "original common case changed during source collection",
            ));
        }
        scope.authenticate_cpu_case(
            original.activation(),
            &original.activation().record().world_binding_hash,
            original.token().route(),
        )?;

        let scheduling = snapshot
            .outcome
            .scheduling
            .as_ref()
            .ok_or_else(|| refusal("CPU case lacks original native scheduling"))?;
        let native_body = body(&evidence, &scheduling.proof_ref)?;
        let native: Gem5Completion =
            serde_json::from_value(canonical::parse_json(native_body, MAXIMUM_PROOF_BYTES)?)
                .map_err(evidence_error)?;
        if native.kind != "completed"
            || native.original.kind != "run"
            || native.operation != native.original.operation
        {
            return Err(refusal(
                "CPU proof is not the original completed native frame",
            ));
        }

        let facts = terminal_facts(&snapshot, &native, expectation)?;
        let verdict = if facts.passed {
            CaseVerdict::Passed
        } else {
            CaseVerdict::Failed
        };
        let case_id = expectation.case_id(snapshot.activation.record(), token.operation())?;
        let oracle = Self::specification()?;
        let result = bounded_json(
            &serde_json::json!({
                "schema": "crucible.gem5.original-terminal-case.v1",
                "case": case_id, "kind": expectation.id(), "verdict": verdict,
                "world": snapshot.world, "route": token.route(),
                "request": snapshot.request, "outcome": snapshot.outcome,
                "acknowledged": snapshot.acknowledged,
                "native_proof": scheduling.proof_ref,
                "preparation": snapshot.preparation.0,
                "prepared_owners": snapshot.prepared_owners.0,
                "original_coordinator": snapshot.coordinator.reference,
                "oracle": oracle.0, "facts": facts,
                "predecessor_case": expectation.predecessor.as_ref().map(|case| &case.result.0),
                "predecessor_native_proof": expectation.predecessor.as_ref()
                    .map(|case| &case.provenance.native_proof),
                "scope": "terminal RF x86 native prefix under original public activation",
                "complete_prior_prefix_history": false,
                "restoration_observed": false,
                "linux_or_device_parity": false,
                "complete_requirement_coverage": false,
            }),
            MAXIMUM_SUMMARY_BYTES,
        )?;

        let provenance = OriginalCaseProvenance {
            token: token.clone(),
            activation: snapshot.activation.clone(),
            request: snapshot.request.clone(),
            outcome: snapshot.outcome.clone(),
            native_proof: scheduling.proof_ref.clone(),
            native,
        };

        let mut objects = Vec::new();
        objects
            .try_reserve_exact(evidence.len() + 5)
            .map_err(evidence_error)?;
        for object in evidence {
            objects.push((object.reference, object.bytes));
        }
        objects.extend([
            snapshot.preparation,
            snapshot.prepared_owners,
            (snapshot.coordinator.reference, snapshot.coordinator.bytes),
            oracle.clone(),
            result.clone(),
        ]);

        if let Some(predecessor) = &expectation.predecessor {
            retain_predecessor_objects(&mut objects, predecessor)?;
        }

        Ok(Self {
            id: case_id,
            verdict,
            observed_lcg_output: facts.observed_lcg_output,
            world_binding_hash: snapshot.activation.record().world_binding_hash.clone(),
            result,
            oracle,
            objects,
            provenance,
            predecessor: expectation.predecessor.clone(),
        })
    }

    /// Binds the compiled guest algorithm and independent implementation bytes.
    ///
    /// # Errors
    /// Refuses canonical encoding or finite source-specification credit failure.
    pub(super) fn specification() -> Result<(ContentRef, Vec<u8>), QualificationError> {
        bounded_json(
            &serde_json::json!({
                "schema": "crucible.gem5.rf-x86-independent-oracle.v1",
                "guest_source": GUEST_SOURCE,
                "independent_implementation": ORACLE_SOURCE,
                "initial_arena_bytes": "262144", "initial_generator": "3",
                "iterations": "20000", "generator_width": "32",
                "word_width": "64", "output": "one little-endian uint64",
                "horizon": "exact original ceiling; no publication; no reaction at equality",
                "post_output_lifecycle": "genuine prior checksum token; syscall60 with edi0; native last-active-thread exit0; empty outputs; original Lifecycle ACK",
                "native_exit_cause": SOURCE_EXIT_CAUSE,
                "source_enrollment": "separately authenticated Gem5CaseScope",
                "coverage": "terminal lawful observations; no whole RFC requirement",
            }),
            MAXIMUM_SUMMARY_BYTES,
        )
    }

    /// Borrows the source-selected case identity.
    pub(super) fn id(&self) -> &str {
        &self.id
    }

    /// Returns the original independent comparison's retained disposition.
    pub(super) fn verdict(&self) -> CaseVerdict {
        self.verdict
    }

    /// Borrows canonical original observations and their exact identity.
    pub(super) fn result(&self) -> (&ContentRef, &[u8]) {
        (&self.result.0, &self.result.1)
    }

    /// Reports whether this original case proved the independent LCG output.
    ///
    /// This fact is false for empty horizon progress and every Failed case.
    /// It supplies historical data; it does not complete a grant or issue ACK.
    pub(super) fn observed_lcg_output(&self) -> bool {
        self.observed_lcg_output
    }

    /// Borrows the retained original checksum case required by this selection.
    pub(super) fn checksum_predecessor(&self) -> Option<&OriginalGem5Case> {
        self.predecessor.as_deref()
    }

    /// Borrows the complete independently compiled oracle specification.
    pub(super) fn oracle(&self) -> (&ContentRef, &[u8]) {
        (&self.oracle.0, &self.oracle.1)
    }

    /// Borrows all complete bodies returned by this selected collection edition.
    ///
    /// Immutable graph/source bindings and nested native diagnostic references
    /// remain separately owned dependencies; this is not an opaque image closure.
    pub(super) fn objects(&self) -> &[(ContentRef, Vec<u8>)] {
        &self.objects
    }

    /// Borrows the actual original complete world binding, not an expected hash.
    pub(super) fn world_binding_hash(&self) -> &HashRef {
        &self.world_binding_hash
    }

    /// Reports complete normative coverage, which this lawful-case edition lacks.
    ///
    /// A successful checksum or horizon is evidence toward a requirement, not
    /// its quantified adverse, lifetime and failure predicates.
    pub(super) fn covers(&self, _requirement: &str) -> bool {
        false
    }
}

struct Snapshot {
    activation: WorldActivation,
    world: SavedRuntimeActivation,
    request: OperationRequest,
    outcome: OperationOutcome,
    acknowledged: bool,
    preparation: (ContentRef, Vec<u8>),
    prepared_owners: (ContentRef, Vec<u8>),
    coordinator: InputPayload,
}

impl Snapshot {
    fn read(
        witness: &mut OriginalRuntimeWitness<'_>,
        token: &OperationToken,
    ) -> Result<Self, QualificationError> {
        let original = witness
            .original_completed_operation(token)
            .map_err(evidence_error)?;
        let admission = original.admission();
        let activation = admission.activation();
        let record = activation.record();
        if record.owners.len() != 4
            || activation.node_preparations().len() != 4
            || token.route().owners.len() != 1
            || admission.inputs().is_some()
        {
            return Err(refusal(
                "oracle requires the original four-owner no-ingress CPU route",
            ));
        }
        let scheduling = original
            .outcome()
            .scheduling
            .as_ref()
            .ok_or_else(|| refusal("oracle lacks retained terminal scheduling"))?;
        if scheduling.bounds.len() != 1
            || scheduling.publications.len() > 1
            || !scheduling.external_inputs.is_empty()
            || scheduling.input_progress.is_some()
            || scheduling
                .publications
                .iter()
                .any(|value| value.payload_bytes.len() != 8)
        {
            return Err(refusal("CPU terminal inventory exceeds selected geometry"));
        }
        let prepared = activation
            .prepared_owners()
            .filter(|owners| owners.len() == 4)
            .ok_or_else(|| refusal("original public prepared-owner barrier is absent"))?;
        let coordinator = activation
            .coordinator_snapshot()
            .ok_or_else(|| refusal("original public coordinator body is absent"))?;
        if coordinator.bytes.len() > MAXIMUM_COORDINATOR_BYTES {
            return Err(refusal("original coordinator body exceeds finite credit"));
        }
        coordinator.reference.verify(&coordinator.bytes)?;
        let preparation = bounded_json(&activation.node_preparations(), MAXIMUM_SUMMARY_BYTES)?;
        let prepared_owners = bounded_json(&prepared, MAXIMUM_SUMMARY_BYTES)?;

        Ok(Self {
            activation: activation.clone(),
            world: record.into(),
            request: admission.request().clone(),
            outcome: original.outcome().clone(),
            acknowledged: original.acknowledged(),
            preparation,
            prepared_owners,
            coordinator: coordinator.clone(),
        })
    }

    fn references(&self) -> Result<Vec<ContentRef>, QualificationError> {
        let scheduling = self
            .outcome
            .scheduling
            .as_ref()
            .ok_or_else(|| refusal("terminal native scheduling vanished"))?;
        if scheduling.proof_ref.length.get() > MAXIMUM_PROOF_BYTES as u64
            || scheduling
                .bounds
                .iter()
                .any(|bound| bound.proof_ref != scheduling.proof_ref)
        {
            return Err(refusal(
                "terminal proof exceeds credit or changes producer root",
            ));
        }
        let mut references = vec![scheduling.proof_ref.clone()];
        for publication in &scheduling.publications {
            if publication.payload.length.get() != 8 {
                return Err(refusal("CPU payload is not eight bytes"));
            }

            if !references.contains(&publication.payload) {
                references.push(publication.payload.clone());
            }
        }
        Ok(references)
    }
}

#[derive(Serialize)]
struct TerminalFacts {
    passed: bool,
    acknowledged: bool,
    scope_matches: bool,
    terminal_prefix_within_original_grant: bool,
    event_count_matches: bool,
    terminal_birth_matches: bool,
    independent_answer_matches: bool,
    exclusive_horizon_matches: bool,
    observed_lcg_output: bool,
    post_output_predecessor_matches: bool,
    lawful_guest_exit_matches: bool,
}

fn terminal_facts(
    snapshot: &Snapshot,
    native: &Gem5Completion,
    expectation: &Gem5CaseExpectation,
) -> Result<TerminalFacts, QualificationError> {
    let (start, limit) = match snapshot.request {
        OperationRequest::ExactRun {
            start,
            limit,
            boundary_policy: ExactBoundaryPolicy::HorizonPark,
        } => (start, limit),
        _ => return Err(refusal("case is not an original exact HorizonPark grant")),
    };
    let observation = snapshot
        .outcome
        .scheduling
        .as_ref()
        .ok_or_else(|| refusal("case lost scheduling"))?;
    let reached = match snapshot.outcome.progress {
        ProgressEvidence::Exact { reached, .. } => reached,
        _ => return Err(refusal("case lacks exact original progress")),
    };
    let range = native
        .original
        .exact_range
        .as_ref()
        .ok_or_else(|| refusal("native prefix lacks full exact range"))?;
    let scope_matches = observation.node == snapshot.outcome.node
        && observation.owners == snapshot.outcome.owners
        && observation.reached == reached
        && observation.closed_prefix == reached
        && native.after.logical_position == reached;
    let prefix_matches = start < limit
        && range.start >= start
        && range.start < limit
        && range.limit == limit
        && native.before.logical_position == range.start
        && reached >= range.start
        && reached <= limit
        && native.original.exclusive_tick == limit.time_ps;
    let event_count_matches = native
        .after
        .ordinal
        .get()
        .checked_sub(native.before.ordinal.get())
        == Some(native.processed_events.get())
        && native.processed_events <= native.original.maximum_events;

    let mut terminal_birth_matches = false;
    let mut independent_answer_matches = false;
    if let ([birth], [publication]) = (
        native.publications.as_slice(),
        observation.publications.as_slice(),
    ) {
        let reaction = birth
            .tick_ordinal
            .get()
            .checked_sub(1)
            .and_then(|value| value.checked_mul(2));
        if let Some(reaction) = reaction
            && let Some(publication_step) = reaction.checked_add(1)
        {
            let evaluation = Position::new(birth.tick, U64::new(reaction), Phase::Reaction);
            let position =
                Position::new(birth.tick, U64::new(publication_step), Phase::Publication);
            terminal_birth_matches = birth.output_id.get() == 1
                && birth.guest_pid.get() == 100
                && birth.context_id.get() == 0
                && birth.guest_fd == 1
                && birth.causal_parent.get() == 0
                && birth.event_ordinal > native.before.ordinal
                && birth.event_ordinal <= native.after.ordinal
                && birth.tick == native.after.tick
                && publication_step < range.maximum_microsteps.get()
                && publication.native_sequence == birth.output_id
                && publication.evaluation == Some(evaluation)
                && publication.publication == position
                && publication.causal_parents.is_empty()
                && publication.payload_bytes == birth.payload
                && native.output == birth.payload
                && publication.publication_id.as_str() == "gem5/output/1"
                && evaluation >= range.start
                && evaluation < limit;
            publication.payload.verify(&birth.payload)?;
            independent_answer_matches = birth.payload.as_slice() == lcg::expected_output();
        }
    }
    let horizon = reached == limit
        && matches!(native.reason.as_str(), "horizon" | "idle")
        && native.publications.is_empty()
        && native.output.is_empty()
        && observation.publications.is_empty()
        && snapshot.outcome.retained_outputs.is_empty()
        && matches!(
            snapshot.outcome.progress,
            ProgressEvidence::Exact {
                stop: StopReason::HorizonPark,
                ..
            }
        )
        && (!native.after.has_next_event
            || native
                .after
                .next_reaction(range.maximum_microsteps)
                .map_err(evidence_error)?
                .is_some_and(|next| next >= limit));
    let output_inventory_matches = match observation.publications.as_slice() {
        [publication] => {
            snapshot.outcome.retained_outputs.as_slice()
                == std::slice::from_ref(&publication.publication_id)
        }
        _ => false,
    };
    let lcg_output = terminal_birth_matches
        && independent_answer_matches
        && native.reason == "output"
        && native.processed_events.get() > 0
        && matches!(
            snapshot.outcome.progress,
            ProgressEvidence::Exact {
                stop: StopReason::Output,
                ..
            }
        )
        && output_inventory_matches;
    let post_output_predecessor_matches = expectation.predecessor.as_ref().is_some_and(|prior| {
        prior.observed_lcg_output
            && prior
                .provenance
                .activation
                .same_authority(&snapshot.activation)
            && prior.provenance.token.route().node == snapshot.outcome.node
            && prior.provenance.token.route().owners == snapshot.outcome.owners
            && prior.provenance.native.after.logical_position <= range.start
            && prior.provenance.native.after.ordinal <= native.before.ordinal
            && prior.provenance.native.after.tick <= native.before.tick
    });
    let lifecycle_coordinate_matches = source_lifecycle_coordinate_matches(
        native.after.tick,
        native.after.tick_ordinal,
        range.maximum_microsteps,
        reached,
    );
    let lawful_guest_exit_matches = lifecycle_coordinate_matches
        && native.reason == "guest_exit"
        && native.processed_events.get() > 0
        && reached < limit
        && source_exit_matches(
            native.exit_cause.as_deref(),
            native.exit_code,
            native.publications.len(),
            native.output.len(),
            observation.publications.len(),
            snapshot.outcome.retained_outputs.len(),
            &snapshot.outcome.progress,
        );
    let selected_matches = source_terminal_selection(
        expectation.kind,
        lcg_output,
        horizon,
        post_output_predecessor_matches,
        lawful_guest_exit_matches,
    );
    let common_matches =
        snapshot.acknowledged && scope_matches && prefix_matches && event_count_matches;

    Ok(TerminalFacts {
        passed: common_matches && selected_matches,
        acknowledged: snapshot.acknowledged,
        scope_matches,
        terminal_prefix_within_original_grant: prefix_matches,
        event_count_matches,
        terminal_birth_matches,
        independent_answer_matches,
        exclusive_horizon_matches: horizon,
        observed_lcg_output: common_matches && lcg_output && selected_matches,
        post_output_predecessor_matches,
        lawful_guest_exit_matches,
    })
}

fn authenticate_predecessor(
    witness: &mut OriginalRuntimeWitness<'_>,
    current_token: &OperationToken,
    current: &Snapshot,
    predecessor: &OriginalGem5Case,
    scope: &Gem5CaseScope,
) -> Result<(), QualificationError> {
    let prior = &predecessor.provenance;
    if !predecessor.observed_lcg_output
        || !matches!(predecessor.verdict, CaseVerdict::Passed)
        || prior.token.same_authority(current_token)
        || prior.token.route() != current_token.route()
        || !prior.activation.same_authority(&current.activation)
    {
        return Err(refusal(
            "post-output case changes original runtime or CPU route",
        ));
    }
    scope.authenticate_cpu_case(
        &prior.activation,
        &predecessor.world_binding_hash,
        prior.token.route(),
    )?;

    // A historical result body alone cannot replace this genuine same-runtime
    // token lookup. Finish the prior borrow before current source reads.
    let original = witness
        .original_completed_operation(&prior.token)
        .map_err(evidence_error)?;
    if !original.admission().token().same_authority(&prior.token)
        || !original
            .admission()
            .activation()
            .same_authority(&prior.activation)
        || original.admission().request() != &prior.request
        || original.outcome() != &prior.outcome
        || !original.acknowledged()
        || original.admission().inputs().is_some()
        || original.staged_inputs().map_err(evidence_error)?.is_some()
        || original
            .outcome()
            .scheduling
            .as_ref()
            .is_none_or(|observed| observed.proof_ref != prior.native_proof)
    {
        return Err(refusal(
            "prior checksum original changed its grant, result or ACK",
        ));
    }
    let evidence = witness
        .operation_evidence(
            &prior.token,
            std::slice::from_ref(&prior.native_proof),
            U64::new(MAXIMUM_PROOF_BYTES as u64),
        )
        .map_err(evidence_error)?;
    let actual = body(&evidence, &prior.native_proof)?;
    if actual != retained_case_body(predecessor, &prior.native_proof)? {
        return Err(refusal("prior checksum original native proof changed"));
    }
    Ok(())
}

fn retained_case_body<'a>(
    case: &'a OriginalGem5Case,
    reference: &ContentRef,
) -> Result<&'a [u8], QualificationError> {
    let (_, bytes) = case
        .objects
        .iter()
        .find(|(actual, _)| actual == reference)
        .ok_or_else(|| refusal("prior original dependency body is absent"))?;
    reference.verify(bytes)?;
    Ok(bytes)
}

fn retain_predecessor_objects(
    objects: &mut Vec<(ContentRef, Vec<u8>)>,
    predecessor: &OriginalGem5Case,
) -> Result<(), QualificationError> {
    let mut bytes = objects.iter().try_fold(0usize, |total, (_, body)| {
        total
            .checked_add(body.len())
            .ok_or_else(|| refusal("case body credit overflow"))
    })?;
    let additional = predecessor
        .objects
        .iter()
        .filter(|(reference, _)| !objects.iter().any(|(old, _)| old == reference))
        .count();
    if objects
        .len()
        .checked_add(additional)
        .is_none_or(|count| count > MAXIMUM_CASE_OBJECTS)
    {
        return Err(refusal(
            "complete predecessor dependency roster exceeds case credit",
        ));
    }
    for (reference, body) in &predecessor.objects {
        reference.verify(body)?;
        if let Some((_, old)) = objects.iter().find(|(old, _)| old == reference) {
            if old != body {
                return Err(refusal(
                    "case dependency identity has different original bytes",
                ));
            }
        } else {
            bytes = bytes
                .checked_add(body.len())
                .ok_or_else(|| refusal("case dependency byte credit overflow"))?;
        }
    }
    if bytes > MAXIMUM_CASE_BYTES {
        return Err(refusal(
            "complete predecessor bodies exceed unchanged case credit",
        ));
    }
    objects
        .try_reserve_exact(additional)
        .map_err(evidence_error)?;
    for (reference, body) in &predecessor.objects {
        if objects.iter().any(|(old, _)| old == reference) {
            continue;
        }
        let mut retained = Vec::new();
        retained
            .try_reserve_exact(body.len())
            .map_err(evidence_error)?;
        retained.extend_from_slice(body);
        objects.push((reference.clone(), retained));
    }
    Ok(())
}

fn source_terminal_selection(
    kind: CaseKind,
    lcg_output: bool,
    horizon: bool,
    genuine_prior_output: bool,
    lawful_exit: bool,
) -> bool {
    match kind {
        CaseKind::LcgCompleted => lcg_output,
        CaseKind::LcgProgress => lcg_output || horizon,
        CaseKind::PostOutputProgress => genuine_prior_output && (lawful_exit || horizon),
        CaseKind::Horizon => horizon,
    }
}

// The stopped cursor follows evaluation in BoundaryControl. A publication's
// Reaction coordinate remains distinct from this original callback stop.
fn source_lifecycle_coordinate_matches(
    tick: U64,
    tick_ordinal: U64,
    maximum_microsteps: U64,
    reached: Position,
) -> bool {
    tick_ordinal
        .get()
        .checked_sub(1)
        .and_then(|tie| tie.checked_mul(2))
        .and_then(|reaction| reaction.checked_add(1))
        .is_some_and(|microstep| {
            microstep < maximum_microsteps.get()
                && reached == Position::new(tick, U64::new(microstep), Phase::BoundaryControl)
        })
}

fn source_exit_matches(
    cause: Option<&str>,
    code: Option<i32>,
    native_publications: usize,
    native_output_bytes: usize,
    common_publications: usize,
    retained_outputs: usize,
    progress: &ProgressEvidence,
) -> bool {
    cause == Some(SOURCE_EXIT_CAUSE)
        && code == Some(0)
        && native_publications == 0
        && native_output_bytes == 0
        && common_publications == 0
        && retained_outputs == 0
        && matches!(
            progress,
            ProgressEvidence::Exact {
                stop: StopReason::Lifecycle,
                ..
            }
        )
}

fn body<'a>(
    objects: &'a [InputPayload],
    reference: &ContentRef,
) -> Result<&'a [u8], QualificationError> {
    let object = objects
        .iter()
        .find(|object| &object.reference == reference)
        .ok_or_else(|| refusal("original native proof body is absent"))?;
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
    let value = canonical::parse_json(&writer.bytes, maximum)?;
    let bytes = canonical::canonical_json(&value)?;
    if bytes.len() > maximum {
        return Err(refusal("canonical case exceeds reserved credit"));
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
            .is_none_or(|size| size > self.maximum)
        {
            return Err(io::Error::other("original oracle byte credit exhausted"));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_writer_refuses_aggregate_growth_before_copy() {
        let mut writer = BoundedWriter {
            bytes: Vec::new(),
            maximum: 8,
        };

        assert!(writer.write_all(b"original").is_ok());
        assert!(writer.write_all(b"x").is_err());
        assert_eq!(writer.bytes, b"original");
    }

    #[test]
    fn bounded_summary_accounts_json_escaping_before_copy() {
        let mut writer = BoundedWriter {
            bytes: Vec::new(),
            maximum: 8,
        };

        assert!(serde_json::to_writer(&mut writer, &"\u{0000}\u{0000}").is_err());
        assert!(writer.bytes.len() <= 8);
    }

    #[test]
    fn unsupported_reference_cannot_select_an_unrelated_body() {
        let first = canonical::content_ref(b"first", "application/octet-stream");
        let second = canonical::content_ref(b"second", "application/octet-stream");
        let (Ok(first), Ok(second)) = (first, second) else {
            panic!("fixed source byte references must encode");
        };
        let objects = [InputPayload {
            reference: first,
            bytes: b"first".to_vec(),
        }];

        assert!(body(&objects, &second).is_err());
    }
}
