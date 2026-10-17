//! Owns the independently installed conditional capture codec and source bodies.
//!
//! Native measurement envelopes are historical attestations. This codec never
//! opens their named executables after installation. The current host executable
//! is a reconstruction dependency; every replayed tape, input and ACK body is
//! likewise retained under its complete typed reference. Unknown roles refuse.

use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, VecDeque},
    rc::Rc,
};

use crucible::{
    node_adapters::transcript::{
        TranscriptAction, authenticate_tape2_continuation, decode_original_lineage_model_capture,
        replay_input_custody_references,
    },
    node_admission::AdmittedGraph,
    node_contract::{ActivationRecord, NodeRoute, OriginalLineageRuntimeRecord, RuntimeSnapshot},
    node_scheduling::{InputPayload, NativeInputAcknowledgement, SchedulingSnapshot},
    node_state::{
        AuthenticatedNativeSource, AuthenticatedOriginalLineageSource, CaptureEvidence,
        NativeArchiveLimits, NativeArchiveRecord, NativeCoordinatorCaptureProof,
        NativeOwnerCaptureProof, NativeRestoreStaging, NativeWorldFactory, RestoreReservations,
        StateError, StateLimits, StateRequirements, VerifiedStateContent, admitted_graph_records,
    },
};
use crucible_node_contract::{CaptureManifest, CapturedOwner, ContentRef};

use super::{
    conditional_capture_records::{insert, original_rows},
    conditional_capture_scope::{authenticate, authenticate_scheduler, refused},
    conditional_policy::ConditionalPolicy,
    conditional_profile::{ConditionalProfile, encode},
};

/// Decodes only the successful original Stage response from the authenticated tape.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum OriginalStageResponse {
    Input(Box<NativeInputAcknowledgement>),
}

/// Retains the exact source-capture tuple independently of parsed archive claims.
struct AcceptedCut {
    runtime: OriginalLineageRuntimeRecord,
    scheduler: SchedulingSnapshot,
}

pub(super) struct ConditionalCaptureFactory {
    profile: Rc<ConditionalProfile>,
    rows: BTreeMap<ContentRef, Vec<ContentRef>>,
    qualifications: BTreeMap<ContentRef, Vec<u8>>,
    continuation_qualifications: BTreeMap<crucible_node_contract::Id, ContentRef>,
    immutable_roots: Vec<ContentRef>,
    attempted: Cell<bool>,
    accepted: RefCell<Option<AcceptedCut>>,
}

impl ConditionalCaptureFactory {
    /// Reserves source codec rows before any model is constructed or activated.
    pub(super) fn install(
        profile: Rc<ConditionalProfile>,
        graph: &AdmittedGraph,
    ) -> Result<Self, StateError> {
        let mut rows = original_rows(&profile)?;
        let limits = StateLimits {
            maximum_content_objects: 4096,
            maximum_total_content_bytes: 64 * 1024 * 1024,
            maximum_dependency_edges: 65_536,
            ..StateLimits::default()
        };
        let projected = admitted_graph_records(graph, limits)?;
        // Count all candidate occurrences before any additional dependency
        // copies. Sharing can only reduce these conservative lifetime credits.
        let roles = rows
            .len()
            .checked_add(profile.construction_rows.len())
            .and_then(|count| count.checked_add(projected.len()))
            .and_then(|count| count.checked_add(9))
            .filter(|count| *count <= 4096)
            .ok_or_else(|| refused("installed aggregate codec role credit exhausted"))?;
        let mut edges = 36usize;
        for dependencies in rows.values().chain(profile.construction_rows.values()) {
            edges = edges
                .checked_add(dependencies.len())
                .filter(|count| *count <= 65_536)
                .ok_or_else(|| refused("installed aggregate codec edge credit exhausted"))?;
        }
        for record in &projected {
            edges = edges
                .checked_add(record.dependencies().len())
                .filter(|count| *count <= 65_536)
                .ok_or_else(|| refused("installed aggregate graph edge credit exhausted"))?;
        }
        for (reference, dependencies) in &profile.construction_rows {
            insert(
                &mut rows,
                reference.clone(),
                bounded_copy(dependencies, 4096)?,
            )?;
        }
        let mut immutable_roots = Vec::new();
        immutable_roots.try_reserve_exact(roles).map_err(refused)?;
        for projected in projected {
            let object = projected.object();
            if profile.content.get(&object.reference) != Some(&object.bytes) {
                return Err(refused(
                    "regenerated graph row differs from its original builder-owned encoding",
                ));
            }
            insert(
                &mut rows,
                object.reference.clone(),
                bounded_copy(projected.dependencies(), 4096)?,
            )?;
            immutable_roots.push(object.reference.clone());
        }
        let policy = ConditionalPolicy::install(Rc::clone(&profile)).map_err(refused)?;
        let mut qualifications = BTreeMap::new();
        let mut continuation_qualifications = BTreeMap::new();
        for binding in &profile.bindings {
            let node = &binding.compatibility.node_id;
            let source = profile
                .history
                .originals
                .get(node)
                .ok_or_else(|| refused("qualified original tape is absent"))?;
            let route = NodeRoute {
                node: node.clone(),
                owners: profile
                    .activation
                    .owners
                    .iter()
                    .filter(|owner| owner.owner == binding.compatibility.execution_owner.id)
                    .cloned()
                    .collect(),
            };
            for obligation in [
                "original-boundary-replay",
                "original-native-lineage",
                "complete-conditional-runtime7",
            ] {
                let qualified = policy
                    .qualification(
                        source,
                        graph,
                        &route,
                        &source.transcript().origin.context,
                        obligation,
                    )
                    .map_err(refused)?;
                insert(
                    &mut rows,
                    qualified.proof.reference.clone(),
                    vec![
                        source.reference().clone(),
                        qualified.source_context,
                        qualified.target_binding,
                        profile.host.clone(),
                    ],
                )?;
                if obligation == "complete-conditional-runtime7" {
                    continuation_qualifications
                        .insert(node.clone(), qualified.proof.reference.clone());
                }
                qualifications.insert(qualified.proof.reference, qualified.proof.bytes);
            }
        }
        Ok(Self {
            profile,
            rows,
            qualifications,
            continuation_qualifications,
            immutable_roots,
            attempted: Cell::new(false),
            accepted: RefCell::new(None),
        })
    }

    /// Checks the immutable codec closure without dispatching any model control.
    pub(super) fn preflight_immutable(&self) -> Result<(), StateError> {
        let mut queue = VecDeque::new();
        queue.try_reserve(4096).map_err(refused)?;
        queue.extend(self.immutable_roots.iter().cloned());
        let mut visited = BTreeSet::new();
        let mut total = 0usize;
        let mut unresolved = Vec::new();
        unresolved.try_reserve_exact(64).map_err(refused)?;
        while let Some(reference) = queue.pop_front() {
            if visited.contains(&reference) {
                continue;
            }
            if visited.len() == 4096 {
                return Err(refused("immutable installed role credit exhausted"));
            }
            visited.insert(reference.clone());
            let bytes = match self.content(&reference, 256 * 1024 * 1024) {
                Ok(bytes) => bytes,
                Err(error) => {
                    unresolved.push(format!("{reference:?}: {error}"));
                    if unresolved.len() == 64 {
                        break;
                    }
                    continue;
                }
            };
            total = total
                .checked_add(bytes.len())
                .filter(|total| *total <= 384 * 1024 * 1024)
                .ok_or_else(|| refused("immutable unique byte credit exhausted"))?;
            let edges = match self.dependencies_for(&reference, &bytes, 4096) {
                Ok(edges) => edges,
                Err(error) => {
                    // An unresolved role has no assumed children or implicit
                    // leaf. Continue only through other already-known rows.
                    // A bounded diagnostic exposes only an already owned
                    // small current graph body. It installs no row or leaf and
                    // preserves the same terminal refusal for this unknown role.
                    let diagnostic = self
                        .profile
                        .content
                        .get(&reference)
                        .filter(|body| body.len() <= 1024)
                        .and_then(|body| std::str::from_utf8(body).ok())
                        .unwrap_or("<no small owned UTF-8 body>");
                    unresolved.push(format!("{reference:?}: {error}; owned_body={diagnostic}"));
                    if unresolved.len() == 64 {
                        break;
                    }
                    continue;
                }
            };
            if queue
                .len()
                .checked_add(edges.len())
                .is_none_or(|count| count > 4096)
            {
                return Err(refused("immutable queued role credit exhausted"));
            }
            queue.extend(edges);
        }
        if unresolved.is_empty() {
            Ok(())
        } else {
            Err(refused(format!(
                "immutable dependency frontier unresolved (at most 64 roles): {}",
                unresolved.join("\n")
            )))
        }
    }

    /// Revalidates each actual pinned source against the retained accepted cut.
    pub(super) fn verify_pinned_source(
        &self,
        graph: &AdmittedGraph,
        source: &crucible::node_state::PinnedOriginalLineageSource,
    ) -> Result<(), StateError> {
        self.authenticate_original_lineage_source(graph, &source.source())
    }

    /// Checks the reference export without claiming signed capture or scheduler support.
    pub(super) fn authenticate_prefix(
        &self,
        graph: &AdmittedGraph,
        runtime: &OriginalLineageRuntimeRecord,
    ) -> Result<(), StateError> {
        authenticate(&self.profile, graph, runtime)
    }

    fn dependencies_for(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        maximum: usize,
    ) -> Result<Vec<ContentRef>, StateError> {
        reference.verify(bytes).map_err(refused)?;
        if reference == &self.profile.host {
            // The actual measured host ELF is an explicit opaque byte leaf.
            // Its complete bytes are retained by the archive, not its pathname.
            return Ok(Vec::new());
        }
        if let Some(row) = self.rows.get(reference) {
            if self
                .profile
                .content
                .get(reference)
                .or_else(|| self.qualifications.get(reference))
                .map(Vec::as_slice)
                != Some(bytes)
                || row.len() > maximum
            {
                return Err(refused("changed original typed body or adjacency credit"));
            }
            return bounded_copy(row, maximum);
        }
        let accepted = self.accepted.try_borrow().map_err(refused)?;
        let accepted = accepted.as_ref().ok_or_else(|| {
            refused(format!(
                "immutable role has no installed dependency codec: {reference:?}"
            ))
        })?;
        for input in &accepted.runtime.inputs {
            if input.inventory == *reference {
                if encode(&input.deliveries).map_err(refused)? != bytes {
                    return Err(refused("original ordered input inventory bytes changed"));
                }
                let count = input
                    .deliveries
                    .len()
                    .checked_mul(3)
                    .filter(|count| *count <= maximum)
                    .ok_or_else(|| refused("input inventory edge credit exhausted"))?;
                let mut edges = Vec::new();
                edges.try_reserve_exact(count).map_err(refused)?;
                for delivery in &input.deliveries {
                    edges.push(delivery.payload.clone());
                    edges.push(delivery.provenance_ref.clone());
                    edges.push(delivery.connection_policy_ref.clone().ok_or_else(|| {
                        refused("declared native input has no original connection policy")
                    })?);
                }
                return normalize(edges);
            }
            if input
                .acknowledgement
                .as_ref()
                .is_some_and(|ack| ack.proof_ref == *reference)
            {
                let data = replay_input_custody_references(
                    &InputPayload {
                        reference: reference.clone(),
                        bytes: bounded_bytes(bytes, 1024 * 1024)?,
                    },
                    1024 * 1024,
                )
                .map_err(refused)?;
                let tape = self
                    .profile
                    .history
                    .originals
                    .get(&input.node)
                    .ok_or_else(|| refused("original input tape is absent"))?;
                let stage = tape
                    .transcript()
                    .records
                    .iter()
                    .find(|record| {
                        record.request.action == TranscriptAction::StageInput
                            && record.request.identity == input.stage_operation
                    })
                    .ok_or_else(|| refused("signed original input Stage is absent"))?;
                stage
                    .response
                    .verify(&stage.response_bytes)
                    .map_err(refused)?;
                let value = crucible_node_contract::canonical::parse_json(
                    &stage.response_bytes,
                    1024 * 1024,
                )
                .map_err(refused)?;
                let response: OriginalStageResponse =
                    serde_json::from_value(value).map_err(refused)?;
                if encode(&response).map_err(refused)? != stage.response_bytes {
                    return Err(refused("signed original Stage response encoding differs"));
                }
                let OriginalStageResponse::Input(original_ack) = response;
                if data.source_state != *tape.reference()
                    || data.inventory != input.inventory
                    || original_ack.proof_ref != data.source_acknowledgement
                    || original_ack.stage_operation != input.stage_operation
                    || original_ack.batch != input.batch
                    || original_ack.node != input.node
                    || original_ack.cutoff != input.cutoff
                    || original_ack.inventory != input.inventory
                    || original_ack.owners != tape.transcript().origin.route.owners
                {
                    return Err(refused(
                        "model ACK does not bind its exact signed original Stage",
                    ));
                }
                return bounded_copy(
                    &[
                        data.source_state,
                        data.source_acknowledgement,
                        data.inventory,
                    ],
                    maximum,
                );
            }
            if input.payloads.contains(reference) {
                // The fixed installed source codec authenticates these exact raw
                // payload bodies through the original native producer relation.
                if self
                    .profile
                    .history
                    .objects
                    .get(reference)
                    .map(Vec::as_slice)
                    != Some(bytes)
                {
                    return Err(refused(
                        "original input payload is not independently retained",
                    ));
                }
                return Ok(Vec::new());
            }
        }
        Err(refused(format!(
            "unsupported complete conditional body role: {reference:?}"
        )))
    }
}

impl CaptureEvidence for ConditionalCaptureFactory {
    fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, StateError> {
        if reference == &self.profile.host {
            use std::io::Read;

            if reference.length.get() > maximum as u64 {
                return Err(refused(
                    "installed host executable exceeds reconstruction object credit",
                ));
            }
            let file = std::fs::File::open("/proc/self/exe").map_err(refused)?;
            if file.metadata().map_err(refused)?.len() != reference.length.get() {
                return Err(refused("installed host executable extent changed"));
            }
            let length = usize::try_from(reference.length.get()).map_err(refused)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(
                    length
                        .checked_add(1)
                        .ok_or_else(|| refused("host extent overflow"))?,
                )
                .map_err(refused)?;
            file.take(reference.length.get() + 1)
                .read_to_end(&mut bytes)
                .map_err(refused)?;
            reference.verify(&bytes).map_err(refused)?;
            return Ok(bytes);
        }
        let bytes = self
            .profile
            .content
            .get(reference)
            .or_else(|| self.qualifications.get(reference))
            .ok_or_else(|| {
                refused(format!(
                    "installed conditional immutable body is absent: {reference:?}"
                ))
            })?;
        reference.verify(bytes).map_err(refused)?;
        bounded_bytes(bytes, maximum)
    }

    fn dependencies(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        maximum: usize,
    ) -> Result<Vec<ContentRef>, StateError> {
        self.dependencies_for(reference, bytes, maximum)
    }

    fn verify_owner_capture(
        &self,
        _: &AdmittedGraph,
        _: &CaptureManifest,
        _: &CapturedOwner,
        _: &StateRequirements,
        _: &VerifiedStateContent,
    ) -> Result<NativeOwnerCaptureProof, StateError> {
        Err(refused(
            "conditional Runtime7 cannot use legacy owner capture admission",
        ))
    }

    fn verify_coordinator_capture(
        &self,
        _: &AdmittedGraph,
        _: &CaptureManifest,
        _: &VerifiedStateContent,
    ) -> Result<NativeCoordinatorCaptureProof, StateError> {
        Err(refused(
            "conditional Runtime7 cannot use legacy coordinator admission",
        ))
    }
}

impl NativeWorldFactory for ConditionalCaptureFactory {
    fn authenticate_original_lineage_capture(
        &self,
        graph: &AdmittedGraph,
        runtime: &OriginalLineageRuntimeRecord,
        scheduler: &SchedulingSnapshot,
    ) -> Result<(), StateError> {
        // The once-only marker precedes source callbacks and all record copies.
        // A refusal or unwind retains this attempted original, never a retry.
        if self.attempted.replace(true) {
            return Err(refused("original signed capture was already attempted"));
        }
        authenticate(&self.profile, graph, runtime)?;
        authenticate_scheduler(&self.profile, runtime, scheduler)?;
        let mut accepted = self.accepted.try_borrow_mut().map_err(refused)?;
        if accepted.is_some() {
            return Err(refused("original signed capture was already attempted"));
        }
        // This tuple remains owned before the first native model callback. A
        // later refusal never authorizes a replacement capture or fresh dispatch.
        *accepted = Some(AcceptedCut {
            runtime: runtime.clone(),
            scheduler: scheduler.clone(),
        });
        Ok(())
    }

    fn original_lineage_capture_immutable_roots(
        &self,
        graph: &AdmittedGraph,
        runtime: &OriginalLineageRuntimeRecord,
        scheduler: &SchedulingSnapshot,
        maximum: usize,
    ) -> Result<Vec<ContentRef>, StateError> {
        // These are the already installed continuation obligations. Their
        // positive binding and enrollment rows must precede model callbacks.
        if maximum < 3
            || self.profile.bindings.len() != 3
            || self.continuation_qualifications.len() != 3
            || graph.world() != &self.profile.world
            || self
                .profile
                .bindings
                .iter()
                .any(|binding| graph.binding(&binding.compatibility.node_id) != Some(binding))
        {
            return Err(refused(
                "changed installed continuation root roster or credit",
            ));
        }
        let accepted = self.accepted.try_borrow().map_err(refused)?;
        let accepted = accepted
            .as_ref()
            .ok_or_else(|| refused("original source cut is absent"))?;
        if runtime != &accepted.runtime || scheduler != &accepted.scheduler {
            return Err(refused(
                "additional roots received a different original cut",
            ));
        }
        for binding in &self.profile.bindings {
            let reference = self
                .continuation_qualifications
                .get(&binding.compatibility.node_id)
                .ok_or_else(|| refused("installed continuation qualification is absent"))?;
            let bytes = self
                .qualifications
                .get(reference)
                .ok_or_else(|| refused("installed continuation qualification body is absent"))?;
            reference.verify(bytes).map_err(refused)?;
        }

        // Complete borrowed validation and fixed occurrence credit precede copies.
        let mut roots = Vec::new();
        roots.try_reserve_exact(3).map_err(refused)?;
        roots.extend(self.continuation_qualifications.values().cloned());
        roots.sort();
        if roots.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(refused("installed continuation roots are not distinct"));
        }
        Ok(roots)
    }

    fn original_lineage_capture_dependencies(
        &self,
        graph: &AdmittedGraph,
        reference: &ContentRef,
        bytes: &[u8],
        maximum: usize,
    ) -> Result<Vec<ContentRef>, StateError> {
        if graph.world() != &self.profile.world {
            return Err(refused(
                "dependency callback received a foreign durable world",
            ));
        }
        self.dependencies_for(reference, bytes, maximum)
    }

    fn authenticate_original_lineage_source(
        &self,
        graph: &AdmittedGraph,
        source: &AuthenticatedOriginalLineageSource<'_>,
    ) -> Result<(), StateError> {
        let accepted = self.accepted.try_borrow().map_err(refused)?;
        let accepted = accepted
            .as_ref()
            .ok_or_else(|| refused("original source cut is absent"))?;
        if source.runtime() != &accepted.runtime || source.scheduling() != &accepted.scheduler {
            return Err(refused(
                "signed source replaced the actual accepted runtime or scheduler",
            ));
        }
        authenticate(&self.profile, graph, source.runtime())?;
        authenticate_scheduler(&self.profile, source.runtime(), source.scheduling())?;
        let [node] = source.owner().participants.as_slice() else {
            return Err(refused(
                "conditional source has changed participant ownership",
            ));
        };
        let original = self
            .profile
            .history
            .originals
            .get(node)
            .ok_or_else(|| refused("original owning tape is absent"))?;
        let binding = self
            .profile
            .bindings
            .iter()
            .find(|binding| binding.compatibility.node_id == *node)
            .ok_or_else(|| refused("actual source-capture binding is absent"))?;
        let bytes = source.native()?;
        let view = decode_original_lineage_model_capture(
            &InputPayload {
                reference: source.owner().state.clone(),
                bytes: bounded_bytes(bytes, 8 * 1024 * 1024)?,
            },
            8 * 1024 * 1024,
        )
        .map_err(refused)?;
        let pending = crucible_node_contract::Id::new(format!("run/{node}/2")).map_err(refused)?;
        let begin = original
            .transcript()
            .records
            .iter()
            .position(|record| {
                record.request.action == TranscriptAction::Begin
                    && record.request.identity == pending
            })
            .ok_or_else(|| refused("signed original q2 Begin is absent"))?;
        if view.runtime() != source.runtime_reference()
            || view.binding() != binding
            || view.route().node != *node
            || view.route().owners.len() != 1
            || view.route().owners[0].owner != source.owner().owner
            || !self
                .profile
                .activation
                .owners
                .contains(&view.route().owners[0])
            || view.transcript() != original.reference()
            || view.cursor().diverged
            || view.cursor().next_record.get() != begin as u64 + 1
            || view.boundary() != source.runtime().capture_cut
        {
            return Err(refused(
                "model cursor, owner or pending original prefix changed",
            ));
        }
        if self.continuation_qualifications.get(node) != Some(view.qualification()) {
            return Err(refused(
                "model state substituted a different qualification obligation",
            ));
        }
        let expected = self
            .qualifications
            .get(view.qualification())
            .ok_or_else(|| {
                refused("model continuation qualification was not independently installed")
            })?;
        if source.content().get(view.qualification()) != Some(expected.as_slice()) {
            return Err(refused("signed continuation qualification bytes changed"));
        }
        let tape =
            authenticate_tape2_continuation(source, node).map_err(|error| refused(error.reason))?;
        if tape.transcript().reference() != original.reference()
            || tape.transcript().bytes() != original.bytes()
        {
            return Err(refused(
                "signed complete source replaced the original tape bytes",
            ));
        }
        Ok(())
    }

    fn authenticate_source(
        &self,
        _: &AdmittedGraph,
        _: &CapturedOwner,
        _: &AuthenticatedNativeSource<'_>,
    ) -> Result<(), StateError> {
        Err(refused("physical native source restoration is unsupported"))
    }

    fn authenticate_coordinator(
        &self,
        _: &AdmittedGraph,
        _: &RuntimeSnapshot,
        _: &SchedulingSnapshot,
        _: &VerifiedStateContent,
    ) -> Result<(), StateError> {
        Err(refused("legacy coordinator restoration is unsupported"))
    }

    fn reservation(
        &self,
        _: &AdmittedGraph,
        _: &CapturedOwner,
        _: &AuthenticatedNativeSource<'_>,
        _: NativeArchiveLimits,
    ) -> Result<RestoreReservations, StateError> {
        Err(refused(
            "physical reconstruction reservation is unsupported",
        ))
    }

    fn empty_staging(
        &self,
        _: Rc<AdmittedGraph>,
        _: NativeArchiveRecord,
        _: &ActivationRecord,
        _: RestoreReservations,
        _: NativeArchiveLimits,
    ) -> Result<Box<dyn NativeRestoreStaging>, StateError> {
        Err(refused("legacy native staging is unsupported"))
    }
}

fn bounded_copy(references: &[ContentRef], maximum: usize) -> Result<Vec<ContentRef>, StateError> {
    if references.len() > maximum {
        return Err(refused("typed dependency credit exhausted"));
    }
    let mut copied = Vec::new();
    copied
        .try_reserve_exact(references.len())
        .map_err(refused)?;
    copied.extend_from_slice(references);
    normalize(copied)
}

fn normalize(mut references: Vec<ContentRef>) -> Result<Vec<ContentRef>, StateError> {
    references.sort();
    references.dedup();
    Ok(references)
}

fn bounded_bytes(bytes: &[u8], maximum: usize) -> Result<Vec<u8>, StateError> {
    if bytes.len() > maximum {
        return Err(refused("typed original body byte credit exhausted"));
    }
    let mut copied = Vec::new();
    copied.try_reserve_exact(bytes.len()).map_err(refused)?;
    copied.extend_from_slice(bytes);
    Ok(copied)
}
