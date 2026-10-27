//! Delta-aware, bounded campaign closure walks.
//!
//! A walk authenticates every object reachable from its start entries except
//! anchors, which the caller proves are owned by an already authenticated
//! closure. Each object is read under its exact content ID and semantically
//! validated by its owning record codec before its children are trusted.
//!
//! Three rules keep resident state independent of campaign length:
//!
//! - A Merkle root is authenticated by a lazily advanced
//!   [`MerkleClosureCursor`] on the walk stack. The cursor retains only the
//!   unvisited siblings on its current path.
//! - An object may carry a *predecessor*: an object owned by the authenticated
//!   parent closure that it replaces, such as the prior value at the same trie
//!   key. Children shared with the predecessor are already covered and are not
//!   walked. A trie child paired by role with the predecessor's trie child is
//!   authenticated as a trie diff, so only changed node positions are read.
//! - An unanchored snapshot is never walked depth-first through its parent
//!   edges. Inside an inductive history walk it becomes an obligation that the
//!   history walk discharges when it reaches that ancestor, or validates on its
//!   own at the end. Elsewhere it is authenticated by its own history walk.
//!
//! The visited set lives only for one walk. When the inductive history walk
//! runs one walk per snapshot transition, it therefore holds one transition's
//! newly reachable objects at a time.

use crucible_store::content_envelope::ContentEnvelope;

use super::*;
use crate::merkle::MerkleClosureCursor;

/// Bounds one walk's retained visited objects plus traversed trie positions.
///
/// The inductive history walk resets this bound for every snapshot
/// transition, so it limits one transition's newly reachable objects, not the
/// campaign closure.
pub(in crate::repository) const MAX_CLOSURE_WALK_OBJECTS: usize = 64_000_000;

/// Receives each authenticated object and whether it is an exact raw leaf.
///
/// One object may be delivered more than once, and delivery order is
/// unspecified. Delivered identities are trustworthy only when the walk that
/// produced them returns `Ok`.
pub(in crate::repository) type ClosureSink<'a> =
    dyn FnMut(ContentId, bool) -> Result<(), CampaignRepositoryError> + 'a;

/// One pending unit of closure work.
pub(in crate::repository) enum WalkEntry {
    /// An object to authenticate, with an optional parent-owned predecessor.
    Object {
        id: ContentId,
        exact_leaf: bool,
        predecessor: Option<ContentId>,
    },
    /// A partially authenticated Merkle root.
    Trie(MerkleClosureCursor),
}

impl WalkEntry {
    pub(in crate::repository) const fn object(id: ContentId) -> Self {
        Self::Object {
            id,
            exact_leaf: false,
            predecessor: None,
        }
    }
}

/// Where one walk starts.
pub(in crate::repository) enum WalkStart<'a> {
    /// Ordinary entries; snapshots among them are delegated to history walks.
    Entries(Vec<WalkEntry>),
    /// One loaded snapshot whose own children are walked directly.
    ///
    /// The snapshot was already authenticated by [`CampaignRepository::read_snapshot`].
    /// With a predecessor, children shared with the parent snapshot are
    /// covered and paired roots are authenticated as trie diffs.
    Snapshot {
        loaded: &'a LoadedSnapshot,
        predecessor: Option<&'a LoadedSnapshot>,
    },
}

/// Shared policy and observers for one walk.
pub(in crate::repository) struct WalkContext<'w, 's> {
    pub(in crate::repository) anchors: &'w BTreeSet<ContentId>,
    /// Lets exact checkpoint roots grant raw-leaf traversal to their evidence.
    pub(in crate::repository) exact_roots: bool,
    pub(in crate::repository) choice_cache: &'w mut ChoiceValidationCache,
    pub(in crate::repository) planner_context: Option<&'w mut PlannerValidationContext>,
    pub(in crate::repository) sink: Option<&'w mut ClosureSink<'s>>,
    /// Collects unanchored snapshots for the enclosing history walk.
    ///
    /// Records that a transition makes reachable can name an older snapshot,
    /// such as the snapshot a savepoint request or a finding's exact
    /// retention expected. When that snapshot is an ancestor, the history
    /// walk authenticates its closure anyway when it reaches it.
    pub(in crate::repository) deferred_snapshots: Option<&'w mut BTreeSet<ContentId>>,
    /// The authenticated parent's accounting root, when walking a transition.
    ///
    /// A continuation attempt names its origin attempt. When the parent's
    /// `accounting.attempt` index binds that origin, the origin and its whole
    /// continuation chain are parent-owned and are not walked again.
    pub(in crate::repository) parent_accounting: Option<ContentId>,
    /// Raised to the largest resident entry total any walk with this context reached.
    pub(in crate::repository) peak_resident: usize,
}

/// Envelope whose role-tagged children an authenticated object exposes.
enum AuthenticatedChildren {
    None,
    Content {
        envelope: ContentEnvelope,
        exact_root: bool,
    },
    Record(ObjectEnvelope),
}

impl AuthenticatedChildren {
    fn children(&self) -> Vec<(&str, ContentId, bool)> {
        match self {
            Self::None => Vec::new(),
            Self::Content {
                envelope,
                exact_root,
            } => envelope
                .children()
                .iter()
                .map(|child| {
                    // Replay-closure frames are exact leaves like the
                    // closure root that names them.
                    let exact_leaf = *exact_root
                        && (matches!(
                            child.role(),
                            "checkpoint-choice-closure" | "replay-oracle-evidence"
                        ) || child.role().starts_with("checkpoint-choice-frame-"));
                    (child.role(), child.id(), exact_leaf)
                })
                .collect(),
            Self::Record(envelope) => envelope
                .children()
                .iter()
                .map(|child| (child.role(), child.id(), false))
                .collect(),
        }
    }
}

/// Visited set and work accounting for one walk.
struct WalkState {
    stack: Vec<WalkEntry>,
    visited: BTreeSet<(ContentId, bool)>,
    trie_positions: usize,
    /// Largest visited, trie-position, and pending-entry total observed.
    peak_resident: usize,
}

impl WalkState {
    fn charge_resident(&mut self) -> Result<(), CampaignRepositoryError> {
        let resident = self
            .visited
            .len()
            .saturating_add(self.trie_positions)
            .saturating_add(self.stack.len());
        self.peak_resident = self.peak_resident.max(resident);
        if self
            .visited
            .len()
            .checked_add(self.trie_positions)
            .is_none_or(|objects| objects > MAX_CLOSURE_WALK_OBJECTS)
        {
            return Err(integrity("campaign-closure-object-limit"));
        }
        Ok(())
    }

    fn total(&self) -> Result<usize, CampaignRepositoryError> {
        self.visited
            .len()
            .checked_add(self.trie_positions)
            .ok_or_else(|| integrity("campaign-closure-object-limit"))
    }
}

impl CampaignRepository {
    /// Authenticates every object reachable from `start` except anchors.
    ///
    /// Returns a conservative count of the objects this walk authenticated:
    /// visited objects plus traversed trie positions. A snapshot's own history
    /// walk counts that snapshot's closure.
    ///
    /// # Errors
    ///
    /// Returns original store, codec, closure-bound, child, record, or trie
    /// integrity errors; cached tuples never replace fresh byte authentication.
    pub(in crate::repository) fn walk_campaign_closure(
        &self,
        start: WalkStart<'_>,
        context: &mut WalkContext<'_, '_>,
    ) -> Result<usize, CampaignRepositoryError> {
        let mut state = WalkState {
            stack: Vec::new(),
            visited: BTreeSet::new(),
            trie_positions: 0,
            peak_resident: 0,
        };
        match start {
            WalkStart::Entries(entries) => state.stack = entries,
            WalkStart::Snapshot {
                loaded,
                predecessor,
            } => {
                let id = loaded.envelope.content_id();
                state.visited.insert((id, false));
                emit(context, id, false)?;
                let children = loaded
                    .envelope
                    .children()
                    .iter()
                    .map(|child| (child.role(), child.id(), false))
                    .collect::<Vec<_>>();
                let predecessor = predecessor.map(|parent| {
                    parent
                        .envelope
                        .children()
                        .iter()
                        .map(|child| (child.role(), child.id()))
                        .collect::<Vec<_>>()
                });
                self.push_children(&mut state, context, &children, predecessor.as_deref())?;
            }
        }

        while let Some(entry) = state.stack.pop() {
            match entry {
                WalkEntry::Trie(cursor) => self.advance_trie(&mut state, context, cursor)?,
                WalkEntry::Object {
                    id,
                    exact_leaf,
                    predecessor,
                } => {
                    if context.anchors.contains(&id) || !state.visited.insert((id, exact_leaf)) {
                        continue;
                    }
                    state.charge_resident()?;
                    emit(context, id, exact_leaf)?;
                    self.walk_object(&mut state, context, id, exact_leaf, predecessor)?;
                }
            }
        }
        context.peak_resident = context.peak_resident.max(state.peak_resident);
        state.total()
    }

    fn walk_object(
        &self,
        state: &mut WalkState,
        context: &mut WalkContext<'_, '_>,
        id: ContentId,
        exact_leaf: bool,
        predecessor: Option<ContentId>,
    ) -> Result<(), CampaignRepositoryError> {
        if id.kind() == ObjectKind::MerkleNode && !exact_leaf {
            state
                .stack
                .push(WalkEntry::Trie(self.merkle.closure_cursor(id)?));
            return Ok(());
        }
        if id.kind() == ObjectKind::CampaignSnapshot && !exact_leaf {
            // A depth-first walk through parent edges would retain the whole
            // history; the inductive walk retains one transition at a time.
            match context.deferred_snapshots.as_deref_mut() {
                Some(deferred) => {
                    deferred.insert(id);
                }
                None => self.delegated_snapshot_closure(id, context.sink.as_deref_mut())?,
            }
            return Ok(());
        }

        let authenticated = self.authenticate_closure_object(
            id,
            exact_leaf,
            context.exact_roots,
            context.choice_cache,
            context.planner_context.as_deref_mut(),
        )?;
        let mut children = authenticated.children();
        if let Some(origin) = self.parent_owned_origin(&authenticated, &children, context)? {
            children.retain(|&(_, child, _)| child != origin);
        }
        let predecessor = predecessor.map(|predecessor| self.predecessor_children(predecessor));
        let predecessor = predecessor.as_ref().map(|children| {
            children
                .iter()
                .map(|(role, id)| (role.as_str(), *id))
                .collect::<Vec<_>>()
        });
        self.push_children(state, context, &children, predecessor.as_deref())
    }

    /// Returns an attempt's origin when the parent's accounting index binds it.
    fn parent_owned_origin(
        &self,
        authenticated: &AuthenticatedChildren,
        children: &[(&str, ContentId, bool)],
        context: &WalkContext<'_, '_>,
    ) -> Result<Option<ContentId>, CampaignRepositoryError> {
        let (AuthenticatedChildren::Record(envelope), Some(accounting)) =
            (authenticated, context.parent_accounting)
        else {
            return Ok(None);
        };
        if envelope.record_kind() != crate::CampaignRecordKind::Attempt {
            return Ok(None);
        }
        let Some(&(_, origin, _)) = children.iter().find(|(role, ..)| *role == "origin-attempt")
        else {
            return Ok(None);
        };
        let key = map_key_content("accounting.attempt", origin);
        Ok((self.merkle.get(accounting, key)? == Some(origin)).then_some(origin))
    }

    fn advance_trie(
        &self,
        state: &mut WalkState,
        context: &mut WalkContext<'_, '_>,
        mut cursor: MerkleClosureCursor,
    ) -> Result<(), CampaignRepositoryError> {
        let Some(step) = self.merkle.advance_closure_cursor(&mut cursor)? else {
            return Ok(());
        };
        state.trie_positions = state
            .trie_positions
            .checked_add(1)
            .ok_or_else(|| integrity("campaign-closure-object-limit"))?;
        state.charge_resident()?;
        emit(context, step.node, false)?;

        // Values are pushed above the cursor so the walk finishes them before
        // reading the next node, keeping the stack bounded by trie depth.
        state.stack.push(WalkEntry::Trie(cursor));
        for value in step.values.into_iter().rev() {
            if context.anchors.contains(&value) {
                // An anchored leaf is not walked again, but this trie must
                // still bind a present object.
                if !self.blobs.contains(value)? {
                    return Err(StoreError::NotFound { id: value }.into());
                }
                continue;
            }
            state.stack.push(WalkEntry::object(value));
        }
        Ok(())
    }

    /// Pushes children, skipping and diffing against a covered predecessor.
    ///
    /// Every predecessor child is owned by the authenticated parent closure.
    /// A shared child is therefore covered. A trie child paired by unique role
    /// with a predecessor trie is authenticated by reading only its changed
    /// positions; other role-paired children carry the predecessor's child as
    /// their own predecessor.
    fn push_children(
        &self,
        state: &mut WalkState,
        context: &mut WalkContext<'_, '_>,
        children: &[(&str, ContentId, bool)],
        predecessor: Option<&[(&str, ContentId)]>,
    ) -> Result<(), CampaignRepositoryError> {
        let Some(predecessor) = predecessor else {
            state.stack.extend(
                children
                    .iter()
                    .map(|&(_, id, exact_leaf)| WalkEntry::Object {
                        id,
                        exact_leaf,
                        predecessor: None,
                    }),
            );
            return Ok(());
        };

        let covered = predecessor
            .iter()
            .map(|&(_, id)| id)
            .collect::<BTreeSet<_>>();
        let paired_role = |role: &str| -> Option<ContentId> {
            let mut matches = predecessor.iter().filter(|(other, _)| *other == role);
            let (_, id) = matches.next()?;
            matches.next().is_none().then_some(*id)
        };

        // Unpaired children are pushed first so paired children, and the
        // values their diffs expose, are walked first. A record that both a
        // trie diff and a fresh transition reach is then paired, not rewalked.
        let mut paired = Vec::new();
        for &(role, id, exact_leaf) in children {
            if covered.contains(&id) || context.anchors.contains(&id) {
                continue;
            }
            let unique = children.iter().filter(|(other, ..)| *other == role).count() == 1;
            match paired_role(role).filter(|_| unique && !exact_leaf) {
                Some(prior) => paired.push((id, prior)),
                None => state.stack.push(WalkEntry::Object {
                    id,
                    exact_leaf,
                    predecessor: None,
                }),
            }
        }
        for (id, prior) in paired {
            if id.kind() == ObjectKind::MerkleNode && prior.kind() == ObjectKind::MerkleNode {
                self.push_trie_diff(state, context, prior, id)?;
            } else {
                state.stack.push(WalkEntry::Object {
                    id,
                    exact_leaf: false,
                    predecessor: Some(prior),
                });
            }
        }
        Ok(())
    }

    /// Authenticates the changed positions of `next` relative to `prior`.
    fn push_trie_diff(
        &self,
        state: &mut WalkState,
        context: &mut WalkContext<'_, '_>,
        prior: ContentId,
        next: ContentId,
    ) -> Result<(), CampaignRepositoryError> {
        if !state.visited.insert((next, false)) {
            return Ok(());
        }
        let mut positions = BTreeSet::new();
        let mut roots = BTreeSet::new();
        let mut values = BTreeMap::new();
        self.merkle.collect_changed_node_positions(
            prior,
            next,
            &mut positions,
            &mut roots,
            &mut values,
            MAX_CLOSURE_WALK_OBJECTS,
        )?;

        // Changed nested roots are complete here; an unpaired path to one of
        // them later must not rewalk its whole trie.
        for root in roots {
            state.visited.insert((root, false));
        }
        state.trie_positions = state
            .trie_positions
            .checked_add(positions.len())
            .ok_or_else(|| integrity("campaign-closure-object-limit"))?;
        state.charge_resident()?;
        emit(context, next, false)?;
        for (node, _prefix) in positions {
            emit(context, node, false)?;
        }
        state.stack.extend(
            values
                .into_iter()
                .map(|(id, predecessor)| WalkEntry::Object {
                    id,
                    exact_leaf: false,
                    predecessor,
                }),
        );
        Ok(())
    }

    /// Reads the role-tagged children of a parent-owned predecessor.
    ///
    /// Pairing only skips work that the parent closure already covers, so it
    /// never weakens authentication. A predecessor that is opaque, a trie, or
    /// unreadable as an envelope under its exact ID simply disables pairing,
    /// and every child of the new object is then walked in full.
    fn predecessor_children(&self, predecessor: ContentId) -> Vec<(String, ContentId)> {
        if is_opaque_campaign_leaf(predecessor.kind())
            || predecessor.kind() == ObjectKind::MerkleNode
        {
            return Vec::new();
        }
        self.read_predecessor_children(predecessor)
            .unwrap_or_default()
    }

    fn read_predecessor_children(
        &self,
        predecessor: ContentId,
    ) -> Result<Vec<(String, ContentId)>, CampaignRepositoryError> {
        let bytes = self
            .blobs
            .read(predecessor, None)?
            .read_all(MAX_ENVELOPE_BYTES)?;
        if is_campaign_record_kind(predecessor.kind()) {
            let envelope = ObjectEnvelope::from_canonical_bytes(&bytes)?;
            if envelope.content_id() != predecessor {
                return Err(integrity("campaign-closure-envelope-id-mismatch"));
            }
            return Ok(envelope
                .children()
                .iter()
                .map(|child| (child.role().to_owned(), child.id()))
                .collect());
        }
        let envelope =
            ContentEnvelope::from_canonical_bytes(&bytes).map_err(CampaignCodecError::from)?;
        if envelope.content_id(predecessor.kind()) != predecessor {
            return Err(integrity("campaign-closure-envelope-id-mismatch"));
        }
        Ok(envelope
            .children()
            .iter()
            .map(|child| (child.role().to_owned(), child.id()))
            .collect())
    }

    /// Authenticates one non-trie object and returns its child table.
    ///
    /// Semantic reuse never anchors or skips a closure object: its original
    /// bytes and children are authenticated on this fresh read.
    fn authenticate_closure_object(
        &self,
        id: ContentId,
        exact_leaf: bool,
        exact_roots: bool,
        choice_cache: &mut ChoiceValidationCache,
        planner_context: Option<&mut PlannerValidationContext>,
    ) -> Result<AuthenticatedChildren, CampaignRepositoryError> {
        let handle = self.blobs.read(id, None)?;
        if exact_leaf {
            // Exact-root choice and replay evidence use Observation identities
            // for raw protocol bytes. Their parent role, not their kind alone,
            // grants opaque traversal; the immutable digest remains checked.
            if id.kind() != ObjectKind::Observation
                || id.schema_version() != 1
                || ContentId::for_source(id.kind(), id.schema_version(), &handle)? != id
            {
                return Err(integrity("campaign-exact-leaf-identity-mismatch"));
            }
            return Ok(AuthenticatedChildren::None);
        }
        if is_opaque_campaign_leaf(id.kind()) {
            let mut sink = std::io::sink();
            handle.copy_to(&mut sink)?;
            return Ok(AuthenticatedChildren::None);
        }
        let bytes = handle.read_all(MAX_ENVELOPE_BYTES)?;
        if !is_campaign_record_kind(id.kind()) {
            let envelope =
                ContentEnvelope::from_canonical_bytes(&bytes).map_err(CampaignCodecError::from)?;
            if envelope.content_id(id.kind()) != id {
                return Err(integrity("campaign-closure-envelope-id-mismatch"));
            }
            let exact_root = exact_roots
                && id.kind() == ObjectKind::ExactManifest
                && envelope.schema_name() == "crucible.executor.exact-checkpoint-root"
                && envelope.schema_version() == 5;
            return Ok(AuthenticatedChildren::Content {
                envelope,
                exact_root,
            });
        }
        let envelope = ObjectEnvelope::from_canonical_bytes(&bytes)?;
        if envelope.content_id() != id {
            return Err(integrity("campaign-closure-envelope-id-mismatch"));
        }
        self.validate_closure_record(id, &envelope, choice_cache, planner_context)?;
        Ok(AuthenticatedChildren::Record(envelope))
    }

    fn validate_closure_record(
        &self,
        id: ContentId,
        envelope: &ObjectEnvelope,
        choice_cache: &mut ChoiceValidationCache,
        planner_context: Option<&mut PlannerValidationContext>,
    ) -> Result<(), CampaignRepositoryError> {
        match envelope.record_kind() {
            crate::CampaignRecordKind::Lineage => {
                self.read_lineage(id)?;
            }
            crate::CampaignRecordKind::Policy => {
                self.read_policy(id)?;
            }
            crate::CampaignRecordKind::Fact => {
                self.read_fact_with_planner_context(id, planner_context)?;
            }
            crate::CampaignRecordKind::CandidateGeneratorSpec => {
                self.read_generator(id)?;
            }
            crate::CampaignRecordKind::ScenarioArtifact => {
                self.read_scenario_artifact(id)?;
            }
            crate::CampaignRecordKind::ConfigurationArtifact => {
                self.read_configuration_artifact(id)?;
            }
            crate::CampaignRecordKind::ReproductionArtifact => {
                self.read_reproduction_artifact(id)?;
            }
            crate::CampaignRecordKind::Finding => {
                self.read_finding_cached(id, choice_cache)?;
            }
            crate::CampaignRecordKind::FindingCandidateBundle => {
                let bundle = self.decode_finding_candidate_bundle(id)?;
                self.validate_finding_candidate_bundle(
                    &bundle,
                    super::finding_candidate::FindingCandidateValidation::Load,
                )?;
            }
            crate::CampaignRecordKind::FindingTriageReplayEvidence => {
                let evidence = self.decode_finding_triage_replay_evidence(id)?;
                self.validate_finding_triage_replay_evidence(&evidence)?;
            }
            crate::CampaignRecordKind::BranchRequest => {
                let request = self.decode_branch_request(id)?;
                self.validate_branch_request_references_shallow(&request)?;
            }
            crate::CampaignRecordKind::Proposal => {
                let proposal = self.decode_proposal(id)?;
                self.validate_proposal_references_shallow(&proposal)?;
            }
            crate::CampaignRecordKind::Attempt => {
                self.read_attempt_cached(id, choice_cache)?;
            }
            crate::CampaignRecordKind::AttemptAdmission => {
                let admission = self.decode_attempt_admission(id)?;
                self.validate_attempt_admission_references_shallow_cached(
                    &admission,
                    choice_cache,
                )?;
            }
            crate::CampaignRecordKind::PlannerStep => {
                self.read_planner_step_with_context(id, planner_context)?;
            }
            crate::CampaignRecordKind::RetainedPlannerRequest => {
                self.read_planner_request_with_context(id, planner_context)?;
            }
            crate::CampaignRecordKind::ExpansionState => {
                self.read_expansion_state(id)?;
            }
            crate::CampaignRecordKind::ContinuationProjection => {
                self.read_continuation_projection(id)?;
            }
            crate::CampaignRecordKind::ExpansionCredit => {
                self.read_expansion_credit(id)?;
            }
            crate::CampaignRecordKind::MeasurementSet => {
                self.read_measurement_set(id)?;
            }
            crate::CampaignRecordKind::PropertyVerdictSet => {
                self.read_property_verdict_set(id)?;
            }
            crate::CampaignRecordKind::CoverageProjection => {
                self.read_coverage_projection(id)?;
            }
            crate::CampaignRecordKind::CoverageIdentityFrequency => {
                self.read_coverage_identity_frequency(id)?;
            }
            crate::CampaignRecordKind::Observation => {
                let observation = self.decode_observation(id)?;
                self.validate_observation_references_cached(&observation, choice_cache)?;
            }
            crate::CampaignRecordKind::ObjectiveEvaluation => {
                self.read_objective_evaluation_cached(id, choice_cache)?;
            }
            crate::CampaignRecordKind::RankingExplanation => {
                self.read_ranking_explanation_cached(id, choice_cache)?;
            }
            crate::CampaignRecordKind::SurvivorSelection => {
                self.read_survivor_selection_bundle_cached(id, choice_cache)?;
            }
            crate::CampaignRecordKind::PolicyArtifact => {
                self.validate_policy_artifact_references(envelope)?;
            }
            crate::CampaignRecordKind::PlannerState => {
                self.validate_planner_state_references(envelope)?;
            }
            crate::CampaignRecordKind::PlannerInvocation => {
                self.validate_planner_invocation_references(envelope)?;
            }
            crate::CampaignRecordKind::ChoiceOpportunity => {
                self.validate_opportunity_references_cached(envelope, choice_cache)?;
            }
            crate::CampaignRecordKind::ChoiceGroup => {
                self.validate_group_references(envelope)?;
            }
            crate::CampaignRecordKind::Selection => {
                self.validate_selection_references(envelope)?;
            }
            _ => {}
        }
        Ok(())
    }
}

fn emit(
    context: &mut WalkContext<'_, '_>,
    id: ContentId,
    exact_leaf: bool,
) -> Result<(), CampaignRepositoryError> {
    match context.sink.as_deref_mut() {
        Some(sink) => sink(id, exact_leaf),
        None => Ok(()),
    }
}
