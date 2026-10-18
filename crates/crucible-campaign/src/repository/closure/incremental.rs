//! Incremental campaign closure authentication.

use super::*;

impl CampaignRepository {
    pub(super) fn incremental_closure_anchors(
        &self,
        parent: &LoadedSnapshot,
        transition: ContentId,
    ) -> Result<BTreeSet<ContentId>, CampaignRepositoryError> {
        let fact = self.read_fact(transition)?;
        self.incremental_closure_anchors_for_fact(parent, &fact)
    }

    /// Returns exact parent-owned anchors for one already decoded transition.
    ///
    /// # Errors
    ///
    /// Returns original store, codec, or index errors while proving that a
    /// fact-specific anchor is bound by the parent.
    pub(super) fn incremental_closure_anchors_for_fact(
        &self,
        parent: &LoadedSnapshot,
        fact: &CampaignFact,
    ) -> Result<BTreeSet<ContentId>, CampaignRepositoryError> {
        let mut anchors = self.authenticated_head_closure_anchors(parent)?;
        let roots = parent.snapshot.roots();
        match fact.clone() {
            CampaignFact::CampaignDerived(_) => {}
            CampaignFact::BranchRequestAccepted {
                request: request_id,
                ..
            } => {
                let request = self.decode_branch_request(request_id.content_id())?;
                if let BranchRequestCause::Planner(invocation) = request.cause()
                    && self
                        .merkle
                        .get(
                            roots.coordination,
                            planner_invocation_result_key(invocation),
                        )?
                        .is_some()
                {
                    anchors.insert(invocation.content_id());
                }
            }
            CampaignFact::ProposalIssued(proposal_id) => {
                let proposal = self.decode_proposal(proposal_id.content_id())?;
                let request = proposal.request().content_id();
                if self.merkle.get(
                    roots.exploration,
                    map_key_content("exploration.branch-request", request),
                )? == Some(request)
                {
                    anchors.insert(request);
                }
                if let Some(invocation) = proposal.planner_invocation()
                    && self
                        .merkle
                        .get(
                            roots.coordination,
                            planner_invocation_result_key(invocation),
                        )?
                        .is_some()
                {
                    anchors.insert(invocation.content_id());
                }
            }
            CampaignFact::AttemptAdmitted(admission_id) => {
                let admission = self.decode_attempt_admission(admission_id.content_id())?;
                let proposal = match admission.role() {
                    AttemptAdmissionRole::ExecutionBasis {
                        proposal: Some(proposal),
                        ..
                    }
                    | AttemptAdmissionRole::AdditionalCause { proposal } => Some(proposal),
                    AttemptAdmissionRole::ExecutionBasis { proposal: None, .. } => None,
                };
                if let Some(proposal) = proposal {
                    let proposal = proposal.content_id();
                    if self.merkle.get(
                        roots.exploration,
                        map_key_content("exploration.proposal", proposal),
                    )? == Some(proposal)
                    {
                        anchors.insert(proposal);
                    }
                }
            }
            CampaignFact::PlannerAdvanced(step_id) => {
                let envelope = self.require_record_kind(
                    step_id.content_id(),
                    crate::CampaignRecordKind::PlannerStep,
                )?;
                let step = PlannerStep::from_canonical_bytes(envelope.body())?;
                if step.id()? != step_id {
                    return Err(integrity("planner-step-envelope-shape"));
                }
                let (_, invocation) =
                    self.decode_planner_invocation(step.invocation().content_id())?;
                let mut sources = invocation
                    .scan_page()
                    .positions()
                    .iter()
                    .map(|position| position.source().content_id())
                    .collect::<BTreeSet<_>>();
                if let Some(after) = invocation.scan_page().after() {
                    sources.insert(after.source().content_id());
                }
                for source in sources {
                    if self.merkle.get(
                        roots.exploration,
                        map_key_content("exploration.branch-request", source),
                    )? == Some(source)
                    {
                        anchors.insert(source);
                    }
                }
            }
            CampaignFact::ObservationCredited(observation_id) => {
                let observation = self.decode_observation(observation_id.content_id())?;
                let attempt = observation.attempt().content_id();
                if self.merkle.get(
                    roots.accounting,
                    map_key_content("accounting.attempt", attempt),
                )? == Some(attempt)
                {
                    anchors.insert(attempt);
                }
            }
            CampaignFact::ObjectiveEvaluationPublished(evaluation_id) => {
                let evaluation = self.read_objective_evaluation(evaluation_id.content_id())?;
                anchors.insert(evaluation.observation().content_id());
            }
            CampaignFact::AttemptClosed { attempt, .. } => {
                let attempt = attempt.content_id();
                if self.merkle.get(
                    roots.accounting,
                    map_key_content("accounting.attempt", attempt),
                )? == Some(attempt)
                {
                    anchors.insert(attempt);
                }
            }
            // A resolution or selection names earlier savepoint facts. Each one
            // that the parent's accounting index already binds is parent-owned,
            // and with it the older snapshot that its request expected.
            CampaignFact::SavepointCaptureResolved(resolution) => {
                self.anchor_indexed_fact(
                    &mut anchors,
                    roots.accounting,
                    savepoint_capture_request_key(resolution.request),
                    resolution.request,
                )?;
            }
            CampaignFact::SavepointContinuationSelected(selection) => {
                self.anchor_indexed_fact(
                    &mut anchors,
                    roots.accounting,
                    savepoint_capture_request_key(selection.request),
                    selection.request,
                )?;
                self.anchor_indexed_fact(
                    &mut anchors,
                    roots.accounting,
                    savepoint_capture_resolution_key(selection.request),
                    selection.ready,
                )?;
            }
            CampaignFact::ChoiceOpportunityDiscovered { .. }
            | CampaignFact::ControlRequested(_)
            | CampaignFact::FindingPublished(_)
            | CampaignFact::PolicyActivated(_)
            | CampaignFact::BudgetGranted(_)
            | CampaignFact::PinChanged(_)
            | CampaignFact::PinCommandAccepted(_)
            | CampaignFact::DiscoveryRequested(_) => {}
            CampaignFact::SavepointCaptureRequested(request) => {
                let attempt = request.attempt.content_id();
                if self.merkle.get(
                    roots.accounting,
                    map_key_content("accounting.attempt", attempt),
                )? == Some(attempt)
                {
                    anchors.insert(attempt);
                }
            }
        }
        Ok(anchors)
    }

    /// Anchors a fact only when the parent's index binds exactly that fact.
    fn anchor_indexed_fact(
        &self,
        anchors: &mut BTreeSet<ContentId>,
        index: ContentId,
        key: CampaignHash,
        fact: CampaignFactId,
    ) -> Result<(), CampaignRepositoryError> {
        let fact = fact.content_id();
        if self.merkle.get(index, key)? == Some(fact) {
            anchors.insert(fact);
        }
        Ok(())
    }

    pub(in crate::repository) fn verify_campaign_closure_anchored(
        &self,
        root: ContentId,
        anchors: &BTreeSet<ContentId>,
    ) -> Result<usize, CampaignRepositoryError> {
        self.verify_campaign_closures_anchored_cached(
            [root],
            anchors,
            &mut ChoiceValidationCache::default(),
        )
    }

    /// Authenticates one transition's closure relative to its parent.
    ///
    /// Besides the exact anchors, origin attempts bound by the parent's
    /// accounting index are covered.
    ///
    /// # Errors
    ///
    /// Returns original store, codec, closure-bound, child, record, or trie
    /// integrity errors.
    pub(in crate::repository) fn verify_transition_closure_anchored(
        &self,
        transition: ContentId,
        anchors: &BTreeSet<ContentId>,
        parent: &LoadedSnapshot,
    ) -> Result<usize, CampaignRepositoryError> {
        self.walk_campaign_closure(
            WalkStart::Entries(vec![WalkEntry::object(transition)]),
            &mut WalkContext {
                anchors,
                exact_roots: false,
                choice_cache: &mut ChoiceValidationCache::default(),
                planner_context: None,
                sink: None,
                deferred_snapshots: None,
                parent_accounting: Some(parent.snapshot.roots().accounting),
                peak_resident: 0,
            },
        )
    }

    /// Authenticates and returns every unique object in the supplied closures.
    ///
    /// The returned set includes Merkle nodes, Merkle leaf values, generic
    /// content envelopes, campaign records, and opaque leaves. A snapshot's
    /// closure is authenticated by complete inductive history validation.
    /// This operation performs no writes and does not trust child references
    /// until the enclosing object has authenticated under its exact content ID.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRepositoryError`] when any root or descendant is
    /// missing, corrupt, semantically invalid, or one closure walk exceeds its
    /// resident object bound.
    pub fn authenticated_closure_ids(
        &self,
        roots: impl IntoIterator<Item = ContentId>,
    ) -> Result<BTreeSet<ContentId>, CampaignRepositoryError> {
        let mut objects = BTreeSet::new();
        self.visit_authenticated_closure_ids(roots, &mut |id| {
            objects.insert(id);
        })?;
        Ok(objects)
    }

    /// Authenticates the supplied closures and passes every object to `visit`.
    ///
    /// This is [`Self::authenticated_closure_ids`] without the collected set,
    /// for callers that stream the closure into bounded or external storage.
    /// An object may be passed more than once and in no particular order. The
    /// visited identities are trustworthy only when the call returns `Ok`;
    /// after an error the caller must discard everything it was passed. A
    /// snapshot's history is authenticated one transition at a time, so the
    /// traversal's own resident state does not grow with campaign length.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRepositoryError`] when any root or descendant is
    /// missing, corrupt, semantically invalid, or one closure walk exceeds its
    /// resident object bound.
    pub fn visit_authenticated_closure_ids(
        &self,
        roots: impl IntoIterator<Item = ContentId>,
        visit: &mut dyn FnMut(ContentId),
    ) -> Result<(), CampaignRepositoryError> {
        self.walk_campaign_closures(
            roots,
            &BTreeSet::new(),
            false,
            &mut ChoiceValidationCache::default(),
            Some(&mut |id, _exact_leaf| {
                visit(id);
                Ok(())
            }),
        )?;
        Ok(())
    }

    pub(in crate::repository) fn verify_campaign_closures_anchored_cached(
        &self,
        roots: impl IntoIterator<Item = ContentId>,
        anchors: &BTreeSet<ContentId>,
        choice_cache: &mut ChoiceValidationCache,
    ) -> Result<usize, CampaignRepositoryError> {
        self.walk_campaign_closures(roots, anchors, false, choice_cache, None)
    }

    /// Walks ordinary roots as one bounded union.
    ///
    /// # Errors
    ///
    /// Returns original store, codec, closure-bound, child, record, or trie
    /// integrity errors, or the first error returned by `sink`.
    pub(in crate::repository) fn walk_campaign_closures(
        &self,
        roots: impl IntoIterator<Item = ContentId>,
        anchors: &BTreeSet<ContentId>,
        exact_roots: bool,
        choice_cache: &mut ChoiceValidationCache,
        sink: Option<&mut ClosureSink<'_>>,
    ) -> Result<usize, CampaignRepositoryError> {
        let entries = roots.into_iter().map(WalkEntry::object).collect();
        self.walk_campaign_closure(
            WalkStart::Entries(entries),
            &mut WalkContext {
                anchors,
                exact_roots,
                choice_cache,
                planner_context: None,
                sink,
                deferred_snapshots: None,
                parent_accounting: None,
                peak_resident: 0,
            },
        )
    }
}
