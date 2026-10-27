//! Streaming version-10 corpus mutation over the direct-selection index.
//!
//! Version 10 orders candidates by ascending anchor value, then by legal-step
//! distance, trying the lower neighbor before the upper one, and omits values
//! outside the domain or already emitted. A request proposes the first
//! candidate in that order that it has not already proposed, looking only at
//! the first `maximum_proposals` candidates.
//!
//! The owner reads anchors from the observation root's direct-selection index
//! (see `repository::observation::direct_selection`), which yields each
//! direct child of the branch point in ascending value order. Because both
//! the anchor order and the candidate window are monotone, the walk stops at
//! the first unproposed candidate or at the window limit without reading the
//! remaining anchors. Retained state is one index page plus the emitted
//! candidate offsets, which are bounded by the proposal window.
//!
//! [`CorpusMutationWalk`] skips over runs of already emitted offsets instead
//! of probing every distance, so its work is proportional to anchors visited
//! plus candidates emitted rather than to `anchors * maximum_distance`.

use super::*;

/// Direct-selection index entries authenticated per page.
const DIRECT_SELECTION_PAGE_ITEMS: usize = 4_096;

/// Outcome of feeding one anchor to a [`CorpusMutationWalk`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::repository) enum CorpusMutationStep {
    /// Later anchors may still produce an unproposed candidate.
    Continue,
    /// The first candidate in version-10 order that the request has not proposed.
    Found(IntegerValue),
    /// The candidate window filled without an unproposed candidate.
    Exhausted,
}

/// Exact version-10 candidate order consumed one ascending anchor at a time.
pub(in crate::repository) struct CorpusMutationWalk<'a> {
    domain: &'a IntegerDomain,
    maximum_distance: u128,
    maximum_candidates: usize,
    emitted_count: usize,
    emitted: LatticeRuns,
    previous_anchor: Option<IntegerValue>,
}

impl<'a> CorpusMutationWalk<'a> {
    /// Starts a walk after enforcing the version-10 owner bounds.
    pub(in crate::repository) fn new(
        domain: &'a IntegerDomain,
        maximum_distance: u64,
        maximum_candidates: usize,
    ) -> Result<Self, CampaignRepositoryError> {
        if maximum_distance == 0
            || maximum_distance > crate::CORPUS_MUTATION_GENERATOR_MAX_DISTANCE
            || maximum_candidates == 0
            || maximum_candidates > crate::CORPUS_MUTATION_GENERATOR_MAX_PROPOSALS as usize
        {
            return Err(integrity("corpus-mutation-generator-owner-limit"));
        }
        Ok(Self {
            domain,
            maximum_distance: u128::from(maximum_distance),
            maximum_candidates,
            emitted_count: 0,
            emitted: LatticeRuns::default(),
            previous_anchor: None,
        })
    }

    /// Emits the candidates contributed by the next anchor.
    ///
    /// Anchors must arrive in ascending order. An anchor equal to its
    /// predecessor contributes nothing, matching the version-10 deduplicated
    /// anchor set.
    pub(in crate::repository) fn visit(
        &mut self,
        anchor: IntegerValue,
        is_proposed: impl Fn(IntegerValue) -> bool,
    ) -> Result<CorpusMutationStep, CampaignRepositoryError> {
        match self.previous_anchor {
            Some(previous) if anchor == previous => return Ok(CorpusMutationStep::Continue),
            Some(previous) if anchor < previous => {
                return Err(integrity("corpus-mutation-anchor-order-mismatch"));
            }
            _ => {}
        }
        self.previous_anchor = Some(anchor);

        let offset = integer_candidate_offset(self.domain, anchor)?;
        let last = self
            .domain
            .cardinality()
            .checked_sub(1)
            .ok_or_else(|| integrity("candidate-source-cardinality-overflow"))?;

        // Neighbors leave the domain monotonically, so distance `k` has an
        // in-domain lower value exactly when `k <= lower_reach`, and likewise
        // for the upper side. The reference walk stops at the first distance
        // where both sides are outside the domain.
        let lower_reach = self.maximum_distance.min(offset);
        let upper_reach = self.maximum_distance.min(last - offset);

        let mut distance = 1_u128;
        loop {
            let lower = (distance <= lower_reach)
                .then(|| self.emitted.unemitted_at_or_below(offset - distance))
                .flatten()
                .map(|candidate| offset - candidate)
                .filter(|reach| *reach <= lower_reach);
            let upper = (distance <= upper_reach)
                .then(|| self.emitted.unemitted_at_or_above(offset + distance))
                .flatten()
                .map(|candidate| candidate - offset)
                .filter(|reach| *reach <= upper_reach);
            let next = match (lower, upper) {
                (None, None) => return Ok(CorpusMutationStep::Continue),
                (Some(lower), None) => lower,
                (None, Some(upper)) => upper,
                (Some(lower), Some(upper)) => lower.min(upper),
            };

            if lower == Some(next) {
                let step = self.emit(offset - next, &is_proposed)?;
                if step != CorpusMutationStep::Continue {
                    return Ok(step);
                }
            }
            if upper == Some(next) {
                let step = self.emit(offset + next, &is_proposed)?;
                if step != CorpusMutationStep::Continue {
                    return Ok(step);
                }
            }
            distance = next + 1;
        }
    }

    fn emit(
        &mut self,
        offset: u128,
        is_proposed: &impl Fn(IntegerValue) -> bool,
    ) -> Result<CorpusMutationStep, CampaignRepositoryError> {
        let candidate = integer_candidate_at_offset(self.domain, offset)?;
        self.emitted.insert(offset);
        self.emitted_count += 1;

        if !is_proposed(candidate) {
            return Ok(CorpusMutationStep::Found(candidate));
        }
        if self.emitted_count == self.maximum_candidates {
            return Ok(CorpusMutationStep::Exhausted);
        }
        Ok(CorpusMutationStep::Continue)
    }
}

/// Disjoint, non-adjacent inclusive runs of emitted lattice offsets.
#[derive(Default)]
struct LatticeRuns {
    runs: BTreeMap<u128, u128>,
}

impl LatticeRuns {
    fn containing(&self, offset: u128) -> Option<(u128, u128)> {
        self.runs
            .range(..=offset)
            .next_back()
            .filter(|(_, end)| **end >= offset)
            .map(|(start, end)| (*start, *end))
    }

    fn unemitted_at_or_below(&self, offset: u128) -> Option<u128> {
        match self.containing(offset) {
            // Runs are maximal, so the offset just below a run is unemitted.
            Some((start, _)) => start.checked_sub(1),
            None => Some(offset),
        }
    }

    fn unemitted_at_or_above(&self, offset: u128) -> Option<u128> {
        match self.containing(offset) {
            Some((_, end)) => end.checked_add(1),
            None => Some(offset),
        }
    }

    fn insert(&mut self, offset: u128) {
        if self.containing(offset).is_some() {
            return;
        }
        let mut start = offset;
        let mut end = offset;
        if let Some((prior_start, _)) = offset
            .checked_sub(1)
            .and_then(|below| self.containing(below))
        {
            self.runs.remove(&prior_start);
            start = prior_start;
        }
        if let Some(following_end) = offset
            .checked_add(1)
            .and_then(|above| self.runs.remove(&above))
        {
            end = following_end;
        }
        self.runs.insert(start, end);
    }
}

fn walk_result(step: CorpusMutationStep) -> Option<Option<ChoiceValue>> {
    match step {
        CorpusMutationStep::Continue => None,
        CorpusMutationStep::Found(value) => Some(Some(ChoiceValue::Integer(value))),
        CorpusMutationStep::Exhausted => Some(None),
    }
}

impl CampaignRepository {
    /// Returns the first version-10 candidate that `proposed` does not contain.
    ///
    /// `additional_selection` names a just-completed branch selection that is
    /// not yet published in `view`; it joins the anchors when it belongs to
    /// the request's branch point.
    pub(super) fn first_unproposed_corpus_mutation(
        &self,
        request: &BranchRequest,
        domain: &ChoiceDomain,
        view: CandidateViewRoots,
        additional_selection: Option<SelectionId>,
        proposed: &BTreeSet<ChoiceValue>,
    ) -> Result<Option<ChoiceValue>, CampaignRepositoryError> {
        let (integer, maximum_distance) = self.corpus_mutation_basis(request, domain)?;
        let maximum_candidates = usize::try_from(request.budget().maximum_proposals())
            .map_err(|_| integrity("corpus-mutation-generator-proposal-limit"))?;
        let mut walk = CorpusMutationWalk::new(integer, maximum_distance, maximum_candidates)?;
        let is_proposed = |value: IntegerValue| proposed.contains(&ChoiceValue::Integer(value));

        let mut pending_additional = match additional_selection {
            Some(selection) => self.additional_corpus_anchor(request, selection)?,
            None => None,
        };

        let index = self
            .merkle
            .get(view.observations, direct_selection_index_anchor_key())?
            .ok_or_else(|| integrity("current-campaign-direct-selection-index-is-missing"))?;
        if let Some(branch_root) = self.merkle.get(
            index,
            direct_selection_index_branch_key(request.branch_point()),
        )? {
            let mut after = None;
            loop {
                let page = self
                    .merkle
                    .scan(branch_root, after, DIRECT_SELECTION_PAGE_ITEMS)?;
                for anchor in self.direct_selection_page_anchors(request, view, page.entries())? {
                    if let Some(additional) = pending_additional.filter(|value| *value < anchor) {
                        pending_additional = None;
                        if let Some(result) = walk_result(walk.visit(additional, is_proposed)?) {
                            return Ok(result);
                        }
                    }
                    if let Some(result) = walk_result(walk.visit(anchor, is_proposed)?) {
                        return Ok(result);
                    }
                }
                let Some(next) = page.next_after() else {
                    break;
                };
                after = Some(next);
            }
        }

        if let Some(additional) = pending_additional
            && let Some(result) = walk_result(walk.visit(additional, is_proposed)?)
        {
            return Ok(result);
        }
        Ok(None)
    }

    fn corpus_mutation_basis<'a>(
        &self,
        request: &BranchRequest,
        domain: &'a ChoiceDomain,
    ) -> Result<(&'a IntegerDomain, u64), CampaignRepositoryError> {
        let generator = request
            .source()
            .generator()
            .ok_or_else(|| integrity("candidate-source-kind-is-invalid"))?;
        let spec = self.read_generator(generator.content_id())?;
        let (
            CandidateGeneratorAlgorithm::MutateNearCorpus { maximum_distance },
            crate::CORPUS_MUTATION_GENERATOR_IMPLEMENTATION_VERSION,
            ChoiceDomain::Integer(integer),
        ) = (spec.algorithm(), spec.implementation_version(), domain)
        else {
            return Err(integrity("corpus-mutation-generator-basis-mismatch"));
        };
        if *maximum_distance > crate::CORPUS_MUTATION_GENERATOR_MAX_DISTANCE
            || request.budget().maximum_proposals() > crate::CORPUS_MUTATION_GENERATOR_MAX_PROPOSALS
        {
            return Err(integrity("corpus-mutation-generator-owner-limit"));
        }
        Ok((integer, *maximum_distance))
    }

    /// Authenticates one direct-selection index page and returns its anchors.
    ///
    /// Each entry must name a retained observation whose branch attempt
    /// realized exactly the keyed selection at the request's branch point.
    fn direct_selection_page_anchors(
        &self,
        request: &BranchRequest,
        view: CandidateViewRoots,
        entries: &[(CampaignHash, ContentId)],
    ) -> Result<Vec<IntegerValue>, CampaignRepositoryError> {
        let mut input_bytes = 0_usize;
        let mut selections = Vec::with_capacity(entries.len());
        for (_, content) in entries {
            let observation = self.decode_observation(*content)?;
            input_bytes =
                charge_corpus_mutation_input(input_bytes, observation.canonical_bytes().len())?;
            if self.merkle.get(
                view.corpus,
                map_key_hash("corpus.configuration", observation.child().as_hash()),
            )? != Some(observation.child_content().content_id())
            {
                return Err(integrity("corpus-mutation-observation-is-not-retained"));
            }

            let attempt = self.read_attempt(observation.attempt().content_id())?;
            input_bytes =
                charge_corpus_mutation_input(input_bytes, attempt.canonical_bytes().len())?;
            let AttemptStart::Branch { selection, .. } = attempt.start() else {
                return Err(integrity("corpus-mutation-direct-selection-index-mismatch"));
            };
            selections.push(selection);
        }

        let mut resolver = self.selection_resolver();
        let mut anchors = Vec::with_capacity(entries.len());
        for ((key, _), selection_id) in entries.iter().zip(&selections) {
            let resolved = resolver.resolve(*selection_id)?;
            let selection = resolved.selection();
            if !matches!(
                selection.origin(),
                crate::SelectionOrigin::CampaignBranch { branch_point, .. }
                    if branch_point == request.branch_point()
            ) {
                return Err(integrity("corpus-mutation-direct-selection-index-mismatch"));
            }
            let value = corpus_mutation_anchor_value(request, selection)?;
            if *key != direct_selection_index_order_key(value, *selection_id) {
                return Err(integrity("corpus-mutation-direct-selection-index-mismatch"));
            }
            anchors.push(value);
        }
        Ok(anchors)
    }

    fn additional_corpus_anchor(
        &self,
        request: &BranchRequest,
        selection: SelectionId,
    ) -> Result<Option<IntegerValue>, CampaignRepositoryError> {
        let resolved = self.resolve_selection(selection)?;
        let crate::SelectionOrigin::CampaignBranch { branch_point, .. } =
            resolved.selection().origin()
        else {
            return Err(integrity("corpus-mutation-selection-origin-mismatch"));
        };
        if branch_point != request.branch_point() {
            return Ok(None);
        }
        corpus_mutation_anchor_value(request, resolved.selection()).map(Some)
    }
}

fn corpus_mutation_anchor_value(
    request: &BranchRequest,
    selection: &Selection,
) -> Result<IntegerValue, CampaignRepositoryError> {
    if selection.opportunity() != request.opportunity() || selection.domain() != request.domain() {
        return Err(integrity("corpus-mutation-selection-basis-mismatch"));
    }
    let ChoiceValue::Integer(value) = selection.value() else {
        return Err(integrity("corpus-mutation-selection-is-not-integer"));
    };
    Ok(*value)
}

pub(in crate::repository) fn charge_corpus_mutation_input(
    prior: usize,
    bytes: usize,
) -> Result<usize, CampaignRepositoryError> {
    let total = prior
        .checked_add(bytes)
        .ok_or_else(|| integrity("corpus-mutation-generator-input-byte-limit"))?;
    if total > crate::CORPUS_MUTATION_GENERATOR_MAX_INPUT_BYTES {
        return Err(integrity("corpus-mutation-generator-input-byte-limit"));
    }
    Ok(total)
}

#[cfg(test)]
mod tests;
