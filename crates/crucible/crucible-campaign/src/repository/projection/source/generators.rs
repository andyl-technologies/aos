//! Static generator replay under the caller's explicit read authority.

use super::*;

impl ClosureSemanticRead<'_, '_> {
    pub(super) fn weighted_categorical_candidates(
        &mut self,
        request: &BranchRequest,
        domain: &crate::DiscreteDomain,
        weights: &BTreeMap<crate::AlternativeId, u64>,
    ) -> Result<Vec<crate::AlternativeId>, CampaignRepositoryError> {
        if weights.len() > crate::WEIGHTED_CATEGORICAL_GENERATOR_MAX_ALTERNATIVES {
            return Err(integrity("weighted-generator-alternative-limit"));
        }
        if weights
            .keys()
            .any(|alternative| !domain.alternatives().contains_key(alternative))
        {
            return Err(integrity(
                "candidate-generator-discrete-alternative-mismatch",
            ));
        }

        let request_digest = request.id()?.content_id().digest();
        let mut remaining = weights
            .iter()
            .map(|(alternative, weight)| (*alternative, *weight))
            .collect_admitted(self)?;
        let mut candidates = Vec::new();
        while !remaining.is_empty() {
            self.poll()?;
            let total_weight = remaining.iter().try_fold(0_u128, |total, (_, weight)| {
                total
                    .checked_add(u128::from(*weight))
                    .ok_or_else(|| integrity("weighted-generator-weight-sum-overflow"))
            })?;
            let draw = weighted_categorical_draw(
                request_digest,
                u64::try_from(candidates.len())
                    .map_err(|_| integrity("candidate-source-cardinality-overflow"))?,
                total_weight,
            )?;
            let mut cumulative = 0_u128;
            let mut selected = None;
            for (index, (_, weight)) in remaining.iter().enumerate() {
                cumulative = cumulative
                    .checked_add(u128::from(*weight))
                    .ok_or_else(|| integrity("weighted-generator-weight-sum-overflow"))?;
                if draw < cumulative {
                    selected = Some(index);
                    break;
                }
            }
            let selected =
                selected.ok_or_else(|| integrity("weighted-generator-draw-is-out-of-range"))?;
            self.push(&mut candidates, remaining.remove(selected).0)?;
        }
        Ok(candidates)
    }

    pub(super) fn ordered_mixture_candidates(
        &mut self,
        request: &BranchRequest,
        domain: &ChoiceDomain,
        components: &[crate::WeightedGenerator],
    ) -> Result<Option<Vec<ChoiceValue>>, CampaignRepositoryError> {
        let mut remaining_work = crate::ORDERED_MIXTURE_GENERATOR_MAX_WORK_ITEMS;
        self.ordered_mixture_candidates_with_budget(
            request,
            domain,
            components,
            0,
            &mut remaining_work,
        )
    }

    pub(super) fn ordered_mixture_candidates_with_budget(
        &mut self,
        request: &BranchRequest,
        domain: &ChoiceDomain,
        components: &[crate::WeightedGenerator],
        depth: usize,
        remaining_work: &mut usize,
    ) -> Result<Option<Vec<ChoiceValue>>, CampaignRepositoryError> {
        if depth > crate::ORDERED_MIXTURE_GENERATOR_MAX_DEPTH {
            return Err(integrity("ordered-mixture-generator-depth-limit"));
        }
        let mut states = Vec::new();
        for component in components {
            let Some(values) = self.bounded_static_generator_candidates(
                request,
                domain,
                component.generator(),
                depth + 1,
                remaining_work,
            )?
            else {
                return Ok(None);
            };
            self.push(
                &mut states,
                MixtureComponentState {
                    values,
                    cursor: 0,
                    weight: component.weight(),
                },
            )?;
        }

        let mut emitted = BTreeSet::new();
        let mut candidates = Vec::new();
        while let Some(selected) = next_mixture_component(&states)? {
            self.poll()?;
            charge_mixture_work(remaining_work, 1)?;
            let state = &mut states[selected];
            let value = state
                .values
                .get(state.cursor)
                .ok_or_else(|| integrity("ordered-mixture-cursor-is-invalid"))?
                .clone_admitted()?;
            state.cursor += 1;
            if !self.insert_set(&mut emitted, value.clone_admitted()?)? {
                continue;
            }
            if candidates.len() == crate::ORDERED_MIXTURE_GENERATOR_MAX_CANDIDATES {
                return Err(integrity("ordered-mixture-generator-candidate-limit"));
            }
            self.push(&mut candidates, value)?;
        }
        Ok(Some(candidates))
    }

    pub(super) fn bounded_static_generator_candidates(
        &mut self,
        request: &BranchRequest,
        domain: &ChoiceDomain,
        generator: CandidateGeneratorSpecId,
        depth: usize,
        remaining_work: &mut usize,
    ) -> Result<Option<Vec<ChoiceValue>>, CampaignRepositoryError> {
        if depth > crate::ORDERED_MIXTURE_GENERATOR_MAX_DEPTH {
            return Err(integrity("ordered-mixture-generator-depth-limit"));
        }
        let spec = self.read_generator(generator.content_id())?;
        let values = match (spec.algorithm(), spec.implementation_version(), domain) {
            (
                CandidateGeneratorAlgorithm::All,
                crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Boolean(_),
            ) => [ChoiceValue::Boolean(false), ChoiceValue::Boolean(true)]
                .into_iter()
                .collect_admitted(self)?,
            (
                CandidateGeneratorAlgorithm::All,
                crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Discrete(discrete),
            ) => {
                require_mixture_work_capacity(remaining_work, discrete.alternatives().len())?;
                discrete
                    .alternatives()
                    .keys()
                    .copied()
                    .map(ChoiceValue::Discrete)
                    .collect_admitted(self)?
            }
            (
                CandidateGeneratorAlgorithm::All,
                crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) => {
                let count = integer
                    .cardinality()
                    .min(u128::from(request.budget().maximum_proposals()));
                let count = usize::try_from(count)
                    .map_err(|_| integrity("ordered-mixture-generator-work-limit"))?;
                require_mixture_work_capacity(remaining_work, count)?;
                (0..count)
                    .map(|offset| {
                        integer_candidate_at_offset(integer, offset as u128)
                            .map(ChoiceValue::Integer)
                    })
                    .try_collect_admitted(self)?
            }
            (
                CandidateGeneratorAlgorithm::BoundaryInteger,
                crate::BOUNDARY_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) => self
                .boundary_integer_candidates(request, integer)?
                .into_iter()
                .map(ChoiceValue::Integer)
                .collect_admitted(self)?,
            (
                CandidateGeneratorAlgorithm::StratifiedInteger { strata },
                crate::STRATIFIED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) => {
                let count = stratified_integer_candidate_count(*strata, integer)?;
                let count = usize::try_from(count)
                    .map_err(|_| integrity("ordered-mixture-generator-work-limit"))?;
                require_mixture_work_capacity(remaining_work, count)?;
                (1..=count)
                    .map(|ordinal| {
                        let ordinal = u64::try_from(ordinal)
                            .map_err(|_| integrity("ordered-mixture-generator-work-limit"))?;
                        stratified_integer_candidate(*strata, integer, ordinal)
                            .map(ChoiceValue::Integer)
                    })
                    .try_collect_admitted(self)?
            }
            (
                CandidateGeneratorAlgorithm::LogInteger { base },
                crate::LOG_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) => log_integer_candidates(*base, integer)?
                .into_iter()
                .map(ChoiceValue::Integer)
                .collect_admitted(self)?,
            (
                CandidateGeneratorAlgorithm::WeightedCategorical { weights },
                crate::WEIGHTED_CATEGORICAL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Discrete(discrete),
            ) => self
                .weighted_categorical_candidates(request, discrete, weights)?
                .into_iter()
                .map(ChoiceValue::Discrete)
                .collect_admitted(self)?,
            (
                CandidateGeneratorAlgorithm::OrderedMixture { components },
                crate::ORDERED_MIXTURE_GENERATOR_IMPLEMENTATION_VERSION,
                _,
            ) => {
                return self.ordered_mixture_candidates_with_budget(
                    request,
                    domain,
                    components,
                    depth,
                    remaining_work,
                );
            }
            (
                CandidateGeneratorAlgorithm::WeightedCategorical { .. },
                crate::WEIGHTED_CATEGORICAL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Boolean(_) | ChoiceDomain::Integer(_),
            )
            | (
                CandidateGeneratorAlgorithm::BoundaryInteger,
                crate::BOUNDARY_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Boolean(_) | ChoiceDomain::Discrete(_),
            )
            | (
                CandidateGeneratorAlgorithm::StratifiedInteger { .. },
                crate::STRATIFIED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Boolean(_) | ChoiceDomain::Discrete(_),
            )
            | (
                CandidateGeneratorAlgorithm::LogInteger { .. },
                crate::LOG_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Boolean(_) | ChoiceDomain::Discrete(_),
            )
            | (
                CandidateGeneratorAlgorithm::PermutedInteger,
                crate::PERMUTED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Boolean(_) | ChoiceDomain::Discrete(_),
            ) => return Err(integrity("candidate-generator-domain-family-mismatch")),
            _ => return Ok(None),
        };
        charge_mixture_work(remaining_work, values.len())?;
        Ok(Some(values))
    }

    pub(super) fn boundary_integer_candidates(
        &mut self,
        request: &BranchRequest,
        domain: &IntegerDomain,
    ) -> Result<Vec<IntegerValue>, CampaignRepositoryError> {
        if domain.landmarks().len() > crate::BOUNDARY_INTEGER_GENERATOR_MAX_LANDMARKS {
            return Err(integrity("boundary-generator-landmark-limit"));
        }
        let opportunity = self.read_opportunity(request.opportunity().content_id())?;
        let ChoiceValue::Integer(default) = opportunity.default() else {
            return Err(integrity("boundary-generator-default-is-not-integer"));
        };
        let mut values = Vec::new();
        let mut seen = BTreeSet::new();
        push_static_integer_candidate(&mut values, &mut seen, domain, domain.minimum())?;
        push_static_integer_candidate(&mut values, &mut seen, domain, domain.maximum())?;
        push_static_integer_candidate(&mut values, &mut seen, domain, *default)?;
        for landmark in domain.landmarks() {
            push_static_integer_candidate(&mut values, &mut seen, domain, *landmark)?;
        }

        let anchors = values.iter().copied().collect_admitted(self)?;
        for anchor in anchors {
            if let Some(lower) = integer_step_neighbor(anchor, domain.step(), false) {
                push_static_integer_candidate(&mut values, &mut seen, domain, lower)?;
            }
            if let Some(upper) = integer_step_neighbor(anchor, domain.step(), true) {
                push_static_integer_candidate(&mut values, &mut seen, domain, upper)?;
            }
        }

        match domain.representation() {
            IntegerRepresentation::Unsigned64 => {
                for exponent in 0..64 {
                    if let Some(value) = 1_u64.checked_shl(exponent) {
                        push_static_integer_candidate(
                            &mut values,
                            &mut seen,
                            domain,
                            IntegerValue::Unsigned(value),
                        )?;
                    }
                }
            }
            IntegerRepresentation::Signed64 => {
                for exponent in 0..64 {
                    if exponent < 63 {
                        push_static_integer_candidate(
                            &mut values,
                            &mut seen,
                            domain,
                            IntegerValue::Signed(1_i64 << exponent),
                        )?;
                    }
                    let negative = if exponent == 63 {
                        i64::MIN
                    } else {
                        -(1_i64 << exponent)
                    };
                    push_static_integer_candidate(
                        &mut values,
                        &mut seen,
                        domain,
                        IntegerValue::Signed(negative),
                    )?;
                }
            }
        }
        Ok(values)
    }
}
