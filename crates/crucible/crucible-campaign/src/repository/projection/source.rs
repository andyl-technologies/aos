//! Candidate source profiles and immutable prefix replay over explicit readers.

use super::*;

mod expected;
mod generators;

/// Collects candidate replay outputs after paying each geometric vector growth.
trait AdmittedValues: Iterator + Sized {
    fn collect_admitted(
        self,
        reader: &mut ClosureSemanticRead<'_, '_>,
    ) -> Result<Vec<Self::Item>, CampaignRepositoryError> {
        let mut values = Vec::new();
        for value in self {
            reader.poll()?;
            reader.push(&mut values, value)?;
        }
        Ok(values)
    }

    fn try_collect_admitted<T, E>(
        self,
        reader: &mut ClosureSemanticRead<'_, '_>,
    ) -> Result<Vec<T>, CampaignRepositoryError>
    where
        Self: Iterator<Item = Result<T, E>>,
        E: Into<CampaignRepositoryError>,
    {
        let mut values = Vec::new();
        for value in self {
            reader.poll()?;
            reader.push(&mut values, value.map_err(Into::into)?)?;
        }
        Ok(values)
    }
}

impl<I: Iterator> AdmittedValues for I {}

impl ClosureSemanticRead<'_, '_> {
    pub(in crate::repository) fn candidate_source_profile(
        &mut self,
        request: &BranchRequest,
        domain: &ChoiceDomain,
    ) -> Result<Option<CandidateSourceProfile>, CampaignRepositoryError> {
        let _operation = self.enter_operation();
        if let Some(count) = self.static_candidate_count(request, domain)? {
            let proposal_budget_covers_domain =
                domain.cardinality() <= u128::from(request.budget().maximum_proposals());
            let modeled_source = matches!(request.source(), CandidateSource::ModeledGenerated(_));
            let budget_bounded_generator = if let Some(generator) = request.source().generator() {
                let spec = self.read_generator(generator.content_id())?;
                matches!(
                    (domain, spec.algorithm(), spec.implementation_version()),
                    (
                        ChoiceDomain::Integer(_),
                        CandidateGeneratorAlgorithm::All,
                        crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION
                    ) | (
                        ChoiceDomain::Group(_),
                        CandidateGeneratorAlgorithm::GroupProgressive { .. },
                        crate::GROUP_PROGRESSIVE_GENERATOR_IMPLEMENTATION_VERSION
                    )
                )
            } else {
                false
            };
            let exhausts_domain =
                if matches!(domain, ChoiceDomain::Group(_)) && budget_bounded_generator {
                    false
                } else {
                    (!modeled_source && !budget_bounded_generator) || proposal_budget_covers_domain
                };
            return Ok(Some(CandidateSourceProfile::Static {
                count,
                exhausts_domain,
            }));
        }
        let Some(generator) = request.source().generator() else {
            return Ok(None);
        };
        let spec = self.read_generator(generator.content_id())?;
        if let (
            CandidateGeneratorAlgorithm::MutateNearCorpus { maximum_distance },
            crate::CORPUS_MUTATION_GENERATOR_IMPLEMENTATION_VERSION,
            ChoiceDomain::Integer(_),
        ) = (spec.algorithm(), spec.implementation_version(), domain)
        {
            if *maximum_distance > crate::CORPUS_MUTATION_GENERATOR_MAX_DISTANCE {
                return Err(integrity("corpus-mutation-generator-distance-limit"));
            }
            if request.budget().maximum_proposals() > crate::CORPUS_MUTATION_GENERATOR_MAX_PROPOSALS
            {
                return Err(integrity("corpus-mutation-generator-proposal-limit"));
            }
            return Ok(Some(CandidateSourceProfile::CorpusMutation));
        }
        if matches!(
            (spec.algorithm(), spec.implementation_version(), domain),
            (
                CandidateGeneratorAlgorithm::MutateNearCorpus { .. },
                crate::CORPUS_MUTATION_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Boolean(_) | ChoiceDomain::Discrete(_),
            )
        ) {
            return Err(integrity("candidate-generator-domain-family-mismatch"));
        }

        let (
            CandidateGeneratorAlgorithm::ProgressiveInteger {
                initial_strata,
                feedback_interval,
            },
            crate::PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
            ChoiceDomain::Integer(integer),
        ) = (spec.algorithm(), spec.implementation_version(), domain)
        else {
            return Ok(None);
        };
        if *initial_strata > crate::PROGRESSIVE_INTEGER_GENERATOR_MAX_INITIAL_STRATA {
            return Err(integrity("progressive-generator-initial-strata-limit"));
        }
        if request.budget().maximum_proposals() > crate::PROGRESSIVE_INTEGER_GENERATOR_MAX_PROPOSALS
        {
            return Err(integrity("progressive-generator-proposal-limit"));
        }

        let budget = request.budget().maximum_proposals();
        let cardinality = integer.cardinality();
        let count = u64::try_from(cardinality.min(u128::from(budget)))
            .map_err(|_| integrity("candidate-source-cardinality-overflow"))?;
        let initial_count = count.min(u64::from(*initial_strata));
        count
            .checked_sub(initial_count)
            .and_then(|refinements| refinements.checked_mul(*feedback_interval))
            .ok_or_else(|| integrity("progressive-generator-feedback-threshold-overflow"))?;
        Ok(Some(CandidateSourceProfile::ProgressiveInteger {
            count,
            initial_count,
            feedback_interval: *feedback_interval,
            exhausts_domain: cardinality <= u128::from(budget),
        }))
    }

    pub(in crate::repository) fn static_candidate_count(
        &mut self,
        request: &BranchRequest,
        domain: &ChoiceDomain,
    ) -> Result<Option<u64>, CampaignRepositoryError> {
        let _operation = self.enter_operation();
        if matches!(
            request.source(),
            CandidateSource::StatisticalFinite(_) | CandidateSource::StatisticalSmc(_)
        ) {
            return Ok(Some(1));
        }
        if let Some(values) = request.source().finite_values() {
            return u64::try_from(values.len())
                .map(Some)
                .map_err(|_| integrity("candidate-source-cardinality-overflow"));
        }

        let generator = request
            .source()
            .generator()
            .ok_or_else(|| integrity("candidate-source-kind-is-invalid"))?;
        let spec = self.read_generator(generator.content_id())?;
        match (spec.algorithm(), spec.implementation_version(), domain) {
            (
                CandidateGeneratorAlgorithm::All,
                crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Boolean(_),
            ) => Ok(Some(2)),
            (
                CandidateGeneratorAlgorithm::All,
                crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Discrete(discrete),
            ) => u64::try_from(discrete.alternatives().len())
                .map(Some)
                .map_err(|_| integrity("candidate-source-cardinality-overflow")),
            (
                CandidateGeneratorAlgorithm::All,
                crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Group(group),
            ) => match group.domain() {
                crate::ChoiceGroupDomain::Finite { tuples, .. } => u64::try_from(tuples.len())
                    .map(Some)
                    .map_err(|_| integrity("candidate-source-cardinality-overflow")),
                crate::ChoiceGroupDomain::Cartesian { .. } => Err(integrity(
                    "Cartesian group requires a bounded group generator",
                )),
            },
            (
                CandidateGeneratorAlgorithm::GroupProgressive { maximum_proposals },
                crate::GROUP_PROGRESSIVE_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Group(group),
            ) => {
                if group.supports_progressive_generation_checked(*maximum_proposals, &mut || {
                    self.poll()
                })? {
                    Ok(Some(
                        u64::from(*maximum_proposals).min(request.budget().maximum_proposals()),
                    ))
                } else {
                    Ok(None)
                }
            }
            (
                CandidateGeneratorAlgorithm::WeightedCategorical { weights },
                crate::WEIGHTED_CATEGORICAL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Discrete(discrete),
            ) => u64::try_from(
                self.weighted_categorical_candidates(request, discrete, weights)?
                    .len(),
            )
            .map(Some)
            .map_err(|_| integrity("candidate-source-cardinality-overflow")),
            (
                CandidateGeneratorAlgorithm::OrderedMixture { components },
                crate::ORDERED_MIXTURE_GENERATOR_IMPLEMENTATION_VERSION,
                _,
            ) => self
                .ordered_mixture_candidates(request, domain, components)?
                .map(|candidates| {
                    u64::try_from(candidates.len())
                        .map_err(|_| integrity("candidate-source-cardinality-overflow"))
                })
                .transpose(),
            (
                CandidateGeneratorAlgorithm::All,
                crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) => u64::try_from(
                integer
                    .cardinality()
                    .min(u128::from(request.budget().maximum_proposals())),
            )
            .map(Some)
            .map_err(|_| integrity("candidate-source-cardinality-overflow")),
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
            ) => Err(integrity("candidate-generator-domain-family-mismatch")),
            (
                CandidateGeneratorAlgorithm::BoundaryInteger,
                crate::BOUNDARY_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) => u64::try_from(self.boundary_integer_candidates(request, integer)?.len())
                .map(Some)
                .map_err(|_| integrity("candidate-source-cardinality-overflow")),
            (
                CandidateGeneratorAlgorithm::StratifiedInteger { strata },
                crate::STRATIFIED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) => stratified_integer_candidate_count(*strata, integer).map(Some),
            (
                CandidateGeneratorAlgorithm::LogInteger { base },
                crate::LOG_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) => u64::try_from(log_integer_candidates(*base, integer)?.len())
                .map(Some)
                .map_err(|_| integrity("candidate-source-cardinality-overflow")),
            (
                CandidateGeneratorAlgorithm::PermutedInteger,
                crate::PERMUTED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) if matches!(request.source(), CandidateSource::ModeledGenerated(_)) => {
                modeled_uniform_integer_candidate_count(request, integer).map(Some)
            }
            _ => Ok(None),
        }
    }

    pub(in crate::repository) fn static_candidate_at(
        &mut self,
        request: &BranchRequest,
        domain: &ChoiceDomain,
        ordinal: u64,
    ) -> Result<Option<ChoiceValue>, CampaignRepositoryError> {
        let _operation = self.enter_operation();
        if ordinal == 0 {
            return Err(integrity("proposal-ordinal-is-not-canonical"));
        }
        if let CandidateSource::StatisticalFinite(source) = request.source() {
            if ordinal != 1 {
                return Err(integrity("proposal-ordinal-exceeds-source-cardinality"));
            }
            let BranchRequestCause::Planner(invocation_id) = request.cause() else {
                return Err(integrity("statistical-request-cause-is-not-planner"));
            };
            let invocation = self.read_planner_invocation(invocation_id)?;
            let policy = self.read_policy(invocation.policy().content_id())?;
            let design = policy
                .statistical_sampling_design()
                .ok_or_else(|| integrity("statistical-policy-lacks-sampling-design"))?;
            let draw_plan = design
                .draw(source.coordinate())
                .ok_or_else(|| integrity("statistical-request-coordinate-is-not-planned"))?;
            let distribution = design
                .distributions()
                .get(&draw_plan.model())
                .ok_or_else(|| integrity("statistical-request-model-is-not-planned"))?;
            if source.model() != draw_plan.model()
                || source.target_masses() != distribution.target_masses()
                || source.proposal_masses() != distribution.proposal_masses()
            {
                return Err(integrity("statistical-request-distribution-mismatch"));
            }
            let draw = weighted_categorical_draw(
                invocation.policy().content_id().digest(),
                source.coordinate(),
                u128::from(source.proposal_total()),
            )?;
            let mut cumulative = 0_u128;
            for (value, mass) in source.proposal_masses() {
                cumulative = cumulative
                    .checked_add(u128::from(*mass))
                    .ok_or_else(|| integrity("statistical-proposal-mass-sum-overflow"))?;
                if draw < cumulative {
                    return Ok(Some(value.clone_admitted()?));
                }
            }
            return Err(integrity("statistical-proposal-draw-is-out-of-range"));
        }
        if let CandidateSource::StatisticalSmc(source) = request.source() {
            if ordinal != 1 {
                return Err(integrity("proposal-ordinal-exceeds-source-cardinality"));
            }
            let BranchRequestCause::Planner(invocation_id) = request.cause() else {
                return Err(integrity("SMC request cause is not a planner"));
            };
            let invocation = self.read_planner_invocation(invocation_id)?;
            let policy = self.read_policy(invocation.policy().content_id())?;
            let design = policy
                .sequential_monte_carlo_design()
                .ok_or_else(|| integrity("SMC policy lacks a design"))?;
            let stage = design
                .stage(source.stage())
                .ok_or_else(|| integrity("SMC request stage is not planned"))?;
            let distribution = design
                .distributions()
                .get(&stage.selector().model())
                .ok_or_else(|| integrity("SMC request model is not planned"))?;
            if source.model() != stage.selector().model()
                || source.target_masses() != distribution.target_masses()
                || source.proposal_masses() != distribution.proposal_masses()
            {
                return Err(integrity("SMC request distribution mismatch"));
            }
            let draw = smc_weighted_categorical_draw(
                invocation.policy().content_id().digest(),
                source.stage(),
                source.slot(),
                u128::from(source.proposal_total()),
            )?;
            let mut cumulative = 0_u128;
            for (value, mass) in source.proposal_masses() {
                cumulative = cumulative
                    .checked_add(u128::from(*mass))
                    .ok_or_else(|| integrity("SMC proposal mass sum overflow"))?;
                if draw < cumulative {
                    return Ok(Some(value.clone_admitted()?));
                }
            }
            return Err(integrity("SMC proposal draw is out of range"));
        }
        if let Some(values) = request.source().finite_values() {
            return values
                .iter()
                .nth(candidate_index(ordinal)?)
                .map(ChoiceValue::clone_admitted)
                .transpose()?
                .map(Some)
                .ok_or_else(|| integrity("proposal-ordinal-exceeds-source-cardinality"));
        }

        let generator = request
            .source()
            .generator()
            .ok_or_else(|| integrity("candidate-source-kind-is-invalid"))?;
        let spec = self.read_generator(generator.content_id())?;
        match (spec.algorithm(), spec.implementation_version(), domain) {
            (
                CandidateGeneratorAlgorithm::All,
                crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Boolean(_),
            ) => match ordinal {
                1 => Ok(Some(ChoiceValue::Boolean(false))),
                2 => Ok(Some(ChoiceValue::Boolean(true))),
                _ => Err(integrity("proposal-ordinal-exceeds-source-cardinality")),
            },
            (
                CandidateGeneratorAlgorithm::All,
                crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Discrete(discrete),
            ) => discrete
                .alternatives()
                .keys()
                .nth(candidate_index(ordinal)?)
                .copied()
                .map(ChoiceValue::Discrete)
                .map(Some)
                .ok_or_else(|| integrity("proposal-ordinal-exceeds-source-cardinality")),
            (
                CandidateGeneratorAlgorithm::All,
                crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Group(group),
            ) => match group.domain() {
                crate::ChoiceGroupDomain::Finite { tuples, .. } => tuples
                    .iter()
                    .nth(candidate_index(ordinal)?)
                    .map(crate::codec::admitted_clone)
                    .transpose()?
                    .map(|tuple| group.select(tuple).map(ChoiceValue::Group))
                    .transpose()?
                    .map(Some)
                    .ok_or_else(|| integrity("proposal-ordinal-exceeds-source-cardinality")),
                crate::ChoiceGroupDomain::Cartesian { .. } => Err(integrity(
                    "Cartesian group requires a bounded group generator",
                )),
            },
            (
                CandidateGeneratorAlgorithm::GroupProgressive { maximum_proposals },
                crate::GROUP_PROGRESSIVE_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Group(group),
            ) => group
                .progressive_candidate_checked(ordinal, *maximum_proposals, &mut || self.poll())
                .map(ChoiceValue::Group)
                .map(Some),
            (
                CandidateGeneratorAlgorithm::All,
                crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) => integer_candidate_at_offset(integer, u128::from(ordinal - 1))
                .map(ChoiceValue::Integer)
                .map(Some),
            (
                CandidateGeneratorAlgorithm::WeightedCategorical { weights },
                crate::WEIGHTED_CATEGORICAL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Discrete(discrete),
            ) => self
                .weighted_categorical_candidates(request, discrete, weights)?
                .get(candidate_index(ordinal)?)
                .copied()
                .map(ChoiceValue::Discrete)
                .map(Some)
                .ok_or_else(|| integrity("proposal-ordinal-exceeds-source-cardinality")),
            (
                CandidateGeneratorAlgorithm::OrderedMixture { components },
                crate::ORDERED_MIXTURE_GENERATOR_IMPLEMENTATION_VERSION,
                _,
            ) => self
                .ordered_mixture_candidates(request, domain, components)?
                .ok_or_else(|| integrity("generated-proposal-owner-is-not-implemented"))?
                .get(candidate_index(ordinal)?)
                .map(ChoiceValue::clone_admitted)
                .transpose()?
                .map(Some)
                .ok_or_else(|| integrity("proposal-ordinal-exceeds-source-cardinality")),
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
            ) => Err(integrity("candidate-generator-domain-family-mismatch")),
            (
                CandidateGeneratorAlgorithm::BoundaryInteger,
                crate::BOUNDARY_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) => self
                .boundary_integer_candidates(request, integer)?
                .get(candidate_index(ordinal)?)
                .copied()
                .map(ChoiceValue::Integer)
                .map(Some)
                .ok_or_else(|| integrity("proposal-ordinal-exceeds-source-cardinality")),
            (
                CandidateGeneratorAlgorithm::StratifiedInteger { strata },
                crate::STRATIFIED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) => stratified_integer_candidate(*strata, integer, ordinal)
                .map(ChoiceValue::Integer)
                .map(Some),
            (
                CandidateGeneratorAlgorithm::LogInteger { base },
                crate::LOG_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) => log_integer_candidates(*base, integer)?
                .get(candidate_index(ordinal)?)
                .copied()
                .map(ChoiceValue::Integer)
                .map(Some)
                .ok_or_else(|| integrity("proposal-ordinal-exceeds-source-cardinality")),
            (
                CandidateGeneratorAlgorithm::PermutedInteger,
                crate::PERMUTED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) if matches!(request.source(), CandidateSource::ModeledGenerated(_)) => {
                modeled_uniform_integer_candidate(request, integer, ordinal)
                    .map(ChoiceValue::Integer)
                    .map(Some)
            }
            _ => Ok(None),
        }
    }

    pub(in crate::repository) fn static_candidate_prefix(
        &mut self,
        request: &BranchRequest,
        domain: &ChoiceDomain,
        limit: u64,
    ) -> Result<Vec<ChoiceValue>, CampaignRepositoryError> {
        let _operation = self.enter_operation();
        let limit = usize::try_from(limit)
            .map_err(|_| integrity("static-candidate-prefix-limit-overflow"))?;
        if matches!(
            request.source(),
            CandidateSource::StatisticalFinite(_) | CandidateSource::StatisticalSmc(_)
        ) {
            return if limit == 0 {
                Ok(Vec::new())
            } else {
                self.static_candidate_at(request, domain, 1)?
                    .map(|value| std::iter::once(value).collect_admitted(self))
                    .ok_or_else(|| integrity("statistical-proposal-draw-is-missing"))?
            };
        }
        if let Some(values) = request.source().finite_values() {
            return values
                .iter()
                .take(limit)
                .map(ChoiceValue::clone_admitted)
                .try_collect_admitted(self);
        }

        let generator = request
            .source()
            .generator()
            .ok_or_else(|| integrity("candidate-source-kind-is-invalid"))?;
        let spec = self.read_generator(generator.content_id())?;
        let ordinals = || {
            u64::try_from(limit)
                .map(|limit| 1..=limit)
                .map_err(|_| integrity("static-candidate-prefix-limit-overflow"))
        };
        let candidates = match (spec.algorithm(), spec.implementation_version(), domain) {
            (
                CandidateGeneratorAlgorithm::All,
                crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Boolean(_),
            ) => [ChoiceValue::Boolean(false), ChoiceValue::Boolean(true)]
                .into_iter()
                .take(limit)
                .collect_admitted(self)?,
            (
                CandidateGeneratorAlgorithm::All,
                crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Discrete(discrete),
            ) => discrete
                .alternatives()
                .keys()
                .take(limit)
                .copied()
                .map(ChoiceValue::Discrete)
                .collect_admitted(self)?,
            (
                CandidateGeneratorAlgorithm::All,
                crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) => ordinals()?
                .map(|ordinal| {
                    integer_candidate_at_offset(integer, u128::from(ordinal - 1))
                        .map(ChoiceValue::Integer)
                })
                .try_collect_admitted(self)?,
            (
                CandidateGeneratorAlgorithm::WeightedCategorical { weights },
                crate::WEIGHTED_CATEGORICAL_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Discrete(discrete),
            ) => self
                .weighted_categorical_candidates(request, discrete, weights)?
                .into_iter()
                .take(limit)
                .map(ChoiceValue::Discrete)
                .collect_admitted(self)?,
            (
                CandidateGeneratorAlgorithm::OrderedMixture { components },
                crate::ORDERED_MIXTURE_GENERATOR_IMPLEMENTATION_VERSION,
                _,
            ) => self
                .ordered_mixture_candidates(request, domain, components)?
                .ok_or_else(|| integrity("generated-proposal-owner-is-not-implemented"))?
                .into_iter()
                .take(limit)
                .collect_admitted(self)?,
            (
                CandidateGeneratorAlgorithm::BoundaryInteger,
                crate::BOUNDARY_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) => self
                .boundary_integer_candidates(request, integer)?
                .into_iter()
                .take(limit)
                .map(ChoiceValue::Integer)
                .collect_admitted(self)?,
            (
                CandidateGeneratorAlgorithm::StratifiedInteger { strata },
                crate::STRATIFIED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) => ordinals()?
                .map(|ordinal| {
                    stratified_integer_candidate(*strata, integer, ordinal)
                        .map(ChoiceValue::Integer)
                })
                .try_collect_admitted(self)?,
            (
                CandidateGeneratorAlgorithm::LogInteger { base },
                crate::LOG_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) => log_integer_candidates(*base, integer)?
                .into_iter()
                .take(limit)
                .map(ChoiceValue::Integer)
                .collect_admitted(self)?,
            (
                CandidateGeneratorAlgorithm::PermutedInteger,
                crate::PERMUTED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
                ChoiceDomain::Integer(integer),
            ) if matches!(request.source(), CandidateSource::ModeledGenerated(_)) => ordinals()?
                .map(|ordinal| {
                    modeled_uniform_integer_candidate(request, integer, ordinal)
                        .map(ChoiceValue::Integer)
                })
                .try_collect_admitted(self)?,
            _ => return Err(integrity("static-candidate-prefix-is-not-implemented")),
        };
        Ok(candidates)
    }
}
