//! Progressive and pseudorandom integer candidate generators.

use super::*;

pub(in crate::repository) fn progressive_integer_candidate(
    initial_strata: u32,
    domain: &IntegerDomain,
    ordinal: u64,
) -> Result<IntegerValue, CampaignRepositoryError> {
    if initial_strata > crate::PROGRESSIVE_INTEGER_GENERATOR_MAX_INITIAL_STRATA {
        return Err(integrity("progressive-generator-initial-strata-limit"));
    }
    if ordinal == 0 || ordinal > crate::PROGRESSIVE_INTEGER_GENERATOR_MAX_PROPOSALS {
        return Err(integrity("proposal-ordinal-exceeds-source-cardinality"));
    }
    let initial_count = u64::try_from(domain.cardinality().min(u128::from(initial_strata)))
        .map_err(|_| integrity("candidate-source-cardinality-overflow"))?;
    if ordinal <= initial_count {
        return stratified_integer_candidate(initial_strata, domain, ordinal);
    }

    let mut selected = BTreeSet::new();
    for initial_ordinal in 1..=initial_count {
        selected.insert(stratified_integer_offset(
            initial_strata,
            domain,
            initial_ordinal,
        )?);
    }
    let mut gaps = progressive_refinement_gaps(domain.cardinality(), &selected)?;
    let refinements = ordinal
        .checked_sub(initial_count)
        .ok_or_else(|| integrity("progressive-generator-ordinal-underflow"))?;
    let mut selected_offset = None;
    for _ in 0..refinements {
        let gap = gaps
            .pop()
            .ok_or_else(|| integrity("proposal-ordinal-exceeds-source-cardinality"))?;
        let midpoint = gap
            .lower
            .checked_add((gap.len() - 1) / 2)
            .ok_or_else(|| integrity("candidate-source-cardinality-overflow"))?;
        if midpoint > gap.lower {
            gaps.push(RefinementGap {
                lower: gap.lower,
                upper: midpoint - 1,
            });
        }
        if midpoint < gap.upper {
            gaps.push(RefinementGap {
                lower: midpoint + 1,
                upper: gap.upper,
            });
        }
        selected_offset = Some(midpoint);
    }
    integer_candidate_at_offset(
        domain,
        selected_offset.ok_or_else(|| integrity("progressive-generator-refinement-is-empty"))?,
    )
}

pub(in crate::repository::projection) fn feedback_progressive_integer_candidate(
    request: &BranchRequest,
    domain: &IntegerDomain,
    domain_semantic: crate::ChoiceDomainSemanticId,
    proposed: &BTreeSet<ChoiceValue>,
    feedback: CandidateFeedbackProjection<'_>,
    terms: FeedbackIntervalTerms,
) -> Result<IntegerValue, CampaignRepositoryError> {
    let projection = feedback.projection;
    if projection.branch_point() != request.branch_point() || projection.policy() != feedback.policy
    {
        return Err(integrity(
            "progressive-generator-feedback-projection-basis-mismatch",
        ));
    }
    if proposed.len() >= crate::PROGRESSIVE_INTEGER_GENERATOR_MAX_PROPOSALS as usize {
        return Err(integrity("progressive-generator-proposal-limit"));
    }

    let mut selected = BTreeSet::new();
    for value in proposed {
        let ChoiceValue::Integer(value) = value else {
            return Err(integrity("candidate-generator-domain-family-mismatch"));
        };
        selected.insert(integer_candidate_offset(domain, *value)?);
    }
    let gaps = progressive_refinement_gaps(domain.cardinality(), &selected)?;
    let landmark_offsets = if terms.landmarks {
        domain
            .landmarks()
            .iter()
            .map(|landmark| integer_candidate_offset(domain, *landmark))
            .collect::<Result<BTreeSet<_>, _>>()?
    } else {
        BTreeSet::new()
    };
    let prospective_prior = projection.prospective_prior_basis(1)?;
    let mut endpoints = BTreeMap::<u128, FeedbackEndpoint>::new();
    let mut scored = BinaryHeap::new();
    for gap in gaps {
        let lower_endpoint = selected.range(..gap.lower).next_back().copied();
        let upper_endpoint = selected
            .range((
                std::ops::Bound::Excluded(gap.upper),
                std::ops::Bound::Unbounded,
            ))
            .next()
            .copied();
        let lower = feedback_endpoint(
            request,
            domain,
            domain_semantic,
            projection,
            prospective_prior,
            lower_endpoint,
            &mut endpoints,
        )?;
        let upper = feedback_endpoint(
            request,
            domain,
            domain_semantic,
            projection,
            prospective_prior,
            upper_endpoint,
            &mut endpoints,
        )?;
        scored.push(FeedbackRefinementGap {
            gap,
            rarity_discontinuity: if terms.rarity_discontinuity {
                rarity_discontinuity(projection, lower.edge, upper.edge)?
            } else {
                ExactMeanDiscontinuity::ZERO
            },
            finding_discontinuity: if terms.finding_discontinuity {
                finding_discontinuity(projection, lower.edge, upper.edge)?
            } else {
                ExactMeanDiscontinuity::ZERO
            },
            novelty_discontinuity: if terms.novelty_discontinuity {
                novelty_discontinuity(projection, lower.edge, upper.edge)?
            } else {
                ExactMeanDiscontinuity::ZERO
            },
            objective_discontinuity: if terms.objective_discontinuity {
                objective_discontinuity(projection, lower.edge, upper.edge)?
            } else {
                ExactMeanDiscontinuity::ZERO
            },
            producer_landmarks: landmark_offsets.range(gap.lower..=gap.upper).count(),
            endpoint_score_delta: lower.score_micros.abs_diff(upper.score_micros),
        });
    }
    let selected = scored
        .pop()
        .ok_or_else(|| integrity("progressive-generator-refinement-is-empty"))?;
    let midpoint = selected
        .gap
        .lower
        .checked_add((selected.gap.len() - 1) / 2)
        .ok_or_else(|| integrity("candidate-source-cardinality-overflow"))?;
    let offset = if selected.producer_landmarks == 0 {
        midpoint
    } else {
        landmark_offsets
            .range(selected.gap.lower..=selected.gap.upper)
            .min_by_key(|landmark| (landmark.abs_diff(midpoint), **landmark))
            .copied()
            .ok_or_else(|| integrity("progressive-generator-landmark-index-mismatch"))?
    };
    integer_candidate_at_offset(domain, offset)
}

fn feedback_endpoint(
    request: &BranchRequest,
    domain: &IntegerDomain,
    domain_semantic: crate::ChoiceDomainSemanticId,
    projection: &crate::BranchPuctProjection,
    prospective_prior: crate::exploration::BranchProspectivePriorBasis,
    offset: Option<u128>,
    cache: &mut BTreeMap<u128, FeedbackEndpoint>,
) -> Result<FeedbackEndpoint, CampaignRepositoryError> {
    let Some(offset) = offset else {
        return Ok(FeedbackEndpoint {
            edge: None,
            score_micros: 0,
        });
    };
    if let Some(endpoint) = cache.get(&offset) {
        return Ok(*endpoint);
    }
    let value = ChoiceValue::Integer(integer_candidate_at_offset(domain, offset)?);
    let edge = crate::Selection::campaign_edge_id(request.branch_point(), domain_semantic, &value);
    let raw_prior_weight = request
        .source()
        .prior_weight(&value)
        .ok_or_else(|| integrity("progressive-generator-endpoint-is-not-in-source"))?;
    if raw_prior_weight != 1 {
        return Err(integrity(
            "progressive-generator-endpoint-prior-is-not-uniform",
        ));
    }
    let evidence = if projection.edge_statistics().contains_key(&edge) {
        projection.candidate_evidence_with_prior(edge, raw_prior_weight)?
    } else {
        projection.candidate_evidence_with_prior_basis(edge, prospective_prior)?
    };
    let endpoint = FeedbackEndpoint {
        edge: Some(edge),
        score_micros: crate::PuctScore::derive(projection.puct(), evidence.statistics)?
            .total_micros(),
    };
    cache.insert(offset, endpoint);
    Ok(endpoint)
}

fn objective_discontinuity(
    projection: &crate::BranchPuctProjection,
    lower: Option<crate::BranchEdgeId>,
    upper: Option<crate::BranchEdgeId>,
) -> Result<ExactMeanDiscontinuity, CampaignRepositoryError> {
    let (lower_reward, lower_visits) = objective_endpoint_mean_basis(projection, lower);
    let (upper_reward, upper_visits) = objective_endpoint_mean_basis(projection, upper);
    let lower_scaled = i128::from(lower_reward)
        .checked_mul(i128::from(upper_visits))
        .ok_or_else(|| integrity("progressive-generator-objective-discontinuity-overflow"))?;
    let upper_scaled = i128::from(upper_reward)
        .checked_mul(i128::from(lower_visits))
        .ok_or_else(|| integrity("progressive-generator-objective-discontinuity-overflow"))?;
    let numerator = lower_scaled
        .checked_sub(upper_scaled)
        .ok_or_else(|| integrity("progressive-generator-objective-discontinuity-overflow"))?
        .unsigned_abs();
    let denominator = u128::from(lower_visits)
        .checked_mul(u128::from(upper_visits))
        .ok_or_else(|| integrity("progressive-generator-objective-discontinuity-overflow"))?;
    Ok(ExactMeanDiscontinuity {
        numerator,
        denominator,
    })
}

fn novelty_discontinuity(
    projection: &crate::BranchPuctProjection,
    lower: Option<crate::BranchEdgeId>,
    upper: Option<crate::BranchEdgeId>,
) -> Result<ExactMeanDiscontinuity, CampaignRepositoryError> {
    let (lower_events, lower_visits) = novelty_endpoint_mean_basis(projection, lower);
    let (upper_events, upper_visits) = novelty_endpoint_mean_basis(projection, upper);
    let lower_scaled = u128::from(lower_events)
        .checked_mul(u128::from(upper_visits))
        .ok_or_else(|| integrity("progressive-generator-novelty-discontinuity-overflow"))?;
    let upper_scaled = u128::from(upper_events)
        .checked_mul(u128::from(lower_visits))
        .ok_or_else(|| integrity("progressive-generator-novelty-discontinuity-overflow"))?;
    let numerator = lower_scaled.abs_diff(upper_scaled);
    let denominator = u128::from(lower_visits)
        .checked_mul(u128::from(upper_visits))
        .ok_or_else(|| integrity("progressive-generator-novelty-discontinuity-overflow"))?;
    Ok(ExactMeanDiscontinuity {
        numerator,
        denominator,
    })
}

fn finding_discontinuity(
    projection: &crate::BranchPuctProjection,
    lower: Option<crate::BranchEdgeId>,
    upper: Option<crate::BranchEdgeId>,
) -> Result<ExactMeanDiscontinuity, CampaignRepositoryError> {
    let (lower_reward, lower_visits) = finding_endpoint_mean_basis(projection, lower);
    let (upper_reward, upper_visits) = finding_endpoint_mean_basis(projection, upper);
    let lower_scaled = i128::from(lower_reward)
        .checked_mul(i128::from(upper_visits))
        .ok_or_else(|| integrity("progressive-generator-finding-discontinuity-overflow"))?;
    let upper_scaled = i128::from(upper_reward)
        .checked_mul(i128::from(lower_visits))
        .ok_or_else(|| integrity("progressive-generator-finding-discontinuity-overflow"))?;
    let numerator = lower_scaled
        .checked_sub(upper_scaled)
        .ok_or_else(|| integrity("progressive-generator-finding-discontinuity-overflow"))?
        .unsigned_abs();
    let denominator = u128::from(lower_visits)
        .checked_mul(u128::from(upper_visits))
        .ok_or_else(|| integrity("progressive-generator-finding-discontinuity-overflow"))?;
    Ok(ExactMeanDiscontinuity {
        numerator,
        denominator,
    })
}

fn rarity_discontinuity(
    projection: &crate::BranchPuctProjection,
    lower: Option<crate::BranchEdgeId>,
    upper: Option<crate::BranchEdgeId>,
) -> Result<ExactMeanDiscontinuity, CampaignRepositoryError> {
    let (lower_weight, lower_visits) = rarity_endpoint_mean_basis(projection, lower);
    let (upper_weight, upper_visits) = rarity_endpoint_mean_basis(projection, upper);
    let lower_scaled = u128::from(lower_weight)
        .checked_mul(u128::from(upper_visits))
        .ok_or_else(|| integrity("progressive-generator-rarity-discontinuity-overflow"))?;
    let upper_scaled = u128::from(upper_weight)
        .checked_mul(u128::from(lower_visits))
        .ok_or_else(|| integrity("progressive-generator-rarity-discontinuity-overflow"))?;
    let numerator = lower_scaled.abs_diff(upper_scaled);
    let denominator = u128::from(lower_visits)
        .checked_mul(u128::from(upper_visits))
        .ok_or_else(|| integrity("progressive-generator-rarity-discontinuity-overflow"))?;
    Ok(ExactMeanDiscontinuity {
        numerator,
        denominator,
    })
}

fn rarity_endpoint_mean_basis(
    projection: &crate::BranchPuctProjection,
    edge: Option<crate::BranchEdgeId>,
) -> (u64, u64) {
    let Some(edge) = edge else {
        return (0, 1);
    };
    let Some(statistics) = projection.edge_statistics().get(&edge) else {
        return (0, 1);
    };
    (
        projection
            .edge_rarity_weights()
            .get(&edge)
            .copied()
            .unwrap_or(0),
        statistics.edge_visits(),
    )
}

fn finding_endpoint_mean_basis(
    projection: &crate::BranchPuctProjection,
    edge: Option<crate::BranchEdgeId>,
) -> (i64, u64) {
    let Some(edge) = edge else {
        return (0, 1);
    };
    let Some(statistics) = projection.edge_statistics().get(&edge) else {
        return (0, 1);
    };
    (
        projection
            .edge_finding_reward_micros()
            .get(&edge)
            .copied()
            .unwrap_or(0),
        statistics.edge_visits(),
    )
}

fn novelty_endpoint_mean_basis(
    projection: &crate::BranchPuctProjection,
    edge: Option<crate::BranchEdgeId>,
) -> (u64, u64) {
    let Some(edge) = edge else {
        return (0, 1);
    };
    let Some(statistics) = projection.edge_statistics().get(&edge) else {
        return (0, 1);
    };
    (
        projection
            .edge_novelty_events()
            .get(&edge)
            .copied()
            .unwrap_or(0),
        statistics.edge_visits(),
    )
}

fn objective_endpoint_mean_basis(
    projection: &crate::BranchPuctProjection,
    edge: Option<crate::BranchEdgeId>,
) -> (i64, u64) {
    let Some(edge) = edge else {
        return (0, 1);
    };
    let Some(statistics) = projection.edge_statistics().get(&edge) else {
        return (0, 1);
    };
    (
        projection
            .edge_objective_reward_micros()
            .get(&edge)
            .copied()
            .unwrap_or(0),
        statistics.edge_visits(),
    )
}

fn integer_candidate_offset(
    domain: &IntegerDomain,
    value: IntegerValue,
) -> Result<u128, CampaignRepositoryError> {
    if !domain.contains_integer(value) {
        return Err(integrity("candidate-source-integer-is-not-in-domain"));
    }
    let delta = match (domain.minimum(), value) {
        (IntegerValue::Signed(minimum), IntegerValue::Signed(value)) => {
            u128::try_from(i128::from(value) - i128::from(minimum))
                .map_err(|_| integrity("candidate-source-cardinality-overflow"))?
        }
        (IntegerValue::Unsigned(minimum), IntegerValue::Unsigned(value)) => {
            u128::from(value - minimum)
        }
        _ => return Err(integrity("candidate-generator-domain-family-mismatch")),
    };
    Ok(delta / u128::from(domain.step()))
}

fn progressive_refinement_gaps(
    cardinality: u128,
    selected: &BTreeSet<u128>,
) -> Result<BinaryHeap<RefinementGap>, CampaignRepositoryError> {
    let maximum = cardinality
        .checked_sub(1)
        .ok_or_else(|| integrity("candidate-source-cardinality-overflow"))?;
    let mut gaps = BinaryHeap::new();
    let mut prior = None;
    for offset in selected.iter().copied() {
        let lower = prior.map_or(0, |value: u128| value + 1);
        if lower < offset {
            gaps.push(RefinementGap {
                lower,
                upper: offset - 1,
            });
        }
        prior = Some(offset);
    }
    let lower = prior.map_or(0, |value| value + 1);
    if lower <= maximum {
        gaps.push(RefinementGap {
            lower,
            upper: maximum,
        });
    }
    Ok(gaps)
}

pub(super) fn integer_candidate_at_offset(
    domain: &IntegerDomain,
    offset: u128,
) -> Result<IntegerValue, CampaignRepositoryError> {
    if offset >= domain.cardinality() {
        return Err(integrity("candidate-source-offset-is-out-of-range"));
    }
    let delta = offset
        .checked_mul(u128::from(domain.step()))
        .ok_or_else(|| integrity("candidate-source-cardinality-overflow"))?;
    let value = match domain.minimum() {
        IntegerValue::Signed(minimum) => {
            let delta = i128::try_from(delta)
                .map_err(|_| integrity("candidate-source-cardinality-overflow"))?;
            let value = i128::from(minimum)
                .checked_add(delta)
                .and_then(|value| i64::try_from(value).ok())
                .ok_or_else(|| integrity("candidate-source-cardinality-overflow"))?;
            IntegerValue::Signed(value)
        }
        IntegerValue::Unsigned(minimum) => {
            let value = u128::from(minimum)
                .checked_add(delta)
                .and_then(|value| u64::try_from(value).ok())
                .ok_or_else(|| integrity("candidate-source-cardinality-overflow"))?;
            IntegerValue::Unsigned(value)
        }
    };
    if !domain.contains_integer(value) {
        return Err(integrity("static-generator-produced-illegal-integer"));
    }
    Ok(value)
}

pub(in crate::repository) fn permuted_integer_candidate_count(
    domain: &IntegerDomain,
) -> Result<u64, CampaignRepositoryError> {
    if domain.cardinality() > crate::PERMUTED_INTEGER_GENERATOR_MAX_CARDINALITY {
        return Err(integrity("permuted-generator-cardinality-limit"));
    }
    u64::try_from(domain.cardinality())
        .map_err(|_| integrity("permuted-generator-cardinality-limit"))
}

pub(in crate::repository) fn permuted_integer_candidate(
    request: &BranchRequest,
    domain: &IntegerDomain,
    ordinal: u64,
) -> Result<IntegerValue, CampaignRepositoryError> {
    let cardinality = permuted_integer_candidate_count(domain)?;
    if ordinal == 0 || ordinal > cardinality {
        return Err(integrity("proposal-ordinal-exceeds-source-cardinality"));
    }
    let request_digest = request.id()?.content_id().digest();
    let key = CampaignHash::derive(
        "crucible.campaign.generator.permuted-integer.v6",
        &request_digest,
    );
    let envelope_mask = u64::try_from(u128::from(cardinality).next_power_of_two() - 1)
        .map_err(|_| integrity("permuted-generator-cardinality-limit"))?;
    let mut offset = ordinal - 1;
    for (round, chunk) in key.as_bytes().chunks_exact(8).enumerate() {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(chunk);
        let word = u64::from_be_bytes(bytes);
        let candidate = if round % 2 == 0 {
            offset ^ (word & envelope_mask)
        } else {
            word.wrapping_sub(offset) & envelope_mask
        };
        if candidate < cardinality {
            offset = candidate;
        }
    }
    integer_candidate_at_offset(domain, u128::from(offset))
}

pub(in crate::repository) fn modeled_uniform_integer_candidate_count(
    request: &BranchRequest,
    domain: &IntegerDomain,
) -> Result<u64, CampaignRepositoryError> {
    let cardinality = domain.cardinality();
    if cardinality == 0
        || !cardinality.is_power_of_two()
        || cardinality > (u128::from(u64::MAX) + 1)
    {
        return Err(integrity("modeled-uniform-integer-domain-is-not-supported"));
    }
    u64::try_from(cardinality.min(u128::from(request.budget().maximum_proposals())))
        .map_err(|_| integrity("candidate-source-cardinality-overflow"))
}

pub(in crate::repository) fn modeled_uniform_integer_candidate(
    request: &BranchRequest,
    domain: &IntegerDomain,
    ordinal: u64,
) -> Result<IntegerValue, CampaignRepositoryError> {
    let count = modeled_uniform_integer_candidate_count(request, domain)?;
    if ordinal == 0 || ordinal > count {
        return Err(integrity("proposal-ordinal-exceeds-source-cardinality"));
    }

    let cardinality = domain.cardinality();
    let request_digest = request.id()?.content_id().digest();
    let key = CampaignHash::derive(
        "crucible.campaign.generator.modeled-uniform-integer.v17",
        &request_digest,
    );
    let envelope_mask = if cardinality == u128::from(u64::MAX) + 1 {
        u64::MAX
    } else {
        u64::try_from(cardinality - 1)
            .map_err(|_| integrity("modeled-uniform-integer-cardinality-limit"))?
    };
    let mut offset = ordinal - 1;
    for (round, chunk) in key.as_bytes().chunks_exact(8).enumerate() {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(chunk);
        let word = u64::from_be_bytes(bytes);
        offset = if round % 2 == 0 {
            offset ^ (word & envelope_mask)
        } else {
            word.wrapping_sub(offset) & envelope_mask
        };
    }
    integer_candidate_at_offset(domain, u128::from(offset))
}
