//! Progressive and pseudorandom integer candidate generators.

use std::cmp::Ordering;

use super::*;

pub(in crate::repository::projection) fn feedback_progressive_integer_candidate(
    request: &BranchRequest,
    domain: &IntegerDomain,
    domain_semantic: crate::ChoiceDomainSemanticId,
    proposed: &BTreeSet<ChoiceValue>,
    feedback: CandidateFeedbackProjection<'_>,
    poll: &mut impl FnMut() -> Result<(), CampaignRepositoryError>,
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
        poll()?;
        let ChoiceValue::Integer(value) = value else {
            return Err(integrity("candidate-generator-domain-family-mismatch"));
        };
        let offset = integer_candidate_offset(domain, *value)?;
        if !selected.contains(&offset) {
            crucible_store::owned_decode::charge_btree_set_entry::<u128>()
                .map_err(CampaignCodecError::from)?;
            selected.insert(offset);
        }
    }
    let gaps = progressive_refinement_gaps(domain.cardinality(), &selected, poll)?;
    let mut landmark_offsets = BTreeSet::new();
    for landmark in domain.landmarks() {
        poll()?;
        let offset = integer_candidate_offset(domain, *landmark)?;
        if !landmark_offsets.contains(&offset) {
            crucible_store::owned_decode::charge_btree_set_entry::<u128>()
                .map_err(CampaignCodecError::from)?;
            landmark_offsets.insert(offset);
        }
    }
    poll()?;
    let prospective_prior = projection.prospective_prior_basis(1)?;
    poll()?;
    let mut endpoints = BTreeMap::<u128, FeedbackEndpoint>::new();
    let mut selected_gap: Option<FeedbackRefinementGap> = None;
    for gap in gaps {
        poll()?;
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
        let scored = FeedbackRefinementGap {
            gap,
            rarity_discontinuity: rarity_discontinuity(projection, lower.edge, upper.edge)?,
            finding_discontinuity: finding_discontinuity(projection, lower.edge, upper.edge)?,
            novelty_discontinuity: novelty_discontinuity(projection, lower.edge, upper.edge)?,
            objective_discontinuity: objective_discontinuity(projection, lower.edge, upper.edge)?,
            producer_landmarks: landmark_offsets.range(gap.lower..=gap.upper).count(),
            endpoint_score_delta: lower.score_micros.abs_diff(upper.score_micros),
        };
        if selected_gap
            .as_ref()
            .is_none_or(|selected| feedback_gap_order(&scored, selected).is_gt())
        {
            selected_gap = Some(scored);
        }
    }
    let selected =
        selected_gap.ok_or_else(|| integrity("progressive-generator-refinement-is-empty"))?;
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
    if let Some(budget) = crucible_store::owned_decode::current_budget() {
        budget.check().map_err(CampaignCodecError::from)?;
    }
    let raw_prior_weight = request
        .source()
        .prior_weight(&value)
        .ok_or_else(|| integrity("progressive-generator-endpoint-is-not-in-source"))?;
    if raw_prior_weight != 1 {
        return Err(integrity(
            "progressive-generator-endpoint-prior-is-not-uniform",
        ));
    }
    let statistics = if let Some(statistics) = projection.edge_statistics().get(&edge).copied() {
        statistics
    } else {
        projection
            .candidate_evidence_with_prior_basis(edge, prospective_prior)?
            .statistics
    };
    let endpoint = FeedbackEndpoint {
        edge: Some(edge),
        score_micros: crate::PuctScore::derive(projection.puct(), statistics)?.total_micros(),
    };
    crucible_store::owned_decode::charge_btree_entry::<u128, FeedbackEndpoint>()
        .map_err(CampaignCodecError::from)?;
    cache.insert(offset, endpoint);
    Ok(endpoint)
}

fn feedback_gap_order(left: &FeedbackRefinementGap, right: &FeedbackRefinementGap) -> Ordering {
    exact_fraction_order(left.rarity_discontinuity, right.rarity_discontinuity)
        .then_with(|| exact_fraction_order(left.finding_discontinuity, right.finding_discontinuity))
        .then_with(|| exact_fraction_order(left.novelty_discontinuity, right.novelty_discontinuity))
        .then_with(|| {
            exact_fraction_order(left.objective_discontinuity, right.objective_discontinuity)
        })
        .then_with(|| left.producer_landmarks.cmp(&right.producer_landmarks))
        .then_with(|| left.endpoint_score_delta.cmp(&right.endpoint_score_delta))
        .then_with(|| left.gap.len().cmp(&right.gap.len()))
        .then_with(|| right.gap.lower.cmp(&left.gap.lower))
}

fn exact_fraction_order(left: ExactMeanDiscontinuity, right: ExactMeanDiscontinuity) -> Ordering {
    let (mut left_numerator, mut left_denominator) = (left.numerator, left.denominator);
    let (mut right_numerator, mut right_denominator) = (right.numerator, right.denominator);
    let mut reverse = false;

    loop {
        let quotient_order =
            (left_numerator / left_denominator).cmp(&(right_numerator / right_denominator));
        if quotient_order != Ordering::Equal {
            return if reverse {
                quotient_order.reverse()
            } else {
                quotient_order
            };
        }

        let left_remainder = left_numerator % left_denominator;
        let right_remainder = right_numerator % right_denominator;
        let remainder_order = left_remainder.cmp(&right_remainder);
        if left_remainder == 0 || right_remainder == 0 {
            return if reverse {
                remainder_order.reverse()
            } else {
                remainder_order
            };
        }

        left_numerator = left_denominator;
        left_denominator = left_remainder;
        right_numerator = right_denominator;
        right_denominator = right_remainder;
        reverse = !reverse;
    }
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
    poll: &mut impl FnMut() -> Result<(), CampaignRepositoryError>,
) -> Result<BinaryHeap<RefinementGap>, CampaignRepositoryError> {
    let maximum = cardinality
        .checked_sub(1)
        .ok_or_else(|| integrity("candidate-source-cardinality-overflow"))?;
    let mut gaps = Vec::new();
    let mut prior = None;
    for offset in selected.iter().copied() {
        poll()?;
        let lower = prior.map_or(0, |value: u128| value + 1);
        if lower < offset {
            push_vec_admitted(
                &mut gaps,
                RefinementGap {
                    lower,
                    upper: offset - 1,
                },
            )?;
        }
        prior = Some(offset);
    }
    let lower = prior.map_or(0, |value| value + 1);
    if lower <= maximum {
        push_vec_admitted(
            &mut gaps,
            RefinementGap {
                lower,
                upper: maximum,
            },
        )?;
    }
    Ok(BinaryHeap::from(gaps))
}

fn push_vec_admitted<T>(values: &mut Vec<T>, value: T) -> Result<(), CampaignRepositoryError> {
    if values.len() == values.capacity() {
        let capacity = values
            .capacity()
            .checked_mul(2)
            .map(|capacity| capacity.max(8))
            .ok_or_else(|| integrity("progressive-generator-work-allocation-overflow"))?;
        let additional = capacity
            .checked_sub(values.len())
            .ok_or_else(|| integrity("progressive-generator-work-allocation-overflow"))?;
        crucible_store::owned_decode::reserve_vec(values, additional)
            .map_err(CampaignCodecError::from)?;
    }
    values.push(value);
    Ok(())
}

pub(in crate::repository::projection) fn integer_candidate_at_offset(
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
    for (round, chunk) in key.as_bytes().as_chunks::<8>().0.iter().enumerate() {
        let word = u64::from_be_bytes(*chunk);
        offset = if round % 2 == 0 {
            offset ^ (word & envelope_mask)
        } else {
            word.wrapping_sub(offset) & envelope_mask
        };
    }
    integer_candidate_at_offset(domain, u128::from(offset))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_host_resources::test_support::TestAllocationObserver;
    use num_bigint::BigUint;

    #[global_allocator]
    static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

    fn cross_product_order(
        left: ExactMeanDiscontinuity,
        right: ExactMeanDiscontinuity,
    ) -> Ordering {
        (BigUint::from(left.numerator) * BigUint::from(right.denominator))
            .cmp(&(BigUint::from(right.numerator) * BigUint::from(left.denominator)))
    }

    #[test]
    fn exact_fraction_order_matches_cross_products_without_allocating() {
        let maximum = u128::MAX;
        let cases = [
            ((0, 1), (0, maximum)),
            ((0, maximum), (1, maximum)),
            ((maximum, maximum), (maximum - 1, maximum - 1)),
            ((maximum, 1), (maximum - 1, 1)),
            ((1, maximum), (1, maximum - 1)),
            ((1, 3), (1, 2)),
            ((3, 1), (2, 1)),
            ((maximum, maximum - 1), (maximum - 1, maximum - 2)),
            ((maximum - 1, maximum), (maximum - 2, maximum - 1)),
            ((maximum, maximum - 2), (maximum - 1, maximum - 3)),
        ];

        for ((left_numerator, left_denominator), (right_numerator, right_denominator)) in cases {
            let left = ExactMeanDiscontinuity {
                numerator: left_numerator,
                denominator: left_denominator,
            };
            let right = ExactMeanDiscontinuity {
                numerator: right_numerator,
                denominator: right_denominator,
            };
            let expected = cross_product_order(left, right);

            let (actual, allocations) =
                TestAllocationObserver::count(|| exact_fraction_order(left, right));

            assert_eq!(
                actual, expected,
                "{left_numerator}/{left_denominator} versus {right_numerator}/{right_denominator}"
            );
            assert!(!allocations.overflow);
            assert_eq!(allocations.allocations, 0);
            assert_eq!(allocations.reallocations, 0);
        }
    }
}
