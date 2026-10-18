//! Candidate enumeration and integer-generator mechanics.

use super::*;

mod integer_generators;

pub(super) use integer_generators::*;

pub(in crate::repository) fn projection_order_key(id: ContentId) -> CampaignHash {
    CampaignHash::from_bytes(id.digest())
}

pub(in crate::repository) fn candidate_index(
    ordinal: u64,
) -> Result<usize, CampaignRepositoryError> {
    usize::try_from(ordinal - 1).map_err(|_| integrity("proposal-ordinal-is-not-canonical"))
}

pub(in crate::repository) fn continuation_state_after_progress(
    profile: CandidateSourceProfile,
    proposed: u64,
    pending: bool,
    has_next_candidate: bool,
    maximum_proposals: u64,
    completed_visits: u64,
) -> Result<crate::ContinuationState, CampaignRepositoryError> {
    if pending {
        return Ok(crate::ContinuationState::Open);
    }
    if profile == CandidateSourceProfile::CorpusMutation {
        if proposed >= maximum_proposals {
            return Ok(crate::ContinuationState::Closed);
        }
        if has_next_candidate {
            return Ok(crate::ContinuationState::Ready);
        }
        let required = completed_visits
            .checked_add(1)
            .ok_or_else(|| integrity("corpus-mutation-feedback-threshold-overflow"))?;
        return Ok(crate::ContinuationState::WaitingForFeedback(
            crate::FeedbackWait::new(completed_visits, required)?,
        ));
    }
    if Some(proposed) == profile.count() {
        return Ok(if profile.exhausts_at_count() {
            crate::ContinuationState::Exhausted
        } else {
            crate::ContinuationState::Closed
        });
    }
    if proposed >= maximum_proposals {
        return Ok(crate::ContinuationState::Closed);
    }
    if proposed < profile.available_count(completed_visits)? {
        return Ok(crate::ContinuationState::Ready);
    }
    let required = profile
        .required_visits(proposed)?
        .ok_or_else(|| integrity("candidate-source-readiness-is-inconsistent"))?;
    Ok(crate::ContinuationState::WaitingForFeedback(
        crate::FeedbackWait::new(completed_visits, required)?,
    ))
}

pub(super) fn next_mixture_component(
    states: &[MixtureComponentState],
) -> Result<Option<usize>, CampaignRepositoryError> {
    let mut selected = None;
    for (index, state) in states.iter().enumerate() {
        if state.cursor == state.values.len() {
            continue;
        }
        let Some(current) = selected else {
            selected = Some(index);
            continue;
        };
        let current_state = &states[current];
        let state_finish = u128::try_from(
            state
                .cursor
                .checked_add(1)
                .ok_or_else(|| integrity("ordered-mixture-generator-work-limit"))?,
        )
        .map_err(|_| integrity("ordered-mixture-generator-work-limit"))?
        .checked_mul(u128::from(current_state.weight))
        .ok_or_else(|| integrity("ordered-mixture-generator-weight-overflow"))?;
        let current_finish = u128::try_from(
            current_state
                .cursor
                .checked_add(1)
                .ok_or_else(|| integrity("ordered-mixture-generator-work-limit"))?,
        )
        .map_err(|_| integrity("ordered-mixture-generator-work-limit"))?
        .checked_mul(u128::from(state.weight))
        .ok_or_else(|| integrity("ordered-mixture-generator-weight-overflow"))?;
        if state_finish < current_finish {
            selected = Some(index);
        }
    }
    Ok(selected)
}

pub(in crate::repository) fn charge_mixture_work(
    remaining_work: &mut usize,
    work: usize,
) -> Result<(), CampaignRepositoryError> {
    *remaining_work = remaining_work
        .checked_sub(work)
        .ok_or_else(|| integrity("ordered-mixture-generator-work-limit"))?;
    Ok(())
}

pub(in crate::repository) fn require_mixture_work_capacity(
    remaining_work: &usize,
    work: usize,
) -> Result<(), CampaignRepositoryError> {
    if work > *remaining_work {
        return Err(integrity("ordered-mixture-generator-work-limit"));
    }
    Ok(())
}

pub(in crate::repository) fn weighted_categorical_draw(
    request_digest: [u8; 32],
    draw_index: u64,
    total_weight: u128,
) -> Result<u128, CampaignRepositoryError> {
    if total_weight == 0 {
        return Err(integrity("weighted-generator-weight-sum-is-zero"));
    }
    let rejection_threshold = 0_u128.wrapping_sub(total_weight) % total_weight;
    for nonce in 0..MAX_WEIGHTED_CATEGORICAL_REJECTION_DRAWS {
        let mut basis = [0_u8; 48];
        basis[..32].copy_from_slice(&request_digest);
        basis[32..40].copy_from_slice(&draw_index.to_be_bytes());
        basis[40..].copy_from_slice(&nonce.to_be_bytes());
        let hash = CampaignHash::derive(
            "crucible.campaign.generator.weighted-categorical.v7",
            &basis,
        );
        let mut sample_bytes = [0_u8; 16];
        sample_bytes.copy_from_slice(&hash.as_bytes()[..16]);
        let sample = u128::from_be_bytes(sample_bytes);
        if sample >= rejection_threshold {
            return Ok(sample % total_weight);
        }
    }
    Err(integrity("weighted-generator-rejection-limit"))
}

pub(in crate::repository) fn smc_weighted_categorical_draw(
    policy_digest: [u8; 32],
    stage: u32,
    slot: u32,
    total_weight: u128,
) -> Result<u128, CampaignRepositoryError> {
    if stage == 0 || total_weight == 0 {
        return Err(integrity(
            "SMC proposal draw has an invalid stage or weight sum",
        ));
    }
    let rejection_threshold = 0_u128.wrapping_sub(total_weight) % total_weight;
    for nonce in 0..MAX_WEIGHTED_CATEGORICAL_REJECTION_DRAWS {
        let mut basis = [0_u8; 48];
        basis[..32].copy_from_slice(&policy_digest);
        basis[32..36].copy_from_slice(&stage.to_be_bytes());
        basis[36..40].copy_from_slice(&slot.to_be_bytes());
        basis[40..].copy_from_slice(&nonce.to_be_bytes());
        let hash = CampaignHash::derive("crucible.campaign.smc-proposal-draw.v1", &basis);
        let mut sample_bytes = [0_u8; 16];
        sample_bytes.copy_from_slice(&hash.as_bytes()[..16]);
        let sample = u128::from_be_bytes(sample_bytes);
        if sample >= rejection_threshold {
            return Ok(sample % total_weight);
        }
    }
    Err(integrity("SMC proposal rejection limit"))
}

pub(in crate::repository) fn push_static_integer_candidate(
    values: &mut Vec<IntegerValue>,
    seen: &mut BTreeSet<IntegerValue>,
    domain: &IntegerDomain,
    value: IntegerValue,
) -> Result<(), CampaignRepositoryError> {
    if domain.contains_integer(value) && seen.insert(value) {
        if values.len() == MAX_STATIC_GENERATOR_CANDIDATES {
            return Err(integrity("static-generator-candidate-limit"));
        }
        values.push(value);
    }
    Ok(())
}

pub(in crate::repository) fn log_integer_candidates(
    base: u32,
    domain: &IntegerDomain,
) -> Result<Vec<IntegerValue>, CampaignRepositoryError> {
    if base < 2 {
        return Err(integrity("log-generator-base-is-invalid"));
    }
    let minimum = positive_integer_magnitude(domain.minimum())
        .ok_or_else(|| integrity("log-generator-domain-is-not-positive"))?;
    let maximum = positive_integer_magnitude(domain.maximum())
        .ok_or_else(|| integrity("log-generator-domain-is-not-positive"))?;
    let step = u128::from(domain.step());
    let mut values = Vec::new();
    let mut seen = BTreeSet::new();
    push_static_integer_candidate(&mut values, &mut seen, domain, domain.minimum())?;

    let mut power = 1_u128;
    while power <= maximum {
        let rounded = if power <= minimum {
            minimum
        } else {
            let distance = power - minimum;
            let steps = distance / step + u128::from(!distance.is_multiple_of(step));
            minimum
                .checked_add(
                    steps
                        .checked_mul(step)
                        .ok_or_else(|| integrity("candidate-source-cardinality-overflow"))?,
                )
                .ok_or_else(|| integrity("candidate-source-cardinality-overflow"))?
        };
        if rounded <= maximum {
            let value = integer_value_from_magnitude(domain.representation(), rounded)?;
            push_static_integer_candidate(&mut values, &mut seen, domain, value)?;
        }
        power = match power.checked_mul(u128::from(base)) {
            Some(next) => next,
            None => break,
        };
    }

    push_static_integer_candidate(&mut values, &mut seen, domain, domain.maximum())?;
    if values.len() > crate::LOG_INTEGER_GENERATOR_MAX_CANDIDATES {
        return Err(integrity("log-generator-candidate-limit"));
    }
    Ok(values)
}

fn positive_integer_magnitude(value: IntegerValue) -> Option<u128> {
    match value {
        IntegerValue::Signed(value) => u128::try_from(value).ok().filter(|value| *value > 0),
        IntegerValue::Unsigned(value) => (value > 0).then_some(u128::from(value)),
    }
}

fn integer_value_from_magnitude(
    representation: IntegerRepresentation,
    magnitude: u128,
) -> Result<IntegerValue, CampaignRepositoryError> {
    match representation {
        IntegerRepresentation::Signed64 => i64::try_from(magnitude)
            .map(IntegerValue::Signed)
            .map_err(|_| integrity("candidate-source-cardinality-overflow")),
        IntegerRepresentation::Unsigned64 => u64::try_from(magnitude)
            .map(IntegerValue::Unsigned)
            .map_err(|_| integrity("candidate-source-cardinality-overflow")),
    }
}

pub(in crate::repository) fn integer_step_neighbor(
    value: IntegerValue,
    step: u64,
    add: bool,
) -> Option<IntegerValue> {
    match value {
        IntegerValue::Signed(value) => {
            let value = i128::from(value);
            let step = i128::from(step);
            let neighbor = if add {
                value.checked_add(step)?
            } else {
                value.checked_sub(step)?
            };
            i64::try_from(neighbor).ok().map(IntegerValue::Signed)
        }
        IntegerValue::Unsigned(value) => {
            let neighbor = if add {
                value.checked_add(step)?
            } else {
                value.checked_sub(step)?
            };
            Some(IntegerValue::Unsigned(neighbor))
        }
    }
}

/// Adds `amount` to one key's checked count, leaving zero amounts unrecorded.
pub(in crate::repository) fn add_edge_count<K: Ord>(
    counts: &mut BTreeMap<K, u64>,
    key: K,
    amount: u64,
    overflow: &'static str,
) -> Result<(), CampaignRepositoryError> {
    if amount == 0 {
        return Ok(());
    }
    let total = counts.entry(key).or_default();
    *total = total
        .checked_add(amount)
        .ok_or_else(|| integrity(overflow))?;
    Ok(())
}

/// Keeps the prior of the lowest admission ordinal credited to each edge.
pub(super) fn merge_edge_prior_basis(
    basis: &mut BTreeMap<crate::BranchEdgeId, AttemptProposalPrior>,
    edge: crate::BranchEdgeId,
    prior: AttemptProposalPrior,
) -> Result<(), CampaignRepositoryError> {
    match basis.entry(edge) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(prior);
        }
        std::collections::btree_map::Entry::Occupied(mut entry) => {
            let current = *entry.get();
            if prior.admission_ordinal < current.admission_ordinal {
                entry.insert(prior);
            } else if prior.admission_ordinal == current.admission_ordinal
                && prior.raw_weight != current.raw_weight
            {
                return Err(integrity("branch-edge-prior-basis-conflict"));
            }
        }
    }
    Ok(())
}

pub(in crate::repository) fn charge_branch_prior_normalization_visits(
    prior: usize,
    visits: usize,
) -> Result<usize, CampaignRepositoryError> {
    let total = prior
        .checked_add(visits)
        .ok_or_else(|| integrity("planner-prior-normalization-visit-count"))?;
    if total > crate::MAX_BRANCH_PRIOR_NORMALIZATION_VISITS {
        return Err(integrity("planner-prior-normalization-visit-count"));
    }
    Ok(total)
}

/// Returns one occurrence's inverse-frequency rarity, `max(1, floor(Q / f))`.
///
/// `f` is the identity's positive global frequency, saturated by the
/// coverage-identity frequency index; every saturated or larger frequency
/// contributes one.
pub(in crate::repository) fn branch_rarity_contribution(frequency: u64) -> u64 {
    crate::BRANCH_RARITY_SCALE
        .checked_div(frequency)
        .unwrap_or(0)
        .max(1)
}

pub(in crate::repository) fn charge_branch_finding_work(
    prior: usize,
    bytes: usize,
) -> Result<usize, CampaignRepositoryError> {
    let total = prior
        .checked_add(bytes)
        .ok_or_else(|| integrity("branch-finding-projection-byte-limit"))?;
    if total > crate::MAX_BRANCH_FINDING_PROJECTION_BYTES {
        return Err(integrity("branch-finding-projection-byte-limit"));
    }
    Ok(total)
}

pub(in crate::repository) fn charge_branch_finding_occurrence_visits(
    prior: u64,
    occurrences: u64,
) -> Result<u64, CampaignRepositoryError> {
    let total = prior
        .checked_add(occurrences)
        .ok_or_else(|| integrity("branch-finding-occurrence-visit-limit"))?;
    if total > crate::MAX_BRANCH_FINDING_OCCURRENCE_VISITS {
        return Err(integrity("branch-finding-occurrence-visit-limit"));
    }
    Ok(total)
}

pub(in crate::repository) fn charge_planner_guidance_domain_work(
    prior: usize,
    bytes: usize,
) -> Result<usize, CampaignRepositoryError> {
    let total = prior
        .checked_add(bytes)
        .ok_or_else(|| integrity("planner-guidance-domain-byte-limit"))?;
    if total > crate::MAX_PLANNER_GUIDANCE_DOMAIN_BYTES {
        return Err(integrity("planner-guidance-domain-byte-limit"));
    }
    Ok(total)
}

pub(in crate::repository) fn stratified_integer_candidate_count(
    strata: u32,
    domain: &IntegerDomain,
) -> Result<u64, CampaignRepositoryError> {
    if strata > crate::STRATIFIED_INTEGER_GENERATOR_MAX_STRATA {
        return Err(integrity("stratified-generator-strata-limit"));
    }
    u64::try_from(domain.cardinality().min(u128::from(strata)))
        .map_err(|_| integrity("candidate-source-cardinality-overflow"))
}

pub(in crate::repository) fn stratified_integer_candidate(
    strata: u32,
    domain: &IntegerDomain,
    ordinal: u64,
) -> Result<IntegerValue, CampaignRepositoryError> {
    integer_candidate_at_offset(domain, stratified_integer_offset(strata, domain, ordinal)?)
}

fn stratified_integer_offset(
    strata: u32,
    domain: &IntegerDomain,
    ordinal: u64,
) -> Result<u128, CampaignRepositoryError> {
    let candidate_count = stratified_integer_candidate_count(strata, domain)?;
    if ordinal == 0 || ordinal > candidate_count {
        return Err(integrity("proposal-ordinal-exceeds-source-cardinality"));
    }

    let maximum_offset = domain
        .cardinality()
        .checked_sub(1)
        .ok_or_else(|| integrity("candidate-source-cardinality-overflow"))?;
    let offset = if candidate_count == 1 {
        maximum_offset / 2
    } else {
        u128::from(ordinal - 1)
            .checked_mul(maximum_offset)
            .ok_or_else(|| integrity("candidate-source-cardinality-overflow"))?
            / u128::from(candidate_count - 1)
    };
    Ok(offset)
}
