//! Equivalence tests for the streaming version-10 corpus-mutation walk.

// crucible-lint: allow panic-shortcut -- these pure walk tests use panics to identify invalid fixtures.
#![allow(clippy::expect_used)]

use super::*;
use crate::ExactRational;

/// Reproduces the original whole-set version-10 candidate list.
///
/// This is the pre-streaming algorithm without its anchor-distance work cap:
/// every anchor in ascending order probes each distance, lower before upper,
/// and the list stops at `maximum_candidates`.
fn reference_candidates(
    domain: &IntegerDomain,
    anchors: &BTreeSet<IntegerValue>,
    maximum_distance: u64,
    maximum_candidates: usize,
) -> Vec<IntegerValue> {
    let mut candidates = Vec::new();
    let mut seen = BTreeSet::new();
    for anchor in anchors.iter().copied() {
        let mut lower = Some(anchor);
        let mut upper = Some(anchor);
        for _ in 0..maximum_distance {
            lower = lower.and_then(|value| integer_step_neighbor(value, domain.step(), false));
            upper = upper.and_then(|value| integer_step_neighbor(value, domain.step(), true));
            let mut admitted = false;
            for candidate in [lower, upper].into_iter().flatten() {
                if domain.contains_integer(candidate) && seen.insert(candidate) {
                    candidates.push(candidate);
                    admitted = true;
                    if candidates.len() == maximum_candidates {
                        return candidates;
                    }
                }
            }
            if lower.is_none() && upper.is_none() {
                break;
            }
            if !admitted
                && lower.is_none_or(|value| !domain.contains_integer(value))
                && upper.is_none_or(|value| !domain.contains_integer(value))
            {
                break;
            }
        }
    }
    candidates
}

fn walk_first_unproposed(
    domain: &IntegerDomain,
    anchors: &[IntegerValue],
    maximum_distance: u64,
    maximum_candidates: usize,
    proposed: &BTreeSet<IntegerValue>,
) -> Option<IntegerValue> {
    let mut walk =
        CorpusMutationWalk::new(domain, maximum_distance, maximum_candidates).expect("walk");
    for anchor in anchors {
        match walk
            .visit(*anchor, |value| proposed.contains(&value))
            .expect("visit anchor")
        {
            CorpusMutationStep::Continue => {}
            CorpusMutationStep::Found(value) => return Some(value),
            CorpusMutationStep::Exhausted => return None,
        }
    }
    None
}

fn integer_domain(minimum: IntegerValue, maximum: IntegerValue, step: u64) -> IntegerDomain {
    let representation = match minimum {
        IntegerValue::Signed(_) => IntegerRepresentation::Signed64,
        IntegerValue::Unsigned(_) => IntegerRepresentation::Unsigned64,
    };
    IntegerDomain::new(
        1,
        representation,
        minimum,
        maximum,
        step,
        None,
        ExactRational::new(1, 1).expect("scale"),
        Vec::new(),
    )
    .expect("integer domain")
}

/// Small deterministic generator so failures reproduce exactly.
struct SplitMix(u64);

impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

#[test]
fn walk_matches_reference_order_for_random_corpora() {
    let mut random = SplitMix(0x0c0f_fee0);
    let domains = [
        integer_domain(IntegerValue::Unsigned(0), IntegerValue::Unsigned(60), 1),
        integer_domain(IntegerValue::Unsigned(5), IntegerValue::Unsigned(305), 3),
        integer_domain(IntegerValue::Signed(-40), IntegerValue::Signed(40), 1),
        integer_domain(IntegerValue::Signed(-100), IntegerValue::Signed(98), 2),
        integer_domain(
            IntegerValue::Signed(i64::MIN),
            IntegerValue::Signed(i64::MIN + 20),
            1,
        ),
        integer_domain(
            IntegerValue::Unsigned(u64::MAX - 30),
            IntegerValue::Unsigned(u64::MAX),
            1,
        ),
    ];

    for case in 0..4_000 {
        let domain = &domains[case % domains.len()];
        let cardinality = u64::try_from(domain.cardinality()).expect("small domain");
        let anchor_count = 1 + random.below(24);
        let anchors = (0..anchor_count)
            .map(|_| {
                integer_candidate_at_offset(domain, u128::from(random.below(cardinality)))
                    .expect("anchor in domain")
            })
            .collect::<BTreeSet<_>>();
        let proposed = (0..random.below(cardinality))
            .map(|_| {
                integer_candidate_at_offset(domain, u128::from(random.below(cardinality)))
                    .expect("proposed value in domain")
            })
            .collect::<BTreeSet<_>>();
        let maximum_distance = 1 + random.below(12);
        let maximum_candidates = usize::try_from(1 + random.below(40)).expect("small window");

        let expected = reference_candidates(domain, &anchors, maximum_distance, maximum_candidates)
            .into_iter()
            .find(|candidate| !proposed.contains(candidate));

        // Repeated anchors model distinct selection records with one value.
        let mut streamed = Vec::new();
        for anchor in &anchors {
            streamed.push(*anchor);
            if random.below(4) == 0 {
                streamed.push(*anchor);
            }
        }
        let actual = walk_first_unproposed(
            domain,
            &streamed,
            maximum_distance,
            maximum_candidates,
            &proposed,
        );
        assert_eq!(actual, expected, "case {case}");
    }
}

#[test]
fn walk_reports_exhaustion_exactly_when_the_window_is_proposed() {
    let domain = integer_domain(IntegerValue::Unsigned(0), IntegerValue::Unsigned(100), 1);
    let anchors = [IntegerValue::Unsigned(10), IntegerValue::Unsigned(50)];
    let window = reference_candidates(&domain, &anchors.into_iter().collect(), 3, 6);
    let proposed = window.iter().copied().collect::<BTreeSet<_>>();

    let mut walk = CorpusMutationWalk::new(&domain, 3, 6).expect("walk");
    assert_eq!(
        walk.visit(anchors[0], |value| proposed.contains(&value))
            .expect("first anchor"),
        CorpusMutationStep::Exhausted
    );

    // A larger window reaches the second anchor's first neighbor.
    assert_eq!(
        walk_first_unproposed(&domain, &anchors, 3, 7, &proposed),
        Some(IntegerValue::Unsigned(49))
    );
}

/// A dense anchor cluster near the domain edge once required
/// `anchors * maximum_distance` probes and failed the 65,536-unit work cap.
#[test]
fn walk_skips_emitted_runs_in_dense_corpora() {
    let domain = integer_domain(IntegerValue::Unsigned(0), IntegerValue::Unsigned(9_000), 1);
    let anchors = (8_000..=9_000)
        .map(IntegerValue::Unsigned)
        .collect::<Vec<_>>();
    let anchor_set = anchors.iter().copied().collect::<BTreeSet<_>>();
    let reference = reference_candidates(&domain, &anchor_set, 2_000, 4_096);
    assert_eq!(reference.len(), 3_001);

    // Only the second anchor's own lower neighbor remains unproposed.
    let proposed = reference
        .iter()
        .copied()
        .filter(|value| *value != IntegerValue::Unsigned(8_000))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        walk_first_unproposed(&domain, &anchors, 2_000, 4_096, &proposed),
        Some(IntegerValue::Unsigned(8_000))
    );

    let all_proposed = reference.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(
        walk_first_unproposed(&domain, &anchors, 2_000, 4_096, &all_proposed),
        None
    );
}

#[test]
fn walk_rejects_descending_anchors_and_owner_limits() {
    let domain = integer_domain(IntegerValue::Signed(-5), IntegerValue::Signed(5), 1);
    let mut walk = CorpusMutationWalk::new(&domain, 1, 4).expect("walk");
    assert_eq!(
        walk.visit(IntegerValue::Signed(2), |_| true)
            .expect("first anchor"),
        CorpusMutationStep::Continue
    );
    assert!(matches!(
        walk.visit(IntegerValue::Signed(1), |_| true),
        Err(CampaignRepositoryError::Integrity {
            reason: "corpus-mutation-anchor-order-mismatch"
        })
    ));

    for (distance, window) in [
        (0, 1),
        (crate::CORPUS_MUTATION_GENERATOR_MAX_DISTANCE + 1, 1),
        (1, 0),
        (
            1,
            usize::try_from(crate::CORPUS_MUTATION_GENERATOR_MAX_PROPOSALS + 1).expect("window"),
        ),
    ] {
        assert!(matches!(
            CorpusMutationWalk::new(&domain, distance, window),
            Err(CampaignRepositoryError::Integrity {
                reason: "corpus-mutation-generator-owner-limit"
            })
        ));
    }
}

#[test]
fn direct_selection_order_keys_sort_in_canonical_integer_order() {
    let kind = crate::CampaignRecordKind::Selection;
    let selection = crate::SelectionId::from_content_id(ContentId::for_bytes(
        kind.object_kind(),
        kind.schema_version(),
        b"selection",
    ))
    .expect("selection id");
    let values = [
        IntegerValue::Signed(i64::MIN),
        IntegerValue::Signed(-1),
        IntegerValue::Signed(0),
        IntegerValue::Signed(i64::MAX),
        IntegerValue::Unsigned(0),
        IntegerValue::Unsigned(1 << 63),
        IntegerValue::Unsigned(u64::MAX),
    ];
    let keys = values
        .iter()
        .map(|value| direct_selection_index_order_key(*value, selection))
        .collect::<Vec<_>>();
    assert!(keys.windows(2).all(|pair| pair[0] < pair[1]));
}
