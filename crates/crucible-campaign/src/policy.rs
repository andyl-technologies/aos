//! Immutable campaign policy and exact exploration parameters.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use crucible_cas::content_store::ContentId;

use super::codec::{self, Canonical, Decoder, Encoder};
use super::{
    AlternativeId, CampaignCodecError, CampaignHash, CampaignPolicyId, CandidateGeneratorSpecId,
    ScenarioDefId,
};

mod smc;
mod statistical;

pub use smc::{
    MAX_SMC_TOTAL_PARTICLE_TRANSITIONS, SequentialMonteCarloDesign, SmcOpportunitySelector,
    SmcResamplingAlgorithm, SmcResamplingPolicy, SmcStagePlan,
};
pub use statistical::{StatisticalDistribution, StatisticalDrawPlan, StatisticalSamplingDesign};

const BASE_CAMPAIGN_POLICY_SCHEMA_VERSION: u32 = 1;
const INTERVENTION_CAMPAIGN_POLICY_SCHEMA_VERSION: u32 = 2;
const FINITE_STATISTICAL_CAMPAIGN_POLICY_SCHEMA_VERSION: u32 = 3;
const CAMPAIGN_POLICY_SCHEMA_VERSION: u32 = 4;
pub(crate) const MAX_POLICY_ENTRIES: usize = 4_096;
const MAX_CAMPAIGN_POLICY_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_IDENTIFIER_BYTES: usize = 512;
const CANDIDATE_GENERATOR_SCHEMA_VERSION: u32 = 1;
const MAX_GENERATOR_WEIGHTS: usize = 4096;
const MAX_GENERATOR_COMPONENTS: usize = 256;
const MAX_CANDIDATE_GENERATOR_BYTES: usize = 4 * 1024 * 1024;

/// Generator implementation version for static `all` enumeration.
///
/// This version enumerates Boolean values as `false`, then `true`, and discrete
/// alternatives in stable [`AlternativeId`] order. For integer domains, the
/// request addresses only the canonical prefix bounded by its proposal budget;
/// exhausting that prefix closes the request unless it also covers the complete
/// semantic domain. Unknown versions fail closed.
pub const STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION: u32 = 2;

/// Generator implementation version for static boundary-integer enumeration.
///
/// This version has a closed ordering over boundaries, the opportunity default,
/// landmarks, adjacent legal values, and signedness-appropriate powers of two.
/// Unknown versions fail closed.
pub const BOUNDARY_INTEGER_GENERATOR_IMPLEMENTATION_VERSION: u32 = 3;

/// Maximum landmarks admitted by boundary-integer implementation version 3.
///
/// The implementation derives at most 512 candidates including boundaries,
/// neighbors, and powers of two, keeping restart validation work bounded.
pub const BOUNDARY_INTEGER_GENERATOR_MAX_LANDMARKS: usize = 64;

/// Generator implementation version for static stratified-integer enumeration.
///
/// This version maps evenly spaced ordinal offsets onto the exact stepped
/// integer domain, includes both endpoints when more than one stratum is
/// requested, and uses the lower midpoint for a single stratum. Unknown versions fail closed.
pub const STRATIFIED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION: u32 = 4;

/// Maximum strata admitted by stratified-integer implementation version 4.
///
/// Candidate values are reconstructed in constant space, while this bound
/// limits proposal and restart owner-validation work for one branch request.
pub const STRATIFIED_INTEGER_GENERATOR_MAX_STRATA: u32 = 4_096;

/// Generator implementation version for static logarithmic-integer enumeration.
///
/// This version emits a positive stepped domain's minimum, each integral power
/// of the declared base rounded upward to the next legal value, and its maximum.
/// Unknown versions fail closed.
pub const LOG_INTEGER_GENERATOR_IMPLEMENTATION_VERSION: u32 = 5;

/// Maximum candidates derived by logarithmic-integer implementation version 5.
///
/// A base of two over the full unsigned 64-bit range is the largest sequence:
/// 64 powers plus a distinct inclusive maximum.
pub const LOG_INTEGER_GENERATOR_MAX_CANDIDATES: usize = 65;

/// Generator implementation version for keyed finite-integer permutation.
///
/// This version derives a four-round bounded permutation from the immutable
/// branch-request identity and maps it onto exact stepped-domain offsets.
/// Unknown versions fail closed.
pub const PERMUTED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION: u32 = 6;

/// Maximum cardinality admitted by permuted-integer implementation version 6.
///
/// Proposal ordinals are 64-bit and one-based, so a domain with `2^64` legal
/// values cannot be named completely and fails closed.
pub const PERMUTED_INTEGER_GENERATOR_MAX_CARDINALITY: u128 = u64::MAX as u128;

/// Generator implementation version for modeled uniform-integer permutation.
///
/// This version resolves a uniform integer probability model into a
/// request-keyed permutation of its exact stepped domain. It admits the full
/// `2^64` unsigned domain while one request still emits at most its explicit
/// 64-bit proposal budget. Unknown versions fail closed.
pub const MODELED_UNIFORM_INTEGER_GENERATOR_IMPLEMENTATION_VERSION: u32 = 17;

/// Generator implementation version for weighted categorical enumeration.
///
/// This version derives a request-keyed exact integer-weight draw at each
/// ordinal and removes the selected alternative before the next draw. Unknown
/// versions fail closed.
pub const WEIGHTED_CATEGORICAL_GENERATOR_IMPLEMENTATION_VERSION: u32 = 7;

/// Maximum alternatives admitted by weighted-categorical implementation version 7.
///
/// Owner validation may reconstruct the complete weighted permutation for
/// every retained proposal. This bound keeps that restart work finite while
/// allowing substantially larger sources than explicit finite requests.
pub const WEIGHTED_CATEGORICAL_GENERATOR_MAX_ALTERNATIVES: usize = 256;

/// Generator implementation version for ordered static-generator mixtures.
///
/// This version schedules child values by exact weighted virtual finish time,
/// advances duplicate-producing children, and emits each choice value once.
/// Unknown versions fail closed.
pub const ORDERED_MIXTURE_GENERATOR_IMPLEMENTATION_VERSION: u32 = 8;

/// Maximum distinct values emitted by ordered-mixture implementation version 8.
pub const ORDERED_MIXTURE_GENERATOR_MAX_CANDIDATES: usize = 512;

/// Maximum recursive materialization and scheduling work for one mixture poll.
pub const ORDERED_MIXTURE_GENERATOR_MAX_WORK_ITEMS: usize = 8_192;

/// Maximum nested executable-mixture depth.
pub const ORDERED_MIXTURE_GENERATOR_MAX_DEPTH: usize = 64;

/// Generator implementation version for feedback-gated integer refinement.
///
/// This version emits an initial exact stratification, then repeatedly bisects
/// the largest remaining legal-offset interval. Refinement `r` requires the
/// branch point's cumulative completed-visit count to reach `r` times the
/// declared interval. Version 11 retains these gates with a distinct
/// feedback-scored interval order; unknown versions fail closed.
pub const PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION: u32 = 9;

/// Generator implementation version for feedback-scored integer refinement.
///
/// This version retains version 9's exact stratified prefix and visit gates,
/// then scores every remaining interval by the absolute difference between its
/// owner-derived endpoint PUCT scores. Equal scores prefer the largest interval
/// and then its lowest legal offset. Each listed current version retains its
/// defined behavior, while unknown versions fail closed.
pub const FEEDBACK_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION: u32 = 11;

/// Generator implementation version for landmark-aware integer refinement.
///
/// This version retains version 11's exact prefix, visit gates, and endpoint
/// PUCT-score basis. Intervals sort by the count of unproposed producer
/// landmarks before the version-11 terms; the selected interval emits the
/// landmark nearest to its lower midpoint before ordinary refinement resumes.
pub const LANDMARK_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION: u32 = 12;

/// Generator implementation version for measurement-sensitive integer refinement.
///
/// This version retains version 12's exact landmark and PUCT terms, preceded by
/// the exact discontinuity between the endpoint edges' mean owner-verified
/// objective rewards. Each listed current version retains its own interval order.
pub const MEASUREMENT_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION: u32 = 13;

/// Generator implementation version for coverage-sensitive integer refinement.
///
/// This version retains version 13's exact objective, landmark, and PUCT terms,
/// preceded by the exact discontinuity between the endpoint edges' mean counts
/// of globally unique owner-verified coverage identities. Each listed current
/// version retains its own interval order.
pub const COVERAGE_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION: u32 = 14;

/// Generator implementation version for finding-sensitive integer refinement.
///
/// This version retains version 14's exact coverage, objective, landmark, and
/// PUCT terms, preceded by the exact discontinuity between the endpoint edges'
/// mean active-policy-weighted owner-verified finding rewards. Each listed
/// current version retains its own interval order.
pub const FINDING_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION: u32 = 15;

/// Implementation version for rarity-sensitive progressive integer refinement.
///
/// Version 16 retains version 15's finding, coverage, objective, landmark, and
/// PUCT terms but first compares the exact mean inverse-frequency coverage
/// rarity mass at the two interval endpoints.
pub const RARITY_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION: u32 = 16;

/// Maximum initial strata admitted by executable progressive-integer versions.
pub const PROGRESSIVE_INTEGER_GENERATOR_MAX_INITIAL_STRATA: u32 = 4_096;

/// Maximum proposals admitted by one executable progressive-integer request.
///
/// Owner recomputation retains a bounded interval heap through proposal,
/// observation, import, and restart validation.
pub const PROGRESSIVE_INTEGER_GENERATOR_MAX_PROPOSALS: u64 = 4_096;

/// Generator implementation version for retained-corpus integer mutation.
///
/// This version derives direct completed selections from the exact planning
/// view, then emits bounded lower/upper legal-step mutations while suppressing
/// every value already proposed by the same immutable branch request. Unknown
/// versions fail closed.
pub const CORPUS_MUTATION_GENERATOR_IMPLEMENTATION_VERSION: u32 = 10;

/// Maximum completed branch-point credits inspected by corpus mutation.
pub const CORPUS_MUTATION_GENERATOR_MAX_CREDITS: u64 = 4_096;

/// Maximum legal-step distance admitted by corpus-mutation version 10.
pub const CORPUS_MUTATION_GENERATOR_MAX_DISTANCE: u64 = 4_096;

/// Maximum proposals admitted by one corpus-mutation branch request.
pub const CORPUS_MUTATION_GENERATOR_MAX_PROPOSALS: u64 = 4_096;

/// Maximum canonical credit, observation, and attempt bytes inspected per poll.
pub const CORPUS_MUTATION_GENERATOR_MAX_INPUT_BYTES: usize = 128 * 1024 * 1024;

/// Maximum mutation-neighbor work units consumed by one owner recomputation.
pub const CORPUS_MUTATION_GENERATOR_MAX_WORK_ITEMS: usize = 65_536;

/// Fixed seed that makes campaign proposal streams reproducible.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CampaignSeed([u8; 32]);

impl CampaignSeed {
    /// Builds a campaign seed from exactly 32 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the exact seed bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl Canonical for CampaignSeed {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.fixed(&self.0);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self(decoder.fixed()?))
    }
}

/// Reproducibility and statistical claim mode for campaign planning.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CampaignMode {
    /// Folds attempt results in deterministic admission order.
    Strict,
    /// Folds results as their canonical observations become available.
    Streaming,
    /// Enforces modeled support and proposal-weight accounting.
    Statistical,
}

impl Canonical for CampaignMode {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(match self {
            Self::Strict => 0,
            Self::Streaming => 1,
            Self::Statistical => 2,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Strict),
            1 => Ok(Self::Streaming),
            2 => Ok(Self::Statistical),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "campaign-mode",
                tag,
            }),
        }
    }
}

/// Reduced nonnegative rational used by exact planner arithmetic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ExactRational {
    numerator: u64,
    denominator: u64,
}

impl Ord for ExactRational {
    fn cmp(&self, other: &Self) -> Ordering {
        (u128::from(self.numerator) * u128::from(other.denominator))
            .cmp(&(u128::from(other.numerator) * u128::from(self.denominator)))
    }
}

impl PartialOrd for ExactRational {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl ExactRational {
    /// Builds and reduces a nonnegative rational.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError::InvalidValue`] when `denominator` is zero.
    pub fn new(numerator: u64, denominator: u64) -> Result<Self, CampaignCodecError> {
        if denominator == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "rational denominator is zero",
            });
        }
        let divisor = greatest_common_divisor(numerator, denominator);
        Ok(Self {
            numerator: numerator / divisor,
            denominator: denominator / divisor,
        })
    }

    /// Returns the reduced numerator.
    #[must_use]
    pub const fn numerator(self) -> u64 {
        self.numerator
    }

    /// Returns the positive reduced denominator.
    #[must_use]
    pub const fn denominator(self) -> u64 {
        self.denominator
    }
}

impl Canonical for ExactRational {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u64(self.numerator);
        encoder.u64(self.denominator);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(decoder.u64()?, decoder.u64()?)
    }
}

/// Deterministic fixed-point PUCT parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PuctPolicy {
    exploration_weight_micros: u64,
    novelty_bonus_micros: u64,
    fairness_bonus_micros: u64,
}

impl PuctPolicy {
    /// Builds fixed-point PUCT weights.
    #[must_use]
    pub const fn new(
        exploration_weight_micros: u64,
        novelty_bonus_micros: u64,
        fairness_bonus_micros: u64,
    ) -> Self {
        Self {
            exploration_weight_micros,
            novelty_bonus_micros,
            fairness_bonus_micros,
        }
    }

    /// Returns the exploration weight in millionths.
    #[must_use]
    pub const fn exploration_weight_micros(self) -> u64 {
        self.exploration_weight_micros
    }

    /// Returns the novelty bonus in millionths.
    #[must_use]
    pub const fn novelty_bonus_micros(self) -> u64 {
        self.novelty_bonus_micros
    }

    /// Returns the fairness bonus in millionths.
    #[must_use]
    pub const fn fairness_bonus_micros(self) -> u64 {
        self.fairness_bonus_micros
    }
}

impl Canonical for PuctPolicy {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u64(self.exploration_weight_micros);
        encoder.u64(self.novelty_bonus_micros);
        encoder.u64(self.fairness_bonus_micros);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self {
            exploration_weight_micros: decoder.u64()?,
            novelty_bonus_micros: decoder.u64()?,
            fairness_bonus_micros: decoder.u64()?,
        })
    }
}

/// Exact progressive-widening admission parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProgressiveWideningPolicy {
    k: ExactRational,
    alpha: ExactRational,
    initial_children: u64,
    maximum_children: u64,
    minimum_visits_per_child: u64,
}

impl ProgressiveWideningPolicy {
    /// Builds a bounded widening policy.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError::InvalidValue`] when limits are empty or
    /// inconsistent, or when the supported exponent is not `0`, `1/2`, or `1`.
    pub fn new(
        k: ExactRational,
        alpha: ExactRational,
        initial_children: u64,
        maximum_children: u64,
        minimum_visits_per_child: u64,
    ) -> Result<Self, CampaignCodecError> {
        let supported_alpha = matches!(
            (alpha.numerator(), alpha.denominator()),
            (0, 1) | (1, 2) | (1, 1)
        );
        if !supported_alpha {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported progressive-widening exponent",
            });
        }
        if maximum_children == 0 || initial_children > maximum_children {
            return Err(CampaignCodecError::InvalidValue {
                reason: "progressive-widening child limits are inconsistent",
            });
        }
        if minimum_visits_per_child == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "progressive-widening visit minimum is zero",
            });
        }
        Ok(Self {
            k,
            alpha,
            initial_children,
            maximum_children,
            minimum_visits_per_child,
        })
    }

    /// Returns the exact widening multiplier.
    #[must_use]
    pub const fn k(self) -> ExactRational {
        self.k
    }

    /// Returns the exact supported widening exponent.
    #[must_use]
    pub const fn alpha(self) -> ExactRational {
        self.alpha
    }

    /// Returns the initial fairness allocation.
    #[must_use]
    pub const fn initial_children(self) -> u64 {
        self.initial_children
    }

    /// Returns the hard distinct-child ceiling.
    #[must_use]
    pub const fn maximum_children(self) -> u64 {
        self.maximum_children
    }

    /// Returns the required completed visits per existing child.
    #[must_use]
    pub const fn minimum_visits_per_child(self) -> u64 {
        self.minimum_visits_per_child
    }
}

impl Canonical for ProgressiveWideningPolicy {
    fn encode(&self, encoder: &mut Encoder) {
        self.k.encode(encoder);
        self.alpha.encode(encoder);
        encoder.u64(self.initial_children);
        encoder.u64(self.maximum_children);
        encoder.u64(self.minimum_visits_per_child);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            ExactRational::decode(decoder)?,
            ExactRational::decode(decoder)?,
            decoder.u64()?,
            decoder.u64()?,
            decoder.u64()?,
        )
    }
}

/// Closed first-version exploration algorithm configuration.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ExplorerPolicy {
    /// Deterministic PUCT with optional progressive widening.
    TreeSearch {
        /// Exact fixed-point tree-selection policy.
        puct: PuctPolicy,
        /// Optional widening policy for large domains.
        widening: Option<ProgressiveWideningPolicy>,
    },
    /// Bounded Pareto or lexicographic stage survival.
    Beam {
        /// Maximum configurations retained at one barrier.
        width: u64,
        /// Slots reserved for novelty rather than objective rank.
        novelty_reserve: u64,
    },
    /// Complete iteration, admitted only below an explicit cardinality ceiling.
    Exhaustive {
        /// Maximum domain cardinality admitted for exhaustive expansion.
        maximum_cardinality: u64,
    },
}

impl ExplorerPolicy {
    fn validate(&self) -> Result<(), CampaignCodecError> {
        match self {
            Self::TreeSearch { .. } => Ok(()),
            Self::Beam {
                width,
                novelty_reserve,
            } if *width != 0 && novelty_reserve <= width => Ok(()),
            Self::Exhaustive {
                maximum_cardinality,
            } if *maximum_cardinality != 0 => Ok(()),
            Self::Beam { .. } => Err(CampaignCodecError::InvalidValue {
                reason: "beam width and novelty reserve are inconsistent",
            }),
            Self::Exhaustive { .. } => Err(CampaignCodecError::InvalidValue {
                reason: "exhaustive cardinality ceiling is zero",
            }),
        }
    }
}

impl Canonical for ExplorerPolicy {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::TreeSearch { puct, widening } => {
                encoder.u8(0);
                puct.encode(encoder);
                widening.encode(encoder);
            }
            Self::Beam {
                width,
                novelty_reserve,
            } => {
                encoder.u8(1);
                encoder.u64(*width);
                encoder.u64(*novelty_reserve);
            }
            Self::Exhaustive {
                maximum_cardinality,
            } => {
                encoder.u8(2);
                encoder.u64(*maximum_cardinality);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::TreeSearch {
                puct: PuctPolicy::decode(decoder)?,
                widening: Option::decode(decoder)?,
            }),
            1 => {
                let width = decoder.u64()?;
                let novelty_reserve = decoder.u64()?;
                if width == 0 || novelty_reserve > width {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "beam width and novelty reserve are inconsistent",
                    });
                }
                Ok(Self::Beam {
                    width,
                    novelty_reserve,
                })
            }
            2 => {
                let maximum_cardinality = decoder.u64()?;
                if maximum_cardinality == 0 {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "exhaustive cardinality ceiling is zero",
                    });
                }
                Ok(Self::Exhaustive {
                    maximum_cardinality,
                })
            }
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "explorer-policy",
                tag,
            }),
        }
    }
}

/// One weighted child in an ordered candidate-generator mixture.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WeightedGenerator {
    generator: CandidateGeneratorSpecId,
    weight: u64,
}

impl WeightedGenerator {
    /// Builds a positive weighted generator reference.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError::InvalidValue`] when `weight` is zero.
    pub fn new(
        generator: CandidateGeneratorSpecId,
        weight: u64,
    ) -> Result<Self, CampaignCodecError> {
        if weight == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "candidate-generator mixture weight is zero",
            });
        }
        Ok(Self { generator, weight })
    }

    /// Returns the referenced child generator.
    #[must_use]
    pub const fn generator(self) -> CandidateGeneratorSpecId {
        self.generator
    }

    /// Returns the exact positive integer mixture weight.
    #[must_use]
    pub const fn weight(self) -> u64 {
        self.weight
    }
}

impl Canonical for WeightedGenerator {
    fn encode(&self, encoder: &mut Encoder) {
        self.generator.encode(encoder);
        self.weight.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            CandidateGeneratorSpecId::decode(decoder)?,
            u64::decode(decoder)?,
        )
    }
}

/// Closed deterministic candidate-generation algorithm and exact parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CandidateGeneratorAlgorithm {
    /// Enumerates a domain or an explicitly proposal-bounded integer prefix.
    All,
    /// Samples discrete alternatives without replacement using exact weights.
    WeightedCategorical {
        /// Positive weights keyed by stable alternative identity.
        weights: BTreeMap<AlternativeId, u64>,
    },
    /// Spreads integer candidates across a fixed number of deterministic strata.
    StratifiedInteger {
        /// Positive number of strata.
        strata: u32,
    },
    /// Prioritizes boundaries, defaults, landmarks, adjacencies, and powers of two.
    BoundaryInteger,
    /// Samples positive integers from exact logarithmic buckets.
    LogInteger {
        /// Integer logarithm base, at least two.
        base: u32,
    },
    /// Walks a keyed permutation of a finite integer domain.
    PermutedInteger,
    /// Refines integer intervals after a declared amount of feedback.
    ProgressiveInteger {
        /// Positive initial number of strata.
        initial_strata: u32,
        /// Positive completed-visit interval between refinements.
        feedback_interval: u64,
    },
    /// Mutates deterministically near retained corpus values.
    MutateNearCorpus {
        /// Maximum legal-step distance from a selected corpus value.
        maximum_distance: u64,
    },
    /// Polls an ordered weighted mixture of other immutable specifications.
    OrderedMixture {
        /// Nonempty ordered component list.
        components: Vec<WeightedGenerator>,
    },
}

impl CandidateGeneratorAlgorithm {
    fn supports_implementation_version(&self, implementation_version: u32) -> bool {
        match self {
            Self::All => implementation_version == STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
            Self::WeightedCategorical { .. } => {
                implementation_version == WEIGHTED_CATEGORICAL_GENERATOR_IMPLEMENTATION_VERSION
            }
            Self::StratifiedInteger { .. } => {
                implementation_version == STRATIFIED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
            }
            Self::BoundaryInteger => {
                implementation_version == BOUNDARY_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
            }
            Self::LogInteger { .. } => {
                implementation_version == LOG_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
            }
            Self::PermutedInteger => matches!(
                implementation_version,
                PERMUTED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                    | MODELED_UNIFORM_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
            ),
            Self::ProgressiveInteger { .. } => matches!(
                implementation_version,
                PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                    | FEEDBACK_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                    | LANDMARK_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                    | MEASUREMENT_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                    | COVERAGE_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                    | FINDING_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                    | RARITY_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
            ),
            Self::MutateNearCorpus { .. } => {
                implementation_version == CORPUS_MUTATION_GENERATOR_IMPLEMENTATION_VERSION
            }
            Self::OrderedMixture { .. } => {
                implementation_version == ORDERED_MIXTURE_GENERATOR_IMPLEMENTATION_VERSION
            }
        }
    }

    fn validate(&self) -> Result<(), CampaignCodecError> {
        match self {
            Self::WeightedCategorical { weights } => {
                if weights.is_empty()
                    || weights.len() > MAX_GENERATOR_WEIGHTS
                    || weights.values().any(|weight| *weight == 0)
                {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "weighted categorical generator is empty, oversized, or zero-weighted",
                    });
                }
            }
            Self::StratifiedInteger { strata } if *strata == 0 => {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "stratified integer generator has zero strata",
                });
            }
            Self::LogInteger { base } if *base < 2 => {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "log integer generator base is below two",
                });
            }
            Self::ProgressiveInteger {
                initial_strata,
                feedback_interval,
            } if *initial_strata == 0 || *feedback_interval == 0 => {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "progressive integer generator has a zero parameter",
                });
            }
            Self::MutateNearCorpus { maximum_distance } if *maximum_distance == 0 => {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "corpus mutation generator has zero distance",
                });
            }
            Self::OrderedMixture { components }
                if components.is_empty() || components.len() > MAX_GENERATOR_COMPONENTS =>
            {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "candidate-generator mixture is empty or oversized",
                });
            }
            _ => {}
        }
        Ok(())
    }

    fn content_children(&self) -> Vec<(String, ContentId)> {
        match self {
            Self::OrderedMixture { components } => components
                .iter()
                .enumerate()
                .map(|(index, component)| {
                    (
                        format!("component.{index:04x}"),
                        component.generator().content_id(),
                    )
                })
                .collect(),
            _ => Vec::new(),
        }
    }
}

impl Canonical for CandidateGeneratorAlgorithm {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::All => encoder.u8(0),
            Self::WeightedCategorical { weights } => {
                encoder.u8(1);
                weights.encode(encoder);
            }
            Self::StratifiedInteger { strata } => {
                encoder.u8(2);
                strata.encode(encoder);
            }
            Self::BoundaryInteger => encoder.u8(3),
            Self::LogInteger { base } => {
                encoder.u8(4);
                base.encode(encoder);
            }
            Self::PermutedInteger => encoder.u8(5),
            Self::ProgressiveInteger {
                initial_strata,
                feedback_interval,
            } => {
                encoder.u8(6);
                initial_strata.encode(encoder);
                feedback_interval.encode(encoder);
            }
            Self::MutateNearCorpus { maximum_distance } => {
                encoder.u8(7);
                maximum_distance.encode(encoder);
            }
            Self::OrderedMixture { components } => {
                encoder.u8(8);
                components.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let algorithm = match decoder.u8()? {
            0 => Self::All,
            1 => Self::WeightedCategorical {
                weights: decoder
                    .map_bounded(MAX_GENERATOR_WEIGHTS, "candidate-generator-weight-count")?,
            },
            2 => Self::StratifiedInteger {
                strata: u32::decode(decoder)?,
            },
            3 => Self::BoundaryInteger,
            4 => Self::LogInteger {
                base: u32::decode(decoder)?,
            },
            5 => Self::PermutedInteger,
            6 => Self::ProgressiveInteger {
                initial_strata: u32::decode(decoder)?,
                feedback_interval: u64::decode(decoder)?,
            },
            7 => Self::MutateNearCorpus {
                maximum_distance: u64::decode(decoder)?,
            },
            8 => Self::OrderedMixture {
                components: decoder.sequence_bounded(
                    MAX_GENERATOR_COMPONENTS,
                    "candidate-generator-component-count",
                    WeightedGenerator::decode,
                )?,
            },
            tag => {
                return Err(CampaignCodecError::UnknownTag {
                    kind: "candidate-generator-algorithm",
                    tag,
                });
            }
        };
        algorithm.validate()?;
        Ok(algorithm)
    }
}

/// Immutable versioned candidate-generator specification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateGeneratorSpec {
    schema_version: u32,
    implementation_version: u32,
    algorithm: CandidateGeneratorAlgorithm,
}

impl CandidateGeneratorSpec {
    /// Builds a closed reproducible candidate-generator specification.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the implementation version does not match
    /// the algorithm, parameters are invalid, or the canonical record is oversized.
    pub fn new(
        implementation_version: u32,
        algorithm: CandidateGeneratorAlgorithm,
    ) -> Result<Self, CampaignCodecError> {
        if !algorithm.supports_implementation_version(implementation_version) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "candidate-generator implementation version does not match its algorithm",
            });
        }
        algorithm.validate()?;
        let spec = Self {
            schema_version: CANDIDATE_GENERATOR_SCHEMA_VERSION,
            implementation_version,
            algorithm,
        };
        codec::ensure_encoded_size(
            &spec,
            MAX_CANDIDATE_GENERATOR_BYTES,
            "candidate-generator-encoded-bytes",
        )?;
        Ok(spec)
    }

    /// Returns the generator implementation protocol version.
    #[must_use]
    pub const fn implementation_version(&self) -> u32 {
        self.implementation_version
    }

    /// Returns the closed algorithm and exact parameters.
    #[must_use]
    pub const fn algorithm(&self) -> &CandidateGeneratorAlgorithm {
        &self.algorithm
    }

    /// Returns the exact content-derived record identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(&self) -> Result<CandidateGeneratorSpecId, CampaignCodecError> {
        let envelope = crate::ObjectEnvelope::for_record(
            crate::CampaignRecordKind::CandidateGeneratorSpec,
            crate::object::content_children(self.content_children())?,
            codec::encode(self),
        )?;
        CandidateGeneratorSpecId::from_content_id(envelope.content_id())
    }

    pub(crate) fn content_children(&self) -> Vec<(String, ContentId)> {
        self.algorithm.content_children()
    }

    /// Returns strict canonical generator-specification bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical generator-specification bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical, invalid, or
    /// oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        if bytes.len() > MAX_CANDIDATE_GENERATOR_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "candidate-generator-encoded-bytes",
            });
        }
        codec::decode(bytes)
    }
}

impl Canonical for CandidateGeneratorSpec {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.implementation_version.encode(encoder);
        self.algorithm.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        if u32::decode(decoder)? != CANDIDATE_GENERATOR_SCHEMA_VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported candidate-generator schema version",
            });
        }
        Self::new(
            u32::decode(decoder)?,
            CandidateGeneratorAlgorithm::decode(decoder)?,
        )
    }
}

/// Generator selection for one stable selectable selector.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ChoicePolicy {
    selector: String,
    generator: CandidateGeneratorSpecId,
    required: bool,
}

impl ChoicePolicy {
    /// Builds one choice policy.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError::InvalidValue`] for an unsafe selector.
    pub fn new(
        selector: impl Into<String>,
        generator: CandidateGeneratorSpecId,
        required: bool,
    ) -> Result<Self, CampaignCodecError> {
        let selector = selector.into();
        validate_identifier(&selector, "choice selector is invalid")?;
        Ok(Self {
            selector,
            generator,
            required,
        })
    }

    /// Returns the stable selectable selector.
    #[must_use]
    pub fn selector(&self) -> &str {
        &self.selector
    }

    /// Returns the candidate generator specification.
    #[must_use]
    pub const fn generator(&self) -> CandidateGeneratorSpecId {
        self.generator
    }

    /// Returns whether a matching selectable is required at admission.
    #[must_use]
    pub const fn required(&self) -> bool {
        self.required
    }
}

impl Canonical for ChoicePolicy {
    fn encode(&self, encoder: &mut Encoder) {
        self.selector.encode(encoder);
        self.generator.encode(encoder);
        self.required.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            decoder.string_bounded(MAX_IDENTIFIER_BYTES, "choice-selector-bytes")?,
            CandidateGeneratorSpecId::decode(decoder)?,
            bool::decode(decoder)?,
        )
    }
}

/// Direction applied to a named exact measurement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObjectiveGoal {
    /// Lower values rank ahead of higher values.
    Minimize,
    /// Higher values rank ahead of lower values.
    Maximize,
}

impl Canonical for ObjectiveGoal {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(match self {
            Self::Minimize => 0,
            Self::Maximize => 1,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Minimize),
            1 => Ok(Self::Maximize),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "objective-goal",
                tag,
            }),
        }
    }
}

/// Exact campaign objective over one scenario measurement.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Objective {
    measurement: String,
    goal: ObjectiveGoal,
    weight_micros: u64,
}

impl Objective {
    /// Builds one objective.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError::InvalidValue`] for an invalid measurement
    /// name or a zero weight.
    pub fn new(
        measurement: impl Into<String>,
        goal: ObjectiveGoal,
        weight_micros: u64,
    ) -> Result<Self, CampaignCodecError> {
        let measurement = measurement.into();
        validate_identifier(&measurement, "objective measurement is invalid")?;
        if weight_micros == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "objective weight is zero",
            });
        }
        Ok(Self {
            measurement,
            goal,
            weight_micros,
        })
    }

    /// Returns the stable measurement name.
    #[must_use]
    pub fn measurement(&self) -> &str {
        &self.measurement
    }

    /// Returns whether the measurement is minimized or maximized.
    #[must_use]
    pub const fn goal(&self) -> ObjectiveGoal {
        self.goal
    }

    /// Returns the exact fixed-point objective weight in millionths.
    #[must_use]
    pub const fn weight_micros(&self) -> u64 {
        self.weight_micros
    }
}

impl Canonical for Objective {
    fn encode(&self, encoder: &mut Encoder) {
        self.measurement.encode(encoder);
        self.goal.encode(encoder);
        self.weight_micros.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            decoder.string_bounded(MAX_IDENTIFIER_BYTES, "objective-measurement-bytes")?,
            ObjectiveGoal::decode(decoder)?,
            u64::decode(decoder)?,
        )
    }
}

mod campaign;
use campaign::greatest_common_divisor;
pub(crate) use campaign::validate_identifier;
pub use campaign::{
    CampaignPolicy, CampaignPolicyIdentity, CampaignPolicyRules, FairnessPolicy, GuidanceWeight,
    InterventionLearningPolicy, RetentionPolicy,
};
