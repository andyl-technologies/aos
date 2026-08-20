//! Immutable campaign policy and exact exploration parameters.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use crucible_cas::content_store::ContentId;

use super::codec::{self, Canonical, Decoder, Encoder};
use super::{
    AlternativeId, CampaignCodecError, CampaignPolicyId, CandidateGeneratorSpecId, ScenarioDefId,
};

const CAMPAIGN_POLICY_SCHEMA_VERSION: u32 = 1;
const MAX_POLICY_ENTRIES: usize = 4_096;
const MAX_CAMPAIGN_POLICY_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_IDENTIFIER_BYTES: usize = 512;
const CANDIDATE_GENERATOR_SCHEMA_VERSION: u32 = 1;
const MAX_GENERATOR_WEIGHTS: usize = 4096;
const MAX_GENERATOR_COMPONENTS: usize = 256;
const MAX_CANDIDATE_GENERATOR_BYTES: usize = 4 * 1024 * 1024;

/// Generator implementation version for static `all` enumeration.
///
/// This version enumerates Boolean values as `false`, then `true`, and discrete
/// alternatives in stable [`AlternativeId`] order. Earlier and unknown versions
/// remain suspended so repository upgrades do not reinterpret persisted work.
pub const STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION: u32 = 2;

/// Generator implementation version for static boundary-integer enumeration.
///
/// This version has a closed ordering over boundaries, the opportunity default,
/// landmarks, adjacent legal values, and signedness-appropriate powers of two.
/// Earlier and unknown versions remain suspended.
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
/// requested, and uses the lower midpoint for a single stratum. Earlier and
/// unknown versions remain suspended.
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
/// Earlier and unknown versions remain suspended.
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
/// Earlier and unknown versions remain suspended.
pub const PERMUTED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION: u32 = 6;

/// Maximum cardinality admitted by permuted-integer implementation version 6.
///
/// Proposal ordinals are 64-bit and one-based, so a domain with `2^64` legal
/// values cannot be named completely and fails closed.
pub const PERMUTED_INTEGER_GENERATOR_MAX_CARDINALITY: u128 = u64::MAX as u128;

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
    /// Enumerates a small Boolean or discrete domain in canonical order.
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
    /// Returns [`CampaignCodecError`] for a zero implementation version,
    /// invalid algorithm parameters, or an oversized canonical record.
    pub fn new(
        implementation_version: u32,
        algorithm: CandidateGeneratorAlgorithm,
    ) -> Result<Self, CampaignCodecError> {
        if implementation_version == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "candidate-generator implementation version is zero",
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

/// Exact fixed-point weight for one canonical guidance signal.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GuidanceWeight {
    signal: String,
    weight_micros: u64,
}

impl GuidanceWeight {
    /// Builds one guidance signal weight.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError::InvalidValue`] for an invalid signal name
    /// or zero weight.
    pub fn new(signal: impl Into<String>, weight_micros: u64) -> Result<Self, CampaignCodecError> {
        let signal = signal.into();
        validate_identifier(&signal, "guidance signal is invalid")?;
        if weight_micros == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "guidance weight is zero",
            });
        }
        Ok(Self {
            signal,
            weight_micros,
        })
    }

    /// Returns the stable guidance signal name.
    #[must_use]
    pub fn signal(&self) -> &str {
        &self.signal
    }

    /// Returns the exact fixed-point guidance weight in millionths.
    #[must_use]
    pub const fn weight_micros(&self) -> u64 {
        self.weight_micros
    }
}

impl Canonical for GuidanceWeight {
    fn encode(&self, encoder: &mut Encoder) {
        self.signal.encode(encoder);
        self.weight_micros.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            decoder.string_bounded(MAX_IDENTIFIER_BYTES, "guidance-signal-bytes")?,
            u64::decode(decoder)?,
        )
    }
}

/// Fairness reservations independent of objective ranking.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FairnessPolicy {
    breadth_first_percent: u8,
    novelty_reserve: u64,
}

impl FairnessPolicy {
    /// Builds bounded fairness reservations.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError::InvalidValue`] when the percentage exceeds
    /// 100.
    pub fn new(
        breadth_first_percent: u8,
        novelty_reserve: u64,
    ) -> Result<Self, CampaignCodecError> {
        if breadth_first_percent > 100 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "breadth-first fairness percentage exceeds 100",
            });
        }
        Ok(Self {
            breadth_first_percent,
            novelty_reserve,
        })
    }

    /// Returns the breadth-first reservation percentage.
    #[must_use]
    pub const fn breadth_first_percent(self) -> u8 {
        self.breadth_first_percent
    }

    /// Returns the minimum novelty-reserved work allowance.
    #[must_use]
    pub const fn novelty_reserve(self) -> u64 {
        self.novelty_reserve
    }
}

impl Canonical for FairnessPolicy {
    fn encode(&self, encoder: &mut Encoder) {
        self.breadth_first_percent.encode(encoder);
        self.novelty_reserve.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(u8::decode(decoder)?, u64::decode(decoder)?)
    }
}

/// Semantic retention intent; physical tier choices remain operational.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RetentionPolicy {
    retain_all_findings: bool,
    survivor_limit: u64,
    exact_findings: bool,
    exact_user_pins: bool,
}

impl RetentionPolicy {
    /// Builds semantic retention intent.
    #[must_use]
    pub const fn new(
        retain_all_findings: bool,
        survivor_limit: u64,
        exact_findings: bool,
        exact_user_pins: bool,
    ) -> Self {
        Self {
            retain_all_findings,
            survivor_limit,
            exact_findings,
            exact_user_pins,
        }
    }

    /// Returns whether every finding is retained semantically.
    #[must_use]
    pub const fn retain_all_findings(self) -> bool {
        self.retain_all_findings
    }

    /// Returns the retained survivor cap.
    #[must_use]
    pub const fn survivor_limit(self) -> u64 {
        self.survivor_limit
    }

    /// Returns whether finding closures require exact retention.
    #[must_use]
    pub const fn exact_findings(self) -> bool {
        self.exact_findings
    }

    /// Returns whether user pins require exact retention.
    #[must_use]
    pub const fn exact_user_pins(self) -> bool {
        self.exact_user_pins
    }
}

impl Canonical for RetentionPolicy {
    fn encode(&self, encoder: &mut Encoder) {
        self.retain_all_findings.encode(encoder);
        self.survivor_limit.encode(encoder);
        self.exact_findings.encode(encoder);
        self.exact_user_pins.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self {
            retain_all_findings: bool::decode(decoder)?,
            survivor_limit: u64::decode(decoder)?,
            exact_findings: bool::decode(decoder)?,
            exact_user_pins: bool::decode(decoder)?,
        })
    }
}

/// Complete immutable campaign policy revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignPolicy {
    schema_version: u32,
    scenario: ScenarioDefId,
    campaign_seed: CampaignSeed,
    mode: CampaignMode,
    explorer: ExplorerPolicy,
    choice_policies: BTreeMap<String, ChoicePolicy>,
    objectives: BTreeMap<String, Objective>,
    guidance: BTreeMap<String, GuidanceWeight>,
    stop_conditions: BTreeSet<String>,
    fairness: FairnessPolicy,
    retention: RetentionPolicy,
    admit_scenario_defaults: bool,
}

impl CampaignPolicy {
    /// Builds a validated version-one policy with canonical map/set ordering.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError::InvalidValue`] when a collection exceeds
    /// its bound, a map key disagrees with its value, or a stop name is invalid.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scenario: ScenarioDefId,
        campaign_seed: CampaignSeed,
        mode: CampaignMode,
        explorer: ExplorerPolicy,
        choice_policies: BTreeMap<String, ChoicePolicy>,
        objectives: BTreeMap<String, Objective>,
        guidance: BTreeMap<String, GuidanceWeight>,
        stop_conditions: BTreeSet<String>,
        fairness: FairnessPolicy,
        retention: RetentionPolicy,
        admit_scenario_defaults: bool,
    ) -> Result<Self, CampaignCodecError> {
        explorer.validate()?;
        for length in [
            choice_policies.len(),
            objectives.len(),
            guidance.len(),
            stop_conditions.len(),
        ] {
            if length > MAX_POLICY_ENTRIES {
                return Err(CampaignCodecError::LimitExceeded {
                    limit: "campaign-policy-entry-count",
                });
            }
        }
        for (selector, policy) in &choice_policies {
            if selector != policy.selector() {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "choice-policy map key disagrees with selector",
                });
            }
        }
        for (measurement, objective) in &objectives {
            if measurement != objective.measurement() {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "objective map key disagrees with measurement",
                });
            }
        }
        for (signal, weight) in &guidance {
            if signal != weight.signal() {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "guidance map key disagrees with signal",
                });
            }
        }
        for stop in &stop_conditions {
            validate_identifier(stop, "stop-condition identifier is invalid")?;
        }
        let policy = Self {
            schema_version: CAMPAIGN_POLICY_SCHEMA_VERSION,
            scenario,
            campaign_seed,
            mode,
            explorer,
            choice_policies,
            objectives,
            guidance,
            stop_conditions,
            fairness,
            retention,
            admit_scenario_defaults,
        };
        codec::ensure_encoded_size(
            &policy,
            MAX_CAMPAIGN_POLICY_BYTES,
            "campaign-policy-encoded-bytes",
        )?;
        Ok(policy)
    }

    /// Returns the referenced immutable scenario.
    #[must_use]
    pub const fn scenario(&self) -> ScenarioDefId {
        self.scenario
    }

    /// Returns the policy's reproducibility mode.
    #[must_use]
    pub const fn mode(&self) -> CampaignMode {
        self.mode
    }

    /// Returns the policy's fixed campaign seed.
    #[must_use]
    pub const fn campaign_seed(&self) -> CampaignSeed {
        self.campaign_seed
    }

    /// Returns the configured exploration algorithm.
    #[must_use]
    pub const fn explorer(&self) -> &ExplorerPolicy {
        &self.explorer
    }

    /// Returns selectable policies keyed by stable selector.
    #[must_use]
    pub const fn choice_policies(&self) -> &BTreeMap<String, ChoicePolicy> {
        &self.choice_policies
    }

    /// Returns objectives keyed by measurement name.
    #[must_use]
    pub const fn objectives(&self) -> &BTreeMap<String, Objective> {
        &self.objectives
    }

    /// Returns guidance weights keyed by signal name.
    #[must_use]
    pub const fn guidance(&self) -> &BTreeMap<String, GuidanceWeight> {
        &self.guidance
    }

    /// Returns named semantic stop conditions.
    #[must_use]
    pub const fn stop_conditions(&self) -> &BTreeSet<String> {
        &self.stop_conditions
    }

    /// Returns fairness reservations independent of objective ordering.
    #[must_use]
    pub const fn fairness(&self) -> FairnessPolicy {
        self.fairness
    }

    /// Returns semantic retention intent.
    #[must_use]
    pub const fn retention(&self) -> RetentionPolicy {
        self.retention
    }

    /// Returns whether undeclared scenario defaults may be admitted.
    #[must_use]
    pub const fn admits_scenario_defaults(&self) -> bool {
        self.admit_scenario_defaults
    }

    pub(crate) fn content_children(&self) -> Vec<(String, ContentId)> {
        self.choice_policies
            .values()
            .enumerate()
            .map(|(index, policy)| {
                (
                    format!("choice-generator.{index:04x}"),
                    policy.generator().content_id(),
                )
            })
            .collect()
    }

    /// Returns the canonical binary representation.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Parses and validates the strict canonical binary representation.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, oversized,
    /// non-canonical, or semantically invalid bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        if bytes.len() > MAX_CAMPAIGN_POLICY_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "campaign-policy-encoded-bytes",
            });
        }
        codec::decode(bytes)
    }

    /// Returns the domain-separated policy identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(&self) -> Result<CampaignPolicyId, CampaignCodecError> {
        CampaignPolicyId::from_content_id(crate::ObjectEnvelope::for_policy(self)?.content_id())
    }
}

impl Canonical for CampaignPolicy {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.scenario.encode(encoder);
        self.campaign_seed.encode(encoder);
        self.mode.encode(encoder);
        self.explorer.encode(encoder);
        self.choice_policies.encode(encoder);
        self.objectives.encode(encoder);
        self.guidance.encode(encoder);
        self.stop_conditions.encode(encoder);
        self.fairness.encode(encoder);
        self.retention.encode(encoder);
        self.admit_scenario_defaults.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        if schema_version != CAMPAIGN_POLICY_SCHEMA_VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported campaign-policy schema version",
            });
        }
        Self::new(
            ScenarioDefId::decode(decoder)?,
            CampaignSeed::decode(decoder)?,
            CampaignMode::decode(decoder)?,
            ExplorerPolicy::decode(decoder)?,
            decoder.map_bounded_by(
                MAX_POLICY_ENTRIES,
                "campaign-choice-policy-count",
                |decoder| {
                    decoder.string_bounded(MAX_IDENTIFIER_BYTES, "choice-policy-map-key-bytes")
                },
                ChoicePolicy::decode,
            )?,
            decoder.map_bounded_by(
                MAX_POLICY_ENTRIES,
                "campaign-objective-count",
                |decoder| decoder.string_bounded(MAX_IDENTIFIER_BYTES, "objective-map-key-bytes"),
                Objective::decode,
            )?,
            decoder.map_bounded_by(
                MAX_POLICY_ENTRIES,
                "campaign-guidance-count",
                |decoder| decoder.string_bounded(MAX_IDENTIFIER_BYTES, "guidance-map-key-bytes"),
                GuidanceWeight::decode,
            )?,
            decoder.set_bounded_by(
                MAX_POLICY_ENTRIES,
                "campaign-stop-condition-count",
                |decoder| decoder.string_bounded(MAX_IDENTIFIER_BYTES, "stop-condition-name-bytes"),
            )?,
            FairnessPolicy::decode(decoder)?,
            RetentionPolicy::decode(decoder)?,
            bool::decode(decoder)?,
        )
    }
}

pub(crate) fn validate_identifier(
    value: &str,
    reason: &'static str,
) -> Result<(), CampaignCodecError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':')
        });
    if valid {
        Ok(())
    } else {
        Err(CampaignCodecError::InvalidValue { reason })
    }
}

const fn greatest_common_divisor(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    if left == 0 { 1 } else { left }
}
