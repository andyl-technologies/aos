//! Exact objective evaluation, deterministic ranking, and survivor evidence.
//!
//! Execution-model adapters project already-verified measurement aggregates
//! into [`ObjectiveValue`] values. This module applies immutable campaign
//! policy using integer and arbitrary-precision rational arithmetic only. It
//! records every considered evaluation and a stable explanation for every
//! selected, filtered, dominated, or rank-pruned configuration.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use crucible_cas::content_store::ContentId;
use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::Zero;

use crate::codec::{self, Canonical, Decoder, Encoder};
use crate::policy::{MAX_IDENTIFIER_BYTES, validate_identifier};
use crate::{
    CampaignCodecError, CampaignPolicy, CampaignPolicyId, ConfigurationId, Objective,
    ObjectiveEvaluationId, ObjectiveGoal, Observation, ObservationId, PropertyVerdict,
    PropertyVerdictSet, RankingExplanationId, SurvivorSelectionId,
};

const RECORD_SCHEMA_VERSION: u32 = 1;
const MAX_OBJECTIVE_RECORD_BYTES: usize = 4 * 1024 * 1024;
const MAX_SURVIVOR_SELECTION_BYTES: usize = 32 * 1024 * 1024;
const MAX_FIXED_REWARD_MAGNITUDE_BYTES: usize = 8 * 1024;
const MAX_FIXED_REWARD_WORK_BYTES: usize = 64 * 1024 * 1024;
const OBJECTIVE_CONTRACT_DOMAIN: &str = "crucible.campaign.objective-contract.v1";
/// Maximum observations considered by one survivor decision.
pub const MAX_SURVIVOR_CANDIDATES: usize = 16_384;
/// Maximum aggregate canonical evaluation and explanation bytes in one decision.
pub const MAX_SURVIVOR_EVIDENCE_BYTES: usize = 128 * 1024 * 1024;
/// Maximum pair-by-component comparisons admitted by Pareto ranking.
pub const MAX_PARETO_COMPONENT_VISITS: usize = 4_000_000;
/// Maximum component visits conservatively admitted by lexicographic ranking.
pub const MAX_LEXICOGRAPHIC_COMPONENT_VISITS: usize = 4_000_000;
/// Maximum conservative reward-operand byte visits admitted by weighted ordering.
pub const MAX_WEIGHTED_RANKING_BYTE_VISITS: usize = 512 * 1024 * 1024;

pub(crate) fn objective_contract_hash<'a>(
    components: impl ExactSizeIterator<Item = (&'a str, ObjectiveGoal, u64)>,
) -> crate::CampaignHash {
    let mut encoder = Encoder::new();
    encoder.u64(components.len() as u64);
    for (measurement, goal, weight_micros) in components {
        measurement.to_owned().encode(&mut encoder);
        goal.encode(&mut encoder);
        weight_micros.encode(&mut encoder);
    }
    crate::CampaignHash::derive(OBJECTIVE_CONTRACT_DOMAIN, &encoder.finish())
}

/// One exact numeric aggregate admitted as an objective component.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ObjectiveValue {
    /// Signed 64-bit integer.
    Signed(i64),
    /// Unsigned 64-bit integer.
    Unsigned(u64),
    /// Reduced signed-magnitude rational.
    Rational {
        /// Whether the nonzero value is negative.
        negative: bool,
        /// Reduced numerator magnitude.
        numerator: u128,
        /// Positive reduced denominator.
        denominator: u128,
    },
}

impl ObjectiveValue {
    /// Builds one reduced exact rational objective value.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError::InvalidValue`] when `denominator` is zero.
    pub fn rational(
        negative: bool,
        numerator: u128,
        denominator: u128,
    ) -> Result<Self, CampaignCodecError> {
        if denominator == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "objective denominator is zero",
            });
        }
        if numerator == 0 {
            return Ok(Self::Rational {
                negative: false,
                numerator: 0,
                denominator: 1,
            });
        }
        let divisor = numerator.gcd(&denominator);
        Ok(Self::Rational {
            negative,
            numerator: numerator / divisor,
            denominator: denominator / divisor,
        })
    }

    fn fraction(&self) -> (BigInt, BigUint) {
        match self {
            Self::Signed(value) => (BigInt::from(*value), BigUint::from(1_u8)),
            Self::Unsigned(value) => (BigInt::from(*value), BigUint::from(1_u8)),
            Self::Rational {
                negative,
                numerator,
                denominator,
            } => {
                let sign = if *negative && *numerator != 0 {
                    Sign::Minus
                } else {
                    Sign::Plus
                };
                (
                    BigInt::from_biguint(sign, BigUint::from(*numerator)),
                    BigUint::from(*denominator),
                )
            }
        }
    }

    fn exact_cmp(&self, other: &Self) -> Ordering {
        let (left_numerator, left_denominator) = self.fraction();
        let (right_numerator, right_denominator) = other.fraction();
        (left_numerator * BigInt::from_biguint(Sign::Plus, right_denominator))
            .cmp(&(right_numerator * BigInt::from_biguint(Sign::Plus, left_denominator)))
    }
}

impl Canonical for ObjectiveValue {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Signed(value) => {
                encoder.u8(0);
                value.encode(encoder);
            }
            Self::Unsigned(value) => {
                encoder.u8(1);
                value.encode(encoder);
            }
            Self::Rational {
                negative,
                numerator,
                denominator,
            } => {
                encoder.u8(2);
                negative.encode(encoder);
                numerator.encode(encoder);
                denominator.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Signed(i64::decode(decoder)?)),
            1 => Ok(Self::Unsigned(u64::decode(decoder)?)),
            2 => Self::rational(
                bool::decode(decoder)?,
                u128::decode(decoder)?,
                u128::decode(decoder)?,
            ),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "objective-value",
                tag,
            }),
        }
    }
}

/// One arbitrary-precision reduced fixed reward.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FixedReward {
    negative: bool,
    numerator: Vec<u8>,
    denominator: Vec<u8>,
}

impl FixedReward {
    fn from_fraction(numerator: BigInt, denominator: BigUint) -> Result<Self, CampaignCodecError> {
        if denominator.is_zero() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "fixed reward denominator is zero",
            });
        }
        let negative = numerator.sign() == Sign::Minus;
        let magnitude = numerator.magnitude();
        let divisor = magnitude.gcd(&denominator);
        let reduced_numerator = magnitude / &divisor;
        let reduced_denominator = denominator / divisor;
        let numerator = canonical_magnitude_bytes(&reduced_numerator);
        let denominator = canonical_magnitude_bytes(&reduced_denominator);
        if numerator.len() > MAX_FIXED_REWARD_MAGNITUDE_BYTES
            || denominator.len() > MAX_FIXED_REWARD_MAGNITUDE_BYTES
        {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "objective-fixed-reward-magnitude-bytes",
            });
        }
        Ok(Self {
            negative: negative && numerator != [0],
            numerator,
            denominator,
        })
    }

    fn from_parts(
        negative: bool,
        numerator: Vec<u8>,
        denominator: Vec<u8>,
    ) -> Result<Self, CampaignCodecError> {
        validate_magnitude(&numerator, "objective fixed-reward numerator is invalid")?;
        validate_magnitude(
            &denominator,
            "objective fixed-reward denominator is invalid",
        )?;
        let numerator_value = BigUint::from_bytes_be(&numerator);
        let denominator_value = BigUint::from_bytes_be(&denominator);
        if denominator_value.is_zero() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "fixed reward denominator is zero",
            });
        }
        if numerator_value.gcd(&denominator_value) != BigUint::from(1_u8) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "fixed reward is not reduced",
            });
        }
        if numerator_value.is_zero() && negative {
            return Err(CampaignCodecError::InvalidValue {
                reason: "zero fixed reward is negative",
            });
        }
        Ok(Self {
            negative,
            numerator,
            denominator,
        })
    }

    /// Returns whether the nonzero reward is negative.
    #[must_use]
    pub const fn is_negative(&self) -> bool {
        self.negative
    }

    /// Returns the canonical numerator magnitude bytes.
    #[must_use]
    pub fn numerator(&self) -> &[u8] {
        &self.numerator
    }

    /// Returns the canonical positive denominator bytes.
    #[must_use]
    pub fn denominator(&self) -> &[u8] {
        &self.denominator
    }

    /// Converts this exact rational reward to signed millionths.
    ///
    /// The conversion multiplies by `1_000_000`, divides with truncation toward
    /// zero, and saturates to the signed 64-bit range. This is the canonical
    /// bridge from arbitrary-precision objective ranking to fixed-point PUCT.
    #[must_use]
    pub fn to_micros_saturating(&self) -> i64 {
        let numerator = BigUint::from_bytes_be(&self.numerator) * BigUint::from(1_000_000_u64);
        let denominator = BigUint::from_bytes_be(&self.denominator);
        let quotient = numerator / denominator;
        let digits = quotient.to_u64_digits();
        let magnitude = match digits.as_slice() {
            [] => 0,
            [value] => *value,
            [_, ..] => u64::MAX,
        };
        if self.negative {
            if magnitude >= (1_u64 << 63) {
                i64::MIN
            } else {
                -(magnitude as i64)
            }
        } else {
            magnitude.min(i64::MAX as u64) as i64
        }
    }

    fn fraction(&self) -> (BigInt, BigUint) {
        let magnitude = BigUint::from_bytes_be(&self.numerator);
        let sign = if self.negative {
            Sign::Minus
        } else {
            Sign::Plus
        };
        (
            BigInt::from_biguint(sign, magnitude),
            BigUint::from_bytes_be(&self.denominator),
        )
    }
}

impl Ord for FixedReward {
    fn cmp(&self, other: &Self) -> Ordering {
        let (left_numerator, left_denominator) = self.fraction();
        let (right_numerator, right_denominator) = other.fraction();
        (left_numerator * BigInt::from_biguint(Sign::Plus, right_denominator))
            .cmp(&(right_numerator * BigInt::from_biguint(Sign::Plus, left_denominator)))
    }
}

impl PartialOrd for FixedReward {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Canonical for FixedReward {
    fn encode(&self, encoder: &mut Encoder) {
        self.negative.encode(encoder);
        self.numerator.encode(encoder);
        self.denominator.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::from_parts(
            bool::decode(decoder)?,
            decoder.sequence_bounded(
                MAX_FIXED_REWARD_MAGNITUDE_BYTES,
                "objective-fixed-reward-numerator-bytes",
                u8::decode,
            )?,
            decoder.sequence_bounded(
                MAX_FIXED_REWARD_MAGNITUDE_BYTES,
                "objective-fixed-reward-denominator-bytes",
                u8::decode,
            )?,
        )
    }
}

/// One policy-bound metric component in canonical objective-name order.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ObjectiveComponent {
    measurement: String,
    goal: ObjectiveGoal,
    weight_micros: u64,
    value: Option<ObjectiveValue>,
}

impl ObjectiveComponent {
    fn new(
        measurement: String,
        objective: &Objective,
        value: Option<ObjectiveValue>,
    ) -> Result<Self, CampaignCodecError> {
        validate_identifier(&measurement, "objective component name is invalid")?;
        if measurement != objective.measurement() || objective.weight_micros() == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "objective component disagrees with policy objective",
            });
        }
        Ok(Self {
            measurement,
            goal: objective.goal(),
            weight_micros: objective.weight_micros(),
            value,
        })
    }

    /// Returns the stable qualified measurement name.
    #[must_use]
    pub fn measurement(&self) -> &str {
        &self.measurement
    }

    /// Returns the policy direction retained with this component.
    #[must_use]
    pub const fn goal(&self) -> ObjectiveGoal {
        self.goal
    }

    /// Returns the exact fixed-point policy weight in millionths.
    #[must_use]
    pub const fn weight_micros(&self) -> u64 {
        self.weight_micros
    }

    /// Returns the exact aggregate value, or `None` when it was missing.
    #[must_use]
    pub const fn value(&self) -> Option<&ObjectiveValue> {
        self.value.as_ref()
    }
}

impl Canonical for ObjectiveComponent {
    fn encode(&self, encoder: &mut Encoder) {
        self.measurement.encode(encoder);
        self.goal.encode(encoder);
        self.weight_micros.encode(encoder);
        self.value.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let measurement = decoder.string_bounded(
            MAX_IDENTIFIER_BYTES,
            "objective-component-measurement-bytes",
        )?;
        validate_identifier(&measurement, "objective component name is invalid")?;
        let goal = ObjectiveGoal::decode(decoder)?;
        let weight_micros = u64::decode(decoder)?;
        if weight_micros == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "objective component weight is zero",
            });
        }
        Ok(Self {
            measurement,
            goal,
            weight_micros,
            value: Option::decode(decoder)?,
        })
    }
}

/// One stable reason an observation cannot enter objective ranking.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObjectiveRejection {
    /// A policy objective had no verified numeric aggregate.
    MissingMeasurement(String),
    /// A declared property failed.
    PropertyFailed(String),
    /// A declared property was inconclusive.
    PropertyInconclusive(String),
    /// The guest reached a modeled crash class.
    GuestCrash(String),
    /// The observation stopped at an assertion failure.
    AssertionFailure(String),
}

impl Canonical for ObjectiveRejection {
    fn encode(&self, encoder: &mut Encoder) {
        let (tag, value) = match self {
            Self::MissingMeasurement(value) => (0, value),
            Self::PropertyFailed(value) => (1, value),
            Self::PropertyInconclusive(value) => (2, value),
            Self::GuestCrash(value) => (3, value),
            Self::AssertionFailure(value) => (4, value),
        };
        encoder.u8(tag);
        value.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let tag = decoder.u8()?;
        let value =
            decoder.string_bounded(MAX_IDENTIFIER_BYTES, "objective-rejection-identifier-bytes")?;
        validate_identifier(&value, "objective rejection identifier is invalid")?;
        match tag {
            0 => Ok(Self::MissingMeasurement(value)),
            1 => Ok(Self::PropertyFailed(value)),
            2 => Ok(Self::PropertyInconclusive(value)),
            3 => Ok(Self::GuestCrash(value)),
            4 => Ok(Self::AssertionFailure(value)),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "objective-rejection",
                tag,
            }),
        }
    }
}

/// Exact policy evaluation of one canonical observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectiveEvaluation {
    schema_version: u32,
    observation: ObservationId,
    configuration: ConfigurationId,
    policy: CampaignPolicyId,
    rejections: BTreeSet<ObjectiveRejection>,
    components: BTreeMap<String, ObjectiveComponent>,
    scalar_reward: Option<FixedReward>,
}

impl ObjectiveEvaluation {
    fn from_parts(
        observation: ObservationId,
        configuration: ConfigurationId,
        policy: CampaignPolicyId,
        rejections: BTreeSet<ObjectiveRejection>,
        components: BTreeMap<String, ObjectiveComponent>,
        scalar_reward: Option<FixedReward>,
    ) -> Result<Self, CampaignCodecError> {
        for (name, component) in &components {
            if name != component.measurement() {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "objective component map key disagrees with component",
                });
            }
            let missing =
                rejections.contains(&ObjectiveRejection::MissingMeasurement(name.clone()));
            if missing != component.value().is_none() {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "objective missing-value evidence is inconsistent",
                });
            }
        }
        let computed = if rejections.is_empty() && !components.is_empty() {
            Some(compute_scalar_reward(components.values())?)
        } else {
            None
        };
        if computed != scalar_reward {
            return Err(CampaignCodecError::InvalidValue {
                reason: "objective scalar reward disagrees with metric vector",
            });
        }
        let value = Self {
            schema_version: RECORD_SCHEMA_VERSION,
            observation,
            configuration,
            policy,
            rejections,
            components,
            scalar_reward,
        };
        codec::ensure_encoded_size(
            &value,
            MAX_OBJECTIVE_RECORD_BYTES,
            "objective-evaluation-encoded-bytes",
        )?;
        Ok(value)
    }

    /// Returns the evaluated observation.
    #[must_use]
    pub const fn observation(&self) -> ObservationId {
        self.observation
    }

    /// Returns the ranked child configuration.
    #[must_use]
    pub const fn configuration(&self) -> ConfigurationId {
        self.configuration
    }

    /// Returns the exact policy revision.
    #[must_use]
    pub const fn policy(&self) -> CampaignPolicyId {
        self.policy
    }

    /// Returns whether the observation is eligible for ranking.
    #[must_use]
    pub fn is_admissible(&self) -> bool {
        self.rejections.is_empty()
    }

    /// Returns every canonical filtering reason.
    #[must_use]
    pub const fn rejections(&self) -> &BTreeSet<ObjectiveRejection> {
        &self.rejections
    }

    /// Returns objective components in canonical measurement-name order.
    #[must_use]
    pub const fn components(&self) -> &BTreeMap<String, ObjectiveComponent> {
        &self.components
    }

    /// Returns the exact weighted scalar reward for an admissible nonempty vector.
    #[must_use]
    pub const fn scalar_reward(&self) -> Option<&FixedReward> {
        self.scalar_reward.as_ref()
    }

    /// Validates this retained vector against its exact policy revision.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy identity, component set, direction, or
    /// weight differs from the retained evaluation.
    pub fn validate_policy(&self, policy: &CampaignPolicy) -> Result<(), CampaignCodecError> {
        if policy.id()? != self.policy {
            return Err(CampaignCodecError::InvalidValue {
                reason: "objective evaluation policy identity mismatch",
            });
        }
        if self.components.len() != policy.objectives().len() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "objective evaluation component set differs from policy",
            });
        }
        for (name, objective) in policy.objectives() {
            match self.components.get(name) {
                Some(component)
                    if component.goal() == objective.goal()
                        && component.weight_micros() == objective.weight_micros() => {}
                Some(_) | None => {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "objective evaluation component policy mismatch",
                    });
                }
            }
        }
        if self.objective_contract_hash() != policy.objective_contract_hash() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "objective evaluation policy contract mismatch",
            });
        }
        Ok(())
    }

    /// Validates observation, property, and policy ownership of this evaluation.
    ///
    /// This check recomputes admissibility and the scalar reward from the exact
    /// retained vector. Execution-model adapters must additionally prove that
    /// each vector value came from the observation's verified measurement payload.
    ///
    /// # Errors
    ///
    /// Returns an error when any retained identity, filtering reason, component,
    /// or scalar differs from exact recomputation.
    pub fn validate_basis(
        &self,
        policy: &CampaignPolicy,
        observation: &Observation,
        properties: &PropertyVerdictSet,
    ) -> Result<(), CampaignCodecError> {
        if observation.id()? != self.observation
            || observation.child() != self.configuration
            || observation.properties() != properties.id()?
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "objective evaluation observation basis mismatch",
            });
        }
        self.validate_policy(policy)?;
        let values = self
            .components
            .iter()
            .filter_map(|(name, component)| {
                component.value().map(|value| (name.clone(), value.clone()))
            })
            .collect();
        let recomputed = evaluate_objectives(policy, observation, properties, values)?;
        if &recomputed != self {
            return Err(CampaignCodecError::InvalidValue {
                reason: "objective evaluation differs from exact basis recomputation",
            });
        }
        Ok(())
    }

    pub(crate) fn validate_compact_basis(
        &self,
        policy: CampaignPolicyId,
        objective_contract: crate::CampaignHash,
        observation: &Observation,
        properties: &PropertyVerdictSet,
    ) -> Result<(), CampaignCodecError> {
        if self.policy != policy || self.objective_contract_hash() != objective_contract {
            return Err(CampaignCodecError::InvalidValue {
                reason: "objective evaluation compact policy contract mismatch",
            });
        }
        if observation.id()? != self.observation
            || observation.child() != self.configuration
            || observation.properties() != properties.id()?
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "objective evaluation observation basis mismatch",
            });
        }
        let retained_nonmissing = self
            .rejections
            .iter()
            .filter(|rejection| !matches!(rejection, ObjectiveRejection::MissingMeasurement(_)))
            .cloned()
            .collect::<BTreeSet<_>>();
        if retained_nonmissing != observation_rejections(observation, properties) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "objective evaluation filtering evidence mismatch",
            });
        }
        Ok(())
    }

    pub(crate) fn objective_contract_hash(&self) -> crate::CampaignHash {
        objective_contract_hash(self.components.values().map(|component| {
            (
                component.measurement(),
                component.goal(),
                component.weight_micros(),
            )
        }))
    }

    /// Returns strict canonical bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, inconsistent, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        if bytes.len() > MAX_OBJECTIVE_RECORD_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "objective-evaluation-encoded-bytes",
            });
        }
        codec::decode(bytes)
    }

    /// Returns the content-addressed evaluation identity.
    ///
    /// # Errors
    ///
    /// Returns an error if envelope construction fails.
    pub fn id(&self) -> Result<ObjectiveEvaluationId, CampaignCodecError> {
        ObjectiveEvaluationId::from_content_id(
            crate::ObjectEnvelope::for_record(
                crate::CampaignRecordKind::ObjectiveEvaluation,
                crate::object::content_children(self.content_children())?,
                self.canonical_bytes(),
            )?
            .content_id(),
        )
    }

    pub(crate) fn content_children(&self) -> Vec<(String, ContentId)> {
        vec![
            ("observation".to_owned(), self.observation.content_id()),
            ("policy".to_owned(), self.policy.content_id()),
        ]
    }
}

impl Canonical for ObjectiveEvaluation {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.observation.encode(encoder);
        self.configuration.encode(encoder);
        self.policy.encode(encoder);
        self.rejections.encode(encoder);
        self.components.encode(encoder);
        self.scalar_reward.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_schema(u32::decode(decoder)?)?;
        Self::from_parts(
            ObservationId::decode(decoder)?,
            ConfigurationId::decode(decoder)?,
            CampaignPolicyId::decode(decoder)?,
            decoder.set_bounded_by(
                crate::policy::MAX_POLICY_ENTRIES,
                "objective-rejection-count",
                ObjectiveRejection::decode,
            )?,
            decoder.map_bounded_by(
                crate::policy::MAX_POLICY_ENTRIES,
                "objective-component-count",
                |decoder| {
                    decoder
                        .string_bounded(MAX_IDENTIFIER_BYTES, "objective-component-map-key-bytes")
                },
                ObjectiveComponent::decode,
            )?,
            Option::decode(decoder)?,
        )
    }
}

/// Evaluates one observation against exact already-verified objective values.
///
/// The input map must contain only policy objective names. Missing values are
/// retained as explicit filtering evidence. Failed or inconclusive properties,
/// guest crashes, and assertion failures also make the result inadmissible.
///
/// # Errors
///
/// Returns an error when record identities disagree, the value map contains an
/// undeclared objective, exact scalar work exceeds its bound, or record encoding
/// exceeds its bound.
pub fn evaluate_objectives(
    policy: &CampaignPolicy,
    observation: &Observation,
    properties: &PropertyVerdictSet,
    values: BTreeMap<String, ObjectiveValue>,
) -> Result<ObjectiveEvaluation, CampaignCodecError> {
    if properties.id()? != observation.properties() {
        return Err(CampaignCodecError::InvalidValue {
            reason: "objective property set disagrees with observation",
        });
    }
    if values
        .keys()
        .any(|name| !policy.objectives().contains_key(name))
    {
        return Err(CampaignCodecError::InvalidValue {
            reason: "objective values contain an undeclared measurement",
        });
    }

    let mut rejections = observation_rejections(observation, properties);

    let mut components = BTreeMap::new();
    for (name, objective) in policy.objectives() {
        let value = values.get(name).cloned();
        if value.is_none() {
            rejections.insert(ObjectiveRejection::MissingMeasurement(name.clone()));
        }
        components.insert(
            name.clone(),
            ObjectiveComponent::new(name.clone(), objective, value)?,
        );
    }
    let scalar_reward = if rejections.is_empty() && !components.is_empty() {
        Some(compute_scalar_reward(components.values())?)
    } else {
        None
    };
    ObjectiveEvaluation::from_parts(
        observation.id()?,
        observation.child(),
        policy.id()?,
        rejections,
        components,
        scalar_reward,
    )
}

fn observation_rejections(
    observation: &Observation,
    properties: &PropertyVerdictSet,
) -> BTreeSet<ObjectiveRejection> {
    let mut rejections = BTreeSet::new();
    for (name, evidence) in properties.properties() {
        match evidence.verdict() {
            PropertyVerdict::Passed => {}
            PropertyVerdict::Failed => {
                rejections.insert(ObjectiveRejection::PropertyFailed(name.clone()));
            }
            PropertyVerdict::Inconclusive => {
                rejections.insert(ObjectiveRejection::PropertyInconclusive(name.clone()));
            }
        }
    }
    match observation.stop() {
        crate::StopOutcome::GuestCrash(class) => {
            rejections.insert(ObjectiveRejection::GuestCrash(class.clone()));
        }
        crate::StopOutcome::AssertionFailure(property) => {
            rejections.insert(ObjectiveRejection::AssertionFailure(property.clone()));
        }
        crate::StopOutcome::Reached(_)
        | crate::StopOutcome::TerminalSuccess
        | crate::StopOutcome::ModeledTimeout(_) => {}
    }
    rejections
}

/// Primary deterministic ranking method for one survivor barrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RankingMethod {
    /// Retains the nondominated frontier, truncating it by scalar reward.
    ParetoTopK,
    /// Orders exact components lexicographically in policy name order.
    Lexicographic,
    /// Orders the exact weighted scalar reward.
    WeightedTopK,
}

impl Canonical for RankingMethod {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(match self {
            Self::ParetoTopK => 0,
            Self::Lexicographic => 1,
            Self::WeightedTopK => 2,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::ParetoTopK),
            1 => Ok(Self::Lexicographic),
            2 => Ok(Self::WeightedTopK),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "ranking-method",
                tag,
            }),
        }
    }
}

/// Exact ranking and fairness capacity rule retained with one decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SurvivorRule {
    method: RankingMethod,
    keep: u32,
    novelty_reserve: u32,
    breadth_first_reserve: u32,
}

impl SurvivorRule {
    /// Builds one nonempty bounded survivor rule.
    ///
    /// # Errors
    ///
    /// Returns an error when reserves exceed the retained survivor count.
    pub fn new(
        method: RankingMethod,
        keep: u32,
        novelty_reserve: u32,
        breadth_first_reserve: u32,
    ) -> Result<Self, CampaignCodecError> {
        if keep == 0
            || novelty_reserve
                .checked_add(breadth_first_reserve)
                .is_none_or(|reserved| reserved > keep)
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "survivor count and fairness reserves are inconsistent",
            });
        }
        Ok(Self {
            method,
            keep,
            novelty_reserve,
            breadth_first_reserve,
        })
    }

    /// Returns the primary ranking method.
    #[must_use]
    pub const fn method(self) -> RankingMethod {
        self.method
    }

    /// Returns the maximum selected configurations.
    #[must_use]
    pub const fn keep(self) -> u32 {
        self.keep
    }

    /// Returns slots reserved for highest novelty score.
    #[must_use]
    pub const fn novelty_reserve(self) -> u32 {
        self.novelty_reserve
    }

    /// Returns slots reserved for earliest breadth ordinal.
    #[must_use]
    pub const fn breadth_first_reserve(self) -> u32 {
        self.breadth_first_reserve
    }
}

impl Canonical for SurvivorRule {
    fn encode(&self, encoder: &mut Encoder) {
        self.method.encode(encoder);
        self.keep.encode(encoder);
        self.novelty_reserve.encode(encoder);
        self.breadth_first_reserve.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            RankingMethod::decode(decoder)?,
            u32::decode(decoder)?,
            u32::decode(decoder)?,
            u32::decode(decoder)?,
        )
    }
}

/// One evaluated observation plus exact fairness inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RankingCandidate {
    evaluation: ObjectiveEvaluation,
    novelty_score: u64,
    breadth_ordinal: u64,
}

impl RankingCandidate {
    /// Builds one ranking candidate from an exact evaluation and fairness basis.
    #[must_use]
    pub const fn new(
        evaluation: ObjectiveEvaluation,
        novelty_score: u64,
        breadth_ordinal: u64,
    ) -> Self {
        Self {
            evaluation,
            novelty_score,
            breadth_ordinal,
        }
    }

    /// Returns the objective evaluation.
    #[must_use]
    pub const fn evaluation(&self) -> &ObjectiveEvaluation {
        &self.evaluation
    }

    /// Returns the exact novelty score supplied by the canonical guidance projection.
    #[must_use]
    pub const fn novelty_score(&self) -> u64 {
        self.novelty_score
    }

    /// Returns the exact breadth-first ordinal.
    #[must_use]
    pub const fn breadth_ordinal(&self) -> u64 {
        self.breadth_ordinal
    }
}

/// Stable reason one candidate was selected or excluded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RankingDisposition {
    /// Selected by the primary objective order.
    SelectedObjective,
    /// Selected by the novelty reserve.
    SelectedNovelty,
    /// Selected by the breadth-first reserve.
    SelectedBreadthFirst,
    /// Excluded by objective admissibility filters.
    Filtered(BTreeSet<ObjectiveRejection>),
    /// Excluded from the Pareto frontier by one canonical dominator.
    ParetoDominated(ObjectiveEvaluationId),
    /// Eligible but beyond the retained rank or reserve capacity.
    RankPruned,
}

impl Canonical for RankingDisposition {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::SelectedObjective => encoder.u8(0),
            Self::SelectedNovelty => encoder.u8(1),
            Self::SelectedBreadthFirst => encoder.u8(2),
            Self::Filtered(rejections) => {
                encoder.u8(3);
                rejections.encode(encoder);
            }
            Self::ParetoDominated(evaluation) => {
                encoder.u8(4);
                evaluation.encode(encoder);
            }
            Self::RankPruned => encoder.u8(5),
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::SelectedObjective),
            1 => Ok(Self::SelectedNovelty),
            2 => Ok(Self::SelectedBreadthFirst),
            3 => Ok(Self::Filtered(decoder.set_bounded_by(
                crate::policy::MAX_POLICY_ENTRIES,
                "ranking-filter-rejection-count",
                ObjectiveRejection::decode,
            )?)),
            4 => Ok(Self::ParetoDominated(ObjectiveEvaluationId::decode(
                decoder,
            )?)),
            5 => Ok(Self::RankPruned),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "ranking-disposition",
                tag,
            }),
        }
    }
}

/// Deterministic explanation for one considered objective evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RankingExplanation {
    schema_version: u32,
    evaluation: ObjectiveEvaluationId,
    disposition: RankingDisposition,
    primary_rank: Option<u32>,
    novelty_score: u64,
    breadth_ordinal: u64,
}

impl RankingExplanation {
    fn new(
        evaluation: ObjectiveEvaluationId,
        disposition: RankingDisposition,
        primary_rank: Option<u32>,
        novelty_score: u64,
        breadth_ordinal: u64,
    ) -> Result<Self, CampaignCodecError> {
        let value = Self {
            schema_version: RECORD_SCHEMA_VERSION,
            evaluation,
            disposition,
            primary_rank,
            novelty_score,
            breadth_ordinal,
        };
        codec::ensure_encoded_size(
            &value,
            MAX_OBJECTIVE_RECORD_BYTES,
            "ranking-explanation-encoded-bytes",
        )?;
        Ok(value)
    }

    /// Returns the explained evaluation.
    #[must_use]
    pub const fn evaluation(&self) -> ObjectiveEvaluationId {
        self.evaluation
    }

    /// Returns the exact retained disposition.
    #[must_use]
    pub const fn disposition(&self) -> &RankingDisposition {
        &self.disposition
    }

    /// Returns the zero-based primary rank when the candidate entered that order.
    #[must_use]
    pub const fn primary_rank(&self) -> Option<u32> {
        self.primary_rank
    }

    /// Returns the retained novelty score.
    #[must_use]
    pub const fn novelty_score(&self) -> u64 {
        self.novelty_score
    }

    /// Returns the retained breadth-first ordinal.
    #[must_use]
    pub const fn breadth_ordinal(&self) -> u64 {
        self.breadth_ordinal
    }

    /// Returns strict canonical bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        if bytes.len() > MAX_OBJECTIVE_RECORD_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "ranking-explanation-encoded-bytes",
            });
        }
        codec::decode(bytes)
    }

    /// Returns the content-addressed explanation identity.
    ///
    /// # Errors
    ///
    /// Returns an error if envelope construction fails.
    pub fn id(&self) -> Result<RankingExplanationId, CampaignCodecError> {
        RankingExplanationId::from_content_id(
            crate::ObjectEnvelope::for_record(
                crate::CampaignRecordKind::RankingExplanation,
                crate::object::content_children(self.content_children())?,
                self.canonical_bytes(),
            )?
            .content_id(),
        )
    }

    pub(crate) fn content_children(&self) -> Vec<(String, ContentId)> {
        let mut children = vec![("evaluation".to_owned(), self.evaluation.content_id())];
        if let RankingDisposition::ParetoDominated(dominator) = self.disposition {
            children.push(("dominator".to_owned(), dominator.content_id()));
        }
        children
    }
}

impl Canonical for RankingExplanation {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.evaluation.encode(encoder);
        self.disposition.encode(encoder);
        self.primary_rank.encode(encoder);
        self.novelty_score.encode(encoder);
        self.breadth_ordinal.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_schema(u32::decode(decoder)?)?;
        Self::new(
            ObjectiveEvaluationId::decode(decoder)?,
            RankingDisposition::decode(decoder)?,
            Option::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
        )
    }
}

/// Canonical bounded survivor decision over one exact considered set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SurvivorSelection {
    schema_version: u32,
    policy: CampaignPolicyId,
    rule: SurvivorRule,
    considered: BTreeMap<ConfigurationId, ObjectiveEvaluationId>,
    selected: BTreeSet<ConfigurationId>,
    explanations: BTreeMap<ConfigurationId, RankingExplanationId>,
}

impl SurvivorSelection {
    fn new(
        policy: CampaignPolicyId,
        rule: SurvivorRule,
        considered: BTreeMap<ConfigurationId, ObjectiveEvaluationId>,
        selected: BTreeSet<ConfigurationId>,
        explanations: BTreeMap<ConfigurationId, RankingExplanationId>,
    ) -> Result<Self, CampaignCodecError> {
        if considered.is_empty() || considered.len() > MAX_SURVIVOR_CANDIDATES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "survivor-candidate-count",
            });
        }
        if selected.len() > rule.keep as usize
            || selected
                .iter()
                .any(|configuration| !considered.contains_key(configuration))
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "survivor selected set is inconsistent with considered evaluations",
            });
        }
        if explanations.keys().ne(considered.keys()) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "survivor explanations do not cover the considered set exactly",
            });
        }
        let value = Self {
            schema_version: RECORD_SCHEMA_VERSION,
            policy,
            rule,
            considered,
            selected,
            explanations,
        };
        codec::ensure_encoded_size(
            &value,
            MAX_SURVIVOR_SELECTION_BYTES,
            "survivor-selection-encoded-bytes",
        )?;
        Ok(value)
    }

    /// Returns the exact policy revision.
    #[must_use]
    pub const fn policy(&self) -> CampaignPolicyId {
        self.policy
    }

    /// Returns the exact ranking and reserve rule.
    #[must_use]
    pub const fn rule(&self) -> SurvivorRule {
        self.rule
    }

    /// Returns all considered evaluations keyed by configuration identity.
    #[must_use]
    pub const fn considered(&self) -> &BTreeMap<ConfigurationId, ObjectiveEvaluationId> {
        &self.considered
    }

    /// Returns the selected configuration identities.
    #[must_use]
    pub const fn selected(&self) -> &BTreeSet<ConfigurationId> {
        &self.selected
    }

    /// Returns one explanation for every considered configuration.
    #[must_use]
    pub const fn explanations(&self) -> &BTreeMap<ConfigurationId, RankingExplanationId> {
        &self.explanations
    }

    /// Returns strict canonical bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, inconsistent, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        if bytes.len() > MAX_SURVIVOR_SELECTION_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "survivor-selection-encoded-bytes",
            });
        }
        codec::decode(bytes)
    }

    /// Returns the content-addressed survivor-decision identity.
    ///
    /// # Errors
    ///
    /// Returns an error if envelope construction fails.
    pub fn id(&self) -> Result<SurvivorSelectionId, CampaignCodecError> {
        SurvivorSelectionId::from_content_id(
            crate::ObjectEnvelope::for_record(
                crate::CampaignRecordKind::SurvivorSelection,
                crate::object::content_children(self.content_children())?,
                self.canonical_bytes(),
            )?
            .content_id(),
        )
    }

    pub(crate) fn content_children(&self) -> Vec<(String, ContentId)> {
        let mut children = vec![("policy".to_owned(), self.policy.content_id())];
        children.extend(
            self.considered
                .values()
                .enumerate()
                .map(|(index, evaluation)| {
                    (format!("evaluation.{index:04x}"), evaluation.content_id())
                }),
        );
        children.extend(
            self.explanations
                .values()
                .enumerate()
                .map(|(index, explanation)| {
                    (format!("explanation.{index:04x}"), explanation.content_id())
                }),
        );
        children
    }
}

impl Canonical for SurvivorSelection {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.policy.encode(encoder);
        self.rule.encode(encoder);
        self.considered.encode(encoder);
        self.selected.encode(encoder);
        self.explanations.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_schema(u32::decode(decoder)?)?;
        Self::new(
            CampaignPolicyId::decode(decoder)?,
            SurvivorRule::decode(decoder)?,
            decoder.map_bounded(MAX_SURVIVOR_CANDIDATES, "survivor-candidate-count")?,
            decoder.set_bounded(MAX_SURVIVOR_CANDIDATES, "survivor-selected-count")?,
            decoder.map_bounded(MAX_SURVIVOR_CANDIDATES, "survivor-explanation-count")?,
        )
    }
}

/// Complete immutable result of one survivor-ranking operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SurvivorSelectionBundle {
    evaluations: BTreeMap<ConfigurationId, ObjectiveEvaluation>,
    explanations: BTreeMap<ConfigurationId, RankingExplanation>,
    selection: SurvivorSelection,
}

impl SurvivorSelectionBundle {
    /// Returns every considered evaluation.
    #[must_use]
    pub const fn evaluations(&self) -> &BTreeMap<ConfigurationId, ObjectiveEvaluation> {
        &self.evaluations
    }

    /// Returns every deterministic explanation.
    #[must_use]
    pub const fn explanations(&self) -> &BTreeMap<ConfigurationId, RankingExplanation> {
        &self.explanations
    }

    /// Returns the survivor selection binding all records.
    #[must_use]
    pub const fn selection(&self) -> &SurvivorSelection {
        &self.selection
    }
}

/// Ranks exact evaluations and produces complete deterministic survivor evidence.
///
/// Fairness first reserves the lowest breadth ordinals, then the highest
/// novelty scores. The remaining capacity is filled by the declared primary
/// objective order. Filtered observations never consume a reserve.
///
/// # Errors
///
/// Returns an error for duplicate configurations, policy mismatch, excessive
/// candidates or Pareto comparison work, missing scalar rewards, or oversized
/// canonical records.
pub fn rank_survivors(
    policy: &CampaignPolicy,
    rule: SurvivorRule,
    candidates: Vec<RankingCandidate>,
) -> Result<SurvivorSelectionBundle, CampaignCodecError> {
    if candidates.is_empty() || candidates.len() > MAX_SURVIVOR_CANDIDATES {
        return Err(CampaignCodecError::LimitExceeded {
            limit: "survivor-candidate-count",
        });
    }
    let policy_id = policy.id()?;
    let mut by_configuration = BTreeMap::new();
    let mut evidence_bytes = 0;
    for candidate in candidates {
        charge_survivor_evidence_bytes(
            &mut evidence_bytes,
            candidate.evaluation.canonical_bytes().len(),
        )?;
        candidate.evaluation.validate_policy(policy)?;
        if candidate.evaluation.policy() != policy_id
            || by_configuration
                .insert(candidate.evaluation.configuration(), candidate)
                .is_some()
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "survivor candidates have duplicate configurations or policy mismatch",
            });
        }
    }

    let admissible = by_configuration
        .iter()
        .filter(|(_, candidate)| candidate.evaluation.is_admissible())
        .map(|(configuration, _)| *configuration)
        .collect::<Vec<_>>();
    let (mut primary, dominated_by) =
        primary_order(policy, rule.method(), &by_configuration, &admissible)?;
    let primary_rank = primary
        .iter()
        .enumerate()
        .map(|(rank, configuration)| (*configuration, rank as u32))
        .collect::<BTreeMap<_, _>>();

    let mut selected = BTreeSet::new();
    let mut selected_disposition = BTreeMap::new();
    let mut breadth = admissible.clone();
    breadth.sort_by_key(|configuration| {
        let candidate = &by_configuration[configuration];
        (candidate.breadth_ordinal, *configuration)
    });
    select_reserved(
        &breadth,
        rule.breadth_first_reserve as usize,
        RankingDisposition::SelectedBreadthFirst,
        &mut selected,
        &mut selected_disposition,
    );

    let mut novelty = admissible.clone();
    novelty.sort_by(|left, right| {
        let left_candidate = &by_configuration[left];
        let right_candidate = &by_configuration[right];
        right_candidate
            .novelty_score
            .cmp(&left_candidate.novelty_score)
            .then_with(|| left.cmp(right))
    });
    select_reserved(
        &novelty,
        rule.novelty_reserve as usize,
        RankingDisposition::SelectedNovelty,
        &mut selected,
        &mut selected_disposition,
    );

    for configuration in primary.drain(..) {
        if selected.len() >= rule.keep as usize {
            break;
        }
        if selected.insert(configuration) {
            selected_disposition.insert(configuration, RankingDisposition::SelectedObjective);
        }
    }

    let mut evaluations = BTreeMap::new();
    let mut explanations = BTreeMap::new();
    for (configuration, candidate) in by_configuration {
        let evaluation_id = candidate.evaluation.id()?;
        let disposition = if let Some(disposition) = selected_disposition.remove(&configuration) {
            disposition
        } else if !candidate.evaluation.is_admissible() {
            RankingDisposition::Filtered(candidate.evaluation.rejections().clone())
        } else if let Some(dominator) = dominated_by.get(&configuration) {
            RankingDisposition::ParetoDominated(*dominator)
        } else {
            RankingDisposition::RankPruned
        };
        let explanation = RankingExplanation::new(
            evaluation_id,
            disposition,
            primary_rank.get(&configuration).copied(),
            candidate.novelty_score,
            candidate.breadth_ordinal,
        )?;
        charge_survivor_evidence_bytes(&mut evidence_bytes, explanation.canonical_bytes().len())?;
        explanations.insert(configuration, explanation);
        evaluations.insert(configuration, candidate.evaluation);
    }
    let considered = evaluations
        .iter()
        .map(|(configuration, evaluation)| Ok((*configuration, evaluation.id()?)))
        .collect::<Result<BTreeMap<_, _>, CampaignCodecError>>()?;
    let explanation_ids = explanations
        .iter()
        .map(|(configuration, explanation)| Ok((*configuration, explanation.id()?)))
        .collect::<Result<BTreeMap<_, _>, CampaignCodecError>>()?;
    let selection = SurvivorSelection::new(policy_id, rule, considered, selected, explanation_ids)?;
    Ok(SurvivorSelectionBundle {
        evaluations,
        explanations,
        selection,
    })
}

pub(crate) fn charge_survivor_evidence_bytes(
    charged: &mut usize,
    bytes: usize,
) -> Result<(), CampaignCodecError> {
    *charged = charged
        .checked_add(bytes)
        .ok_or(CampaignCodecError::LimitExceeded {
            limit: "survivor-evidence-aggregate-bytes",
        })?;
    if *charged > MAX_SURVIVOR_EVIDENCE_BYTES {
        return Err(CampaignCodecError::LimitExceeded {
            limit: "survivor-evidence-aggregate-bytes",
        });
    }
    Ok(())
}

fn primary_order(
    policy: &CampaignPolicy,
    method: RankingMethod,
    candidates: &BTreeMap<ConfigurationId, RankingCandidate>,
    admissible: &[ConfigurationId],
) -> Result<
    (
        Vec<ConfigurationId>,
        BTreeMap<ConfigurationId, ObjectiveEvaluationId>,
    ),
    CampaignCodecError,
> {
    let mut dominated_by = BTreeMap::new();
    let mut primary = admissible.to_vec();
    match method {
        RankingMethod::ParetoTopK => {
            let visits = admissible
                .len()
                .checked_mul(admissible.len().saturating_sub(1))
                .and_then(|pairs| pairs.checked_mul(policy.objectives().len().max(1)))
                .ok_or(CampaignCodecError::LimitExceeded {
                    limit: "pareto-component-visits",
                })?;
            if visits > MAX_PARETO_COMPONENT_VISITS {
                return Err(CampaignCodecError::LimitExceeded {
                    limit: "pareto-component-visits",
                });
            }
            preflight_weighted_ranking_work(candidates, admissible)?;
            for candidate in admissible {
                let mut dominators = admissible
                    .iter()
                    .filter(|other| *other != candidate)
                    .filter(|other| {
                        dominates(
                            policy,
                            &candidates[other].evaluation,
                            &candidates[candidate].evaluation,
                        )
                    })
                    .copied()
                    .collect::<Vec<_>>();
                dominators.sort();
                if let Some(dominator) = dominators.first() {
                    dominated_by.insert(*candidate, candidates[dominator].evaluation.id()?);
                }
            }
            primary.retain(|configuration| !dominated_by.contains_key(configuration));
            primary.sort_by(|left, right| weighted_order(candidates, *left, *right));
        }
        RankingMethod::Lexicographic => {
            let visits = admissible
                .len()
                .checked_mul(admissible.len())
                .and_then(|pairs| pairs.checked_mul(policy.objectives().len().max(1)))
                .ok_or(CampaignCodecError::LimitExceeded {
                    limit: "lexicographic-component-visits",
                })?;
            if visits > MAX_LEXICOGRAPHIC_COMPONENT_VISITS {
                return Err(CampaignCodecError::LimitExceeded {
                    limit: "lexicographic-component-visits",
                });
            }
            primary.sort_by(|left, right| {
                lexicographic_order(
                    policy,
                    &candidates[left].evaluation,
                    &candidates[right].evaluation,
                )
                .then_with(|| left.cmp(right))
            });
        }
        RankingMethod::WeightedTopK => {
            preflight_weighted_ranking_work(candidates, admissible)?;
            primary.sort_by(|left, right| weighted_order(candidates, *left, *right));
        }
    }
    Ok((primary, dominated_by))
}

fn preflight_weighted_ranking_work(
    candidates: &BTreeMap<ConfigurationId, RankingCandidate>,
    admissible: &[ConfigurationId],
) -> Result<(), CampaignCodecError> {
    let maximum_reward_bytes = admissible
        .iter()
        .filter_map(|configuration| candidates[configuration].evaluation.scalar_reward())
        .map(|reward| {
            reward
                .numerator
                .len()
                .saturating_add(reward.denominator.len())
        })
        .max()
        .unwrap_or(0);
    let visits = admissible
        .len()
        .checked_mul(admissible.len())
        .and_then(|pairs| pairs.checked_mul(maximum_reward_bytes))
        .ok_or(CampaignCodecError::LimitExceeded {
            limit: "weighted-ranking-byte-visits",
        })?;
    if visits > MAX_WEIGHTED_RANKING_BYTE_VISITS {
        return Err(CampaignCodecError::LimitExceeded {
            limit: "weighted-ranking-byte-visits",
        });
    }
    Ok(())
}

fn dominates(
    policy: &CampaignPolicy,
    left: &ObjectiveEvaluation,
    right: &ObjectiveEvaluation,
) -> bool {
    let mut strictly_better = false;
    for (name, objective) in policy.objectives() {
        let ordering = objective_order(
            objective.goal(),
            left.components()[name].value(),
            right.components()[name].value(),
        );
        if ordering == Ordering::Greater {
            return false;
        }
        strictly_better |= ordering == Ordering::Less;
    }
    strictly_better
}

fn lexicographic_order(
    policy: &CampaignPolicy,
    left: &ObjectiveEvaluation,
    right: &ObjectiveEvaluation,
) -> Ordering {
    for (name, objective) in policy.objectives() {
        let ordering = objective_order(
            objective.goal(),
            left.components()[name].value(),
            right.components()[name].value(),
        );
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    Ordering::Equal
}

fn objective_order(
    goal: ObjectiveGoal,
    left: Option<&ObjectiveValue>,
    right: Option<&ObjectiveValue>,
) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => match goal {
            ObjectiveGoal::Minimize => left.exact_cmp(right),
            ObjectiveGoal::Maximize => right.exact_cmp(left),
        },
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

fn weighted_order(
    candidates: &BTreeMap<ConfigurationId, RankingCandidate>,
    left: ConfigurationId,
    right: ConfigurationId,
) -> Ordering {
    match (
        candidates[&left].evaluation.scalar_reward(),
        candidates[&right].evaluation.scalar_reward(),
    ) {
        (Some(left_reward), Some(right_reward)) => {
            right_reward.cmp(left_reward).then_with(|| left.cmp(&right))
        }
        (None, None) => left.cmp(&right),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
    }
}

fn select_reserved(
    order: &[ConfigurationId],
    reserve: usize,
    disposition: RankingDisposition,
    selected: &mut BTreeSet<ConfigurationId>,
    selected_disposition: &mut BTreeMap<ConfigurationId, RankingDisposition>,
) {
    let mut admitted = 0;
    for configuration in order {
        if admitted >= reserve {
            break;
        }
        if selected.insert(*configuration) {
            selected_disposition.insert(*configuration, disposition.clone());
            admitted += 1;
        }
    }
}

fn compute_scalar_reward<'a>(
    components: impl Iterator<Item = &'a ObjectiveComponent>,
) -> Result<FixedReward, CampaignCodecError> {
    let mut numerator = BigInt::zero();
    let mut denominator = BigUint::from(1_u8);
    let mut charged_work = 0usize;
    for component in components {
        let Some(value) = component.value() else {
            return Err(CampaignCodecError::InvalidValue {
                reason: "admissible objective vector contains a missing value",
            });
        };
        let (mut term_numerator, mut term_denominator) = value.fraction();
        term_numerator *= component.weight_micros;
        term_denominator *= 1_000_000_u64;
        if component.goal == ObjectiveGoal::Minimize {
            term_numerator = -term_numerator;
        }
        let common = denominator.gcd(&term_denominator);
        let left_scale = &term_denominator / &common;
        let right_scale = &denominator / &common;
        charged_work = charged_work
            .checked_add(
                numerator
                    .magnitude()
                    .to_bytes_be()
                    .len()
                    .saturating_add(denominator.to_bytes_be().len())
                    .saturating_add(term_numerator.magnitude().to_bytes_be().len())
                    .saturating_add(term_denominator.to_bytes_be().len()),
            )
            .ok_or(CampaignCodecError::LimitExceeded {
                limit: "objective-fixed-reward-work-bytes",
            })?;
        if charged_work > MAX_FIXED_REWARD_WORK_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "objective-fixed-reward-work-bytes",
            });
        }
        numerator = numerator * BigInt::from_biguint(Sign::Plus, left_scale.clone())
            + term_numerator * BigInt::from_biguint(Sign::Plus, right_scale);
        denominator *= left_scale;
        let divisor = numerator.magnitude().gcd(&denominator);
        numerator /= BigInt::from_biguint(Sign::Plus, divisor.clone());
        denominator /= divisor;
        if numerator.magnitude().to_bytes_be().len() > MAX_FIXED_REWARD_MAGNITUDE_BYTES
            || denominator.to_bytes_be().len() > MAX_FIXED_REWARD_MAGNITUDE_BYTES
        {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "objective-fixed-reward-magnitude-bytes",
            });
        }
    }
    FixedReward::from_fraction(numerator, denominator)
}

fn canonical_magnitude_bytes(value: &BigUint) -> Vec<u8> {
    let bytes = value.to_bytes_be();
    if bytes.is_empty() { vec![0] } else { bytes }
}

fn validate_magnitude(bytes: &[u8], reason: &'static str) -> Result<(), CampaignCodecError> {
    if bytes.is_empty()
        || bytes.len() > MAX_FIXED_REWARD_MAGNITUDE_BYTES
        || bytes.len() > 1 && bytes[0] == 0
    {
        Err(CampaignCodecError::InvalidValue { reason })
    } else {
        Ok(())
    }
}

fn require_schema(actual: u32) -> Result<(), CampaignCodecError> {
    if actual == RECORD_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported objective record schema version",
        })
    }
}

#[cfg(test)]
mod tests;
