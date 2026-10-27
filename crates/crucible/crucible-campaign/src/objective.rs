//! Exact objective evaluation, deterministic ranking, and survivor evidence.
//!
//! Execution-model adapters project already-verified measurement aggregates
//! into [`ObjectiveValue`] values. This module applies immutable campaign
//! policy using integer and arbitrary-precision rational arithmetic only. It
//! records every considered evaluation and a stable explanation for every
//! selected, filtered, dominated, or rank-pruned configuration.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use crucible_store::content_store::ContentId;
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
const OBJECTIVE_SCHEMA_VERSION: u32 = 2;
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
// Keeps streamed cross-product work within the existing weighted-work scale.
const MAX_WEIGHTED_RANKING_LIMB_PRODUCTS: usize = 512 * 1024 * 1024;
const MAGNITUDE_COMPARISON_POLL_LIMBS: usize = 32;

fn insert_paid_btree_map<K: Ord, V>(
    values: &mut BTreeMap<K, V>,
    key: K,
    value: V,
) -> Result<Option<V>, CampaignCodecError> {
    if !values.contains_key(&key) {
        crucible_store::owned_decode::charge_btree_entry::<K, V>()?;
    }
    Ok(values.insert(key, value))
}

fn insert_paid_btree_set<T: Ord>(
    values: &mut BTreeSet<T>,
    value: T,
) -> Result<bool, CampaignCodecError> {
    if values.contains(&value) {
        return Ok(false);
    }
    crucible_store::owned_decode::charge_btree_set_entry::<T>()?;
    Ok(values.insert(value))
}

fn reserve_paid_vec<T>(values: &mut Vec<T>, additional: usize) -> Result<(), CampaignCodecError> {
    crucible_store::owned_decode::reserve_vec(values, additional).map_err(CampaignCodecError::from)
}

fn copy_paid_slice<T: Copy>(values: &[T]) -> Result<Vec<T>, CampaignCodecError> {
    let mut copy = Vec::new();
    reserve_paid_vec(&mut copy, values.len())?;
    copy.extend_from_slice(values);
    Ok(copy)
}

fn verify_budget(
    budget: Option<&crucible_store::owned_decode::DecodeBudget>,
) -> Result<(), CampaignCodecError> {
    budget
        .map(crucible_store::owned_decode::DecodeBudget::verify_live)
        .transpose()
        .map(|_| ())
        .map_err(CampaignCodecError::from)
}

fn try_sort_by<T, E>(
    values: &mut [T],
    mut compare: impl FnMut(&T, &T) -> Result<Ordering, E>,
) -> Result<(), E> {
    fn sift_down<T, E>(
        values: &mut [T],
        mut root: usize,
        end: usize,
        compare: &mut impl FnMut(&T, &T) -> Result<Ordering, E>,
    ) -> Result<(), E> {
        while let Some(left_child) = root.checked_mul(2).and_then(|index| index.checked_add(1)) {
            if left_child >= end {
                break;
            }
            let right_child = left_child + 1;
            let child = if right_child < end
                && compare(&values[left_child], &values[right_child])?.is_lt()
            {
                right_child
            } else {
                left_child
            };
            if !compare(&values[root], &values[child])?.is_lt() {
                break;
            }
            values.swap(root, child);
            root = child;
        }
        Ok(())
    }

    let length = values.len();
    for root in (0..length / 2).rev() {
        sift_down(values, root, length, &mut compare)?;
    }
    for end in (1..length).rev() {
        values.swap(0, end);
        sift_down(values, 0, end, &mut compare)?;
    }
    Ok(())
}

fn reserve_big_arithmetic_scratch(
    maximum_bits: u64,
    live_storage_extents: u64,
) -> Result<Option<crucible_store::owned_decode::DecodeScratch>, CampaignCodecError> {
    let digit_bits = u64::from(usize::BITS);
    let digits = maximum_bits.max(1).div_ceil(digit_bits);
    let bytes = digits
        .checked_mul(std::mem::size_of::<usize>() as u64)
        .and_then(|bytes| bytes.checked_mul(live_storage_extents))
        .ok_or(CampaignCodecError::LimitExceeded {
            limit: "objective-big-arithmetic-scratch-bytes",
        })?;
    crucible_store::owned_decode::current_budget()
        .map(|budget| budget.reserve_scratch_bytes(bytes))
        .transpose()
        .map_err(CampaignCodecError::from)
}

fn magnitude_byte_length(value: &BigUint) -> usize {
    usize::try_from(value.bits().div_ceil(8)).unwrap_or(usize::MAX)
}

fn scalar_bit_length(value: u128) -> u64 {
    u64::from(u128::BITS - value.leading_zeros())
}

fn trim_magnitude(bytes: &[u8]) -> &[u8] {
    let mut first = 0;
    while first + 1 < bytes.len() && bytes[first] == 0 {
        first += 1;
    }
    &bytes[first..]
}

fn magnitude_bits(bytes: &[u8]) -> usize {
    let bytes = trim_magnitude(bytes);
    if bytes == [0] {
        0
    } else {
        (bytes.len() - 1) * 8 + (u8::BITS - bytes[0].leading_zeros()) as usize
    }
}

fn magnitude_limb(bytes: &[u8], index: usize) -> u64 {
    let Some(end) = bytes.len().checked_sub(index.saturating_mul(8)) else {
        return 0;
    };
    if end == 0 {
        return 0;
    }
    let start = end.saturating_sub(8);
    bytes[start..end]
        .iter()
        .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte))
}

struct MagnitudeProduct<'a> {
    left: &'a [u8],
    right: &'a [u8],
    left_limbs: usize,
    right_limbs: usize,
    next_limb: usize,
    carry: [u64; 3],
}

impl<'a> MagnitudeProduct<'a> {
    fn new(left: &'a [u8], right: &'a [u8]) -> Self {
        Self {
            left,
            right,
            left_limbs: left.len().div_ceil(8),
            right_limbs: right.len().div_ceil(8),
            next_limb: 0,
            carry: [0; 3],
        }
    }

    fn add_product(&mut self, left: u64, right: u64) {
        // The canonical magnitude cap limits each diagonal to 1,024 terms;
        // the third carry limb therefore cannot overflow.
        let product = u128::from(left) * u128::from(right);
        let low = product as u64;
        let high = (product >> 64) as u64;
        let low_sum = u128::from(self.carry[0]) + u128::from(low);
        self.carry[0] = low_sum as u64;
        let high_sum = u128::from(self.carry[1]) + u128::from(high) + (low_sum >> 64);
        self.carry[1] = high_sum as u64;
        self.carry[2] += (high_sum >> 64) as u64;
    }

    fn take_limb(&mut self) -> Option<u64> {
        if self.next_limb >= self.left_limbs + self.right_limbs {
            return None;
        }
        let first_left = self
            .next_limb
            .saturating_add(1)
            .saturating_sub(self.right_limbs);
        let last_left = self.next_limb.min(self.left_limbs.saturating_sub(1));
        if first_left <= last_left {
            for left_index in first_left..=last_left {
                let right_index = self.next_limb - left_index;
                self.add_product(
                    magnitude_limb(self.left, left_index),
                    magnitude_limb(self.right, right_index),
                );
            }
        }
        let result = self.carry[0];
        self.carry[0] = self.carry[1];
        self.carry[1] = self.carry[2];
        self.carry[2] = 0;
        self.next_limb += 1;
        Some(result)
    }
}

fn try_compare_magnitude_products<E>(
    left: (&[u8], &[u8]),
    right: (&[u8], &[u8]),
    mut poll: impl FnMut() -> Result<(), E>,
) -> Result<Ordering, E> {
    poll()?;
    let product_bits = |factors: (&[u8], &[u8])| {
        let left_bits = magnitude_bits(factors.0);
        let right_bits = magnitude_bits(factors.1);
        if left_bits == 0 || right_bits == 0 {
            0
        } else {
            left_bits.saturating_add(right_bits)
        }
    };
    let left_bits = product_bits(left);
    let right_bits = product_bits(right);
    if left_bits + 1 < right_bits {
        return Ok(Ordering::Less);
    }
    if right_bits + 1 < left_bits {
        return Ok(Ordering::Greater);
    }

    let mut left_product = MagnitudeProduct::new(left.0, left.1);
    let mut right_product = MagnitudeProduct::new(right.0, right.1);
    let limbs = (left_product.left_limbs + left_product.right_limbs)
        .max(right_product.left_limbs + right_product.right_limbs);
    let mut ordering = Ordering::Equal;
    for limb in 0..limbs {
        if limb % MAGNITUDE_COMPARISON_POLL_LIMBS == 0 {
            poll()?;
        }
        let left_limb = left_product.take_limb().unwrap_or(0);
        let right_limb = right_product.take_limb().unwrap_or(0);
        if left_limb != right_limb {
            // Later limbs are more significant and supersede earlier differences.
            ordering = left_limb.cmp(&right_limb);
        }
    }
    Ok(ordering)
}

fn compare_magnitude_products(left: (&[u8], &[u8]), right: (&[u8], &[u8])) -> Ordering {
    match try_compare_magnitude_products(left, right, || Ok::<(), std::convert::Infallible>(())) {
        Ok(ordering) => ordering,
        Err(error) => match error {},
    }
}

fn compare_fraction_magnitudes(
    left_numerator: u128,
    left_denominator: u128,
    right_numerator: u128,
    right_denominator: u128,
) -> Ordering {
    let left_numerator = left_numerator.to_be_bytes();
    let left_denominator = left_denominator.to_be_bytes();
    let right_numerator = right_numerator.to_be_bytes();
    let right_denominator = right_denominator.to_be_bytes();
    compare_magnitude_products(
        (
            trim_magnitude(&left_numerator),
            trim_magnitude(&right_denominator),
        ),
        (
            trim_magnitude(&right_numerator),
            trim_magnitude(&left_denominator),
        ),
    )
}

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

    fn signed_magnitude_fraction(&self) -> (bool, u128, u128) {
        match self {
            Self::Signed(value) => (value.is_negative(), u128::from(value.unsigned_abs()), 1),
            Self::Unsigned(value) => (false, u128::from(*value), 1),
            Self::Rational {
                negative,
                numerator,
                denominator,
            } => (*negative && *numerator != 0, *numerator, *denominator),
        }
    }

    fn exact_cmp(&self, other: &Self) -> Ordering {
        let (left_negative, left_numerator, left_denominator) = self.signed_magnitude_fraction();
        let (right_negative, right_numerator, right_denominator) =
            other.signed_magnitude_fraction();
        match (left_negative, right_negative) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => compare_fraction_magnitudes(
                left_numerator,
                left_denominator,
                right_numerator,
                right_denominator,
            ),
            (true, true) => compare_fraction_magnitudes(
                right_numerator,
                right_denominator,
                left_numerator,
                left_denominator,
            ),
        }
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
        let numerator_bytes = magnitude_byte_length(&reduced_numerator).max(1);
        let denominator_bytes = magnitude_byte_length(&reduced_denominator).max(1);
        if numerator_bytes > MAX_FIXED_REWARD_MAGNITUDE_BYTES
            || denominator_bytes > MAX_FIXED_REWARD_MAGNITUDE_BYTES
        {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "objective-fixed-reward-magnitude-bytes",
            });
        }
        crucible_store::owned_decode::charge_array::<u8>(numerator_bytes)?;
        let numerator = canonical_magnitude_bytes(&reduced_numerator);
        crucible_store::owned_decode::charge_array::<u8>(denominator_bytes)?;
        let denominator = canonical_magnitude_bytes(&reduced_denominator);
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
        let scratch_bits = u64::try_from(numerator.len().saturating_add(denominator.len()))
            .ok()
            .and_then(|bytes| bytes.checked_mul(8))
            .ok_or(CampaignCodecError::LimitExceeded {
                limit: "objective-big-arithmetic-scratch-bytes",
            })?;
        // Two decoded values, their conversion buffers, and the two mutable
        // operands used by Stein's GCD are simultaneously live here.
        let _scratch = reserve_big_arithmetic_scratch(scratch_bits, 6)?;
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

    fn try_cmp<E>(
        &self,
        other: &Self,
        mut poll: impl FnMut() -> Result<(), E>,
    ) -> Result<Ordering, E> {
        poll()?;
        match (self.negative, other.negative) {
            (true, false) => Ok(Ordering::Less),
            (false, true) => Ok(Ordering::Greater),
            (false, false) => try_compare_magnitude_products(
                (&self.numerator, &other.denominator),
                (&other.numerator, &self.denominator),
                poll,
            ),
            (true, true) => try_compare_magnitude_products(
                (&other.numerator, &self.denominator),
                (&self.numerator, &other.denominator),
                poll,
            ),
        }
    }
}

impl Ord for FixedReward {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.try_cmp(other, || Ok::<(), std::convert::Infallible>(())) {
            Ok(ordering) => ordering,
            Err(error) => match error {},
        }
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
    /// Scenario actions declared failure, bound to the ordered reason vector.
    ScenarioFailure(crate::CampaignHash),
}

impl Canonical for ObjectiveRejection {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::MissingMeasurement(value) => {
                encoder.u8(0);
                value.encode(encoder);
            }
            Self::PropertyFailed(value) => {
                encoder.u8(1);
                value.encode(encoder);
            }
            Self::PropertyInconclusive(value) => {
                encoder.u8(2);
                value.encode(encoder);
            }
            Self::GuestCrash(value) => {
                encoder.u8(3);
                value.encode(encoder);
            }
            Self::AssertionFailure(value) => {
                encoder.u8(4);
                value.encode(encoder);
            }
            Self::ScenarioFailure(reasons) => {
                encoder.u8(5);
                reasons.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let tag = decoder.u8()?;
        if tag == 5 {
            return Ok(Self::ScenarioFailure(crate::CampaignHash::decode(decoder)?));
        }
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
        Self::from_validated_parts(
            observation,
            configuration,
            policy,
            rejections,
            components,
            scalar_reward,
        )
    }

    fn from_validated_parts(
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
            crate::ObjectEnvelope::for_record_versioned(
                crate::CampaignRecordKind::ObjectiveEvaluation,
                OBJECTIVE_SCHEMA_VERSION,
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

    pub(crate) const fn schema_version(&self) -> u32 {
        OBJECTIVE_SCHEMA_VERSION
    }
}

impl Canonical for ObjectiveEvaluation {
    fn encode(&self, encoder: &mut Encoder) {
        OBJECTIVE_SCHEMA_VERSION.encode(encoder);
        self.observation.encode(encoder);
        self.configuration.encode(encoder);
        self.policy.encode(encoder);
        self.rejections.encode(encoder);
        self.components.encode(encoder);
        self.scalar_reward.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        if u32::decode(decoder)? != OBJECTIVE_SCHEMA_VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported objective-evaluation schema version",
            });
        }
        Self::from_validated_parts(
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
/// guest crashes, assertion failures, and scenario failures also make the
/// result inadmissible.
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
        crate::StopOutcome::ScenarioFailure(reasons) => {
            rejections.insert(ObjectiveRejection::ScenarioFailure(
                crate::observation::scenario_failure_hash(reasons),
            ));
        }
        crate::StopOutcome::Reached(_)
        | crate::StopOutcome::BoundedPrimaryReached { .. }
        | crate::StopOutcome::BoundedPrimaryTimeout { .. }
        | crate::StopOutcome::ObservationReached(_)
        | crate::StopOutcome::TerminalSuccess
        | crate::StopOutcome::ModeledTimeout(_)
        | crate::StopOutcome::PolicyTimeout { .. } => {}
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
        Self::from_validated_parts(
            evaluation,
            disposition,
            primary_rank,
            novelty_score,
            breadth_ordinal,
        )
    }

    fn from_validated_parts(
        evaluation: ObjectiveEvaluationId,
        disposition: RankingDisposition,
        primary_rank: Option<u32>,
        novelty_score: u64,
        breadth_ordinal: u64,
    ) -> Result<Self, CampaignCodecError> {
        let value = Self {
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
            crate::ObjectEnvelope::for_record_versioned(
                crate::CampaignRecordKind::RankingExplanation,
                OBJECTIVE_SCHEMA_VERSION,
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

    pub(crate) const fn schema_version(&self) -> u32 {
        OBJECTIVE_SCHEMA_VERSION
    }
}

impl Canonical for RankingExplanation {
    fn encode(&self, encoder: &mut Encoder) {
        OBJECTIVE_SCHEMA_VERSION.encode(encoder);
        self.evaluation.encode(encoder);
        self.disposition.encode(encoder);
        self.primary_rank.encode(encoder);
        self.novelty_score.encode(encoder);
        self.breadth_ordinal.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        if u32::decode(decoder)? != OBJECTIVE_SCHEMA_VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported ranking-explanation schema version",
            });
        }
        Self::from_validated_parts(
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
/// candidates or comparison work, missing scalar rewards, oversized canonical
/// records, or refusal by an active decode resource authority.
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
        if candidate.evaluation.policy() != policy_id {
            return Err(CampaignCodecError::InvalidValue {
                reason: "survivor candidates have duplicate configurations or policy mismatch",
            });
        }
        if insert_paid_btree_map(
            &mut by_configuration,
            candidate.evaluation.configuration(),
            candidate,
        )?
        .is_some()
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "survivor candidates have duplicate configurations or policy mismatch",
            });
        }
    }

    let admissible_count = by_configuration
        .iter()
        .filter(|(_, candidate)| candidate.evaluation.is_admissible())
        .count();
    let mut admissible = Vec::new();
    reserve_paid_vec(&mut admissible, admissible_count)?;
    admissible.extend(
        by_configuration
            .iter()
            .filter(|(_, candidate)| candidate.evaluation.is_admissible())
            .map(|(configuration, _)| *configuration),
    );
    let (mut primary, dominated_by) =
        primary_order(policy, rule.method(), &by_configuration, &admissible)?;
    let mut primary_rank = BTreeMap::new();
    for (rank, configuration) in primary.iter().enumerate() {
        insert_paid_btree_map(&mut primary_rank, *configuration, rank as u32)?;
    }

    let mut selected = BTreeSet::new();
    let mut selected_disposition = BTreeMap::new();
    let mut reserve_order = copy_paid_slice(&admissible)?;
    let budget = crucible_store::owned_decode::current_budget();
    try_sort_by(
        &mut reserve_order,
        |left, right| -> Result<Ordering, CampaignCodecError> {
            verify_budget(budget.as_ref())?;
            let left_candidate = &by_configuration[left];
            let right_candidate = &by_configuration[right];
            Ok((left_candidate.breadth_ordinal, *left)
                .cmp(&(right_candidate.breadth_ordinal, *right)))
        },
    )?;
    select_reserved(
        &reserve_order,
        rule.breadth_first_reserve as usize,
        || RankingDisposition::SelectedBreadthFirst,
        &mut selected,
        &mut selected_disposition,
    )?;

    try_sort_by(
        &mut reserve_order,
        |left, right| -> Result<Ordering, CampaignCodecError> {
            verify_budget(budget.as_ref())?;
            let left_candidate = &by_configuration[left];
            let right_candidate = &by_configuration[right];
            Ok(right_candidate
                .novelty_score
                .cmp(&left_candidate.novelty_score)
                .then_with(|| left.cmp(right)))
        },
    )?;
    select_reserved(
        &reserve_order,
        rule.novelty_reserve as usize,
        || RankingDisposition::SelectedNovelty,
        &mut selected,
        &mut selected_disposition,
    )?;

    for configuration in primary.drain(..) {
        if selected.len() >= rule.keep as usize {
            break;
        }
        if insert_paid_btree_set(&mut selected, configuration)? {
            insert_paid_btree_map(
                &mut selected_disposition,
                configuration,
                RankingDisposition::SelectedObjective,
            )?;
        }
    }

    let mut evaluations = BTreeMap::new();
    let mut explanations = BTreeMap::new();
    for (configuration, candidate) in by_configuration {
        let evaluation_id = candidate.evaluation.id()?;
        let disposition = if let Some(disposition) = selected_disposition.remove(&configuration) {
            disposition
        } else if !candidate.evaluation.is_admissible() {
            RankingDisposition::Filtered(codec::admitted_clone(candidate.evaluation.rejections())?)
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
        insert_paid_btree_map(&mut explanations, configuration, explanation)?;
        insert_paid_btree_map(&mut evaluations, configuration, candidate.evaluation)?;
    }
    let mut considered = BTreeMap::new();
    for (configuration, evaluation) in &evaluations {
        insert_paid_btree_map(&mut considered, *configuration, evaluation.id()?)?;
    }
    let mut explanation_ids = BTreeMap::new();
    for (configuration, explanation) in &explanations {
        insert_paid_btree_map(&mut explanation_ids, *configuration, explanation.id()?)?;
    }
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
    let budget = crucible_store::owned_decode::current_budget();
    verify_budget(budget.as_ref())?;
    let mut dominated_by = BTreeMap::new();
    let mut primary = copy_paid_slice(admissible)?;
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
                let mut dominator = None;
                for other in admissible {
                    if other == candidate {
                        continue;
                    }
                    verify_budget(budget.as_ref())?;
                    if dominates(
                        policy,
                        &candidates[other].evaluation,
                        &candidates[candidate].evaluation,
                    ) && dominator.is_none_or(|selected| other < &selected)
                    {
                        dominator = Some(*other);
                    }
                }
                if let Some(dominator) = dominator {
                    insert_paid_btree_map(
                        &mut dominated_by,
                        *candidate,
                        candidates[&dominator].evaluation.id()?,
                    )?;
                }
            }
            primary.retain(|configuration| !dominated_by.contains_key(configuration));
            try_sort_by(
                &mut primary,
                |left, right| -> Result<Ordering, CampaignCodecError> {
                    weighted_order(candidates, *left, *right, budget.as_ref())
                },
            )?;
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
            try_sort_by(
                &mut primary,
                |left, right| -> Result<Ordering, CampaignCodecError> {
                    verify_budget(budget.as_ref())?;
                    Ok(lexicographic_order(
                        policy,
                        &candidates[left].evaluation,
                        &candidates[right].evaluation,
                    )
                    .then_with(|| left.cmp(right)))
                },
            )?;
        }
        RankingMethod::WeightedTopK => {
            preflight_weighted_ranking_work(candidates, admissible)?;
            try_sort_by(
                &mut primary,
                |left, right| -> Result<Ordering, CampaignCodecError> {
                    weighted_order(candidates, *left, *right, budget.as_ref())
                },
            )?;
        }
    }
    Ok((primary, dominated_by))
}

fn preflight_weighted_ranking_work(
    candidates: &BTreeMap<ConfigurationId, RankingCandidate>,
    admissible: &[ConfigurationId],
) -> Result<(), CampaignCodecError> {
    let budget = crucible_store::owned_decode::current_budget();
    let mut maximum_reward_bytes = 0;
    let mut maximum_numerator_limbs = 0;
    let mut maximum_denominator_limbs = 0;
    for reward in admissible
        .iter()
        .filter_map(|configuration| candidates[configuration].evaluation.scalar_reward())
    {
        verify_budget(budget.as_ref())?;
        maximum_reward_bytes = maximum_reward_bytes.max(
            reward
                .numerator
                .len()
                .saturating_add(reward.denominator.len()),
        );
        maximum_numerator_limbs = maximum_numerator_limbs.max(reward.numerator.len().div_ceil(8));
        maximum_denominator_limbs =
            maximum_denominator_limbs.max(reward.denominator.len().div_ceil(8));
    }
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

    let limb_products_per_pair = maximum_numerator_limbs
        .checked_mul(maximum_denominator_limbs)
        .and_then(|products| products.checked_mul(2))
        .ok_or(CampaignCodecError::LimitExceeded {
            limit: "weighted-ranking-limb-products",
        })?;
    let limb_products = admissible
        .len()
        .checked_mul(admissible.len())
        .and_then(|pairs| pairs.checked_mul(limb_products_per_pair))
        .ok_or(CampaignCodecError::LimitExceeded {
            limit: "weighted-ranking-limb-products",
        })?;
    if limb_products > MAX_WEIGHTED_RANKING_LIMB_PRODUCTS {
        return Err(CampaignCodecError::LimitExceeded {
            limit: "weighted-ranking-limb-products",
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
    budget: Option<&crucible_store::owned_decode::DecodeBudget>,
) -> Result<Ordering, CampaignCodecError> {
    verify_budget(budget)?;
    match (
        candidates[&left].evaluation.scalar_reward(),
        candidates[&right].evaluation.scalar_reward(),
    ) {
        (Some(left_reward), Some(right_reward)) => Ok(right_reward
            .try_cmp(left_reward, || verify_budget(budget))?
            .then_with(|| left.cmp(&right))),
        (None, None) => Ok(left.cmp(&right)),
        (Some(_), None) => Ok(Ordering::Less),
        (None, Some(_)) => Ok(Ordering::Greater),
    }
}

fn select_reserved(
    order: &[ConfigurationId],
    reserve: usize,
    disposition: impl Fn() -> RankingDisposition,
    selected: &mut BTreeSet<ConfigurationId>,
    selected_disposition: &mut BTreeMap<ConfigurationId, RankingDisposition>,
) -> Result<(), CampaignCodecError> {
    let mut admitted = 0;
    for configuration in order {
        if admitted >= reserve {
            break;
        }
        if insert_paid_btree_set(selected, *configuration)? {
            insert_paid_btree_map(selected_disposition, *configuration, disposition())?;
            admitted += 1;
        }
    }
    Ok(())
}

fn compute_scalar_reward<'a, I>(components: I) -> Result<FixedReward, CampaignCodecError>
where
    I: Iterator<Item = &'a ObjectiveComponent> + Clone,
{
    let budget = crucible_store::owned_decode::current_budget();
    verify_budget(budget.as_ref())?;
    let initial_scratch = reserve_big_arithmetic_scratch(usize::BITS.into(), 2)?;
    let mut numerator = BigInt::zero();
    let mut denominator = BigUint::from(1_u8);

    // Preserve the missing-value error before admitting scratch for arithmetic
    // on later components. The initial zero and one remain funded above.
    for component in components.clone() {
        verify_budget(budget.as_ref())?;
        if component.value().is_none() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "admissible objective vector contains a missing value",
            });
        }
    }

    let mut denominator_bits = 0_u64;
    let mut largest_term_numerator_bits = 0_u64;
    let mut component_count = 0_u64;
    for component in components.clone() {
        verify_budget(budget.as_ref())?;
        let Some(value) = component.value() else {
            return Err(CampaignCodecError::InvalidValue {
                reason: "admissible objective vector contains a missing value",
            });
        };
        let (_, value_numerator, value_denominator) = value.signed_magnitude_fraction();
        let term_numerator_bits = scalar_bit_length(value_numerator)
            .checked_add(scalar_bit_length(u128::from(component.weight_micros)))
            .ok_or(CampaignCodecError::LimitExceeded {
                limit: "objective-big-arithmetic-scratch-bytes",
            })?;
        let term_denominator_bits = scalar_bit_length(value_denominator)
            .checked_add(scalar_bit_length(1_000_000))
            .ok_or(CampaignCodecError::LimitExceeded {
                limit: "objective-big-arithmetic-scratch-bytes",
            })?;
        denominator_bits = denominator_bits.checked_add(term_denominator_bits).ok_or(
            CampaignCodecError::LimitExceeded {
                limit: "objective-big-arithmetic-scratch-bytes",
            },
        )?;
        largest_term_numerator_bits = largest_term_numerator_bits.max(term_numerator_bits);
        component_count =
            component_count
                .checked_add(1)
                .ok_or(CampaignCodecError::LimitExceeded {
                    limit: "objective-big-arithmetic-scratch-bytes",
                })?;
    }
    let sum_bits = scalar_bit_length(u128::from(component_count))
        .checked_add(largest_term_numerator_bits)
        .and_then(|bits| bits.checked_add(denominator_bits))
        .ok_or(CampaignCodecError::LimitExceeded {
            limit: "objective-big-arithmetic-scratch-bytes",
        })?;

    // At the arithmetic expression's peak, twelve caller-visible magnitudes
    // coexist. One num-bigint Toom-3 level retains ten operand-sized extents:
    // two for the six thirds, three for four evaluation values, three for five
    // products, and two for interpolation. Recursive levels shrink by thirds,
    // so fifteen extents cover the geometric series; three cover conversions.
    let arithmetic_scratch = reserve_big_arithmetic_scratch(sum_bits.max(denominator_bits), 30)?;
    drop(initial_scratch);

    let mut charged_work = 0usize;
    for component in components {
        verify_budget(budget.as_ref())?;
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
                magnitude_byte_length(numerator.magnitude())
                    .saturating_add(magnitude_byte_length(&denominator))
                    .saturating_add(magnitude_byte_length(term_numerator.magnitude()))
                    .saturating_add(magnitude_byte_length(&term_denominator)),
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
        if magnitude_byte_length(numerator.magnitude()) > MAX_FIXED_REWARD_MAGNITUDE_BYTES
            || magnitude_byte_length(&denominator) > MAX_FIXED_REWARD_MAGNITUDE_BYTES
        {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "objective-fixed-reward-magnitude-bytes",
            });
        }
        verify_budget(budget.as_ref())?;
    }
    verify_budget(budget.as_ref())?;
    let reward = FixedReward::from_fraction(numerator, denominator)?;
    drop(arithmetic_scratch);
    Ok(reward)
}

mod codec_helpers;
use codec_helpers::*;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod magnitude_product_tests {
    use super::*;
    use crucible_host_resources::test_support::TestAllocationObserver;
    use crucible_store::owned_decode::{
        DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority, ResourceLoan,
    };
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    struct RevokingAuthority {
        calls: AtomicUsize,
        fail_at: usize,
    }

    impl DecodeResourceAuthority for RevokingAuthority {
        fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
            let call = self.calls.fetch_add(1, AtomicOrdering::SeqCst);
            if call >= self.fail_at {
                Err(DecodeAdmissionError::new(std::io::Error::other(
                    "comparison cancelled",
                )))
            } else {
                Ok(())
            }
        }

        fn reserve(&self, _bytes: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
            Ok(ResourceLoan::new(()))
        }
    }

    fn oracle(left: (&[u8], &[u8]), right: (&[u8], &[u8])) -> Ordering {
        (BigUint::from_bytes_be(left.0) * BigUint::from_bytes_be(left.1))
            .cmp(&(BigUint::from_bytes_be(right.0) * BigUint::from_bytes_be(right.1)))
    }

    fn assert_product_order(left: (&[u8], &[u8]), right: (&[u8], &[u8])) {
        let expected = oracle(left, right);
        let (actual, allocations) =
            TestAllocationObserver::count(|| compare_magnitude_products(left, right));

        assert_eq!(actual, expected);
        assert!(!allocations.overflow);
        assert_eq!(allocations.allocations, 0);
        assert_eq!(allocations.reallocations, 0);
    }

    #[test]
    fn magnitude_products_match_biguint_without_allocating() {
        let zero = [0];
        let one = [1];
        let large = [0xff; 257];
        let carry_heavy_left = [0xff; 33];
        let carry_heavy_right = [0xff; 25];
        let unequal_left = [0x81; 41];
        let unequal_right = [0x7f; 9];

        assert_product_order((&zero, &large), (&one, &one));
        assert_product_order((&one, &one), (&zero, &large));
        assert_product_order((&zero, &large), (&large, &zero));
        assert_product_order(
            (&carry_heavy_left, &carry_heavy_right),
            (&large[..17], &large[..41]),
        );
        assert_product_order(
            (&unequal_left, &unequal_right),
            (&large[..13], &large[..29]),
        );

        let maximum_magnitude = [0xff; MAX_FIXED_REWARD_MAGNITUDE_BYTES];
        let near_maximum_magnitude = [0xfe; MAX_FIXED_REWARD_MAGNITUDE_BYTES];
        assert_product_order(
            (&maximum_magnitude, &maximum_magnitude),
            (&near_maximum_magnitude, &maximum_magnitude),
        );

        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        for case in 0..128_usize {
            let mut next_byte = || {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            };
            let left_length = 1 + case % 67;
            let right_length = 1 + (case * 17) % 71;
            let mut left_numerator = Vec::with_capacity(left_length);
            let mut left_denominator = Vec::with_capacity(right_length);
            let mut right_numerator = Vec::with_capacity(right_length);
            let mut right_denominator = Vec::with_capacity(left_length);
            left_numerator.extend((0..left_length).map(|_| next_byte()));
            left_denominator.extend((0..right_length).map(|_| next_byte()));
            right_numerator.extend((0..right_length).map(|_| next_byte()));
            right_denominator.extend((0..left_length).map(|_| next_byte()));

            assert_product_order(
                (&left_numerator, &left_denominator),
                (&right_numerator, &right_denominator),
            );
        }
    }

    #[test]
    fn product_comparison_propagates_active_budget_revocation() {
        let authority = Arc::new(RevokingAuthority {
            calls: AtomicUsize::new(0),
            fail_at: 3,
        });
        let budget = DecodeBudget::new(authority.clone(), 1024 * 1024)
            .unwrap_or_else(|error| panic!("test budget: {error}"));
        let _scope = budget.enter();
        let active = crucible_store::owned_decode::current_budget();
        let magnitude = [0xff; 1024];
        let result = try_compare_magnitude_products(
            (&magnitude, &magnitude),
            (&magnitude, &magnitude),
            || verify_budget(active.as_ref()),
        );

        assert!(matches!(
            result,
            Err(CampaignCodecError::DecodeAdmission(_))
        ));
        assert_eq!(authority.calls.load(AtomicOrdering::SeqCst), 4);
    }

    #[test]
    fn fallible_heap_sort_matches_total_standard_order() {
        let mut expected = vec![17_i32, -4, 0, 91, 8, -100, 42, 5];
        let mut actual = expected.clone();
        expected.sort_unstable();

        try_sort_by(&mut actual, |left, right| {
            Ok::<_, std::convert::Infallible>(left.cmp(right))
        })
        .unwrap_or_else(|error| match error {});

        assert_eq!(actual, expected);

        let mut comparisons = 0;
        let refused = try_sort_by(&mut actual, |left, right| {
            comparisons += 1;
            if comparisons == 3 {
                Err(CampaignCodecError::from(DecodeAdmissionError::new(
                    std::io::Error::other("sort cancelled"),
                )))
            } else {
                Ok(left.cmp(right))
            }
        });
        assert!(matches!(
            refused,
            Err(CampaignCodecError::DecodeAdmission(_))
        ));
        assert_eq!(comparisons, 3);
    }
}
