//! Boolean, discrete, and fixed-width integer choice domains.

use std::collections::BTreeMap;

use crate::codec::{self, Canonical, Decoder, Encoder};
use crate::policy::ExactRational;
use crate::{
    AlternativeId, CampaignCodecError, CampaignHash, ChoiceDomainId, ChoiceDomainSemanticId,
};

const CHOICE_DOMAIN_SCHEMA_VERSION: u32 = 1;
const MAX_DISCRETE_ALTERNATIVES: usize = 4096;
const MAX_PRESENTATION_BYTES: usize = 2048;
const MAX_INTEGER_LANDMARKS: usize = 4096;
const MAX_CHOICE_DOMAIN_BYTES: usize = 32 * 1024 * 1024;

/// Boolean domain with an explicit semantic version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BooleanDomain {
    semantic_version: u32,
}

impl BooleanDomain {
    /// Builds a versioned Boolean domain.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError::InvalidValue`] for semantic version zero.
    pub fn new(semantic_version: u32) -> Result<Self, CampaignCodecError> {
        if semantic_version == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "choice-domain semantic version is zero",
            });
        }
        Ok(Self { semantic_version })
    }

    /// Returns the semantic domain version.
    #[must_use]
    pub const fn semantic_version(self) -> u32 {
        self.semantic_version
    }
}

impl Canonical for BooleanDomain {
    fn encode(&self, encoder: &mut Encoder) {
        self.semantic_version.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(u32::decode(decoder)?)
    }
}

/// Stable discrete alternative with explicitly non-semantic presentation text.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DiscreteAlternative {
    id: AlternativeId,
    label: String,
    description: Option<String>,
}

impl DiscreteAlternative {
    /// Builds one stable alternative.
    ///
    /// Labels and descriptions are stored and exported but excluded from
    /// [`ChoiceDomainSemanticId`].
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError::InvalidValue`] for empty or oversized
    /// presentation text.
    pub fn new(
        id: AlternativeId,
        label: impl Into<String>,
        description: Option<String>,
    ) -> Result<Self, CampaignCodecError> {
        let label = label.into();
        codec::validate_nfc(&label)?;
        if let Some(value) = &description {
            codec::validate_nfc(value)?;
        }
        if label.is_empty()
            || label.len() > MAX_PRESENTATION_BYTES
            || description
                .as_ref()
                .is_some_and(|value| value.len() > MAX_PRESENTATION_BYTES)
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "discrete alternative presentation text is invalid",
            });
        }
        Ok(Self {
            id,
            label,
            description,
        })
    }

    /// Returns the stable semantic alternative identity.
    #[must_use]
    pub const fn id(&self) -> AlternativeId {
        self.id
    }

    /// Returns the non-semantic display label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Returns the optional non-semantic display description.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

impl Canonical for DiscreteAlternative {
    fn encode(&self, encoder: &mut Encoder) {
        self.id.encode(encoder);
        self.label.encode(encoder);
        self.description.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            AlternativeId::decode(decoder)?,
            decoder.string_bounded(MAX_PRESENTATION_BYTES, "discrete-label-bytes")?,
            decoder.option_string_bounded(MAX_PRESENTATION_BYTES, "discrete-description-bytes")?,
        )
    }
}

/// Nonempty finite discrete choice domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscreteDomain {
    semantic_version: u32,
    alternatives: BTreeMap<AlternativeId, DiscreteAlternative>,
}

impl DiscreteDomain {
    /// Builds a canonical alternative map keyed by stable ID.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for version zero, an empty or oversized
    /// map, or a key/value identity mismatch.
    pub fn new(
        semantic_version: u32,
        alternatives: BTreeMap<AlternativeId, DiscreteAlternative>,
    ) -> Result<Self, CampaignCodecError> {
        if semantic_version == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "choice-domain semantic version is zero",
            });
        }
        if alternatives.is_empty() || alternatives.len() > MAX_DISCRETE_ALTERNATIVES {
            return Err(CampaignCodecError::InvalidValue {
                reason: "discrete domain is empty or oversized",
            });
        }
        if alternatives
            .iter()
            .any(|(id, alternative)| *id != alternative.id())
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "discrete-domain key disagrees with alternative ID",
            });
        }
        let domain = Self {
            semantic_version,
            alternatives,
        };
        codec::ensure_encoded_size(
            &domain,
            MAX_CHOICE_DOMAIN_BYTES,
            "choice-domain-encoded-bytes",
        )?;
        Ok(domain)
    }

    /// Returns the semantic domain version.
    #[must_use]
    pub const fn semantic_version(&self) -> u32 {
        self.semantic_version
    }

    /// Returns alternatives in canonical ID order.
    #[must_use]
    pub fn alternatives(&self) -> &BTreeMap<AlternativeId, DiscreteAlternative> {
        &self.alternatives
    }
}

impl Canonical for DiscreteDomain {
    fn encode(&self, encoder: &mut Encoder) {
        self.semantic_version.encode(encoder);
        self.alternatives.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            u32::decode(decoder)?,
            decoder.map_bounded(
                MAX_DISCRETE_ALTERNATIVES,
                "discrete-domain-alternative-count",
            )?,
        )
    }
}

/// Signedness and canonical width of an integer choice domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IntegerRepresentation {
    /// Canonical signed 64-bit integer.
    Signed64,
    /// Canonical unsigned 64-bit integer.
    Unsigned64,
}

impl Canonical for IntegerRepresentation {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(match self {
            Self::Signed64 => 0,
            Self::Unsigned64 => 1,
        });
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Signed64),
            1 => Ok(Self::Unsigned64),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "integer-representation",
                tag,
            }),
        }
    }
}

/// Fixed-width integer value without platform-native narrowing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IntegerValue {
    /// Signed 64-bit value.
    Signed(i64),
    /// Unsigned 64-bit value.
    Unsigned(u64),
}

impl Canonical for IntegerValue {
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
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => i64::decode(decoder).map(Self::Signed),
            1 => u64::decode(decoder).map(Self::Unsigned),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "integer-value",
                tag,
            }),
        }
    }
}

/// Inclusive stepped integer domain with exact unit scale and landmarks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntegerDomain {
    semantic_version: u32,
    representation: IntegerRepresentation,
    minimum: IntegerValue,
    maximum: IntegerValue,
    step: u64,
    unit: Option<String>,
    scale: ExactRational,
    landmarks: Vec<IntegerValue>,
}

impl IntegerDomain {
    /// Builds and validates an integer domain.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for representation mismatch, an inverted
    /// range, zero step, invalid unit, duplicate or illegal landmarks, or
    /// semantic version zero.
    // crucible-lint: allow rust-allow -- this narrowly scoped exception preserves the surrounding typed boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        semantic_version: u32,
        representation: IntegerRepresentation,
        minimum: IntegerValue,
        maximum: IntegerValue,
        step: u64,
        unit: Option<String>,
        scale: ExactRational,
        mut landmarks: Vec<IntegerValue>,
    ) -> Result<Self, CampaignCodecError> {
        if semantic_version == 0 || step == 0 || scale.numerator() == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "integer domain has zero version or step",
            });
        }
        if unit
            .as_ref()
            .is_some_and(|unit| unit.is_empty() || unit.len() > MAX_PRESENTATION_BYTES)
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "integer domain unit is invalid",
            });
        }
        if let Some(unit) = &unit {
            codec::validate_nfc(unit)?;
        }
        if landmarks.len() > MAX_INTEGER_LANDMARKS {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "integer-domain-landmark-count",
            });
        }
        validate_representation(representation, minimum)?;
        validate_representation(representation, maximum)?;
        let span = integer_offset(minimum, maximum).ok_or(CampaignCodecError::InvalidValue {
            reason: "integer domain range is inverted",
        })?;
        if span % u128::from(step) != 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "integer domain maximum is unreachable by its step",
            });
        }

        landmarks.sort_unstable();
        if landmarks.windows(2).any(|window| window[0] == window[1]) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "integer domain contains duplicate landmarks",
            });
        }
        let domain = Self {
            semantic_version,
            representation,
            minimum,
            maximum,
            step,
            unit,
            scale,
            landmarks,
        };
        for landmark in &domain.landmarks {
            if !domain.contains_integer(*landmark) {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "integer domain contains an illegal landmark",
                });
            }
        }
        Ok(domain)
    }

    /// Returns the semantic domain version.
    #[must_use]
    pub const fn semantic_version(&self) -> u32 {
        self.semantic_version
    }

    /// Returns the integer representation.
    #[must_use]
    pub const fn representation(&self) -> IntegerRepresentation {
        self.representation
    }

    /// Returns the inclusive minimum.
    #[must_use]
    pub const fn minimum(&self) -> IntegerValue {
        self.minimum
    }

    /// Returns the inclusive maximum.
    #[must_use]
    pub const fn maximum(&self) -> IntegerValue {
        self.maximum
    }

    /// Returns the positive step magnitude.
    #[must_use]
    pub const fn step(&self) -> u64 {
        self.step
    }

    /// Returns the optional physical unit.
    #[must_use]
    pub fn unit(&self) -> Option<&str> {
        self.unit.as_deref()
    }

    /// Returns the exact physical scale.
    #[must_use]
    pub const fn scale(&self) -> ExactRational {
        self.scale
    }

    /// Returns generator-guidance landmarks in canonical numeric order.
    #[must_use]
    pub fn landmarks(&self) -> &[IntegerValue] {
        &self.landmarks
    }

    /// Computes exact finite cardinality with 128-bit intermediates.
    #[must_use]
    pub fn cardinality(&self) -> u128 {
        let span = integer_offset(self.minimum, self.maximum).unwrap_or_default();
        span / u128::from(self.step) + 1
    }

    /// Returns whether one integer is legal in this domain.
    #[must_use]
    pub fn contains_integer(&self, value: IntegerValue) -> bool {
        validate_representation(self.representation, value).is_ok()
            && integer_offset(self.minimum, value)
                .zip(integer_offset(value, self.maximum))
                .is_some_and(|(offset, _)| offset % u128::from(self.step) == 0)
    }
}

impl Canonical for IntegerDomain {
    fn encode(&self, encoder: &mut Encoder) {
        self.semantic_version.encode(encoder);
        self.representation.encode(encoder);
        self.minimum.encode(encoder);
        self.maximum.encode(encoder);
        self.step.encode(encoder);
        self.unit.encode(encoder);
        self.scale.encode(encoder);
        self.landmarks.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            u32::decode(decoder)?,
            IntegerRepresentation::decode(decoder)?,
            IntegerValue::decode(decoder)?,
            IntegerValue::decode(decoder)?,
            u64::decode(decoder)?,
            decoder.option_string_bounded(MAX_PRESENTATION_BYTES, "integer-unit-bytes")?,
            ExactRational::decode(decoder)?,
            decoder.sequence_bounded(
                MAX_INTEGER_LANDMARKS,
                "integer-domain-landmark-count",
                IntegerValue::decode,
            )?,
        )
    }
}

/// Closed typed legal-value domain shared by every opportunity source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChoiceDomain {
    /// Boolean false/true domain.
    Boolean(BooleanDomain),
    /// Nonempty finite stable alternatives.
    Discrete(DiscreteDomain),
    /// Large or small stepped integer range.
    Integer(IntegerDomain),
}

impl ChoiceDomain {
    /// Returns whether `value` is legal in this domain.
    #[must_use]
    pub fn contains(&self, value: &ChoiceValue) -> bool {
        match (self, value) {
            (Self::Boolean(_), ChoiceValue::Boolean(_)) => true,
            (Self::Discrete(domain), ChoiceValue::Discrete(id)) => {
                domain.alternatives.contains_key(id)
            }
            (Self::Integer(domain), ChoiceValue::Integer(value)) => domain.contains_integer(*value),
            _ => false,
        }
    }

    /// Returns exact finite cardinality without enumerating values.
    #[must_use]
    pub fn cardinality(&self) -> u128 {
        match self {
            Self::Boolean(_) => 2,
            Self::Discrete(domain) => domain.alternatives.len() as u128,
            Self::Integer(domain) => domain.cardinality(),
        }
    }

    /// Returns whether this domain is a legal narrowing of `parent`.
    #[must_use]
    pub fn is_subset_of(&self, parent: &Self) -> bool {
        match (self, parent) {
            (Self::Boolean(child), Self::Boolean(parent)) => {
                child.semantic_version == parent.semantic_version
            }
            (Self::Discrete(child), Self::Discrete(parent)) => {
                child.semantic_version == parent.semantic_version
                    && child
                        .alternatives
                        .keys()
                        .all(|id| parent.alternatives.contains_key(id))
            }
            (Self::Integer(child), Self::Integer(parent)) => {
                child.semantic_version == parent.semantic_version
                    && child.representation == parent.representation
                    && child.unit == parent.unit
                    && child.scale == parent.scale
                    && child.step % parent.step == 0
                    && parent.contains_integer(child.minimum)
                    && parent.contains_integer(child.maximum)
            }
            _ => false,
        }
    }

    /// Returns strict canonical bytes including presentation metadata.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        CHOICE_DOMAIN_SCHEMA_VERSION.encode(&mut encoder);
        self.encode(&mut encoder);
        encoder.finish()
    }

    /// Decodes strict canonical bytes and validates all domain invariants.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical, oversized,
    /// or semantically invalid bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        if bytes.len() > MAX_CHOICE_DOMAIN_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "choice-domain-encoded-bytes",
            });
        }
        #[derive(Clone, Debug, PartialEq, Eq)]
        struct VersionedDomain(ChoiceDomain);

        impl Canonical for VersionedDomain {
            fn encode(&self, encoder: &mut Encoder) {
                CHOICE_DOMAIN_SCHEMA_VERSION.encode(encoder);
                self.0.encode(encoder);
            }

            fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
                if u32::decode(decoder)? != CHOICE_DOMAIN_SCHEMA_VERSION {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "unsupported choice-domain schema version",
                    });
                }
                ChoiceDomain::decode(decoder).map(Self)
            }
        }

        codec::decode::<VersionedDomain>(bytes).map(|domain| domain.0)
    }

    /// Returns the exact stored domain-object identity, including presentation.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if the canonical envelope exceeds bounds.
    pub fn id(&self) -> Result<ChoiceDomainId, CampaignCodecError> {
        let envelope = crate::ObjectEnvelope::for_record(
            crate::CampaignRecordKind::ChoiceDomain,
            std::collections::BTreeSet::new(),
            self.canonical_bytes(),
        )?;
        ChoiceDomainId::from_content_id(envelope.content_id())
    }

    /// Returns presentation-independent semantic domain identity.
    #[must_use]
    pub fn semantic_id(&self) -> ChoiceDomainSemanticId {
        let mut encoder = Encoder::new();
        CHOICE_DOMAIN_SCHEMA_VERSION.encode(&mut encoder);
        match self {
            Self::Boolean(domain) => {
                encoder.u8(0);
                domain.semantic_version.encode(&mut encoder);
            }
            Self::Discrete(domain) => {
                encoder.u8(1);
                domain.semantic_version.encode(&mut encoder);
                encoder.u64(domain.alternatives.len() as u64);
                for id in domain.alternatives.keys() {
                    id.encode(&mut encoder);
                }
            }
            Self::Integer(domain) => {
                encoder.u8(2);
                domain.semantic_version.encode(&mut encoder);
                domain.representation.encode(&mut encoder);
                domain.minimum.encode(&mut encoder);
                domain.maximum.encode(&mut encoder);
                domain.step.encode(&mut encoder);
                domain.unit.encode(&mut encoder);
                domain.scale.encode(&mut encoder);
            }
        }
        ChoiceDomainSemanticId::from_hash(CampaignHash::derive(
            "crucible.choice-domain-semantics.v1",
            &encoder.finish(),
        ))
    }
}

impl Canonical for ChoiceDomain {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Boolean(domain) => {
                encoder.u8(0);
                domain.encode(encoder);
            }
            Self::Discrete(domain) => {
                encoder.u8(1);
                domain.encode(encoder);
            }
            Self::Integer(domain) => {
                encoder.u8(2);
                domain.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => BooleanDomain::decode(decoder).map(Self::Boolean),
            1 => DiscreteDomain::decode(decoder).map(Self::Discrete),
            2 => IntegerDomain::decode(decoder).map(Self::Integer),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "choice-domain",
                tag,
            }),
        }
    }
}

/// Concrete legal value selected from a [`ChoiceDomain`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChoiceValue {
    /// Boolean value.
    Boolean(bool),
    /// Stable discrete alternative.
    Discrete(AlternativeId),
    /// Signed or unsigned fixed-width integer.
    Integer(IntegerValue),
}

impl ChoiceValue {
    /// Returns strict canonical value bytes for guest delivery and replay.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes and validates strict canonical value bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical, or
    /// unsupported value bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        codec::decode(bytes)
    }
}

impl Canonical for ChoiceValue {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Boolean(value) => {
                encoder.u8(0);
                value.encode(encoder);
            }
            Self::Discrete(id) => {
                encoder.u8(1);
                id.encode(encoder);
            }
            Self::Integer(value) => {
                encoder.u8(2);
                value.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => bool::decode(decoder).map(Self::Boolean),
            1 => AlternativeId::decode(decoder).map(Self::Discrete),
            2 => IntegerValue::decode(decoder).map(Self::Integer),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "choice-value",
                tag,
            }),
        }
    }
}

fn validate_representation(
    representation: IntegerRepresentation,
    value: IntegerValue,
) -> Result<(), CampaignCodecError> {
    if matches!(
        (representation, value),
        (IntegerRepresentation::Signed64, IntegerValue::Signed(_))
            | (IntegerRepresentation::Unsigned64, IntegerValue::Unsigned(_))
    ) {
        Ok(())
    } else {
        Err(CampaignCodecError::InvalidValue {
            reason: "integer value disagrees with domain representation",
        })
    }
}

fn integer_offset(minimum: IntegerValue, value: IntegerValue) -> Option<u128> {
    match (minimum, value) {
        (IntegerValue::Signed(minimum), IntegerValue::Signed(value)) => {
            let difference = i128::from(value) - i128::from(minimum);
            u128::try_from(difference).ok()
        }
        (IntegerValue::Unsigned(minimum), IntegerValue::Unsigned(value)) => {
            value.checked_sub(minimum).map(u128::from)
        }
        _ => None,
    }
}
